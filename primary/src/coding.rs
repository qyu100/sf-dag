use crate::error::{DagError, DagResult};
use log::debug;
use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuilder};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

// Thread-local cache to avoid global Mutex contention. Each thread keeps its own
// optional (encoder, decoder, shard_len) so reconstruct_shards can be lock-free.
thread_local! {
    static SIMD_CACHE_TLS: RefCell<Option<(ReedSolomonEncoder, ReedSolomonDecoder, usize)>> = RefCell::new(None);
}

static RS_BLOCK_POOLS: OnceLock<Mutex<HashMap<usize, Arc<ThreadPool>>>> = OnceLock::new();

fn rs_block_pool(rs_block_threads: usize) -> Arc<ThreadPool> {
    let pools = RS_BLOCK_POOLS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = pools.lock().expect("failed to lock RS block pool map");
    if let Some(pool) = guard.get(&rs_block_threads) {
        return Arc::clone(pool);
    }

    let pool = Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(rs_block_threads)
            .build()
            .expect("failed to build RS block thread pool"),
    );
    guard.insert(rs_block_threads, Arc::clone(&pool));
    pool
}
/// A wrapper for `ReedSolomon` that doesn't panic if there are no parity shards.
pub enum Coding {
    /// A `ReedSolomon` instance with at least one parity shard.
    ReedSolomon {
        data_shards: usize,
        parity_shards: usize,
    },
    /// A no-op replacement that doesn't encode or decode anything.
    Trivial(usize),
}

impl Coding {
    /// Creates a new `Coding` instance with the given number of shards.
    pub fn new(data_shard_num: usize, parity_shard_num: usize) -> DagResult<Self> {
        if parity_shard_num > 0 {
            Ok(Coding::ReedSolomon {
                data_shards: data_shard_num,
                parity_shards: parity_shard_num,
            })
        } else {
            Ok(Coding::Trivial(data_shard_num))
        }
    }

    /// Returns the number of data shards.
    pub fn data_shard_count(&self) -> usize {
        match *self {
            Coding::ReedSolomon { data_shards, .. } => data_shards,
            Coding::Trivial(dsc) => dsc,
        }
    }

    /// Returns the number of parity shards.
    pub fn parity_shard_count(&self) -> usize {
        match *self {
            Coding::ReedSolomon { parity_shards, .. } => parity_shards,
            Coding::Trivial(_) => 0,
        }
    }

    /// Constructs (and overwrites) the parity shards.
    pub fn encode(
        &self,
        slices: &mut [&mut [u8]],
        rs_block_size: usize,
        rs_block_threads: usize,
    ) -> DagResult<()> {
        match *self {
            Coding::ReedSolomon {
                data_shards,
                parity_shards,
                ..
            } => {
                let total_shards = data_shards + parity_shards;
                if slices.len() != total_shards {
                    return Err(DagError::ProofConstructionFailed);
                }

                // Determine shard_size from first data shard and validate consistency.
                let shard_size = slices[0].len();
                for i in 0..data_shards {
                    if slices[i].len() != shard_size {
                        return Err(DagError::ProofConstructionFailed);
                    }
                }

                if shard_size % 64 != 0 {
                    return Err(DagError::ProofConstructionFailed);
                }

                let mut parity_ptrs: Vec<usize> = vec![0; parity_shards];
                for ridx in 0..parity_shards {
                    let abs_idx = data_shards + ridx;
                    parity_ptrs[ridx] = slices[abs_idx].as_mut_ptr() as usize;
                }

                let mut originals_slices: Vec<&[u8]> = Vec::with_capacity(data_shards);
                for i in 0..data_shards {
                    originals_slices.push(&slices[i][..]);
                }

                let block_size = rs_block_size;
                let num_blocks = (shard_size + block_size - 1) / block_size;
                debug!(
                    "encode: block params block_size={} num_blocks={} pool_threads={}",
                    block_size, num_blocks, rs_block_threads
                );
                let t_encode = Instant::now();
                rs_block_pool(rs_block_threads)
                    .install(|| {
                        (0..num_blocks)
                            .into_par_iter()
                            .try_for_each(|block_idx| -> DagResult<()> {
                                let offset = block_idx * block_size;
                                let block_len = std::cmp::min(block_size, shard_size - offset);
                                if block_len % 64 != 0 {
                                    return Err(DagError::ProofConstructionFailed);
                                }

                                let mut block_encoder =
                                    ReedSolomonEncoder::new(data_shards, parity_shards, block_len)
                                        .map_err(|_| DagError::ProofConstructionFailed)?;
                                for i in 0..data_shards {
                                    block_encoder
                                        .add_original_shard(
                                            &originals_slices[i][offset..offset + block_len],
                                        )
                                        .map_err(|_| DagError::ProofConstructionFailed)?;
                                }

                                let block_result = block_encoder
                                    .encode()
                                    .map_err(|_| DagError::ProofConstructionFailed)?;
                                for (ridx, recovery) in block_result.recovery_iter().enumerate() {
                                    let ptr = parity_ptrs[ridx] as *mut u8;
                                    unsafe {
                                        std::ptr::copy_nonoverlapping(
                                            recovery.as_ptr(),
                                            ptr.add(offset),
                                            block_len,
                                        );
                                    }
                                }
                                Ok(())
                            })
                    })
                    .map_err(|_| DagError::ProofConstructionFailed)?;
                debug!(
                    "encode: parity encode (block) took {:?}",
                    t_encode.elapsed()
                );

                Ok(())
            }
            Coding::Trivial(_) => Ok(()),
        }
    }

    /// If enough shards are present, reconstructs the missing ones.
    pub fn reconstruct_shards(
        &self,
        shards: &mut [Option<Box<[u8]>>],
        rs_block_size: usize,
        rs_block_threads: usize,
    ) -> DagResult<()> {
        match *self {
            Coding::ReedSolomon {
                data_shards,
                parity_shards,
                ..
            } => {
                let t_start = Instant::now();

                let shard_size = shards
                    .iter()
                    .find_map(|s| s.as_ref().map(|b| b.len()))
                    .ok_or(DagError::ProofConstructionFailed)?;

                let missing_data_indices: Vec<usize> = shards
                    .iter()
                    .enumerate()
                    .take(data_shards)
                    .filter(|(_, s)| s.is_none())
                    .map(|(i, _)| i)
                    .collect();

                let missing_parity_indices: Vec<usize> = shards
                    .iter()
                    .enumerate()
                    .skip(data_shards)
                    .filter(|(_, s)| s.is_none())
                    .map(|(i, _)| i)
                    .collect();

                if missing_data_indices.is_empty() && missing_parity_indices.is_empty() {
                    return Ok(());
                }

                let mut cached = None;
                SIMD_CACHE_TLS.with(|cell| cached = cell.borrow_mut().take());

                let (mut encoder, decoder) = match cached {
                    Some((e, d, len)) if len == shard_size => (e, d),
                    _ => (
                        ReedSolomonEncoder::new(data_shards, parity_shards, shard_size)
                            .map_err(|_| DagError::ProofConstructionFailed)?,
                        ReedSolomonDecoder::new(data_shards, parity_shards, shard_size)
                            .map_err(|_| DagError::ProofConstructionFailed)?,
                    ),
                };

                if !missing_data_indices.is_empty() {
                    let current_data_count = shards
                        .iter()
                        .take(data_shards)
                        .filter(|s| s.is_some())
                        .count();

                    if current_data_count < data_shards {
                        let available_shards = shards.iter().filter(|s| s.is_some()).count();
                        if available_shards < data_shards {
                            return Err(DagError::ProofConstructionFailed);
                        }

                        let mut missing_data_mask = vec![false; data_shards];
                        for &idx in &missing_data_indices {
                            missing_data_mask[idx] = true;
                        }

                        let mut data_ptrs: Vec<usize> = vec![0; data_shards];
                        for &idx in &missing_data_indices {
                            if shards[idx].is_none() {
                                let mut buf = Vec::with_capacity(shard_size);
                                unsafe {
                                    buf.set_len(shard_size);
                                }
                                shards[idx] = Some(buf.into_boxed_slice());
                            }
                            let ptr = shards[idx]
                                .as_mut()
                                .ok_or(DagError::ProofConstructionFailed)?
                                .as_mut_ptr();
                            data_ptrs[idx] = ptr as usize;
                        }

                        let mut data_slices: Vec<Option<&[u8]>> = Vec::with_capacity(data_shards);
                        for i in 0..data_shards {
                            if missing_data_mask[i] {
                                data_slices.push(None);
                            } else {
                                data_slices.push(shards[i].as_ref().map(|b| b.as_ref()));
                            }
                        }

                        let mut parity_slices: Vec<Option<&[u8]>> =
                            Vec::with_capacity(parity_shards);
                        for ridx in 0..parity_shards {
                            parity_slices
                                .push(shards[data_shards + ridx].as_ref().map(|b| b.as_ref()));
                        }

                        let block_size = rs_block_size;
                        let num_blocks = (shard_size + block_size - 1) / block_size;
                        debug!(
                        "reconstruct: decode block params block_size={} num_blocks={} pool_threads={} available_shards={}",
                        block_size,
                        num_blocks,
                        rs_block_threads,
                        available_shards
                    );

                        let t_decode = Instant::now();
                        rs_block_pool(rs_block_threads)
                            .install(|| {
                                (0..num_blocks).into_par_iter().try_for_each(
                                    |block_idx| -> DagResult<()> {
                                        let offset = block_idx * block_size;
                                        let block_len =
                                            std::cmp::min(block_size, shard_size - offset);
                                        if block_len % 64 != 0 {
                                            return Err(DagError::ProofConstructionFailed);
                                        }

                                        let mut block_decoder = ReedSolomonDecoder::new(
                                            data_shards,
                                            parity_shards,
                                            block_len,
                                        )
                                        .map_err(|_| DagError::ProofConstructionFailed)?;
                                        for i in 0..data_shards {
                                            if let Some(s) = data_slices[i] {
                                                block_decoder
                                                    .add_original_shard(
                                                        i,
                                                        &s[offset..offset + block_len],
                                                    )
                                                    .map_err(|_| {
                                                        DagError::ProofConstructionFailed
                                                    })?;
                                            }
                                        }
                                        for ridx in 0..parity_shards {
                                            if let Some(s) = parity_slices[ridx] {
                                                block_decoder
                                                    .add_recovery_shard(
                                                        ridx,
                                                        &s[offset..offset + block_len],
                                                    )
                                                    .map_err(|_| {
                                                        DagError::ProofConstructionFailed
                                                    })?;
                                            }
                                        }

                                        let block_result = block_decoder
                                            .decode()
                                            .map_err(|_| DagError::ProofConstructionFailed)?;
                                        for (idx, restored) in block_result.restored_original_iter()
                                        {
                                            let ptr = data_ptrs[idx] as *mut u8;
                                            if !ptr.is_null() {
                                                unsafe {
                                                    std::ptr::copy_nonoverlapping(
                                                        restored.as_ptr(),
                                                        ptr.add(offset),
                                                        block_len,
                                                    );
                                                }
                                            }
                                        }
                                        Ok(())
                                    },
                                )
                            })
                            .map_err(|_| DagError::ProofConstructionFailed)?;
                        debug!("reconstruct: decode (block) took: {:?}", t_decode.elapsed());
                    } else {
                        debug!("reconstruct: Data shards already complete, skipping decoder.");
                    }
                }

                if !missing_parity_indices.is_empty() {
                    let t_p_total = Instant::now();
                    debug!(
                        "reconstruct: parity params data_shards={} parity_shards={} shard_size={}",
                        data_shards, parity_shards, shard_size
                    );

                    encoder
                        .reset(data_shards, parity_shards, shard_size)
                        .map_err(|_| DagError::ProofConstructionFailed)?;

                    let t_add = Instant::now();
                    for i in 0..data_shards {
                        let s = shards[i]
                            .as_ref()
                            .ok_or(DagError::ProofConstructionFailed)?;
                        encoder
                            .add_original_shard(s)
                            .map_err(|_| DagError::ProofConstructionFailed)?;
                    }
                    debug!(
                        "reconstruct: parity add_original_shard took {:?}",
                        t_add.elapsed()
                    );

                    let t_encode = Instant::now();
                    let mut missing_parity_mask = vec![false; parity_shards];
                    for abs_idx in &missing_parity_indices {
                        missing_parity_mask[abs_idx - data_shards] = true;
                    }

                    let mut parity_ptrs: Vec<usize> = vec![0; parity_shards];
                    for ridx in 0..parity_shards {
                        if missing_parity_mask[ridx] {
                            let abs_idx = data_shards + ridx;
                            if shards[abs_idx].is_none() {
                                let mut buf = Vec::with_capacity(shard_size);
                                unsafe {
                                    buf.set_len(shard_size);
                                }
                                shards[abs_idx] = Some(buf.into_boxed_slice());
                            }
                            let ptr = shards[abs_idx]
                                .as_mut()
                                .ok_or(DagError::ProofConstructionFailed)?
                                .as_mut_ptr();
                            parity_ptrs[ridx] = ptr as usize;
                        }
                    }

                    let mut originals_slices: Vec<&[u8]> = Vec::with_capacity(data_shards);
                    for i in 0..data_shards {
                        let s = shards[i]
                            .as_ref()
                            .ok_or(DagError::ProofConstructionFailed)?;
                        originals_slices.push(s);
                    }

                    let block_size = rs_block_size;
                    let num_blocks = (shard_size + block_size - 1) / block_size;
                    debug!(
                    "reconstruct: parity block params block_size={} num_blocks={} pool_threads={}",
                    block_size,
                    num_blocks,
                    rs_block_threads
                );
                    rs_block_pool(rs_block_threads)
                        .install(|| {
                            (0..num_blocks).into_par_iter().try_for_each(
                                |block_idx| -> DagResult<()> {
                                    let offset = block_idx * block_size;
                                    let block_len = std::cmp::min(block_size, shard_size - offset);
                                    if block_len % 64 != 0 {
                                        return Err(DagError::ProofConstructionFailed);
                                    }

                                    let mut block_encoder = ReedSolomonEncoder::new(
                                        data_shards,
                                        parity_shards,
                                        block_len,
                                    )
                                    .map_err(|_| DagError::ProofConstructionFailed)?;
                                    for i in 0..data_shards {
                                        block_encoder
                                            .add_original_shard(
                                                &originals_slices[i][offset..offset + block_len],
                                            )
                                            .map_err(|_| DagError::ProofConstructionFailed)?;
                                    }

                                    let block_result = block_encoder
                                        .encode()
                                        .map_err(|_| DagError::ProofConstructionFailed)?;
                                    for (ridx, recovery) in block_result.recovery_iter().enumerate()
                                    {
                                        let ptr = parity_ptrs[ridx] as *mut u8;
                                        if !ptr.is_null() {
                                            unsafe {
                                                std::ptr::copy_nonoverlapping(
                                                    recovery.as_ptr(),
                                                    ptr.add(offset),
                                                    block_len,
                                                );
                                            }
                                        }
                                    }
                                    Ok(())
                                },
                            )
                        })
                        .map_err(|_| DagError::ProofConstructionFailed)?;
                    debug!(
                        "reconstruct: parity encode (block) took {:?}",
                        t_encode.elapsed()
                    );
                    debug!("reconstruct: parity total took {:?}", t_p_total.elapsed());
                }

                SIMD_CACHE_TLS.with(|cell| {
                    *cell.borrow_mut() = Some((encoder, decoder, shard_size));
                });

                debug!("reconstruct: total total_elapsed={:?}", t_start.elapsed());
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
