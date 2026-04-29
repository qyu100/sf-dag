use crate::error::{ConsensusError, ConsensusResult};
use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuilder};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

static RS_BLOCK_POOLS: OnceLock<Mutex<HashMap<usize, Arc<ThreadPool>>>> = OnceLock::new();

fn rs_block_pool(rs_block_threads: usize) -> Arc<ThreadPool> {
    let threads = rs_block_threads.max(1);
    let pools = RS_BLOCK_POOLS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = pools.lock().expect("failed to lock RS block pool map");
    if let Some(pool) = guard.get(&threads) {
        return Arc::clone(pool);
    }

    let pool = Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("failed to build RS block thread pool"),
    );
    guard.insert(threads, Arc::clone(&pool));
    pool
}

fn normalized_block_size(rs_block_size: usize) -> usize {
    let block_size = rs_block_size.max(64);
    block_size - (block_size % 64)
}

pub struct Coding {
    data_shards: usize,
    parity_shards: usize,
}

impl Coding {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
        }
    }

    pub fn data_shard_count(&self) -> usize {
        self.data_shards
    }

    pub fn parity_shard_count(&self) -> usize {
        self.parity_shards
    }

    pub fn total_shard_count(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    pub fn encode(
        &self,
        slices: &mut [&mut [u8]],
        rs_block_size: usize,
        rs_block_threads: usize,
    ) -> ConsensusResult<()> {
        if self.parity_shards == 0 {
            return Ok(());
        }
        if slices.len() != self.total_shard_count() {
            return Err(ConsensusError::ProofConstructionFailed);
        }
        let shard_len = slices[0].len();
        if slices.iter().any(|s| s.len() != shard_len) {
            return Err(ConsensusError::ProofConstructionFailed);
        }
        if shard_len % 64 != 0 {
            return Err(ConsensusError::ProofConstructionFailed);
        }

        let block_size = normalized_block_size(rs_block_size);
        let num_blocks = (shard_len + block_size - 1) / block_size;
        let (data_slices, parity_slices) = slices.split_at_mut(self.data_shards);
        let originals: Vec<&[u8]> = data_slices
            .iter()
            .map(|s| &s[..])
            .collect();
        let parity_ptrs: Vec<usize> = parity_slices
            .iter_mut()
            .map(|s| s.as_mut_ptr() as usize)
            .collect();

        rs_block_pool(rs_block_threads)
            .install(|| {
                (0..num_blocks)
                    .into_par_iter()
                    .try_for_each(|block_idx| -> ConsensusResult<()> {
                        let offset = block_idx * block_size;
                        let block_len = std::cmp::min(block_size, shard_len - offset);
                        if block_len % 64 != 0 {
                            return Err(ConsensusError::ProofConstructionFailed);
                        }

                        let mut encoder = ReedSolomonEncoder::new(
                            self.data_shards,
                            self.parity_shards,
                            block_len,
                        )
                        .map_err(|_| ConsensusError::ProofConstructionFailed)?;
                        for shard in originals.iter().take(self.data_shards) {
                            encoder
                                .add_original_shard(&shard[offset..offset + block_len])
                                .map_err(|_| ConsensusError::ProofConstructionFailed)?;
                        }
                        let result = encoder
                            .encode()
                            .map_err(|_| ConsensusError::ProofConstructionFailed)?;
                        for (idx, recovery) in result.recovery_iter().enumerate() {
                            let ptr = parity_ptrs[idx] as *mut u8;
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
            .map_err(|_| ConsensusError::ProofConstructionFailed)
    }

    pub fn reconstruct_shards(
        &self,
        shards: &mut [Option<Box<[u8]>>],
        rs_block_size: usize,
        rs_block_threads: usize,
    ) -> ConsensusResult<()> {
        if self.parity_shards == 0 {
            return Ok(());
        }
        if shards.len() != self.total_shard_count() {
            return Err(ConsensusError::ProofConstructionFailed);
        }
        let shard_len = shards
            .iter()
            .find_map(|s| s.as_ref().map(|b| b.len()))
            .ok_or(ConsensusError::ProofConstructionFailed)?;

        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < self.data_shards {
            return Err(ConsensusError::ProofConstructionFailed);
        }

        if shards.iter().take(self.data_shards).any(|s| s.is_none()) {
            let block_size = normalized_block_size(rs_block_size);
            let num_blocks = (shard_len + block_size - 1) / block_size;
            let missing_data: Vec<usize> = shards
                .iter()
                .take(self.data_shards)
                .enumerate()
                .filter_map(|(idx, shard)| shard.is_none().then_some(idx))
                .collect();

            for idx in &missing_data {
                let mut buf = Vec::with_capacity(shard_len);
                buf.resize(shard_len, 0);
                shards[*idx] = Some(buf.into_boxed_slice());
            }

            let missing_mask: Vec<bool> = (0..self.data_shards)
                .map(|idx| missing_data.contains(&idx))
                .collect();
            let data_ptrs: Vec<usize> = shards
                .iter_mut()
                .take(self.data_shards)
                .map(|shard| {
                    shard
                        .as_mut()
                        .map(|s| s.as_mut_ptr() as usize)
                        .unwrap_or_default()
                })
                .collect();
            let data_slices: Vec<Option<&[u8]>> = shards
                .iter()
                .take(self.data_shards)
                .enumerate()
                .map(|(idx, shard)| {
                    if missing_mask[idx] {
                        None
                    } else {
                        shard.as_ref().map(|s| s.as_ref())
                    }
                })
                .collect();
            let parity_slices: Vec<Option<&[u8]>> = shards
                .iter()
                .skip(self.data_shards)
                .map(|shard| shard.as_ref().map(|s| s.as_ref()))
                .collect();

            rs_block_pool(rs_block_threads)
                .install(|| {
                    (0..num_blocks)
                        .into_par_iter()
                        .try_for_each(|block_idx| -> ConsensusResult<()> {
                            let offset = block_idx * block_size;
                            let block_len = std::cmp::min(block_size, shard_len - offset);
                            if block_len % 64 != 0 {
                                return Err(ConsensusError::ProofConstructionFailed);
                            }

                            let mut decoder = ReedSolomonDecoder::new(
                                self.data_shards,
                                self.parity_shards,
                                block_len,
                            )
                            .map_err(|_| ConsensusError::ProofConstructionFailed)?;
                            for (idx, shard) in data_slices.iter().enumerate() {
                                if let Some(shard) = shard {
                                    decoder
                                        .add_original_shard(idx, &shard[offset..offset + block_len])
                                        .map_err(|_| ConsensusError::ProofConstructionFailed)?;
                                }
                            }
                            for (idx, shard) in parity_slices.iter().enumerate() {
                                if let Some(shard) = shard {
                                    decoder
                                        .add_recovery_shard(idx, &shard[offset..offset + block_len])
                                        .map_err(|_| ConsensusError::ProofConstructionFailed)?;
                                }
                            }

                            let decoded = decoder
                                .decode()
                                .map_err(|_| ConsensusError::ProofConstructionFailed)?;
                            for (idx, restored) in decoded.restored_original_iter() {
                                let ptr = data_ptrs[idx] as *mut u8;
                                unsafe {
                                    std::ptr::copy_nonoverlapping(
                                        restored.as_ptr(),
                                        ptr.add(offset),
                                        block_len,
                                    );
                                }
                            }
                            Ok(())
                        })
                })
                .map_err(|_| ConsensusError::ProofConstructionFailed)?;
        }

        if shards.iter().skip(self.data_shards).any(|s| s.is_none()) {
            let block_size = normalized_block_size(rs_block_size);
            let num_blocks = (shard_len + block_size - 1) / block_size;
            let mut parity_ptrs = Vec::with_capacity(self.parity_shards);
            for idx in self.data_shards..self.total_shard_count() {
                if shards[idx].is_none() {
                    let mut buf = Vec::with_capacity(shard_len);
                    buf.resize(shard_len, 0);
                    shards[idx] = Some(buf.into_boxed_slice());
                }
                parity_ptrs.push(
                    shards[idx]
                        .as_mut()
                        .ok_or(ConsensusError::ProofConstructionFailed)?
                        .as_mut_ptr() as usize,
                );
            }
            let originals: Vec<&[u8]> = shards
                .iter()
                .take(self.data_shards)
                .map(|shard| {
                    shard
                        .as_ref()
                        .map(|s| s.as_ref())
                        .ok_or(ConsensusError::ProofConstructionFailed)
                })
                .collect::<ConsensusResult<_>>()?;

            rs_block_pool(rs_block_threads)
                .install(|| {
                    (0..num_blocks)
                        .into_par_iter()
                        .try_for_each(|block_idx| -> ConsensusResult<()> {
                            let offset = block_idx * block_size;
                            let block_len = std::cmp::min(block_size, shard_len - offset);
                            if block_len % 64 != 0 {
                                return Err(ConsensusError::ProofConstructionFailed);
                            }

                            let mut encoder = ReedSolomonEncoder::new(
                                self.data_shards,
                                self.parity_shards,
                                block_len,
                            )
                            .map_err(|_| ConsensusError::ProofConstructionFailed)?;
                            for shard in originals.iter().take(self.data_shards) {
                                encoder
                                    .add_original_shard(&shard[offset..offset + block_len])
                                    .map_err(|_| ConsensusError::ProofConstructionFailed)?;
                            }
                            let encoded = encoder
                                .encode()
                                .map_err(|_| ConsensusError::ProofConstructionFailed)?;
                            for (idx, recovery) in encoded.recovery_iter().enumerate() {
                                let ptr = parity_ptrs[idx] as *mut u8;
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
                .map_err(|_| ConsensusError::ProofConstructionFailed)?;
        }
        Ok(())
    }
}

pub fn shard_hashes(shards: &[Option<Box<[u8]>>]) -> ConsensusResult<Vec<crypto::Digest>> {
    shards
        .par_iter()
        .map(|shard| {
            shard
                .as_ref()
                .map(|s| crate::merkle::MerkleTree::digest(s))
                .ok_or(ConsensusError::ProofConstructionFailed)
        })
        .collect()
}
