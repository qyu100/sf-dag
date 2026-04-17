use crate::error::{ConsensusError, ConsensusResult};
use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuilder};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

static RS_BLOCK_POOLS: OnceLock<Mutex<HashMap<usize, Arc<ThreadPool>>>> = OnceLock::new();

fn rs_block_pool(rs_block_threads: usize) -> Arc<ThreadPool> {
    let rs_block_threads = rs_block_threads.max(1);
    let pools = RS_BLOCK_POOLS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut pools = pools.lock().expect("RS block pool lock poisoned");
    pools
        .entry(rs_block_threads)
        .or_insert_with(|| {
            let thread_name = format!("rs-block-{rs_block_threads}");
            Arc::new(
                ThreadPoolBuilder::new()
                    .num_threads(rs_block_threads)
                    .thread_name(move |i| format!("{thread_name}-{i}"))
                    .build()
                    .expect("failed to build RS block thread pool"),
            )
        })
        .clone()
}

fn block_size_for(shard_len: usize, rs_block_size: usize) -> ConsensusResult<usize> {
    if shard_len == 0 || shard_len % 64 != 0 {
        return Err(ConsensusError::InvalidPayload);
    }
    let requested = rs_block_size.max(64).min(shard_len);
    Ok((requested - (requested % 64)).max(64))
}

fn block_len(shard_len: usize, block_size: usize, block_idx: usize) -> ConsensusResult<usize> {
    let offset = block_idx * block_size;
    let len = block_size.min(shard_len - offset);
    if len == 0 || len % 64 != 0 {
        return Err(ConsensusError::InvalidPayload);
    }
    Ok(len)
}

#[derive(Clone)]
pub struct Coding {
    data_shards: usize,
    parity_shards: usize,
}

impl Coding {
    pub fn new(data_shards: usize, parity_shards: usize) -> ConsensusResult<Self> {
        if data_shards == 0 {
            return Err(ConsensusError::InvalidPayload);
        }
        Ok(Self {
            data_shards,
            parity_shards,
        })
    }

    pub fn data_shard_count(&self) -> usize {
        self.data_shards
    }

    pub fn total_shard_count(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    pub fn encode(
        &self,
        shards: &mut [&mut [u8]],
        rs_block_size: usize,
        rs_block_threads: usize,
    ) -> ConsensusResult<()> {
        if self.parity_shards == 0 {
            return Ok(());
        }
        if shards.len() != self.total_shard_count() {
            return Err(ConsensusError::InvalidPayload);
        }

        let shard_len = shards[0].len();
        if shards.iter().any(|shard| shard.len() != shard_len) {
            return Err(ConsensusError::InvalidPayload);
        }
        let block_size = block_size_for(shard_len, rs_block_size)?;
        let num_blocks = (shard_len + block_size - 1) / block_size;
        let (data_shards, parity_shards) = shards.split_at_mut(self.data_shards);
        let data_slices: Vec<&[u8]> = data_shards.iter().map(|shard| &shard[..]).collect();
        let parity_ptrs: Vec<usize> = parity_shards
            .iter_mut()
            .map(|shard| shard.as_mut_ptr() as usize)
            .collect();

        rs_block_pool(rs_block_threads).install(|| {
            (0..num_blocks)
                .into_par_iter()
                .try_for_each(|block_idx| -> ConsensusResult<()> {
                    let offset = block_idx * block_size;
                    let block_len = block_len(shard_len, block_size, block_idx)?;
                    let mut encoder =
                        ReedSolomonEncoder::new(self.data_shards, self.parity_shards, block_len)
                            .map_err(|_| ConsensusError::InvalidPayload)?;
                    for shard in &data_slices {
                        encoder
                            .add_original_shard(&shard[offset..offset + block_len])
                            .map_err(|_| ConsensusError::InvalidPayload)?;
                    }
                    let result = encoder
                        .encode()
                        .map_err(|_| ConsensusError::InvalidPayload)?;
                    for (i, recovery) in result.recovery_iter().enumerate() {
                        let parity_ptr = parity_ptrs[i] as *mut u8;
                        unsafe {
                            parity_ptr
                                .add(offset)
                                .copy_from_nonoverlapping(recovery.as_ptr(), block_len);
                        }
                    }
                    Ok(())
                })
        })
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
            return Err(ConsensusError::InvalidPayload);
        }
        let shard_len = shards
            .iter()
            .find_map(|x| x.as_ref().map(|s| s.len()))
            .ok_or(ConsensusError::InvalidPayload)?;
        if shards
            .iter()
            .flatten()
            .any(|shard| shard.len() != shard_len)
        {
            return Err(ConsensusError::InvalidPayload);
        }
        if shards.iter().filter(|x| x.is_some()).count() < self.data_shards {
            return Err(ConsensusError::InvalidPayload);
        }
        let block_size = block_size_for(shard_len, rs_block_size)?;
        let num_blocks = (shard_len + block_size - 1) / block_size;

        let missing_data_indices: Vec<_> = (0..self.data_shards)
            .filter(|&i| shards[i].is_none())
            .collect();
        if !missing_data_indices.is_empty() {
            let mut restored_data: Vec<(usize, Box<[u8]>)> = missing_data_indices
                .iter()
                .map(|&i| (i, vec![0u8; shard_len].into_boxed_slice()))
                .collect();
            let data_ptrs: Vec<(usize, usize)> = restored_data
                .iter_mut()
                .map(|(i, shard)| (*i, shard.as_mut_ptr() as usize))
                .collect();
            let data_slices: Vec<(usize, &[u8])> = shards
                .iter()
                .take(self.data_shards)
                .enumerate()
                .filter_map(|(i, shard)| shard.as_ref().map(|s| (i, &s[..])))
                .collect();
            let recovery_slices: Vec<(usize, &[u8])> = shards
                .iter()
                .skip(self.data_shards)
                .enumerate()
                .filter_map(|(i, shard)| shard.as_ref().map(|s| (i, &s[..])))
                .collect();

            rs_block_pool(rs_block_threads).install(|| {
                (0..num_blocks)
                    .into_par_iter()
                    .try_for_each(|block_idx| -> ConsensusResult<()> {
                        let offset = block_idx * block_size;
                        let block_len = block_len(shard_len, block_size, block_idx)?;
                        let mut decoder = ReedSolomonDecoder::new(
                            self.data_shards,
                            self.parity_shards,
                            block_len,
                        )
                        .map_err(|_| ConsensusError::InvalidPayload)?;
                        for (i, shard) in &data_slices {
                            decoder
                                .add_original_shard(*i, &shard[offset..offset + block_len])
                                .map_err(|_| ConsensusError::InvalidPayload)?;
                        }
                        for (i, shard) in &recovery_slices {
                            decoder
                                .add_recovery_shard(*i, &shard[offset..offset + block_len])
                                .map_err(|_| ConsensusError::InvalidPayload)?;
                        }
                        let result = decoder
                            .decode()
                            .map_err(|_| ConsensusError::InvalidPayload)?;
                        for (i, restored) in result.restored_original_iter() {
                            if let Some((_, ptr)) =
                                data_ptrs.iter().find(|(data_idx, _)| *data_idx == i)
                            {
                                let data_ptr = *ptr as *mut u8;
                                unsafe {
                                    data_ptr
                                        .add(offset)
                                        .copy_from_nonoverlapping(restored.as_ptr(), block_len);
                                }
                            }
                        }
                        Ok(())
                    })
            })?;

            for (i, shard) in restored_data {
                shards[i] = Some(shard);
            }
        }

        let missing_parity_indices: Vec<_> = (self.data_shards..self.total_shard_count())
            .filter(|&i| shards[i].is_none())
            .collect();
        if !missing_parity_indices.is_empty() {
            let data_slices: Vec<&[u8]> = shards
                .iter()
                .take(self.data_shards)
                .map(|shard| {
                    shard
                        .as_ref()
                        .map(|s| &s[..])
                        .ok_or(ConsensusError::InvalidPayload)
                })
                .collect::<ConsensusResult<_>>()?;
            let mut restored_parity: Vec<(usize, Box<[u8]>)> = missing_parity_indices
                .iter()
                .map(|&i| (i, vec![0u8; shard_len].into_boxed_slice()))
                .collect();
            let parity_ptrs: Vec<(usize, usize)> = restored_parity
                .iter_mut()
                .map(|(i, shard)| (*i - self.data_shards, shard.as_mut_ptr() as usize))
                .collect();

            rs_block_pool(rs_block_threads).install(|| {
                (0..num_blocks)
                    .into_par_iter()
                    .try_for_each(|block_idx| -> ConsensusResult<()> {
                        let offset = block_idx * block_size;
                        let block_len = block_len(shard_len, block_size, block_idx)?;
                        let mut encoder = ReedSolomonEncoder::new(
                            self.data_shards,
                            self.parity_shards,
                            block_len,
                        )
                        .map_err(|_| ConsensusError::InvalidPayload)?;
                        for shard in &data_slices {
                            encoder
                                .add_original_shard(&shard[offset..offset + block_len])
                                .map_err(|_| ConsensusError::InvalidPayload)?;
                        }
                        let result = encoder
                            .encode()
                            .map_err(|_| ConsensusError::InvalidPayload)?;
                        for (i, recovery) in result.recovery_iter().enumerate() {
                            if let Some((_, ptr)) =
                                parity_ptrs.iter().find(|(parity_idx, _)| *parity_idx == i)
                            {
                                let parity_ptr = *ptr as *mut u8;
                                unsafe {
                                    parity_ptr
                                        .add(offset)
                                        .copy_from_nonoverlapping(recovery.as_ptr(), block_len);
                                }
                            }
                        }
                        Ok(())
                    })
            })?;

            for (i, shard) in restored_parity {
                shards[i] = Some(shard);
            }
        }
        Ok(())
    }
}
