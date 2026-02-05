use crate::error::{DagError, DagResult};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder, encode as rs_encode};
use std::cell::RefCell;
use std::sync::Mutex;
use std::time::Instant;
use log::debug;

// Thread-local cache to avoid global Mutex contention. Each thread keeps its own
// optional (encoder, decoder, shard_len) so reconstruct_shards can be lock-free.
thread_local! {
    static SIMD_CACHE_TLS: RefCell<Option<(ReedSolomonEncoder, ReedSolomonDecoder, usize)>> = RefCell::new(None);
}

/// A wrapper for `ReedSolomon` that doesn't panic if there are no parity shards.
pub enum Coding {
    /// A `ReedSolomon` instance with at least one parity shard.
    ReedSolomon {
        data_shards: usize,
        parity_shards: usize,
        simd_cache: Mutex<Option<(ReedSolomonEncoder, ReedSolomonDecoder, usize)>>,
    },
    /// A no-op replacement that doesn't encode or decode anything.
    Trivial(usize),
}

impl Coding {
    /// Creates a new `Coding` instance with the given number of shards.
    pub fn new(data_shard_num: usize, parity_shard_num: usize) -> DagResult<Self> {
        if parity_shard_num > 0 {
            Ok(Coding::ReedSolomon { data_shards: data_shard_num, parity_shards: parity_shard_num, simd_cache: Mutex::new(None) })
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
    pub fn encode(&self, slices: &mut [&mut [u8]]) -> DagResult<()> {
        match *self {
            Coding::ReedSolomon { data_shards, parity_shards, .. } => {
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

                // Try to reuse a thread-local encoder/decoder to avoid repeated
                // initialization. Keep decoder too so we can put a full pair back.
                let mut maybe: Option<(ReedSolomonEncoder, ReedSolomonDecoder, usize)> = None;
                SIMD_CACHE_TLS.with(|cell| {
                    maybe = cell.borrow_mut().take();
                });

                let (mut encoder, mut decoder) = if let Some((e, d, len)) = maybe {
                    if len == shard_size {
                        (e, d)
                    } else {
                        // Put back the mismatched cached pair and create new ones.
                        SIMD_CACHE_TLS.with(|cell| {
                            *cell.borrow_mut() = Some((e, d, len));
                        });
                        (
                            ReedSolomonEncoder::new(data_shards, parity_shards, shard_size).map_err(|_| DagError::ProofConstructionFailed)?,
                            ReedSolomonDecoder::new(data_shards, parity_shards, shard_size).map_err(|_| DagError::ProofConstructionFailed)?,
                        )
                    }
                } else {
                    (
                        ReedSolomonEncoder::new(data_shards, parity_shards, shard_size).map_err(|_| DagError::ProofConstructionFailed)?,
                        ReedSolomonDecoder::new(data_shards, parity_shards, shard_size).map_err(|_| DagError::ProofConstructionFailed)?,
                    )
                };

                // Reset encoder state for these shard params (safe for both new and reused).
                encoder.reset(data_shards, parity_shards, shard_size).map_err(|_| DagError::ProofConstructionFailed)?;

                // Feed original data shards into encoder.
                for i in 0..data_shards {
                    encoder.add_original_shard(&slices[i][..]).map_err(|_| DagError::ProofConstructionFailed)?;
                }

                // Encode parity shards and write them into provided parity slices.
                let enc_result = encoder.encode().map_err(|_| DagError::ProofConstructionFailed)?;
                for (ridx, recovery) in enc_result.recovery_iter().enumerate() {
                    let abs_idx = data_shards + ridx;
                    slices[abs_idx].copy_from_slice(recovery);
                }
                drop(enc_result);

                // Put encoder/decoder back into thread-local cache.
                SIMD_CACHE_TLS.with(|cell| {
                    *cell.borrow_mut() = Some((encoder, decoder, shard_size));
                });

                Ok(())
            }
            Coding::Trivial(_) => Ok(()),
        }
    }

    /// If enough shards are present, reconstructs the missing ones.
    pub fn reconstruct_shards(&self, shards: &mut [Option<Box<[u8]>>]) -> DagResult<()> {
    match *self {
        Coding::ReedSolomon { data_shards, parity_shards, .. } => {
            let t_start = Instant::now();
            let total_shards = data_shards + parity_shards;

            let shard_size = shards.iter()
                .find_map(|s| s.as_ref().map(|b| b.len()))
                .ok_or(DagError::ProofConstructionFailed)?;

            let missing_data_indices: Vec<usize> = shards.iter().enumerate()
                .take(data_shards)
                .filter(|(_, s)| s.is_none())
                .map(|(i, _)| i).collect();
            
            let missing_parity_indices: Vec<usize> = shards.iter().enumerate()
                .skip(data_shards)
                .filter(|(_, s)| s.is_none())
                .map(|(i, _)| i).collect();
            
            if missing_data_indices.is_empty() && missing_parity_indices.is_empty() {
                return Ok(());
            }

            let mut cached = None;
            SIMD_CACHE_TLS.with(|cell| cached = cell.borrow_mut().take());

            let (mut encoder, mut decoder) = match cached {
                Some((e, d, len)) if len == shard_size => (e, d),
                _ => (
                    ReedSolomonEncoder::new(data_shards, parity_shards, shard_size)
                        .map_err(|_| DagError::ProofConstructionFailed)?,
                    ReedSolomonDecoder::new(data_shards, parity_shards, shard_size)
                        .map_err(|_| DagError::ProofConstructionFailed)?,
                ),
            };

            if !missing_data_indices.is_empty() {
                let current_data_count = shards.iter().take(data_shards).filter(|s| s.is_some()).count();

                if current_data_count < data_shards {
                    let t_feed = Instant::now();
                    decoder.reset(data_shards, parity_shards, shard_size)
                        .map_err(|_| DagError::ProofConstructionFailed)?;

                    let mut fed_count = 0;
                    for i in 0..total_shards {
                        if let Some(ref b) = shards[i] {
                            if i < data_shards {
                                decoder.add_original_shard(i, b).map_err(|_| DagError::ProofConstructionFailed)?;
                            } else {
                                decoder.add_recovery_shard(i - data_shards, b).map_err(|_| DagError::ProofConstructionFailed)?;
                            }
                            fed_count += 1;
                            if fed_count >= data_shards { break; }
                        }
                    }

                    let t_decode = Instant::now();
                    let decode_result = decoder.decode().map_err(|_| DagError::ProofConstructionFailed)?;
                    
                    for (idx, restored) in decode_result.restored_original_iter() {
                        if shards[idx].is_none() {
                            let mut buf = Vec::with_capacity(shard_size);
                            unsafe { buf.set_len(shard_size); }
                            buf.copy_from_slice(restored);
                            shards[idx] = Some(buf.into_boxed_slice());
                        }
                    }
                    debug!("reconstruct: decode math took: {:?}", t_decode.elapsed());
                } else {
                    debug!("reconstruct: Data shards already complete, skipping decoder.");
                }
            }

            if !missing_parity_indices.is_empty() {
                let t_p_feed = Instant::now();
                encoder.reset(data_shards, parity_shards, shard_size)
                    .map_err(|_| DagError::ProofConstructionFailed)?;

                for i in 0..data_shards {
                    let s = shards[i].as_ref().ok_or(DagError::ProofConstructionFailed)?;
                    encoder.add_original_shard(s).map_err(|_| DagError::ProofConstructionFailed)?;
                }

                let enc_result = encoder.encode().map_err(|_| DagError::ProofConstructionFailed)?;
                for (ridx, recovery) in enc_result.recovery_iter().enumerate() {
                    let abs_idx = data_shards + ridx;
                    if shards[abs_idx].is_none() {
                        let mut buf = Vec::with_capacity(shard_size);
                        unsafe { buf.set_len(shard_size); }
                        buf.copy_from_slice(recovery);
                        shards[abs_idx] = Some(buf.into_boxed_slice());
                    }
                }
                debug!("reconstruct: parity compute took {:?}", t_p_feed.elapsed());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
fn bench_rs_decode_real() {
    let data_shards = 18;
    let parity_shards = 32;
    let shard_size = 2888896;

    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut shards = vec![vec![0u8; shard_size]; data_shards + parity_shards];
    for s in shards.iter_mut() {
        rng.fill_bytes(s);
    }

    let mut decoder = ReedSolomonDecoder::new(data_shards, parity_shards, shard_size).unwrap();

    for i in 5..23 {
        if i < data_shards {
            decoder.add_original_shard(i, &shards[i]).unwrap();
        } else {
            decoder.add_recovery_shard(i - data_shards, &shards[i]).unwrap();
        }
    }

    let start = Instant::now();
    let _result = decoder.decode().expect("Decode failed");
    let duration = start.elapsed();

    println!("======================================");
    println!("Real RS Decode Time (Worst Case): {:?}", duration);
    println!("======================================");
}
}