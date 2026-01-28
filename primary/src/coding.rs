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

                // Collect original shards as &[u8]
                let originals: Vec<&[u8]> = (0..data_shards).map(|i| &slices[i][..]).collect();

                // Use top-level convenience encode()
                let recovery = rs_encode(data_shards, parity_shards, &originals)
                    .map_err(|_| DagError::ProofConstructionFailed)?;

                for (ridx, rec) in recovery.iter().enumerate() {
                    let abs_idx = data_shards + ridx;
                    slices[abs_idx].copy_from_slice(&rec[..]);
                }

                Ok(())
            }
            Coding::Trivial(_) => Ok(()),
        }
    }

    /// If enough shards are present, reconstructs the missing ones.
    pub fn reconstruct_shards(&self, shards: &mut [Option<Box<[u8]>>]) -> DagResult<()> {
        match *self {
            Coding::ReedSolomon { data_shards, parity_shards, ref simd_cache } => {
                let t_start = Instant::now();
                let total_shards = data_shards + parity_shards;

                // 1. Get shard size from any present shard
                let shard_size = shards.iter().find_map(|s| s.as_ref().map(|b| b.len())).ok_or(DagError::ProofConstructionFailed)?;

                // Log how many shards are missing before reconstruction
                let missing = shards.iter().filter(|s| s.is_none()).count();
                debug!("reconstruct_shards: missing shards={} total_shards={} shard_size={}", missing, total_shards, shard_size);

                // Determine whether original (data) shards or parity shards are missing
                let missing_data = shards.iter().take(data_shards).any(|s| s.is_none());
                let missing_parity = shards.iter().skip(data_shards).any(|s| s.is_none());
                debug!("reconstruct_shards: missing_data={} missing_parity={}", missing_data, missing_parity);

                // If nothing is missing, nothing to do
                if !missing_data && !missing_parity {
                    debug!("reconstruct_shards: nothing missing, returning");
                    return Ok(());
                }

                // 2. Try to take encoder/decoder from cache if matches shard_size
                // Use thread-local cache: fast, no global Mutex contention.
                let mut maybe: Option<(ReedSolomonEncoder, ReedSolomonDecoder, usize)> = None;
                SIMD_CACHE_TLS.with(|cell| {
                    maybe = cell.borrow_mut().take();
                });

                let (mut encoder, mut decoder) = if let Some((e, d, len)) = maybe {
                    if len == shard_size {
                        (e, d)
                    } else {
                        // put it back into TLS and create new instances
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

                // 3/4. If data shards are missing, feed decoder and decode
                if missing_data {
                    let t_feed_start = Instant::now();
                    for i in 0..total_shards {
                        if let Some(ref b) = shards[i] {
                            if i < data_shards {
                                decoder.add_original_shard(i, &b[..]).map_err(|_| DagError::ProofConstructionFailed)?;
                            } else {
                                decoder.add_recovery_shard(i - data_shards, &b[..]).map_err(|_| DagError::ProofConstructionFailed)?;
                            }
                        }
                    }
                    debug!("reconstruct_shards: decoder feed elapsed={:?}", t_feed_start.elapsed());

                    // Decode
                    let t_decode_start = Instant::now();
                    let decode_result = decoder.decode().map_err(|_| DagError::ProofConstructionFailed)?;
                    let restored_count = decode_result.restored_original_iter().count();
                    debug!("reconstruct_shards: actually restored {} shards", restored_count);
                    debug!("reconstruct_shards: decode elapsed={:?}", t_decode_start.elapsed());
                    let t_alloc_start = Instant::now();
                    for (idx, restored) in decode_result.restored_original_iter() {
                        let mut buf = vec![0u8; shard_size].into_boxed_slice();
                        buf.copy_from_slice(restored);
                        shards[idx] = Some(buf);
                    }
                    debug!("reconstruct_shards: alloc/copy restored elapsed={:?}", t_alloc_start.elapsed());
                    drop(decode_result);
                } else {
                    debug!("reconstruct_shards: no missing data shards, skipping decoder/decode");
                }

                // 5. Recompute parity shards only if parity shards were missing
                if missing_parity {
                    let t_parity_feed = Instant::now();
                    for i in 0..data_shards {
                        let s = shards[i].as_ref().ok_or(DagError::ProofConstructionFailed)?;
                        encoder.add_original_shard(&s[..]).map_err(|_| DagError::ProofConstructionFailed)?;
                    }
                    debug!("reconstruct_shards: encoder feed elapsed={:?}", t_parity_feed.elapsed());
                    let t_parity_encode = Instant::now();
                    let enc_result = encoder.encode().map_err(|_| DagError::ProofConstructionFailed)?;
                    debug!("reconstruct_shards: parity encode elapsed={:?}", t_parity_encode.elapsed());
                    let t_parity_alloc = Instant::now();
                    for (ridx, recovery) in enc_result.recovery_iter().enumerate() {
                        let abs_idx = data_shards + ridx;
                        if shards[abs_idx].is_none() {
                            let mut buf = vec![0u8; shard_size].into_boxed_slice();
                            buf.copy_from_slice(recovery);
                            shards[abs_idx] = Some(buf);
                        }
                    }
                    debug!("reconstruct_shards: parity alloc/copy elapsed={:?}", t_parity_alloc.elapsed());
                    drop(enc_result);
                } else {
                    debug!("reconstruct_shards: no missing parity shards, skipping encoder/encode");
                }

                // 6. Put encoder/decoder back into thread-local cache
                let t_putback_start = Instant::now();
                SIMD_CACHE_TLS.with(|cell| {
                    *cell.borrow_mut() = Some((encoder, decoder, shard_size));
                });
                debug!("reconstruct_shards: tls cache putback elapsed={:?}", t_putback_start.elapsed());

                debug!("reconstruct_shards: done total elapsed={:?}", t_start.elapsed());
                Ok(())
              }
              _ => Ok(()),
          }
      }
 }

 #[cfg(test)]
 mod tests {
     use super::*;

     // Simple deterministic PRNG to avoid adding external dev-deps.
     fn pseudo_random(len: usize) -> Vec<u8> {
         let mut x: u32 = 0x1234_5678;
         let mut v = Vec::with_capacity(len);
         for _ in 0..len {
             x = x.wrapping_mul(1664525).wrapping_add(1013904223);
             v.push((x >> 24) as u8);
         }
         v
     }

     #[test]
     fn test_encode_reconstruct_roundtrip() {
         // parameters
         let data_shards = 3usize;
         let parity_shards = 2usize;
         let coding = Coding::new(data_shards, parity_shards).expect("Failed to create coding");

         // payload
         let payload_len = 1000usize;
         let payload = pseudo_random(payload_len);

         // shard sizing and padding
         let shard_len = (payload_len + data_shards - 1) / data_shards;
         let total_shards = data_shards + parity_shards;
         let mut bytes = payload.clone();
         bytes.resize(shard_len * total_shards, 0u8);

         // split into shards
         let mut shards: Vec<Vec<u8>> = bytes.chunks(shard_len).map(|c| c.to_vec()).collect();
         assert_eq!(shards.len(), total_shards);

         // encode parity into parity shards
         {
             let mut slices: Vec<&mut [u8]> = shards.iter_mut().map(|s| s.as_mut_slice()).collect();
             coding.encode(&mut slices[..]).expect("encode failed");
         }

         // keep a copy of original shards (including parity)
         let original_shards = shards.clone();

         // simulate lost shards (within parity tolerance)
         let mut shard_opts: Vec<Option<Box<[u8]>>> = shards.into_iter().map(|s| Some(s.into_boxed_slice())).collect();
         // drop one data shard and one parity shard (indices chosen deterministically)
         shard_opts[1] = None;
         shard_opts[4] = None;

         // reconstruct
         coding.reconstruct_shards(&mut shard_opts[..]).expect("reconstruct failed");

         // collect recovered shards
         let recovered_shards: Vec<Vec<u8>> = shard_opts.iter().map(|opt| opt.as_ref().unwrap().to_vec()).collect();
         assert_eq!(recovered_shards.len(), total_shards);

         // reassemble payload from data shards and truncate
         let mut recovered_bytes: Vec<u8> = recovered_shards
             .iter()
             .take(data_shards)
             .flat_map(|s| s.iter().cloned())
             .collect();
         recovered_bytes.truncate(payload_len);

         assert_eq!(recovered_bytes, payload, "Reconstructed payload differs from original");

         // also check parity shards match original parity
         let original_parity: Vec<Vec<u8>> = original_shards.iter().skip(data_shards).cloned().collect();
         let recovered_parity: Vec<Vec<u8>> = recovered_shards.iter().skip(data_shards).cloned().collect();
         assert_eq!(recovered_parity, original_parity, "Recovered parity shards differ from original parity");
     }
 }