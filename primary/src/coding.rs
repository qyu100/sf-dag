use reed_solomon_erasure as rse;
use reed_solomon_erasure::{galois_8::Field as Field8, ReedSolomon};
use crate::error::{DagError, DagResult};

/// A wrapper for `ReedSolomon` that doesn't panic if there are no parity shards.
#[derive(Debug)]
pub enum Coding {
    /// A `ReedSolomon` instance with at least one parity shard.
    ReedSolomon(Box<ReedSolomon<Field8>>),
    /// A no-op replacement that doesn't encode or decode anything.
    Trivial(usize),
}

impl Coding {
    /// Creates a new `Coding` instance with the given number of shards.
    pub fn new(data_shard_num: usize, parity_shard_num: usize) -> DagResult<Self> {
        if parity_shard_num > 0 {
            let rs = ReedSolomon::new(data_shard_num, parity_shard_num)
                .map_err(|_| DagError::ProofConstructionFailed)?;
            Ok(Coding::ReedSolomon(Box::new(rs)))
        } else {
            Ok(Coding::Trivial(data_shard_num))
        }
    }

    /// Returns the number of data shards.
    pub fn data_shard_count(&self) -> usize {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.data_shard_count(),
            Coding::Trivial(dsc) => dsc,
        }
    }

    /// Returns the number of parity shards.
    pub fn parity_shard_count(&self) -> usize {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.parity_shard_count(),
            Coding::Trivial(_) => 0,
        }
    }

    /// Constructs (and overwrites) the parity shards.
    pub fn encode(&self, slices: &mut [&mut [u8]]) -> DagResult<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.encode(slices).map_err(|_| DagError::ProofConstructionFailed),
            Coding::Trivial(_) => Ok(()),
        }
    }

    /// If enough shards are present, reconstructs the missing ones.
    pub fn reconstruct_shards(&self, shards: &mut [Option<Box<[u8]>>]) -> DagResult<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.reconstruct(shards).map_err(|_| DagError::ProofConstructionFailed),
            Coding::Trivial(_) => {
                if shards.iter().all(Option::is_some) {
                    Ok(())
                } else {
                    Err(DagError::ProofConstructionFailed)
                }
            }
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