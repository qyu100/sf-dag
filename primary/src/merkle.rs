use std::mem;
use std::time::Instant;

use log::debug;
use rayon::prelude::*; // parallel iterator for hashing leaves
use serde::{Deserialize, Serialize};
use blake3;
use crypto::{Digest};

use crate::batch_maker::Transaction;
// pub type Digest = [u8; 32];

/// A Merkle tree: The leaves are values and their hashes. Each level consists of the hashes of
/// pairs of values on the previous level. The root is the value in the first level with only one
/// entry.
#[derive(Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<Digest>>,
    values: Vec<Transaction>,
    root_hash: Digest,
}

impl MerkleTree {
    /// Creates a new Merkle tree with the given values.
    pub fn from_vec(values: Vec<Transaction>) -> Self {
        let start = Instant::now();
        let t_hash = Instant::now();
        let mut levels = Vec::new();
        // Parallelize hashing of leaf values to utilize multiple cores.
        let mut cur_lvl: Vec<Digest> = values.par_iter().map(hash).collect();
        debug!("merkle.from_vec: hashed {} leaf values in {:?}", values.len(), t_hash.elapsed());

        // Time building of upper levels; log each iteration
        while cur_lvl.len() > 1 {
            let level_before = cur_lvl.len();
            let t_level = Instant::now();
            let next_lvl: Vec<Digest> = cur_lvl.chunks(2).map(hash_chunk).collect();
            levels.push(mem::replace(&mut cur_lvl, next_lvl));
            debug!(
                "merkle.from_vec: built level {} ({} -> {}) in {:?}",
                levels.len(),
                level_before,
                cur_lvl.len(),
                t_level.elapsed()
            );
        }
        let root_hash = cur_lvl[0];
        debug!("merkle.from_vec: total time {:?}", start.elapsed());
        MerkleTree {
            levels,
            values,
            root_hash,
        }
    }

    /// Create a Merkle tree from precomputed leaf digests (no owned values).
    pub fn from_hashes(mut hashes: Vec<Digest>) -> Self {
        let mut levels = Vec::new();

        // Build upper levels from the provided leaf hashes.
        while hashes.len() > 1 {
            let level_before = hashes.len();
            let next_lvl: Vec<Digest> = hashes.chunks(2).map(hash_chunk).collect();
            levels.push(mem::replace(&mut hashes, next_lvl));
        }
        let root_hash = hashes[0];
        MerkleTree { levels, values: Vec::new(), root_hash }
    }

    /// Returns the number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        if !self.levels.is_empty() {
            self.levels[0].len()
        } else {
            self.values.len()
        }
    }

    /// Returns the proof for entry `index`, if that is a valid index.
    pub fn proof(&self, index: usize) -> Option<Proof> {
        let value = self.values.get(index)?.clone();
        let mut lvl_i = index;
        let mut digests = Vec::new();
        for level in &self.levels {
            // Insert the sibling hash if there is one.
            if let Some(digest) = level.get(lvl_i ^ 1) {
                digests.push(*digest);
            }
            lvl_i /= 2;
        }
        // Determine cached leaf hash: if levels has the bottom (levels[0]) use it,
        // otherwise compute it.
        let value_hash = if !self.levels.is_empty() {
            self.levels[0][index]
        } else {
            hash(&value)
        };
        // Store the leaf as boxed slice to allow cheap moves later.
        Some(Proof {
            index,
            digests,
            value: value.into_boxed_slice(),
            root_hash: self.root_hash,
            value_hash,
        })
    }

    /// Produce a proof for `index` using the provided `leaf` as the value. This avoids
    /// requiring the tree to own the value. Returns None if index invalid.
    pub fn proof_with_leaf(&self, index: usize, leaf: Transaction) -> Option<Proof> {
        // Build digests exactly as in `proof` but set value from provided `leaf` and cache its hash.
        let mut lvl_i = index;
        let mut digests = Vec::new();
        for level in &self.levels {
            if let Some(digest) = level.get(lvl_i ^ 1) {
                digests.push(*digest);
            }
            lvl_i /= 2;
        }
        let value_hash = hash(&leaf);
        Some(Proof { index, digests, value: leaf.into_boxed_slice(), root_hash: self.root_hash, value_hash })
    }

    /// Returns the root hash of the tree.
    pub fn root_hash(&self) -> &Digest {
        &self.root_hash
    }

    /// Returns a the slice containing all leaf values.
    pub fn values(&self) -> &Vec<Transaction> {
        &self.values
    }

    /// Consumes the tree, and returns the vector of leaf values.
    pub fn into_values(self) -> Vec<Transaction> {
        self.values
    }

    /// Public helper to compute the digest of a value.
    pub fn digest(value: &Transaction) -> Digest {
        hash(value)
    }
}

/// A proof that a value is at a particular index in the Merkle tree specified by its root hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Proof {
    // Store the leaf as a boxed slice to make moves cheap and clones explicit.
    value: Box<[u8]>,
    index: usize,
    digests: Vec<Digest>,
    root_hash: Digest,
    /// Cached hash of `value` so validate() doesn't re-hash the value repeatedly.
    value_hash: Digest,
}

impl Proof {
    /// Returns `true` if the digests in this proof constitute a valid branch in a Merkle tree with
    /// the root hash.
    pub fn validate(&self, n: usize) -> bool {
        let mut digest = self.value_hash;
        let mut lvl_i = self.index;
        let mut lvl_n = n;
        let mut digest_itr = self.digests.iter();
        while lvl_n > 1 {
            if lvl_i ^ 1 < lvl_n {
                digest = match digest_itr.next() {
                    None => return false, // Not enough levels in the proof.
                    Some(sibling) if lvl_i & 1 == 1 => hash_pair(&sibling, &digest),
                    Some(sibling) => hash_pair(&digest, &sibling),
                };
            }
            lvl_i /= 2; // Our index on the next level.
            lvl_n = (lvl_n + 1) / 2; // The next level's size.
        }
        if digest_itr.next().is_some() {
            return false; // Too many levels in the proof.
        }
        let result = digest == self.root_hash;
        result
    }

    /// Returns the index of this proof's value in the tree.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the tree's root hash.
    pub fn root_hash(&self) -> &Digest {
        &self.root_hash
    }

    /// Returns the leaf value.
    pub fn value(&self) -> &Box<[u8]> {
        &self.value
    }

    /// Consumes the proof and returns the leaf value.
    pub fn into_value(self) -> Box<[u8]> {
        self.value
    }
}

/// Takes a chunk of one or two digests. In the former case, returns the digest itself, in the
/// latter, it returns the hash of the two digests.
fn hash_chunk(chunk: &[Digest]) -> Digest {
    if chunk.len() == 1 {
        chunk[0]
    } else {
        hash_pair(&chunk[0], &chunk[1])
    }
}


#[inline]
pub fn hash_pair<T0, T1>(v0: &T0, v1: &T1) -> Digest 
where 
    T0: AsRef<[u8]>, 
    T1: AsRef<[u8]> 
{
    let mut hasher = blake3::Hasher::new();
    hasher.update(v0.as_ref());
    hasher.update(v1.as_ref());
    crypto::Digest(*hasher.finalize().as_bytes())
}

fn hash<T: AsRef<[u8]>>(value: &T) -> Digest {
    let out = blake3::hash(value.as_ref());
    crypto::Digest(*out.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::MerkleTree;

    #[test]
    fn test_merkle() {
        for &n in &[4, 7, 8, 9, 17] {
            let tree = MerkleTree::from_vec((0..n).map(|i| vec![i as u8]).collect());
            for i in 0..n {
                let proof = tree.proof(i).expect("couldn't get proof");
                assert!(proof.validate(n));
            }
            assert!(tree.proof(n).is_none());
        }
    }
}
