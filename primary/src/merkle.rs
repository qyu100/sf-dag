use std::time::Instant;
use serde::{Deserialize, Serialize};
use log::debug;
use rayon::prelude::*;
use blake3;
use crypto::Digest;
use crate::batch_maker::Transaction;

// Use rs_merkle types internally but expose the original API to the rest of the codebase.
use rs_merkle::{MerkleTree as RsMerkleTree, MerkleProof as RsMerkleProof, Hasher as RsHasher};

// A small wrapper hasher implementing rs_merkle::Hasher using blake3.
#[derive(Clone, Copy, Default)]
pub struct Blake3Hasher;

impl RsHasher for Blake3Hasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let h = blake3::hash(data);
        let bytes = h.as_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        arr
    }
}

/// Compatibility MerkleTree that preserves the existing API but uses rs_merkle+blake3 internally.
pub struct MerkleTree {
    inner: RsMerkleTree<Blake3Hasher>,
    values: Vec<Transaction>,
    root_hash: Digest,
    leaf_count: usize,
}

impl MerkleTree {
    /// Build from owned values. We hash leaves in parallel for performance, then construct an rs_merkle tree.
    pub fn from_vec(values: Vec<Transaction>) -> Self {
        let t_start = Instant::now();
        
        let leaf_hashes: Vec<[u8; 32]> = values
            .par_iter()
            .map(|v| *blake3::hash(v.as_ref()).as_bytes()) 
            .collect();

        debug!("merkle.from_vec: hashed {} leaves in {:?}", leaf_hashes.len(), t_start.elapsed());

        let inner = RsMerkleTree::<Blake3Hasher>::from_leaves(&leaf_hashes);
        
        let root_hash = inner.root()
            .map(|r| Digest(r))
            .expect("merkle has a root");

        MerkleTree { 
            inner, 
            values, 
            root_hash, 
            leaf_count: leaf_hashes.len() 
        }
    }

    /// Build from precomputed leaf digests (no owned values).
    pub fn from_hashes(hashes: Vec<Digest>) -> Self {
        // Convert our Digest -> rs_merkle leaf hashes (Vec<[u8;32]>) and build upper levels.
        let leaf_hashes: Vec<[u8; 32]> = hashes.into_iter().map(|d| d.0).collect();
        let inner = RsMerkleTree::<Blake3Hasher>::from_leaves(&leaf_hashes);
        let root_ref = inner.root().expect("merkle has a root");
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(root_ref.as_ref());
        let root_hash = Digest(root_arr);
        MerkleTree { inner, values: Vec::new(), root_hash, leaf_count: leaf_hashes.len() }
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Returns a Proof for the specified index (keeps existing Proof API but built from rs_merkle proof).
    pub fn proof(&self, index: usize) -> Option<Proof> {
        // Ensure index valid
        if index >= self.leaf_count() {
            return None;
        }
        // Use rs_merkle to build proof for single index
        let proof: RsMerkleProof<Blake3Hasher> = self.inner.proof(&[index]);
        // Extract sibling hashes from rs_merkle proof into Vec<Digest>
        let mut digests: Vec<Digest> = Vec::new();
        for h in proof.proof_hashes().iter() {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(h.as_ref());
            digests.push(Digest(arr));
        }
        // value must come from our owned values if present
        let vec = self.values.get(index).cloned()?;
        let value_hash = MerkleTree::digest(&vec);
        let value_box = vec.into_boxed_slice();
        Some(Proof { value: value_box, index, digests, root_hash: self.root_hash, value_hash })
    }

    pub fn proof_with_leaf(&self, index: usize, leaf: Transaction) -> Option<Proof> {
        if index >= self.leaf_count() {
            return None;
        }
        // start total timing
        let t_start = Instant::now();
        // Step 1: obtain rs_merkle proof
        let proof_start = Instant::now();
        let proof: RsMerkleProof<Blake3Hasher> = self.inner.proof(&[index]);
        let t_after_proof = Instant::now();

        // Step 2: extract sibling hashes from rs_merkle proof into Vec<Digest>
        let digests_start = Instant::now();
        let mut digests: Vec<Digest> = Vec::new();
        for h in proof.proof_hashes().iter() {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(h.as_ref());
            digests.push(Digest(arr));
        }
        let t_after_digests = Instant::now();

        // Step 3: compute value hash (blake3)
        let hash_start = Instant::now();
        let value_hash = MerkleTree::digest(&leaf);
        let t_after_hash = Instant::now();

        // Step 4: convert leaf into boxed slice (this moves leaf)
        let box_start = Instant::now();
        let value_box = leaf.into_boxed_slice();
        let t_after_box = Instant::now();

        // log per-step timings
        debug!(
            "merkle.proof_with_leaf: index={} leaf_len={} timings: total={:?} proof={:?} digests={:?} hash={:?} box={:?}",
            index,
            value_box.len(),
            t_after_box.duration_since(t_start),
            t_after_proof.duration_since(proof_start),
            t_after_digests.duration_since(digests_start),
            t_after_hash.duration_since(hash_start),
            t_after_box.duration_since(box_start),
        );

        Some(Proof { value: value_box, index, digests, root_hash: self.root_hash, value_hash })
    }

    pub fn root_hash(&self) -> &Digest {
        &self.root_hash
    }

    pub fn values(&self) -> &Vec<Transaction> {
        &self.values
    }

    pub fn into_values(self) -> Vec<Transaction> {
        self.values
    }

    pub fn digest(value: &Transaction) -> Digest {
        let out = blake3::hash(value.as_ref());
        let bytes = out.as_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Digest(arr)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Proof {
    value: Box<[u8]>,
    index: usize,
    digests: Vec<Digest>,
    root_hash: Digest,
    value_hash: Digest,
}

impl Proof {
    pub fn validate(&self, n: usize) -> bool {
        let proof_hashes: Vec<[u8; 32]> = self.digests.iter().map(|d| d.0).collect();
        let proof = RsMerkleProof::<Blake3Hasher>::new(proof_hashes);
        proof.verify(self.root_hash.0, &[self.index], &[self.value_hash.0], n)
    }

    pub fn index(&self) -> usize { self.index }
    pub fn root_hash(&self) -> &Digest { &self.root_hash }
    pub fn value(&self) -> &Box<[u8]> { &self.value }
    pub fn into_value(self) -> Box<[u8]> { self.value }
}

fn hash_pair(a: &Digest, b: &Digest) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(a.as_ref());
    hasher.update(b.as_ref());
    let mut arr = [0u8; 32];
    arr.copy_from_slice(hasher.finalize().as_bytes());
    Digest(arr)
}