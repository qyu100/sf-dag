use blake3;
use crypto::Digest;
use serde::{Deserialize, Serialize};

// Use rs_merkle types internally but expose the original API to the rest of the codebase.
use rs_merkle::{Hasher as RsHasher, MerkleProof as RsMerkleProof, MerkleTree as RsMerkleTree};

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
    root_hash: Digest,
    leaf_count: usize,
}

impl MerkleTree {
    /// Build from precomputed leaf digests (no owned values).
    pub fn from_hashes(hashes: Vec<Digest>) -> Self {
        // Convert our Digest -> rs_merkle leaf hashes (Vec<[u8;32]>) and build upper levels.
        let leaf_hashes: Vec<[u8; 32]> = hashes.into_iter().map(|d| d.0).collect();
        let inner = RsMerkleTree::<Blake3Hasher>::from_leaves(&leaf_hashes);
        let root_ref = inner.root().expect("merkle has a root");
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(root_ref.as_ref());
        let root_hash = Digest(root_arr);
        MerkleTree {
            inner,
            root_hash,
            leaf_count: leaf_hashes.len(),
        }
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub fn proof_with_leaf(&self, index: usize, leaf: &[u8]) -> Option<Proof> {
        if index >= self.leaf_count() {
            return None;
        }
        let proof: RsMerkleProof<Blake3Hasher> = self.inner.proof(&[index]);
        let mut digests: Vec<Digest> = Vec::new();
        for h in proof.proof_hashes().iter() {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(h.as_ref());
            digests.push(Digest(arr));
        }

        let value_hash = MerkleTree::digest(leaf);
        let value_box = leaf.to_vec().into_boxed_slice();

        Some(Proof {
            value: value_box,
            index,
            digests,
            root_hash: self.root_hash,
            value_hash,
        })
    }

    pub fn root_hash(&self) -> &Digest {
        &self.root_hash
    }

    pub fn digest(value: &[u8]) -> Digest {
        let out = blake3::hash(value);
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

    pub fn index(&self) -> usize {
        self.index
    }
    pub fn root_hash(&self) -> &Digest {
        &self.root_hash
    }
    pub fn value(&self) -> &Box<[u8]> {
        &self.value
    }
    pub fn into_value(self) -> Box<[u8]> {
        self.value
    }
}
