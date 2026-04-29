use crypto::Digest;
use rs_merkle::{Hasher as RsHasher, MerkleProof as RsMerkleProof, MerkleTree as RsMerkleTree};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Default)]
pub struct Blake3Hasher;

impl RsHasher for Blake3Hasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let h = blake3::hash(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.as_bytes());
        out
    }
}

pub struct MerkleTree {
    inner: RsMerkleTree<Blake3Hasher>,
    root_hash: Digest,
    leaf_count: usize,
}

impl MerkleTree {
    pub fn from_hashes(hashes: Vec<Digest>) -> Self {
        let leaf_hashes: Vec<[u8; 32]> = hashes.into_iter().map(|d| d.0).collect();
        let inner = RsMerkleTree::<Blake3Hasher>::from_leaves(&leaf_hashes);
        let root_hash = Digest(inner.root().expect("merkle tree has a root"));
        Self {
            inner,
            root_hash,
            leaf_count: leaf_hashes.len(),
        }
    }

    pub fn proof_with_leaf(&self, index: usize, leaf: &[u8]) -> Option<Proof> {
        if index >= self.leaf_count {
            return None;
        }
        let proof = self.inner.proof(&[index]);
        let digests = proof.proof_hashes().iter().map(|h| Digest(*h)).collect();
        Some(Proof {
            value: leaf.to_vec().into_boxed_slice(),
            index,
            digests,
            root_hash: self.root_hash.clone(),
            value_hash: Self::digest(leaf),
        })
    }

    pub fn root_hash(&self) -> &Digest {
        &self.root_hash
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub fn digest(value: &[u8]) -> Digest {
        let h = blake3::hash(value);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.as_bytes());
        Digest(out)
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

impl Default for Proof {
    fn default() -> Self {
        Self {
            value: Vec::new().into_boxed_slice(),
            index: 0,
            digests: Vec::new(),
            root_hash: Digest::default(),
            value_hash: Digest::default(),
        }
    }
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
