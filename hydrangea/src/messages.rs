use crate::consensus::Round;
use crate::error::{ConsensusError, ConsensusResult};
use crate::merkle::Proof;
use blsttc::SignatureShareG1;
use config::Committee;
use crypto::{BlsSignatureService, Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt;

// #[cfg(test)]
// #[path = "tests/messages_tests.rs"]
// pub mod messages_tests;

pub type Transaction = Vec<u8>;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Header {
    pub author: PublicKey,
    pub parent: Digest,
    pub payload: Vec<Transaction>,
    pub round: Round,
}

impl Header {
    pub fn new(author: PublicKey, parent: Digest, payload: Vec<Transaction>, round: Round) -> Self {
        Self {
            author,
            parent,
            payload,
            round,
        }
    }
}

pub fn payload_hash(payload: &[Transaction]) -> Digest {
    let mut hasher = Sha512::new();
    for tx in payload {
        hasher.update(tx);
    }
    Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub author: PublicKey,
    pub parent: Digest,
    pub payload_hash: Digest,
    pub payload_root: Digest,
    pub payload_len: usize,
    pub round: Round,
    pub signature: Signature,
}

impl Block {
    pub async fn new(
        author: PublicKey,
        parent: Digest,
        payload_hash: Digest,
        payload_root: Digest,
        payload_len: usize,
        round: Round,
        _signature_service: SignatureService,
    ) -> Self {
        let b = Block {
            author,
            parent,
            payload_hash,
            payload_root,
            payload_len,
            round,
            signature: Signature::default(),
        };
        b
    }

    pub fn genesis() -> Self {
        Self {
            author: PublicKey::default(),
            parent: Digest::default(),
            payload_hash: Digest::default(),
            payload_root: Digest::default(),
            payload_len: 0,
            round: 0,
            signature: Signature::default(),
        }
    }

    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ignore Genesis block.
        if self.digest() != Block::genesis().digest() {
            // Ensure the proposer has voting rights.
            let voting_rights = committee.stake(&self.author);
            ensure!(
                voting_rights > 0,
                ConsensusError::UnknownAuthority(self.author)
            );
        }
        Ok(())
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.parent.clone());
        hasher.update(&self.payload_hash);
        hasher.update(self.payload_len.to_le_bytes());
        hasher.update(self.round.to_le_bytes());

        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: CMB(author {}, parent {}, round {}, payload_len {})",
            self.digest(),
            self.author,
            self.parent,
            self.round,
            self.payload_len
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "CMB{}", self.round)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ShardRequest {
    pub block: Digest,
    pub payload_root: Digest,
    pub index: usize,
    pub origin: PublicKey,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ShardResponse {
    pub block: Digest,
    pub payload_root: Digest,
    pub proof: Proof,
}

pub fn shard_store_key(block: &Digest, payload_root: &Digest, index: usize) -> Vec<u8> {
    let mut key = b"hydrangea-shard-v1".to_vec();
    key.extend_from_slice(&block.0);
    key.extend_from_slice(&payload_root.0);
    key.extend_from_slice(&(index as u64).to_le_bytes());
    key
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NormalProposal {
    pub block: Block,
    pub proof: Proof,
}

impl NormalProposal {
    pub fn new(block: Block, proof: Proof) -> Self {
        Self { block, proof }
    }

    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        self.block.is_well_formed(committee)?;
        ensure!(
            *self.proof.root_hash() == self.block.payload_root
                && self.proof.validate(committee.size()),
            ConsensusError::InvalidProof
        );

        Ok(())
    }
}

impl Hash for NormalProposal {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.block.digest());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for NormalProposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "NormalProposal {}: Block {:?})",
            self.digest(),
            self.block
        )
    }
}

impl fmt::Display for NormalProposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "NormalProposal B{}", self.block.round)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum ProposalType {
    Fallback,
    Normal,
}

impl Hash for ProposalType {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        match self {
            Self::Fallback => hasher.update("Fallback"),
            Self::Normal => hasher.update("Normal"),
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Display for ProposalType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Self::Fallback => write!(f, "Fallback"),
            Self::Normal => write!(f, "Normal"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Default, Debug)]
pub enum VoteType {
    Commit,
    Decide,
    #[default]
    Normal,
}

impl Hash for VoteType {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        match self {
            Self::Commit => hasher.update("C"),
            Self::Decide => hasher.update("D"),
            Self::Normal => hasher.update("NV"),
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Display for VoteType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Self::Commit => write!(f, "C"),
            Self::Decide => write!(f, "D"),
            Self::Normal => write!(f, "NV"),
        }
    }
}

// TODO: Timeouts and Prepares should come with justification to prevent
// Byzantine nodes spamming messages for higher rounds.
#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub author: PublicKey,
    pub blk_hash: Digest,
    pub payload_root: Digest,
    pub kind: VoteType,
    pub round: Round,
    pub proof: Option<Proof>,
    pub signature: SignatureShareG1,
}

impl Vote {
    pub async fn new(
        author: PublicKey,
        blk_hash: Digest,
        payload_root: Digest,
        kind: VoteType,
        round: Round,
        proof: Option<Proof>,
        _bls_signature_service: &mut BlsSignatureService,
    ) -> Self {
        let vote = Self {
            author,
            blk_hash: blk_hash.clone(),
            payload_root,
            kind,
            round,
            proof,
            signature: SignatureShareG1::default(),
        };
        // Bracha RBC uses authenticated channels but no vote signatures.
        vote
    }

    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // let author_bls_key_g1 = committee.get_bls_public_g1(&self.author);
        // // Check the signature.
        // self.signature
        //     .verify_batch(&self.digest().0, &author_bls_key_g1)
        //     .map_err(ConsensusError::from)
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.blk_hash);
        hasher.update(&self.payload_root);
        hasher.update(self.kind.digest());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "V({}, {}, {}, {})",
            self.kind, self.author, self.round, self.blk_hash
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct QC {
    pub blk_hash: Digest,
    pub payload_root: Digest,
    pub kind: VoteType,
    pub round: Round,
    pub block: Option<Block>,
    pub availability_shards: Vec<Option<Box<[u8]>>>,
    pub votes: (Vec<u128>, SignatureShareG1),
}

impl QC {
    pub fn genesis() -> Self {
        QC {
            blk_hash: Block::genesis().digest(),
            payload_root: Digest::default(),
            kind: VoteType::Commit,
            round: 0,
            block: None,
            availability_shards: Vec::new(),
            votes: (Vec::new(), SignatureShareG1::default()),
        }
    }

    pub fn is_well_formed(&self, committee: &Committee) -> ConsensusResult<()> {
        if self.round == 0 {
            return Ok(());
        }

        let expected_chunks = (committee.size() + 127) / 128;
        ensure!(
            self.votes.0.len() >= expected_chunks,
            ConsensusError::QCRequiresQuorum(self.round)
        );

        let mut ids_to_remove = Vec::new();
        for idx in 0..committee.size() {
            let x = idx / 128;
            let bit = idx % 128;
            if self.votes.0[x] & (1u128 << bit) != 0 {
                ids_to_remove.push(idx);
            }
        }

        let mut weight = 0;
        for (name, authority) in &committee.authorities {
            let signer_idx = committee
                .sorted_keys
                .binary_search(&authority.bls_pubkey_g2)
                .map_err(|_| ConsensusError::UnknownAuthority(*name))?;
            let x = signer_idx / 128;
            let bit = signer_idx % 128;
            if self.votes.0[x] & (1u128 << bit) == 0 {
                weight += authority.stake;
            }
        }

        ensure!(
            weight >= committee.n - committee.f,
            ConsensusError::QCRequiresQuorum(self.round)
        );

        let _ = ids_to_remove;
        Ok(())
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.blk_hash);
        hasher.update(&self.payload_root);
        hasher.update(&self.kind.digest());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Display for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "QC({}, {})", self.blk_hash, self.round)
    }
}

impl fmt::Debug for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self.kind {
            VoteType::Commit => write!(f, "CommitQC({}, {})", self.blk_hash, self.round),
            _ => write!(f, "NQC({}, {}, {})", self.kind, self.blk_hash, self.round),
        }
    }
}

impl PartialEq for QC {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.blk_hash == other.blk_hash && self.round == other.round
    }
}
