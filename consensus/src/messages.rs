use crate::config::Committee;
use crate::consensus::Round;
use crate::error::{ConsensusError, ConsensusResult};
use crate::merkle::Proof;
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryInto;
use std::fmt;

pub type Transaction = Vec<u8>;

#[cfg(test)]
#[path = "tests/messages_tests.rs"]
pub mod messages_tests;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub qc: QC,
    pub tc: Option<TC>,
    pub parent: Digest,
    pub author: PublicKey,
    pub round: Round,
    pub payload: Vec<Transaction>,
    pub signature: Signature,
}

impl Block {
    pub async fn new(
        qc: QC,
        tc: Option<TC>,
        parent: Digest,
        author: PublicKey,
        round: Round,
        payload: Vec<Transaction>,
        mut signature_service: SignatureService,
    ) -> Self {
        let block = Self {
            qc,
            tc,
            parent,
            author,
            round,
            payload,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(block.digest()).await;
        Self { signature, ..block }
    }

    pub fn genesis() -> Self {
        Block::default()
    }

    pub fn parent(&self) -> &Digest {
        &self.parent
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        // Check the TC embedded in the block (if any).
        if let Some(ref tc) = self.tc {
            tc.verify(committee)?;
        }
        Ok(())
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.round.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        hasher.update(&self.parent);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B({}, {}, {:?}, {})",
            self.digest(),
            self.author,
            self.round,
            self.qc,
            self.payload.iter().map(|x| x.len()).sum::<usize>(),
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub qc: QC,
    pub tc: Option<TC>,
    pub parent: Digest,
    pub author: PublicKey,
    pub round: Round,
    pub payload_digest: Digest,
    pub payload_len: usize,
    pub id: Digest,
    pub signature: Signature,
}

impl BlockInfo {
    pub fn create_from(block: &Block) -> Self {
        Self {
            qc: block.qc.clone(),
            tc: block.tc.clone(),
            parent: block.parent.clone(),
            author: block.author,
            round: block.round,
            payload_digest: payload_digest(&block.payload),
            payload_len: bincode::serialized_size(&block.payload)
                .expect("payload serialization should not fail") as usize,
            id: block.digest(),
            signature: block.signature.clone(),
        }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        self.signature.verify(&self.id, &self.author)?;
        if let Some(ref tc) = self.tc {
            tc.verify(committee)?;
        }
        Ok(())
    }
}

impl fmt::Debug for BlockInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}: BI({}, {})", self.id, self.author, self.round)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BlockInfoWithProof {
    pub info: BlockInfo,
    pub proof: Proof,
}

impl BlockInfoWithProof {
    pub fn new(info: BlockInfo, proof: Proof) -> Self {
        Self { info, proof }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        self.info.verify(committee)?;
        ensure!(
            self.proof.validate(committee.size()),
            ConsensusError::InvalidPayload
        );
        Ok(())
    }
}

impl fmt::Debug for BlockInfoWithProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self.info)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Echo {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
    pub proof: Proof,
    pub signature: Signature,
}

impl Echo {
    pub async fn new(
        block_info: &BlockInfoWithProof,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let echo = Self {
            id: block_info.info.id.clone(),
            round: block_info.info.round,
            origin: block_info.info.author,
            author,
            proof: block_info.proof.clone(),
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(echo.digest()).await;
        Self { signature, ..echo }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        ensure!(
            self.proof.validate(committee.size()),
            ConsensusError::InvalidPayload
        );
        self.signature.verify(&self.digest(), &self.author)?;
        Ok(())
    }
}

impl Hash for Echo {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.id);
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.origin.0);
        hasher.update(self.author.0);
        hasher.update(self.proof.root_hash());
        hasher.update((self.proof.index() as u64).to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Echo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "E({}, {}, {})", self.id, self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PayloadReady {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
    pub root_hash: Digest,
    pub signature: Signature,
}

impl PayloadReady {
    pub async fn new(
        info: &BlockInfo,
        author: PublicKey,
        root_hash: Digest,
        mut signature_service: SignatureService,
    ) -> Self {
        let ready = Self {
            id: info.id.clone(),
            round: info.round,
            origin: info.author,
            author,
            root_hash,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(ready.digest()).await;
        Self { signature, ..ready }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        self.signature.verify(&self.digest(), &self.author)?;
        Ok(())
    }
}

impl Hash for PayloadReady {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.id);
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.origin.0);
        hasher.update(self.author.0);
        hasher.update(&self.root_hash);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for PayloadReady {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "PR({}, {}, {}, {})",
            self.id, self.round, self.root_hash, self.author
        )
    }
}

pub fn payload_digest(payload: &[Transaction]) -> Digest {
    let mut hasher = Sha512::new();
    for x in payload {
        hasher.update(x);
    }
    Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}", self.round)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct QC {
    pub hash: Digest,
    pub round: Round,
    pub votes: Vec<(PublicKey, Signature)>,
}

impl QC {
    pub fn genesis() -> Self {
        QC::default()
    }

    pub fn timeout(&self) -> bool {
        self.hash == Digest::default() && self.round != 0
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::QCRequiresQuorum
        );

        // Check the signatures.
        Signature::verify_batch(&self.digest(), &self.votes).map_err(ConsensusError::from)
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.hash);
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "QC({}, {})", self.hash, self.round)
    }
}

impl PartialEq for QC {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.round == other.round
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    pub high_qc: QC,
    pub round: Round,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Timeout {
    pub async fn new(
        high_qc: QC,
        round: Round,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let timeout = Self {
            high_qc,
            round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(timeout.digest()).await;
        Self {
            signature,
            ..timeout
        }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        // Check the embedded QC.
        if self.high_qc != QC::genesis() {
            self.high_qc.verify(committee)?;
        }
        Ok(())
    }
}

impl Hash for Timeout {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.high_qc.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TV({}, {}, {:?})", self.author, self.round, self.high_qc)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TC {
    pub round: Round,
    pub votes: Vec<(PublicKey, Signature, Round)>,
}

impl TC {
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _, _) in self.votes.iter() {
            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::TCRequiresQuorum
        );

        // Check the signatures.
        for (author, signature, high_qc_round) in &self.votes {
            let mut hasher = Sha512::new();
            hasher.update(self.round.to_le_bytes());
            hasher.update(high_qc_round.to_le_bytes());
            let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
            signature.verify(&digest, author)?;
        }
        Ok(())
    }

    pub fn high_qc_rounds(&self) -> Vec<Round> {
        self.votes.iter().map(|(_, _, r)| r).cloned().collect()
    }
}

impl fmt::Debug for TC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TC({}, {:?})", self.round, self.high_qc_rounds())
    }
}
