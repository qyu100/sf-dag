// Copyright(C) Facebook, Inc. and its affiliates.

use crate::error::{DagError, DagResult};
use crate::primary::{Height, Slot, View};
use config::{Committee, WorkerId};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryInto;
use std::fmt;

pub type Round = u64;
pub type Transaction = Vec<u8>;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Header {
    pub author: PublicKey,
    pub height: Height,
    pub payload: Vec<Transaction>,
    pub parent: Digest,
    pub id: Digest,
}

impl Header {
    pub async fn new(
        author: PublicKey,
        height: Height,
        payload: Vec<Transaction>,
        parent: Digest,
    ) -> Self {
        let header = Self {
            author,
            height,
            payload,
            parent,
            id: Digest::default(),
        };
        let id = header.digest();
        Self { id, ..header }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the header id is well formed.
        ensure!(self.digest() == self.id, DagError::InvalidHeaderId);

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));
        Ok(())
    }

    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|_| Self { ..Self::default() })
            .collect()
    }
    pub fn height(&self) -> Height {
        self.height
    }

    pub fn origin(&self) -> PublicKey {
        self.author
    }

    pub fn genesis_headers(committee: &Committee) -> HashMap<PublicKey, Header> {
        committee
            .authorities
            .keys()
            .map(|pk| (*pk, Header::default()))
            .collect()
    }

    pub fn genesis_proposals(committee: &Committee) -> HashMap<PublicKey, Proposal> {
        committee
            .authorities
            .keys()
            .map(|pk| (*pk, Proposal::default()))
            .collect()
    }
}

impl Hash for Header {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.author);
        hasher.update(self.height.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        // hasher.update(&self.parent);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}: B{}({})", self.id, self.height, self.author,)
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.height, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HeaderInfo {
    pub author: PublicKey,
    pub height: Height,
    pub parent: Digest,
    pub payload: Digest,
    pub id: Digest,
}

impl HeaderInfo {
    pub fn from_header(header: &Header) -> Self {
        Self {
            author: header.author,
            height: header.height,
            parent: header.parent.clone(),
            payload: payload_digest(header),
            id: header.id.clone(),
        }
    }
}

fn payload_digest(header: &Header) -> Digest {
    let mut hasher = Sha512::new();
    for x in &header.payload {
        hasher.update(x);
    }
    Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
}

impl fmt::Debug for HeaderInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}: B{}({})", self.id, self.height, self.author)
    }
}

impl fmt::Display for HeaderInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.height, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HeaderWithCertificate {
    pub header: Header,
    pub parents: Vec<Certificate>,
}
impl fmt::Debug for HeaderWithCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({})",
            self.header.id, self.header.height, self.header.author,
        )
    }
}
impl fmt::Display for HeaderWithCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.header.height, self.header.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    pub round: Round,
    pub author: PublicKey,
}

impl Timeout {
    pub async fn new(round: Round, author: PublicKey) -> Self {
        let timeout = Self { round, author };
        Self { ..timeout }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );
        Ok(())
    }
}

impl Hash for Timeout {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.author);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Timeout: R{}({})", self.round, self.author,)
    }
}

impl fmt::Display for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Round {} Timeout by {}", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TimeoutAccept {
    pub round: Round,
    pub author: PublicKey,
}

impl TimeoutAccept {
    pub fn new(round: Round, author: PublicKey) -> Self {
        Self { round, author }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );
        Ok(())
    }
}

impl Hash for TimeoutAccept {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.author);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for TimeoutAccept {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TimeoutAccept: R{}({})", self.round, self.author,)
    }
}

impl fmt::Display for TimeoutAccept {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Round {} TimeoutAccept by {}", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub id: Digest,
    pub height: Height,
    pub origin: PublicKey,
    pub author: PublicKey,
}

impl Vote {
    pub async fn new(header: &Header, author: &PublicKey) -> Self {
        Self {
            id: header.id.clone(),
            height: header.height(),
            origin: header.author,
            author: *author,
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );
        Ok(())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.id, self.height, self.author, self.id
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Echo {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
}

impl Echo {
    pub async fn new(header: &Header, author: &PublicKey) -> Self {
        Self {
            id: header.id.clone(),
            round: header.height,
            origin: header.author,
            author: *author,
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );
        Ok(())
    }
}

impl fmt::Debug for Echo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: E{}({}, {})",
            self.id, self.round, self.author, self.id
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Ready {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
}

impl Ready {
    pub async fn new(
        header_id: Digest,
        round: Round,
        origin: &PublicKey,
        author: &PublicKey,
    ) -> Self {
        Self {
            id: header_id,
            round,
            origin: *origin,
            author: *author,
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );
        Ok(())
    }
}

impl fmt::Debug for Ready {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: R{}({}, {})",
            self.id, self.round, self.author, self.id
        )
    }
}

// Commit message in the protocol
#[derive(Clone, Serialize, Deserialize)]
pub struct Decide {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
}

impl Decide {
    pub async fn new(
        header_id: Digest,
        round: Round,
        origin: &PublicKey,
        author: &PublicKey,
    ) -> Self {
        Self {
            id: header_id,
            round,
            origin: *origin,
            author: *author,
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );
        Ok(())
    }
}

impl fmt::Debug for Decide {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: D{}({}, {})",
            self.id, self.round, self.author, self.id
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct TimeoutCert {
    pub round: Round,
    // Stores a list of public keys and their corresponding signatures.
    pub timeouts: Vec<PublicKey>,
}

impl TimeoutCert {
    pub fn new(round: Round) -> Self {
        Self {
            round,
            timeouts: Vec::new(),
        }
    }

    // Adds a timeout to the certificate.
    pub fn add_timeout(&mut self, author: PublicKey) -> DagResult<()> {
        // Ensure this public key hasn't already submitted a timeout for this round
        if self.timeouts.iter().any(|pk| *pk == author) {
            return Err(DagError::AuthorityReuse(author));
        }

        // Add the timeout to the list
        self.timeouts.push(author);

        Ok(())
    }

    // Verifies the timeout certificate against the committee.
    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        let mut weight = 0;

        let mut used = HashSet::new();
        for name in self.timeouts.iter() {
            ensure!(!used.contains(name), DagError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, DagError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }

        // Check if the accumulated weight meets the quorum threshold.
        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Certificate {
    pub header_id: Digest,
    pub height: Height,
    pub origin: PublicKey,
}

impl Certificate {
    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|pk| Self {
                header_id: Digest::default(),
                height: 0,
                origin: *pk,
            })
            .collect()
    }

    pub fn genesis_cert(_committee: &Committee) -> Self {
        Self {
            header_id: Digest::default(),
            ..Self::default()
        }
    }

    pub fn genesis_certs(committee: &Committee) -> HashMap<PublicKey, Self> {
        committee
            .authorities
            .keys()
            .map(|pk| {
                (
                    *pk,
                    Self {
                        header_id: Digest::default(),
                        height: 0,
                        origin: *pk,
                    },
                )
            })
            .collect()
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Genesis certificates are always valid.
        if Self::genesis(committee).contains(self) {
            return Ok(());
        }

        Ok(())
    }

    pub fn height(&self) -> Height {
        self.height
    }

    pub fn origin(&self) -> PublicKey {
        self.origin
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct QC {
    pub id: Digest,
    pub votes: Vec<(PublicKey, Signature)>,
}

impl QC {
    pub fn genesis(_committee: &Committee) -> Self {
        Self::default()
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct TC {
    pub slot: Slot,
    pub view: View,
    pub timeouts: Vec<Timeout>,
}

impl TC {
    pub fn genesis(_committee: &Committee) -> Self {
        Self::default()
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub enum ConsensusType {
    #[default]
    Prepare,
    Confirm,
    Commit,
}

pub type CommitQC = QC;

pub fn transform_commitQC(qc: QC) -> CommitQC {
    qc
}

pub fn verify_confirm(_msg: &ConsensusMessage) -> DagResult<()> {
    Ok(())
}

pub fn verify_commit(_msg: &ConsensusMessage) -> DagResult<()> {
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ConsensusMessage {
    Prepare {
        slot: Slot,
        view: View,
        tc: Option<TC>,
        qc_ticket: Option<QC>,
        proposals: HashMap<PublicKey, Proposal>,
    },
    Confirm {
        slot: Slot,
        view: View,
        qc: QC,
        proposals: HashMap<PublicKey, Proposal>,
    },
    Commit {
        round: Round,
        proposals: HashMap<PublicKey, Proposal>,
    },
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct ConsensusRequest {
    pub id: Digest,
    pub slot: Slot,
    pub view: View,
    pub request_type: ConsensusType,
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct ConsensusVote {
    pub id: Digest,
    pub slot: Slot,
    pub view: View,
    pub vote_type: ConsensusType,
    pub author: PublicKey,
}

pub fn proposal_digest(consensus_message: &ConsensusMessage) -> Digest {
    let mut hasher = Sha512::new();
    match consensus_message {
        ConsensusMessage::Prepare {
            slot,
            view,
            proposals,
            ..
        } => {
            hasher.update(slot.to_le_bytes());
            hasher.update(view.to_le_bytes());
            for (pk, proposal) in proposals {
                hasher.update(pk);
                hasher.update(proposal.digest());
            }
        }
        ConsensusMessage::Confirm {
            slot,
            view,
            proposals,
            ..
        } => {
            hasher.update(slot.to_le_bytes());
            hasher.update(view.to_le_bytes());
            for (pk, proposal) in proposals {
                hasher.update(pk);
                hasher.update(proposal.digest());
            }
        }
        ConsensusMessage::Commit {
            round, proposals, ..
        } => {
            hasher.update(round.to_le_bytes());
            for (pk, proposal) in proposals {
                hasher.update(pk);
                hasher.update(proposal.digest());
            }
        }
    }
    Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
}

impl Hash for Certificate {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.header_id);
        hasher.update(self.height().to_le_bytes());
        hasher.update(&self.origin());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: C{}({}, {})",
            self.header_id,
            self.height(),
            self.origin(),
            self.header_id
        )
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        let mut ret = self.header_id == other.header_id;
        ret &= self.height() == other.height();
        ret &= self.origin() == other.origin();
        ret
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Proposal {
    pub header_digest: Digest,
    pub height: Height,
}

impl Proposal {
    pub async fn new(header_digest: Digest, height: Height) -> Self {
        Self {
            header_digest,
            height,
        }
    }
}

impl PartialEq for Proposal {
    fn eq(&self, other: &Self) -> bool {
        self.height == other.height && self.header_digest == other.header_digest
    }
}

impl fmt::Debug for Proposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "P({}, {})", self.height, self.header_digest)
    }
}

impl fmt::Display for Proposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "P({}, {})", self.height, self.header_digest)
    }
}

impl Hash for Proposal {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.header_digest.0);
        hasher.update(&self.height.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

/// A cut is a snapshot of certified tips across all lanes.
pub type Cut = BTreeMap<PublicKey, Proposal>;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct CutProposal {
    pub round: u64,
    pub proposer: PublicKey,
    pub parent_cut: Digest,
    pub tips: Cut,
}

impl CutProposal {
    pub fn id(&self) -> Digest {
        self.digest()
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        ensure!(
            committee.stake(&self.proposer) > 0,
            DagError::UnknownAuthority(self.proposer)
        );
        Ok(())
    }
}

impl Hash for CutProposal {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.round.to_le_bytes());
        hasher.update(&self.proposer);
        hasher.update(&self.parent_cut);
        for (author, proposal) in &self.tips {
            hasher.update(author);
            hasher.update(&proposal.header_digest);
            hasher.update(&proposal.height.to_le_bytes());
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for CutProposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "CutProposal(r={}, proposer={}, parent={}, tips={})",
            self.round,
            self.proposer,
            self.parent_cut,
            self.tips.len()
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct CutVote {
    pub round: u64,
    pub cut_id: Digest,
    pub author: PublicKey,
}

impl CutVote {
    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );
        Ok(())
    }
}

impl Hash for CutVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.round.to_le_bytes());
        hasher.update(&self.cut_id);
        hasher.update(&self.author);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct CutCertificate {
    pub round: u64,
    pub cut_id: Digest,
    pub votes: Vec<PublicKey>,
}

impl CutCertificate {
    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        let mut weight = 0;
        let mut used = HashSet::new();
        for author in &self.votes {
            ensure!(used.insert(*author), DagError::AuthorityReuse(*author));
            let stake = committee.stake(author);
            ensure!(stake > 0, DagError::UnknownAuthority(*author));
            weight += stake;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );
        Ok(())
    }
}
