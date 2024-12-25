// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::primary::Round;
use config::{Committee, WorkerId};
use crypto::{Digest, Hash, PublicKey};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::TryInto;
use std::fmt;

pub type Transaction = Vec<u8>;

#[derive(Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Header {
    pub author: PublicKey,
    pub round: Round,
    pub payload: Vec<Transaction>,
    pub parents: BTreeSet<Digest>,
    pub id: Digest,
}

impl Header {
    pub async fn new(
        author: PublicKey,
        round: Round,
        payload: Vec<Transaction>,
        parents: BTreeSet<Digest>,
    ) -> Self {
        let header = Self {
            author,
            round,
            payload,
            parents,
            id: Digest::default(),
        };
        let id = header.digest();
        Self {
            id,
            ..header
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the header id is well formed.
        ensure!(self.digest() == self.id, DagError::InvalidHeaderId);

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));

        Ok(())    
    }
    // Check if pointer to prev leader exists

    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|name| Self { ..Self::default() })
            .collect()
    }
}

impl Hash for Header {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.author);
        hasher.update(self.round.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        for x in &self.parents {
            hasher.update(x);
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({})",
            self.id,
            self.round,
            self.author,
        )
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.author)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchoHeader {
    pub id: Digest, 
    pub round: Round,
    pub author: PublicKey,
    pub origin: PublicKey,
}

impl EchoHeader {
    pub async fn new(
        header: &Header,
        author: &PublicKey) -> Self {
        EchoHeader {
            id: header.id.clone(), 
            round: header.round,
            author: *author,
            origin: header.author,
        }
    }

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyHeader {
    pub id: Digest, 
    pub round: Round,
    pub author: PublicKey,
    pub origin: PublicKey,
}

impl ReadyHeader {
    pub async fn new(
        echo_header: &EchoHeader,
        author: &PublicKey
    ) -> Self {
        ReadyHeader {
            id: echo_header.id.clone(), 
            round: echo_header.round,
            author: *author,
            origin: echo_header.origin,
        }
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    pub round: Round,
    pub author: PublicKey,
}

impl Timeout {
    pub async fn new(
        round: Round,
        author: PublicKey,
    ) -> Self {
        let timeout = Self {
            round,
            author,
        };
        Self {
            ..timeout
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
        write!(
            f,
            "Timeout: R{}({})",
            self.round,
            self.author,
        )
    }
}

impl fmt::Display for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Round {} Timeout by {}", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NoVoteMsg {
    pub round: Round,
    pub author: PublicKey,
}

impl NoVoteMsg {
    pub async fn new(
        round: Round,
        author: PublicKey,
    ) -> Self {
        let msg = Self {
            round,
            author,
        };
        Self {
            ..msg
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

impl Hash for NoVoteMsg {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.author);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for NoVoteMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "NoVoteMsg: R{}({})",
            self.round,
            self.author,
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
}

impl Vote {
    pub async fn new(
        header: &Header,
        author: &PublicKey,
    ) -> Self {
        let vote = Self {
            id: header.id.clone(),
            round: header.round,
            origin: header.author,
            author: *author,
        };
        Self { ..vote }
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

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.id);
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.origin);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.digest(),
            self.round,
            self.author,
            self.id
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct TimeoutCert {
    pub round: Round,
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
    pub fn add_timeout(&mut self, author: PublicKey,) -> DagResult<()> {
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
pub struct NoVoteCert {
    pub round: Round,
    pub no_votes: Vec<PublicKey>,
}

impl NoVoteCert {
    pub fn new(round: Round) -> Self {
        Self {
            round,
            no_votes: Vec::new(),
        }
    }

    pub fn add_no_vote(&mut self, author: PublicKey) -> DagResult<()> {
        if self.no_votes.iter().any(|pk| *pk == author) {
            return Err(DagError::AuthorityReuse(author));
        }

        self.no_votes.push(author);

        Ok(())
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        let mut weight = 0;
        let mut used = HashSet::new();
        for author in &self.no_votes {
            ensure!(!used.contains(author), DagError::AuthorityReuse(*author));
            let voting_rights = committee.stake(author);
            ensure!(voting_rights > 0, DagError::UnknownAuthority(*author));
            used.insert(*author);
            weight += voting_rights;
        }

        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Certificate {
    pub header: Header,
    pub votes: Vec<PublicKey>,
}

impl Certificate {
    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|name| Self {
                header: Header {
                    author: *name,
                    ..Header::default()
                },
                ..Self::default()
            })
            .collect()
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Genesis certificates are always valid.
        if Self::genesis(committee).contains(self) {
            return Ok(());
        }

        // Check the embedded header.
        self.header.verify(committee)?;

        // Ensure the certificate has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for name in self.votes.iter() {
            ensure!(!used.contains(name), DagError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, DagError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );
        Ok(())
    }

    pub fn round(&self) -> Round {
        self.header.round
    }

    pub fn origin(&self) -> PublicKey {
        self.header.author
    }
}

impl Hash for Certificate {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.header.id);
        hasher.update(self.round().to_le_bytes());
        hasher.update(&self.origin());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: C{}({}, {})",
            self.digest(),
            self.round(),
            self.origin(),
            self.header.id
        )
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        let mut ret = self.header.id == other.header.id;
        ret &= self.round() == other.round();
        ret &= self.origin() == other.origin();
        ret
    }
}

