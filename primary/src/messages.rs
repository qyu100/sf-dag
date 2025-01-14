// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::primary::Round;
use config::Committee;
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::convert::TryInto;
use std::fmt;

pub type Transaction = Vec<u8>;

#[derive(Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Header {
    pub author: PublicKey,
    pub round: Round,
    pub payload: Vec<Transaction>,
    pub parents: Vec<Digest>,
    pub id: Digest,
}

impl Header {
    pub async fn new(
        author: PublicKey,
        round: Round,
        payload: Vec<Transaction>,
        parents: Vec<Digest>,
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

#[derive(Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct HeaderInfo {
    pub author: PublicKey,
    pub round: Round,
    pub payload: Digest,
    pub parents: Vec<Digest>,
    pub id: Digest,
}

impl HeaderInfo {
    pub fn create_from(header: &Header) -> Self {
        let header_info = Self {
            author: header.author,
            round: header.round,
            payload: payload_digest(&header),
            parents: header.parents.clone(),
            id: header.id.clone(),
        };

        header_info
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
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
        write!(f, "{}: B{}({})", self.id, self.round, self.author,)
    }
}

impl fmt::Display for HeaderInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HeaderWithParents {
    pub header: Header,
    pub parents: Vec<HeaderInfo>,
}
impl fmt::Debug for HeaderWithParents {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({})",
            self.header.id, self.header.round, self.header.author,
        )
    }
}
impl fmt::Display for HeaderWithParents {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.header.round, self.header.author)
    }
}
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HeaderInfoWithParents {
    pub header_info: HeaderInfo,
    pub parents: Vec<HeaderInfo>,
}
impl fmt::Debug for HeaderInfoWithParents {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({})",
            self.header_info.id, self.header_info.round, self.header_info.author,
        )
    }
}
impl fmt::Display for HeaderInfoWithParents {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "B{}({})",
            self.header_info.round, self.header_info.author
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Vote {
    pub async fn new(
        header: &Header,
        author: &PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let vote = Self {
            id: header.id.clone(),
            round: header.round,
            origin: header.author,
            author: *author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
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
pub struct Certificate {
    pub header: Header,
    pub votes: Vec<(PublicKey, Signature)>,
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
        for (name, _) in self.votes.iter() {
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

        // Check the signatures.
        Signature::verify_batch(&self.digest(), &self.votes).map_err(DagError::from)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchoHeader {
    pub id: Digest, 
    pub round: Round,
    pub author: PublicKey,
    pub origin: PublicKey,
}

impl EchoHeader {
    pub async fn new(
        header_info: &HeaderInfo,
        author: &PublicKey) -> Self {
        EchoHeader {
            id: header_info.id.clone(), 
            round: header_info.round,
            author: *author,
            origin: header_info.author,
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

