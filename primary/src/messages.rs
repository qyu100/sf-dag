use crate::batch_maker::Transaction;
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::primary::Round;
use crate::merkle::Proof;
use config::Committee;
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryInto;
use std::fmt;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Header {
    pub author: PublicKey,
    pub round: Round,
    pub payload: Vec<Transaction>,
    pub parent: Digest,
    pub id: Digest,
}

impl Header {
    pub async fn new(
        author: PublicKey,
        round: Round,
        payload: Vec<Transaction>,
        parent: Digest,
    ) -> Self {
        let header = Self {
            author,
            round,
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
}

impl Hash for Header {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.author);
        hasher.update(self.round.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        // for x in &self.parents {
        //     hasher.update(x);
        // }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}: B{}({})", self.id, self.round, self.author,)
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.author)
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
            self.header.id, self.header.round, self.header.author,
        )
    }
}
impl fmt::Display for HeaderWithCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.header.round, self.header.author)
    }
}
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HeaderInfoWithCertificate {
    pub header_info: HeaderInfo,
    pub parents: Vec<Certificate>,
}
impl fmt::Debug for HeaderInfoWithCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({})",
            self.header_info.id, self.header_info.round, self.header_info.author,
        )
    }
}
impl fmt::Display for HeaderInfoWithCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "B{}({})",
            self.header_info.round, self.header_info.author
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HeaderInfoWithProof {
    pub author: PublicKey,
    pub round: Round,
    pub parent: Digest,
    pub id: Digest,
    pub proof: Proof,
    pub payload_len: usize,
}
impl HeaderInfoWithProof {
    pub fn new(header_info: &HeaderInfo, proof: &Proof) -> Self {
        let header_info_with_proof = Self {
            author: header_info.author,
            round: header_info.round,
            parent: header_info.parent.clone(),
            id: header_info.id,
            proof: proof.clone(),
            payload_len: header_info.payload_len,
        };
        header_info_with_proof
    }
    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));
        Ok(())
    }
}

impl fmt::Debug for HeaderInfoWithProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}: B{}({})", self.id, self.round, self.author,)
    }
}
impl fmt::Display for HeaderInfoWithProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HeaderInfo {
    pub author: PublicKey,
    pub round: Round,
    pub payload: Digest,
    pub parent: Digest,
    pub id: Digest,
    pub payload_len: usize,
}
impl HeaderInfo {
    pub fn create_from(header: &Header) -> Self {
        let header_info = Self {
            author: header.author,
            round: header.round,
            payload: payload_digest(&header),
            parent: header.parent.clone(),
            id: header.id,
            payload_len: 0,
        };
        header_info
    }
    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));
        Ok(())
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

#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    pub round: Round,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Timeout {
    pub async fn new(
        round: Round,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let timeout = Self {
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
pub struct Echo {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
    pub proof: Proof
}

impl Echo {
    pub async fn new(header_info_with_proof: &HeaderInfoWithProof, author: &PublicKey) -> Self {
        Self {
            id: header_info_with_proof.id.clone(),
            round: header_info_with_proof.round,
            origin: header_info_with_proof.author,
            author: *author,
            proof: header_info_with_proof.proof.clone(),
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
            "{}: V{}({}, {})",
            self.id,
            self.round,
            self.author,
            self.id
        )
    }
}

// #[derive(Clone, Serialize, Deserialize)]
// pub struct Vote {
//     pub id: Digest,
//     pub round: Round,
//     pub origin: PublicKey,
//     pub author: PublicKey,
// }

// impl Vote {
//     pub async fn new_for_header_info(header_info: &HeaderInfo, author: &PublicKey) -> Self {
//         Self {
//             id: header_info.id.clone(),
//             round: header_info.round,
//             origin: header_info.author,
//             author: *author,
//         }
//     }

//     pub fn verify(&self, committee: &Committee) -> DagResult<()> {
//         // Ensure the authority has voting rights.
//         ensure!(
//             committee.stake(&self.author) > 0,
//             DagError::UnknownAuthority(self.author)
//         );
//         Ok(())
//     }
// }

// impl Hash for Vote {
//     fn digest(&self) -> Digest {
//         let mut hasher = Sha512::new();
//         hasher.update(&self.id);
//         hasher.update(self.round.to_le_bytes());
//         hasher.update(&self.origin);
//         Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
//     }
// }

// impl fmt::Debug for Vote {
//     fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
//         write!(
//             f,
//             "{}: V{}({}, {})",
//             self.digest(),
//             self.round,
//             self.author,
//             self.id
//         )
//     }
// }

#[derive(Clone, Serialize, Deserialize)]
pub struct Ready {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
    pub root_hash: Digest,
}

impl Ready {
    pub async fn new(
        header_id: Digest,
        round: Round,
        origin: &PublicKey,
        author: &PublicKey,
        root_hash: Digest,
    ) -> Self {
        Self {
            id: header_id,
            round,
            origin: *origin,
            author: *author,
            root_hash,
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
            self.id,
            self.round,
            self.author,
            self.id
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
            self.id,
            self.round,
            self.author,
            self.id
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct TimeoutCert {
    pub round: Round,
    // Stores a list of public keys and their corresponding signatures.
    pub timeouts: Vec<(PublicKey, Signature)>,
}

impl TimeoutCert {
    pub fn new(round: Round) -> Self {
        Self {
            round,
            timeouts: Vec::new(),
        }
    }

    // Adds a timeout to the certificate.
    pub fn add_timeout(&mut self, author: PublicKey, signature: Signature) -> DagResult<()> {
        // Ensure this public key hasn't already submitted a timeout for this round
        if self.timeouts.iter().any(|(pk, _)| *pk == author) {
            return Err(DagError::AuthorityReuse(author));
        }

        // Add the timeout to the list
        self.timeouts.push((author, signature));

        Ok(())
    }

    // Verifies the timeout certificate against the committee.
    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        let mut weight = 0;

        let mut used = HashSet::new();
        for (name, _) in self.timeouts.iter() {
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
    pub round: Round,
    pub origin: PublicKey,
}

impl Certificate {
    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|_| Self { ..Self::default() })
            .collect()
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Genesis certificates are always valid.
        if Self::genesis(committee).contains(self) {
            return Ok(());
        }

        Ok(())
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn origin(&self) -> PublicKey {
        self.origin
    }
}

impl Hash for Certificate {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.header_id);
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
            self.header_id,
            self.round(),
            self.origin(),
            self.header_id
        )
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        let mut ret = self.header_id == other.header_id;
        ret &= self.round() == other.round();
        ret &= self.origin() == other.origin();
        ret
    }
}
