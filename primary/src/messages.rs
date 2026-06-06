use crate::batch_maker::Transaction;
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::merkle::Proof;
use crate::primary::Round;
use blsttc::{PublicKeyShareG2, SignatureShareG1};
use config::Committee;
use crypto::{
    combine_key_from_ids, BlsSignatureService, Digest, Hash, PublicKey, Signature, SignatureService,
};
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
    pub payload_hash: Digest,
    pub parent: Digest,
    pub id: Digest,
    pub signature: Signature,
}

impl Header {
    pub async fn new(
        author: PublicKey,
        round: Round,
        payload: Vec<Transaction>,
        parent: Digest,
        signature_service: &mut SignatureService,
    ) -> Self {
        let header = Self {
            author,
            round,
            payload_hash: payload_digest(&payload),
            payload,
            parent,
            id: Digest::default(),
            signature: Signature::default(),
        };
        let id = header.digest();
        let signature = signature_service.request_signature(id).await;
        Self {
            id,
            signature,
            ..header
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        if self.round == 0 && self.id == Digest::default() {
            return Ok(());
        }

        // Ensure the header id is well formed.
        ensure!(self.digest() == self.id, DagError::InvalidHeaderId);
        ensure!(
            payload_digest(&self.payload) == self.payload_hash,
            DagError::InvalidHeaderId
        );

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));
        self.signature
            .verify(&self.id, &self.author)
            .map_err(DagError::from)
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
        header_digest(self.author, self.round, self.payload_hash, self.parent)
    }
}

fn header_digest(author: PublicKey, round: Round, payload_hash: Digest, parent: Digest) -> Digest {
    let mut hasher = Sha512::new();
    hasher.update(&author);
    hasher.update(round.to_le_bytes());
    hasher.update(&payload_hash);
    hasher.update(&parent);
    Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
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
    pub payload: Digest,
    pub parent: Digest,
    pub id: Digest,
    pub signature: Signature,
    pub proof: Proof,
    pub payload_len: usize,
}
impl HeaderInfoWithProof {
    pub fn new(header_info: &HeaderInfo, proof: &Proof) -> Self {
        let header_info_with_proof = Self {
            author: header_info.author,
            round: header_info.round,
            payload: header_info.payload,
            parent: header_info.parent.clone(),
            id: header_info.id,
            signature: header_info.signature.clone(),
            proof: proof.clone(),
            payload_len: header_info.payload_len,
        };
        header_info_with_proof
    }
    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        ensure!(
            header_digest(self.author, self.round, self.payload, self.parent) == self.id,
            DagError::InvalidHeaderId
        );

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));
        self.signature
            .verify(&self.id, &self.author)
            .map_err(DagError::from)
    }
}

impl fmt::Debug for HeaderInfoWithProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}: B{}({})", self.id, self.round, self.author,)
    }
}

/// Hint sent from Core to Proposer as soon as a header proof is received and its parent is available.
/// This is intentionally distinct from `Certificate` to make receive-vs-deliver semantics explicit.
#[derive(Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct ProposerParent {
    pub header_id: Digest,
    pub round: Round,
    pub origin: PublicKey,
}

impl ProposerParent {
    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|_| Self { ..Self::default() })
            .collect()
    }

    pub fn round(&self) -> Round {
        self.round
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
    pub signature: Signature,
    pub payload_len: usize,
}
impl HeaderInfo {
    pub fn create_from(header: &Header) -> Self {
        let header_info = Self {
            author: header.author,
            round: header.round,
            payload: header.payload_hash,
            parent: header.parent.clone(),
            id: header.id,
            signature: header.signature.clone(),
            payload_len: 0,
        };
        header_info
    }

    /// Fast variant using blake3 for payload digest (internally parallelized for large inputs).
    #[allow(dead_code)]
    pub fn create_from_fast(header: &Header) -> Self {
        Self {
            author: header.author,
            round: header.round,
            payload: header.payload_hash,
            parent: header.parent.clone(),
            id: header.id,
            signature: header.signature.clone(),
            payload_len: 0,
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        ensure!(
            header_digest(self.author, self.round, self.payload, self.parent) == self.id,
            DagError::InvalidHeaderId
        );

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));
        self.signature
            .verify(&self.id, &self.author)
            .map_err(DagError::from)
    }
}

fn payload_digest(payload: &[Transaction]) -> Digest {
    let mut hasher = Sha512::new();
    for x in payload {
        hasher.update(x);
    }
    Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
}

/// Fast payload digest using blake3 (internally parallelized for large inputs).
#[allow(dead_code)]
fn payload_digest_fast(header: &Header) -> Digest {
    let mut hasher = blake3::Hasher::new();
    for x in &header.payload {
        hasher.update(x);
    }
    let hash = hasher.finalize();
    Digest(*hash.as_bytes())
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
    pub proof: Proof,
    pub signature: SignatureShareG1,
}

impl Echo {
    pub async fn new(
        header_info_with_proof: &HeaderInfoWithProof,
        author: &PublicKey,
        bls_signature_service: &mut BlsSignatureService,
    ) -> Self {
        let echo = Self {
            id: header_info_with_proof.id.clone(),
            round: header_info_with_proof.round,
            origin: header_info_with_proof.author,
            author: *author,
            proof: header_info_with_proof.proof.clone(),
            signature: SignatureShareG1::default(),
        };
        let signature = bls_signature_service.request_signature(echo.digest()).await;
        Self { signature, ..echo }
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

impl Hash for Echo {
    fn digest(&self) -> Digest {
        echo_digest(self.id, *self.proof.root_hash(), self.round, self.origin)
    }
}

pub(crate) fn echo_digest(
    id: Digest,
    root_hash: Digest,
    round: Round,
    origin: PublicKey,
) -> Digest {
    let mut hasher = Sha512::new();
    hasher.update(b"Echo");
    hasher.update(&id);
    hasher.update(&root_hash);
    hasher.update(round.to_le_bytes());
    hasher.update(&origin);
    Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
}

impl fmt::Debug for Echo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.id, self.round, self.author, self.id
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
    pub signature: SignatureShareG1,
}

impl Ready {
    pub async fn new(
        header_id: Digest,
        round: Round,
        origin: &PublicKey,
        author: &PublicKey,
        root_hash: Digest,
        bls_signature_service: &mut BlsSignatureService,
    ) -> Self {
        let ready = Self {
            id: header_id,
            round,
            origin: *origin,
            author: *author,
            root_hash,
            signature: SignatureShareG1::default(),
        };
        let signature = bls_signature_service
            .request_signature(ready.digest())
            .await;
        Self { signature, ..ready }
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

impl Hash for Ready {
    fn digest(&self) -> Digest {
        ready_digest(self.id, self.root_hash, self.round, self.origin)
    }
}

pub(crate) fn ready_digest(
    id: Digest,
    root_hash: Digest,
    round: Round,
    origin: PublicKey,
) -> Digest {
    let mut hasher = Sha512::new();
    hasher.update(b"Ready");
    hasher.update(&id);
    hasher.update(&root_hash);
    hasher.update(round.to_le_bytes());
    hasher.update(&origin);
    Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
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

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ShardRequest {
    pub id: Digest,
    pub root_hash: Digest,
    pub index: usize,
    pub origin: PublicKey,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ShardResponse {
    pub id: Digest,
    pub root_hash: Digest,
    pub proof: Proof,
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
    pub root_hash: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub votes: (Vec<u128>, SignatureShareG1),
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

        let signer_ids = signer_ids_from_bitset(&self.votes.0, committee)?;
        let sorted_bls_keys = sorted_bls_public_keys(committee);
        let agg_pk = combine_key_from_ids(signer_ids, &sorted_bls_keys);
        SignatureShareG1::verify_batch(&self.digest().0, &agg_pk, &self.votes.1)
            .map_err(|_| DagError::InvalidBlsSignature)
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
        ready_digest(self.header_id, self.root_hash, self.round(), self.origin())
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
        ret &= self.root_hash == other.root_hash;
        ret &= self.round() == other.round();
        ret &= self.origin() == other.origin();
        ret
    }
}

pub(crate) fn empty_signer_bitset(committee: &Committee) -> Vec<u128> {
    vec![0; (committee.size() + 127) / 128]
}

pub(crate) fn set_signer_bit(bits: &mut [u128], index: usize) {
    let chunk = index / 128;
    let bit = index % 128;
    bits[chunk] |= 1u128 << bit;
}

pub(crate) fn signer_ids_from_bitset(
    bits: &[u128],
    committee: &Committee,
) -> DagResult<Vec<usize>> {
    let expected_chunks = (committee.size() + 127) / 128;
    ensure!(
        bits.len() >= expected_chunks,
        DagError::CertificateRequiresQuorum
    );

    let mut ids = Vec::new();
    let mut weight = 0;
    for (idx, public_key) in committee.sorted_keys.iter().enumerate() {
        let chunk = idx / 128;
        let bit = idx % 128;
        if bits[chunk] & (1u128 << bit) != 0 {
            ids.push(idx);
            weight += committee.stake(public_key);
        }
    }

    ensure!(
        weight >= committee.quorum_threshold(),
        DagError::CertificateRequiresQuorum
    );
    Ok(ids)
}

pub(crate) fn sorted_bls_public_keys(committee: &Committee) -> Vec<PublicKeyShareG2> {
    committee
        .sorted_keys
        .iter()
        .map(|key| committee.get_bls_public_g2(key))
        .collect()
}
