// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::merkle::Proof;
use crate::messages::{
    echo_digest, empty_signer_bitset, set_signer_bit, signer_ids_from_bitset,
    sorted_bls_public_keys, Certificate, Ready, Timeout, TimeoutCert,
};
use blsttc::SignatureShareG1;
use config::{Committee, Stake};
use crypto::{aggregate_sign, combine_key_from_ids, Digest, Hash as _, PublicKey, Signature};
use std::collections::{HashMap, HashSet};
use std::mem;

pub struct EchoAggregator {
    weight: Stake,
    used: HashSet<PublicKey>,
    // Map from root_hash -> map(author -> proof)
    echos: HashMap<Digest, HashMap<PublicKey, Proof>>,
    // Accumulated stake per root hash
    weights: HashMap<Digest, Stake>,
    signatures: HashMap<Digest, SignatureShareG1>,
    signer_bits: HashMap<Digest, Vec<u128>>,
}

impl EchoAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            used: HashSet::new(),
            echos: HashMap::new(),
            weights: HashMap::new(),
            signatures: HashMap::new(),
            signer_bits: HashMap::new(),
        }
    }

    pub fn append(
        &mut self,
        author: PublicKey,
        proof: Proof,
        signature: SignatureShareG1,
        id: Digest,
        round: crate::primary::Round,
        origin: PublicKey,
        committee: &Committee,
    ) -> DagResult<Option<(Digest, Vec<Option<Box<[u8]>>>)>> {
        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        // Clone the root digest first (avoids borrowing `proof`), then move the proof into the map.
        let root = proof.root_hash().clone();
        let author_map = self.echos.entry(root.clone()).or_insert_with(HashMap::new);
        // Move proof into the map to avoid cloning large leaf data.
        author_map.insert(author, proof);

        let author_index = committee
            .index_of(&author)
            .ok_or(DagError::UnknownAuthority(author))?;
        let current_weight = *self.weights.get(&root).unwrap_or(&0);
        let agg_signature = self
            .signatures
            .entry(root.clone())
            .or_insert_with(SignatureShareG1::default);
        if current_weight == 0 {
            *agg_signature = signature;
        } else {
            *agg_signature = aggregate_sign(agg_signature, &signature);
        }
        let bits = self
            .signer_bits
            .entry(root.clone())
            .or_insert_with(|| empty_signer_bitset(committee));
        set_signer_bit(bits, author_index);

        let w = self.weights.entry(root.clone()).or_insert(0);
        *w += committee.stake(&author);
        // If this particular root reached quorum, build the ordered leaf vector
        if *w >= committee.quorum_threshold() {
            self.weights.remove(&root);
            let bits = self
                .signer_bits
                .remove(&root)
                .expect("signer bitset exists");
            let agg_signature = self
                .signatures
                .remove(&root)
                .expect("aggregate signature exists");
            verify_quorum_signature(
                echo_digest(id, root, round, origin),
                &bits,
                &agg_signature,
                committee,
            )?;
            let author_map = self.echos.remove(&root).expect("author_map exists");
            let mut owned_map = author_map;
            let leaf_values: Vec<Option<Box<[u8]>>> = committee
                .sorted_keys
                .iter()
                .map(|pk| owned_map.remove(pk).map(|p| p.into_value()))
                .collect();
            return Ok(Some((root.clone(), leaf_values)));
        }
        Ok(None)
    }
}

pub struct ReadyAggregator {
    used: HashSet<PublicKey>,
    // Map from root_hash -> map(author -> Ready)
    readies: HashMap<Digest, HashMap<PublicKey, Ready>>,
    // Accumulated stake per root hash
    weights: HashMap<Digest, Stake>,
    signatures: HashMap<Digest, SignatureShareG1>,
    signer_bits: HashMap<Digest, Vec<u128>>,
    relay_roots: HashSet<Digest>,
    quorum_roots: HashSet<Digest>,
}

pub enum ReadyThreshold {
    Relay(Digest),
    Quorum(Digest, Vec<u128>, SignatureShareG1),
}

impl ReadyAggregator {
    pub fn new() -> Self {
        Self {
            used: HashSet::new(),
            readies: HashMap::new(),
            weights: HashMap::new(),
            signatures: HashMap::new(),
            signer_bits: HashMap::new(),
            relay_roots: HashSet::new(),
            quorum_roots: HashSet::new(),
        }
    }

    // Return the root hash when either f+1 or n-f Ready messages are collected for it.
    pub fn append(
        &mut self,
        ready: &Ready,
        committee: &Committee,
    ) -> DagResult<Option<ReadyThreshold>> {
        let author = ready.author;
        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));
        let root = ready.root_hash;
        let author_map = self.readies.entry(root).or_insert_with(HashMap::new);
        author_map.insert(author, ready.clone());
        let author_index = committee
            .index_of(&author)
            .ok_or(DagError::UnknownAuthority(author))?;
        let current_weight = *self.weights.get(&root).unwrap_or(&0);
        let agg_signature = self
            .signatures
            .entry(root)
            .or_insert_with(SignatureShareG1::default);
        if current_weight == 0 {
            *agg_signature = ready.signature;
        } else {
            *agg_signature = aggregate_sign(agg_signature, &ready.signature);
        }
        let bits = self
            .signer_bits
            .entry(root)
            .or_insert_with(|| empty_signer_bitset(committee));
        set_signer_bit(bits, author_index);
        let w = self.weights.entry(root).or_insert(0);
        *w += committee.stake(&author);
        if *w >= committee.quorum_threshold() && self.quorum_roots.insert(root) {
            let bits = self
                .signer_bits
                .get(&root)
                .expect("signer bitset exists")
                .clone();
            let agg_signature = *self
                .signatures
                .get(&root)
                .expect("aggregate signature exists");
            verify_quorum_signature(ready.digest(), &bits, &agg_signature, committee)?;
            return Ok(Some(ReadyThreshold::Quorum(root, bits, agg_signature)));
        }
        if *w >= committee.validity_threshold() && self.relay_roots.insert(root) {
            return Ok(Some(ReadyThreshold::Relay(root)));
        }
        Ok(None)
    }
}

fn verify_quorum_signature(
    digest: Digest,
    signer_bits: &[u128],
    signature: &SignatureShareG1,
    committee: &Committee,
) -> DagResult<()> {
    let signer_ids = signer_ids_from_bitset(signer_bits, committee)?;
    let sorted_bls_keys = sorted_bls_public_keys(committee);
    let agg_pk = combine_key_from_ids(signer_ids, &sorted_bls_keys);
    SignatureShareG1::verify_batch(&digest.0, &agg_pk, signature)
        .map_err(|_| DagError::InvalidBlsSignature)
}

/// Aggregate certificates and check if we reach a quorum.
pub struct CertificatesAggregator {
    weight: Stake,
    certificates: Vec<Certificate>,
    used: HashSet<PublicKey>,
}

impl CertificatesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            certificates: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        certificate: &Certificate,
        committee: &Committee,
    ) -> DagResult<Option<Vec<Certificate>>> {
        let origin = certificate.origin();

        // Ensure it is the first time this authority votes.
        if !self.used.insert(origin) {
            return Ok(None);
        }

        let round = certificate.round;

        self.certificates.push(certificate.clone());
        self.weight += committee.stake(&origin);

        let leader = committee.leader(round as usize);
        if !self.used.contains(&leader) {
            return Ok(None);
        }

        if self.weight >= committee.quorum_threshold() {
            //self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(self.certificates.drain(..).collect()));
        }
        Ok(None)
    }
}

/// Aggregates timeouts for a particular round into an action or trigger.
pub struct TimeoutAggregator {
    weight: Stake,
    timeouts: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl TimeoutAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            timeouts: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        timeout: Timeout,
        committee: &Committee,
    ) -> DagResult<Option<TimeoutCert>> {
        let author = timeout.author;

        // Ensure it is the first time this authority sends a timeout.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.timeouts.push((author, timeout.signature));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            // Once quorum is reached, move the accumulated timeouts out (avoids cloning the vec).
            return Ok(Some(TimeoutCert {
                round: timeout.round,
                timeouts: mem::take(&mut self.timeouts),
            }));
        }
        Ok(None)
    }
}
