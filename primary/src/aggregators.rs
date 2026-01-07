// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::merkle::Proof;
use crate::messages::{Certificate, Ready, Timeout, TimeoutCert, Echo, Decide};
use config::{Committee, Stake};
use crypto::{PublicKey, Digest};
use crypto::Signature;
use log::debug;
use std::collections::{HashSet, HashMap};

pub struct EchoAggregator {
    weight: Stake,
    used: HashSet<PublicKey>,
    // Map from root_hash -> map(author -> proof)
    echos: HashMap<Digest, HashMap<PublicKey, Proof>>,
    // Accumulated stake per root hash
    weights: HashMap<Digest, Stake>,
}

impl EchoAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            used: HashSet::new(),
            echos: HashMap::new(),
            weights: HashMap::new(),
        }
    }

    pub fn append(&mut self, echo: &Echo, committee: &Committee) -> DagResult<Option<(Digest, Vec<Option<Box<[u8]>>>)>> {
        let author = echo.author;
        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        let root = echo.proof.root_hash();
        let author_map = self.echos.entry(*root).or_insert_with(HashMap::new);
        author_map.insert(author, echo.proof.clone());


        let w = self.weights.entry(*root).or_insert(0);
        *w += committee.stake(&author);

        // If this particular root reached quorum, build the ordered leaf vector
        if *w >= committee.quorum_threshold() {

            self.weights.remove(&root);
            let author_map = self.echos.remove(&root).expect("author_map exists");
            
            let leaf_values: Vec<Option<Box<[u8]>>> = committee
                .sorted_keys
                .iter()
                .map(|pk| author_map.get(pk).map(|p| p.value().clone().into_boxed_slice()))
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
}

impl ReadyAggregator {
    pub fn new() -> Self {
        Self {
            used: HashSet::new(),
            readies: HashMap::new(),
            weights: HashMap::new(),
        }
    }

    // Return the root hash when 2f+1 Ready messages are collected for it.
    pub fn append(
        &mut self,
        ready: &Ready,
        committee: &Committee,
    ) -> DagResult<Option<Digest>> {
        let author = ready.author;
        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));
        let root = ready.root_hash;
        let author_map = self.readies.entry(root).or_insert_with(HashMap::new);
        author_map.insert(author, ready.clone());
        let w = self.weights.entry(root).or_insert(0);
        *w += committee.stake(&author);
        if *w >= committee.quorum_threshold() {
            self.weights.remove(&root);
            let _author_map = self.readies.remove(&root).expect("author_map exists");
            return Ok(Some(root));
        }
        Ok(None)
    }
}

pub struct DecideAggregator {
    weight: Stake,
    used: HashSet<PublicKey>,
}

impl DecideAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            used: HashSet::new(),
        }
    }

    pub fn append(
    &mut self,
    decide: &Decide,
    committee: &Committee,
    ) -> DagResult<Option<bool>> {
        let author = decide.author;
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));
        self.weight += committee.stake(&author);

        if self.weight >= committee.quorum_threshold() {
            self.weight = 0;
            return Ok(Some(true));
        }
        Ok(None)
    }
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
            // Once quorum is reached, you might want to reset for the next round or trigger an action.
            return Ok(Some(TimeoutCert {
                round: timeout.round.clone(),
                timeouts: self.timeouts.clone(),
            })); // Return the authorities that contributed to this quorum.
        }
        Ok(None)
    }
}
