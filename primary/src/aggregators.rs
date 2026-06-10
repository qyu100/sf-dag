// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::merkle::Proof;
use crate::messages::{Decide, Timeout, TimeoutAccept, TimeoutCert};
use config::{Committee, Stake};
use crypto::{Digest, PublicKey};
use std::collections::{HashMap, HashSet};
use std::mem;

pub struct EchoAggregator {
    used: HashSet<PublicKey>,
    // Map from root_hash -> map(author -> proof)
    echos: HashMap<Digest, HashMap<PublicKey, Proof>>,
    // Accumulated stake per root hash
    weights: HashMap<Digest, Stake>,
}

impl EchoAggregator {
    pub fn new() -> Self {
        Self {
            used: HashSet::new(),
            echos: HashMap::new(),
            weights: HashMap::new(),
        }
    }

    pub fn append(
        &mut self,
        author: PublicKey,
        proof: Proof,
        committee: &Committee,
    ) -> DagResult<Option<(Digest, Vec<Option<Box<[u8]>>>, Stake, usize)>> {
        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        // Clone the root digest first (avoids borrowing `proof`), then move the proof into the map.
        let root = proof.root_hash().clone();
        let author_map = self.echos.entry(root.clone()).or_insert_with(HashMap::new);
        // Move proof into the map to avoid cloning large leaf data.
        author_map.insert(author, proof);

        let w = self.weights.entry(root.clone()).or_insert(0);
        *w += committee.stake(&author);
        // If this particular root reached quorum, build the ordered leaf vector
        if *w >= committee.optimistic_threshold() {
            let collected_weight = *w;
            self.weights.remove(&root);
            let author_map = self.echos.remove(&root).expect("author_map exists");
            let collected_count = author_map.len();
            let mut owned_map = author_map;
            let leaf_values: Vec<Option<Box<[u8]>>> = committee
                .sorted_keys
                .iter()
                .map(|pk| owned_map.remove(pk).map(|p| p.into_value()))
                .collect();
            return Ok(Some((
                root.clone(),
                leaf_values,
                collected_weight,
                collected_count,
            )));
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

    pub fn append(&mut self, decide: &Decide, committee: &Committee) -> DagResult<Option<bool>> {
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

/// Aggregates timeout votes for a particular round into an accept trigger.
pub struct TimeoutAggregator {
    weight: Stake,
    used: HashSet<PublicKey>,
}

impl TimeoutAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            used: HashSet::new(),
        }
    }

    pub fn append(&mut self, timeout: Timeout, committee: &Committee) -> DagResult<Option<()>> {
        let author = timeout.author;

        // Ensure it is the first time this authority sends a timeout.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            return Ok(Some(()));
        }
        Ok(None)
    }
}

/// Aggregates timeout accepts for a particular round into a timeout certificate.
pub struct TimeoutAcceptAggregator {
    weight: Stake,
    accepts: Vec<PublicKey>,
    used: HashSet<PublicKey>,
}

impl TimeoutAcceptAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            accepts: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        accept: TimeoutAccept,
        committee: &Committee,
    ) -> DagResult<(Stake, Option<TimeoutCert>)> {
        let author = accept.author;

        // Ensure it is the first time this authority sends a timeout accept.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.accepts.push(author);
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            return Ok((
                self.weight,
                Some(TimeoutCert {
                    round: accept.round,
                    timeouts: mem::take(&mut self.accepts),
                }),
            ));
        }
        Ok((self.weight, None))
    }
}
