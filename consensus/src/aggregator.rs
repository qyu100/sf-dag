use crate::config::{Committee, Stake};
use crate::consensus::Round;
use crate::error::ConsensusResult;
use crate::merkle::Proof;
use crate::messages::{Echo, PayloadReady, Timeout, TC};
use crypto::{Digest, PublicKey, Signature};
use log::debug;
use std::collections::{HashMap, HashSet};

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

pub struct Aggregator {
    committee: Committee,
    echo_aggregators: HashMap<Digest, Box<EchoMaker>>,
    payload_ready_aggregators: HashMap<Digest, Box<PayloadReadyMaker>>,
    timeouts_aggregators: HashMap<Round, Box<TCMaker>>,
}

impl Aggregator {
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            echo_aggregators: HashMap::new(),
            payload_ready_aggregators: HashMap::new(),
            timeouts_aggregators: HashMap::new(),
        }
    }

    pub fn add_echo(
        &mut self,
        echo: Echo,
    ) -> ConsensusResult<Option<(Digest, Vec<Option<Box<[u8]>>>)>> {
        let shard_count = self.committee.size();
        self.echo_aggregators
            .entry(echo.id.clone())
            .or_insert_with(|| Box::new(EchoMaker::new(shard_count)))
            .append(echo, &self.committee)
    }

    pub fn add_payload_ready(&mut self, ready: PayloadReady) -> ConsensusResult<Option<Digest>> {
        self.payload_ready_aggregators
            .entry(ready.id.clone())
            .or_insert_with(|| Box::new(PayloadReadyMaker::new()))
            .append(ready, &self.committee)
    }

    pub fn add_timeout(&mut self, timeout: Timeout) -> ConsensusResult<Option<TC>> {
        // TODO: A bad node may make us run out of memory by sending many timeouts
        // with different round numbers.

        // Add the new timeout to our aggregator and see if we have a TC.
        self.timeouts_aggregators
            .entry(timeout.round)
            .or_insert_with(|| Box::new(TCMaker::new()))
            .append(timeout, &self.committee)
    }

    pub fn cleanup(&mut self, round: &Round) {
        self.timeouts_aggregators.retain(|k, _| k >= round);
    }

    pub fn cleanup_payloads(&mut self, live_ids: &HashSet<Digest>) {
        self.echo_aggregators
            .retain(|digest, _| live_ids.contains(digest));
        self.payload_ready_aggregators
            .retain(|digest, _| live_ids.contains(digest));
    }
}

struct EchoMaker {
    used: HashSet<PublicKey>,
    proofs: HashMap<Digest, HashMap<PublicKey, Proof>>,
    weights: HashMap<Digest, Stake>,
    shard_count: usize,
}

impl EchoMaker {
    fn new(shard_count: usize) -> Self {
        Self {
            used: HashSet::new(),
            proofs: HashMap::new(),
            weights: HashMap::new(),
            shard_count,
        }
    }

    fn append(
        &mut self,
        echo: Echo,
        committee: &Committee,
    ) -> ConsensusResult<Option<(Digest, Vec<Option<Box<[u8]>>>)>> {
        let id = echo.id.clone();
        let author = echo.author;
        if !self.used.insert(author) {
            debug!("Ignoring duplicate echo for {:?} from {}", id, author);
            return Ok(None);
        }

        let root = echo.proof.root_hash().clone();
        let entry = self.proofs.entry(root.clone()).or_insert_with(HashMap::new);
        entry.insert(author, echo.proof);
        let weight = self.weights.entry(root.clone()).or_insert(0);
        *weight += committee.stake(&author);
        debug!(
            "Echo weight for {:?} root {:?} is {}/{} after {}",
            id,
            root,
            *weight,
            committee.quorum_threshold(),
            author
        );

        if *weight >= committee.quorum_threshold() {
            let mut proofs = self.proofs.remove(&root).expect("proofs exist");
            self.weights.remove(&root);
            let shards = committee
                .sorted_keys()
                .into_iter()
                .take(self.shard_count)
                .map(|pk| proofs.remove(&pk).map(|p| p.into_value()))
                .collect();
            debug!("Echo quorum reached for {:?} root {:?}", id, root);
            return Ok(Some((root, shards)));
        }
        Ok(None)
    }
}

struct PayloadReadyMaker {
    used: HashSet<PublicKey>,
    weights: HashMap<Digest, Stake>,
}

impl PayloadReadyMaker {
    fn new() -> Self {
        Self {
            used: HashSet::new(),
            weights: HashMap::new(),
        }
    }

    fn append(
        &mut self,
        ready: PayloadReady,
        committee: &Committee,
    ) -> ConsensusResult<Option<Digest>> {
        let author = ready.author;
        if !self.used.insert(author) {
            return Ok(None);
        }
        let weight = self.weights.entry(ready.root_hash.clone()).or_insert(0);
        *weight += committee.stake(&author);
        if *weight >= committee.quorum_threshold() {
            return Ok(Some(ready.root_hash));
        }
        Ok(None)
    }
}

struct TCMaker {
    weight: Stake,
    votes: Vec<(PublicKey, Signature, Round)>,
    used: HashSet<PublicKey>,
}

impl TCMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        timeout: Timeout,
        committee: &Committee,
    ) -> ConsensusResult<Option<TC>> {
        let author = timeout.author;

        // Ensure it is the first time this authority votes.
        if !self.used.insert(author) {
            return Ok(None);
        }

        // Add the timeout to the accumulator.
        self.votes
            .push((author, timeout.signature, timeout.high_qc.round));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures TC is only created once.
            return Ok(Some(TC {
                round: timeout.round,
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}
