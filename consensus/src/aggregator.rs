use crate::config::{Committee, Stake};
use crate::consensus::Round;
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::{Timeout, Vote, QC, TC, Ready, Decide};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, Signature};
use std::collections::{HashMap, HashSet};

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

pub struct Aggregator {
    committee: Committee,
    // Track votes per round. For each round we keep (accumulated weight, map author->Vote).
    votes_aggregators: HashMap<Round, (Stake, HashMap<PublicKey, Vote>)>,
    ready_aggregators: HashMap<Round, (Stake, HashMap<PublicKey, Ready>)>,
    decide_aggregators: HashMap<Round, (Stake, HashMap<PublicKey, Decide>)>,
    timeouts_aggregators: HashMap<Round, (u32, HashMap<PublicKey, Timeout>)>,
}

impl Aggregator {
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            votes_aggregators: HashMap::new(),
            ready_aggregators: HashMap::new(),
            decide_aggregators: HashMap::new(),
            timeouts_aggregators: HashMap::new(),
        }
    }

    // Append a vote for the given round. Returns Ok(true) when accumulated stake for
    // that round reaches committee.quorum_threshold().
    pub fn add_vote(&mut self, vote: Vote) -> ConsensusResult<bool> {
        // TODO [issue #7]: A bad node may make us run out of memory by sending many votes
        // with different round numbers.

        let round_entry = self
            .votes_aggregators
            .entry(vote.round)
            .or_insert_with(|| (0 as Stake, HashMap::new()));

        let weight = &mut round_entry.0;
        let votes_map = &mut round_entry.1;

        let author = vote.author;

        // Ensure it is the first time this authority votes in this round.
        ensure!(
            !votes_map.contains_key(&author),
            ConsensusError::AuthorityReuse(author)
        );

        // Record the vote and update accumulated stake for the round.
        votes_map.insert(author, vote);
        *weight += self.committee.stake(&author);

        if *weight >= self.committee.quorum_threshold() {
            *weight = 0; // Ensures quorum is only reported once for this round.
            return Ok(true);
        }
        Ok(false)
    }

    pub fn add_ready(&mut self, ready: Ready) -> ConsensusResult<bool> {
        // TODO [issue #7]: A bad node may make us run out of memory by sending many votes
        // with different round numbers.

        let round_entry = self
            .ready_aggregators
            .entry(ready.round)
            .or_insert_with(|| (0 as Stake, HashMap::new()));

        let weight = &mut round_entry.0;
        let ready_map = &mut round_entry.1;

        let author = ready.author;

        // Ensure it is the first time this authority votes in this round.
        ensure!(
            !ready_map.contains_key(&author),
            ConsensusError::AuthorityReuse(author)
        );

        // Record the vote and update accumulated stake for the round.
        ready_map.insert(author, ready);
        *weight += self.committee.stake(&author);

        if *weight >= self.committee.quorum_threshold() {
            *weight = 0; // Ensures quorum is only reported once for this round.
            return Ok(true);
        }
        Ok(false)
    }

    pub fn add_decide(&mut self, decide: Decide) -> ConsensusResult<bool> {
        let round_entry = self
            .decide_aggregators
            .entry(decide.round)
            .or_insert_with(|| (0 as Stake, HashMap::new()));

        let weight = &mut round_entry.0;
        let decide_map = &mut round_entry.1;

        let author = decide.author;

        // Ensure it is the first time this authority votes in this round.
        ensure!(
            !decide_map.contains_key(&author),
            ConsensusError::AuthorityReuse(author)
        );

        // Record the vote and update accumulated stake for the round.
        decide_map.insert(author, decide);
        *weight += self.committee.stake(&author);

        if *weight >= self.committee.quorum_threshold() {
            *weight = 0; // Ensures quorum is only reported once for this round.
            return Ok(true);
        }
        Ok(false)
    }

    pub fn add_timeout(&mut self, timeout: Timeout) -> ConsensusResult<bool> {
        let round_entry = self
            .timeouts_aggregators
            .entry(timeout.round)
            .or_insert_with(|| (0, HashMap::new()));

        let weight = &mut round_entry.0;
        let timeout_map = &mut round_entry.1;

        let author = timeout.author;

        // Ensure it is the first time this authority votes in this round.
        ensure!(
            !timeout_map.contains_key(&author),
            ConsensusError::AuthorityReuse(author)
        );

        // Record the vote and update accumulated stake for the round.
        timeout_map.insert(author, timeout);
        *weight += 1;

        if *weight >= self.committee.quorum_threshold() {
            *weight = 0; // Ensures quorum is only reported once for this round.
            return Ok(true);
        }
        Ok(false)
    }

    pub fn cleanup(&mut self, round: &Round) {
        self.votes_aggregators.retain(|k, _| k >= round);
        self.timeouts_aggregators.retain(|k, _| k >= round);
        self.ready_aggregators.retain(|k, _| k >= round);
        self.decide_aggregators.retain(|k, _| k >= round);
    }
}
