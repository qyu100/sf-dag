// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{HeaderInfo, Certificate, Header, Timeout, TimeoutCert, Vote, NoVoteMsg, NoVoteCert};
use config::{Committee, Stake};
use crypto::PublicKey;
use std::collections::HashSet;

pub struct ThresholdAggregator {
    weight: Stake,
    used: HashSet<PublicKey>,
}

impl ThresholdAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            used: HashSet::new(),
        }
    }

    pub fn append(&mut self, author: PublicKey, committee: &Committee) -> DagResult<Stake> {
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));
        self.weight += committee.stake(&author);
        Ok(self.weight)
    }

    pub fn check_threshold(&self, threshold: Stake) -> bool {
        self.weight >= threshold
    }

    pub fn authors(&self) -> &HashSet<PublicKey> {
        &self.used
    }
}
/// Aggregate headers and check if we reach a quorum.
pub struct HeadersAggregator {
    weight: Stake,
    header_infos: Vec<HeaderInfo>,
    used: HashSet<PublicKey>,
}

impl HeadersAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            header_infos: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        header_info: HeaderInfo,
        committee: &Committee,
    ) -> DagResult<Option<Vec<HeaderInfo>>> {
        let author = header_info.author;

        if !self.used.insert(author) {
            return Ok(None);
        }

        self.header_infos.push(header_info.clone());
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            return Ok(Some(self.header_infos.drain(..).collect()));
        }
        Ok(None)
    }
}


