// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Ready, Timeout, TimeoutCert, Echo, Decide};
use config::{Committee, Stake};
use crypto::{PublicKey, Digest};
use crypto::Signature;
use log::debug;
use std::collections::{HashSet, HashMap};

pub struct EchoAggregator {
    weight: Stake,
    used: HashSet<PublicKey>,
}

impl EchoAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            used: HashSet::new(),
        }
    }

    pub fn append(&mut self, echo: &Echo, committee: &Committee) -> DagResult<Option<Certificate>> {
        let author = echo.author;
        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));
        self.weight += committee.stake(&author);
        if self.weight >= committee.optimistic_threshold() {
            self.weight = 0; // Ensures quorum is only reached once.

            return Ok(Some(Certificate {
                header_id: echo.id,
                round: echo.round,
                origin: echo.origin,
            }));
        }
        Ok(None)
    }
}

pub struct ReadyAggregator {
    weight: Stake,
    used: HashSet<PublicKey>,
}

impl ReadyAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        ready: &Ready,
        committee: &Committee,
    ) -> DagResult<Option<Certificate>> {
        let author = ready.author;
        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0;
            return Ok(Some(Certificate {
                header_id: ready.id,
                round: ready.round,
                origin: ready.origin,
            }));
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
    timeouts: Vec<PublicKey>,
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

        self.timeouts.push((author));
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
