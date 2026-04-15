// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Timeout, TimeoutCert, Vote, Support};
use blsttc::{PublicKeyShareG2, SignatureShareG1};
use config::{Committee, Stake};
use crypto::{aggregate_sign, PublicKey, Signature};
use log::debug;
use std::collections::HashSet;

/// Aggregates votes for a particular header into a certificate.
pub struct VotesAggregator {
    weight: Stake,
    votes: Vec<(PublicKeyShareG2, SignatureShareG1)>,
    used: HashSet<PublicKey>,
    agg_sign: SignatureShareG1,
    pk_bit_vec: Vec<u128>,
    sorted_keys: Vec<PublicKeyShareG2>,
}

impl VotesAggregator {
    pub fn new(sorted_keys: Vec<PublicKeyShareG2>, total_nodes: usize) -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
            agg_sign: SignatureShareG1::default(),
            pk_bit_vec: vec![u128::MAX; (total_nodes + 127) / 128],
            sorted_keys,
        }
    }

    pub fn append(&mut self, vote: &Vote, committee: &Committee) -> DagResult<Option<Certificate>> {
        let author = vote.author;
        let author_bls = committee.get_bls_public_g2(&author);

        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.votes.push((author_bls, vote.signature));
        self.weight += committee.stake(&author);

        let id = self.sorted_keys.binary_search(&author_bls).unwrap();
        let chunk = id / 128;
        let bit = id % 128;
        //adding it to bitvec
        self.pk_bit_vec[chunk] &= !(1 << bit);

        if self.votes.len() == 1 {
            self.agg_sign = vote.signature;
        } else if self.votes.len() >= 2 {
            let new_agg_sign = aggregate_sign(&self.agg_sign, &vote.signature);
            self.agg_sign = new_agg_sign;
        }

        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures quorum is only reached once.

            return Ok(Some(Certificate {
                header_id: vote.id,
                round: vote.round,
                origin: vote.origin,
                votes: (self.pk_bit_vec.clone(), self.agg_sign),
            }));
        }
        Ok(None)
    }
}

/// Aggregate certificates and supports and check if we reach a quorum.
pub struct CertificatesAggregator {
    weight: Stake,
    certificates: Vec<Certificate>,
    supports: Vec<Support>,
    used: HashSet<PublicKey>,
    certificate_weight: Stake,
}

impl CertificatesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            certificates: Vec::new(),
            supports: Vec::new(),
            used: HashSet::new(),
            certificate_weight: 0,
        }
    }

    pub fn append_certificate(
        &mut self,
        certificate: &Certificate,
        committee: &Committee,
        propose_num: usize,
    ) -> DagResult<Option<Vec<Certificate>>> {
        let origin = certificate.origin();

        // Ensure it is the first time this authority votes.
        if !self.used.insert(origin) {
            return Ok(None);
        }

        let round = certificate.round;

        self.certificates.push(certificate.clone());
        self.weight += committee.stake(&origin);
        self.certificate_weight += committee.stake(&origin);

        let leader = committee.leader(round as usize);
        // if !self.used.contains(&leader) {
        //     return Ok(None);
        // }
        // Enter round if 1) weight >= 2f+1 - votes number
        // and 2) weight >= max (propose_num - f, 0)
        if self.weight >= committee.quorum_threshold()
            && self.used.contains(&leader)
        {
            std::thread::sleep(std::time::Duration::from_millis(50));
            self.weight = 0;
            return Ok(Some(self.certificates.drain(..).collect()));
        }
        Ok(None)
    }

    pub fn append_support(        
        &mut self,
        support: &Support,
        committee: &Committee,
        propose_num: usize,
    ) -> DagResult<Option<Vec<Certificate>>> {
        let origin = support.author;

        // Ensure it is the first time this authority votes.
        if !self.used.insert(origin) {
            return Ok(None);
        }

        let round = support.round;

        self.supports.push(support.clone());
        self.weight += committee.stake(&origin);

        let leader = committee.leader(round as usize);
        // if !self.used.contains(&leader) {
        //     return Ok(None);
        // }
        // Enter round if 1) weight >= 2f+1 - votes number
        // and 2) certificate_weight >= max (propose_num - f, 0)
        if self.weight >= committee.quorum_threshold()
            && self.used.contains(&leader)
        {
            std::thread::sleep(std::time::Duration::from_millis(50));
            self.weight = 0;
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
