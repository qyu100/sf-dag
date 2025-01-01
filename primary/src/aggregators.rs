// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, Vote};
use config::{Committee, Stake};
use crypto::PublicKey;
use log::info;
use std::collections::HashSet;

// Aggregates votes for a particular header into a certificate.
pub struct VotesAggregator {
    weight: Stake,
    votes: Vec<PublicKey>,
    used: HashSet<PublicKey>,
}

impl VotesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    // pub fn append(
    //     &mut self,
    //     vote: Vote,
    //     committee: &Committee,
    //     header: &Header,
    // ) -> DagResult<Option<Certificate>> {
    //     let author = vote.author;

    //     // Ensure it is the first time this authority votes.
    //     ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

    //     self.votes.push((author, vote.signature));
    //     self.weight += committee.stake(&author);
    //     if self.weight >= committee.quorum_threshold() {
    //         self.weight = 0; // Ensures quorum is only reached once.
    //         return Ok(Some(Certificate {
    //             header: header.clone(),
    //             votes: self.votes.clone(),
    //         }));
    //     }
    //     Ok(None)
    // }
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
        certificate: Certificate,
        committee: &Committee,
    ) -> DagResult<Option<Vec<Certificate>>> {
        let origin = certificate.origin();

        // Ensure it is the first time this authority votes.
        if !self.used.insert(origin) {
            return Ok(None);
        }

        self.certificates.push(certificate);
        self.weight += committee.stake(&origin);
        if self.weight >= committee.quorum_threshold() {
            //self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(self.certificates.drain(..).collect()));
        }
        Ok(None)
    }
}


/// Aggregate headers and check if we reach a quorum.
pub struct HeadersAggregator {
    weight: Stake,
    headers: Vec<Header>,
    used: HashSet<PublicKey>,
}

impl HeadersAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            headers: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        header: Header,
        committee: &Committee,
    ) -> DagResult<Option<Vec<Header>>> {
        let author = header.author;

        if !self.used.insert(author) {
            return Ok(None);
        }

        self.headers.push(header.clone());
        self.weight += committee.stake(&author);
        // QY: happy case: parents have leader.
        if self.weight >= committee.quorum_threshold() {
            if let Some(headers) = self.headers.iter().find(|headers| headers.author 
                == committee.leader(header.round as usize))      
            {
                // self.weight = 0; // Ensures quorum is only reached once.
                return Ok(Some(self.headers.drain(..).collect()));
            }
        }
        Ok(None)
    }
}
