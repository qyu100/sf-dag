// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{HeaderInfo, Certificate, Header, Timeout, TimeoutCert, Vote, NoVoteMsg, NoVoteCert};
use config::{Committee, Stake};
use crypto::PublicKey;
use log::info;
use std::collections::HashSet;

/// Aggregates votes for a particular header into a certificate.
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

    pub fn append(
        &mut self,
        vote: Vote,
        committee: &Committee,
        header: &Header,
    ) -> DagResult<Option<Certificate>> {
        let author = vote.author;

        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.votes.push(author);
        self.weight += committee.stake(&author);

        //to check if we have received vote from the current round leader
        let leader = committee.leader(vote.round as usize);
        if !self.used.contains(&leader){
            return Ok(None);
        }
        
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(Certificate {
                header: header.clone(),
                votes: self.votes.clone(),
            }));
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
        info!("Weight_append: {}", self.weight);
        info!("Quorum_threshold: {}", committee.quorum_threshold());
        if self.weight >= committee.quorum_threshold() {
            if let Some(headers) = self.header_infos.iter().find(|headers| headers.author 
                == committee.leader(header_info.round as usize))      
            {
                // self.weight = 0; // Ensures quorum is only reached once.
                return Ok(Some(self.header_infos.drain(..).collect()));
            }
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

        self.timeouts.push(author);
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

    pub fn has_quorum(&self, committee: &Committee) -> bool {
        let weight = self.weight;
        weight >= committee.quorum_threshold()
    }

}

/// Aggregates no-vote messages for a particular round into a certification.
pub struct NoVoteAggregator {
    weight: Stake,
    no_votes: Vec<PublicKey>,
    used: HashSet<PublicKey>,
}

impl NoVoteAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            no_votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        no_vote_msg: NoVoteMsg,
        committee: &Committee,
    ) -> DagResult<Option<NoVoteCert>> {
        let author = no_vote_msg.author;

        // Ensure it is the first time this authority sends a no-vote message.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.no_votes.push(author);
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            // Once quorum is reached, you might reset for the next round or use the certification as needed.
            return Ok(Some(NoVoteCert {
                round: no_vote_msg.round.clone(),
                no_votes: self.no_votes.clone(),
            })); // Return the certification that aggregates the no-votes reaching quorum.
        }
        Ok(None)
    }

    pub fn has_quorum(&self, committee: &Committee) -> bool {
        let weight = self.weight;
        weight >= committee.quorum_threshold()
    }
    
}