#![allow(dead_code)]
#![allow(unused_variables)]
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{ConsensusError, DagError, DagResult};
use crate::messages::{
    Certificate, CutCertificate, CutVote, Decide, Header, Timeout, TimeoutAccept, TimeoutCert,
    Vote, QC, TC,
};
use config::{Committee, Stake};
use crypto::{Digest, PublicKey, Signature};
use std::collections::HashSet;

pub struct VoteAggregator {
    weight: Stake,
    used: HashSet<PublicKey>,
}

impl VoteAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        vote: &Vote,
        committee: &Committee,
        use_block_threshold: bool,
    ) -> DagResult<Option<Certificate>> {
        let author = vote.author;
        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));
        self.weight += committee.stake(&author);

        let threshold = if use_block_threshold {
            committee.block_threshold()
        } else {
            committee.quorum_threshold()
        };

        if self.weight >= threshold {
            self.weight = 0; // Ensures certificate is only reached once.
            return Ok(Some(Certificate {
                header_id: vote.id.clone(),
                height: vote.height,
                origin: vote.origin,
            }));
        }

        Ok(None)
    }
}

pub struct CutVoteAggregator {
    weight: Stake,
    used: HashSet<PublicKey>,
    voters: Vec<PublicKey>,
}

pub struct DecideAggregator {
    weight: Stake,
    used: HashSet<PublicKey>,
    round: Option<u64>,
    cut_id: Option<Digest>,
}

impl DecideAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            used: HashSet::new(),
            round: None,
            cut_id: None,
        }
    }

    pub fn append(&mut self, decide: &Decide, committee: &Committee) -> DagResult<Option<Decide>> {
        if let Some(round) = self.round {
            ensure!(round == decide.round, DagError::InvalidHeaderId);
        } else {
            self.round = Some(decide.round);
        }

        if let Some(cut_id) = &self.cut_id {
            ensure!(*cut_id == decide.id, DagError::InvalidHeaderId);
        } else {
            self.cut_id = Some(decide.id.clone());
        }

        let author = decide.author;
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));
        self.weight += committee.stake(&author);

        if self.weight >= committee.quorum_threshold() {
            self.weight = 0;
            return Ok(Some(decide.clone()));
        }

        Ok(None)
    }
}

/// Aggregates timeout votes for a cut round into an accept trigger.
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
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            return Ok(Some(()));
        }
        Ok(None)
    }
}

/// Aggregates timeout accepts for a cut round into a timeout certificate.
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
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.accepts.push(author);
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            return Ok((
                self.weight,
                Some(TimeoutCert {
                    round: accept.round,
                    timeouts: std::mem::take(&mut self.accepts),
                }),
            ));
        }
        Ok((self.weight, None))
    }
}

impl CutVoteAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            used: HashSet::new(),
            voters: Vec::new(),
        }
    }

    pub fn append(
        &mut self,
        vote: &CutVote,
        committee: &Committee,
    ) -> DagResult<Option<CutCertificate>> {
        let author = vote.author;
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));
        self.voters.push(author);
        self.weight += committee.stake(&author);
        if self.weight >= committee.optimistic_threshold() {
            self.weight = 0;
            return Ok(Some(CutCertificate {
                round: vote.round,
                cut_id: vote.cut_id.clone(),
                votes: self.voters.clone(),
            }));
        }
        Ok(None)
    }
}

/// Aggregate consensus info votes and check if we reach a quorum.
pub struct QCMaker {
    weight: Stake,
    pub votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,

    pub try_fast: bool, //TODO: Configure it for Fast path (if it's a Quorummaker for Prepare)
    qc_dig: Digest,
    first: bool, //Indicate when SlowQC is first ready -> I.e. only start ONE timer.
    completed_fast: bool, //Indicate whether or not we succeeded on Fast Path. This stops timer that loopbacks from re-submitting QC
}

impl QCMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
            try_fast: false, // explicitly set it. (NOT done via constructor)
            qc_dig: Digest::default(),
            first: true,
            completed_fast: false,
        }
    }

    pub fn append(
        &mut self,
        author: PublicKey,
        vote: (Digest, Signature),
        committee: &Committee,
    ) -> DagResult<(bool, Option<QC>)> {
        //bool = QC is available. Option = Some only if QC ready to be used.
        //println!("calling append");
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));
        //println!("after ensure");

        self.votes.push((author, vote.1));
        self.weight += committee.stake(&author);
        //println!("QC weight is {:?}", self.weight);

        if self.try_fast {
            return self.check_fast_qc(vote.0, committee);
        }
        //else Slow path:
        if self.weight >= committee.quorum_threshold() {
            // Ensure QC is only made once.
            self.weight = 0;
            return Ok((
                true,
                Some(QC {
                    id: vote.0,
                    votes: self.votes.clone(),
                }),
            ));
        }

        Ok((false, None))
    }

    pub fn check_fast_qc(
        &mut self,
        vote_dig: Digest,
        committee: &Committee,
    ) -> DagResult<(bool, Option<QC>)> {
        if self.weight >= committee.fast_threshold() {
            // Ensure QC is only made once.
            self.weight = 0;
            self.completed_fast = true;
            return Ok((
                true,
                Some(QC {
                    id: vote_dig,
                    votes: self.votes.clone(),
                }),
            ));
        } else if self.weight >= committee.quorum_threshold() {
            self.qc_dig = vote_dig;
            let first = self.first;
            self.first = false;
            return Ok((first, None)); //Only say qc_ready ONCE for 2f+1 => I.e. only one timer will be started
        }

        Ok((false, None))
    }

    //Call this function to fetch slowQC after fastQC timer expires
    pub fn get_qc(&mut self) -> DagResult<(bool, Option<QC>)> {
        if self.completed_fast {
            return Ok((false, None)); //Already finished fast.
        }
        ensure!(
            self.qc_dig != Digest::default(), //I.e. SlowQC is ready!
            DagError::InvalidSlowQCRequest
        );
        return Ok((
            true,
            Some(QC {
                id: self.qc_dig.clone(),
                votes: self.votes.clone(),
            }),
        ));
    }
}

pub struct TCMaker {
    weight: Stake,
    votes: Vec<Timeout>,
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
    pub fn append(&mut self, timeout: Timeout, committee: &Committee) -> DagResult<Option<TC>> {
        let author = timeout.author;

        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        let slot = timeout.round;
        let view = timeout.round;

        // Add the timeout to the accumulator.
        self.votes.push(timeout);
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures TC is only created once.
            return Ok(Some(TC {
                slot,
                view,
                timeouts: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}
