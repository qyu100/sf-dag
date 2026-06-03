#![allow(dead_code)]
#![allow(unused_variables)]
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::aggregators::{CutVoteAggregator, DecideAggregator, QCMaker, TCMaker, VoteAggregator};
//use crate::common::special_header;
use crate::error::{DagError, DagResult};
use crate::leader::LeaderElector;
use crate::messages::{
    Certificate, ConsensusMessage, Header, Proposal, Timeout, Vote, TC, CommitQC, ConsensusRequest, ConsensusVote, Cut, CutProposal, CutCertificate, CutVote, Decide,
};
use crate::primary::{Height, PrimaryMessage, PrimaryMessageRef, Slot, View};
use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use bytes::Bytes;
use config::Committee;
use crypto::{Digest, PublicKey, SignatureService};
use crypto::Hash as _;
use futures::stream::FuturesUnordered;
use futures::Future;
use log::{debug, error, warn};
use network::{CancelHandler, ReliableSender};
use core::panic;
//use tokio::time::error::Elapsed;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
//use std::task::Poll;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
//use tokio::time::{sleep, Duration, Instant};

// fn collect_uncommitted_cut_chain(
//     tip_cut: Digest,
//     cut_parents: &HashMap<Digest, Digest>,
//     committed_cuts: &HashSet<Digest>,
// ) -> Vec<Digest> {
//     let mut chain: Vec<Digest> = Vec::new();
//     let mut cursor = tip_cut;

//     while cursor != Digest::default() && !committed_cuts.contains(&cursor) {
//         chain.push(cursor.clone());
//         cursor = cut_parents.get(&cursor).cloned().unwrap_or_default();
//     }

//     chain.reverse();
//     chain
// }

pub struct Core {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Handles synchronization with other nodes and our workers.
    synchronizer: Synchronizer,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Height,

    /// Receiver for dag messages (headers, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<crate::messages::HeaderInfo>,
    /// Receives loopback instances from the 'HeaderWaiter'
    rx_header_waiter_instances: Receiver<(ConsensusMessage, crate::messages::HeaderInfo)>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<Header>,
    // Output all certificates to the consensus Dag view
    tx_committer: Sender<ConsensusMessage>,
    /// Sends observed/formed certificates to the committer for commit-time checks.
    tx_committer_cert: Sender<Certificate>,

    /// Send a valid parent certificate to the `Proposer` 
    tx_proposer: Sender<Certificate>,
    // Receive sync requests for headers required at the consensus layer
    rx_request_header_sync: Receiver<Digest>,

    /// The last garbage collected round.
    gc_round: Height,

    /// The authors of the last voted headers. (Ensures only voting for one header per round)
    last_voted: HashMap<Height, HashSet<PublicKey>>,
    /// The last header we proposed (for which we are waiting votes).
    // current_header: Header,
    // Whether we have already sent certificate to proposer
    sent_cert_to_proposer: bool,

    // /// Aggregates votes into a certificate.
    votes_aggregator: VoteAggregator,

    network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Height, Vec<CancelHandler>>,
    consensus_cancel_handlers: HashMap<Slot, Vec<CancelHandler>>,

    current_proposal_tips: HashMap<PublicKey, Proposal>,
    current_certified_tips: HashMap<PublicKey, Proposal>,
    cut_vote_aggregators: HashMap<Digest, CutVoteAggregator>,
    cut_proposals: HashMap<Digest, CutProposal>,
    pending_cut_children: HashMap<Digest, Vec<CutProposal>>,
    cut_parents: HashMap<Digest, Digest>,
    cut_round_by_id: HashMap<Digest, u64>,
    leader_cut_by_round: HashMap<u64, Digest>,
    cut_certificates: HashMap<u64, CutCertificate>,
    decide_aggregators: HashMap<(u64, Digest), DecideAggregator>,
    decides_by_round: HashMap<u64, Decide>,
    voted_cut_rounds: HashSet<u64>,
    proposed_cut_rounds: HashSet<u64>,
    sent_decide_rounds: HashSet<u64>,
    sent_commit_rounds: HashSet<u64>,
    cut_round: u64,
    highest_certified_cut: Digest,
    committed_cuts: HashSet<Digest>,
    last_committed_cut_round: u64,

    consensus_instances: HashMap<(Slot, Digest), ConsensusMessage>,
    views: HashMap<Slot, View>,
    timers: HashSet<(Slot, View)>,
    last_voted_consensus: HashSet<(Slot, View)>,
    timer_futures: FuturesUnordered<Pin<Box<dyn Future<Output = (Slot, View)> + Send>>>,
    // TODO: Add garbage collection, related to how deep pipeline (parameter k)
    high_proposals: HashMap<Slot, ConsensusMessage>,
    high_qcs: HashMap<Slot, ConsensusMessage>, // NOTE: Store the latest QC for each slot
    qc_makers: HashMap<(Slot, Digest), QCMaker>,
    // pqc_makers: HashMap<(Slot, View), QCMaker>,
    // cqc_makers: HashMap<(Slot, View), QCMaker>,
    current_qcs_formed: usize,
    tc_makers: HashMap<(Slot, View), TCMaker>,
    prepare_tickets: VecDeque<ConsensusMessage>,
    already_proposed_slots: HashSet<Slot>,
    tx_info: Sender<ConsensusMessage>,
    leader_elector: LeaderElector,
    timeout_delay: u64,
    // GC the vote aggregators and current headers
    // gc_map: HashMap<Round, Digest>,
  
    committed_slots: HashMap<Slot, CommitQC>,
    last_committed_slot: u64, 
    //TODO: if we are not enforcing a ticket, then only start when we committed all instances < s-k.
    // If we just check that s-k is committed, but all it's predecessors are not, then we may still open an arbitrary number of instances in the absolute worst case
                                                                                // E.g. s-1 has not committed, but s has, so we can open s+k 

    //Configuration options: //TODO: Move to Primary level -> make configurable from main.rs
    use_fast_path: bool,           //default = false
    use_optimistic_tips: bool,     //default = true (TODO: implement non optimistic tip option)
    use_parallel_proposals: bool,  //default = true (TODO: implement sequential slot option)
    k: u64, //limit k on number of open honest instances (k+f instances can be open) => if require QC, then hard limit to k.
    fast_path_timeout: u64,

    use_ride_share: bool,
    car_timeout: u64,
    car_timer_futures: FuturesUnordered<Pin<Box<dyn Future<Output = Vote> + Send>>>,
    fast_timer_futures: FuturesUnordered<Pin<Box<dyn Future<Output = ConsensusVote> + Send>>>, // Use this one for Fast Path on external Consensus case

    //asynchrony simulation,
    simulate_asynchrony: bool,
    asynchrony_start: u64,
    asynchrony_duration: u64,
    during_simulated_asynchrony: bool,
    async_timer_futures: FuturesUnordered<Pin<Box<dyn Future<Output = (Slot, View)> + Send>>>,
    current_time: Instant,
    async_delayed_prepare: Option<ConsensusMessage>,
    processing_vote_aggregators: HashMap<Digest, VoteAggregator>,
    rx_certificate_waiter: Receiver<Certificate>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        synchronizer: Synchronizer,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Height,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<crate::messages::HeaderInfo>,
        rx_header_waiter_instances: Receiver<(ConsensusMessage, crate::messages::HeaderInfo)>,
        rx_proposer: Receiver<Header>,
        tx_committer: Sender<ConsensusMessage>,
        tx_committer_cert: Sender<Certificate>,
        tx_proposer: Sender<Certificate>,
        rx_request_header_sync: Receiver<Digest>,
        tx_info: Sender<ConsensusMessage>,
        leader_elector: LeaderElector,
        timeout_delay: u64,
        use_optimistic_tips: bool,
        use_parallel_proposals: bool,
        k: u64,
        use_fast_path: bool,
        fast_path_timeout: u64,
        use_ride_share: bool,
        car_timeout: u64,

        simulate_asynchrony: bool,
        asynchrony_start: u64,
        asynchrony_duration: u64,
        rx_certificate_waiter: Receiver<Certificate>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                //current_header: Header::genesis(&committee),
                committee,
                store,
                synchronizer,
                consensus_round,
                gc_depth,
                rx_primaries,
                rx_header_waiter,
                rx_header_waiter_instances,
                rx_proposer,
                tx_committer,
                tx_committer_cert,
                tx_proposer,
                rx_request_header_sync,
                tx_info,
                leader_elector,
                gc_round: 0,
                current_qcs_formed: 0,
                sent_cert_to_proposer: false,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                // current_header: Header::default(),
                votes_aggregator: VoteAggregator::new(),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                consensus_cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                already_proposed_slots: HashSet::new(),
                current_proposal_tips: HashMap::with_capacity(2 * gc_depth as usize),
                current_certified_tips: HashMap::with_capacity(2 * gc_depth as usize),
                cut_vote_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                cut_proposals: HashMap::with_capacity(2 * gc_depth as usize),
                pending_cut_children: HashMap::with_capacity(2 * gc_depth as usize),
                cut_parents: HashMap::with_capacity(2 * gc_depth as usize),
                cut_round_by_id: HashMap::with_capacity(2 * gc_depth as usize),
                leader_cut_by_round: HashMap::with_capacity(2 * gc_depth as usize),
                cut_certificates: HashMap::with_capacity(2 * gc_depth as usize),
                decide_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                decides_by_round: HashMap::with_capacity(2 * gc_depth as usize),
                voted_cut_rounds: HashSet::with_capacity(2 * gc_depth as usize),
                proposed_cut_rounds: HashSet::with_capacity(2 * gc_depth as usize),
                sent_decide_rounds: HashSet::with_capacity(2 * gc_depth as usize),
                sent_commit_rounds: HashSet::with_capacity(2 * gc_depth as usize),
                cut_round: 1,
                highest_certified_cut: Digest::default(),
                committed_cuts: HashSet::with_capacity(2 * gc_depth as usize),
                last_committed_cut_round: 0,
                consensus_instances: HashMap::with_capacity(2 * gc_depth as usize),
                views: HashMap::with_capacity(2 * gc_depth as usize),
                timers: HashSet::with_capacity(2 * gc_depth as usize),
                last_voted_consensus: HashSet::with_capacity(2 * gc_depth as usize),
                high_qcs: HashMap::with_capacity(2 * gc_depth as usize),
                high_proposals: HashMap::with_capacity(2 * gc_depth as usize),
                qc_makers: HashMap::with_capacity(2 * gc_depth as usize),
                // pqc_makers: HashMap::with_capacity(2 * gc_depth as usize),
                // cqc_makers: HashMap::with_capacity(2 * gc_depth as usize),
                tc_makers: HashMap::with_capacity(2 * gc_depth as usize),
                prepare_tickets: VecDeque::with_capacity(2 * gc_depth as usize),
                timeout_delay,
                timer_futures: FuturesUnordered::new(),
                //gc_map: HashMap::with_capacity(2 * gc_depth as usize),
                
                committed_slots: HashMap::with_capacity(2 * gc_depth as usize),
                last_committed_slot: 0,
                
                use_fast_path,           //default = true
                use_optimistic_tips,     //default = true (TODO: implement non optimistic tip option)
                use_parallel_proposals,    //default = true (TODO: implement sequential slot option)
                k,
                fast_path_timeout,
                use_ride_share,
                car_timeout,
                car_timer_futures: FuturesUnordered::new(),
                fast_timer_futures: FuturesUnordered::new(),

                simulate_asynchrony,
                asynchrony_start,
                asynchrony_duration,
                during_simulated_asynchrony: false,
                async_timer_futures: FuturesUnordered::new(),
                current_time: Instant::now(),
                async_delayed_prepare: None,
                processing_vote_aggregators: HashMap::new(),
                rx_certificate_waiter,
            }
            .run()
            .await;
        });
    }

    async fn process_own_header(&mut self, mut header: Header) -> DagResult<()> {
        //println!("Received own header");
        debug!("Processing own header {:?}", header);

        // Indicate that we haven't sent a cert yet for this header
        self.sent_cert_to_proposer = false;

        // Reset the votes aggregator.
        self.votes_aggregator = VoteAggregator::new();
        self.current_proposal_tips.insert(header.origin(), Proposal {header_digest: header.digest(), height: header.height(),}); 

        // Broadcast the new header in a reliable manner.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        let bytes = bincode::serialize(&PrimaryMessageRef::Header(&header, false))
            .expect("Failed to serialize our own header");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(header.height)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Process the header.
        self.process_header(header, false).await
    }

    #[async_recursion]
    async fn process_header(&mut self, header: Header, sync: bool) -> DagResult<()> {
        debug!("Processing Header:  {:?}", header);
        debug!("Processing the header with height {:?}", header.height);

        if header.height != 1 {
            let parent = self
                .synchronizer
                .get_parent(&header)
                .await?;
            if parent.is_none() {
                debug!(
                    "Processing of {} suspended: missing parent",
                    header.id
                );
                return Ok(());
            }
        }

        // Store the header since we have the parents (recursively).
        let bytes = bincode::serialize(&header).expect("Failed to serialize header");
        self.store.write(header.digest().to_vec(), bytes).await;

        // If the header received is at a greater height then add it to our local tips and proposals
        if header.height() > self.current_proposal_tips.get(&header.origin()).unwrap().height {
            self.current_proposal_tips.insert(
                header.origin(),
                Proposal {
                    header_digest: header.digest(),
                    height: header.height(),
                },
            );
            debug!("updating tip");
        }
        if self
            .last_voted
            .entry(header.height())
            .or_insert_with(HashSet::new)
            .insert(header.author)
        {
            let vote = Vote::new(&header, &self.name).await;
            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, x)| x.primary_to_primary)
                .collect();
            let bytes = bincode::serialize(&PrimaryMessage::Vote(vote.clone()))
                .expect("Failed to serialize our own vote");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(header.height)
                .or_insert_with(Vec::new)
                .extend(handlers);

            self.process_vote(vote)
                .await
                .expect("Failed to process our own vote");
        }
        Ok(())
    }

    
    async fn process_vote(&mut self, vote: Vote) -> DagResult<()> {
        debug!("Processing vote: {:?}", vote);

        if !self.processing_vote_aggregators.contains_key(&vote.id) {
            self.processing_vote_aggregators
                .entry(vote.id.clone())
                .or_insert(VoteAggregator::new());
        }

        // // Add it to the votes' aggregator and try to make a new certificate.
        if let Some(vote_aggregator) = self.processing_vote_aggregators.get_mut(&vote.id) {
            let use_block_threshold = vote.origin != self.name;

            if let Some(certificate) =
                vote_aggregator.append(&vote, &self.committee, use_block_threshold)?
            {
                // Process the new certificate.
                let _ = self.process_certificate(certificate).await;
            }
        }

        Ok(())
    }

    async fn process_cut_vote(&mut self, vote: CutVote) -> DagResult<()> {
        vote.verify(&self.committee)?;

        if !self.cut_vote_aggregators.contains_key(&vote.cut_id) {
            self.cut_vote_aggregators
                .entry(vote.cut_id.clone())
                .or_insert_with(CutVoteAggregator::new);
        }

        if let Some(aggregator) = self.cut_vote_aggregators.get_mut(&vote.cut_id) {
            if let Some(certificate) = aggregator.append(&vote, &self.committee)? {
                let addresses = self
                    .committee
                    .others_primaries(&self.name)
                    .iter()
                    .map(|(_, x)| x.primary_to_primary)
                    .collect();
                let bytes = bincode::serialize(&PrimaryMessage::CutCertificate(certificate.clone()))
                    .expect("Failed to serialize cut certificate");
                let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                self.consensus_cancel_handlers
                    .entry(vote.round)
                    .or_default()
                    .extend(handlers);
                self.process_cut_certificate(certificate).await?;
            }
        }

        Ok(())
    }

    #[async_recursion]
    async fn process_cut_proposal(&mut self, proposal: CutProposal) -> DagResult<()> {
        debug!("Processing cut proposal: {:?}", proposal);
        let mut queue = VecDeque::from([proposal]);
        while let Some(proposal) = queue.pop_front() {
            proposal.verify(&self.committee)?;
            let expected_leader = self.leader_elector.get_leader(proposal.round);
            ensure!(proposal.proposer == expected_leader, DagError::InvalidHeaderId);

            if !self.parent_cut_ready(&proposal) {
                self.pending_cut_children
                    .entry(proposal.parent_cut.clone())
                    .or_default()
                    .push(proposal);
                continue;
            }

            let cut_id = proposal.id();
            if self.cut_proposals.contains_key(&cut_id) {
                continue;
            }

            let round = proposal.round;
            let cut_id = self.record_cut_proposal(proposal);
            self.leader_cut_by_round
                .entry(round)
                .or_insert(cut_id.clone());

            if let Some(children) = self.pending_cut_children.remove(&cut_id) {
                queue.extend(children);
            }

            if self.voted_cut_rounds.insert(round) {
                let vote = CutVote {
                    round,
                    cut_id: cut_id.clone(),
                    author: self.name,
                };

                let addresses = self
                    .committee
                    .others_primaries(&self.name)
                    .iter()
                    .map(|(_, x)| x.primary_to_primary)
                    .collect();
                let bytes = bincode::serialize(&PrimaryMessage::CutVote(vote.clone()))
                    .expect("Failed to serialize cut vote");
                let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                self.consensus_cancel_handlers
                    .entry(round)
                    .or_default()
                    .extend(handlers);
                self.process_cut_vote(vote).await?;
            }

            self.try_commit_round(round).await;
        }
        Ok(())
    }

    fn parent_cut_ready(&self, proposal: &CutProposal) -> bool {
        if proposal.round == 1 {
            return proposal.parent_cut == Digest::default();
        }

        self.cut_proposals.contains_key(&proposal.parent_cut)
            || self.committed_cuts.contains(&proposal.parent_cut)
    }

    fn parent_cut_certified(&self, round: u64, parent_cut: &Digest) -> bool {
        if round == 1 {
            return *parent_cut == Digest::default();
        }

        self.cut_certificates
            .get(&(round - 1))
            .map(|certificate| certificate.cut_id == *parent_cut)
            .unwrap_or(false)
    }


    #[async_recursion]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        // Ensure we have all the ancestor of this certificate yet. If we don't, the synchronizer will gather it and trigger re-processing of this certificate.
        // let t_deliver = Instant::now();
        // Keep the latest certified tip per lane. Lionfish cut proposals are built from this map.
        debug!("Processing certificate: {:?}", certificate);
        self.current_certified_tips.insert(
            certificate.origin(),
            Proposal {
                header_digest: certificate.header_id.clone(),
                height: certificate.height(),
            },
        );

        // Feed committer with certificates so commit decisions are backed by certified headers.
        if let Err(e) = self.tx_committer_cert.send(certificate.clone()).await {
            debug!("Failed to send certificate to committer cache: {}", e);
        }
        
        // Store the certificate.
        // let t_store = Instant::now();
        // let bytes = bincode::serialize(&certificate).expect("Failed to serialize certificate");
        // self.store.write(certificate.digest().to_vec(), bytes).await;
        // debug!("certificate length: {}", bytes.len());
        // debug!("store certificate time: {:?}", t_store.elapsed());

        // Send it to the `Proposer`.
        if certificate.origin() == self.name {
            self.tx_proposer
                .send(certificate.clone())
                .await
                .expect("Failed to send certificate");
        }
        self.try_propose_cut_for_current_round().await?;
        Ok(())
    }

    fn current_cut(&self) -> Cut {
        let mut cut = BTreeMap::new();
        for (author, proposal) in &self.current_certified_tips {
            cut.insert(*author, proposal.clone());
        }
        cut
    }

    fn make_cut_proposal(&self, round: u64, parent_cut: Digest) -> CutProposal {
        CutProposal {
            round,
            proposer: self.name,
            parent_cut,
            tips: self.current_cut(),
        }
    }

    fn make_and_record_cut_proposal(&mut self, round: u64, parent_cut: Digest) -> CutProposal {
        let proposal = self.make_cut_proposal(round, parent_cut);
        self.record_cut_proposal(proposal.clone());
        proposal
    }

    fn record_cut_proposal(&mut self, proposal: CutProposal) -> Digest {
        let cut_id = proposal.id();
        self.cut_parents.insert(cut_id.clone(), proposal.parent_cut.clone());
        self.cut_round_by_id.insert(cut_id.clone(), proposal.round);
        self.cut_proposals.insert(cut_id.clone(), proposal);
        cut_id
    }

    // fn commit_cut_chain(&mut self, tip_cut: Digest) {
    //     let chain = collect_uncommitted_cut_chain(tip_cut, &self.cut_parents, &self.committed_cuts);
    //     for cut_id in chain {
    //         if self.committed_cuts.insert(cut_id.clone()) {
    //             if let Some(round) = self.cut_round_by_id.get(&cut_id).cloned() {
    //                 self.last_committed_cut_round = self.last_committed_cut_round.max(round);
    //                 debug!("Committed cut {} at round {}", cut_id, round);
    //             } else {
    //                 debug!("Committed cut {}", cut_id);
    //             }
    //         }
    //     }
    // }

    async fn process_cut_certificate(&mut self, certificate: CutCertificate) -> DagResult<()> {
        certificate.verify(&self.committee)?;
        let round = certificate.round;
        let cut_id = certificate.cut_id.clone();
        self.cut_certificates.entry(round).or_insert(certificate);
        if round + 1 >= self.cut_round {
            self.highest_certified_cut = cut_id.clone();
        }
        self.cut_round = self.cut_round.max(round + 1);

        if self.sent_decide_rounds.insert(round) {
            let decide = Decide::new(cut_id.clone(), round, &self.name, &self.name).await;
            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, x)| x.primary_to_primary)
                .collect();
            let bytes = bincode::serialize(&PrimaryMessage::Decide(decide.clone()))
                .expect("Failed to serialize decide");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.consensus_cancel_handlers
                .entry(round)
                .or_default()
                .extend(handlers);
            self.process_decide(decide).await?;
        }

        if let Some(children) = self.pending_cut_children.remove(&cut_id) {
            for child in children {
                self.process_cut_proposal(child).await?;
            }
        }

        self.try_propose_cut_for_current_round().await?;
        Ok(())
    }

    async fn process_decide(&mut self, decide: Decide) -> DagResult<()> {
        decide.verify(&self.committee)?;

        if self.decides_by_round.contains_key(&decide.round) {
            return Ok(());
        }

        let key = (decide.round, decide.id.clone());
        if !self.decide_aggregators.contains_key(&key) {
            self.decide_aggregators
                .insert(key.clone(), DecideAggregator::new());
        }

        if let Some(aggregator) = self.decide_aggregators.get_mut(&key) {
            if let Some(quorum_decide) = aggregator.append(&decide, &self.committee)? {
                self.decides_by_round
                    .entry(quorum_decide.round)
                    .or_insert(quorum_decide.clone());
                self.try_commit_round(quorum_decide.round).await;
            }
        }

        Ok(())
    }

    async fn try_commit_round(&mut self, round: u64) {
        let decide = match self.decides_by_round.get(&round) {
            Some(x) => x,
            None => return,
        };
        let leader_cut = match self.leader_cut_by_round.get(&round) {
            Some(x) => x.clone(),
            None => return,
        };

        if decide.id == leader_cut {
            self.emit_commit_to_committer(round, &leader_cut).await;
        }
    }

    async fn emit_commit_to_committer(&mut self, round: u64, cut_id: &Digest) {
        if self.sent_commit_rounds.contains(&round) {
            return;
        }

        let Some(cut) = self.cut_proposals.get(cut_id) else {
            debug!("No cut proposal found for round {} cut {}", round, cut_id);
            return;
        };

        let proposals: HashMap<PublicKey, Proposal> = cut
            .tips
            .iter()
            .map(|(pk, proposal)| (*pk, proposal.clone()))
            .collect();

        let commit_msg = ConsensusMessage::Commit {
            round,
            proposals,
        };

        if let Err(e) = self.tx_committer.send(commit_msg).await {
            debug!("Failed to send commit to committer for round {}: {}", round, e);
            return;
        }

        self.sent_commit_rounds.insert(round);
    }


    #[async_recursion]
    async fn try_propose_cut_for_current_round(&mut self) -> DagResult<()> {
        let round = self.cut_round;
        if self.name != self.leader_elector.get_leader(round) {
            return Ok(());
        }
        let parent_cut = self.highest_certified_cut.clone();
        if !self.parent_cut_certified(round, &parent_cut) {
            return Ok(());
        }
        if !self.proposed_cut_rounds.insert(round) {
            return Ok(());
        }
        debug!("Proposing cut for round {}", round);
        let proposal = self.make_cut_proposal(round, parent_cut);

        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        let bytes = bincode::serialize(&PrimaryMessage::CutProposal(proposal.clone()))
            .expect("Failed to serialize cut proposal");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.consensus_cancel_handlers
            .entry(round)
            .or_default()
            .extend(handlers);
        
        self.process_cut_proposal(proposal).await?;
        Ok(())
    }

    fn sanitize_header(&mut self, header: &Header) -> DagResult<()> {
        ensure!(
            self.gc_round <= header.height,
            DagError::HeaderTooOld(header.id.clone(), header.height)
        );

        // Verify the header's signature.
        header.verify(&self.committee)?;

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
    }

    fn sanitize_vote(&mut self, vote: &Vote) -> DagResult<()> {
        // Verify the vote.
        vote.verify(&self.committee).map_err(DagError::from)
    }

    fn sanitize_certificate(&mut self, certificate: &Certificate) -> DagResult<()> {
        ensure!(
            self.gc_round <= certificate.height(),
            DagError::CertificateTooOld(certificate.digest(), certificate.height())
        );

        //println!("Past first ensure");

        // Verify the certificate (and the embedded header).
        certificate.verify(&self.committee).map_err(DagError::from)
    }

    async fn handle_timeout(&mut self, _timeout: &Timeout) -> DagResult<()> {
        Ok(())
    }

    async fn handle_tc(&mut self, _tc: &TC) -> DagResult<()> {
        Ok(())
    }

    async fn process_forwarded_message(
        &mut self,
        _consensus_message: ConsensusMessage,
    ) -> DagResult<()> {
        Ok(())
    }

    async fn process_consensus_request(
        &mut self,
        _consensus_req: ConsensusRequest,
    ) -> DagResult<()> {
        Ok(())
    }

    async fn process_consensus_vote(
        &mut self,
        _consensus_vote: ConsensusVote,
        _sync: bool,
    ) -> DagResult<()> {
        Ok(())
    }

    async fn process_loopback(
        &mut self,
        _consensus_message: ConsensusMessage,
        _header: crate::messages::HeaderInfo,
    ) -> DagResult<()> {
        Ok(())
    }

    async fn process_header_loopback(
        &mut self,
        header_info: crate::messages::HeaderInfo,
    ) -> DagResult<()> {
        let Some(bytes) = self.store.read(header_info.id.to_vec()).await? else {
            return Err(DagError::MalformedHeader(header_info.id));
        };
        let header: Header = bincode::deserialize(&bytes)?;
        self.process_header(header, true).await
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        // Initialize current proposals with the genesis tips
        self.current_proposal_tips = Header::genesis_proposals(&self.committee);
        self.current_certified_tips = Header::genesis_proposals(&self.committee);
        debug!("genesis tips are {:?}", self.current_proposal_tips);

        // Initiate the proposer with a genesis parent
        let genesis_cert = Certificate::genesis_certs(&self.committee).get(&self.name).unwrap().clone();
        self.tx_proposer
            .send(genesis_cert)
            .await
            .expect("failed to send cert to proposer");
        let _ = self.try_propose_cut_for_current_round().await;

        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::Header(header, sync) => {
                            match self.sanitize_header(&header) {
                                Ok(()) => self.process_header(header, sync).await,
                                error => error
                            }

                        },
                        PrimaryMessage::Vote(vote) => {
                            match self.sanitize_vote(&vote) {
                                Ok(()) => {
                                    self.process_vote(vote).await
                                },
                                error => {
                                    error
                                }
                            }
                        },
                        PrimaryMessage::Certificate(certificate) => {
                            match self.sanitize_certificate(&certificate) {
                                Ok(()) => self.process_certificate(certificate).await, //self.receive_certificate(certificate).await,
                                error => {
                                    error
                                }
                            }
                        },
                        PrimaryMessage::CutProposal(proposal) => self.process_cut_proposal(proposal).await,
                        PrimaryMessage::CutVote(vote) => self.process_cut_vote(vote).await,
                        PrimaryMessage::CutCertificate(certificate) => self.process_cut_certificate(certificate).await,
                        PrimaryMessage::Decide(decide) => self.process_decide(decide).await,
                        PrimaryMessage::Timeout(timeout) => self.handle_timeout(&timeout).await,
                        PrimaryMessage::TC(tc) => self.handle_tc(&tc).await,

                        // We receive a forwarded prepare or commit message from another replica
                        PrimaryMessage::ConsensusMessage(consensus_message) => self.process_forwarded_message(consensus_message).await,
                          
                    
                        // External Consensus implementation: Receive Consensus Requests (Prep/Confirm/Commit) or Votes (Prep-Vote/Confirm-Ack)
                        PrimaryMessage::ConsensusRequest(consensus_req) => self.process_consensus_request(consensus_req).await,
                        PrimaryMessage::ConsensusVote(consensus_vote) => self.process_consensus_vote(consensus_vote, false).await,
                        _ => { debug!("Received unexpected message: {:?}", message);
                            panic!("Unexpected core message")}
                    }
                },

                Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate(certificate).await,


                // We also receive here our new headers created by the `Proposer`.
                Some(header) = self.rx_proposer.recv() => self.process_own_header(header).await,

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header) = self.rx_header_waiter.recv() => {
                    debug!("normal loopback for header");
                    self.process_header_loopback(header).await
                },

                // Loopback for committed instance that hasn't had all of it ancestors yet
                Some((consensus_message, header)) = self.rx_header_waiter_instances.recv() => self.process_loopback(consensus_message, header).await,
                //Loopback for special headers that were validated by consensus layer.
                //Some((header, consensus_sigs)) = self.rx_validation.recv() => self.create_vote(header, consensus_sigs).await,
                //i.e. core requests validation from consensus (check if ticket valid; wait to receive ticket if we don't have it yet -- should arrive: using all to all or forwarding)

                // Some(header_digest) = self.rx_request_header_sync.recv() => self.synchronizer.fetch_header(header_digest).await,



            };
            match result {
                Ok(()) => (),
                Err(DagError::StoreError(e)) => {
                    error!("{}", e);
                    panic!("Storage failure: killing node.");
                }
                Err(e @ DagError::HeaderTooOld(..)) => debug!("{}", e),
                Err(e @ DagError::VoteTooOld(..)) => debug!("{}", e),
                Err(e @ DagError::CertificateTooOld(..)) => debug!("{}", e),
                Err(e) => warn!("{}", e),
            }

            // Cleanup internal state.
            let round = self.consensus_round.load(Ordering::Relaxed);
            if round > self.gc_depth {
                let gc_round = round - self.gc_depth;
                self.last_voted.retain(|k, _| k >= &gc_round);
                //self.processing.retain(|k, _| k >= &gc_round);

                //self.current_headers.retain(|k, _| k >= &gc_round);
                //self.vote_aggregators.retain(|k, _| k >= &gc_round);

                //self.certificates_aggregators.retain(|k, _| k >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.gc_round = gc_round;
                debug!("GC round moved to {}", self.gc_round);
            }
        }
    }
}
