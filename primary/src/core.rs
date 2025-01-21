// Copyright(C) Facebook, Inc. and its affiliates.
use crate::aggregators::{
    CertificatesAggregator, NoVoteAggregator, TimeoutAggregator, VotesAggregator, HeadersAggregator 
};
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, HeaderWithParents, HeaderInfoWithParents, 
    HeaderInfo, NoVoteCert, NoVoteMsg, Timeout, TimeoutCert, EchoHeader, ReadyHeader
    ,EchoNoVoteMsg, ReadyNoVoteMsg};
use crate::primary::{HeaderMessage, HeaderType, PrimaryMessage, Round};
use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use bytes::Bytes;
use config::{Committee, Stake};
use crypto::Hash;
use crypto::{Digest, PublicKey};
use log::{debug, error, info, warn};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::Duration;

// #[cfg(test)]
// #[path = "tests/core_tests.rs"]
// pub mod core_tests;

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
    gc_depth: Round,

    // tx_primary: Sender<PrimaryMessage>,
    /// Receiver for dag messages (headers, timeouts, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<HeaderMessage>,
    /// Receives loopback certificates from the `CertificateWaiter`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<HeaderWithParents>,
    /// Receives our newly created timeouts from the `Proposer`.
    rx_timeout: Receiver<Timeout>,
    /// Receives our newly created no vote msgs from the `Proposer`.
    rx_no_vote_msg: Receiver<NoVoteMsg>,
    /// Output all certificates to the consensus layer.
    tx_consensus: Sender<Certificate>,
    /// Send valid a quorum of certificates' ids to the `Proposer` (along with their round).
    tx_proposer: Sender<(Vec<HeaderInfo>, Round)>,
    tx_timeout: Sender<Timeout>,
    /// Send a valid TimeoutCertificate along with the round to the `Proposer`.
    tx_timeout_cert: Sender<(TimeoutCert, Round)>,
    /// Send a valid NoVoteCert along with the round to the `Proposer`.
    tx_no_vote_cert: Sender<(NoVoteCert, Round)>,
    /// Send a the header that has voted for the prev leader to the `Consensus` logic.
    tx_consensus_header: Sender<Header>,
    tx_consensus_header_msg: Sender<HeaderType>,

    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    /// The last header we proposed (for which we are waiting votes).
    current_header: Header,
    /// Aggregates votes into a certificate.
    votes_aggregator: VotesAggregator,
    processing_header_infos: HashMap<Digest, (HeaderInfo, bool)>,
    processing_no_vote_msgs: HashMap<Digest, NoVoteMsg>,
    // Aggregates certificates to use as parents for new headers.
    certificates_aggregators: HashMap<Round, Box<CertificatesAggregator>>,
    // A network sender to send the batches to the other workers.
    network: ReliableSender,
    // Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
    // Aggregates timeouts to use for sending timeout certificate.
    timeouts_aggregators: HashMap<Round, Box<TimeoutAggregator>>,
    // Aggregates no vote messages to use for sending no vote certificates.
    no_vote_aggregators: HashMap<Round, Box<NoVoteAggregator>>,
    // Aggregates headers.
    header_aggregators: HashMap<Round, Box<HeadersAggregator>>,
    echo_headers: HashMap<(Round, Digest), HashSet<PublicKey>>,
    ready_headers: HashMap<(Round, Digest), HashSet<PublicKey>>,
    ready_header_sent: HashMap<(Round, Digest), bool>,
    consensus_header_sent: HashMap<(Round, Digest), bool>,
    timeout_sent: HashMap<Round, bool>,
    timeouts: HashMap<Round, HashSet<PublicKey>>,
    timeout_weight: HashMap<Round, Stake>,
    echo_no_vote_msgs: HashMap<(Round, Digest), HashSet<PublicKey>>,
    ready_no_vote_sent: HashMap<(Round, Digest), bool>,
    ready_no_vote_msgs: HashMap<(Round, Digest), HashSet<PublicKey>>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        synchronizer: Synchronizer,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<HeaderMessage>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<HeaderWithParents>,
        rx_timeout: Receiver<Timeout>,
        rx_no_vote_msg: Receiver<NoVoteMsg>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<(Vec<HeaderInfo>, Round)>,
        tx_timeout: Sender<Timeout>,
        tx_timeout_cert: Sender<(TimeoutCert, Round)>,
        tx_no_vote_cert: Sender<(NoVoteCert, Round)>,
        tx_consensus_header: Sender<Header>,
        tx_consensus_header_msg: Sender<HeaderType>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                synchronizer,
                consensus_round,
                gc_depth,
                rx_primaries,
                rx_header_waiter,
                rx_certificate_waiter,
                rx_proposer,
                rx_timeout,
                rx_no_vote_msg,
                tx_consensus,
                tx_proposer,
                tx_timeout,
                tx_timeout_cert,
                tx_no_vote_cert,
                tx_consensus_header,
                tx_consensus_header_msg,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                current_header: Header::default(),
                votes_aggregator: VotesAggregator::new(),
                processing_header_infos: HashMap::new(),
                processing_no_vote_msgs: HashMap::new(),
                certificates_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                timeouts_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                no_vote_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                header_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                echo_headers: HashMap::new(),
                ready_headers: HashMap::new(),
                ready_header_sent: HashMap::new(),
                consensus_header_sent: HashMap::new(),
                timeout_sent: HashMap::new(),
                timeouts: HashMap::new(),
                timeout_weight: HashMap::new(),
                echo_no_vote_msgs: HashMap::new(),
                ready_no_vote_sent: HashMap::new(),
                ready_no_vote_msgs: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    async fn process_own_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        // Serialize the Timeout instance into bytes using bincode or a similar serialization tool.
        let bytes = bincode::serialize(&PrimaryMessage::Timeout(timeout.clone()))
            .expect("Failed to serialize own timeout");

        // Broadcast the serialized Timeout to all other primaries.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();

        // Send the Timeout to each address.
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

        self.cancel_handlers
            .entry(timeout.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        self.timeout_sent.insert(timeout.round.clone(), true);

        // Log the broadcast for debugging purposes.
        // debug!("Broadcasted own timeout {:?} for round {}", timeout, timeout.round);

        self.process_timeout(timeout).await
    }

    async fn process_own_no_vote_msg(&mut self, no_vote_msg: NoVoteMsg) -> DagResult<()> {
        let bytes = bincode::serialize(&PrimaryMessage::NoVoteMsg(no_vote_msg.clone()))
            .expect("Failed to serialize own no_vote_msg");

        // Broadcast the serialized NoVoteMsg to all other primaries.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();

        // Send the NoVoteMsg to each address.
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

        self.cancel_handlers
            .entry(no_vote_msg.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Log the broadcast for debugging purposes.
        // debug!("Broadcasted own no_vote_msg for round {}", no_vote_msg.round);

        self.process_no_vote_msg(no_vote_msg).await
    }

    async fn process_own_header(&mut self, 
        header_with_parents: HeaderWithParents
    ) -> DagResult<()> {
        debug!("Processing own {:?}", header_with_parents);
        
        let round = header_with_parents.header.round;
        let parents = header_with_parents.parents.clone();


        let header_info= HeaderInfo::create_from(&header_with_parents.header);
        // Broadcast the new header in a reliable manner.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();

        let header_msg = HeaderMessage::HeaderWithParents(header_with_parents);
        let bytes = bincode::serialize(&PrimaryMessage::HeaderMsg(header_msg))
            .expect("Failed to serialize our own header");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        let header_info_with_parents = HeaderInfoWithParents {
            header_info,
            parents,
        };

        let header_info_msg: HeaderMessage =
            HeaderMessage::HeaderInfoWithParents(header_info_with_parents);

        // Process the header.
        self.process_header(&header_info_msg).await
    }

    #[async_recursion]
    async fn process_header(
        &mut self,
        header_msg: &HeaderMessage,
    ) -> DagResult<()> {
        debug!("Processing {:?}", header_msg);

        let header_info: HeaderInfo;
        match header_msg {
            HeaderMessage::HeaderWithParents(header_with_parents) => {
                header_info = HeaderInfo::create_from(&header_with_parents.header);
            }
            HeaderMessage::HeaderInfoWithParents(header_info_with_parents) => {
                header_info = header_info_with_parents.header_info.clone();
            }
            HeaderMessage::Header(header) => {
                header_info = HeaderInfo::create_from(&header);
            }
            HeaderMessage::HeaderInfo(h_info) => {
                header_info = h_info.clone();
            }
        }

        // Ensure we have the parents. If at least one parent is missing, the synchronizer returns an empty
        // vector; it will gather the missing parents (as well as all ancestors) from other nodes and then
        // reschedule processing of this header.
        let mut has_leader = true;

        if header_info.round != 1 {
            let parents = self.synchronizer.get_parents(&HeaderType::HeaderInfo(header_info.clone())).await?;
            
            if parents.is_empty() {
                debug!("Processing of {} suspended: missing parent(s)", header_info.id);
                return Ok(());
            }
            // Ensure the parents form a quorum and are all from the previous round.
            let mut stake = 0;

            for parent in &parents {
                let parent_header_info: HeaderInfo;
                match parent {
                    HeaderType::Header(header) => {
                        parent_header_info = HeaderInfo::create_from(&header);
                    }
                    HeaderType::HeaderInfo(h_info) => {
                        parent_header_info = h_info.clone();
                    }
                }
                ensure!(
                    parent_header_info.round + 1 == header_info.round,
                    DagError::MalformedHeader(header_info.id.clone())
                );
                stake += self.committee.stake(&parent_header_info.author);

                has_leader = has_leader
                    || self
                        .committee
                        .leader((header_info.round - 1) as usize)
                        .eq(&parent_header_info.author);
            }
            // info!("stake: {:?}", stake);
            ensure!(
                stake >= self.committee.quorum_threshold(),
                DagError::HeaderRequiresQuorum(header_info.id.clone())
            );
        }
        self.processing_header_infos
            .entry(header_info.id)
            .or_insert((header_info.clone(), has_leader));
        // Store the header.
        let hid = header_info.id;
        let header_type = HeaderType::HeaderInfo(header_info.clone());
        let bytes = bincode::serialize(&header_type).expect("Failed to serialize header");
        self.store.write(hid.to_vec(), bytes).await;
        
        // Send <ECHO, H(m)> to primaries.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();

        let echo_header = EchoHeader::new(&header_info.clone(), &self.name).await;
        let bytes = bincode::serialize(&PrimaryMessage::Echo(echo_header))
            .expect("Failed to serialize EchoHeader");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

        self.cancel_handlers
            .entry(header_info.clone().round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Initialize the HashMap if it doesn't exist
        self.echo_headers
            .entry((header_info.clone().round, header_info.clone().id))
            .or_insert_with(HashSet::new)
            .insert(self.name.clone());

        // Log the broadcast for debugging purposes
        // debug!("Broadcasted EchoHeader with hash {:?} by {:?} for origin {:?}", header_info.clone().round, self.name, header_info.clone().author);

        Ok(())
    }

    #[async_recursion]
    async fn process_echo_header(&mut self, echo_header: EchoHeader) -> DagResult<()> {
        // debug!("Processing {:?}", echo_header);

        let round = echo_header.round;
        let digest = echo_header.id.clone();
        let author = echo_header.author.clone();

        self.echo_headers
            .entry((round, digest.clone()))
            .or_insert_with(HashSet::new)
            .insert(author.clone());

        // info!("Initialized echo_headers: {:?}", self.echo_headers);

        // Check if we have received 2f+1 EchoHeaders for this round and digest
        if let Some(echo_key) = self.echo_headers.get(&(round, digest.clone())) {
            let weight: Stake = echo_key.iter().map(|author| self.committee.stake(author)).sum();
            if weight >= self.committee.quorum_threshold() {
                if !self.ready_header_sent.contains_key(&(echo_header.round, echo_header.id.clone())) {
                    // Send <Ready, H(m)> to primaries.
                    let addresses = self
                        .committee
                        .others_primaries(&self.name)
                        .iter()
                        .map(|(_, info)| info.primary_to_primary)
                        .collect();
                    
                    let ready_header = ReadyHeader::new(&echo_header, &self.name).await;
                    let bytes = bincode::serialize(&PrimaryMessage::Ready(ready_header))
                        .expect("Failed to serialize ReadyHeader");
                    let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                
                    self.cancel_handlers
                        .entry(echo_header.round)
                        .or_insert_with(Vec::new)
                        .extend(handlers);

                    self.ready_headers
                        .entry((round, echo_header.id.clone()))
                        .or_insert_with(HashSet::new)
                        .insert(self.name); 

                    self.ready_header_sent.insert((echo_header.round.clone(), echo_header.id.clone()), true);
                    // info!("Broadcasted ReadyHeader with hash {:?} by {:?}", echo_header.round, self.name);
                };
            }
        };

        Ok(())
    }

    #[async_recursion]
    async fn process_ready_header(&mut self, ready_header: ReadyHeader) -> DagResult<()> {
        // debug!("Processing {:?}", ready_header);

        let round = ready_header.round;
        let digest = ready_header.id.clone();
        let author = ready_header.author.clone();
    
        // Initialize the HashMap if it doesn't exist
        self.ready_headers
            .entry((round, digest.clone()))
            .or_insert_with(HashSet::new)
            .insert(author.clone());    
        
        if let Some(ready_key) = self.ready_headers.get(&(round, digest.clone())) {
            let mut weight: Stake = ready_key.iter().map(|author| self.committee.stake(author)).sum();
            // Check if we have received f+1 <Ready, H(m)> for this round and digest, send <Ready, H(m)>
            if weight >= self.committee.validity_threshold() 
                && weight < self.committee.quorum_threshold() {
                if !self.ready_header_sent.contains_key(&(ready_header.round, ready_header.id.clone())) {
                    // Send <Ready, H(m)> to primaries.
                    let addresses = self
                        .committee
                        .others_primaries(&self.name)
                        .iter()
                        .map(|(_, info)| info.primary_to_primary)
                        .collect();
                    
                    let bytes = bincode::serialize(&PrimaryMessage::Ready(ready_header.clone()))
                        .expect("Failed to serialize ReadyHeader");
                    let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                
                    self.cancel_handlers
                        .entry(ready_header.clone().round)
                        .or_insert_with(Vec::new)
                        .extend(handlers);

                    self.ready_headers
                        .entry((round, ready_header.id))
                        .or_insert_with(HashSet::new)
                        .insert(self.name); 

                    self.ready_header_sent.insert((ready_header.round.clone(), ready_header.id.clone()), true);
                    weight += self.committee.stake(&self.name);
                    info!("sent ready header!");
                }
            }

            // Check if we have received 2f+1 <Ready, H(m)> 
            if weight >= self.committee.quorum_threshold() {  
                loop {
                    if self.processing_header_infos.get(&ready_header.id).is_some() {
                        break;
                    }
                }
                if let Some((header_info, has_leader)) = self.processing_header_infos.get(&ready_header.id) {
                    // Check if the header is valid
                    if !has_leader {
                        // Check if we have enough timeout messages to meet the quorum threshold
                        loop {
                            if let Some(timeout_weight) = self.timeout_weight.get(&(header_info.round - 1)) {
                                if *timeout_weight >= self.committee.quorum_threshold() {
                                    if header_info.author.eq(&self.committee.leader(header_info.round as usize)) {
                                        // Wait for no_vote messages to meet the quorum threshold
                                        loop {
                                            let has_quorum = self
                                                .no_vote_aggregators
                                                .entry(header_info.round - 1)
                                                .or_insert_with(|| Box::new(NoVoteAggregator::new()))
                                                .has_quorum(&self.committee);
                        
                                            if has_quorum {
                                                break;
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                        debug!("Timeout has reached quorum for round {:?}", header_info.round - 1);
                    }

                    // Send header to consensus
                    if !self.consensus_header_sent.contains_key(&(header_info.round, header_info.id.clone())) {
                        // info!("Sending header {:?} to consensus at round {:?}", header_info.id, header_info.round);
                        self.tx_consensus_header_msg
                            .send(HeaderType::HeaderInfo(header_info.clone()))
                            .await
                            .expect("Failed to send header_info to consensus");
                        self.consensus_header_sent.insert((header_info.round.clone(), header_info.id.clone()), true);
                    }

                    // Check if we have enough headers to enter a new dag round and propose a header.
                    if let Some(parents) = self
                        .header_aggregators
                        .entry(header_info.round)
                        .or_insert_with(|| Box::new(HeadersAggregator::new()))
                        .append(header_info.clone(), &self.committee)? {    
                        // Send it to the `Proposer`.
                        self.tx_proposer
                            .send((parents, header_info.round))
                            .await
                            .expect("Failed to send header_info to proposer");
                    } 
                }
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        // debug!("Processing {:?}", timeout);
        
        let round = timeout.round;
        let author = timeout.author;
        // Initialize the HashMap if it doesn't exist
        self.timeouts
            .entry(round)
            .or_insert_with(HashSet::new)
            .insert(author);    
        
        if let Some(timeout_key) = self.timeouts.get(&round) {
            let mut weight: Stake = timeout_key.iter().map(|author| self.committee.stake(author)).sum();
            self.timeout_weight
                .entry(round)
                .and_modify(|existing_weight| *existing_weight = weight)
                .or_insert(weight);

            // Check if we have received f+1 timeout for this round, send timeout
            if weight >= self.committee.validity_threshold() 
                && weight < self.committee.quorum_threshold() {
                if !self.timeout_sent.contains_key(&round) {
                    let new_timeout = Timeout::new(round, self.name).await;
                    let bytes = bincode::serialize(&PrimaryMessage::Timeout(new_timeout.clone()))
                        .expect("Failed to serialize own timeout");

                    // Broadcast the serialized Timeout to all other primaries.
                    let addresses = self
                        .committee
                        .others_primaries(&self.name)
                        .iter()
                        .map(|(_, info)| info.primary_to_primary)
                        .collect();

                    // Send the Timeout to each address.
                    let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

                    self.cancel_handlers
                        .entry(round)
                        .or_insert_with(Vec::new)
                        .extend(handlers);

                    // Send it to the `Proposer`.
                    self.tx_timeout
                        .send(new_timeout.clone())
                        .await
                        .expect("Failed to send timeout");

                    self.timeout_sent.insert(round, true);
                    weight += self.committee.stake(&self.name);
                    self.timeouts
                        .entry(round)
                        .or_insert_with(HashSet::new)
                        .insert(self.name.clone());

                    // info!("Broadcasted Timeout {:?} for round {}", new_timeout.clone(), round);
                }
            }
            if weight >= self.committee.quorum_threshold() {
                let timeout_cert = TimeoutCert {
                    round,
                    timeouts: self
                        .timeouts
                        .get(&round)
                        .map(|set| set.iter().cloned().collect())
                        .unwrap_or_default(),
                };
                    
                self.tx_timeout_cert
                    .send((timeout_cert, timeout.round))
                    .await
                    .expect("Failed to send timeout");
                // info!("Sent timeout cert for round {}", round);
            }
        }

        Ok(())
    }

    #[async_recursion]
    async fn process_no_vote_msg(&mut self, no_vote_msg: NoVoteMsg) -> DagResult<()> {
        // debug!("Processing {:?}", no_vote_msg);

        self.processing_no_vote_msgs
            .entry(no_vote_msg.id)
            .or_insert(no_vote_msg.clone());

        // Send <ECHO, H(m)> to primaries.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();

        let echo_no_vote_msg = EchoNoVoteMsg::new(&no_vote_msg.clone(), &self.name).await;
        let bytes = bincode::serialize(&PrimaryMessage::EchoNoVoteMsg(echo_no_vote_msg))
            .expect("Failed to serialize EchoNoVoteMsg");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

        self.cancel_handlers
            .entry(no_vote_msg.clone().round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Initialize the HashMap if it doesn't exist
        self.echo_no_vote_msgs
            .entry((no_vote_msg.clone().round, no_vote_msg.clone().id))
            .or_insert_with(HashSet::new)
            .insert(self.name.clone());

        Ok(())
    }

    #[async_recursion]
    async fn process_echo_no_vote_msg(&mut self, echo_no_vote_msg: EchoNoVoteMsg) -> DagResult<()> {
        // debug!("Processing {:?}", echo_no_vote_msg);

        let round = echo_no_vote_msg.round;
        let digest = echo_no_vote_msg.id.clone();
        let author = echo_no_vote_msg.author.clone();

        self.echo_no_vote_msgs
            .entry((round, digest.clone()))
            .or_insert_with(HashSet::new)
            .insert(author.clone());

        // Check if we have received 2f+1 EchoNoVotes for this round and digest
        if let Some(echo_key) = self.echo_no_vote_msgs.get(&(round, digest.clone())) {
            let weight: Stake = echo_key.iter().map(|author| self.committee.stake(author)).sum();
            if weight >= self.committee.quorum_threshold() {
                if !self.ready_no_vote_sent.contains_key(&(echo_no_vote_msg.round, echo_no_vote_msg.id.clone())) {
                    // Send <Ready, H(m)> to primaries.
                    let addresses = self
                        .committee
                        .others_primaries(&self.name)
                        .iter()
                        .map(|(_, info)| info.primary_to_primary)
                        .collect();
                    
                    let ready_no_vote_msg = ReadyNoVoteMsg::new(&echo_no_vote_msg, &self.name).await;
                    let bytes = bincode::serialize(&PrimaryMessage::ReadyNoVoteMsg(ready_no_vote_msg))
                        .expect("Failed to serialize ReadyNoVoteMsg");
                    let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                
                    self.cancel_handlers
                        .entry(echo_no_vote_msg.round)
                        .or_insert_with(Vec::new)
                        .extend(handlers);

                    self.ready_no_vote_msgs
                        .entry((round, echo_no_vote_msg.id.clone()))
                        .or_insert_with(HashSet::new)
                        .insert(self.name); 

                    self.ready_no_vote_sent.insert((echo_no_vote_msg.round.clone(), echo_no_vote_msg.id.clone()), true);
                    // info!("Broadcasted ReadyNoVoteMsg with hash {:?}", echo_no_vote_msg.round);
                };
            }
        };

        Ok(())
    }

    #[async_recursion]
    async fn process_ready_no_vote_msg(&mut self, ready_no_vote_msg: ReadyNoVoteMsg) -> DagResult<()> {
        // debug!("Processing {:?}", ready_no_vote_msg);

        let round = ready_no_vote_msg.round;
        let digest = ready_no_vote_msg.id.clone();
        let author = ready_no_vote_msg.author.clone();
    
        // Initialize the HashMap if it doesn't exist
        self.ready_no_vote_msgs
            .entry((round, digest.clone()))
            .or_insert_with(HashSet::new)
            .insert(author.clone());    
        
        if let Some(ready_key) = self.ready_no_vote_msgs.get(&(round, digest.clone())) {
            let weight: Stake = ready_key.iter().map(|author| self.committee.stake(author)).sum();
            // Check if we have received f+1 <Ready, H(m)> for this round and digest, send <Ready, H(m)>
            if weight >= self.committee.validity_threshold() 
                && weight < self.committee.quorum_threshold() {
                if !self.ready_no_vote_sent.contains_key(&(ready_no_vote_msg.round, ready_no_vote_msg.id.clone())) {
                    // Send <Ready, H(m)> to primaries.
                    let addresses = self
                        .committee
                        .others_primaries(&self.name)
                        .iter()
                        .map(|(_, info)| info.primary_to_primary)
                        .collect();
                    
                    let bytes = bincode::serialize(&PrimaryMessage::ReadyNoVoteMsg(ready_no_vote_msg.clone()))
                        .expect("Failed to serialize ReadyNoVoteMsg");
                    let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                
                    self.cancel_handlers
                        .entry(ready_no_vote_msg.clone().round)
                        .or_insert_with(Vec::new)
                        .extend(handlers);

                    self.ready_no_vote_sent.insert((ready_no_vote_msg.round.clone(), ready_no_vote_msg.id.clone()), true);
                }
            }

            // Check if we have received 2f+1 <Ready, H(m)> 
            if weight >= self.committee.quorum_threshold() {  
                loop {
                    if self.processing_no_vote_msgs.get(&ready_no_vote_msg.id).is_some() {
                        break;
                    }
                }

                if let Some(no_vote_msg) = self.processing_no_vote_msgs.get(&ready_no_vote_msg.id) {
                    let no_vote_cert = NoVoteCert {
                        round,
                        no_votes: self
                            .ready_no_vote_msgs
                            .get(&(round, ready_no_vote_msg.id))
                            .map(|set| set.iter().cloned().collect())
                            .unwrap_or_default(),
                    };
                        
                    self.tx_no_vote_cert
                        .send((no_vote_cert, no_vote_msg.round))
                        .await
                        .expect("Failed to send no vote cert");
                }
            }
        }
        Ok(())
    }

    fn sanitize_header_msg(&mut self, header_msg: &HeaderMessage) -> DagResult<()> {
        match header_msg {
            HeaderMessage::HeaderWithParents(header_with_parents) => {
                let header = &header_with_parents.header;
                ensure!(
                    self.gc_round <= header.round,
                    DagError::TooOld(header.id, header.round)
                );
                header.verify(&self.committee)?;
                Ok(())
            }

            HeaderMessage::HeaderInfoWithParents(header_info_with_parents) => {
                let header_info = &header_info_with_parents.header_info;
                ensure!(
                    self.gc_round <= header_info.round,
                    DagError::TooOld(header_info.id, header_info.round)
                );
                // Verify the header's signature.
                header_info.verify(&self.committee)?;
                Ok(())
            }

            HeaderMessage::Header(header) => {
                ensure!(
                    self.gc_round <= header.round,
                    DagError::TooOld(header.id, header.round)
                );
                header.verify(&self.committee)?;
                Ok(())
            }

            HeaderMessage::HeaderInfo(header_info) => {
                ensure!(
                    self.gc_round <= header_info.round,
                    DagError::TooOld(header_info.id, header_info.round)
                );
                header_info.verify(&self.committee)?;
                Ok(())
            }
        }
    }

    fn sanitize_echo_header(&mut self, echo_header: &EchoHeader) -> DagResult<()> {
        ensure!(
            self.gc_round <= echo_header.round,
            DagError::TooOld(echo_header.id.clone(), echo_header.round)
        );

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
    }

    fn sanitize_ready_header(&mut self, ready_header: &ReadyHeader) -> DagResult<()> {
        ensure!(
            self.gc_round <= ready_header.round,
            DagError::TooOld(ready_header.id.clone(), ready_header.round)
        );

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
    }
    
    fn sanitize_timeout(&mut self, timeout: &Timeout) -> DagResult<()> {
        ensure!(
            self.gc_round <= timeout.round,
            DagError::TooOld(timeout.digest(), timeout.round)
        );

        timeout.verify(&self.committee)?;

        Ok(())
    }

    fn sanitize_no_vote_msg(&mut self, no_vote_msg: &NoVoteMsg) -> DagResult<()> {
        ensure!(
            self.gc_round <= no_vote_msg.round,
            DagError::TooOld(no_vote_msg.digest(), no_vote_msg.round)
        );

        no_vote_msg.verify(&self.committee)?;

        Ok(())
    }

    fn sanitize_echo_no_vote_msg(&mut self, echo_no_vote_msg: &EchoNoVoteMsg) -> DagResult<()> {
        ensure!(
            self.gc_round <= echo_no_vote_msg.round,
            DagError::TooOld(echo_no_vote_msg.id.clone(), echo_no_vote_msg.round)
        );

        Ok(())
    }

    fn sanitize_ready_no_vote_msg(&mut self, ready_no_vote_msg: &ReadyNoVoteMsg) -> DagResult<()> {
        ensure!(
            self.gc_round <= ready_no_vote_msg.round,
            DagError::TooOld(ready_no_vote_msg.id.clone(), ready_no_vote_msg.round)
        );

        Ok(())
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::HeaderMsg(header_msg) => {
                            match self.sanitize_header_msg(&header_msg) {
                                Ok(()) => self.process_header(&header_msg).await,
                                error => error
                            }
                        },
                        PrimaryMessage::Echo(echo_header) => {
                            match self.sanitize_echo_header(&echo_header) {
                                Ok(()) => self.process_echo_header(echo_header).await,
                                error => error
                            }
                        },
                        PrimaryMessage::Ready(ready_header) => {
                            match self.sanitize_ready_header(&ready_header) {
                                Ok(()) => self.process_ready_header(ready_header).await,
                                error => error
                            }
                        },
                        PrimaryMessage::Timeout(timeout) => {
                            match self.sanitize_timeout(&timeout) {
                                Ok(()) => self.process_timeout(timeout).await,
                                error => error
                            }
                        },
                        PrimaryMessage::NoVoteMsg(no_vote_msg) => {
                            match self.sanitize_no_vote_msg(&no_vote_msg) {
                                Ok(()) => self.process_no_vote_msg(no_vote_msg).await,
                                error => error
                            }
                        },
                        PrimaryMessage::EchoNoVoteMsg(echo_no_vote_msg) => {
                            match self.sanitize_echo_no_vote_msg(&echo_no_vote_msg) {
                                Ok(()) => self.process_echo_no_vote_msg(echo_no_vote_msg).await,
                                error => error
                            }
                        },
                        PrimaryMessage::ReadyNoVoteMsg(ready_no_vote_msg) => {
                            match self.sanitize_ready_no_vote_msg(&ready_no_vote_msg) {
                                Ok(()) => self.process_ready_no_vote_msg(ready_no_vote_msg).await,
                                error => error
                            }
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header_msg) = self.rx_header_waiter.recv() => self.process_header(&header_msg).await,
                // We also receive here our new headers created by the `Proposer`.
                Some(header_with_parents) = self.rx_proposer.recv() => self.process_own_header(header_with_parents).await,
                // We also receive here our timeout created by the `Proposer`.
                Some(timeout) = self.rx_timeout.recv() => self.process_own_timeout(timeout).await,
                // // We also receive here our no vote messages created by the `Proposer`.
                Some(no_vote_msg) = self.rx_no_vote_msg.recv() => self.process_own_no_vote_msg(no_vote_msg).await,
            };
            match result {
                Ok(()) => (),
                Err(DagError::StoreError(e)) => {
                    error!("{}", e);
                    panic!("Storage failure: killing node.");
                }
                Err(e @ DagError::TooOld(..)) => debug!("{}", e),
                Err(e) => warn!("{}", e),
            }

            // Cleanup internal state.
            let round = self.consensus_round.load(Ordering::Relaxed);
            if round > self.gc_depth {
                let gc_round = round - self.gc_depth;
                self.last_voted.retain(|k, _| k >= &gc_round);
                self.processing_header_infos.retain(|_, (h, _)| &h.round >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.gc_round = gc_round;
                self.echo_headers.retain(|(k,_),_| k>= &gc_round);
                self.ready_headers.retain(|(k,_),_| k>= &gc_round);
                self.ready_header_sent.retain(|(k,_),_| k>= &gc_round);
                self.consensus_header_sent.retain(|(k,_),_| k>= &gc_round);
                self.timeout_sent.retain(|k,_| k>= &gc_round);
                self.echo_no_vote_msgs.retain(|(k,_),_| k>= &gc_round);
                self.ready_no_vote_sent.retain(|(k,_),_| k>= &gc_round);
                self.ready_no_vote_msgs.retain(|(k,_),_| k>= &gc_round);
            }
        }
    }

}