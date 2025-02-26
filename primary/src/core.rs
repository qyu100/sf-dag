// Copyright(C) Facebook, Inc. and its affiliates.
use crate::aggregators::{HeadersAggregator, ThresholdAggregator}; 
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, HeaderWithParents, HeaderInfoWithParents, 
    HeaderInfo, NoVoteCert, NoVoteMsg, Timeout, TimeoutCert, EchoHeader, ReadyHeader
    ,EchoNoVoteMsg, ReadyNoVoteMsg};
use crate::primary::{HeaderMessage, HeaderType, PrimaryMessage, Round};
use crate::synchronizer::Synchronizer;
use crate::Header;
use async_recursion::async_recursion;
use bytes::Bytes;
use config::Committee;
use crypto::Hash;
use crypto::{Digest, PublicKey};
use log::{debug, error, info, warn};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

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
    tx_consensus_header_msg: Sender<HeaderType>,

    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    echo_header_aggregators: HashMap<(Round, Digest), ThresholdAggregator>,
    ready_header_aggregators: HashMap<(Round, Digest), ThresholdAggregator>,
    echo_no_vote_aggregators: HashMap<(Round, Digest), ThresholdAggregator>,
    ready_no_vote_aggregators: HashMap<(Round, Digest), ThresholdAggregator>,
    timeout_aggregators:  HashMap<Round, ThresholdAggregator>,
    processing_header_infos: HashMap<Digest, (HeaderInfo, bool)>,
    processing_no_vote_msgs: HashMap<Digest, NoVoteMsg>,
    // A network sender to send the batches to the other workers.
    network: ReliableSender,
    // Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
    // Aggregates headers.
    header_aggregators: HashMap<Round, Box<HeadersAggregator>>,
    ready_header_sent: HashMap<(Round, Digest), bool>,
    consensus_header_sent: HashMap<(Round, Digest), bool>,
    no_vote_cert_sent: HashMap<Round, bool>,
    timeout_sent: HashMap<Round, bool>,
    ready_no_vote_sent: HashMap<(Round, Digest), bool>,
    timeout_suspended: HashMap<Round, Vec<HeaderInfo>>,
    no_vote_suspended: HashMap<Round, Vec<HeaderInfo>>,
    timeout_cert_sent: HashMap<Round, bool>,
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
                tx_consensus_header_msg,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                echo_header_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                ready_header_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                echo_no_vote_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                ready_no_vote_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                timeout_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                processing_header_infos: HashMap::new(),
                processing_no_vote_msgs: HashMap::new(),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                header_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                ready_header_sent: HashMap::new(),
                consensus_header_sent: HashMap::new(),
                no_vote_cert_sent: HashMap::new(),
                timeout_sent: HashMap::new(),
                ready_no_vote_sent: HashMap::new(),
                timeout_suspended: HashMap::new(),
                no_vote_suspended: HashMap::new(),
                timeout_cert_sent: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    async fn send_consensus_header(
        &mut self,
        round: u64,
        digest: Digest,
        header_info: HeaderInfo,
    ) -> DagResult<()> {
        let key = (round, digest);
        if !self.consensus_header_sent.contains_key(&key) {
            self.tx_consensus_header_msg
                .send(HeaderType::HeaderInfo(header_info.clone()))
                .await
                .expect("Failed to send header_info to consensus");
            self.consensus_header_sent.insert(key, true);
            if let Some(parents) = self.header_aggregators
                .entry(round)
                .or_insert_with(|| Box::new(HeadersAggregator::new()))
                .append(header_info, &self.committee)?
            {
                self.tx_proposer
                    .send((parents, round))
                    .await
                    .expect("Failed to send header_info to proposer");
            }
        }
        Ok(())
    }

    async fn process_own_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        let trd = timeout.round;
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
            .entry(trd)
            .or_insert_with(Vec::new)
            .extend(handlers);

        let aggregator = self.timeout_aggregators
            .entry(trd)
            .or_insert_with(ThresholdAggregator::new);

        aggregator.append(self.name, &self.committee)?; 
        self.timeout_sent.insert(trd, true);

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
        let round = header_info.round;
        let digest = header_info.id;
        // Ensure we have the parents. If at least one parent is missing, the synchronizer returns an empty
        // vector; it will gather the missing parents (as well as all ancestors) from other nodes and then
        // reschedule processing of this header.
        let mut has_leader = true;
        
        if round != 1 {
            let parents = self.synchronizer.get_parents(&HeaderType::HeaderInfo(header_info.clone())).await?;
            
            if parents.is_empty() {
                debug!("Processing of {} suspended: missing parent(s)", header_info.id);
                return Ok(());
            }
            // Ensure the parents form a quorum and are all from the previous round.
            let mut stake = 0;
            let leader = self.committee.leader((header_info.round - 1) as usize);
            has_leader = false;
            
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

                if leader == parent_header_info.author {
                    has_leader = true; 
                }            
            }
            ensure!(
                stake >= self.committee.quorum_threshold(),
                DagError::HeaderRequiresQuorum(header_info.id.clone())
            );
        }
        self.processing_header_infos
            .entry(header_info.id)
            .or_insert((header_info.clone(), has_leader));

        if self.ready_header_aggregators
            .get(&(round, digest))
            .map(|ready_aggregator| ready_aggregator.check_threshold(self.committee.quorum_threshold()))
            .unwrap_or(false){
            // Optimistic threshold reached, send to proposer
            debug!("Processing missing header for digest: {:?}", digest);
            if !has_leader {
                if let Some(timeout_agg) = self.timeout_aggregators.get(&(round - 1)) {
                    if !timeout_agg.check_threshold(self.committee.quorum_threshold()) {
                        self.timeout_suspended
                            .entry(round - 1)
                            .or_insert_with(Vec::new)
                            .push(header_info.clone());
                        debug!("Processing of {} suspended: missing timeout quorum", digest);
                        return Ok(());
                    }
                    if header_info.author == self.committee.leader(round as usize) {
                        self.no_vote_suspended
                            .entry(round - 1)
                            .or_insert_with(Vec::new)
                            .push(header_info.clone());
                        if !self.no_vote_cert_sent.get(&(header_info.round - 1)).unwrap_or(&false) == true {
                            debug!("Processing of {} suspended: missing no_vote quorum", digest);
                            return Ok(());          
                        }
                    }
                debug!("Timeout has reached quorum for round {:?}", round - 1);
                }
            }
            self.send_consensus_header(round, digest, header_info.clone()).await?;  
        }
    
        // Store the header.
        let hid = header_info.id;
        let hr = header_info.round;

        let header_type = HeaderType::HeaderInfo(header_info.clone());
        let bytes = bincode::serialize(&header_type).expect("Failed to serialize header");
        self.store.write(hid.to_vec(), bytes).await;
        self.synchronizer.deliver_vertex(hr, header_type).await?;

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
            .entry(hr)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Initialize the HashMap if it doesn't exist
        let aggregator = self.echo_header_aggregators
            .entry((hr, hid))
            .or_insert_with(ThresholdAggregator::new);
        aggregator.append(self.name, &self.committee)?;
        Ok(())
    }

    #[async_recursion]
    async fn process_echo_header(&mut self, echo_header: EchoHeader) -> DagResult<()> {
        let round = echo_header.round;
        let digest = echo_header.id;
        let author = echo_header.author;

        let aggregator = self.echo_header_aggregators
            .entry((round, digest))
            .or_insert_with(ThresholdAggregator::new);

        let weight = aggregator.append(author, &self.committee)?;
        if weight >= self.committee.optimistic_threshold() {
            // Optimistic threshold reached, send to proposer
            if let Some((header_info, has_leader)) = self.processing_header_infos.get(&digest) {
                if !has_leader {
                    if let Some(timeout_agg) = self.timeout_aggregators.get(&(round - 1)) {
                        if !timeout_agg.check_threshold(self.committee.quorum_threshold()) {
                            self.timeout_suspended
                                .entry(round - 1)
                                .or_insert_with(Vec::new)
                                .push(header_info.clone());
                            debug!("Processing of {} suspended: missing timeout quorum", digest);
                            return Ok(());
                        }
                        if header_info.author == self.committee.leader(round as usize) {
                            self.no_vote_suspended
                                .entry(round - 1)
                                .or_insert_with(Vec::new)
                                .push(header_info.clone());
                            if !self.no_vote_cert_sent.get(&(header_info.round - 1)).unwrap_or(&false) == true {
                                debug!("Processing of {} suspended: missing no_vote quorum", digest);
                                return Ok(());          
                            }
                        }
                    debug!("Timeout has reached quorum for round {:?}", round - 1);
                    }
                }
                self.send_consensus_header(round, digest, header_info.clone()).await?;
            }
        } else if weight >= self.committee.quorum_threshold() {
            // 2f+1 reached, send ready message
            if !self.ready_header_sent.get(&(round, digest)).unwrap_or(&false) {
                let addresses = self.committee.others_primaries(&self.name)
                    .iter()
                    .map(|(_, info)| info.primary_to_primary)
                    .collect();
                let ready_header = ReadyHeader::new(&echo_header, &self.name).await;
                let bytes = bincode::serialize(&PrimaryMessage::Ready(ready_header.clone()))
                    .expect("Failed to serialize ReadyHeader");
                let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                self.cancel_handlers.entry(round).or_insert_with(Vec::new).extend(handlers);
                self.ready_header_sent.insert((round, digest), true);
                let ready_aggregator = self.ready_header_aggregators
                    .entry((round, digest))
                    .or_insert_with(ThresholdAggregator::new);
                ready_aggregator.append(self.name, &self.committee)?;
            }
        }
        Ok(())
    }
            
    #[async_recursion]
    async fn process_ready_header(&mut self, ready_header: ReadyHeader) -> DagResult<()> {
        let round = ready_header.round;
        let digest = ready_header.id;
        let author = ready_header.author;
    
        let aggregator = self.ready_header_aggregators
            .entry((round, digest))
            .or_insert_with(ThresholdAggregator::new);
        let weight = aggregator.append(author, &self.committee)?;

        if weight >= self.committee.validity_threshold() 
            && weight < self.committee.quorum_threshold(){
            if !self.ready_header_sent.get(&(round, digest)).unwrap_or(&false) {
                let addresses = self.committee.others_primaries(&self.name)
                    .iter()
                    .map(|(_, info)| info.primary_to_primary)
                    .collect();
                let new_ready_header = ReadyHeader::new_ready_header(&ready_header, &self.name).await;
                let bytes = bincode::serialize(&PrimaryMessage::Ready(new_ready_header))
                    .expect("Failed to serialize ReadyHeader");
                let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                self.cancel_handlers.entry(round).or_insert_with(Vec::new).extend(handlers);
                self.ready_header_sent.insert((round, digest), true);
            }
        }

        if weight >= self.committee.quorum_threshold() {
            if !self.processing_header_infos.contains_key(&digest) {
                debug!("Processing of {} suspended: missing header message", digest);
                return Ok(());
            }
            if let Some((header_info, has_leader)) = self.processing_header_infos.get(&digest) {
                if !has_leader {
                    if let Some(timeout_agg) = self.timeout_aggregators.get(&(round - 1)) {
                        if !timeout_agg.check_threshold(self.committee.quorum_threshold()) {
                            self.timeout_suspended
                                .entry(round - 1)
                                .or_insert_with(Vec::new)
                                .push(header_info.clone());
                            debug!("Processing of {} suspended: missing timeout quorum", digest);
                            return Ok(());
                        }
                        if header_info.author == self.committee.leader(round as usize) {
                            self.no_vote_suspended
                                .entry(round - 1)
                                .or_insert_with(Vec::new)
                                .push(header_info.clone());
                            if !self.no_vote_cert_sent.get(&(header_info.round - 1)).unwrap_or(&false) == true {
                                debug!("Processing of {} suspended: missing no_vote quorum", digest);
                                return Ok(());          
                            }
                        }
                    debug!("Timeout has reached quorum for round {:?}", round - 1);
                    }
                }
                self.send_consensus_header(round, digest, header_info.clone()).await?;
            }
        }
        Ok(())
    }

    async fn process_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        let round = timeout.round;
        let author = timeout.author;

        let aggregator = self.timeout_aggregators
            .entry(round)
            .or_insert_with(ThresholdAggregator::new);
        let mut weight = aggregator.append(author, &self.committee)?;  
        
        let validity = self.committee.validity_threshold();
        let quorum = self.committee.quorum_threshold();

        if weight >= validity && weight < quorum && !self.timeout_sent.contains_key(&round) {
            let new_timeout = Timeout::new(round, self.name).await;
            let bytes = bincode::serialize(&PrimaryMessage::Timeout(new_timeout.clone()))
                .expect("Failed to serialize own timeout");
            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, info)| info.primary_to_primary)
                .collect();
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(round)
                .or_insert_with(Vec::new)
                .extend(handlers);
            self.tx_timeout
                .send(new_timeout)
                .await
                .expect("Failed to send timeout");
            self.timeout_sent.insert(round, true);
            weight = aggregator.append(self.name, &self.committee)?;
            
        }

        if weight < quorum {
            return Ok(());
        }
        if self.timeout_cert_sent.contains_key(&round) {
            return Ok(());
        }

        let timeout_cert = TimeoutCert {
            round,
            timeouts: aggregator.authors().into_iter().cloned().collect(),
        };
        self.tx_timeout_cert
            .send((timeout_cert, round))
            .await
            .expect("Failed to send timeout");
        self.timeout_cert_sent.insert(round, true);
        // process has_leader timeout suspended vertex.
        if let Some(header_infos) = self.timeout_suspended.remove(&round) {
            for header_info in header_infos {
                let digest = header_info.id;
                self.send_consensus_header(round, digest, header_info).await?;
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_no_vote_msg(&mut self, no_vote_msg: NoVoteMsg) -> DagResult<()> {
        // debug!("Processing {:?}", no_vote_msg);
        let round = no_vote_msg.round;
        let digest = no_vote_msg.id;

        self.processing_no_vote_msgs
            .entry(digest)
            .or_insert(no_vote_msg.clone());

        if let Some(ready_no_vote_aggregator) = self.ready_no_vote_aggregators.get(&(round, digest)) {
            if ready_no_vote_aggregator.check_threshold(self.committee.quorum_threshold()) {
                // Optimistic threshold reached, send to proposer
                debug!("Processing missing no_vote for digest: {:?}", digest);
                if self.no_vote_cert_sent.contains_key(&round) {
                    return Ok(());
                }
                let no_vote_cert = NoVoteCert {
                    round,
                    no_votes: ready_no_vote_aggregator.authors().into_iter().cloned().collect(),
                };
        
                self.tx_no_vote_cert
                    .send((no_vote_cert, no_vote_msg.round))
                    .await
                    .expect("Failed to send no vote cert");
                self.no_vote_cert_sent.insert(round, true);
                // process has_leader no_vote suspended vertex.
                if let Some(header_infos) = self.no_vote_suspended.remove(&round) {
                    for header_info in header_infos {
                        let digest = header_info.id;
                        self.send_consensus_header(round, digest, header_info.clone()).await?;
                    }
                }
            }
        }
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
            .entry(round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Initialize the HashMap if it doesn't exist
        let aggregator = self.echo_no_vote_aggregators
            .entry((round, digest))
            .or_insert_with(ThresholdAggregator::new);
        aggregator.append(self.name, &self.committee)?;

        Ok(())
    }

    #[async_recursion]
    async fn process_echo_no_vote_msg(&mut self, echo_no_vote_msg: EchoNoVoteMsg) -> DagResult<()> {
        let round = echo_no_vote_msg.round;
        let digest = echo_no_vote_msg.id;
        let author = echo_no_vote_msg.author;

        let aggregator = self.echo_no_vote_aggregators
            .entry((round, digest))
            .or_insert_with(ThresholdAggregator::new);

        let weight = aggregator.append(author, &self.committee)?;

        if weight >= self.committee.optimistic_threshold() {
            if let Some(no_vote_msg) = self.processing_no_vote_msgs.get(&digest) {
                if !self.no_vote_cert_sent.contains_key(&round) {
                    let no_vote_cert = NoVoteCert {
                        round,
                        no_votes: aggregator.authors().into_iter().cloned().collect(),
                    };
                    self.tx_no_vote_cert
                        .send((no_vote_cert, no_vote_msg.round))
                        .await
                        .expect("Failed to send no vote cert");
                    self.no_vote_cert_sent.insert(round, true);
                    // process has_leader no_vote suspended vertex.
                    if let Some(header_infos) = self.no_vote_suspended.remove(&round) {
                        for header_info in header_infos {
                            let digest = header_info.id;
                            self.send_consensus_header(round, digest, header_info.clone()).await?;
                        }
                    }
                }
            }
        }

        if weight < self.committee.quorum_threshold() || *self.ready_no_vote_sent.get(&(round, digest)).unwrap_or(&false) {
            return Ok(());
        }

        let addresses = self.committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();
        let ready_no_vote_msg = ReadyNoVoteMsg::new(&echo_no_vote_msg, &self.name).await;
        let bytes = bincode::serialize(&PrimaryMessage::ReadyNoVoteMsg(ready_no_vote_msg))
            .expect("Failed to serialize ReadyNoVoteMsg");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(round)
            .or_insert_with(Vec::new)
            .extend(handlers);
        let aggregator = self.ready_no_vote_aggregators
            .entry((round, digest))
            .or_insert_with(ThresholdAggregator::new);
        aggregator.append(self.name, &self.committee)?; 
        self.ready_no_vote_sent.insert((round, digest), true);

        Ok(())
    }

    async fn process_ready_no_vote_msg(&mut self, ready_no_vote_msg: ReadyNoVoteMsg) -> DagResult<()> {
        let round = ready_no_vote_msg.round;
        let digest = ready_no_vote_msg.id;
        let author = ready_no_vote_msg.author;
    
        let aggregator = self.ready_no_vote_aggregators
            .entry((round, digest))
            .or_insert_with(ThresholdAggregator::new);

        let weight = aggregator.append(author, &self.committee)?;    
        
        if weight >= self.committee.validity_threshold() && !self.ready_no_vote_sent.get(&(round, digest)).unwrap_or(&false){
            let addresses = self.committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, info)| info.primary_to_primary)
                .collect();
            let bytes = bincode::serialize(&PrimaryMessage::ReadyNoVoteMsg(ready_no_vote_msg.clone()))
                .expect("Failed to serialize ReadyNoVoteMsg");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(round)
                .or_insert_with(Vec::new)
                .extend(handlers);
            self.ready_no_vote_sent.insert((round, digest), true);  
        }

        if weight < self.committee.quorum_threshold() {
            return Ok(());
        }

        let Some(no_vote_msg) = self.processing_no_vote_msgs.get(&digest) else {
            debug!("Processing of {} suspended: missing no_vote message", digest);
            return Ok(());
        };
    
        if self.no_vote_cert_sent.contains_key(&round) {
            return Ok(());
        }
        let no_vote_cert = NoVoteCert {
            round,
            no_votes: aggregator.authors().into_iter().cloned().collect(),
        };

        self.tx_no_vote_cert
            .send((no_vote_cert, no_vote_msg.round))
            .await
            .expect("Failed to send no vote cert");
        self.no_vote_cert_sent.insert(round, true);
        // process has_leader no_vote suspended vertex.
        if let Some(header_infos) = self.no_vote_suspended.remove(&round) {
            for header_info in header_infos {
                let digest = header_info.id;
                self.send_consensus_header(round, digest, header_info.clone()).await?;
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
            DagError::TooOld(echo_header.id, echo_header.round)
        );

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
    }

    fn sanitize_ready_header(&mut self, ready_header: &ReadyHeader) -> DagResult<()> {
        ensure!(
            self.gc_round <= ready_header.round,
            DagError::TooOld(ready_header.id, ready_header.round)
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
            DagError::TooOld(echo_no_vote_msg.id, echo_no_vote_msg.round)
        );

        Ok(())
    }

    fn sanitize_ready_no_vote_msg(&mut self, ready_no_vote_msg: &ReadyNoVoteMsg) -> DagResult<()> {
        ensure!(
            self.gc_round <= ready_no_vote_msg.round,
            DagError::TooOld(ready_no_vote_msg.id, ready_no_vote_msg.round)
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
                self.ready_header_sent.retain(|(k, _), _| k >= &gc_round);
                self.consensus_header_sent.retain(|(k,_),_| k>= &gc_round);
                self.timeout_sent.retain(|k,_| k>= &gc_round);
                self.ready_no_vote_sent.retain(|(k,_),_| k>= &gc_round);
                self.no_vote_cert_sent.retain(|k,_| k>= &gc_round);
                self.echo_header_aggregators.retain(|(r, _), _| r >= &gc_round);
                self.ready_header_aggregators.retain(|(r, _), _| r >= &gc_round);
                self.echo_no_vote_aggregators.retain(|(r, _), _| r >= &gc_round);
                self.ready_no_vote_aggregators.retain(|(r, _), _| r >= &gc_round);
                self.timeout_aggregators.retain(|r, _| r >= &gc_round);
                let _ = self.synchronizer.garbage_collect(gc_round).await;
            }
        }
    }
}