// Copyright(C) Facebook, Inc. and its affiliates.
use crate::batch_maker::Transaction;
use crate::aggregators::{
    EchoAggregator, ReadyAggregator, DecideAggregator, TimeoutAggregator
};
use crate::error::{DagError, DagResult};
use crate::messages::{
    Certificate, Header, Ready, Timeout, TimeoutCert, Echo, Decide
};
use crate::primary::{PrimaryMessage, Round};
use crate::synchronizer::Synchronizer;
use crate::{ConsensusMessage, HeaderMessage};
use async_recursion::async_recursion;
use bytes::Bytes;
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

// #[cfg(test)]
// #[path = "tests/core_tests.rs"]
// pub mod core_tests;

pub struct Core {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Arc<Committee>,
    /// The persistent storage.
    store: Store,
    /// Handles synchronization with other nodes and our workers.
    synchronizer: Synchronizer,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,
    /// Sender to loopback messages to self (core)
    tx_primary: Sender<PrimaryMessage>,
    /// Receiver for dag messages (headers, timeouts, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<Header>,
    /// Receives loopback certificates from the `CertificateWaiter`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<Header>,
    /// Receives our newly created timeouts from the `Proposer`.
    rx_timeout: Receiver<Timeout>,
    /// Output all certificates to the consensus layer.
    tx_consensus: Sender<Certificate>,
    /// Send valid a quorum of certificates' ids to the `Proposer` (along with their round).
    tx_proposer: Sender<Certificate>,
    /// Send a valid TimeoutCertificate along with the round to the `Proposer`.
    tx_timeout_cert: Sender<(TimeoutCert, Round)>,
    /// Send a the header that has voted for the prev leader to the `Consensus` logic.
    tx_consensus_header_msg: Sender<ConsensusMessage>,
    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    /// For storing info of header in processing
    processing_headers: HashMap<Digest, Header>,
    /// For storing info of echo aggregators in processing
    processing_echo_aggregators: HashMap<Digest, EchoAggregator>,
    /// For storing info of ready aggregators in processing
    processing_ready_aggregators: HashMap<Digest, ReadyAggregator>,
    /// For storing info of decide aggregators in processing
    processing_decide_aggregators: HashMap<Digest, DecideAggregator>,
    /// For storing info of processed certificates
    processed_certs: HashMap<Round, HashSet<PublicKey>>,
    /// Rounds pending commit because certificate was missing at commit time
    pending_commit_rounds: HashSet<Round>,
    /// A network sender to send the batches to the other workers.
    network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
    /// Aggregates timeouts to use for sending timeout certificate.
    timeouts_aggregators: HashMap<Round, Box<TimeoutAggregator>>,
    // certificates to commit
    certificates: HashMap<Round, Certificate>,
    /// last committed round
    last_committed_round: Round,
    // Stored parent info
    parent_info: HashMap<Digest, Header>,
    // // payload_lens
    // reconstructed_lens: HashMap<Digest, usize>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Arc<Committee>,
        store: Store,
        synchronizer: Synchronizer,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        tx_primary: Sender<PrimaryMessage>,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<Header>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        rx_timeout: Receiver<Timeout>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<Certificate>,
        tx_timeout_cert: Sender<(TimeoutCert, Round)>,
        tx_consensus_header_msg: Sender<ConsensusMessage>,
    ) {
        tokio::spawn(async move {
            // Precompute shard counts so we don't move `committee` before using it.
            let data_shard_num = committee.data_shard_num() as usize;
            let parity_shard_num = committee.parity_shard_num() as usize;
            Self {
                name,
                committee: committee.clone(),
                store,
                synchronizer,
                consensus_round,
                gc_depth,
                tx_primary,
                rx_primaries,
                rx_header_waiter,
                rx_certificate_waiter,
                rx_proposer,
                rx_timeout,
                tx_consensus,
                tx_proposer,
                tx_timeout_cert,
                tx_consensus_header_msg,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                processing_headers: HashMap::new(),
                processing_echo_aggregators: HashMap::new(),
                processing_ready_aggregators: HashMap::new(),
                processing_decide_aggregators: HashMap::new(),
                processed_certs: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                timeouts_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                pending_commit_rounds: HashSet::new(),
                certificates: HashMap::new(),
                last_committed_round: 0,
                parent_info: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    // async fn process_own_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
    //     // Serialize the Timeout instance into bytes using bincode or a similar serialization tool.
    //     let bytes = bincode::serialize(&PrimaryMessage::Timeout(timeout.clone()))
    //         .expect("Failed to serialize own timeout");

    //     // Broadcast the serialized Timeout to all other primaries.
    //     let addresses = self
    //         .committee
    //         .others_primaries(&self.name)
    //         .iter()
    //         .map(|(_, info)| info.primary_to_primary)
    //         .collect();

    //     // Send the Timeout to each address.
    //     let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

    //     self.cancel_handlers
    //         .entry(timeout.round)
    //         .or_insert_with(Vec::new)
    //         .extend(handlers);

    //     // Log the broadcast for debugging purposes.
    //     debug!("Broadcasted own timeout for round {}", timeout.round);

    //     self.process_timeout(timeout).await
    // }

    async fn process_own_header(
        &mut self,
        header: Header,
    ) -> DagResult<()> {
        debug!("Processing own header: {:?}", header);

        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        let bytes = bincode::serialize(&PrimaryMessage::Header(header.clone()))
        .expect("Failed to serialize our own header");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(header.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        self.process_header_msg(&header).await?;

         Ok(())
    }

    async fn process_header_msg(&mut self, header: &Header) -> DagResult<()> {
        debug!("Processing header: {:?}", header);

        // store the full Header for later parent lookups
        self.parent_info.entry(header.id).or_insert(header.clone());

        if self.synchronizer.missing_payload(header).await? {
                debug!("Downloading the payload of {header}");
            return Ok(());
        }

        self.processing_headers
             .entry(header.id)
             .or_insert(header.clone());

        if self.last_voted.entry(header.round).or_insert_with(HashSet::new).insert(header.author) {
            // Make an echo and send it to all nodes
            let echo = Echo::new(&header, &self.name).await;
            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, x)| x.primary_to_primary)
                .collect();
            let bytes = bincode::serialize(&PrimaryMessage::Echo(echo.clone()))
                .expect("Failed to serialize our own echo");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(header.round)
                .or_insert_with(Vec::new)
                .extend(handlers);

            self.process_echo(&echo)
                .await
                .expect("Failed to process our own echo");
        }
        
        if header.round != 1 {
            let parent = self
                .synchronizer
                .get_parent(&header.clone())
                .await?;
            if parent.is_none() {
                debug!(
                    "Processing of {} suspended: missing parent",
                    header.id
                );
                return Ok(());
            }
        }

        let hid = header.id;
        let bytes = bincode::serialize(header).expect("Failed to serialize header");
        // Store the header.
        self.store.write(hid.to_vec(), bytes).await;

        Ok(())
    }

    // #[async_recursion]
    // async fn process_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
    //     debug!("Processing {:?}", timeout);

    //     // Check if we have enough timeout messages to create a timeout cert to propose next header.
    //     if let Some(timeout_cert) = self
    //         .timeouts_aggregators
    //         .entry(timeout.round)
    //         .or_insert_with(|| Box::new(TimeoutAggregator::new()))
    //         .append(timeout.clone(), &self.committee)?
    //     {
    //         debug!("Aggregated timeout cert {:?}", timeout);
    //         // Send it to the `Proposer`.
    //         self.tx_timeout_cert
    //             .send((timeout_cert, timeout.round))
    //             .await
    //             .expect("Failed to send timeout");
    //     }
    //     Ok(())
    // }

    async fn process_echo(&mut self, echo: &Echo) -> DagResult<()> {
        debug!("Processing {:?}", echo);

        if !self.processing_echo_aggregators.contains_key(&echo.id) {
            self.processing_echo_aggregators
                .entry(echo.id.clone())
                .or_insert(EchoAggregator::new());
        }
        if let Some(echo_aggregator) = self.processing_echo_aggregators.get_mut(&echo.id) {
            if let Some(certificate) = echo_aggregator.append(&echo, &self.committee)? {
                let ready = Ready::new(echo.id, echo.round, &echo.origin, &self.name).await;

                let addresses = self
                    .committee
                    .others_primaries(&self.name)
                    .iter()
                    .map(|(_, x)| x.primary_to_primary)
                    .collect();
                let bytes = bincode::serialize(&PrimaryMessage::Ready(ready.clone()))
                    .expect("Failed to serialize our own ready");
                let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                self.cancel_handlers
                    .entry(echo.round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);

                let _ = self.process_ready(&ready).await;
            }
        }     
        Ok(())
    }

    #[async_recursion]
    async fn process_ready(&mut self, ready: &Ready) -> DagResult<()> {
        debug!("Processing {:?}", ready);

        if !self.processing_ready_aggregators.contains_key(&ready.id) {
            self.processing_ready_aggregators
                .entry(ready.id.clone())
                .or_insert(ReadyAggregator::new());
        }

        // // Add it to the votes' aggregator and try to make a new certificate.
        if let Some(ready_aggregator) = self.processing_ready_aggregators.get_mut(&ready.id) {
            // Add it to the votes' aggregator and try to make a new certificate.
            if let Some(certificate) = ready_aggregator.append(&ready, &self.committee)? {
                // Process the new certificate.
                let _ = self.process_certificate(certificate).await;
            }
        }

        Ok(())
    }

    #[async_recursion]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        debug!("Processing cert {:?}", certificate);

        // Ensure we have all the ancestor of this certificate yet. If we don't, the synchronizer will gather it and trigger re-processing of this certificate.
        if !self.synchronizer.deliver_certificate(&certificate).await? {
            debug!(
                "Processing of {:?} suspended: missing parent",
                certificate
            );
            return Ok(());
        }

        if self.pending_commit_rounds.contains(&certificate.round) {
            self.commit(certificate.round).await?;
        }
        
        // Store the certificate.
        let bytes = bincode::serialize(&certificate).expect("Failed to serialize certificate");
        self.store.write(certificate.digest().to_vec(), bytes).await;

        // Send it to the `Proposer`.
        self.tx_proposer
            .send(certificate.clone())
            .await
            .expect("Failed to send certificate");

        self.certificates.entry(certificate.round).or_insert(certificate.clone());

        let decide = Decide::new(certificate.header_id, certificate.round, &certificate.origin, &self.name).await;

        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        let bytes = bincode::serialize(&PrimaryMessage::Decide(decide.clone()))
            .expect("Failed to serialize our own decide");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(certificate.round)
            .or_insert_with(Vec::new)
            .extend(handlers);
        Ok(())
    }


    #[async_recursion]
    async fn process_decide(&mut self, decide: &Decide) -> DagResult<()> {
        debug!("Processing {:?}", decide);

        if !self.processing_decide_aggregators.contains_key(&decide.id) {
            self.processing_decide_aggregators
                .entry(decide.id.clone())
                .or_insert(DecideAggregator::new());
        }
        if let Some(decide_aggregator) = self.processing_decide_aggregators.get_mut(&decide.id) {
            // Call append() while holding a mutable borrow, capture the result and drop the borrow
            let decide_quorum = decide_aggregator.append(&decide, &self.committee)?;
            
            if decide_quorum.is_some() {
                self.commit(decide.round).await?;
            }
        }

        Ok(())
    }

    async fn commit(&mut self, round: Round) -> DagResult<()> {
        if self.last_committed_round >= round{
            return Ok(());
        }

        // Parent has been put in self.certificates.
        let certificate = match self.certificates.get(&round) {
            Some(c) => c.clone(),
            None => {
                // Record the round so we can attempt commit again when the certificate arrives.
                self.pending_commit_rounds.insert(round);
                return Ok(());
            }
        };

        let mut to_commit = VecDeque::new();
        // Collect full Header objects to commit (starting from the certificate's header)
        let mut cur = certificate.header_id;
        // Try to get the Header for the certificate's header_id. If missing, abort collection.
        let first_header = match self.parent_info.get(&cur).cloned() {
            Some(h) => h,
            None => {
                // Missing header info: record pending and return.
                self.pending_commit_rounds.insert(round);
                return Ok(());
            }
        };
        to_commit.push_front(first_header.clone());
        // We were able to collect the header to commit: clear any pending marker for this round.
        self.pending_commit_rounds.remove(&round);

        for _r in (self.last_committed_round + 1..=round - 1).rev() {
            let header = match self.parent_info.get(&cur).cloned() {
                Some(info) => info,
                None => break, // Missing ancestor -> stop collecting
            };
            let parent_digest = header.parent;

            let parent_header = match self.parent_info.get(&parent_digest).cloned() {
                Some(info) => info,
                None => break, // Missing parent header -> stop collecting
            };
            // push the parent Header to the front so deque orders from earliest->latest
            to_commit.push_front(parent_header.clone());
            self.pending_commit_rounds.remove(&parent_header.round);
            cur = parent_digest;
        }
        self.last_committed_round = round;
        // If parent is missing, to do.
        while let Some(header) = to_commit.pop_front() {
            for digest in header.payload.keys() {
                    // NOTE: This log entry is used to compute performance.
                    info!("Committed {} -> {:?}", header, digest);
            }
            info!("Committed {:?} ", header.id);
            debug!("round {:?} committed", round);
        }
        Ok(())
    }


    // fn sanitize_timeout(&mut self, timeout: &Timeout) -> DagResult<()> {
    //     ensure!(
    //         self.gc_round <= timeout.round,
    //         DagError::TooOld(timeout.digest(), timeout.round)
    //     );
    //     Ok(())
    // }

    fn sanitize_header_msg(&mut self, header: &Header) -> DagResult<()> {
        ensure!(
            self.gc_round <= header.round,
            DagError::TooOld(header.id, header.round)
        );
        Ok(())
    }

    fn sanitize_echo(&mut self, echo: &Echo) -> DagResult<()> {
        if let Some(header) = self.processing_headers.get(&echo.id) {
            ensure!(
                header.round <= echo.round,
                DagError::TooOld(echo.id, echo.round)
            );

            // Ensure we receive a vote on the expected header.
            ensure!(
                echo.id == header.id
                    && echo.origin == header.author
                    && echo.round == header.round,
                DagError::UnexpectedVote(echo.id.clone())
            );
        }
        Ok(())
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        let tx_primary = Arc::new(self.tx_primary.clone());

        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        // PrimaryMessage::Timeout(timeout) => {
                        //     match self.sanitize_timeout(&timeout) {
                        //         Ok(()) => self.process_timeout(timeout).await,
                        //         error => error
                        //     }
                        // },
                        PrimaryMessage::Echo(echo) => {
                            match self.sanitize_echo(&echo) {
                                Ok(()) => self.process_echo(&echo).await,
                                error => error
                            }
                        },
                        PrimaryMessage::Ready(ready) => {
                            self.process_ready(&ready).await
                        },
                        PrimaryMessage::Decide(decide) => {
                            self.process_decide(&decide).await
                        },
                        PrimaryMessage::Header(header) => {
                            match self.sanitize_header_msg(&header) {
                                Ok(()) => self.process_header_msg(&header).await,
                                error => error
                            }
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header) = self.rx_header_waiter.recv() => self.process_header_msg(&header).await,

                // We receive here loopback certificates from the `CertificateWaiter`. Those are certificates for which
                // we interrupted execution (we were missing some of their ancestors) and we are now ready to resume
                // processing.
                Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate(certificate).await,

                // We also receive here our new headers created by the `Proposer`.
                Some(header) = self.rx_proposer.recv() => self.process_own_header(header).await,

                // We also receive here our timeout created by the `Proposer`.
                // Some(timeout) = self.rx_timeout.recv() => self.process_own_timeout(timeout).await,
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
                self.processing_headers
                    .retain(|_, h| &h.round >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                // let _ = self.synchronizer.garbage_collect(gc_round).await;
                self.gc_round = gc_round;
            }
        }
    }
}
