// Copyright(C) Facebook, Inc. and its affiliates.
use crate::aggregators::{CertificatesAggregator, HeadersAggregator, VotesAggregator};
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, Vote, ReadyHeader, EchoHeader};
use crate::primary::{PrimaryMessage, Round};
use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use bytes::Bytes;
use config::{Committee, Stake,};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, warn, info};
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

    /// Receiver for dag messages (headers, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<Header>,
    /// Receives loopback certificates from the `CertificateWaiter`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<Header>,
    /// Output all certificates to the consensus layer.
    tx_consensus: Sender<Certificate>,
    /// Send valid a quorum of certificates' ids to the `Proposer` (along with their round).
    tx_proposer: Sender<(Vec<Header>, Round)>,

    tx_consensus_header: Sender<Header>,
    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    /// The set of headers we are currently processing.
    processing: HashMap<Round, HashSet<Digest>>,
    /// The last header we proposed (for which we are waiting votes).
    current_header: Header,
    /// Aggregates votes into a certificate.
    votes_aggregator: VotesAggregator,
    processing_headers: HashMap<Digest, Header>,
    /// Aggregates certificates to use as parents for new headers.
    certificates_aggregators: HashMap<Round, Box<CertificatesAggregator>>,
    /// A network sender to send the batches to the other workers.
    network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
    header_aggregators: HashMap<Round, Box<HeadersAggregator>>,
    echo_headers: HashMap<(Round, Digest), HashSet<PublicKey>>,
    ready_headers: HashMap<(Round, Digest), HashSet<PublicKey>>,
    ready_header_sent: HashMap<(Round, Digest), bool>,
    consensus_header_sent: HashMap<(Round, Digest), bool>,
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
        rx_header_waiter: Receiver<Header>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<(Vec<Header>, Round)>,
        tx_consensus_header: Sender<Header>,
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
                tx_consensus,
                tx_proposer,
                tx_consensus_header,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                processing: HashMap::with_capacity(2 * gc_depth as usize),
                current_header: Header::default(),
                votes_aggregator: VotesAggregator::new(),
                processing_headers: HashMap::new(),
                certificates_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                header_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                echo_headers: HashMap::new(),
                ready_headers: HashMap::new(),
                ready_header_sent: HashMap::new(),
                consensus_header_sent: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    async fn process_own_header(&mut self, header: Header) -> DagResult<()> {
        // Reset the votes aggregator.
        self.current_header = header.clone();
        // self.votes_aggregator = VotesAggregator::new();

        // Broadcast the new header in a reliable manner.
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

        // Process the header.
        self.process_header(&header).await
    }

    #[async_recursion]
    async fn process_header(&mut self, header: &Header) -> DagResult<()> {
        debug!("Processing {:?} at round {:?}", header, header.round);
        // Indicate that we are processing this header.
        // self.processing
        //     .entry(header.round)
        //     .or_insert_with(HashSet::new)
        //     .insert(header.id.clone());

        self.processing_headers
            .entry(header.id.clone())
            .or_insert(header.clone());

        if header.round != 1 {
            // Ensure we have the parents. If at least one parent is missing, the synchronizer returns an empty
            // vector; it will gather the missing parents (as well as all ancestors) from other nodes and then
            // reschedule processing of this header.
            let parents = self.synchronizer.get_parents(header).await?;
            if parents.is_empty() {
                debug!("Processing of {} suspended: missing parent(s)", header.id);
                return Ok(());
            }

            // Check the parent headers. Ensure the parents form a quorum and are all from the previous round.
            let mut stake = 0;
            for x in parents {
                ensure!(
                    x.round + 1 == header.round,
                    DagError::MalformedHeader(header.id.clone())
                );
                stake += self.committee.stake(&x.author);
            }
            ensure!(
                stake >= self.committee.quorum_threshold(),
                DagError::HeaderRequiresQuorum(header.id.clone())
            );

            // Ensure we have the payload. If we don't, the synchronizer will ask our workers to get it, and then
            // reschedule processing of this header once we have it.
            if self.synchronizer.missing_payload(header).await? {
                debug!("Processing of {} suspended: missing payload", header);
                return Ok(());
            }
        }
        // Store the header.
        let bytes = bincode::serialize(header).expect("Failed to serialize header");
        self.store.write(header.id.to_vec(), bytes).await;

        // Send <ECHO, H(m)> to primaries.
        let addresses = self
        .committee
        .others_primaries(&self.name)
        .iter()
        .map(|(_, info)| info.primary_to_primary)
        .collect();

        let echo_header = EchoHeader::new(&header, &self.name).await;
        let bytes = bincode::serialize(&PrimaryMessage::Echo(echo_header))
        .expect("Failed to serialize EchoHeader");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

        self.cancel_handlers
        .entry(header.round)
        .or_insert_with(Vec::new)
        .extend(handlers);

        // Initialize the HashMap if it doesn't exist
        self.echo_headers
        .entry((header.round, header.id.clone()))
        .or_insert_with(HashSet::new)
        .insert(self.name.clone());

        // info!("self.name: {:?}", self.name);
        // info!("Initialized echo_headers from header: {:?}", self.echo_headers);

        // Log the broadcast for debugging purposes
        debug!("Broadcasted EchoHeader with hash {:?}", header.round);

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
                    // info!("Broadcasted ReadyHeader with hash {:?}", echo_header.round);
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
    
        let ready_headers: Vec<_> = self.ready_headers
            .iter()
            .filter(|((r, d), _)| *r == round && *d == digest)
            .map(|(_, a)| a.clone())
            .collect();
        
        if let Some(ready_key) = self.ready_headers.get(&(round, digest.clone())) {
            let weight: Stake = ready_key.iter().map(|author| self.committee.stake(author)).sum();
            // info!("weight: {:?}", weight);
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

                    self.ready_header_sent.insert((ready_header.round.clone(), ready_header.id.clone()), true);
                    info!("sent ready header!");
                }
            }

            // Check if we have received 2f+1 <Ready, H(m)> 
            if weight >= self.committee.quorum_threshold() {   
                while self.processing_headers.get(&ready_header.id).is_none() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }

                if let Some(header) = self.processing_headers.get(&ready_header.id) {
                    // Send header to consensus
                    if !self.consensus_header_sent.contains_key(&(header.round, header.id.clone())) {
                        // info!("Sending header {:?} to consensus at round {:?}", header.id, header.round);
                        self.tx_consensus_header
                            .send(header.clone())
                            .await
                            .expect("Failed to send header to consensus");
                        self.consensus_header_sent.insert((header.round.clone(), header.id.clone()), true);
                        // Check if we have enough headers to enter a new dag round and propose a header.
                        // QY: in the happy case: check if we have received leader's Header
                        if let Some(parents) = self
                            .header_aggregators
                            .entry(header.round)
                            .or_insert_with(|| Box::new(HeadersAggregator::new()))
                            .append(header.clone(), &self.committee)? {

                            if let Some(parent) = parents.iter()
                                .find(|parent| parent.author == self.committee.leader(header.round as usize)) {
                                // Send it to the `Proposer`.
                                self.tx_proposer
                                    .send((parents.clone(), header.round))
                                    .await
                                    .expect("Failed to send header to proposer");
                                // info!("sending parents: {:?} at round {:?}", parents.clone(), header.round);
                                // info!("parents_len: {:?}", parents.len());
                                // info!("sent parents to proposer at round {:?}!", header.round);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }


    // #[async_recursion]
    // async fn process_vote(&mut self, vote: Vote) -> DagResult<()> {
    //     debug!("Processing {:?}", vote);

    //     // Add it to the votes' aggregator and try to make a new certificate.
    //     if let Some(certificate) =
    //         self.votes_aggregator
    //             .append(vote, &self.committee, &self.current_header)?
    //     {
    //         debug!("Assembled {:?}", certificate);

    //         // Broadcast the certificate.
    //         let addresses = self
    //             .committee
    //             .others_primaries(&self.name)
    //             .iter()
    //             .map(|(_, x)| x.primary_to_primary)
    //             .collect();
    //         let bytes = bincode::serialize(&PrimaryMessage::Certificate(certificate.clone()))
    //             .expect("Failed to serialize our own certificate");
    //         let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
    //         self.cancel_handlers
    //             .entry(certificate.round())
    //             .or_insert_with(Vec::new)
    //             .extend(handlers);

    //         // Process the new certificate.
    //         self.process_certificate(certificate)
    //             .await
    //             .expect("Failed to process valid certificate");
    //     }
    //     Ok(())
    // }

    fn sanitize_header(&mut self, header: &Header) -> DagResult<()> {
        ensure!(
            self.gc_round <= header.round,
            DagError::TooOld(header.id.clone(), header.round)
        );

        // Verify the header's signature.
        header.verify(&self.committee)?;

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
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

    fn sanitize_vote(&mut self, vote: &Vote) -> DagResult<()> {
        ensure!(
            self.current_header.round <= vote.round,
            DagError::TooOld(vote.digest(), vote.round)
        );

        // Ensure we receive a vote on the expected header.
        ensure!(
            vote.id == self.current_header.id
                && vote.origin == self.current_header.author
                && vote.round == self.current_header.round,
            DagError::UnexpectedVote(vote.id.clone())
        );

        // Verify the vote.
        vote.verify(&self.committee).map_err(DagError::from)
    }

    fn sanitize_certificate(&mut self, certificate: &Certificate) -> DagResult<()> {
        ensure!(
            self.gc_round <= certificate.round(),
            DagError::TooOld(certificate.digest(), certificate.round())
        );

        // Verify the certificate (and the embedded header).
        certificate.verify(&self.committee).map_err(DagError::from)
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::Header(header) => {
                            match self.sanitize_header(&header) {
                                Ok(()) => self.process_header(&header).await,
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

                        // PrimaryMessage::Vote(vote) => {
                        //     match self.sanitize_vote(&vote) {
                        //         Ok(()) => self.process_vote(vote).await,
                        //         error => error
                        //     }
                        // },
                        // PrimaryMessage::Certificate(certificate) => {
                        //     match self.sanitize_certificate(&certificate) {
                        //         Ok(()) =>  self.process_certificate(certificate).await,
                        //         error => error
                        //     }
                        // },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header) = self.rx_header_waiter.recv() => self.process_header(&header).await,

                // We receive here loopback certificates from the `CertificateWaiter`. Those are certificates for which
                // we interrupted execution (we were missing some of their ancestors) and we are now ready to resume
                // processing.
                // Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate(certificate).await,

                // We also receive here our new headers created by the `Proposer`.
                Some(header) = self.rx_proposer.recv() => self.process_own_header(header).await,
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
                self.processing.retain(|k, _| k >= &gc_round);
                self.certificates_aggregators.retain(|k, _| k >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.gc_round = gc_round;
            }
        }
    }
}
