// Copyright(C) Facebook, Inc. and its affiliates.
use crate::aggregators::VotesAggregator;
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, Vote};
use crate::primary::{PrimaryMessage, Round};
// use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use blsttc::{PublicKeyShareG1, PublicKeyShareG2};
use bytes::Bytes;
use config::Committee;
use crypto::Hash as _;
use crypto::{BlsSignatureService, Digest, PublicKey};
#[cfg(feature = "benchmark")]
use log::{debug, error, info, warn};
#[cfg(not(feature = "benchmark"))]
use log::{debug, error, warn};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use threadpool::ThreadPool;
use tokio::sync::mpsc::{Receiver, Sender};

// #[cfg(test)]
// #[path = "tests/core_tests.rs"]
// pub mod core_tests;

pub struct Core {
    /// The public key of this primary.
    name: PublicKey,
    name_bls_g1: PublicKeyShareG1,
    name_bls_g2: PublicKeyShareG2,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Handles synchronization with other nodes and our workers.
    // synchronizer: Synchronizer,
    /// Service to sign headers.
    bls_signature_service: BlsSignatureService,
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
    tx_proposer: Sender<(Vec<Digest>, Round)>,
    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    /// A network sender to send the batches to the other workers.
    network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
    /// Active set of headers we are currenting waiting for votes
    processing_headers: HashMap<Digest, Header>,
    processing_vote_aggregators: HashMap<Digest, VotesAggregator>,
    tx_primaries: Sender<PrimaryMessage>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        name_bls_g1: PublicKeyShareG1,
        name_bls_g2: PublicKeyShareG2,
        committee: Committee,
        store: Store,
        // synchronizer: Synchronizer,
        bls_signature_service: BlsSignatureService,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<Header>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<(Vec<Digest>, Round)>,
        tx_primaries: Sender<PrimaryMessage>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                name_bls_g1,
                name_bls_g2,
                committee,
                store,
                // synchronizer,
                bls_signature_service,
                consensus_round,
                gc_depth,
                rx_primaries,
                rx_header_waiter,
                rx_certificate_waiter,
                rx_proposer,
                tx_consensus,
                tx_proposer,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                processing_headers: HashMap::new(),
                processing_vote_aggregators: HashMap::new(),
                tx_primaries,
            }
            .run()
            .await;
        });
    }

    async fn process_own_header(&mut self, header: Header) -> DagResult<()> {
        // Reset the votes aggregator.
        self.processing_headers
            .entry(header.id.clone())
            .or_insert(header.clone());
        self.processing_vote_aggregators
            .entry(header.id.clone())
            .or_insert(VotesAggregator::new());

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
        // debug!("Processing {:?}", header);

        // Ensure we have the payload. If we don't, the synchronizer will ask our workers to get it, and then
        // reschedule processing of this header once we have it.
        // if self.synchronizer.missing_payload(header).await? {
        //     // debug!("Processing of {} suspended: missing payload", header);
        //     return Ok(());
        // }

        // Store the header.
        let bytes = bincode::serialize(header).expect("Failed to serialize header");
        self.store.write(header.id.to_vec(), bytes).await;

        // Check if we can vote for this header.

        // Make a vote and send it to the header's creator.
        let vote = Vote::new(header, &self.name, &mut self.bls_signature_service).await;
        // debug!("Created {:?}", vote);

        if vote.origin == self.name {
            self.process_vote(vote)
                .await
                .expect("Failed to process our own vote");
        } else {
            let address = self
                .committee
                .primary(&header.author)
                .expect("Author of valid header is not in the committee")
                .primary_to_primary;
            let bytes = bincode::serialize(&PrimaryMessage::Vote(vote))
                .expect("Failed to serialize our own vote");
            let handler = self.network.send(address, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(header.round)
                .or_insert_with(Vec::new)
                .push(handler);
        }

        Ok(())
    }

    #[async_recursion]
    async fn process_vote(&mut self, vote: Vote) -> DagResult<()> {
        // debug!("Processing {:?}", vote);

        if let (Some(header), Some(vote_aggregator)) = (
            self.processing_headers.get(&vote.id),
            self.processing_vote_aggregators.get_mut(&vote.id),
        ) {
            // Add it to the votes' aggregator and try to make a new certificate.
            if let Some(certificate) =
                vote_aggregator.append(vote.clone(), &self.committee, header)?
            {
                // debug!("Assembled {:?}", certificate);

                // Broadcast the certificate.
                let addresses = self
                    .committee
                    .others_primaries(&self.name)
                    .iter()
                    .map(|(_, x)| x.primary_to_primary)
                    .collect();
                let bytes = bincode::serialize(&PrimaryMessage::Certificate(certificate.clone()))
                    .expect("Failed to serialize our own certificate");
                let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                self.cancel_handlers
                    .entry(certificate.round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);

                self.processing_headers.remove(&vote.id);
                self.processing_vote_aggregators.remove(&vote.id);

                // Process the new certificate.
                self.process_certificate(certificate)
                    .await
                    .expect("Failed to process valid certificate");
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        // debug!("Processing {:?}", certificate);

        // Process the header embedded in the certificate if we haven't already voted for it (if we already
        // voted, it means we already processed it). Since this header got certified, we are sure that all
        // the data it refers to (ie. its payload and its parents) are available. We can thus continue the
        // processing of the certificate even if we don't have them in store right now.
        // if !self
        //     .processing
        //     .get(&certificate.header.round)
        //     .map_or_else(|| false, |x| x.contains(&certificate.header.id))
        // {
        //     // This function may still throw an error if the storage fails.
        //     self.process_header(&certificate.header).await?;
        // }

        // Store the certificate.
        let bytes = bincode::serialize(&certificate).expect("Failed to serialize certificate");
        self.store.write(certificate.digest().to_vec(), bytes).await;

        #[cfg(feature = "benchmark")]
        {
            info!(
                "Sending Certificate for Header {:?} to consensus",
                certificate.id
            );
        }
        // Send it to the consensus layer.
        let id = certificate.id.clone();
        if let Err(e) = self.tx_consensus.send(certificate).await {
            warn!(
                "Failed to deliver certificate {} to the consensus: {}",
                id, e
            );
        }
        Ok(())
    }

    fn sanitize_header(&mut self, header: &Header) -> DagResult<()> {
        ensure!(
            self.gc_round <= header.round,
            DagError::HeaderTooOld(header.id.clone(), header.round)
        );

        // Verify the header's signature.
        header.verify(&self.committee)?;

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
    }

    fn sanitize_vote(&mut self, vote: &Vote) -> DagResult<()> {
        if let Some(header) = self.processing_headers.get(&vote.id) {
            // Ensure we receive a vote on the expected header.
            ensure!(
                vote.id == header.id && vote.origin == header.author && vote.round == header.round,
                DagError::UnexpectedVote(vote.id.clone())
            );

            // Verify the vote.
            // vote.verify(&self.committee).map_err(DagError::from)
            Ok(())
        } else {
            Ok(())
        }
    }

    fn sanitize_certificate(
        &mut self,
        certificate: Certificate,
        tx_primaries: Sender<PrimaryMessage>,
        pool: &ThreadPool,
        committee: Arc<Committee>,
    ) -> DagResult<()> {
        ensure!(
            self.gc_round <= certificate.round,
            DagError::CertificateTooOld(certificate.digest(), certificate.round)
        );

        pool.execute(move || {
            let _ = certificate.verify(&committee).map_err(DagError::from);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let _ = tx_primaries
                    .send(PrimaryMessage::VerifiedCertificate(certificate))
                    .await;
            });
        });
        Ok(())

        // // Verify the certificate (and the embedded header).
        // certificate
        //     .verify(&self.committee, &self.sorted_keys)
        //     .map_err(DagError::from)
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        let pool = ThreadPool::new(4);

        let committee = Arc::new(self.committee.clone());
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
                        PrimaryMessage::Vote(vote) => {
                            match self.sanitize_vote(&vote) {
                                Ok(()) => self.process_vote(vote).await,
                                error => error
                            }
                        },
                        PrimaryMessage::Certificate(certificate) => {
                            let committee = Arc::clone(&committee);
                            let result = self.sanitize_certificate(certificate, self.tx_primaries.clone(), &pool, committee);
                            result
                        },
                        PrimaryMessage::VerifiedCertificate(certificate) => {
                            let result = self.process_certificate(certificate).await;
                            result
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header) = self.rx_header_waiter.recv() => self.process_header(&header).await,

                // We receive here loopback certificates from the `CertificateWaiter`. Those are certificates for which
                // we interrupted execution (we were missing some of their ancestors) and we are now ready to resume
                // processing.
                Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate(certificate).await,

                // We also receive here our new headers created by the `Proposer`.
                Some(header) = self.rx_proposer.recv() => self.process_own_header(header).await,
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
                // self.processing.retain(|k, _| k >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.gc_round = gc_round;
                // debug!("GC round moved to {}", self.gc_round);
            }
        }
    }
}
