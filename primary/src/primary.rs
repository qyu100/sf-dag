#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::certificate_waiter::CertificateWaiter;
use crate::committer::Committer;
use crate::core::Core;
use crate::error::DagError;
use crate::garbage_collector::GarbageCollector;
use crate::header_waiter::HeaderWaiter;
use crate::helper::Helper;
use crate::leader::LeaderElector;
use crate::messages::{Certificate, Header, HeaderInfo, Vote, Timeout, TC, Proposal, ConsensusMessage, ConsensusVote, ConsensusRequest, CutProposal, CutVote, CutReady, CutCertificate, Decide};
use crate::payload_receiver::PayloadReceiver;
use crate::proposer::Proposer;
use crate::synchronizer::Synchronizer;
use async_trait::async_trait;
use bytes::Bytes;
use config::{Committee, Parameters, WorkerId};
use crypto::{Digest, PublicKey, SignatureService};
use futures::sink::SinkExt as _;
use log::info;
use network::{MessageHandler, Receiver as NetworkReceiver, Writer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};

/// The default channel capacity for each channel of the primary.
pub const CHANNEL_CAPACITY: usize = 1_000;

/// The round number.
pub type Height = u64;
/// The view number (of consensus)
pub type View = u64;
// The slot (sequence) number of consensus
pub type Slot = u64;

#[derive(Debug, Serialize, Deserialize)]
pub enum PrimaryMessage {
    Header(Header, bool),
    Vote(Vote),
    Certificate(Certificate),
    CutProposal(CutProposal),
    CutVote(CutVote),
    CutReady(CutReady),
    CutCertificate(CutCertificate),
    Decide(Decide),
    Timeout(Timeout),
    TC(TC),
    ConsensusMessage(ConsensusMessage),
    ConsensusRequest(ConsensusRequest),
    ConsensusVote(ConsensusVote),
    CertificatesRequest(Vec<Digest>, /* requestor */ PublicKey),
    HeadersRequest(Vec<Digest>, /* requestor */ PublicKey),
    ProposalHeadersRequest(Proposal, Height, /* requestor */ PublicKey),
}

#[derive(Serialize)]
pub enum PrimaryMessageRef<'a> {
    Header(&'a Header, bool),
}

/// The messages sent by the primary to its workers.
#[derive(Debug, Serialize, Deserialize)]
pub enum PrimaryWorkerMessage {
    /// The primary indicates that the worker need to sync the target missing batches.
    Synchronize(Vec<Digest>, /* target */ PublicKey),
    /// The primary indicates a round update.
    Cleanup(Height),
}

/// The messages sent by the workers to their primary.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerPrimaryMessage {
    /// The worker indicates it sealed a new batch.
    OurBatch(Digest, WorkerId),
    /// The worker indicates it received a batch's digest from another authority.
    OthersBatch(Digest, WorkerId),
}

pub struct Primary;

impl Primary {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        // signature_service: SignatureService,
        store: Store,
        _tx_consensus: Sender<Certificate>,
        tx_committer: Sender<Certificate>,
        rx_committer: Receiver<Certificate>,
        rx_consensus: Receiver<Certificate>,
        _tx_sailfish: Sender<Header>,
        _rx_pushdown_cert: Receiver<Certificate>,
        rx_request_header_sync: Receiver<Digest>,
        tx_output: Sender<Header>,
    ) {
        let (tx_others_digests, rx_others_digests) = channel(CHANNEL_CAPACITY);
        let (tx_our_digests, rx_our_digests) = channel(CHANNEL_CAPACITY);
        let (tx_parents, rx_parents) = channel(CHANNEL_CAPACITY);
        let (tx_headers, rx_headers) = channel(CHANNEL_CAPACITY);
        let (tx_sync_headers, rx_sync_headers) = channel(CHANNEL_CAPACITY);
        let (tx_sync_certificates, rx_sync_certificates) = channel(CHANNEL_CAPACITY);
        let (tx_headers_loopback, rx_headers_loopback) = channel::<HeaderInfo>(CHANNEL_CAPACITY);
        let (tx_certificates_loopback, rx_certificates_loopback) = channel(CHANNEL_CAPACITY);
        let (tx_primary_messages, rx_primary_messages) = channel(CHANNEL_CAPACITY);
        let (tx_cert_requests, rx_cert_requests) = channel(CHANNEL_CAPACITY);
        let (tx_header_requests, rx_header_requests) = channel(CHANNEL_CAPACITY);
        let (tx_instance, rx_instance) = channel(CHANNEL_CAPACITY);
        let (tx_header_waiter_instances, rx_header_waiter_instances) = channel(CHANNEL_CAPACITY);
        let (tx_commit, rx_commit) = channel(CHANNEL_CAPACITY);
        let (_tx_mempool, rx_mempool) = channel(CHANNEL_CAPACITY);


        // Write the parameters to the logs.
        // NOTE: These log entries are needed to compute performance.
        parameters.log();

        // Atomic variable use to synchronizer all tasks with the latest consensus round. This is only
        // used for cleanup. The only tasks that write into this variable is `GarbageCollector`.
        let consensus_round = Arc::new(AtomicU64::new(0));

        // Spawn the network receiver listening to messages from the other primaries.
        let mut address = committee
            .primary(&name)
            .expect("Our public key or worker id is not in the committee")
            .primary_to_primary;
        address.set_ip("0.0.0.0".parse().unwrap());
        NetworkReceiver::spawn(
            address,
            /* handler */
            PrimaryReceiverHandler {
                tx_primary_messages,
                tx_cert_requests,
                tx_header_requests,
            },
        );
        info!(
            "Primary {} listening to primary messages on {}",
            name, address
        );

        // Spawn the network receiver listening to messages from our workers.
        let mut address = committee
            .primary(&name)
            .expect("Our public key or worker id is not in the committee")
            .worker_to_primary;
        address.set_ip("0.0.0.0".parse().unwrap());
        NetworkReceiver::spawn(
            address,
            /* handler */
            WorkerReceiverHandler {
                tx_our_digests,
                tx_others_digests,
            },
        );
        info!(
            "Primary {} listening to workers messages on {}",
            name, address
        );

        // The `Synchronizer` provides auxiliary methods helping to `Core` to sync.
        let synchronizer = Synchronizer::new(
            name,
            &committee,
            store.clone(),
            /* tx_header_waiter */ tx_sync_headers,
            /* tx_certificate_waiter */ tx_sync_certificates,
        );

        let timeout_delay = 1000;


        // use_optimistic_tips: bool,     //default = true (TODO: implement non optimistic tip option)
        
        // use_parallel_proposals: bool,  //default = true (TODO: implement sequential slot option)
        // let k = 1; //Max open conensus instances at a time.

        // use_fast_path: bool,           //default = false
        // fast_path_timeout: u64,

        // use_ride_share: bool,
        // car_timeout: u64,

        // The `Core` receives and handles headers, votes, and certificates from the other primaries.
        Core::spawn(
            name,
            committee.clone(),
            store.clone(),
            synchronizer.clone(),
            // signature_service.clone(),
            consensus_round.clone(),
            parameters.gc_depth,
            /* rx_primaries */ rx_primary_messages,
            /* rx_header_waiter */ rx_headers_loopback,
            rx_header_waiter_instances,
            /* rx_proposer */ rx_headers,
            /* tx_committer */ tx_commit,
            /* tx_committer_cert */ tx_committer,
            /* tx_proposer */ tx_parents,
            rx_request_header_sync,
            /*tx info */ tx_instance,
            LeaderElector::new(committee.clone()),
            parameters.timeout_delay,
            parameters.use_optimistic_tips,
            parameters.use_parallel_proposals,
            parameters.k,
            parameters.use_fast_path,
            parameters.fast_path_timeout,
            parameters.use_ride_share,
            parameters.car_timeout,
            parameters.simulate_asynchrony,
            parameters.asynchrony_start,
            parameters.asynchrony_duration,
            rx_certificates_loopback,
        );

        Committer::spawn(committee.clone(), store.clone(), parameters.gc_depth, rx_mempool, rx_committer, rx_commit, tx_output, synchronizer);

        // Keeps track of the latest consensus round and allows other tasks to clean up their their internal state
        GarbageCollector::spawn(
            &name,
            &committee,
            store.clone(),
            consensus_round.clone(),
            rx_consensus,
            tx_certificates_loopback.clone(),
        );

        // Receives batch digests from other workers. They are only used to validate headers.
        PayloadReceiver::spawn(store.clone(), /* rx_workers */ rx_others_digests);

        // Whenever the `Synchronizer` does not manage to validate a header due to missing parent certificates of
        // batch digests, it commands the `HeaderWaiter` to synchronizer with other nodes, wait for their reply, and
        // re-schedule execution of the header once we have all missing data.
        HeaderWaiter::spawn(
            name,
            committee.clone(),
            store.clone(),
            consensus_round,
            parameters.gc_depth,
            parameters.sync_retry_delay,
            parameters.sync_retry_nodes,
            /* rx_synchronizer */ rx_sync_headers,
            /* tx_core */ tx_headers_loopback,
            tx_header_waiter_instances,
        );

        // The `CertificateWaiter` waits to receive all the ancestors of a certificate before looping it back to the
        // `Core` for further processing.
        CertificateWaiter::spawn(
            store.clone(),
            /* rx_synchronizer */ rx_sync_certificates,
            /* tx_core */ tx_certificates_loopback,
        );

        // When the `Core` collects enough parent certificates, the `Proposer` generates a new header with new batch
        // digests from our workers and it back to the `Core`.
        Proposer::spawn(
            name,
            committee.clone(),
            // signature_service,
            parameters.header_size,
            parameters.max_header_delay,
            /* rx_core */ rx_parents,
            /* rx_workers */ rx_our_digests,
            /* tx_core */ tx_headers,
            parameters.tx_size,
        );

        // The `Helper` is dedicated to reply to certificates requests from other primaries.
        Helper::spawn(committee.clone(), store, rx_cert_requests, rx_header_requests);

        // NOTE: This log entry is used to compute performance.
        info!(
            "Primary {} successfully booted on {}",
            name,
            committee
                .primary(&name)
                .expect("Our public key or worker id is not in the committee")
                .primary_to_primary
                .ip()
        );
    }
}

/// Defines how the network receiver handles incoming primary messages.
#[derive(Clone)]
struct PrimaryReceiverHandler {
    tx_primary_messages: Sender<PrimaryMessage>,
    tx_cert_requests: Sender<(Vec<Digest>, PublicKey)>,
    tx_header_requests: Sender<(Vec<Digest>, PublicKey)>,
}

#[async_trait]
impl MessageHandler for PrimaryReceiverHandler {
    async fn dispatch(&self, writer: &mut Writer, serialized: Bytes) -> Result<(), Box<dyn Error>> {
        // Reply with an ACK.
        let _ = writer.send(Bytes::from("Ack")).await;

        // Deserialize and parse the message.
        match bincode::deserialize(&serialized).map_err(DagError::SerializationError)? {
            PrimaryMessage::CertificatesRequest(missing, requestor) => self
                .tx_cert_requests
                .send((missing, requestor))
                .await
                .expect("Failed to send primary message"),
            PrimaryMessage::HeadersRequest(missing, requestor) => self
                .tx_header_requests
                .send((missing, requestor))
                .await
                .expect("Failed to send primary message"),
            request => {
                ////println!("Made it to dispatch");
                self
                .tx_primary_messages
                .send(request)
                .await
                .expect("Failed to send certificate")
            }
        }
        Ok(())
    }
}

/// Defines how the network receiver handles incoming workers messages.
#[derive(Clone)]
struct WorkerReceiverHandler {
    tx_our_digests: Sender<(Digest, WorkerId)>,
    tx_others_digests: Sender<(Digest, WorkerId)>,
}

#[async_trait]
impl MessageHandler for WorkerReceiverHandler {
    async fn dispatch(
        &self,
        _writer: &mut Writer,
        serialized: Bytes,
    ) -> Result<(), Box<dyn Error>> {
        // Deserialize and parse the message.
        match bincode::deserialize(&serialized).map_err(DagError::SerializationError)? {
            WorkerPrimaryMessage::OurBatch(digest, worker_id) => self
                .tx_our_digests                                         //sender channel to Proposer
                .send((digest, worker_id))
                .await
                .expect("Failed to send workers' digests"),
            WorkerPrimaryMessage::OthersBatch(digest, worker_id) => self
                .tx_others_digests                                      //sender channel to PayloadReceiver
                .send((digest, worker_id))
                .await
                .expect("Failed to send workers' digests"),
        }
        Ok(())
    }
}
