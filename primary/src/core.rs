// Copyright(C) Facebook, Inc. and its affiliates.
use crate::aggregators::{
    DecideAggregator, EchoAggregator, TimeoutAcceptAggregator, TimeoutAggregator,
};
use crate::coding::Coding;
use crate::error::{DagError, DagResult};
use crate::merkle::MerkleTree;
use crate::messages::{
    Certificate, Decide, Echo, Header, HeaderInfoWithProof, ProposerParent, Timeout, TimeoutAccept,
    TimeoutCert,
};
use crate::primary::{PrimaryMessage, PrimaryMessageRef, Round};
use crate::proposer::{ProposalSource, ProposerCommand};
use crate::synchronizer::Synchronizer;
use crate::{ConsensusMessage, HeaderInfo};
use async_recursion::async_recursion;
use bytes::Bytes;
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::{CancelHandler, ReliableSender};
use rayon::prelude::*; // parallel iterator for hashing reconstructed shards
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

// #[cfg(test)]
// #[path = "tests/core_tests.rs"]
// pub mod core_tests;

/// Result from background own-header computation.
struct OwnHeaderComputeResult {
    header_info: HeaderInfo,
    messages: Vec<(Option<HeaderInfoWithProof>, Option<Bytes>)>,
    round: Round,
    build_total_ms: u128,
}

struct ReconstructionResult {
    id: Digest,
    round: Round,
    origin: PublicKey,
    success: bool,
}

pub struct Core {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Arc<Committee>,
    /// The persistent storage.
    store: Store,
    /// Handles synchronization with other nodes and our workers.
    synchronizer: Synchronizer,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,
    /// Sender to loopback messages to self (core)
    tx_primary: Sender<PrimaryMessage>,
    /// Receiver for dag messages (headers, timeouts, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<HeaderInfoWithProof>,
    /// Receives loopback certificates from the `CertificateWaiter`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<Header>,
    /// Receives our newly created timeouts from the `Proposer`.
    rx_timeout: Receiver<Timeout>,
    /// Output all certificates to the consensus layer.
    tx_consensus: Sender<Certificate>,
    /// Send normal and speculative parent signals to the `Proposer`.
    tx_proposer: Sender<ProposerCommand>,
    /// Send a valid TimeoutCertificate along with the round to the `Proposer`.
    tx_timeout_cert: Sender<(TimeoutCert, Round)>,
    /// Send a the header that has voted for the prev leader to the `Consensus` logic.
    tx_consensus_header_msg: Sender<ConsensusMessage>,
    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    /// For storing info of header infos in processing
    processing_header_infos: HashMap<Digest, HeaderInfo>,
    /// For storing proof of header infos in processing
    processing_header_proofs: HashMap<Digest, HeaderInfoWithProof>,
    /// For storing info of echo aggregators in processing
    processing_echo_aggregators: HashMap<Digest, EchoAggregator>,
    /// For storing info of decide aggregators in processing
    processing_decide_aggregators: HashMap<Digest, DecideAggregator>,
    /// For storing info of processed certificates
    processed_certs: HashMap<Round, HashSet<PublicKey>>,
    /// Rounds pending commit because certificate was missing at commit time
    pending_commit_rounds: HashSet<Round>,
    /// Speculative parent hints waiting for opt cert(r-2).
    pending_proposer_parents: HashMap<Round, (ProposerParent, Instant)>,
    /// Rounds for which a speculative parent hint has already been sent to the proposer.
    proposer_hints_sent: HashSet<Round>,
    /// Rounds for which a normal certificate parent hint has already been sent to the proposer.
    normal_hints_sent: HashSet<Round>,
    /// Rounds for which speculative proposing already requested local cert reprocessing.
    syncing_speculative_certificates: HashSet<Round>,
    /// Rounds whose certificate reached the optimistic RBC threshold.
    optimistic_certificates: HashSet<Round>,
    /// Header digests currently being reconstructed for RBC delivery.
    delivery_reconstructions: HashSet<Digest>,
    /// Certificates waiting for the previous round certificate before being processed.
    pending_certificates: HashMap<Round, Vec<Certificate>>,
    /// Headers waiting for local safe-parent evidence (certificate or timeout cert).
    pending_headers: HashMap<Round, Vec<HeaderInfoWithProof>>,
    /// A network sender to send the batches to the other workers.
    network: ReliableSender,
    /// Separate control-plane sender for timeout and timeout-accept messages.
    timeout_network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
    /// Aggregates timeout votes to use for sending timeout accepts.
    timeouts_aggregators: HashMap<Round, Box<TimeoutAggregator>>,
    /// Aggregates timeout accepts to use for creating timeout certificates.
    timeout_accept_aggregators: HashMap<Round, Box<TimeoutAcceptAggregator>>,
    /// Rounds for which this node has already sent a timeout accept.
    sent_timeout_accepts: HashSet<Round>,
    /// Rounds for which a timeout certificate has already been formed.
    certified_timed_out: HashSet<Round>,
    /// The Reed-Solomon erasure coding configuration.
    coding: Arc<Coding>,
    /// Stored Merkle trees for reconstructed data
    mtrees: HashMap<Digest, MerkleTree>,
    /// Stored leaf shards collected from Echo quorum (keyed by (round, root) -> leaf values)
    echo_shards: HashMap<(Round, Digest), Vec<Option<Box<[u8]>>>>,
    /// Pending reconstructions waiting for HeaderInfoWithProof (keyed by header id): (root, shards)
    pending_reconstructions: HashMap<Digest, Digest>,
    // certificates to commit
    certificates: HashMap<Round, Certificate>,
    /// last committed round
    last_committed_round: Round,
    // Stored parent info
    parent_info: HashMap<Digest, (Round, Digest)>,
    rs_block_size: usize,
    rs_block_threads: usize,
    /// Channel for receiving background own-header compute results.
    tx_own_header_result: Sender<OwnHeaderComputeResult>,
    rx_own_header_result: Receiver<OwnHeaderComputeResult>,
    /// Channel for receiving background echo reconstruction results.
    tx_reconstruction_result: Sender<ReconstructionResult>,
    rx_reconstruction_result: Receiver<ReconstructionResult>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Arc<Committee>,
        store: Store,
        synchronizer: Synchronizer,
        signature_service: SignatureService,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        tx_primary: Sender<PrimaryMessage>,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<HeaderInfoWithProof>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        rx_timeout: Receiver<Timeout>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<ProposerCommand>,
        tx_timeout_cert: Sender<(TimeoutCert, Round)>,
        tx_consensus_header_msg: Sender<ConsensusMessage>,
        rs_block_size: usize,
        rs_block_threads: usize,
    ) {
        tokio::spawn(async move {
            // Precompute shard counts so we don't move `committee` before using it.
            let data_shard_num = committee.data_shard_num() as usize;
            let parity_shard_num = committee.parity_shard_num() as usize;
            let (tx_own_header_result, rx_own_header_result) = tokio::sync::mpsc::channel(8);
            let (tx_reconstruction_result, rx_reconstruction_result) =
                tokio::sync::mpsc::channel(8);
            Self {
                name,
                committee: committee.clone(),
                store,
                synchronizer,
                signature_service,
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
                processing_header_infos: HashMap::new(),
                processing_header_proofs: HashMap::new(),
                processing_echo_aggregators: HashMap::new(),
                processing_decide_aggregators: HashMap::new(),
                processed_certs: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                timeout_network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                timeouts_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                timeout_accept_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                sent_timeout_accepts: HashSet::new(),
                certified_timed_out: HashSet::new(),
                coding: Arc::new(
                    Coding::new(data_shard_num, parity_shard_num).unwrap_or_else(|e| {
                        warn!(
                            "Failed to create Reed-Solomon coding (falling back to trivial): {:?}",
                            e
                        );
                        Coding::Trivial(data_shard_num)
                    }),
                ),
                mtrees: HashMap::new(),
                echo_shards: HashMap::new(),
                pending_reconstructions: HashMap::new(),
                pending_commit_rounds: HashSet::new(),
                pending_proposer_parents: HashMap::new(),
                proposer_hints_sent: HashSet::new(),
                normal_hints_sent: HashSet::new(),
                syncing_speculative_certificates: HashSet::new(),
                optimistic_certificates: HashSet::new(),
                delivery_reconstructions: HashSet::new(),
                pending_certificates: HashMap::new(),
                pending_headers: HashMap::new(),
                certificates: HashMap::new(),
                last_committed_round: 0,
                parent_info: HashMap::new(),
                rs_block_size: rs_block_size,
                rs_block_threads: rs_block_threads,
                tx_own_header_result,
                rx_own_header_result,
                tx_reconstruction_result,
                rx_reconstruction_result,
            }
            .run()
            .await;
        });
    }

    /// Test-only constructor: identical to the body of `spawn()` but returns
    /// `Self` instead of spawning a tokio task.  This allows benchmarks and
    /// unit tests to call methods directly on a `Core` instance.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_test(
        name: PublicKey,
        committee: Arc<Committee>,
        store: Store,
        synchronizer: Synchronizer,
        signature_service: SignatureService,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        tx_primary: Sender<PrimaryMessage>,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<HeaderInfoWithProof>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        rx_timeout: Receiver<Timeout>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<ProposerCommand>,
        tx_timeout_cert: Sender<(TimeoutCert, Round)>,
        tx_consensus_header_msg: Sender<ConsensusMessage>,
        rs_block_size: usize,
        rs_block_threads: usize,
    ) -> Self {
        let data_shard_num = committee.data_shard_num() as usize;
        let parity_shard_num = committee.parity_shard_num() as usize;
        let (tx_own_header_result, rx_own_header_result) = tokio::sync::mpsc::channel(8);
        let (tx_reconstruction_result, rx_reconstruction_result) = tokio::sync::mpsc::channel(8);
        Self {
            name,
            committee: committee.clone(),
            store,
            synchronizer,
            signature_service,
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
            processing_header_infos: HashMap::new(),
            processing_header_proofs: HashMap::new(),
            processing_echo_aggregators: HashMap::new(),
            processing_decide_aggregators: HashMap::new(),
            processed_certs: HashMap::with_capacity(2 * gc_depth as usize),
            network: ReliableSender::new(),
            timeout_network: ReliableSender::new(),
            cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
            timeouts_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
            timeout_accept_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
            sent_timeout_accepts: HashSet::new(),
            certified_timed_out: HashSet::new(),
            coding: Arc::new(
                Coding::new(data_shard_num, parity_shard_num).unwrap_or_else(|e| {
                    warn!(
                        "Failed to create Reed-Solomon coding (falling back to trivial): {:?}",
                        e
                    );
                    Coding::Trivial(data_shard_num)
                }),
            ),
            mtrees: HashMap::new(),
            echo_shards: HashMap::new(),
            pending_reconstructions: HashMap::new(),
            pending_commit_rounds: HashSet::new(),
            pending_proposer_parents: HashMap::new(),
            proposer_hints_sent: HashSet::new(),
            normal_hints_sent: HashSet::new(),
            syncing_speculative_certificates: HashSet::new(),
            optimistic_certificates: HashSet::new(),
            delivery_reconstructions: HashSet::new(),
            pending_certificates: HashMap::new(),
            pending_headers: HashMap::new(),
            certificates: HashMap::new(),
            last_committed_round: 0,
            parent_info: HashMap::new(),
            rs_block_size,
            rs_block_threads,
            tx_own_header_result,
            rx_own_header_result,
            tx_reconstruction_result,
            rx_reconstruction_result,
        }
    }

    async fn process_own_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        let bytes = bincode::serialize(&PrimaryMessage::Timeout(timeout.clone()))
            .expect("Failed to serialize own timeout");

        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();
        let handlers = self
            .timeout_network
            .broadcast(addresses, Bytes::from(bytes))
            .await;
        self.cancel_handlers
            .entry(timeout.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        debug!("Broadcasted own timeout for round {}", timeout.round);
        self.process_timeout(timeout).await
    }

    async fn process_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        timeout.verify(&self.committee)?;
        let round = timeout.round;
        if self.certified_timed_out.contains(&round) {
            return Ok(());
        }
        self.timeouts_aggregators
            .entry(round)
            .or_insert_with(|| Box::new(TimeoutAggregator::new()));

        if let Some(aggregator) = self.timeouts_aggregators.get_mut(&round) {
            if aggregator.append(timeout, &self.committee)?.is_some() {
                if let Some((weight, timeout_cert)) = self.send_timeout_accept(round).await? {
                    self.handle_timeout_accept_action(round, weight, timeout_cert)
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn broadcast_timeout_accept(&mut self, accept: &TimeoutAccept) -> DagResult<()> {
        let bytes = bincode::serialize(&PrimaryMessage::TimeoutAccept(accept.clone()))
            .expect("Failed to serialize timeout accept");

        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();
        let handlers = self
            .timeout_network
            .broadcast(addresses, Bytes::from(bytes))
            .await;
        self.cancel_handlers
            .entry(accept.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        #[cfg(feature = "benchmark")]
        info!(
            "BENCH event=timeout_accept_sent round={} node={:?}",
            accept.round, accept.author
        );
        Ok(())
    }

    async fn send_timeout_accept(
        &mut self,
        round: Round,
    ) -> DagResult<Option<(u32, Option<TimeoutCert>)>> {
        if !self.sent_timeout_accepts.insert(round) {
            return Ok(None);
        }

        let accept = TimeoutAccept::new(round, self.name);
        let result = self.record_timeout_accept(accept.clone()).map(Some)?;
        self.broadcast_timeout_accept(&accept).await?;
        Ok(result)
    }

    fn record_timeout_accept(
        &mut self,
        accept: TimeoutAccept,
    ) -> DagResult<(u32, Option<TimeoutCert>)> {
        accept.verify(&self.committee)?;
        let round = accept.round;
        if self.certified_timed_out.contains(&round) {
            return Ok((0, None));
        }

        self.timeout_accept_aggregators
            .entry(round)
            .or_insert_with(|| Box::new(TimeoutAcceptAggregator::new()));

        self.timeout_accept_aggregators
            .get_mut(&round)
            .expect("timeout accept aggregator exists")
            .append(accept, &self.committee)
    }

    async fn process_timeout_accept(&mut self, accept: TimeoutAccept) -> DagResult<()> {
        let round = accept.round;
        let (weight, timeout_cert) = self.record_timeout_accept(accept)?;
        self.handle_timeout_accept_action(round, weight, timeout_cert)
            .await
    }

    async fn handle_timeout_accept_action(
        &mut self,
        round: Round,
        weight: u32,
        mut timeout_cert: Option<TimeoutCert>,
    ) -> DagResult<()> {
        if weight >= self.committee.validity_threshold() {
            if let Some((_, own_timeout_cert)) = self.send_timeout_accept(round).await? {
                timeout_cert = timeout_cert.or(own_timeout_cert);
            }
        }

        if let Some(timeout_cert) = timeout_cert {
            if self.certified_timed_out.insert(round) {
                #[cfg(feature = "benchmark")]
                info!(
                    "BENCH event=timeout_cert round={} node={:?}",
                    round, self.name
                );
                self.tx_timeout_cert
                    .send((timeout_cert, round))
                    .await
                    .expect("Failed to send timeout certificate to proposer");
                self.release_deferred_certificates(round).await?;
                self.release_deferred_headers(round).await?;
            }
        }
        Ok(())
    }

    fn dispatch_own_header(&self, header: Header) -> DagResult<()> {
        let coding = Arc::clone(&self.coding);
        let committee = Arc::clone(&self.committee);
        let name = self.name;
        let rs_block_size = self.rs_block_size;
        let rs_block_threads = self.rs_block_threads;
        let tx = self.tx_own_header_result.clone();

        tokio::task::spawn_blocking(move || {
            let start_total = Instant::now();

            let t_setup = Instant::now();
            let mut header_info = HeaderInfo::create_from_fast(&header);
            let data_shard_num = coding.data_shard_count();
            let parity_shard_num = coding.parity_shard_count();
            let payload = header.payload;
            let d_setup = t_setup.elapsed();

            let t_ser = Instant::now();
            let payload_bytes = match bincode::serialize(&payload) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to serialize payload: {:?}", e);
                    return;
                }
            };
            let d_ser = t_ser.elapsed();
            let mut payload_bytes = payload_bytes;

            let payload_len = payload_bytes.len();
            header_info.payload_len = payload_len;

            let t_pad = Instant::now();
            let mut shard_len = (payload_len + data_shard_num - 1) / data_shard_num;
            if shard_len == 0 {
                shard_len = 1;
            }
            if shard_len % 64 != 0 {
                shard_len += 64 - (shard_len % 64);
            }
            payload_bytes.resize(shard_len * (data_shard_num + parity_shard_num), 0);
            let d_pad = t_pad.elapsed();

            let mut shards_vec: Vec<&mut [u8]> = payload_bytes.chunks_mut(shard_len).collect();

            let t_encode = Instant::now();
            coding
                .encode(&mut shards_vec, rs_block_size, rs_block_threads)
                .expect("wrong shard size");
            let d_encode = t_encode.elapsed();

            let t_mtree = Instant::now();
            let hashes: Vec<Digest> = shards_vec
                .par_iter()
                .map(|s| MerkleTree::digest(&**s))
                .collect();
            let mtree = MerkleTree::from_hashes(hashes);
            let d_mtree = t_mtree.elapsed();

            assert_eq!(committee.total_stake() as usize, mtree.leaf_count());

            let t_proofs = Instant::now();
            let sorted_keys = &committee.sorted_keys;
            let self_index = sorted_keys.iter().position(|pk| pk == &name);

            let shards_refs: Vec<&[u8]> = shards_vec.iter().map(|s| &**s).collect();

            let messages: Vec<(Option<HeaderInfoWithProof>, Option<Bytes>)> = (0..sorted_keys
                .len())
                .into_par_iter()
                .map(|index| {
                    let leaf = shards_refs[index];
                    let proof = mtree
                        .proof_with_leaf(index, leaf)
                        .expect("proof construction failed");
                    let hiwp = HeaderInfoWithProof {
                        author: header_info.author,
                        round: header_info.round,
                        parent: header_info.parent,
                        id: header_info.id,
                        proof,
                        payload_len: header_info.payload_len,
                    };
                    if Some(index) == self_index {
                        (Some(hiwp), None)
                    } else {
                        let bytes = bincode::serialize(&PrimaryMessage::HeaderInfoWithProof(hiwp))
                            .expect("Failed to serialize proof");
                        (None, Some(Bytes::from(bytes)))
                    }
                })
                .collect();
            let d_proofs = t_proofs.elapsed();

            let round = header_info.round;
            let build_total = start_total.elapsed();
            debug!("dispatch_own_header bg setup={:?} serialize={:?} pad={:?} encode={:?} merkle={:?} proofs={:?} total={:?}",
                d_setup, d_ser, d_pad, d_encode, d_mtree, d_proofs, build_total);

            let _ = tx.blocking_send(OwnHeaderComputeResult {
                header_info,
                messages,
                round,
                build_total_ms: build_total.as_millis(),
            });
        });
        Ok(())
    }

    /// Handle the result of a background own-header computation.
    /// Performs network sends and state updates inline.
    async fn handle_own_header_result(&mut self, result: OwnHeaderComputeResult) -> DagResult<()> {
        let start = Instant::now();

        // Store header_info in processing map
        self.processing_header_infos
            .entry(result.header_info.id)
            .or_insert(result.header_info.clone());

        let sorted_keys = self.committee.sorted_keys.clone();
        for (index, pk) in sorted_keys.iter().enumerate() {
            match &result.messages[index] {
                (Some(hiwp), _) => {
                    self.process_header_proof_optimized(hiwp)
                        .await
                        .expect("Failed to process our own proof");
                }
                (_, Some(bytes)) => {
                    let address = self
                        .committee
                        .primary(pk)
                        .expect("unknown primary")
                        .primary_to_primary;
                    let handler = self.network.send(address, bytes.clone()).await;
                    self.cancel_handlers
                        .entry(result.round)
                        .or_insert_with(Vec::new)
                        .push(handler);
                }
                _ => unreachable!(),
            }
        }
        #[cfg(feature = "benchmark")]
        info!(
            "BENCH event=own_header_ready node={:?} round={} digest={:?} build_total_ms={} send_ms={} recipients={}",
            self.name,
            result.round,
            result.header_info.id,
            result.build_total_ms,
            start.elapsed().as_millis(),
            self.committee.sorted_keys.len().saturating_sub(1)
        );
        Ok(())
    }

    async fn process_header_proof_optimized(
        &mut self,
        header_info_with_proof: &HeaderInfoWithProof,
    ) -> DagResult<()> {
        let start = Instant::now();
        debug!(
            "Header info with proof payload len: {}",
            header_info_with_proof.proof.value().len()
        );
        self.parent_info
            .entry(header_info_with_proof.id)
            .or_insert((header_info_with_proof.round, header_info_with_proof.parent));

        // 2c: Use or_insert_with for lazy clone — only clones on cache miss.
        self.processing_header_proofs
            .entry(header_info_with_proof.id)
            .or_insert_with(|| header_info_with_proof.clone());

        let t_parent = Instant::now();
        if header_info_with_proof.round != 1 {
            // 2b: Pass header_info_with_proof directly — no unnecessary .clone().
            let parent = self.synchronizer.get_parent(header_info_with_proof).await?;
            debug!("get_parent time: {:?}", t_parent.elapsed());
            if parent.is_none() {
                debug!(
                    "Processing of {} suspended: missing parent",
                    header_info_with_proof.id
                );
                return Ok(());
            }
        }

        if self
            .defer_header_until_safe_parent(header_info_with_proof)
            .await?
        {
            return Ok(());
        }

        self.register_proposer_parent(header_info_with_proof)
            .await?;

        self.echo_header(header_info_with_proof).await?;

        let hid = header_info_with_proof.id;
        let bytes = bincode::serialize(header_info_with_proof).expect("Failed to serialize header");
        // Store the header.
        self.store.write(hid.to_vec(), bytes).await;

        // If a reconstruction was waiting for this header's info, resume it now.
        if let Some(_root) = self
            .pending_reconstructions
            .remove(&header_info_with_proof.id)
        {
            // 3b: pass only the small fields needed by finalize_reconstruction_optimized.
            if let Err(e) = self
                .finalize_reconstruction_optimized(
                    header_info_with_proof.id,
                    header_info_with_proof.round,
                    header_info_with_proof.author,
                )
                .await
            {
                warn!(
                    "Failed to finalize pending reconstruction for {:?}: {}",
                    header_info_with_proof.id, e
                );
            }
            debug!(
                "process_header_proof_optimized total time: {:?}",
                start.elapsed()
            );
            return Ok(());
        }
        debug!(
            "process_header_proof_optimized total time: {:?}",
            start.elapsed()
        );
        Ok(())
    }

    fn is_genesis_parent(&self, digest: Digest) -> bool {
        Header::genesis(&self.committee)
            .iter()
            .any(|header| header.id == digest)
    }

    async fn parent_round_for_digest(&mut self, digest: Digest) -> DagResult<Option<Round>> {
        if self.is_genesis_parent(digest) {
            return Ok(Some(0));
        }

        if let Some((round, _)) = self.parent_info.get(&digest) {
            return Ok(Some(*round));
        }

        let Some(bytes) = self.store.read(digest.to_vec()).await? else {
            return Ok(None);
        };

        let header_info_with_proof: HeaderInfoWithProof = bincode::deserialize(&bytes)?;
        self.parent_info
            .entry(digest)
            .or_insert((header_info_with_proof.round, header_info_with_proof.parent));
        Ok(Some(header_info_with_proof.round))
    }

    fn defer_header_until_round(
        &mut self,
        header_info_with_proof: &HeaderInfoWithProof,
        wait_round: Round,
        reason: &'static str,
    ) {
        let pending = self
            .pending_headers
            .entry(wait_round)
            .or_insert_with(Vec::new);

        if !pending.iter().any(|x| {
            x.round == header_info_with_proof.round
                && x.id == header_info_with_proof.id
                && x.author == header_info_with_proof.author
        }) {
            debug!(
                "Deferring header {:?} round {} until {} for round {}",
                header_info_with_proof.id, header_info_with_proof.round, reason, wait_round
            );
            pending.push(header_info_with_proof.clone());
        }
    }

    async fn defer_header_until_safe_parent(
        &mut self,
        header_info_with_proof: &HeaderInfoWithProof,
    ) -> DagResult<bool> {
        let round = header_info_with_proof.round;
        if round <= 1 {
            return Ok(false);
        }

        let Some(parent_round) = self
            .parent_round_for_digest(header_info_with_proof.parent)
            .await?
        else {
            return Ok(false);
        };

        if parent_round >= round {
            warn!(
                "Ignoring header {:?} for round {} with invalid parent round {}",
                header_info_with_proof.id, round, parent_round
            );
            return Ok(true);
        }

        for timeout_round in parent_round + 1..round {
            if !self.certified_timed_out.contains(&timeout_round) {
                self.defer_header_until_round(
                    header_info_with_proof,
                    timeout_round,
                    "timeout certificate",
                );
                return Ok(true);
            }
        }

        if parent_round + 1 < round && parent_round > 0 {
            match self.certificates.get(&parent_round) {
                Some(certificate) if certificate.header_id == header_info_with_proof.parent => {}
                _ => {
                    self.defer_header_until_round(
                        header_info_with_proof,
                        parent_round,
                        "parent certificate",
                    );
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn register_proposer_parent(
        &mut self,
        header_info_with_proof: &HeaderInfoWithProof,
    ) -> DagResult<()> {
        let parent_round = header_info_with_proof.round;
        if parent_round == 0
            || self.committee.leader(parent_round as usize) != header_info_with_proof.author
        {
            return Ok(());
        }

        let propose_round = parent_round + 1;

        let parent = ProposerParent {
            header_id: header_info_with_proof.id,
            round: parent_round,
            origin: header_info_with_proof.author,
        };

        self.pending_proposer_parents
            .entry(propose_round)
            .or_insert((parent, Instant::now()));
        self.try_release_proposer_parent(propose_round).await?;

        if self.proposer_hints_sent.contains(&propose_round) {
            return Ok(());
        }

        if parent_round > 1 {
            let opt_cert_round = parent_round - 1;
            if self.certified_timed_out.contains(&opt_cert_round) {
                return Ok(());
            }
            if !self.optimistic_certificates.contains(&opt_cert_round) {
                self.sync_missing_speculative_certificate(
                    opt_cert_round,
                    header_info_with_proof.parent,
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn sync_missing_speculative_certificate(
        &mut self,
        required_cert_round: Round,
        required_header_id: Digest,
    ) -> DagResult<()> {
        if !self
            .syncing_speculative_certificates
            .insert(required_cert_round)
        {
            return Ok(());
        }

        match self.store.read(required_header_id.to_vec()).await? {
            Some(bytes) => match bincode::deserialize::<HeaderInfoWithProof>(&bytes) {
                Ok(header_info_with_proof)
                    if header_info_with_proof.round == required_cert_round
                        && header_info_with_proof.id == required_header_id =>
                {
                    #[cfg(feature = "benchmark")]
                    debug!(
                        "BENCH event=speculative_cert_sync node={:?} wait_cert_round={} digest={:?} origin={:?} source=local_header_reprocess",
                        self.name,
                        required_cert_round,
                        required_header_id,
                        header_info_with_proof.author
                    );

                    if let Err(e) = self
                        .tx_primary
                        .try_send(PrimaryMessage::HeaderInfoWithProof(header_info_with_proof))
                    {
                        self.syncing_speculative_certificates
                            .remove(&required_cert_round);
                        warn!(
                            "Failed to enqueue speculative certificate sync for round {}: {}",
                            required_cert_round, e
                        );
                    }
                }
                Ok(header_info_with_proof) => {
                    self.syncing_speculative_certificates
                        .remove(&required_cert_round);
                    warn!(
                        "Stored header mismatch while syncing speculative certificate: expected round {} digest {:?}, got round {} digest {:?}",
                        required_cert_round,
                        required_header_id,
                        header_info_with_proof.round,
                        header_info_with_proof.id
                    );
                }
                Err(e) => {
                    self.syncing_speculative_certificates
                        .remove(&required_cert_round);
                    warn!(
                        "Failed to deserialize header while syncing speculative certificate for round {} digest {:?}: {}",
                        required_cert_round,
                        required_header_id,
                        e
                    );
                }
            },
            None => {
                self.syncing_speculative_certificates
                    .remove(&required_cert_round);
                #[cfg(feature = "benchmark")]
                debug!(
                    "BENCH event=speculative_cert_sync node={:?} wait_cert_round={} digest={:?} source=missing_header",
                    self.name,
                    required_cert_round,
                    required_header_id
                );
            }
        }

        Ok(())
    }

    async fn notify_proposer(
        &mut self,
        parent: ProposerParent,
        source: ProposalSource,
        wait_cert_round: Round,
        wait_ms: u128,
    ) -> DagResult<()> {
        #[cfg(feature = "benchmark")]
        debug!(
            "BENCH event=parent_ready node={:?} source={} propose_round={} parent_round={} parent_digest={:?} wait_cert_round={} wait_ms={}",
            self.name,
            match source {
                ProposalSource::Speculative => "speculative",
                ProposalSource::Normal => "normal",
            },
            parent.round + 1,
            parent.round,
            parent.header_id,
            wait_cert_round,
            wait_ms
        );
        self.tx_proposer
            .send(ProposerCommand::Parent(parent, source))
            .await
            .expect("Failed to send parent to proposer");
        Ok(())
    }

    async fn try_release_proposer_parent(&mut self, propose_round: Round) -> DagResult<()> {
        if self.proposer_hints_sent.contains(&propose_round) {
            return Ok(());
        };

        let Some((parent, started_at)) = self.pending_proposer_parents.get(&propose_round).cloned()
        else {
            return Ok(());
        };

        let parent_round = parent.round;
        let ready = if parent_round <= 1 {
            Some((ProposalSource::Speculative, 0))
        } else if self.optimistic_certificates.contains(&(parent_round - 1)) {
            Some((ProposalSource::Speculative, parent_round - 1))
        } else {
            None
        };

        let Some((source, wait_cert_round)) = ready else {
            return Ok(());
        };

        self.pending_proposer_parents.remove(&propose_round);
        self.proposer_hints_sent.insert(propose_round);
        self.notify_proposer(
            parent,
            source,
            wait_cert_round,
            started_at.elapsed().as_millis(),
        )
        .await?;

        Ok(())
    }

    async fn release_proposer_parents_for_certificate(
        &mut self,
        certified_round: Round,
    ) -> DagResult<()> {
        self.notify_normal_proposer_for_certificate(certified_round)
            .await?;
        self.try_release_proposer_parent(certified_round + 2).await
    }

    async fn notify_normal_proposer_for_certificate(
        &mut self,
        certified_round: Round,
    ) -> DagResult<()> {
        let Some(certificate) = self.certificates.get(&certified_round).cloned() else {
            return Ok(());
        };

        let propose_round = certified_round + 1;
        if certified_round == 0 || !self.normal_hints_sent.insert(propose_round) {
            return Ok(());
        }

        let parent = ProposerParent {
            header_id: certificate.header_id,
            round: certificate.round,
            origin: certificate.origin,
        };

        self.proposer_hints_sent.insert(propose_round);
        self.notify_proposer(parent, ProposalSource::Normal, certified_round, 0)
            .await?;

        Ok(())
    }

    fn defer_certificate_until_previous(&mut self, certificate: Certificate) -> bool {
        if certificate.round <= 1
            || self.certificates.contains_key(&(certificate.round - 1))
            || self.certified_timed_out.contains(&(certificate.round - 1))
        {
            return false;
        }

        let wait_round = certificate.round - 1;
        self.defer_certificate_until_round(certificate, wait_round);
        true
    }

    fn defer_certificate_until_round(&mut self, certificate: Certificate, wait_round: Round) {
        let pending = self
            .pending_certificates
            .entry(wait_round)
            .or_insert_with(Vec::new);

        if !pending.iter().any(|x| {
            x.round == certificate.round
                && x.header_id == certificate.header_id
                && x.origin == certificate.origin
        }) {
            pending.push(certificate);
        }
    }

    async fn release_deferred_certificates(&mut self, certified_round: Round) -> DagResult<()> {
        let Some(certificates) = self.pending_certificates.remove(&certified_round) else {
            return Ok(());
        };

        for certificate in certificates {
            self.process_certificate_optimized(certificate).await?;
        }

        Ok(())
    }

    async fn release_deferred_headers(&mut self, wait_round: Round) -> DagResult<()> {
        let Some(headers) = self.pending_headers.remove(&wait_round) else {
            return Ok(());
        };

        for header_info_with_proof in headers {
            self.process_header_proof_optimized(&header_info_with_proof)
                .await?;
        }

        Ok(())
    }

    async fn defer_certificate_until_safe_parent(
        &mut self,
        certificate: Certificate,
    ) -> DagResult<bool> {
        let Some((round, parent_digest)) = self.parent_info.get(&certificate.header_id).cloned()
        else {
            return Ok(false);
        };

        let Some(parent_round) = self.parent_round_for_digest(parent_digest).await? else {
            return Ok(false);
        };

        if parent_round >= round {
            warn!(
                "Ignoring certificate {:?} for round {} with invalid parent round {}",
                certificate.header_id, round, parent_round
            );
            return Ok(true);
        }

        for timeout_round in parent_round + 1..round {
            if !self.certified_timed_out.contains(&timeout_round) {
                self.defer_certificate_until_round(certificate, timeout_round);
                return Ok(true);
            }
        }

        if parent_round + 1 < round && parent_round > 0 {
            match self.certificates.get(&parent_round) {
                Some(parent_certificate) if parent_certificate.header_id == parent_digest => {}
                _ => {
                    self.defer_certificate_until_round(certificate, parent_round);
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn echo_header(&mut self, header_info_with_proof: &HeaderInfoWithProof) -> DagResult<()> {
        let round = header_info_with_proof.round;

        if self
            .last_voted
            .entry(round)
            .or_insert_with(HashSet::new)
            .insert(header_info_with_proof.author)
        {
            let echo = Echo::new(header_info_with_proof, &self.name).await;
            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, x)| x.primary_to_primary)
                .collect();

            let bytes = bincode::serialize(&PrimaryMessageRef::Echo(&echo))
                .expect("Failed to serialize our own echo");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(round)
                .or_insert_with(Vec::new)
                .extend(handlers);

            self.process_echo_optimized(echo)
                .await
                .expect("Failed to process our own echo");
        }

        Ok(())
    }

    async fn process_echo_optimized(&mut self, echo: Echo) -> DagResult<()> {
        let proof = echo.proof;
        let author = echo.author;
        let id = echo.id;
        let round = echo.round;
        let origin = echo.origin;

        let valid = self.committee.index_of(&author) == Some(proof.index())
            && proof.validate(self.committee.total_stake() as usize);

        if valid {
            if !self.processing_echo_aggregators.contains_key(&id) {
                self.processing_echo_aggregators
                    .entry(id)
                    .or_insert(EchoAggregator::new());
            }
            if let Some(echo_aggregator) = self.processing_echo_aggregators.get_mut(&id) {
                let agg_result = echo_aggregator.append(author, proof, &self.committee)?;

                if let Some((root, leaf_values)) = agg_result.optimistic {
                    self.spawn_reconstruction(id, round, origin, root, leaf_values)
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn spawn_reconstruction(
        &mut self,
        header_id: Digest,
        round: Round,
        origin: PublicKey,
        root: Digest,
        mut leaf_values: Vec<Option<Box<[u8]>>>,
    ) -> DagResult<()> {
        if self.certificates.contains_key(&round)
            || !self.delivery_reconstructions.insert(header_id)
        {
            return Ok(());
        }

        let coding = Arc::clone(&self.coding);
        let rs_block_size = self.rs_block_size;
        let rs_block_threads = self.rs_block_threads;
        let tx = self.tx_reconstruction_result.clone();

        tokio::task::spawn_blocking(move || {
            if let Err(e) =
                coding.reconstruct_shards(&mut leaf_values[..], rs_block_size, rs_block_threads)
            {
                warn!("Reconstruction failed: {:?}", e);
                let _ = tx.blocking_send(ReconstructionResult {
                    id: header_id,
                    round,
                    origin,
                    success: false,
                });
                return;
            }

            let hashes: Vec<Digest> = leaf_values
                .par_iter()
                .map(|opt| {
                    let shard = opt
                        .as_ref()
                        .expect("reconstruct_shards produced all shards");
                    MerkleTree::digest(&**shard)
                })
                .collect();

            let mtree = MerkleTree::from_hashes(hashes);
            let success = *mtree.root_hash() == root;

            let _ = tx.blocking_send(ReconstructionResult {
                id: header_id,
                round,
                origin,
                success,
            });
        });

        Ok(())
    }

    /// Optimized finalize_reconstruction: takes only the small fields (id, round, author)
    /// instead of the full HeaderInfoWithProof (~2.9MB).
    #[allow(dead_code)]
    async fn finalize_reconstruction_optimized(
        &mut self,
        header_id: Digest,
        round: Round,
        author: PublicKey,
    ) -> DagResult<()> {
        let start = Instant::now();

        let certificate = Certificate {
            header_id,
            round,
            origin: author,
        };

        self.process_certificate_optimized(certificate).await?;
        debug!(
            "finalize_reconstruction_optimized total time: {:?}",
            start.elapsed()
        );
        Ok(())
    }

    /// Handle the result of a background echo reconstruction.
    async fn handle_reconstruction_result(
        &mut self,
        result: ReconstructionResult,
    ) -> DagResult<()> {
        self.delivery_reconstructions.remove(&result.id);

        if !result.success {
            warn!("Reconstruction verification failed for {:?}", result.id);
            return Err(DagError::ProofConstructionFailed);
        }

        let t_finalize = Instant::now();
        self.finalize_reconstruction_optimized(result.id, result.round, result.origin)
            .await?;
        debug!(
            "handle_reconstruction_result finalize={:?}",
            t_finalize.elapsed()
        );
        Ok(())
    }

    #[async_recursion]
    async fn process_certificate_optimized(&mut self, certificate: Certificate) -> DagResult<()> {
        debug!("Processing cert (optimized) {:?}", certificate);

        // Look up parent from in-memory map to avoid store read+deserialize.
        let parent = self
            .parent_info
            .get(&certificate.header_id)
            .map(|(_, p)| *p);
        if !self
            .synchronizer
            .deliver_certificate_optimized(&certificate, parent)
            .await?
        {
            debug!("Processing of {:?} suspended: missing parent", certificate);
            return Ok(());
        }

        if self.defer_certificate_until_previous(certificate.clone()) {
            return Ok(());
        }

        if self
            .defer_certificate_until_safe_parent(certificate.clone())
            .await?
        {
            return Ok(());
        }

        if matches!(self.certificates.get(&certificate.round), Some(existing) if existing.header_id == certificate.header_id)
        {
            return Ok(());
        }

        if self.pending_commit_rounds.contains(&certificate.round) {
            self.commit(certificate.round).await?;
        }

        // Extract small Copy/Clone-cheap fields before moving the certificate.
        let header_id = certificate.header_id;
        let round = certificate.round;
        let origin = certificate.origin;

        // Store in local map — move certificate in (no extra clone).
        self.certificates.entry(round).or_insert(certificate);
        self.syncing_speculative_certificates.remove(&round);
        if self.optimistic_certificates.insert(round) {
            #[cfg(feature = "benchmark")]
            debug!(
                "BENCH event=optimistic_cert round={} node={:?} digest={:?}",
                round, self.name, header_id
            );
        }
        self.release_deferred_headers(round).await?;
        self.release_proposer_parents_for_certificate(round).await?;

        // 4a: Build decide from the extracted small fields.
        let decide = Decide::new(header_id, round, &origin, &self.name).await;

        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        // 4a: Move decide into serialization (no clone needed).
        let bytes = bincode::serialize(&PrimaryMessage::Decide(decide.clone()))
            .expect("Failed to serialize our own decide");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        self.process_decide(&decide).await?;

        self.release_deferred_certificates(round).await?;

        Ok(())
    }

    #[async_recursion]
    async fn process_decide(&mut self, decide: &Decide) -> DagResult<()> {
        // debug!("Processing {:?}", decide);

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
        if self.last_committed_round >= round {
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
        let mut cur = certificate.header_id;
        to_commit.push_front(cur.clone());
        for _r in (self.last_committed_round + 1..=round - 1).rev() {
            let cur_info = match self.parent_info.get(&cur).cloned() {
                Some(info) => info,
                None => break, // To do.
            };
            let (_cur_round, parent_digest) = cur_info;

            let parent_info = match self.parent_info.get(&parent_digest).cloned() {
                Some(info) => info,
                None => break, // To do.
            };
            let (parent_round, _) = parent_info;
            if parent_round <= self.last_committed_round {
                break;
            }

            to_commit.push_front(parent_digest.clone());

            cur = parent_digest;
        }
        self.last_committed_round = round;
        // If parent is missing, to do.
        while let Some(header_id) = to_commit.pop_front() {
            info!("Committed {:?} ", header_id);
            // debug!("round {:?} committed", round);
        }
        Ok(())
    }

    fn sanitize_timeout(&mut self, timeout: &Timeout) -> DagResult<()> {
        ensure!(
            self.gc_round <= timeout.round,
            DagError::TooOld(timeout.digest(), timeout.round)
        );
        Ok(())
    }

    fn sanitize_timeout_accept(&mut self, accept: &TimeoutAccept) -> DagResult<()> {
        ensure!(
            self.gc_round <= accept.round,
            DagError::TooOld(accept.digest(), accept.round)
        );
        Ok(())
    }

    fn sanitize_header_proof(
        &mut self,
        header_info_with_proof: &HeaderInfoWithProof,
    ) -> DagResult<()> {
        ensure!(
            self.gc_round <= header_info_with_proof.round,
            DagError::TooOld(header_info_with_proof.id, header_info_with_proof.round)
        );
        Ok(())
    }

    fn sanitize_echo(&mut self, echo: &Echo) -> DagResult<()> {
        if let Some(header_info_with_proof) = self.processing_header_proofs.get(&echo.id) {
            ensure!(
                header_info_with_proof.round <= echo.round,
                DagError::TooOld(echo.id, echo.round)
            );

            // Ensure we receive a vote on the expected header.
            ensure!(
                echo.id == header_info_with_proof.id
                    && echo.origin == header_info_with_proof.author
                    && echo.round == header_info_with_proof.round,
                DagError::UnexpectedVote(echo.id.clone())
            );
        }
        Ok(())
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::Timeout(timeout) => {
                            match self.sanitize_timeout(&timeout) {
                                Ok(()) => self.process_timeout(timeout).await,
                                error => error
                            }
                        },
                        PrimaryMessage::TimeoutAccept(accept) => {
                            match self.sanitize_timeout_accept(&accept) {
                                Ok(()) => self.process_timeout_accept(accept).await,
                                error => error
                            }
                        },
                        PrimaryMessage::Echo(echo) => {
                            match self.sanitize_echo(&echo) {
                                Ok(()) => self.process_echo_optimized(echo).await,
                                error => error
                            }
                        },
                        PrimaryMessage::Decide(decide) => {
                            self.process_decide(&decide).await
                        },
                        PrimaryMessage::HeaderInfoWithProof(header_info_with_proof) => {
                            match self.sanitize_header_proof(&header_info_with_proof) {
                                Ok(()) => self.process_header_proof_optimized(&header_info_with_proof).await,
                                error => error
                            }
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header_info_with_proof) = self.rx_header_waiter.recv() => self.process_header_proof_optimized(&header_info_with_proof).await,

                // We receive here loopback certificates from the `CertificateWaiter`. Those are certificates for which
                // we interrupted execution (we were missing some of their ancestors) and we are now ready to resume
                // processing.
                Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate_optimized(certificate).await,

                // We also receive here our new headers created by the `Proposer`.
                // Dispatched to background thread — does not block the event loop.
                Some(header) = self.rx_proposer.recv() => self.dispatch_own_header(header),

                // Background own-header computation completed — do network sends inline.
                Some(result) = self.rx_own_header_result.recv() => self.handle_own_header_result(result).await,

                // Background echo reconstruction completed — finalize inline.
                Some(result) = self.rx_reconstruction_result.recv() => self.handle_reconstruction_result(result).await,

                // We also receive here our timeout created by the `Proposer`.
                Some(timeout) = self.rx_timeout.recv() => self.process_own_timeout(timeout).await,
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
                let header_rounds: HashMap<Digest, Round> = self
                    .processing_header_proofs
                    .iter()
                    .map(|(id, header)| (*id, header.round))
                    .collect();
                let keep_header_state = |id: &Digest| {
                    header_rounds
                        .get(id)
                        .map_or(true, |round| *round >= gc_round)
                };
                self.last_voted.retain(|k, _| k >= &gc_round);
                self.processing_header_infos
                    .retain(|_, h| &h.round >= &gc_round);
                self.processing_header_proofs
                    .retain(|_, h| &h.round >= &gc_round);
                self.pending_proposer_parents.retain(|k, _| k >= &gc_round);
                self.proposer_hints_sent.retain(|r| r >= &gc_round);
                self.normal_hints_sent.retain(|r| r >= &gc_round);
                self.syncing_speculative_certificates
                    .retain(|r| r >= &gc_round);
                self.optimistic_certificates.retain(|r| r >= &gc_round);
                self.delivery_reconstructions.retain(keep_header_state);
                self.pending_certificates.retain(|k, _| k >= &gc_round);
                self.pending_headers.retain(|k, _| k >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.timeouts_aggregators.retain(|k, _| k >= &gc_round);
                self.timeout_accept_aggregators
                    .retain(|k, _| k >= &gc_round);
                self.sent_timeout_accepts.retain(|r| r >= &gc_round);
                self.certified_timed_out.retain(|r| r >= &gc_round);
                // let _ = self.synchronizer.garbage_collect(gc_round).await;
                self.gc_round = gc_round;
            }
        }
    }
}

#[cfg(test)]
mod core_bench {
    use crate::coding::Coding;
    use crate::merkle::MerkleTree;
    use crate::messages::{Echo, HeaderInfoWithProof};
    use crate::primary::{PrimaryMessage, PrimaryMessageRef};
    use blsttc::PublicKeyShareG2;
    use config::{Authority, Committee, PrimaryAddresses};
    use crypto::{generate_production_keypair, Digest, PublicKey};
    use rayon::prelude::*;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

    /// Build a Committee of `n` authorities with f = `f_num`, each with stake 1.
    /// Returns (committee, vec of PublicKeys, vec of SecretKeys).
    /// SecretKeys are returned separately since they don't implement Clone.
    fn make_committee(n: usize, f_num: u32) -> (Committee, Vec<PublicKey>, Vec<crypto::SecretKey>) {
        let mut pks = Vec::with_capacity(n);
        let mut sks = Vec::with_capacity(n);
        for _ in 0..n {
            let (pk, sk) = generate_production_keypair();
            pks.push(pk);
            sks.push(sk);
        }
        let mut authorities = BTreeMap::new();
        let base_port = 10_000u16;
        for (i, pk) in pks.iter().enumerate() {
            let port = base_port + (i as u16) * 10;
            let authority = Authority {
                bls_pubkey_g2: PublicKeyShareG2::default(),
                stake: 1,
                primary: PrimaryAddresses {
                    primary_to_primary: format!("127.0.0.1:{}", port).parse().unwrap(),
                    worker_to_primary: format!("127.0.0.1:{}", port + 1).parse().unwrap(),
                },
                workers: HashMap::new(),
            };
            authorities.insert(*pk, authority);
        }
        let committee = Committee::new(authorities, f_num);
        (committee, pks, sks)
    }

    // -----------------------------------------------------------------------
    // Wire-format verification: PrimaryMessageRef vs PrimaryMessage
    // -----------------------------------------------------------------------
    /// Verify that PrimaryMessageRef::Echo(&echo) serializes to the same bytes
    /// as PrimaryMessage::Echo(echo), ensuring the borrowing wrapper is
    /// wire-compatible with the owning enum.
    #[tokio::test]
    async fn test_primary_message_ref_echo_wire_compat() {
        let n = 50usize;
        let f_num = 16u32;
        let (committee, pks, _sks) = make_committee(n, f_num);
        let committee = Arc::new(committee);

        // Build a small HeaderInfoWithProof to create a realistic Echo.
        let payload: Vec<Vec<u8>> = vec![vec![1u8; 64]; 10];
        let coding = Arc::new(
            Coding::new(
                committee.data_shard_num() as usize,
                committee.parity_shard_num() as usize,
            )
            .unwrap(),
        );
        let payload_bytes_raw = bincode::serialize(&payload).unwrap();
        let mut payload_bytes = payload_bytes_raw;
        let payload_len = payload_bytes.len();
        let data_shard_num = coding.data_shard_count();
        let parity_shard_num = coding.parity_shard_count();
        let total_shards = data_shard_num + parity_shard_num;
        let mut shard_len = (payload_len + data_shard_num - 1) / data_shard_num;
        if shard_len == 0 {
            shard_len = 1;
        }
        if shard_len % 64 != 0 {
            shard_len += 64 - (shard_len % 64);
        }
        payload_bytes.resize(shard_len * total_shards, 0);
        let mut shards_vec: Vec<&mut [u8]> = payload_bytes.chunks_mut(shard_len).collect();
        coding
            .encode(&mut shards_vec, 16 * 1024, 4)
            .expect("encode failed");
        let hashes: Vec<Digest> = shards_vec
            .par_iter()
            .map(|s| MerkleTree::digest(&**s))
            .collect();
        let mtree = MerkleTree::from_hashes(hashes);

        let proof = mtree.proof_with_leaf(0, &*shards_vec[0]).unwrap();
        let echo = Echo {
            id: Digest::default(),
            round: 42,
            origin: pks[0],
            author: pks[1],
            proof,
        };

        // Serialize with owning enum.
        let bytes_owned = bincode::serialize(&PrimaryMessage::Echo(echo.clone()))
            .expect("owned serialize failed");
        // Serialize with borrowing enum.
        let bytes_ref =
            bincode::serialize(&PrimaryMessageRef::Echo(&echo)).expect("ref serialize failed");

        assert_eq!(
            bytes_owned, bytes_ref,
            "PrimaryMessageRef::Echo wire format does not match PrimaryMessage::Echo"
        );
        println!(
            "PrimaryMessageRef wire-compat test passed ({} bytes)",
            bytes_owned.len()
        );
    }

    // -----------------------------------------------------------------------
    // Wire-format verification: helper.rs zero-copy variant tag prepend
    // -----------------------------------------------------------------------
    /// Verify that prepending the HIWP variant tag (3u32 LE) to a serialized
    /// HeaderInfoWithProof produces the same bytes as serializing
    /// PrimaryMessage::HeaderInfoWithProof(hiwp).
    #[tokio::test]
    async fn test_helper_zero_copy_wire_compat() {
        let n = 50usize;
        let f_num = 16u32;
        let (committee, pks, _sks) = make_committee(n, f_num);
        let committee = Arc::new(committee);

        let payload: Vec<Vec<u8>> = vec![vec![1u8; 64]; 10];
        let coding = Arc::new(
            Coding::new(
                committee.data_shard_num() as usize,
                committee.parity_shard_num() as usize,
            )
            .unwrap(),
        );
        let payload_bytes_raw = bincode::serialize(&payload).unwrap();
        let mut payload_bytes = payload_bytes_raw;
        let payload_len = payload_bytes.len();
        let data_shard_num = coding.data_shard_count();
        let parity_shard_num = coding.parity_shard_count();
        let total_shards = data_shard_num + parity_shard_num;
        let mut shard_len = (payload_len + data_shard_num - 1) / data_shard_num;
        if shard_len == 0 {
            shard_len = 1;
        }
        if shard_len % 64 != 0 {
            shard_len += 64 - (shard_len % 64);
        }
        payload_bytes.resize(shard_len * total_shards, 0);
        let mut shards_vec: Vec<&mut [u8]> = payload_bytes.chunks_mut(shard_len).collect();
        coding
            .encode(&mut shards_vec, 16 * 1024, 4)
            .expect("encode failed");
        let hashes: Vec<Digest> = shards_vec
            .par_iter()
            .map(|s| MerkleTree::digest(&**s))
            .collect();
        let mtree = MerkleTree::from_hashes(hashes);

        let proof = mtree.proof_with_leaf(0, &*shards_vec[0]).unwrap();
        let hiwp = HeaderInfoWithProof {
            author: pks[0],
            round: 7,
            parent: Digest::default(),
            id: Digest::default(),
            proof,
            payload_len: 12345,
        };

        // Canonical: serialize the full PrimaryMessage.
        let canonical = bincode::serialize(&PrimaryMessage::HeaderInfoWithProof(hiwp.clone()))
            .expect("canonical serialize failed");

        // Zero-copy: serialize just the HIWP and prepend the variant tag.
        let hiwp_bytes = bincode::serialize(&hiwp).expect("hiwp serialize failed");
        let variant_index: u32 = 3; // HeaderInfoWithProof is variant 3
        let mut zero_copy = Vec::with_capacity(4 + hiwp_bytes.len());
        zero_copy.extend_from_slice(&variant_index.to_le_bytes());
        zero_copy.extend_from_slice(&hiwp_bytes);

        assert_eq!(
            canonical, zero_copy,
            "Helper zero-copy wire format does not match PrimaryMessage::HeaderInfoWithProof"
        );
        println!(
            "Helper zero-copy wire-compat test passed ({} bytes)",
            canonical.len()
        );
    }
}
