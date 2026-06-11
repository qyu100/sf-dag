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

/// Result from background own-header computation.
struct OwnHeaderComputeResult {
    header_info: HeaderInfo,
    messages: Vec<(Option<HeaderInfoWithProof>, Option<Bytes>)>,
    round: Round,
    build_total_ms: u128,
}

/// Result from background echo reconstruction.
struct ReconstructionResult {
    id: Digest,
    round: Round,
    origin: PublicKey,
    root: Digest,
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
    /// Send valid a quorum of certificates' ids to the `Proposer` (along with their round).
    tx_proposer: Sender<ProposerParent>,
    /// Send a valid TimeoutCertificate along with the round to the `Proposer`.
    tx_timeout_cert: Sender<(TimeoutCert, Round)>,
    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    /// Parent notifications waiting for cert(r-2) before a local leader can propose.
    pending_proposer_parents: HashMap<Round, HashMap<ProposerParent, Instant>>,
    /// Rounds for which the proposer gate already nudged header processing to obtain cert(r-2).
    syncing_proposer_certificates: HashSet<Round>,
    /// Certificates waiting for the previous round certificate before being processed.
    pending_certificates: HashMap<Round, Vec<Certificate>>,
    /// For storing info of header infos in processing
    processing_header_infos: HashMap<Digest, HeaderInfo>,
    /// For storing proof of header infos in processing
    processing_header_proofs: HashMap<Digest, HeaderInfoWithProof>,
    /// For storing info of echo aggregators in processing
    processing_echo_aggregators: HashMap<Digest, EchoAggregator>,
    /// For storing info of decide aggregators in processing
    processing_decide_aggregators: HashMap<Digest, DecideAggregator>,
    /// Rounds pending commit because certificate was missing at commit time
    pending_commit_rounds: HashSet<Round>,
    /// A network sender to send the batches to the other workers.
    network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
    /// Aggregates timeouts to use for sending timeout certificate.
    timeouts_aggregators: HashMap<Round, Box<TimeoutAggregator>>,
    /// Aggregates timeout accepts to use for creating timeout certificates.
    timeout_accept_aggregators: HashMap<Round, Box<TimeoutAcceptAggregator>>,
    /// Rounds for which this node has already sent a timeout accept.
    sent_timeout_accepts: HashSet<Round>,
    /// Timeout certificates already confirmed locally, keyed by round.
    certified_timed_out: HashMap<Round, TimeoutCert>,
    /// Timeout rounds for which a proposer hint has already been sent.
    timeout_proposer_hints_sent: HashSet<Round>,
    /// Certified rounds for which a normal fallback parent hint has already been sent.
    fallback_proposer_hints_sent: HashSet<Round>,
    /// The Reed-Solomon erasure coding configuration.
    coding: Arc<Coding>,
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
        _signature_service: SignatureService,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        tx_primary: Sender<PrimaryMessage>,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<HeaderInfoWithProof>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        rx_timeout: Receiver<Timeout>,
        _tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<ProposerParent>,
        tx_timeout_cert: Sender<(TimeoutCert, Round)>,
        _tx_consensus_header_msg: Sender<ConsensusMessage>,
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
                consensus_round,
                gc_depth,
                tx_primary,
                rx_primaries,
                rx_header_waiter,
                rx_certificate_waiter,
                rx_proposer,
                rx_timeout,
                tx_proposer,
                tx_timeout_cert,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                pending_proposer_parents: HashMap::new(),
                syncing_proposer_certificates: HashSet::new(),
                pending_certificates: HashMap::new(),
                processing_header_infos: HashMap::new(),
                processing_header_proofs: HashMap::new(),
                processing_echo_aggregators: HashMap::new(),
                processing_decide_aggregators: HashMap::new(),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                timeouts_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                timeout_accept_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                sent_timeout_accepts: HashSet::new(),
                certified_timed_out: HashMap::new(),
                timeout_proposer_hints_sent: HashSet::new(),
                fallback_proposer_hints_sent: HashSet::new(),
                coding: Arc::new(
                    Coding::new(data_shard_num, parity_shard_num).unwrap_or_else(|e| {
                        warn!(
                            "Failed to create Reed-Solomon coding (falling back to trivial): {:?}",
                            e
                        );
                        Coding::Trivial(data_shard_num)
                    }),
                ),
                pending_reconstructions: HashMap::new(),
                pending_commit_rounds: HashSet::new(),
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

    async fn process_own_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        let bytes = bincode::serialize(&PrimaryMessage::Timeout(timeout.clone()))
            .expect("Failed to serialize own timeout");

        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(timeout.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        #[cfg(feature = "benchmark")]
        debug!(
            "BENCH event=timeout_sent round={} node={:?}",
            timeout.round, timeout.author
        );

        self.process_timeout(timeout).await
    }

    async fn process_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        timeout.verify(&self.committee)?;
        let round = timeout.round;
        if self.certified_timed_out.contains_key(&round) || self.certificates.contains_key(&round) {
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
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(accept.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        #[cfg(feature = "benchmark")]
        debug!(
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
        if self.certified_timed_out.contains_key(&round) || self.certificates.contains_key(&round) {
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
            timeout_cert.verify(&self.committee)?;
            if self
                .certified_timed_out
                .insert(round, timeout_cert.clone())
                .is_none()
            {
                #[cfg(feature = "benchmark")]
                debug!(
                    "BENCH event=timeout_cert round={} node={:?}",
                    round, self.name
                );
                self.tx_timeout_cert
                    .send((timeout_cert, round))
                    .await
                    .expect("Failed to send timeout certificate to proposer");
                self.try_notify_timeout_parent(round).await?;
                self.release_timeout_proposer_parents().await?;
                self.release_deferred_certificates(round).await?;
            }
        }
        Ok(())
    }

    fn timeout_parent_candidate(&self, timeout_round: Round) -> Option<ProposerParent> {
        let mut parent_round = timeout_round.saturating_sub(1);
        while parent_round > 0 && self.certified_timed_out.contains_key(&parent_round) {
            parent_round -= 1;
        }

        if parent_round == 0 {
            return Some(ProposerParent {
                round: timeout_round,
                ..ProposerParent::default()
            });
        }

        let certificate = self.certificates.get(&parent_round)?;
        Some(ProposerParent {
            header_id: certificate.header_id,
            round: timeout_round,
            origin: certificate.origin,
        })
    }

    async fn try_notify_timeout_parent(&mut self, timeout_round: Round) -> DagResult<()> {
        if self.timeout_proposer_hints_sent.contains(&timeout_round) {
            return Ok(());
        }

        let Some(parent) = self.timeout_parent_candidate(timeout_round) else {
            debug!(
                "BENCH event=timeout_parent_deferred node={:?} timeout_round={}",
                self.name, timeout_round
            );
            return Ok(());
        };

        self.timeout_proposer_hints_sent.insert(timeout_round);
        #[cfg(feature = "benchmark")]
        debug!(
            "BENCH event=timeout_parent_hint node={:?} timeout_round={} propose_round={} parent_hint_round={} parent_digest={:?} parent_origin={:?}",
            self.name,
            timeout_round,
            timeout_round + 1,
            parent.round,
            parent.header_id,
            parent.origin
        );
        self.notify_proposer(parent).await
    }

    async fn release_timeout_proposer_parents(&mut self) -> DagResult<()> {
        let rounds = self
            .certified_timed_out
            .keys()
            .copied()
            .filter(|round| !self.timeout_proposer_hints_sent.contains(round))
            .collect::<Vec<_>>();

        for round in rounds {
            self.try_notify_timeout_parent(round).await?;
        }
        Ok(())
    }

    /// Dispatch own header computation to a background blocking thread.
    /// Returns immediately so the event loop can keep processing echoes.
    fn dispatch_own_header(&self, header: Header) -> DagResult<()> {
        let coding = Arc::clone(&self.coding);
        let committee = Arc::clone(&self.committee);
        let name = self.name;
        let rs_block_size = self.rs_block_size;
        let rs_block_threads = self.rs_block_threads;
        let tx = self.tx_own_header_result.clone();

        tokio::task::spawn_blocking(move || {
            let start_total = Instant::now();

            let mut header_info = HeaderInfo::create_from_fast(&header);
            let data_shard_num = coding.data_shard_count();
            let parity_shard_num = coding.parity_shard_count();
            let payload = header.payload;

            let payload_bytes = match bincode::serialize(&payload) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to serialize payload: {:?}", e);
                    return;
                }
            };
            let mut payload_bytes = payload_bytes;

            let payload_len = payload_bytes.len();
            header_info.payload_len = payload_len;

            let mut shard_len = (payload_len + data_shard_num - 1) / data_shard_num;
            if shard_len == 0 {
                shard_len = 1;
            }
            if shard_len % 64 != 0 {
                shard_len += 64 - (shard_len % 64);
            }
            payload_bytes.resize(shard_len * (data_shard_num + parity_shard_num), 0);

            let mut shards_vec: Vec<&mut [u8]> = payload_bytes.chunks_mut(shard_len).collect();

            coding
                .encode(&mut shards_vec, rs_block_size, rs_block_threads)
                .expect("wrong shard size");

            let hashes: Vec<Digest> = shards_vec
                .par_iter()
                .map(|s| MerkleTree::digest(&**s))
                .collect();
            let mtree = MerkleTree::from_hashes(hashes);

            assert_eq!(committee.total_stake() as usize, mtree.leaf_count());

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

            let round = header_info.round;

            let _ = tx.blocking_send(OwnHeaderComputeResult {
                header_info,
                messages,
                round,
                build_total_ms: start_total.elapsed().as_millis(),
            });
        });
        Ok(())
    }

    /// Handle the result of a background own-header computation.
    /// Performs network sends and state updates inline.
    async fn handle_own_header_result(&mut self, result: OwnHeaderComputeResult) -> DagResult<()> {
        let start = Instant::now();
        let recipient_count = self.committee.sorted_keys.len().saturating_sub(1);

        debug!(
            "BENCH event=own_header_ready node={:?} round={} digest={:?} build_total_ms={} recipients={}",
            self.name,
            result.round,
            result.header_info.id,
            result.build_total_ms,
            recipient_count
        );

        // Store header_info in processing map
        self.processing_header_infos
            .entry(result.header_info.id)
            .or_insert(result.header_info.clone());

        let sorted_keys = self.committee.sorted_keys.clone();
        for (index, pk) in sorted_keys.iter().enumerate() {
            match &result.messages[index] {
                (Some(hiwp), _) => {
                    self.process_header_proof_optimized_with_source(hiwp, "self")
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
        debug!(
            "BENCH event=own_header_sent node={:?} round={} digest={:?} build_total_ms={} send_ms={} recipients={}",
            self.name,
            result.round,
            result.header_info.id,
            result.build_total_ms,
            start.elapsed().as_millis(),
            recipient_count
        );
        Ok(())
    }

    async fn process_header_proof_optimized_with_source(
        &mut self,
        header_info_with_proof: &HeaderInfoWithProof,
        source: &'static str,
    ) -> DagResult<()> {
        self.parent_info
            .entry(header_info_with_proof.id)
            .or_insert((header_info_with_proof.round, header_info_with_proof.parent));

        let first_seen = !self
            .processing_header_proofs
            .contains_key(&header_info_with_proof.id);
        if first_seen {
            self.processing_header_proofs
                .insert(header_info_with_proof.id, header_info_with_proof.clone());
            debug!(
                "BENCH event=header_first_seen node={:?} round={} digest={:?} origin={:?} parent={:?} source={} proof_index={} payload_bytes={}",
                self.name,
                header_info_with_proof.round,
                header_info_with_proof.id,
                header_info_with_proof.author,
                header_info_with_proof.parent,
                source,
                header_info_with_proof.proof.index(),
                header_info_with_proof.payload_len
            );
        }

        if header_info_with_proof.round != 1 {
            // 2b: Pass header_info_with_proof directly — no unnecessary .clone().
            let parent = self.synchronizer.get_parent(header_info_with_proof).await?;
            if parent.is_none() {
                return Ok(());
            }
        }

        self.maybe_notify_proposer_or_defer(header_info_with_proof)
            .await?;

        self.send_echo(header_info_with_proof).await?;

        let hid = header_info_with_proof.id;
        let bytes = bincode::serialize(header_info_with_proof).expect("Failed to serialize header");
        // Store the header.
        self.store.write(hid.to_vec(), bytes).await;

        // If a reconstruction was waiting for this header's info, resume it now.
        if let Some(root) = self
            .pending_reconstructions
            .remove(&header_info_with_proof.id)
        {
            debug!(
                "BENCH event=header_unblocks_reconstruction node={:?} round={} digest={:?} origin={:?} root={:?}",
                self.name,
                header_info_with_proof.round,
                header_info_with_proof.id,
                header_info_with_proof.author,
                root
            );
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
            return Ok(());
        }
        Ok(())
    }

    /// Notify the proposer only after the local leader has parent(r-1) and cert(r-2).
    async fn maybe_notify_proposer_or_defer(
        &mut self,
        header_info_with_proof: &HeaderInfoWithProof,
    ) -> DagResult<()> {
        let parent = ProposerParent {
            header_id: header_info_with_proof.id,
            round: header_info_with_proof.round,
            origin: header_info_with_proof.author,
        };
        let propose_round = parent.round + 1;
        let is_local_leader = self.committee.leader(propose_round as usize) == self.name;

        if is_local_leader && parent.round > 1 {
            let required_cert_round = parent.round - 1;
            if self.certified_timed_out.contains_key(&required_cert_round) {
                debug!(
                    "BENCH event=propose_blocked_by_timeout node={:?} propose_round={} parent_round={} parent_digest={:?} parent_origin={:?} timeout_round={}",
                    self.name,
                    propose_round,
                    parent.round,
                    parent.header_id,
                    parent.origin,
                    required_cert_round
                );
                return Ok(());
            }
            if !self.certificates.contains_key(&required_cert_round) {
                self.sync_missing_proposer_certificate(
                    required_cert_round,
                    header_info_with_proof.parent,
                )
                .await?;

                let pending = self
                    .pending_proposer_parents
                    .entry(required_cert_round)
                    .or_insert_with(HashMap::new);
                if let std::collections::hash_map::Entry::Vacant(entry) =
                    pending.entry(parent.clone())
                {
                    entry.insert(Instant::now());
                    debug!(
                        "BENCH event=propose_deferred node={:?} propose_round={} parent_round={} parent_digest={:?} parent_origin={:?} wait_cert_round={}",
                        self.name,
                        propose_round,
                        parent.round,
                        parent.header_id,
                        parent.origin,
                        required_cert_round
                    );
                }
                return Ok(());
            }
            debug!(
                "BENCH event=propose_ready node={:?} propose_round={} parent_round={} parent_digest={:?} parent_origin={:?} wait_cert_round={} wait_ms=0 source=cert_present",
                self.name,
                propose_round,
                parent.round,
                parent.header_id,
                parent.origin,
                required_cert_round
            );
        }

        self.notify_proposer(parent).await
    }

    async fn sync_missing_proposer_certificate(
        &mut self,
        required_cert_round: Round,
        required_header_id: Digest,
    ) -> DagResult<()> {
        if !self
            .syncing_proposer_certificates
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
                    debug!(
                        "BENCH event=propose_cert_sync node={:?} wait_cert_round={} digest={:?} origin={:?} source=local_header_reprocess",
                        self.name,
                        required_cert_round,
                        required_header_id,
                        header_info_with_proof.author
                    );

                    if let Err(e) = self
                        .tx_primary
                        .try_send(PrimaryMessage::HeaderInfoWithProof(header_info_with_proof))
                    {
                        self.syncing_proposer_certificates
                            .remove(&required_cert_round);
                        warn!(
                            "Failed to enqueue proposer certificate sync for round {}: {}",
                            required_cert_round, e
                        );
                    }
                }
                Ok(header_info_with_proof) => {
                    self.syncing_proposer_certificates
                        .remove(&required_cert_round);
                    warn!(
                        "Stored header mismatch while syncing proposer certificate: expected round {} digest {:?}, got round {} digest {:?}",
                        required_cert_round,
                        required_header_id,
                        header_info_with_proof.round,
                        header_info_with_proof.id
                    );
                }
                Err(e) => {
                    self.syncing_proposer_certificates
                        .remove(&required_cert_round);
                    warn!(
                        "Failed to deserialize header while syncing proposer certificate for round {} digest {:?}: {}",
                        required_cert_round,
                        required_header_id,
                        e
                    );
                }
            },
            None => {
                self.syncing_proposer_certificates
                    .remove(&required_cert_round);
                debug!(
                    "BENCH event=propose_cert_sync node={:?} wait_cert_round={} digest={:?} source=missing_header",
                    self.name,
                    required_cert_round,
                    required_header_id
                );
            }
        }

        Ok(())
    }

    async fn notify_proposer(&mut self, parent: ProposerParent) -> DagResult<()> {
        self.tx_proposer
            .send(parent)
            .await
            .expect("Failed to send parent candidate to proposer");
        Ok(())
    }

    async fn maybe_notify_fallback_parent(
        &mut self,
        header_id: Digest,
        round: Round,
        origin: PublicKey,
    ) -> DagResult<()> {
        if round <= 1 || !self.certified_timed_out.contains_key(&(round - 1)) {
            return Ok(());
        }

        let propose_round = round + 1;
        if self.committee.leader(propose_round as usize) != self.name {
            return Ok(());
        }

        if !self.fallback_proposer_hints_sent.insert(round) {
            return Ok(());
        }

        let parent = ProposerParent {
            header_id,
            round,
            origin,
        };
        #[cfg(feature = "benchmark")]
        debug!(
            "BENCH event=fallback_parent_hint node={:?} propose_round={} parent_round={} parent_digest={:?} parent_origin={:?} timeout_round={}",
            self.name,
            propose_round,
            round,
            header_id,
            origin,
            round - 1
        );
        self.notify_proposer(parent).await
    }

    async fn request_header_from_author(
        &mut self,
        header_id: Digest,
        round: Round,
        origin: PublicKey,
    ) -> DagResult<()> {
        if origin == self.name {
            warn!(
                "Missing locally authored header while syncing reconstruction: round={} digest={:?}",
                round,
                header_id
            );
            return Ok(());
        }

        let address = self
            .committee
            .primary(&origin)
            .expect("Author of valid header not in the committee")
            .primary_to_primary;
        let message = PrimaryMessage::CertificatesRequest(vec![header_id], self.name);
        let bytes = bincode::serialize(&message).expect("Failed to serialize header sync request");
        let handler = self.network.send(address, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(round)
            .or_insert_with(Vec::new)
            .push(handler);
        debug!(
            "BENCH event=header_sync_request node={:?} round={} digest={:?} origin={:?} target={:?} source=reconstruction_pending_header",
            self.name,
            round,
            header_id,
            origin,
            origin
        );
        Ok(())
    }

    async fn send_echo(&mut self, header_info_with_proof: &HeaderInfoWithProof) -> DagResult<()> {
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
                .collect::<Vec<_>>();
            let recipient_count = addresses.len();

            let bytes = bincode::serialize(&PrimaryMessageRef::Echo(&echo))
                .expect("Failed to serialize our own echo");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(round)
                .or_insert_with(Vec::new)
                .extend(handlers);
            debug!(
                "BENCH event=echo_sent node={:?} round={} digest={:?} origin={:?} proof_index={} recipients={}",
                self.name,
                round,
                header_info_with_proof.id,
                header_info_with_proof.author,
                header_info_with_proof.proof.index(),
                recipient_count
            );

            self.process_echo_optimized(echo)
                .await
                .expect("Failed to process our own echo");
        }

        Ok(())
    }

    async fn release_deferred_proposer_parents(&mut self, certified_round: Round) -> DagResult<()> {
        let Some(parents) = self.pending_proposer_parents.remove(&certified_round) else {
            return Ok(());
        };

        for (parent, started_at) in parents {
            debug!(
                "BENCH event=propose_released node={:?} propose_round={} parent_round={} parent_digest={:?} parent_origin={:?} wait_cert_round={} wait_ms={}",
                self.name,
                parent.round + 1,
                parent.round,
                parent.header_id,
                parent.origin,
                certified_round,
                started_at.elapsed().as_millis()
            );
            self.notify_proposer(parent).await?;
        }

        Ok(())
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

    fn defer_certificate_until_safe_parent(&mut self, certificate: Certificate) -> bool {
        let round = certificate.round;
        if round <= 1 {
            return false;
        }

        if self.certified_timed_out.is_empty() {
            if self.certificates.contains_key(&(round - 1)) {
                return false;
            }
            self.defer_certificate_until_round(certificate, round - 1);
            return true;
        }

        let Some((_, parent_digest)) = self.parent_info.get(&certificate.header_id).cloned() else {
            self.defer_certificate_until_round(certificate, round.saturating_sub(1));
            return true;
        };

        if parent_digest == Digest::default() {
            for timeout_round in 1..round {
                if !self.certified_timed_out.contains_key(&timeout_round) {
                    self.defer_certificate_until_round(certificate, timeout_round);
                    return true;
                }
            }
            return false;
        }

        let Some((parent_round, _)) = self.parent_info.get(&parent_digest).cloned() else {
            self.defer_certificate_until_round(certificate, round.saturating_sub(1));
            return true;
        };

        if parent_round >= round {
            self.defer_certificate_until_round(certificate, round.saturating_sub(1));
            return true;
        }

        if parent_round > 0 && !self.certificates.contains_key(&parent_round) {
            self.defer_certificate_until_round(certificate, parent_round);
            return true;
        }

        for timeout_round in parent_round + 1..round {
            if !self.certified_timed_out.contains_key(&timeout_round) {
                self.defer_certificate_until_round(certificate, timeout_round);
                return true;
            }
        }

        false
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

    /// Optimized version of process_echo:
    /// - Hashes directly from Option<Box<[u8]>> refs via par_iter, skipping the
    ///   intermediate Vec<Vec<u8>> conversion.
    /// - Calls finalize_reconstruction_optimized with small fields only.
    #[allow(dead_code)]
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

                if let Some((root, mut leaf_values, collected_weight, collected_count)) = agg_result
                {
                    let header_seen = self.processing_header_proofs.contains_key(&id);
                    debug!(
                        "BENCH event=echo_quorum node={:?} round={} digest={:?} origin={:?} root={:?} collected={} weight={} threshold={} header_seen={}",
                        self.name,
                        round,
                        id,
                        origin,
                        root,
                        collected_count,
                        collected_weight,
                        self.committee.optimistic_threshold(),
                        header_seen
                    );
                    // Dispatch reconstruction to background so the event loop stays responsive.
                    let coding = Arc::clone(&self.coding);
                    let rs_block_size = self.rs_block_size;
                    let rs_block_threads = self.rs_block_threads;
                    let tx = self.tx_reconstruction_result.clone();
                    let recon_id = id;
                    let recon_round = round;
                    let recon_origin = origin;

                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = coding.reconstruct_shards(
                            &mut leaf_values[..],
                            rs_block_size,
                            rs_block_threads,
                        ) {
                            warn!("Reconstruction failed: {:?}", e);
                            let _ = tx.blocking_send(ReconstructionResult {
                                id: recon_id,
                                round: recon_round,
                                origin: recon_origin,
                                root,
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
                            id: recon_id,
                            round: recon_round,
                            origin: recon_origin,
                            root,
                            success,
                        });
                    });
                } else {
                }
            }
        }
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
        if !result.success {
            warn!("Reconstruction verification failed for {:?}", result.id);
            return Err(DagError::ProofConstructionFailed);
        }

        let (header_id, round, origin) = match self.processing_header_proofs.get(&result.id) {
            Some(h) => (h.id, h.round, h.author),
            None => {
                debug!(
                    "BENCH event=reconstruction_pending_header node={:?} round={} digest={:?} origin={:?} root={:?}",
                    self.name,
                    result.round,
                    result.id,
                    result.origin,
                    result.root
                );
                self.request_header_from_author(result.id, result.round, result.origin)
                    .await?;
                self.pending_reconstructions.insert(result.id, result.root);
                return Ok(());
            }
        };

        self.finalize_reconstruction_optimized(header_id, round, origin)
            .await?;
        Ok(())
    }

    /// Optimized version of process_certificate:
    /// - Uses deliver_certificate_optimized to skip store read+deserialize of ~2.9MB HeaderInfoWithProof
    /// - Extracts small fields before moving the certificate into the map (avoids extra clones)
    /// - Moves decide instead of cloning for serialization
    #[allow(dead_code)]
    #[async_recursion]
    async fn process_certificate_optimized(&mut self, certificate: Certificate) -> DagResult<()> {
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
            return Ok(());
        }

        if self.defer_certificate_until_safe_parent(certificate.clone()) {
            return Ok(());
        }

        // Extract small Copy/Clone-cheap fields before moving the certificate.
        let header_id = certificate.header_id;
        let round = certificate.round;
        let origin = certificate.origin;

        // Store in local map — move certificate in (no extra clone).
        self.certificates.entry(round).or_insert(certificate);
        self.syncing_proposer_certificates.remove(&round);
        self.maybe_notify_fallback_parent(header_id, round, origin)
            .await?;
        self.release_deferred_proposer_parents(round).await?;
        self.release_timeout_proposer_parents().await?;

        if self.pending_commit_rounds.remove(&round) {
            self.commit(round).await?;
        }

        // 4a: Build decide from the extracted small fields.
        let decide = Decide::new(header_id, round, &origin, &self.name).await;
        self.process_decide(&decide).await?;

        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        // 4a: Move decide into serialization (no clone needed).
        let bytes = bincode::serialize(&PrimaryMessage::Decide(decide))
            .expect("Failed to serialize our own decide");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(round)
            .or_insert_with(Vec::new)
            .extend(handlers);

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
        loop {
            let Some((cur_round, parent_digest)) = self.parent_info.get(&cur).cloned() else {
                self.pending_commit_rounds.insert(round);
                return Ok(());
            };

            if cur_round <= self.last_committed_round {
                break;
            }
            to_commit.push_front(cur);

            if parent_digest == Digest::default() {
                for timeout_round in self.last_committed_round + 1..cur_round {
                    if !self.certified_timed_out.contains_key(&timeout_round) {
                        self.pending_commit_rounds.insert(round);
                        return Ok(());
                    }
                }
                break;
            }

            let Some((parent_round, _)) = self.parent_info.get(&parent_digest).cloned() else {
                self.pending_commit_rounds.insert(round);
                return Ok(());
            };

            if parent_round >= cur_round {
                warn!(
                    "Invalid parent round while committing: child_round={} parent_round={}",
                    cur_round, parent_round
                );
                return Ok(());
            }

            if parent_round > 0 && !self.certificates.contains_key(&parent_round) {
                self.pending_commit_rounds.insert(round);
                return Ok(());
            }

            for timeout_round in parent_round + 1..cur_round {
                if !self.certified_timed_out.contains_key(&timeout_round) {
                    self.pending_commit_rounds.insert(round);
                    return Ok(());
                }
            }

            cur = parent_digest;
        }

        self.last_committed_round = round;
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
                                Ok(()) => self
                                    .process_header_proof_optimized_with_source(
                                        &header_info_with_proof,
                                        "primary_channel",
                                    )
                                    .await,
                                error => error
                            }
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header_info_with_proof) = self.rx_header_waiter.recv() => self
                    .process_header_proof_optimized_with_source(&header_info_with_proof, "header_waiter")
                    .await,

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
                self.last_voted.retain(|k, _| k >= &gc_round);
                self.processing_header_infos
                    .retain(|_, h| &h.round >= &gc_round);
                self.processing_header_proofs
                    .retain(|_, h| &h.round >= &gc_round);
                self.pending_proposer_parents.retain(|k, _| k >= &gc_round);
                self.syncing_proposer_certificates
                    .retain(|k| k >= &gc_round);
                self.pending_certificates.retain(|k, _| k >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.timeouts_aggregators.retain(|k, _| k >= &gc_round);
                self.timeout_accept_aggregators
                    .retain(|k, _| k >= &gc_round);
                self.sent_timeout_accepts.retain(|k| k >= &gc_round);
                self.certified_timed_out.retain(|k, _| k >= &gc_round);
                self.timeout_proposer_hints_sent.retain(|k| k >= &gc_round);
                self.fallback_proposer_hints_sent.retain(|k| k >= &gc_round);
                self.gc_round = gc_round;
            }
        }
    }
}
