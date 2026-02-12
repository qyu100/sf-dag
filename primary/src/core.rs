// Copyright(C) Facebook, Inc. and its affiliates.
use crate::batch_maker::Transaction;
use crate::merkle::{Proof, MerkleTree};
use hex_fmt::HexList;
use crate::coding::Coding;
use crate::aggregators::{
    EchoAggregator, ReadyAggregator, DecideAggregator, TimeoutAggregator
};
use crate::error::{DagError, DagResult};
use crate::messages::{
    Certificate, Header, Ready, Timeout, TimeoutCert, HeaderInfoWithProof, Echo, Decide
};
use crate::primary::{HeaderType, PrimaryMessage, Round};
use crate::synchronizer::Synchronizer;
use crate::{ConsensusMessage, HeaderInfo, HeaderMessage};
use async_recursion::async_recursion;
use bytes::Bytes;
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashMap, HashSet};
use rayon::prelude::*; // parallel iterator for hashing reconstructed shards
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::time::Instant;

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
    /// For storing info of header infos in processing
    processing_header_infos: HashMap<Digest, HeaderInfo>,
    /// For storing proof of header infos in processing
    processing_header_proofs: HashMap<Digest, HeaderInfoWithProof>,
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
    parent_info: HashMap<Digest, (Round,Digest)>,
    rs_block_size: usize,
    rs_block_threads: usize,
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
        tx_proposer: Sender<Certificate>,
        tx_timeout_cert: Sender<(TimeoutCert, Round)>,
        tx_consensus_header_msg: Sender<ConsensusMessage>,
        rs_block_size: usize,
        rs_block_threads: usize,
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
                processing_ready_aggregators: HashMap::new(),
                processing_decide_aggregators: HashMap::new(),
                processed_certs: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                timeouts_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                coding: Arc::new(Coding::new(data_shard_num, parity_shard_num)
                .unwrap_or_else(|e| {
                    warn!("Failed to create Reed-Solomon coding (falling back to trivial): {:?}", e);
                    Coding::Trivial(data_shard_num)
                })),
                mtrees: HashMap::new(),
                echo_shards: HashMap::new(),
                pending_reconstructions: HashMap::new(),
                pending_commit_rounds: HashSet::new(),
                certificates: HashMap::new(),
                last_committed_round: 0,
                parent_info: HashMap::new(),
                rs_block_size: rs_block_size,
                rs_block_threads: rs_block_threads,
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
        let start_total = Instant::now();

        let mut header_info = HeaderInfo::create_from(&header);
        self.processing_header_infos
            .entry(header_info.id)
            .or_insert(header_info.clone());

        let data_shard_num = self.coding.data_shard_count();
        let parity_shard_num = self.coding.parity_shard_count();
        debug!("data_shard_num: {}", data_shard_num);
        debug!("parity_shard_num: {}", parity_shard_num);
        let payload = header.payload;

        let t_ser = Instant::now();
        let payload_bytes = bincode::serialize(&payload).map_err(DagError::SerializationError)?;
        debug!("serialize time: {:?}", t_ser.elapsed());
        let mut payload_bytes = payload_bytes; 

        let payload_len = payload_bytes.len();
        debug!("Original payload length: {}", payload_len);
        // record payload_len in header_info so HeaderInfoWithProof carries it
        header_info.payload_len = payload_len;
        // update stored header_info with the correct payload_len
        if let Some(h) = self.processing_header_infos.get_mut(&header_info.id) {
            *h = header_info.clone();
        }

        let t_pad = Instant::now();
        // Size of a Merkle tree leaf value: the value size divided by the number of data shards,
        // and rounded up, so that the full value always fits in the data shards.
        // Align shard size to 64 bytes which improves SIMD throughput for reed-solomon-simd.
        let mut shard_len = (payload_len + data_shard_num - 1) / data_shard_num;
        if shard_len == 0 {
            shard_len = 1;
        }
        // Align to 64 bytes for better SIMD performance
        if shard_len % 64 != 0 {
            shard_len += 64 - (shard_len % 64);
        }
        // Pad the last data shard with zeros. Fill the parity shards with zeros.
        payload_bytes.resize(shard_len * (data_shard_num + parity_shard_num), 0);
        debug!("pad time: {:?} shard_len_aligned={}", t_pad.elapsed(), shard_len);

        // Divide the vector into chunks/shards.
        let mut shards_vec: Vec<&mut [u8]> = payload_bytes.chunks_mut(shard_len).collect();

        let t_encode = Instant::now();
        // Construct the parity chunks/shards.
        self.coding.encode(&mut shards_vec, self.rs_block_size, self.rs_block_threads).expect("wrong shard size");
        debug!("encode time: {:?}", t_encode.elapsed());

        let t_mtree = Instant::now();
        // Create a Merkle tree from the shards.
        let hashes: Vec<Digest> = shards_vec
            .par_iter()
            .map(|s| MerkleTree::digest(&**s))
            .collect();
        let mtree = MerkleTree::from_hashes(hashes);
        debug!("merkle build time: {:?}", t_mtree.elapsed());

        assert_eq!(self.committee.total_stake() as usize, mtree.leaf_count());

        let t = Instant::now();
        let sorted_keys = self.committee.sorted_keys.clone();
        for (index, pk) in sorted_keys.iter().enumerate() {
             // Use proof_with_leaf to construct the proof from the leaf value provided here.
             // This keeps the code explicit about which leaf value is used for the proof.
             let leaf = shards_vec
                 .get(index)
                 .ok_or(DagError::ProofConstructionFailed)?;
             let proof = mtree
                 .proof_with_leaf(index, &**leaf)
                 .ok_or(DagError::ProofConstructionFailed)?;
             let header_info_with_proof = HeaderInfoWithProof::new(&header_info, &proof);
             if pk == &self.name {
                 self.process_header_proof(&header_info_with_proof)
                     .await
                     .expect("Failed to process our own proof");
             } else {
                let address = self
                    .committee
                    .primary(&pk)
                    .expect("unknown primary")
                    .primary_to_primary;
                let bytes = bincode::serialize(&PrimaryMessage::HeaderInfoWithProof(header_info_with_proof.clone()))
                .expect("Failed to serialize our own proof");
                let handler = self.network.send(address, Bytes::from(bytes)).await;
                self.cancel_handlers
                    .entry(header_info.round)
                    .or_insert_with(Vec::new)
                    .push(handler);
              }
            }
        debug!("process_own_header proof construction and sending time: {:?}", t.elapsed());
        debug!("process_own_header total time: {:?}", start_total.elapsed());
        Ok(())
    }

    async fn process_header_proof(&mut self, header_info_with_proof: &HeaderInfoWithProof) -> DagResult<()> {
        let start = Instant::now();
        // debug!("Processing proof: {:?}", header_info_with_proof);
        debug!(
            "Header info with proof payload len: {}",
            header_info_with_proof.proof.value().len()
        );
        self.parent_info.entry(header_info_with_proof.id).or_insert((header_info_with_proof.round, header_info_with_proof.parent));

        self.processing_header_proofs
             .entry(header_info_with_proof.id)
             .or_insert(header_info_with_proof.clone());

        if self.last_voted.entry(header_info_with_proof.round).or_insert_with(HashSet::new).insert(header_info_with_proof.author) {
             // Make an echo and send it to all nodes
             let echo = Echo::new(&header_info_with_proof, &self.name).await;
             let addresses = self
                 .committee
                 .others_primaries(&self.name)
                 .iter()
                 .map(|(_, x)| x.primary_to_primary)
                 .collect();
                // Serialize a clone for the network but keep the original to process locally (move into process_echo).
                let bytes = bincode::serialize(&PrimaryMessage::Echo(echo.clone()))
                    .expect("Failed to serialize our own echo");

                let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

                self.cancel_handlers
                     .entry(header_info_with_proof.round)
                     .or_insert_with(Vec::new)
                     .extend(handlers);

                self.process_echo(echo)
                   .await
                    .expect("Failed to process our own echo");
             }
        
        let t_parent = Instant::now();
        if header_info_with_proof.round != 1 {
            let parent = self
                .synchronizer
                .get_parent(&header_info_with_proof.clone())
                .await?;
            debug!("get_parent time: {:?}", t_parent.elapsed());
            if parent.is_none() {
                debug!(
                    "Processing of {} suspended: missing parent",
                    header_info_with_proof.id
                );
                return Ok(());
            }
        }

        let hid = header_info_with_proof.id;
        let bytes = bincode::serialize(header_info_with_proof).expect("Failed to serialize header");
        // Store the header.
        self.store.write(hid.to_vec(), bytes).await;

        // If a reconstruction was waiting for this header's info, resume it now.
        if let Some(root) = self.pending_reconstructions.remove(&header_info_with_proof.id) {
            // clone header info to pass ownership into the async helper
            if let Err(e) = self.finalize_reconstruction(header_info_with_proof.clone()).await {
                warn!("Failed to finalize pending reconstruction for {:?}: {}", header_info_with_proof.id, e);
            }
            debug!("process_header_proof total time: {:?}", start.elapsed());
            return Ok(());
        }
        debug!("process_header_proof total time: {:?}", start.elapsed());
        Ok(())
    }

    async fn process_echo(&mut self, echo: Echo) -> DagResult<()> {
        // debug!("Processing {:?}", echo);
        let proof = echo.proof;
        let author = echo.author;
        let id = echo.id;
        // Validate the proof
        if self.committee.index_of(&author) == Some(proof.index()) && proof.validate(self.committee.total_stake() as usize) {
            if !self.processing_echo_aggregators.contains_key(&id) {
                self.processing_echo_aggregators
                    .entry(id.clone())
                    .or_insert(EchoAggregator::new());
            }
            if let Some(echo_aggregator) = self.processing_echo_aggregators.get_mut(&id) {
                if let Some((root, mut leaf_values)) = echo_aggregator.append(author, proof, &self.committee)? {
                    // Store the collected leaf values for this root so we can reconstruct later
                    // key by (round, root_hash)
                    let t_reconstruct = Instant::now();
                    // debug!("round {:?} - reconstructing for root", ready.round);
                    // debug!("leaf_values {}", leaf_values.len());

                    // Move the coding handle and the leaf_values into a blocking task so the
                    // async runtime threads are not blocked by the CPU-heavy reconstruction.
                    let coding = Arc::clone(&self.coding);
                    let rs_block_size = self.rs_block_size;
                    let rs_block_threads = self.rs_block_threads;
                    let leaf_values = tokio::task::spawn_blocking(move || {
                        coding.reconstruct_shards(&mut leaf_values[..], rs_block_size, rs_block_threads)?;
                        Ok::<_, DagError>(leaf_values)
                    })
                    .await
                    .map_err(|_| DagError::ProofConstructionFailed)??;

                    debug!("reconstruct_shards time: {:?}", t_reconstruct.elapsed());

                    let shards: Vec<Vec<u8>> = leaf_values
                        .into_iter()
                        .map(|opt| opt.expect("reconstruct_shards produced all shards").into_vec())
                        .collect();

                    // debug!("Reconstructed shards: {:0.10}", HexList(&shards));
                    debug!("rayon threads: {}", rayon::current_num_threads());
                    // Construct the Merkle tree.
                    let t_mtree = Instant::now();
                    // Compute leaf digests in parallel and build tree from hashes to avoid cloning all shards.
                    let hashes: Vec<Digest> = shards
                        .par_iter()
                        .map(|s| MerkleTree::digest(s.as_slice()))
                        .collect();
                    debug!("hashes compute time: {:?}", t_mtree.elapsed());
                    let mtree = MerkleTree::from_hashes(hashes);
                    debug!("mtree rebuild time: {:?}", t_mtree.elapsed());
                    // If the root hash of the reconstructed tree does not match the one
                    // received with proofs then abort.
                    if *mtree.root_hash() != root {
                        return Err(DagError::ProofConstructionFailed);
                    }
                    // self.mtrees.entry(root).or_insert(mtree);

                    // Reconstruct and process the payload only if we have the corresponding header info with proof.
                    let rid = echo.id;
                    // Clone header info to avoid holding an immutable borrow across an await.
                    let header_clone = match self.processing_header_proofs.get(&rid) {
                        Some(h) => h.clone(),
                        None => {
                            // Store pending reconstruction to be resumed when HeaderInfoWithProof arrives.
                            debug!("Missing HeaderInfoWithProof for echo id {:?}, storing pending reconstruction", rid);
                            self.pending_reconstructions.insert(rid, root);
                            return Ok(());
                        }
                    };

                    // Move shards into helper that rebuilds the payload and submits the certificate.
                    let t_finalize = Instant::now();
                    self.finalize_reconstruction(header_clone).await?;
                    debug!("finalize_reconstruction time: {:?}", t_finalize.elapsed());
                }
            }
        }
        Ok(())
    }


    // Helper to finalize reconstruction: rebuild payload bytes from shards, deserialize,
    // store reconstructed payload and create/process the Certificate.
    async fn finalize_reconstruction(
        &mut self,
        // root: Digest,
        // shards: Vec<Vec<u8>>,
        header_info_with_proof: HeaderInfoWithProof,
    ) -> DagResult<()> {
        let start = Instant::now();
        // let payload_len = header_info_with_proof.payload_len;


        // let data_count = self.coding.data_shard_count() as usize;
        // let t_concat = Instant::now();
        // let mut payload_bytes: Vec<u8> = shards
        //     .into_iter()
        //     .take(data_count)
        //     .flat_map(|s| s.into_iter())
        //     .collect();
        // debug!("concat data shards time: {:?}", t_concat.elapsed());
        // payload_bytes.truncate(payload_len);

        // let payload: Vec<Transaction> = bincode::deserialize(&payload_bytes)
        //     .map_err(DagError::SerializationError)?;

        // store reconstructed payload for later use
        // self.reconstructed_payloads.insert(root, payload.clone());

        let certificate = Certificate {
            header_id: header_info_with_proof.id,
            round: header_info_with_proof.round,
            origin: header_info_with_proof.author,
        };

        self.process_certificate(certificate).await?;
        debug!("finalize_reconstruction total time: {:?}", start.elapsed());
        Ok(())
    }

    #[async_recursion]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        debug!("Processing cert {:?}", certificate);

        // Ensure we have all the ancestor of this certificate yet. If we don't, the synchronizer will gather it and trigger re-processing of this certificate.
        // let t_deliver = Instant::now();
        if !self.synchronizer.deliver_certificate(&certificate).await? {
            // debug!("deliver_certificate time: {:?}", t_deliver.elapsed());
            debug!(
                "Processing of {:?} suspended: missing parent",
                certificate
            );
            return Ok(());
        }
        // debug!("deliver_certificate time: {:?}", t_deliver.elapsed());

        if self.pending_commit_rounds.contains(&certificate.round) {
            self.commit(certificate.round).await?;
        }
        
        // Store the certificate.
        // let t_store = Instant::now();
        // let bytes = bincode::serialize(&certificate).expect("Failed to serialize certificate");
        // self.store.write(certificate.digest().to_vec(), bytes).await;
        // debug!("certificate length: {}", bytes.len());
        // debug!("store certificate time: {:?}", t_store.elapsed());

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
        let mut cur = certificate.header_id;
        to_commit.push_front(cur.clone());
        for r in (self.last_committed_round + 1..=round - 1).rev() {
            
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


    // fn sanitize_timeout(&mut self, timeout: &Timeout) -> DagResult<()> {
    //     ensure!(
    //         self.gc_round <= timeout.round,
    //         DagError::TooOld(timeout.digest(), timeout.round)
    //     );
    //     Ok(())
    // }

    fn sanitize_header_proof(&mut self, header_info_with_proof: &HeaderInfoWithProof) -> DagResult<()> {
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
                        // PrimaryMessage::Timeout(timeout) => {
                        //     match self.sanitize_timeout(&timeout) {
                        //         Ok(()) => self.process_timeout(timeout).await,
                        //         error => error
                        //     }
                        // },
                        PrimaryMessage::Echo(echo) => {
                            match self.sanitize_echo(&echo) {
                                Ok(()) => self.process_echo(echo).await,
                                error => error
                            }
                        },
                        PrimaryMessage::Decide(decide) => {
                            self.process_decide(&decide).await
                        },
                        PrimaryMessage::HeaderInfoWithProof(header_info_with_proof) => {
                            match self.sanitize_header_proof(&header_info_with_proof) {
                                Ok(()) => self.process_header_proof(&header_info_with_proof).await,
                                error => error
                            }
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header_info_with_proof) = self.rx_header_waiter.recv() => self.process_header_proof(&header_info_with_proof).await,

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
                self.processing_header_infos
                    .retain(|_, h| &h.round >= &gc_round);
                self.processing_header_proofs
                    .retain(|_, h| &h.round >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                // let _ = self.synchronizer.garbage_collect(gc_round).await;
                self.gc_round = gc_round;
            }
        }
    }
}
