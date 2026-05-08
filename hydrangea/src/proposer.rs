use crate::coding::{shard_hashes, Coding};
use crate::consensus::{ConsensusMessage, ProposalMessage, Round};
use crate::merkle::MerkleTree;
use crate::messages::{
    Block, FallbackRecoveryProposal, NormalProposal, Transaction, QC, TC,
};
use bytes::Bytes;
use config::Committee;
use crypto::{Digest, Hash as _, PublicKey, SignatureService};
use log::{debug, info};
use network::{CancelHandler, ReliableSender};
use primary::Certificate;
use rayon::prelude::*;
use std::collections::HashMap;
use std::time::Instant as StdInstant;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

#[derive(Debug, Clone)]
pub enum ProposalTrigger {
    QC(QC),
    TC(TC),
    Optimistic { parent: Block, qc: QC },
}

#[derive(Debug)]
pub enum ProposerMessage {
    Propose(ProposalTrigger),
    Cleanup(Round),
    Observed(Vec<Transaction>),
}

enum ProposalTarget {
    Local(ProposalMessage),
    Remote(PublicKey, Bytes),
}

// Result of Phase 1: RS encoding + Merkle tree construction.
struct Phase1Result {
    round: Round,
    parent: Digest,
    trigger: ProposalTrigger,
    encoded: Vec<u8>,
    shard_len: usize,
    payload_len: usize,
    merkle_tree: MerkleTree,
    payload_ms: u128,
    encode_ms: u128,
    merkle_ms: u128,
    encode_blocking_ms: u128,
}

// Result of Phase 2: per-recipient proof generation + serialization.
struct Phase2Result {
    round: Round,
    block: Block,
    local: ProposalMessage,
    remote: Vec<(PublicKey, Bytes)>,
    shard_len: usize,
    total_bytes: usize,
    payload_ms: u128,
    encode_ms: u128,
    merkle_ms: u128,
    sign_ms: u128,
    proof_blocking_ms: u128,
    encode_blocking_ms: u128,
}

// Speculatively pre-encoded payload: trigger-independent fields of Phase1Result.
// parent/round/trigger are not known yet; they are attached when the trigger arrives.
struct SpeculativeEncoding {
    encoded: Vec<u8>,
    shard_len: usize,
    payload_len: usize,
    merkle_tree: MerkleTree,
    payload_ms: u128,
    encode_ms: u128,
    merkle_ms: u128,
    encode_blocking_ms: u128,
}

pub struct Proposer {
    name: PublicKey,
    consensus_only: bool,
    committee: Committee,
    in_progress: HashMap<Round, Vec<CancelHandler>>,
    last_proposed: Block,
    max_block_delay: u64,
    header_size: usize,
    tx_size: usize,
    max_block_size: usize,
    rs_block_size: usize,
    rs_block_threads: usize,
    rx_mempool: Receiver<Certificate>,
    rx_message: Receiver<ProposerMessage>,
    signature_service: SignatureService,
    tx_proposer_core: Sender<ProposalMessage>,
    network: ReliableSender,
    proposal_request: Option<ProposalTrigger>,
    buffer: Vec<Transaction>,
    tx_phase1: Sender<Phase1Result>,
    rx_phase1: Receiver<Phase1Result>,
    tx_phase2: Sender<Phase2Result>,
    rx_phase2: Receiver<Phase2Result>,
    // Speculative pre-encoding state.
    // start_speculative_phase1() fires RS encoding immediately after proposals are sent,
    // overlapping with the voting period.  When the trigger for the next round arrives,
    // the encoded payload is already ready so the proposer skips the blocking Phase 1 wait.
    tx_speculative: Sender<SpeculativeEncoding>,
    rx_speculative: Receiver<SpeculativeEncoding>,
    speculative_payload: Option<SpeculativeEncoding>, // encoded but trigger not yet received
    pending_trigger: Option<ProposalTrigger>,         // trigger arrived before encoding done
    speculative_in_flight: bool,
}

impl Proposer {
    pub fn spawn(
        name: PublicKey,
        consensus_only: bool,
        committee: Committee,
        header_size: usize,
        tx_size: usize,
        max_block_size: usize,
        rs_block_size: usize,
        rs_block_threads: usize,
        signature_service: SignatureService,
        rx_mempool: Receiver<Certificate>,
        rx_message: Receiver<ProposerMessage>,
        tx_proposer_core: Sender<ProposalMessage>,
    ) {
        tokio::spawn(async move {
            let (tx_phase1, rx_phase1) = channel(8);
            let (tx_phase2, rx_phase2) = channel(8);
            let (tx_speculative, rx_speculative) = channel(4);
            Self {
                name,
                consensus_only,
                committee,
                in_progress: HashMap::new(),
                last_proposed: Block::genesis(),
                signature_service,
                max_block_delay: 2_000,
                header_size,
                tx_size,
                max_block_size,
                rs_block_size,
                rs_block_threads,
                rx_mempool,
                rx_message,
                tx_proposer_core,
                network: ReliableSender::new(),
                proposal_request: None,
                buffer: Vec::new(),
                tx_phase1,
                rx_phase1,
                tx_phase2,
                rx_phase2,
                tx_speculative,
                rx_speculative,
                speculative_payload: None,
                pending_trigger: None,
                speculative_in_flight: false,
            }
            .run()
            .await;
        });
    }

    fn get_payload(&mut self) -> Vec<Transaction> {
        if self.consensus_only {
            let tx_count = (self.header_size / self.tx_size).max(1);
            vec![vec![0u8; self.tx_size]; tx_count]
        } else {
            if self.buffer.len() < self.max_block_size {
                self.buffer.drain(..).collect()
            } else {
                self.buffer.drain(0..self.max_block_size).collect()
            }
        }
    }

    async fn send_proposals(
        &mut self,
        proposals: Vec<(PublicKey, Bytes)>,
        round: Round,
        digest: Digest,
    ) {
        let send_start = Instant::now();
        let peers: HashMap<PublicKey, _> = self
            .committee
            .others_consensus(&self.name)
            .into_iter()
            .map(|(name, x)| (name, x.consensus_to_consensus))
            .collect();

        let mut handles = Vec::new();
        for (recipient, message) in proposals {
            if recipient == self.name {
                continue;
            }
            let Some(address) = peers.get(&recipient).cloned() else {
                continue;
            };
            debug!(
                "Proposing to {}. Proposal size is {}B",
                recipient,
                message.len()
            );
            let bytes = message.len();
            let label = format!(
                "proposal,node={},round={},digest={}",
                self.name, round, digest
            );
            let enqueue_start = Instant::now();
            let handle = self
                .network
                .send_with_label(address, message, Some(label.clone()))
                .await;
            debug!(
                "TIMELINE event=proposal_remote_enqueued label={} recipient={} address={} bytes={} enqueue_ms={}",
                label,
                recipient,
                address,
                bytes,
                enqueue_start.elapsed().as_millis()
            );
            handles.push(handle);
        }
        debug!(
            "TIMING proposal_send round={} remotes={} enqueue_ms={}",
            round,
            handles.len(),
            send_start.elapsed().as_millis()
        );
        self.in_progress.insert(round, handles);
    }

    fn record_proposal(&mut self, b: Block) {
        info!("Created {:?}", b);
        info!("Created {}", b.digest());
        info!("Header {} contains {} B", b.digest(), b.payload_len);
        debug!(
            "TIMELINE event=block_created node={} author={} round={} digest={} payload_bytes={}",
            self.name,
            b.author,
            b.round,
            b.digest(),
            b.payload_len
        );
        self.last_proposed = b;
    }

    // Decomposes a trigger into (parent_digest, round).
    fn trigger_parent_and_round(trigger: &ProposalTrigger) -> (Digest, Round) {
        match trigger {
            ProposalTrigger::QC(qc) => (qc.blk_hash.clone(), qc.round + 1),
            ProposalTrigger::TC(tc) => (tc.high_qc.blk_hash.clone(), tc.round + 1),
            ProposalTrigger::Optimistic { parent, .. } => (parent.digest(), parent.round + 1),
        }
    }

    // Starts RS encoding + Merkle tree construction speculatively (no trigger needed).
    // Called immediately after proposals are sent so encoding overlaps with the voting period.
    // When the trigger for the next round arrives, the encoded payload will already be ready.
    fn start_speculative_phase1(&mut self) {
        if self.speculative_in_flight || self.speculative_payload.is_some() {
            return;
        }
        self.speculative_in_flight = true;
        let payload = self.get_payload();
        let data_shards = (self.committee.n - 2 * self.committee.f) as usize;
        let parity_shards = (2 * self.committee.f) as usize;
        let total_shards = self.committee.size();
        let rs_block_size = self.rs_block_size;
        let rs_block_threads = self.rs_block_threads;
        let tx = self.tx_speculative.clone();
        tokio::task::spawn_blocking(move || {
            let encode_blocking_start = StdInstant::now();

            let payload_start = StdInstant::now();
            let payload_bytes =
                bincode::serialize(&payload).expect("Failed to serialize payload");
            let payload_len = payload_bytes.len();
            let payload_ms = payload_start.elapsed().as_millis();

            let encode_start = StdInstant::now();
            let coding = Coding::new(data_shards, parity_shards);
            assert_eq!(coding.total_shard_count(), total_shards);
            let mut shard_len = (payload_len + data_shards - 1) / data_shards;
            if shard_len == 0 {
                shard_len = 1;
            }
            shard_len = ((shard_len + 63) / 64) * 64;
            let mut encoded = payload_bytes;
            encoded.resize(shard_len * total_shards, 0);
            let mut shards: Vec<&mut [u8]> = encoded.chunks_mut(shard_len).collect();
            coding
                .encode(&mut shards, rs_block_size, rs_block_threads)
                .expect("Failed to encode payload");
            let encode_ms = encode_start.elapsed().as_millis();

            let merkle_start = StdInstant::now();
            let shard_options: Vec<Option<Box<[u8]>>> = shards
                .iter()
                .map(|s| Some(s.to_vec().into_boxed_slice()))
                .collect();
            let merkle_tree = MerkleTree::from_hashes(
                shard_hashes(&shard_options).expect("Failed to hash shards"),
            );
            let merkle_ms = merkle_start.elapsed().as_millis();

            let _ = tx.blocking_send(SpeculativeEncoding {
                encoded,
                shard_len,
                payload_len,
                merkle_tree,
                payload_ms,
                encode_ms,
                merkle_ms,
                encode_blocking_ms: encode_blocking_start.elapsed().as_millis(),
            });
        });
    }

    // Attaches a trigger to a completed speculative encoding and sends to rx_phase1.
    fn dispatch_phase1(&mut self, spec: SpeculativeEncoding, trigger: ProposalTrigger) {
        let (parent, round) = Self::trigger_parent_and_round(&trigger);
        let p1 = Phase1Result {
            round,
            parent,
            trigger,
            encoded: spec.encoded,
            shard_len: spec.shard_len,
            payload_len: spec.payload_len,
            merkle_tree: spec.merkle_tree,
            payload_ms: spec.payload_ms,
            encode_ms: spec.encode_ms,
            merkle_ms: spec.merkle_ms,
            encode_blocking_ms: spec.encode_blocking_ms,
        };
        self.tx_phase1.try_send(p1).expect("tx_phase1 channel full");
    }

    // Fires Phase 1 (RS encode + Merkle tree) in a background thread; returns immediately.
    // If a speculative encoding is already ready, uses it directly (zero blocking wait).
    // If encoding is in flight, stores the trigger and pairs them in handle_speculative_result.
    fn start_phase1(&mut self, trigger: ProposalTrigger) {
        if let Some(spec) = self.speculative_payload.take() {
            // Fast path: encoding already done, just attach the trigger.
            debug!(
                "TIMING speculative_phase1_hit round={}",
                Self::trigger_parent_and_round(&trigger).1
            );
            self.dispatch_phase1(spec, trigger);
            // Immediately start the next speculative encoding.
            self.start_speculative_phase1();
        } else {
            // Encoding not ready yet: store trigger and wait for rx_speculative.
            self.pending_trigger = Some(trigger);
            if !self.speculative_in_flight {
                // No speculation started (first round or after a gap): start one now.
                self.start_speculative_phase1();
            }
        }
    }

    // Called when speculative encoding completes.
    fn handle_speculative_result(&mut self, spec: SpeculativeEncoding) {
        self.speculative_in_flight = false;
        debug!(
            "TIMING speculative_phase1_done encode_blocking_ms={}",
            spec.encode_blocking_ms
        );
        if let Some(trigger) = self.pending_trigger.take() {
            // Trigger was already waiting — pair immediately.
            self.dispatch_phase1(spec, trigger);
            self.start_speculative_phase1();
        } else {
            // Trigger not yet received — store for when it arrives.
            self.speculative_payload = Some(spec);
        }
    }

    // Signs the block (fast async), then fires Phase 2 (proof generation) in background.
    async fn handle_phase1_result(&mut self, p1: Phase1Result) {
        let sign_start = StdInstant::now();
        let block = Block::new(
            self.name,
            p1.parent.clone(),
            p1.merkle_tree.root_hash().clone(),
            p1.payload_len,
            p1.round,
            self.signature_service.clone(),
        )
        .await;
        let sign_ms = sign_start.elapsed().as_millis();
        self.record_proposal(block.clone());

        let my_name = self.name;
        let consensus_only = self.consensus_only;
        let mut recipients: Vec<PublicKey> = self.committee.authorities.keys().cloned().collect();
        recipients.sort_by_key(|pk| self.committee.id(pk));
        let tx = self.tx_phase2.clone();
        let payload_ms = p1.payload_ms;
        let encode_ms = p1.encode_ms;
        let merkle_ms = p1.merkle_ms;
        let encode_blocking_ms = p1.encode_blocking_ms;
        let round = p1.round;
        let shard_len = p1.shard_len;
        let encoded = p1.encoded;
        let merkle_tree = p1.merkle_tree;
        let trigger = p1.trigger;

        tokio::task::spawn_blocking(move || {
            let proof_blocking_start = StdInstant::now();
            let shard_refs: Vec<&[u8]> = encoded.chunks(shard_len).collect();
            let targets: Vec<ProposalTarget> = recipients
                .into_par_iter()
                .enumerate()
                .map(|(index, recipient)| {
                    // In consensus_only mode, strip the raw shard bytes from the proof.
                    // Proof.validate() uses value_hash (not value), so verification still passes.
                    // This reduces NV size from ~shard_size to ~300 bytes.
                    let proof = if consensus_only {
                        merkle_tree
                            .proof_hash_only(index, shard_refs[index])
                            .expect("Failed to build proof")
                    } else {
                        merkle_tree
                            .proof_with_leaf(index, shard_refs[index])
                            .expect("Failed to build proof")
                    };
                    let proposal = match trigger.clone() {
                        ProposalTrigger::QC(qc) => ProposalMessage::N(NormalProposal::new(
                            block.clone(),
                            qc,
                            proof,
                        )),
                        ProposalTrigger::TC(tc) => ProposalMessage::F(
                            FallbackRecoveryProposal::new(block.clone(), tc, proof),
                        ),
                        ProposalTrigger::Optimistic { qc, .. } => ProposalMessage::N(
                            NormalProposal::new(block.clone(), qc, proof),
                        ),
                    };
                    if recipient == my_name {
                        ProposalTarget::Local(proposal)
                    } else {
                        let message = bincode::serialize(&ConsensusMessage::Propose(proposal))
                            .expect("Failed to serialize block");
                        ProposalTarget::Remote(recipient, Bytes::from(message))
                    }
                })
                .collect();

            let mut local = None;
            let mut remote = Vec::new();
            for target in targets {
                match target {
                    ProposalTarget::Local(proposal) => local = Some(proposal),
                    ProposalTarget::Remote(recipient, message) => remote.push((recipient, message)),
                }
            }
            let total_bytes: usize = remote.iter().map(|(_, msg)| msg.len()).sum();

            let _ = tx.blocking_send(Phase2Result {
                round,
                block: block.clone(),
                local: local.expect("missing local proposal"),
                remote,
                shard_len,
                total_bytes,
                payload_ms,
                encode_ms,
                merkle_ms,
                sign_ms,
                proof_blocking_ms: proof_blocking_start.elapsed().as_millis(),
                encode_blocking_ms,
            });
        });
    }

    // Sends the local proposal to Core and remote proposals to peers.
    async fn handle_phase2_result(&mut self, p2: Phase2Result) {
        let round = p2.round;
        let digest = p2.block.digest();
        debug!(
            "TIMELINE event=proposal_messages_ready node={} author={} round={} digest={} remotes={} proof_blocking_ms={}",
            self.name,
            p2.block.author,
            round,
            digest,
            p2.remote.len(),
            p2.proof_blocking_ms
        );
        debug!(
            "TIMING proposal_make round={} payload_bytes={} shard_len={} remote_count={} remote_bytes={} payload_ms={} encode_ms={} merkle_ms={} sign_ms={} proof_blocking_ms={} encode_blocking_ms={}",
            round,
            p2.block.payload_len,
            p2.shard_len,
            p2.remote.len(),
            p2.total_bytes,
            p2.payload_ms,
            p2.encode_ms,
            p2.merkle_ms,
            p2.sign_ms,
            p2.proof_blocking_ms,
            p2.encode_blocking_ms,
        );

        let local_start = StdInstant::now();
        self.tx_proposer_core
            .send(p2.local)
            .await
            .expect("Failed to send block");
        let local_ms = local_start.elapsed().as_millis();

        self.send_proposals(p2.remote, round, digest).await;

        debug!(
            "TIMING propose_done round={} local_send_ms={}",
            round, local_ms,
        );

        // Proposals are out: start encoding the next block's payload speculatively so
        // it is ready before the next trigger arrives.
        self.start_speculative_phase1();
    }

    fn cleanup(&mut self, r: Round) {
        self.in_progress
            .retain(|proposal_round, _| *proposal_round > r);
    }

    fn observe(&mut self, _transactions: Vec<Transaction>) {}

    async fn run(&mut self) {
        if self.consensus_only {
            loop {
                tokio::select! {
                    Some(spec) = self.rx_speculative.recv() => self.handle_speculative_result(spec),
                    Some(phase1) = self.rx_phase1.recv() => self.handle_phase1_result(phase1).await,
                    Some(phase2) = self.rx_phase2.recv() => self.handle_phase2_result(phase2).await,
                    Some(m) = self.rx_message.recv() => match m {
                        ProposerMessage::Propose(trigger) => self.start_phase1(trigger),
                        ProposerMessage::Cleanup(r) => self.cleanup(r),
                        ProposerMessage::Observed(_) => (),
                    },
                }
            }
        } else {
            let timer = sleep(Duration::from_millis(self.max_block_delay));
            tokio::pin!(timer);
            loop {
                let timer_expired = timer.is_elapsed();
                let got_payload = !self.buffer.is_empty();

                if timer_expired || got_payload {
                    if timer_expired {
                        info!("Block timer expired");
                    }
                    if let Some(trigger) = self.proposal_request.take() {
                        self.start_phase1(trigger);
                        let deadline =
                            Instant::now() + Duration::from_millis(self.max_block_delay);
                        timer.as_mut().reset(deadline);
                    }
                }

                tokio::select! {
                    Some(phase1) = self.rx_phase1.recv() => self.handle_phase1_result(phase1).await,
                    Some(phase2) = self.rx_phase2.recv() => self.handle_phase2_result(phase2).await,
                    Some(certificate) = self.rx_mempool.recv() => {
                        self.buffer.push(
                            bincode::serialize(&certificate).expect("Failed to serialize certificate"),
                        );
                    },
                    Some(m) = self.rx_message.recv() => match m {
                        ProposerMessage::Propose(trigger) => self.proposal_request = Some(trigger),
                        ProposerMessage::Cleanup(r) => self.cleanup(r),
                        ProposerMessage::Observed(certificates) => self.observe(certificates),
                    },
                    () = &mut timer => {},
                }
            }
        }
    }
}
