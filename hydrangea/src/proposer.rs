use crate::coding::{shard_hashes, Coding};
use crate::consensus::{ConsensusMessage, ProposalMessage, Round};
use crate::merkle::MerkleTree;
use crate::messages::{
    payload_hash, Block, FallbackRecoveryProposal, NormalProposal, Transaction, QC, TC,
};
use bytes::Bytes;
use config::Committee;
use crypto::{Digest, Hash as _, PublicKey, SignatureService};
use log::{debug, info};
use primary::Certificate;
use rayon::prelude::*;
use std::collections::HashMap;
use std::net::SocketAddr;
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
    trigger: ProposalTrigger,
    block: Block,
    encoded: Vec<u8>,
    shard_len: usize,
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

pub struct Proposer {
    name: PublicKey,
    consensus_only: bool,
    committee: Committee,
    in_progress: HashMap<Round, ()>,
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
    tx_proposal_net: Sender<Vec<(SocketAddr, Bytes, String)>>,
    proposal_request: Option<ProposalTrigger>,
    buffer: Vec<Transaction>,
    tx_phase1: Sender<Phase1Result>,
    rx_phase1: Receiver<Phase1Result>,
    tx_phase2: Sender<Phase2Result>,
    rx_phase2: Receiver<Phase2Result>,
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
        tx_proposal_net: Sender<Vec<(SocketAddr, Bytes, String)>>,
    ) {
        tokio::spawn(async move {
            let (tx_phase1, rx_phase1) = channel(8);
            let (tx_phase2, rx_phase2) = channel(8);
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
                tx_proposal_net,
                proposal_request: None,
                buffer: Vec::new(),
                tx_phase1,
                rx_phase1,
                tx_phase2,
                rx_phase2,
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

        let mut sends = Vec::new();
        for (recipient, message) in proposals {
            if recipient == self.name {
                continue;
            }
            let Some(address) = peers.get(&recipient).cloned() else {
                continue;
            };
            let label = format!(
                "proposal,node={},round={},digest={}",
                self.name, round, digest
            );
            sends.push((address, message, label));
        }
        let total_wire_bytes: usize = sends.iter().map(|(_, message, _)| message.len()).sum();
        info!(
            "BENCH event=proposal_send protocol=hydrangea node={} round={} digest={} remotes={} total_wire_bytes={} enqueue_ms={}",
            self.name,
            round,
            digest,
            sends.len(),
            total_wire_bytes,
            send_start.elapsed().as_millis()
        );
        debug!(
            "TIMING proposal_send round={} remotes={} enqueue_ms={}",
            round,
            sends.len(),
            send_start.elapsed().as_millis()
        );
        self.in_progress.insert(round, ());
        let _ = self.tx_proposal_net.send(sends).await;
    }

    fn record_proposal(&mut self, b: Block) {
        debug!("Created {:?}", b);
        info!("Created {}", b.digest());
        info!("Header {} contains {} B", b.digest(), b.payload_len);
        info!(
            "BENCH event=created protocol=hydrangea node={} author={} round={} digest={} parent={} payload_root={} payload_bytes={}",
            self.name,
            b.author,
            b.round,
            b.digest(),
            b.parent,
            b.payload_root,
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

    // Fires Phase 1 (RS encode + Merkle tree) in a background thread on trigger arrival.
    // Encoding starts only after the trigger is known; the cost is on the critical path.
    async fn start_phase1(&mut self, trigger: ProposalTrigger) {
        let (parent, round) = Self::trigger_parent_and_round(&trigger);
        let payload = self.get_payload();
        let logical_payload_len: usize = payload.iter().map(|tx| tx.len()).sum();
        let payload_hash = payload_hash(&payload);
        let block = Block::new(
            self.name,
            parent,
            payload_hash,
            Digest::default(),
            logical_payload_len,
            round,
            self.signature_service.clone(),
        )
        .await;
        self.record_proposal(block.clone());

        let data_shards = (self.committee.n - 2 * self.committee.f) as usize;
        let parity_shards = (2 * self.committee.f) as usize;
        let total_shards = self.committee.size();
        let rs_block_size = self.rs_block_size;
        let rs_block_threads = self.rs_block_threads;
        let tx = self.tx_phase1.clone();
        tokio::task::spawn_blocking(move || {
            let encode_blocking_start = StdInstant::now();

            let payload_start = StdInstant::now();
            let payload_bytes = bincode::serialize(&payload).expect("Failed to serialize payload");
            let serialized_payload_len = payload_bytes.len();
            let payload_ms = payload_start.elapsed().as_millis();

            let encode_start = StdInstant::now();
            let coding = Coding::new(data_shards, parity_shards);
            assert_eq!(coding.total_shard_count(), total_shards);
            let mut shard_len = (serialized_payload_len + data_shards - 1) / data_shards;
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
            let mut block = block;
            block.payload_root = merkle_tree.root_hash().clone();

            let _ = tx.blocking_send(Phase1Result {
                trigger,
                block,
                encoded,
                shard_len,
                merkle_tree,
                payload_ms,
                encode_ms,
                merkle_ms,
                encode_blocking_ms: encode_blocking_start.elapsed().as_millis(),
            });
        });
    }

    // Fires Phase 2 (proof generation) once the payload root is available.
    async fn handle_phase1_result(&mut self, p1: Phase1Result) {
        let my_name = self.name;
        let mut recipients: Vec<PublicKey> = self.committee.authorities.keys().cloned().collect();
        recipients.sort_by_key(|pk| self.committee.id(pk));
        let tx = self.tx_phase2.clone();
        let payload_ms = p1.payload_ms;
        let encode_ms = p1.encode_ms;
        let merkle_ms = p1.merkle_ms;
        let encode_blocking_ms = p1.encode_blocking_ms;
        let round = p1.block.round;
        let shard_len = p1.shard_len;
        let encoded = p1.encoded;
        let merkle_tree = p1.merkle_tree;
        let trigger = p1.trigger;
        let block = p1.block;
        let sign_ms = 0;

        tokio::task::spawn_blocking(move || {
            let proof_blocking_start = StdInstant::now();
            let shard_refs: Vec<&[u8]> = encoded.chunks(shard_len).collect();
            let targets: Vec<ProposalTarget> = recipients
                .into_par_iter()
                .enumerate()
                .map(|(index, recipient)| {
                    let proof = merkle_tree
                        .proof_with_leaf(index, shard_refs[index])
                        .expect("Failed to build proof");
                    let proposal = match trigger.clone() {
                        ProposalTrigger::QC(qc) => {
                            ProposalMessage::N(NormalProposal::new(block.clone(), qc, proof))
                        }
                        ProposalTrigger::TC(tc) => ProposalMessage::F(
                            FallbackRecoveryProposal::new(block.clone(), tc, proof),
                        ),
                        ProposalTrigger::Optimistic { qc, .. } => {
                            ProposalMessage::N(NormalProposal::new(block.clone(), qc, proof))
                        }
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
        info!(
            "BENCH event=proposal_ready protocol=hydrangea node={} author={} round={} digest={} remotes={} proof_blocking_ms={}",
            self.name,
            p2.block.author,
            round,
            digest,
            p2.remote.len(),
            p2.proof_blocking_ms
        );
        debug!(
            "TIMING proposal_make round={} shard_len={} encode_ms={} proof_blocking_ms={}",
            round, p2.shard_len, p2.encode_ms, p2.proof_blocking_ms,
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
                    Some(phase1) = self.rx_phase1.recv() => self.handle_phase1_result(phase1).await,
                    Some(phase2) = self.rx_phase2.recv() => self.handle_phase2_result(phase2).await,
                    Some(m) = self.rx_message.recv() => match m {
                        ProposerMessage::Propose(trigger) => self.start_phase1(trigger).await,
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
                        self.start_phase1(trigger).await;
                        let deadline = Instant::now() + Duration::from_millis(self.max_block_delay);
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
