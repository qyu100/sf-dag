use crate::coding::{shard_hashes, Coding};
use crate::consensus::{ConsensusMessage, ProposalMessage, Round};
use crate::merkle::MerkleTree;
use crate::messages::{
    Block, FallbackRecoveryProposal, Header, NormalProposal, Transaction, QC, TC,
};
use bytes::Bytes;
use config::Committee;
use crypto::{Hash as _, PublicKey, SignatureService};
use log::{debug, info};
use network::{CancelHandler, ReliableSender};
use primary::Certificate;
use rayon::prelude::*;
use std::collections::HashMap;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

#[derive(Debug, Clone)]
pub enum ProposalTrigger {
    QC(QC),
    TC(TC),
}

#[derive(Debug)]
pub enum ProposerMessage {
    Propose(ProposalTrigger),
    Cleanup(Round),
    Observed(Vec<Transaction>),
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
            }
            .run()
            .await;
        });
    }

    // TODO: This function simulates payload creation. An actual payload manager will need to
    // have logic for identifying "pending" txs in order to prevent duplicates and/or lost txs.
    // Such pending txs should be those included in blocks that have been proposed/voted on
    // but have not yet satisfied the commit rule. Txs should only be removed from the Proposer
    // once they have been committed.
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

    async fn send_proposals(&mut self, proposals: Vec<(PublicKey, Bytes)>) {
        let send_start = Instant::now();
        let peers: HashMap<PublicKey, _> = self
            .committee
            .others_consensus(&self.name)
            .into_iter()
            .map(|(name, x)| (name, x.consensus_to_consensus))
            .collect();

        // References to the connections that we are continuously trying to deliver
        // this proposal on. We keep them around to ensure that we keep sending until:
        //   1. we deliver it (indicated by an ACK from the recipient), or;
        //   2. we observe either a QC for it (indicating our job is done), or;
        //   3. we observe a TC for the round (indicating the network is asynchronous), or;
        //   4. we replace it with another proposal for this round (only occurs if Optimistic).
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
            handles.push(self.network.send(address, message).await);
        }
        info!(
            "TIMING proposal_send round={} remotes={} enqueue_ms={}",
            self.last_proposed.round,
            handles.len(),
            send_start.elapsed().as_millis()
        );
        self.in_progress.insert(self.last_proposed.round, handles);
    }

    fn record_proposal(&mut self, b: Block) {
        info!("Created {:?}", b);
        info!("Created {}", b.digest());
        info!("Header {} contains {} B", b.digest(), b.payload_len);
        info!(
            "TIMELINE event=block_created node={} author={} round={} digest={} payload_bytes={}",
            self.name,
            b.author,
            b.round,
            b.digest(),
            b.payload_len
        );
        self.last_proposed = b;
    }

    async fn make_proposals(
        &mut self,
        trigger: ProposalTrigger,
    ) -> (ProposalMessage, Vec<(PublicKey, Bytes)>) {
        let total_start = Instant::now();
        let (parent, round) = match &trigger {
            ProposalTrigger::QC(qc) => (qc.blk_hash.clone(), qc.round + 1),
            ProposalTrigger::TC(tc) => (tc.high_qc.blk_hash.clone(), tc.round + 1),
        };

        let payload_start = Instant::now();
        let header = Header::new(self.name, parent, self.get_payload(), round);
        let payload_bytes =
            bincode::serialize(&header.payload).expect("Failed to serialize payload");
        let payload_len = payload_bytes.len();
        let payload_ms = payload_start.elapsed().as_millis();

        let encode_start = Instant::now();
        let data_shards = (self.committee.n - 2 * self.committee.f) as usize;
        let parity_shards = (2 * self.committee.f) as usize;
        let coding = Coding::new(data_shards, parity_shards);
        let total_shards = coding.total_shard_count();
        assert_eq!(total_shards, self.committee.size());

        let mut shard_len = (payload_len + data_shards - 1) / data_shards;
        if shard_len == 0 {
            shard_len = 1;
        }
        shard_len = ((shard_len + 63) / 64) * 64;
        let mut encoded = payload_bytes;
        encoded.resize(shard_len * total_shards, 0);
        let mut shards: Vec<&mut [u8]> = encoded.chunks_mut(shard_len).collect();
        coding
            .encode(&mut shards, self.rs_block_size, self.rs_block_threads)
            .expect("Failed to encode payload");
        let encode_ms = encode_start.elapsed().as_millis();

        let merkle_start = Instant::now();
        let shard_options: Vec<Option<Box<[u8]>>> = shards
            .iter()
            .map(|s| Some(s.to_vec().into_boxed_slice()))
            .collect();
        let mtree =
            MerkleTree::from_hashes(shard_hashes(&shard_options).expect("Failed to hash shards"));
        let merkle_ms = merkle_start.elapsed().as_millis();

        let sign_start = Instant::now();
        let block = Block::new(
            self.name,
            header.parent,
            mtree.root_hash().clone(),
            payload_len,
            round,
            self.signature_service.clone(),
        )
        .await;
        let sign_ms = sign_start.elapsed().as_millis();
        self.record_proposal(block.clone());

        let mut recipients: Vec<PublicKey> = self.committee.authorities.keys().cloned().collect();
        recipients.sort_by_key(|pk| self.committee.id(pk));

        enum ProposalTarget {
            Local(ProposalMessage),
            Remote(PublicKey, Bytes),
        }

        let my_name = self.name;
        let shard_refs: Vec<&[u8]> = shards.iter().map(|s| &**s).collect();
        let proof_serialize_start = Instant::now();
        let targets: Vec<ProposalTarget> = recipients
            .into_par_iter()
            .enumerate()
            .map(|(index, recipient)| {
                let proof = mtree
                    .proof_with_leaf(index, shard_refs[index])
                    .expect("Failed to build proof");
                let proposal = match trigger.clone() {
                    ProposalTrigger::QC(qc) => {
                        ProposalMessage::N(NormalProposal::new(block.clone(), qc, proof))
                    }
                    ProposalTrigger::TC(tc) => {
                        ProposalMessage::F(FallbackRecoveryProposal::new(block.clone(), tc, proof))
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
        let proof_serialize_ms = proof_serialize_start.elapsed().as_millis();

        let mut local = None;
        let mut remote = Vec::new();
        for target in targets {
            match target {
                ProposalTarget::Local(proposal) => local = Some(proposal),
                ProposalTarget::Remote(recipient, message) => remote.push((recipient, message)),
            }
        }
        let total_bytes: usize = remote.iter().map(|(_, message)| message.len()).sum();
        info!(
            "TIMING proposal_make round={} payload_bytes={} shard_len={} remote_count={} remote_bytes={} payload_ms={} encode_ms={} merkle_ms={} sign_ms={} proof_serialize_ms={} total_ms={}",
            round,
            payload_len,
            shard_len,
            remote.len(),
            total_bytes,
            payload_ms,
            encode_ms,
            merkle_ms,
            sign_ms,
            proof_serialize_ms,
            total_start.elapsed().as_millis()
        );
        (local.expect("missing local proposal"), remote)
    }

    async fn propose(&mut self, trigger: ProposalTrigger) {
        let propose_start = Instant::now();
        let (local, remote) = self.make_proposals(trigger).await;
        // Send the Proposal to the Core for local processing.
        let local_start = Instant::now();
        self.tx_proposer_core
            .send(local)
            .await
            .expect("Failed to send block");
        let local_ms = local_start.elapsed().as_millis();
        // Broadcast the Proposal.
        self.send_proposals(remote).await;
        info!(
            "TIMING propose_done round={} local_send_ms={} total_ms={}",
            self.last_proposed.round,
            local_ms,
            propose_start.elapsed().as_millis()
        );
    }

    fn cleanup(&mut self, r: Round) {
        // Core sent a Cleanup request after we transitioned to a new round.
        // Stop trying to deliver proposals for previous rounds. Ensures
        // we are able to use the resend loop to reliably deliver our proposals
        // to honest validators while preventing Byzantine validators from arbitrarily
        // consuming our bandwidth by never ACKing.
        self.in_progress
            .retain(|proposal_round, _| *proposal_round > r);
    }

    fn observe(&mut self, _transactions: Vec<Transaction>) {
        // Consensus-only erasure-coded blocks generate synthetic transactions.
    }

    async fn run(&mut self) {
        // Initialize connections with all peers to avoid the negotiation delay the first time we propose.
        // If we don't do this then the delay is repeated each time there is a new proposer, making it
        // non-trivial in shorter runs in larger networks.
        self.network
            .broadcast(
                self.committee.others_consensus_sockets(&self.name),
                Bytes::from("Ack"),
            )
            .await;

        if self.consensus_only {
            loop {
                tokio::select! {
                    Some(m) = self.rx_message.recv() => {
                        match m {
                            ProposerMessage::Propose(trigger) => self.propose(trigger).await,
                            ProposerMessage::Cleanup(r) => self.cleanup(r),
                            ProposerMessage::Observed(_) => (),
                        }
                    }
                }
            }
        } else {
            let timer = sleep(Duration::from_millis(self.max_block_delay));
            tokio::pin!(timer);

            loop {
                // Check if we can propose a new block.
                let timer_expired = timer.is_elapsed();
                let got_payload = !self.buffer.is_empty();

                if timer_expired || got_payload {
                    if timer_expired {
                        info!("Block timer expired");
                    }
                    if let Some(trigger) = self.proposal_request.take() {
                        // Make a new block.
                        self.propose(trigger).await;

                        // Reschedule the timer.
                        let deadline = Instant::now() + Duration::from_millis(self.max_block_delay);
                        timer.as_mut().reset(deadline);
                    }
                }

                tokio::select! {
                    Some(certificate) = self.rx_mempool.recv() => {
                        self.buffer.push(bincode::serialize(&certificate).expect("Failed to serialize certificate"));
                    },
                    Some(m) = self.rx_message.recv() =>  {
                        match m {
                            ProposerMessage::Propose(trigger) => self.proposal_request = Some(trigger),
                            ProposerMessage::Cleanup(r) => self.cleanup(r),
                            ProposerMessage::Observed(certificates) => self.observe(certificates)
                        }
                    },
                    () = &mut timer => {
                        // Nothing to do.
                    },
                }
            }
        }
    }
}
