use crate::committer::Committer;
use crate::core::Core;
use crate::error::ConsensusError;
use crate::helper::Helper;
use crate::leader::LeaderElector;
use crate::mempool::MempoolDriver;
use crate::messages::{Block, FallbackRecoveryProposal, NormalProposal, Timeout, Vote, QC, TC};
use crate::proposer::Proposer;
use crate::synchronizer::Synchronizer;
use async_trait::async_trait;
use bytes::Bytes;
use config::{Committee, Parameters};
use crypto::{BlsSignatureService, Digest, Hash as _, PublicKey, SignatureService};
use futures::SinkExt as _;
use log::{debug, info};
use network::{MessageHandler, Receiver as NetworkReceiver, Writer};
use primary::Certificate;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Instant;
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};

// #[cfg(test)]
// #[path = "tests/consensus_tests.rs"]
// pub mod consensus_tests;

/// The default channel capacity for each channel of the consensus.
pub const CHANNEL_CAPACITY: usize = 1_000;

/// The consensus round number.
pub type Round = u64;

#[derive(Serialize, Deserialize, Debug)]
pub enum ConsensusMessage {
    Propose(ProposalMessage),
    Vote(Vote),
    VerifiedVote(Vote),
    Timeout(Timeout),
    QC(QC),
    TC(TC),
    SyncRequest(Digest, PublicKey),
    SyncResponse(Block),
}

#[allow(dead_code)]
#[derive(Serialize)]
pub enum ConsensusMessageRef<'a> {
    Propose(&'a ProposalMessage),
    Vote(&'a Vote),
    VerifiedVote(&'a Vote),
    Timeout(&'a Timeout),
    QC(&'a QC),
    TC(&'a TC),
    SyncRequest(&'a Digest, &'a PublicKey),
    SyncResponse(&'a Block),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProposalMessage {
    F(FallbackRecoveryProposal),
    N(NormalProposal),
}

pub struct Consensus;

impl Consensus {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        signature_service: SignatureService,
        bls_signature_service: BlsSignatureService,
        store: Store,
        rx_mempool: Receiver<Certificate>,
        tx_mempool: Sender<Certificate>,
        tx_output: Sender<Block>,
    ) {
        // NOTE: This log entry is used to compute performance.
        parameters.log(&committee);

        let (tx_consensus, rx_consensus) = channel(CHANNEL_CAPACITY);
        let (tx_proposer_core, rx_proposer_core) = channel(CHANNEL_CAPACITY);
        let (tx_sync_core, rx_sync_core) = channel(CHANNEL_CAPACITY);
        let (tx_core_proposer, rx_core_proposer) = channel(CHANNEL_CAPACITY);
        let (tx_helper, rx_helper) = channel(CHANNEL_CAPACITY);
        let (tx_commit, rx_commit) = channel(CHANNEL_CAPACITY);
        // let (tx_mempool_copy, rx_mempool_copy) = channel(CHANNEL_CAPACITY);

        // Spawn the network receiver.
        let mut address = committee
            .consensus(&name)
            .expect("Our public key is not in the committee")
            .consensus_to_consensus;
        address.set_ip("0.0.0.0".parse().unwrap());
        NetworkReceiver::spawn(
            address,
            /* handler */
            ConsensusReceiverHandler {
                name,
                tx_consensus: tx_consensus.clone(),
                tx_proposals: tx_proposer_core.clone(),
                tx_helper,
            },
        );
        info!(
            "Node {} listening to consensus messages on {}",
            name, address
        );

        // Make the leader election module.
        let leader_elector = LeaderElector::new(parameters.leader_elector, committee.clone());

        // Make the mempool driver.
        let mempool_driver = MempoolDriver::new(committee.clone(), tx_mempool);

        // Make the synchronizer.
        let synchronizer = Synchronizer::new(
            name,
            committee.clone(),
            store.clone(),
            tx_sync_core.clone(),
            parameters.sync_retry_delay,
        );

        // Spawn the consensus core.
        Core::spawn(
            name,
            committee.clone(),
            parameters.consensus_only,
            signature_service.clone(),
            bls_signature_service,
            store.clone(),
            leader_elector,
            mempool_driver,
            synchronizer,
            parameters.timeout_delay,
            parameters.rs_block_size,
            parameters.rs_block_threads,
            tx_consensus,
            /* rx_message */ rx_consensus,
            rx_proposer_core,
            rx_sync_core,
            tx_core_proposer,
            tx_commit,
            tx_output,
        );

        if !parameters.consensus_only {
            // Commits the mempool certificates and their sub-dag.
            Committer::spawn(rx_commit);
        }

        // Spawn the block proposer.
        Proposer::spawn(
            name,
            parameters.consensus_only,
            committee.clone(),
            parameters.header_size,
            parameters.tx_size,
            parameters.max_block_size,
            parameters.rs_block_size,
            parameters.rs_block_threads,
            signature_service,
            rx_mempool,
            /* rx_message */ rx_core_proposer,
            tx_proposer_core,
        );

        // Spawn the helper module.
        Helper::spawn(committee, store, /* rx_requests */ rx_helper);
    }
}

/// Defines how the network receiver handles incoming primary messages.
#[derive(Clone)]
struct ConsensusReceiverHandler {
    name: PublicKey,
    tx_consensus: Sender<ConsensusMessage>,
    tx_proposals: Sender<ProposalMessage>,
    tx_helper: Sender<(Digest, PublicKey)>,
}

#[async_trait]
impl MessageHandler for ConsensusReceiverHandler {
    async fn dispatch(&self, writer: &mut Writer, serialized: Bytes) -> Result<(), Box<dyn Error>> {
        let total_start = Instant::now();
        let bytes = serialized.len();
        let ack_start = Instant::now();
        let _ = writer.send(Bytes::from("Ack")).await;
        let ack_ms = ack_start.elapsed().as_millis();

        let deserialize_start = Instant::now();
        let message: ConsensusMessage =
            bincode::deserialize(&serialized).map_err(ConsensusError::SerializationError)?;
        let deserialize_ms = deserialize_start.elapsed().as_millis();
        let label = match &message {
            ConsensusMessage::Propose(ProposalMessage::N(p)) => {
                format!(
                    "Propose(Normal),round={},digest={}",
                    p.block.round,
                    p.block.digest()
                )
            }
            ConsensusMessage::Propose(ProposalMessage::F(p)) => {
                format!(
                    "Propose(Fallback),round={},digest={}",
                    p.block.round,
                    p.block.digest()
                )
            }
            ConsensusMessage::Vote(v) => format!(
                "Vote({}),round={},digest={},root={}",
                v.kind, v.round, v.blk_hash, v.payload_root
            ),
            ConsensusMessage::VerifiedVote(v) => format!(
                "VerifiedVote({}),round={},digest={},root={}",
                v.kind, v.round, v.blk_hash, v.payload_root
            ),
            ConsensusMessage::Timeout(t) => format!("Timeout,round={}", t.round),
            ConsensusMessage::QC(qc) => format!(
                "QC({}),round={},digest={},root={}",
                qc.kind, qc.round, qc.blk_hash, qc.payload_root
            ),
            ConsensusMessage::TC(tc) => format!("TC,round={}", tc.round),
            ConsensusMessage::SyncRequest(missing, _) => {
                format!("SyncRequest,digest={}", missing)
            }
            ConsensusMessage::SyncResponse(block) => {
                format!(
                    "SyncResponse,round={},digest={}",
                    block.round,
                    block.digest()
                )
            }
        };

        match message {
            ConsensusMessage::SyncRequest(missing, origin) => {
                let send_start = Instant::now();
                self.tx_helper
                    .send((missing, origin))
                    .await
                    .expect("Failed to send consensus message");
                Self::log_dispatch_timing(
                    &label,
                    bytes,
                    deserialize_ms,
                    ack_ms,
                    send_start.elapsed().as_millis(),
                    total_start.elapsed().as_millis(),
                );
            }
            ConsensusMessage::Propose(proposal) => {
                // Keep proposals off the shared consensus queue so large vote bursts do not
                // delay the proposal-to-vote path.
                let (author, round, digest, payload_bytes) = Self::proposal_metadata(&proposal);
                info!(
                    "TIMELINE event=proposal_frame_received node={} author={} round={} digest={} bytes={} payload_bytes={} deserialize_ms={} ack_ms={}",
                    self.name,
                    author,
                    round,
                    digest,
                    bytes,
                    payload_bytes,
                    deserialize_ms,
                    ack_ms
                );
                let send_start = Instant::now();
                self.tx_proposals
                    .send(proposal)
                    .await
                    .expect("Failed to send proposal message");
                let core_send_ms = send_start.elapsed().as_millis();
                debug!(
                    "TIMELINE event=proposal_core_queued node={} author={} round={} digest={} core_send_ms={}",
                    self.name,
                    author,
                    round,
                    digest,
                    core_send_ms
                );
                Self::log_dispatch_timing(
                    &label,
                    bytes,
                    deserialize_ms,
                    ack_ms,
                    core_send_ms,
                    total_start.elapsed().as_millis(),
                );
            }
            message => {
                // debug!("Received message from peer: {:?}", message);
                if let ConsensusMessage::Vote(vote) = &message {
                    debug!(
                        "TIMELINE event=vote_frame_received node={} kind={} author={} round={} digest={} payload_root={} bytes={} deserialize_ms={} ack_ms={}",
                        self.name,
                        vote.kind,
                        vote.author,
                        vote.round,
                        vote.blk_hash,
                        vote.payload_root,
                        bytes,
                        deserialize_ms,
                        ack_ms
                    );
                }
                let send_start = Instant::now();
                self.tx_consensus
                    .send(message)
                    .await
                    .expect("Failed to consensus message");
                Self::log_dispatch_timing(
                    &label,
                    bytes,
                    deserialize_ms,
                    ack_ms,
                    send_start.elapsed().as_millis(),
                    total_start.elapsed().as_millis(),
                );
            }
        }
        Ok(())
    }
}

impl ConsensusReceiverHandler {
    fn proposal_metadata(proposal: &ProposalMessage) -> (PublicKey, Round, Digest, usize) {
        match proposal {
            ProposalMessage::N(proposal) => (
                proposal.block.author,
                proposal.block.round,
                proposal.block.digest(),
                proposal.block.payload_len,
            ),
            ProposalMessage::F(proposal) => (
                proposal.block.author,
                proposal.block.round,
                proposal.block.digest(),
                proposal.block.payload_len,
            ),
        }
    }

    fn log_dispatch_timing(
        label: &str,
        bytes: usize,
        deserialize_ms: u128,
        ack_ms: u128,
        core_send_ms: u128,
        total_ms: u128,
    ) {
        if total_ms >= 10 || deserialize_ms >= 10 || core_send_ms >= 10 {
            info!(
                "TIMING consensus_receive label={} bytes={} deserialize_ms={} ack_ms={} core_send_ms={} total_ms={}",
                label, bytes, deserialize_ms, ack_ms, core_send_ms, total_ms
            );
        } else {
        }
    }
}
