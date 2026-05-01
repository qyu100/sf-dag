use crate::committer::Committer;
use crate::core::Core;
use crate::error::ConsensusError;
use crate::helper::Helper;
use crate::leader::LeaderElector;
use crate::mempool::MempoolDriver;
use crate::messages::{
    Block, Echo, FallbackRecoveryProposal, NormalProposal, Timeout, Vote, QC, TC,
};
use crate::proposer::Proposer;
use crate::synchronizer::Synchronizer;
use async_trait::async_trait;
use bytes::Bytes;
use config::{Committee, Parameters};
use crypto::{BlsSignatureService, Digest, PublicKey, SignatureService};
use futures::SinkExt as _;
use log::{debug, info};
use network::{MessageHandler, Receiver as NetworkReceiver, Writer};
use primary::Certificate;
use serde::{Deserialize, Serialize};
use std::error::Error;
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
    Echo(Echo),
    Vote(Vote),
    VerifiedVote(Vote),
    Timeout(Timeout),
    QC(QC),
    TC(TC),
    SyncRequest(Digest, PublicKey),
    SyncResponse(Block),
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
                tx_consensus: tx_consensus.clone(),
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
    tx_consensus: Sender<ConsensusMessage>,
    tx_helper: Sender<(Digest, PublicKey)>,
}

#[async_trait]
impl MessageHandler for ConsensusReceiverHandler {
    async fn dispatch(&self, writer: &mut Writer, serialized: Bytes) -> Result<(), Box<dyn Error>> {
        // Deserialize and parse the message.
        match bincode::deserialize(&serialized).map_err(ConsensusError::SerializationError)? {
            ConsensusMessage::SyncRequest(missing, origin) => self
                .tx_helper
                .send((missing, origin))
                .await
                .expect("Failed to send consensus message"),
            message @ ConsensusMessage::Propose(..) => {
                // TODO: Remove
                debug!("Acking Proposal: {:?}", message);
                // Reply with an ACK.
                let _ = writer.send(Bytes::from("Ack")).await;

                // Pass the message to the consensus core.
                self.tx_consensus
                    .send(message)
                    .await
                    .expect("Failed to consensus message")
            }
            message => {
                // debug!("Received message from peer: {:?}", message);
                self.tx_consensus
                    .send(message)
                    .await
                    .expect("Failed to consensus message")
            }
        }
        Ok(())
    }
}
