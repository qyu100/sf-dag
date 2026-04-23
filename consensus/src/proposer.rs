use crate::consensus::Round;
use crate::messages::{Block, QC, TC};
#[cfg(feature = "benchmark")]
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::debug;
use tokio::sync::mpsc::{Receiver, Sender};

#[derive(Debug)]
pub enum ProposerMessage {
    Make(Round, QC, Digest, Option<TC>),
    Cleanup,
}

pub struct Proposer {
    name: PublicKey,
    signature_service: SignatureService,
    rx_message: Receiver<ProposerMessage>,
    tx_loopback: Sender<Block>,
    header_size: usize,
    tx_size: usize,
}

impl Proposer {
    pub fn spawn(
        name: PublicKey,
        signature_service: SignatureService,
        header_size: usize,
        tx_size: usize,
        rx_message: Receiver<ProposerMessage>,
        tx_loopback: Sender<Block>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                signature_service,
                rx_message,
                tx_loopback,
                header_size,
                tx_size,
            }
            .run()
            .await;
        });
    }

    async fn make_block(&mut self, round: Round, qc: QC, parent: Digest, tc: Option<TC>) {
        let payload = vec![vec![0u8; self.tx_size]; self.header_size / self.tx_size];
        // Generate a new block.
        let block = Block::new(
            qc,
            tc,
            parent,
            self.name,
            round,
            payload,
            self.signature_service.clone(),
        )
        .await;

        if !block.payload.is_empty() {
            debug!("Created {}", block);

            #[cfg(feature = "benchmark")]
            {
                // NOTE: This log entry is used to compute performance.
                log::info!("Created {:?}", block.digest());
                log::info!(
                    "Block {:?} contains {} B",
                    block.digest(),
                    block.payload.iter().map(|tx| tx.len()).sum::<usize>()
                );
            }
        }
        debug!("Created {:?}", block);

        // Send our block to the core for processing.
        self.tx_loopback
            .send(block)
            .await
            .expect("Failed to send block");
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(message) = self.rx_message.recv() => match message {
                    ProposerMessage::Make(round, qc, parent, tc) => {
                        self.make_block(round, qc, parent, tc).await
                    }
                    ProposerMessage::Cleanup => {}
                }
            }
        }
    }
}
