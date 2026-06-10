// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::Certificate;
use config::Committee;
use crypto::PublicKey;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;

/// Receives the highest round reached by consensus and update it for all tasks.
pub struct GarbageCollector {
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// Receives the ordered certificates from consensus.
    rx_consensus: Receiver<Certificate>,
}

impl GarbageCollector {
    pub fn spawn(
        _name: &PublicKey,
        _committee: &Committee,
        consensus_round: Arc<AtomicU64>,
        rx_consensus: Receiver<Certificate>,
    ) {
        tokio::spawn(async move {
            Self {
                consensus_round,
                rx_consensus,
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        let mut last_committed_round = 0;
        while let Some(certificate) = self.rx_consensus.recv().await {
            // TODO [issue #9]: Re-include batch digests that have not been sequenced into our next block.

            let round = certificate.round();
            if round > last_committed_round {
                last_committed_round = round;

                // Trigger cleanup on the primary.
                self.consensus_round.store(round, Ordering::Relaxed);
            }
        }
    }
}
