use crate::consensus::ConsensusMessage;
use crate::messages::{shard_store_key, ShardRequest, ShardResponse};
use bytes::Bytes;
use config::Committee;
use crypto::{Digest, PublicKey};
use log::{debug, warn};
use network::SimpleSender;
use store::Store;
use tokio::sync::mpsc::Receiver;

// #[cfg(test)]
// #[path = "tests/helper_tests.rs"]
// pub mod helper_tests;

pub enum HelperRequest {
    Block { digest: Digest, origin: PublicKey },
    Shard(ShardRequest),
}

/// A task dedicated to help other authorities by replying to their sync requests.
pub struct Helper {
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Input channel to receive sync requests.
    rx_requests: Receiver<HelperRequest>,
    /// A network sender to reply to the sync requests.
    network: SimpleSender,
}

impl Helper {
    pub fn spawn(committee: Committee, store: Store, rx_requests: Receiver<HelperRequest>) {
        tokio::spawn(async move {
            Self {
                committee,
                store,
                rx_requests,
                network: SimpleSender::new(),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        while let Some(request) = self.rx_requests.recv().await {
            match request {
                HelperRequest::Block { digest, origin } => self.serve_block(digest, origin).await,
                HelperRequest::Shard(request) => self.serve_shard(request).await,
            }
        }
    }

    async fn serve_block(&mut self, digest: Digest, origin: PublicKey) {
        let address = match self.committee.consensus(&origin) {
            Ok(x) => x.consensus_to_consensus,
            Err(e) => {
                warn!("Received unexpected sync request: {}", e);
                return;
            }
        };

        debug!("Received request for {} from {}", digest, address);

        if let Some(bytes) = self
            .store
            .read(digest.to_vec())
            .await
            .expect("Failed to read from storage")
        {
            let block = bincode::deserialize(&bytes).expect("Failed to deserialize our own block");
            let message = bincode::serialize(&ConsensusMessage::SyncResponse(block))
                .expect("Failed to serialize block");
            debug!("Serving {} to {}", digest, address);
            self.network.send(address, Bytes::from(message)).await;
        }
    }

    async fn serve_shard(&mut self, request: ShardRequest) {
        let address = match self.committee.consensus(&request.origin) {
            Ok(x) => x.consensus_to_consensus,
            Err(e) => {
                warn!("Received unexpected shard request: {}", e);
                return;
            }
        };

        let key = shard_store_key(&request.block, &request.payload_root, request.index);
        if let Some(bytes) = self
            .store
            .read(key)
            .await
            .expect("Failed to read shard proof from storage")
        {
            let proof = bincode::deserialize(&bytes).expect("Failed to deserialize shard proof");
            let response = ShardResponse {
                block: request.block.clone(),
                payload_root: request.payload_root.clone(),
                proof,
            };
            let message = bincode::serialize(&ConsensusMessage::ShardResponse(response))
                .expect("Failed to serialize shard response");
            debug!(
                "Serving shard {} for {} to {}",
                request.index, request.block, address
            );
            self.network.send(address, Bytes::from(message)).await;
        }
    }
}
