use crate::config::Committee;
use bytes::Bytes;
use crypto::{Digest, PublicKey};
use log::warn;
use network::SimpleSender;
use store::Store;
use tokio::sync::mpsc::Receiver;

#[cfg(test)]
#[path = "tests/helper_tests.rs"]
pub mod helper_tests;

/// Bincode variant index for `ConsensusMessage::Propose`.
///
/// The store keeps bincode-serialized `Block`s. A sync reply needs the same
/// block wrapped as `ConsensusMessage::Propose`, which bincode represents as a
/// little-endian u32 variant tag followed by the variant payload.
const PROPOSE_VARIANT_INDEX: u32 = 0;

/// A task dedicated to help other authorities by replying to their sync requests.
pub struct Helper {
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Input channel to receive sync requests.
    rx_requests: Receiver<(Digest, PublicKey)>,
    /// A network sender to reply to the sync requests.
    network: SimpleSender,
}

impl Helper {
    pub fn spawn(committee: Committee, store: Store, rx_requests: Receiver<(Digest, PublicKey)>) {
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
        while let Some((digest, origin)) = self.rx_requests.recv().await {
            // TODO [issue #58]: Do some accounting to prevent bad nodes from monopolizing our resources.

            // get the requestors address.
            let address = match self.committee.address(&origin) {
                Some(x) => x,
                None => {
                    warn!("Received sync request from unknown authority: {}", origin);
                    continue;
                }
            };

            // Reply to the request (if we can).
            if let Some(bytes) = self
                .store
                .read(digest.to_vec())
                .await
                .expect("Failed to read from storage")
            {
                let mut message = Vec::with_capacity(4 + bytes.len());
                message.extend_from_slice(&PROPOSE_VARIANT_INDEX.to_le_bytes());
                message.extend_from_slice(&bytes);
                self.network.send(address, Bytes::from(message)).await;
            }
        }
    }
}
