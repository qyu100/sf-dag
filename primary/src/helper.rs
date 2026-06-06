// Copyright(C) Facebook, Inc. and its affiliates.
use crate::primary::{HeaderMessage, HeaderType};
use bytes::Bytes;
use config::Committee;
use crypto::{Digest, PublicKey};
use log::{debug, error, warn};
use network::SimpleSender;
use store::Store;
use tokio::sync::mpsc::Receiver;

/// bincode variant index for `PrimaryMessage::HeaderInfoWithProof`.
/// PrimaryMessage variants: Timeout=0, Echo=1, Ready=2, CertificatesRequest=3,
/// HeaderInfoWithProof=4, ShardRequest=5, ShardResponse=6, Certificate=7.
const HIWP_VARIANT_INDEX: u32 = 4;

/// A task dedicated to help other authorities by replying to their certificates requests.
pub struct Helper {
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Input channel to receive certificates requests.
    rx_primaries: Receiver<(Vec<Digest>, PublicKey)>,
    /// A network sender to reply to the sync requests.
    network: SimpleSender,
}

impl Helper {
    pub fn spawn(
        committee: Committee,
        store: Store,
        rx_primaries: Receiver<(Vec<Digest>, PublicKey)>,
    ) {
        tokio::spawn(async move {
            Self {
                committee,
                store,
                rx_primaries,
                network: SimpleSender::new(),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        while let Some((digests, origin)) = self.rx_primaries.recv().await {
            // TODO [issue #195]: Do some accounting to prevent bad nodes from monopolizing our resources.

            // get the requestors address.
            let address = match self.committee.primary(&origin) {
                Ok(x) => x.primary_to_primary,
                Err(e) => {
                    warn!("Unexpected certificate request: {}", e);
                    continue;
                }
            };

            // Reply to the request (the best we can).
            for digest in digests {
                match self.store.read(digest.to_vec()).await {
                    Ok(Some(data)) => {
                        // The store contains bincode-serialized HeaderInfoWithProof.
                        // The network expects bincode-serialized PrimaryMessage::HeaderInfoWithProof(...).
                        // bincode encodes enums as u32 variant index (little-endian) + variant data.
                        // PrimaryMessage::HeaderInfoWithProof is variant index 4 (0-based).
                        // By prepending the 4-byte variant tag we skip a full deserialize-serialize
                        // roundtrip of the ~2.9MB payload.
                        let mut bytes = Vec::with_capacity(4 + data.len());
                        bytes.extend_from_slice(&HIWP_VARIANT_INDEX.to_le_bytes());
                        bytes.extend_from_slice(&data);

                        self.network.send(address, Bytes::from(bytes)).await;
                    }
                    Ok(None) => (),
                    Err(e) => error!("{}", e),
                }
            }
        }
    }
}
