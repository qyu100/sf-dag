use std::collections::HashMap;

// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::DagResult;
use crate::header_waiter::WaiterMessage;
use crate::messages::{Certificate, Header, HeaderInfoWithProof};
use crate::primary::HeaderType;
use crate::{HeaderInfo, Round};
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use std::collections::HashSet;
use store::Store;
use tokio::sync::mpsc::Sender;

/// The `Synchronizer` checks if we have all batches and parents referenced by a header. If we don't, it sends
/// a command to the `Waiter` to request the missing data.
pub struct Synchronizer {
    /// The public key of this primary.
    name: PublicKey,
    /// The persistent storage.
    store: Store,
    /// Send commands to the `HeaderWaiter`.
    tx_header_waiter: Sender<WaiterMessage>,
    /// Send commands to the `CertificateWaiter`.
    tx_certificate_waiter: Sender<Certificate>,
    /// The genesis and its digests.
    genesis: Vec<(Digest, Header)>,
    delivered_parents: HashMap<Round, HashSet<Digest>>,
    gc_depth: Round,
}

impl Synchronizer {
    pub fn new(
        name: PublicKey,
        committee: &Committee,
        store: Store,
        tx_header_waiter: Sender<WaiterMessage>,
        tx_certificate_waiter: Sender<Certificate>,
        gc_depth: Round,
    ) -> Self {
        Self {
            name,
            store,
            tx_header_waiter,
            tx_certificate_waiter,
            genesis: Header::genesis(committee)
                .into_iter()
                .map(|x| (x.id, x))
                .collect(),
            delivered_parents: HashMap::with_capacity(2 * gc_depth as usize),
            gc_depth,
        }
    }

    /// Returns `true` if we have all transactions of the payload. If we don't, we return false,
    /// synchronize with other nodes (through our workers), and re-schedule processing of the
    /// header for when we will have its complete payload.
    // pub async fn missing_payload(&mut self, header: &Header) -> DagResult<bool> {
    //     // We don't store the payload of our own workers.
    //     if header.author == self.name {
    //         return Ok(false);
    //     }

    //     let mut missing = Digest::default();
    //         // Check whether we have the batch. If one of our worker has the batch, the primary stores the pair
    //         // (digest, worker_id) in its own storage. It is important to verify that we received the batch
    //         // from the correct worker id to prevent the following attack:
    //         //      1. A Bad node sends a batch X to 2f good nodes through their worker #0.
    //         //      2. The bad node proposes a malformed block containing the batch X and claiming it comes
    //         //         from worker #1.
    //         //      3. The 2f good nodes do not need to sync and thus don't notice that the header is malformed.
    //         //         The bad node together with the 2f good nodes thus certify a block containing the batch X.
    //         //      4. The last good node will never be able to sync as it will keep sending its sync requests
    //         //         to workers #1 (rather than workers #0). Also, clients will never be able to retrieve batch
    //         //         X as they will be querying worker #1.
    //     let key = header.digest().to_vec();
    //     if self.store.read(key).await?.is_none() {
    //         missing = header.digest()
    //     }

    //     if missing == Digest::default() {
    //         return Ok(false);
    //     }

    //     self.tx_header_waiter
    //         .send(WaiterMessage::SyncPayload(missing, header.clone()))
    //         .await
    //         .expect("Failed to send sync batch request");
    //     Ok(true)
    // }

    pub async fn deliver_vertex(&mut self, round: Round, header_id: Digest) -> DagResult<()> {
        self.delivered_parents
            .entry(round)
            .or_insert_with(HashSet::new)
            .insert(header_id);
        Ok(())
    }

    pub async fn garbage_collect(&mut self, gc_round: Round) -> DagResult<()> {
        self.delivered_parents.retain(|k, _| k >= &gc_round);
        Ok(())
    }

    /// Returns the parent digest if we have it. If we don't, send a request to the `HeaderWaiter` to synchronize the missing parent and return None.
    pub async fn get_parent(
        &mut self,
        header_info_with_proof: &HeaderInfoWithProof,
    ) -> DagResult<Option<Digest>> {
        let parent_digest = header_info_with_proof.parent;
        let round = header_info_with_proof.round;

        // If parent is genesis, we already have it.
        if self.genesis.iter().any(|(x, _)| x == &parent_digest) {
            return Ok(Some(parent_digest));
        }

        // If we've already delivered this parent for the round, return it.
        if let Some(set) = self.delivered_parents.get(&round) {
            if set.contains(&parent_digest) {
                return Ok(Some(parent_digest));
            }
        }

        // Check local storage.
        match self.store.read(parent_digest.to_vec()).await? {
            Some(_bytes) => {
                // Record as delivered and return.
                self.delivered_parents
                    .entry(round)
                    .or_insert_with(HashSet::new)
                    .insert(parent_digest);
                Ok(Some(parent_digest))
            }
            None => {
                // Request the missing parent from peers via the HeaderWaiter and return None to indicate it's missing.
                let missing = vec![parent_digest];
                // Construct a minimal HeaderInfo to send to the waiter.
                self.tx_header_waiter
                    .send(WaiterMessage::SyncParents(
                        missing,
                        header_info_with_proof.clone(),
                    ))
                    .await
                    .expect("Failed to send sync parents request");
                Ok(None)
            }
        }
    }

    /// Check whether we have the ancestor of the certificate. If we don't, send the certificate to
    /// the `CertificateWaiter` which will trigger re-processing once we have all the missing data.
    // pub async fn deliver_certificate(&mut self, certificate: &Certificate) -> DagResult<bool> {
    //     let key = certificate.header_id.to_vec();

    //     match self.store.read(key).await? {
    //         Some(head) => {
    //             // We expect the stored value to be a HeaderInfoWithProof for certificates produced by this core.
    //             let header_info_with_proof: HeaderInfoWithProof =
    //                 bincode::deserialize(&head).map_err(crate::error::DagError::from)?;

    //             let parent = header_info_with_proof.parent;

    //             // If parent is genesis we already have it.
    //             if self.genesis.iter().any(|(d, _)| d == &parent) {
    //                 return Ok(true);
    //             }

    //             // Check local storage for the single parent.
    //             if self.store.read(parent.to_vec()).await?.is_none() {
    //                 self.tx_certificate_waiter
    //                     .send(certificate.clone())
    //                     .await
    //                     .expect("Failed to send sync certificate request");
    //                 return Ok(false);
    //             }

    //             Ok(true)
    //         }
    //         None => {
    //             // We don't have the header itself -> request sync via CertificateWaiter.
    //             self.tx_certificate_waiter
    //                 .send(certificate.clone())
    //                 .await
    //                 .expect("Failed to send sync certificate request");
    //             Ok(false)
    //         }
    //     }
    // }
    pub async fn deliver_certificate(&mut self, certificate: &Certificate) -> DagResult<bool> {
        let key = certificate.header_id.to_vec();

        match self.store.read(key).await? {
            Some(head) => {
                // We expect the stored value to be a HeaderInfoWithProof for certificates produced by this core.
                let header_info_with_proof: HeaderInfoWithProof =
                    bincode::deserialize(&head).map_err(crate::error::DagError::from)?;

                let parent = header_info_with_proof.parent;

                // If parent is genesis we already have it.
                if self.genesis.iter().any(|(d, _)| d == &parent) {
                    return Ok(true);
                }

                // Check local storage for the single parent.
                if self.store.read(parent.to_vec()).await?.is_none() {
                    self.tx_certificate_waiter
                        .send(certificate.clone())
                        .await
                        .expect("Failed to send sync certificate request");
                    return Ok(false);
                }

                Ok(true)
            }
            None => {
                // We don't have the header itself -> request sync via CertificateWaiter.
                self.tx_certificate_waiter
                    .send(certificate.clone())
                    .await
                    .expect("Failed to send sync certificate request");
                Ok(false)
            }
        }
    }

    /// Optimized version of deliver_certificate: accepts the parent digest directly
    /// from Core's in-memory `parent_info` map, eliminating the store read + deserialize
    /// of the full ~2.9MB HeaderInfoWithProof on every certificate.
    /// Falls back to the original store-based path if `parent` is None.
    #[allow(dead_code)]
    pub async fn deliver_certificate_optimized(
        &mut self,
        certificate: &Certificate,
        parent: Option<Digest>,
    ) -> DagResult<bool> {
        let parent = match parent {
            Some(p) => p,
            None => {
                // Fallback: read from store (original path).
                return self.deliver_certificate(certificate).await;
            }
        };

        // If parent is genesis we already have it.
        if self.genesis.iter().any(|(d, _)| d == &parent) {
            return Ok(true);
        }

        // Check local storage for the single parent.
        if self.store.read(parent.to_vec()).await?.is_none() {
            self.tx_certificate_waiter
                .send(certificate.clone())
                .await
                .expect("Failed to send sync certificate request");
            return Ok(false);
        }

        Ok(true)
    }
}
