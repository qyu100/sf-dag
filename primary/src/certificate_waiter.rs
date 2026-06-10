// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, HeaderInfoWithProof};
use crate::primary::{PrimaryMessage, Round};
use bytes::Bytes;
use config::Committee;
use crypto::{Digest, PublicKey};
use futures::future::try_join_all;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use log::{error, warn};
use network::SimpleSender;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

/// The resolution of the timer that checks whether we received replies to our sync requests, and triggers
/// new sync requests if we didn't.
const TIMER_RESOLUTION: u64 = 1_000;

/// Waits to receive all the ancestors of a certificate before looping it back to the `Core`
/// for further processing.
pub struct CertificateWaiter {
    /// The name of this authority.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,
    /// The delay to wait before re-trying sync requests.
    sync_retry_delay: u64,
    /// Receives sync commands from the `Synchronizer`.
    rx_synchronizer: Receiver<Certificate>,
    /// Loops back to the core certificates for which we got all parents.
    tx_core: Sender<Certificate>,
    /// Network driver allowing to send sync requests.
    network: SimpleSender,
    /// Digests requested through sync, with the round and last request timestamp.
    requests: HashMap<Digest, (Round, u128, PublicKey)>,
    genesis: Vec<Digest>,
}

impl CertificateWaiter {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        sync_retry_delay: u64,
        _sync_retry_nodes: usize,
        rx_synchronizer: Receiver<Certificate>,
        tx_core: Sender<Certificate>,
    ) {
        tokio::spawn(async move {
            let genesis = Header::genesis(&committee)
                .into_iter()
                .map(|x| x.id)
                .collect();
            Self {
                name,
                committee,
                store,
                consensus_round,
                gc_depth,
                sync_retry_delay,
                rx_synchronizer,
                tx_core,
                network: SimpleSender::new(),
                requests: HashMap::new(),
                genesis,
            }
            .run()
            .await
        });
    }

    /// Helper function. It waits for particular data to become available in the storage
    /// and then delivers the specified header.
    async fn waiter(
        mut missing: Vec<(Vec<u8>, Store)>,
        requested: Digest,
        deliver: Certificate,
    ) -> DagResult<(Digest, Certificate)> {
        let waiting: Vec<_> = missing
            .iter_mut()
            .map(|(x, y)| y.notify_read(x.to_vec()))
            .collect();

        try_join_all(waiting)
            .await
            .map(|_| (requested, deliver))
            .map_err(DagError::from)
    }

    fn now_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to measure time")
            .as_millis()
    }

    async fn request_missing(
        &mut self,
        digest: Digest,
        round: Round,
        target: PublicKey,
        reason: &str,
    ) {
        let now = Self::now_millis();
        let mut should_request = false;
        self.requests.entry(digest).or_insert_with(|| {
            should_request = true;
            (round, now, target)
        });

        if !should_request {
            return;
        }

        let address = match self.committee.primary(&target) {
            Ok(authority) => authority.primary_to_primary,
            Err(e) => {
                warn!("Unexpected sync target for certificate waiter: {}", e);
                return;
            }
        };

        let message = PrimaryMessage::CertificatesRequest(vec![digest], self.name);
        let bytes = bincode::serialize(&message).expect("Failed to serialize cert request");
        self.network.send(address, Bytes::from(bytes)).await;
        log::info!(
            "BENCH event=certificate_waiter_sync_request node={:?} round={} digest={:?} target={:?} reason={}",
            self.name, round, digest, target, reason
        );
    }

    async fn run(&mut self) {
        let mut waiting = FuturesUnordered::new();

        let timer = sleep(Duration::from_millis(TIMER_RESOLUTION));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                Some(certificate) = self.rx_synchronizer.recv() => {
                    // Add the certificate to the waiter pool. The waiter will return it to us
                    // when all its parents are in the store.

                    let header_id = certificate.header_id;
                    let key = header_id.to_vec();

                    if let Some(res) = self.store.read(key.clone()).await.unwrap() {
                        let header_info_with_proof: HeaderInfoWithProof = match bincode::deserialize(&res) {
                            Ok(header) => header,
                            Err(e) => {
                                error!("Failed to deserialize synced header {:?}: {}", header_id, e);
                                continue;
                            }
                        };

                        let parent = header_info_with_proof.parent;
                        if self.genesis.contains(&parent)
                            || self.store.read(parent.to_vec()).await.unwrap().is_some()
                        {
                            log::info!(
                                "BENCH event=certificate_waiter_local_ready node={:?} round={} digest={:?} parent={:?}",
                                self.name,
                                certificate.round,
                                certificate.header_id,
                                parent
                            );
                            self.tx_core
                                .send(certificate)
                                .await
                                .expect("Failed to send certificate");
                            continue;
                        }

                        self.request_missing(
                            parent,
                            certificate.round,
                            header_info_with_proof.author,
                            "missing parent",
                        )
                        .await;
                        let wait_for = vec![(parent.to_vec(), self.store.clone())];

                        let fut = Self::waiter(wait_for, parent, certificate);
                        waiting.push(fut);
                    }else{
                        self.request_missing(
                            header_id,
                            certificate.round,
                            certificate.origin,
                            "missing header",
                        ).await;

                        let wait_for = vec![(key, self.store.clone())];
                        let fut = Self::waiter(wait_for, header_id, certificate);
                        waiting.push(fut);
                    }
                }
                Some(result) = waiting.next() => match result {
                    Ok((requested, certificate)) => {
                        self.requests.remove(&requested);
                        self.tx_core.send(certificate).await.expect("Failed to send certificate");
                    },
                    Err(e) => {
                        error!("{}", e);
                        panic!("Storage failure: killing node.");
                    }
                },

                () = &mut timer => {
                    let now = Self::now_millis();
                    let mut retry_by_target: HashMap<PublicKey, Vec<Digest>> = HashMap::new();
                    for (digest, (_, timestamp, target)) in self.requests.iter_mut() {
                        if *timestamp + (self.sync_retry_delay as u128) < now {
                            retry_by_target
                                .entry(*target)
                                .or_insert_with(Vec::new)
                                .push(*digest);
                            *timestamp = now;
                        }
                    }

                    for (target, retry) in retry_by_target {
                        let address = match self.committee.primary(&target) {
                            Ok(authority) => authority.primary_to_primary,
                            Err(e) => {
                                warn!("Unexpected sync retry target for certificate waiter: {}", e);
                                continue;
                            }
                        };
                        let message = PrimaryMessage::CertificatesRequest(retry, self.name);
                        let bytes = bincode::serialize(&message).expect("Failed to serialize cert request");
                        self.network.send(address, Bytes::from(bytes)).await;
                    }

                    timer.as_mut().reset(Instant::now() + Duration::from_millis(TIMER_RESOLUTION));
                }
            }

            let round = self.consensus_round.load(Ordering::Relaxed);
            if round > self.gc_depth {
                let gc_round = round - self.gc_depth;
                self.requests.retain(|_, (r, _, _)| *r > gc_round);
            }
        }
    }
}
