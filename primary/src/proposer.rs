use crate::batch_maker::Transaction;
use crate::messages::{Certificate, Header, Timeout, TimeoutCert};
use crate::primary::Round;
use config::Committee;
use crypto::{PublicKey, SignatureService};
use log::debug;
#[cfg(feature = "benchmark")]
use log::info;
use std::cmp::Ordering;
use std::convert::TryInto;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

// #[cfg(test)]
// #[path = "tests/proposer_tests.rs"]
// pub mod proposer_tests;

/// The proposer creates new headers and send them to the core for broadcasting and further processing.
pub struct Proposer {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The size of the headers' payload.
    header_size: usize,
    tx_size: usize,
    /// The maximum delay to wait for batches' digests.
    max_header_delay: u64,
    consensus_only: bool,

    /// Receives the parent certificate to include in the next header.
    rx_core: Receiver<Certificate>,
    /// Receives the batch digest from our workers.
    rx_workers: Receiver<Vec<Transaction>>,
    /// Sends newly created headers to the `Core`.
    tx_core: Sender<Header>,
    /// Sends newly created timeouts to the `Core`.
    tx_core_timeout: Sender<Timeout>,
    /// Receives timeout certs from the `Core`.
    rx_timeout_cert: Receiver<(TimeoutCert, Round)>,
    /// The current round of the dag.
    round: Round,
    /// Holds the certificates' ids waiting to be included in the next header.
    last_parent: Vec<Certificate>,
    /// Holds the txns waiting to be included in the next header.
    txns: Vec<Transaction>,
    /// Keeps track of the size (in bytes) of batches' digests that we received so far.
    payload_size: usize,
    /// Holds the Timeout certificate for the latest round.
    last_timeout_cert: TimeoutCert,
}

impl Proposer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        _signature_service: SignatureService,
        header_size: usize,
        tx_size: usize,
        max_header_delay: u64,
        consensus_only: bool,
        rx_core: Receiver<Certificate>,
        rx_workers: Receiver<Vec<Transaction>>,
        tx_core: Sender<Header>,
        tx_core_timeout: Sender<Timeout>,
        rx_timeout_cert: Receiver<(TimeoutCert, Round)>,
    ) {
        let genesis = Certificate::genesis(&committee);
        tokio::spawn(async move {
            Self {
                name,
                committee,
                header_size,
                tx_size,
                max_header_delay,
                consensus_only,
                rx_core,
                rx_workers,
                tx_core,
                tx_core_timeout,
                rx_timeout_cert,
                round: 0,
                last_parent: genesis,
                txns: Vec::new(),
                payload_size: 0,
                last_timeout_cert: TimeoutCert::new(0),
            }
            .run()
            .await;
        });
    }

    async fn make_header(&mut self) {
        // Make a new header.
        let limit = if self.txns.len() * self.tx_size <= self.header_size {
            self.txns.len()
        } else {
            self.header_size / self.tx_size
        };

        let payload = if self.consensus_only {
            vec![vec![0u8; self.tx_size]; self.header_size / self.tx_size]
        } else {
            self.txns.drain(..limit).collect()
        };

        let parent = self.last_parent.pop().expect("no parent available");

        let header = Header::new(self.name, self.round, payload, parent.header_id).await;

        #[cfg(feature = "benchmark")]
        {
            info!("Created {:?}", header.id);
            info!(
                "Header {:?} contains {} B",
                header.id,
                header.payload.len() * self.tx_size
            );
            if !self.consensus_only {
                let tx_ids: Vec<[u8; 8]> = header
                    .payload
                    .iter()
                    .filter(|tx| tx.len() > 8 && tx[0] == 0u8)
                    .filter_map(|tx| tx[1..9].try_into().ok())
                    .collect();
                for id in tx_ids {
                    info!(
                        "Header {:?} contains sample tx {}",
                        header.id,
                        u64::from_be_bytes(id)
                    );
                }
            }
            // NOTE: This log entry is used to compute performance.
        }
        // Send the new header to the `Core` that will broadcast and process it.
        self.tx_core
            .send(header)
            .await
            .expect("Failed to send header");
    }

    async fn make_timeout_msg(&mut self) {
        let timeout = Timeout::new(self.round, self.name);
        debug!("Created {:?}", timeout);
        self.tx_core_timeout
            .send(timeout)
            .await
            .expect("Failed to send timeout");
    }

    /// Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        debug!("Protocol starting at round {}", self.round);
        let mut advance = true;
        let timer = sleep(Duration::from_millis(self.max_header_delay));
        let mut timeout_sent = false;
        tokio::pin!(timer);

        loop {
            let timer_expired = timer.is_elapsed();
            if timer_expired && !timeout_sent {
                self.make_timeout_msg().await;
                timeout_sent = true;
            }

            // Check if we can propose a new header. We now only set `advance` when
            // Core delivers a certificate, so proposals are certificate-triggered.
            let enough_parents = !self.last_parent.is_empty();
            let is_next_leader = self.committee.leader((self.round + 1) as usize) == self.name;
            let enough_digests = self.payload_size >= self.header_size;
            if ((enough_digests || self.consensus_only) && advance) && enough_parents {
                // Advance to the next round.
                self.round += 1;
                debug!("Protocol moved to round {}", self.round);

                // Make a new header.
                if is_next_leader {
                    self.make_header().await;
                    self.payload_size = 0;
                }
                // Require a fresh certificate before advancing again.
                advance = false;
                let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                timer.as_mut().reset(deadline);
                timeout_sent = false;
            }

            tokio::select! {
                Some(certificate) = self.rx_core.recv() => {
                    debug!("Received certificate {:?} for round {}", certificate.round(), self.round);
                    // Compare the certificate's round number with our current round.
                    match certificate.round().cmp(&self.round) {
                        Ordering::Greater => {
                            // We accept round bigger than our current round to jump ahead in case we were
                            // late (or just joined the network).
                            self.round = certificate.round();
                            self.last_parent = vec![certificate];
                            advance = true;
                        },
                        Ordering::Less => {
                            // Ignore certificates from older rounds.
                        },
                        Ordering::Equal => {
                            self.last_parent = vec![certificate];
                            advance = true;
                        }
                    }
                }
                Some(txns) = self.rx_workers.recv() => {
                    self.payload_size += txns.iter().map(|txn| txn.len()).sum::<usize>();
                    self.txns.extend(txns);
                }
                Some((timeout_cert, round)) = self.rx_timeout_cert.recv() => {
                    timeout_cert.verify(&self.committee).expect("Invalid timeout certificate");
                    match round.cmp(&self.last_timeout_cert.round) {
                        Ordering::Greater => {
                            self.last_timeout_cert = timeout_cert;
                            if round >= self.round {
                                self.round = round;
                                advance = true;
                            }
                        },
                        Ordering::Less => {
                            // Ignore timeout certificates from older rounds.
                        },
                        Ordering::Equal => {
                            self.last_timeout_cert = timeout_cert;
                            if round >= self.round {
                                self.round = round;
                                advance = true;
                            }
                        }
                    }
                }
                () = &mut timer, if !timeout_sent => {
                    self.make_timeout_msg().await;
                    timeout_sent = true;
                }
            }
        }
    }
}
