use crate::batch_maker::Transaction;
use crate::messages::{
    Header, HeaderWithCertificate, ProposerParent, Timeout, TimeoutCert,
};
use crate::primary::Round;
use config::Committee;
use crypto::{PublicKey, SignatureService};
#[cfg(feature = "benchmark")]
use log::info;
use log::{debug, warn};
use std::cmp::Ordering;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};
use std::convert::TryInto;

// #[cfg(test)]
// #[path = "tests/proposer_tests.rs"]
// pub mod proposer_tests;

/// The proposer creates new headers and send them to the core for broadcasting and further processing.
pub struct Proposer {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// The size of the headers' payload.
    header_size: usize,
    tx_size: usize,
    /// The maximum delay to wait for batches' digests.
    max_header_delay: u64,
    consensus_only: bool,

    /// Receives the parents to include in the next header (along with their round number).
    rx_core: Receiver<ProposerParent>,
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
    last_parent: Vec<ProposerParent>,
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
        signature_service: SignatureService,
        header_size: usize,
        tx_size: usize,
        max_header_delay: u64,
        consensus_only: bool,
        rx_core: Receiver<ProposerParent>,
        rx_workers: Receiver<Vec<Transaction>>,
        tx_core: Sender<Header>,
        tx_core_timeout: Sender<Timeout>,
        rx_timeout_cert: Receiver<(TimeoutCert, Round)>,
    ) {
        let genesis = ProposerParent::genesis(&committee);
        tokio::spawn(async move {
            Self {
                name,
                committee,
                signature_service,
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

    async fn make_timeout_msg(&mut self) {
        let timeout_cert_msg =
            Timeout::new(self.round, self.name, &mut self.signature_service).await;

        debug!("Created {:?}", timeout_cert_msg);

        // Send the new timeout to the `Core` that will broadcast and process it.
        self.tx_core_timeout
            .send(timeout_cert_msg)
            .await
            .expect("Failed to send timeout");
    }

    async fn make_header(&mut self) {
        // Make a new header.
        // let timeout_cert = if self.last_timeout_cert.round == self.round - 1 {
        //     self.last_timeout_cert.clone()
        // } else {
        //     TimeoutCert::new(0) // Assuming TimeoutCert::new creates an empty certificate
        // };

        let limit = if self.txns.len() * self.tx_size <= self.header_size {
            self.txns.len()
        } else {
            self.header_size / self.tx_size
        };

        let mut payload;
        if self.consensus_only {
            payload = vec![vec![0u8; self.tx_size]; self.header_size / self.tx_size];
        } else {
            payload = self.txns.drain(..limit).collect();
        }

        let parent = self.last_parent.pop().expect("no parent available");

        let header = Header::new(
            self.name,
            self.round,
            payload,
            parent.header_id,
        )
        .await;

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
        // let header_with_parents = HeaderWithCertificate { header, parents };

        // Send the new header to the `Core` that will broadcast and process it.
        self.tx_core
            .send(header)
            .await
            .expect("Failed to send header");
    }

    /// Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        debug!("Protocol starting at round {}", self.round);
        let mut advance = true;

        let timer = sleep(Duration::from_millis(self.max_header_delay));
        let mut timeout_sent = false;
        tokio::pin!(timer);

        loop {
            // Check if we can propose a new header. We propose a new header when we have a quorum of parents
            // and one of the following conditions is met:
            // (i) the timer expired (we timed out on the leader or gave up gather votes for the leader),
            // (ii) we have enough digests (minimum header size) and we are on the happy path (we can vote for
            // the leader or the leader has enough votes to enable a commit).
            let enough_parents = !self.last_parent.is_empty();
            let timeout_cert_gathered = self.last_timeout_cert.round == self.round;
            let is_next_leader = self.committee.leader((self.round + 1) as usize) == self.name;
            let enough_digests = self.payload_size >= self.header_size;
            let timer_expired = timer.is_elapsed();
            // TODO: This has to be fixed by sending timeout only once.
            if timer_expired && !timeout_sent {
                warn!("Timer expired for round {}", self.round);
                self.make_timeout_msg().await;
                timeout_sent = true;
            }
            if (((enough_digests || self.consensus_only) && advance))
                && enough_parents
            {
                // Advance to the next round.
                self.round += 1;
                debug!("Protocol moved to round {}", self.round);

                // Make a new header.
                if is_next_leader {
                    self.make_header().await;
                    self.payload_size = 0;
                }
                // Require a fresh parent notification before advancing again.
                advance = false;
                // Reschedule the timer.
                let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                timer.as_mut().reset(deadline);
                timeout_sent = false;
            }

            tokio::select! {
                Some(parent) = self.rx_core.recv() => {
                    debug!("Received parent {:?} for round {}", parent.round(), self.round);
                    // Compare the parents' round number with our current round.
                    match parent.round().cmp(&self.round) {
                        Ordering::Greater => {
                            // We accept round bigger than our current round to jump ahead in case we were
                            // late (or just joined the network).
                            self.round = parent.round();
                            self.last_parent = vec![parent];
                            advance = true;
                        },
                        Ordering::Less => {
                            // Ignore parents from older rounds.
                        },
                        Ordering::Equal => {
                            self.last_parent = vec![parent];
                            advance = true;
                        }
                    }
                }
                Some(txns) = self.rx_workers.recv() => {
                    self.payload_size += txns.iter().map(|txn| txn.len()).sum::<usize>();
                    self.txns.extend(txns);
                }
                Some((timeout_cert, round)) = self.rx_timeout_cert.recv() => {
                    match round.cmp(&self.last_timeout_cert.round) {
                        Ordering::Greater => {
                            // We accept round bigger than our current round to jump ahead in case we were
                            // late (or just joined the network).
                            self.last_timeout_cert = timeout_cert.clone();

                            // TODO: How do we react?
                        },
                        Ordering::Less => {
                            // Ignore parents from older rounds.
                        },
                        Ordering::Equal => {
                            // TODO: Here we have to create header and include the timeout certificate in the header?
                            self.last_timeout_cert = timeout_cert.clone();
                        }
                    }
                }
            }
        }
    }
}
