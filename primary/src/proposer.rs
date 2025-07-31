use crate::batch_maker::Transaction;
use crate::messages::{
    Certificate, Header, HeaderWithCertificate, Timeout, TimeoutCert, Support,
};
use crate::primary::Round;
use config::Committee;
use crypto::{PublicKey, SignatureService};
#[cfg(feature = "benchmark")]
use log::info;
use log::{debug, warn};
use core::time;
use std::cmp::Ordering;
use std::sync::atomic::Ordering as AtomicOrdering;
use std::sync::atomic::AtomicU64;
use std::convert::TryInto;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};
use std::collections::HashMap;
use std::sync::Arc;

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
    rx_core: Receiver<(Vec<Certificate>, Round)>,
    /// Receives the leader's certificate from the `Core`.
    rx_core_leader: Receiver<Certificate>,
    /// Receives the batch digest from our workers.
    rx_workers: Receiver<Vec<Transaction>>,
    /// Sends newly created headers to the `Core`.
    tx_core: Sender<HeaderWithCertificate>,
    /// Sends newly created timeouts to the `Core`.
    tx_core_timeout: Sender<Timeout>,
    /// Receives timeout certs from the `Core`.
    rx_timeout_cert: Receiver<(TimeoutCert, Round)>,
    /// Sends support messages to the `Core`.
    tx_core_support: Sender<Support>,

    /// The current round of the dag.
    round: Round,
    /// Holds the certificates' ids waiting to be included in the next header.
    last_parents: Vec<Certificate>,
    /// Holds the certificate of the last leader (if any).
    last_leader: Option<Certificate>,
    /// Holds the txns waiting to be included in the next header.
    txns: Vec<Transaction>,
    /// Keeps track of the size (in bytes) of batches' digests that we received so far.
    payload_size: usize,
    /// Holds the Timeout certificate for the latest round.
    last_timeout_cert: TimeoutCert,
    /// Holds the timeout certificates.
    timeout_certs: HashMap<Round, Vec<TimeoutCert>>,
    // Rate of proposing a header
    propose_rate: f64, 
    /// Whether the proposer should propose in the this round.
    propose_this_round: bool,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,
    /// The last garbage collected round.
    gc_round: Round,
    /// The last received leader's public key.
    last_received_leader: Option<Certificate>,
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
        rx_core: Receiver<(Vec<Certificate>, Round)>,
        rx_core_leader: Receiver<Certificate>,
        rx_workers: Receiver<Vec<Transaction>>,
        tx_core: Sender<HeaderWithCertificate>,
        tx_core_timeout: Sender<Timeout>,
        rx_timeout_cert: Receiver<(TimeoutCert, Round)>,
        propose_rate: f64,
        tx_core_support: Sender<Support>,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
    ) {
        let genesis = Certificate::genesis(&committee);
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
                rx_core_leader,
                rx_workers,
                tx_core,
                tx_core_timeout,
                rx_timeout_cert,
                tx_core_support,
                round: 0,
                last_parents: genesis,
                last_leader: None,
                txns: Vec::new(),
                payload_size: 0,
                last_timeout_cert: TimeoutCert::new(0),
                timeout_certs: HashMap::new(),
                propose_rate,
                propose_this_round: true,
                consensus_round,
                gc_depth,
                gc_round: 0,
                last_received_leader: None,
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

    async fn make_support_msg(
        &mut self,
        vote: bool,
        propose_next_round: bool, 
    ) {
        self.last_parents.clear();
        let support = Support::new(
            self.name,
            self.round,
            &mut self.signature_service,
            vote,
            propose_next_round,
        )
        .await;

        debug!("Created support {:?}", support);

        // Send the new support to the `Core` that will broadcast and process it.
        self.tx_core_support
            .send(support)
            .await
            .expect("Failed to send support message");
    }

    async fn make_header(&mut self, propose_next_round: bool) {
        // Make a new header.
        // Prepare the timeout certificates
        let timeout_cert = if self.last_timeout_cert.round == self.round - 1 {
            self.last_timeout_cert.clone()
        } else {
            TimeoutCert::new(0) // Assuming TimeoutCert::new creates an empty certificate
        };

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

        let parents: Vec<Certificate> = self.last_parents.drain(..).collect();
        let previous_leader = if self.committee.leader(self.round as usize) == self.name {
            self.last_received_leader
                .as_ref()
                .map(|leader| leader.header_id.clone())
        } else {
            None
        };

        let header = Header::new(
            self.name,
            self.round,
            payload,
            parents.iter().map(|x| x.header_id).collect(),
            timeout_cert,
            &mut self.signature_service,
            propose_next_round,
            previous_leader,
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
                let tx_ids: Vec<_> = header
                    .payload
                    .clone()
                    .iter()
                    .filter(|tx| tx[0] == 0u8 && tx.len() > 8)
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
        let header_with_parents = HeaderWithCertificate { header, parents };

        // Send the new header to the `Core` that will broadcast and process it.
        self.tx_core
            .send(header_with_parents)
            .await
            .expect("Failed to send header");
    }

    /// Update the last leader.
    fn update_leader(&mut self) -> bool {
        let leader_name = self.committee.leader(self.round as usize);
        self.last_leader = self
            .last_parents
            .iter()
            .find(|x| x.origin() == leader_name)
            .cloned();

        if let Some(leader) = self.last_leader.as_ref() {
            debug!("Got leader {} for round {}", leader.origin(), self.round);
        }

        self.last_leader.is_some()
    }

    /// Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        debug!("Dag starting at round {}", self.round);
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
            let enough_parents = !self.last_parents.is_empty();
            let timeout_cert_gathered = self.last_timeout_cert.round == self.round;
            let is_next_leader = self.committee.leader((self.round + 1) as usize) == self.name;
            let enough_digests = self.payload_size >= self.header_size;
            let timer_expired = timer.is_elapsed();

            if timer_expired && !timeout_sent {
                warn!("Timer expired for round {}", self.round);
                self.make_timeout_msg().await;
                timeout_sent = true;
            }
            
            if ((timer_expired
                && timeout_cert_gathered
                && (!is_next_leader
                    || (self.last_received_leader.is_some() && self.last_received_leader.as_ref().unwrap().round + 1 == self.last_timeout_cert.round)))
                || ((enough_digests || self.consensus_only) && advance))
                && enough_parents
            {   
                if ((enough_digests || self.consensus_only) && advance) {
                    debug!("enter round by leader")
                }
                // Advance to the next round.
                self.round += 1;
                info!("Dag moved to round {}", self.round);

                let header_proposers = self.committee.header_proposers((self.round) as usize, self.propose_rate);
                let propose_next_round = header_proposers.contains(&self.name);
                // If propose this round or is the leader of the next round, make a new header; otherwise, send a support message.
                if self.propose_this_round || is_next_leader {
                    self.make_header(propose_next_round).await;
                } else {
                    let vote = self.last_leader.is_some();
                    self.make_support_msg(vote, propose_next_round).await;
                }
                self.propose_this_round = propose_next_round;
                self.payload_size = 0;

                // Reschedule the timer.
                let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                timer.as_mut().reset(deadline);
                timeout_sent = false;
            }

            tokio::select! {
                Some((parents, round)) = self.rx_core.recv() => {
                    // Compare the parents' round number with our current round.
                    match round.cmp(&self.round) {
                        Ordering::Greater => {
                            // We accept round bigger than our current round to jump ahead in case we were
                            // late (or just joined the network).
                            self.round = round;
                            self.last_parents = parents;
                        },
                        Ordering::Less => {
                            // Ignore parents from older rounds.
                        },
                        Ordering::Equal => {
                            // The core gives us the parents the first time they are enough to form a quorum.
                            // Then it keeps giving us all the extra parents.
                            self.last_parents.extend(parents)
                        }
                    }

                    // Check whether we can advance to the next round. Note that if we timeout,
                    // we ignore this check and advance anyway.
                    // TODO: (1) Implement the wait for NVC if leader logic here
                    // (2) Also implement the wait for leader idea what is was there before
                    advance = self.update_leader();
                }
                Some(leader) = self.rx_core_leader.recv() => {
                    match self.last_received_leader.as_ref() {
                        Some(last) if leader.round > last.round => {
                            self.last_received_leader = Some(leader);
                        }
                        None => {
                            self.last_received_leader = Some(leader);
                        }
                        _ => {} 
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

                () = &mut timer => {
                    // Nothing to do.
                }
            }

            let round = self.consensus_round.load(AtomicOrdering::Relaxed);
            if round > self.gc_depth {
                let gc_round = round - self.gc_depth;
                self.timeout_certs.retain(|k, _| k >= &gc_round);
            }
        }
    }
}
