use crate::batch_maker::Transaction;
use crate::messages::{Certificate, Header, ProposerParent, Timeout, TimeoutCert};
use crate::primary::Round;
use config::Committee;
use crypto::Digest;
use crypto::{PublicKey, SignatureService};
use log::debug;
#[cfg(feature = "benchmark")]
use log::info;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::process;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

// #[cfg(test)]
// #[path = "tests/proposer_tests.rs"]
// pub mod proposer_tests;

#[derive(Clone, Copy, Debug)]
enum AdvanceReason {
    Certificate(Round),
    Timeout(Round),
}

pub enum ProposerCommand {
    NormalCertificate(Certificate),
    SpeculativeParent(ProposerParent),
}

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
    crash_author: Option<PublicKey>,
    crash_on_proposal: u64,
    crash_duration: u64,

    /// Receives normal and speculative parent signals from the `Core`.
    rx_core: Receiver<ProposerCommand>,
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
    /// Holds speculative parent hints waiting for enough payload.
    pending_speculative_parents: HashMap<Round, ProposerParent>,
    /// Rounds for which this proposer already emitted a header.
    proposed_rounds: HashSet<Round>,
    /// Holds the txns waiting to be included in the next header.
    txns: Vec<Transaction>,
    /// Keeps track of the size (in bytes) of batches' digests that we received so far.
    payload_size: usize,
    /// Holds the Timeout certificate for the latest round.
    last_timeout_cert: TimeoutCert,
    proposal_count: u64,
    crash_triggered: bool,
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
        crash_author: Option<PublicKey>,
        crash_on_proposal: u64,
        crash_duration: u64,
        rx_core: Receiver<ProposerCommand>,
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
                crash_author,
                crash_on_proposal,
                crash_duration,
                rx_core,
                rx_workers,
                tx_core,
                tx_core_timeout,
                rx_timeout_cert,
                round: 0,
                last_parent: genesis,
                pending_speculative_parents: HashMap::new(),
                proposed_rounds: HashSet::new(),
                txns: Vec::new(),
                payload_size: 0,
                last_timeout_cert: TimeoutCert::new(0),
                proposal_count: 0,
                crash_triggered: false,
            }
            .run()
            .await;
        });
    }

    fn parent_round(&self) -> Option<Round> {
        self.last_parent.last().map(Certificate::round)
    }

    fn can_advance(&self, advance: Option<AdvanceReason>) -> bool {
        match advance {
            Some(AdvanceReason::Certificate(round)) => self.parent_round() == Some(round),
            Some(AdvanceReason::Timeout(round)) => {
                round > 0 && self.parent_round() == Some(round - 1)
            }
            None => false,
        }
    }

    fn arm_pending_timeout(
        &mut self,
        pending_timeout_cert: &mut Option<TimeoutCert>,
        advance: &mut Option<AdvanceReason>,
    ) {
        let Some(timeout_cert) = pending_timeout_cert.take() else {
            return;
        };

        let timeout_round = timeout_cert.round;
        let parent_round = self.parent_round();
        if timeout_round <= self.last_timeout_cert.round
            || timeout_round < self.round
            || matches!(parent_round, Some(round) if round >= timeout_round)
        {
            return;
        }

        if timeout_round > 0 && parent_round == Some(timeout_round - 1) {
            self.last_timeout_cert = timeout_cert;
            self.round = timeout_round;
            *advance = Some(AdvanceReason::Timeout(timeout_round));
        } else {
            *pending_timeout_cert = Some(timeout_cert);
        }
    }

    fn has_payload(&self) -> bool {
        self.consensus_only || self.payload_size >= self.header_size
    }

    fn take_payload(&mut self) -> Vec<Transaction> {
        let limit = if self.txns.len() * self.tx_size <= self.header_size {
            self.txns.len()
        } else {
            self.header_size / self.tx_size
        };

        if self.consensus_only {
            vec![vec![0u8; self.tx_size]; self.header_size / self.tx_size]
        } else {
            self.txns.drain(..limit).collect()
        }
    }

    async fn make_header(&mut self) {
        let parent = self.last_parent.pop().expect("no parent available");
        self.make_header_for_round(self.round, parent.header_id, "normal")
            .await;
    }

    async fn make_header_for_round(&mut self, round: Round, parent: Digest, source: &'static str) {
        self.maybe_permanent_crash(round, source);
        let payload = self.take_payload();
        let header = Header::new(self.name, round, payload, parent).await;

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
            info!(
                "BENCH event=proposal_sent source={} round={} parent={:?} node={:?}",
                source, header.round, header.parent, header.author
            );
        }
        // Send the new header to the `Core` that will broadcast and process it.
        self.tx_core
            .send(header)
            .await
            .expect("Failed to send header");
    }

    fn maybe_permanent_crash(&mut self, round: Round, source: &'static str) {
        self.proposal_count += 1;
        if self.crash_triggered
            || self.crash_on_proposal == 0
            || self.crash_author != Some(self.name)
            || self.proposal_count != self.crash_on_proposal
        {
            return;
        }

        self.crash_triggered = true;
        #[cfg(feature = "benchmark")]
        info!(
            "BENCH event=crash_start node={:?} round={} proposal_index={} duration_ms={} source={} permanent=true",
            self.name, round, self.proposal_count, self.crash_duration, source
        );
        log::logger().flush();
        process::exit(0);
    }

    async fn try_speculative_propose(&mut self, parent: ProposerParent) {
        let propose_round = parent.round + 1;
        if self.committee.leader(propose_round as usize) != self.name {
            return;
        }
        if propose_round < self.round || self.proposed_rounds.contains(&propose_round) {
            return;
        }
        if !self.has_payload() {
            self.pending_speculative_parents
                .entry(propose_round)
                .or_insert(parent);
            return;
        }

        self.make_header_for_round(propose_round, parent.header_id, "speculative")
            .await;
        self.proposed_rounds.insert(propose_round);
        self.payload_size = 0;
    }

    async fn try_pending_speculative_propose(&mut self) {
        if !self.has_payload() {
            return;
        }

        let Some(round) = self
            .pending_speculative_parents
            .keys()
            .filter(|&&round| round >= self.round && !self.proposed_rounds.contains(&round))
            .min()
            .cloned()
        else {
            return;
        };

        if let Some(parent) = self.pending_speculative_parents.remove(&round) {
            self.make_header_for_round(round, parent.header_id, "speculative")
                .await;
            self.proposed_rounds.insert(round);
            self.payload_size = 0;
        }
    }

    async fn make_timeout_msg(&mut self) {
        let timeout = Timeout::new(self.round, self.name);
        debug!("Created {:?}", timeout);
        #[cfg(feature = "benchmark")]
        info!(
            "BENCH event=timeout_sent round={} node={:?}",
            timeout.round, timeout.author
        );
        self.tx_core_timeout
            .send(timeout)
            .await
            .expect("Failed to send timeout");
    }

    /// Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        debug!("Protocol starting at round {}", self.round);
        let mut advance = Some(AdvanceReason::Certificate(0));
        let mut pending_timeout_cert: Option<TimeoutCert> = None;
        let timer = sleep(Duration::from_millis(self.max_header_delay));
        let mut timeout_sent = false;
        tokio::pin!(timer);

        loop {
            let failure_fallback_enabled = self.crash_on_proposal > 0;
            let timer_expired = timer.is_elapsed();
            if failure_fallback_enabled && timer_expired && !timeout_sent {
                self.make_timeout_msg().await;
                timeout_sent = true;
            }
            self.try_pending_speculative_propose().await;

            // Check if we can propose a new header. A timeout certificate for round r
            // is only actionable after we have the parent certificate from round r - 1.
            let can_advance = self.can_advance(advance);
            let is_next_leader = self.committee.leader((self.round + 1) as usize) == self.name;
            if self.has_payload() && can_advance {
                // Advance to the next round.
                self.round += 1;
                debug!("Protocol moved to round {}", self.round);
                #[cfg(feature = "benchmark")]
                info!(
                    "BENCH event=round_start round={} leader={:?} node={:?}",
                    self.round,
                    self.committee.leader(self.round as usize),
                    self.name
                );

                // Make a new header.
                if is_next_leader && self.proposed_rounds.insert(self.round) {
                    self.make_header().await;
                    self.payload_size = 0;
                }
                // Require a fresh certificate before advancing again.
                advance = None;
                let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                timer.as_mut().reset(deadline);
                timeout_sent = false;
            }

            tokio::select! {
                Some(command) = self.rx_core.recv() => {
                    match command {
                        ProposerCommand::NormalCertificate(certificate) => {
                            if self.crash_on_proposal == 0 {
                                debug!(
                                    "Ignoring normal certificate for round {} because failure fallback is disabled",
                                    certificate.round()
                                );
                                continue;
                            }
                            let certificate_round = certificate.round();
                            debug!(
                                "Received certificate {:?} for round {}",
                                certificate_round, self.round
                            );
                            // Compare the certificate round with our current round.
                            match certificate_round.cmp(&self.round) {
                                Ordering::Greater => {
                                    // Accept a higher-round certificate to jump ahead if we were late.
                                    self.round = certificate_round;
                                    self.last_parent = vec![certificate];
                                    advance = Some(AdvanceReason::Certificate(certificate_round));
                                },
                                Ordering::Less => {
                                    // Ignore certificates from older rounds.
                                },
                                Ordering::Equal => {
                                    self.last_parent = vec![certificate];
                                    advance = Some(AdvanceReason::Certificate(certificate_round));
                                }
                            }
                            self.arm_pending_timeout(&mut pending_timeout_cert, &mut advance);
                        }
                        ProposerCommand::SpeculativeParent(parent) => {
                            let propose_round = parent.round() + 1;
                            debug!(
                                "Received speculative parent for round {} while at round {}",
                                parent.round(),
                                self.round
                            );
                            self.try_speculative_propose(parent).await;
                            if propose_round > self.round {
                                self.round = propose_round;
                            }
                            let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                            timer.as_mut().reset(deadline);
                            timeout_sent = false;
                        }
                    }
                }
                Some(txns) = self.rx_workers.recv() => {
                    self.payload_size += txns.iter().map(|txn| txn.len()).sum::<usize>();
                    self.txns.extend(txns);
                }
                Some((timeout_cert, round)) = self.rx_timeout_cert.recv() => {
                    if !failure_fallback_enabled {
                        debug!(
                            "Ignoring timeout certificate for round {} because failure fallback is disabled",
                            timeout_cert.round
                        );
                        continue;
                    }
                    timeout_cert.verify(&self.committee).expect("Invalid timeout certificate");
                    let timeout_round = timeout_cert.round;
                    if timeout_round != round {
                        debug!(
                            "Ignoring timeout certificate with mismatched rounds: cert {}, message {}",
                            timeout_round, round
                        );
                    } else {
                        match timeout_round.cmp(&self.last_timeout_cert.round) {
                            Ordering::Greater => {
                                let parent_round = self.parent_round();
                                let should_replace_pending = pending_timeout_cert.as_ref().map_or(true, |pending| {
                                    timeout_round < pending.round
                                        || (timeout_round > 0
                                            && parent_round == Some(timeout_round - 1))
                                });

                                if should_replace_pending {
                                    if timeout_round > 0 && parent_round == Some(timeout_round - 1) {
                                        debug!(
                                            "Received actionable timeout certificate for round {}",
                                            timeout_round
                                        );
                                    } else {
                                        debug!(
                                            "Deferring timeout certificate for round {} until parent round {} is available",
                                            timeout_round,
                                            timeout_round.saturating_sub(1)
                                        );
                                    }
                                    pending_timeout_cert = Some(timeout_cert);
                                }
                                self.arm_pending_timeout(&mut pending_timeout_cert, &mut advance);
                            },
                            Ordering::Less => {
                                // Ignore timeout certificates from older rounds.
                            },
                            Ordering::Equal => {
                                // Duplicate of the latest armed timeout certificate.
                            }
                        }
                    }
                }
                () = &mut timer, if failure_fallback_enabled && !timeout_sent => {
                    self.make_timeout_msg().await;
                    timeout_sent = true;
                }
            }
        }
    }
}
