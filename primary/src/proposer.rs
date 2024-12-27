// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::{Certificate, Header, NoVoteCert, NoVoteMsg, Timeout, TimeoutCert};
use crate::primary::Round;
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
// #[cfg(feature = "benchmark")]
use log::info;
use log::{debug, warn};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::convert::TryInto;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};
pub type Transaction = Vec<u8>;

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
    batch_size: usize,
    tx_size: usize,
    /// The maximum delay to wait for batches' digests.
    max_header_delay: u64,

    /// Receives the parents to include in the next header (along with their round number).
    rx_core: Receiver<(Vec<Header>, Round)>,
    /// Receives the batch digest from our workers.
    rx_workers: Receiver<Vec<Transaction>>,
    /// Sends newly created headers to the `Core`.
    tx_core: Sender<Header>,
    /// Sends newly created timeouts to the `Core`.
    tx_core_timeout: Sender<Timeout>,
    /// Receives timeout certs from the `Core`.
    rx_timeout_cert: Receiver<(TimeoutCert, Round)>,
    /// Sends newly created no vote message to the `Core`.
    tx_core_no_vote_msg: Sender<NoVoteMsg>,
    /// Receives no vote certs from the `Core`.
    rx_no_vote_cert: Receiver<(NoVoteCert, Round)>,

    /// The current round of the dag.
    round: Round,
    /// Holds the certificates' ids waiting to be included in the next header.
    last_parents: Vec<Header>,
    /// Holds the certificate of the last leader (if any).
    last_leader: Option<Header>,
    /// Holds the txns waiting to be included in the next header.
    txns: Vec<Transaction>,
    /// Keeps track of the size (in bytes) of batches' digests that we received so far.
    payload_size: usize,
    /// Holds the Timeout certificate for the latest round.
    last_timeout_cert: TimeoutCert,
    /// Holds the latest No Vote Certificate received.
    last_no_vote_cert: NoVoteCert,
}

impl Proposer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        header_size: usize,
        batch_size: usize,
        tx_size: usize,
        max_header_delay: u64,
        rx_core: Receiver<(Vec<Header>, Round)>,
        rx_workers: Receiver<Vec<Transaction>>,
        tx_core: Sender<Header>,
        tx_core_timeout: Sender<Timeout>,
        rx_timeout_cert: Receiver<(TimeoutCert, Round)>,
        tx_core_no_vote_msg: Sender<NoVoteMsg>,
        rx_no_vote_cert: Receiver<(NoVoteCert, Round)>,
    ) {
        let genesis = Header::genesis(&committee);
        tokio::spawn(async move {
            Self {
                name,
                committee,
                header_size,
                batch_size,
                tx_size,
                max_header_delay,
                rx_core,
                rx_workers,
                tx_core,
                tx_core_timeout,
                rx_timeout_cert,
                tx_core_no_vote_msg,
                rx_no_vote_cert,
                round: 0,
                last_parents: genesis,
                last_leader: None,
                txns: Vec::new(),
                payload_size: 0,
                last_timeout_cert: TimeoutCert::new(0),
                last_no_vote_cert: NoVoteCert::new(0),
            }
            .run()
            .await;
        });
    }

    async fn make_timeout_msg(&mut self) {
        let timeout_cert_msg =
            Timeout::new(self.round, self.name).await;

        debug!("Created {:?}", timeout_cert_msg);

        // Send the new timeout to the `Core` that will broadcast and process it.
        self.tx_core_timeout
            .send(timeout_cert_msg)
            .await
            .expect("Failed to send timeout");
    }

    async fn make_no_vote_msg(&mut self) {
        let no_vote_msg = NoVoteMsg::new(self.round, self.name).await;

        debug!("Created {:?}", no_vote_msg);

        // Send the new timeout to the `Core` that will broadcast and process it.
        self.tx_core_no_vote_msg
            .send(no_vote_msg)
            .await
            .expect("Failed to send no vote message");
    }

    async fn make_header(&mut self) {
        // Make a new header.
        // Prepare the timeout and no vote certificates
        // let timeout_cert = if self.last_timeout_cert.round == self.round - 1 {
        //     self.last_timeout_cert.clone()
        // } else {
        //     TimeoutCert::new(0) // Assuming TimeoutCert::new creates an empty certificate
        // };

        // let no_vote_cert = if self.committee.leader((self.round) as usize) == self.name
        //     && self.last_no_vote_cert.round == self.round - 1
        // {
        //     self.last_no_vote_cert.clone()
        // } else {
        //     NoVoteCert::new(0) // Assuming NoVoteCert::new creates an empty certificate
        // };

        let limit = if self.txns.len() * self.tx_size <= self.header_size {
            self.txns.len()
        } else {
            self.header_size / self.tx_size
        };

        let header = Header::new(
            self.name,
            self.round,
            self.txns.drain(..limit).collect(),
            self.last_parents.drain(..).map(|x| x.id.clone()).collect(),
        )
        .await;

        debug!("Created {:?}", header.id);

        #[cfg(feature = "benchmark")]
        {
            info!("Created {:?}", header.id);
            info!(
                "Header {:?} contains {} B",
                header.id,
                header.payload.len() * self.tx_size
            );
            // info!("self.txns.len(): {:?}", self.txns.len());
            // info!("self.header_size: {:?}", self.header_size);
            // info!("payload_len: {:?}", header.payload.len());
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
            // NOTE: This log entry is used to compute performance.
        }

        // Send the new header to the `Core` that will broadcast and process it.
        self.tx_core
            .send(header)
            .await
            .expect("Failed to send header");
    }

    /// Update the last leader.
    fn update_leader(&mut self) -> bool {
        let leader_name = self.committee.leader(self.round as usize);
        self.last_leader = self
            .last_parents
            .iter()
            .find(|x| x.author == leader_name)
            .cloned();

        if let Some(leader) = self.last_leader.as_ref() {
            debug!("Got leader {} for round {}", leader.author, self.round);
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
            // let enough_parents = !self.last_parents.is_empty();
            let enough_parents = self.last_parents.len() as u32 >= self.committee.quorum_threshold();
            let timeout_cert_gathered = self.last_timeout_cert.round == self.round;
            let is_next_leader = self.committee.leader((self.round + 1) as usize) == self.name;
            let no_vote_cert_gathered = self.last_no_vote_cert.round == self.round;
            let enough_digests = self.payload_size >= self.header_size;
            let timer_expired = timer.is_elapsed();

            // TODO: This has to be fixed by sending timeout only once.
            if timer_expired && !timeout_sent {
                warn!("Timer expired for round {}", self.round);
                self.make_timeout_msg().await;
                timeout_sent = true;
            }
            // QY: happy case
            // if ((timer_expired
            //     && timeout_cert_gathered
            //     && (!is_next_leader || no_vote_cert_gathered))
            //     || (enough_digests && advance))
            //     && enough_parents
            if enough_digests && advance && enough_parents
            {
                if timer_expired && self.last_leader.is_none() && !is_next_leader {
                    self.make_no_vote_msg().await;
                }
                // info!("enough_parents: {:?}", self.last_parents.len());
                // Advance to the next round.
                self.round += 1;
                debug!("Dag moved to round {}", self.round);
                // Make a new header.
                self.make_header().await;
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
                Some((no_vote_cert, round)) = self.rx_no_vote_cert.recv() => {
                    match round.cmp(&self.last_no_vote_cert.round) {
                        Ordering::Greater => {
                            // We accept round bigger than our current round to jump ahead in case we were
                            // late (or just joined the network).
                            self.last_no_vote_cert = no_vote_cert;

                            // TODO: How do we react?
                        },
                        Ordering::Less => {
                            // Ignore parents from older rounds.
                        },
                        Ordering::Equal => {
                            // TODO: Here we have to create header and include the timeout certificate in the header?
                            self.last_no_vote_cert = no_vote_cert;
                        }
                    }
                }
                () = &mut timer => {
                    // Nothing to do.
                }
            }
        }
    }
}