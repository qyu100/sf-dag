// Copyright(C) Facebook, Inc. and its affiliates.
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use log::{debug, info, warn};
use primary::{Certificate, ConsensusMessage, Round};
use std::cmp::max;
use std::collections::{BTreeMap, HashMap, HashSet};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration};

// #[cfg(test)]
// #[path = "tests/consensus_tests.rs"]
// pub mod consensus_tests;

/// The representation of the DAG in memory.
type Dag = HashMap<Round, HashMap<PublicKey, (Digest, Certificate)>>;
type ParentInfo = HashMap<Digest, Vec<Digest>>;
/// The state that needs to be persisted for crash-recovery.
struct State {
    /// The last committed round.
    last_committed_round: Round,
    // Keeps the last committed round for each authority. This map is used to clean up the dag and
    // ensure we don't commit twice the same certificate.
    last_committed: HashMap<PublicKey, Round>,
    /// Keeps the latest committed certificate (and its parents) for every authority. Anything older
    /// must be regularly cleaned up through the function `update`.
    dag: Dag,
    parent_info: ParentInfo,
    /// Keeps certificates that have been delivered but not yet committed, indexed by round.
    pending: BTreeMap<Round, HashMap<PublicKey, Certificate>>,
}

impl State {
    fn new(genesis: Vec<Certificate>) -> Self {
        let genesis = genesis
            .into_iter()
            .map(|x| (x.origin(), (x.digest(), x)))
            .collect::<HashMap<_, _>>();

        Self {
            last_committed_round: 0,
            last_committed: genesis.iter().map(|(x, (_, y))| (*x, y.round())).collect(),
            dag: [(0, genesis)].iter().cloned().collect(),
            parent_info: HashMap::new(),
            pending: BTreeMap::new(),
        }
    }

    fn insert_certificate(&mut self, certificate: Certificate) {
        let round = certificate.round();
        let origin = certificate.origin();
        self.dag
            .entry(round)
            .or_insert_with(HashMap::new)
            .insert(origin, (certificate.header_id, certificate.clone()));

        let already_committed = self
            .last_committed
            .get(&origin)
            .map_or(false, |committed_round| committed_round >= &round);
        if !already_committed {
            self.pending
                .entry(round)
                .or_insert_with(HashMap::new)
                .insert(origin, certificate);
        }
    }

    /// Update and clean up internal state base on committed certificates.
    fn update(&mut self, certificate: &Certificate, gc_depth: Round) {
        self.last_committed
            .entry(certificate.origin())
            .and_modify(|r| *r = max(*r, certificate.round()))
            .or_insert_with(|| certificate.round());

        let last_committed_round = *self.last_committed.values().max().unwrap();
        self.last_committed_round = last_committed_round;
        if let Some(round_pending) = self.pending.get_mut(&certificate.round()) {
            round_pending.remove(&certificate.origin());
            if round_pending.is_empty() {
                self.pending.remove(&certificate.round());
            }
        }

        // TODO: This cleanup is dangerous: we need to ensure consensus can receive idempotent replies
        // from the primary. Here we risk cleaning up a certificate and receiving it again later.
        for (name, round) in &self.last_committed {
            self.dag.retain(|r, authorities| {
                authorities.retain(|n, _| n != name || r >= round);
                !authorities.is_empty() && r + gc_depth >= last_committed_round
            });
            self.pending.retain(|r, authorities| {
                authorities.retain(|n, _| n != name || r >= round);
                !authorities.is_empty() && r + gc_depth >= last_committed_round
            });
        }
    }
}

pub struct Consensus {
    /// The committee information.
    committee: Committee,
    /// The depth of the garbage collector.
    gc_depth: Round,

    /// Receives new certificates from the primary. The primary should send us new certificates only
    /// if it already sent us its whole history.
    rx_primary: Receiver<Certificate>,
    /// Receives new headers from the primary.
    rx_primary_header_msg: Receiver<ConsensusMessage>,
    /// Outputs the sequence of ordered certificates to the primary (for cleanup and feedback).
    tx_primary: Sender<Certificate>,
    /// Outputs the sequence of ordered certificates to the application layer.
    tx_output: Sender<Certificate>,

    /// The genesis certificates.
    genesis: Vec<Certificate>,
    /// The stake vote received by the leader of a round.
    stake_vote: HashMap<Round, u32>,
}

impl Consensus {
    pub fn spawn(
        committee: Committee,
        gc_depth: Round,
        rx_primary: Receiver<Certificate>,
        rx_primary_header_msg: Receiver<ConsensusMessage>,
        tx_primary: Sender<Certificate>,
        tx_output: Sender<Certificate>,
    ) {
        tokio::spawn(async move {
            Self {
                committee: committee.clone(),
                gc_depth,
                rx_primary,
                rx_primary_header_msg,
                tx_primary,
                tx_output,
                genesis: Certificate::genesis(&committee),
                stake_vote: HashMap::with_capacity(2 * gc_depth as usize),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        // The consensus state (everything else is immutable).
        let mut state = State::new(self.genesis.clone());

        // Listen to incoming certificates and header quorums.
        loop {
            tokio::select! {
                // Listen to incoming headers.
                Some(header_msg) = self.rx_primary_header_msg.recv() => {

                    match header_msg {
                        ConsensusMessage::Certificate(certificate) => {
                            state.insert_certificate(certificate);
                            continue;
                        }

                        ConsensusMessage::HeaderInfo(header_info) => {
                            debug!("Processing header info {:?} at round {}", header_info.id, header_info.round);

                            state.parent_info.insert(header_info.id, header_info.parents.clone());
                            // Try to order the dag to commit. Start from the previous round.
                            let r = header_info.round - 1;

                            // Get the certificate's digest of the leader. If we already ordered this leader, there is nothing to do.
                            let leader_round = r;
                            if leader_round <= state.last_committed_round || leader_round == 0 {
                                continue;
                            }

                            let (leader_digest, leader) = match self.leader(leader_round, &state.dag) {
                                Some(x) => x,
                                None => continue,
                            };

                            if header_info.parents.contains(leader_digest) {
                                *self.stake_vote.entry(header_info.round).or_insert(0) += self.committee.stake(&header_info.author);
                            }

                            let current_stake = self.stake_vote.get(&header_info.round);
                            let current_stake_value = *current_stake.unwrap_or(&0);

                            // Commit if we have QT
                            if current_stake_value >= self.committee.quorum_threshold() {
                                debug!("Leader {:?} has enough support with header at round {}", leader, leader_round);
                                let sequence =
                                    self.collect_commit_sequence(leader, &state).await;

                                // Output the sequence in the right order.
                                for (certificate, orphan) in sequence {
                                    state.update(&certificate, self.gc_depth);
                                    #[cfg(not(feature = "benchmark"))]
                                    info!("Committed {} with header", certificate.header_id);

                                    if orphan {
                                        info!(
                                            "Committed {:?} Orphan age {}",
                                            certificate.header_id,
                                            leader_round.saturating_sub(certificate.round())
                                        );
                                    } else if certificate.round == leader_round {
                                        info!("Committed {:?} Leader", certificate.header_id);
                                    }else if certificate.round == leader_round-1 {
                                        info!("Committed {:?} NonLeader", certificate.header_id);
                                    }else{
                                        info!("Committed {:?} ", certificate.header_id);
                                    }

                                    self.tx_primary
                                        .send(certificate.clone())
                                        .await
                                        .expect("Failed to send certificate to primary with header");

                                    if let Err(e) = self.tx_output.send(certificate).await {
                                        warn!("Failed to output certificate: {} with header", e);
                                    }
                                }
                            }
                        }
                    }
                }

                // Listen to incoming certificates.
                Some(certificate) = self.rx_primary.recv() => {
                    debug!("Processing {:?}", certificate);
                    state.insert_certificate(certificate);
                }
            }
        }
    }

    /// Returns the certificate (and the certificate's digest) originated by the leader of the
    /// specified round (if any).
    fn leader<'a>(&self, round: Round, dag: &'a Dag) -> Option<&'a (Digest, Certificate)> {
        // TODO: We should elect the leader of round r-2 using the common coin revealed at round r.
        // At this stage, we are guaranteed to have 2f+1 certificates from round r (which is enough to
        // compute the coin). We currently just use round-robin.
        #[cfg(test)]
        let seed = 0;
        #[cfg(not(test))]
        let seed = round;

        // Elect the leader.
        let leader = self.committee.leader(seed as usize);

        // Return its certificate and the certificate's digest.
        dag.get(&round).map(|x| x.get(&leader)).flatten()
    }

    async fn collect_commit_sequence(
        &self,
        leader: &Certificate,
        state: &State,
    ) -> Vec<(Certificate, bool)> {
        let mut sequence = Vec::new();
        let mut already_ordered = HashSet::new();

        for linked_leader in self.order_leaders(leader, state).await.iter().rev() {
            for certificate in self.order_dag(linked_leader, state).await {
                let digest = certificate.digest();
                if already_ordered.insert(digest) {
                    sequence.push((certificate, false));
                }
            }
        }

        let commit_horizon = leader.round().saturating_sub(2);
        let pending_candidates = state
            .pending
            .range(..=commit_horizon)
            .flat_map(|(_, certificates)| certificates.values().cloned())
            .collect::<Vec<_>>();
        for certificate in pending_candidates {
            let digest = certificate.digest();
            if already_ordered.contains(&digest) {
                continue;
            }
            if self.referenced_by_next_round(&certificate, state).await {
                continue;
            }

            for candidate in self.order_dag(&certificate, state).await {
                let candidate_digest = candidate.digest();
                if already_ordered.insert(candidate_digest) {
                    let candidate_is_orphan = candidate.header_id == certificate.header_id;
                    sequence.push((candidate, candidate_is_orphan));
                }
            }
        }

        sequence.sort_by_key(|(certificate, _)| certificate.round());
        sequence
    }

    async fn referenced_by_next_round(&self, certificate: &Certificate, state: &State) -> bool {
        let next_round = certificate.round().saturating_add(1);
        let next_round_certificates = match state.dag.get(&next_round) {
            Some(certificates) => certificates,
            None => return false,
        };

        for (_, next_round_certificate) in next_round_certificates.values() {
            let parents = loop {
                if let Some(parents) = state.parent_info.get(&next_round_certificate.header_id) {
                    break parents;
                }

                sleep(Duration::from_millis(1)).await;
            };

            if parents.contains(&certificate.header_id) {
                return true;
            }
        }

        false
    }

    /// Order the past leaders that we didn't already commit.
    async fn order_leaders(&self, leader: &Certificate, state: &State) -> Vec<Certificate> {
        let mut to_commit = vec![leader.clone()];
        let mut leader = leader;
        for r in (state.last_committed_round + 1..=leader.round() - 1).rev() {
            // Get the certificate proposed by the previous leader.
            let (_, prev_leader) = match self.leader(r, &state.dag) {
                Some(x) => x,
                None => continue,
            };

            // Check whether there is a path between the last two leaders.
            if self.linked(leader, prev_leader, &state).await {
                to_commit.push(prev_leader.clone());
                leader = prev_leader;
            }
        }
        to_commit
    }

    /// Checks if there is a path between two leaders.
    async fn linked(&self, leader: &Certificate, prev_leader: &Certificate, state: &State) -> bool {
        let mut parents = vec![leader];
        for r in (prev_leader.round()..leader.round()).rev() {
            let round_certificates = state
                .dag
                .get(&(r))
                .expect("We should have the whole history by now");

            let mut new_parents = Vec::new();

            for (digest, certificate) in round_certificates.values() {
                for parent_cert in &parents {
                    loop {
                        if let Some(parents_set) = state.parent_info.get(&parent_cert.header_id) {
                            if parents_set.contains(digest) {
                                new_parents.push(certificate);
                                break;
                            } else {
                                break;
                            }
                        } else {
                            sleep(Duration::from_millis(1)).await;
                        }
                    }
                }
            }

            parents = new_parents;
        }
        parents.contains(&prev_leader)
    }

    /// Flatten the dag referenced by the input certificate. This is a classic depth-first search (pre-order):
    /// https://en.wikipedia.org/wiki/Tree_traversal#Pre-order
    async fn order_dag(&self, leader: &Certificate, state: &State) -> Vec<Certificate> {
        debug!("Processing sub-dag of {:?}", leader);
        let mut ordered = Vec::new();
        let mut already_ordered = HashSet::new();

        let mut buffer = vec![leader];

        while let Some(x) = buffer.pop() {
            debug!("Sequencing {:?}", x);
            ordered.push(x.clone());

            let parents = loop {
                if let Some(parents) = state.parent_info.get(&x.header_id) {
                    break parents;
                }

                sleep(Duration::from_millis(1)).await;
            };

            for parent in parents {
                let (digest, certificate) = match state
                    .dag
                    .get(&(x.round() - 1))
                    .map(|x| x.values().find(|(x, _)| x == parent))
                    .flatten()
                {
                    Some(x) => x,
                    None => continue, // We already ordered or GC up to here.
                };

                // We skip the certificate if we (1) already processed it or (2) we reached a round that we already
                // committed for this authority.
                let mut skip = already_ordered.contains(&digest);
                skip |= state
                    .last_committed
                    .get(&certificate.origin())
                    .map_or_else(|| false, |r| r == &certificate.round());
                if !skip {
                    buffer.push(certificate);
                    already_ordered.insert(digest);
                }
            }
        }

        // Ensure we do not commit garbage collected certificates.
        ordered.retain(|x| x.round() + self.gc_depth >= state.last_committed_round);

        // Ordering the output by round is not really necessary but it makes the commit sequence prettier.
        ordered.sort_by_key(|x| x.round());
        ordered
    }
}
