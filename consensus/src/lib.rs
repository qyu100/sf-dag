// Copyright(C) Facebook, Inc. and its affiliates.
use config::{Committee, Stake};
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use log::{debug, info, log_enabled, warn};
use primary::{Certificate, Header, Round};
use std::cmp::max;
use std::collections::{BTreeSet, HashMap, HashSet};
use tokio::sync::mpsc::{Receiver, Sender};

// #[cfg(test)]
// #[path = "tests/consensus_tests.rs"]
// pub mod consensus_tests;

/// The representation of the DAG in memory.
type Dag = HashMap<Round, HashMap<PublicKey, (Digest, Header)>>;
type ParentInfo = HashMap<Digest, BTreeSet<Digest>>;

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
}

impl State {
    fn new(genesis: Vec<Header>) -> Self {
        let genesis = genesis
            .into_iter()
            .map(|x| (x.author, (x.id.clone(), x)))
            .collect::<HashMap<_, _>>();

        Self {
            last_committed_round: 0,
            last_committed: genesis.iter().map(|(x, (_, y))| (*x, y.round)).collect(),
            dag: [(0, genesis)].iter().cloned().collect(),
        }
    }

    /// Update and clean up internal state base on committed certificates.
    fn update(&mut self, header: &Header, gc_depth: Round) {
        self.last_committed
            .entry(header.author)
            .and_modify(|r| *r = max(*r, header.round))
            .or_insert_with(|| header.round);

        let last_committed_round = *self.last_committed.values().max().unwrap();
        self.last_committed_round = last_committed_round;

        // TODO: This cleanup is dangerous: we need to ensure consensus can receive idempotent replies
        // from the primary. Here we risk cleaning up a certificate and receiving it again later.
        for (name, round) in &self.last_committed {
            self.dag.retain(|r, authorities| {
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
    rx_primary_header: Receiver<Header>,
    /// Outputs the sequence of ordered certificates to the primary (for cleanup and feedback).
    tx_primary: Sender<Header>,
    /// Outputs the sequence of ordered certificates to the application layer.
    tx_output: Sender<Header>,

    /// The genesis headers.
    genesis: Vec<Header>,
    /// The stake vote received by the leader of a round.
    stake_vote: HashMap<Round, u32>,
}

impl Consensus {
    pub fn spawn(
        committee: Committee,
        gc_depth: Round,
        rx_primary: Receiver<Certificate>,
        rx_primary_header: Receiver<Header>,
        tx_primary: Sender<Header>,
        tx_output: Sender<Header>,
    ) {
        tokio::spawn(async move {
            Self {
                committee: committee.clone(),
                gc_depth,
                rx_primary,
                rx_primary_header,
                tx_primary,
                tx_output,
                genesis: Header::genesis(&committee),
                stake_vote: HashMap::with_capacity(2 * gc_depth as usize),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        // The consensus state (everything else is immutable).
        let mut state = State::new(self.genesis.clone());
        // Listen to incoming header quorums.
        loop {
            tokio::select! {
                // Listen to incoming headers.
                Some(header) = self.rx_primary_header.recv() => {
                    debug!("Processing {:?}", header);

                    // Try to order the dag to commit. Start from the previous round.
                    let r = header.round - 1;
                    state
                        .dag
                        .entry(header.round)
                        .or_insert_with(HashMap::new)
                        .insert(header.author, (header.id.clone(), header.clone()));

                    let leader_round = r;

                    info!("Leader round: {}", leader_round);
                    info!("Last committed round: {}", state.last_committed_round);
                    if leader_round <= state.last_committed_round {
                        continue;
                    }

                    let (leader_digest, leader) = match self.leader(leader_round, &state.dag) {
                        Some(x) => x,
                        None => continue,
                    };
                    info!("parents: {:?} at round {:?}", header.parents, header.round);
                    info!("leader_digest: {:?}", leader_digest);
                    if header.parents.contains(leader_digest) {
                        *self.stake_vote.entry(header.round.clone()).or_insert(0) += self.committee.stake(&header.author);
                    }
                    info!("stake_vote: {:?}", self.stake_vote);
                    let current_stake = self.stake_vote.get(&header.round);
                    let current_stake_value = *current_stake.unwrap_or(&0);
                    info!("Current stake value: {}", current_stake_value);
                    // Commit if we have QT
                    if current_stake_value >= self.committee.quorum_threshold() {
                        // Get an ordered list of past leaders that are linked to the current leader.
                        debug!("Leader {:?} has enough support with header", leader);
                        let mut sequence = Vec::new();
                        for leader in self.order_leaders(leader, &state).iter().rev() {
                            // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                            for x in self.order_dag(leader, &state) {
                                // Update and clean up internal state.
                                state.update(&x, self.gc_depth);

                                // Add the certificate to the sequence.
                                sequence.push(x);
                                info!("sequence: {:?}", sequence);
                            }
                        }

                        // Output the sequence in the right order.
                        for header in sequence {
                            // #[cfg(not(feature = "benchmark"))]
                            // info!("Committed {} with header", certificate.header);

                            if header.round == leader_round {
                                info!("Committed {:?} Leader", header.id);
                            }else if header.round == leader_round-1 {
                                info!("Committed {:?} NonLeader", header.id);
                            } else{
                                info!("Committed {:?} ", header.id);
                            }
                            // Garbage Collection.
                            self.tx_primary
                                .send(header.clone())
                                .await
                                .expect("Failed to send header to primary for gc");

                            if let Err(e) = self.tx_output.send(header).await {
                                warn!("Failed to output header: {} with header", e);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Returns the certificate (and the certificate's digest) originated by the leader of the
    /// specified round (if any).
    fn leader<'a>(&self, round: Round, dag: &'a Dag) -> Option<&'a (Digest, Header)> {
        // TODO: We should elect the leader of round r-2 using the common coin revealed at round r.
        // At this stage, we are guaranteed to have 2f+1 certificates from round r (which is enough to
        // compute the coin). We currently just use round-robin.
        #[cfg(test)]
        let seed = 0;
        #[cfg(not(test))]
        let seed = round;

        // Elect the leader.
        let leader = self.committee.leader(seed as usize);
        info!("dag {:?}", dag);
        // Return its certificate and the certificate's digest.
        dag.get(&round).map(|x| x.get(&leader)).flatten()
    }

    /// Order the past leaders that we didn't already commit.
    fn order_leaders(&self, leader: &Header, state: &State) -> Vec<Header> {
        let mut to_commit = vec![leader.clone()];
        let mut leader = leader;
        for r in (state.last_committed_round + 1..=leader.round - 1).rev() {
            // Get the certificate proposed by the previous leader.
            let (_, prev_leader) = match self.leader(r, &state.dag) {
                Some(x) => x,
                None => continue,
            };

            // Check whether there is a path between the last two leaders.
            if self.linked(leader, prev_leader, &state.dag) {
                to_commit.push(prev_leader.clone());
                leader = prev_leader;
            }
        }
        to_commit
    }

    /// Checks if there is a path between two leaders.
    fn linked(&self, leader: &Header, prev_leader: &Header, dag: &Dag) -> bool {
        let mut parents = vec![leader];
        for r in (prev_leader.round..leader.round).rev() {
            parents = dag
                .get(&(r))
                .expect("We should have the whole history by now")
                .values()
                .filter(|(digest, _)| parents.iter().any(|x| x.parents.contains(digest)))
                .map(|(_, header)| header)
                .collect();
        }
        parents.contains(&prev_leader)
    }

    /// Flatten the dag referenced by the input certificate. This is a classic depth-first search (pre-order):
    /// https://en.wikipedia.org/wiki/Tree_traversal#Pre-order
    fn order_dag(&self, leader: &Header, state: &State) -> Vec<Header> {
        debug!("Processing sub-dag of {:?}", leader);
        let mut ordered = Vec::new();
        let mut already_ordered = HashSet::new();

        let mut buffer = vec![leader];
        while let Some(x) = buffer.pop() {
            debug!("Sequencing {:?}", x);
            ordered.push(x.clone());

            for parent in &x.parents {
                let (digest, header) = match state
                    .dag
                    .get(&(x.round - 1))
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
                    .get(&header.author)
                    .map_or_else(|| false, |r| r == &header.round);
                if !skip {
                    buffer.push(header);
                    already_ordered.insert(digest);
                }
            }
        }

        // Ensure we do not commit garbage collected certificates.
        ordered.retain(|x| x.round + self.gc_depth >= state.last_committed_round);

        // Ordering the output by round is not really necessary but it makes the commit sequence prettier.
        ordered.sort_by_key(|x| x.round);
        ordered
    }
}