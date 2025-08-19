// Copyright(C) Facebook, Inc. and its affiliates.
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use log::{debug, info, warn, log_enabled};
use primary::{Certificate, ConsensusMessage, Round, HeaderInfo, Support};
use std::cmp::max;
use std::collections::{HashMap, HashSet};
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
    rx_primary_header_msg: Receiver<ConsensusMessage>,
    /// Outputs the sequence of ordered certificates to the primary (for cleanup and feedback).
    tx_primary: Sender<Certificate>,
    /// Outputs the sequence of ordered certificates to the application layer.
    tx_output: Sender<Certificate>,

    /// The genesis certificates.
    genesis: Vec<Certificate>,
    /// The stake vote received by the leader of a round.
    stake_vote: HashMap<Round, u32>,
    /// The stake vote received by the sub leaders of a round.
    sub_leaders_stake_vote: HashMap<Round, HashMap<PublicKey, u32>>,
    ///The total numbers of leaders in each round
    leaders_per_round: usize,
}

impl Consensus {
    pub fn spawn(
        committee: Committee,
        gc_depth: Round,
        rx_primary: Receiver<Certificate>,
        rx_primary_header_msg: Receiver<ConsensusMessage>,
        tx_primary: Sender<Certificate>,
        tx_output: Sender<Certificate>,
        leaders_per_round: usize,
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
                sub_leaders_stake_vote: HashMap::with_capacity(2 * gc_depth as usize),
                leaders_per_round
            }
            .run()
            .await;
        });
    }

    fn update_sub_leaders(&mut self, dag: &Dag, round: Round, header_info: &HeaderInfo) -> Vec<Certificate> {
        // Number of leaders might be dynamic, consider parameterizing it if necessary
        // TODO: Change this to input
        let num_leaders = self.leaders_per_round;
        let current_leaders = self.committee.sub_leaders(round as usize, num_leaders);
        let mut commitable_leaders = Vec::new();
        let mut push_to_leaders = true;
    
        // Safely access the DAG and update stakes based on valid leader digests in header parents.
        if let Some(round_entries) = dag.get(&round) {
            for leader in current_leaders {
                if let Some((leader_digest, _cert)) = round_entries.get(&leader) {
                    if header_info.parents.contains(leader_digest) {
                        let stake = self.committee.stake(&header_info.author);
                        let stake_entry = self.sub_leaders_stake_vote.entry(round).or_default().entry(leader).or_insert(0);
                        *stake_entry += stake;

                        // Check if the updated stake meets the quorum threshold
                        if *stake_entry >= self.committee.quorum_threshold() && push_to_leaders {
                            commitable_leaders.push(_cert.clone());
                        } else {
                            push_to_leaders = false;
                        }
                    }
                }
            }
        }
        commitable_leaders
    }

    fn update_sub_leaders_support(&mut self, dag: &Dag, round: Round, support: &Support) -> Vec<Certificate> {
        // Number of leaders might be dynamic, consider parameterizing it if necessary
        // TODO: Change this to input
        let num_leaders = self.leaders_per_round;
        let current_leaders = self.committee.sub_leaders(round as usize, num_leaders);
        let mut commitable_leaders = Vec::new();
        let mut push_to_leaders = true;
    
        // Safely access the DAG and update stakes based on valid leader digests in header parents.
        if let Some(round_entries) = dag.get(&round) {
            for leader in current_leaders {
                if let Some((leader_digest, _cert)) = round_entries.get(&leader) {
                    if support.parents.contains(leader_digest) {
                        let stake = self.committee.stake(&support.author);
                        let stake_entry = self.sub_leaders_stake_vote.entry(round).or_default().entry(leader).or_insert(0);
                        *stake_entry += stake;

                        // Check if the updated stake meets the quorum threshold
                        if *stake_entry >= self.committee.quorum_threshold() && push_to_leaders {
                            commitable_leaders.push(_cert.clone());
                        } else {
                            push_to_leaders = false;
                        }
                    }
                }
            }
        }
        commitable_leaders
    }

    fn update_sub_leaders_post_commit(&mut self, dag: &Dag, round: Round, header_info: &HeaderInfo) -> Vec<Certificate> {
        // Number of leaders might be dynamic, consider parameterizing it if necessary
        // TODO: Change this to input
        let num_leaders = self.leaders_per_round;
        let current_leaders = self.committee.sub_leaders(round as usize, num_leaders);
        let mut commitable_leaders = Vec::new();
        let mut push_to_leaders = true;
    
        // Safely access the DAG and update stakes based on valid leader digests in header parents.
        if let Some(round_entries) = dag.get(&round) {
            for leader in current_leaders {
                if let Some((leader_digest, _cert)) = round_entries.get(&leader) {
                    let stake_entry = self.sub_leaders_stake_vote.entry(round).or_default().entry(leader).or_insert(0);

                    if header_info.parents.contains(leader_digest) && *stake_entry < self.committee.quorum_threshold() {
                        let stake = self.committee.stake(&header_info.author);
                        *stake_entry += stake;

                        // Check if the updated stake meets the quorum threshold
                        if *stake_entry >= self.committee.quorum_threshold() && push_to_leaders {
                            commitable_leaders.push(_cert.clone());
                        } else {
                            push_to_leaders = false;
                        }
                    }
                }
            }
        }
        commitable_leaders
    }

    fn update_sub_leaders_post_commit_support(&mut self, dag: &Dag, round: Round, support: &Support) -> Vec<Certificate> {
        // Number of leaders might be dynamic, consider parameterizing it if necessary
        // TODO: Change this to input
        let num_leaders = self.leaders_per_round;
        let current_leaders = self.committee.sub_leaders(round as usize, num_leaders);
        let mut commitable_leaders = Vec::new();
        let mut push_to_leaders = true;
    
        // Safely access the DAG and update stakes based on valid leader digests in header parents.
        if let Some(round_entries) = dag.get(&round) {
            for leader in current_leaders {
                if let Some((leader_digest, _cert)) = round_entries.get(&leader) {
                    let stake_entry = self.sub_leaders_stake_vote.entry(round).or_default().entry(leader).or_insert(0);

                    if support.parents.contains(leader_digest) && *stake_entry < self.committee.quorum_threshold() {
                        let stake = self.committee.stake(&support.author);
                        *stake_entry += stake;

                        // Check if the updated stake meets the quorum threshold
                        if *stake_entry >= self.committee.quorum_threshold() && push_to_leaders {
                            commitable_leaders.push(_cert.clone());
                        } else {
                            push_to_leaders = false;
                        }
                    }
                }
            }
        }
        commitable_leaders
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
                            let round = certificate.round();
                            state
                                .dag
                                .entry(round)
                                .or_insert_with(HashMap::new)
                                .insert(certificate.origin(), (certificate.header_id.clone(), certificate.clone()));
                            continue;
                        }
                        
                        ConsensusMessage::Support(support) => {
                            let r = support.round - 1;
                            let leader_round = r;
                            if leader_round <= state.last_committed_round || leader_round == 0 {
                                continue;
                            }
                            
                            if leader_round == state.last_committed_round {
                                let commitable_leaders = self.update_sub_leaders_post_commit_support(&state.dag, leader_round, &support);

                                let mut sequence = Vec::new();

                                for leader in commitable_leaders {
                                    // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                                    for x in self.order_dag(&leader, &state).await {
                                        // Update and clean up internal state.
                                        state.update(&x, self.gc_depth);
                    
                                        // Add the certificate to the sequence.
                                        sequence.push(x);
                                    }
                                }

                                // Output the sequence in the right order.
                                for certificate in sequence {
                                    #[cfg(not(feature = "benchmark"))]
                                    info!("Committed {} with header", certificate.header_id);
                    
                                    #[cfg(feature = "benchmark")]
                                    // NOTE: This log entry is used to compute performance.
                                    info!("Committed {:?} Leader", certificate.header_id);
                
                                    self.tx_primary
                                        .send(certificate.clone())
                                        .await
                                        .expect("Failed to send certificate to primary with header");
                    
                                    if let Err(e) = self.tx_output.send(certificate).await {
                                        warn!("Failed to output certificate: {} with header", e);
                                    }
                                }

                                continue;
                            }

                            let (leader_digest, leader) = match self.leader(leader_round, &state.dag) {
                                Some(x) => x,
                                None => continue,
                            };

                            if support.vote {
                                *self.stake_vote.entry(support.round).or_insert(0) += self.committee.stake(&support.author);
                            }

                            let commitable_leaders = self.update_sub_leaders_support(&state.dag, leader_round, &support);

                            let current_stake = self.stake_vote.get(&support.round);
                            let current_stake_value = *current_stake.unwrap_or(&0);
                            
                            // Commit if we have QT
                            if current_stake_value >= self.committee.quorum_threshold() {
                                // Get an ordered list of past leaders that are linked to the current leader.
                                debug!("Leader {:?} has enough support with header at round {}", leader, leader_round);
                                let mut sequence = Vec::new();
                                for leader in self.order_leaders(leader, &state).await.iter().rev() {
                                    // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                                    for x in self.order_dag(leader, &state).await {
                                        // Update and clean up internal state.
                                        state.update(&x, self.gc_depth);

                                        // Add the certificate to the sequence.
                                        sequence.push(x);
                                    }
                                }

                                for leader in commitable_leaders {
                                    // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                                    for x in self.order_dag(&leader, &state).await {
                                        // Update and clean up internal state.
                                        state.update(&x, self.gc_depth);
                    
                                        // Add the certificate to the sequence.
                                        sequence.push(x);
                                    }
                                }
                                
                                // Output the sequence in the right order.
                                for certificate in sequence {
                                    #[cfg(not(feature = "benchmark"))]
                                    info!("Committed {} with header", certificate.header_id);
                                    
                                    if certificate.round == leader_round {
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
                            
                            if leader_round == state.last_committed_round {
                                let commitable_leaders = self.update_sub_leaders_post_commit(&state.dag, leader_round, &header_info);

                                let mut sequence = Vec::new();

                                for leader in commitable_leaders {
                                    // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                                    for x in self.order_dag(&leader, &state).await {
                                        // Update and clean up internal state.
                                        state.update(&x, self.gc_depth);
                    
                                        // Add the certificate to the sequence.
                                        sequence.push(x);
                                    }
                                }

                                // Output the sequence in the right order.
                                for certificate in sequence {
                                    #[cfg(not(feature = "benchmark"))]
                                    info!("Committed {} with header", certificate.header_id);
                    
                                    #[cfg(feature = "benchmark")]
                                    // NOTE: This log entry is used to compute performance.
                                    info!("Committed {:?} Leader", certificate.header_id);
                
                                    self.tx_primary
                                        .send(certificate.clone())
                                        .await
                                        .expect("Failed to send certificate to primary with header");
                    
                                    if let Err(e) = self.tx_output.send(certificate).await {
                                        warn!("Failed to output certificate: {} with header", e);
                                    }
                                }

                                continue;
                            }

                            let (leader_digest, leader) = match self.leader(leader_round, &state.dag) {
                                Some(x) => x,
                                None => continue,
                            };

                            if header_info.parents.contains(leader_digest) {
                                *self.stake_vote.entry(header_info.round).or_insert(0) += self.committee.stake(&header_info.author);
                            }

                            let commitable_leaders = self.update_sub_leaders(&state.dag, leader_round, &header_info);

                            let current_stake = self.stake_vote.get(&header_info.round);
                            let current_stake_value = *current_stake.unwrap_or(&0);

                            // Commit if we have QT
                            if current_stake_value >= self.committee.quorum_threshold() {
                                // Get an ordered list of past leaders that are linked to the current leader.
                                debug!("Leader {:?} has enough support with header at round {}", leader, leader_round);
                                let mut sequence = Vec::new();
                                for leader in self.order_leaders(leader, &state).await.iter().rev() {
                                    // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                                    for x in self.order_dag(leader, &state).await {
                                        // Update and clean up internal state.
                                        state.update(&x, self.gc_depth);

                                        // Add the certificate to the sequence.
                                        sequence.push(x);
                                    }
                                }
                                
                                for leader in commitable_leaders {
                                    // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                                    for x in self.order_dag(&leader, &state).await {
                                        // Update and clean up internal state.
                                        state.update(&x, self.gc_depth);
                    
                                        // Add the certificate to the sequence.
                                        sequence.push(x);
                                    }
                                }
                    
                                // Log the latest committed round of every authority (for debug).
                                if log_enabled!(log::Level::Debug) {
                                    for (name, round) in &state.last_committed {
                                        debug!("Latest commit of {}: Round {} with header", name, round);
                                    }
                                }

                                // Output the sequence in the right order.
                                for certificate in sequence {
                                    #[cfg(not(feature = "benchmark"))]
                                    info!("Committed {} with header", certificate.header_id);

                                    if certificate.round == leader_round {
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
                    let round = certificate.round();

                    // Add the new certificate to the local storage.
                    state
                        .dag
                        .entry(round)
                        .or_insert_with(HashMap::new)
                        .insert(certificate.origin(), (certificate.header_id.clone(), certificate.clone()));
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
    async fn linked(
        &self,
        leader: &Certificate,
        prev_leader: &Certificate,
        state: &State,
    ) -> bool {
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
