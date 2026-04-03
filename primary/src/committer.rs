#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
use crate::messages::ConsensusMessage;
use crate::primary::{Slot, CHANNEL_CAPACITY};
use crate::synchronizer::Synchronizer;
use crate::DagError;
use crate::{Certificate, Header, Height};
//use crate::error::{ConsensusError, ConsensusResult};
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use log::{debug, info, warn};
use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

/// The representation of the DAG in memory.
type Dag = HashMap<Height, HashMap<PublicKey, (Digest, Certificate)>>;

/// The state that needs to be persisted for crash-recovery.
struct State {
    // Keeps the last committed height for each authority. This map is used to clean up the dag and
    // ensure we don't commit twice the same certificate.
    last_executed_heights: HashMap<PublicKey, Height>,
    // Certificates observed by the committer, indexed by height and author.
    dag: Dag,
    // Log containing slots and committed certificates
    log: HashMap<Slot, ConsensusMessage>,
    // Commits deferred until the referenced certificates arrive.
    pending_commits: HashMap<Slot, ConsensusMessage>,
}

impl State {
    fn new(genesis: Vec<Certificate>) -> Self {
        let genesis = genesis
            .into_iter()
            .map(|x| (x.origin(), (x.digest(), x)))
            .collect::<HashMap<_, _>>();

        Self {
            last_executed_heights: genesis.iter().map(|(x, (_, _))| (*x, 0)).collect(),
            dag: [(0, genesis)].iter().cloned().collect(),
            log: HashMap::new(),
            pending_commits: HashMap::new(),
        }
    }
}

pub struct Committer {
    gc_depth: Height,
    rx_mempool: Receiver<Certificate>,
    rx_deliver: Receiver<Certificate>,
    rx_commit_message: Receiver<ConsensusMessage>,
    tx_output: Sender<Header>,
    synchronizer: Synchronizer,
    genesis: Vec<Certificate>,
}

impl Committer {
    pub fn spawn(
        committee: Committee,
        store: Store,
        gc_depth: Height,
        rx_mempool: Receiver<Certificate>,
        rx_commit: Receiver<Certificate>,
        rx_commit_message: Receiver<ConsensusMessage>,
        tx_output: Sender<Header>,
        synchronizer: Synchronizer,
    ) {
        let genesis = Certificate::genesis(&committee);

        //special blocks from round >1 can also have genesis as parent!!! ==> Solution: Write genesis to store
        //Alternatively, just store genesis digests and compare against
        //let genesis_digests = genesis.clone().iter().map(|x| x.digest()).collect();

        tokio::spawn(async move {
            Self {
                gc_depth,
                rx_mempool,
                rx_deliver: rx_commit,
                rx_commit_message,
                tx_output,
                synchronizer,
                genesis,
            }
            .run()
            .await;
        });
    }

    async fn execute_commit_proposals(
        &mut self,
        state: &mut State,
        proposals: &HashMap<PublicKey, crate::messages::Proposal>,
    ) -> crate::error::DagResult<()> {
        for (pk, proposal) in proposals {
            let has_matching_certificate = state
                .dag
                .get(&proposal.height)
                .and_then(|per_authority| per_authority.get(pk))
                .map(|(_, certificate)| certificate.header_id == proposal.header_digest)
                .unwrap_or(false);

            if !has_matching_certificate {
                warn!(
                    "Commit blocked: missing/mismatched certificate for author {} at height {}",
                    pk,
                    proposal.height
                );
                return Err(DagError::MalformedHeader(proposal.header_digest.clone()));
            }

            let stop_height = *state.last_executed_heights.get(pk).unwrap_or(&0);
            if proposal.height <= stop_height {
                debug!("skipping this proposal because it's too old");
                continue;
            }

            let headers = self
                .synchronizer
                .get_all_headers_for_proposal(proposal.clone(), stop_height)
                .await?;

            if proposal.height > stop_height {
                state.last_executed_heights.insert(*pk, proposal.height);
            }

            for header in headers {
                info!("Committed {:?} ", header.id);
                if let Err(e) = self.tx_output.send(header).await {
                    debug!("Failed to send block through the output channel: {}", e);
                }
            }
        }
        Ok(())
    }

    async fn process_commit_message(&mut self, state: &mut State, commit_message: ConsensusMessage) {
        match commit_message {
            ConsensusMessage::Commit { round, proposals } => {
                if state.log.contains_key(&round) {
                    debug!("Already processed commit event {}", round);
                    return;
                }
                match self.execute_commit_proposals(state, &proposals).await {
                    Ok(()) => {
                        state.log.insert(
                            round,
                            ConsensusMessage::Commit {
                                round,
                                proposals: proposals.clone(),
                            },
                        );
                    }
                    Err(e) => {
                        warn!("Commit round {} deferred: {}", round, e);
                        state.pending_commits.insert(
                            round,
                            ConsensusMessage::Commit {
                                round,
                                proposals: proposals.clone(),
                            },
                        );
                    }
                }
            }
            _ => {}
        }
    }

    async fn process_pending_commits(&mut self, state: &mut State) {
        let rounds: Vec<_> = state.pending_commits.keys().cloned().collect();

        for round in rounds {
            let Some(commit_message) = state.pending_commits.get(&round).cloned() else {
                continue;
            };

            self.process_commit_message(state, commit_message).await;

            if state.log.contains_key(&round) {
                state.pending_commits.remove(&round);
            }
        }
    }

    async fn run(&mut self) {
        // The consensus state (everything else is immutable).
        let mut state = State::new(self.genesis.clone());

        loop {
            tokio::select! {
                Some(_) = self.rx_mempool.recv() => {},
                Some(commit_message) = self.rx_commit_message.recv() => {
                    self.process_commit_message(state.borrow_mut(), commit_message).await;
                },
                Some(certificate) = self.rx_deliver.recv() => {
                    state.dag
                        .entry(certificate.height())
                        .or_insert_with(HashMap::new)
                        .insert(certificate.origin(), (certificate.digest(), certificate));
                    self.process_pending_commits(state.borrow_mut()).await;
                }

            }
        }
    }
}
