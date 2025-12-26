use crate::aggregator::Aggregator;
use crate::config::Committee;
use crate::consensus::{ConsensusMessage, Round};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::mempool::MempoolDriver;
use crate::messages::{Block, Timeout, Vote, QC, TC, Ready, Decide};
use crate::proposer::ProposerMessage;
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use async_recursion::async_recursion;
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::SimpleSender;
use std::any;
use std::cmp::max;
use std::collections::{VecDeque, HashMap, HashSet};
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub struct Core {
    name: PublicKey,
    committee: Committee,
    store: Store,
    signature_service: SignatureService,
    leader_elector: LeaderElector,
    mempool_driver: MempoolDriver,
    synchronizer: Synchronizer,
    rx_message: Receiver<ConsensusMessage>,
    rx_loopback: Receiver<Block>,
    tx_proposer: Sender<ProposerMessage>,
    tx_commit: Sender<Block>,
    round: Round,
    last_timeout_round: Round,
    last_committed_round: Round,
    high_qc: QC,
    timer: Timer,
    aggregator: Aggregator,
    // Decides for which we don't yet have the decided block.
    pending_decides: HashMap<crypto::Digest, Decide>,
    // Keep track of blocks already processed so we don't re-process them.
    // Map digest -> round when it was processed.
    processed_blocks: HashMap<crypto::Digest, Round>,
    // Garbage collection parameters for processed_blocks.
    gc_depth: Round,
    gc_round: Round,
    network: SimpleSender,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        store: Store,
        leader_elector: LeaderElector,
        mempool_driver: MempoolDriver,
        synchronizer: Synchronizer,
        timeout_delay: u64,
        rx_message: Receiver<ConsensusMessage>,
        rx_loopback: Receiver<Block>,
        tx_proposer: Sender<ProposerMessage>,
        tx_commit: Sender<Block>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee: committee.clone(),
                signature_service,
                store,
                leader_elector,
                mempool_driver,
                synchronizer,
                rx_message,
                rx_loopback,
                tx_proposer,
                tx_commit,
                round: 1,
                last_timeout_round: 0,
                last_committed_round: 0,
                high_qc: QC::genesis(),
                timer: Timer::new(timeout_delay),
                aggregator: Aggregator::new(committee),
                pending_decides: HashMap::new(),
                processed_blocks: HashMap::new(),
                gc_depth: 50,
                gc_round: 0,
                network: SimpleSender::new(),
            }
            .run()
            .await
        });
    }

    async fn store_block(&mut self, block: &Block) {
        let key = block.digest().to_vec();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
    }

    async fn commit(&mut self, decide: Decide) -> ConsensusResult<()> {
        debug!("last committed round {}, decide round {}", self.last_committed_round, decide.round);
        if self.last_committed_round >= decide.round {
            return Ok(());
        }

        // Ensure we commit the entire chain. This is needed after view-change.
        let mut to_commit = VecDeque::new();

        let block_opt = self
            .synchronizer
            .get_block(&decide.id, &self.leader_elector.get_leader(decide.round))
            .await?;
        let mut block = match block_opt {
            Some(b) => b,
            None => {
                debug!("Decided block {} not in store, enqueuing decide", decide.id);
                self.pending_decides.insert(decide.id.clone(), decide.clone());
                return Ok(());
            }
        };

        // Walk ancestors until we reach the next to-commit round. If any ancestor is missing,
        // suspend the commit and return; synchronizer will notify later and commit can be retried.
        let mut parent = block.clone();
        while self.last_committed_round + 1 < parent.round {
            let ancestor_opt = self.synchronizer.get_parent_block(&parent).await?;
            let ancestor = match ancestor_opt {
                Some(a) => a,
                None => {
                    debug!("Commit suspended for {}: missing ancestor {}", block.digest(), parent.parent);
                    return Ok(());
                }
            };
            to_commit.push_front(ancestor.clone());
            parent = ancestor;
        }
        to_commit.push_front(block.clone());
        debug!("to commit length {}", to_commit.len());
        // Save the last committed block.
        self.last_committed_round = block.round;

        // Send all the newly committed blocks to the node's application layer.
        while let Some(block) = to_commit.pop_back() {
            debug!("payload length {}", block.payload.len());
            if !block.payload.is_empty() {
                debug!("Committed {}", block);

                #[cfg(feature = "benchmark")]
                for x in &block.payload {
                    // NOTE: This log entry is used to compute performance.
                    info!("Committed {} -> {:?}", block, x);
                }
            }
            debug!("Committed {:?}", block);
            if let Err(e) = self.tx_commit.send(block).await {
                warn!("Failed to send block through the commit channel: {}", e);
            }
        }
        Ok(())
    }

    fn update_high_qc(&mut self, qc: &QC) {
        if qc.round > self.high_qc.round {
            self.high_qc = qc.clone();
        }
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        warn!("Timeout reached for round {}", self.round);

        // Mark that we've voted (timed out) for this round so we don't later send a vote.
        self.last_timeout_round = max(self.last_timeout_round, self.round);

        // Make a timeout message.
        let timeout = Timeout::new(
            self.round,
            self.name,
        )
        .await;
        debug!("Created {:?}", timeout);

        // Reset the timer.
        self.timer.reset();

        // Broadcast the timeout message.
        debug!("Broadcasting {:?}", timeout);
        let addresses = self
            .committee
            .broadcast_addresses(&self.name)
            .into_iter()
            .map(|(_, x)| x)
            .collect();
        let message = bincode::serialize(&ConsensusMessage::Timeout(timeout.clone()))
            .expect("Failed to serialize timeout message");
        self.network
            .broadcast(addresses, Bytes::from(message))
            .await;

        // Process our message.
        self.handle_timeout(&timeout).await
    }

    #[async_recursion]
    async fn handle_vote(&mut self, vote: &Vote) -> ConsensusResult<()> {
        debug!("Processing {:?}", vote);
        if vote.round < self.round {
            return Ok(());
        }

        // Ensure the vote is well formed.
        vote.verify(&self.committee)?;

        // Add the new vote to our aggregator and see if we have a quorum.
        if self.aggregator.add_vote(vote.clone())? {
            let ready = Ready::new(&vote.clone(), self.name).await;

            let message = bincode::serialize(&ConsensusMessage::Ready(ready.clone()))
            .expect("Failed to serialize vote");
            let addresses = self
                .committee
                .broadcast_addresses(&self.name)
                .into_iter()
                .map(|(_, x)| x)
                .collect();
            self.network
                .broadcast(addresses, Bytes::from(message))
                .await;

            self.handle_ready(&ready).await;
            // // Make a new block if we are the next leader.
            // if self.name == self.leader_elector.get_leader(self.round) {
            //     self.generate_proposal(None).await;
            // }
        }
        Ok(())
    }

    async fn handle_ready(&mut self, ready: &Ready) -> ConsensusResult<()> {
        debug!("Processing {:?}", ready);
        if ready.round < self.round {
            return Ok(());
        }

        // Ensure the ready is well formed.
        ready.verify(&self.committee)?;

        // Add the new ready to our aggregator and see if we have a quorum.
        if self.aggregator.add_ready(ready.clone())? {
            self.advance_round(ready.round).await;
            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal().await;
            }
            let decide = Decide::new(ready, self.name).await;

            let message = bincode::serialize(&ConsensusMessage::Decide(decide.clone()))
            .expect("Failed to serialize vote");
            let addresses = self
                .committee
                .broadcast_addresses(&self.name)
                .into_iter()
                .map(|(_, x)| x)
                .collect();
            self.network
                .broadcast(addresses, Bytes::from(message))
                .await;

            self.handle_decide(&decide).await;
        }
        Ok(())
    }

    async fn handle_decide(&mut self, decide: &Decide) -> ConsensusResult<()> {
        debug!("Processing {:?}", decide);
        // if decide.round < self.round {
        //     return Ok(());
        // }

        // Ensure the decide is well formed.
        decide.verify(&self.committee)?;

        if self.aggregator.add_decide(decide.clone())? {
            self.commit(decide.clone()).await?;
            self.mempool_driver.cleanup(decide.round).await;       
        }
        Ok(())
    }

    async fn handle_timeout(&mut self, timeout: &Timeout) -> ConsensusResult<()> {
        debug!("Processing {:?}", timeout);
        if timeout.round < self.round {
            return Ok(());
        }

        // Ensure the timeout is well formed.
        timeout.verify(&self.committee)?;

        // Add the new vote to our aggregator and see if we have a quorum.
        if self.aggregator.add_timeout(timeout.clone())? {

            self.tx_proposer
                .send(ProposerMessage::Parent((timeout.round, Block::genesis())))
                .await
                .expect("Failed to send message to proposer");

            // Try to advance the round.
            self.advance_round(timeout.round).await;

            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal().await;
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn advance_round(&mut self, round: Round) {
        if round < self.round {
            return;
        }
        // Reset the timer and advance round.
        self.timer.reset();
        self.round = round + 1;
        info!("Moved to round {}", self.round);

        // Cleanup the vote aggregator.
        self.aggregator.cleanup(&self.round);

        // Garbage collect processed_blocks entries older than gc_depth rounds.
        if self.round > self.gc_depth {
            let gc_round = self.round - self.gc_depth;
            self.processed_blocks.retain(|_, &mut r| r >= gc_round);
            self.gc_round = gc_round;
            debug!("Garbage collected processed_blocks up to round {}", gc_round);
        }
    }

    #[async_recursion]
    async fn generate_proposal(&mut self) {
        self.tx_proposer
            .send(ProposerMessage::Make(self.round))
            .await
            .expect("Failed to send message to proposer");
        debug!("send Make for round {}", self.round);
    }

    async fn cleanup_proposer(&mut self, parent: &Block, block: &Block) {
        let digests = parent
            .payload
            .iter()
            .cloned()
            .chain(block.payload.iter().cloned())
            .collect();
        self.tx_proposer
            .send(ProposerMessage::Cleanup(digests))
            .await
            .expect("Failed to send message to proposer");
    }

    #[async_recursion]
    async fn process_block(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!("Processing block {:?}", block);

        // Skip already processed blocks to prevent duplicate work.
        let digest = block.digest();
        if let Some(prev_round) = self.processed_blocks.get(&digest) {
            debug!("Block {} already processed at round {}, skipping", digest, prev_round);
            return Ok(());
        }
        // record that we've processed this digest at this block's round
        self.processed_blocks.insert(digest.clone(), block.round);

        let (parent) = match self.synchronizer.get_ancestors(block).await? {
            Some(ancestor) => ancestor,
            None => {
                debug!("Processing of {} suspended: missing parent", block.digest());
                return Ok(());
            }
        };
        debug!("Block's parent: {}, expected parent: {}", block.parent, parent.id);
        if block.parent != parent.id {
            warn!(
                "Block {} has wrong parent: expected {}, found {}",
                block.digest(),
                parent.digest(),
                block.parent
            );
            return Ok(());
        }
        self.tx_proposer
            .send(ProposerMessage::Parent((block.round, block.clone())))
            .await
            .expect("Failed to send message to proposer");

        // Store the block only if we have already processed all its ancestors.
        self.store_block(block).await;

        // If there is a queued decide waiting for this block, try to commit it now.
        if let Some(decide) = self.pending_decides.remove(&block.digest()) {
            debug!("Found pending decide for block {}, attempting commit", block.digest());
            if let Err(e) = self.commit(decide).await {
                warn!("Failed to commit pending decide for {}: {}", block.digest(), e);
            }
        }

        self.cleanup_proposer(&parent, block).await;

        // // Ensure the block's round is as expected.
        // // This check is important: it prevents bad leaders from producing blocks
        // // far in the future that may cause overflow on the round number.
        // if block.round != self.round {
        //     return Ok(());
        // }

        // If we already sent a timeout for this round, do not send a vote.
        if self.last_timeout_round >= block.round {
            debug!("Already sent timeout for round {}, skipping vote", block.round);
            return Ok(());
        }

        let vote = Vote::new(block, self.name).await;
        debug!("Created {:?}", vote);
        
        let message = bincode::serialize(&ConsensusMessage::Vote(vote.clone()))
            .expect("Failed to serialize vote");
        let addresses = self
            .committee
            .broadcast_addresses(&self.name)
            .into_iter()
            .map(|(_, x)| x)
            .collect();
        self.network
            .broadcast(addresses, Bytes::from(message))
            .await;

        self.handle_vote(&vote).await?;
        
        Ok(())
    }

    async fn handle_proposal(&mut self, block: &Block) -> ConsensusResult<()> {
        let digest = block.digest();
        debug!("Processing proposal {}", digest);
        // Ensure the block proposer is the right leader for the round.
        ensure!(
            block.author == self.leader_elector.get_leader(block.round),
            ConsensusError::WrongLeader {
                digest,
                leader: block.author,
                round: block.round
            }
        );

        // Check the block is correctly formed.
        block.verify(&self.committee)?;


        // Process the TC (if any). This may also allow us to advance round.
        // if let Some(ref tc) = block.tc {
        //     self.advance_round(tc.round).await;
        // }

        // Let's see if we have the block's data. If we don't, the mempool
        // will get it and then make us resume processing this block.
        if !self.mempool_driver.verify(block.clone()).await? {
            debug!("Processing of {} suspended: missing payload", digest);
            return Ok(());
        }

        // All check pass, we can process this block.
        self.process_block(block).await
    }


    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
        // Also, schedule a timer in case we don't hear from the leader.
        self.timer.reset();
        if self.name == self.leader_elector.get_leader(self.round) {
            debug!("Moved to round 1");
            self.generate_proposal().await;
        }

        // This is the main loop: it processes incoming blocks and votes,
        // and receive timeout notifications from our Timeout Manager.
        loop {
            let result = tokio::select! {
                Some(message) = self.rx_message.recv() => {
                    debug!("Core main loop received consensus message: {:?}", message);
                    match message {
                        ConsensusMessage::Propose(block) => self.handle_proposal(&block).await,
                        ConsensusMessage::Vote(vote) => self.handle_vote(&vote).await,
                        ConsensusMessage::Ready(ready) => self.handle_ready(&ready).await,
                        ConsensusMessage::Decide(decide) => self.handle_decide(&decide).await,
                        ConsensusMessage::Timeout(timeout) => self.handle_timeout(&timeout).await,
                        _ => panic!("Unexpected protocol message")
                    }
                },
                Some(block) = self.rx_loopback.recv() => self.process_block(&block).await,
                () = &mut self.timer => self.local_timeout_round().await,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}
