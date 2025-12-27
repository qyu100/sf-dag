use crate::aggregator::Aggregator;
use crate::config::Committee;
use crate::consensus::{ConsensusMessage, Round};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::mempool::MempoolDriver;
use crate::messages::{Block, Timeout, Vote, QC, TC, Ready};
use crate::proposer::ProposerMessage;
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use async_recursion::async_recursion;
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::{CancelHandler, ReliableSender};
use std::cmp::max;
use std::collections::{VecDeque, HashMap};
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
    last_voted_round: Round,
    last_committed_round: Round,
    high_qc: QC,
    timer: Timer,
    aggregator: Aggregator,
    pending_decides: HashMap<crypto::Digest, Ready>,
    // processed_blocks now stores the round in which the block was processed so we can GC old entries
    processed_blocks: HashMap<crypto::Digest, Round>,
    // garbage collection parameters
    gc_depth: Round,
    network: ReliableSender,
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
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
                last_voted_round: 0,
                last_committed_round: 0,
                high_qc: QC::genesis(),
                timer: Timer::new(timeout_delay),
                aggregator: Aggregator::new(committee),
                pending_decides: HashMap::new(),
                processed_blocks: HashMap::new(),
                gc_depth: 50,
                network: ReliableSender::new(),
                cancel_handlers: HashMap::new(),
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

    fn increase_last_voted_round(&mut self, target: Round) {
        self.last_voted_round = max(self.last_voted_round, target);
    }

    async fn make_vote(&mut self, block: &Block) -> Option<Vote> {
        // Check if we can vote for this block.
        let safety_rule_1 = block.round > self.last_voted_round;
        let mut safety_rule_2 = block.qc.round + 1 == block.round;
        if let Some(ref tc) = block.tc {
            let mut can_extend = tc.round + 1 == block.round;
            can_extend &= block.qc.round >= *tc.high_qc_rounds().iter().max().expect("Empty TC");
            safety_rule_2 |= can_extend;
        }
        if !(safety_rule_1 && safety_rule_2) {
            return None;
        }

        // Ensure we won't vote for contradicting blocks.
        self.increase_last_voted_round(block.round);
        // TODO [issue #15]: Write to storage preferred_round and last_voted_round.
        Some(Vote::new(block, self.name, self.signature_service.clone()).await)
    }

    async fn commit(&mut self, ready: Ready) -> ConsensusResult<()> {
        if self.last_committed_round >= ready.round {
            return Ok(());
        }

        // Ensure we commit the entire chain. This is needed after view-change.
        let mut to_commit = VecDeque::new();

        let block_opt = self
            .synchronizer
            .get_block(&ready.hash, &ready.author)
            .await?;

        let mut block = match block_opt {
            Some(b) => b,
            None => {
                warn!("Decided block {} not found in store", ready.hash);
                self.pending_decides.insert(ready.hash.clone(), ready.clone());
                return Ok(());
            }
        };

        let mut parent = block.clone();
        while self.last_committed_round + 1 < parent.round {
            let ancestor = self
                .synchronizer
                .get_block(&parent.parent(), &parent.author)
                .await?
                .expect("We should have all the ancestors by now");
            to_commit.push_front(ancestor.clone());
            parent = ancestor;
        }
        to_commit.push_front(block.clone());

        // Save the last committed block.
        self.last_committed_round = block.round;

        // Send all the newly committed blocks to the node's application layer.
        while let Some(block) = to_commit.pop_back() {
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

        // Increase the last voted round.
        self.increase_last_voted_round(self.round);

        // Make a timeout message.
        let timeout = Timeout::new(
            self.high_qc.clone(),
            self.round,
            self.name,
            self.signature_service.clone(),
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
        let handlers = self.network
            .broadcast(addresses, Bytes::from(message))
            .await;

        self.cancel_handlers
            .entry(timeout.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

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
        if let Some(qc) = self.aggregator.add_vote(vote.clone())? {
            debug!("Assembled {:?}", qc);

            // Process the QC (may advance the round and update high_qc).
            self.process_qc(&qc).await;

            let ready = Ready::new(&vote, self.name, qc.clone(), self.signature_service.clone()).await;
            debug!("Created {:?}", ready);
            // Clone ready for serialization so we can still use the original below.
            let message = bincode::serialize(&ConsensusMessage::Ready(ready.clone()))
                .expect("Failed to serialize ready message");
            let addresses = self
                .committee
                .broadcast_addresses(&self.name)
                .into_iter()
                .map(|(_, x)| x)
                .collect();
            let handlers = self.network.broadcast(addresses, Bytes::from(message)).await;

            self.cancel_handlers
                .entry(ready.round)
                .or_insert_with(Vec::new)
                .extend(handlers);

            self.handle_ready(&ready).await?;

            if self.name == self.leader_elector.get_leader(self.round) {
                debug!("leader of round {}", self.round);
                self.generate_proposal(None).await;
            }

        }
        Ok(())
    }

    #[async_recursion]
    async fn handle_ready(&mut self, ready: &Ready) -> ConsensusResult<()> {
        debug!("Processing {:?}", ready);

        ready.verify(&self.committee)?;
        if let Some(qc) = self.aggregator.add_ready(ready.clone())? {
            self.mempool_driver.cleanup(ready.round).await;
            self.commit(ready.clone()).await?;
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

        // Process the QC embedded in the timeout.
        self.process_qc(&timeout.high_qc).await;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(tc) = self.aggregator.add_timeout(timeout.clone())? {
            debug!("Assembled {:?}", tc);

            // Try to advance the round.
            self.advance_round(tc.round).await;

            // Broadcast the TC.
            debug!("Broadcasting {:?}", tc);
            let addresses = self
                .committee
                .broadcast_addresses(&self.name)
                .into_iter()
                .map(|(_, x)| x)
                .collect();
            let message = bincode::serialize(&ConsensusMessage::TC(tc.clone()))
                .expect("Failed to serialize timeout certificate");
            let handlers = self.network
                .broadcast(addresses, Bytes::from(message))
                .await;
            self.cancel_handlers
                .entry(timeout.round)
                .or_insert_with(Vec::new)
                .extend(handlers);
            
            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(Some(tc)).await;
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
    }

    #[async_recursion]
    async fn generate_proposal(&mut self, tc: Option<TC>) {
        self.tx_proposer
            .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc))
            .await
            .expect("Failed to send message to proposer");
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

    async fn process_qc(&mut self, qc: &QC) {
        self.advance_round(qc.round).await;
        self.update_high_qc(qc);
    }
    
    #[async_recursion]
    async fn process_own_block(&mut self, block: &Block) -> ConsensusResult<()> {

            let message = bincode::serialize(&&ConsensusMessage::Propose(block.clone()))
                .expect("Failed to serialize vote");
            let addresses = self
                .committee
                .broadcast_addresses(&self.name)
                .into_iter()
                .map(|(_, x)| x)
                .collect();
            let handlers = self.network
                .broadcast(addresses, Bytes::from(message))
                .await;
            self.cancel_handlers
                .entry(block.round)
                .or_insert_with(Vec::new)
                .extend(handlers);

        self.process_block(block).await
    }

    #[async_recursion]
    async fn process_block(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);

        let (parent) = match self.synchronizer.get_block(block.parent(), &block.author).await? {
            Some(ancestors) => ancestors,
            None => {
                debug!("Processing of {} suspended: missing parent", block.digest());
                return Ok(());
            }
        };

        // Store the block only if we have already processed all its ancestors.
        self.store_block(block).await;

        self.cleanup_proposer(&parent, block).await;

        // Mark this block as processed to avoid re-processing it.
        self.processed_blocks.insert(block.digest(), block.round);

        if let Some(ready) = self.pending_decides.remove(&block.digest()) {
            debug!("Found pending decide for block {}, attempting commit", block.digest());

            self.mempool_driver.cleanup(ready.round).await;
            if let Err(e) = self.commit(ready).await {
                warn!("Failed to commit pending decide for {}: {}", block.digest(), e);
            }
        }

        // Check if we can vote for this block.
        if let Some(vote) = self.make_vote(block).await {
            debug!("Created {:?}", vote);
            // Broadcast vote1 to all replicas (vote1 all-to-all).
            let message = bincode::serialize(&ConsensusMessage::Vote(vote.clone()))
                .expect("Failed to serialize vote");
            let addresses = self
                .committee
                .broadcast_addresses(&self.name)
                .into_iter()
                .map(|(_, x)| x)
                .collect();
            let handlers = self.network
                .broadcast(addresses, Bytes::from(message))
                .await;
            self.cancel_handlers
                .entry(vote.round)
                .or_insert_with(Vec::new)
                .extend(handlers);
            self.handle_vote(&vote).await?;
        }
        Ok(())
    }

    async fn handle_proposal(&mut self, block: &Block) -> ConsensusResult<()> {
        // // Skip if we've already processed this block.
        // let digest = block.digest();
        // if self.processed_blocks.contains_key(&digest) {
        //     debug!("Already processed {}, skipping", digest);
        //     return Ok(());
        // }

        debug!("Processing proposal {:?}", block);

        let digest = block.digest();
        
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

        // // Process the QC. This may allow us to advance round.
        // self.process_qc(&block.qc).await;

        // Process the TC (if any). This may also allow us to advance round.
        if let Some(ref tc) = block.tc {
            self.advance_round(tc.round).await;
        }

        // Let's see if we have the block's data. If we don't, the mempool
        // will get it and then make us resume processing this block.
        if !self.mempool_driver.verify(block.clone()).await? {
            debug!("Processing of {} suspended: missing payload", digest);
            return Ok(());
        }

        // All check pass, we can process this block.
        self.process_block(block).await?;

        Ok(())
    }

    async fn handle_tc(&mut self, tc: TC) -> ConsensusResult<()> {
        tc.verify(&self.committee)?;
        if tc.round < self.round {
            return Ok(());
        }
        self.advance_round(tc.round).await;
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(Some(tc)).await;
        }
        Ok(())
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
        // Also, schedule a timer in case we don't hear from the leader.
        self.timer.reset();
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(None).await;
        }

        // This is the main loop: it processes incoming blocks and votes,
        // and receive timeout notifications from our Timeout Manager.
        loop {
            let result = tokio::select! {
                Some(message) = self.rx_message.recv() => 
                {
                // debug!("Core main loop received consensus message: {:?}", message);
                match message {
                    ConsensusMessage::Propose(block) => self.handle_proposal(&block).await,
                    ConsensusMessage::Vote(vote) => self.handle_vote(&vote).await,
                    ConsensusMessage::Ready(ready) => self.handle_ready(&ready).await,
                    ConsensusMessage::Timeout(timeout) => self.handle_timeout(&timeout).await,
                    ConsensusMessage::TC(tc) => self.handle_tc(tc).await,
                    _ => panic!("Unexpected protocol message")
                }
                },
                Some(block) = self.rx_loopback.recv() => self.process_own_block(&block).await,
                () = &mut self.timer => self.local_timeout_round().await,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
            // Centralized garbage collection executed each loop iteration.
            if self.round > self.gc_depth {
                let gc_round = self.round - self.gc_depth;
                // drop processed_blocks entries older than gc_round
                self.processed_blocks.retain(|_, &mut r| r >= gc_round);
                // drop cancel handlers for old rounds (dropping receivers cancels them)
                self.cancel_handlers.retain(|r, _| *r >= gc_round);
                // drop pending decides older than gc_round
                self.pending_decides.retain(|_, ready| ready.round >= gc_round);
            }

        }
    }
}
