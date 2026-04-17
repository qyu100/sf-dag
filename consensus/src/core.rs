use crate::aggregator::Aggregator;
use crate::coding::Coding;
use crate::config::Committee;
use crate::consensus::{ConsensusMessage, Round};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::merkle::MerkleTree;
use crate::messages::{
    payload_digest, Block, BlockInfo, BlockInfoWithProof, Echo, PayloadReady, Ready, Timeout,
    Transaction, Vote, QC, TC,
};
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
use std::collections::{HashMap, VecDeque};
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
    block_infos: HashMap<crypto::Digest, BlockInfo>,
    payload_shards: HashMap<crypto::Digest, Vec<Option<Box<[u8]>>>>,
    payload_shard_roots: HashMap<crypto::Digest, Vec<Option<crypto::Digest>>>,
    echo_roots: HashMap<crypto::Digest, crypto::Digest>,
    ready_roots: HashMap<crypto::Digest, crypto::Digest>,
    decoded_payloads: HashMap<crypto::Digest, Vec<Transaction>>,
    coding: Coding,
    rs_block_size: usize,
    rs_block_threads: usize,
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
        synchronizer: Synchronizer,
        timeout_delay: u64,
        rs_block_size: usize,
        rs_block_threads: usize,
        rx_message: Receiver<ConsensusMessage>,
        rx_loopback: Receiver<Block>,
        tx_proposer: Sender<ProposerMessage>,
        tx_commit: Sender<Block>,
    ) {
        tokio::spawn(async move {
            let faults = committee.max_faults();
            let coding = Coding::new(committee.size() - 2 * faults, 2 * faults)
                .expect("committee must produce a valid erasure-coding layout");
            Self {
                name,
                committee: committee.clone(),
                signature_service,
                store,
                leader_elector,
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
                block_infos: HashMap::new(),
                payload_shards: HashMap::new(),
                payload_shard_roots: HashMap::new(),
                echo_roots: HashMap::new(),
                ready_roots: HashMap::new(),
                decoded_payloads: HashMap::new(),
                coding,
                rs_block_size,
                rs_block_threads,
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

        let block = match block_opt {
            Some(b) => b,
            None => {
                warn!("Decided block {} not found in store", ready.hash);
                self.pending_decides
                    .insert(ready.hash.clone(), ready.clone());
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
                #[cfg(feature = "benchmark")]
                info!("Committed {:?} ", block.digest());
            }
            // debug!("Committed {:?} ", block);
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
        let handlers = self
            .network
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

            // Process the QC.
            self.process_qc(&qc).await;

            let ready =
                Ready::new(&vote, self.name, qc.clone(), self.signature_service.clone()).await;
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
            let handlers = self
                .network
                .broadcast(addresses, Bytes::from(message))
                .await;

            self.cancel_handlers
                .entry(ready.round)
                .or_insert_with(Vec::new)
                .extend(handlers);

            self.handle_ready(&ready).await?;

            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(None).await;
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn handle_ready(&mut self, ready: &Ready) -> ConsensusResult<()> {
        debug!("Processing {:?}", ready);

        ready.verify(&self.committee)?;
        if let Some(_qc) = self.aggregator.add_ready(ready.clone())? {
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
            let handlers = self
                .network
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

    async fn cleanup_proposer(&mut self, _parent: &Block, _block: &Block) {
        self.tx_proposer
            .send(ProposerMessage::Cleanup)
            .await
            .expect("Failed to send message to proposer");
    }

    async fn process_qc(&mut self, qc: &QC) {
        self.advance_round(qc.round).await;
        self.update_high_qc(qc);
    }

    fn own_shard_index(&self) -> ConsensusResult<usize> {
        self.committee
            .sorted_keys()
            .iter()
            .position(|name| name == &self.name)
            .ok_or(ConsensusError::NotInCommittee(self.name))
    }

    fn matching_shard_count(&self, id: &crypto::Digest, root_hash: &crypto::Digest) -> usize {
        self.payload_shard_roots
            .get(id)
            .map(|roots| {
                roots
                    .iter()
                    .filter(|root| root.as_ref() == Some(root_hash))
                    .count()
            })
            .unwrap_or(0)
    }

    fn shards_for_root(
        &self,
        id: &crypto::Digest,
        root_hash: &crypto::Digest,
    ) -> Option<Vec<Option<Box<[u8]>>>> {
        let shards = self.payload_shards.get(id)?;
        let roots = self.payload_shard_roots.get(id)?;
        Some(
            shards
                .iter()
                .zip(roots)
                .map(|(shard, root)| {
                    if root.as_ref() == Some(root_hash) {
                        shard.clone()
                    } else {
                        None
                    }
                })
                .collect(),
        )
    }

    fn save_reconstructed_shards(
        &mut self,
        id: &crypto::Digest,
        root_hash: &crypto::Digest,
        shards: &[Option<Box<[u8]>>],
    ) {
        let shard_count = self.committee.size();
        let entry = self
            .payload_shards
            .entry(id.clone())
            .or_insert_with(|| vec![None; shard_count]);
        let root_entry = self
            .payload_shard_roots
            .entry(id.clone())
            .or_insert_with(|| vec![None; shard_count]);
        for (i, shard) in shards.iter().enumerate() {
            if let Some(shard) = shard {
                entry[i] = Some(shard.clone());
                root_entry[i] = Some(root_hash.clone());
            }
        }
    }

    fn recompute_root_sync(
        coding: Coding,
        rs_block_size: usize,
        rs_block_threads: usize,
        root_hash: crypto::Digest,
        mut shards: Vec<Option<Box<[u8]>>>,
    ) -> ConsensusResult<Vec<Option<Box<[u8]>>>> {
        coding.reconstruct_shards(&mut shards, rs_block_size, rs_block_threads)?;
        let hashes: Vec<_> = shards
            .iter()
            .map(|s| MerkleTree::digest(s.as_ref().expect("shard reconstructed")))
            .collect();
        let mtree = MerkleTree::from_hashes(hashes);
        ensure!(
            *mtree.root_hash() == root_hash,
            ConsensusError::InvalidPayload
        );
        Ok(shards)
    }

    fn decode_payload_sync(
        coding: Coding,
        rs_block_size: usize,
        rs_block_threads: usize,
        info: BlockInfo,
        mut shards: Vec<Option<Box<[u8]>>>,
    ) -> ConsensusResult<(Block, Vec<Option<Box<[u8]>>>)> {
        coding.reconstruct_shards(&mut shards, rs_block_size, rs_block_threads)?;
        let mut bytes = Vec::new();
        for shard in shards.iter().take(coding.data_shard_count()) {
            bytes.extend_from_slice(shard.as_ref().expect("data shard reconstructed"));
        }
        bytes.truncate(info.payload_len);
        let payload: Vec<Transaction> =
            bincode::deserialize(&bytes).map_err(ConsensusError::SerializationError)?;
        ensure!(
            payload_digest(&payload) == info.payload_digest,
            ConsensusError::InvalidPayload
        );

        let block = Block {
            qc: info.qc.clone(),
            tc: info.tc.clone(),
            author: info.author,
            round: info.round,
            payload,
            signature: info.signature.clone(),
        };
        ensure!(
            block.digest() == info.id,
            ConsensusError::MalformedBlock(info.id)
        );
        Ok((block, shards))
    }

    fn encode_block_sync(
        coding: Coding,
        rs_block_size: usize,
        rs_block_threads: usize,
        block: Block,
    ) -> ConsensusResult<(BlockInfo, Vec<BlockInfoWithProof>)> {
        let info = BlockInfo::create_from(&block);
        let mut payload_bytes =
            bincode::serialize(&block.payload).map_err(ConsensusError::SerializationError)?;
        let data_shards = coding.data_shard_count();
        let total_shards = coding.total_shard_count();
        let mut shard_len = (payload_bytes.len() + data_shards - 1) / data_shards;
        if shard_len % 64 != 0 {
            shard_len += 64 - (shard_len % 64);
        }
        payload_bytes.resize(shard_len * total_shards, 0);
        let mut shards: Vec<Vec<u8>> = payload_bytes
            .chunks(shard_len)
            .map(|chunk| chunk.to_vec())
            .collect();
        let mut refs: Vec<&mut [u8]> = shards.iter_mut().map(|x| x.as_mut_slice()).collect();
        coding.encode(&mut refs, rs_block_size, rs_block_threads)?;
        let hashes: Vec<_> = shards.iter().map(|s| MerkleTree::digest(s)).collect();
        let mtree = MerkleTree::from_hashes(hashes);
        let infos = shards
            .iter()
            .enumerate()
            .map(|(i, shard)| {
                let proof = mtree
                    .proof_with_leaf(i, shard)
                    .ok_or(ConsensusError::InvalidPayload)?;
                Ok(BlockInfoWithProof::new(info.clone(), proof))
            })
            .collect::<ConsensusResult<Vec<_>>>()?;
        Ok((info, infos))
    }

    async fn broadcast_payload_ready(
        &mut self,
        info: &BlockInfo,
        root_hash: crypto::Digest,
    ) -> ConsensusResult<()> {
        let ready =
            PayloadReady::new(info, self.name, root_hash, self.signature_service.clone()).await;
        debug!("Created {:?}", ready);
        let message = bincode::serialize(&ConsensusMessage::PayloadReady(ready.clone()))
            .expect("Failed to serialize payload ready");
        let addresses = self
            .committee
            .broadcast_addresses(&self.name)
            .into_iter()
            .map(|(_, x)| x)
            .collect();
        let handlers = self
            .network
            .broadcast(addresses, Bytes::from(message))
            .await;
        self.cancel_handlers
            .entry(ready.round)
            .or_insert_with(Vec::new)
            .extend(handlers);
        self.handle_payload_ready(&ready).await
    }

    async fn maybe_recompute_root_and_ready(
        &mut self,
        id: &crypto::Digest,
        root_hash: crypto::Digest,
    ) -> ConsensusResult<()> {
        if self.echo_roots.contains_key(id) {
            return Ok(());
        }
        let mut shards = match self.shards_for_root(id, &root_hash) {
            Some(shards) => shards,
            None => return Ok(()),
        };
        let coding = self.coding.clone();
        let rs_block_size = self.rs_block_size;
        let rs_block_threads = self.rs_block_threads;
        let root_hash_for_task = root_hash.clone();
        shards = tokio::task::spawn_blocking(move || {
            Self::recompute_root_sync(
                coding,
                rs_block_size,
                rs_block_threads,
                root_hash_for_task,
                shards,
            )
        })
        .await
        .map_err(|_| ConsensusError::InvalidPayload)??;
        self.save_reconstructed_shards(id, &root_hash, &shards);
        self.echo_roots.insert(id.clone(), root_hash.clone());

        if let Some(info) = self.block_infos.get(id).cloned() {
            self.broadcast_payload_ready(&info, root_hash).await?;
        }
        self.try_decode_payload(id).await
    }

    async fn try_decode_payload(&mut self, id: &crypto::Digest) -> ConsensusResult<()> {
        if self.decoded_payloads.contains_key(id) {
            return Ok(());
        }
        let root = match self.ready_roots.get(id) {
            Some(root) => root.clone(),
            None => return Ok(()),
        };
        if self.matching_shard_count(id, &root) < self.coding.data_shard_count() {
            return Ok(());
        }
        let info = match self.block_infos.get(id) {
            Some(info) => info.clone(),
            None => return Ok(()),
        };
        let shards = match self.shards_for_root(id, &root) {
            Some(shards) => shards,
            None => return Ok(()),
        };
        let coding = self.coding.clone();
        let rs_block_size = self.rs_block_size;
        let rs_block_threads = self.rs_block_threads;
        let (block, shards) = tokio::task::spawn_blocking(move || {
            Self::decode_payload_sync(coding, rs_block_size, rs_block_threads, info, shards)
        })
        .await
        .map_err(|_| ConsensusError::InvalidPayload)??;
        self.save_reconstructed_shards(id, &root, &shards);
        self.decoded_payloads
            .insert(id.clone(), block.payload.clone());
        self.process_block(&block).await
    }

    async fn encode_block(
        &self,
        block: &Block,
    ) -> ConsensusResult<(BlockInfo, Vec<BlockInfoWithProof>)> {
        let coding = self.coding.clone();
        let rs_block_size = self.rs_block_size;
        let rs_block_threads = self.rs_block_threads;
        let block = block.clone();
        tokio::task::spawn_blocking(move || {
            Self::encode_block_sync(coding, rs_block_size, rs_block_threads, block)
        })
        .await
        .map_err(|_| ConsensusError::InvalidPayload)?
    }

    #[async_recursion]
    async fn process_own_block(&mut self, block: &Block) -> ConsensusResult<()> {
        let (info, proofs) = self.encode_block(block).await?;
        self.block_infos.insert(info.id.clone(), info);
        let sorted_keys = self.committee.sorted_keys();
        for (i, target) in sorted_keys.iter().enumerate() {
            let info_with_proof = proofs[i].clone();
            if target == &self.name {
                self.handle_propose_info(&info_with_proof).await?;
                continue;
            }
            let address = self
                .committee
                .address(target)
                .expect("committee key must have an address");
            let message = bincode::serialize(&ConsensusMessage::ProposeInfo(info_with_proof))
                .expect("Failed to serialize proposal info");
            let handler = self.network.send(address, Bytes::from(message)).await;
            self.cancel_handlers
                .entry(block.round)
                .or_insert_with(Vec::new)
                .push(handler);
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_block(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);

        let parent = match self
            .synchronizer
            .get_block(block.parent(), &block.author)
            .await?
        {
            Some(ancestors) => ancestors,
            None => {
                debug!("Processing of {} suspended: missing parent", block.digest());
                return Ok(());
            }
        };

        // Store the block only if we have already processed all its ancestors.
        self.store_block(block).await;

        self.cleanup_proposer(&parent, block).await;

        if let Some(ready) = self.pending_decides.remove(&block.digest()) {
            debug!(
                "Found pending decide for block {}, attempting commit",
                block.digest()
            );

            if let Err(e) = self.commit(ready).await {
                warn!(
                    "Failed to commit pending decide for {}: {}",
                    block.digest(),
                    e
                );
            }
        }

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
            let handlers = self
                .network
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

    async fn handle_propose_info(
        &mut self,
        block_info: &BlockInfoWithProof,
    ) -> ConsensusResult<()> {
        debug!("Processing proposal info {:?}", block_info);

        let digest = block_info.info.id.clone();
        ensure!(
            block_info.info.author == self.leader_elector.get_leader(block_info.info.round),
            ConsensusError::WrongLeader {
                digest,
                leader: block_info.info.author,
                round: block_info.info.round
            }
        );
        block_info.verify(&self.committee)?;
        ensure!(
            block_info.proof.index() == self.own_shard_index()?,
            ConsensusError::InvalidPayload
        );

        if let Some(ref tc) = block_info.info.tc {
            self.advance_round(tc.round).await;
        }

        self.block_infos
            .entry(block_info.info.id.clone())
            .or_insert_with(|| block_info.info.clone());
        let shard_count = self.committee.size();
        let shards = self
            .payload_shards
            .entry(block_info.info.id.clone())
            .or_insert_with(|| vec![None; shard_count]);
        shards[block_info.proof.index()] = Some(block_info.proof.value().clone());
        let roots = self
            .payload_shard_roots
            .entry(block_info.info.id.clone())
            .or_insert_with(|| vec![None; shard_count]);
        roots[block_info.proof.index()] = Some(block_info.proof.root_hash().clone());

        let echo = Echo::new(block_info, self.name, self.signature_service.clone()).await;
        debug!("Created {:?}", echo);
        let message = bincode::serialize(&ConsensusMessage::Echo(echo.clone()))
            .expect("Failed to serialize echo");
        let addresses = self
            .committee
            .broadcast_addresses(&self.name)
            .into_iter()
            .map(|(_, x)| x)
            .collect();
        let handlers = self
            .network
            .broadcast(addresses, Bytes::from(message))
            .await;
        self.cancel_handlers
            .entry(echo.round)
            .or_insert_with(Vec::new)
            .extend(handlers);
        self.handle_echo(&echo).await
    }

    async fn handle_echo(&mut self, echo: &Echo) -> ConsensusResult<()> {
        debug!("Processing {:?}", echo);
        echo.verify(&self.committee)?;
        let shard_count = self.committee.size();
        let shards = self
            .payload_shards
            .entry(echo.id.clone())
            .or_insert_with(|| vec![None; shard_count]);
        shards[echo.proof.index()] = Some(echo.proof.value().clone());
        let roots = self
            .payload_shard_roots
            .entry(echo.id.clone())
            .or_insert_with(|| vec![None; shard_count]);
        roots[echo.proof.index()] = Some(echo.proof.root_hash().clone());

        if let Some((root_hash, quorum_shards)) = self.aggregator.add_echo(echo.clone())? {
            let entry = self
                .payload_shards
                .entry(echo.id.clone())
                .or_insert_with(|| vec![None; shard_count]);
            let root_entry = self
                .payload_shard_roots
                .entry(echo.id.clone())
                .or_insert_with(|| vec![None; shard_count]);
            for (i, shard) in quorum_shards.into_iter().enumerate() {
                if entry[i].is_none() && shard.is_some() {
                    entry[i] = shard;
                    root_entry[i] = Some(root_hash.clone());
                }
            }
            self.maybe_recompute_root_and_ready(&echo.id, root_hash)
                .await?;
        }
        self.try_decode_payload(&echo.id).await?;
        Ok(())
    }

    async fn handle_payload_ready(&mut self, ready: &PayloadReady) -> ConsensusResult<()> {
        debug!("Processing {:?}", ready);
        ready.verify(&self.committee)?;
        if let Some(root_hash) = self.aggregator.add_payload_ready(ready.clone())? {
            self.ready_roots.insert(ready.id.clone(), root_hash);
            self.try_decode_payload(&ready.id).await?;
        }
        Ok(())
    }

    async fn handle_proposal(&mut self, block: &Block) -> ConsensusResult<()> {
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

        // Process the TC (if any). This may also allow us to advance round.
        if let Some(ref tc) = block.tc {
            self.advance_round(tc.round).await;
        }

        // All check pass, we can process this block.
        self.process_block(block).await
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
                Some(message) = self.rx_message.recv() => match message {
                    ConsensusMessage::Propose(block) => self.handle_proposal(&block).await,
                    ConsensusMessage::ProposeInfo(block_info) => self.handle_propose_info(&block_info).await,
                    ConsensusMessage::Echo(echo) => self.handle_echo(&echo).await,
                    ConsensusMessage::PayloadReady(ready) => self.handle_payload_ready(&ready).await,
                    ConsensusMessage::Vote(vote) => self.handle_vote(&vote).await,
                    ConsensusMessage::Ready(ready) => self.handle_ready(&ready).await,
                    ConsensusMessage::Timeout(timeout) => self.handle_timeout(&timeout).await,
                    ConsensusMessage::TC(tc) => self.handle_tc(tc).await,
                    _ => panic!("Unexpected protocol message")
                },
                Some(block) = self.rx_loopback.recv() => self.process_own_block(&block).await,
                () = &mut self.timer => self.local_timeout_round().await,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => {
                    warn!("{}", e)
                }
            }

            if self.round > self.gc_depth {
                let gc_round = self.round - self.gc_depth;
                self.cancel_handlers.retain(|r, _| *r >= gc_round);
                self.pending_decides
                    .retain(|_, ready| ready.round >= gc_round);
            }
        }
    }
}
