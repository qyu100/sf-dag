use crate::aggregator::Aggregator;
use crate::coding::Coding;
use crate::config::Committee;
use crate::consensus::{ConsensusMessage, Round, CHANNEL_CAPACITY};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::merkle::MerkleTree;
use crate::messages::{
    payload_digest, Block, BlockInfo, BlockInfoWithProof, Echo, PayloadReady, Timeout, Transaction,
    QC, TC,
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
use rayon::prelude::*;
use std::cmp::max;
use std::collections::{HashMap, HashSet, VecDeque};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

struct OwnBlockEncodeResult {
    info: BlockInfo,
    messages: Vec<(Option<BlockInfoWithProof>, Option<Bytes>)>,
    round: Round,
}

pub struct Core {
    name: PublicKey,
    committee: Committee,
    store: Store,
    signature_service: SignatureService,
    leader_elector: LeaderElector,
    synchronizer: Synchronizer,
    rx_message: Receiver<ConsensusMessage>,
    rx_loopback: Receiver<Block>,
    rx_own_block_result: Receiver<ConsensusResult<OwnBlockEncodeResult>>,
    tx_own_block_result: Sender<ConsensusResult<OwnBlockEncodeResult>>,
    tx_proposer: Sender<ProposerMessage>,
    tx_commit: Sender<Block>,
    round: Round,
    last_timeout_round: Round,
    last_committed_round: Round,
    high_qc: QC,
    timer: Timer,
    aggregator: Aggregator,
    block_infos: HashMap<crypto::Digest, BlockInfo>,
    pending_echoes: HashMap<crypto::Digest, BlockInfoWithProof>,
    sent_echoes: HashSet<crypto::Digest>,
    payload_rounds: HashMap<crypto::Digest, Round>,
    payload_shards: HashMap<crypto::Digest, Vec<Option<Box<[u8]>>>>,
    payload_shard_roots: HashMap<crypto::Digest, Vec<Option<crypto::Digest>>>,
    echo_roots: HashMap<crypto::Digest, crypto::Digest>,
    ready_roots: HashMap<crypto::Digest, crypto::Digest>,
    decoded_payloads: HashSet<crypto::Digest>,
    optimistic_parents: HashMap<Round, BlockInfo>,
    proposed_rounds: HashSet<Round>,
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
            let (tx_own_block_result, rx_own_block_result) = channel(CHANNEL_CAPACITY);
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
                rx_own_block_result,
                tx_own_block_result,
                tx_proposer,
                tx_commit,
                round: 1,
                last_timeout_round: 0,
                last_committed_round: 0,
                high_qc: QC::genesis(),
                timer: Timer::new(timeout_delay),
                aggregator: Aggregator::new(committee),
                block_infos: HashMap::new(),
                pending_echoes: HashMap::new(),
                sent_echoes: HashSet::new(),
                payload_rounds: HashMap::new(),
                payload_shards: HashMap::new(),
                payload_shard_roots: HashMap::new(),
                echo_roots: HashMap::new(),
                ready_roots: HashMap::new(),
                decoded_payloads: HashSet::new(),
                optimistic_parents: HashMap::new(),
                proposed_rounds: HashSet::new(),
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

    fn increase_last_timeout_round(&mut self, target: Round) {
        self.last_timeout_round = max(self.last_timeout_round, target);
    }

    async fn commit(&mut self, block: &Block) -> ConsensusResult<()> {
        if self.last_committed_round >= block.round {
            return Ok(());
        }

        // Ensure we commit the entire chain. This is needed after view-change.
        let mut to_commit = VecDeque::new();

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

        // Increase the last timed-out round.
        self.increase_last_timeout_round(self.round);

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

    async fn handle_timeout(&mut self, timeout: &Timeout) -> ConsensusResult<()> {
        debug!("Processing {:?}", timeout);
        if timeout.round < self.round {
            return Ok(());
        }

        // Ensure the timeout is well formed.
        timeout.verify(&self.committee)?;

        // Process the QC embedded in the timeout.
        self.process_qc(&timeout.high_qc).await;

        // Add the timeout share to our aggregator and see if we have a quorum.
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

        // Cleanup the round aggregators.
        self.aggregator.cleanup(&self.round);
    }

    #[async_recursion]
    async fn generate_proposal(&mut self, tc: Option<TC>) {
        let parent = self
            .optimistic_parents
            .get(&self.round)
            .map(|info| info.id.clone())
            .unwrap_or_else(|| self.high_qc.hash.clone());
        if !self.proposed_rounds.insert(self.round) {
            return;
        }
        self.tx_proposer
            .send(ProposerMessage::Make(
                self.round,
                self.high_qc.clone(),
                parent,
                tc,
            ))
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

    async fn parent_delivered(&mut self, info: &BlockInfo) -> ConsensusResult<bool> {
        let parent_author = self
            .block_infos
            .get(&info.parent)
            .map(|parent_info| parent_info.author)
            .unwrap_or(info.author);
        Ok(self
            .synchronizer
            .get_block(&info.parent, &parent_author)
            .await?
            .is_some())
    }

    async fn delivered(&mut self, id: &crypto::Digest) -> ConsensusResult<bool> {
        if id == &crypto::Digest::default() {
            return Ok(true);
        }
        Ok(self.store.read(id.to_vec()).await?.is_some())
    }

    async fn optimistic_child_ready(&mut self, info: &BlockInfo) -> ConsensusResult<bool> {
        if info.parent == crypto::Digest::default() {
            return Ok(true);
        }
        if let Some(root_hash) = self.ready_roots.get(&info.parent).cloned() {
            self.echo_roots
                .entry(info.parent.clone())
                .or_insert(root_hash);
        }

        let has_parent_echo = self.echo_roots.contains_key(&info.parent);
        let parent_delivered = if has_parent_echo {
            false
        } else {
            self.delivered(&info.parent).await?
        };
        if !has_parent_echo && !parent_delivered {
            debug!(
                "Deferring optimistic child B{}: parent {} has no echo quorum yet",
                info.round + 1,
                info.parent
            );
            return Ok(false);
        }
        if parent_delivered {
            debug!(
                "Optimistic child B{} using delivered parent {} as DA-ready",
                info.round + 1,
                info.parent
            );
        }

        let grandparent = match self.block_infos.get(&info.parent) {
            Some(parent_info) => parent_info.parent.clone(),
            None => {
                debug!(
                    "Deferring optimistic child B{}: missing parent info for {}",
                    info.round + 1,
                    info.parent
                );
                return Ok(false);
            }
        };
        let delivered = self.delivered(&grandparent).await?;
        if !delivered {
            debug!(
                "Deferring optimistic child B{}: grandparent {} is not delivered yet",
                info.round + 1,
                grandparent
            );
        }
        Ok(delivered)
    }

    async fn maybe_generate_optimistic_child(&mut self, info: &BlockInfo) -> ConsensusResult<()> {
        let child_round = info.round + 1;
        if child_round < self.round {
            self.optimistic_parents.remove(&child_round);
            return Ok(());
        }
        if self.name != self.leader_elector.get_leader(child_round) {
            return Ok(());
        }
        if self.proposed_rounds.contains(&child_round) {
            return Ok(());
        }
        if !self.optimistic_child_ready(info).await? {
            self.optimistic_parents
                .entry(child_round)
                .or_insert_with(|| info.clone());
            return Ok(());
        }

        self.optimistic_parents.insert(child_round, info.clone());
        self.round = max(self.round, child_round);
        debug!(
            "Optimistic proposal B{} is ready with parent {}",
            child_round, info.id
        );
        self.generate_proposal(None).await;
        Ok(())
    }

    async fn retry_optimistic_children(&mut self) -> ConsensusResult<()> {
        let infos: Vec<_> = self.optimistic_parents.values().cloned().collect();
        for info in infos {
            self.maybe_generate_optimistic_child(&info).await?;
        }
        Ok(())
    }

    async fn retry_pending_echoes(&mut self) -> ConsensusResult<()> {
        let infos: Vec<_> = self.pending_echoes.values().cloned().collect();
        for info in infos {
            if self.parent_delivered(&info.info).await? {
                self.pending_echoes.remove(&info.info.id);
                self.send_echo(&info).await?;
            }
        }
        Ok(())
    }

    fn gc_payload_state(&mut self, gc_round: Round) {
        self.block_infos.retain(|_, info| info.round >= gc_round);
        self.payload_rounds.retain(|_, round| *round >= gc_round);
        let mut live_ids: HashSet<_> = self.payload_rounds.keys().cloned().collect();
        live_ids.extend(self.block_infos.keys().cloned());
        self.pending_echoes
            .retain(|_, block_info| block_info.info.round >= gc_round);
        self.sent_echoes.retain(|id| live_ids.contains(id));
        self.payload_shards.retain(|id, _| live_ids.contains(id));
        self.payload_shard_roots
            .retain(|id, _| live_ids.contains(id));
        self.echo_roots.retain(|id, _| live_ids.contains(id));
        self.ready_roots.retain(|id, _| live_ids.contains(id));
        self.decoded_payloads.retain(|id| live_ids.contains(id));
        self.optimistic_parents
            .retain(|round, info| *round >= gc_round && info.round >= gc_round);
        self.proposed_rounds.retain(|round| *round >= gc_round);
        self.aggregator.cleanup_payloads(&live_ids);
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
            .par_iter()
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
            parent: info.parent.clone(),
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
        name: PublicKey,
        sorted_keys: Vec<PublicKey>,
    ) -> ConsensusResult<OwnBlockEncodeResult> {
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
        let hashes: Vec<_> = shards.par_iter().map(|s| MerkleTree::digest(s)).collect();
        let mtree = MerkleTree::from_hashes(hashes);
        let self_index = sorted_keys.iter().position(|pk| pk == &name);
        let messages = (0..sorted_keys.len())
            .into_par_iter()
            .map(|i| {
                let proof = mtree
                    .proof_with_leaf(i, &shards[i])
                    .ok_or(ConsensusError::InvalidPayload)?;
                let info_with_proof = BlockInfoWithProof::new(info.clone(), proof);
                if Some(i) == self_index {
                    Ok((Some(info_with_proof), None))
                } else {
                    let message =
                        bincode::serialize(&ConsensusMessage::ProposeInfo(info_with_proof))
                            .map_err(ConsensusError::SerializationError)?;
                    Ok((None, Some(Bytes::from(message))))
                }
            })
            .collect::<ConsensusResult<Vec<_>>>()?;
        Ok(OwnBlockEncodeResult {
            info,
            messages,
            round: block.round,
        })
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
        debug!(
            "Recomputing payload root for {} from {} matching shards",
            id,
            self.matching_shard_count(id, &root_hash)
        );
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
        debug!("Recomputed payload root for {}", id);

        if let Some(info) = self.block_infos.get(id).cloned() {
            self.broadcast_payload_ready(&info, root_hash).await?;
        }
        self.try_decode_payload(id).await
    }

    async fn try_decode_payload(&mut self, id: &crypto::Digest) -> ConsensusResult<()> {
        if self.decoded_payloads.contains(id) {
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
        self.decoded_payloads.insert(id.clone());
        self.process_block(&block).await
    }

    fn dispatch_own_block(&self, block: Block) {
        let coding = self.coding.clone();
        let rs_block_size = self.rs_block_size;
        let rs_block_threads = self.rs_block_threads;
        let name = self.name;
        let sorted_keys = self.committee.sorted_keys();
        let tx = self.tx_own_block_result.clone();
        tokio::task::spawn_blocking(move || {
            let result = Self::encode_block_sync(
                coding,
                rs_block_size,
                rs_block_threads,
                block,
                name,
                sorted_keys,
            );
            let _ = tx.blocking_send(result);
        });
    }

    #[async_recursion]
    async fn handle_own_block_result(
        &mut self,
        result: OwnBlockEncodeResult,
    ) -> ConsensusResult<()> {
        self.payload_rounds
            .insert(result.info.id.clone(), result.info.round);
        self.block_infos
            .insert(result.info.id.clone(), result.info.clone());
        let sorted_keys = self.committee.sorted_keys();
        for (i, target) in sorted_keys.iter().enumerate() {
            let address = self
                .committee
                .address(target)
                .expect("committee key must have an address");
            let handler = match &result.messages[i] {
                (Some(info_with_proof), _) => {
                    self.handle_propose_info(info_with_proof).await?;
                    continue;
                }
                (_, Some(message)) => self.network.send(address, message.clone()).await,
                _ => unreachable!("own block encoder must produce one message per authority"),
            };
            self.cancel_handlers
                .entry(result.round)
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
        self.commit(block).await?;

        self.advance_round(block.round).await;
        self.retry_optimistic_children().await?;
        self.retry_pending_echoes().await?;
        Ok(())
    }

    async fn send_echo(&mut self, block_info: &BlockInfoWithProof) -> ConsensusResult<()> {
        if !self.sent_echoes.insert(block_info.info.id.clone()) {
            return Ok(());
        }
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
        self.handle_echo(echo).await
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

        self.payload_rounds
            .insert(block_info.info.id.clone(), block_info.info.round);
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

        self.maybe_generate_optimistic_child(&block_info.info)
            .await?;
        if !self.parent_delivered(&block_info.info).await? {
            self.pending_echoes
                .insert(block_info.info.id.clone(), block_info.clone());
            return Ok(());
        }
        self.send_echo(block_info).await
    }

    async fn handle_echo(&mut self, echo: Echo) -> ConsensusResult<()> {
        debug!("Processing {:?}", echo);
        echo.verify(&self.committee)?;
        self.payload_rounds.insert(echo.id.clone(), echo.round);
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

        let id = echo.id.clone();
        if let Some((root_hash, quorum_shards)) = self.aggregator.add_echo(echo)? {
            let entry = self
                .payload_shards
                .entry(id.clone())
                .or_insert_with(|| vec![None; shard_count]);
            let root_entry = self
                .payload_shard_roots
                .entry(id.clone())
                .or_insert_with(|| vec![None; shard_count]);
            for (i, shard) in quorum_shards.into_iter().enumerate() {
                if let Some(shard) = shard {
                    entry[i] = Some(shard);
                    root_entry[i] = Some(root_hash.clone());
                }
            }
            debug!(
                "Assembled echo quorum for {:?} with root {:?}",
                id, root_hash
            );
            self.maybe_recompute_root_and_ready(&id, root_hash).await?;
        }
        self.retry_optimistic_children().await?;
        self.try_decode_payload(&id).await?;
        Ok(())
    }

    async fn handle_payload_ready(&mut self, ready: &PayloadReady) -> ConsensusResult<()> {
        debug!("Processing {:?}", ready);
        ready.verify(&self.committee)?;
        self.payload_rounds.insert(ready.id.clone(), ready.round);
        if let Some(root_hash) = self.aggregator.add_payload_ready(ready.clone())? {
            self.ready_roots.insert(ready.id.clone(), root_hash);
            self.try_decode_payload(&ready.id).await?;
            self.retry_optimistic_children().await?;
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

        // This is the main loop: it processes incoming blocks, DA messages,
        // and receive timeout notifications from our Timeout Manager.
        loop {
            let result = tokio::select! {
                Some(message) = self.rx_message.recv() => match message {
                    ConsensusMessage::Propose(block) => self.handle_proposal(&block).await,
                    ConsensusMessage::ProposeInfo(block_info) => self.handle_propose_info(&block_info).await,
                    ConsensusMessage::Echo(echo) => self.handle_echo(echo).await,
                    ConsensusMessage::PayloadReady(ready) => self.handle_payload_ready(&ready).await,
                    ConsensusMessage::Timeout(timeout) => self.handle_timeout(&timeout).await,
                    ConsensusMessage::TC(tc) => self.handle_tc(tc).await,
                    _ => panic!("Unexpected protocol message")
                },
                Some(result) = self.rx_own_block_result.recv() => match result {
                    Ok(result) => self.handle_own_block_result(result).await,
                    Err(e) => Err(e),
                },
                Some(block) = self.rx_loopback.recv() => {
                    self.dispatch_own_block(block);
                    Ok(())
                },
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
                self.gc_payload_state(gc_round);
            }
        }
    }
}
