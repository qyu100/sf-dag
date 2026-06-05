use crate::aggregator::Aggregator;
use crate::coding::{shard_hashes, Coding};
use crate::consensus::{ConsensusMessage, ConsensusMessageRef, ProposalMessage, Round};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::mempool::MempoolDriver;
use crate::merkle::MerkleTree;
use crate::merkle::Proof;
use crate::messages::{
    shard_store_key, Block, NormalProposal, ShardRequest, ShardResponse, Vote, VoteType, QC,
};
use crate::proposer::{ProposalTrigger, ProposerMessage};
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use async_recursion::async_recursion;
use bytes::Bytes;
use config::Committee;
use crypto::PublicKey;
use crypto::{BlsSignatureService, Digest, Hash as _};
use log::{debug, error, info, warn};
use network::ReliableSender;
use primary::Certificate;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Instant as StdInstant;
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::Instant;

// #[cfg(test)]
// #[path = "tests/core_tests.rs"]
// pub mod core_tests;

/// Implementation of Chained Moonshot per the latest whitepaper spec (22/09/2023).
/// If any of the terms used below are unclear, please refer to the paper. If you
/// are unsure of where to find the latest version of the paper, please contact
/// Isaac Doidge.

pub struct Core {
    aggregator: Aggregator,
    committee: Committee,
    committable_blocks: HashMap<Digest, (Round, Digest)>,
    commit_qcs: HashMap<Round, QC>,
    consensus_only: bool,
    last_commit: Block,
    leader_elector: LeaderElector,
    // Highest weak certificate
    // hwqc: WQC,
    mempool_driver: MempoolDriver,
    name: PublicKey,
    // Index of uncommitted blocks by round, then by Proposal type.
    // Each round may have at most one Normal or one Fallback Proposal,
    // and up to two Optimistic Proposals.
    pending_proposals: HashMap<Round, Digest>,
    pending_proofs: HashMap<Digest, Proof>,
    availability_proofs: HashMap<(Digest, Digest), Vec<Option<Proof>>>,
    pending_availability_qcs: HashMap<(Round, Digest, Digest), QC>,
    requested_shards: HashSet<(Digest, Digest, usize)>,
    started_shard_verify: HashSet<(Round, Digest, Digest)>,
    network: ReliableSender,
    rx_proposal_net: Receiver<Vec<(SocketAddr, Bytes, String)>>,
    round: Round,
    rs_block_size: usize,
    rs_block_threads: usize,
    rx_proposer: Receiver<ProposalMessage>,
    rx_message: Receiver<ConsensusMessage>,
    rx_synchronizer: Receiver<Block>,
    bls_signature_service: BlsSignatureService,
    store: Store,
    synchronizer: Synchronizer,
    sync_requests: HashSet<Digest>,
    sent_normal_votes: HashSet<(Round, Digest, Digest)>,
    sent_commit_votes: HashSet<(Round, Digest, Digest)>,
    sent_decide_votes: HashSet<(Round, Digest, Digest)>,
    timer: Timer,
    tx_commit: Sender<Vec<Certificate>>,
    tx_output: Sender<Block>,
    tx_proposer: Sender<ProposerMessage>,
    proposal_triggers_sent: HashSet<Round>,
    // Index of uncommitted blocks by Digest.
    uncommitted_blocks: HashMap<Digest, Block>,
    uncommitted_qcs: HashMap<Round, QC>,
    verified_normal_qcs: HashSet<(Round, Digest, Digest)>,
    started_nqc_verify: HashSet<(Round, Digest, Digest)>,
    tx_nqc_verify: Sender<NqcVerifyResult>,
    rx_nqc_verify: Receiver<NqcVerifyResult>,
}

// Identifier of the Genesis round.
const GENESIS: u64 = 0;

struct NqcVerifyResult {
    qc: QC,
    ok: bool,
    aggregate_ms: u128,
    bls_verify_ms: u128,
    reconstruct_ms: u128,
    source: &'static str,
}

struct AvailabilityTiming {
    reconstruct_ms: u128,
    merkle_ms: u128,
    total_ms: u128,
}

struct VoteBroadcastStats {
    peers: usize,
    bytes: usize,
    address_ms: u128,
    serialize_ms: u128,
    enqueue_ms: u128,
    total_ms: u128,
}

fn check_availability_sync(
    payload_root: Digest,
    mut shards: Vec<Option<Box<[u8]>>>,
    data_shards: usize,
    parity_shards: usize,
    rs_block_size: usize,
    rs_block_threads: usize,
) -> ConsensusResult<AvailabilityTiming> {
    let total_start = StdInstant::now();
    let coding = Coding::new(data_shards, parity_shards);
    let reconstruct_start = StdInstant::now();
    coding.reconstruct_shards(&mut shards, rs_block_size, rs_block_threads)?;
    let reconstruct_ms = reconstruct_start.elapsed().as_millis();
    let merkle_start = StdInstant::now();
    let mtree = MerkleTree::from_hashes(shard_hashes(&shards)?);
    ensure!(
        mtree.root_hash() == &payload_root,
        ConsensusError::InvalidProof
    );
    Ok(AvailabilityTiming {
        reconstruct_ms,
        merkle_ms: merkle_start.elapsed().as_millis(),
        total_ms: total_start.elapsed().as_millis(),
    })
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        consensus_only: bool,
        bls_signature_service: BlsSignatureService,
        store: Store,
        leader_elector: LeaderElector,
        mempool_driver: MempoolDriver,
        synchronizer: Synchronizer,
        timeout_delay: u64,
        rs_block_size: usize,
        rs_block_threads: usize,
        rx_message: Receiver<ConsensusMessage>,
        rx_proposer: Receiver<ProposalMessage>,
        rx_synchronizer: Receiver<Block>,
        tx_proposer: Sender<ProposerMessage>,
        tx_commit: Sender<Vec<Certificate>>,
        tx_output: Sender<Block>,
        rx_proposal_net: Receiver<Vec<(SocketAddr, Bytes, String)>>,
    ) {
        tokio::spawn(async move {
            let mut uncommitted_blocks = HashMap::new();
            let mut pending_proposals = HashMap::new();
            let pending_proofs = HashMap::new();
            let availability_proofs = HashMap::new();
            let pending_availability_qcs = HashMap::new();
            let requested_shards = HashSet::new();
            let started_shard_verify = HashSet::new();
            let mut uncommitted_qcs = HashMap::new();
            let genesis_block = Block::genesis();
            let genesis_qc = QC::genesis();
            let digest = genesis_block.digest();
            uncommitted_blocks.insert(digest.clone(), genesis_block.clone());
            pending_proposals.insert(genesis_block.round, digest);
            uncommitted_qcs.insert(genesis_block.round, genesis_qc.clone());
            let mut commit_qcs = HashMap::new();
            commit_qcs.insert(genesis_block.round, genesis_qc.clone());
            let (tx_nqc_verify, rx_nqc_verify) = channel(64);

            Self {
                aggregator: Aggregator::new(committee.clone()),
                committee,
                committable_blocks: HashMap::new(),
                commit_qcs,
                consensus_only,
                last_commit: genesis_block.clone(),
                leader_elector,
                mempool_driver,
                name,
                network: ReliableSender::new(),
                rx_proposal_net,
                round: 1,
                rs_block_size,
                rs_block_threads,
                rx_proposer,
                rx_message,
                rx_synchronizer,
                bls_signature_service,
                store,
                synchronizer,
                sync_requests: HashSet::new(),
                sent_normal_votes: HashSet::new(),
                sent_commit_votes: HashSet::new(),
                sent_decide_votes: HashSet::new(),
                timer: Timer::new(timeout_delay),
                tx_commit,
                tx_output,
                tx_proposer,
                proposal_triggers_sent: HashSet::new(),
                pending_proposals,
                pending_proofs,
                availability_proofs,
                pending_availability_qcs,
                requested_shards,
                started_shard_verify,
                uncommitted_blocks,
                uncommitted_qcs,
                verified_normal_qcs: HashSet::new(),
                started_nqc_verify: HashSet::new(),
                tx_nqc_verify,
                rx_nqc_verify,
            }
            .run()
            .await
        });
    }

    // Sends the given ConsensusMessage to all but self.
    async fn broadcast_vote_ref(&mut self, vote: &Vote) -> VoteBroadcastStats {
        debug!("Broadcasting Vote {:?}", vote);
        let total_start = StdInstant::now();
        let address_start = StdInstant::now();
        let addresses = self.committee.others_consensus_sockets(&self.name);
        let address_ms = address_start.elapsed().as_millis();
        let peers = addresses.len();
        let serialize_start = StdInstant::now();
        let message = bincode::serialize(&ConsensusMessageRef::Vote(vote))
            .expect(format!("Failed to serialize vote {:?}", vote).as_str());
        let serialize_ms = serialize_start.elapsed().as_millis();
        let m_bytes = Bytes::from(message);
        let bytes = m_bytes.len();
        let label = Self::vote_network_label(vote);
        let enqueue_start = StdInstant::now();
        self.broadcast_vote_bytes(&vote.kind, addresses, m_bytes, Some(label))
            .await;
        let enqueue_ms = enqueue_start.elapsed().as_millis();

        VoteBroadcastStats {
            peers,
            bytes,
            address_ms,
            serialize_ms,
            enqueue_ms,
            total_ms: total_start.elapsed().as_millis(),
        }
    }

    async fn broadcast_vote_bytes(
        &mut self,
        _kind: &VoteType,
        addresses: Vec<SocketAddr>,
        m_bytes: Bytes,
        label: Option<String>,
    ) {
        let _ = self
            .network
            .broadcast_with_label(addresses, m_bytes, label)
            .await;
    }

    // Unicasts the given ConsensusMessage to the given recipient if recipient is not self.
    async fn send_to(&mut self, m: ConsensusMessage, recipient: &PublicKey) {
        debug!("Unicasting {:?}", m);

        if *recipient != self.name {
            let address = self
                .committee
                .consensus(recipient)
                .expect("Target node is not in the committee")
                .consensus_to_consensus;
            let message = bincode::serialize(&m)
                .expect(format!("Failed to serialize message {:?}", m).as_str());
            let m_bytes = Bytes::from(message);

            match m {
                ConsensusMessage::Vote(vote) => {
                    let label = Self::vote_network_label(&vote);
                    self.send_vote_bytes(&vote.kind, address, m_bytes, Some(label))
                        .await
                }
                ConsensusMessage::ShardRequest(_) | ConsensusMessage::ShardResponse(_) => {
                    let _ = self.network.send(address, m_bytes).await;
                }
                _ => (),
            }
        }
    }

    async fn send_vote_bytes(
        &mut self,
        _kind: &VoteType,
        address: SocketAddr,
        m_bytes: Bytes,
        label: Option<String>,
    ) {
        let _ = self.network.send_with_label(address, m_bytes, label).await;
    }

    fn vote_network_label(vote: &Vote) -> String {
        format!(
            "vote,kind={},node={},round={},digest={},root={}",
            vote.kind, vote.author, vote.round, vote.blk_hash, vote.payload_root
        )
    }

    fn data_shard_count(&self) -> usize {
        (self.committee.n - 2 * self.committee.f) as usize
    }

    fn availability_key(qc: &QC) -> (Round, Digest, Digest) {
        (qc.round, qc.blk_hash.clone(), qc.payload_root.clone())
    }

    fn proof_key(block: &Digest, payload_root: &Digest) -> (Digest, Digest) {
        (block.clone(), payload_root.clone())
    }

    async fn record_availability_proof(
        &mut self,
        block: Digest,
        proof: Proof,
    ) -> ConsensusResult<()> {
        ensure!(
            proof.index() < self.committee.size()
                && !proof.value().is_empty()
                && proof.validate(self.committee.size()),
            ConsensusError::InvalidProof
        );

        let payload_root = proof.root_hash().clone();
        let index = proof.index();
        if index == self.committee.id(&self.name) as usize {
            self.pending_proofs
                .entry(block.clone())
                .or_insert_with(|| proof.clone());
        }

        let key = Self::proof_key(&block, &payload_root);
        let proofs = self
            .availability_proofs
            .entry(key)
            .or_insert_with(|| vec![None; self.committee.size()]);
        if proofs[index].is_none() {
            proofs[index] = Some(proof.clone());
        }

        let store_key = shard_store_key(&block, &payload_root, index);
        let value = bincode::serialize(&proof).expect("Failed to serialize shard proof");
        let _ = self.store.write(store_key, value).await;
        Ok(())
    }

    fn shard_owners(&self) -> Vec<(usize, PublicKey)> {
        let mut owners: Vec<_> = self
            .committee
            .authorities
            .iter()
            .map(|(name, authority)| (authority.id as usize, *name))
            .collect();
        owners.sort_by_key(|(index, _)| *index);
        owners
    }

    fn collected_shards(&self, block: &Digest, payload_root: &Digest) -> Vec<Option<Box<[u8]>>> {
        let mut shards = vec![None; self.committee.size()];
        if let Some(proofs) = self
            .availability_proofs
            .get(&Self::proof_key(block, payload_root))
        {
            for (idx, proof) in proofs.iter().enumerate() {
                if let Some(proof) = proof {
                    shards[idx] = Some(proof.clone().into_value());
                }
            }
        }
        shards
    }

    fn try_start_shard_recovery(&mut self, key: &(Round, Digest, Digest)) {
        if self.verified_normal_qcs.contains(key)
            || self.started_nqc_verify.contains(key)
            || self.started_shard_verify.contains(key)
        {
            return;
        }
        let Some(qc) = self.pending_availability_qcs.get(key).cloned() else {
            return;
        };
        let shards = self.collected_shards(&key.1, &key.2);
        if shards.iter().filter(|shard| shard.is_some()).count() < self.data_shard_count() {
            return;
        }

        self.started_shard_verify.insert(key.clone());
        self.started_nqc_verify.insert(key.clone());
        self.start_nqc_verification(qc, shards, 0, "shard_sync");
    }

    async fn request_availability_shards(&mut self, qc: &QC) -> ConsensusResult<()> {
        let key = Self::availability_key(qc);
        self.pending_availability_qcs
            .entry(key.clone())
            .or_insert_with(|| qc.clone());
        self.try_start_shard_recovery(&key);
        if self.verified_normal_qcs.contains(&key)
            || self.started_nqc_verify.contains(&key)
            || self.started_shard_verify.contains(&key)
        {
            return Ok(());
        }

        let proof_key = Self::proof_key(&qc.blk_hash, &qc.payload_root);
        for (shard_index, owner) in self.shard_owners() {
            if owner == self.name {
                continue;
            }
            if self
                .availability_proofs
                .get(&proof_key)
                .and_then(|proofs| proofs.get(shard_index))
                .and_then(|proof| proof.as_ref())
                .is_some()
            {
                continue;
            }
            if !self.requested_shards.insert((
                qc.blk_hash.clone(),
                qc.payload_root.clone(),
                shard_index,
            )) {
                continue;
            }
            let request = ShardRequest {
                block: qc.blk_hash.clone(),
                payload_root: qc.payload_root.clone(),
                index: shard_index,
                origin: self.name,
            };
            self.send_to(ConsensusMessage::ShardRequest(request), &owner)
                .await;
        }
        Ok(())
    }

    async fn handle_shard_response(&mut self, response: ShardResponse) -> ConsensusResult<()> {
        ensure!(
            *response.proof.root_hash() == response.payload_root,
            ConsensusError::InvalidProof
        );
        self.record_availability_proof(response.block.clone(), response.proof)
            .await?;

        let keys: Vec<_> = self
            .pending_availability_qcs
            .keys()
            .filter(|(_, block, payload_root)| {
                block == &response.block && payload_root == &response.payload_root
            })
            .cloned()
            .collect();
        for key in keys {
            self.try_start_shard_recovery(&key);
        }
        Ok(())
    }

    async fn handle_shard_request(&mut self, request: ShardRequest) -> ConsensusResult<()> {
        ensure!(
            request.index < self.committee.size(),
            ConsensusError::InvalidProof
        );
        ensure!(
            self.committee.stake(&request.origin) > 0,
            ConsensusError::UnknownAuthority(request.origin)
        );

        let proof_key = Self::proof_key(&request.block, &request.payload_root);
        let proof = self
            .availability_proofs
            .get(&proof_key)
            .and_then(|proofs| proofs.get(request.index))
            .and_then(|proof| proof.as_ref())
            .cloned();

        let proof = match proof {
            Some(proof) => proof,
            None => {
                let store_key =
                    shard_store_key(&request.block, &request.payload_root, request.index);
                let Some(bytes) = self.store.read(store_key).await? else {
                    debug!(
                        "Missing requested shard block={} root={} index={}",
                        request.block, request.payload_root, request.index
                    );
                    return Ok(());
                };
                bincode::deserialize(&bytes)?
            }
        };

        ensure!(
            proof.index() == request.index
                && *proof.root_hash() == request.payload_root
                && proof.validate(self.committee.size()),
            ConsensusError::InvalidProof
        );

        self.send_to(
            ConsensusMessage::ShardResponse(ShardResponse {
                block: request.block,
                payload_root: request.payload_root,
                proof,
            }),
            &request.origin,
        )
        .await;
        Ok(())
    }

    async fn get_block(&mut self, digest: Digest, round: Round) -> ConsensusResult<Option<Block>> {
        if round > self.last_commit.round {
            let proposer = self.leader_elector.get_leader(round);

            // See if we have the corresponding block.
            if let Some(b) = self.uncommitted_blocks.get(&digest) {
                // Have the block.
                Ok(Some(b.clone()))
            } else {
                debug!("Syncing block for given digest");
                // Missing the block with the given digest.
                let maybe_b = self
                    .synchronizer
                    .get_block(&digest, &proposer, None)
                    .await?;
                if maybe_b.is_none() {
                    self.sync_requests.insert(digest);
                }
                Ok(maybe_b)
            }
        } else {
            Ok(None)
        }
    }

    async fn have_all_ancestors(&mut self, block: Block) -> ConsensusResult<bool> {
        if block.round == GENESIS || block.parent == self.last_commit.digest() {
            // Genesis.
            return Ok(true);
        }

        // This function should only ever be called with uncommitted blocks.
        assert!(block.round > self.last_commit.round);
        // This function should only ever be called with blocks that directly
        // satisfy the commit rule (i.e. blocks that are LDC).
        assert!(self.committable_blocks.contains_key(&block.digest()));

        let mut b = block.clone();

        // Trace the chain of ancestors back to our most recently committed block.
        loop {
            let maybe_parent =
                // Check the in-memory index to avoid IO.
                match self.uncommitted_blocks.get(&b.parent)
                {
                    Some(parent) => Some(parent.clone()),
                    // Ensure we resume processing the given LDC block once we have synchronised
                    // its missing ancestor. This ensures that we will be able to recursively
                    // sync all missing ancestors, even if we do not observe their QCs. It also
                    // ensures that we will commit the LDC block once we have all of its ancestors.
                    None => self.synchronizer.get_block(
                            &b.parent,
                            // We do not know the proposer of b.parent at this stage, so we ask
                            // the proposer of b instead. This node may not have b.parent upon
                            // receiving our request if it proposed b on the basis of a QC or TC,
                            // however, if this is the case then we will eventually contact the
                            // rest of our peers and obtain it from them instead.
                            &b.author,
                            Some(block.clone())
                        ).await?
                };

            if let Some(parent) = maybe_parent {
                if parent.round == self.last_commit.round {
                    // Reached the last committed block.
                    return Ok(true);
                }
                assert!(parent.round > self.last_commit.round);
                b = parent;
            } else {
                debug!("Syncing missing ancestor");
                // Missing an ancestor of the given block. Synchronizer will request it from our peers.
                // Make a note of the requested block so that we can authenticate it when it arrives.
                self.sync_requests.insert(b.parent.clone());
                return Ok(false);
            }
        }
    }

    async fn try_commit_or_sync_ancestor(&mut self, block: &Block) -> ConsensusResult<()> {
        // Should only ever call this function with recent blocks.
        assert!(block.round > self.last_commit.round);

        // Check if we have already marked this block for commit.
        if self.committable_blocks.contains_key(&block.digest()) {
            if self.try_commit_if_ready(block.clone()).await? {
                debug!("Late commit");
            }
        }
        // else: Have not yet observed QCs indicating that this block satisfies the
        // commit rule. If we eventually do, then we will commit it at that time.

        Ok(())
    }

    async fn request_availability_for_block(&mut self, block: &Block) -> ConsensusResult<()> {
        let digest = block.digest();
        if let Some(qc) = self
            .uncommitted_qcs
            .get(&block.round)
            .filter(|qc| qc.blk_hash == digest && qc.payload_root == block.payload_root)
            .cloned()
        {
            self.request_availability_shards(&qc).await?;
            return Ok(());
        }

        if let Some(qc) = self
            .commit_qcs
            .get(&block.round)
            .filter(|qc| qc.blk_hash == digest && qc.payload_root == block.payload_root)
            .cloned()
        {
            self.request_availability_shards(&qc).await?;
            return Ok(());
        }

        debug!(
            "Availability pending but no QC available round={} digest={} root={}",
            block.round, digest, block.payload_root
        );
        Ok(())
    }

    async fn commit_chain_available(&mut self, block: &Block) -> ConsensusResult<bool> {
        let mut ancestor = block.clone();
        loop {
            let digest = ancestor.digest();
            let key = (
                ancestor.round,
                digest.clone(),
                ancestor.payload_root.clone(),
            );
            if !self.verified_normal_qcs.contains(&key) {
                self.request_availability_for_block(&ancestor).await?;
                return Ok(false);
            }

            if ancestor.parent == self.last_commit.digest() {
                return Ok(true);
            }

            let Some(parent) = self.uncommitted_blocks.get(&ancestor.parent).cloned() else {
                return Ok(false);
            };
            ensure!(
                parent.round > self.last_commit.round,
                ConsensusError::InvalidProof
            );
            ancestor = parent;
        }
    }

    async fn try_commit_verified_blocks(&mut self) -> ConsensusResult<()> {
        let mut candidates: Vec<_> = self
            .committable_blocks
            .iter()
            .map(|(digest, (round, _))| (*round, digest.clone()))
            .collect();
        candidates.sort_by_key(|(round, _)| *round);

        for (_, digest) in candidates {
            if digest == self.last_commit.digest() {
                continue;
            }
            let Some(block) = self.uncommitted_blocks.get(&digest).cloned() else {
                continue;
            };
            if block.round <= self.last_commit.round {
                continue;
            }
            let _ = self.try_commit_if_ready(block).await?;
        }
        Ok(())
    }

    fn update_pending_proposals(&mut self, block: &Block) {
        // Should only ever be called with blocks that have already passed can_accept_block.
        if self.pending_proposals.contains_key(&block.round) {
            warn!("Already contains a block for this round {:?}", block.round);
        } else {
            // First proposal for this round.
            self.pending_proposals.insert(block.round, block.digest());
        }
    }

    async fn store_block(&mut self, block: &Block, proof: Option<Proof>) {
        // Should only ever call this function with recent blocks.
        assert!(block.round > self.last_commit.round);
        // Store in-memory.
        self.update_pending_proposals(block);
        let digest = block.digest();
        self.uncommitted_blocks
            .insert(digest.clone(), block.clone());
        if let Some(proof) = proof {
            let _ = self.record_availability_proof(digest, proof).await;
        }

        let _ = self.observe_payload(block).await;
        // Write to disk
        let key = block.digest().to_vec();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
        debug!("Stored block {:?}", block);
    }

    async fn store_qc_block(&mut self, qc: &QC) -> ConsensusResult<()> {
        let Some(block) = &qc.block else {
            return Ok(());
        };

        ensure!(
            block.digest() == qc.blk_hash
                && block.payload_root == qc.payload_root
                && block.round == qc.round,
            ConsensusError::InvalidProof
        );
        block.is_well_formed(&self.committee)?;

        if block.round > self.last_commit.round
            && !self.uncommitted_blocks.contains_key(&qc.blk_hash)
        {
            self.store_block(block, None).await;
        }
        Ok(())
    }

    fn attach_block_to_qc(&self, qc: &mut QC) {
        if qc.block.is_none() {
            if let Some(block) = self.uncommitted_blocks.get(&qc.blk_hash) {
                qc.block = Some(block.clone());
            } else if self.last_commit.digest() == qc.blk_hash {
                qc.block = Some(self.last_commit.clone());
            }
        }
    }

    async fn commit(&mut self, block: Block) -> ConsensusResult<()> {
        let commit_start = Instant::now();
        if block.round == GENESIS {
            // Ignore the Genesis block.
            return Ok(());
        }

        assert!(block.round > self.last_commit.round);

        let committing_round = block.round;
        // Stack of blocks to be committed, with the newest block (i.e. the one this function
        // was invoked with) at the base and the oldest ancestor (i.e. the child of the last
        // committed block) at the top.
        let mut to_commit = Vec::new();
        let mut ancestor = block.clone();

        // Identify all uncommitted blocks that can be committed now that
        // their descendent has satisfied the commit rule.
        loop {
            // We should always terminate this loop at our last committed block.
            // If we go back to a lower round then the chain has been compromised.
            let ancestor_parent = ancestor.parent.clone();
            to_commit.push(ancestor);

            if ancestor_parent == self.last_commit.digest() {
                break;
            }
            ancestor = self
                .uncommitted_blocks
                .remove(&ancestor_parent)
                .unwrap_or_else(|| {
                    panic!("Missing ancestor of {:?} detected during commit.", block)
                });

            // We should always terminate this loop at our last committed block.
            // If we encounter another block at the same height as our last commit or
            // skip this height entirely then the chain has been compromised.
            assert!(ancestor.round > self.last_commit.round);
        }

        // Send all the newly committed blocks to the node's application layer.
        while let Some(committing) = to_commit.pop() {
            // These compact logs are required for the benchmark parser and match Lionfish.
            debug!("Committed {:?}", committing);
            if committing.author == self.name {
                info!("Committed {} Leader", committing.digest());
            } else {
                info!("Committed {} NonLeader", committing.digest());
            }
            if !self.consensus_only {
                self.tx_commit
                    .send(Vec::new())
                    .await
                    .expect("Failed to send payload");
                //     let payload = committing.payload.clone();

                //     // Output the block to the top-level application.
                //     if let Err(e) = self.tx_output.send(committing).await {
                //         warn!("Failed to send block through the output channel: {}", e);
                //     }

                //     // Clean up the mempool.
                //     // TODO: Ensure that this also cleans up payloads for blocks from
                //     // previous rounds that can never be committed.
                //     self.mempool_driver.cleanup(payload).await;
            }
        }

        // Record the last commit to assist with validation of future blocks.
        self.last_commit = block;
        // Clean up in-memory storage.
        self.committable_blocks
            .retain(|_, (r, _)| *r > committing_round);
        self.pending_proposals.retain(|r, _| *r > committing_round);
        self.sent_normal_votes
            .retain(|(round, _, _)| *round > committing_round);
        self.sent_commit_votes
            .retain(|(round, _, _)| *round > committing_round);
        self.sent_decide_votes
            .retain(|(round, _, _)| *round > committing_round);
        self.uncommitted_blocks
            .retain(|_, b| b.round > committing_round);
        self.uncommitted_qcs
            .retain(|_, qc| qc.round > committing_round);
        self.verified_normal_qcs
            .retain(|(round, _, _)| *round > committing_round);
        self.started_nqc_verify
            .retain(|(round, _, _)| *round > committing_round);
        self.pending_availability_qcs
            .retain(|(round, _, _), _| *round > committing_round);
        self.started_shard_verify
            .retain(|(round, _, _)| *round > committing_round);
        self.availability_proofs.retain(|(_, payload_root), _| {
            self.uncommitted_blocks
                .values()
                .any(|block| block.payload_root == *payload_root)
        });
        self.requested_shards.retain(|(_, payload_root, _)| {
            self.uncommitted_blocks
                .values()
                .any(|block| block.payload_root == *payload_root)
        });
        self.pending_proofs.retain(|_, proof| {
            self.uncommitted_blocks
                .values()
                .any(|block| block.payload_root == *proof.root_hash())
        });
        debug!(
            "TIMING commit_chain requested_round={} committed_to_round={} total_ms={}",
            committing_round,
            self.last_commit.round,
            commit_start.elapsed().as_millis()
        );

        // TODO: Remove uncommittable blocks from disk.
        Ok(())
    }

    async fn try_commit_if_ready(&mut self, block: Block) -> ConsensusResult<bool> {
        let digest = block.digest();
        let Some((_, payload_root)) = self.committable_blocks.get(&digest).cloned() else {
            return Ok(false);
        };
        ensure!(
            block.payload_root == payload_root,
            ConsensusError::InvalidProof
        );

        if !self.have_all_ancestors(block.clone()).await? {
            debug!(
                "Commit delayed until ancestors arrive round={} digest={}",
                block.round, digest
            );
            return Ok(false);
        }

        if !self.commit_chain_available(&block).await? {
            debug!(
                "Commit delayed until availability is verified round={} digest={}",
                block.round, digest
            );
            return Ok(false);
        }

        self.commit(block).await?;
        Ok(true)
    }

    async fn schedule_commit(&mut self, qc: &QC) -> ConsensusResult<()> {
        let schedule_start = Instant::now();
        // Schedule the related block for commit once we have it and all of its ancestors.
        let d = qc.blk_hash.clone();
        let r = qc.round;
        self.committable_blocks
            .insert(d.clone(), (r, qc.payload_root.clone()));

        if !self
            .verified_normal_qcs
            .contains(&Self::qc_availability_key(qc))
        {
            self.request_availability_shards(qc).await?;
        }

        if let Some(block) = self.uncommitted_blocks.get(&d).cloned() {
            if self.try_commit_if_ready(block).await? {
                debug!("Immediate commit");
            } else {
                // Will have requested in call to have_all_ancestors.
                debug!(
                    "Missing ancestor for commit-scheduled {:?} for round {}",
                    d, r
                );
            }
        } else {
            // Will have requested in call to get_block.
            debug!("Missing block for commit-scheduled {:?} for round {}", d, r);
        }
        debug!(
            "TIMING schedule_commit round={} digest={} total_ms={}",
            r,
            d,
            schedule_start.elapsed().as_millis()
        );
        Ok(())
    }

    fn has_voting_parent_delivered(&self, block: &Block) -> bool {
        block.parent == self.last_commit.digest()
            || self.uncommitted_blocks.contains_key(&block.parent)
    }

    fn voting_parent_block(&self, block: &Block) -> Option<Block> {
        if block.parent == self.last_commit.digest() {
            Some(self.last_commit.clone())
        } else {
            self.uncommitted_blocks.get(&block.parent).cloned()
        }
    }

    async fn sync_voting_parent(&mut self, block: &Block) -> ConsensusResult<()> {
        if !self.has_voting_parent_delivered(block) && !self.sync_requests.contains(&block.parent) {
            self.synchronizer
                .get_block(&block.parent, &block.author, None)
                .await?;
            self.sync_requests.insert(block.parent.clone());
        }
        Ok(())
    }

    fn has_required_certificates_for_normal_vote(&self, block: &Block) -> bool {
        let Some(parent) = self.voting_parent_block(block) else {
            return false;
        };
        parent.round + 1 == block.round
    }

    fn qc_availability_key(qc: &QC) -> (Round, Digest, Digest) {
        (qc.round, qc.blk_hash.clone(), qc.payload_root.clone())
    }

    async fn maybe_send_commit_vote(&mut self, qc: &QC) -> ConsensusResult<()> {
        if qc.kind != VoteType::Normal || qc.round <= self.last_commit.round {
            return Ok(());
        }

        let key = Self::qc_availability_key(qc);
        if !self.verified_normal_qcs.contains(&key) || self.sent_commit_votes.contains(&key) {
            return Ok(());
        }

        if !self.has_block_matching_qc(qc).await? {
            return Ok(());
        }

        self.send_ready_vote(qc.blk_hash.clone(), qc.payload_root.clone(), qc.round)
            .await
    }

    async fn has_block_matching_qc(&mut self, qc: &QC) -> ConsensusResult<bool> {
        let Some(block) = self.uncommitted_blocks.get(&qc.blk_hash).cloned() else {
            self.get_block(qc.blk_hash.clone(), qc.round).await?;
            return Ok(false);
        };
        ensure!(
            block.round == qc.round
                && block.digest() == qc.blk_hash
                && block.payload_root == qc.payload_root,
            ConsensusError::InvalidProof
        );
        if block.round == GENESIS {
            return Ok(false);
        }

        Ok(true)
    }

    async fn try_send_commit_votes(&mut self) -> ConsensusResult<()> {
        let mut qcs: Vec<QC> = self
            .uncommitted_qcs
            .values()
            .filter(|qc| qc.kind == VoteType::Normal)
            .cloned()
            .collect();
        qcs.sort_by_key(|qc| qc.round);

        for qc in qcs {
            self.maybe_send_commit_vote(&qc).await?;
        }
        Ok(())
    }

    async fn try_vote(&mut self) -> ConsensusResult<()> {
        let mut candidates: Vec<(Round, Digest)> = self
            .pending_proposals
            .iter()
            .filter(|(round, _)| **round > self.last_commit.round)
            .map(|(round, digest)| (*round, digest.clone()))
            .collect();
        candidates.sort_by_key(|(round, _)| *round);

        for (_, accepted) in candidates {
            let Some(b) = self.uncommitted_blocks.get(&accepted).cloned() else {
                continue;
            };

            let key = (b.round, accepted.clone(), b.payload_root.clone());
            if self.sent_normal_votes.contains(&key) {
                debug!(
                    "VOTE_BLOCKED reason=already_sent node={} round={} digest={}",
                    self.name, b.round, accepted
                );
                continue;
            }

            self.sync_voting_parent(&b).await?;

            if !self.has_voting_parent_delivered(&b) {
                debug!(
                    "VOTE_BLOCKED reason=missing_parent node={} round={} digest={} parent={}",
                    self.name, b.round, accepted, b.parent
                );
                continue;
            }

            if !self.has_required_certificates_for_normal_vote(&b) {
                debug!(
                    "VOTE_BLOCKED reason=missing_normal_vote_certs node={} round={} digest={} parent={}",
                    self.name, b.round, accepted, b.parent
                );
                continue;
            }

            let Some(proof) = self.pending_proofs.get(&accepted).cloned() else {
                debug!(
                    "VOTE_BLOCKED reason=missing_shard_proof node={} round={} digest={}",
                    self.name, b.round, accepted
                );
                continue;
            };

            debug!(
                "VOTE_READY node={} round={} digest={} payload_root={}",
                self.name, b.round, accepted, b.payload_root
            );
            self.sent_normal_votes.insert(key);
            self.send_prepare_vote(&b, proof).await?;
        }
        Ok(())
    }

    async fn advance_to_round(&mut self, round: Round) -> ConsensusResult<()> {
        if round > self.round {
            self.cleanup_proposals(round - 1).await;
            // Enter the new round.
            self.round = round;
            // Reset round timer and timeout after \tau.
            self.timer.reset();
            debug!("Moved to round {}", self.round);
            // Try to vote and propose.
            // Covers the case where we receive the proposal for r before the QC for r-1.
            self.try_vote().await?;
        }
        Ok(())
    }

    async fn send_vote(
        &mut self,
        b: Digest,
        payload_root: Digest,
        r: Round,
        t: VoteType,
        proof: Option<Proof>,
    ) -> ConsensusResult<()> {
        let total_start = Instant::now();
        let sign_start = Instant::now();
        let vote = Vote::new(
            self.name,
            b,
            payload_root,
            t.clone(),
            r,
            proof,
            &mut self.bls_signature_service,
        )
        .await;
        let sign_ms = sign_start.elapsed().as_millis();
        debug!("Created {} vote for round {} in {} ms", t, r, sign_ms);
        debug!("Created {:?}", vote);
        let vote_event = match vote.kind {
            VoteType::Normal => "nv_sent",
            VoteType::Commit => "cv_sent",
            VoteType::Decide => "dv_sent",
        };
        debug!(
            "TIMELINE event={} node={} round={} digest={} payload_root={}",
            vote_event, self.name, vote.round, vote.blk_hash, vote.payload_root
        );

        let local_handle_start = Instant::now();
        let _ = self.handle_vote(&vote).await;
        let local_handle_ms = local_handle_start.elapsed().as_millis();

        let broadcast_start = Instant::now();
        let broadcast_stats = self.broadcast_vote_ref(&vote).await;
        debug!(
            "TIMING vote_send kind={} round={} bytes={} peers={} sign_ms={} local_handle_ms={} address_ms={} serialize_ms={} enqueue_ms={} broadcast_total_ms={} total_ms={}",
            t,
            r,
            broadcast_stats.bytes,
            broadcast_stats.peers,
            sign_ms,
            local_handle_ms,
            broadcast_stats.address_ms,
            broadcast_stats.serialize_ms,
            broadcast_stats.enqueue_ms,
            broadcast_stats.total_ms,
            total_start.elapsed().as_millis()
        );
        debug!(
            "Scheduled {} vote broadcast for round {} in {} ms",
            t,
            r,
            broadcast_start.elapsed().as_millis()
        );

        Ok(())
    }

    async fn send_prepare_vote(&mut self, block: &Block, proof: Proof) -> ConsensusResult<()> {
        self.send_vote(
            block.digest(),
            block.payload_root.clone(),
            block.round,
            VoteType::Normal,
            Some(proof),
        )
        .await
    }

    async fn send_ready_vote(
        &mut self,
        block: Digest,
        payload_root: Digest,
        round: Round,
    ) -> ConsensusResult<()> {
        let key = (round, block.clone(), payload_root.clone());
        if !self.sent_commit_votes.insert(key) {
            return Ok(());
        }
        self.send_vote(block, payload_root, round, VoteType::Commit, None)
            .await
    }

    async fn send_decide_vote(
        &mut self,
        block: Digest,
        payload_root: Digest,
        round: Round,
    ) -> ConsensusResult<()> {
        let key = (round, block.clone(), payload_root.clone());
        if !self.sent_decide_votes.insert(key) {
            return Ok(());
        }
        self.send_vote(block, payload_root, round, VoteType::Decide, None)
            .await
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        warn!("Timeout reached for round {}", self.round);
        // In the no-signature Bracha path, NQC/CQC are local-only and cannot
        // justify Hydrangea timeout-sync or fallback recovery messages.
        self.timer.reset();
        Ok(())
    }

    #[async_recursion]
    async fn handle_vote(&mut self, vote: &Vote) -> ConsensusResult<()> {
        let handle_start = Instant::now();
        debug!("Received {:?}", vote);
        if vote.round > self.last_commit.round {
            debug!("Processing {:?}", vote);
            match vote.kind {
                VoteType::Decide => {
                    let aggregate_start = Instant::now();
                    if let Some(mut qc) = self.aggregator.add_decide_vote(vote.clone())? {
                        debug!(
                            "TIMING decide_qc_formed round={} aggregate_ms={}",
                            qc.round,
                            aggregate_start.elapsed().as_millis()
                        );
                        debug!("Assembled {:?}", qc);
                        self.attach_block_to_qc(&mut qc);
                        self.handle_decide_qc(&qc).await?;
                    }
                }
                VoteType::Commit => {
                    let aggregate_start = Instant::now();
                    let outcome = self.aggregator.add_ready_vote(vote.clone())?;
                    if let Some((round, block, payload_root)) = outcome.relay {
                        debug!(
                            "TIMING ready_relay round={} aggregate_ms={}",
                            round,
                            aggregate_start.elapsed().as_millis()
                        );
                        self.send_ready_vote(block, payload_root, round).await?;
                    }
                    if let Some(mut qc) = outcome.quorum {
                        debug!(
                            "TIMING cqc_formed round={} aggregate_ms={}",
                            qc.round,
                            aggregate_start.elapsed().as_millis()
                        );
                        debug!("Assembled {:?}", qc);
                        self.attach_block_to_qc(&mut qc);
                        self.handle_ready_qc(&qc).await?;
                    }
                }
                VoteType::Normal => {
                    let aggregate_start = Instant::now();
                    if let Some((mut qc, shards)) = self.aggregator.add_normal_vote(vote.clone())? {
                        let aggregate_ms = aggregate_start.elapsed().as_millis();
                        debug!("Assembled {:?}", qc);
                        let key = Self::qc_availability_key(&qc);
                        self.uncommitted_qcs
                            .entry(qc.round)
                            .or_insert_with(|| qc.clone());
                        if self.started_nqc_verify.insert(key) {
                            // Vote accumulation path: verify both the aggregate BLS signature
                            // and that the collected shards interpolate to the committed payload
                            // root (verify_interpolation per the protocol spec) before sending a
                            // commit vote.
                            self.start_nqc_verification(
                                qc.clone(),
                                shards,
                                aggregate_ms,
                                "local_nqc",
                            );
                        }
                        self.attach_block_to_qc(&mut qc);
                    }
                }
            }
            // Add the new vote to our aggregator and see if we have a quorum.
            // Validation is done inside the aggregator.
            // if let Some(qc) = self.aggregator.add_normal_vote(vote.clone())? {
            //     debug!("Assembled {:?}", qc);
            //     self.handle_qc(&qc).await?;
            // }
        }
        let handle_ms = handle_start.elapsed().as_millis();
        if handle_ms >= 10 {
            debug!(
                "TIMING handle_vote_slow kind={} round={} digest={} total_ms={}",
                vote.kind, vote.round, vote.blk_hash, handle_ms
            );
        }
        Ok(())
    }

    async fn propose_if_leader(&mut self, r: Round, trigger: ProposalTrigger) {
        if self.name == self.leader_elector.get_leader(r) && self.proposal_triggers_sent.insert(r) {
            self.tx_proposer
                .send(ProposerMessage::Propose(trigger))
                .await
                .expect("Failed to send message to proposer");
        }
    }

    async fn cleanup_proposals(&mut self, r: Round) {
        // Stop trying to deliver proposals for all rounds up to and including this round.
        // Invocation of this function upon entering a new round (i.e. upon QC or TC
        // observation) prevents Byzantine nodes from draining our resources by never
        // ACKing proposals.
        self.tx_proposer
            .send(ProposerMessage::Cleanup(r))
            .await
            .expect("Failed to send message to proposer");
        self.proposal_triggers_sent.retain(|round| round > &r);
        self.commit_qcs
            .retain(|round, _| round >= &r.saturating_sub(2));
    }

    async fn propose_parent(&mut self, parent: Block) {
        self.propose_if_leader(parent.round + 1, ProposalTrigger::Parent { parent })
            .await
    }

    async fn propose_optimistic_child(&mut self, parent: &Block) {
        if parent.round == GENESIS {
            return;
        }
        let commit_qc_round = parent.round.saturating_sub(2);
        if !self.commit_qcs.contains_key(&commit_qc_round) {
            return;
        };
        self.propose_parent(parent.clone()).await
    }

    async fn propose_optimistic_children_waiting_on_commit_qc(&mut self, qc_round: Round) {
        let parent_round = qc_round + 2;
        let parents: Vec<Block> = self
            .uncommitted_blocks
            .values()
            .filter(|block| block.round == parent_round)
            .cloned()
            .collect();
        for parent in parents {
            self.propose_optimistic_child(&parent).await;
        }
    }

    async fn observe_payload(&mut self, _block: &Block) -> ConsensusResult<()> {
        self.tx_proposer
            .send(ProposerMessage::Observed(Vec::new()))
            .await
            .expect("Failed to send message to proposer");
        Ok(())
    }

    fn consensus_message_label(message: &ConsensusMessage) -> String {
        match message {
            ConsensusMessage::Propose(proposal) => Self::proposal_message_label(proposal),
            ConsensusMessage::Vote(vote) => format!(
                "Vote({}),round={},digest={},root={}",
                vote.kind, vote.round, vote.blk_hash, vote.payload_root
            ),
            ConsensusMessage::VerifiedVote(vote) => format!(
                "VerifiedVote({}),round={},digest={},root={}",
                vote.kind, vote.round, vote.blk_hash, vote.payload_root
            ),
            ConsensusMessage::SyncRequest(digest, _) => format!("SyncRequest,digest={}", digest),
            ConsensusMessage::SyncResponse(block) => {
                format!(
                    "SyncResponse,round={},digest={}",
                    block.round,
                    block.digest()
                )
            }
            ConsensusMessage::ShardRequest(request) => format!(
                "ShardRequest,digest={},root={},index={}",
                request.block, request.payload_root, request.index
            ),
            ConsensusMessage::ShardResponse(response) => format!(
                "ShardResponse,digest={},root={},index={}",
                response.block,
                response.payload_root,
                response.proof.index()
            ),
        }
    }

    fn proposal_message_label(proposal: &ProposalMessage) -> String {
        match proposal {
            ProposalMessage::N(proposal) => format!(
                "Propose(Normal),round={},digest={}",
                proposal.block.round,
                proposal.block.digest()
            ),
        }
    }

    fn log_core_dispatch(label: &str, handle_ms: u128) {
        if handle_ms >= 10 {
            debug!(
                "TIMING core_dispatch label={} handle_ms={}",
                label, handle_ms
            );
        } else {
            debug!(
                "TIMING core_dispatch label={} handle_ms={}",
                label, handle_ms
            );
        }
    }

    // NQC verification: BLS aggregate verify + RS reconstruction (verify_interpolation
    // per the protocol spec). Sends result to rx_nqc_verify; commit vote is only sent
    // once both checks pass.
    fn start_nqc_verification(
        &self,
        qc: QC,
        shards: Vec<Option<Box<[u8]>>>,
        aggregate_ms: u128,
        source: &'static str,
    ) {
        let tx = self.tx_nqc_verify.clone();
        let committee = self.committee.clone();
        let payload_root = qc.payload_root.clone();
        let data_shards = (committee.n - 2 * committee.f) as usize;
        let parity_shards = (2 * committee.f) as usize;
        let rs_block_size = self.rs_block_size;
        let rs_block_threads = self.rs_block_threads;
        tokio::task::spawn_blocking(move || {
            let bls_start = StdInstant::now();
            let bls_ok = qc.is_well_formed(&committee).is_ok();
            let bls_verify_ms = bls_start.elapsed().as_millis();
            if !bls_ok {
                let _ = tx.blocking_send(NqcVerifyResult {
                    qc,
                    ok: false,
                    aggregate_ms,
                    bls_verify_ms,
                    reconstruct_ms: 0,
                    source,
                });
                return;
            }

            let recon_start = StdInstant::now();
            let rs_ok = if shards.is_empty() {
                true
            } else {
                match check_availability_sync(
                    payload_root.clone(),
                    shards,
                    data_shards,
                    parity_shards,
                    rs_block_size,
                    rs_block_threads,
                ) {
                    Ok(_) => true,
                    Err(e) => {
                        warn!(
                            "NQC availability check failed payload_root={}: {}",
                            payload_root, e
                        );
                        false
                    }
                }
            };
            let reconstruct_ms = recon_start.elapsed().as_millis();

            let _ = tx.blocking_send(NqcVerifyResult {
                qc,
                ok: rs_ok,
                aggregate_ms,
                bls_verify_ms,
                reconstruct_ms,
                source,
            });
        });
    }

    async fn handle_ready_qc(&mut self, qc: &QC) -> ConsensusResult<()> {
        let start = Instant::now();
        self.store_qc_block(qc).await?;
        let key = Self::qc_availability_key(qc);
        self.commit_qcs
            .entry(qc.round)
            .or_insert_with(|| qc.clone());

        if self.verified_normal_qcs.contains(&key) {
            self.send_decide_vote(qc.blk_hash.clone(), qc.payload_root.clone(), qc.round)
                .await?;
        } else {
            self.request_availability_shards(qc).await?;
        }

        self.propose_optimistic_children_waiting_on_commit_qc(qc.round)
            .await;
        self.advance_to_round(qc.round + 1).await?;
        self.try_vote().await?;
        debug!(
            "TIMING handle_ready_qc round={} digest={} total_ms={}",
            qc.round,
            qc.blk_hash,
            start.elapsed().as_millis()
        );
        Ok(())
    }

    async fn handle_decide_qc(&mut self, qc: &QC) -> ConsensusResult<()> {
        let start = Instant::now();
        self.store_qc_block(qc).await?;
        self.schedule_commit(qc).await?;
        self.aggregator.cleanup_prepares(&qc.round);
        debug!(
            "TIMING handle_decide_qc round={} digest={} total_ms={}",
            qc.round,
            qc.blk_hash,
            start.elapsed().as_millis()
        );
        Ok(())
    }

    fn is_non_equivocal_and_certifiable(&self, block: &Block) -> bool {
        !self.pending_proposals.contains_key(&block.round)
    }

    async fn can_accept_block(&mut self, block: &Block) -> ConsensusResult<bool> {
        let digest = block.digest();

        if block.round <= self.last_commit.round {
            // Old block.
            return Ok(false);
        }

        if self.sync_requests.remove(&digest) {
            // Was waiting to sync this block so have already received a QC for it.
            return Ok(true);
        }

        if let Some(qc) = self.uncommitted_qcs.get(&block.round) {
            // In the Bracha path, votes can arrive before the proposal frame is
            // processed. If the local NQC is for this block, accept the delayed
            // block now; otherwise this round already certified a different block.
            return Ok(qc.blk_hash == digest);
        }

        // Ensure that the block proposer is the leader of block.round.
        // TODO: This should yield an error log, not panic.
        ensure!(
            block.author == self.leader_elector.get_leader(block.round),
            ConsensusError::WrongLeader {
                digest,
                leader: block.author,
                round: block.round
            }
        );

        // TODO: REVIEW THIS. Should actually return false if verify fails because it means
        // that we are missing a batch. However, don't actually need Narwhal at all for the PoC,
        // so could just remove all non-consensus-only features.
        if !self.consensus_only {
            // Check that the payload certificates are valid.
            // self.mempool_driver.verify(block).await?;
        }

        // Block has a valid payload.
        Ok(self.is_non_equivocal_and_certifiable(block))
    }

    async fn process_block(&mut self, block: &Block, proof: Option<Proof>) -> ConsensusResult<()> {
        debug!("Received Block {:?}", block);

        if self.can_accept_block(block).await? {
            self.store_block(block, proof).await;
            self.advance_to_round(block.round).await?;
            self.try_vote().await?;
            self.try_commit_or_sync_ancestor(block).await?;
            self.propose_optimistic_child(block).await;
        }
        self.try_send_commit_votes().await?;
        Ok(())
    }

    async fn process_normal_proposal(&mut self, p: NormalProposal) -> ConsensusResult<()> {
        debug!("Received Normal Proposal {:?}", p); // Ensure embedded QC is valid. TODO: Remove panics.
                                                    // Ensure:
                                                    //   1. Proposer has voting rights.
                                                    //   2. Block is signed by the proposer.
        p.is_well_formed(&self.committee)?;
        ensure!(
            p.proof.index() == self.committee.id(&self.name) as usize,
            ConsensusError::InvalidProof
        );
        let proof = p.proof.clone();
        self.process_block(&p.block, Some(proof)).await
    }

    async fn handle_proposal(&mut self, proposal: ProposalMessage) -> ConsensusResult<()> {
        match proposal {
            ProposalMessage::N(n) => self.process_normal_proposal(n).await,
        }
    }

    async fn handle_sync_response(&mut self, block: Block) -> ConsensusResult<()> {
        debug!(
            "Received SyncResponse from peer containing block {:?}",
            block
        );
        let digest = block.digest();
        // Ensure that we were waiting for this block and have not already received
        // it via another channel (e.g. a late Proposal).
        if self.sync_requests.remove(&digest) && block.round > self.last_commit.round {
            // Store the block.
            //
            // If we requested this block via have_all_ancestors then this will trigger the
            // Synchronizer to send the latest LDC descendent of this block to us again via
            // the loopback channel so we can resume searching for missing ancestors.
            //
            // If we requested this block via get_block then we will start recursively syncing
            // ancestors if it is LDC. If this block (B) is LDC but we are already in the process
            // or syncing the ancestors of a higher LDC block (B'), then we will replace B with
            // B' as the block to yield upon receiving any subsequently-requested missing ancestor
            // (B_a) when the Synchronizer sends B' to us via loopback, which will trigger a
            // second SyncRequest for B_a (unless we get B_a before making this second request,
            // which should not happen when network latency is non-trivial).
            self.store_block(&block, None).await;
            self.try_commit_or_sync_ancestor(&block).await?;
            self.try_vote().await?;
        }
        Ok(())
    }

    async fn handle_synchronizer_loopback(&mut self, block: Block) -> ConsensusResult<()> {
        debug!(
            "Reprocessing of block {:?} triggered by Synchronizer",
            block
        );
        // The Synchronizer will only ever send us certified blocks that satisfy the commit
        // rule (i.e. blocks that are LDC) because we only ever request a loopback when we
        // are syncing blocks as a part of have_all_ancestors, which we only ever call with
        // LDC blocks. We will have already stored this block when we first received it.
        // We now re-process it to check if the chain of ancestors in now complete, as
        // long as we have not already committed it.
        if block.round > self.last_commit.round {
            self.try_commit_or_sync_ancestor(&block).await?;
        }
        Ok(())
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
        // Also, schedule a timer in case we don't hear from the leader.
        self.timer.reset();
        self.propose_parent(Block::genesis()).await;

        // This is the main loop: it processes incoming blocks, votes and QCs,
        // and receives timeout notifications from our Timeout Manager.
        loop {
            let result = tokio::select! {
                biased;
                Some(sends) = self.rx_proposal_net.recv() => {
                    for (addr, bytes, label) in sends {
                        let _ = self.network.send_with_label(addr, bytes, Some(label)).await;
                    }
                    Ok(())
                },
                Some(result) = self.rx_nqc_verify.recv() => {
                    if result.ok {
                        let qc = result.qc;
                        debug!(
                            "TIMING nqc_verified round={} aggregate_ms={} bls_verify_ms={} reconstruct_ms={}",
                            qc.round, result.aggregate_ms, result.bls_verify_ms, result.reconstruct_ms
                        );
                        self.verified_normal_qcs.insert(Self::qc_availability_key(&qc));
                        match qc.kind {
                            VoteType::Normal => match self.maybe_send_commit_vote(&qc).await {
                                Ok(()) => self.try_commit_verified_blocks().await,
                                Err(e) => Err(e),
                            },
                            VoteType::Commit => {
                                self.send_decide_vote(
                                    qc.blk_hash.clone(),
                                    qc.payload_root.clone(),
                                    qc.round,
                                )
                                .await
                            }
                            VoteType::Decide => self.try_commit_verified_blocks().await,
                        }
                    } else {
                        warn!(
                            "NQC verification failed round={} digest={}",
                            result.qc.round, result.qc.blk_hash
                        );
                        Ok(())
                    }
                },
                Some(proposal) = self.rx_proposer.recv() => {
                    let label = Self::proposal_message_label(&proposal);
                    let handle_start = Instant::now();
                    let result = self.handle_proposal(proposal).await;
                    Self::log_core_dispatch(&label, handle_start.elapsed().as_millis());
                    result
                },
                Some(block) = self.rx_synchronizer.recv() =>
                    self.handle_synchronizer_loopback(block).await,
                Some(message) = self.rx_message.recv() =>
                {
                    let label = Self::consensus_message_label(&message);
                    let handle_start = Instant::now();
                    let result = match message {
                        ConsensusMessage::Propose(proposal) => self.handle_proposal(proposal).await,
                        ConsensusMessage::SyncResponse(block) => self.handle_sync_response(block).await,
                        ConsensusMessage::ShardRequest(request) => self.handle_shard_request(request).await,
                        ConsensusMessage::ShardResponse(response) => self.handle_shard_response(response).await,
                        ConsensusMessage::Vote(vote) => self.handle_vote(&vote).await,
                        _ => panic!("Unexpected protocol message")
                    };
                    Self::log_core_dispatch(&label, handle_start.elapsed().as_millis());
                    result
                },
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
