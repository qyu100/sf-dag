use crate::config::{Committee, Stake};
use crate::consensus::{ConsensusMessage, Round};
use crate::messages::{Block};
use bytes::Bytes;
use crypto::{Digest, PublicKey, SignatureService};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use log::{debug, info};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashSet, HashMap};
use tokio::sync::mpsc::{Receiver, Sender};

#[derive(Debug)]
pub enum ProposerMessage {
    Make(Round),
    Cleanup(Vec<Digest>),
    Parent((Round,Block)),
}

pub struct Proposer {
    name: PublicKey,
    committee: Committee,
    signature_service: SignatureService,
    rx_mempool: Receiver<Digest>,
    rx_message: Receiver<ProposerMessage>,
    tx_loopback: Sender<Block>,
    buffer: HashSet<Digest>,
    network: ReliableSender,
    last_parent: HashMap<Round, Block>,
}

impl Proposer {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        rx_mempool: Receiver<Digest>,
        rx_message: Receiver<ProposerMessage>,
        tx_loopback: Sender<Block>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                signature_service,
                rx_mempool,
                rx_message,
                tx_loopback,
                buffer: HashSet::new(),
                network: ReliableSender::new(),
                last_parent: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    /// Helper function. It waits for a future to complete and then delivers a value.
    async fn waiter(wait_for: CancelHandler, deliver: Stake) -> Stake {
        let _ = wait_for.await;
        deliver
    }

    async fn make_block(&mut self, round: Round) {
        debug!("Buffer size: {}", self.buffer.len());
        // Find the most recent non-genesis parent starting from round-1 and produce its digest.
        let parent: Digest = if round != 1 {
            debug!("last_parent = {:?}", self.last_parent);
            let r_found_opt = (0..round)
                .rev()
                .find(|r| {
                    self.last_parent
                        .get(r)
                        .map_or(false, |b| b.id != Digest::default())
                });

            // If we didn't find a non-genesis parent, fall back to the smallest stored round
            // (or 0 if none). This avoids panics when last_parent doesn't contain a non-genesis block.
            let r_found = match r_found_opt {
                Some(r) => r,
                None => match self.last_parent.keys().min().cloned() {
                    Some(min_r) => min_r,
                    None => 0,
                },
            };

            // Extract the parent digest from the found block (or default if missing).
            let parent_digest = self
                .last_parent
                .get(&r_found)
                .map(|b| b.id.clone())
                .unwrap_or_else(Digest::default);
            debug!("Found parent at round {}: {:?}", r_found, parent_digest);
            // Clear stored last_parent entries up to the found round to free memory,
            // but only remove entries that are not the default digest.
            for r in 0..=r_found.saturating_sub(1) {
                if let Some(b) = self.last_parent.get(&r) {
                    if b.id != Digest::default() {
                        self.last_parent.remove(&r);
                    }
                }
            }
            parent_digest
        } else {
            Digest::default()
        };
        // Generate a new block.
        let block = Block::new(
            self.name,
            round,
            /* payload */ self.buffer.drain().collect(),
            parent
        )
        .await;
        if !block.payload.is_empty() {
            debug!("Created {}", block);
            #[cfg(feature = "benchmark")]
            for x in &block.payload {
                // NOTE: This log entry is used to compute performance.
                info!("Created {} -> {:?}", block, x);
            }
        }
        debug!("Created {:?}", block);

        // Broadcast our new block.
        debug!("Broadcasting block {:?}", block);
        let (names, addresses): (Vec<_>, _) = self
            .committee
            .broadcast_addresses(&self.name)
            .iter()
            .cloned()
            .unzip();
        let message = bincode::serialize(&ConsensusMessage::Propose(block.clone()))
            .expect("Failed to serialize block");
        let handles = self
            .network
            .broadcast(addresses, Bytes::from(message))
            .await;

        // Send our block to the core for processing.
        debug!("Proposer: about to send block to core (round {})", round);
        self.tx_loopback
            .send(block)
            .await
            .expect("Failed to send block");
        debug!("Proposer: sent block to core (round {})", round);

        // Control system: Wait for 2f+1 nodes to acknowledge our block before continuing.
        let mut wait_for_quorum: FuturesUnordered<_> = names
            .into_iter()
            .zip(handles.into_iter())
            .map(|(name, handler)| {
                let stake = self.committee.stake(&name);
                Self::waiter(handler, stake)
            })
            .collect();

        let mut total_stake = self.committee.stake(&self.name);
        while let Some(stake) = wait_for_quorum.next().await {
            total_stake += stake;
            if total_stake >= self.committee.quorum_threshold() {
                break;
            }
        }
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(digest) = self.rx_mempool.recv() => {
                    //if self.buffer.len() < 155 {
                        self.buffer.insert(digest);
                        debug!("Proposer received digest buffer size {}", self.buffer.len())
                    //}
                },
                Some(message) = self.rx_message.recv() => match message {
                    ProposerMessage::Make(round) => self.make_block(round).await,
                    ProposerMessage::Parent((round, block)) => {
                        debug!("Proposer received parent block for round {}: {:?}", round, block);
                        self.last_parent.insert(round, block);
                    }
                    ProposerMessage::Cleanup(digests) => {
                        debug!("buffer size before cleanup: {}", self.buffer.len());
                        for x in &digests {
                            self.buffer.remove(x);
                        }
                        debug!("buffer size after cleanup: {}", self.buffer.len());
                    }
                }
            }
        }
    }
}
