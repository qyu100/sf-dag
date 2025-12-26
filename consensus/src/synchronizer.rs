use crate::config::Committee;
use crate::consensus::{ConsensusMessage, CHANNEL_CAPACITY};
use crate::error::{ConsensusResult, ConsensusError};
use crate::messages::{Block, QC};
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use futures::future::BoxFuture;
use futures::FutureExt;
use log::{debug, error};
use network::SimpleSender;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

#[cfg(test)]
#[path = "tests/synchronizer_tests.rs"]
pub mod synchronizer_tests;

const TIMER_ACCURACY: u64 = 5_000;

#[derive(Debug)]
pub enum SyncMessage {
    Block(Block, oneshot::Sender<ConsensusResult<Block>>),
    Digest(Digest, PublicKey, oneshot::Sender<ConsensusResult<Block>>),
}

pub struct Synchronizer {
    store: Store,
    inner_channel: Sender<SyncMessage>,
}

impl Synchronizer {
    pub fn new(
        name: PublicKey,
        committee: Committee,
        store: Store,
        tx_loopback: Sender<Block>,
        sync_retry_delay: u64,
    ) -> Self {
        let mut network = SimpleSender::new();
        let (tx_inner, mut rx_inner): (_, Receiver<SyncMessage>) = channel(CHANNEL_CAPACITY);

        let store_copy = store.clone();
        tokio::spawn(async move {
            let mut waiting: FuturesUnordered<BoxFuture<'static, ConsensusResult<Block>>> = FuturesUnordered::new();
            let mut pending = HashSet::new();
            let mut requests = HashMap::new();

            let timer = sleep(Duration::from_millis(TIMER_ACCURACY));
            tokio::pin!(timer);
            loop {
                tokio::select! {
                    Some(message) = rx_inner.recv() => match message {
                        SyncMessage::Block(block, responder) =>
                        {
                            // Always create a waiter future that will reply to the requester when ready.
                            let parent = block.parent.clone();
                            let store_for_fut = store_copy.clone();
                            let parent_for_fut = parent.clone();
                            let block_for_fut = block.clone();
                            let fut = async move {
                                let res = Self::waiter(store_for_fut, parent_for_fut.clone(), block_for_fut).await;
                                if let Ok(b) = &res {
                                    let _ = responder.send(Ok(b.clone()));
                                }
                                res
                            };
                            waiting.push(fut.boxed());

                            // Only mark as pending / broadcast on the first request for this block
                            if pending.insert(parent.clone()) {
                                if !requests.contains_key(&parent){
                                    debug!("Requesting sync for parent {}", parent);
                                    let now = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .expect("Failed to measure time")
                                        .as_millis();
                                    requests.insert(parent.clone(), now);
                                    let addresses = committee
                                        .broadcast_addresses(&name)
                                        .into_iter()
                                        .map(|(_, x)| x)
                                        .collect();
                                    let message = ConsensusMessage::SyncRequest(parent.clone(), name);
                                    let message = bincode::serialize(&message)
                                        .expect("Failed to serialize sync request");
                                    network.broadcast(addresses, Bytes::from(message)).await;
                                }
                            }
                        },
                        SyncMessage::Digest(digest, leader, responder) =>
                        {
                            if pending.insert(digest.clone()) {
                                let store_for_fut = store_copy.clone();
                                let d_for_fut = digest.clone();
                                let fut = async move {
                                    let res = Self::waiter_digest(store_for_fut, d_for_fut.clone()).await;
                                    if let Ok(b) = &res {
                                        let _ = responder.send(Ok(b.clone()));
                                    }
                                    res
                                };
                                waiting.push(fut.boxed());

                                if !requests.contains_key(&digest){
                                    debug!("Requesting sync for block {}", digest);
                                    let now = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .expect("Failed to measure time")
                                        .as_millis();
                                    requests.insert(digest.clone(), now);
                                    let addresses = committee
                                        .broadcast_addresses(&name)
                                        .into_iter()
                                        .map(|(_, x)| x)
                                        .collect();
                                    let message = ConsensusMessage::SyncRequest(digest.clone(), name);
                                    let message = bincode::serialize(&message)
                                        .expect("Failed to serialize sync request");
                                    network.broadcast(addresses, Bytes::from(message)).await;
                                }
                            }
                        }
                    },
                    Some(result) = waiting.next() => {
                        debug!("Synchronizer received block {:?} from waiter", result);
                        match result {
                        Ok(block) => {
                            let _ = pending.remove(&block.digest());
                            let _ = requests.remove(&block.digest());
                            if let Err(e) = tx_loopback.send(block).await {
                                panic!("Failed to send message through core channel: {}", e);
                            }
                        },
                        Err(e) => error!("{}", e)
                    }
                    },
                    () = &mut timer => {
                        // This implements the 'perfect point to point link' abstraction.
                        for (digest, timestamp) in &requests {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Failed to measure time")
                                .as_millis();
                            if timestamp + (sync_retry_delay as u128) < now {
                                debug!("Requesting sync for block {} (retry)", digest);
                                let addresses = committee
                                    .broadcast_addresses(&name)
                                    .into_iter()
                                    .map(|(_, x)| x)
                                    .collect();
                                let message = ConsensusMessage::SyncRequest(digest.clone(), name);
                                let message = bincode::serialize(&message)
                                    .expect("Failed to serialize sync request");
                                network.broadcast(addresses, Bytes::from(message)).await;
                            }
                        }
                        timer.as_mut().reset(Instant::now() + Duration::from_millis(TIMER_ACCURACY));
                    }
                }
            }
        });
        Self {
            store,
            inner_channel: tx_inner,
        }
    }

    async fn waiter(mut store: Store, wait_on: Digest, deliver: Block) -> ConsensusResult<Block> {
        let notify_res = store.notify_read(wait_on.to_vec()).await?;
        match store.read(wait_on.to_vec()).await? {
            Some(bytes) => {
                Ok(bincode::deserialize(&bytes)?)
            },
            None => {
                Err(ConsensusError::MalformedBlock(wait_on))
            }
        }
    }

    async fn waiter_digest(mut store: Store, wait_on: Digest) -> ConsensusResult<Block> {
        let _ = store.notify_read(wait_on.to_vec()).await?;
        match store.read(wait_on.to_vec()).await? {
            Some(bytes) => {
                Ok(bincode::deserialize(&bytes)?)
            },
            None => {
                Err(ConsensusError::MalformedBlock(wait_on))
            }
        }
    }

    pub async fn get_block(&mut self, digest: &Digest, leader: &PublicKey) -> ConsensusResult<Option<Block>> {
        match self.store.read(digest.to_vec()).await? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => {
                let (tx, _rx) = oneshot::channel();
                if let Err(e) = self.inner_channel.send(SyncMessage::Digest(digest.clone(), leader.clone(), tx)).await {
                    panic!("Failed to send request to synchronizer: {}", e);
                }
                debug!("Requested synchronizer to fetch block {} (non-blocking)", digest);
                Ok(None)
            }
        }
    }
    
    pub async fn get_parent_block(&mut self, block: &Block) -> ConsensusResult<Option<Block>> {
        debug!("Getting parent block {:?}", block.parent);
        if block.round < 2 {
            return Ok(Some(Block::genesis()));
        }
        let parent = block.parent.clone();
        match self.store.read(parent.to_vec()).await? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => {
                // Send a non-blocking request to the synchronizer and return None immediately.
                // The synchronizer will push the block back into core via tx_loopback when available.
                let (tx, _rx) = oneshot::channel();
                if let Err(e) = self.inner_channel.send(SyncMessage::Block(block.clone(), tx)).await {
                    panic!("Failed to send request to synchronizer: {}", e);
                }
                Ok(None)
            }
        }
    }

    pub async fn get_ancestors(
        &mut self,
        block: &Block,
    ) -> ConsensusResult<Option<(Block)>> {
        let parent = match self.get_parent_block(block).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        Ok(Some((parent)))
    }
}
