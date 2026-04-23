use crate::config::Committee;
use crate::consensus::{ConsensusMessage, CHANNEL_CAPACITY};
use crate::error::ConsensusResult;
use crate::messages::Block;
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use futures::future::BoxFuture;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use futures::FutureExt;
use log::{debug, error};
use network::SimpleSender;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time::{sleep, Duration, Instant};

#[cfg(test)]
#[path = "tests/synchronizer_tests.rs"]
pub mod synchronizer_tests;

const TIMER_ACCURACY: u64 = 5_000;

#[derive(Debug)]
pub enum SyncMessage {
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
            let mut waiting: FuturesUnordered<BoxFuture<'static, ConsensusResult<Block>>> =
                FuturesUnordered::new();
            let mut pending = HashSet::new();
            let mut requests = HashMap::new();

            let timer = sleep(Duration::from_millis(TIMER_ACCURACY));
            tokio::pin!(timer);
            loop {
                tokio::select! {
                    Some(message) = rx_inner.recv() => match message {
                        SyncMessage::Digest(digest, author, responder) =>
                        {
                            if pending.insert(digest.clone()) {
                                let store_for_fut = store_copy.clone();
                                let d_for_fut = digest.clone();
                                let fut = async move {
                                    let res = Self::waiter(store_for_fut, d_for_fut.clone()).await;
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
                                    let address = committee
                                        .address(&author)
                                        .expect("Author of valid block is not in the committee");
                                    let message = ConsensusMessage::SyncRequest(digest.clone(), name);
                                    let message = bincode::serialize(&message)
                                        .expect("Failed to serialize sync request");
                                    network.send(address, Bytes::from(message)).await;
                                }
                            }
                        }
                    },
                    Some(result) = waiting.next() => match result {
                        Ok(block) => {
                            let _ = pending.remove(&block.digest());
                            let _ = requests.remove(&block.digest());
                            if let Err(e) = tx_loopback.send(block).await {
                                panic!("Failed to send message through core channel: {}", e);
                            }
                        },
                        Err(e) => error!("{}", e)
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

    async fn waiter(mut store: Store, wait_on: Digest) -> ConsensusResult<Block> {
        let bytes = store.notify_read(wait_on.to_vec()).await?;
        Ok(bincode::deserialize(&bytes)?)
    }

    pub async fn get_block(
        &mut self,
        digest: &Digest,
        author: &PublicKey,
    ) -> ConsensusResult<Option<Block>> {
        if digest == &Digest::default() {
            return Ok(Some(Block::genesis()));
        }
        match self.store.read(digest.to_vec()).await? {
            Some(bytes) => {
                debug!("Found block {} in local store", digest);
                Ok(Some(bincode::deserialize(&bytes)?))
            }
            None => {
                debug!("Block {} missing locally; requesting sync", digest);
                let (tx, _rx) = oneshot::channel();
                if let Err(e) = self
                    .inner_channel
                    .send(SyncMessage::Digest(digest.clone(), author.clone(), tx))
                    .await
                {
                    panic!("Failed to send request to synchronizer: {}", e);
                }
                Ok(None)
            }
        }
    }

    #[cfg(test)]
    pub async fn get_parent_block(&mut self, block: &Block) -> ConsensusResult<Option<Block>> {
        self.get_block(block.parent(), &block.author).await
    }
}
