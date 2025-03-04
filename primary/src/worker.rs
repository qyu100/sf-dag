use async_trait::async_trait;
use bytes::Bytes;
use config::{Committee, Parameters, WorkerId};
use crypto::{Digest, PublicKey};
use log::info;
use network::{MessageHandler, Receiver, Writer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Sender, Receiver as TokioReceiver};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration, Instant};

/// The default channel capacity for each channel of the worker.
pub const CHANNEL_CAPACITY: usize = 1_000;

pub type Round = u64;
pub type Transaction = Vec<u8>;
pub type Batch = Vec<Transaction>;

pub struct Worker {
    /// The public key of this authority.
    name: PublicKey,
    /// The id of this worker.
    id: WorkerId,
    /// The committee information.
    committee: Committee,
    /// The configuration parameters.
    parameters: Parameters,
    batch_size: usize,
    max_batch_delay: u64,
    batch_handler: BatchHandler,
}

impl Worker {
    pub fn spawn(
        name: PublicKey,
        id: WorkerId,
        committee: Committee,
        parameters: Parameters,
        batch_size: usize,
        max_batch_delay: u64,
    ) -> Worker {
        let (tx_reset, mut rx_reset) = channel::<()>(1);
        let batch_state = Arc::new(Mutex::new(BatchState {
            current_batch: Batch::with_capacity(batch_size * 2),
            current_batch_size: 0,
            batch_buffer: Vec::new(),
        }));

        let batch_handler = BatchHandler {
            state: batch_state.clone(),
            batch_size,
            max_batch_delay,
            tx_reset: tx_reset.clone(),
        };

        let worker = Self {
            name,
            id,
            committee,
            parameters,
            batch_size,
            max_batch_delay,
            batch_handler, 
        };

        worker.run(batch_state, tx_reset, rx_reset);

        info!(
            "Worker {} successfully booted on {}",
            id,
            worker
                .committee
                .worker(&worker.name, &worker.id)
                .expect("Our public key or worker id is not in the committee")
                .transactions
                .ip()
        );
        worker
    }

    fn run(&self, batch_state: Arc<Mutex<BatchState>>, tx_reset: Sender<()>, mut rx_reset: TokioReceiver<()>) {
        let mut address = self
            .committee
            .worker(&self.name, &self.id)
            .expect("Our public key or worker id is not in the committee")
            .transactions;
        address.set_ip("0.0.0.0".parse().unwrap());
        Receiver::spawn(address, self.batch_handler.clone());

        info!(
            "Worker {} listening to client transactions on {}",
            self.id, address
        );

        tokio::spawn({
            let state = batch_state;
            let max_batch_delay = self.max_batch_delay;
            async move {
                loop {
                    let timer = sleep(Duration::from_millis(max_batch_delay));
                    tokio::pin!(timer);
                    tokio::select! {
                        () = &mut timer => {
                            let mut state = state.lock().await;
                            if !state.current_batch.is_empty() {
                                state.seal().await;
                            }
                        },
                        Some(()) = rx_reset.recv() => { }
                    }
                    tokio::task::yield_now().await;
                }
            }
        });
    }

    pub fn get_batch_handler(&self) -> BatchHandler {
        self.batch_handler.clone()
    }
}

#[derive(Clone)]
pub struct BatchState {
    current_batch: Batch,
    current_batch_size: usize,
    batch_buffer: Vec<Batch>,
}

impl BatchState {
    async fn seal(&mut self) {
        let batch: Vec<Transaction> = self.current_batch.drain(..).collect();
        self.current_batch_size = 0;
        self.batch_buffer.push(batch);
    }
}

/// Defines how the network receiver handles incoming transactions.
#[derive(Clone)]
pub struct BatchHandler {
    state: Arc<Mutex<BatchState>>,
    batch_size: usize,
    max_batch_delay: u64,
    tx_reset: Sender<()>,
}

#[async_trait]
impl MessageHandler for BatchHandler {
    async fn dispatch(&self, _writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        let transaction = message.to_vec();
        {
            let mut state = self.state.lock().await;
            state.current_batch_size += transaction.len();
            state.current_batch.push(transaction);
            if state.current_batch_size >= self.batch_size {
                state.seal().await;
                self.tx_reset
                    .send(())
                    .await
                    .expect("Failed to send reset signal");
            }
        }
        tokio::task::yield_now().await;
        Ok(())
    }
}

impl BatchHandler {
    pub async fn get_txns(&self, limit: u64) -> Vec<Transaction> {
        let mut state = self.state.lock().await;
        let mut payload = Vec::new();
        let limit = limit as usize; 
        while let Some(batch) = state.batch_buffer.first_mut() {
            let take_count = (limit - payload.len()).min(batch.len());
            if take_count == 0 {
                break;
            }
            let extracted: Vec<Transaction> = batch.drain(..take_count).collect();
            payload.extend(extracted);
            if batch.is_empty() {
                state.batch_buffer.remove(0);
            }
            if payload.len() >= limit {
                break;
            }
        }
        payload
    }
}