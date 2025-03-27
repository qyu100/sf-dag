use async_trait::async_trait;
use bytes::Bytes;
use config::{Committee, Parameters, WorkerId};
use crypto::{Digest, PublicKey};
use log::info;
use network::{MessageHandler, Receiver, Writer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration, Instant};

pub const CHANNEL_CAPACITY: usize = 1_000;

pub type Round = u64;
pub type Transaction = Vec<u8>;

#[derive(Clone)]
pub struct Worker {
    name: PublicKey,
    id: WorkerId,
    committee: Committee,
    parameters: Parameters,
    txn_buffer: Arc<Mutex<Vec<Transaction>>>,
}

impl Worker {
    pub fn spawn(
        name: PublicKey,
        id: WorkerId,
        committee: Committee,
        parameters: Parameters,
    ) -> Self {
        let worker = Self {
            name,
            id,
            committee,
            parameters,
            txn_buffer: Arc::new(Mutex::new(Vec::new())),
        };

        let worker_clone = worker.clone();
        tokio::spawn(async move {
            worker_clone.run().await;
        });

        info!(
            "Worker {} successfully booted on {}",
            id,
            worker.committee
                .worker(&worker.name, &worker.id)
                .expect("Our public key or worker id is not in the committee")
                .transactions
                .ip()
        );

        worker
    }

    async fn run(&self) {
        let mut address = self
            .committee
            .worker(&self.name, &self.id)
            .expect("Our public key or worker id is not in the committee")
            .transactions;
        address.set_ip("0.0.0.0".parse().unwrap());
        Receiver::spawn(address, self.clone());

        info!(
            "Worker {} listening to client transactions on {}",
            self.id, address
        );
    }

    pub async fn get_txns(&self, limit: u64) -> Vec<Transaction> {
        let start = Instant::now();
        let limit = limit as usize;
        let mut buffer = self.txn_buffer.lock().await;
        // info!("txn_buffer length: {}", buffer.len());
        info!(
            "Worker {}: Acquired lock in {:?}, buffer length: {}",
            self.id,
            start.elapsed(),
            buffer.len()
        );

        let drain_start = Instant::now();
        let take_count = limit.min(buffer.len());
        let payload: Vec<Transaction> = buffer.drain(..take_count).collect();
        info!(
            "Worker {}: Drained {} transactions in {:?}",
            self.id,
            take_count,
            drain_start.elapsed()
        );

        let total_time = start.elapsed();
        info!(
            "Worker {}: Returning {} transactions, total get_txns took {:?}",
            self.id,
            payload.len(),
            total_time
        );

        // info!("Returning {} transactions", payload.len());
        payload
    }
}

#[async_trait]
impl MessageHandler for Worker {
    async fn dispatch(&self, _writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        let start = Instant::now();
        let transaction = message.to_vec();
        // info!("Received transaction of length: {}", transaction.len());
        let lock_start = Instant::now();
        let mut buffer = self.txn_buffer.lock().await;
        info!(
            "Worker {}: Acquired lock in {:?}",
            self.id,
            lock_start.elapsed()
        );
        buffer.push(transaction);
        tokio::task::yield_now().await;
        let total_time = start.elapsed();
        info!("Worker {}: Total dispatch took {:?}", self.id, total_time);
        Ok(())
    }
}