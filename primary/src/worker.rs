use async_trait::async_trait;
use bytes::Bytes;
use config::{Committee, Parameters, WorkerId};
use crypto::{Digest, PublicKey};
use log::{info, debug};
use network::{MessageHandler, Receiver, Writer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::sync::mpsc::{self, Sender};
use std::time::Instant;

#[derive(Debug)]
enum WorkerMessage {
    NewTransaction(Transaction),              
    GetTransactions(u64, Sender<Vec<Transaction>>), 
}

pub const CHANNEL_CAPACITY: usize = 1_000;

pub type Round = u64;
pub type Transaction = Vec<u8>;

#[derive(Clone)]
pub struct Worker {
    name: PublicKey,
    id: WorkerId,
    committee: Committee,
    parameters: Parameters,
    sender: Sender<WorkerMessage>,
}

impl Worker {
    pub fn spawn(
        name: PublicKey,
        id: WorkerId,
        committee: Committee,
        parameters: Parameters,
    ) -> Self {
        let start = Instant::now();
        let (sender, mut receiver) = mpsc::channel::<WorkerMessage>(CHANNEL_CAPACITY);

        tokio::spawn(async move {
            let mut buffer = Vec::new();
            while let Some(message) = receiver.recv().await {
                let msg_start = Instant::now();
                match message {
                    WorkerMessage::NewTransaction(txn) => {
                        buffer.push(txn);
                        info!(
                            "Worker {}: New transaction added, buffer size={}, took {:?}",
                            id,
                            buffer.len(),
                            msg_start.elapsed()
                        );
                    }
                    WorkerMessage::GetTransactions(limit, response_sender) => {
                        let limit = limit as usize;
                        let take_count = limit.min(buffer.len());
                        let payload: Vec<Transaction> = buffer.drain(..take_count).collect();
                        let _ = response_sender.send(payload).await;
                        info!(
                            "Worker {}: Sent {} transactions, took {:?}",
                            id,
                            take_count,
                            msg_start.elapsed()
                        );
                    }
                }
            }
        });

        let worker = Self {
            name,
            id,
            committee,
            parameters,
            sender,
        };

        let worker_clone = worker.clone();
        tokio::spawn(async move {
            worker_clone.run().await;
        });
        let address = worker
            .committee
            .worker(&worker.name, &worker.id)
            .expect("Our public key or worker id is not in the committee")
            .transactions
            .ip();
        debug!(
            "Worker {}: Successfully booted on {} took {:?}",
            id,
            address,
            start.elapsed()
        );
        worker
    }

    async fn run(&self) {
        let start = Instant::now();

        let mut address = self
            .committee
            .worker(&self.name, &self.id)
            .expect("Our public key or worker id is not in the committee")
            .transactions;
        address.set_ip("0.0.0.0".parse().unwrap());

        let receiver_start = Instant::now();
        Receiver::spawn(address, self.clone());

        info!(
            "Worker {}: Receiver spawned took {:?}",
            self.id,
            receiver_start.elapsed()
        );

        info!(
            "Worker {}: Listening to client transactions on {}, total run setup took {:?}",
            self.id,
            address,
            start.elapsed()
        );
    }

    pub async fn get_txns(&self, limit: u64) -> Vec<Transaction> {
        let start = Instant::now();
        let (response_sender, mut response_receiver) = mpsc::channel(1);

        let send_start = Instant::now();
        let _ = self
            .sender
            .send(WorkerMessage::GetTransactions(limit, response_sender))
            .await;
        debug!(
            "Worker {}: Sent GetTransactions request took {:?}",
            self.id,
            send_start.elapsed()
        );
        let recv_start = Instant::now();
        // response_receiver.recv().await.unwrap_or_default()
        let result = response_receiver.recv().await.unwrap_or_default();
        info!(
            "Worker {}: Received {} transactions in {:?}, total get_txns took {:?}",
            self.id,
            result.len(),
            recv_start.elapsed(),
            start.elapsed()
        );

        result
    }
}

#[async_trait]
impl MessageHandler for Worker {
    async fn dispatch(&self, _writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        let start = Instant::now();
        let transaction = message.to_vec();
        let send_start = Instant::now();
        self.sender
            .send(WorkerMessage::NewTransaction(transaction))
            .await
            .map_err(|e| Box::<dyn Error>::from(format!("Failed to send transaction: {}", e)))?;
        info!(
            "Worker {}: Sent transaction to channel in {:?}, total dispatch took {:?}",
            self.id,
            send_start.elapsed(),
            start.elapsed()
        );
        Ok(())
    }
}