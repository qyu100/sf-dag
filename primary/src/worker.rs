use async_trait::async_trait;
use bytes::Bytes;
use config::{Committee, Parameters, WorkerId};
use crypto::{Digest, PublicKey};
use log::{info, debug};
use network::{MessageHandler, Receiver, Writer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::sync::mpsc::{self, Sender};

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
        let (sender, mut receiver) = mpsc::channel::<WorkerMessage>(CHANNEL_CAPACITY);

        tokio::spawn(async move {
            let mut buffer = Vec::new();
            while let Some(message) = receiver.recv().await {
                match message {
                    WorkerMessage::NewTransaction(txn) => {
                        buffer.push(txn);
                    }
                    WorkerMessage::GetTransactions(limit, response_sender) => {
                        let limit = limit as usize;
                        let take_count = limit.min(buffer.len());
                        let payload: Vec<Transaction> = buffer.drain(..take_count).collect();
                        let _ = response_sender.send(payload).await;
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

        debug!(
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
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        let _ = self
            .sender
            .send(WorkerMessage::GetTransactions(limit, response_sender))
            .await;
        response_receiver.recv().await.unwrap_or_default()
    }
}

#[async_trait]
impl MessageHandler for Worker {
    async fn dispatch(&self, _writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        let transaction = message.to_vec();
        self.sender
            .send(WorkerMessage::NewTransaction(transaction))
            .await
            .map_err(|e| Box::<dyn Error>::from(format!("Failed to send transaction: {}", e)))?;
        Ok(())
    }
}