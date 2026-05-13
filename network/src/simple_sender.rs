// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::NetworkError;
use bytes::Bytes;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use log::{debug, info, warn};
use rand::prelude::SliceRandom as _;
use rand::rngs::SmallRng;
use rand::SeedableRng as _;
use std::collections::VecDeque;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
// use tokio::time::{Duration, sleep};

#[cfg(test)]
#[path = "tests/simple_sender_tests.rs"]
pub mod simple_sender_tests;

/// We keep alive one TCP connection per peer, each connection is handled by a separate task (called `Connection`).
/// We communicate with our 'connections' through a dedicated channel kept by the HashMap called `connections`.
pub struct SimpleSender {
    /// A map holding the channels to our connections.
    connections: HashMap<SocketAddr, Sender<InnerMessage>>,
    /// Small RNG just used to shuffle nodes and randomize connections (not crypto related).
    rng: SmallRng,
    // TODO: Remove
    sent: u64,
}

impl std::default::Default for SimpleSender {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleSender {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            rng: SmallRng::from_entropy(),
            // TODO: Remove
            sent: 0,
        }
    }

    /// Helper function to spawn a new connection.
    fn spawn_connection(address: SocketAddr) -> Sender<InnerMessage> {
        let (tx, rx) = channel(1_000);
        Connection::spawn(address, rx);
        tx
    }

    /// Try (best-effort) to send a message to a specific address.
    /// This is useful to answer sync requests.
    pub async fn send(&mut self, address: SocketAddr, data: Bytes) {
        self.send_with_label(address, data, None).await;
    }

    /// Try (best-effort) to send a message to a specific address with an optional benchmark label.
    pub async fn send_with_label(
        &mut self,
        address: SocketAddr,
        data: Bytes,
        label: Option<String>,
    ) {
        // TODO: Remove
        self.sent += 1;

        let bytes = data.len();
        let enqueue_start = Instant::now();
        let enqueued_at = Instant::now();
        let log_label = label.clone();
        let message = InnerMessage {
            data,
            label,
            enqueued_at,
        };

        // Try to re-use an existing connection if possible.
        if let Some(tx) = self.connections.get(&address) {
            if tx.send(message.clone()).await.is_ok() {
                if let Some(label) = log_label.as_deref() {
                    if bytes >= 10_000 {
                        info!(
                            "TIMING simple_sender_enqueue label={} address={} bytes={} enqueue_ms={}",
                            label,
                            address,
                            bytes,
                            enqueue_start.elapsed().as_millis()
                        );
                    }
                }
                return;
            }
        }

        // Otherwise make a new connection.
        let tx = Self::spawn_connection(address);
        if tx.send(message).await.is_ok() {
            self.connections.insert(address, tx);
            if let Some(label) = log_label.as_deref() {
                if bytes >= 10_000 {
                    info!(
                        "TIMING simple_sender_enqueue label={} address={} bytes={} enqueue_ms={}",
                        label,
                        address,
                        bytes,
                        enqueue_start.elapsed().as_millis()
                    );
                }
            }
        }
    }

    /// Try (best-effort) to broadcast the message to all specified addresses.
    pub async fn broadcast(&mut self, addresses: Vec<SocketAddr>, data: Bytes) {
        self.broadcast_with_label(addresses, data, None).await;
    }

    /// Try (best-effort) to broadcast the message with an optional benchmark label.
    pub async fn broadcast_with_label(
        &mut self,
        addresses: Vec<SocketAddr>,
        data: Bytes,
        label: Option<String>,
    ) {
        for address in addresses {
            self.send_with_label(address, data.clone(), label.clone()).await;
        }

        // TODO: Remove
        debug!(
            "Finished scheduling broadcasts. Total messages sent: {}",
            self.sent
        );
    }

    /// Pick a few addresses at random (specified by `nodes`) and try (best-effort) to send the
    /// message only to them. This is useful to pick nodes with whom to sync.
    pub async fn lucky_broadcast(
        &mut self,
        mut addresses: Vec<SocketAddr>,
        data: Bytes,
        nodes: usize,
    ) {
        addresses.shuffle(&mut self.rng);
        addresses.truncate(nodes);
        self.broadcast(addresses, data).await
    }
}

#[derive(Clone)]
struct InnerMessage {
    data: Bytes,
    label: Option<String>,
    enqueued_at: Instant,
}

/// A connection is responsible to establish and keep alive (if possible) a connection with a single peer.
struct Connection {
    /// The destination address.
    address: SocketAddr,
    /// Channel from which the connection receives its commands.
    receiver: Receiver<InnerMessage>,
}

impl Connection {
    fn spawn(address: SocketAddr, receiver: Receiver<InnerMessage>) {
        tokio::spawn(async move {
            Self { address, receiver }.run().await;
        });
    }

    /// Main loop trying to connect to the peer and transmit messages.
    async fn run(&mut self) {
        // Try to connect to the peer.
        let (mut writer, mut reader) = match TcpStream::connect(self.address).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                let mut codec = LengthDelimitedCodec::new();
                codec.set_max_frame_length(320 * 1000 * 1000);
                Framed::new(stream, codec).split()
            }
            Err(e) => {
                warn!(
                    "{}",
                    NetworkError::FailedToConnect(self.address, /* retry */ 0, e)
                );
                return;
            }
        };
        info!("Outgoing connection established with {}", self.address);

        let mut pending_replies = VecDeque::new();

        // Transmit messages once we have established a connection.
        loop {
            // Check if there are any new messages to send or if we get an ACK for messages we already sent.
            tokio::select! {
                Some(InnerMessage { data, label, enqueued_at }) = self.receiver.recv() => {

                    // TODO: REMOVE. Benchmarking only.
                    // sleep(Duration::from_millis(1)).await;
                    // debug!("Sending message to {:?}. Size is {}", self.address, data.len());

                    let bytes = data.len();
                    let queue_delay_ms = enqueued_at.elapsed().as_millis();
                    let write_start = Instant::now();
                    if let Some(label) = label.as_deref() {
                        if bytes >= 10_000 {
                            info!(
                                "TIMELINE event=simple_sender_write_started label={} address={} bytes={} queue_delay_ms={} pending={}",
                                label,
                                self.address,
                                bytes,
                                queue_delay_ms,
                                pending_replies.len()
                            );
                        }
                    }
                    if let Err(e) = writer.send(data).await {
                        warn!("{}", NetworkError::FailedToSendMessage(self.address, e));
                        return;
                    }
                    let write_ms = write_start.elapsed().as_millis();
                    if bytes >= 10_000 || write_ms >= 10 {
                        if let Some(label) = label.as_deref() {
                            info!(
                                "TIMING simple_sender_write label={} address={} bytes={} queue_delay_ms={} write_ms={} pending={}",
                                label,
                                self.address,
                                bytes,
                                queue_delay_ms,
                                write_ms,
                                pending_replies.len()
                            );
                            info!(
                                "TIMELINE event=simple_sender_write_finished label={} address={} bytes={} queue_delay_ms={} write_ms={}",
                                label,
                                self.address,
                                bytes,
                                queue_delay_ms,
                                write_ms
                            );
                        } else {
                            info!(
                                "TIMING simple_sender_write address={} bytes={} write_ms={}",
                                self.address,
                                bytes,
                                write_ms
                            );
                        }
                    }
                    pending_replies.push_back((label, bytes, Instant::now()));
                },
                response = reader.next() => {
                    match response {
                        Some(Ok(_)) => {
                            if let Some((label, bytes, sent_at)) = pending_replies.pop_front() {
                                let ack_wait_ms = sent_at.elapsed().as_millis();
                                if let Some(label) = label.as_deref() {
                                    if bytes >= 10_000 || ack_wait_ms >= 10 {
                                        info!(
                                            "TIMING simple_sender_ack label={} address={} bytes={} ack_wait_ms={} pending={}",
                                            label,
                                            self.address,
                                            bytes,
                                            ack_wait_ms,
                                            pending_replies.len()
                                        );
                                        info!(
                                            "TIMELINE event=simple_sender_ack_received label={} address={} bytes={} ack_wait_ms={}",
                                            label,
                                            self.address,
                                            bytes,
                                            ack_wait_ms
                                        );
                                    }
                                }
                            }
                            // Sink the reply.
                        },
                        _ => {
                            // Something has gone wrong (either the channel dropped or we failed to read from it).
                            warn!("{}", NetworkError::FailedToReceiveAck(self.address));
                            return;
                        }
                    }
                },
            }
        }
    }
}
