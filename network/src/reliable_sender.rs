// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::NetworkError;
use bytes::Bytes;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use log::{debug, info, warn};
use rand::prelude::SliceRandom as _;
use rand::rngs::SmallRng;
use rand::SeedableRng as _;
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time::{sleep, Duration};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

#[cfg(test)]
#[path = "tests/reliable_sender_tests.rs"]
pub mod reliable_sender_tests;

/// Convenient alias for cancel handlers returned to the caller task.
pub type CancelHandler = oneshot::Receiver<Bytes>;

/// We keep alive one TCP connection per peer, each connection is handled by a separate task (called `Connection`).
/// We communicate with our 'connections' through a dedicated channel kept by the HashMap called `connections`.
/// This sender is 'reliable' in the sense that it keeps trying to re-transmit messages for which it didn't
/// receive an ACK back (until they succeed or are canceled).
#[derive(Clone)]
pub struct ReliableSender {
    /// A map holding the channels to our connections.
    connections: HashMap<SocketAddr, Sender<InnerMessage>>,
    /// Small RNG just used to shuffle nodes and randomize connections (not crypto related).
    rng: SmallRng,
    // TODO: Remove
    sent: u64,
}

impl std::default::Default for ReliableSender {
    fn default() -> Self {
        Self::new()
    }
}

impl ReliableSender {
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

    /// Reliably send a message to a specific address.
    pub async fn send(&mut self, address: SocketAddr, data: Bytes) -> CancelHandler {
        self.send_with_label(address, data, None).await
    }

    /// Reliably send a message to a specific address with an optional benchmark label.
    pub async fn send_with_label(
        &mut self,
        address: SocketAddr,
        data: Bytes,
        label: Option<String>,
    ) -> CancelHandler {
        // TODO: Remove
        self.sent += 1;

        let (sender, receiver) = oneshot::channel();
        let bytes = data.len();
        let enqueue_start = Instant::now();
        let enqueued_at = Instant::now();
        let log_label = label.clone();
        self.connections
            .entry(address)
            .or_insert_with(|| Self::spawn_connection(address))
            .send(InnerMessage {
                data,
                label,
                enqueued_at,
                cancel_handler: sender,
            })
            .await
            .expect("Failed to send internal message");
        if let Some(label) = log_label.as_deref() {
            if bytes >= 10_000 {
                debug!(
                    "TIMING reliable_sender_enqueue label={} address={} bytes={} enqueue_ms={}",
                    label,
                    address,
                    bytes,
                    enqueue_start.elapsed().as_millis()
                );
            }
        }
        receiver
    }

    /// Broadcast the message to all specified addresses in a reliable manner. It returns a vector of
    /// cancel handlers ordered as the input `addresses` vector.
    pub async fn broadcast(
        &mut self,
        addresses: Vec<SocketAddr>,
        data: Bytes,
    ) -> Vec<CancelHandler> {
        let mut handlers = Vec::new();
        for address in addresses {
            let handler = self.send(address, data.clone()).await;
            handlers.push(handler);
        }

        // TODO: Remove
        debug!(
            "Finished scheduling broadcasts. Total messages sent: {}",
            self.sent
        );

        handlers
    }

    /// Pick a few addresses at random (specified by `nodes`) and send the message only to them.
    /// It returns a vector of cancel handlers with no specific order.
    pub async fn lucky_broadcast(
        &mut self,
        mut addresses: Vec<SocketAddr>,
        data: Bytes,
        nodes: usize,
    ) -> Vec<CancelHandler> {
        addresses.shuffle(&mut self.rng);
        addresses.truncate(nodes);
        self.broadcast(addresses, data).await
    }
}

/// Simple message used by `ReliableSender` to communicate with its connections.
#[derive(Debug)]
struct InnerMessage {
    /// The data to transmit.
    data: Bytes,
    /// Optional benchmark label for tracing a message across the network path.
    label: Option<String>,
    /// Time when the caller enqueued this message into the per-peer connection task.
    enqueued_at: Instant,
    /// The cancel handler allowing the caller task to cancel the transmission of this message
    /// and to be notified of its successfully transmission.
    cancel_handler: oneshot::Sender<Bytes>,
}

/// A connection is responsible to reliably establish (and keep alive) a connection with a single peer.
struct Connection {
    /// The destination address.
    address: SocketAddr,
    /// Channel from which the connection receives its commands.
    receiver: Receiver<InnerMessage>,
    /// The initial delay to wait before re-attempting a connection (in ms).
    retry_delay: u64,
    /// Buffer keeping all messages that need to be re-transmitted.
    buffer: VecDeque<(Bytes, Option<String>, Instant, oneshot::Sender<Bytes>)>,
}

impl Connection {
    fn spawn(address: SocketAddr, receiver: Receiver<InnerMessage>) {
        tokio::spawn(async move {
            Self {
                address,
                receiver,
                retry_delay: 200,
                buffer: VecDeque::new(),
            }
            .run()
            .await;
        });
    }

    /// Main loop trying to connect to the peer and transmit messages.
    async fn run(&mut self) {
        let mut delay = self.retry_delay;
        let mut retry = 0;
        loop {
            match TcpStream::connect(self.address).await {
                Ok(stream) => {
                    info!("Outgoing connection established with {}", self.address);

                    let _ = stream.set_nodelay(true);
                    // Reset the delay.
                    delay = self.retry_delay;
                    retry = 0;

                    // Try to transmit all messages in the buffer and keep transmitting incoming messages.
                    // The following function only returns if there is an error.
                    let error = self.keep_alive(stream).await;
                    warn!("{}", error);
                }
                Err(e) => {
                    warn!("{}", NetworkError::FailedToConnect(self.address, retry, e));
                    let timer = sleep(Duration::from_millis(delay));
                    tokio::pin!(timer);

                    'waiter: loop {
                        tokio::select! {
                            // Wait an increasing delay before attempting to reconnect.
                            () = &mut timer => {
                                delay = min(2*delay, 60_000);
                                retry +=1;
                                break 'waiter;
                            },

                            // Drain the channel into the buffer to not saturate the channel and block the caller task.
                            // The caller is responsible to cleanup the buffer through the cancel handlers.
                            Some(InnerMessage{data, label, enqueued_at, cancel_handler}) = self.receiver.recv() => {
                                self.buffer.push_back((data, label, enqueued_at, cancel_handler));
                                self.buffer.retain(|(_, _, _, handler)| !handler.is_closed());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Transmit messages once we have established a connection.
    async fn keep_alive(&mut self, stream: TcpStream) -> NetworkError {
        // This buffer keeps all messages and handlers that we have successfully transmitted but for
        // which we are still waiting to receive an ACK.
        let mut pending_replies = VecDeque::new();

        // TODO: REMOVE
        let peer_addr = stream.peer_addr();
        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(320 * 1000 * 1000);

        let (mut writer, mut reader) = Framed::new(stream, codec).split();
        let error = 'connection: loop {
            // Try to send all messages of the buffer.
            while let Some((data, label, enqueued_at, handler)) = self.buffer.pop_front() {
                // Skip messages that have been cancelled.
                if handler.is_closed() {
                    continue;
                }

                // TODO: REMOVE. Benchmarking only.
                // sleep(Duration::from_millis(1)).await;
                // debug!("Sending Proposal to {:?}. Size is {}", peer_addr, data.len());

                // Try to send the message.
                let bytes = data.len();
                let queue_delay_ms = enqueued_at.elapsed().as_millis();
                let write_start = Instant::now();
                if let Some(label) = label.as_deref() {
                    if bytes >= 10_000 {
                        debug!(
                            "TIMELINE event=reliable_sender_write_started label={} address={} bytes={} queue_delay_ms={} buffered={} pending={}",
                            label,
                            self.address,
                            bytes,
                            queue_delay_ms,
                            self.buffer.len(),
                            pending_replies.len()
                        );
                    }
                }
                match writer.send(data.clone()).await {
                    Ok(()) => {
                        let write_ms = write_start.elapsed().as_millis();
                        if bytes >= 10_000 || write_ms >= 10 {
                            if let Some(label) = label.as_deref() {
                                debug!(
                                    "TIMING reliable_sender_write label={} address={} bytes={} queue_delay_ms={} write_ms={} buffered={} pending={}",
                                    label,
                                    self.address,
                                    bytes,
                                    queue_delay_ms,
                                    write_ms,
                                    self.buffer.len(),
                                    pending_replies.len()
                                );
                                debug!(
                                    "TIMELINE event=reliable_sender_write_finished label={} address={} bytes={} queue_delay_ms={} write_ms={}",
                                    label, self.address, bytes, queue_delay_ms, write_ms
                                );
                            } else {
                                debug!(
                                    "TIMING reliable_sender_write address={} bytes={} write_ms={}",
                                    self.address, bytes, write_ms
                                );
                            }
                        }
                        // TODO: REMOVE
                        debug!(
                            "Sent Proposal to {:?}. Buffer size: {}",
                            peer_addr,
                            self.buffer.len()
                        );
                        // The message has been sent, we remove it from the buffer and add it to
                        // `pending_replies` while we wait for an ACK.
                        pending_replies.push_back((data, label, handler, Instant::now()));
                    }
                    Err(e) => {
                        // We failed to send the message, we put it back into the buffer.
                        self.buffer.push_front((data, label, enqueued_at, handler));
                        break 'connection NetworkError::FailedToSendMessage(self.address, e);
                    }
                }
            }

            // Check if there are any new messages to send or if we get an ACK for messages we already sent.
            tokio::select! {
                Some(InnerMessage{data, label, enqueued_at, cancel_handler}) = self.receiver.recv() => {
                    // Add the message to the buffer of messages to send.
                    self.buffer.push_back((data, label, enqueued_at, cancel_handler));
                },
                response = reader.next() => {
                    let (data, label, handler, sent_at) = match pending_replies.pop_front() {
                        Some(message) => message,
                        None => break 'connection NetworkError::UnexpectedAck(self.address)
                    };
                    match response {
                        Some(Ok(bytes)) => {
                            let ack_wait_ms = sent_at.elapsed().as_millis();
                            let sent_bytes = data.len();
                            if let Some(label) = label.as_deref() {
                                debug!(
                                    "TIMING reliable_sender_ack label={} address={} bytes={} ack_wait_ms={} pending={}",
                                    label,
                                    self.address,
                                    sent_bytes,
                                    ack_wait_ms,
                                    pending_replies.len()
                                );
                                debug!(
                                    "TIMELINE event=reliable_sender_ack_received label={} address={} bytes={} ack_wait_ms={}",
                                    label, self.address, sent_bytes, ack_wait_ms
                                );
                            }
                            // Notify the handler that the message has been successfully sent.
                            let _ = handler.send(bytes.freeze());
                        },
                        _ => {
                            // Something has gone wrong (either the channel dropped or we failed to read from it).
                            // Put the message back in the buffer, we will try to send it again.
                            pending_replies.push_front((data, label, handler, sent_at));
                            break 'connection NetworkError::FailedToReceiveAck(self.address);
                        }
                    }
                },
            }
        };

        // If we reach this code, it means something went wrong. Put the messages for which we didn't receive an ACK
        // back into the sending buffer, we will try to send them again once we manage to establish a new connection.
        while let Some((data, label, handler, _sent_at)) = pending_replies.pop_back() {
            self.buffer.push_front((data, label, Instant::now(), handler));
        }
        error
    }
}
