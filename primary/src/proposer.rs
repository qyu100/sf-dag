#![allow(dead_code)]
use std::collections::BTreeMap;

// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::{Certificate, Header};
use crate::primary::Height;
use config::{Committee, WorkerId};
use crypto::{Digest, PublicKey};
use log::{debug, warn};
#[cfg(feature = "benchmark")]
use log::info;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

/// The proposer creates new headers and send them to the core for broadcasting and further processing.
pub struct Proposer {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information
    committee: Committee,
    /// The size of the headers' payload.
    header_size: usize,
    /// The maximum delay to wait for batches' digests.
    max_header_delay: u64,

    /// Receives the parents to include in the next header (along with their round number).
    rx_core: Receiver<Certificate>,
    /// Receives the batches' digests from our workers.
    rx_workers: Receiver<(Digest, WorkerId)>,
    /// Sends newly created headers to the `Core`.
    tx_core: Sender<Header>,
   
    /// The current height of this validator's chain
    height: Height,
    /// Holds the certificate waiting to be included in the next header
    last_parent: Option<Certificate>,
    /// Holds the batches' digests waiting to be included in the next header.
    digests: Vec<(Digest, WorkerId)>,
    /// Keeps track of the size (in bytes) of batches' digests that we received so far.
    payload_size: usize,
    tx_size: usize,
}

impl Proposer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        // _signature_service: SignatureService,
        header_size: usize,
        max_header_delay: u64,
        rx_core: Receiver<Certificate>,
        rx_workers: Receiver<(Digest, WorkerId)>,
        tx_core: Sender<Header>,
        tx_size: usize,
    ) {
        let genesis = Certificate::genesis_cert(&committee);


        tokio::spawn(async move {
            Self {
                name,
                committee,
                header_size,
                max_header_delay,
                rx_core,
                rx_workers,
                tx_core,
                // Height 0 is reserved for genesis certificates/proposals.
                // Start real headers at height 1 so the committer's genesis DAG
                // entry is never overwritten by a real certificate at height 0.
                height: 1,
                last_parent: Some(genesis),
                digests: Vec::with_capacity(2 * header_size),
                payload_size: 0,
                tx_size,
            }
            .run()
            .await;
        });
    }
    
    async fn make_header(&mut self) {
        // Make a new header.
        debug!("digests size before is {:?}", self.digests.len());

        let parent = self.last_parent.take().expect("no parent available").header_id;
        let mut payload = vec![vec![0u8; self.tx_size]; self.header_size / self.tx_size];
        let mut header = Header::new(
                self.name,
                self.height,
                payload,
                parent,
            ).await;

        // debug!("Created {:?}", header);
        #[cfg(feature = "benchmark")]
        {
        info!("Created {:?}", header.id);
        info!(
            "Header {:?} contains {} B",
            header.id,
            header.payload.len() * self.tx_size
        );
        }

        // Reset last parent
        self.last_parent = None;
      
        // Send the new header to the `Core` that will broadcast and process it.
        self.tx_core
            .send(header)
            .await
            .expect("Failed to send header");
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        debug!("Dag starting at round {}", self.height);

        let timer = sleep(Duration::from_millis(self.max_header_delay));
        tokio::pin!(timer);
        let mut current_time = Instant::now();

        loop {
            // Check if we can propose a new header. We propose a new header when one of the following
            // conditions is met:
            // 1. We have a quorum of certificates from the previous round and enough batches' digests;
            // 2. We have a quorum of certificates from the previous round and the specified maximum
            // inter-header delay has passed.
            // 3. If it is a special block opportunity. That is when either a QC or TC from the previous view forms,
            // we have a ticket to propose a new block
            // For both normal blocks and special blocks, delegate the actual sending to the consensus module
            // in other words core should not be disseminating headers
            //let enough_parents = !self.last_parent.is_empty();
            let enough_parent = self.last_parent.is_some();
            // let enough_digests = self.payload_size >= self.header_size;
            let timer_expired = timer.is_elapsed();

            if enough_parent {
                if timer_expired {
                    warn!("Timer expired for height {}", self.height);
                }

                debug!("New car proposed after {:?} ms", current_time.elapsed().as_millis());
                current_time = Instant::now();
                
                // Make a new header.
                self.make_header().await;
                self.payload_size = 0;

                // Reschedule the timer.
                let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                timer.as_mut().reset(deadline);
            }

    
            tokio::select! {
                // Receive own certificate from core (we are the author)
                Some(parent) = self.rx_core.recv() => {
                    debug!("received parent from height {:?}", parent.height);

                    if parent.height < self.height {
                        continue;
                    }

                    // Advance to the child height of this parent certificate.
                    self.height = parent.height + 1;
                    debug!("Chain moved to height {}", self.height);

                    // Signal that we have a parent certificate to propose a new header.
                    self.last_parent = Some(parent);
                }

                // Some((digest, worker_id)) = self.rx_workers.recv() => {
                //     //println!("   received payload from worker {}", worker_id);
                //     self.payload_size += digest.size();
                //     self.digests.push((digest, worker_id));
                // }
                () = &mut timer => {
                    // Nothing to do.
                }
            }
        }
    }
}
