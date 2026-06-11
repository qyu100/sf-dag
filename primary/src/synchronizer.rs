#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
use crate::{DagError, Height};
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::DagResult;
use crate::header_waiter::WaiterMessage;
use crate::messages::{Certificate, ConsensusMessage, Header, HeaderInfo, Proposal};
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use std::collections::{HashMap, HashSet};
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

/// The `Synchronizer` checks if we have all batches and parents referenced by a header. If we don't, it sends
/// a command to the `Waiter` to request the missing data.
#[derive(Clone)]
pub struct Synchronizer {
    /// The public key of this primary.
    name: PublicKey,
    /// The persistent storage.
    store: Store,
    /// Send commands to the `HeaderWaiter`.
    tx_header_waiter: Sender<WaiterMessage>,
    /// Send commands to the `CertificateWaiter`.
    tx_certificate_waiter: Sender<Certificate>,
    /// Genesis header
    genesis_headers: HashMap<PublicKey, Header>,
    genesis: Vec<(Digest, Header)>,
    delivered_parents: HashMap<Height, HashSet<Digest>>,
    gc_depth: Height,
}

impl Synchronizer {
    pub fn new(
        name: PublicKey,
        committee: &Committee,
        store: Store,
        tx_header_waiter: Sender<WaiterMessage>,
        tx_certificate_waiter: Sender<Certificate>,
    ) -> Self {
        let gc_depth: Height = 50;
        Self {
            name,
            store,
            tx_header_waiter,
            tx_certificate_waiter,
            genesis_headers: Header::genesis_headers(committee),
            genesis: Header::genesis(committee)
                .into_iter()
                .map(|x| (x.id.clone(), x))
                .collect(),
            delivered_parents: HashMap::with_capacity(2 * gc_depth as usize),
            gc_depth,
        }
    }

    pub async fn fetch_header(&mut self, header_digest: Digest) -> DagResult<()> {
        self.tx_header_waiter
            .send(WaiterMessage::SyncHeader(header_digest))
            .await
            .expect("Failed to send sync special parent request");
        Ok(())
    }

    /// Returns the proposals of a consensus message if we have them all. If at least one parent is missing,
    /// we return an empty vector, synchronize with other nodes, and re-schedule processing
    /// of the header for when we will have all the parents.
    pub async fn get_proposals(
        &mut self,
        consensus_message: &ConsensusMessage,
        delivered_header: &Header,
    ) -> DagResult<Vec<Header>> {
        let mut missing = Vec::new();
        let mut proposals_vector = Vec::new();
        //println!("getting proposals");

        match consensus_message {
            ConsensusMessage::Prepare {
                slot: _,
                view: _,
                tc: _,
                qc_ticket: _,
                proposals,
            } => {
                for (pk, proposal) in proposals {
                    //println!("proposal inside prepare");

                    if proposal.header_digest == self.genesis_headers.get(&pk).unwrap().digest() {
                        proposals_vector.push(self.genesis_headers.get(&pk).unwrap().clone());
                        continue;
                    }

                    if proposal.header_digest == delivered_header.digest() {
                        proposals_vector.push(delivered_header.clone());
                        continue;
                    }

                    match self.store.read(proposal.header_digest.to_vec()).await? {
                        Some(header) => {
                            //println!("in some case");
                            proposals_vector.push(bincode::deserialize(&header)?);
                            //println!("after adding to proposal vector");
                        }
                        None => missing.push(proposal.clone()),
                    }
                }
            }
            ConsensusMessage::Confirm {
                slot: _,
                view: _,
                qc: _,
                proposals,
            } => {
                for (pk, proposal) in proposals {
                    if proposal.header_digest == self.genesis_headers.get(&pk).unwrap().digest() {
                        proposals_vector.push(self.genesis_headers.get(&pk).unwrap().clone());
                        continue;
                    }

                    match self.store.read(proposal.header_digest.to_vec()).await? {
                        Some(header) => proposals_vector.push(bincode::deserialize(&header)?),
                        None => missing.push(proposal.clone()),
                    }
                }
            }
            ConsensusMessage::Commit {
                round: _,
                proposals,
            } => {
                for (pk, proposal) in proposals {
                    if proposal.height == 0 {
                        continue;
                    }
                    if proposal.header_digest == self.genesis_headers.get(&pk).unwrap().digest() {
                        proposals_vector.push(self.genesis_headers.get(&pk).unwrap().clone());
                        continue;
                    }

                    match self.store.read(proposal.header_digest.to_vec()).await? {
                        Some(header) => proposals_vector.push(bincode::deserialize(&header)?),
                        None => missing.push(proposal.clone()),
                    }
                }
            }
        }

        if missing.is_empty() {
            return Ok(proposals_vector);
        }

        self.tx_header_waiter
            .send(WaiterMessage::SyncProposals(
                missing,
                consensus_message.clone(),
                HeaderInfo::from_header(delivered_header),
            ))
            .await
            .expect("Failed to send sync parents request");
        Ok(Vec::new())
    }

    // pub async fn sync_proposals(&mut self, consensus_message: &ConsensusMessage) -> DagResult<bool> {
    //     let mut missing = Vec::new();
    //     //println!("synchronizing on proposals");

    //     match consensus_message {
    //         ConsensusMessage::Prepare { slot: _, view: _, tc: _, qc_ticket: _, proposals } => {
    //             for (pk, proposal) in proposals {
    //                 //println!("proposal inside prepare");

    //                 if proposal.header_digest == self.genesis_headers.get(&pk).unwrap().digest() {
    //                     continue;
    //                 }

    //                 match self.store.read(proposal.header_digest.to_vec()).await? {
    //                     Some(header) => {},
    //                     None => missing.push(proposal.clone()),
    //                 }
    //             }
    //         },
    //         ConsensusMessage::Confirm { slot: _, view: _, qc: _, proposals } => {
    //             for (pk, proposal) in proposals {

    //                 if proposal.header_digest == self.genesis_headers.get(&pk).unwrap().digest() {
    //                     continue;
    //                 }

    //                 match self.store.read(proposal.header_digest.to_vec()).await? {
    //                     Some(header) => {},
    //                     None => missing.push(proposal.clone()),
    //                 }
    //             }

    //             //Start async sync.
    //             if !missing.is_empty() {
    //                 self.tx_header_waiter
    //                 .send(WaiterMessage::SyncProposalsCAsync(missing))
    //                 .await
    //                 .expect("Failed to send sync parents request");
    //                 return Ok(false);
    //             }
    //         },
    //         ConsensusMessage::Commit { slot: _, view: _, qc: _, proposals } => {
    //             for (pk, proposal) in proposals {

    //                 if proposal.header_digest == self.genesis_headers.get(&pk).unwrap().digest() {
    //                     continue;
    //                 }

    //                 match self.store.read(proposal.header_digest.to_vec()).await? {
    //                     Some(header) => {},
    //                     None => missing.push(proposal.clone()),
    //                 }
    //             }

    //             //Start sync with loopback
    //             if !missing.is_empty() {
    //                 self.tx_header_waiter
    //                 .send(WaiterMessage::SyncProposalsC(missing, consensus_message.clone()))
    //                 .await
    //                 .expect("Failed to send sync parents request");
    //                 return Ok(false);
    //             }
    //         },
    //     }

    //     Ok(true)
    // }

    pub async fn get_all_headers_for_proposal(
        &mut self,
        proposal: Proposal,
        stop_height: Height,
    ) -> DagResult<Vec<Header>> {
        // The list of blocks for this proposal
        let mut ancestors: Vec<Header> = Vec::new();

        // NOTE: Before calling, must check if proposal is ready, assumes that proposal is ready
        // before calling
        let proposal_digest = proposal.header_digest.clone();
        let Some(mut header) = self.get_header(proposal_digest.clone()).await? else {
            self.fetch_header(proposal_digest.clone()).await?;
            return Err(DagError::MalformedHeader(proposal_digest));
        };

        // Otherwise we have the header and all of its ancestors
        let mut current_height = proposal.height;
        while current_height > stop_height {
            let parent_digest = header.parent.clone();
            if current_height == stop_height + 1 {
                ancestors.push(header);
                break;
            }
            let Some(parent_header) = self.get_parent_header(&header).await? else {
                self.fetch_header(parent_digest.clone()).await?;
                return Err(DagError::MalformedHeader(parent_digest));
            };
            ancestors.push(header);
            header = parent_header;
            current_height = header.height();
        }

        Ok(ancestors)
    }

    pub async fn get_parent(&mut self, header: &Header) -> DagResult<Option<Digest>> {
        let parent_digest = header.parent.clone();
        let height = header.height;

        // If parent is genesis, we already have it.
        if self.genesis.iter().any(|(x, _)| x == &parent_digest) {
            return Ok(Some(parent_digest));
        }

        // If we've already delivered this parent for the round, return it.
        if let Some(set) = self.delivered_parents.get(&height) {
            if set.contains(&parent_digest) {
                return Ok(Some(parent_digest));
            }
        }

        match self.store.read(parent_digest.to_vec()).await? {
            Some(bytes) => Ok(Some(parent_digest)),
            None => {
                let bytes =
                    bincode::serialize(header).expect("Failed to serialize suspended header");
                self.store.write(header.id.to_vec(), bytes).await;
                self.tx_header_waiter
                    .send(WaiterMessage::SyncParent(
                        parent_digest,
                        HeaderInfo::from_header(header),
                    ))
                    .await
                    .expect("Failed to send sync parent request");
                Ok(None)
            }
        }
    }

    pub async fn get_parent_header(&mut self, header: &Header) -> DagResult<Option<Header>> {
        self.get_header(header.parent.clone()).await
    }

    pub async fn get_header(&mut self, header_digest: Digest) -> DagResult<Option<Header>> {
        match self.store.read(header_digest.to_vec()).await? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }
}
