// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::DagResult;
use crate::header_waiter::WaiterMessage;
use crate::messages::{Certificate, Header};
use crate::primary::HeaderType;
use crate::Round;
use config::Committee;
use std::collections::{HashSet, HashMap};
use crypto::{Digest, PublicKey};
use store::Store;
use tokio::sync::mpsc::Sender;

/// The `Synchronizer` checks if we have all batches and parents referenced by a header. If we don't, it sends
/// a command to the `Waiter` to request the missing data.
pub struct Synchronizer {
    /// The public key of this primary.
    name: PublicKey,
    /// The persistent storage.
    store: Store,
    /// Send commands to the `HeaderWaiter`.
    tx_header_waiter: Sender<WaiterMessage>,
    /// Send commands to the `CertificateWaiter`.
    tx_certificate_waiter: Sender<Certificate>,
    /// The genesis and its digests.
    genesis: Vec<(Digest, Header)>,
    delivered_parents: HashMap<Round, HashMap<Digest, HeaderType>>,
    gc_depth: Round,
}

impl Synchronizer {
    pub fn new(
        name: PublicKey,
        committee: &Committee,
        store: Store,
        tx_header_waiter: Sender<WaiterMessage>,
        tx_certificate_waiter: Sender<Certificate>,
        gc_depth: Round,
    ) -> Self {
        Self {
            name,
            store,
            tx_header_waiter,
            tx_certificate_waiter,
            genesis: Header::genesis(committee)
                .into_iter()
                .map(|x| (x.id.clone(), x))
                .collect(),
            delivered_parents: HashMap::with_capacity(2 * gc_depth as usize),
            gc_depth,
        }
    }

    pub async fn deliver_vertex(&mut self, round: Round, header_msg: HeaderType) -> DagResult<()> {
        let digest = match &header_msg {
            HeaderType::Header(header) => header.id,
            HeaderType::HeaderInfo(header_info) => header_info.id,
        };
        self.delivered_parents
            .entry(round)
            .or_insert_with(HashMap::new)
            .insert(digest, header_msg);
        Ok(())
    }

    pub async fn garbage_collect(&mut self, gc_round: Round) -> DagResult<()> {
        self.delivered_parents.retain(|k, _| k >= &gc_round);
        Ok(())
    }

    /// Returns the parents of a header if we have them all. If at least one parent is missing,
    /// we return an empty vector, synchronize with other nodes, and re-schedule processing
    /// of the header for when we will have all the parents.
    pub async fn get_parents(&mut self, header_msg: &HeaderType) -> DagResult<Vec<HeaderType>> {
        let h_parents: Vec<_>;
        let round: Round;
        match header_msg {
            HeaderType::Header(header) => {
                h_parents = header.parents.clone();
                round = header.round - 1;
            }
            HeaderType::HeaderInfo(header_info) => {
                h_parents = header_info.parents.clone();
                round = header_info.round - 1;
            }
        }
        let mut missing = Vec::new();
        let mut parents = Vec::new();
        for parent in &h_parents {
            if let Some(genesis) = self
                .genesis
                .iter()
                .find(|(x, _)| x == parent)
                .map(|(_, x)| x)
            {
                let genesis_header_msg = HeaderType::Header(genesis.clone());
                parents.push(genesis_header_msg);
                continue;
            }

            if let Some(round_parents) = self.delivered_parents.get(&round) {
                if let Some(header_type) = round_parents.get(parent) {
                    parents.push(header_type.clone());
                    continue;
                }
            }

            match self.store.read(parent.to_vec()).await? {
                Some(h) => {
                    let header_msg: HeaderType = bincode::deserialize(&h).unwrap();
                    parents.push(header_msg)
                }
                None => missing.push(parent.clone()),
            };
        }

        if missing.is_empty() {
            return Ok(parents);
        }

        self.tx_header_waiter
            .send(WaiterMessage::SyncParents(missing, header_msg.clone()))
            .await
            .expect("Failed to send sync parents request");
        Ok(Vec::new())
    }
}