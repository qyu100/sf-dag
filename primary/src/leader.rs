#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
use crate::primary::{View, Slot};
use config::Committee;
use crypto::PublicKey;

//pub type LeaderElector = RRLeaderElector;
pub type LeaderElector = SemiParallelRRLeaderElector;

fn fixed_leader_order(committee: &Committee) -> Vec<PublicKey> {
    let mut keys: Vec<_> = committee.authorities.keys().cloned().collect();
    if committee
        .authorities
        .values()
        .all(|authority| authority.node_id.is_some())
    {
        keys.sort_by(|a, b| {
            let a_id = committee
                .authorities
                .get(a)
                .and_then(|authority| authority.node_id)
                .expect("node_id checked above");
            let b_id = committee
                .authorities
                .get(b)
                .and_then(|authority| authority.node_id)
                .expect("node_id checked above");
            a_id.cmp(&b_id).then_with(|| a.cmp(b))
        });
    } else {
        keys.sort();
    }
    keys
}

pub struct RRLeaderElector {
    leaders: Vec<PublicKey>,
}

impl RRLeaderElector {
    pub fn new(committee: Committee) -> Self {
        Self {
            leaders: fixed_leader_order(&committee),
        }
    }

    pub fn get_leader(&self, view: View) -> PublicKey {
        self.leaders[view as usize % self.leaders.len()]
        //keys[0]
    }
}

pub struct SemiParallelRRLeaderElector {
    leaders: Vec<PublicKey>,
}

impl SemiParallelRRLeaderElector {
    pub fn new(committee: Committee) -> Self {
        Self {
            leaders: fixed_leader_order(&committee),
        }
    }
    pub fn size(&self) -> usize {
        self.leaders.len()
    }

    pub fn get_leader(&self, seed: u64) -> PublicKey {
        let index = (seed % self.size() as u64) as usize;
        self.leaders[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{Authority, ConsensusAddresses, PrimaryAddresses};
    use std::collections::{BTreeMap, HashMap};

    fn key(byte: u8) -> PublicKey {
        PublicKey([byte; 32])
    }

    fn authority(node_id: usize) -> Authority {
        Authority {
            node_id: Some(node_id),
            stake: 1,
            consensus: ConsensusAddresses {
                consensus_to_consensus: "127.0.0.1:0".parse().unwrap(),
            },
            primary: PrimaryAddresses {
                primary_to_primary: "127.0.0.1:0".parse().unwrap(),
                worker_to_primary: "127.0.0.1:0".parse().unwrap(),
            },
            workers: HashMap::default(),
        }
    }

    #[test]
    fn leader_order_uses_node_ids() {
        let node_0 = key(30);
        let node_1 = key(20);
        let node_2 = key(10);
        let authorities = BTreeMap::from([
            (node_0, authority(0)),
            (node_1, authority(1)),
            (node_2, authority(2)),
        ]);

        let elector = SemiParallelRRLeaderElector::new(Committee::new(authorities, 0));

        assert_eq!(elector.get_leader(0), node_0);
        assert_eq!(elector.get_leader(1), node_1);
        assert_eq!(elector.get_leader(2), node_2);
        assert_eq!(elector.get_leader(3), node_0);
    }
}
