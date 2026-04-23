use super::*;
use crate::common::{chain, committee, committee_with_base_port, keys, listener};
use crypto::{Digest, SecretKey};
use futures::future::try_join_all;
use std::fs;
use tokio::sync::mpsc::channel;

fn core(
    name: PublicKey,
    secret: SecretKey,
    committee: Committee,
    store_path: &str,
) -> (
    Sender<ConsensusMessage>,
    Receiver<ProposerMessage>,
    Receiver<Block>,
) {
    let (tx_core, rx_core) = channel(1);
    let (tx_loopback, rx_loopback) = channel(1);
    let (tx_proposer, rx_proposer) = channel(1);
    let (tx_commit, rx_commit) = channel(1);

    let signature_service = SignatureService::new(secret);
    let _ = fs::remove_dir_all(store_path);
    let store = Store::new(store_path).unwrap();
    let leader_elector = LeaderElector::new(committee.clone());
    let synchronizer = Synchronizer::new(
        name,
        committee.clone(),
        store.clone(),
        tx_loopback,
        /* sync_retry_delay */ 100_000,
    );

    Core::spawn(
        name,
        committee,
        signature_service,
        store,
        leader_elector,
        synchronizer,
        /* timeout_delay */ 100,
        /* rs_block_size */ 1_048_576,
        /* rs_block_threads */ 4,
        /* rx_message */ rx_core,
        rx_loopback,
        tx_proposer,
        tx_commit,
    );

    (tx_core, rx_proposer, rx_commit)
}

fn leader_keys(round: Round) -> (PublicKey, SecretKey) {
    let leader_elector = LeaderElector::new(committee());
    let leader = leader_elector.get_leader(round);
    keys()
        .into_iter()
        .find(|(public_key, _)| *public_key == leader)
        .unwrap()
}

#[tokio::test]
async fn handle_proposal() {
    let committee = committee_with_base_port(16_000);

    // Make a block.
    let block = chain(vec![leader_keys(1)]).pop().unwrap();
    let (public_key, secret_key) = keys().pop().unwrap();

    // Run a core instance.
    let store_path = ".db_test_handle_proposal";
    let (tx_core, _rx_proposer, _rx_commit) =
        core(public_key, secret_key, committee.clone(), store_path);

    // Send a block to the core.
    let message = ConsensusMessage::Propose(block.clone());
    tx_core.send(message).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
}

#[tokio::test]
async fn generate_proposal() {
    let (leader, leader_key) = leader_keys(1);

    // Run a core instance.
    let store_path = ".db_test_generate_proposal";
    let (_tx_core, mut rx_proposer, _rx_commit) = core(leader, leader_key, committee(), store_path);

    // Ensure the core sends a new block.
    match rx_proposer.recv().await.unwrap() {
        ProposerMessage::Make(round, qc, parent, tc) => {
            assert_eq!(round, 1);
            assert_eq!(qc, QC::genesis());
            assert_eq!(parent, Digest::default());
            assert!(tc.is_none());
        }
        _ => panic!("Unexpected protocol message"),
    }
}

#[tokio::test]
#[ignore = "single-core direct proposal test bypasses the DA path and replica vote flow"]
async fn commit_block() {
    // Get enough distinct leaders to form a quorum.
    let leaders = vec![leader_keys(1), leader_keys(2), leader_keys(3)];
    let chain = chain(leaders);

    // Run a core instance.
    let store_path = ".db_test_commit_block";
    let (public_key, secret_key) = keys().pop().unwrap();
    let (tx_core, _rx_proposer, mut rx_commit) =
        core(public_key, secret_key, committee(), store_path);

    // Send a the blocks to the core.
    let committed = chain[0].clone();
    for block in chain {
        let message = ConsensusMessage::Propose(block);
        tx_core.send(message).await.unwrap();
    }

    // Ensure the core commits the head.
    match rx_commit.recv().await {
        Some(b) => assert_eq!(b, committed),
        _ => assert!(false),
    }
}

#[tokio::test]
async fn local_timeout_round() {
    let committee = committee_with_base_port(16_100);

    // Make the timeout vote we expect to send.
    let (public_key, secret_key) = leader_keys(3);
    let timeout = Timeout::new_from_key(QC::genesis(), 1, public_key, &secret_key);
    let expected = bincode::serialize(&ConsensusMessage::Timeout(timeout)).unwrap();

    // Run a core instance.
    let store_path = ".db_test_local_timeout_round";
    let (_tx_core, _rx_proposer, _rx_commit) =
        core(public_key, secret_key, committee.clone(), store_path);

    // Ensure the node broadcasts a timeout vote.
    let handles: Vec<_> = committee
        .broadcast_addresses(&public_key)
        .into_iter()
        .map(|(_, address)| listener(address, Some(Bytes::from(expected.clone()))))
        .collect();
    assert!(try_join_all(handles).await.is_ok());
}
