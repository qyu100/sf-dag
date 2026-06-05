use super::*;
use crate::common::{chain, committee, committee_with_base_port, keys, listener, proposal_from, proposal, proposal_from_block, block_from, qc_from};
use crypto::SecretKey;
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
    let (tx_proposer_core, rx_proposer_core) = channel(1);
    let (tx_sync_core, rx_sync_core) = channel(1);
    let (tx_core_proposer, rx_core_proposer) = channel(1);
    let (tx_mempool, mut rx_mempool) = channel(1);
    let (tx_commit, rx_commit) = channel(1);
    let (tx_output, rx_output) = channel(1);

    let signature_service = SignatureService::new(secret);
    let _ = fs::remove_dir_all(store_path);
    let store = Store::new(store_path).unwrap();
    let leader_elector = LeaderElector::new(committee.clone());
    let mempool_driver = MempoolDriver::new(committee.clone(), tx_mempool);
    let synchronizer = Synchronizer::new(
        name,
        committee.clone(),
        store.clone(),
        tx_sync_core,
        /* sync_retry_delay */ 100_000,
    );

    tokio::spawn(async move {
        loop {
            rx_mempool.recv().await;
        }
    });

    Core::spawn(
        name,
        committee,
        false,
        signature_service,
        store,
        leader_elector,
        mempool_driver,
        synchronizer,
        /* timeout_delay */ 100,
        /* rx_message */ rx_core,
        rx_proposer_core,
        rx_sync_core,
        tx_core_proposer,
        tx_commit,
        tx_output
    );

    (tx_core, rx_core_proposer, rx_output)
}

fn leader_keys(round: Round) -> (PublicKey, SecretKey) {
    let leader_elector = LeaderElector::new(committee());
    let leader = leader_elector.get_leader(round);
    keys()
        .into_iter()
        .find(|(public_key, _)| *public_key == leader)
        .unwrap()
}

// TODO
// #[tokio::test]
// async fn handle_proposal() {
//     let committee = committee_with_base_port(16_000);

//     // Make a block and the vote we expect to receive.
//     let (block, _) = chain(vec![leader_keys(1)]).pop().unwrap();
//     let (public_key, secret_key) = keys().pop().unwrap();
//     let vote = Vote::new_from_key(block.digest(), block.parent, block.round, public_key, &secret_key);
//     let expected = bincode::serialize(&ConsensusMessage::Vote(vote)).unwrap();

//     // Run a core instance.
//     let store_path = ".db_test_handle_proposal";
//     let (tx_core, _rx_proposer, _rx_commit) =
//         core(public_key, secret_key, committee.clone(), store_path);

//     // Send the block to the core.
//     let message = ConsensusMessage::Propose(ProposalMessage::Normal(proposal()));
//     tx_core.send(message).await.unwrap();

//     // Ensure everyone gets the vote.
//     for address in committee.others_consensus_sockets(&public_key) {
//         let handle = listener(address, Some(Bytes::from(expected)));
//         assert!(handle.await.is_ok());
//     }
// }

// TODO
#[tokio::test]
async fn generate_proposal() {
    // Get the keys of the leaders of this round and the next.
    let (l1, l1_key) = leader_keys(1);
    let (l2, l2_key) = leader_keys(2);
    let (l3, l3_key) = leader_keys(3);

    // Create the first two Blocks and Proposals.
    let b1_b2_justification = Justification::QC(QC::genesis());
    let b1 = block_from(l1, Block::genesis().digest(), 1);
    let p1 = proposal_from_block(b1.clone(), b1_b2_justification.clone(), l1_key);
    let b2 = block_from(l2, b1.digest(), 2);
    let p2 = proposal_from_block(b2.clone(), b1_b2_justification.clone(), l2_key);

    // Run a core instance for each of the next two leaders.
    let store_path_1 = ".db_test_generate_proposal_1";
    let store_path_2 = ".db_test_generate_proposal_2";
    let (tx_core_1, mut rx_proposer_1, _rx_commit_1) =
        core(l2, leader_keys(2).1, committee(), store_path_1);
    let (tx_core_2, mut rx_proposer_2, _rx_commit_2) =
        core(l3, l3_key, committee(), store_path_2);

    // Send the first block to both leaders.
    tx_core_1.send(ConsensusMessage::Propose(ProposalMessage::Normal(p1.clone()))).await.unwrap();
    tx_core_2.send(ConsensusMessage::Propose(ProposalMessage::Normal(p1))).await.unwrap();

    // Expect a Normal Proposal from L2 triggered by B1 alone (edge case).
    let ProposerMessage(round, justification, parent, maybe_qc_prime) = 
        rx_proposer_1.recv().await.unwrap();
    assert_eq!(round, 2);
    assert_eq!(justification, b1_b2_justification);
    assert_eq!(parent, b1.digest());
    assert!(maybe_qc_prime.is_none());

    let votes: Vec<_> = keys()
        .iter()
        .map(|(public_key, secret_key)| {
            Vote::new_from_key(b1.digest(), b1.parent.clone(), b1.round, *public_key, &secret_key)
        })
        .collect();
    let qc1 = qc_from(b1.digest(), b1.parent, b1.round);

    // Send all votes to L3.
    for vote in votes.clone() {
        let message = ConsensusMessage::Vote(vote);
        tx_core_2.send(message).await.unwrap();
    }

    // Send the second block to L3.
    tx_core_2.send(ConsensusMessage::Propose(ProposalMessage::Normal(p2))).await.unwrap();

    // Expect a Normal Proposal from L3 triggered by the QC for B1 and B2 (normal case).
    let ProposerMessage(round, justification, parent, maybe_qc_prime) = 
        rx_proposer_2.recv().await.unwrap();
    assert_eq!(round, 3);
    assert_eq!(justification, Justification::QC(qc1));
    assert_eq!(parent, b2.digest());
    assert!(maybe_qc_prime.is_none());
}

// TODO
// #[tokio::test]
// async fn commit_block() {
//     // Get enough distinct leaders to form a quorum.
//     let leaders = vec![leader_keys(1), leader_keys(2), leader_keys(3)];
//     let chain = chain(leaders);

//     // Run a core instance.
//     let store_path = ".db_test_commit_block";
//     let (public_key, secret_key) = keys().pop().unwrap();
//     let (tx_core, _rx_proposer, mut rx_commit) =
//         core(public_key, secret_key, committee(), store_path);

//     // Send the blocks to the core.
//     let (committed, _) = chain[0].clone();
//     for (block, qc) in chain {
//         let message = ConsensusMessage::Propose(
//             proposal_from_block(block, justification, key)
//         );
//         tx_core.send(message).await.unwrap();
//     }

//     // Ensure the core commits the head.
//     match rx_commit.recv().await {
//         Some(b) => assert_eq!(b, committed),
//         _ => assert!(false),
//     }
// }

#[tokio::test]
async fn local_timeout_round_does_not_broadcast_certificate() {}
