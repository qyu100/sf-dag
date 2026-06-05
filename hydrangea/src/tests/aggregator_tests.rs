use super::*;
use crate::Block;
use crate::common::{committee, keys, qc, vote};

#[test]
fn add_vote() {
    let mut aggregator = Aggregator::new(committee());
    let result = aggregator.add_vote(vote());
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn make_qc() {
    let mut aggregator = Aggregator::new(committee());
    let mut keys = keys();
    let qc = qc();
    let hash = qc.digest();
    let parent = Block::genesis().digest();
    let round = qc.round;

    // Add 2f+1 votes to the aggregator and ensure it returns the cryptographic
    // material to make a valid QC.
    let (public_key, secret_key) = keys.pop().unwrap();
    let vote = Vote::new_from_key(hash.clone(), parent.clone(), round, public_key, &secret_key);
    let result = aggregator.add_vote(vote);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    let (public_key, secret_key) = keys.pop().unwrap();
    let vote = Vote::new_from_key(hash.clone(), parent.clone(), round, public_key, &secret_key);
    let result = aggregator.add_vote(vote);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    let (public_key, secret_key) = keys.pop().unwrap();
    let vote = Vote::new_from_key(hash.clone(), parent.clone(), round, public_key, &secret_key);
    match aggregator.add_vote(vote) {
        Ok(Some(qc)) => assert!(qc.is_well_formed(&committee()).is_ok()),
        _ => assert!(false),
    }
}

#[test]
fn cleanup() {
    let mut aggregator = Aggregator::new(committee());

    // Add a vote and ensure it is in the aggregator memory.
    let result = aggregator.add_vote(vote());
    assert!(result.is_ok());
    assert_eq!(aggregator.votes_aggregators.len(), 1);

    // Clean up the aggregator.
    aggregator.cleanup(&2);
    assert!(aggregator.votes_aggregators.is_empty());
}
