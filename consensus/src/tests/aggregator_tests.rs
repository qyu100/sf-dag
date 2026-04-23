use super::*;
use crate::common::{committee, keys};
use crate::messages::{Timeout, QC};

#[test]
fn add_timeout() {
    let mut aggregator = Aggregator::new(committee());
    let (author, secret) = keys().pop().unwrap();
    let timeout = Timeout::new_from_key(QC::genesis(), 1, author, &secret);
    let result = aggregator.add_timeout(timeout);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn make_tc() {
    let mut aggregator = Aggregator::new(committee());

    for (i, (author, secret)) in keys().into_iter().take(3).enumerate() {
        let timeout = Timeout::new_from_key(QC::genesis(), 1, author, &secret);
        let result = aggregator.add_timeout(timeout);
        assert!(result.is_ok());
        if i < 2 {
            assert!(result.unwrap().is_none());
        } else {
            assert!(result.unwrap().is_some());
        }
    }
}

#[test]
fn cleanup() {
    let mut aggregator = Aggregator::new(committee());
    let (author, secret) = keys().pop().unwrap();
    let timeout = Timeout::new_from_key(QC::genesis(), 1, author, &secret);

    let result = aggregator.add_timeout(timeout);
    assert!(result.is_ok());
    assert_eq!(aggregator.timeouts_aggregators.len(), 1);

    aggregator.cleanup(&2);
    assert!(aggregator.timeouts_aggregators.is_empty());
}
