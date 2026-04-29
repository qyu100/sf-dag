use crate::{consensus::Round, QC};
use crypto::{BlsError, CryptoError, Digest, PublicKey};
use primary::DagError;
use store::StoreError;
use thiserror::Error;

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($e);
    };
}

#[macro_export(local_inner_macros)]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            bail!($e);
        }
    };
}

pub type ConsensusResult<T> = Result<T, ConsensusError>;

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] Box<bincode::ErrorKind>),

    #[error("Store error: {0}")]
    StoreError(#[from] StoreError),

    #[error("Node {0} is not in the committee")]
    NotInCommittee(PublicKey),

    #[error("Invalid signature")]
    InvalidSignature(#[from] CryptoError),

    #[error("Invalid bls-signature")]
    InvalidBlsSign(#[from] BlsError),

    #[error("Received more than one vote from {0}")]
    AuthorityReuse(PublicKey),

    #[error("Received vote from unknown authority {0}")]
    UnknownAuthority(PublicKey),

    #[error("Received QC for round {0} without a quorum")]
    QCRequiresQuorum(Round),

    #[error("Received a Timeout for round {0} containing a QC for a higher round {1}")]
    TimeoutBadQC(Round, Round),

    #[error("Received a TC for round {0} containing a QC for a higher round {1}")]
    TCBadQC(Round, Round),

    #[error("Received TC without a quorum")]
    TCRequiresQuorum,

    #[error("Received TC with an invalid high QC: {0}")]
    TCInvalidHighQC(QC),

    #[error("Malformed block {0}")]
    MalformedBlock(Digest),

    #[error("Received a Malformed NormalProposal containing block {0}")]
    MalformedNormalProposal(Digest),

    #[error("Parent of block {0} is not certified by the QC with the maximum sequence number included in the TC")]
    FallbackRecoveryBadParent(Digest),

    #[error(
        "TC of Fallback Recovery Proposal {0} has a QC with round {1} but qc_prime has round {2}"
    )]
    FallbackRecoveryBadQcPrime(Digest, Round, Round),

    #[error("Received a block {0} for round {1} with invalid justification")]
    BlockBadJustification(Digest, Round),

    #[error("Received a block {0} for round {1} with a QC for a higher round {2}")]
    BlockBadQC(Digest, Round, Round),

    #[error("Received a block {0} for round {1} with a TC for round {2}")]
    BlockBadTC(Digest, Round, Round),

    #[error("Received block {digest} from leader {leader} at round {round}")]
    WrongLeader {
        digest: Digest,
        leader: PublicKey,
        round: Round,
    },

    #[error("Invalid payload")]
    InvalidPayload,

    #[error("Proof construction failed")]
    ProofConstructionFailed,

    #[error("Invalid erasure-coding proof")]
    InvalidProof,

    #[error("Message {0} (round {1}) too old")]
    TooOld(Digest, Round),

    #[error(transparent)]
    DagError(#[from] DagError),
}
