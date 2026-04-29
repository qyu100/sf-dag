// Copyright(C) Facebook, Inc. and its affiliates.
use blsttc::{PublicKeyShareG1, PublicKeyShareG2, SecretKeyShare};
use crypto::{combine_keys, generate_production_keypair, PublicKey, SecretKey};
use log::info;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::BufWriter;
use std::io::Write as _;
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Node {0} is not in the committee")]
    NotInCommittee(PublicKey),

    #[error("Unknown worker id {0}")]
    UnknownWorker(WorkerId),

    #[error("Failed to read config file '{file}': {message}")]
    ImportError { file: String, message: String },

    #[error("Failed to write config file '{file}': {message}")]
    ExportError { file: String, message: String },
}

pub trait Import: DeserializeOwned {
    fn import(path: &str) -> Result<Self, ConfigError> {
        let reader = || -> Result<Self, std::io::Error> {
            let data = fs::read(path)?;
            Ok(serde_json::from_slice(data.as_slice())?)
        };
        reader().map_err(|e| ConfigError::ImportError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }
}

pub trait Export: Serialize {
    fn export(&self, path: &str) -> Result<(), ConfigError> {
        let writer = || -> Result<(), std::io::Error> {
            let file = OpenOptions::new().create(true).write(true).open(path)?;
            let mut writer = BufWriter::new(file);
            let data = serde_json::to_string_pretty(self).unwrap();
            writer.write_all(data.as_ref())?;
            writer.write_all(b"\n")?;
            Ok(())
        };
        writer().map_err(|e| ConfigError::ExportError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }
}

pub type Stake = u32;
pub type WorkerId = u32;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum LeaderElectorKind {
    FailureBestCase,
    FailureMidCase,
    FailureWorstCase,
    FairSuccession,
    Simple,
}

#[derive(Deserialize, Clone)]
pub struct Parameters {
    /// Runs the consensus module in isolation if true.
    pub consensus_only: bool,
    /// The timeout delay of the consensus protocol.
    pub timeout_delay: u64,
    /// The preferred header size. The primary creates a new header when it has enough parents and
    /// enough batches' digests to reach `header_size`. Denominated in bytes.
    pub header_size: usize,
    // The maximum number of Certificates that may be included in a single consensus block.
    pub max_block_size: usize,
    /// The maximum delay that the primary waits between generating two headers, even if the header
    /// did not reach `max_header_size`. Denominated in ms.
    pub max_header_delay: u64,
    /// The depth of the garbage collection (Denominated in number of rounds).
    pub gc_depth: u64,
    /// The delay after which the synchronizer retries to send sync requests. Denominated in ms.
    pub sync_retry_delay: u64,
    /// Determine with how many nodes to sync when re-trying to send sync-request. These nodes
    /// are picked at random from the committee.
    pub sync_retry_nodes: usize,
    /// The preferred batch size. The workers seal a batch of transactions when it reaches this size.
    /// Denominated in bytes.
    pub batch_size: usize,
    /// The delay after which the workers seal a batch of transactions, even if `max_batch_size`
    /// is not reached. Denominated in ms.
    pub max_batch_delay: u64,
    /// Reed-Solomon block size used when splitting shard encoding/decoding work. Denominated in bytes.
    pub rs_block_size: usize,
    /// Number of threads used for Reed-Solomon block-level parallelism.
    pub rs_block_threads: usize,
    /// Causes Prepare messages to be unicast to a designated aggregator rather than broadcast.
    pub use_vote_aggregator: bool,
    /// The type of leader election function to use. See leader.rs.
    pub leader_elector: LeaderElectorKind,

    pub n: u32,
    pub f: u32,
    pub c: u32,
    pub k: u32,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            consensus_only: false,
            timeout_delay: 5_000,
            header_size: 1_000,
            max_block_size: 1,
            max_header_delay: 100,
            gc_depth: 50,
            sync_retry_delay: 5_000,
            sync_retry_nodes: 3,
            batch_size: 500_000,
            max_batch_delay: 100,
            rs_block_size: 16 * 1024,
            rs_block_threads: 4,
            use_vote_aggregator: false,
            leader_elector: LeaderElectorKind::Simple,
            n: 15,
            f: 3,
            c: 2,
            k: 1,
        }
    }
}

impl Import for Parameters {}

impl Parameters {
    pub fn log(&self, committee: &Committee) {
        // NOTE: These log entries are needed to compute performance.
        if self.consensus_only {
            info!("Running consensus in isolation");
        }

        let faults = committee.get_byzantine_ids().len();
        info!("With {} faulty nodes in the network", faults);
        info!("Using {:?} leader elector", self.leader_elector);
        info!("Timeout delay set to {} ms", self.timeout_delay);
        info!("Header size set to {} B", self.header_size);
        info!("F value set to {}", self.f);
        info!("C value set to {}", self.c);
        info!("K value set to {}", self.k);
        info!("Max header delay set to {} ms", self.max_header_delay);
        info!("Garbage collection depth set to {} rounds", self.gc_depth);
        info!("Sync retry delay set to {} ms", self.sync_retry_delay);
        info!("Sync retry nodes set to {} nodes", self.sync_retry_nodes);
        info!("Batch size set to {} B", self.batch_size);
        info!("Block size set to {} Certificates", self.max_block_size);
        info!("Max batch delay set to {} ms", self.max_batch_delay);
        info!("Reed-Solomon block size set to {} B", self.rs_block_size);
        info!("Reed-Solomon block threads set to {}", self.rs_block_threads);
    }
}

#[derive(Clone, Deserialize)]
pub struct ConsensusAddresses {
    /// Address to receive messages from other consensus nodes (WAN).
    pub consensus_to_consensus: SocketAddr,
}

#[derive(Clone, Deserialize)]
pub struct PrimaryAddresses {
    /// Address to receive messages from other primaries (WAN).
    pub primary_to_primary: SocketAddr,
    /// Address to receive messages from our workers (LAN).
    pub worker_to_primary: SocketAddr,
}

#[derive(Clone, Deserialize, Eq, Hash, PartialEq)]
pub struct WorkerAddresses {
    /// Address to receive client transactions (WAN).
    pub transactions: SocketAddr,
    /// Address to receive messages from other workers (WAN).
    pub worker_to_worker: SocketAddr,
    /// Address to receive messages from our primary (LAN).
    pub primary_to_worker: SocketAddr,
}

#[derive(Clone, Deserialize)]
pub struct Authority {
    pub id: u32,
    pub bls_pubkey_g1: PublicKeyShareG1,
    pub bls_pubkey_g2: PublicKeyShareG2,

    pub is_honest: bool,
    /// The voting power of this authority.
    pub stake: Stake,
    /// The network addresses of the consensus protocol.
    pub consensus: ConsensusAddresses,
    /// The network addresses of the primary.
    pub primary: PrimaryAddresses,
    /// Map of workers' id and their network addresses.
    pub workers: HashMap<WorkerId, WorkerAddresses>,
}

#[derive(Clone, Deserialize)]
pub struct Comm {
    pub authorities: BTreeMap<PublicKey, Authority>,
}
impl Import for Comm {}

#[derive(Clone, Deserialize)]
pub struct Committee {
    pub authorities: BTreeMap<PublicKey, Authority>,
    pub sorted_keys: Vec<PublicKeyShareG2>,
    pub combined_pubkey: PublicKeyShareG2,
    pub n: u32,
    pub f: u32,
    pub c: u32,
    pub k: u32,
    pub quorum_threshold: u32,
    pub slow_commit_threshold: u32,
    pub view_change_threshold: u32,
}

impl Import for Committee {}

impl Committee {
    pub fn new(
        authorities: BTreeMap<PublicKey, Authority>,
        n: u32,
        f: u32,
        c: u32,
        k: u32,
    ) -> Committee {
        let mut keys: Vec<_> = authorities.iter().map(|(_, x)| x.bls_pubkey_g2).collect();
        keys.sort();

        let x = (n + f + 1) as f64 / 2.0;
        let quorum_threshold = x.ceil() as u32;
        let slow_commit_threshold = 2 * f + c + 1;
        let view_change_threshold = n - f - c;

        let committee = Self {
            authorities,
            sorted_keys: keys.clone(),
            combined_pubkey: combine_keys(&keys),
            n,
            f,
            c,
            k,
            quorum_threshold,
            slow_commit_threshold,
            view_change_threshold,
        };
        committee
    }

    pub fn get_byzantine_ids(&self) -> Vec<PublicKey> {
        self.authorities
            .iter()
            .filter(|(_id, attrs)| !attrs.is_honest)
            .map(|(id, _attrs)| id.clone())
            .collect()
    }

    pub fn get_honest_ids(&self) -> Vec<PublicKey> {
        self.authorities
            .iter()
            .filter(|(_id, attrs)| attrs.is_honest)
            .map(|(id, _attrs)| id.clone())
            .collect()
    }

    /// Returns the number of authorities.
    pub fn size(&self) -> usize {
        self.authorities.len()
    }

    /// Return the stake of a specific authority.
    pub fn stake(&self, name: &PublicKey) -> Stake {
        self.authorities.get(&name).map_or_else(|| 0, |x| x.stake)
    }

    pub fn id(&self, name: &PublicKey) -> u32 {
        self.authorities.get(&name).unwrap().id
    }

    /// Returns the stake of all authorities except `myself`.
    pub fn others_stake(&self, myself: &PublicKey) -> Vec<(PublicKey, Stake)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .map(|(name, authority)| (*name, authority.stake))
            .collect()
    }

    /// Returns the stake required to reach a quorum (n+f+1)/2.
    pub fn quorum_threshold(&self) -> Stake {
        self.quorum_threshold
    }

    pub fn slow_commit_threshold(&self) -> Stake {
        self.slow_commit_threshold
    }

    pub fn view_change_threshold(&self) -> Stake {
        self.view_change_threshold
    }

    /// Returns the stake required to reach availability (f+1).
    pub fn validity_threshold(&self) -> Stake {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (N + 2) / 3 = f + 1 + k/3 = f + 1
        self.f + 1
    }

    /// Returns the consensus addresses of the target consensus node.
    pub fn consensus(&self, to: &PublicKey) -> Result<ConsensusAddresses, ConfigError> {
        self.authorities
            .get(to)
            .map(|x| x.consensus.clone())
            .ok_or_else(|| ConfigError::NotInCommittee(*to))
    }

    /// Returns the addresses of all consensus nodes except `myself`.
    pub fn others_consensus(&self, myself: &PublicKey) -> Vec<(PublicKey, ConsensusAddresses)> {
        self.authorities
            .iter()
            // Note: Only return honest addresses for benchmarking so that we don't waste
            // time trying to connect to Byzantine nodes, which could obscure the results.
            .filter(|(name, attrs)| name != &myself && attrs.is_honest)
            .map(|(name, authority)| (*name, authority.consensus.clone()))
            .collect()
    }

    pub fn others_consensus_sockets(&self, myself: &PublicKey) -> Vec<SocketAddr> {
        self.others_consensus(myself)
            .into_iter()
            .map(|(_, x)| x.consensus_to_consensus)
            .collect()
    }

    /// Returns the primary addresses of the target primary.
    pub fn primary(&self, to: &PublicKey) -> Result<PrimaryAddresses, ConfigError> {
        self.authorities
            .get(to)
            .map(|x| x.primary.clone())
            .ok_or_else(|| ConfigError::NotInCommittee(*to))
    }

    /// Returns the addresses of all primaries except `myself`.
    pub fn others_primaries(&self, myself: &PublicKey) -> Vec<(PublicKey, PrimaryAddresses)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .map(|(name, authority)| (*name, authority.primary.clone()))
            .collect()
    }

    /// Returns the addresses of a specific worker (`id`) of a specific authority (`to`).
    pub fn worker(&self, to: &PublicKey, id: &WorkerId) -> Result<WorkerAddresses, ConfigError> {
        self.authorities
            .iter()
            .find(|(name, _)| name == &to)
            .map(|(_, authority)| authority)
            .ok_or_else(|| ConfigError::NotInCommittee(*to))?
            .workers
            .iter()
            .find(|(worker_id, _)| worker_id == &id)
            .map(|(_, worker)| worker.clone())
            .ok_or_else(|| ConfigError::NotInCommittee(*to))
    }

    /// Returns the addresses of all our workers.
    pub fn our_workers(&self, myself: &PublicKey) -> Result<Vec<WorkerAddresses>, ConfigError> {
        self.authorities
            .iter()
            .find(|(name, _)| name == &myself)
            .map(|(_, authority)| authority)
            .ok_or_else(|| ConfigError::NotInCommittee(*myself))?
            .workers
            .values()
            .cloned()
            .map(Ok)
            .collect()
    }

    /// Returns the addresses of all workers with a specific id except the ones of the authority
    /// specified by `myself`.
    pub fn others_workers(
        &self,
        myself: &PublicKey,
        id: &WorkerId,
    ) -> Vec<(PublicKey, WorkerAddresses)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .filter_map(|(name, authority)| {
                authority
                    .workers
                    .iter()
                    .find(|(worker_id, _)| worker_id == &id)
                    .map(|(_, addresses)| (*name, addresses.clone()))
            })
            .collect()
    }

    pub fn get_public_keys(&self) -> Vec<PublicKey> {
        self.authorities
            .iter()
            .map(|(name, _)| (name.clone()))
            .collect()
    }
    pub fn get_bls_g2_public_keys(&self) -> Vec<PublicKeyShareG2> {
        self.authorities
            .iter()
            .map(|(_, x)| x.bls_pubkey_g2)
            .collect()
    }

    pub fn get_bls_public_g1(&self, name: &PublicKey) -> PublicKeyShareG1 {
        self.authorities.get(name).map(|x| x.bls_pubkey_g1).unwrap()
    }

    pub fn get_bls_public_g2(&self, name: &PublicKey) -> PublicKeyShareG2 {
        self.authorities.get(name).map(|x| x.bls_pubkey_g2).unwrap()
    }
}

#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    /// The node's public key (and identifier).
    pub name: PublicKey,
    /// The node's secret key.
    pub secret: SecretKey,
}

impl Import for KeyPair {}
impl Export for KeyPair {}

impl KeyPair {
    pub fn new() -> Self {
        let (name, secret) = generate_production_keypair();
        Self { name, secret }
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

//bls

#[derive(Clone, Serialize, Deserialize)]
pub struct BlsKeyPair {
    /// The node's public key (and identifier).
    pub nameg2: PublicKeyShareG2,
    pub nameg1: PublicKeyShareG1,
    /// The node's secret key.
    pub secret: SecretKeyShare,
}

impl Import for BlsKeyPair {}
impl Export for BlsKeyPair {}

impl BlsKeyPair {
    pub fn new(nodes: usize, threshold: usize, path: String) {
        crypto::create_bls_key_pairs(nodes, threshold, path);
    }
}

impl Default for BlsKeyPair {
    fn default() -> BlsKeyPair {
        Self {
            nameg2: PublicKeyShareG2::default(),
            nameg1: PublicKeyShareG1::default(),
            secret: SecretKeyShare::default(),
        }
    }
}
