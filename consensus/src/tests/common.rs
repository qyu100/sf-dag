use crate::config::Committee;
use crate::consensus::Round;
use crate::messages::{Block, Timeout, Transaction, QC};
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{generate_keypair, Digest, PublicKey, SecretKey, Signature};
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

// Fixture.
pub fn keys() -> Vec<(PublicKey, SecretKey)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| generate_keypair(&mut rng)).collect()
}

// Fixture.
pub fn committee() -> Committee {
    Committee::new(
        keys()
            .into_iter()
            .enumerate()
            .map(|(i, (name, _))| {
                let address = format!("127.0.0.1:{}", i).parse().unwrap();
                let stake = 1;
                (name, stake, address)
            })
            .collect(),
        /* epoch */ 100,
    )
}

// Fixture.
pub fn committee_with_base_port(base_port: u16) -> Committee {
    let mut committee = committee();
    for authority in committee.authorities.values_mut() {
        let port = authority.address.port();
        authority.address.set_port(base_port + port);
    }
    committee
}

impl Block {
    pub fn new_from_key(
        qc: QC,
        author: PublicKey,
        round: Round,
        payload: Vec<Transaction>,
        secret: &SecretKey,
    ) -> Self {
        Self::new_from_key_with_parent(qc, Digest::default(), author, round, payload, secret)
    }

    pub fn new_from_key_with_parent(
        qc: QC,
        parent: Digest,
        author: PublicKey,
        round: Round,
        payload: Vec<Transaction>,
        secret: &SecretKey,
    ) -> Self {
        let block = Block {
            qc,
            tc: None,
            parent,
            author,
            round,
            payload,
            signature: Signature::default(),
        };
        let signature = Signature::new(&block.digest(), secret);
        Self { signature, ..block }
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

impl Timeout {
    pub fn new_from_key(high_qc: QC, round: Round, author: PublicKey, secret: &SecretKey) -> Self {
        let timeout = Self {
            high_qc,
            round,
            author,
            signature: Signature::default(),
        };
        let signature = Signature::new(&timeout.digest(), &secret);
        Self {
            signature,
            ..timeout
        }
    }
}

impl PartialEq for Timeout {
    fn eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

// Fixture.
pub fn block() -> Block {
    let (public_key, secret_key) = keys().pop().unwrap();
    Block::new_from_key(QC::genesis(), public_key, 1, Vec::new(), &secret_key)
}

// Fixture.
pub fn qc() -> QC {
    let qc = QC {
        hash: Digest::default(),
        round: 1,
        votes: Vec::new(),
    };
    let digest = qc.digest();
    let mut keys = keys();
    let votes: Vec<_> = (0..3)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&digest, &secret_key))
        })
        .collect();
    QC { votes, ..qc }
}

// Fixture.
pub fn chain(keys: Vec<(PublicKey, SecretKey)>) -> Vec<Block> {
    let mut latest_qc = QC::genesis();
    let mut latest_parent = Digest::default();
    keys.iter()
        .enumerate()
        .map(|(i, key)| {
            // Make a block.
            let (public_key, secret_key) = key;
            let block = Block::new_from_key_with_parent(
                latest_qc.clone(),
                latest_parent.clone(),
                *public_key,
                1 + i as Round,
                Vec::new(),
                secret_key,
            );

            // Make a qc for that block (it will be used for the next block).
            let qc = QC {
                hash: block.digest(),
                round: block.round,
                votes: Vec::new(),
            };
            let digest = qc.digest();
            let votes: Vec<_> = keys
                .iter()
                .map(|(public_key, secret_key)| (*public_key, Signature::new(&digest, secret_key)))
                .collect();
            latest_qc = QC { votes, ..qc };
            latest_parent = block.digest();

            // Return the block.
            block
        })
        .collect()
}

// Fixture
pub fn listener(address: SocketAddr, expected: Option<Bytes>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(&address).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let transport = Framed::new(socket, LengthDelimitedCodec::new());
        let (mut writer, mut reader) = transport.split();
        match reader.next().await {
            Some(Ok(received)) => {
                writer.send(Bytes::from("Ack")).await.unwrap();
                if let Some(expected) = expected {
                    assert_eq!(received.freeze(), expected);
                }
            }
            _ => panic!("Failed to receive network message"),
        }
    })
}
