#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
// Copyright(C) Facebook, Inc. and its affiliates.
use anyhow::{Context, Result};
use clap::{crate_name, crate_version, App, AppSettings, ArgMatches, SubCommand};
use config::Export as _;
use config::Import as _;
use config::{Committee, KeyPair, Parameters, WorkerId};
use env_logger::Env;
use primary::Header;
use primary::Primary;
use store::Store;
use tokio::sync::mpsc::{channel, Receiver};
use worker::Worker;
use config::Comm;


/// The default channel capacity.
pub const CHANNEL_CAPACITY: usize = 1_000;

#[tokio::main]
async fn main() -> Result<()> {
    //std::env::set_var("RUST_BACKTRACE", "1");
    
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("A research implementation of Narwhal and Tusk.")
        .args_from_usage("-v... 'Sets the level of verbosity'")
        .subcommand(
            SubCommand::with_name("generate_keys")
                .about("Print a fresh key pair to file")
                .args_from_usage("--filename=<FILE> 'The file where to print the new key pair'"),
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("Run a node")
                .args_from_usage("--edkeys=<FILE> 'The file containing the node keys'")
                .args_from_usage("--committee=<FILE> 'The file containing committee information'")
                .args_from_usage("--parameters=[FILE] 'The file containing the node parameters'")
                .args_from_usage("--store=<PATH> 'The path where to create the data store'")
                .subcommand(SubCommand::with_name("primary").about("Run a single primary"))
                .subcommand(
                    SubCommand::with_name("worker")
                        .about("Run a single worker")
                        .args_from_usage("--id=<INT> 'The worker id'"),
                )
                .setting(AppSettings::SubcommandRequiredElseHelp),
        )
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .get_matches();

    let log_level = match matches.occurrences_of("v") {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    let mut logger = env_logger::Builder::from_env(Env::default().default_filter_or(log_level));
    #[cfg(feature = "benchmark")]
    logger.format_timestamp_millis();
    logger.init();

    match matches.subcommand() {
        ("generate_keys", Some(sub_matches)) => KeyPair::new()
            .export(sub_matches.value_of("filename").unwrap())
            .context("Failed to generate key pair")?,
        ("run", Some(sub_matches)) => run(sub_matches).await?,
        _ => unreachable!(),
    }
    Ok(())
}

// Runs either a worker or a primary.
async fn run(matches: &ArgMatches<'_>) -> Result<()> {
    let ed_key_file = matches.value_of("edkeys").unwrap();
    let committee_file = matches.value_of("committee").unwrap();
    let parameters_file = matches.value_of("parameters");
    let store_path = matches.value_of("store").unwrap();

    // Read the committee and node's keypair from file.
    let ed_keypair = KeyPair::import(ed_key_file).context("Failed to load the node's keypair")?;

    let comm = Comm::import(committee_file).context("Failed to load the committee information")?;

    // Load default parameters if none are specified.
    let parameters = match parameters_file {
        Some(filename) => {
            Parameters::import(filename).context("Failed to load the node's parameters")?
        }
        None => Parameters::default(),
    };

    let committee = Committee::new(comm.authorities, parameters.f_num);

    // The `SignatureService` provides signatures on input digests.
    // let signature_service = SignatureService::new(keypair.secret);

    // Make the data store.
    let store = Store::new(store_path).context("Failed to create a store")?;

    // Channels the sequence of certificates.
    let (tx_output, rx_output) = channel(CHANNEL_CAPACITY);

    // Channel for sending headers between DAG and Consensus
    let (tx_sailfish, rx_sailfish) = channel(CHANNEL_CAPACITY);

    // Channel for sending loopback headerds that completed validation between DAG and Consensus
    //let (tx_validation, rx_validation) = channel(CHANNEL_CAPACITY);

    // Channel for indicating commit and that new header should be proposed
    //let (tx_ticket, rx_ticket) = channel(CHANNEL_CAPACITY);

    // Check whether to run a primary, a worker, or an entire authority.
    //Note: Each node has at most one worker. Workers that don't include a primary (e.g. are not an entire authority) use PrimaryConnector to connect to a designated primary.
    match matches.subcommand() {
        // Spawn the primary and consensus core.
        ("primary", _) => {
            let (tx_new_certificates, rx_new_certificates) = channel(CHANNEL_CAPACITY);
            let (tx_feedback, rx_feedback) = channel(CHANNEL_CAPACITY);
            let (tx_committer, rx_committer) = channel(CHANNEL_CAPACITY);
            let (tx_pushdown_cert, rx_pushdown_cert) = channel(CHANNEL_CAPACITY);
            let(tx_request_header_sync, rx_request_header_sync) = channel(CHANNEL_CAPACITY);

            Primary::spawn(
                ed_keypair.name,
                committee.clone(),
                parameters.clone(),
                store.clone(),
                /* tx_consensus */ tx_new_certificates,
                tx_committer,
                rx_committer,
                /* rx_consensus */ rx_feedback,
                tx_sailfish,
                //rx_ticket,
                rx_pushdown_cert,
                rx_request_header_sync,
                tx_output,
            );
            /*Consensus::spawn(
                name,
                committee,
                parameters,
                signature_service,
                store,
                /* rx_consensus */ rx_new_certificates,
                rx_committer,
                /* tx_mempool */ tx_feedback,
                tx_output,
                tx_ticket,
                tx_validation,
                rx_sailfish,
                tx_pushdown_cert,
                tx_request_header_sync,
            );*/
        }

        // // Spawn a single worker.
        // ("worker", Some(sub_matches)) => {
        //     let id = sub_matches
        //         .value_of("id")
        //         .unwrap()
        //         .parse::<WorkerId>()
        //         .context("The worker id must be a positive integer")?;
        //     Worker::spawn(keypair.name, id, committee, parameters, store);
        // }
        _ => unreachable!(),
    }

    // Analyze the consensus' output.
    analyze(rx_output).await;

    // If this expression is reached, background tasks finished and channels closed.
    unreachable!();
}

/// Receives an ordered list of certificates and apply any application-specific logic.
async fn analyze(mut rx_output: Receiver<Header>) {
    while let Some(_header) = rx_output.recv().await {
        // NOTE: Here goes the application logic.
    }
}
