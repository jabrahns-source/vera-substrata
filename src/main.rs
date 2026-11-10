//! VERA Core CLI
//! Zero-trust, deterministic SB 253 attestation binary.
//!
//! Usage:
//!   vera keygen                          # generate a keypair
//!   vera attest --input data.json        # produce signed receipt
//!   vera verify --receipt receipt.json   # verify signature
//!   vera serve --secret-key keys.txt     # optional remote HTTP surface (feature = "remote")

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use vera_core::{
    crypto::{Keypair, verify_receipt},
    ingestion::RawInput,
    produce_receipt,
};

#[derive(Parser)]
#[command(name = "vera")]
#[command(about = "VERA Substrata – deterministic quantum-ready SB 253 attestation core", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair (secret is printed once – store securely)
    Keygen,

    /// Produce a signed attestation receipt from input JSON
    Attest {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        secret_key: PathBuf,

        #[arg(short, long, default_value = "receipt.json")]
        output: PathBuf,
    },

    /// Verify a receipt's Ed25519 signature and structure
    Verify {
        #[arg(short, long)]
        receipt: PathBuf,
    },

    /// Start the optional zero-trust HTTP listener (requires --features remote)
    #[cfg(feature = "remote")]
    Serve {
        #[arg(short, long)]
        secret_key: PathBuf,

        #[arg(long, default_value = "0.0.0.0:8787")]
        bind: String,
    },
}

fn load_keypair(path: &PathBuf) -> Keypair {
    let secret_hex = fs::read_to_string(path)
        .expect("failed to read secret key file")
        .trim()
        .to_string();
    let secret_hex = secret_hex
        .strip_prefix("SECRET=")
        .unwrap_or(&secret_hex)
        .trim();
    let secret_bytes = hex::decode(secret_hex).expect("invalid secret key hex");
    if secret_bytes.len() != 32 {
        panic!("secret key must be 32 bytes");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&secret_bytes);
    Keypair::from_bytes(&arr).expect("invalid key")
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen => {
            let kp = Keypair::generate();
            let secret = kp.signing.to_bytes();
            println!("# VERA Ed25519 keypair – store the secret securely");
            println!("SECRET={}", hex::encode(secret));
            println!("PUBLIC={}", kp.public_key_hex());
        }

        Commands::Attest {
            input,
            secret_key,
            output,
        } => {
            let raw_json = fs::read_to_string(&input).expect("failed to read input file");
            let raw: RawInput = serde_json::from_str(&raw_json).expect("invalid input JSON");
            let keypair = load_keypair(&secret_key);

            let receipt = produce_receipt(raw, &keypair, "vera-core-0.1.0")
                .expect("failed to produce receipt");

            let out = serde_json::to_string_pretty(&receipt).expect("serialize failed");
            fs::write(&output, out).expect("failed to write receipt");
            println!("Receipt written to {}", output.display());
            println!("Receipt ID: {}", receipt.receipt_id);
            println!("Merkle root: {}", receipt.provenance.merkle_root);
            println!(
                "First-year relief / non-reporting: {}",
                receipt.first_year_relief.statement_of_non_reporting
            );
        }

        Commands::Verify { receipt } => {
            let json = fs::read_to_string(&receipt).expect("failed to read receipt");
            let rec: vera_core::AttestationReceipt =
                serde_json::from_str(&json).expect("invalid receipt JSON");

            match verify_receipt(&rec) {
                Ok(true) => {
                    println!("VALID – Ed25519 signature verifies");
                    println!("Receipt ID: {}", rec.receipt_id);
                    println!("Entity: {}", rec.entity.legal_name);
                    println!("Scope 1 tCO2e: {}", rec.scope1.total_tco2e);
                    println!(
                        "Scope 2 (location) tCO2e: {}",
                        rec.scope2.location_based_total_tco2e
                    );
                    println!("Merkle root: {}", rec.provenance.merkle_root);
                    println!(
                        "Statement of non-reporting: {}",
                        rec.first_year_relief.statement_of_non_reporting
                    );
                }
                Ok(false) => {
                    eprintln!("INVALID – signature does not verify");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Verification error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        #[cfg(feature = "remote")]
        Commands::Serve { secret_key, bind } => {
            let keypair = load_keypair(&secret_key);
            let addr: std::net::SocketAddr = bind.parse().expect("invalid bind address");
            tokio::runtime::Runtime::new()
                .expect("runtime")
                .block_on(vera_core::remote::run_remote(
                    addr,
                    keypair,
                    "vera-core-0.1.0",
                ));
        }
    }
}
