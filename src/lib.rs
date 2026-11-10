//! VERA Substrata Core
//! Four-layer deterministic attestation engine for SB 253 / CARB emissions receipts.
//!
//! Layer 1 – Agnostic ingestion & canonicalization
//! Layer 2 – Pure deterministic compute
//! Layer 3 – Quantum-ready cryptography (Ed25519 + hash-based path + Merkle)
//! Layer 4 – Zero-trust transport (signature travels with payload)

pub mod ingestion;
pub mod compute;
pub mod crypto;
pub mod receipt;
pub mod error;

#[cfg(feature = "remote")]
pub mod remote;

pub use error::VeraError;
pub use receipt::AttestationReceipt;
pub use crypto::{Keypair, sign_receipt, verify_receipt};

/// Public entry point used by both CLI and remote surfaces.
pub fn produce_receipt(
    input: ingestion::RawInput,
    keypair: &Keypair,
    engine_version: &str,
) -> Result<AttestationReceipt, VeraError> {
    // Layer 1
    let canonical = ingestion::canonicalize(&input)?;

    // Layer 2
    let inventory = compute::run_deterministic(&canonical)?;

    // Layer 3 + assembly
    let mut receipt = receipt::build_receipt(input, canonical, inventory, engine_version)?;
    sign_receipt(&mut receipt, keypair)?;

    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingestion::{ActivityRecord, RawInput};

    fn sample_input() -> RawInput {
        RawInput {
            entity_legal_name: "Test Corp".into(),
            ein: "12-3456789".into(),
            fiscal_year_start: "2025-01-01".into(),
            fiscal_year_end: "2025-12-31".into(),
            organizational_boundary: "operational_control".into(),
            was_collecting_data_as_of_2024_12_05: true,
            statement_of_non_reporting: false,
            activities: vec![
                ActivityRecord {
                    scope: 1,
                    category: "stationary_combustion".into(),
                    activity_value: "1000".into(),
                    activity_unit: "MMBtu".into(),
                    emission_factor: "0.05".into(),
                    emission_factor_unit: "tCO2e/MMBtu".into(),
                    emission_factor_source: "EPA".into(),
                    gwp_set: "IPCC AR5 100-year".into(),
                    description: Some("Boiler".into()),
                },
                ActivityRecord {
                    scope: 2,
                    category: "purchased_electricity".into(),
                    activity_value: "2.5".into(),
                    activity_unit: "GWh".into(),
                    emission_factor: "0.0004".into(),
                    emission_factor_unit: "tCO2e/kWh".into(),
                    emission_factor_source: "eGRID".into(),
                    gwp_set: "IPCC AR5 100-year".into(),
                    description: None,
                },
            ],
        }
    }

    #[test]
    fn end_to_end_produce_and_verify() {
        let kp = Keypair::generate();
        let receipt = produce_receipt(sample_input(), &kp, "test-0.1.0").unwrap();
        assert_eq!(receipt.schema_version, "1.0.0");
        assert!(!receipt.provenance.ed25519_signature.is_empty());
        assert!(verify_receipt(&receipt).unwrap());
    }

    #[test]
    fn first_year_relief_path() {
        let mut input = sample_input();
        input.was_collecting_data_as_of_2024_12_05 = false;
        input.statement_of_non_reporting = true;
        input.activities.clear();

        let kp = Keypair::generate();
        let receipt = produce_receipt(input, &kp, "test-0.1.0").unwrap();
        assert!(receipt.first_year_relief.statement_of_non_reporting);
        assert_eq!(receipt.scope1.total_tco2e, "0");
        assert!(verify_receipt(&receipt).unwrap());
    }

    #[test]
    fn deterministic_same_input_same_hashes() {
        let kp = Keypair::generate();
        let r1 = produce_receipt(sample_input(), &kp, "test-0.1.0").unwrap();
        let r2 = produce_receipt(sample_input(), &kp, "test-0.1.0").unwrap();

        assert_eq!(r1.scope1.total_tco2e, r2.scope1.total_tco2e);
        assert_eq!(
            r1.scope2.location_based_total_tco2e,
            r2.scope2.location_based_total_tco2e
        );
        assert_eq!(
            r1.provenance.canonical_byte_stream_hash,
            r2.provenance.canonical_byte_stream_hash
        );
        assert_eq!(r1.provenance.merkle_root, r2.provenance.merkle_root);
    }

    #[test]
    fn signature_fails_on_tamper() {
        let kp = Keypair::generate();
        let mut receipt = produce_receipt(sample_input(), &kp, "test-0.1.0").unwrap();
        assert!(verify_receipt(&receipt).unwrap());

        receipt.scope1.total_tco2e = "99999".into();
        assert!(!verify_receipt(&receipt).unwrap());
    }
}
