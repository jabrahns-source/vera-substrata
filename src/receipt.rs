//! Receipt assembly – turns Layers 1–3 into the final attested artifact
//! that conforms to the published JSON Schema.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::compute::InventoryResult;
use crate::crypto::merkle_root;
use crate::error::VeraError;
use crate::ingestion::{CanonicalInput, RawInput};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub generated_at: String,
    pub engine_version: String,

    pub entity: EntityBlock,
    pub reporting_period: ReportingPeriod,
    pub organizational_boundary: OrgBoundary,
    pub scope1: Scope1Block,
    pub scope2: Scope2Block,
    pub methodology: MethodologyBlock,
    pub assurance: AssuranceBlock,
    pub first_year_relief: FirstYearRelief,
    pub provenance: ProvenanceBlock,
    pub enforcement_awareness: EnforcementBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityBlock {
    pub legal_name: String,
    pub ein: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingPeriod {
    pub fiscal_year_start: String,
    pub fiscal_year_end: String,
    pub submission_deadline: String,
    pub is_first_year_filing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgBoundary {
    pub method: String,
    pub applied_consistently: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope1Block {
    pub total_tco2e: String,
    pub biogenic_co2_separate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope2Block {
    pub location_based_total_tco2e: String,
    pub market_based_total_tco2e: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodologyBlock {
    pub ghg_protocol_conformance: bool,
    pub gwp_set: String,
    pub emission_factor_databases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssuranceBlock {
    pub level_for_this_filing: String, // "none" for 2026
    pub explanation_if_no_assurance: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirstYearRelief {
    pub was_collecting_data_as_of_2024_12_05: bool,
    pub statement_of_non_reporting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceBlock {
    pub input_data_hash: String,
    pub canonical_byte_stream_hash: String,
    pub function_version: String,
    pub merkle_root: String,
    pub ed25519_signature: String,
    pub ed25519_public_key: Option<String>,
    pub hash_based_signature: String,
    pub timestamp_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementBlock {
    pub max_civil_penalty_per_year: u32,
    pub fee_notice_approximate_date: String,
    pub fee_payment_window_days: u32,
    pub ninth_circuit_note: String,
}

pub fn build_receipt(
    _raw: RawInput,
    canonical: CanonicalInput,
    inventory: InventoryResult,
    engine_version: &str,
) -> Result<AttestationReceipt, VeraError> {
    // Build Merkle leaves from line items
    let leaves: Vec<String> = inventory
        .line_items
        .iter()
        .map(|li| {
            let payload = format!(
                "{}|{}|{}|{}",
                li.scope, li.category, li.activity_value, li.tco2e
            );
            hex::encode(Sha256::digest(payload.as_bytes()))
        })
        .collect();
    let root = merkle_root(&leaves);

    let now = Utc::now().to_rfc3339();

    Ok(AttestationReceipt {
        schema_version: "1.0.0".into(),
        receipt_id: Uuid::new_v4().to_string(),
        generated_at: now.clone(),
        engine_version: engine_version.into(),

        entity: EntityBlock {
            legal_name: canonical.entity_legal_name,
            ein: canonical.ein,
        },
        reporting_period: ReportingPeriod {
            fiscal_year_start: canonical.fiscal_year_start,
            fiscal_year_end: canonical.fiscal_year_end,
            submission_deadline: "2026-11-10".into(),
            is_first_year_filing: true,
        },
        organizational_boundary: OrgBoundary {
            method: canonical.organizational_boundary,
            applied_consistently: true,
        },
        scope1: Scope1Block {
            total_tco2e: inventory.scope1_total_tco2e,
            biogenic_co2_separate: inventory.biogenic_co2,
        },
        scope2: Scope2Block {
            location_based_total_tco2e: inventory.scope2_location_tco2e,
            market_based_total_tco2e: inventory.scope2_market_tco2e,
        },
        methodology: MethodologyBlock {
            ghg_protocol_conformance: true,
            gwp_set: "IPCC AR5 100-year".into(),
            emission_factor_databases: vec!["user-supplied".into()],
        },
        assurance: AssuranceBlock {
            level_for_this_filing: "none".into(),
            explanation_if_no_assurance: Some(
                "First-year (2026) filing under CARB enforcement discretion; limited assurance not required for this cycle.".into(),
            ),
        },
        first_year_relief: FirstYearRelief {
            was_collecting_data_as_of_2024_12_05: canonical.was_collecting_data_as_of_2024_12_05,
            statement_of_non_reporting: canonical.statement_of_non_reporting,
        },
        provenance: ProvenanceBlock {
            input_data_hash: canonical.original_input_hash,
            canonical_byte_stream_hash: canonical.canonical_hash,
            function_version: inventory.function_version,
            merkle_root: root,
            ed25519_signature: String::new(), // filled by sign_receipt
            ed25519_public_key: None,
            hash_based_signature: String::new(),
            timestamp_utc: now,
        },
        enforcement_awareness: EnforcementBlock {
            max_civil_penalty_per_year: 500_000,
            fee_notice_approximate_date: "2026-12-10".into(),
            fee_payment_window_days: 60,
            ninth_circuit_note: "As of 2026-11-09 Ninth Circuit (Chamber of Commerce v. Sanchez): Scope 1 & 2 reporting proceeds; Scope 3 subject to preliminary injunction / likely unconstitutional analysis; SB 261 remains enjoined.".into(),
        },
    })
}
