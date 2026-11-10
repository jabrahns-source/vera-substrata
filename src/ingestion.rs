//! Layer 1 – Agnostic ingestion & canonicalization
//!
//! Accepts any structured activity / emissions data.
//! Produces a single, domain-agnostic, deterministic byte stream.
//! No domain logic lives here. Trust boundary starts after this layer.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::error::VeraError;

/// Raw input accepted from CLI, HTTP, or file.
/// Designed to be domain-agnostic: grid intensity, factory fuel, fleet miles, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawInput {
    pub entity_legal_name: String,
    pub ein: String,
    pub fiscal_year_start: String,   // YYYY-MM-DD
    pub fiscal_year_end: String,
    pub organizational_boundary: String, // "operational_control" | "financial_control" | "equity_share"

    /// Activity records. Each record is treated as opaque structured data.
    pub activities: Vec<ActivityRecord>,

    /// Optional first-year relief declaration
    pub was_collecting_data_as_of_2024_12_05: bool,
    pub statement_of_non_reporting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityRecord {
    pub scope: u8,                    // 1 or 2 (3 reserved)
    pub category: String,             // e.g. "stationary_combustion", "purchased_electricity"
    pub activity_value: String,       // decimal string – never f64 to avoid drift
    pub activity_unit: String,
    pub emission_factor: String,      // decimal string
    pub emission_factor_unit: String,
    pub emission_factor_source: String,
    pub gwp_set: String,
    pub description: Option<String>,
}

/// Canonical form after normalization.
/// All numbers remain as strings until the pure compute layer.
/// Ordering is deterministic (stable sort by scope → category → description).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalInput {
    pub entity_legal_name: String,
    pub ein: String,
    pub fiscal_year_start: String,
    pub fiscal_year_end: String,
    pub organizational_boundary: String,
    pub activities: Vec<ActivityRecord>,
    pub was_collecting_data_as_of_2024_12_05: bool,
    pub statement_of_non_reporting: bool,
    /// SHA-256 of the original raw JSON bytes (before any reordering)
    pub original_input_hash: String,
    /// SHA-256 of the canonical JSON bytes (after normalization)
    pub canonical_hash: String,
}

pub fn canonicalize(raw: &RawInput) -> Result<CanonicalInput, VeraError> {
    // Reject empty or malformed required fields early
    if raw.entity_legal_name.trim().is_empty() {
        return Err(VeraError::Ingestion("entity_legal_name is required".into()));
    }
    if raw.ein.trim().is_empty() {
        return Err(VeraError::Ingestion("ein is required".into()));
    }

    // Deep clone and normalize
    let mut activities = raw.activities.clone();

    // Stable deterministic ordering – critical for reproducible hashes
    activities.sort_by(|a, b| {
        a.scope
            .cmp(&b.scope)
            .then(a.category.cmp(&b.category))
            .then(a.description.cmp(&b.description))
            .then(a.activity_value.cmp(&b.activity_value))
    });

    // Validate that all numeric fields are well-formed decimal strings
    for (i, act) in activities.iter().enumerate() {
        if act.scope != 1 && act.scope != 2 {
            return Err(VeraError::Ingestion(format!(
                "activity[{}]: scope must be 1 or 2 (Scope 3 is future)",
                i
            )));
        }
        validate_decimal(&act.activity_value, &format!("activity[{}].activity_value", i))?;
        validate_decimal(&act.emission_factor, &format!("activity[{}].emission_factor", i))?;
    }

    let mut canonical = CanonicalInput {
        entity_legal_name: raw.entity_legal_name.trim().to_string(),
        ein: raw.ein.trim().to_string(),
        fiscal_year_start: raw.fiscal_year_start.clone(),
        fiscal_year_end: raw.fiscal_year_end.clone(),
        organizational_boundary: raw.organizational_boundary.clone(),
        activities,
        was_collecting_data_as_of_2024_12_05: raw.was_collecting_data_as_of_2024_12_05,
        statement_of_non_reporting: raw.statement_of_non_reporting,
        original_input_hash: String::new(),
        canonical_hash: String::new(),
    };

    // Hash original (pre-sort) and canonical forms
    let original_bytes = serde_json::to_vec(raw)
        .map_err(|e| VeraError::Canonicalization(e.to_string()))?;
    canonical.original_input_hash = hex::encode(Sha256::digest(&original_bytes));

    // Re-hash after we have the structure (we zero the hash fields temporarily)
    let mut for_hash = canonical.clone();
    for_hash.original_input_hash = String::new();
    for_hash.canonical_hash = String::new();
    let clean_bytes = serde_json::to_vec(&for_hash)
        .map_err(|e| VeraError::Canonicalization(e.to_string()))?;
    canonical.canonical_hash = hex::encode(Sha256::digest(&clean_bytes));

    Ok(canonical)
}

fn validate_decimal(s: &str, field: &str) -> Result<(), VeraError> {
    if s.trim().is_empty() {
        return Err(VeraError::Ingestion(format!("{} cannot be empty", field)));
    }
    // Accept only well-formed decimal strings (no scientific notation, no NaN/Inf)
    if s.parse::<f64>().is_err() {
        return Err(VeraError::Ingestion(format!(
            "{} is not a valid decimal number: {}",
            field, s
        )));
    }
    // Reject scientific notation and special values by simple character check
    if s.contains('e') || s.contains('E') || s.contains("NaN") || s.contains("inf") {
        return Err(VeraError::Ingestion(format!(
            "{} must be a plain decimal string, not scientific or special value",
            field
        )));
    }
    Ok(())
}
