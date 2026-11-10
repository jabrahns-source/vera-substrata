//! Layer 2 – Pure deterministic compute core
//!
//! All arithmetic is performed on decimal strings via fixed-point style
//! conversion to avoid floating-point drift.
//! Same input bytes → same output bytes on any machine.
//! No hidden state, no RNG, no external calls, no model inference.

use crate::error::VeraError;
use crate::ingestion::CanonicalInput;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryResult {
    pub scope1_total_tco2e: String,       // decimal string
    pub scope2_location_tco2e: String,
    pub scope2_market_tco2e: String,
    pub biogenic_co2: String,
    pub line_items: Vec<LineItem>,
    pub function_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineItem {
    pub scope: u8,
    pub category: String,
    pub activity_value: String,
    pub emission_factor: String,
    pub tco2e: String,
    pub description: Option<String>,
}

/// Pure function. No side effects.
pub fn run_deterministic(canonical: &CanonicalInput) -> Result<InventoryResult, VeraError> {
    const FUNCTION_VERSION: &str = "vera-compute-v0.1.0-pure";

    if canonical.statement_of_non_reporting {
        // First-year relief path – return empty inventory with flag
        return Ok(InventoryResult {
            scope1_total_tco2e: "0".into(),
            scope2_location_tco2e: "0".into(),
            scope2_market_tco2e: "0".into(),
            biogenic_co2: "0".into(),
            line_items: vec![],
            function_version: FUNCTION_VERSION.into(),
        });
    }

    let mut scope1_sum = Decimal::zero();
    let mut scope2_loc_sum = Decimal::zero();
    let mut scope2_mkt_sum = Decimal::zero();
    let mut biogenic = Decimal::zero();
    let mut line_items = Vec::new();

    for act in &canonical.activities {
        let value = Decimal::parse(&act.activity_value)?;
        let factor = Decimal::parse(&act.emission_factor)?;
        let product = value.mul(&factor)?;

        let item = LineItem {
            scope: act.scope,
            category: act.category.clone(),
            activity_value: act.activity_value.clone(),
            emission_factor: act.emission_factor.clone(),
            tco2e: product.to_string(),
            description: act.description.clone(),
        };
        line_items.push(item);

        match act.scope {
            1 => {
                if act.category.to_lowercase().contains("biogenic") {
                    biogenic = biogenic.add(&product)?;
                } else {
                    scope1_sum = scope1_sum.add(&product)?;
                }
            }
            2 => {
                // For v0.1 we treat all Scope 2 as both location and market
                // (caller can later supply separate market instruments)
                scope2_loc_sum = scope2_loc_sum.add(&product)?;
                scope2_mkt_sum = scope2_mkt_sum.add(&product)?;
            }
            _ => {
                return Err(VeraError::Compute(format!(
                    "unsupported scope {}",
                    act.scope
                )));
            }
        }
    }

    Ok(InventoryResult {
        scope1_total_tco2e: scope1_sum.to_string(),
        scope2_location_tco2e: scope2_loc_sum.to_string(),
        scope2_market_tco2e: scope2_mkt_sum.to_string(),
        biogenic_co2: biogenic.to_string(),
        line_items,
        function_version: FUNCTION_VERSION.into(),
    })
}

/// Minimal fixed-point decimal helper.
/// Stores value as integer scaled by 10^9 (nano-precision).
/// Prevents classic floating-point non-determinism.
#[derive(Debug, Clone, Copy)]
struct Decimal {
    scaled: i128, // value * 1_000_000_000
}

impl Decimal {
    const SCALE: i128 = 1_000_000_000;

    fn zero() -> Self {
        Self { scaled: 0 }
    }

    fn parse(s: &str) -> Result<Self, VeraError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(VeraError::Compute("empty decimal".into()));
        }

        let negative = s.starts_with('-');
        let s = if negative { &s[1..] } else { s };

        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() > 2 {
            return Err(VeraError::Compute(format!("invalid decimal: {}", s)));
        }

        let whole: i128 = parts[0]
            .parse()
            .map_err(|_| VeraError::Compute(format!("invalid whole part: {}", parts[0])))?;

        let frac = if parts.len() == 2 {
            let mut f = parts[1].to_string();
            // pad or truncate to 9 digits
            if f.len() > 9 {
                f.truncate(9);
            } else {
                while f.len() < 9 {
                    f.push('0');
                }
            }
            f.parse::<i128>()
                .map_err(|_| VeraError::Compute(format!("invalid fractional part: {}", parts[1])))?
        } else {
            0
        };

        let mut scaled = whole * Self::SCALE + frac;
        if negative {
            scaled = -scaled;
        }
        Ok(Self { scaled })
    }

    fn add(&self, other: &Self) -> Result<Self, VeraError> {
        Ok(Self {
            scaled: self
                .scaled
                .checked_add(other.scaled)
                .ok_or_else(|| VeraError::Compute("decimal overflow on add".into()))?,
        })
    }

    fn mul(&self, other: &Self) -> Result<Self, VeraError> {
        // (a * SCALE) * (b * SCALE) / SCALE = a*b * SCALE
        let prod = self
            .scaled
            .checked_mul(other.scaled)
            .ok_or_else(|| VeraError::Compute("decimal overflow on mul".into()))?;
        Ok(Self {
            scaled: prod / Self::SCALE,
        })
    }

    fn to_string(&self) -> String {
        let neg = self.scaled < 0;
        let abs = self.scaled.abs();
        let whole = abs / Self::SCALE;
        let frac = abs % Self::SCALE;
        let mut s = format!("{}.{:09}", whole, frac);
        // trim trailing zeros after decimal
        if s.contains('.') {
            s = s.trim_end_matches('0').trim_end_matches('.').to_string();
        }
        if neg {
            format!("-{}", s)
        } else {
            s
        }
    }
}
