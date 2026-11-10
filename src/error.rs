use thiserror::Error;

#[derive(Error, Debug)]
pub enum VeraError {
    #[error("Ingestion error: {0}")]
    Ingestion(String),

    #[error("Canonicalization failed: {0}")]
    Canonicalization(String),

    #[error("Deterministic compute error: {0}")]
    Compute(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Schema / validation error: {0}")]
    Validation(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
