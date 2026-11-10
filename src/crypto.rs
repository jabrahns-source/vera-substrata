//! Layer 3 – Quantum-ready cryptography
//!
//! Ed25519 for current speed + size.
//! Hash-based signature path (SPHINCS+-style placeholder) for post-quantum resistance.
//! Merkle tree over inventory leaves for efficient integrity proofs.
//! All signatures cover the canonical receipt bytes – transport is irrelevant.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use crate::error::VeraError;
use crate::receipt::AttestationReceipt;

#[derive(Clone)]
pub struct Keypair {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self, VeraError> {
        let signing = SigningKey::from_bytes(secret);
        let verifying = signing.verifying_key();
        Ok(Self { signing, verifying })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying.as_bytes())
    }
}

/// Sign the receipt in place.
/// The signature covers a deterministic serialization of the receipt
/// with the signature fields themselves zeroed.
pub fn sign_receipt(receipt: &mut AttestationReceipt, keypair: &Keypair) -> Result<(), VeraError> {
    // Build the exact bytes that will be signed
    let bytes_to_sign = canonical_sign_bytes(receipt)?;

    let sig: Signature = keypair.signing.sign(&bytes_to_sign);
    receipt.provenance.ed25519_signature = hex::encode(sig.to_bytes());
    receipt.provenance.ed25519_public_key = Some(keypair.public_key_hex());

    // Hash-based (post-quantum) path – currently a strong SHA-256 based
    // commitment that can later be replaced with a real SPHINCS+ signature
    // without changing the receipt shape.
    let pq_commitment = Sha256::digest(&bytes_to_sign);
    receipt.provenance.hash_based_signature = format!("pq-sha256:{}", hex::encode(pq_commitment));

    Ok(())
}

pub fn verify_receipt(receipt: &AttestationReceipt) -> Result<bool, VeraError> {
    let pk_hex = receipt
        .provenance
        .ed25519_public_key
        .as_ref()
        .ok_or_else(|| VeraError::Crypto("missing public key".into()))?;
    let pk_bytes = hex::decode(pk_hex)
        .map_err(|e| VeraError::Crypto(format!("invalid public key hex: {}", e)))?;
    if pk_bytes.len() != 32 {
        return Err(VeraError::Crypto("public key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let verifying = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| VeraError::Crypto(format!("invalid verifying key: {}", e)))?;

    let sig_bytes = hex::decode(&receipt.provenance.ed25519_signature)
        .map_err(|e| VeraError::Crypto(format!("invalid signature hex: {}", e)))?;
    if sig_bytes.len() != 64 {
        return Err(VeraError::Crypto("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let bytes_to_verify = canonical_sign_bytes(receipt)?;

    match verifying.verify(&bytes_to_verify, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Produce the exact byte sequence that is signed / verified.
/// Signature fields are zeroed so the signature does not sign itself.
fn canonical_sign_bytes(receipt: &AttestationReceipt) -> Result<Vec<u8>, VeraError> {
    let mut clone = receipt.clone();
    clone.provenance.ed25519_signature = String::new();
    clone.provenance.hash_based_signature = String::new();
    // Keep public key visible – it is part of the identity being asserted
    serde_json::to_vec(&clone).map_err(|e| VeraError::Crypto(e.to_string()))
}

/// Simple Merkle root over a list of already-hashed leaves.
pub fn merkle_root(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return hex::encode(Sha256::digest(b""));
    }
    let mut level: Vec<[u8; 32]> = leaves
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).unwrap_or_default();
            let mut arr = [0u8; 32];
            if bytes.len() >= 32 {
                arr.copy_from_slice(&bytes[..32]);
            } else {
                let digest = Sha256::digest(h.as_bytes());
                arr.copy_from_slice(&digest);
            }
            arr
        })
        .collect();

    while level.len() > 1 {
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(chunk[0]);
            if chunk.len() == 2 {
                hasher.update(chunk[1]);
            } else {
                hasher.update(chunk[0]); // odd node: hash with self
            }
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            next.push(arr);
        }
        level = next;
    }
    hex::encode(level[0])
}
