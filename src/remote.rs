//! Layer 4 extension – zero-trust remote surface
//!
//! Tiny Axum listener. The receipt is still self-verifying;
//! the HTTP channel is only a convenience. Air-gapped CLI remains the primary path.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

use crate::crypto::Keypair;
use crate::ingestion::RawInput;
use crate::produce_receipt;
use crate::AttestationReceipt;

#[derive(Clone)]
pub struct AppState {
    pub keypair: Arc<Keypair>,
    pub engine_version: String,
}

#[derive(Deserialize)]
pub struct AttestRequest {
    pub input: RawInput,
}

#[derive(Serialize)]
pub struct AttestResponse {
    pub receipt: AttestationReceipt,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub engine: String,
    pub quantum_ready: bool,
}

pub async fn run_remote(addr: SocketAddr, keypair: Keypair, engine_version: &str) {
    let state = AppState {
        keypair: Arc::new(keypair),
        engine_version: engine_version.to_string(),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/attest", post(attest))
        .route("/v1/verify", post(verify))
        .layer(cors)
        .with_state(state);

    println!("VERA remote listening on http://{}", addr);
    println!("  GET  /health");
    println!("  POST /v1/attest   – body: {{\"input\": <RawInput>}}");
    println!("  POST /v1/verify   – body: <AttestationReceipt>");

    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind failed");
    axum::serve(listener, app).await.expect("server error");
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        engine: state.engine_version,
        quantum_ready: true,
    })
}

async fn attest(
    State(state): State<AppState>,
    Json(req): Json<AttestRequest>,
) -> impl IntoResponse {
    match produce_receipt(req.input, &state.keypair, &state.engine_version) {
        Ok(receipt) => (StatusCode::OK, Json(AttestResponse { receipt })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn verify(Json(receipt): Json<AttestationReceipt>) -> impl IntoResponse {
    match crate::crypto::verify_receipt(&receipt) {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "valid": true,
                "receipt_id": receipt.receipt_id,
                "entity": receipt.entity.legal_name,
                "scope1_tco2e": receipt.scope1.total_tco2e,
                "merkle_root": receipt.provenance.merkle_root
            })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "valid": false, "error": "signature verification failed" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "valid": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}
