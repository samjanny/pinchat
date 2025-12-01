//! WebSocket token generation handler
//!
//! Provides JWT tokens for WebSocket authentication.
//! Requires Proof-of-Work to prevent DoS attacks.
//!
//! Flow:
//! 1. Client requests token with PoW headers
//! 2. Server validates PoW (reuses existing challenge cache + HMAC(IP))
//! 3. Server verifies room exists and is not full
//! 4. Server generates JWT with 30s expiration
//! 5. Client uses JWT in WebSocket upgrade request

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::ip_hash::{extract_client_ip_with_proxy, hash_ip};
use crate::jwt::{sign_token, WsTokenClaims};
use crate::pow::{calculate_difficulty, PowChallenge};
use crate::state::AppState;

/// Response for successful token generation
#[derive(serde::Serialize)]
pub struct WsTokenResponse {
    /// JWT token for WebSocket authentication
    pub token: String,

    /// Pre-allocated connection ID
    /// Client should use this ID for tracking
    pub connection_id: Uuid,

    /// Token expiration (seconds)
    pub expires_in: u64,
}

/// Handler for WebSocket token generation
///
/// Protected by Proof-of-Work to prevent DoS attacks.
/// Reuses existing PoW challenge cache and HMAC(IP) infrastructure.
///
/// # Security
/// - Requires valid PoW solution
/// - Validates room exists and is not full
/// - Token expires in 30 seconds
/// - One token per PoW solution (challenge consumed)
pub async fn generate_ws_token(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(room_id): Path<Uuid>,
) -> Result<Json<WsTokenResponse>, Response> {
    // Extract and hash client IP for challenge cache lookup
    // Considers trusted proxies for X-Forwarded-For when configured
    let client_ip =
        extract_client_ip_with_proxy(&ConnectInfo(addr), &headers, &state.config.trusted_proxies);
    let ip_hash = hash_ip(&client_ip, &state.ip_hash_secret);

    // Calculate current PoW difficulty
    let current_rooms = state.rooms.len();
    let difficulty = calculate_difficulty(
        current_rooms,
        state.max_rooms,
        state.config.pow_min_difficulty,
        state.config.pow_max_difficulty,
    );

    // Check if client provided PoW solution
    match headers.get("x-pow-nonce") {
        Some(nonce_hdr) => {
            // Parse nonce
            let nonce: u64 = nonce_hdr
                .to_str()
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "Invalid nonce format" })),
                    )
                        .into_response()
                })?;

            // Retrieve the issued challenge from cache to enforce one-time use
            // This prevents offline challenge fabrication attacks
            let cached_challenge = state.challenge_cache.take(&ip_hash).ok_or_else(|| {
                // No challenge found for this IP - emit a new challenge
                tracing::info!("No cached challenge for IP, emitting new challenge (ws-token)");

                let challenge = PowChallenge::new(difficulty);
                state
                    .challenge_cache
                    .store(ip_hash.clone(), challenge.clone());

                (
                    StatusCode::PRECONDITION_REQUIRED, // 428
                    Json(json!({
                        "error": "Proof of work required",
                        "pow_required": true,
                        "challenge": challenge.challenge,
                        "difficulty": challenge.difficulty
                    })),
                )
                    .into_response()
            })?;

            // Verify difficulty matches current requirement
            if cached_challenge.difficulty < difficulty {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "Difficulty too low for current server load"
                    })),
                )
                    .into_response());
            }

            // Verify PoW solution against cached challenge
            if !cached_challenge.verify(nonce) {
                tracing::warn!("Invalid PoW solution from IP (ws-token)");

                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "Invalid proof of work solution" })),
                )
                    .into_response());
            }

            tracing::info!("Valid PoW solution verified for ws-token (challenge consumed)");

            // PoW valid, proceed to generate token
        }
        None => {
            // No PoW provided - emit a new challenge
            tracing::info!("No PoW provided, emitting challenge (ws-token)");

            let challenge = PowChallenge::new(difficulty);
            state
                .challenge_cache
                .store(ip_hash.clone(), challenge.clone());

            return Err((
                StatusCode::PRECONDITION_REQUIRED, // 428
                Json(json!({
                    "error": "Proof of work required",
                    "pow_required": true,
                    "challenge": challenge.challenge,
                    "difficulty": challenge.difficulty
                })),
            )
                .into_response());
        }
    }

    // Verify room exists
    if !state.rooms.contains_key(&room_id) {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Room not found" })),
        )
            .into_response());
    }

    // Verify room is not expired
    {
        let room = state.rooms.get(&room_id).unwrap();
        if room.is_expired() {
            state.remove_room(&room_id);
            return Err((
                StatusCode::GONE,
                Json(json!({ "error": "Room has expired" })),
            )
                .into_response());
        }
    }

    // Verify room is not full
    {
        let room = state.rooms.get(&room_id).unwrap();
        if room.is_full() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Room is full" })),
            )
                .into_response());
        }
    }

    // Generate JWT claims with configurable TTL
    let ttl_secs = state.config.jwt_token_ttl_secs;
    let claims = WsTokenClaims::new(room_id, ttl_secs);
    let connection_id = claims.connection_id;

    // Sign JWT token
    let token = sign_token(&claims, &state.jwt_secret).map_err(|e| {
        tracing::error!("Failed to sign JWT: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to generate token" })),
        )
            .into_response()
    })?;

    tracing::info!(
        "Generated WebSocket token for room {} (connection_id: {})",
        room_id,
        connection_id
    );

    // Return token response
    Ok(Json(WsTokenResponse {
        token,
        connection_id,
        expires_in: ttl_secs as u64,
    }))
}
