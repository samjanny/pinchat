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
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::Cookie;
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::handlers::auth::verify_csrf_for_api;
use crate::ip_hash::{extract_client_ip_with_proxy, hash_ip};
use crate::jwt::{WsTokenClaims, sign_token, verify_resume_token};
use crate::models::RoomType;
use crate::pow::{PowChallenge, calculate_difficulty};
use crate::pow_session::{pow_cache_key, resolve_pow_session, should_use_secure_pow_cookies};
use crate::state::AppState;

const RESUME_TOKEN_HEADER: &str = "x-pinchat-resume-token";
const CREATOR_BOOTSTRAP_HEADER: &str = "x-pinchat-creator-bootstrap";
const MLS_CONTROL_SEQ_HEADER: &str = "x-pinchat-mls-control-seq";
const MAX_RESUME_TOKEN_LEN: usize = 2048;
const CREATOR_BOOTSTRAP_TOKEN_LEN: usize = 43;

fn pow_error_response(
    status: StatusCode,
    body: serde_json::Value,
    cookie: Option<Cookie<'static>>,
) -> Response {
    let mut resp = (status, Json(body)).into_response();
    if let Some(c) = cookie
        && let Ok(hv) = c.to_string().parse()
    {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    resp
}

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

    /// Wire-protocol version advertised by this server (v1 gate).
    /// Clients MUST verify that this matches their compiled-in
    /// PINCHAT_PROTOCOL_VERSION before attempting a WebSocket upgrade.
    pub protocol_version: u8,

    /// WebSocket subprotocols the server is willing to negotiate.
    /// Clients MUST verify their preferred subprotocol is present.
    pub supported_subprotocols: Vec<String>,

    /// Server-authoritative cursor bound into a resumed group upgrade token.
    /// Creator-bootstrap reconnects never accept this value from the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_control_cursor: Option<u64>,
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
    // CSRF: this endpoint hands out a JWT bound to the caller's
    // connection_id; without CSRF it can be forged from any same-site
    // injection context (XSS, sibling subdomain, …) and used to hijack
    // the victim's relay slot. POST + double-submit token gating closes
    // that gap on top of SameSite=Strict + session auth.
    verify_csrf_for_api(&headers, &state.csrf_secret)?;

    // Extract and hash client IP for challenge cache lookup
    // Considers trusted proxies for X-Forwarded-For when configured
    let client_ip =
        extract_client_ip_with_proxy(&ConnectInfo(addr), &headers, &state.config.trusted_proxies);
    let ip_hash = hash_ip(&client_ip, &state.ip_hash_secret);

    // Resolve PoW session cookie so clients behind the same NAT do not
    // collide on the challenge cache.
    let use_secure = should_use_secure_pow_cookies(state.config.force_secure_cookies);
    let (pow_cookie, fresh_cookie) =
        resolve_pow_session(&headers, use_secure, state.config.challenge_ttl_secs);
    let cache_key = pow_cache_key(&ip_hash, &pow_cookie);

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
                    pow_error_response(
                        StatusCode::BAD_REQUEST,
                        json!({ "error": "Invalid nonce format" }),
                        fresh_cookie.clone(),
                    )
                })?;

            // Retrieve the issued challenge from cache to enforce one-time use
            // This prevents offline challenge fabrication attacks
            let cached_challenge = state.challenge_cache.take(&cache_key).ok_or_else(|| {
                // No challenge found for this (IP, cookie) pair - emit a new challenge
                tracing::info!("No cached challenge for PoW session, emitting new one (ws-token)");

                let challenge = PowChallenge::new(difficulty);
                state
                    .challenge_cache
                    .store(cache_key.clone(), challenge.clone());

                pow_error_response(
                    StatusCode::PRECONDITION_REQUIRED,
                    json!({
                        "error": "Proof of work required",
                        "pow_required": true,
                        "challenge": challenge.challenge,
                        "difficulty": challenge.difficulty
                    }),
                    fresh_cookie.clone(),
                )
            })?;

            // Verify difficulty matches current requirement
            if cached_challenge.difficulty < difficulty {
                return Err(pow_error_response(
                    StatusCode::FORBIDDEN,
                    json!({
                        "error": "Difficulty too low for current server load"
                    }),
                    fresh_cookie,
                ));
            }

            // Verify PoW solution against cached challenge
            if !cached_challenge.verify(nonce) {
                tracing::warn!("Invalid PoW solution from IP (ws-token)");

                return Err(pow_error_response(
                    StatusCode::FORBIDDEN,
                    json!({ "error": "Invalid proof of work solution" }),
                    fresh_cookie,
                ));
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
                .store(cache_key.clone(), challenge.clone());

            return Err(pow_error_response(
                StatusCode::PRECONDITION_REQUIRED,
                json!({
                    "error": "Proof of work required",
                    "pow_required": true,
                    "challenge": challenge.challenge,
                    "difficulty": challenge.difficulty
                }),
                fresh_cookie,
            ));
        }
    }

    // A resume credential is a longer-lived bearer token issued only after a
    // socket was admitted. The separate creator-bootstrap capability recovers
    // the stable group-creator identity when the initial one-shot upgrade JWT
    // expired or failed before a resume credential arrived. Accept exactly
    // one recovery authority per request.
    if headers.get(RESUME_TOKEN_HEADER).is_some() && headers.get(CREATOR_BOOTSTRAP_HEADER).is_some()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Creator bootstrap and resume credentials are mutually exclusive"
            })),
        )
            .into_response());
    }
    let resume_claims = match headers.get(RESUME_TOKEN_HEADER) {
        None => None,
        Some(value) => {
            let token = value
                .to_str()
                .ok()
                .filter(|s| s.len() <= MAX_RESUME_TOKEN_LEN);
            let claims = token
                .and_then(|token| {
                    verify_resume_token(token, &state.jwt_secret, &state.config.jwt_issuer).ok()
                })
                .filter(|claims| claims.room_id == room_id);
            match claims {
                Some(claims) => Some(claims),
                None => {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(json!({
                            "error": "Secure reconnect credential is invalid or expired",
                            "code": "RESUME_REJECTED"
                        })),
                    )
                        .into_response());
                }
            }
        }
    };
    let creator_bootstrap = match headers.get(CREATOR_BOOTSTRAP_HEADER) {
        None => None,
        Some(value) => {
            let token = value
                .to_str()
                .ok()
                .filter(|token| token.len() == CREATOR_BOOTSTRAP_TOKEN_LEN)
                .map(str::to_owned);
            match token {
                Some(token) => Some(token),
                None => {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(json!({
                            "error": "Group creator bootstrap credential is invalid",
                            "code": "CREATOR_BOOTSTRAP_REJECTED"
                        })),
                    )
                        .into_response());
                }
            }
        }
    };
    let supplied_mls_cursor = match headers.get(MLS_CONTROL_SEQ_HEADER) {
        None => None,
        Some(value) => {
            let parsed = value
                .to_str()
                .ok()
                .filter(|value| !value.is_empty() && value.len() <= 20)
                .and_then(|value| value.parse::<u64>().ok());
            match parsed {
                Some(cursor) => Some(cursor),
                None => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "Invalid MLS control cursor" })),
                    )
                        .into_response());
                }
            }
        }
    };

    // Verify room existence and the creator capability while holding only the
    // room read guard. The stored room contains a digest, never the plaintext
    // bearer token.
    let (
        room_type,
        room_is_expired,
        room_is_full,
        resume_is_reserved,
        creator_connection_id,
        mut creator_is_reserved,
        creator_bootstrap_valid,
    ) = match state.rooms.get(&room_id) {
        Some(room) => {
            let creator_connection_id = creator_bootstrap.as_deref().and_then(|token| {
                room.verify_creator_bootstrap(token)
                    .then(|| room.creator_connection_id())
                    .flatten()
            });
            (
                room.room_type,
                room.is_expired(),
                room.is_full_for_non_creator(),
                resume_claims
                    .as_ref()
                    .map(|claims| room.participant_ids.contains(&claims.connection_id))
                    .unwrap_or(false),
                creator_connection_id,
                creator_connection_id
                    .map(|connection_id| room.participant_ids.contains(&connection_id))
                    .unwrap_or(false),
                creator_bootstrap.is_none() || creator_connection_id.is_some(),
            )
        }
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Room not found" })),
            )
                .into_response());
        }
    };

    if room_is_expired {
        state.remove_room(&room_id);
        return Err((
            StatusCode::GONE,
            Json(json!({ "error": "Room has expired" })),
        )
            .into_response());
    }

    if !creator_bootstrap_valid {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Group creator bootstrap credential is invalid",
                "code": "CREATOR_BOOTSTRAP_REJECTED"
            })),
        )
            .into_response());
    }

    if resume_claims.is_some() && !resume_is_reserved {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Secure reconnect grace period has expired",
                "code": "RESUME_REJECTED"
            })),
        )
            .into_response());
    }

    if creator_connection_id.is_some() && supplied_mls_cursor.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Creator bootstrap reconnect uses the server MLS cursor"
            })),
        )
            .into_response());
    }

    let mls_control_cursor = match (
        resume_claims.as_ref(),
        creator_connection_id,
        creator_is_reserved,
        room_type,
    ) {
        (Some(_), _, _, RoomType::Group) => {
            let Some(cursor) = supplied_mls_cursor else {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "Secure group reconnect cursor is missing",
                        "code": "MLS_CONTROL_RESYNC_REQUIRED"
                    })),
                )
                    .into_response());
            };
            if state.validate_mls_control_cursor(&room_id, cursor).is_err() {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "Secure group replay window is unavailable",
                        "code": "MLS_CONTROL_RESYNC_REQUIRED"
                    })),
                )
                    .into_response());
            }
            Some(cursor)
        }
        (Some(_), _, _, RoomType::OneToOne) => {
            if supplied_mls_cursor.is_some() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "MLS control cursor is invalid for this room"
                    })),
                )
                    .into_response());
            }
            None
        }
        (None, Some(connection_id), true, RoomType::Group) => {
            let cursor = state.acknowledged_mls_control_cursor(&room_id, connection_id);
            if cursor.is_none()
                && !state
                    .rooms
                    .get(&room_id)
                    .map(|room| room.participant_ids.contains(&connection_id))
                    .unwrap_or(false)
            {
                // The reconnect grace finalizer won the race after the room
                // snapshot. Fall back to a fresh creator JWT for the same
                // stable identity instead of returning a terminal 409.
                creator_is_reserved = false;
                None
            } else if let Some(cursor) = cursor {
                if cursor != 0 {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(json!({
                            "error": "Group creator bootstrap handoff is already complete",
                            "code": "CREATOR_BOOTSTRAP_REJECTED"
                        })),
                    )
                        .into_response());
                }
                if state.validate_mls_control_cursor(&room_id, cursor).is_err() {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(json!({
                            "error": "Secure group replay window is unavailable",
                            "code": "MLS_CONTROL_RESYNC_REQUIRED"
                        })),
                    )
                        .into_response());
                }
                Some(cursor)
            } else {
                return Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "Secure group replay cursor is unavailable",
                        "code": "MLS_CONTROL_RESYNC_REQUIRED"
                    })),
                )
                    .into_response());
            }
        }
        (None, Some(_), false, RoomType::Group) => None,
        (None, Some(_), _, RoomType::OneToOne) => {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "Creator bootstrap is invalid for this room",
                    "code": "CREATOR_BOOTSTRAP_REJECTED"
                })),
            )
                .into_response());
        }
        (None, None, _, _) => {
            if supplied_mls_cursor.is_some() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "MLS control cursor requires secure reconnect"
                    })),
                )
                    .into_response());
            }
            None
        }
    };

    if room_is_full && !resume_is_reserved && creator_connection_id.is_none() {
        // Return 404 (same as "not found") to avoid leaking room existence to
        // callers probing UUIDs. See http.rs::room_page for rationale.
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Room not found" })),
        )
            .into_response());
    }

    // Generate JWT claims with configurable TTL
    let ttl_secs = state.config.jwt_token_ttl_secs;
    let claims = match (resume_claims, creator_connection_id, creator_is_reserved) {
        (Some(resume), _, _) => WsTokenClaims::for_resume(
            room_id,
            resume.connection_id,
            ttl_secs,
            &state.config.jwt_issuer,
            mls_control_cursor,
        ),
        (None, Some(connection_id), true) => WsTokenClaims::for_resume(
            room_id,
            connection_id,
            ttl_secs,
            &state.config.jwt_issuer,
            mls_control_cursor,
        ),
        (None, Some(connection_id), false) => WsTokenClaims::new_for_connection(
            room_id,
            connection_id,
            ttl_secs,
            &state.config.jwt_issuer,
        ),
        (None, None, _) => WsTokenClaims::new(room_id, ttl_secs, &state.config.jwt_issuer),
    };
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

    // Return token response (protocol v1 metadata included for client-side gate).
    Ok(Json(WsTokenResponse {
        token,
        connection_id,
        expires_in: ttl_secs,
        protocol_version: crate::models::PINCHAT_PROTOCOL_VERSION,
        supported_subprotocols: vec!["pinchat.v1".to_string()],
        mls_control_cursor,
    }))
}
