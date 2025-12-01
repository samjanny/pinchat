use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::ip_hash::{extract_client_ip_with_proxy, hash_ip};
use crate::jwt::{sign_token, WsTokenClaims};
use crate::models::{CreateRoomResponse, Room, RoomConfig};
use crate::pow::{calculate_difficulty, PowChallenge};
use crate::state::AppState;

/// Homepage handler - redirects to static HTML
pub async fn homepage() -> Redirect {
    Redirect::permanent("/static/index.html")
}

/// Handler for creating a new room
///
/// Protected by 3 layers of DoS mitigation:
/// 1. IP-based rate limiting (tower-governor middleware)
/// 2. Proof-of-Work with dynamic difficulty
/// 3. Global room capacity limit
pub async fn create_room(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(config): Json<RoomConfig>,
) -> Result<Json<CreateRoomResponse>, Response> {
    // Extract and hash client IP for challenge cache lookup
    // Considers trusted proxies for X-Forwarded-For when configured
    let client_ip =
        extract_client_ip_with_proxy(&ConnectInfo(addr), &headers, &state.config.trusted_proxies);
    let ip_hash = hash_ip(&client_ip, &state.ip_hash_secret);
    // Validate configuration
    if config.ttl_minutes == 0 || config.ttl_minutes > 1440 {
        // Max 24 hours
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "TTL must be between 1 and 1440 minutes" })),
        )
            .into_response());
    }

    // Layer 2: Proof-of-Work verification (always required)
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
                // No challenge found for this IP - issue a new one
                let new_challenge = PowChallenge::new(difficulty);
                state
                    .challenge_cache
                    .store(ip_hash.clone(), new_challenge.clone());

                tracing::warn!("No cached challenge for IP, issuing new one");

                (
                    StatusCode::PRECONDITION_REQUIRED, // 428
                    Json(json!({
                        "error": "Challenge not found or expired, new challenge issued",
                        "pow_required": true,
                        "challenge": new_challenge.challenge,
                        "mask": new_challenge.mask,
                        "difficulty": difficulty
                    })),
                )
                    .into_response()
            })?;

            // Verify difficulty matches current requirement (prevent stale challenges)
            if cached_challenge.difficulty < difficulty {
                let new_challenge = PowChallenge::new(difficulty);
                state
                    .challenge_cache
                    .store(ip_hash.clone(), new_challenge.clone());

                return Err((
                    StatusCode::PRECONDITION_REQUIRED, // 428
                    Json(json!({
                        "error": "Difficulty increased, new challenge required",
                        "pow_required": true,
                        "challenge": new_challenge.challenge,
                        "mask": new_challenge.mask,
                        "difficulty": difficulty
                    })),
                )
                    .into_response());
            }

            // Verify PoW solution against cached challenge
            if !cached_challenge.verify(nonce) {
                tracing::warn!("Invalid PoW solution from IP");

                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "Invalid proof of work solution" })),
                )
                    .into_response());
            }

            tracing::info!("Valid PoW solution verified (challenge consumed)");

            // PoW valid, proceed to create room
        }
        None => {
            // No PoW provided, send challenge to client and store in cache
            let challenge = PowChallenge::new(difficulty);
            state
                .challenge_cache
                .store(ip_hash.clone(), challenge.clone());

            tracing::debug!("PoW challenge issued and cached");

            return Err((
                StatusCode::PRECONDITION_REQUIRED, // 428
                Json(json!({
                    "error": "Proof of work required",
                    "pow_required": true,
                    "challenge": challenge.challenge,
                    "mask": challenge.mask,
                    "difficulty": difficulty
                })),
            )
                .into_response());
        }
    }

    // Layer 3: Atomic room creation with capacity check
    // Uses mutex to prevent race condition where concurrent requests exceed max_rooms
    let room = Room::new(config);
    let room_id = room.id;
    let room_type = room.room_type;
    let ttl_minutes = room.ttl_minutes;
    let max_participants = room.max_participants;

    // Atomic check+insert (prevents concurrent requests from exceeding capacity)
    match state.try_create_room(room) {
        Ok(created_room_id) => {
            tracing::info!("Created room: {}", created_room_id);

            // Generate WebSocket token for room creator to avoid second PoW
            // This improves UX by eliminating the second challenge
            let ws_claims = WsTokenClaims::new(room_id, state.config.jwt_token_ttl_secs);
            let connection_id = ws_claims.connection_id;

            let ws_token = match sign_token(&ws_claims, &state.jwt_secret) {
                Ok(token) => {
                    tracing::info!(
                        "Generated WebSocket token for room creator (room: {}, connection: {})",
                        room_id,
                        connection_id
                    );
                    Some(token)
                }
                Err(e) => {
                    // Log error but don't fail room creation
                    // Creator will just need to solve PoW for WebSocket like others
                    tracing::error!("Failed to generate WebSocket token for creator: {}", e);
                    None
                }
            };

            let response = CreateRoomResponse {
                room_id,
                room_type,
                ttl_minutes,
                max_participants,
                connection_id: ws_token.as_ref().map(|_| connection_id),
                ws_token,
            };

            Ok(Json(response))
        }
        Err(_) => {
            // Server at capacity (checked atomically)
            Err((
                StatusCode::SERVICE_UNAVAILABLE, // 503
                Json(json!({
                    "error": "Server at maximum capacity",
                    "retry_after": 60 // Suggest retry after 60 seconds
                })),
            )
                .into_response())
        }
    }
}

/// Handler for the room page - redirects to static HTML with URL parameters
pub async fn room_page(
    State(state): State<AppState>,
    Path(room_id): Path<Uuid>,
) -> Result<Redirect, Response> {
    // Verify that the room exists
    let room = match state.rooms.get(&room_id) {
        Some(room) => room,
        None => {
            tracing::warn!("Room page access failed - Room {} not found", room_id);
            return Err((StatusCode::NOT_FOUND, "Room not found").into_response());
        }
    };

    #[cfg(debug_assertions)]
    {
        use chrono::Utc;
        let now = Utc::now();
        let time_since_creation = now.signed_duration_since(room.created_at);
        tracing::debug!(
            "Room page accessed - ID: {}, Created {} seconds ago, TTL: {} minutes",
            room_id,
            time_since_creation.num_seconds(),
            room.ttl_minutes
        );
    }

    // Verify that the room has not expired
    if room.is_expired() {
        tracing::warn!(
            "Room page access failed - Room {} has expired (created_at: {:?}, ttl_minutes: {})",
            room_id,
            room.created_at,
            room.ttl_minutes
        );
        state.remove_room(&room_id);
        return Err((StatusCode::GONE, "Room has expired").into_response());
    }

    // Verify that the room is not full
    if room.is_full() {
        tracing::warn!("Room page access failed - Room {} is full", room_id);
        return Err((StatusCode::FORBIDDEN, "Room is full").into_response());
    }

    tracing::info!(
        "Room page access successful - Redirecting to chat for room {}",
        room_id
    );

    // Redirect to static HTML with minimal URL (only room_id)
    // Room configuration will be sent via WebSocket to prevent information leakage
    let redirect_url = format!("/static/chat.html?room={}", room_id);

    Ok(Redirect::to(&redirect_url))
}
