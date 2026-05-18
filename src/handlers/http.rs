use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::Cookie;
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::ip_hash::{extract_client_ip_with_proxy, hash_ip};
use crate::jwt::{WsTokenClaims, sign_token};
use crate::models::{CreateRoomResponse, Room, RoomConfig};
use crate::pow::{PowChallenge, calculate_difficulty};
use crate::pow_session::{pow_cache_key, resolve_pow_session, should_use_secure_pow_cookies};
use crate::state::AppState;

/// Truncate a Uuid to the first 8 hex chars for non-strict logging. Enough
/// for debug correlation across log lines, not enough for an external
/// observer to recover the full room id from leaked logs.
fn short_room_id(id: &Uuid) -> String {
    let s = id.simple().to_string();
    s[..8.min(s.len())].to_string()
}

/// Build a 4xx/5xx response, attaching the given Set-Cookie header when
/// present. Centralised so every 428 path in the PoW handlers stays consistent.
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

    // Resolve PoW session cookie to disambiguate clients behind shared NAT.
    // A missing/invalid cookie yields a fresh UUID + a Set-Cookie header to
    // attach on whichever 428 this request emits.
    let use_secure = should_use_secure_pow_cookies(state.config.force_secure_cookies);
    let (pow_cookie, fresh_cookie) =
        resolve_pow_session(&headers, use_secure, state.config.challenge_ttl_secs);
    let cache_key = pow_cache_key(&ip_hash, &pow_cookie);

    // Validate configuration
    if config.ttl_minutes == 0 || config.ttl_minutes > 1440 {
        // Max 24 hours
        return Err(pow_error_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "TTL must be between 1 and 1440 minutes" }),
            fresh_cookie,
        ));
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
                    pow_error_response(
                        StatusCode::BAD_REQUEST,
                        json!({ "error": "Invalid nonce format" }),
                        fresh_cookie.clone(),
                    )
                })?;

            // Retrieve the issued challenge from cache to enforce one-time use
            // This prevents offline challenge fabrication attacks
            let cached_challenge = state.challenge_cache.take(&cache_key).ok_or_else(|| {
                // No challenge found for this (IP, cookie) pair - issue a new one
                let new_challenge = PowChallenge::new(difficulty);
                state
                    .challenge_cache
                    .store(cache_key.clone(), new_challenge.clone());

                tracing::warn!("No cached challenge for PoW session, issuing new one");

                pow_error_response(
                    StatusCode::PRECONDITION_REQUIRED,
                    json!({
                        "error": "Challenge not found or expired, new challenge issued",
                        "pow_required": true,
                        "challenge": new_challenge.challenge,
                        "mask": new_challenge.mask,
                        "difficulty": difficulty
                    }),
                    fresh_cookie.clone(),
                )
            })?;

            // Verify difficulty matches current requirement (prevent stale challenges)
            if cached_challenge.difficulty < difficulty {
                let new_challenge = PowChallenge::new(difficulty);
                state
                    .challenge_cache
                    .store(cache_key.clone(), new_challenge.clone());

                return Err(pow_error_response(
                    StatusCode::PRECONDITION_REQUIRED,
                    json!({
                        "error": "Difficulty increased, new challenge required",
                        "pow_required": true,
                        "challenge": new_challenge.challenge,
                        "mask": new_challenge.mask,
                        "difficulty": difficulty
                    }),
                    fresh_cookie,
                ));
            }

            // Verify PoW solution against cached challenge
            if !cached_challenge.verify(nonce) {
                tracing::warn!("Invalid PoW solution from IP");

                return Err(pow_error_response(
                    StatusCode::FORBIDDEN,
                    json!({ "error": "Invalid proof of work solution" }),
                    fresh_cookie,
                ));
            }

            tracing::info!("Valid PoW solution verified (challenge consumed)");

            // PoW valid, proceed to create room
        }
        None => {
            // No PoW provided, send challenge to client and store in cache
            let challenge = PowChallenge::new(difficulty);
            state
                .challenge_cache
                .store(cache_key.clone(), challenge.clone());

            tracing::debug!("PoW challenge issued and cached");

            return Err(pow_error_response(
                StatusCode::PRECONDITION_REQUIRED,
                json!({
                    "error": "Proof of work required",
                    "pow_required": true,
                    "challenge": challenge.challenge,
                    "mask": challenge.mask,
                    "difficulty": difficulty
                }),
                fresh_cookie,
            ));
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
            tracing::info!("Created room id={}…", short_room_id(&created_room_id));

            // Generate WebSocket token for room creator to avoid second PoW
            // This improves UX by eliminating the second challenge
            let ws_claims = WsTokenClaims::new(
                room_id,
                state.config.jwt_token_ttl_secs,
                &state.config.jwt_issuer,
            );
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
                // Always advertise protocol version so clients can gate even on
                // the creator-optimization path (where they would otherwise skip
                // /api/ws-token and miss the shape check).
                protocol_version: crate::models::PINCHAT_PROTOCOL_VERSION,
                supported_subprotocols: vec!["pinchat.v1".to_string()],
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
            tracing::warn!(
                "Room page access failed - Room {}… not found",
                short_room_id(&room_id)
            );
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
            "Room page access failed - Room {}… has expired (ttl_minutes: {})",
            short_room_id(&room_id),
            room.ttl_minutes
        );
        state.remove_room(&room_id);
        return Err((StatusCode::GONE, "Room has expired").into_response());
    }

    // Verify that the room is not full.
    //
    // Returns 404 (same as "not found") rather than 403 to avoid leaking room
    // existence to callers probing random UUIDs. UUIDv4 (122 bits) makes blind
    // enumeration infeasible, but unified responses remove a metadata side-channel.
    if room.is_full() {
        tracing::warn!(
            "Room page access failed - Room {}… is full",
            short_room_id(&room_id)
        );
        return Err((StatusCode::NOT_FOUND, "Room not found").into_response());
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
