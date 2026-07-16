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

use crate::handlers::auth::verify_csrf_for_api;
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
    // CSRF: defence-in-depth on top of SameSite=Strict + session auth.
    // Required because /api/rooms is a state-creating endpoint reachable
    // from any authenticated context (XSS, sibling-subdomain takeover, …).
    verify_csrf_for_api(&headers, &state.csrf_secret)?;

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
    let (room, creator_bootstrap_token) = Room::new_with_creator_bootstrap(config);
    let room_id = room.id;
    let room_type = room.room_type;
    let ttl_minutes = room.ttl_minutes;
    let max_participants = room.max_participants;
    let creator_connection_id = room.creator_connection_id();

    // Allocate and sign the creator's WebSocket identity before publishing
    // the room. Group rooms fail closed here: inserting a room without a
    // usable token for its stored creator identity would permanently strand
    // the creator-only MLS administration invariant. One-to-one rooms retain
    // the legacy fallback where a later PoW-minted WebSocket token can be used.
    let ws_claims = match creator_connection_id {
        Some(connection_id) => WsTokenClaims::new_for_connection(
            room_id,
            connection_id,
            state.config.jwt_token_ttl_secs,
            &state.config.jwt_issuer,
        ),
        None => WsTokenClaims::new(
            room_id,
            state.config.jwt_token_ttl_secs,
            &state.config.jwt_issuer,
        ),
    };
    let connection_id = ws_claims.connection_id;
    let ws_token = match sign_token(&ws_claims, &state.jwt_secret) {
        Ok(token) => Some(token),
        Err(error) if creator_connection_id.is_some() => {
            tracing::error!(
                "Failed to generate required WebSocket token for group creator: {}",
                error
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Unable to establish group creator identity" })),
            )
                .into_response());
        }
        Err(error) => {
            tracing::error!("Failed to generate WebSocket token for creator: {}", error);
            None
        }
    };

    // Atomic check+insert (prevents concurrent requests from exceeding capacity)
    match state.try_create_room(room) {
        Ok(created_room_id) => {
            tracing::info!("Created room id={}…", short_room_id(&created_room_id));

            if ws_token.is_some() {
                tracing::info!(
                    "Generated WebSocket token for room creator (room: {}, connection: {})",
                    room_id,
                    connection_id
                );
            }

            let response = CreateRoomResponse {
                room_id,
                room_type,
                ttl_minutes,
                max_participants,
                connection_id: ws_token.as_ref().map(|_| connection_id),
                ws_token,
                creator_bootstrap_token,
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
    // Read all room state needed below into locals, then drop the DashMap read
    // guard before any path that mutates `state.rooms`.
    //
    // The guard returned by `state.rooms.get(...)` read-locks the shard that
    // holds `room_id`. `remove_room` (called on the expired path) takes a write
    // lock on that same shard via `rooms.remove(...)`. Holding the read guard
    // across that call self-deadlocks the worker on a sharded RwLock. Scoping
    // the guard so it is released here keeps the expired-room cleanup safe.
    // `created_at` is only read by the debug-only timing log below; silence the
    // unused-variable lint in release builds where that block is compiled out.
    #[cfg_attr(not(debug_assertions), allow(unused_variables))]
    let (room_is_expired, room_is_full, ttl_minutes, created_at) = match state.rooms.get(&room_id) {
        Some(room) => (
            room.is_expired(),
            room.is_full(),
            room.ttl_minutes,
            room.created_at,
        ),
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
        let time_since_creation = now.signed_duration_since(created_at);
        tracing::debug!(
            "Room page accessed - ID: {}, Created {} seconds ago, TTL: {} minutes",
            room_id,
            time_since_creation.num_seconds(),
            ttl_minutes
        );
    }

    // Verify that the room has not expired
    if room_is_expired {
        tracing::warn!(
            "Room page access failed - Room {}… has expired (ttl_minutes: {})",
            short_room_id(&room_id),
            ttl_minutes
        );
        state.remove_room(&room_id);
        return Err((StatusCode::GONE, "Room has expired").into_response());
    }

    // Verify that the room is not full.
    //
    // Returns 404 (same as "not found") rather than 403 to avoid leaking room
    // existence to callers probing random UUIDs. UUIDv4 (122 bits) makes blind
    // enumeration infeasible, but unified responses remove a metadata side-channel.
    if room_is_full {
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

#[cfg(test)]
mod tests {
    //! Regression tests for the room_page handler.
    //!
    //! The key property under test (audit H2): room_page must NOT hold a
    //! DashMap read guard across `state.remove_room`, which write-locks the
    //! same shard. Holding it self-deadlocks the worker on the sharded
    //! RwLock. We exercise the expired-room cleanup path under a hard timeout
    //! so that a regression surfaces as a failed assertion rather than a hung
    //! test that blocks the whole suite forever.
    use super::*;
    use crate::config::Config;
    use crate::models::{Room, RoomConfig, RoomType};
    use crate::state::AppState;
    use chrono::Duration as ChronoDuration;
    use std::time::Duration;

    fn test_config() -> Config {
        Config {
            host: [127, 0, 0, 1],
            port: 0,
            ws_conn_burst_size: 100,
            ws_conn_period_secs: 60,
            room_token_burst_size: 100,
            room_token_period_secs: 600,
            msg_rate_limit: 30,
            msg_rate_window_secs: 1,
            room_msg_rate_limit: 120,
            room_byte_rate_limit: 8 * 1024 * 1024,
            commit_rate_limit: 12,
            commit_rate_window_secs: 60,
            proposal_rate_limit: 8,
            proposal_rate_window_secs: 60,
            frame_rate_limit: 120,
            protocol_error_limit: 10,
            pow_min_difficulty: 12,
            pow_max_difficulty: 18,
            challenge_ttl_secs: 300,
            jwt_token_ttl_secs: 30,
            jwt_issuer: crate::jwt::DEFAULT_JWT_ISSUER.to_string(),
            max_ws_connection_age_secs: 1800,
            ws_reconnect_grace_secs: 20,
            ecdh_burst_limit: 8,
            ecdh_burst_window_secs: 60,
            room_cleanup_interval_secs: 60,
            challenge_cleanup_interval_secs: 60,
            password_hashes: vec![],
            session_ttl_secs: 86400,
            login_burst_size: 5,
            login_period_secs: 900,
            trusted_proxies: vec![],
            replay_cache_max_per_room: 1000,
            force_secure_cookies: false,
            max_image_size: 300 * 1024,
            force_http: false,
            website_dir: None,
            allow_anonymous: true,
            cors_allowed_origins: vec!["https://localhost:3000".to_string()],
        }
    }

    /// H2 regression: hitting the page of an EXPIRED room triggers the
    /// `state.remove_room` cleanup path. Before the fix the room read guard
    /// was still alive at that call and the handler deadlocked. The fix reads
    /// the needed fields and drops the guard first, so this must complete
    /// promptly and return 410 GONE while removing the room.
    #[tokio::test]
    async fn expired_room_page_does_not_deadlock_and_removes_room() {
        let state = AppState::new(1000, test_config());

        let mut room = Room::new(RoomConfig {
            room_type: RoomType::OneToOne,
            ttl_minutes: 1,
            max_participants: 2,
        });
        // Force the room well past its absolute TTL so is_expired() is true.
        room.created_at = chrono::Utc::now() - ChronoDuration::minutes(10);
        let room_id = room.id;
        state.try_create_room(room).unwrap();
        assert!(
            state.rooms.contains_key(&room_id),
            "room must exist pre-call"
        );

        // Wrap in a hard timeout: a deadlock regression manifests as elapsing
        // here instead of returning. 5s is generous; the correct path returns
        // in microseconds.
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            room_page(State(state.clone()), Path(room_id)),
        )
        .await;

        let handler_result =
            result.expect("room_page deadlocked on expired-room cleanup (audit H2)");

        // Expired room -> Err(GONE).
        let response =
            handler_result.expect_err("expired room must return an error response, not a redirect");
        assert_eq!(
            response.status(),
            StatusCode::GONE,
            "expired room must yield 410 GONE"
        );

        // The cleanup path must actually have removed the room.
        assert!(
            !state.rooms.contains_key(&room_id),
            "expired room must be removed by room_page"
        );
    }

    /// Sanity counterpart: a live, non-full room redirects to the chat page
    /// and does not touch the removal path.
    #[tokio::test]
    async fn live_room_page_redirects() {
        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::OneToOne,
            ttl_minutes: 60,
            max_participants: 2,
        });
        let room_id = room.id;
        state.try_create_room(room).unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            room_page(State(state.clone()), Path(room_id)),
        )
        .await
        .expect("room_page must not hang for a live room");

        assert!(result.is_ok(), "live room must redirect, got error");
        assert!(
            state.rooms.contains_key(&room_id),
            "live room must NOT be removed"
        );
    }

    #[tokio::test]
    async fn group_room_page_stays_visible_for_reserved_creator_slot() {
        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 2,
        });
        let room_id = room.id;
        state.try_create_room(room).unwrap();
        assert!(
            state
                .add_connection(Uuid::new_v4(), room_id, false)
                .is_none(),
            "non-creator admission waits for the creator's stream boundary"
        );
        {
            let room = state.rooms.get(&room_id).unwrap();
            assert!(room.is_full_for_non_creator());
            assert!(
                !room.is_full(),
                "the creator's physical slot remains available"
            );
        }

        let result = room_page(State(state), Path(room_id)).await;
        assert!(
            result.is_ok(),
            "room_page must not hide the reserved creator slot"
        );
    }
}
