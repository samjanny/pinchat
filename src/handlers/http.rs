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

use crate::challenge_cache::PowRejection;
use crate::handlers::auth::verify_csrf_for_api;
use crate::ip_hash::{extract_client_ip_with_proxy, hash_ip};
use crate::jwt::{WsTokenClaims, sign_token};
use crate::models::{CreateRoomResponse, Room, RoomConfig, RoomType};
use crate::pow::calculate_difficulty;
use crate::pow_session::{build_pow_cookie, presented_challenge, should_use_secure_pow_cookies};
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
) -> Result<Response, Response> {
    // CSRF: defence-in-depth on top of SameSite=Strict + session auth.
    // Required because /api/rooms is a state-creating endpoint reachable
    // from any authenticated context (XSS, sibling-subdomain takeover, ...).
    verify_csrf_for_api(&headers, &state.csrf_secret)?;
    if config.room_type == RoomType::Group && !state.config.group_chat_enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Group chat is not enabled on this server" })),
        )
            .into_response());
    }

    // Extract and hash client IP, which the challenge is bound to
    // Considers trusted proxies for X-Forwarded-For when configured
    let client_ip =
        extract_client_ip_with_proxy(&ConnectInfo(addr), &headers, &state.config.trusted_proxies);
    let ip_hash = hash_ip(&client_ip, &state.ip_hash_secret);

    // A client the WebSocket admission control would turn away is told now,
    // before it spends its proof of work. Advisory: the upgrade checks again
    // and takes the slot.
    if let Err(refused) = state.ws_admission_open(&state.client_address(&client_ip)) {
        return Err(crate::handlers::websocket::admission_refused(refused, true));
    }

    // Validate configuration
    if config.ttl_minutes == 0 || config.ttl_minutes > 1440 {
        // Max 24 hours
        return Err(pow_error_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "TTL must be between 1 and 1440 minutes" }),
            None,
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

    // A new challenge, bound to the client's address hash. Nothing is
    // stored; the challenge travels in the pc_pow cookie (pow_session.rs).
    let challenge_required = |error: &str| {
        let challenge = state.challenge_cache.issue(&ip_hash, difficulty);
        let cookie = build_pow_cookie(
            &challenge.challenge,
            should_use_secure_pow_cookies(state.config.force_secure_cookies),
            state.config.challenge_ttl_secs,
        );
        pow_error_response(
            StatusCode::PRECONDITION_REQUIRED,
            json!({
                "error": error,
                "pow_required": true,
                "challenge": challenge.challenge,
                "mask": challenge.mask,
                "difficulty": difficulty
            }),
            Some(cookie),
        )
    };

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
                        None,
                    )
                })?;

            // The challenge must be one this server issued to this address,
            // still valid and not used before; accepting the solution uses
            // it up. This prevents offline challenge fabrication.
            match state.challenge_cache.accept(
                &ip_hash,
                presented_challenge(&headers),
                nonce,
                difficulty,
            ) {
                Ok(()) => {
                    tracing::info!("Valid PoW solution verified (challenge consumed)");
                }
                Err(PowRejection::Unknown) => {
                    tracing::warn!("No valid challenge presented, issuing new one");
                    return Err(challenge_required(
                        "Challenge not found or expired, new challenge issued",
                    ));
                }
                Err(PowRejection::DifficultyTooLow) => {
                    // Stale challenge from before the load went up.
                    return Err(challenge_required(
                        "Difficulty increased, new challenge required",
                    ));
                }
                Err(PowRejection::WrongSolution) => {
                    tracing::warn!("Invalid PoW solution from IP");
                    return Err(pow_error_response(
                        StatusCode::FORBIDDEN,
                        json!({ "error": "Invalid proof of work solution" }),
                        None,
                    ));
                }
            }

            // PoW valid, proceed to create room
        }
        None => {
            // No PoW provided, send a challenge to the client
            tracing::debug!("PoW challenge issued");
            return Err(challenge_required("Proof of work required"));
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
    let creator_bootstrap_generation = room.creator_bootstrap_generation();

    // Allocate and sign the creator's WebSocket identity before publishing
    // the room. Group rooms fail closed here: inserting a room without a
    // usable token for its stored creator identity would permanently strand
    // the creator-only MLS administration invariant. One-to-one rooms retain
    // the legacy fallback where a later PoW-minted WebSocket token can be used.
    let ws_claims = match creator_connection_id {
        Some(connection_id) => WsTokenClaims::for_creator_bootstrap(
            room_id,
            connection_id,
            state.config.jwt_token_ttl_secs,
            &state.config.jwt_issuer,
            creator_bootstrap_generation,
            false,
            None,
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
            tracing::info!("Created room id={}...", short_room_id(&created_room_id));

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

            let mut response = Json(response).into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                "no-store".parse().expect("static Cache-Control value"),
            );
            Ok(response)
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
            // No part of the room id in warnings: minimal privacy mode
            // keeps them, and they must not record which rooms existed.
            tracing::warn!("Room page access failed - room not found");
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

    // Verify that the room has not expired.
    //
    // Audit L-4: this used to answer 410 Gone while a missing or full room
    // answered 404. That distinction told a caller holding a room id whether
    // the room had ever existed, which is the one bit UUIDv4 was chosen to
    // withhold. All three states now share a single response; the room is
    // still removed eagerly rather than waiting for the cleanup tick.
    if room_is_expired {
        tracing::warn!(
            "Room page access failed - room has expired (ttl_minutes: {})",
            ttl_minutes
        );
        state.remove_room(&room_id);
        return Err((StatusCode::NOT_FOUND, "Room not found").into_response());
    }

    // Verify that the room is not full.
    //
    // Returns 404 (same as "not found") rather than 403 to avoid leaking room
    // existence to callers probing random UUIDs. UUIDv4 (122 bits) makes blind
    // enumeration infeasible, but unified responses remove a metadata side-channel.
    if room_is_full {
        tracing::warn!("Room page access failed - room is full");
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
            max_ws_connections: crate::config::DEFAULT_MAX_WS_CONNECTIONS,
            max_ws_connections_per_address: crate::config::DEFAULT_MAX_WS_CONNECTIONS_PER_ADDRESS,
            max_http_connections: crate::config::DEFAULT_MAX_HTTP_CONNECTIONS,
            max_http_connections_per_address:
                crate::config::DEFAULT_MAX_HTTP_CONNECTIONS_PER_ADDRESS,
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
            group_chat_enabled: true,
        }
    }

    /// H2 regression: hitting the page of an EXPIRED room triggers the
    /// `state.remove_room` cleanup path. Before the fix the room read guard
    /// was still alive at that call and the handler deadlocked. The fix reads
    /// the needed fields and drops the guard first, so this must complete
    /// promptly while removing the room.
    ///
    /// L-4 regression: the response must be 404, indistinguishable from a room
    /// that never existed. A 410 here would leak the existence of the id.
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

        // Expired room -> Err(NOT_FOUND), same as a room that never existed.
        let response =
            handler_result.expect_err("expired room must return an error response, not a redirect");
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "expired room must be indistinguishable from a missing room (audit L-4)"
        );

        // The cleanup path must actually have removed the room.
        assert!(
            !state.rooms.contains_key(&room_id),
            "expired room must be removed by room_page"
        );
    }

    /// M-4 regression: the API must refuse `room_type: group`.
    ///
    /// The variant still deserializes off the wire and Room::new preserves it
    /// while capping participants at two, but the client only runs the ECDH +
    /// Double Ratchet handshake for `onetoone`. Both encryptMessage and
    /// decryptMessage throw without an initialised ratchet, so a group room
    /// cannot carry a single message. Reject at creation, before the PoW gate,
    /// so the caller sees a clear 400 rather than an opaque encryption failure
    /// at first send.
    /// Build the CSRF cookie + header pair `/api/rooms` requires. The token is
    /// minted from the state's own secret, so this exercises the real check
    /// rather than bypassing it.
    fn csrf_headers(state: &AppState) -> HeaderMap {
        let token = crate::auth::generate_csrf_token(&state.csrf_secret);
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("csrf_token={token}").parse().unwrap(),
        );
        headers.insert("x-csrf-token", token.parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn create_room_refuses_group_when_the_flag_is_off() {
        // Group rooms are gated behind GROUP_CHAT_ENABLED, which defaults to
        // false. With the flag off the endpoint answers 404 rather than
        // describing a feature this deployment does not run.
        let mut config = test_config();
        config.group_chat_enabled = false;
        let state = AppState::new(1000, config);
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = create_room(
            State(state.clone()),
            ConnectInfo(addr),
            csrf_headers(&state),
            Json(RoomConfig {
                room_type: RoomType::Group,
                ttl_minutes: 60,
                max_participants: 2,
            }),
        )
        .await;

        let response = result.expect_err("group rooms must be refused while the flag is off");
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a disabled feature must not be described to the caller"
        );
        assert_eq!(state.total_rooms(), 0, "no room may be created");
    }

    /// Counterpart to the above: a 1:1 request is NOT short-circuited by the
    /// type check. It falls through to the PoW gate and stops there with 428
    /// because this call carries no nonce, which shows the group branch is
    /// type-specific rather than a blanket rejection.
    #[tokio::test]
    async fn create_room_onetoone_reaches_pow_gate() {
        let state = AppState::new(1000, test_config());
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = create_room(
            State(state.clone()),
            ConnectInfo(addr),
            csrf_headers(&state),
            Json(RoomConfig {
                room_type: RoomType::OneToOne,
                ttl_minutes: 60,
                max_participants: 2,
            }),
        )
        .await;

        let response = result.expect_err("no PoW nonce supplied, so this cannot succeed");
        assert_eq!(
            response.status(),
            StatusCode::PRECONDITION_REQUIRED,
            "a 1:1 request must reach the PoW challenge"
        );
        assert_eq!(state.total_rooms(), 0);
    }

    /// The challenge comes back in the pc_pow cookie a 428 sets, and a
    /// solution creates one room, not two. Audit T-03: issuing a challenge
    /// keeps nothing on the server, so no number of other requests can
    /// take it away before it is solved.
    #[tokio::test]
    async fn a_solved_challenge_from_the_cookie_creates_one_room() {
        let mut config = test_config();
        config.pow_min_difficulty = 10;
        config.pow_max_difficulty = 10;
        let state = AppState::new(1000, config);
        let addr: SocketAddr = "203.0.113.20:9999".parse().unwrap();
        let body = || {
            Json(RoomConfig {
                room_type: RoomType::OneToOne,
                ttl_minutes: 60,
                max_participants: 2,
            })
        };

        let response = create_room(
            State(state.clone()),
            ConnectInfo(addr),
            csrf_headers(&state),
            body(),
        )
        .await
        .expect_err("first request gets a challenge");
        assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("the challenge is carried by the pc_pow cookie")
            .to_str()
            .unwrap()
            .to_string();
        let cookie = set_cookie.split(';').next().unwrap().to_string();
        let challenge = cookie.strip_prefix("pc_pow=").unwrap().to_string();
        let solver = crate::pow::PowChallenge {
            challenge: challenge.clone(),
            mask: String::new(),
            difficulty: 10,
        };
        let nonce = (0..).find(|n| solver.verify(*n)).unwrap();

        // Other clients asking for challenges in the meantime change nothing.
        for i in 0..200u8 {
            let other: SocketAddr = format!("198.51.100.{i}:9999").parse().unwrap();
            let _ = create_room(
                State(state.clone()),
                ConnectInfo(other),
                csrf_headers(&state),
                body(),
            )
            .await;
        }
        assert!(state.challenge_cache.is_empty());

        let solved = || {
            let mut headers = csrf_headers(&state);
            let csrf = headers
                .get(axum::http::header::COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            headers.insert(
                axum::http::header::COOKIE,
                format!("{csrf}; {cookie}").parse().unwrap(),
            );
            headers.insert("x-pow-nonce", nonce.to_string().parse().unwrap());
            headers
        };
        create_room(State(state.clone()), ConnectInfo(addr), solved(), body())
            .await
            .expect("the solution is accepted");
        assert_eq!(state.total_rooms(), 1);

        let replay = create_room(State(state.clone()), ConnectInfo(addr), solved(), body())
            .await
            .expect_err("the same solution is not accepted twice");
        assert_eq!(replay.status(), StatusCode::PRECONDITION_REQUIRED);
        assert_eq!(state.total_rooms(), 1);

        // Nor from another address.
        let elsewhere: SocketAddr = "203.0.113.21:9999".parse().unwrap();
        let response = create_room(
            State(state.clone()),
            ConnectInfo(elsewhere),
            solved(),
            body(),
        )
        .await
        .expect_err("a challenge is bound to the address it was issued to");
        assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
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
