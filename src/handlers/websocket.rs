use axum::{
    extract::{
        Path, State, WebSocketUpgrade,
        ws::{Message as WsMessage, WebSocket},
    },
    http::{HeaderMap, StatusCode, header, header::SEC_WEBSOCKET_PROTOCOL},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use tokio::time::{Duration, Instant, interval};
use uuid::Uuid;

use crate::jwt::verify_token;
use crate::models::{IncomingMessage, Message};
use crate::state::AppState;

/// Maximum allowed size for ECDH public key payload (8KB)
/// Typical ECDH payload with P-256: ~500 bytes (65-byte key + encryption overhead + AAD)
/// 8KB limit prevents DoS attacks with oversized payloads
const MAX_ECDH_PAYLOAD_SIZE: usize = 8192;

/// Minimum WebSocket message/frame size (512KB)
/// Used as floor even for small image configs to support text messages and handshakes
const MIN_WS_SIZE: usize = 524288;

/// Calculates maximum image payload size from raw image size
/// Accounts for ~37% overhead from base64 encoding + encryption
fn max_image_payload_size(max_image_size: usize) -> usize {
    // Base64 adds ~33% overhead, encryption adds ~4% more
    (max_image_size as f64 * 1.37) as usize
}

/// Calculates maximum WebSocket message/frame size based on max_image_size
/// Ensures sufficient headroom for the largest possible image payload
fn max_ws_size(max_image_size: usize) -> usize {
    // Use at least MIN_WS_SIZE, or larger if needed for big images
    // Add 50% margin on top of image payload for protocol overhead and safety
    let image_payload = max_image_payload_size(max_image_size);
    std::cmp::max(MIN_WS_SIZE, (image_payload as f64 * 1.5) as usize)
}

/// Transport-level MLS references are SHA-256 values encoded as unpadded
/// base64url (32 bytes -> exactly 43 ASCII characters). Cryptographic
/// equality is checked by the browser; the relay only rejects malformed
/// framing before rebroadcasting it.
fn valid_mls_correlation_ref(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        // A 32-byte input leaves two bytes in the final Base64 quantum.
        // The low two bits of the last sextet must therefore be zero; this
        // rejects alternate, non-canonical spellings of the same digest.
        && matches!(
            value.as_bytes()[42],
            b'A' | b'E' | b'I' | b'M' | b'Q' | b'U' | b'Y' | b'c'
                | b'g' | b'k' | b'o' | b's' | b'w' | b'0' | b'4' | b'8'
        )
}

/// Handler for upgrading the WebSocket connection (protocol v1).
///
/// JWT is carried in the `Sec-WebSocket-Protocol` header rather than a query
/// string, so it never appears in access logs, proxy logs, or Referer headers.
/// The client offers two subprotocols in a comma-separated list:
///   - `pinchat.v1`                (the wire-protocol version; echoed in the 101 response)
///   - `pinchat.v1.jwt.<token>`    (base64url-encoded single-use JWT)
///
/// Both MUST be present. The server echoes only `pinchat.v1` back so the
/// token never appears in the upgrade response.
///
/// # Security
/// - Requires explicit `pinchat.v1` subprotocol (gate against v0 clients)
/// - Validates JWT signature + expiration (30s) + room_id claim + single-use jti
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(room_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    // Read Sec-WebSocket-Protocol; absence = client did not perform a v1 handshake.
    let sec_proto = match headers
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|h| h.to_str().ok())
    {
        Some(s) => s,
        None => {
            return (StatusCode::UNAUTHORIZED, "Missing Sec-WebSocket-Protocol").into_response();
        }
    };

    let offered: Vec<&str> = sec_proto.split(',').map(|s| s.trim()).collect();

    // Gate: client MUST offer the base `pinchat.v1` subprotocol.
    if !offered.contains(&"pinchat.v1") {
        tracing::warn!("WebSocket upgrade rejected: base pinchat.v1 subprotocol missing");
        return (StatusCode::UPGRADE_REQUIRED, "Protocol pinchat.v1 required").into_response();
    }

    // Extract JWT from the `pinchat.v1.jwt.<token>` companion subprotocol.
    let token = match offered
        .iter()
        .find_map(|p| p.strip_prefix("pinchat.v1.jwt."))
    {
        Some(t) => t,
        None => {
            tracing::warn!("WebSocket upgrade rejected: JWT subprotocol missing");
            return (StatusCode::UNAUTHORIZED, "Missing JWT in subprotocol").into_response();
        }
    };

    // C-07: Order matters. All stateless rejections (Origin, signature, room
    // claim) MUST run BEFORE the single-use JTI consumption. Otherwise a
    // bounce of a legitimate token through an Origin/room-mismatch path
    // would burn its jti and lock the real client out of its own session.

    // Origin check — defense-in-depth (RFC 6455 §4.1).
    // The primary guard is the SameSite=Strict session cookie preventing
    // cross-origin token acquisition; this check makes the guarantee
    // explicit and holds even if that assumption ever changes.
    //
    // Production policy (PRIVACY_MODE != "development"): Origin is REQUIRED
    // and must be in the allowlist. A missing Origin would let a non-browser
    // client (curl/script) with a stolen session cookie bypass the allowlist.
    // Development policy: a missing Origin is allowed so test harnesses and
    // raw-socket integration tests still work.
    let dev_mode = std::env::var("PRIVACY_MODE").unwrap_or_default() == "development";
    match headers.get(header::ORIGIN) {
        Some(origin_val) => {
            let origin_str = origin_val.to_str().unwrap_or("");
            if !state
                .config
                .cors_allowed_origins
                .iter()
                .any(|o| o == origin_str)
            {
                tracing::warn!(
                    "WebSocket upgrade rejected: Origin '{}' not in allowlist",
                    origin_str
                );
                return (StatusCode::FORBIDDEN, "Origin not allowed").into_response();
            }
        }
        None if !dev_mode => {
            tracing::warn!("WebSocket upgrade rejected: Origin header missing (production)");
            return (StatusCode::FORBIDDEN, "Origin header required").into_response();
        }
        None => {
            // dev mode: tolerate missing Origin for raw-socket test clients
        }
    }

    // Validate JWT token before accepting the WebSocket upgrade.
    // Audit C-2: verify_token now pins both `aud` (WS_TOKEN_AUDIENCE) and
    // `iss` (state.config.jwt_issuer) in addition to the algorithm and
    // expiry. A token forged or replayed from another component, audience,
    // or PinChat instance fails here even if the HMAC checks out.
    let claims = match verify_token(token, &state.jwt_secret, &state.config.jwt_issuer) {
        Ok(claims) => claims,
        Err(e) => {
            tracing::warn!("Invalid JWT token for WebSocket: {}", e);
            return (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response();
        }
    };

    // Verify room_id matches token claim (prevent token reuse for different rooms)
    if claims.room_id != room_id {
        tracing::warn!(
            "JWT room_id mismatch: token={}, path={}",
            claims.room_id,
            room_id
        );
        return (StatusCode::FORBIDDEN, "Token not valid for this room").into_response();
    }

    // SECURITY: Single-use token enforcement (prevents replay attacks).
    // C-07: this is the LAST gate before upgrade — every stateless check
    // above has already passed by the time we mutate state. A failed
    // upgrade attempt past this point cannot have "wasted" the JTI of a
    // legitimate client whose Origin / room / signature didn't match.
    if !state.consume_token(claims.jti, state.config.jwt_token_ttl_secs) {
        tracing::warn!(
            "JWT token replay attempt detected: jti={}, room={}",
            claims.jti,
            room_id
        );
        return (StatusCode::FORBIDDEN, "Token already used").into_response();
    }

    tracing::info!(
        "WebSocket upgrade authenticated for room {} (connection_id: {})",
        room_id,
        claims.connection_id
    );

    let connection_id = claims.connection_id;
    let ws_size = max_ws_size(state.config.max_image_size);

    // Echo only the base subprotocol back (do NOT echo the jwt.* companion —
    // the RFC requires the response subprotocol to be one the client offered,
    // but we pick the non-secret one so the 101 response carries no token).
    ws.protocols(["pinchat.v1"])
        .max_message_size(ws_size)
        .max_frame_size(ws_size)
        .on_upgrade(move |socket| handle_socket(socket, state, room_id, connection_id))
}

/// Increments the per-connection protocol-error counter. Returns true once the
/// counter reaches `config.protocol_error_limit`, signalling the recv loop to
/// close the connection. Counts parse failures, unknown msg_type, and ECDH
/// oversize — categories a well-behaved client never produces.
fn bump_protocol_error(state: &AppState, connection_id: Uuid) -> bool {
    let limit = state.config.protocol_error_limit;
    let mut entry = state
        .connection_protocol_errors
        .entry(connection_id)
        .or_insert(0);
    *entry = entry.saturating_add(1);
    let current = *entry;
    if current >= limit {
        tracing::warn!(
            "Connection {} exceeded protocol error limit ({}/{}), closing",
            connection_id,
            current,
            limit
        );
        true
    } else {
        false
    }
}

/// Handles the WebSocket connection
///
/// # Arguments
/// * `socket` - WebSocket connection
/// * `state` - Application state
/// * `room_id` - Room ID (already validated by ws_handler)
/// * `connection_id` - Pre-allocated connection ID from JWT token (ensures uniqueness)
async fn handle_socket(socket: WebSocket, state: AppState, room_id: Uuid, connection_id: Uuid) {
    // Verify that the room exists AND is not expired.
    // Without the is_expired() gate, a room past its hard TTL can still accept
    // new WebSocket connections until the next cleanup tick (default 60s).
    let room_status = state.rooms.get(&room_id).map(|r| r.is_expired());
    match room_status {
        Some(false) => {}
        Some(true) => {
            #[cfg(debug_assertions)]
            tracing::debug!("WebSocket connection attempt to expired room");
            state.remove_room(&room_id);
            return;
        }
        None => {
            #[cfg(debug_assertions)]
            tracing::debug!("WebSocket connection attempt to non-existent room");
            return;
        }
    }

    // connection_id is pre-allocated from JWT token (not generated here)

    // Attempt to add the connection to the room
    if !state.add_connection(connection_id, room_id) {
        #[cfg(debug_assertions)]
        tracing::debug!("Failed to add connection to room (full or unavailable)");
        // Room is full or another error
        let _ = send_error(socket, "Room is full or unavailable").await;
        return;
    }

    #[cfg(debug_assertions)]
    tracing::debug!(
        "Connection joined room ({} participants)",
        state.get_participant_count(&room_id)
    );

    // Split the socket into sender and receiver
    let (mut sender, mut receiver) = socket.split();

    // Get validated room configuration from server (prevents URL spoofing)
    let (room_type, ttl_minutes, max_participants, created_at) = {
        let room = state.rooms.get(&room_id).expect("Room must exist");
        (
            room.room_type,
            room.ttl_minutes,
            room.max_participants,
            room.created_at,
        )
    };

    // Send connection confirmation message with validated room config
    let connected_msg = Message::Connected {
        user_id: connection_id,
        room_id,
        participant_count: state.get_participant_count(&room_id),
        room_type,                                   // Validated from server
        ttl_minutes,                                 // Validated from server
        max_participants,                            // Validated from server
        max_image_size: state.config.max_image_size, // From server config
        created_at,                                  // Room creation timestamp for countdown
    };

    if let Ok(json) = serde_json::to_string(&connected_msg) {
        let _ = sender.send(WsMessage::Text(json)).await;
    }

    // Notify other users that someone joined (broadcast BEFORE subscribing)
    let join_msg = Message::UserJoined {
        user_id: connection_id,
        participant_count: state.get_participant_count(&room_id),
    };

    if let Ok(json) = serde_json::to_string(&join_msg) {
        if let Some(tx) = state.broadcast_channels.get(&room_id) {
            let _ = tx.send(json);
        }
    }

    // Now subscribe to the broadcast channel (after sending UserJoined)
    // This ensures the client doesn't receive their own join message
    let mut broadcast_rx = match state.broadcast_channels.get(&room_id) {
        Some(tx) => tx.subscribe(),
        None => {
            tracing::error!("Broadcast channel not found for room");
            state.remove_connection(&connection_id);
            return;
        }
    };

    // Task that receives broadcast messages and forwards them to the client
    // Also sends heartbeat pings every 30 seconds to keep the connection alive,
    // and re-validates room TTL to enforce the hard expiry deadline even on
    // connections opened just before the TTL boundary.
    let send_state = state.clone();
    let connected_at = Instant::now();
    let max_connection_age = Duration::from_secs(send_state.config.max_ws_connection_age_secs);
    let mut send_task = tokio::spawn(async move {
        let mut ping_interval = interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                result = broadcast_rx.recv() => {
                    match result {
                        Ok(msg) => {
                            if sender.send(WsMessage::Text(msg)).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = ping_interval.tick() => {
                    // Enforce room TTL at every ping tick (~30s). Without this,
                    // a connection can outlive its room up to the cleanup tick
                    // (default 60s) after the hard expiry.
                    let expired = send_state
                        .rooms
                        .get(&room_id)
                        .map(|r| r.is_expired())
                        .unwrap_or(true);
                    if expired {
                        #[cfg(debug_assertions)]
                        tracing::debug!("Room TTL expired on live connection, closing");
                        send_state.remove_room(&room_id);
                        let _ = sender.send(WsMessage::Close(None)).await;
                        break;
                    }
                    // Hard cap on connection lifetime: even an active client is
                    // forced to reconnect, which re-runs PoW + JWT issuance and
                    // restarts the Double Ratchet handshake. Bounds resource
                    // usage from clients that heartbeat indefinitely.
                    if connected_at.elapsed() > max_connection_age {
                        #[cfg(debug_assertions)]
                        tracing::debug!("Connection exceeded max age, closing");
                        let _ = sender.send(WsMessage::Close(None)).await;
                        break;
                    }
                    if sender.send(WsMessage::Ping(vec![])).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Task that receives messages from the client and broadcasts them.
    // The 90-second idle timeout closes zombie connections that stop sending
    // frames (including pong responses) within that window, protecting
    // against file-descriptor exhaustion from stale TCP sessions.
    const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
    let state_clone = state.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Ok(Some(Ok(msg))) = tokio::time::timeout(IDLE_TIMEOUT, receiver.next()).await {
            // C-14: classify the frame up front. Close terminates the loop
            // and is not counted against the rate limit. All other frame
            // types (Text, Binary, Ping, Pong) pass through the lifecycle
            // gates and the global rate limiter, but only Text is
            // application-relevant — Binary/Ping/Pong are accounted for
            // and dropped.
            let text = match msg {
                WsMessage::Close(_) => break,
                WsMessage::Text(t) => Some(t),
                _ => None,
            };

            // Enforce room TTL on the receive path. Hoisted above the
            // type-specific branch so a hostile peer flooding Ping/Binary
            // on an already-expired room is severed immediately.
            let room_alive = state_clone
                .rooms
                .get(&room_id)
                .map(|r| !r.is_expired())
                .unwrap_or(false);
            if !room_alive {
                #[cfg(debug_assertions)]
                tracing::debug!("Recv on expired room, closing");
                break;
            }
            // Hard cap on connection lifetime. The send-side ping check
            // already enforces this, but applying it here closes the
            // connection on the next inbound frame instead of waiting
            // for the next ping tick.
            if connected_at.elapsed() > max_connection_age {
                #[cfg(debug_assertions)]
                tracing::debug!("Recv past max connection age, closing");
                break;
            }

            // GLOBAL FRAME RATE LIMIT (C-14): counts EVERY non-Close frame,
            // not just Text. Previously the limiter sat inside the Text
            // branch; a hostile peer could flood Ping/Pong/Binary frames
            // to keep the recv loop busy without consuming the budget.
            // axum/tungstenite auto-answers Ping with Pong, but the recv
            // task still wakes up for each frame and burns CPU; this
            // closes the gap. Lifecycle-bound (Close + max age + room
            // expiry) frames still bypass the counter because they break
            // the loop above.
            {
                let frame_limit = state_clone.config.frame_rate_limit;
                let window = state_clone.config.msg_rate_window_secs;
                let now = Utc::now();
                let cutoff = now - chrono::Duration::seconds(window);
                let mut ts = state_clone
                    .connection_frame_timestamps
                    .entry(connection_id)
                    .or_default();
                ts.retain(|&t| t > cutoff);
                if ts.len() >= frame_limit {
                    tracing::warn!(
                        "Connection {} exceeded frame rate limit ({}/{}s), disconnecting",
                        connection_id,
                        ts.len(),
                        window
                    );
                    break;
                }
                ts.push_back(now);
            }

            // Per-type handling: only Text frames carry application data.
            // Binary/Ping/Pong have been counted above and are dropped
            // silently here.
            let Some(text) = text else {
                continue;
            };

            // Early size check before JSON parsing
            // This acts as an extra safeguard in addition to WebSocket frame limits
            let ws_limit = max_ws_size(state_clone.config.max_image_size);
            if text.len() > ws_limit {
                tracing::warn!(
                    "⚠️ Message exceeds size limit: {} bytes (max {}) from connection_id={} - closing connection",
                    text.len(),
                    ws_limit,
                    connection_id
                );
                break; // Close connection
            }

            {
                // Parse the incoming message
                match serde_json::from_str::<IncomingMessage>(&text) {
                    Ok(incoming) => {
                        // Handle ECDH public key exchange (blind relay, no crypto server-side)
                        if incoming.msg_type == "ecdh_public_key" {
                            // Per-connection ECDH burst limiter. The looser
                            // frame_rate_limit (default 120/s) was the only gate
                            // here; an authenticated peer could flood handshake
                            // frames and force the receiver client into repeated
                            // signature verification + key import + Double
                            // Ratchet reinit. Real handshakes need 1–2 frames
                            // per session, so a small burst over a long window
                            // is more than enough for legitimate reconnects.
                            {
                                let limit = state_clone.config.ecdh_burst_limit;
                                let window = state_clone.config.ecdh_burst_window_secs;
                                let now = Utc::now();
                                let cutoff = now - chrono::Duration::seconds(window);
                                let mut ts = state_clone
                                    .connection_ecdh_timestamps
                                    .entry(connection_id)
                                    .or_default();
                                ts.retain(|&t| t > cutoff);
                                if ts.len() >= limit {
                                    tracing::warn!(
                                        "Connection {} exceeded ECDH burst limit ({}/{}s), disconnecting",
                                        connection_id,
                                        ts.len(),
                                        window
                                    );
                                    break;
                                }
                                ts.push_back(now);
                            }

                            tracing::info!(
                                "ECDH public key received from connection_id={} in room={}",
                                connection_id,
                                room_id
                            );

                            if let Some(payload) = incoming.payload {
                                tracing::debug!("ECDH payload length: {} bytes", payload.len());

                                // SECURITY: Validate payload size to prevent DoS attacks
                                if payload.len() > MAX_ECDH_PAYLOAD_SIZE {
                                    tracing::warn!(
                                        "⚠️ ECDH payload too large: {} bytes (max {} bytes) from connection_id={} - rejecting",
                                        payload.len(),
                                        MAX_ECDH_PAYLOAD_SIZE,
                                        connection_id
                                    );

                                    if bump_protocol_error(&state_clone, connection_id) {
                                        break;
                                    }
                                    continue;
                                }

                                // Create ECDH public key message
                                let ecdh_msg = Message::ECDHPublicKey {
                                    payload,
                                    sender_id: connection_id,
                                };

                                match serde_json::to_string(&ecdh_msg) {
                                    Ok(json) => {
                                        tracing::debug!(
                                            "ECDH message serialized, attempting broadcast..."
                                        );

                                        // Broadcast to all participants in the room
                                        if let Some(tx) =
                                            state_clone.broadcast_channels.get(&room_id)
                                        {
                                            match tx.send(json) {
                                                Ok(receiver_count) => {
                                                    tracing::info!(
                                                        "✅ ECDH public key broadcasted to {} receivers in room={}",
                                                        receiver_count,
                                                        room_id
                                                    );
                                                }
                                                Err(e) => {
                                                    tracing::error!(
                                                        "❌ Failed to broadcast ECDH message: {}",
                                                        e
                                                    );
                                                }
                                            }
                                        } else {
                                            tracing::error!(
                                                "❌ Broadcast channel not found for room={}",
                                                room_id
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "❌ Failed to serialize ECDH message: {}",
                                            e
                                        );
                                    }
                                }
                            } else {
                                tracing::warn!(
                                    "⚠️ ECDH message received but payload is missing (connection_id={})",
                                    connection_id
                                );
                            }
                        }
                        // MLS envelope (RFC 9420). Blind relay: the server never
                        // parses the wire format. DoS caps + anti-replay + rate
                        // limit apply identically to "message" / "image".
                        else if incoming.msg_type == "mls" {
                            let payload = match incoming.payload {
                                Some(p) => p,
                                None => {
                                    tracing::warn!(
                                        "mls envelope without payload from connection_id={}",
                                        connection_id
                                    );
                                    if bump_protocol_error(&state_clone, connection_id) {
                                        break;
                                    }
                                    continue;
                                }
                            };
                            let wire_format = match incoming.wire_format {
                                Some(w) => w,
                                None => {
                                    tracing::warn!(
                                        "mls envelope without wire_format from connection_id={}",
                                        connection_id
                                    );
                                    if bump_protocol_error(&state_clone, connection_id) {
                                        break;
                                    }
                                    continue;
                                }
                            };

                            // Upper bound on the MLS payload itself: Welcome
                            // and Commit messages stay well under the image
                            // ceiling, which is also the AEAD-framed budget.
                            let max_size =
                                max_image_payload_size(state_clone.config.max_image_size);
                            if payload.len() > max_size {
                                tracing::warn!(
                                    "mls payload too large from connection_id={} ({} > {})",
                                    connection_id,
                                    payload.len(),
                                    max_size
                                );
                                if bump_protocol_error(&state_clone, connection_id) {
                                    break;
                                }
                                continue;
                            }
                            // Tighter cap on ratchet_tree side-channel: a
                            // 64 KB tree comfortably fits ≥ 32-leaf groups
                            // at ciphersuite 0x0002 (~2 KB/leaf in the
                            // worst case), well above our ≤ 20-member
                            // room cap. Larger blobs are bandwidth +
                            // CPU amplification (every joiner has to
                            // tree-hash whatever they receive) — drop
                            // them rather than forward.
                            const RATCHET_TREE_MAX_BYTES: usize = 64 * 1024;
                            let rt_len =
                                incoming.ratchet_tree.as_ref().map(|s| s.len()).unwrap_or(0);
                            if rt_len > RATCHET_TREE_MAX_BYTES {
                                tracing::warn!(
                                    "mls ratchet_tree too large from connection_id={} ({} > {})",
                                    connection_id,
                                    rt_len,
                                    RATCHET_TREE_MAX_BYTES
                                );
                                if bump_protocol_error(&state_clone, connection_id) {
                                    break;
                                }
                                continue;
                            }

                            // Add/Welcome correlation metadata. These values
                            // are opaque to the relay, but their canonical,
                            // fixed-size framing is cheap to enforce and
                            // prevents unbounded/arbitrary strings from being
                            // reflected to every room participant.
                            let key_package_ref = incoming.key_package_ref;
                            let commit_ref = incoming.commit_ref;
                            let malformed_ref = key_package_ref
                                .as_deref()
                                .map(|value| !valid_mls_correlation_ref(value))
                                .unwrap_or(false)
                                || commit_ref
                                    .as_deref()
                                    .map(|value| !valid_mls_correlation_ref(value))
                                    .unwrap_or(false);
                            const WIRE_PUBLIC_MESSAGE: u16 = 1;
                            const WIRE_WELCOME: u16 = 3;
                            let invalid_ref_placement = match wire_format {
                                WIRE_WELCOME => key_package_ref.is_none() || commit_ref.is_none(),
                                WIRE_PUBLIC_MESSAGE => {
                                    key_package_ref.is_some() && commit_ref.is_none()
                                }
                                _ => key_package_ref.is_some() || commit_ref.is_some(),
                            };
                            if malformed_ref || invalid_ref_placement {
                                tracing::warn!(
                                    "invalid MLS correlation metadata from connection_id={}",
                                    connection_id
                                );
                                if bump_protocol_error(&state_clone, connection_id) {
                                    break;
                                }
                                continue;
                            }

                            // Anti-replay by payload hash, same pattern as the
                            // 1:1 relay — a retransmitted MLS envelope is
                            // silently discarded rather than broadcast twice.
                            let payload_hash = {
                                let mut hasher = Sha256::new();
                                hasher.update(payload.as_bytes());
                                format!("{:x}", hasher.finalize())
                            };
                            let mut seen_hashes = state_clone
                                .seen_message_hashes
                                .entry(room_id)
                                .or_insert_with(HashSet::new);
                            let room_ttl_minutes = state_clone
                                .rooms
                                .get(&room_id)
                                .map(|r| r.ttl_minutes)
                                .unwrap_or(60);
                            let cutoff =
                                Utc::now() - chrono::Duration::minutes(room_ttl_minutes as i64);
                            seen_hashes.retain(|(_, ts)| *ts > cutoff);
                            let now = Utc::now();
                            if seen_hashes.iter().any(|(h, _)| h == &payload_hash) {
                                continue;
                            }
                            let max_entries = state_clone.config.replay_cache_max_per_room;
                            if seen_hashes.len() >= max_entries {
                                let mut entries: Vec<_> = seen_hashes.iter().cloned().collect();
                                entries.sort_by(|a, b| b.1.cmp(&a.1));
                                entries.truncate(max_entries - 1);
                                seen_hashes.clear();
                                for entry in entries {
                                    seen_hashes.insert(entry);
                                }
                            }
                            seen_hashes.insert((payload_hash, now));

                            // Per-connection rate limit (same cadence).
                            let max_messages = state_clone.config.msg_rate_limit;
                            let rate_window_secs = state_clone.config.msg_rate_window_secs;
                            let mut timestamps = state_clone
                                .connection_message_timestamps
                                .entry(connection_id)
                                .or_insert_with(VecDeque::new);
                            let rate_cutoff = now - chrono::Duration::seconds(rate_window_secs);
                            timestamps.retain(|&ts| ts > rate_cutoff);
                            if timestamps.len() >= max_messages {
                                tracing::warn!(
                                    "Connection {} exceeded rate limit on mls, disconnecting",
                                    connection_id
                                );
                                break;
                            }
                            timestamps.push_back(now);
                            // Release the entry guard before grabbing the
                            // commit-specific one to avoid holding two
                            // DashMap shards across an await point.
                            drop(timestamps);

                            // Tighter per-connection commit rate limit.
                            // wire_format = 1 (MLS_PUBLIC_MESSAGE) is the
                            // Commit channel — every other room member has
                            // to verify TreeKEM + signatures + transcripts
                            // on receipt, so the cost scales with member
                            // count. A handful of commits per minute is
                            // far below any legitimate add/remove cadence.
                            if wire_format == WIRE_PUBLIC_MESSAGE {
                                let max_commits = state_clone.config.commit_rate_limit;
                                let commit_window = state_clone.config.commit_rate_window_secs;
                                let mut commit_ts = state_clone
                                    .connection_commit_timestamps
                                    .entry(connection_id)
                                    .or_insert_with(VecDeque::new);
                                let commit_cutoff = now - chrono::Duration::seconds(commit_window);
                                commit_ts.retain(|&ts| ts > commit_cutoff);
                                if commit_ts.len() >= max_commits {
                                    tracing::warn!(
                                        "Connection {} exceeded MLS commit rate limit ({}/{}s), dropping",
                                        connection_id,
                                        max_commits,
                                        commit_window
                                    );
                                    if bump_protocol_error(&state_clone, connection_id) {
                                        break;
                                    }
                                    continue;
                                }
                                commit_ts.push_back(now);
                            }

                            let broadcast_msg = Message::Mls {
                                payload,
                                wire_format,
                                ratchet_tree: incoming.ratchet_tree,
                                key_package_ref,
                                commit_ref,
                                sender_id: connection_id,
                            };
                            if let Ok(json) = serde_json::to_string(&broadcast_msg) {
                                if let Some(tx) = state_clone.broadcast_channels.get(&room_id) {
                                    let _ = tx.send(json);
                                }
                            }

                            if let Some(mut room) = state_clone.rooms.get_mut(&room_id) {
                                room.update_activity();
                            }
                        }
                        // Handle regular encrypted message (text or image)
                        else if incoming.msg_type == "message" || incoming.msg_type == "image" {
                            if let Some(payload) = incoming.payload {
                                // Validate payload size based on message type
                                let max_size = if incoming.msg_type == "image" {
                                    max_image_payload_size(state_clone.config.max_image_size)
                                } else {
                                    65536 // 64KB for text messages
                                };

                                if payload.len() > max_size {
                                    tracing::warn!(
                                        "{} payload too large: {} bytes (limit: {} bytes)",
                                        incoming.msg_type,
                                        payload.len(),
                                        max_size
                                    );
                                    continue;
                                }

                                // Validate header: must be present, v1, and within size bounds.
                                // The cryptographic signature verification happens client-side
                                // (server is blind relay), but we enforce shape + DoS caps here.
                                const MAX_SIG_LEN: usize = 100; // ECDSA P-256 base64url ≤ 88 chars
                                const MAX_DH_LEN: usize = 100; // P-256 uncompressed raw 65 B → ~88 chars base64url
                                let hdr = match incoming.header {
                                    Some(h)
                                        if h.v == crate::models::PINCHAT_PROTOCOL_VERSION
                                            && h.sig.len() <= MAX_SIG_LEN
                                            && h.dh.len() <= MAX_DH_LEN =>
                                    {
                                        h
                                    }
                                    _ => {
                                        tracing::warn!(
                                            "Rejecting {} with missing/invalid v1 header from connection_id={}",
                                            incoming.msg_type,
                                            connection_id
                                        );
                                        continue;
                                    }
                                };

                                // ANTI-REPLAY: Calculate SHA-256 hash of encrypted payload
                                let payload_hash = {
                                    let mut hasher = Sha256::new();
                                    hasher.update(payload.as_bytes());
                                    format!("{:x}", hasher.finalize())
                                };

                                // Get or create hash set for this room
                                let mut seen_hashes = state_clone
                                    .seen_message_hashes
                                    .entry(room_id)
                                    .or_insert_with(HashSet::new);

                                // Cleanup old hashes (beyond room TTL)
                                let room_ttl_minutes = state_clone
                                    .rooms
                                    .get(&room_id)
                                    .map(|r| r.ttl_minutes)
                                    .unwrap_or(60);
                                let cutoff =
                                    Utc::now() - chrono::Duration::minutes(room_ttl_minutes as i64);
                                seen_hashes.retain(|(_, ts)| *ts > cutoff);

                                // Check for duplicate (replay attack)
                                let now = Utc::now();
                                if seen_hashes.iter().any(|(hash, _)| hash == &payload_hash) {
                                    // REPLAY DETECTED - Ignore silently (don't broadcast)
                                    #[cfg(debug_assertions)]
                                    tracing::debug!(
                                        "Replay attack detected (duplicate payload hash)"
                                    );
                                    continue;
                                }

                                // MEMORY CAP: Evict oldest entries if cache exceeds limit
                                // Prevents memory exhaustion from malicious clients
                                let max_entries = state_clone.config.replay_cache_max_per_room;
                                if seen_hashes.len() >= max_entries {
                                    // Rebuild set keeping only the newest entries
                                    let mut entries: Vec<_> = seen_hashes.iter().cloned().collect();
                                    entries.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by timestamp descending (newest first)
                                    entries.truncate(max_entries - 1); // Keep max_entries - 1 to make room for new one
                                    seen_hashes.clear();
                                    for entry in entries {
                                        seen_hashes.insert(entry);
                                    }
                                }

                                // Store hash with timestamp
                                seen_hashes.insert((payload_hash, now));

                                // RATE LIMITING: Enforce per-connection message rate limit
                                // Prevents bandwidth exhaustion and client-side decryption DoS
                                let max_messages = state_clone.config.msg_rate_limit;
                                let rate_window_secs = state_clone.config.msg_rate_window_secs;

                                // Get or create timestamp queue for this connection
                                let mut timestamps = state_clone
                                    .connection_message_timestamps
                                    .entry(connection_id)
                                    .or_insert_with(VecDeque::new);

                                // Remove old timestamps outside the rate window
                                let rate_cutoff = now - chrono::Duration::seconds(rate_window_secs);
                                timestamps.retain(|&ts| ts > rate_cutoff);

                                // Check if rate limit exceeded
                                if timestamps.len() >= max_messages {
                                    tracing::warn!(
                                        "Connection {} exceeded rate limit ({}/{}s), disconnecting",
                                        connection_id,
                                        timestamps.len(),
                                        rate_window_secs
                                    );

                                    // Disconnect immediately (break recv loop)
                                    // Client will see WebSocket close event
                                    break;
                                }

                                // Record this message timestamp
                                timestamps.push_back(now);

                                // Create the message to broadcast based on type
                                // Signal Protocol: Include header for DH ratchet on receive
                                let broadcast_msg = if incoming.msg_type == "image" {
                                    Message::Image {
                                        payload,
                                        header: hdr,
                                        sender_id: connection_id,
                                    }
                                } else {
                                    Message::Message {
                                        payload,
                                        header: hdr,
                                        sender_id: connection_id,
                                    }
                                };

                                if let Ok(json) = serde_json::to_string(&broadcast_msg) {
                                    // Broadcast to all participants in the room
                                    if let Some(tx) = state_clone.broadcast_channels.get(&room_id) {
                                        let _ = tx.send(json);
                                    }
                                }

                                // Update the room activity
                                if let Some(mut room) = state_clone.rooms.get_mut(&room_id) {
                                    room.update_activity();
                                }
                            }
                        } else {
                            // Unknown msg_type: counts as a protocol error.
                            // A well-behaved v1 client only sends the three
                            // known types above.
                            #[cfg(debug_assertions)]
                            tracing::debug!(
                                "Unknown msg_type '{}' from connection_id={}",
                                incoming.msg_type,
                                connection_id
                            );
                            if bump_protocol_error(&state_clone, connection_id) {
                                break;
                            }
                        }
                    }
                    Err(_e) => {
                        #[cfg(debug_assertions)]
                        tracing::debug!("Failed to parse message: {}", _e);
                        if bump_protocol_error(&state_clone, connection_id) {
                            break;
                        }
                    }
                }
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = &mut send_task => {
            recv_task.abort();
        }
        _ = &mut recv_task => {
            send_task.abort();
        }
    }

    // Cleanup: remove the connection
    state.remove_connection(&connection_id);

    // Notify other users that someone left
    let leave_msg = Message::UserLeft {
        user_id: connection_id,
        participant_count: state.get_participant_count(&room_id),
    };

    if let Ok(json) = serde_json::to_string(&leave_msg) {
        if let Some(tx) = state.broadcast_channels.get(&room_id) {
            let _ = tx.send(json);
        }
    }

    #[cfg(debug_assertions)]
    tracing::debug!(
        "Connection left room ({} participants remaining)",
        state.get_participant_count(&room_id)
    );
}

/// Sends an error message and closes the connection
async fn send_error(mut socket: WebSocket, error: &str) -> Result<(), axum::Error> {
    let error_msg = Message::Error {
        message: error.to_string(),
    };

    if let Ok(json) = serde_json::to_string(&error_msg) {
        socket.send(WsMessage::Text(json)).await?;
    }

    socket.send(WsMessage::Close(None)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Integration tests for the v1 WebSocket upgrade handshake.
    //!
    //! We cannot use `ServiceExt::oneshot` because axum's `WebSocketUpgrade`
    //! extractor requires a `hyper::upgrade::OnUpgrade` request extension
    //! that is only installed by a real server during an actual upgrade
    //! (absence → axum returns 426 before our handler runs). Instead we
    //! spin up a bound listener and issue raw upgrade requests via reqwest.
    use super::*;
    use crate::config::Config;
    use crate::jwt::{WsTokenClaims, sign_token};
    use crate::models::{Room, RoomConfig, RoomType};
    use axum::{Router, routing::get};
    use std::net::SocketAddr;
    use uuid::Uuid;

    #[test]
    fn mls_correlation_ref_shape_is_bounded() {
        let mixed = "_-".repeat(21) + "A";
        assert!(valid_mls_correlation_ref(&"A".repeat(43)));
        assert!(valid_mls_correlation_ref(&mixed));
        assert!(!valid_mls_correlation_ref(&"A".repeat(42)));
        assert!(!valid_mls_correlation_ref(&"A".repeat(44)));
        assert!(!valid_mls_correlation_ref(&("A".repeat(42) + "=")));
        assert!(!valid_mls_correlation_ref(&("A".repeat(42) + "/")));
        assert!(!valid_mls_correlation_ref(&("A".repeat(42) + "B")));
    }

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
            commit_rate_limit: 12,
            commit_rate_window_secs: 60,
            frame_rate_limit: 120,
            protocol_error_limit: 10,
            pow_min_difficulty: 12,
            pow_max_difficulty: 18,
            challenge_ttl_secs: 300,
            jwt_token_ttl_secs: 30,
            jwt_issuer: crate::jwt::DEFAULT_JWT_ISSUER.to_string(),
            max_ws_connection_age_secs: 30 * 60,
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

    /// Spawn a bound listener with a minimal router exposing /ws/:room_id and
    /// return `(base_addr, state, room_id)`. Caller is responsible for issuing
    /// upgrade requests against `base_addr`.
    async fn spawn_test_server() -> (SocketAddr, AppState, Uuid) {
        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::OneToOne,
            ttl_minutes: 60,
            max_participants: 2,
        });
        let room_id = room.id;
        state.try_create_room(room).unwrap();

        let app: Router = Router::new()
            .route("/ws/:room_id", get(ws_handler))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, state, room_id)
    }

    /// Issue a raw HTTP/1.1 WebSocket upgrade request and return the status line.
    /// Using raw TCP + manual request so we can avoid pulling a full reqwest
    /// feature set just for these tests.
    ///
    /// `origin`: pass `Some(o)` to set Origin (default for tests is the allowed
    /// origin from `test_config`); pass `None` to omit the header explicitly
    /// (used by the test that verifies production rejection of missing Origin).
    async fn raw_upgrade_with_origin(
        addr: SocketAddr,
        path: &str,
        subprotocol: Option<&str>,
        origin: Option<&str>,
    ) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let sp_header = match subprotocol {
            Some(sp) => format!("Sec-WebSocket-Protocol: {}\r\n", sp),
            None => String::new(),
        };
        let origin_header = match origin {
            Some(o) => format!("Origin: {}\r\n", o),
            None => String::new(),
        };
        let req = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             {origin_header}{sp_header}\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        let head = std::str::from_utf8(&buf[..n]).unwrap_or("");
        // First line: "HTTP/1.1 <status> <reason>"
        head.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// Convenience wrapper: send a request with the test's allowed Origin so
    /// existing tests keep validating only their specific failure mode.
    async fn raw_upgrade(addr: SocketAddr, path: &str, subprotocol: Option<&str>) -> u16 {
        raw_upgrade_with_origin(addr, path, subprotocol, Some("https://localhost:3000")).await
    }

    #[tokio::test]
    async fn rejects_without_subprotocol_header() {
        let (addr, _state, room_id) = spawn_test_server().await;
        let path = format!("/ws/{}", room_id);
        let status = raw_upgrade(addr, &path, None).await;
        assert_eq!(status, 401);
    }

    #[tokio::test]
    async fn rejects_missing_origin_in_production() {
        // PRIVACY_MODE not set → production policy applies: missing Origin → 403.
        // Defense-in-depth against non-browser clients (curl/script) that could
        // otherwise bypass the cors_allowed_origins allowlist with a stolen
        // session cookie.
        //
        // C-07: the Origin gate now runs BEFORE consume_token, so an
        // Origin-rejected request must NOT have burned its jti. This test
        // only checks the status code; rejects_bad_origin_preserves_jti
        // below verifies the conservation property directly.
        let (addr, state, room_id) = spawn_test_server().await;
        let claims = WsTokenClaims::new(room_id, 30, &state.config.jwt_issuer);
        let token = sign_token(&claims, &state.jwt_secret).unwrap();
        let sp = format!("pinchat.v1, pinchat.v1.jwt.{}", token);
        let path = format!("/ws/{}", room_id);
        let status = raw_upgrade_with_origin(addr, &path, Some(&sp), None).await;
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn rejects_bad_origin_preserves_jti() {
        // C-07: a bounce on the Origin gate (bad Origin or missing-in-prod)
        // MUST NOT consume the JTI. Otherwise a hostile cross-origin script
        // armed with a stolen WS token could lock the legitimate client out
        // of its own session by triggering one mistargeted upgrade attempt.
        //
        // We assert the conservation property directly: send the upgrade
        // request with a non-allowlisted Origin (403), then verify the JTI
        // is still absent from state.consumed_tokens.
        let (addr, state, room_id) = spawn_test_server().await;
        let claims = WsTokenClaims::new(room_id, 30, &state.config.jwt_issuer);
        let jti = claims.jti;
        let token = sign_token(&claims, &state.jwt_secret).unwrap();
        let sp = format!("pinchat.v1, pinchat.v1.jwt.{}", token);
        let path = format!("/ws/{}", room_id);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let status =
            raw_upgrade_with_origin(addr, &path, Some(&sp), Some("https://evil.example.com")).await;
        assert_eq!(status, 403);
        assert!(
            !state.consumed_tokens.contains_key(&jti),
            "JTI must NOT be consumed on Origin rejection (C-07)"
        );
    }

    #[tokio::test]
    async fn rejects_old_protocol_version() {
        let (addr, _state, room_id) = spawn_test_server().await;
        let path = format!("/ws/{}", room_id);
        // Only a non-v1 subprotocol offered → 426.
        let status = raw_upgrade(addr, &path, Some("pinchat.v0")).await;
        assert_eq!(status, 426);
    }

    #[tokio::test]
    async fn rejects_missing_jwt_subprotocol() {
        let (addr, _state, room_id) = spawn_test_server().await;
        let path = format!("/ws/{}", room_id);
        // Base pinchat.v1 present, but no companion jwt token → 401.
        let status = raw_upgrade(addr, &path, Some("pinchat.v1")).await;
        assert_eq!(status, 401);
    }

    #[tokio::test]
    async fn rejects_expired_jwt() {
        let (addr, state, room_id) = spawn_test_server().await;
        let expired = WsTokenClaims {
            room_id,
            connection_id: Uuid::new_v4(),
            exp: 1, // 1970
            jti: Uuid::new_v4(),
            aud: crate::jwt::WS_TOKEN_AUDIENCE.to_string(),
            iss: state.config.jwt_issuer.clone(),
        };
        let token = sign_token(&expired, &state.jwt_secret).unwrap();
        let sp = format!("pinchat.v1, pinchat.v1.jwt.{}", token);
        let path = format!("/ws/{}", room_id);
        let status = raw_upgrade(addr, &path, Some(&sp)).await;
        assert_eq!(status, 401);
    }

    #[tokio::test]
    async fn rejects_token_for_wrong_room() {
        let (addr, state, room_id) = spawn_test_server().await;
        let other_room = Uuid::new_v4();
        let claims = WsTokenClaims::new(other_room, 30, &state.config.jwt_issuer);
        let token = sign_token(&claims, &state.jwt_secret).unwrap();
        let sp = format!("pinchat.v1, pinchat.v1.jwt.{}", token);
        let path = format!("/ws/{}", room_id);
        let status = raw_upgrade(addr, &path, Some(&sp)).await;
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn accepts_valid_subprotocol_and_jwt() {
        // Full success path: bound listener + valid single-use JWT → 101 + echoed subprotocol.
        let (addr, state, room_id) = spawn_test_server().await;
        let claims = WsTokenClaims::new(room_id, 30, &state.config.jwt_issuer);
        let token = sign_token(&claims, &state.jwt_secret).unwrap();
        let sp = format!("pinchat.v1, pinchat.v1.jwt.{}", token);
        let path = format!("/ws/{}", room_id);

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Small wait to let axum::serve() start accepting on the listener.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Origin: https://localhost:3000\r\n\
             Sec-WebSocket-Protocol: {sp}\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();

        // Read until we have the status line + headers (up to \r\n\r\n) or timeout.
        let mut buf = Vec::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let mut chunk = [0u8; 512];
            let n = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
                .await
                .expect("timeout reading upgrade response")
                .expect("read error");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        assert!(
            head.starts_with("HTTP/1.1 101"),
            "expected 101, got: {}",
            head
        );
        // Server must echo only the base subprotocol (NOT the jwt.* companion).
        let low = head.to_ascii_lowercase();
        assert!(
            low.contains("sec-websocket-protocol: pinchat.v1\r\n"),
            "expected pinchat.v1 echoed, got: {}",
            head
        );
        assert!(
            !head.contains("pinchat.v1.jwt."),
            "server must NOT echo the jwt token subprotocol"
        );
    }
}
