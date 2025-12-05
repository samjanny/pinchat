use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket},
        Path, Query, State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use tokio::time::{interval, Duration};
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

/// Query parameters for WebSocket upgrade
#[derive(Deserialize)]
pub struct WsQuery {
    /// JWT token for authentication
    pub token: String,
}

/// Handler for upgrading the WebSocket connection
///
/// Requires JWT token for authentication (obtained from `/api/ws-token/{room_id}`).
/// Token must be provided as query parameter: `/ws/{room_id}?token={jwt}`
///
/// # Security
/// - Validates JWT signature
/// - Checks token expiration (30s)
/// - Verifies room_id matches token claim
/// - Prevents connection flooding (requires PoW for token)
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(room_id): Path<Uuid>,
    Query(query): Query<WsQuery>,
) -> Response {
    // Validate JWT token before accepting the WebSocket upgrade
    let claims = match verify_token(&query.token, &state.jwt_secret) {
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

    // SECURITY: Single-use token enforcement (prevents replay attacks)
    // Token can only be used once within its validity window
    if !state.consume_token(claims.jti, state.config.jwt_token_ttl_secs as u64) {
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

    // Use pre-allocated connection_id from token (ensures uniqueness)
    let connection_id = claims.connection_id;

    // Configure WebSocket limits to prevent memory exhaustion attacks
    // These limits are enforced before any application logic is invoked
    // Dynamically sized based on MAX_IMAGE_SIZE config
    let ws_size = max_ws_size(state.config.max_image_size);
    ws.max_message_size(ws_size)
        .max_frame_size(ws_size)
        .on_upgrade(move |socket| handle_socket(socket, state, room_id, connection_id))
}

/// Handles the WebSocket connection
///
/// # Arguments
/// * `socket` - WebSocket connection
/// * `state` - Application state
/// * `room_id` - Room ID (already validated by ws_handler)
/// * `connection_id` - Pre-allocated connection ID from JWT token (ensures uniqueness)
async fn handle_socket(socket: WebSocket, state: AppState, room_id: Uuid, connection_id: Uuid) {
    // Verify that the room exists
    let room_exists = state.rooms.contains_key(&room_id);
    if !room_exists {
        #[cfg(debug_assertions)]
        tracing::debug!("WebSocket connection attempt to non-existent room");
        return;
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
        (room.room_type, room.ttl_minutes, room.max_participants, room.created_at)
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
    // Also sends heartbeat pings every 30 seconds to keep the connection alive
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
                    if sender.send(WsMessage::Ping(vec![])).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Task that receives messages from the client and broadcasts them
    let state_clone = state.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let WsMessage::Text(text) = msg {
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

                // Parse the incoming message
                match serde_json::from_str::<IncomingMessage>(&text) {
                    Ok(incoming) => {
                        // Handle ECDH public key exchange (blind relay, no crypto server-side)
                        if incoming.msg_type == "ecdh_public_key" {
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

                                    // Note: We don't send error message to client to avoid giving
                                    // attackers feedback on DoS attempts. Just log and skip.
                                    continue; // Skip processing this message
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
                                                    tracing::info!("✅ ECDH public key broadcasted to {} receivers in room={}", receiver_count, room_id);
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
                                tracing::warn!("⚠️ ECDH message received but payload is missing (connection_id={})", connection_id);
                            }
                        }
                        // Handle DH Ratchet messages as a blind relay for post-compromise security
                        else if incoming.msg_type == "dh_ratchet" {
                            tracing::info!(
                                "DH Ratchet received from connection_id={} in room={}",
                                connection_id,
                                room_id
                            );

                            // Parse the full DH ratchet message to extract fields
                            match serde_json::from_str::<serde_json::Value>(&text) {
                                Ok(value) => {
                                    // Extract required fields
                                    if let (
                                        Some(public_key),
                                        Some(signature),
                                        Some(ratchet_count),
                                        Some(reason),
                                    ) = (
                                        value.get("publicKey").and_then(|v| v.as_str()),
                                        value.get("signature").and_then(|v| v.as_str()),
                                        value.get("ratchetCount").and_then(|v| v.as_u64()),
                                        value.get("reason").and_then(|v| v.as_str()),
                                    ) {
                                        tracing::debug!(
                                            "DH Ratchet details: ratchet_count={}, reason={}, signature_len={}",
                                            ratchet_count, reason, signature.len()
                                        );

                                        // SECURITY: Validate signature size to prevent DoS
                                        const MAX_SIGNATURE_SIZE: usize = 512; // ECDSA P-256 signature is ~64-72 bytes
                                        if signature.len() > MAX_SIGNATURE_SIZE {
                                            tracing::warn!(
                                                "⚠️ DH Ratchet signature too large: {} bytes (max {}) - rejecting",
                                                signature.len(), MAX_SIGNATURE_SIZE
                                            );
                                            continue;
                                        }

                                        // Create DH Ratchet message
                                        let dh_ratchet_msg = Message::DHRatchet {
                                            public_key: public_key.to_string(),
                                            signature: signature.to_string(),
                                            ratchet_count: ratchet_count as u32,
                                            reason: reason.to_string(),
                                            sender_id: connection_id,
                                        };

                                        match serde_json::to_string(&dh_ratchet_msg) {
                                            Ok(json) => {
                                                tracing::debug!("DH Ratchet message serialized, broadcasting...");

                                                // Broadcast to all participants in the room
                                                if let Some(tx) =
                                                    state_clone.broadcast_channels.get(&room_id)
                                                {
                                                    match tx.send(json) {
                                                        Ok(receiver_count) => {
                                                            tracing::info!(
                                                                "✅ DH Ratchet broadcasted to {} receivers (ratchet #{}, reason: {})",
                                                                receiver_count, ratchet_count, reason
                                                            );
                                                        }
                                                        Err(e) => {
                                                            tracing::error!("❌ Failed to broadcast DH Ratchet: {}", e);
                                                        }
                                                    }
                                                } else {
                                                    tracing::warn!(
                                                        "⚠️ No broadcast channel for room={}",
                                                        room_id
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                tracing::error!(
                                                    "Failed to serialize DH Ratchet message: {}",
                                                    e
                                                );
                                            }
                                        }
                                    } else {
                                        tracing::warn!("⚠️ DH Ratchet message missing required fields (connection_id={})", connection_id);
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Failed to parse DH Ratchet message: {}", e);
                                }
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
                                        header: incoming.header, // Relay header (contains DH public key)
                                        sender_id: connection_id,
                                        timestamp: now,
                                    }
                                } else {
                                    Message::Message {
                                        payload,
                                        header: incoming.header, // Relay header (contains DH public key)
                                        sender_id: connection_id,
                                        timestamp: now,
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
                        }
                    }
                    Err(_e) => {
                        #[cfg(debug_assertions)]
                        tracing::debug!("Failed to parse message: {}", _e);
                    }
                }
            } else if let WsMessage::Close(_) = msg {
                break;
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
