use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode, header, header::SEC_WEBSOCKET_PROTOCOL},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use futures_util::FutureExt;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Duration, Instant, interval};
use uuid::Uuid;

use crate::ip_hash::extract_client_ip_with_proxy;

use crate::jwt::{WsResumeTokenClaims, WsTokenClaims, sign_resume_token, verify_token};
use crate::models::message::MessageHeader;
use crate::models::{IncomingMessage, Message, RoomType};
use crate::state::app_state::MlsControlAppendError;
use crate::state::app_state::{AdmissionRefused, WsAdmission};
use crate::state::{
    AppState, ClientBroadcastLease, ConnectionAdmission, MlsControlAdmission, ReplayAdmission,
};
use crate::ws_transport::{
    self, Closing, Incoming, Outgoing, Reader, Writer, WsSocket, WsUpgrade, close_code,
};

/// Maximum allowed size for ECDH public key payload (8KB)
/// Typical ECDH payload with P-256: ~500 bytes (65-byte key + encryption overhead + AAD)
/// 8KB limit prevents DoS attacks with oversized payloads
const MAX_ECDH_PAYLOAD_SIZE: usize = 8192;

const WIRE_PUBLIC_MESSAGE: u16 = 1;
const WIRE_PRIVATE_MESSAGE: u16 = 2;
const WIRE_WELCOME: u16 = 3;
const WIRE_KEY_PACKAGE: u16 = 5;

const CONTENT_TYPE_PROPOSAL: u8 = 2;
const CONTENT_TYPE_COMMIT: u8 = 3;

/// Decoded-byte ceilings for the MLS transport envelope. The WebSocket frame
/// cap is necessarily larger because Base64url expands data by roughly 4/3.
/// Keeping format-specific limits here prevents a small KeyPackage or Commit
/// parser from receiving an image-sized allocation.
const MAX_MLS_CONTROL_BYTES: usize = 128 * 1024;
const MAX_MLS_KEY_PACKAGE_BYTES: usize = 16 * 1024;
const MAX_RATCHET_TREE_BYTES: usize = 64 * 1024;
const MLS_REPLAY_WINDOW_ENTRIES: usize = 16;
/// Unacknowledged controls at which a participant counts as lagging, once
/// that backlog has lasted longer than the grace period. See
/// `MLS_CONTROL_LAG_GRACE` and `MLS_CONTROL_LAG_HARD_LIMIT` in app_state.rs
/// for the two rules around it.
const MAX_MLS_UNACKNOWLEDGED_CONTROLS: u64 = 64;
/// Longest a participant may leave any control unacknowledged.
const MLS_CONTROL_ACK_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicMessageKind {
    Proposal,
    Commit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayAckError {
    /// The connection ends, and this is how.
    Transport(Closing),
    Protocol,
}

#[derive(Debug)]
struct ValidatedMlsEnvelope {
    payload_bytes: Vec<u8>,
    ratchet_tree_bytes: Option<Vec<u8>>,
    public_kind: Option<PublicMessageKind>,
}

/// Convert permanent, sender-correctable MLS admission failures into a direct
/// typed response. Capacity/rate/transient failures retain their existing
/// retry-or-close handling.
fn permanent_mls_append_rejection(
    error: MlsControlAppendError,
    commit_ref: Option<String>,
) -> Option<Message> {
    let reason = match error {
        // A group that has used every KeyPackage reference it may consume
        // accepts no Add again. The browser already handles this reason by
        // abandoning the Add, which is what it must do here as well; the
        // close it got before made it reconnect and send the same Add again.
        MlsControlAppendError::UnknownKeyPackageRef
        | MlsControlAppendError::KeyPackageRefsExhausted => "unknown_key_package_ref",
        MlsControlAppendError::UnauthorizedGroupCreatorControl => "not_group_creator",
        MlsControlAppendError::CommitCorrelationConflict => "commit_correlation_conflict",
        MlsControlAppendError::WelcomeNotCorrelated => "welcome_not_correlated",
        _ => return None,
    };
    Some(Message::MlsRejected {
        commit_ref,
        reason: reason.to_string(),
        retry_after_secs: 0,
    })
}

/// Decode unpadded Base64url and reject alternate/non-canonical spellings.
/// The encoded-length check happens before allocation; the decoded check is
/// retained as defense in depth around integer rounding.
fn decode_bounded_base64url(
    value: &str,
    max_decoded_bytes: usize,
) -> Result<Vec<u8>, &'static str> {
    if value.is_empty() {
        return Err("empty Base64url value");
    }
    let max_encoded_bytes = max_decoded_bytes.saturating_mul(4).saturating_add(2) / 3;
    if value.len() > max_encoded_bytes {
        return Err("Base64url value exceeds decoded-byte limit");
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "invalid Base64url value")?;
    if decoded.len() > max_decoded_bytes {
        return Err("decoded value exceeds byte limit");
    }
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err("non-canonical Base64url value");
    }
    Ok(decoded)
}

fn append_mls_varint(output: &mut Vec<u8>, value: usize) -> Result<(), &'static str> {
    if value < 64 {
        output.push(value as u8);
        return Ok(());
    }
    if value < 16_384 {
        let encoded = (value as u16) | 0x4000;
        output.extend_from_slice(&encoded.to_be_bytes());
        return Ok(());
    }
    if value < (1usize << 30) {
        let encoded = (value as u32) | 0x8000_0000;
        output.extend_from_slice(&encoded.to_be_bytes());
        return Ok(());
    }
    Err("MLS vector length exceeds 2^30-1")
}

/// RFC 9420 §5.2 RefHash for the fixed KeyPackage reference label. The relay
/// computes this from the already-bounded opaque KeyPackage body so an Add
/// Commit can only reserve a Welcome for a KeyPackage it previously accepted.
fn mls_key_package_ref(key_package_bytes: &[u8]) -> Result<String, &'static str> {
    const LABEL: &[u8] = b"MLS 1.0 KeyPackage Reference";
    let mut input = Vec::with_capacity(
        LABEL
            .len()
            .saturating_add(key_package_bytes.len())
            .saturating_add(6),
    );
    append_mls_varint(&mut input, LABEL.len())?;
    input.extend_from_slice(LABEL);
    append_mls_varint(&mut input, key_package_bytes.len())?;
    input.extend_from_slice(key_package_bytes);
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(input)))
}

/// Read the MLS vector-length varint used by the shallow PublicMessage
/// classifier. MLS permits canonical 1/2/4-byte encodings only. This parser
/// deliberately stops before the Proposal/Commit body: the relay remains
/// cryptographically blind and only needs the signed content_type byte to
/// select the correct rate-limit bucket.
fn read_mls_varint(bytes: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *bytes.get(*pos)?;
    let encoded_len = 1usize << (first >> 6);
    if encoded_len == 8 || bytes.len().saturating_sub(*pos) < encoded_len {
        return None;
    }
    let mut value = usize::from(first & 0x3f);
    for offset in 1..encoded_len {
        value = value.checked_shl(8)? | usize::from(bytes[*pos + offset]);
    }
    if (encoded_len == 2 && value < 64) || (encoded_len == 4 && value < 16_384) {
        return None;
    }
    *pos += encoded_len;
    Some(value)
}

fn skip_mls_opaque(bytes: &[u8], pos: &mut usize) -> Option<()> {
    let len = read_mls_varint(bytes, pos)?;
    let end = pos.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    *pos = end;
    Some(())
}

fn classify_public_message(bytes: &[u8]) -> Result<PublicMessageKind, &'static str> {
    let mut pos = 0usize;
    skip_mls_opaque(bytes, &mut pos).ok_or("malformed PublicMessage group_id")?;
    pos = pos.checked_add(8).ok_or("malformed PublicMessage epoch")?;
    if pos > bytes.len() {
        return Err("truncated PublicMessage epoch");
    }

    let sender_type = *bytes.get(pos).ok_or("missing PublicMessage sender")?;
    pos += 1;
    if sender_type != 1 {
        return Err("unsupported PublicMessage sender type");
    }
    pos = pos.checked_add(4).ok_or("malformed PublicMessage sender")?;
    if pos > bytes.len() {
        return Err("truncated PublicMessage sender");
    }

    skip_mls_opaque(bytes, &mut pos).ok_or("malformed PublicMessage authenticated_data")?;
    let content_type = *bytes.get(pos).ok_or("missing PublicMessage content type")?;
    pos += 1;
    if pos >= bytes.len() {
        return Err("truncated PublicMessage body");
    }
    match content_type {
        CONTENT_TYPE_PROPOSAL => Ok(PublicMessageKind::Proposal),
        CONTENT_TYPE_COMMIT => Ok(PublicMessageKind::Commit),
        _ => Err("unsupported PublicMessage content type"),
    }
}

fn validate_mls_envelope(
    payload: &str,
    wire_format: u16,
    ratchet_tree: Option<&str>,
    key_package_ref: Option<&str>,
    commit_ref: Option<&str>,
    bootstrap_proof: Option<&str>,
    max_image_size: usize,
) -> Result<ValidatedMlsEnvelope, &'static str> {
    let max_payload_bytes = match wire_format {
        WIRE_PUBLIC_MESSAGE | WIRE_WELCOME => MAX_MLS_CONTROL_BYTES,
        WIRE_PRIVATE_MESSAGE => max_image_size.saturating_add(64 * 1024),
        WIRE_KEY_PACKAGE => MAX_MLS_KEY_PACKAGE_BYTES,
        _ => return Err("unsupported MLS wire format"),
    };
    let payload_bytes = decode_bounded_base64url(payload, max_payload_bytes)?;

    let malformed_ref = key_package_ref
        .map(|value| !valid_mls_correlation_ref(value))
        .unwrap_or(false)
        || commit_ref
            .map(|value| !valid_mls_correlation_ref(value))
            .unwrap_or(false)
        || bootstrap_proof
            .map(|value| !valid_mls_correlation_ref(value))
            .unwrap_or(false);
    if malformed_ref {
        return Err("malformed MLS correlation reference");
    }

    let (public_kind, ratchet_tree_bytes) = match wire_format {
        WIRE_PUBLIC_MESSAGE => {
            if ratchet_tree.is_some() || bootstrap_proof.is_some() {
                return Err("PublicMessage carries invalid MLS metadata");
            }
            let kind = classify_public_message(&payload_bytes)?;
            match kind {
                PublicMessageKind::Proposal => {
                    if key_package_ref.is_some() || commit_ref.is_some() {
                        return Err("Proposal cannot carry Commit correlation metadata");
                    }
                }
                PublicMessageKind::Commit => {
                    let supplied = commit_ref.ok_or("Commit requires commit_ref")?;
                    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(&payload_bytes));
                    if supplied != expected {
                        return Err("commit_ref does not match Commit payload");
                    }
                }
            }
            (Some(kind), None)
        }
        WIRE_WELCOME => {
            if key_package_ref.is_none() || commit_ref.is_none() {
                return Err("Welcome requires KeyPackageRef and CommitRef");
            }
            if bootstrap_proof.is_some() {
                return Err("bootstrap_proof is only valid on KeyPackage");
            }
            let tree = ratchet_tree.ok_or("Welcome requires ratchet_tree")?;
            (
                None,
                Some(decode_bounded_base64url(tree, MAX_RATCHET_TREE_BYTES)?),
            )
        }
        WIRE_PRIVATE_MESSAGE => {
            if ratchet_tree.is_some() || key_package_ref.is_some() || commit_ref.is_some() {
                return Err("MLS metadata is invalid for this wire format");
            }
            if bootstrap_proof.is_some() {
                return Err("bootstrap_proof is only valid on KeyPackage");
            }
            (None, None)
        }
        WIRE_KEY_PACKAGE => {
            if ratchet_tree.is_some() || key_package_ref.is_some() || commit_ref.is_some() {
                return Err("MLS metadata is invalid for this wire format");
            }
            if bootstrap_proof.is_none() {
                return Err("KeyPackage requires bootstrap_proof");
            }
            (None, None)
        }
        _ => unreachable!("wire format allowlisted above"),
    };

    Ok(ValidatedMlsEnvelope {
        payload_bytes,
        ratchet_tree_bytes,
        public_kind,
    })
}

fn hash_replay_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Hash every security-relevant transport field, not just the MLS payload.
/// This means an attacker who races a bad tree/reference cannot cause the
/// later authentic envelope with the same payload to be discarded as a
/// duplicate. Sender ID is intentionally excluded so cross-sender replay of
/// an otherwise identical envelope remains suppressed.
fn mls_envelope_replay_hash(
    wire_format: u16,
    validated: &ValidatedMlsEnvelope,
    key_package_ref: Option<&str>,
    commit_ref: Option<&str>,
    bootstrap_proof: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"pinchat-mls-relay-envelope-v1");
    hasher.update(wire_format.to_be_bytes());
    hash_replay_field(&mut hasher, &validated.payload_bytes);
    hash_replay_field(
        &mut hasher,
        validated.ratchet_tree_bytes.as_deref().unwrap_or_default(),
    );
    hash_replay_field(&mut hasher, key_package_ref.unwrap_or_default().as_bytes());
    hash_replay_field(&mut hasher, commit_ref.unwrap_or_default().as_bytes());
    hash_replay_field(&mut hasher, bootstrap_proof.unwrap_or_default().as_bytes());
    hex::encode(hasher.finalize())
}

/// Bind the advisory relay replay identity to the complete one-to-one
/// ciphertext envelope. Hashing only `payload` lets an attacker race the same
/// ciphertext with a corrupted header, causing the later authentic header to
/// be discarded before the client can verify it.
fn one_to_one_envelope_replay_hash(
    msg_type: &str,
    payload: &str,
    header: &MessageHeader,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"pinchat-double-ratchet-relay-envelope-v1");
    hash_replay_field(&mut hasher, msg_type.as_bytes());
    hash_replay_field(&mut hasher, payload.as_bytes());
    hasher.update([header.v]);
    hash_replay_field(&mut hasher, header.dh.as_bytes());
    hasher.update(header.pn.to_be_bytes());
    hasher.update(header.n.to_be_bytes());
    hasher.update(header.rc.to_be_bytes());
    hash_replay_field(&mut hasher, header.sig.as_bytes());
    hex::encode(hasher.finalize())
}

fn room_accepts_client_message(room_type: RoomType, msg_type: &str) -> bool {
    match room_type {
        RoomType::Group => matches!(msg_type, "mls" | "mlsack"),
        RoomType::OneToOne => matches!(msg_type, "ecdh_public_key" | "message" | "image"),
    }
}

/// Minimum WebSocket message/frame size (512KB)
/// Used as floor even for small image configs to support text messages and handshakes
const MIN_WS_SIZE: usize = 524288;

/// Images are Base64 inside an image JSON string, wrapped in the ratchet's
/// plaintext JSON, encrypted, then Base64url encoded again. Reserve 1 KiB
/// for both JSON envelopes (including escaping), the IV and the GCM tag.
/// Integer ceilings cover padding at each encoding boundary. Configuration
/// caps raw images at 2 MiB, so these operations are bounded.
fn max_image_payload_size(max_image_size: usize) -> usize {
    let inner_base64_size = max_image_size.div_ceil(3) * 4;
    (inner_base64_size + 1024).div_ceil(3) * 4
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

/// The rejections of an upgrade that depend on nothing but the request and
/// the configuration: subprotocol, Origin, token signature, and the room the
/// token was issued for.
///
/// None of them consumes the token (see C-07 below), so they can run twice
/// for one request: in `require_ws_token`, ahead of the connection quota,
/// and again in the handler, which does not rely on the layer being there.
fn check_upgrade_request(
    state: &AppState,
    room_id: &Uuid,
    headers: &HeaderMap,
) -> Result<WsTokenClaims, Box<Response>> {
    // Read Sec-WebSocket-Protocol; absence = client did not perform a v1 handshake.
    let sec_proto = match headers
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|h| h.to_str().ok())
    {
        Some(s) => s,
        None => {
            return Err(Box::new(
                (StatusCode::UNAUTHORIZED, "Missing Sec-WebSocket-Protocol").into_response(),
            ));
        }
    };

    let offered: Vec<&str> = sec_proto.split(',').map(|s| s.trim()).collect();

    // Gate: client MUST offer the base `pinchat.v1` subprotocol.
    if !offered.contains(&"pinchat.v1") {
        tracing::warn!("WebSocket upgrade rejected: base pinchat.v1 subprotocol missing");
        return Err(Box::new(
            (StatusCode::UPGRADE_REQUIRED, "Protocol pinchat.v1 required").into_response(),
        ));
    }

    // Extract JWT from the `pinchat.v1.jwt.<token>` companion subprotocol.
    let token = match offered
        .iter()
        .find_map(|p| p.strip_prefix("pinchat.v1.jwt."))
    {
        Some(t) => t,
        None => {
            tracing::warn!("WebSocket upgrade rejected: JWT subprotocol missing");
            return Err(Box::new(
                (StatusCode::UNAUTHORIZED, "Missing JWT in subprotocol").into_response(),
            ));
        }
    };

    // C-07: Order matters. All stateless rejections (Origin, signature, room
    // claim) MUST run BEFORE the single-use JTI consumption. Otherwise a
    // bounce of a legitimate token through an Origin/room-mismatch path
    // would burn its jti and lock the real client out of its own session.

    // Origin check - defense-in-depth (RFC 6455 §4.1).
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
                return Err(Box::new(
                    (StatusCode::FORBIDDEN, "Origin not allowed").into_response(),
                ));
            }
        }
        None if !dev_mode => {
            tracing::warn!("WebSocket upgrade rejected: Origin header missing (production)");
            return Err(Box::new(
                (StatusCode::FORBIDDEN, "Origin header required").into_response(),
            ));
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
            return Err(Box::new(
                (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response(),
            ));
        }
    };

    // Verify room_id matches token claim (prevent token reuse for different rooms)
    if claims.room_id != *room_id {
        tracing::warn!(
            "JWT room_id mismatch: token={}, path={}",
            claims.room_id,
            room_id
        );
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "Token not valid for this room").into_response(),
        ));
    }

    Ok(claims)
}

/// Refuses an upgrade that carries no valid token for the room before it
/// reaches the connection quota.
///
/// The quota is keyed by client address. With the quota in front, anyone
/// sharing an address with a user (an office NAT, a VPN, a Tor exit) could
/// spend that user's connections with requests that were never going to be
/// accepted, without holding a token or knowing the site password. A token
/// is only issued by /api/ws-token, behind the session check and its own
/// quota.
pub async fn require_ws_token(
    State(state): State<AppState>,
    Path(room_id): Path<Uuid>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if let Err(rejection) = check_upgrade_request(&state, &room_id, request.headers()) {
        return *rejection;
    }
    next.run(request).await
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
    ws: WsUpgrade,
    State(state): State<AppState>,
    Path(room_id): Path<Uuid>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let claims = match check_upgrade_request(&state, &room_id, &headers) {
        Ok(claims) => claims,
        Err(rejection) => return *rejection,
    };
    if let Some(generation) = claims.creator_bootstrap_generation
        && !state.creator_bootstrap_claim_is_live(&room_id, claims.connection_id, generation)
    {
        tracing::warn!(
            "Revoked creator-bootstrap JWT rejected for room {} generation {}",
            room_id,
            generation
        );
        return (
            StatusCode::FORBIDDEN,
            "Group creator bootstrap token has been revoked",
        )
            .into_response();
    }

    // Admission control, before anything is looked up or allocated for the
    // connection and before the single-use token is spent: a refused client
    // may come back with the same token while it is valid. The client is
    // counted by the keyed hash of its address, never the address itself.
    // The server is always run with connection info; only a router
    // assembled without it (tests) has none, and then only the relay-wide
    // limit applies.
    let client = connect_info.map(|connect_info| {
        state.client_address(&extract_client_ip_with_proxy(
            &connect_info,
            &headers,
            &state.config.trusted_proxies,
        ))
    });
    let admission = match state.admit_ws_connection(client.as_ref()) {
        Ok(admission) => admission,
        Err(refused) => return admission_refused(refused, false),
    };

    // Audit M-2: room-state gate BEFORE the single-use jti is burned.
    //
    // The existence / expiry / capacity checks used to live exclusively in
    // handle_socket, i.e. AFTER consume_token. A client that lost the race for
    // the second slot, or arrived at a room that had just expired, therefore
    // had its token consumed by a rejection it did not cause, and had to
    // re-run Proof-of-Work to try again. Hoisting the read here keeps
    // consume_token as the last gate (C-07 still holds: every check above it
    // is a rejection the client can retry with the same token) while removing
    // the stateful rejections from the burn path.
    //
    // add_participant inside handle_socket remains the authoritative capacity
    // check; this read is advisory and can go stale in the narrow window
    // between here and the upgrade. That residual race burns a token at most
    // once per genuine tie, instead of on every full-room arrival.
    //
    // Capacity only applies to an upgrade that needs a new slot. A resume
    // reclaims the slot its own identity still holds (active or reserved for
    // the reconnect grace period): it adds no participant, and it cannot
    // reach another peer's slot because the identity is the one signed into
    // the token. The token endpoint already mints resume tokens for a full
    // room on that basis; refusing them here made every reconnect into a
    // one-to-one room with both peers present fail until the grace period
    // ran out, and the peer then came back as a new identity with a new
    // handshake. A resume token whose reservation is gone gets no exemption:
    // it is treated like any other arrival and add_connection refuses to
    // turn it into a fresh admission.
    //
    // The `.map()` keeps the DashMap read guard scoped to this statement.
    // remove_room write-locks the same shard, so holding the guard across the
    // expired branch would self-deadlock the worker (cf. the room_page
    // regression test in handlers/http.rs).
    let room_state = state.rooms.get(&room_id).map(|room| {
        let reclaims_own_slot = claims.resume && room.holds_slot_for(&claims.connection_id);
        (room.is_expired(), room.is_full() && !reclaims_own_slot)
    });
    match room_state {
        Some((false, false)) => {}
        Some((true, _)) => {
            // Expired: clean up eagerly rather than waiting for the next
            // cleanup tick, then answer exactly like a missing room.
            state.remove_room(&room_id);
            #[cfg(debug_assertions)]
            tracing::debug!("WebSocket upgrade rejected: room expired");
            return (StatusCode::NOT_FOUND, "Room not found").into_response();
        }
        Some((false, true)) => {
            // Audit L-4: full and missing share one response so a caller
            // holding a room id cannot tell the two apart.
            #[cfg(debug_assertions)]
            tracing::debug!("WebSocket upgrade rejected: room full");
            return (StatusCode::NOT_FOUND, "Room not found").into_response();
        }
        None => {
            #[cfg(debug_assertions)]
            tracing::debug!("WebSocket upgrade rejected: room not found");
            return (StatusCode::NOT_FOUND, "Room not found").into_response();
        }
    }

    // An identity has one socket at a time. After a change of network the
    // browser reconnects at once, while the relay may still hold the old
    // socket open until its idle timeout (90 seconds) notices that nothing
    // comes from it any more. Admission refuses the second socket; this
    // refusal comes before the token is spent, so the client may try again
    // with the same token instead of paying for a new one with proof of
    // work. Advisory, like the room checks above: admission decides.
    //
    // The old socket is not taken over. A resume credential is a bearer
    // token, and taking over would let whoever holds one end the live
    // socket at any time rather than only reclaim one that has gone; it
    // would also need every eviction made by the old socket's replay loop
    // to know that its identity has moved on.
    if state.connections.contains_key(&claims.connection_id) {
        #[cfg(debug_assertions)]
        tracing::debug!("WebSocket upgrade rejected: identity still has a socket");
        return (
            StatusCode::CONFLICT,
            "This relay identity is still connected; try again shortly",
        )
            .into_response();
    }

    // SECURITY: Single-use token enforcement (prevents replay attacks).
    // C-07: this is the LAST gate before upgrade. Every check above has
    // already passed by the time we mutate state, so a failed upgrade attempt
    // past this point cannot have "wasted" the JTI of a legitimate client
    // whose Origin / room / signature didn't match, or whose room was gone.
    //
    // Audit H-1: the retention window is derived from `claims.exp`, so the
    // record outlives every instant at which the signature still verifies.
    if !state.consume_token(claims.jti, claims.exp) {
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
    let resume_requested = claims.resume;
    let mls_control_cursor = claims.mls_control_cursor;
    let creator_bootstrap_generation = claims.creator_bootstrap_generation;
    let ws_size = max_ws_size(state.config.max_image_size);

    // What this connection sends into the room counts against the share of
    // the broadcast budget of the address it comes from, the share its
    // admission took; it lives as long as the connection.
    // Echo only the base subprotocol back (do NOT echo the jwt.* companion -
    // the RFC requires the response subprotocol to be one the client offered,
    // but we pick the non-secret one so the 101 response carries no token).
    let inbound = state.inbound_budget(admission.share.as_deref());
    ws.on_upgrade("pinchat.v1", ws_size, inbound, move |socket| {
        handle_socket(
            socket,
            state,
            room_id,
            connection_id,
            resume_requested,
            mls_control_cursor,
            creator_bootstrap_generation,
            admission,
        )
    })
}

/// The answer to an upgrade, or to a request for a token or a room, that
/// the admission control refuses: 503 when the relay holds all the
/// connections it may, 429 when the client's address does. Neither is a
/// fault of the client, so both say when to try again. `json` gives the
/// API's error form.
pub(crate) fn admission_refused(refused: AdmissionRefused, json: bool) -> Response {
    let (status, code, message) = match refused {
        AdmissionRefused::RelayFull => (
            StatusCode::SERVICE_UNAVAILABLE,
            "RELAY_FULL",
            "The relay is at its connection limit; try again later",
        ),
        AdmissionRefused::AddressFull => (
            StatusCode::TOO_MANY_REQUESTS,
            "ADDRESS_FULL",
            "Too many connections from this address; try again later",
        ),
    };
    let mut response = if json {
        (
            status,
            axum::Json(serde_json::json!({ "error": message, "code": code })),
        )
            .into_response()
    } else {
        (status, message).into_response()
    };
    response.headers_mut().insert(
        header::RETRY_AFTER,
        header::HeaderValue::from_static(ADMISSION_RETRY_AFTER_SECS),
    );
    response
}

/// `Retry-After` of a refused admission, in seconds: about how long a
/// connection slot takes to come free when the relay is busy (a closing
/// handshake takes up to 5 seconds, a reconnect grace period 20).
const ADMISSION_RETRY_AFTER_SECS: &str = "30";

/// Increments the per-connection protocol-error counter. Returns true once the
/// counter reaches `config.protocol_error_limit`, signalling the recv loop to
/// close the connection. Counts parse failures, unknown msg_type, and ECDH
/// oversize - categories a well-behaved client never produces.
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

fn append_ordered_group_departure(
    state: &AppState,
    room_id: Uuid,
    connection_id: Uuid,
    participant_count: usize,
) -> bool {
    let append_result = state.append_and_broadcast_mls_lifecycle(&room_id, |control_seq| {
        serde_json::to_string(&Message::UserLeft {
            user_id: connection_id,
            participant_count,
            control_seq: Some(control_seq),
        })
        .ok()
    });
    if let Err(error) = append_result {
        // Error output names the failure, never the room it happened in.
        // Strict privacy mode still emits error level, so anything
        // interpolated here survives in the container log and becomes a
        // record of which room was live at which time. The variant alone
        // is what diagnosis needs (docs/design-decisions.md, entry 1).
        tracing::error!(
            "Failed to append ordered group departure; closing the room fail-closed: {:?}",
            error
        );
        state.remove_room(&room_id);
        return false;
    }
    true
}

fn evict_group_participant(
    state: &AppState,
    room_id: Uuid,
    connection_id: Uuid,
    reason: &str,
) -> bool {
    let closes_room = state
        .rooms
        .get(&room_id)
        .map(|room| {
            room.room_type == RoomType::Group
                && room.creator_connection_id() == Some(connection_id)
                && room.creator_control_ready()
        })
        .unwrap_or(false);
    if closes_room {
        tracing::warn!(
            "Closing MLS room {} after definitive creator eviction {}: {}",
            room_id,
            connection_id,
            reason
        );
        state.remove_room(&room_id);
        return true;
    }
    let Some(participant_count) = state.evict_participant(&connection_id, room_id) else {
        return false;
    };
    tracing::warn!(
        "Evicted MLS participant {} in room {}: {}",
        connection_id,
        room_id,
        reason
    );
    let _ = append_ordered_group_departure(state, room_id, connection_id, participant_count);
    true
}

/// Remove members that are no longer advancing the authenticated control
/// cursor before accepting more room-wide MLS work. Their stable identity is
/// evicted atomically, so reconnect cycling cannot keep an obsolete ACK in the
/// pruning quorum.
fn evict_lagging_group_participants(state: &AppState, room_id: Uuid) {
    loop {
        let lagging = state.lagging_mls_control_participants(
            &room_id,
            MAX_MLS_UNACKNOWLEDGED_CONTROLS,
            MLS_CONTROL_ACK_TIMEOUT,
        );
        if lagging.is_empty() {
            return;
        }

        let mut removed_any = false;
        for connection_id in lagging {
            removed_any |=
                evict_group_participant(state, room_id, connection_id, "ACK progress stalled");
        }
        if !removed_any {
            return;
        }
    }
}

/// Longest a single WebSocket write may take before the peer is treated as
/// gone.
///
/// A write completes once the kernel has taken the frame, so it only waits
/// when the peer has stopped reading and the socket buffers are full. Left
/// unbounded, such a write parked the connection's send task for as long as
/// the peer kept the TCP connection open: the frames queued for it stayed
/// counted against the room and global broadcast byte budgets, and the ping,
/// room TTL and connection age checks on that task never ran. A peer that
/// kept sending but never read could hold that state until the connection
/// age limit, half an hour by default.
#[cfg(not(test))]
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(1);

/// How long the relay waits for the next frame of a client before it closes
/// the connection, and how long one message may take from its first frame to
/// its last byte.
#[cfg(not(test))]
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
#[cfg(test)]
const IDLE_TIMEOUT: Duration = Duration::from_secs(6);

/// How long the closing handshake may take: the relay's Close frame, the
/// client's answer, and the end of the TCP connection. A browser answers at
/// once; a peer that does not costs this long and nothing more.
#[cfg(not(test))]
const CLOSE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const CLOSE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);

/// How a connection that is no longer active in its room is closed: 1001
/// when the room itself is gone (expired, closed), 1008 when the relay took
/// the participant out of a room that still exists (evicted, or replaced by
/// a resumed connection). Both loops of a connection may notice either first.
fn no_longer_active(state: &AppState, room_id: &Uuid) -> Closing {
    if state.rooms.contains_key(room_id) {
        Closing::Initiate(close_code::POLICY)
    } else {
        Closing::Initiate(close_code::GOING_AWAY)
    }
}

/// End the connection as `closing` says (RFC 6455, section 7).
async fn close_connection(sender: &mut Writer, receiver: &mut Reader, closing: Closing) {
    ws_transport::close(sender, receiver, closing, CLOSE_HANDSHAKE_TIMEOUT).await;
}

/// How long a frame a client sent waits for room in the broadcast budgets
/// before its connection is closed, as it used to be at once. The budgets
/// are held by frames that are being written, and a write that takes longer
/// than [`WS_SEND_TIMEOUT`] ends its connection, so the wait is given the
/// same length.
const BROADCAST_ADMISSION_WAIT: Duration = WS_SEND_TIMEOUT;

/// Write one frame, giving up after [`WS_SEND_TIMEOUT`]. Returns whether the
/// frame was handed to the transport; `false` means the caller must drop the
/// connection.
///
/// The payload is borrowed: a broadcast frame is written from the allocation
/// every receiver of the room shares, and nothing of it is copied or kept by
/// the connection. A write that the deadline cuts short leaves the writer
/// refusing every later frame.
async fn send_within_deadline(sender: &mut Writer, frame: Outgoing<'_>) -> bool {
    matches!(
        tokio::time::timeout(WS_SEND_TIMEOUT, sender.send(frame)).await,
        Ok(Ok(()))
    )
}

fn schedule_connection_departure(state: &AppState, connection_id: Uuid) {
    let Some((detached_room_id, detach_count)) = state.detach_connection_counted(&connection_id)
    else {
        // The identity was taken out of its room while this socket ran
        // (evicted, or the room closed). What the socket recorded after
        // that is erased here; nothing else would.
        state.forget_departed_identity(&connection_id);
        return;
    };
    let grace_state = state.clone();
    let grace = Duration::from_secs(state.config.ws_reconnect_grace_secs);
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        let room_departure = grace_state.rooms.get(&detached_room_id).map(|room| {
            (
                room.room_type,
                room.room_type == RoomType::Group
                    && room.creator_connection_id() == Some(connection_id)
                    && room.creator_control_ready(),
            )
        });
        // Only this detach's own grace period ends here. If the identity
        // resumed and was detached again since, a later timer owns it.
        let Some(participant_count) = grace_state.finalize_disconnection_at(
            &connection_id,
            detached_room_id,
            Some(detach_count),
        ) else {
            return;
        };

        match room_departure {
            Some((RoomType::Group, true)) => {
                tracing::warn!("Closing MLS room after creator reconnect grace expired");
                grace_state.remove_room(&detached_room_id);
            }
            Some((RoomType::Group, false)) => {
                evict_lagging_group_participants(&grace_state, detached_room_id);
                let _ = append_ordered_group_departure(
                    &grace_state,
                    detached_room_id,
                    connection_id,
                    participant_count,
                );
            }
            Some((RoomType::OneToOne, _)) => {
                let leave_msg = Message::UserLeft {
                    user_id: connection_id,
                    participant_count,
                    control_seq: None,
                };
                if let Ok(json) = serde_json::to_string(&leave_msg) {
                    // Never refused by a full budget: the peer must learn
                    // that the session it holds keys for has ended.
                    let _ = grace_state.broadcast_relay_event(&detached_room_id, json);
                }
            }
            None => {}
        }

        #[cfg(debug_assertions)]
        tracing::debug!(
            "Reconnect grace expired; participant left room ({} remaining)",
            participant_count
        );
    });
}

/// Handles the WebSocket connection
///
/// # Arguments
/// * `socket` - WebSocket connection
/// * `state` - Application state
/// * `room_id` - Room ID (already validated by ws_handler)
/// * `connection_id` - Pre-allocated connection ID from JWT token (ensures uniqueness)
// One value per fact established by the upgrade; they are only ever passed
// together here.
#[allow(clippy::too_many_arguments)]
async fn handle_socket(
    socket: WsSocket,
    state: AppState,
    room_id: Uuid,
    connection_id: Uuid,
    resume_requested: bool,
    mls_control_cursor: Option<u64>,
    creator_bootstrap_generation: Option<u64>,
    admission: WsAdmission,
) {
    // Held to the end of this function, closing handshake included: the
    // connection's slots come free when the connection is really gone.
    let client_share: Option<Arc<ClientBroadcastLease>> = admission.share.clone();
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

    // Attempt to add the connection to the room. Reclaiming an ID that is
    // already grace-reserved requires the resume bit from the signed upgrade
    // JWT; two simultaneously active sockets with the same ID are rejected.
    let admission = match state.add_connection_with_bootstrap_generation(
        connection_id,
        room_id,
        resume_requested,
        creator_bootstrap_generation,
    ) {
        Some(admission) => admission,
        None => {
            #[cfg(debug_assertions)]
            tracing::debug!("Failed to add connection to room (full, active, or unavailable)");
            send_error(
                socket,
                "Room is full or reconnect is unavailable",
                close_code::POLICY,
            )
            .await;
            return;
        }
    };

    #[cfg(debug_assertions)]
    tracing::debug!(
        "Connection joined room ({} participants)",
        state.get_participant_count(&room_id)
    );

    // Get validated room configuration from server (prevents URL spoofing).
    //
    // This used to be `.expect("Room must exist")`. The invariant is real but
    // not exclusive: the cleanup task, or a concurrent handler hitting the
    // expired path, can remove the room between add_connection above and this
    // read. That is a lost race, not a bug, and panicking the connection task
    // over it is the wrong response. Unwind cleanly instead, releasing the
    // participant slot we just took.
    let room_config = state.rooms.get(&room_id).map(|room| {
        (
            room.room_type,
            room.ttl_minutes,
            room.max_participants,
            room.created_at,
        )
    });
    let Some((room_type, ttl_minutes, max_participants, created_at)) = room_config else {
        #[cfg(debug_assertions)]
        tracing::debug!("Room disappeared between add_connection and config read");
        state.remove_connection(&connection_id);
        return;
    };

    // Issue the longer-lived resume credential only after successful room
    // admission. It is sent in the direct Connected frame and never through
    // the room broadcast channel. The room's own hard TTL remains the final
    // authority even if this bearer token's wall-clock lifetime is longer by
    // a small scheduling margin.
    let resume_claims = WsResumeTokenClaims::new(
        room_id,
        connection_id,
        u64::from(ttl_minutes).saturating_mul(60),
        &state.config.jwt_issuer,
    );
    let resume_token = match sign_resume_token(&resume_claims, &state.jwt_secret) {
        Ok(token) => token,
        Err(err) => {
            tracing::error!("Failed to sign WebSocket resume credential: {}", err);
            state.remove_connection(&connection_id);
            send_error(
                socket,
                "Unable to establish reconnect state",
                close_code::INTERNAL,
            )
            .await;
            return;
        }
    };

    // Preserve the legacy one-to-one behavior: announce first admission
    // before subscribing so that socket does not receive its own transient
    // join notification. Group joins are sequenced after opening the atomic
    // control stream below.
    if admission == ConnectionAdmission::New && room_type == RoomType::OneToOne {
        let participant_count = state.get_participant_count(&room_id);
        let join_msg = Message::UserJoined {
            user_id: connection_id,
            participant_count,
            control_seq: None,
        };
        if let Ok(json) = serde_json::to_string(&join_msg) {
            // Never refused by a full budget: the peer starts its handshake
            // on this event.
            let _ = state.broadcast_relay_event(&room_id, json);
        }
    }

    // Open the live subscription and MLS replay snapshot atomically with
    // respect to control-message append+broadcast. Group reconnects replay
    // strictly after the cursor signed into their one-shot upgrade JWT.
    // Fresh participants start at the current head and do not consume
    // pre-admission MLS history.
    let (broadcast_rx, mls_control_stream) = if room_type == RoomType::Group {
        let resume_cursor = if admission == ConnectionAdmission::Resumed {
            mls_control_cursor
        } else {
            None
        };
        match state.open_mls_control_stream(&room_id, connection_id, resume_cursor) {
            Ok((receiver, stream)) => (receiver, Some(stream)),
            Err(error) => {
                tracing::warn!(
                    "Unable to open MLS control replay for connection {}: {:?}",
                    connection_id,
                    error
                );
                if admission == ConnectionAdmission::Resumed {
                    let _ = evict_group_participant(
                        &state,
                        room_id,
                        connection_id,
                        "invalid or unavailable replay cursor",
                    );
                } else {
                    let _ = state.evict_participant(&connection_id, room_id);
                }
                send_error(
                    socket,
                    "Secure group replay window is unavailable",
                    close_code::POLICY,
                )
                .await;
                return;
            }
        }
    } else {
        match state.broadcast_channels.get(&room_id) {
            Some(tx) => (tx.subscribe(), None),
            None => {
                tracing::error!("Broadcast channel not found for room");
                state.remove_connection(&connection_id);
                return;
            }
        }
    };

    // A resumed socket is the same MLS member and relay identity, so it must
    // not generate a synthetic leave/join cycle. For a fresh group member,
    // append UserJoined only after the live subscription and replay boundary
    // have been captured. Any control accepted after admission is then
    // delivered in sequence instead of being skipped as pre-admission history.
    if room_type == RoomType::Group {
        evict_lagging_group_participants(&state, room_id);
        if !state.connection_is_active(&room_id, &connection_id) {
            send_error(
                socket,
                "Secure group control stream did not advance",
                close_code::POLICY,
            )
            .await;
            return;
        }
    }
    if admission == ConnectionAdmission::New && room_type == RoomType::Group {
        let participant_count = state.get_participant_count(&room_id);
        let append_result = state.append_and_broadcast_mls_lifecycle(&room_id, |control_seq| {
            serde_json::to_string(&Message::UserJoined {
                user_id: connection_id,
                participant_count,
                control_seq: Some(control_seq),
            })
            .ok()
        });
        if let Err(error) = append_result {
            // No room identifier in error output (docs/design-decisions.md).
            tracing::error!("Failed to append ordered group join: {:?}", error);
            // Existing members must never continue in a room whose relay
            // lifecycle can no longer be represented in the authenticated
            // control order.
            state.remove_room(&room_id);
            send_error(
                socket,
                "Unable to establish secure group lifecycle",
                close_code::INTERNAL,
            )
            .await;
            return;
        }
        let creator_needs_handoff = state
            .rooms
            .get(&room_id)
            .map(|room| {
                room.creator_connection_id() == Some(connection_id) && !room.creator_control_ready()
            })
            .unwrap_or(false);
        if creator_needs_handoff && !state.mark_creator_control_ready(&room_id, connection_id) {
            state.remove_room(&room_id);
            send_error(
                socket,
                "Unable to establish group creator control boundary",
                close_code::INTERNAL,
            )
            .await;
            return;
        }
    }

    // Split the socket only after every fallible setup step that needs the
    // unsplit value has completed.
    let (mut sender, mut receiver) = socket.split();

    // Send connection confirmation message with validated room config.
    let connected_msg = Message::Connected {
        user_id: connection_id,
        room_id,
        participant_count: state.get_participant_count(&room_id),
        room_type,                                   // Validated from server
        ttl_minutes,                                 // Validated from server
        max_participants,                            // Validated from server
        max_image_size: state.config.max_image_size, // From server config
        created_at,                                  // Room creation timestamp for countdown
        resume_token,
        resumed: admission == ConnectionAdmission::Resumed,
        mls_control_cursor: mls_control_stream.as_ref().map(|stream| stream.cursor),
    };

    let connected_sent = match serde_json::to_string(&connected_msg) {
        Ok(json) => send_within_deadline(&mut sender, Outgoing::Text(&json)).await,
        Err(_) => false,
    };
    if !connected_sent {
        schedule_connection_departure(&state, connection_id);
        return;
    }

    // Replay is sent after Connected in bounded windows. The next window is
    // released only after the browser has authenticated, applied, and
    // cumulatively ACKed the previous one. This prevents a retained server
    // backlog from overflowing the browser's serial cryptographic queue.
    //
    // After a non-empty snapshot is ACKed, subscribe and snapshot again from
    // that exact cursor. Controls accepted while replay was in progress are
    // therefore recovered from the durable log even if the transient
    // broadcast ring wrapped meanwhile.
    //
    // The live subscription of a non-empty snapshot is dropped before the
    // replay starts: it is replaced by that next one, and nothing reads it
    // in between. Kept, it held every frame the room sent meanwhile in the
    // broadcast budgets until the browser had acknowledged the whole replay,
    // up to a minute for each window, where any other receiver holds a frame
    // for 30 seconds at most.
    let mut broadcast_rx = Some(broadcast_rx);
    if let Some(mut stream) = mls_control_stream {
        loop {
            if !stream.replay.is_empty() {
                broadcast_rx = None;
            }
            for window in stream.replay.chunks(MLS_REPLAY_WINDOW_ENTRIES) {
                for entry in window {
                    if !send_within_deadline(&mut sender, Outgoing::Text(entry.json.as_str())).await
                    {
                        schedule_connection_departure(&state, connection_id);
                        return;
                    }
                }

                let target_seq = window.last().expect("replay window is non-empty").seq;
                let ack_result = tokio::time::timeout(MLS_CONTROL_ACK_TIMEOUT, async {
                    let mut replay_frames = 0usize;
                    loop {
                        let frame = match receiver.next().await {
                            Some(Ok(frame)) => frame,
                            Some(Err(error)) => {
                                return Err(ReplayAckError::Transport(error.closing()));
                            }
                            None => return Err(ReplayAckError::Transport(Closing::Abort)),
                        };
                        replay_frames = replay_frames.saturating_add(1);
                        if replay_frames > MLS_REPLAY_WINDOW_ENTRIES.saturating_mul(4) {
                            return Err(ReplayAckError::Protocol);
                        }
                        match frame {
                            Incoming::Text(text) => {
                                if text.len() > max_ws_size(state.config.max_image_size) {
                                    return Err(ReplayAckError::Protocol);
                                }
                                let incoming = serde_json::from_str::<IncomingMessage>(&text)
                                    .map_err(|_| ReplayAckError::Protocol)?;
                                let ack_shape_valid = incoming.msg_type == "mlsack"
                                    && incoming.payload.is_none()
                                    && incoming.header.is_none()
                                    && incoming.wire_format.is_none()
                                    && incoming.ratchet_tree.is_none()
                                    && incoming.key_package_ref.is_none()
                                    && incoming.commit_ref.is_none()
                                    && incoming.bootstrap_proof.is_none();
                                let Some(ack_seq) = incoming.control_seq.filter(|seq| *seq > 0)
                                else {
                                    return Err(ReplayAckError::Protocol);
                                };
                                if !ack_shape_valid
                                    || !state.acknowledge_mls_control(
                                        &room_id,
                                        connection_id,
                                        ack_seq,
                                    )
                                {
                                    return Err(ReplayAckError::Protocol);
                                }
                                if ack_seq >= target_seq {
                                    return Ok(());
                                }
                            }
                            Incoming::Ping(payload) => {
                                if !send_within_deadline(&mut sender, Outgoing::Pong(&payload))
                                    .await
                                {
                                    return Err(ReplayAckError::Transport(Closing::Abort));
                                }
                            }
                            Incoming::Pong => {}
                            Incoming::Close(code) => {
                                return Err(ReplayAckError::Transport(Closing::Answer(code)));
                            }
                            Incoming::Binary => {
                                return Err(ReplayAckError::Protocol);
                            }
                        }
                    }
                })
                .await;

                match ack_result {
                    Ok(Ok(())) => {}
                    Ok(Err(ReplayAckError::Transport(closing))) => {
                        schedule_connection_departure(&state, connection_id);
                        close_connection(&mut sender, &mut receiver, closing).await;
                        return;
                    }
                    Ok(Err(ReplayAckError::Protocol)) => {
                        let _ = evict_group_participant(
                            &state,
                            room_id,
                            connection_id,
                            "invalid frame while replay ACK was required",
                        );
                        close_connection(
                            &mut sender,
                            &mut receiver,
                            Closing::Initiate(close_code::POLICY),
                        )
                        .await;
                        return;
                    }
                    Err(_) => {
                        let _ = evict_group_participant(
                            &state,
                            room_id,
                            connection_id,
                            "replay ACK deadline expired",
                        );
                        close_connection(
                            &mut sender,
                            &mut receiver,
                            Closing::Initiate(close_code::POLICY),
                        )
                        .await;
                        return;
                    }
                }
            }

            if stream.replay.is_empty() {
                let sync = serde_json::to_string(&Message::MlsSync {
                    through_seq: stream.through_seq,
                })
                .expect("MlsSync serialization cannot fail");
                let sync_sent = send_within_deadline(&mut sender, Outgoing::Text(&sync)).await;
                if !sync_sent {
                    schedule_connection_departure(&state, connection_id);
                    return;
                }
                break;
            }

            match state.open_mls_control_stream(&room_id, connection_id, Some(stream.through_seq)) {
                Ok((next_receiver, next_stream)) => {
                    broadcast_rx = Some(next_receiver);
                    stream = next_stream;
                }
                Err(error) => {
                    tracing::warn!("Unable to continue MLS control replay: {:?}", error);
                    let _ = evict_group_participant(
                        &state,
                        room_id,
                        connection_id,
                        "replay cursor became unavailable",
                    );
                    close_connection(
                        &mut sender,
                        &mut receiver,
                        Closing::Initiate(close_code::POLICY),
                    )
                    .await;
                    return;
                }
            }
        }
    }
    // The replay ends with an empty snapshot, which keeps its subscription.
    let Some(mut broadcast_rx) = broadcast_rx else {
        schedule_connection_departure(&state, connection_id);
        return;
    };

    // Direct responses (currently Commit rate-limit rejections) share the
    // single socket writer with room broadcasts.
    let (direct_tx, mut direct_rx) = tokio::sync::mpsc::channel::<String>(8);
    // A ping from the client is answered by the task that owns the writer.
    // One slot: while an answer is waiting, further pings are not queued.
    let (pong_tx, mut pong_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);

    // Task that receives broadcast messages and forwards them to the client
    // Also sends heartbeat pings every 30 seconds to keep the connection alive,
    // and re-validates room TTL to enforce the hard expiry deadline even on
    // connections opened just before the TTL boundary.
    let send_state = state.clone();
    let connected_at = Instant::now();
    let max_connection_age = Duration::from_secs(send_state.config.max_ws_connection_age_secs);
    // Whichever of the two loops below ends first says how the connection
    // closes. When the receiving one does, this tells the sending one to
    // stop once the frame it is writing, if any, is out: a frame cut short
    // could not be followed by a Close frame.
    let (stop_sending, mut stopped) = tokio::sync::oneshot::channel::<()>();
    let send_half = &mut sender;
    let send_side = async move {
        let mut ping_interval = interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = &mut stopped => return Closing::Abort,
                Some(msg) = direct_rx.recv() => {
                    if !send_state.connection_is_active(&room_id, &connection_id) {
                        return no_longer_active(&send_state, &room_id);
                    }
                    if !send_within_deadline(&mut *send_half, Outgoing::Text(&msg)).await {
                        return Closing::Abort;
                    }
                }
                Some(payload) = pong_rx.recv() => {
                    if !send_within_deadline(&mut *send_half, Outgoing::Pong(&payload)).await {
                        return Closing::Abort;
                    }
                }
                result = broadcast_rx.recv() => {
                    match result {
                        Ok(msg) => {
                            if !send_state
                                .connection_is_active(&room_id, &connection_id)
                            {
                                return no_longer_active(&send_state, &room_id);
                            }
                            // Written from the allocation the whole room
                            // shares. While this write is pending the frame
                            // stays counted in the broadcast budgets, which
                            // is what bounds the memory a receiver that does
                            // not read can hold.
                            if !send_within_deadline(&mut *send_half, Outgoing::Text(msg.as_str()))
                                .await
                            {
                                return Closing::Abort;
                            }
                        }
                        // A receiver that fell behind the room's ring.
                        Err(RecvError::Lagged(_)) => return Closing::Initiate(close_code::POLICY),
                        // The room is gone.
                        Err(RecvError::Closed) => return Closing::Initiate(close_code::GOING_AWAY),
                    }
                }
                _ = ping_interval.tick() => {
                    if room_type == RoomType::Group {
                        evict_lagging_group_participants(&send_state, room_id);
                    }
                    if !send_state.connection_is_active(&room_id, &connection_id) {
                        return no_longer_active(&send_state, &room_id);
                    }
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
                        return Closing::Initiate(close_code::GOING_AWAY);
                    }
                    // Hard cap on connection lifetime: even an active client is
                    // forced to reconnect, which re-runs PoW + JWT issuance.
                    // Stable resume retains the browser's Double Ratchet.
                    // Bounds resource usage from clients that heartbeat indefinitely.
                    if connected_at.elapsed() > max_connection_age {
                        #[cfg(debug_assertions)]
                        tracing::debug!("Connection exceeded max age, closing");
                        return Closing::Initiate(close_code::GOING_AWAY);
                    }
                    if !send_within_deadline(&mut *send_half, Outgoing::Ping).await {
                        return Closing::Abort;
                    }
                }
            }
        }
    };

    // Loop that receives messages from the client and broadcasts them.
    // The idle timeout closes zombie connections that stop sending frames
    // (including pong responses) within that window, protecting against
    // file-descriptor exhaustion from stale TCP sessions. The same span is
    // the most one message may take from its first frame to its last byte,
    // however many control frames come in between (WsReader::next_within).
    let state_clone = state.clone();
    let recv_direct_tx = direct_tx.clone();
    let recv_client_share = client_share.clone();
    // A client that breaks the relay's rules (rate limits, malformed or
    // misplaced relay messages) still speaks WebSocket correctly, so its
    // connection is closed with the full handshake and code 1008, as a
    // browser expects. Only a stream that breaks RFC 6455 itself is failed
    // without waiting for an answer (`WsError::closing`).
    let recv_half = &mut receiver;
    let recv_side = async move {
        loop {
            let msg = match recv_half.next_within(IDLE_TIMEOUT).await {
                Some(Ok(Incoming::Close(code))) => return Closing::Answer(code),
                Some(Ok(msg)) => msg,
                Some(Err(error)) => return error.closing(),
                None => return Closing::Abort,
            };
            if !state_clone.connection_is_active(&room_id, &connection_id) {
                return no_longer_active(&state_clone, &room_id);
            }
            // C-14: classify the frame up front. Close terminates the loop
            // and is not counted against the rate limit. All other frame
            // types (Text, Binary, Ping, Pong) pass through the lifecycle
            // gates and the global rate limiter, but only Text is
            // application-relevant - Binary/Ping/Pong are accounted for
            // and dropped.
            let mut ping = None;
            let text = match msg {
                Incoming::Text(t) => Some(t),
                Incoming::Ping(payload) => {
                    ping = Some(payload);
                    None
                }
                // A Close frame has ended the loop above.
                Incoming::Close(_) | Incoming::Pong | Incoming::Binary => None,
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
                return Closing::Initiate(close_code::GOING_AWAY);
            }
            // Hard cap on connection lifetime. The send-side ping check
            // already enforces this, but applying it here closes the
            // connection on the next inbound frame instead of waiting
            // for the next ping tick.
            if connected_at.elapsed() > max_connection_age {
                #[cfg(debug_assertions)]
                tracing::debug!("Recv past max connection age, closing");
                return Closing::Initiate(close_code::GOING_AWAY);
            }

            // GLOBAL FRAME RATE LIMIT (C-14): counts EVERY non-Close frame,
            // not just Text. Previously the limiter sat inside the Text
            // branch; a hostile peer could flood Ping/Pong/Binary frames
            // to keep the recv loop busy without consuming the budget.
            // Each of those frames wakes this task, and a Ping is answered
            // further down; counting them all closes the gap.
            // Lifecycle-bound (Close + max age + room
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
                    return Closing::Initiate(close_code::POLICY);
                }
                ts.push_back(now);
            }

            // Per-type handling: only Text frames carry application data.
            // Binary and Pong have been counted above and are dropped
            // silently here. A Ping, counted like the rest, is answered.
            if let Some(payload) = ping {
                let _ = pong_tx.try_send(payload);
            }
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
                return Closing::Fail(close_code::TOO_BIG);
            }

            {
                // Parse the incoming message. The parsed form owns its
                // strings, so the frame it was read from goes at once: a
                // picture is not held twice while it is checked and sent on.
                let parsed = serde_json::from_str::<IncomingMessage>(&text);
                drop(text);
                match parsed {
                    Ok(incoming) => {
                        // Room types are cryptographic protocol boundaries,
                        // not a UI preference. A group room accepts only MLS;
                        // a 1:1 room accepts only the Double-Ratchet transport.
                        if !room_accepts_client_message(room_type, &incoming.msg_type) {
                            tracing::warn!(
                                "message type '{}' is invalid for room type {:?} (connection_id={})",
                                incoming.msg_type,
                                room_type,
                                connection_id
                            );
                            if bump_protocol_error(&state_clone, connection_id) {
                                return Closing::Initiate(close_code::POLICY);
                            }
                            continue;
                        }

                        // Ordered MLS-control acknowledgement. ACKs are direct
                        // transport bookkeeping and are never rebroadcast.
                        if incoming.msg_type == "mlsack" {
                            let ack_shape_valid = incoming.payload.is_none()
                                && incoming.header.is_none()
                                && incoming.wire_format.is_none()
                                && incoming.ratchet_tree.is_none()
                                && incoming.key_package_ref.is_none()
                                && incoming.commit_ref.is_none()
                                && incoming.bootstrap_proof.is_none();
                            let acknowledged = incoming
                                .control_seq
                                .filter(|seq| *seq > 0)
                                .map(|seq| {
                                    state_clone.acknowledge_mls_control(
                                        &room_id,
                                        connection_id,
                                        seq,
                                    )
                                })
                                .unwrap_or(false);
                            if !ack_shape_valid || !acknowledged {
                                tracing::warn!(
                                    "invalid MLS control ACK from connection_id={}",
                                    connection_id
                                );
                                if bump_protocol_error(&state_clone, connection_id) {
                                    return Closing::Initiate(close_code::POLICY);
                                }
                            }
                            continue;
                        }

                        // Handle ECDH public key exchange (blind relay, no crypto server-side)
                        if incoming.msg_type == "ecdh_public_key" {
                            // Per-connection ECDH burst limiter. The looser
                            // frame_rate_limit (default 120/s) was the only gate
                            // here; an authenticated peer could flood handshake
                            // frames and force the receiver client into repeated
                            // signature verification + key import + Double
                            // Ratchet reinit. Real handshakes need 1-2 frames
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
                                    return Closing::Initiate(close_code::POLICY);
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
                                        return Closing::Initiate(close_code::POLICY);
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

                                        match state_clone
                                            .broadcast_room_message_when_room(
                                                &room_id,
                                                json,
                                                recv_client_share.as_deref(),
                                                BROADCAST_ADMISSION_WAIT,
                                            )
                                            .await
                                        {
                                            Ok(receiver_count) => {
                                                tracing::info!(
                                                    "✅ ECDH public key broadcasted to {} receivers in room={}",
                                                    receiver_count,
                                                    room_id
                                                );
                                            }
                                            Err(e) => {
                                                tracing::error!(
                                                    "❌ Failed to broadcast ECDH message: {:?}",
                                                    e
                                                );
                                            }
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
                        // MLS envelope (RFC 9420). The relay remains blind to
                        // cryptographic contents, but validates the supported
                        // transport shape and shallow PublicMessage content
                        // type before allocating or rebroadcasting it.
                        else if incoming.msg_type == "mls" {
                            if incoming.control_seq.is_some() {
                                tracing::warn!(
                                    "client attempted to set server MLS control sequence (connection_id={})",
                                    connection_id
                                );
                                if bump_protocol_error(&state_clone, connection_id) {
                                    return Closing::Initiate(close_code::POLICY);
                                }
                                continue;
                            }
                            let payload = match incoming.payload {
                                Some(p) => p,
                                None => {
                                    tracing::warn!(
                                        "mls envelope without payload from connection_id={}",
                                        connection_id
                                    );
                                    if bump_protocol_error(&state_clone, connection_id) {
                                        return Closing::Initiate(close_code::POLICY);
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
                                        return Closing::Initiate(close_code::POLICY);
                                    }
                                    continue;
                                }
                            };
                            let ratchet_tree = incoming.ratchet_tree;
                            let key_package_ref = incoming.key_package_ref;
                            let commit_ref = incoming.commit_ref;
                            let bootstrap_proof = incoming.bootstrap_proof;
                            let validated = match validate_mls_envelope(
                                &payload,
                                wire_format,
                                ratchet_tree.as_deref(),
                                key_package_ref.as_deref(),
                                commit_ref.as_deref(),
                                bootstrap_proof.as_deref(),
                                state_clone.config.max_image_size,
                            ) {
                                Ok(validated) => validated,
                                Err(reason) => {
                                    tracing::warn!(
                                        "invalid MLS envelope from connection_id={}: {}",
                                        connection_id,
                                        reason
                                    );
                                    if bump_protocol_error(&state_clone, connection_id) {
                                        return Closing::Initiate(close_code::POLICY);
                                    }
                                    continue;
                                }
                            };

                            // Anti-replay covers the complete canonical relay
                            // envelope. Hashing only payload lets an attacker
                            // race altered correlation/tree metadata and cause
                            // the authentic envelope to be discarded later.
                            let payload_hash = mls_envelope_replay_hash(
                                wire_format,
                                &validated,
                                key_package_ref.as_deref(),
                                commit_ref.as_deref(),
                                bootstrap_proof.as_deref(),
                            );
                            let now = Utc::now();

                            // Per-connection rate limit (same cadence).
                            let max_messages = state_clone.config.msg_rate_limit;
                            let rate_window_secs = state_clone.config.msg_rate_window_secs;
                            let mut timestamps = state_clone
                                .connection_message_timestamps
                                .entry(connection_id)
                                .or_default();
                            let rate_cutoff = now - chrono::Duration::seconds(rate_window_secs);
                            timestamps.retain(|&ts| ts > rate_cutoff);
                            if timestamps.len() >= max_messages {
                                tracing::warn!(
                                    "Connection {} exceeded rate limit on mls, disconnecting",
                                    connection_id
                                );
                                return Closing::Initiate(close_code::POLICY);
                            }
                            timestamps.push_back(now);
                            // Release the entry guard before grabbing the
                            // commit-specific one to avoid holding two
                            // DashMap shards across an await point.
                            drop(timestamps);

                            let is_commit =
                                validated.public_kind == Some(PublicMessageKind::Commit);

                            // Only the group creator may send a Commit or a
                            // Welcome; the log refuses them from anyone else
                            // (`append_and_broadcast_mls_control_at`). They are
                            // refused here already, before the room's traffic
                            // budget: each member may take half of it, so two
                            // identities sending controls the relay refuses
                            // anyway took all of it from the creator. An
                            // honest client never sends one, so each counts
                            // as a protocol error.
                            if (is_commit || wire_format == WIRE_WELCOME)
                                && state_clone
                                    .rooms
                                    .get(&room_id)
                                    .and_then(|room| room.creator_connection_id())
                                    != Some(connection_id)
                            {
                                tracing::warn!(
                                    "MLS Commit or Welcome from a member that is not the group creator"
                                );
                                if let Some(rejection) = permanent_mls_append_rejection(
                                    MlsControlAppendError::UnauthorizedGroupCreatorControl,
                                    commit_ref.clone(),
                                ) && let Ok(json) = serde_json::to_string(&rejection)
                                {
                                    let _ = recv_direct_tx.try_send(json);
                                }
                                if bump_protocol_error(&state_clone, connection_id) {
                                    return Closing::Initiate(close_code::POLICY);
                                }
                                continue;
                            }

                            // Tighter per-connection Commit rate limit. A
                            // PublicMessage Proposal is authenticated but does
                            // not run TreeKEM/key schedule and must not consume
                            // the creator's Commit budget.
                            if is_commit {
                                let max_commits = state_clone.config.commit_rate_limit;
                                let commit_window = state_clone.config.commit_rate_window_secs;
                                let mut commit_ts = state_clone
                                    .connection_commit_timestamps
                                    .entry(connection_id)
                                    .or_default();
                                let commit_cutoff = now - chrono::Duration::seconds(commit_window);
                                commit_ts.retain(|&ts| ts > commit_cutoff);
                                if commit_ts.len() >= max_commits {
                                    tracing::warn!(
                                        "Connection {} exceeded MLS commit rate limit ({}/{}s), rejecting",
                                        connection_id,
                                        max_commits,
                                        commit_window
                                    );
                                    let rejection = Message::MlsRejected {
                                        commit_ref: commit_ref.clone(),
                                        reason: "commit_rate_limited".to_string(),
                                        retry_after_secs: u64::try_from(commit_window)
                                            .unwrap_or(60),
                                    };
                                    if let Ok(json) = serde_json::to_string(&rejection) {
                                        let _ = recv_direct_tx.try_send(json);
                                    }
                                    continue;
                                }
                            } else if validated.public_kind == Some(PublicMessageKind::Proposal) {
                                let max_proposals = state_clone.config.proposal_rate_limit;
                                let proposal_window = state_clone.config.proposal_rate_window_secs;
                                let mut proposal_ts = state_clone
                                    .connection_proposal_timestamps
                                    .entry(connection_id)
                                    .or_default();
                                let proposal_cutoff =
                                    now - chrono::Duration::seconds(proposal_window);
                                proposal_ts.retain(|&ts| ts > proposal_cutoff);
                                if proposal_ts.len() >= max_proposals {
                                    tracing::warn!(
                                        "Connection {} exceeded MLS Proposal rate limit ({}/{}s), disconnecting",
                                        connection_id,
                                        max_proposals,
                                        proposal_window
                                    );
                                    return Closing::Initiate(close_code::POLICY);
                                }
                                proposal_ts.push_back(now);
                            }

                            let traffic_bytes = validated.payload_bytes.len().saturating_add(
                                validated
                                    .ratchet_tree_bytes
                                    .as_ref()
                                    .map(Vec::len)
                                    .unwrap_or(0),
                            );
                            // Every MLS envelope consumes aggregate room
                            // count/byte budget. Otherwise large Welcome or
                            // KeyPackage controls can amplify decode, replay,
                            // and broadcast work on every member while
                            // bypassing the room-wide limiter.
                            if !state_clone.admit_room_traffic(
                                room_id,
                                connection_id,
                                now,
                                traffic_bytes,
                            ) {
                                tracing::warn!(
                                    "Room {} rejected traffic from {} at aggregate/sender budget",
                                    room_id,
                                    connection_id,
                                );
                                if is_commit {
                                    let rejection = Message::MlsRejected {
                                        commit_ref: commit_ref.clone(),
                                        reason: "room_rate_limited".to_string(),
                                        retry_after_secs: u64::try_from(
                                            state_clone.config.msg_rate_window_secs,
                                        )
                                        .unwrap_or(1),
                                    };
                                    if let Ok(json) = serde_json::to_string(&rejection) {
                                        let _ = recv_direct_tx.try_send(json);
                                    }
                                }
                                if is_commit {
                                    // A staged Commit gets a typed retry and
                                    // remains pending on the browser.
                                    continue;
                                }
                                if wire_format == WIRE_PRIVATE_MESSAGE {
                                    // Private messages are ephemeral.
                                    continue;
                                }
                                // WebSocketManager retains ordered controls
                                // until their sequenced own echo. Closing here
                                // causes the exact KeyPackage/Proposal/Welcome
                                // to be retried after replay sync rather than
                                // silently accepting-and-dropping it.
                                return Closing::Initiate(close_code::TRY_AGAIN_LATER);
                            }
                            if is_commit {
                                state_clone
                                    .connection_commit_timestamps
                                    .entry(connection_id)
                                    .or_default()
                                    .push_back(now);
                            }

                            if wire_format != WIRE_PRIVATE_MESSAGE {
                                evict_lagging_group_participants(&state_clone, room_id);
                                if !state_clone.connection_is_active(&room_id, &connection_id) {
                                    return no_longer_active(&state_clone, &room_id);
                                }
                            }

                            // Record replay identity only after every quota
                            // gate accepts the envelope. A rate-limited Commit
                            // must remain retryable after the window instead of
                            // poisoning the replay cache despite never having
                            // been broadcast.
                            //
                            // The cache lock lives only inside this call. The
                            // append and the lag eviction below can close the
                            // room, and room teardown takes the same lock.
                            match state_clone.record_replay_hash(&room_id, &payload_hash, now) {
                                ReplayAdmission::New => {}
                                ReplayAdmission::Duplicate => continue,
                                ReplayAdmission::RoomGone => {
                                    return Closing::Initiate(close_code::GOING_AWAY);
                                }
                            }

                            if wire_format == WIRE_PRIVATE_MESSAGE {
                                let broadcast_msg = Message::Mls {
                                    payload,
                                    wire_format,
                                    ratchet_tree,
                                    key_package_ref,
                                    commit_ref,
                                    bootstrap_proof,
                                    control_seq: None,
                                    sender_id: connection_id,
                                };
                                let serialized = serde_json::to_string(&broadcast_msg);
                                // Only the serialized frame is kept while it
                                // waits for room in the broadcast budgets.
                                drop(broadcast_msg);
                                drop(validated);
                                match serialized {
                                    Ok(json) => {
                                        if state_clone
                                            .broadcast_room_message_when_room(
                                                &room_id,
                                                json,
                                                recv_client_share.as_deref(),
                                                BROADCAST_ADMISSION_WAIT,
                                            )
                                            .await
                                            .is_err()
                                        {
                                            state_clone.forget_replay_hash(&room_id, &payload_hash);
                                            tracing::warn!(
                                                "Room {} broadcast byte budget exhausted",
                                                room_id
                                            );
                                            return Closing::Initiate(close_code::TRY_AGAIN_LATER);
                                        }
                                    }
                                    Err(error) => {
                                        state_clone.forget_replay_hash(&room_id, &payload_hash);
                                        tracing::error!(
                                            "Failed to serialize MLS PrivateMessage: {}",
                                            error
                                        );
                                        return Closing::Initiate(close_code::INTERNAL);
                                    }
                                }
                            } else {
                                let admission = match wire_format {
                                    WIRE_KEY_PACKAGE => MlsControlAdmission::KeyPackage {
                                        sender_id: connection_id,
                                        key_package_ref: mls_key_package_ref(
                                            &validated.payload_bytes,
                                        )
                                        .expect("bounded KeyPackage reference input"),
                                    },
                                    WIRE_WELCOME => MlsControlAdmission::Welcome {
                                        sender_id: connection_id,
                                        commit_ref: commit_ref
                                            .clone()
                                            .expect("Welcome validated with commit_ref"),
                                        key_package_ref: key_package_ref
                                            .clone()
                                            .expect("Welcome validated with key_package_ref"),
                                    },
                                    WIRE_PUBLIC_MESSAGE
                                        if is_commit && key_package_ref.is_some() =>
                                    {
                                        MlsControlAdmission::AddCommit {
                                            sender_id: connection_id,
                                            commit_ref: commit_ref
                                                .clone()
                                                .expect("Commit validated with commit_ref"),
                                            key_package_ref: key_package_ref
                                                .clone()
                                                .expect("guarded by is_some"),
                                        }
                                    }
                                    WIRE_PUBLIC_MESSAGE if is_commit => {
                                        MlsControlAdmission::Commit {
                                            sender_id: connection_id,
                                        }
                                    }
                                    _ => MlsControlAdmission::Ordinary,
                                };
                                // Only the strings are kept while the control
                                // waits for room in the broadcast budgets.
                                drop(validated);
                                let submitted_commit_ref = commit_ref.clone();
                                // A full broadcast budget is waited out, as
                                // for every other frame a client sends; it
                                // used to close the connection at once.
                                let append_result = state_clone
                                    .append_and_broadcast_mls_envelope_when_room(
                                        &room_id,
                                        admission,
                                        recv_client_share.as_deref(),
                                        BROADCAST_ADMISSION_WAIT,
                                        |control_seq| {
                                            serde_json::to_string(&Message::Mls {
                                                payload: payload.clone(),
                                                wire_format,
                                                ratchet_tree: ratchet_tree.clone(),
                                                key_package_ref: key_package_ref.clone(),
                                                commit_ref: commit_ref.clone(),
                                                bootstrap_proof: bootstrap_proof.clone(),
                                                control_seq: Some(control_seq),
                                                sender_id: connection_id,
                                            })
                                            .ok()
                                        },
                                    )
                                    .await;
                                if let Err(error) = append_result {
                                    state_clone.forget_replay_hash(&room_id, &payload_hash);
                                    // No room identifier in error output
                                    // (docs/design-decisions.md).
                                    tracing::error!(
                                        "Failed to append MLS control envelope: {:?}",
                                        error
                                    );
                                    // What only a misbehaving client sends is
                                    // also counted, like any other malformed
                                    // control.
                                    let misbehaving = matches!(
                                        error,
                                        MlsControlAppendError::UnauthorizedGroupCreatorControl
                                            | MlsControlAppendError::CommitCorrelationConflict
                                    );
                                    if let Some(rejection) =
                                        permanent_mls_append_rejection(error, submitted_commit_ref)
                                    {
                                        if misbehaving
                                            && bump_protocol_error(&state_clone, connection_id)
                                        {
                                            return Closing::Initiate(close_code::POLICY);
                                        }
                                        if let Ok(json) = serde_json::to_string(&rejection)
                                            && recv_direct_tx.try_send(json).is_ok()
                                        {
                                            continue;
                                        }
                                        tracing::warn!(
                                            "Unable to deliver permanent MLS rejection; closing for retry"
                                        );
                                    }
                                    return Closing::Initiate(close_code::TRY_AGAIN_LATER);
                                }
                                evict_lagging_group_participants(&state_clone, room_id);
                                if !state_clone.connection_is_active(&room_id, &connection_id) {
                                    return no_longer_active(&state_clone, &room_id);
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
                                    // A WebSocket write only confirms local
                                    // buffering. Tell the sender explicitly
                                    // when a payload was refused by the relay.
                                    let error = Message::Error {
                                        message: format!(
                                            "The {} was not sent because it exceeds the server size limit.",
                                            incoming.msg_type
                                        ),
                                    };
                                    if let Ok(json) = serde_json::to_string(&error)
                                        && recv_direct_tx.try_send(json).is_err()
                                    {
                                        return Closing::Initiate(close_code::POLICY);
                                    }
                                    continue;
                                }

                                // Validate header: must be present, v1, and within size bounds.
                                // The cryptographic signature verification happens client-side
                                // (server is blind relay), but we enforce shape + DoS caps here.
                                const MAX_SIG_LEN: usize = 100; // ECDSA P-256 base64url ≤ 88 chars
                                const MAX_DH_LEN: usize = 100; // P-256 uncompressed raw 65 B -> ~88 chars base64url
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
                                        // Audit L-6: a malformed header is the
                                        // same class of misbehaviour as an
                                        // unknown msg_type or unparseable JSON,
                                        // and a well-behaved v1 client never
                                        // emits one. Without this the only
                                        // ceiling was frame_rate_limit (120/s),
                                        // so a peer could sit just under it and
                                        // stream junk headers indefinitely.
                                        if bump_protocol_error(&state_clone, connection_id) {
                                            return Closing::Initiate(close_code::POLICY);
                                        }
                                        continue;
                                    }
                                };

                                let payload_hash = one_to_one_envelope_replay_hash(
                                    &incoming.msg_type,
                                    &payload,
                                    &hdr,
                                );

                                let now = Utc::now();
                                // RATE LIMITING: enforce per-connection first,
                                // then aggregate room count/bytes. Rejected
                                // traffic must not poison the replay cache.
                                let max_messages = state_clone.config.msg_rate_limit;
                                let rate_window_secs = state_clone.config.msg_rate_window_secs;
                                let mut timestamps = state_clone
                                    .connection_message_timestamps
                                    .entry(connection_id)
                                    .or_default();
                                let rate_cutoff = now - chrono::Duration::seconds(rate_window_secs);
                                timestamps.retain(|&ts| ts > rate_cutoff);
                                if timestamps.len() >= max_messages {
                                    tracing::warn!(
                                        "Connection {} exceeded rate limit ({}/{}s), disconnecting",
                                        connection_id,
                                        timestamps.len(),
                                        rate_window_secs
                                    );
                                    return Closing::Initiate(close_code::POLICY);
                                }
                                timestamps.push_back(now);
                                drop(timestamps);

                                if !state_clone.admit_room_traffic(
                                    room_id,
                                    connection_id,
                                    now,
                                    payload.len(),
                                ) {
                                    tracing::warn!(
                                        "Room {} rejected traffic from {} at aggregate/sender budget",
                                        room_id,
                                        connection_id,
                                    );
                                    // Aggregate pressure is not evidence that
                                    // this sender caused it. Drop this
                                    // ephemeral frame without severing the
                                    // authenticated relay identity.
                                    continue;
                                }

                                // Same lock discipline as the MLS branch:
                                // the cache lock is released before anything
                                // else touches room state.
                                match state_clone.record_replay_hash(&room_id, &payload_hash, now) {
                                    ReplayAdmission::New => {}
                                    ReplayAdmission::Duplicate => {
                                        // REPLAY DETECTED - Ignore silently (don't broadcast)
                                        #[cfg(debug_assertions)]
                                        tracing::debug!(
                                            "Replay attack detected (duplicate payload hash)"
                                        );
                                        continue;
                                    }
                                    ReplayAdmission::RoomGone => {
                                        return Closing::Initiate(close_code::GOING_AWAY);
                                    }
                                }

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

                                let serialized = serde_json::to_string(&broadcast_msg);
                                // Only the serialized frame is kept while it
                                // waits for room in the broadcast budgets.
                                drop(broadcast_msg);
                                match serialized {
                                    Ok(json) => {
                                        if state_clone
                                            .broadcast_room_message_when_room(
                                                &room_id,
                                                json,
                                                recv_client_share.as_deref(),
                                                BROADCAST_ADMISSION_WAIT,
                                            )
                                            .await
                                            .is_err()
                                        {
                                            state_clone.forget_replay_hash(&room_id, &payload_hash);
                                            tracing::warn!(
                                                "Room {} broadcast byte budget exhausted",
                                                room_id
                                            );
                                            return Closing::Initiate(close_code::TRY_AGAIN_LATER);
                                        }
                                    }
                                    Err(error) => {
                                        state_clone.forget_replay_hash(&room_id, &payload_hash);
                                        tracing::error!(
                                            "Failed to serialize relay message: {}",
                                            error
                                        );
                                        return Closing::Initiate(close_code::INTERNAL);
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
                                return Closing::Initiate(close_code::POLICY);
                            }
                        }
                    }
                    Err(_e) => {
                        #[cfg(debug_assertions)]
                        tracing::debug!("Failed to parse message: {}", _e);
                        if bump_protocol_error(&state_clone, connection_id) {
                            return Closing::Initiate(close_code::POLICY);
                        }
                    }
                }
            }
        }
    };

    // Both loops run in this task, each borrowing its half of the socket.
    // The one that ends first decides how the connection closes; the other
    // is stopped, and the closing handshake then runs on the two halves.
    // Dropping the receiving loop loses nothing the transport has read: a
    // read may be abandoned at any point.
    enum Ended {
        Sending(Closing),
        Receiving(Closing),
    }
    //
    // The loops used to run as tasks of their own, and a panic in one of
    // them ended only that task: the connection was still detached from
    // its room below. A panic is caught here for the same reason, and the
    // connection then ends without a closing handshake.
    let mut send_side = Box::pin(AssertUnwindSafe(send_side).catch_unwind());
    let mut recv_side = Box::pin(AssertUnwindSafe(recv_side).catch_unwind());
    let ended = tokio::select! {
        closing = &mut send_side => Ended::Sending(closing.unwrap_or(Closing::Abort)),
        closing = &mut recv_side => Ended::Receiving(closing.unwrap_or(Closing::Abort)),
    };
    drop(recv_side);
    let closing = match ended {
        Ended::Sending(closing) => {
            drop(send_side);
            closing
        }
        Ended::Receiving(closing) => {
            let _ = stop_sending.send(());
            // Bounded by the write deadline of the frame in progress. A
            // panic there leaves the writer refusing frames, as a cut write
            // does.
            match send_side.await {
                Ok(_) => closing,
                Err(_) => Closing::Abort,
            }
        }
    };

    // Detach the socket now, but keep the stable participant ID reserved for a
    // short grace period. A valid resume reconnect cancels departure simply by
    // reclaiming the ID before the delayed finalizer runs.
    schedule_connection_departure(&state, connection_id);
    close_connection(&mut sender, &mut receiver, closing).await;
}

/// Sends an error message and closes the connection with `code`.
async fn send_error(socket: WsSocket, error: &str, code: u16) {
    let (mut sender, mut receiver) = socket.split();
    let error_msg = Message::Error {
        message: error.to_string(),
    };
    // Best effort and bounded: a peer that does not read must not keep the
    // handler task alive.
    let sent = match serde_json::to_string(&error_msg) {
        Ok(json) => send_within_deadline(&mut sender, Outgoing::Text(&json)).await,
        Err(_) => true,
    };
    let closing = if sent {
        Closing::Initiate(code)
    } else {
        Closing::Abort
    };
    close_connection(&mut sender, &mut receiver, closing).await;
}

#[cfg(test)]
mod tests {
    //! Integration tests for the v1 WebSocket upgrade handshake.
    //!
    //! We cannot use `ServiceExt::oneshot` because axum's `WebSocketUpgrade`
    //! extractor requires a `hyper::upgrade::OnUpgrade` request extension
    //! that is only installed by a real server during an actual upgrade
    //! (absence -> axum returns 426 before our handler runs). Instead we
    //! spin up a bound listener and issue raw upgrade requests via reqwest.
    use super::*;
    use crate::config::Config;
    use crate::jwt::{WsTokenClaims, sign_token};
    use crate::models::{Room, RoomConfig, RoomType};
    use crate::state::app_state::{MLS_CONTROL_LAG_GRACE, MLS_CONTROL_LAG_HARD_LIMIT};
    use axum::{Router, routing::get};
    use futures_util::{SinkExt, StreamExt};
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use uuid::Uuid;

    // Reproduce the browser's nested image/ratchet JSON and two Base64
    // encodings. Ciphertext bytes are opaque to the relay; AES-GCM preserves
    // plaintext length and adds a 16-byte tag, with a 12-byte IV prepended.
    fn browser_image_envelope(raw_size: usize) -> serde_json::Value {
        let image = serde_json::json!({
            "type": "image", "mimeType": "image/jpeg",
            "data": base64::engine::general_purpose::STANDARD.encode(vec![0u8; raw_size]),
            "ts": 1788877773000u64,
        });
        let plaintext = serde_json::to_vec(&serde_json::json!({
            "ts": 1788877773000u64,
            "text": serde_json::to_string(&image).unwrap(),
        }))
        .unwrap();
        serde_json::json!({
            "type": "image",
            "payload": URL_SAFE_NO_PAD.encode(vec![0u8; plaintext.len() + 12 + 16]),
            "header": { "v": 1, "dh": "A".repeat(87), "pn": 0, "n": 0,
                "rc": 0, "sig": "A".repeat(86) },
        })
    }

    #[test]
    fn image_limits_cover_browser_encoding_at_configured_boundaries() {
        // Remainders modulo three exercise both Base64 padding boundaries.
        for raw_size in [1, 2, 3, 300 * 1024, 300 * 1024 + 1, 2 * 1024 * 1024] {
            let envelope = browser_image_envelope(raw_size);
            assert!(
                envelope["payload"].as_str().unwrap().len() <= max_image_payload_size(raw_size),
                "an image at the configured raw limit {raw_size} must fit its wire payload budget",
            );
            assert!(serde_json::to_vec(&envelope).unwrap().len() <= max_ws_size(raw_size));
        }
    }

    #[tokio::test]
    async fn image_relay_accepts_limit_sized_images_and_reports_oversized_payloads() {
        use tokio_tungstenite::tungstenite::{Message as ClientMessage, client::IntoClientRequest};

        async fn next_json(
            socket: &mut tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        ) -> serde_json::Value {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match socket
                        .next()
                        .await
                        .expect("socket closed")
                        .expect("valid frame")
                    {
                        ClientMessage::Text(text) => return serde_json::from_str(&text).unwrap(),
                        ClientMessage::Ping(_) | ClientMessage::Pong(_) => continue,
                        other => panic!("unexpected frame: {other:?}"),
                    }
                }
            })
            .await
            .expect("relay must answer, not silently drop the image")
        }

        for raw_size in [300 * 1024, 2 * 1024 * 1024] {
            let mut config = test_config();
            config.max_image_size = raw_size;
            let state = AppState::new(1, config);
            let room_id = state
                .try_create_room(Room::new(RoomConfig {
                    room_type: RoomType::OneToOne,
                    ttl_minutes: 5,
                    max_participants: 2,
                }))
                .unwrap();
            let token = sign_token(
                &WsTokenClaims::new(room_id, 30, &state.config.jwt_issuer),
                &state.jwt_secret,
            )
            .unwrap();
            let app = Router::new()
                .route("/ws/:room_id", get(ws_handler))
                .with_state(state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let mut request = format!("ws://{addr}/ws/{room_id}")
                .into_client_request()
                .unwrap();
            request
                .headers_mut()
                .insert("origin", "https://localhost:3000".parse().unwrap());
            request.headers_mut().insert(
                "sec-websocket-protocol",
                format!("pinchat.v1, pinchat.v1.jwt.{token}")
                    .parse()
                    .unwrap(),
            );
            let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
            assert_eq!(next_json(&mut socket).await["type"], "connected");

            let image = browser_image_envelope(raw_size);
            socket
                .send(ClientMessage::Text(image.to_string()))
                .await
                .unwrap();
            let echoed = next_json(&mut socket).await;
            assert_eq!(echoed["type"], "image");
            assert_eq!(echoed["payload"], image["payload"]);
            assert_eq!(echoed["header"], image["header"]);

            let mut oversized = image;
            oversized["payload"] =
                serde_json::Value::String("A".repeat(max_image_payload_size(raw_size) + 1));
            socket
                .send(ClientMessage::Text(oversized.to_string()))
                .await
                .unwrap();
            let rejected = next_json(&mut socket).await;
            assert_eq!(rejected["type"], "error");
            assert!(rejected["message"].as_str().unwrap().contains("not sent"));

            // A rejected image must not sever the connection or prevent a
            // subsequent valid message from reaching the relay stream.
            let mut text = browser_image_envelope(1);
            text["type"] = serde_json::json!("message");
            socket
                .send(ClientMessage::Text(text.to_string()))
                .await
                .unwrap();
            assert_eq!(next_json(&mut socket).await["type"], "message");
            socket.close(None).await.unwrap();
            server.abort();
        }
    }

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

    #[test]
    fn permanent_mls_append_errors_have_typed_zero_retry_rejections() {
        for (error, expected_reason) in [
            (
                MlsControlAppendError::UnknownKeyPackageRef,
                "unknown_key_package_ref",
            ),
            (
                MlsControlAppendError::UnauthorizedGroupCreatorControl,
                "not_group_creator",
            ),
            (
                MlsControlAppendError::CommitCorrelationConflict,
                "commit_correlation_conflict",
            ),
            (
                MlsControlAppendError::WelcomeNotCorrelated,
                "welcome_not_correlated",
            ),
        ] {
            let rejection = permanent_mls_append_rejection(error, Some("C".repeat(43)))
                .expect("permanent admission error must produce a typed rejection");
            let json = serde_json::to_value(rejection).unwrap();
            assert_eq!(json["type"], "mlsrejected");
            assert_eq!(json["reason"], expected_reason);
            assert_eq!(json["retry_after_secs"], 0);
            assert_eq!(json["commit_ref"], "C".repeat(43));
        }
        assert!(
            permanent_mls_append_rejection(MlsControlAppendError::CapacityExceeded, None,)
                .is_none(),
            "capacity pressure is not a permanent semantic rejection"
        );
    }

    fn synthetic_public_message(content_type: u8) -> Vec<u8> {
        let mut body = vec![1, 0xAA]; // group_id opaque<V>, one byte
        body.extend_from_slice(&0u64.to_be_bytes()); // epoch
        body.push(1); // SenderType::member
        body.extend_from_slice(&0u32.to_be_bytes()); // leaf_index
        body.push(0); // empty authenticated_data opaque<V>
        body.push(content_type);
        body.push(0); // enough trailing body for shallow classification
        body
    }

    #[test]
    fn mls_transport_validation_is_canonical_and_format_specific() {
        let commit_body = synthetic_public_message(CONTENT_TYPE_COMMIT);
        let commit_payload = URL_SAFE_NO_PAD.encode(&commit_body);
        let commit_ref = URL_SAFE_NO_PAD.encode(Sha256::digest(&commit_body));
        let commit = validate_mls_envelope(
            &commit_payload,
            WIRE_PUBLIC_MESSAGE,
            None,
            None,
            Some(&commit_ref),
            None,
            300 * 1024,
        )
        .expect("valid Commit transport");
        assert_eq!(commit.public_kind, Some(PublicMessageKind::Commit));

        let proposal_body = synthetic_public_message(CONTENT_TYPE_PROPOSAL);
        let proposal_payload = URL_SAFE_NO_PAD.encode(&proposal_body);
        let proposal = validate_mls_envelope(
            &proposal_payload,
            WIRE_PUBLIC_MESSAGE,
            None,
            None,
            None,
            None,
            300 * 1024,
        )
        .expect("valid Proposal transport");
        assert_eq!(proposal.public_kind, Some(PublicMessageKind::Proposal));

        assert!(
            validate_mls_envelope(
                &proposal_payload,
                WIRE_PUBLIC_MESSAGE,
                None,
                None,
                Some(&commit_ref),
                None,
                300 * 1024,
            )
            .is_err(),
            "Proposal must not consume or spoof the Commit correlation/rate bucket"
        );
        assert!(
            validate_mls_envelope(
                &commit_payload,
                WIRE_PUBLIC_MESSAGE,
                None,
                None,
                Some(&"A".repeat(43)),
                None,
                300 * 1024,
            )
            .is_err(),
            "CommitRef must equal SHA-256 of the exact decoded Commit body"
        );

        let small = URL_SAFE_NO_PAD.encode([0u8]);
        let reference = "A".repeat(43);
        let welcome = validate_mls_envelope(
            &small,
            WIRE_WELCOME,
            Some(&small),
            Some(&reference),
            Some(&reference),
            None,
            300 * 1024,
        )
        .expect("valid Welcome transport shape");
        assert_eq!(welcome.ratchet_tree_bytes.as_deref(), Some(&[0u8][..]));
        assert!(
            validate_mls_envelope(
                &small,
                WIRE_WELCOME,
                None,
                Some(&reference),
                Some(&reference),
                None,
                300 * 1024,
            )
            .is_err(),
            "Welcome must carry its bounded ratchet tree"
        );
        assert!(
            validate_mls_envelope(
                &small,
                WIRE_PRIVATE_MESSAGE,
                Some(&small),
                None,
                None,
                None,
                300 * 1024,
            )
            .is_err(),
            "ratchet_tree must be rejected outside Welcome"
        );
        assert!(
            validate_mls_envelope(
                &small,
                4, // standalone GroupInfo is unsupported by this transport
                None,
                None,
                None,
                None,
                300 * 1024,
            )
            .is_err(),
            "unsupported MLS wire formats must be rejected"
        );

        let oversized_key_package = URL_SAFE_NO_PAD.encode(vec![0u8; 16 * 1024 + 1]);
        assert!(
            validate_mls_envelope(
                &oversized_key_package,
                WIRE_KEY_PACKAGE,
                None,
                None,
                None,
                Some(&reference),
                300 * 1024,
            )
            .is_err(),
            "limits apply to decoded bytes for each wire format"
        );
        assert!(
            validate_mls_envelope(&small, WIRE_KEY_PACKAGE, None, None, None, None, 300 * 1024,)
                .is_err(),
            "KeyPackage transport requires an invite-secret possession proof"
        );
        assert!(
            validate_mls_envelope(
                &small,
                WIRE_KEY_PACKAGE,
                None,
                None,
                None,
                Some(&reference),
                300 * 1024,
            )
            .is_ok(),
            "canonical bootstrap proof is relayed only with KeyPackage"
        );
        assert!(decode_bounded_base64url("AA==", 16).is_err());
        assert!(decode_bounded_base64url("AB", 16).is_err());

        let mut non_minimal = vec![0x40, 0x01]; // length 1 encoded in two bytes
        non_minimal.extend_from_slice(&commit_body[1..]);
        assert!(
            classify_public_message(&non_minimal).is_err(),
            "shallow classifier rejects non-minimal MLS varints"
        );
    }

    #[test]
    fn mls_shallow_classifier_matches_ietf_public_messages() {
        let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../tests/vectors/mls/message-protection.json"
        ))
        .expect("parse vendored IETF message-protection vectors");
        let vector = vectors
            .iter()
            .find(|entry| entry["cipher_suite"].as_u64() == Some(2))
            .expect("ciphersuite 0x0002 vector");

        for (field, expected) in [
            ("proposal_pub", PublicMessageKind::Proposal),
            ("commit_pub", PublicMessageKind::Commit),
        ] {
            let framed = hex::decode(vector[field].as_str().expect("hex PublicMessage"))
                .expect("decode PublicMessage vector");
            assert_eq!(&framed[..4], &[0, 1, 0, 1]);
            assert_eq!(
                classify_public_message(&framed[4..]),
                Ok(expected),
                "relay classifier must match the RFC vector's signed content_type"
            );
        }
    }

    #[test]
    fn mls_replay_hash_binds_metadata_and_room_protocols_are_disjoint() {
        let payload = URL_SAFE_NO_PAD.encode([7u8]);
        let first_ref = "A".repeat(43);
        let second_ref = format!("{}E", "B".repeat(42));
        let first = validate_mls_envelope(
            &payload,
            WIRE_WELCOME,
            Some(&payload),
            Some(&first_ref),
            Some(&first_ref),
            None,
            300 * 1024,
        )
        .unwrap();
        let second = validate_mls_envelope(
            &payload,
            WIRE_WELCOME,
            Some(&payload),
            Some(&second_ref),
            Some(&first_ref),
            None,
            300 * 1024,
        )
        .unwrap();
        assert_ne!(
            mls_envelope_replay_hash(
                WIRE_WELCOME,
                &first,
                Some(&first_ref),
                Some(&first_ref),
                None,
            ),
            mls_envelope_replay_hash(
                WIRE_WELCOME,
                &second,
                Some(&second_ref),
                Some(&first_ref),
                None,
            ),
            "tree/correlation metadata participates in anti-replay identity"
        );
        let proof_a = URL_SAFE_NO_PAD.encode([3u8; 32]);
        let proof_b = URL_SAFE_NO_PAD.encode([4u8; 32]);
        let key_package = validate_mls_envelope(
            &payload,
            WIRE_KEY_PACKAGE,
            None,
            None,
            None,
            Some(&proof_a),
            300 * 1024,
        )
        .unwrap();
        assert_ne!(
            mls_envelope_replay_hash(WIRE_KEY_PACKAGE, &key_package, None, None, Some(&proof_a),),
            mls_envelope_replay_hash(WIRE_KEY_PACKAGE, &key_package, None, None, Some(&proof_b),),
            "KeyPackage possession proof participates in anti-replay identity"
        );

        let header = MessageHeader {
            v: crate::models::PINCHAT_PROTOCOL_VERSION,
            dh: "dh".into(),
            pn: 1,
            n: 2,
            rc: 3,
            sig: "sig".into(),
        };
        let mut altered_header = header.clone();
        altered_header.sig = "altered".into();
        assert_ne!(
            one_to_one_envelope_replay_hash("message", "ciphertext", &header),
            one_to_one_envelope_replay_hash("message", "ciphertext", &altered_header),
            "a corrupted header cannot poison the authentic ciphertext replay identity"
        );
        assert_ne!(
            one_to_one_envelope_replay_hash("message", "ciphertext", &header),
            one_to_one_envelope_replay_hash("image", "ciphertext", &header),
            "one-to-one message types are domain-separated in the replay cache"
        );

        assert!(room_accepts_client_message(RoomType::Group, "mls"));
        assert!(room_accepts_client_message(RoomType::Group, "mlsack"));
        assert!(!room_accepts_client_message(RoomType::Group, "message"));
        assert!(!room_accepts_client_message(RoomType::Group, "image"));
        assert!(!room_accepts_client_message(
            RoomType::Group,
            "ecdh_public_key"
        ));
        assert!(room_accepts_client_message(
            RoomType::OneToOne,
            "ecdh_public_key"
        ));
        assert!(room_accepts_client_message(RoomType::OneToOne, "message"));
        assert!(room_accepts_client_message(RoomType::OneToOne, "image"));
        assert!(!room_accepts_client_message(RoomType::OneToOne, "mls"));
        assert!(!room_accepts_client_message(RoomType::OneToOne, "mlsack"));
    }

    fn test_config() -> Config {
        Config {
            host: [127, 0, 0, 1],
            port: 0,
            ws_conn_burst_size: 100,
            ws_conn_period_secs: 60,
            max_ws_connections: crate::config::DEFAULT_MAX_WS_CONNECTIONS,
            max_ws_connections_per_address: crate::config::DEFAULT_MAX_WS_CONNECTIONS_PER_ADDRESS,
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
            max_ws_connection_age_secs: 30 * 60,
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
        // PRIVACY_MODE not set -> production policy applies: missing Origin -> 403.
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
    async fn full_room_preserves_jti() {
        // Audit M-2: the room-state gate now runs BEFORE consume_token, so a
        // client that arrives at a room whose second slot was already taken
        // keeps its token instead of having it burned by a rejection it did
        // not cause. Before the fix the capacity check lived in handle_socket,
        // i.e. after the jti had been recorded, and the loser of the race had
        // to re-run Proof-of-Work to try again.
        let (addr, state, room_id) = spawn_test_server().await;

        // Fill both slots; Room::new hard-codes max_participants to 2.
        assert!(
            state
                .add_connection(Uuid::new_v4(), room_id, false)
                .is_some()
        );
        assert!(
            state
                .add_connection(Uuid::new_v4(), room_id, false)
                .is_some()
        );

        let claims = WsTokenClaims::new(room_id, 30, &state.config.jwt_issuer);
        let jti = claims.jti;
        let token = sign_token(&claims, &state.jwt_secret).unwrap();
        let sp = format!("pinchat.v1, pinchat.v1.jwt.{}", token);
        let path = format!("/ws/{}", room_id);

        let status = raw_upgrade(addr, &path, Some(&sp)).await;
        assert_eq!(
            status, 404,
            "a full room must answer 404, indistinguishable from a missing room (audit L-4)"
        );
        assert!(
            !state.consumed_tokens.contains_key(&jti),
            "JTI must NOT be consumed when the room is full (audit M-2)"
        );
    }

    #[tokio::test]
    async fn missing_room_preserves_jti() {
        // Same conservation property for a room that never existed. The token
        // stays spendable and the response is the same 404 a full or expired
        // room produces, so the status code carries no existence signal.
        let (addr, state, _room_id) = spawn_test_server().await;
        let unknown_room = Uuid::new_v4();
        let claims = WsTokenClaims::new(unknown_room, 30, &state.config.jwt_issuer);
        let jti = claims.jti;
        let token = sign_token(&claims, &state.jwt_secret).unwrap();
        let sp = format!("pinchat.v1, pinchat.v1.jwt.{}", token);
        let path = format!("/ws/{}", unknown_room);

        let status = raw_upgrade(addr, &path, Some(&sp)).await;
        assert_eq!(status, 404);
        assert!(
            !state.consumed_tokens.contains_key(&jti),
            "JTI must NOT be consumed when the room does not exist (audit M-2)"
        );
    }

    #[tokio::test]
    async fn rejects_old_protocol_version() {
        let (addr, _state, room_id) = spawn_test_server().await;
        let path = format!("/ws/{}", room_id);
        // Only a non-v1 subprotocol offered -> 426.
        let status = raw_upgrade(addr, &path, Some("pinchat.v0")).await;
        assert_eq!(status, 426);
    }

    #[tokio::test]
    async fn rejects_missing_jwt_subprotocol() {
        let (addr, _state, room_id) = spawn_test_server().await;
        let path = format!("/ws/{}", room_id);
        // Base pinchat.v1 present, but no companion jwt token -> 401.
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
            resume: false,
            mls_control_cursor: None,
            creator_bootstrap_generation: None,
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
        // Full success path: bound listener + valid single-use JWT -> 101 + echoed subprotocol.
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

    #[test]
    fn reconnect_reservation_is_reclaimed_fail_closed() {
        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let room_id = room.id;
        let connection_id = room
            .creator_connection_id()
            .expect("group room has creator identity");
        state.try_create_room(room).unwrap();

        assert_eq!(
            state.add_connection(connection_id, room_id, false),
            Some(ConnectionAdmission::New)
        );
        assert_eq!(state.get_participant_count(&room_id), 1);
        state
            .connection_commit_timestamps
            .insert(connection_id, VecDeque::from([Utc::now()]));

        // Even a valid resume credential cannot open two simultaneously
        // active sockets for the same relay identity.
        assert_eq!(state.add_connection(connection_id, room_id, true), None);

        assert_eq!(state.detach_connection(&connection_id), Some(room_id));
        assert_eq!(state.get_participant_count(&room_id), 1);
        assert_eq!(
            state
                .connection_commit_timestamps
                .get(&connection_id)
                .map(|timestamps| timestamps.len()),
            Some(1),
            "transport cycling must not reset the stable identity's rate budget"
        );

        // The reserved ID cannot be reclaimed by a normal fresh-token path.
        assert_eq!(state.add_connection(connection_id, room_id, false), None);
        assert_eq!(
            state.add_connection(connection_id, room_id, true),
            Some(ConnectionAdmission::Resumed)
        );
        assert_eq!(state.get_participant_count(&room_id), 1);

        // An older grace finalizer observes the resumed active socket and
        // cannot remove its participant reservation.
        assert_eq!(state.finalize_disconnection(&connection_id, room_id), None);
        assert_eq!(state.get_participant_count(&room_id), 1);

        assert_eq!(state.detach_connection(&connection_id), Some(room_id));
        assert_eq!(
            state.finalize_disconnection(&connection_id, room_id),
            Some(0)
        );
        assert!(
            !state
                .connection_commit_timestamps
                .contains_key(&connection_id),
            "final departure must erase retained limiter state"
        );

        // Critical race regression: if grace expires after token issuance but
        // before upgrade, a resume token must fail rather than be admitted as
        // a brand-new participant under the old ID.
        assert_eq!(state.add_connection(connection_id, room_id, true), None);
        assert_eq!(state.get_participant_count(&room_id), 0);
        assert_eq!(
            state.add_connection(connection_id, room_id, false),
            Some(ConnectionAdmission::New)
        );
    }

    #[tokio::test]
    async fn mls_group_control_log_replays_lifecycle_until_every_participant_acknowledges() {
        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let room_id = room.id;
        let alice = room
            .creator_connection_id()
            .expect("group room has creator identity");
        state.try_create_room(room).unwrap();
        let bob = Uuid::new_v4();

        assert_eq!(
            state.add_connection(alice, room_id, false),
            Some(ConnectionAdmission::New)
        );
        let (_alice_rx, alice_stream) = state
            .open_mls_control_stream(&room_id, alice, None)
            .expect("open Alice control stream");
        assert_eq!(alice_stream.cursor, 0);
        assert_eq!(alice_stream.through_seq, 0);
        assert!(state.mark_creator_control_ready(&room_id, alice));

        assert_eq!(
            state.add_connection(bob, room_id, false),
            Some(ConnectionAdmission::New)
        );
        let (mut bob_rx, bob_stream) = state
            .open_mls_control_stream(&room_id, bob, None)
            .expect("open Bob control stream");
        assert_eq!(bob_stream.cursor, 0);

        // Group admission captures the replay boundary first, then appends
        // UserJoined. The fresh socket therefore receives its own lifecycle
        // event live instead of skipping controls accepted after admission.
        let join_seq = state
            .append_and_broadcast_mls_control(&room_id, |seq| {
                serde_json::to_string(&Message::UserJoined {
                    user_id: bob,
                    participant_count: 2,
                    control_seq: Some(seq),
                })
                .ok()
            })
            .expect("append ordered join");
        assert_eq!(join_seq, 1);
        let live_join_payload = bob_rx
            .try_recv()
            .expect("fresh participant receives live join");
        let live_join: serde_json::Value =
            serde_json::from_str(live_join_payload.as_str()).expect("live join JSON");
        assert_eq!(live_join["type"], "userjoined");
        assert_eq!(live_join["control_seq"], 1);
        assert!(state.acknowledge_mls_control(&room_id, alice, 1));

        let seq = state
            .append_and_broadcast_mls_control(&room_id, |seq| {
                Some(
                    serde_json::json!({
                        "type": "mls",
                        "wire_format": WIRE_KEY_PACKAGE,
                        "payload": "AA",
                        "sender_id": alice,
                        "control_seq": seq,
                    })
                    .to_string(),
                )
            })
            .expect("append ordered control");
        assert_eq!(seq, 2);
        assert!(state.acknowledge_mls_control(&room_id, alice, 2));

        let departed = Uuid::new_v4();
        let leave_seq = state
            .append_and_broadcast_mls_control(&room_id, |seq| {
                serde_json::to_string(&Message::UserLeft {
                    user_id: departed,
                    participant_count: 2,
                    control_seq: Some(seq),
                })
                .ok()
            })
            .expect("append ordered lifecycle event");
        assert_eq!(leave_seq, 3);
        assert!(state.acknowledge_mls_control(&room_id, alice, 3));

        // Bob's lower cursor keeps both MLS and lifecycle controls retained
        // throughout a transport drop and grace-reserved resume.
        assert_eq!(state.detach_connection(&bob), Some(room_id));
        assert_eq!(
            state.add_connection(bob, room_id, true),
            Some(ConnectionAdmission::Resumed)
        );
        let (_resumed_rx, replay) = state
            .open_mls_control_stream(&room_id, bob, Some(0))
            .expect("replay from Bob's signed cursor");
        assert_eq!(replay.cursor, 0);
        assert_eq!(replay.through_seq, 3);
        assert_eq!(replay.replay.len(), 3);
        let replayed_join: serde_json::Value =
            serde_json::from_str(replay.replay[0].json.as_ref()).expect("replayed join JSON");
        assert_eq!(replayed_join["type"], "userjoined");
        assert_eq!(replayed_join["control_seq"], 1);
        let replayed_mls: serde_json::Value =
            serde_json::from_str(replay.replay[1].json.as_ref()).expect("replayed MLS JSON");
        assert_eq!(replayed_mls["control_seq"], 2);
        let replayed_leave: serde_json::Value =
            serde_json::from_str(replay.replay[2].json.as_ref()).expect("replayed lifecycle JSON");
        assert_eq!(replayed_leave["type"], "userleft");
        assert_eq!(replayed_leave["user_id"], departed.to_string());
        assert_eq!(replayed_leave["control_seq"], 3);

        assert!(state.acknowledge_mls_control(&room_id, bob, 3));
        assert!(
            state.validate_mls_control_cursor(&room_id, 3).is_ok(),
            "current head remains a valid resume cursor after pruning"
        );
        assert!(
            state.validate_mls_control_cursor(&room_id, 0).is_err(),
            "a cursor older than the fully-acknowledged retained window fails closed"
        );

        assert_eq!(state.detach_connection(&bob), Some(room_id));
        assert_eq!(
            state.add_connection(bob, room_id, true),
            Some(ConnectionAdmission::Resumed)
        );
        assert!(matches!(
            state.open_mls_control_stream(&room_id, bob, Some(2)),
            Err(crate::state::app_state::MlsControlCursorError::CursorRegressed)
        ));
        assert!(
            state.acknowledge_mls_control(&room_id, bob, 3),
            "a regressed resume attempt must not lower the server ACK"
        );
    }

    #[test]
    fn non_acknowledging_mls_participant_is_evicted_before_log_capacity() {
        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let room_id = room.id;
        let alice = room
            .creator_connection_id()
            .expect("group room has creator identity");
        state.try_create_room(room).unwrap();
        let stalled = Uuid::new_v4();

        assert_eq!(
            state.add_connection(alice, room_id, false),
            Some(ConnectionAdmission::New)
        );
        state
            .open_mls_control_stream(&room_id, alice, None)
            .expect("open Alice stream");
        assert!(state.mark_creator_control_ready(&room_id, alice));
        assert_eq!(
            state.add_connection(stalled, room_id, false),
            Some(ConnectionAdmission::New)
        );
        state
            .open_mls_control_stream(&room_id, stalled, None)
            .expect("open stalled stream");

        // A participant that never acknowledges is evicted on count alone,
        // without waiting for the grace period, once its backlog reaches the
        // hard limit. That limit lies below the log capacity.
        for expected in 1..=MLS_CONTROL_LAG_HARD_LIMIT {
            let seq = state
                .append_and_broadcast_mls_control(&room_id, |seq| {
                    Some(format!(r#"{{"type":"test","control_seq":{seq}}}"#))
                })
                .expect("append before lag eviction");
            assert_eq!(seq, expected);
            assert!(state.acknowledge_mls_control(&room_id, alice, seq));
            if expected == 1 {
                assert_eq!(
                    state.lagging_mls_control_participants(&room_id, u64::MAX, Duration::ZERO,),
                    vec![stalled],
                    "an outstanding cursor with an expired progress deadline is evictable",
                );
            }
            evict_lagging_group_participants(&state, room_id);
        }

        assert!(
            !state.connection_is_active(&room_id, &stalled)
                && !state
                    .rooms
                    .get(&room_id)
                    .expect("room survives lag eviction")
                    .participant_ids
                    .contains(&stalled),
            "a participant that withholds every ACK is removed from the room and pruning quorum"
        );

        // Eviction appends one ordered UserLeft after the last test control.
        let departure_seq = MLS_CONTROL_LAG_HARD_LIMIT + 1;
        assert!(state.acknowledge_mls_control(&room_id, alice, departure_seq));

        // Continue well beyond the retained-log count cap. Alice's advancing
        // ACK must keep pruning history instead of letting the removed peer
        // freeze all future group control.
        for expected in (departure_seq + 1)..=(departure_seq + 300) {
            let seq = state
                .append_and_broadcast_mls_control(&room_id, |seq| {
                    Some(format!(r#"{{"type":"test","control_seq":{seq}}}"#))
                })
                .expect("ordered control continues after lagger eviction");
            assert_eq!(seq, expected);
            assert!(state.acknowledge_mls_control(&room_id, alice, seq));
        }
    }

    #[test]
    fn burst_of_controls_does_not_evict_members_that_acknowledge_within_the_grace_period() {
        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let room_id = room.id;
        let creator = room
            .creator_connection_id()
            .expect("group room has creator identity");
        state.try_create_room(room).unwrap();
        let member = Uuid::new_v4();
        for participant in [creator, member] {
            assert_eq!(
                state.add_connection(participant, room_id, false),
                Some(ConnectionAdmission::New)
            );
            state
                .open_mls_control_stream(&room_id, participant, None)
                .expect("open control stream");
            if participant == creator {
                assert!(state.mark_creator_control_ready(&room_id, creator));
            }
        }

        // A burst well past the count threshold lands before anybody could
        // have acknowledged anything: one link holder with a handful of
        // sockets can produce it.
        let burst_at = std::time::Instant::now();
        let burst = MAX_MLS_UNACKNOWLEDGED_CONTROLS + 40;
        for _ in 0..burst {
            state
                .append_and_broadcast_mls_control_at_for_test(&room_id, burst_at, |seq| {
                    Some(format!(r#"{{"type":"test","control_seq":{seq}}}"#))
                })
                .expect("append burst");
        }
        let lagging_at = |at| {
            let mut lagging = state.lagging_mls_control_participants_at_for_test(
                &room_id,
                MAX_MLS_UNACKNOWLEDGED_CONTROLS,
                MLS_CONTROL_ACK_TIMEOUT,
                at,
            );
            lagging.sort_unstable();
            lagging
        };
        assert!(
            lagging_at(burst_at).is_empty(),
            "nobody is stalled the instant a burst lands"
        );
        assert!(lagging_at(burst_at + MLS_CONTROL_LAG_GRACE - Duration::from_millis(1)).is_empty());

        // The real eviction path agrees: the room and both members survive.
        evict_lagging_group_participants(&state, room_id);
        assert!(state.rooms.contains_key(&room_id));
        assert_eq!(state.get_participant_count(&room_id), 2);

        // The creator catches up inside the grace period; the member does not.
        assert!(state.acknowledge_mls_control(&room_id, creator, burst));
        assert_eq!(
            lagging_at(burst_at + MLS_CONTROL_LAG_GRACE),
            vec![member],
            "a backlog that outlives the grace period is still evicted on count"
        );

        // A partial acknowledgement that leaves less than the threshold
        // outstanding is governed by the stall deadline alone.
        assert!(state.acknowledge_mls_control(&room_id, member, 50));
        assert!(lagging_at(burst_at + MLS_CONTROL_LAG_GRACE).is_empty());
        assert_eq!(lagging_at(burst_at + MLS_CONTROL_ACK_TIMEOUT), vec![member]);
    }

    #[test]
    fn backlog_at_the_hard_limit_is_evicted_without_a_grace_period() {
        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let room_id = room.id;
        let creator = room.creator_connection_id().unwrap();
        state.try_create_room(room).unwrap();
        assert_eq!(
            state.add_connection(creator, room_id, false),
            Some(ConnectionAdmission::New)
        );
        state
            .open_mls_control_stream(&room_id, creator, None)
            .expect("open control stream");

        let now = std::time::Instant::now();
        for _ in 1..MLS_CONTROL_LAG_HARD_LIMIT {
            state
                .append_and_broadcast_mls_control_at_for_test(&room_id, now, |seq| {
                    Some(format!(r#"{{"type":"test","control_seq":{seq}}}"#))
                })
                .expect("append below the hard limit");
        }
        let lagging = |state: &AppState| {
            state.lagging_mls_control_participants_at_for_test(
                &room_id,
                MAX_MLS_UNACKNOWLEDGED_CONTROLS,
                MLS_CONTROL_ACK_TIMEOUT,
                now,
            )
        };
        assert!(lagging(&state).is_empty());
        state
            .append_and_broadcast_mls_control_at_for_test(&room_id, now, |seq| {
                Some(format!(r#"{{"type":"test","control_seq":{seq}}}"#))
            })
            .expect("append reaching the hard limit");
        assert_eq!(lagging(&state), vec![creator]);

        // The limit leaves the lifecycle reserve and more untouched, so the
        // departure of an evicted member can always be recorded.
        assert!(
            (MLS_CONTROL_LAG_HARD_LIMIT as usize)
                < crate::state::app_state::MAX_MLS_CONTROL_LOG_ENTRIES
                    - crate::state::app_state::MLS_LIFECYCLE_RESERVED_ENTRIES
        );
    }

    #[test]
    fn idle_room_does_not_age_a_future_mls_control_backlog() {
        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let room_id = room.id;
        let alice = room
            .creator_connection_id()
            .expect("group room has creator identity");
        state.try_create_room(room).unwrap();
        let bob = Uuid::new_v4();

        assert_eq!(
            state.add_connection(alice, room_id, false),
            Some(ConnectionAdmission::New)
        );
        state
            .open_mls_control_stream(&room_id, alice, None)
            .expect("open synchronized creator MLS stream");
        assert!(state.mark_creator_control_ready(&room_id, alice));
        assert_eq!(
            state.add_connection(bob, room_id, false),
            Some(ConnectionAdmission::New)
        );
        state
            .open_mls_control_stream(&room_id, bob, None)
            .expect("open synchronized member MLS stream");

        let opened_at = std::time::Instant::now();
        let appended_at = opened_at + MLS_CONTROL_ACK_TIMEOUT + Duration::from_secs(1);
        state
            .append_and_broadcast_mls_control_at_for_test(&room_id, appended_at, |seq| {
                Some(format!(r#"{{"type":"test","control_seq":{seq}}}"#))
            })
            .expect("append control after an idle interval");

        assert!(
            state
                .lagging_mls_control_participants_at_for_test(
                    &room_id,
                    u64::MAX,
                    MLS_CONTROL_ACK_TIMEOUT,
                    appended_at,
                )
                .is_empty(),
            "time spent fully caught up must not consume a new backlog's ACK deadline"
        );

        let expired_at = appended_at + MLS_CONTROL_ACK_TIMEOUT;
        let mut lagging = state.lagging_mls_control_participants_at_for_test(
            &room_id,
            u64::MAX,
            MLS_CONTROL_ACK_TIMEOUT,
            expired_at,
        );
        lagging.sort_unstable();
        let mut expected = vec![alice, bob];
        expected.sort_unstable();
        assert_eq!(
            lagging, expected,
            "the same unacknowledged control becomes evictable only after its own deadline"
        );
    }

    #[test]
    fn room_traffic_and_broadcast_memory_are_byte_bounded() {
        let mut config = test_config();
        config.msg_rate_window_secs = 1;
        config.room_msg_rate_limit = 4;
        config.room_byte_rate_limit = 1024;
        let state = AppState::new(1000, config);
        let room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let room_id = room.id;
        let alice = room
            .creator_connection_id()
            .expect("group room has creator identity");
        state.try_create_room(room).unwrap();
        let bob = Uuid::new_v4();
        assert_eq!(
            state.add_connection(alice, room_id, false),
            Some(ConnectionAdmission::New)
        );
        assert!(state.mark_creator_control_ready(&room_id, alice));
        assert_eq!(
            state.add_connection(bob, room_id, false),
            Some(ConnectionAdmission::New)
        );

        let now = Utc::now();
        assert!(state.admit_room_traffic(room_id, alice, now, 512));
        assert!(
            !state.admit_room_traffic(room_id, alice, now, 1),
            "one sender cannot consume bytes reserved for its peers"
        );
        assert!(
            state.admit_room_traffic(room_id, bob, now, 512),
            "another sender retains its share after a peer reaches its cap"
        );
        assert!(
            !state.admit_room_traffic(room_id, bob, now, 1),
            "aggregate and per-sender byte ceilings remain bounded"
        );

        let _receiver = state
            .broadcast_channels
            .get(&room_id)
            .expect("room broadcast sender")
            .subscribe();
        for _ in 0..4 {
            assert!(
                state
                    .broadcast_room_message(&room_id, "x".repeat(1024 * 1024))
                    .is_ok()
            );
        }
        assert!(
            state
                .broadcast_room_message(&room_id, "y".repeat(1024 * 1024))
                .is_err(),
            "per-room retained broadcast bytes are capped independently of count"
        );
        state.remove_room(&room_id);
    }

    #[test]
    fn one_address_cannot_fill_the_global_broadcast_budget() {
        use crate::state::app_state::{BroadcastError, MAX_BROADCAST_CLIENT_BYTES};

        const MIB: usize = 1024 * 1024;
        let state = AppState::new(1000, test_config());
        // Rooms with a receiver that never reads, so every frame sent into
        // them stays counted.
        let mut rooms = Vec::new();
        let mut receivers = Vec::new();
        for _ in 0..7 {
            let room_id = state
                .try_create_room(Room::new(RoomConfig {
                    room_type: RoomType::OneToOne,
                    ttl_minutes: 5,
                    max_participants: 2,
                }))
                .unwrap();
            receivers.push(
                state
                    .broadcast_channels
                    .get(&room_id)
                    .expect("room broadcast sender")
                    .subscribe(),
            );
            rooms.push(room_id);
        }
        let megabyte = || "x".repeat(MIB);

        // Two full rooms are the whole share of one address.
        assert_eq!(MAX_BROADCAST_CLIENT_BYTES, 8 * MIB);
        let first = state.lease_client_broadcast_share("address-a");
        for room_id in &rooms[..2] {
            for _ in 0..4 {
                assert!(
                    state
                        .broadcast_room_message_from(room_id, megabyte(), Some(&first))
                        .is_ok()
                );
            }
        }
        assert_eq!(
            state.broadcast_room_message_from(&rooms[2], megabyte(), Some(&first)),
            Err(BroadcastError::ClientByteCapacity),
            "an empty room does not help an address that is at its share"
        );

        // A second connection from the same address draws on the same share.
        let second = state.lease_client_broadcast_share("address-a");
        assert_eq!(
            state.broadcast_room_message_from(&rooms[2], megabyte(), Some(&second)),
            Err(BroadcastError::ClientByteCapacity)
        );

        // Another address is not affected, and the refused frames left
        // nothing counted against the room they were meant for.
        let other = state.lease_client_broadcast_share("address-b");
        for _ in 0..4 {
            assert!(
                state
                    .broadcast_room_message_from(&rooms[2], megabyte(), Some(&other))
                    .is_ok()
            );
        }
        // Frames the relay produces itself are charged to no address.
        assert!(state.broadcast_room_message(&rooms[3], megabyte()).is_ok());

        // Closing every connection does not hand the address a fresh share
        // while its frames are still held by receivers that do not read.
        drop(first);
        drop(second);
        assert_eq!(state.sweep_client_broadcast_shares(), 2);
        let reconnected = state.lease_client_broadcast_share("address-a");
        assert_eq!(
            state.broadcast_room_message_from(&rooms[4], megabyte(), Some(&reconnected)),
            Err(BroadcastError::ClientByteCapacity)
        );

        // Once the frames are gone the share is available again. A frame is
        // gone when the room is and no receiver holds it any more.
        for room_id in &rooms[..2] {
            state.remove_room(room_id);
        }
        receivers.drain(..2);
        assert!(
            state
                .broadcast_room_message_from(&rooms[4], megabyte(), Some(&reconnected))
                .is_ok()
        );

        // The address is kept only while a connection or a frame needs it.
        drop(reconnected);
        drop(other);
        assert_eq!(
            state.client_broadcast_share_count(),
            2,
            "both addresses still have frames in flight"
        );
        for room_id in &rooms[4..] {
            state.remove_room(room_id);
        }
        drop(receivers);
        assert_eq!(state.sweep_client_broadcast_shares(), 0);

        // With nothing in flight the entry goes with the last connection.
        let idle = state.lease_client_broadcast_share("address-c");
        let idle_too = state.lease_client_broadcast_share("address-c");
        assert_eq!(state.client_broadcast_share_count(), 1);
        drop(idle);
        assert_eq!(state.client_broadcast_share_count(), 1);
        drop(idle_too);
        assert_eq!(state.client_broadcast_share_count(), 0);
    }

    #[tokio::test]
    async fn a_connection_holds_the_share_of_its_address_until_it_closes() {
        use std::net::SocketAddr;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let state = AppState::new(1, test_config());
        let room_id = state
            .try_create_room(Room::new(RoomConfig {
                room_type: RoomType::OneToOne,
                ttl_minutes: 5,
                max_participants: 2,
            }))
            .unwrap();
        let token = sign_token(
            &WsTokenClaims::new(room_id, 30, &state.config.jwt_issuer),
            &state.jwt_secret,
        )
        .unwrap();
        let app = Router::new()
            .route("/ws/:room_id", get(ws_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let mut request = format!("ws://{addr}/ws/{room_id}")
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("origin", "https://localhost:3000".parse().unwrap());
        request.headers_mut().insert(
            "sec-websocket-protocol",
            format!("pinchat.v1, pinchat.v1.jwt.{token}")
                .parse()
                .unwrap(),
        );

        assert_eq!(state.client_broadcast_share_count(), 0);
        let (socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        assert_eq!(
            state.client_broadcast_share_count(),
            1,
            "the upgrade registers the address of the connection"
        );

        drop(socket);
        let gone = tokio::time::timeout(Duration::from_secs(5), async {
            while state.client_broadcast_share_count() != 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            gone.is_ok(),
            "the address must not be kept once the connection is closed"
        );
        server.abort();
    }

    #[test]
    fn mls_control_log_reserves_unacknowledged_capacity_for_lifecycle() {
        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let room_id = room.id;
        state.try_create_room(room).unwrap();

        let ordinary_limit = (crate::state::app_state::MAX_MLS_CONTROL_LOG_ENTRIES
            - crate::state::app_state::MLS_LIFECYCLE_RESERVED_ENTRIES)
            as u64;
        for expected in 1..=ordinary_limit {
            let seq = state
                .append_and_broadcast_mls_control(&room_id, |seq| {
                    Some(format!(r#"{{"type":"test","control_seq":{seq}}}"#))
                })
                .expect("entry within hard control-log count");
            assert_eq!(seq, expected);
        }
        assert!(
            state
                .append_and_broadcast_mls_control(&room_id, |seq| {
                    Some(format!(r#"{{"type":"test","control_seq":{seq}}}"#))
                })
                .is_err(),
            "ordinary controls cannot consume lifecycle-reserved entries"
        );
        for offset in 1..=crate::state::app_state::MLS_LIFECYCLE_RESERVED_ENTRIES as u64 {
            let expected = ordinary_limit + offset;
            let seq = state
                .append_and_broadcast_mls_lifecycle(&room_id, |seq| {
                    Some(format!(r#"{{"type":"userleft","control_seq":{seq}}}"#))
                })
                .expect("reserved lifecycle entry remains appendable");
            assert_eq!(seq, expected);
        }
        assert!(
            state
                .append_and_broadcast_mls_lifecycle(&room_id, |seq| {
                    Some(format!(r#"{{"type":"userleft","control_seq":{seq}}}"#))
                })
                .is_err(),
            "the hard log cap still rejects rather than evicting history"
        );
        assert!(
            state.validate_mls_control_cursor(&room_id, 0).is_ok(),
            "the oldest unacknowledged cursor remains replayable"
        );
        assert!(
            !append_ordered_group_departure(&state, room_id, Uuid::new_v4(), 1,),
            "an unsequencable departure reports fail-closed",
        );
        assert!(
            !state.rooms.contains_key(&room_id),
            "failure to durably sequence UserLeft closes the entire MLS room",
        );
    }

    #[test]
    fn creator_slot_and_bootstrap_resume_cursor_preserve_stable_identity() {
        let state = AppState::new(1000, test_config());
        let (room, creator_bootstrap) = Room::new_with_creator_bootstrap(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 2,
        });
        let room_id = room.id;
        let creator = room
            .creator_connection_id()
            .expect("group room has stable creator identity");
        let creator_bootstrap =
            creator_bootstrap.expect("group room exposes creator bootstrap capability");
        let bootstrap_generation = room.creator_bootstrap_generation();
        assert!(room.verify_creator_bootstrap(&creator_bootstrap));
        state.try_create_room(room).unwrap();

        let first_noncreator = Uuid::new_v4();
        let second_noncreator = Uuid::new_v4();
        assert_eq!(
            state.add_connection(first_noncreator, room_id, false),
            None,
            "ordinary admission waits until the creator opens the room"
        );
        assert_eq!(
            state.add_connection(creator, room_id, false),
            Some(ConnectionAdmission::New),
            "creator consumes its own reserved slot atomically"
        );
        assert_eq!(
            state.add_connection(first_noncreator, room_id, false),
            None,
            "ordinary admission stays closed until durable creator control setup"
        );

        let (_creator_rx, creator_stream) = state
            .open_mls_control_stream(&room_id, creator, None)
            .expect("creator opens initial MLS stream");
        assert_eq!(creator_stream.cursor, 0);
        assert_eq!(
            state
                .append_and_broadcast_mls_lifecycle(&room_id, |seq| {
                    Some(format!(r#"{{"type":"userjoined","control_seq":{seq}}}"#))
                })
                .expect("append creator lifecycle"),
            1
        );
        assert!(state.mark_creator_control_ready(&room_id, creator));
        assert_eq!(
            state.add_connection(first_noncreator, room_id, false),
            Some(ConnectionAdmission::New),
            "ordinary admission opens after creator control readiness"
        );
        assert_eq!(
            state.add_connection(second_noncreator, room_id, false),
            None,
            "ordinary admission cannot exceed the physical room cap"
        );
        assert!(state.acknowledge_mls_control(&room_id, creator, 1));
        assert!(
            !state
                .rooms
                .get(&room_id)
                .expect("room remains live")
                .verify_creator_bootstrap(&creator_bootstrap),
            "the creator's first authenticated MLS ACK revokes bootstrap recovery"
        );
        assert_eq!(state.detach_connection(&creator), Some(room_id));
        let cursor = state
            .acknowledged_mls_control_cursor(&room_id, creator)
            .expect("grace-reserved creator has server-authoritative cursor");
        assert_eq!(cursor, 1);
        assert_eq!(
            state.add_connection_with_bootstrap_generation(
                creator,
                room_id,
                true,
                Some(bootstrap_generation),
            ),
            None,
            "a JWT minted before bootstrap revocation cannot reclaim the creator"
        );
        assert_eq!(
            state.add_connection_with_bootstrap_generation(creator, room_id, true, None,),
            Some(ConnectionAdmission::Resumed),
            "the normal post-ACK resume credential remains valid"
        );

        let claims =
            WsTokenClaims::for_resume(room_id, creator, 30, &state.config.jwt_issuer, Some(cursor));
        assert_eq!(claims.connection_id, creator);
        assert!(claims.resume);
        assert_eq!(claims.mls_control_cursor, Some(1));
    }

    #[test]
    fn definitive_creator_eviction_closes_established_group_room() {
        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let room_id = room.id;
        let creator = room.creator_connection_id().unwrap();
        state.try_create_room(room).unwrap();
        assert_eq!(
            state.add_connection(creator, room_id, false),
            Some(ConnectionAdmission::New),
        );
        state
            .open_mls_control_stream(&room_id, creator, None)
            .expect("creator stream");
        state
            .append_and_broadcast_mls_lifecycle(&room_id, |seq| {
                Some(format!(r#"{{"type":"userjoined","control_seq":{seq}}}"#))
            })
            .expect("creator lifecycle");
        assert!(state.mark_creator_control_ready(&room_id, creator));

        assert!(evict_group_participant(
            &state,
            room_id,
            creator,
            "test definitive creator departure",
        ));
        assert!(
            !state.rooms.contains_key(&room_id),
            "an established creator-centric group cannot survive creator eviction",
        );
    }

    #[test]
    fn relay_correlates_welcome_and_limits_keypackage_per_admission() {
        use crate::state::app_state::MlsControlAppendError;

        let state = AppState::new(1000, test_config());
        let room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let room_id = room.id;
        let creator = room
            .creator_connection_id()
            .expect("group room has creator binding");
        state.try_create_room(room).unwrap();
        let joiner = Uuid::new_v4();
        let noncreator = Uuid::new_v4();
        let key_package_ref = mls_key_package_ref(b"accepted-key-package").unwrap();
        assert_eq!(
            key_package_ref, "RS0flmwTqm9bsvjt1GZttoE7EkV1iO5FP3xaZxOqNGE",
            "relay RefHash matches the MLS client implementation",
        );

        assert_eq!(
            state
                .append_and_broadcast_mls_envelope(
                    &room_id,
                    MlsControlAdmission::KeyPackage {
                        sender_id: joiner,
                        key_package_ref: key_package_ref.clone(),
                    },
                    |seq| Some(format!(r#"{{"type":"kp","control_seq":{seq}}}"#)),
                )
                .expect("first KeyPackage for stable admission"),
            1
        );
        assert!(matches!(
            state.append_and_broadcast_mls_envelope(
                &room_id,
                MlsControlAdmission::KeyPackage {
                    sender_id: joiner,
                    key_package_ref: key_package_ref.clone(),
                },
                |seq| Some(format!(r#"{{"type":"kp2","control_seq":{seq}}}"#)),
            ),
            Err(MlsControlAppendError::DuplicateKeyPackage),
        ));

        let serialized = std::cell::Cell::new(false);
        assert_eq!(
            state.append_and_broadcast_mls_envelope(
                &room_id,
                MlsControlAdmission::Commit {
                    sender_id: noncreator,
                },
                |seq| {
                    serialized.set(true);
                    Some(format!(r#"{{"type":"commit-bad","control_seq":{seq}}}"#))
                },
            ),
            Err(MlsControlAppendError::UnauthorizedGroupCreatorControl),
        );
        assert!(
            !serialized.get(),
            "unauthorized Commit is rejected before sequence allocation/serialization"
        );
        assert_eq!(
            state
                .append_and_broadcast_mls_envelope(
                    &room_id,
                    MlsControlAdmission::Commit { sender_id: creator },
                    |seq| Some(format!(r#"{{"type":"commit-ok","control_seq":{seq}}}"#)),
                )
                .expect("creator ordinary Commit is accepted"),
            2,
            "rejected non-creator Commit did not consume a sequence"
        );

        let commit_ref = "C".repeat(43);
        assert!(matches!(
            state.append_and_broadcast_mls_envelope(
                &room_id,
                MlsControlAdmission::AddCommit {
                    sender_id: creator,
                    commit_ref: "U".repeat(43),
                    key_package_ref: "X".repeat(43),
                },
                |seq| Some(format!(r#"{{"type":"commit0","control_seq":{seq}}}"#)),
            ),
            Err(MlsControlAppendError::UnknownKeyPackageRef),
        ));
        assert_eq!(
            state.append_and_broadcast_mls_envelope(
                &room_id,
                MlsControlAdmission::AddCommit {
                    sender_id: noncreator,
                    commit_ref: commit_ref.clone(),
                    key_package_ref: key_package_ref.clone(),
                },
                |seq| Some(format!(r#"{{"type":"commit-bad","control_seq":{seq}}}"#)),
            ),
            Err(MlsControlAppendError::UnauthorizedGroupCreatorControl),
            "a non-creator cannot consume a valid KeyPackageRef"
        );
        assert_eq!(
            state
                .append_and_broadcast_mls_envelope(
                    &room_id,
                    MlsControlAdmission::AddCommit {
                        sender_id: creator,
                        commit_ref: commit_ref.clone(),
                        key_package_ref: key_package_ref.clone(),
                    },
                    |seq| Some(format!(r#"{{"type":"commit","control_seq":{seq}}}"#)),
                )
                .expect("creator Add Commit registers one pending Welcome"),
            3,
            "rejected Add Commits consumed neither sequence nor KeyPackageRef"
        );
        assert!(matches!(
            state.append_and_broadcast_mls_envelope(
                &room_id,
                MlsControlAdmission::KeyPackage {
                    sender_id: Uuid::new_v4(),
                    key_package_ref: key_package_ref.clone(),
                },
                |seq| Some(format!(r#"{{"type":"kp-replay","control_seq":{seq}}}"#)),
            ),
            Err(MlsControlAppendError::DuplicateKeyPackageRef),
        ));

        assert_eq!(
            state.append_and_broadcast_mls_envelope(
                &room_id,
                MlsControlAdmission::Welcome {
                    sender_id: noncreator,
                    commit_ref: commit_ref.clone(),
                    key_package_ref: key_package_ref.clone(),
                },
                |seq| Some(format!(r#"{{"type":"welcome","control_seq":{seq}}}"#)),
            ),
            Err(MlsControlAppendError::UnauthorizedGroupCreatorControl),
            "a non-creator cannot consume the creator's pending Welcome correlation"
        );
        assert!(matches!(
            state.append_and_broadcast_mls_envelope(
                &room_id,
                MlsControlAdmission::Welcome {
                    sender_id: creator,
                    commit_ref: "M".repeat(43),
                    key_package_ref: key_package_ref.clone(),
                },
                |seq| Some(format!(r#"{{"type":"welcome-bad","control_seq":{seq}}}"#)),
            ),
            Err(MlsControlAppendError::WelcomeNotCorrelated),
        ));
        assert_eq!(
            state
                .append_and_broadcast_mls_envelope(
                    &room_id,
                    MlsControlAdmission::Welcome {
                        sender_id: creator,
                        commit_ref: commit_ref.clone(),
                        key_package_ref: key_package_ref.clone(),
                    },
                    |seq| Some(format!(r#"{{"type":"welcome","control_seq":{seq}}}"#)),
                )
                .expect("matching creator Welcome consumes the correlation"),
            4,
            "rejected Welcome controls consumed neither sequence nor correlation"
        );
        assert!(matches!(
            state.append_and_broadcast_mls_envelope(
                &room_id,
                MlsControlAdmission::Welcome {
                    sender_id: creator,
                    commit_ref,
                    key_package_ref,
                },
                |seq| Some(format!(r#"{{"type":"welcome2","control_seq":{seq}}}"#)),
            ),
            Err(MlsControlAppendError::WelcomeNotCorrelated),
        ));

        let departed_joiner = Uuid::new_v4();
        let departed_key_package_ref = mls_key_package_ref(b"departed-key-package").unwrap();
        let departed_commit_ref = "D".repeat(43);
        state
            .append_and_broadcast_mls_envelope(
                &room_id,
                MlsControlAdmission::KeyPackage {
                    sender_id: departed_joiner,
                    key_package_ref: departed_key_package_ref.clone(),
                },
                |seq| Some(format!(r#"{{"type":"kp3","control_seq":{seq}}}"#)),
            )
            .expect("departing joiner publishes KeyPackage");
        state
            .append_and_broadcast_mls_envelope(
                &room_id,
                MlsControlAdmission::AddCommit {
                    sender_id: creator,
                    commit_ref: departed_commit_ref.clone(),
                    key_package_ref: departed_key_package_ref.clone(),
                },
                |seq| Some(format!(r#"{{"type":"commit3","control_seq":{seq}}}"#)),
            )
            .expect("accepted Add registers target-bound Welcome correlation");
        state.forget_mls_control_participant(room_id, &departed_joiner);
        assert!(
            matches!(
                state.append_and_broadcast_mls_envelope(
                    &room_id,
                    MlsControlAdmission::Welcome {
                        sender_id: creator,
                        commit_ref: departed_commit_ref,
                        key_package_ref: departed_key_package_ref,
                    },
                    |seq| Some(format!(r#"{{"type":"welcome3","control_seq":{seq}}}"#)),
                ),
                Err(MlsControlAppendError::WelcomeNotCorrelated),
            ),
            "departure of the Welcome target removes the pending correlation"
        );
    }

    // ---- Real-socket relay scenarios -------------------------------------

    type TestSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// Run an async relay scenario on its own multi-thread runtime and fail
    /// the test when it does not finish in time.
    ///
    /// A worker blocked on a lock cannot be cancelled, and dropping a runtime
    /// waits for its workers, so under a plain `#[tokio::test]` a relay
    /// deadlock hangs the whole test binary instead of failing one test. The
    /// scenario thread is detached: on a missed deadline it is left behind
    /// and the failure is raised from the calling thread.
    fn run_relay_scenario<F, Fut>(limit: std::time::Duration, scenario: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()>,
    {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("build scenario runtime");
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                runtime.block_on(scenario())
            }));
            // Report before the runtime is dropped: the drop never returns
            // while a worker is stuck.
            let _ = done_tx.send(outcome);
        });
        match done_rx.recv_timeout(limit) {
            Ok(Ok(())) => {}
            Ok(Err(panic)) => std::panic::resume_unwind(panic),
            Err(_) => {
                panic!("relay scenario did not finish within {limit:?}: a worker is blocked")
            }
        }
    }

    async fn spawn_relay(state: AppState) -> SocketAddr {
        let app: Router = Router::new()
            .route("/ws/:room_id", get(ws_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    /// Attempt a WebSocket upgrade with the given one-shot JWT. A refused
    /// upgrade yields the HTTP status the relay answered with.
    async fn try_open_socket(
        addr: SocketAddr,
        room_id: Uuid,
        token: &str,
    ) -> Result<TestSocket, u16> {
        use tokio_tungstenite::tungstenite::{Error, client::IntoClientRequest};

        let mut request = format!("ws://{addr}/ws/{room_id}")
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("origin", "https://localhost:3000".parse().unwrap());
        request.headers_mut().insert(
            "sec-websocket-protocol",
            format!("pinchat.v1, pinchat.v1.jwt.{token}")
                .parse()
                .unwrap(),
        );
        let attempt = tokio::time::timeout(
            Duration::from_secs(5),
            tokio_tungstenite::connect_async(request),
        )
        .await
        .expect("relay must answer the upgrade request");
        match attempt {
            Ok((socket, _)) => Ok(socket),
            Err(Error::Http(response)) => Err(response.status().as_u16()),
            Err(other) => panic!("unexpected upgrade failure: {other:?}"),
        }
    }

    /// Next JSON text frame, or `None` once the relay closed the socket.
    async fn next_frame(socket: &mut TestSocket) -> Option<serde_json::Value> {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match socket.next().await {
                    Some(Ok(ClientMessage::Text(text))) => {
                        return Some(serde_json::from_str(&text).expect("relay sends JSON"));
                    }
                    Some(Ok(ClientMessage::Ping(_) | ClientMessage::Pong(_))) => continue,
                    Some(Ok(ClientMessage::Close(_))) | Some(Err(_)) | None => return None,
                    Some(Ok(other)) => panic!("unexpected frame: {other:?}"),
                }
            }
        })
        .await
        .expect("relay must send a frame or close the socket")
    }

    async fn expect_frame(socket: &mut TestSocket, expected_type: &str) -> serde_json::Value {
        let frame = next_frame(socket)
            .await
            .unwrap_or_else(|| panic!("socket closed while waiting for `{expected_type}`"));
        assert_eq!(frame["type"], expected_type, "unexpected frame: {frame}");
        frame
    }

    /// Asserts that nothing arrives on the socket for a short quiet period.
    async fn expect_silence(socket: &mut TestSocket, context: &str) {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        let quiet = tokio::time::timeout(Duration::from_millis(300), async {
            loop {
                match socket.next().await {
                    Some(Ok(ClientMessage::Ping(_) | ClientMessage::Pong(_))) => continue,
                    other => return other,
                }
            }
        })
        .await;
        assert!(quiet.is_err(), "{context}: unexpected frame {quiet:?}");
    }

    async fn wait_until(context: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for: {context}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// A distinct one-to-one ciphertext envelope per marker. The fixture
    /// payload is all zeroes, so only its length tells two envelopes apart;
    /// multiples of three give every marker its own Base64 length.
    fn one_to_one_text_frame(marker: usize) -> String {
        let mut frame = browser_image_envelope(marker * 3);
        frame["type"] = serde_json::json!("message");
        frame.to_string()
    }

    fn fresh_token(state: &AppState, room_id: Uuid, connection_id: Uuid) -> String {
        sign_token(
            &WsTokenClaims::new_for_connection(
                room_id,
                connection_id,
                30,
                &state.config.jwt_issuer,
            ),
            &state.jwt_secret,
        )
        .unwrap()
    }

    fn resume_token(state: &AppState, room_id: Uuid, connection_id: Uuid) -> String {
        sign_token(
            &WsTokenClaims::for_resume(room_id, connection_id, 30, &state.config.jwt_issuer, None),
            &state.jwt_secret,
        )
        .unwrap()
    }

    #[test]
    fn replay_admission_is_scoped_to_the_room_lifetime() {
        let state = AppState::new(1000, test_config());
        let room_id = state
            .try_create_room(Room::new(RoomConfig {
                room_type: RoomType::OneToOne,
                ttl_minutes: 60,
                max_participants: 2,
            }))
            .unwrap();
        let now = Utc::now();

        assert_eq!(
            state.record_replay_hash(&room_id, "envelope", now),
            ReplayAdmission::New
        );
        assert_eq!(
            state.record_replay_hash(&room_id, "envelope", now),
            ReplayAdmission::Duplicate,
            "a relayed envelope stays suppressed"
        );

        // A failed relay rolls the identity back so the sender can retry.
        state.forget_replay_hash(&room_id, "envelope");
        assert_eq!(
            state.record_replay_hash(&room_id, "envelope", now),
            ReplayAdmission::New
        );

        // Teardown is not blocked by an earlier admission on the same
        // thread, and a removed room never gets its cache entry back.
        state.remove_room(&room_id);
        assert!(!state.seen_message_hashes.contains_key(&room_id));
        assert_eq!(
            state.record_replay_hash(&room_id, "late", now),
            ReplayAdmission::RoomGone
        );
        state.forget_replay_hash(&room_id, "late");
        assert!(
            !state.seen_message_hashes.contains_key(&room_id),
            "neither admission nor rollback may re-create the cache of a removed room"
        );
    }

    #[test]
    fn creator_lag_eviction_on_append_closes_the_room_without_blocking_the_relay() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let state = AppState::new(1000, test_config());
            let room = Room::new(RoomConfig {
                room_type: RoomType::Group,
                ttl_minutes: 60,
                max_participants: 4,
            });
            let room_id = room.id;
            let creator = room
                .creator_connection_id()
                .expect("group room has creator identity");
            let generation = room.creator_bootstrap_generation();
            state.try_create_room(room).unwrap();
            let other_room = state
                .try_create_room(Room::new(RoomConfig {
                    room_type: RoomType::OneToOne,
                    ttl_minutes: 60,
                    max_participants: 2,
                }))
                .unwrap();
            let addr = spawn_relay(state.clone()).await;

            let creator_token = sign_token(
                &WsTokenClaims::for_creator_bootstrap(
                    room_id,
                    creator,
                    30,
                    &state.config.jwt_issuer,
                    generation,
                    false,
                    None,
                ),
                &state.jwt_secret,
            )
            .unwrap();
            let mut creator_socket = try_open_socket(addr, room_id, &creator_token)
                .await
                .expect("creator is admitted");
            expect_frame(&mut creator_socket, "connected").await;
            expect_frame(&mut creator_socket, "mlssync").await;
            expect_frame(&mut creator_socket, "userjoined").await;

            // The creator reads every control but never acknowledges one. Its
            // own ordered join is control 1; fill the log up to one below the
            // backlog that is evicted at once. Reading keeps the socket
            // inside the small broadcast ring, so it is evicted for missing
            // ACKs and not for being a slow consumer.
            for _ in 2..MLS_CONTROL_LAG_HARD_LIMIT {
                state
                    .append_and_broadcast_mls_control(&room_id, |seq| {
                        Some(format!(r#"{{"type":"test","control_seq":{seq}}}"#))
                    })
                    .expect("append below the lag threshold");
                expect_frame(&mut creator_socket, "test").await;
            }
            assert!(state.connection_is_active(&room_id, &creator));
            assert!(
                state
                    .lagging_mls_control_participants(
                        &room_id,
                        MAX_MLS_UNACKNOWLEDGED_CONTROLS,
                        MLS_CONTROL_ACK_TIMEOUT,
                    )
                    .is_empty(),
                "one control below the hard limit nobody is evicted yet"
            );

            // The next control arrives through the relay itself, so the
            // creator crosses the limit inside the receive loop, right after
            // the append.
            let proposal = URL_SAFE_NO_PAD.encode(synthetic_public_message(CONTENT_TYPE_PROPOSAL));
            creator_socket
                .send(ClientMessage::Text(
                    serde_json::json!({
                        "type": "mls",
                        "wire_format": WIRE_PUBLIC_MESSAGE,
                        "payload": proposal,
                    })
                    .to_string(),
                ))
                .await
                .unwrap();

            wait_until("creator eviction closes the room", || {
                !state.rooms.contains_key(&room_id)
            })
            .await;

            // Every per-room index is cleared. `len()` visits every shard of
            // the replay cache, so it only returns when none was left locked.
            let probe = state.clone();
            let cleared = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::task::spawn_blocking(move || {
                    let _ = probe.seen_message_hashes.len();
                    !probe.seen_message_hashes.contains_key(&room_id)
                        && probe
                            .acknowledged_mls_control_cursor(&room_id, creator)
                            .is_none()
                        && !probe.broadcast_channels.contains_key(&room_id)
                        && !probe.connections.contains_key(&creator)
                }),
            )
            .await
            .expect("room teardown must not leave the replay cache locked")
            .unwrap();
            assert!(cleared, "room teardown must clear every per-room index");

            while next_frame(&mut creator_socket).await.is_some() {}

            // An unrelated room keeps relaying through the same state.
            let alice = Uuid::new_v4();
            let bob = Uuid::new_v4();
            let mut alice_socket =
                try_open_socket(addr, other_room, &fresh_token(&state, other_room, alice))
                    .await
                    .expect("other room admits its first peer");
            expect_frame(&mut alice_socket, "connected").await;
            let mut bob_socket =
                try_open_socket(addr, other_room, &fresh_token(&state, other_room, bob))
                    .await
                    .expect("other room admits its second peer");
            expect_frame(&mut bob_socket, "connected").await;
            expect_frame(&mut alice_socket, "userjoined").await;
            alice_socket
                .send(ClientMessage::Text(one_to_one_text_frame(1)))
                .await
                .unwrap();
            let relayed = expect_frame(&mut bob_socket, "message").await;
            assert_eq!(relayed["sender_id"], alice.to_string());
            assert!(
                state.seen_message_hashes.contains_key(&other_room),
                "the other room's replay cache recorded the relayed message"
            );
        });
    }

    // ---- One-to-one resume through the real upgrade gate ------------------

    struct LiveRoom {
        state: AppState,
        addr: SocketAddr,
        room_id: Uuid,
        alice: Uuid,
        alice_socket: TestSocket,
        bob: Uuid,
        bob_socket: TestSocket,
    }

    /// A one-to-one room with both peers connected, which is a full room.
    async fn live_one_to_one_room(config: Config) -> LiveRoom {
        let state = AppState::new(1000, config);
        let room_id = state
            .try_create_room(Room::new(RoomConfig {
                room_type: RoomType::OneToOne,
                ttl_minutes: 60,
                max_participants: 2,
            }))
            .unwrap();
        let addr = spawn_relay(state.clone()).await;
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        let mut alice_socket = try_open_socket(addr, room_id, &fresh_token(&state, room_id, alice))
            .await
            .expect("first peer is admitted");
        expect_frame(&mut alice_socket, "connected").await;
        let mut bob_socket = try_open_socket(addr, room_id, &fresh_token(&state, room_id, bob))
            .await
            .expect("second peer is admitted");
        expect_frame(&mut bob_socket, "connected").await;
        expect_frame(&mut alice_socket, "userjoined").await;
        assert!(state.rooms.get(&room_id).unwrap().is_full());
        LiveRoom {
            state,
            addr,
            room_id,
            alice,
            alice_socket,
            bob,
            bob_socket,
        }
    }

    /// Drop a peer's transport and wait until the relay holds its slot only
    /// as a reconnect grace reservation.
    async fn drop_transport(state: &AppState, room_id: Uuid, peer: Uuid, socket: TestSocket) {
        drop(socket);
        wait_until("relay notices the dropped transport", || {
            !state.connection_is_active(&room_id, &peer)
        })
        .await;
        assert!(
            state.rooms.get(&room_id).unwrap().holds_slot_for(&peer),
            "the slot stays reserved during the grace period"
        );
    }

    async fn assert_relays(
        from: &mut TestSocket,
        from_id: Uuid,
        to: &mut TestSocket,
        marker: usize,
    ) {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        from.send(ClientMessage::Text(one_to_one_text_frame(marker)))
            .await
            .unwrap();
        let relayed = expect_frame(to, "message").await;
        assert_eq!(relayed["sender_id"], from_id.to_string());
        // The relay also echoes a message to its sender.
        let echoed = expect_frame(from, "message").await;
        assert_eq!(echoed["sender_id"], from_id.to_string());
    }

    #[test]
    fn resume_into_a_full_one_to_one_room_keeps_the_relay_identity() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let mut config = test_config();
            config.ws_reconnect_grace_secs = 1;
            let LiveRoom {
                state,
                addr,
                room_id,
                alice,
                alice_socket,
                bob,
                mut bob_socket,
            } = live_one_to_one_room(config).await;

            drop_transport(&state, room_id, alice, alice_socket).await;

            let mut resumed = try_open_socket(addr, room_id, &resume_token(&state, room_id, alice))
                .await
                .expect("a resume into a full room must be admitted");
            let connected = expect_frame(&mut resumed, "connected").await;
            assert_eq!(connected["resumed"], true);
            assert_eq!(connected["user_id"], alice.to_string());
            assert_eq!(connected["participant_count"], 2);

            // The peer sees no leave/join cycle: that cycle is what makes the
            // browsers discard the ratchet and ask for a new SAS check.
            expect_silence(&mut bob_socket, "peer during a stable resume").await;

            // The grace finalizer of the dropped transport fires after one
            // second. It must find the resumed socket and leave the slot.
            tokio::time::sleep(Duration::from_millis(1500)).await;
            assert!(state.connection_is_active(&room_id, &alice));
            assert_eq!(state.get_participant_count(&room_id), 2);
            expect_silence(&mut bob_socket, "peer after the old grace timer").await;

            assert_relays(&mut resumed, alice, &mut bob_socket, 1).await;
            assert_relays(&mut bob_socket, bob, &mut resumed, 2).await;

            // The replay cache belongs to the room, not to a socket: an
            // envelope relayed before stays suppressed after the resume, from
            // either peer.
            resumed
                .send(ClientMessage::Text(one_to_one_text_frame(2)))
                .await
                .unwrap();
            bob_socket
                .send(ClientMessage::Text(one_to_one_text_frame(1)))
                .await
                .unwrap();
            expect_silence(&mut bob_socket, "replayed envelope").await;
            expect_silence(&mut resumed, "replayed envelope").await;
        });
    }

    #[test]
    fn reserved_slot_is_not_available_to_other_arrivals() {
        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let LiveRoom {
                state,
                addr,
                room_id,
                alice,
                alice_socket,
                bob,
                mut bob_socket,
            } = live_one_to_one_room(test_config()).await;
            drop_transport(&state, room_id, alice, alice_socket).await;

            // A link holder arriving during the grace period finds a full
            // room, and keeps its token because the refusal was not its fault.
            let intruder = Uuid::new_v4();
            let intruder_claims =
                WsTokenClaims::new_for_connection(room_id, intruder, 30, &state.config.jwt_issuer);
            let intruder_jti = intruder_claims.jti;
            let intruder_token = sign_token(&intruder_claims, &state.jwt_secret).unwrap();
            assert_eq!(
                try_open_socket(addr, room_id, &intruder_token).await.err(),
                Some(404)
            );
            assert!(!state.consumed_tokens.contains_key(&intruder_jti));

            // A resume token for an identity that holds no slot gets no
            // exemption from capacity.
            assert_eq!(
                try_open_socket(addr, room_id, &resume_token(&state, room_id, intruder))
                    .await
                    .err(),
                Some(404)
            );

            // A fresh (non-resume) token naming the reserved identity cannot
            // reclaim the reservation either.
            assert_eq!(
                try_open_socket(addr, room_id, &fresh_token(&state, room_id, alice))
                    .await
                    .err(),
                Some(404)
            );

            // The other peer was never disturbed and the reservation is
            // still there for its owner.
            assert!(state.connection_is_active(&room_id, &bob));
            assert_eq!(state.get_participant_count(&room_id), 2);
            expect_silence(&mut bob_socket, "peer while arrivals are refused").await;
            let mut resumed = try_open_socket(addr, room_id, &resume_token(&state, room_id, alice))
                .await
                .expect("the owner still resumes");
            assert_eq!(
                expect_frame(&mut resumed, "connected").await["resumed"],
                true
            );
        });
    }

    #[test]
    fn resume_tokens_are_bound_to_room_expiry_and_single_use() {
        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let LiveRoom {
                state,
                addr,
                room_id,
                alice,
                alice_socket,
                bob: _bob,
                bob_socket: _bob_socket,
            } = live_one_to_one_room(test_config()).await;
            let other_room = state
                .try_create_room(Room::new(RoomConfig {
                    room_type: RoomType::OneToOne,
                    ttl_minutes: 60,
                    max_participants: 2,
                }))
                .unwrap();
            drop_transport(&state, room_id, alice, alice_socket).await;

            // Minted for another room: the signed room does not match the path.
            assert_eq!(
                try_open_socket(addr, room_id, &resume_token(&state, other_room, alice))
                    .await
                    .err(),
                Some(403)
            );
            // And it opens nothing in that other room, where the identity
            // holds no slot: admission refuses to turn a resume into a join.
            let mut stray =
                try_open_socket(addr, other_room, &resume_token(&state, other_room, alice))
                    .await
                    .expect("upgrade completes, admission decides");
            expect_frame(&mut stray, "error").await;
            assert!(next_frame(&mut stray).await.is_none());
            assert_eq!(state.get_participant_count(&other_room), 0);

            // Expired.
            let mut expired =
                WsTokenClaims::for_resume(room_id, alice, 30, &state.config.jwt_issuer, None);
            expired.exp = 1;
            assert_eq!(
                try_open_socket(
                    addr,
                    room_id,
                    &sign_token(&expired, &state.jwt_secret).unwrap()
                )
                .await
                .err(),
                Some(401)
            );

            // Signed with another key.
            let forged = sign_token(
                &WsTokenClaims::for_resume(room_id, alice, 30, &state.config.jwt_issuer, None),
                &[7u8; 32],
            )
            .unwrap();
            assert_eq!(
                try_open_socket(addr, room_id, &forged).await.err(),
                Some(401)
            );

            // The long-lived resume credential is not an upgrade token: it
            // carries another audience and must go through the token endpoint.
            let credential = sign_resume_token(
                &WsResumeTokenClaims::new(room_id, alice, 600, &state.config.jwt_issuer),
                &state.jwt_secret,
            )
            .unwrap();
            assert_eq!(
                try_open_socket(addr, room_id, &credential).await.err(),
                Some(401)
            );

            // None of the refusals above disturbed the reservation. A valid
            // token works once.
            let token = resume_token(&state, room_id, alice);
            let mut resumed = try_open_socket(addr, room_id, &token)
                .await
                .expect("valid resume");
            assert_eq!(
                expect_frame(&mut resumed, "connected").await["resumed"],
                true
            );

            drop_transport(&state, room_id, alice, resumed).await;
            assert_eq!(
                try_open_socket(addr, room_id, &token).await.err(),
                Some(403),
                "a spent upgrade token must not resume a second time"
            );
            let mut again = try_open_socket(addr, room_id, &resume_token(&state, room_id, alice))
                .await
                .expect("a new token resumes again");
            assert_eq!(expect_frame(&mut again, "connected").await["resumed"], true);
        });
    }

    #[test]
    fn concurrent_resumes_admit_exactly_one_socket() {
        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let LiveRoom {
                state,
                addr,
                room_id,
                alice,
                alice_socket,
                bob,
                mut bob_socket,
            } = live_one_to_one_room(test_config()).await;
            drop_transport(&state, room_id, alice, alice_socket).await;

            let first_token = resume_token(&state, room_id, alice);
            let second_token = resume_token(&state, room_id, alice);
            let (first, second) = tokio::join!(
                try_open_socket(addr, room_id, &first_token),
                try_open_socket(addr, room_id, &second_token),
            );
            // Exactly one socket may own a relay identity. The other is
            // refused: before its token is spent (409) when the winner was
            // already admitted at its upgrade, or by admission, with an
            // error and a close, when both passed the upgrade together.
            let mut winner = None;
            let mut refused = 0;
            for attempt in [first, second] {
                match attempt {
                    Err(409) => refused += 1,
                    Ok(mut socket) => {
                        let frame = next_frame(&mut socket).await.expect("first frame");
                        if frame["type"] == "connected" {
                            assert!(winner.is_none(), "two sockets own one identity");
                            winner = Some(socket);
                        } else {
                            assert_eq!(frame["type"], "error", "{frame}");
                            assert!(
                                next_frame(&mut socket).await.is_none(),
                                "the loser is closed"
                            );
                            refused += 1;
                        }
                    }
                    Err(status) => panic!("unexpected refusal {status}"),
                }
            }
            assert_eq!(refused, 1);
            let mut winner = winner.expect("one resume is admitted");

            assert_eq!(state.get_participant_count(&room_id), 2);
            assert!(state.connection_is_active(&room_id, &bob));
            expect_silence(&mut bob_socket, "peer during concurrent resumes").await;
            assert_relays(&mut winner, alice, &mut bob_socket, 1).await;

            // A further resume while the identity is active is refused before
            // its token is spent, and leaves the live socket in place.
            let late =
                WsTokenClaims::for_resume(room_id, alice, 30, &state.config.jwt_issuer, None);
            let late_jti = late.jti;
            assert_eq!(
                try_open_socket(
                    addr,
                    room_id,
                    &sign_token(&late, &state.jwt_secret).unwrap()
                )
                .await
                .err(),
                Some(409)
            );
            assert!(!state.consumed_tokens.contains_key(&late_jti));
            assert!(state.connection_is_active(&room_id, &alice));
            assert_relays(&mut bob_socket, bob, &mut winner, 2).await;
        });
    }

    #[test]
    fn resume_after_the_grace_period_is_not_admitted_as_a_new_peer() {
        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let mut config = test_config();
            config.ws_reconnect_grace_secs = 1;
            let LiveRoom {
                state,
                addr,
                room_id,
                alice,
                alice_socket,
                bob,
                mut bob_socket,
            } = live_one_to_one_room(config).await;
            let token = resume_token(&state, room_id, alice);
            drop_transport(&state, room_id, alice, alice_socket).await;

            let left = expect_frame(&mut bob_socket, "userleft").await;
            assert_eq!(left["user_id"], alice.to_string());
            assert!(!state.rooms.get(&room_id).unwrap().holds_slot_for(&alice));

            // The slot is free again, so the upgrade itself is not refused,
            // but a resume is never converted into a fresh admission.
            let mut stale = try_open_socket(addr, room_id, &token)
                .await
                .expect("upgrade completes, admission decides");
            expect_frame(&mut stale, "error").await;
            assert!(next_frame(&mut stale).await.is_none());
            assert_eq!(state.get_participant_count(&room_id), 1);
            assert!(state.connection_is_active(&room_id, &bob));
            expect_silence(&mut bob_socket, "peer after a refused late resume").await;
        });
    }

    #[test]
    fn resume_into_a_full_group_room_passes_the_capacity_gate() {
        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let state = AppState::new(1000, test_config());
            let room = Room::new(RoomConfig {
                room_type: RoomType::Group,
                ttl_minutes: 60,
                max_participants: 2,
            });
            let room_id = room.id;
            let creator = room.creator_connection_id().unwrap();
            state.try_create_room(room).unwrap();
            let member = Uuid::new_v4();
            assert_eq!(
                state.add_connection(creator, room_id, false),
                Some(ConnectionAdmission::New)
            );
            let _creator_stream = state
                .open_mls_control_stream(&room_id, creator, None)
                .expect("open creator stream");
            assert!(state.mark_creator_control_ready(&room_id, creator));
            assert_eq!(
                state.add_connection(member, room_id, false),
                Some(ConnectionAdmission::New)
            );
            let _member_stream = state
                .open_mls_control_stream(&room_id, member, None)
                .expect("open member stream");
            assert!(state.rooms.get(&room_id).unwrap().is_full());
            assert_eq!(state.detach_connection(&member), Some(room_id));

            let addr = spawn_relay(state.clone()).await;
            let outsider = Uuid::new_v4();
            assert_eq!(
                try_open_socket(addr, room_id, &fresh_token(&state, room_id, outsider))
                    .await
                    .err(),
                Some(404)
            );
            let token = sign_token(
                &WsTokenClaims::for_resume(room_id, member, 30, &state.config.jwt_issuer, Some(0)),
                &state.jwt_secret,
            )
            .unwrap();
            let mut resumed = try_open_socket(addr, room_id, &token)
                .await
                .expect("a group member resumes into a full room");
            let connected = expect_frame(&mut resumed, "connected").await;
            assert_eq!(connected["resumed"], true);
            assert_eq!(connected["user_id"], member.to_string());
            assert_eq!(state.get_participant_count(&room_id), 2);
        });
    }

    #[test]
    fn socket_that_stops_reading_is_disconnected_instead_of_pinning_broadcast_memory() {
        use tokio_tungstenite::tungstenite::{Message as ClientMessage, client::IntoClientRequest};

        run_relay_scenario(std::time::Duration::from_secs(60), || async {
            let state = AppState::new(1000, test_config());
            let room_id = state
                .try_create_room(Room::new(RoomConfig {
                    room_type: RoomType::OneToOne,
                    ttl_minutes: 60,
                    max_participants: 2,
                }))
                .unwrap();
            let addr = spawn_relay(state.clone()).await;
            let sender_id = Uuid::new_v4();
            let stalled_id = Uuid::new_v4();
            let mut sender_socket =
                try_open_socket(addr, room_id, &fresh_token(&state, room_id, sender_id))
                    .await
                    .expect("sender is admitted");
            expect_frame(&mut sender_socket, "connected").await;

            // The second peer keeps its TCP connection open but never reads
            // after the handshake. A small receive buffer makes the relay's
            // writes back up after a few image frames.
            let tcp = tokio::net::TcpSocket::new_v4().unwrap();
            tcp.set_recv_buffer_size(4096).unwrap();
            let stream = tcp.connect(addr).await.unwrap();
            let mut request = format!("ws://{addr}/ws/{room_id}")
                .into_client_request()
                .unwrap();
            request
                .headers_mut()
                .insert("origin", "https://localhost:3000".parse().unwrap());
            request.headers_mut().insert(
                "sec-websocket-protocol",
                format!(
                    "pinchat.v1, pinchat.v1.jwt.{}",
                    fresh_token(&state, room_id, stalled_id)
                )
                .parse()
                .unwrap(),
            );
            let (_stalled_socket, _) = tokio_tungstenite::client_async(request, stream)
                .await
                .expect("stalled peer is admitted");
            expect_frame(&mut sender_socket, "userjoined").await;
            assert!(state.connection_is_active(&room_id, &stalled_id));

            // Stream distinct maximum-size images, paced below the per-sender
            // traffic budget. The sender drains its own socket, so only the
            // stalled peer backs up. The relay ends the sender's connection
            // once the room's broadcast byte budget is exhausted by frames
            // the stalled peer has not taken.
            let image_size = state.config.max_image_size;
            'stream: for index in 0..120 {
                let mut image = browser_image_envelope(image_size - 3 * index);
                image["type"] = serde_json::json!("image");
                if sender_socket
                    .send(ClientMessage::Text(image.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
                let pause = tokio::time::sleep(Duration::from_millis(250));
                tokio::pin!(pause);
                loop {
                    tokio::select! {
                        _ = &mut pause => break,
                        frame = sender_socket.next() => match frame {
                            Some(Ok(ClientMessage::Close(_))) | Some(Err(_)) | None => break 'stream,
                            Some(Ok(_)) => {}
                        },
                    }
                }
                if !state.connection_is_active(&room_id, &stalled_id) {
                    break;
                }
            }

            // The stalled peer must lose its slot within the send deadline,
            // not sit on the frames until the idle or age limits fire.
            wait_until("relay disconnects the peer that stopped reading", || {
                !state.connection_is_active(&room_id, &stalled_id)
            })
            .await;
        });
    }

    #[test]
    fn a_ping_from_a_client_is_answered_with_the_same_payload() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let mut room = live_one_to_one_room(test_config()).await;
            room.alice_socket
                .send(ClientMessage::Ping(b"are you there".to_vec()))
                .await
                .unwrap();
            let answer = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match room.alice_socket.next().await {
                        Some(Ok(ClientMessage::Pong(payload))) => return payload,
                        Some(Ok(_)) => continue,
                        other => panic!("socket ended before the pong: {other:?}"),
                    }
                }
            })
            .await
            .expect("the relay answers a ping");
            assert_eq!(answer, b"are you there");

            // The connection carries messages as before.
            assert_relays(&mut room.alice_socket, room.alice, &mut room.bob_socket, 1).await;
        });
    }

    #[test]
    fn largest_images_are_relayed_intact_again_and_again_on_the_same_connections() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        run_relay_scenario(std::time::Duration::from_secs(120), || async {
            let mut config = test_config();
            config.max_image_size = 2 * 1024 * 1024;
            config.room_byte_rate_limit = 64 * 1024 * 1024;
            let mut room = live_one_to_one_room(config).await;
            for round in 0..6usize {
                // Every frame differs, or the relay would drop it as a replay.
                let mut frame = browser_image_envelope(2 * 1024 * 1024 - round * 3);
                frame["header"]["n"] = serde_json::json!(round);
                let (from, from_id, to) = if round % 2 == 0 {
                    (&mut room.alice_socket, room.alice, &mut room.bob_socket)
                } else {
                    (&mut room.bob_socket, room.bob, &mut room.alice_socket)
                };
                from.send(ClientMessage::Text(frame.to_string()))
                    .await
                    .unwrap();
                let relayed = expect_frame(to, "image").await;
                assert_eq!(relayed["sender_id"], from_id.to_string());
                assert!(
                    relayed["payload"] == frame["payload"],
                    "round {round}: the receiver got another payload"
                );
                assert!(relayed["header"]["n"] == frame["header"]["n"]);
                let echoed = expect_frame(from, "image").await;
                assert!(
                    echoed["payload"] == frame["payload"],
                    "round {round}: the echo carries another payload"
                );
            }

            // Delivered frames are no longer counted against any budget.
            let state = room.state.clone();
            wait_until("delivered frames leave the broadcast budget", || {
                state.broadcast_bytes_in_flight() == 0
            })
            .await;
        });
    }

    #[test]
    fn both_peers_can_send_their_largest_image_at_the_same_moment() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        // One largest image takes nearly the whole byte budget of its room
        // and keeps it while it is written out. The image the other peer
        // sends at the same moment has to wait for it, not cost its sender
        // the connection.
        run_relay_scenario(std::time::Duration::from_secs(120), || async {
            let mut config = test_config();
            config.max_image_size = 2 * 1024 * 1024;
            config.room_byte_rate_limit = 64 * 1024 * 1024;
            let mut room = live_one_to_one_room(config).await;
            let state = room.state.clone();
            for round in 0..4usize {
                let mut from_alice = browser_image_envelope(2 * 1024 * 1024 - round * 3);
                from_alice["header"]["n"] = serde_json::json!(2 * round);
                let mut from_bob = browser_image_envelope(2 * 1024 * 1024 - round * 3 - 1);
                from_bob["header"]["n"] = serde_json::json!(2 * round + 1);

                let (sent_a, sent_b) = tokio::join!(
                    room.alice_socket
                        .send(ClientMessage::Text(from_alice.to_string())),
                    room.bob_socket
                        .send(ClientMessage::Text(from_bob.to_string())),
                );
                sent_a.unwrap();
                sent_b.unwrap();

                // Each side gets both images, its own echo and the other's,
                // in the order the relay let them through. Both read at the
                // same time, as two browsers do: the second image is let
                // through once the first has reached everybody.
                async fn two_images(socket: &mut TestSocket) -> Vec<serde_json::Value> {
                    let first = expect_frame(socket, "image").await;
                    let second = expect_frame(socket, "image").await;
                    vec![first, second]
                }
                let (at_alice, at_bob) = tokio::join!(
                    two_images(&mut room.alice_socket),
                    two_images(&mut room.bob_socket),
                );
                for received in [at_alice, at_bob] {
                    assert_ne!(
                        received[0]["sender_id"], received[1]["sender_id"],
                        "round {round}: one image came twice"
                    );
                    for relayed in received {
                        let expected = if relayed["sender_id"] == room.alice.to_string() {
                            &from_alice
                        } else {
                            assert_eq!(relayed["sender_id"], room.bob.to_string());
                            &from_bob
                        };
                        assert!(
                            relayed["payload"] == expected["payload"],
                            "round {round}: an image arrived with another payload"
                        );
                    }
                }
                assert!(state.connection_is_active(&room.room_id, &room.alice));
                assert!(state.connection_is_active(&room.room_id, &room.bob));
            }
            wait_until("delivered frames leave the broadcast budget", || {
                state.broadcast_bytes_in_flight() == 0
            })
            .await;

            // The same with a member of the room that is slow to take the
            // first image, which here is a receiver held by the test: the
            // second image is held back, its sender stays connected, and it
            // goes through when the first one has left the budget.
            let mut slow = state
                .broadcast_channels
                .get(&room.room_id)
                .expect("room broadcast sender")
                .subscribe();
            let mut first = browser_image_envelope(2 * 1024 * 1024 - 100);
            first["header"]["n"] = serde_json::json!(100);
            let mut second = browser_image_envelope(2 * 1024 * 1024 - 101);
            second["header"]["n"] = serde_json::json!(101);
            room.alice_socket
                .send(ClientMessage::Text(first.to_string()))
                .await
                .unwrap();
            assert!(
                expect_frame(&mut room.bob_socket, "image").await["payload"] == first["payload"]
            );
            assert!(
                expect_frame(&mut room.alice_socket, "image").await["payload"] == first["payload"]
            );
            room.bob_socket
                .send(ClientMessage::Text(second.to_string()))
                .await
                .unwrap();
            expect_silence(
                &mut room.alice_socket,
                "the second image waits for the first to leave the budget",
            )
            .await;
            assert!(state.connection_is_active(&room.room_id, &room.bob));
            drop(slow.recv().await.unwrap());
            assert!(
                expect_frame(&mut room.alice_socket, "image").await["payload"] == second["payload"]
            );
            assert!(
                expect_frame(&mut room.bob_socket, "image").await["payload"] == second["payload"]
            );
            assert!(state.connection_is_active(&room.room_id, &room.bob));
        });
    }

    #[test]
    fn a_frame_waits_for_room_in_the_broadcast_budget_and_gives_up_in_time() {
        use crate::state::app_state::BroadcastError;

        const MIB: usize = 1024 * 1024;
        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let state = AppState::new(1000, test_config());
            let room_id = state
                .try_create_room(Room::new(RoomConfig {
                    room_type: RoomType::OneToOne,
                    ttl_minutes: 5,
                    max_participants: 2,
                }))
                .unwrap();
            // A receiver that takes nothing: what is sent stays counted.
            let mut receiver = state
                .broadcast_channels
                .get(&room_id)
                .expect("room broadcast sender")
                .subscribe();
            let megabyte = || "x".repeat(MIB);
            for _ in 0..4 {
                state.broadcast_room_message(&room_id, megabyte()).unwrap();
            }
            assert_eq!(state.broadcast_bytes_in_flight(), 4 * MIB);
            assert_eq!(
                state.broadcast_room_message(&room_id, megabyte()),
                Err(BroadcastError::RoomByteCapacity),
            );

            // Too little patience: the frame is refused with the budget
            // that was full, and nothing of it stays counted.
            let started = Instant::now();
            assert_eq!(
                state
                    .broadcast_room_message_when_room(
                        &room_id,
                        megabyte(),
                        None,
                        Duration::from_millis(80),
                    )
                    .await,
                Err(BroadcastError::RoomByteCapacity),
            );
            assert!(started.elapsed() >= Duration::from_millis(80));
            assert_eq!(state.broadcast_bytes_in_flight(), 4 * MIB);

            // Enough patience: it goes through as soon as one frame leaves.
            let waiting_state = state.clone();
            let waiting = tokio::spawn(async move {
                waiting_state
                    .broadcast_room_message_when_room(
                        &room_id,
                        "y".repeat(MIB),
                        None,
                        Duration::from_secs(20),
                    )
                    .await
            });
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                !waiting.is_finished(),
                "the frame went through a full budget"
            );
            drop(receiver.recv().await.unwrap());
            assert_eq!(waiting.await.unwrap(), Ok(1));
            assert_eq!(state.broadcast_bytes_in_flight(), 4 * MIB);

            // A room that is gone is an answer at once, not a wait.
            let started = Instant::now();
            assert_eq!(
                state
                    .broadcast_room_message_when_room(
                        &Uuid::new_v4(),
                        megabyte(),
                        None,
                        Duration::from_secs(20),
                    )
                    .await,
                Err(BroadcastError::MissingRoom),
            );
            assert!(started.elapsed() < Duration::from_secs(5));

            drop(receiver);
            state.remove_room(&room_id);
            assert_eq!(state.broadcast_bytes_in_flight(), 0);
        });
    }

    #[test]
    fn every_member_of_a_full_group_can_send_at_once_without_overrunning_a_receiver() {
        use crate::state::app_state::BROADCAST_CHANNEL_ENTRIES;
        use tokio::sync::broadcast::error::TryRecvError;

        let state = AppState::new(1000, test_config());
        let room_id = state
            .try_create_room(Room::new(RoomConfig {
                room_type: RoomType::Group,
                ttl_minutes: 60,
                max_participants: 20,
            }))
            .unwrap();
        let members = state.rooms.get(&room_id).unwrap().max_participants;
        let mut receiver = state
            .broadcast_channels
            .get(&room_id)
            .expect("room broadcast sender")
            .subscribe();
        // Three messages from every member before this receiver takes one:
        // all of them sending at the same moment, while it is still writing
        // a picture. With a ring of 8 it lagged at the ninth.
        let sent = 3 * members;
        assert!(sent <= BROADCAST_CHANNEL_ENTRIES);
        for n in 0..sent {
            state
                .broadcast_room_message(&room_id, format!("{{\"n\":{n}}}"))
                .unwrap();
        }
        for n in 0..sent {
            let message = receiver.try_recv().expect("nothing is lost");
            assert_eq!(message.as_str(), format!("{{\"n\":{n}}}"), "in order");
        }
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        state.remove_room(&room_id);
    }

    #[test]
    fn a_message_leaves_the_broadcast_budget_once_every_receiver_has_taken_it() {
        const KIB: usize = 1024;
        let state = AppState::new(1000, test_config());
        let room_id = state
            .try_create_room(Room::new(RoomConfig {
                room_type: RoomType::OneToOne,
                ttl_minutes: 5,
                max_participants: 2,
            }))
            .unwrap();
        let (mut first, mut second) = {
            let sender = state
                .broadcast_channels
                .get(&room_id)
                .expect("room broadcast sender");
            (sender.subscribe(), sender.subscribe())
        };
        for _ in 0..4 {
            state
                .broadcast_room_message(&room_id, "m".repeat(KIB))
                .unwrap();
        }
        assert_eq!(state.broadcast_bytes_in_flight(), 4 * KIB);

        for _ in 0..4 {
            drop(first.try_recv().unwrap());
        }
        assert_eq!(
            state.broadcast_bytes_in_flight(),
            4 * KIB,
            "the other receiver has not taken them yet"
        );

        // A receiver holds the message it is writing.
        let writing = second.try_recv().unwrap();
        for _ in 0..3 {
            drop(second.try_recv().unwrap());
        }
        assert_eq!(state.broadcast_bytes_in_flight(), KIB);
        drop(writing);
        assert_eq!(
            state.broadcast_bytes_in_flight(),
            0,
            "a slot that every receiver has read keeps nothing until it is reused"
        );
        state.remove_room(&room_id);
    }

    #[test]
    fn a_receiver_further_behind_than_the_ring_lags_and_what_it_missed_is_released() {
        use crate::state::app_state::BROADCAST_CHANNEL_ENTRIES;
        use tokio::sync::broadcast::error::TryRecvError;

        const KIB: usize = 1024;
        let state = AppState::new(1000, test_config());
        let room_id = state
            .try_create_room(Room::new(RoomConfig {
                room_type: RoomType::OneToOne,
                ttl_minutes: 5,
                max_participants: 2,
            }))
            .unwrap();
        let mut receiver = state
            .broadcast_channels
            .get(&room_id)
            .expect("room broadcast sender")
            .subscribe();
        for _ in 0..BROADCAST_CHANNEL_ENTRIES + 3 {
            state
                .broadcast_room_message(&room_id, "m".repeat(KIB))
                .unwrap();
        }
        assert_eq!(
            state.broadcast_bytes_in_flight(),
            BROADCAST_CHANNEL_ENTRIES * KIB,
            "the three oldest were overwritten and released"
        );
        // The relay closes such a connection with 1008.
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Lagged(3))));
        drop(receiver);
        assert_eq!(state.broadcast_bytes_in_flight(), 0);
        state.remove_room(&room_id);
    }

    #[test]
    fn a_picture_overwritten_in_the_ring_while_a_receiver_writes_it_stays_counted() {
        use crate::state::app_state::BROADCAST_CHANNEL_ENTRIES;
        use tokio::sync::broadcast::error::TryRecvError;

        const KIB: usize = 1024;
        const MIB: usize = 1024 * KIB;
        let state = AppState::new(1000, test_config());
        let room_id = state
            .try_create_room(Room::new(RoomConfig {
                room_type: RoomType::OneToOne,
                ttl_minutes: 5,
                max_participants: 2,
            }))
            .unwrap();
        let (mut writer, mut lagging) = {
            let sender = state
                .broadcast_channels
                .get(&room_id)
                .expect("room broadcast sender");
            (sender.subscribe(), sender.subscribe())
        };
        state
            .broadcast_room_message(&room_id, "p".repeat(2 * MIB))
            .unwrap();
        // The writer takes the picture and is still writing it.
        let writing = writer.try_recv().unwrap();
        // The room goes on until the picture's slot is reused.
        for _ in 0..BROADCAST_CHANNEL_ENTRIES {
            state
                .broadcast_room_message(&room_id, "t".repeat(KIB))
                .unwrap();
        }
        assert_eq!(
            state.broadcast_bytes_in_flight(),
            2 * MIB + BROADCAST_CHANNEL_ENTRIES * KIB,
            "the ring no longer holds the picture, the write does, and it is still counted"
        );
        assert!(matches!(lagging.try_recv(), Err(TryRecvError::Lagged(1))));
        assert_eq!(writing.as_str().len(), 2 * MIB);

        drop(writing);
        assert_eq!(
            state.broadcast_bytes_in_flight(),
            BROADCAST_CHANNEL_ENTRIES * KIB,
            "the picture leaves the budget with its last reference"
        );
        drop(writer);
        drop(lagging);
        assert_eq!(state.broadcast_bytes_in_flight(), 0);
        state.remove_room(&room_id);
    }

    #[test]
    fn a_frame_above_the_size_limit_ends_the_connection_and_only_that_one() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        run_relay_scenario(std::time::Duration::from_secs(60), || async {
            let mut room = live_one_to_one_room(test_config()).await;
            let limit = max_ws_size(room.state.config.max_image_size);
            let state = room.state.clone();
            let (room_id, alice) = (room.room_id, room.alice);

            // The relay stops at the header: the client may fail to push the
            // whole body into a connection that is already gone.
            let _ = room
                .alice_socket
                .send(ClientMessage::Text("x".repeat(limit + 1)))
                .await;
            wait_until("the relay drops the oversized sender", || {
                !state.connection_is_active(&room_id, &alice)
            })
            .await;
            // The other peer is untouched; the slot of the sender is held
            // for the reconnect grace period like after any other drop.
            assert!(state.connection_is_active(&room_id, &room.bob));
            expect_silence(
                &mut room.bob_socket,
                "nothing of the oversized frame is relayed",
            )
            .await;
        });
    }

    #[test]
    fn binary_frames_are_dropped_and_the_stream_goes_on() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let mut room = live_one_to_one_room(test_config()).await;
            room.alice_socket
                .send(ClientMessage::Binary(vec![7u8; 70_000]))
                .await
                .unwrap();
            assert_relays(&mut room.alice_socket, room.alice, &mut room.bob_socket, 2).await;
            assert_relays(&mut room.bob_socket, room.bob, &mut room.alice_socket, 3).await;
        });
    }

    #[test]
    fn a_message_sent_in_fragments_is_relayed_as_one() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        use tokio_tungstenite::tungstenite::protocol::frame::{
            Frame,
            coding::{Data, OpCode},
        };

        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let mut room = live_one_to_one_room(test_config()).await;
            let whole = one_to_one_text_frame(900);
            let expected: serde_json::Value = serde_json::from_str(&whole).unwrap();
            let (first, rest) = whole.as_bytes().split_at(whole.len() / 3);
            let (second, third) = rest.split_at(rest.len() / 2);

            let fragments = [
                ClientMessage::Frame(Frame::message(
                    first.to_vec(),
                    OpCode::Data(Data::Text),
                    false,
                )),
                // A control frame may sit between the fragments of a message.
                ClientMessage::Ping(b"between".to_vec()),
                ClientMessage::Frame(Frame::message(
                    second.to_vec(),
                    OpCode::Data(Data::Continue),
                    false,
                )),
                ClientMessage::Frame(Frame::message(
                    third.to_vec(),
                    OpCode::Data(Data::Continue),
                    true,
                )),
            ];
            for fragment in fragments {
                room.alice_socket.send(fragment).await.unwrap();
            }
            let relayed = expect_frame(&mut room.bob_socket, "message").await;
            assert_eq!(relayed["sender_id"], room.alice.to_string());
            assert!(relayed["payload"] == expected["payload"]);
        });
    }

    /// A frame as a browser puts it on the wire, masked, with the first byte
    /// (FIN, reserved bits, opcode) given as it is.
    fn raw_client_frame(first: u8, payload: &[u8]) -> Vec<u8> {
        const MASK: [u8; 4] = [0x1F, 0x2E, 0x3D, 0x4C];
        let mut frame = vec![first];
        if payload.len() < 126 {
            frame.push(0x80 | payload.len() as u8);
        } else if payload.len() <= usize::from(u16::MAX) {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(&MASK);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ MASK[index & 3]),
        );
        frame
    }

    /// Bytes written to the socket under the client library, which knows
    /// nothing of them.
    async fn write_raw(socket: &mut TestSocket, bytes: &[u8]) {
        use tokio::io::AsyncWriteExt;
        match socket.get_mut() {
            tokio_tungstenite::MaybeTlsStream::Plain(stream) => {
                stream.write_all(bytes).await.unwrap();
            }
            _ => unreachable!("the test relay is plain TCP"),
        }
    }

    /// How the connection ended for the client: the status code of the
    /// relay's Close frame, if one came, and whether the stream then ended
    /// with an orderly close rather than an error. The socket is dropped at
    /// the end, as a browser closes its own once the server has.
    async fn closing_seen_by(mut socket: TestSocket) -> (Option<u16>, bool) {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        tokio::time::timeout(Duration::from_secs(10), async {
            let mut code = None;
            loop {
                match socket.next().await {
                    Some(Ok(ClientMessage::Close(frame))) => {
                        code = Some(frame.map(|frame| u16::from(frame.code)).unwrap_or(1005));
                    }
                    Some(Ok(_)) => continue,
                    None => return (code, true),
                    Some(Err(_)) => return (code, false),
                }
            }
        })
        .await
        .expect("the connection ends")
    }

    #[test]
    fn a_close_from_a_client_is_answered_with_its_code_and_ends_cleanly() {
        use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};

        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let mut room = live_one_to_one_room(test_config()).await;
            room.alice_socket
                .close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "Manual disconnect".into(),
                }))
                .await
                .unwrap();
            let started = Instant::now();
            assert_eq!(closing_seen_by(room.alice_socket).await, (Some(1000), true));
            assert!(started.elapsed() < Duration::from_secs(1));

            // A departure like any other: the slot waits for a resume and the
            // other peer stays.
            let state = room.state.clone();
            let (room_id, alice) = (room.room_id, room.alice);
            wait_until("the relay lets the closed connection go", || {
                !state.connection_is_active(&room_id, &alice)
            })
            .await;
            assert!(state.rooms.get(&room_id).unwrap().holds_slot_for(&alice));
            assert!(state.connection_is_active(&room_id, &room.bob));
            expect_silence(&mut room.bob_socket, "nothing is relayed for a close").await;
        });
    }

    #[test]
    fn a_close_started_by_the_relay_carries_its_code_and_ends_cleanly() {
        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let room = live_one_to_one_room(test_config()).await;
            room.state.remove_room(&room.room_id);
            let (alice, bob) = tokio::join!(
                closing_seen_by(room.alice_socket),
                closing_seen_by(room.bob_socket),
            );
            assert_eq!(alice, (Some(1001), true));
            assert_eq!(bob, (Some(1001), true));
        });
    }

    #[test]
    fn a_frame_that_breaks_the_protocol_is_answered_with_the_matching_close_code() {
        let mut unmasked = raw_client_frame(0x81, b"hello");
        unmasked[1] &= 0x7F;
        unmasked.truncate(2);
        unmasked.extend_from_slice(b"hello");
        let mut non_minimal = vec![0x81, 0x80 | 126, 0, 5, 0, 0, 0, 0];
        non_minimal.extend_from_slice(b"hello");
        let cases: Vec<(&str, Vec<u8>, u16)> = vec![
            ("unmasked frame", unmasked, 1002),
            ("reserved bit", raw_client_frame(0xC1, b"hello"), 1002),
            ("reserved opcode", raw_client_frame(0x83, b"x"), 1002),
            ("length not in its shortest form", non_minimal, 1002),
            (
                "close frame with a bad code",
                raw_client_frame(0x88, &[0x03, 0xED]),
                1002,
            ),
            (
                "invalid UTF-8",
                raw_client_frame(0x81, &[b'{', 0xC3, 0x28]),
                1007,
            ),
            (
                "too many fragments",
                {
                    let mut frames = raw_client_frame(0x01, b"{");
                    for _ in 0..ws_transport::MAX_MESSAGE_FRAMES {
                        frames.extend(raw_client_frame(0x00, b""));
                    }
                    frames
                },
                1009,
            ),
        ];
        for (what, bytes, code) in cases {
            run_relay_scenario(std::time::Duration::from_secs(30), move || async move {
                let mut room = live_one_to_one_room(test_config()).await;
                write_raw(&mut room.alice_socket, &bytes).await;
                let (seen, _) = closing_seen_by(room.alice_socket).await;
                assert_eq!(seen, Some(code), "{what}");
                assert!(room.state.connection_is_active(&room.room_id, &room.bob));
            });
        }
    }

    #[test]
    fn a_client_that_breaks_the_relay_rules_gets_1008_and_a_clean_close() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let mut room = live_one_to_one_room(test_config()).await;
            let limit = room.state.config.protocol_error_limit;
            for index in 0..limit {
                // The relay may already be closing when the last ones go.
                let _ = room
                    .alice_socket
                    .send(ClientMessage::Text(format!("not json {index}")))
                    .await;
            }
            assert_eq!(closing_seen_by(room.alice_socket).await, (Some(1008), true));
            assert!(room.state.connection_is_active(&room.room_id, &room.bob));
        });
    }

    /// The case of a peer that starts a 63 KiB message in a frame that is
    /// not final, never finishes it, and sends pings to keep the connection
    /// busy.
    #[test]
    fn an_unfinished_message_cannot_be_kept_alive_with_pings() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        run_relay_scenario(std::time::Duration::from_secs(60), || async {
            let mut room = live_one_to_one_room(test_config()).await;
            let state = room.state.clone();
            let (small_free, large_free) = state.inbound_bytes_available();

            write_raw(
                &mut room.alice_socket,
                &raw_client_frame(0x01, &vec![b'x'; 63 * 1024]),
            )
            .await;
            wait_until(
                "the unfinished message is charged to the small class",
                || state.inbound_bytes_available() == (small_free - 64 * 1024, large_free),
            )
            .await;

            let started = Instant::now();
            let mut ticker = interval(Duration::from_millis(500));
            let mut pongs = 0usize;
            let code = loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if room.alice_socket
                            .send(ClientMessage::Ping(b"still here".to_vec()))
                            .await
                            .is_err()
                        {
                            break None;
                        }
                    }
                    frame = room.alice_socket.next() => match frame {
                        Some(Ok(ClientMessage::Pong(_))) => pongs += 1,
                        Some(Ok(ClientMessage::Close(frame))) => {
                            break frame.map(|frame| u16::from(frame.code));
                        }
                        Some(Ok(_)) => {}
                        None | Some(Err(_)) => break None,
                    }
                }
            };
            let elapsed = started.elapsed();
            assert_eq!(code, Some(1008), "closed as a policy violation");
            assert!(pongs >= 5, "the pings were answered ({pongs})");
            assert!(
                elapsed < IDLE_TIMEOUT + Duration::from_secs(2),
                "the pings did not extend the message: {elapsed:?}"
            );
            wait_until("what the message held is returned", || {
                state.inbound_bytes_available() == (small_free, large_free)
            })
            .await;
        });
    }

    #[test]
    fn pictures_cannot_take_what_text_needs_of_the_broadcast_budget() {
        use crate::state::app_state::BroadcastError;

        const MIB: usize = 1024 * 1024;
        let state = AppState::new(1000, test_config());
        let mut rooms = Vec::new();
        let mut receivers = Vec::new();
        for _ in 0..8 {
            let room_id = state
                .try_create_room(Room::new(RoomConfig {
                    room_type: RoomType::OneToOne,
                    ttl_minutes: 5,
                    max_participants: 2,
                }))
                .unwrap();
            // A receiver that never reads: every frame stays counted.
            receivers.push(
                state
                    .broadcast_channels
                    .get(&room_id)
                    .expect("room broadcast sender")
                    .subscribe(),
            );
            rooms.push(room_id);
        }
        // Large frames fill three quarters of the 32 MiB, six rooms' worth.
        for room_id in &rooms[..6] {
            for _ in 0..4 {
                state
                    .broadcast_room_message(room_id, "p".repeat(MIB))
                    .unwrap();
            }
        }
        assert_eq!(state.broadcast_bytes_in_flight(), 24 * MIB);
        assert_eq!(
            state.broadcast_room_message(&rooms[6], "p".repeat(MIB)),
            Err(BroadcastError::GlobalByteCapacity),
            "no more pictures"
        );
        // Text still has the last quarter.
        for _ in 0..8 {
            state
                .broadcast_room_message(&rooms[6], "t".repeat(32 * 1024))
                .unwrap();
        }
        state
            .broadcast_room_message(&rooms[7], "t".repeat(2 * 1024))
            .unwrap();
        drop(receivers);
        for room_id in &rooms {
            state.remove_room(room_id);
        }
        assert_eq!(state.broadcast_bytes_in_flight(), 0);
    }

    #[test]
    fn one_address_cannot_fill_the_mls_control_log() {
        let state = AppState::new(1000, test_config());
        let mut rooms = Vec::new();
        let mut receivers = Vec::new();
        for _ in 0..8 {
            let room = Room::new(RoomConfig {
                room_type: RoomType::Group,
                ttl_minutes: 60,
                max_participants: 4,
            });
            let creator = room.creator_connection_id().unwrap();
            let room_id = state.try_create_room(room).unwrap();
            state.add_connection(creator, room_id, false).unwrap();
            let (receiver, _) = state
                .open_mls_control_stream(&room_id, creator, None)
                .unwrap();
            // Kept so the frames are counted until the log lets them go;
            // read as they come so that the room's ring does not lag.
            receivers.push(receiver);
            rooms.push(room_id);
        }
        let append = |room_id: &Uuid, lease: &ClientBroadcastLease| {
            state.append_and_broadcast_mls_envelope_from(
                room_id,
                MlsControlAdmission::Ordinary,
                Some(lease),
                |seq| {
                    Some(format!(
                        "{{\"seq\":{seq},\"pad\":\"{}\"}}",
                        "m".repeat(32 * 1024)
                    ))
                },
            )
        };
        // One address appends in room after room until its quarter of the
        // global log is used up, long before the global log is.
        let a = state.lease_client_broadcast_share("address-a");
        let mut accepted = 0usize;
        let mut refused_with_room_to_spare = false;
        'rooms: for room_id in &rooms[..6] {
            loop {
                for receiver in receivers.iter_mut() {
                    while receiver.try_recv().is_ok() {}
                }
                match append(room_id, &a) {
                    Ok(_) => accepted += 1,
                    Err(MlsControlAppendError::CapacityExceeded) => {
                        // Full room, or full share: a fresh room tells which.
                        if append(&rooms[6], &a).is_err() {
                            refused_with_room_to_spare = true;
                            break 'rooms;
                        }
                        accepted += 1;
                        break;
                    }
                    Err(other) => panic!("{other:?}"),
                }
            }
        }
        assert!(refused_with_room_to_spare, "the address hit its share");
        let held = accepted * (32 * 1024 + 30);
        assert!(held <= 8 * 1024 * 1024 + 64 * 1024, "{held} bytes");
        assert!(held >= 7 * 1024 * 1024, "{held} bytes");
        // Another address appends in the room the first could not.
        let b = state.lease_client_broadcast_share("address-b");
        append(&rooms[7], &b).unwrap();
        drop((a, b, receivers));
        for room_id in &rooms {
            state.remove_room(room_id);
        }
        assert_eq!(state.sweep_client_broadcast_shares(), 0);
    }

    // ---------------------------------------------------------------------
    // Admission control
    // ---------------------------------------------------------------------

    fn admission_config(max: usize, per_address: usize) -> Config {
        let mut config = test_config();
        config.max_ws_connections = max;
        config.max_ws_connections_per_address = per_address;
        config
    }

    fn client(key: &str, prefix: Option<&str>) -> crate::state::app_state::ClientAddress {
        crate::state::app_state::ClientAddress {
            key: key.to_string(),
            prefix: prefix.map(str::to_string),
        }
    }

    #[test]
    fn admission_counts_the_relay_and_each_address_and_gives_everything_back() {
        let state = AppState::new(10, admission_config(5, 2));
        let a = client("a", None);
        let b = client("b", None);
        let first = state.admit_ws_connection(Some(&a)).unwrap();
        let second = state.admit_ws_connection(Some(&a)).unwrap();
        assert_eq!(
            state.admit_ws_connection(Some(&a)).err(),
            Some(AdmissionRefused::AddressFull)
        );
        assert_eq!(
            state.ws_admission_open(&a),
            Err(AdmissionRefused::AddressFull)
        );
        // A refusal for the address takes nothing of the relay's.
        assert_eq!(state.ws_connections_open(), 2);
        let others: Vec<_> = (0..3)
            .map(|index| {
                state
                    .admit_ws_connection(Some(&client(&format!("other {index}"), None)))
                    .unwrap()
            })
            .collect();
        assert_eq!(
            state.admit_ws_connection(Some(&b)).err(),
            Some(AdmissionRefused::RelayFull)
        );
        assert_eq!(
            state.ws_admission_open(&b),
            Err(AdmissionRefused::RelayFull)
        );
        assert_eq!(
            state.admit_ws_connection(None).err(),
            Some(AdmissionRefused::RelayFull)
        );
        // A refusal for the relay leaves no count for its address behind.
        assert_eq!(state.ws_address_connections("b"), 0);

        drop(first);
        assert_eq!(state.ws_address_connections("a"), 1);
        let again = state.admit_ws_connection(Some(&b)).unwrap();
        drop((second, others, again));
        assert_eq!(state.ws_connections_open(), 0);
        assert_eq!(state.client_broadcast_share_count(), 0);
    }

    #[test]
    fn one_ipv6_slash_48_holds_four_addresses_worth_of_connections() {
        let state = AppState::new(10, admission_config(1000, 2));
        // Eight /64s of one /48: each may hold two, all of them eight.
        let mut held = Vec::new();
        for host in 0..8 {
            let address = client(&format!("2001:db8:1:{host}::/64"), Some("2001:db8:1::/48"));
            held.push(state.admit_ws_connection(Some(&address)).unwrap());
        }
        let ninth = client("2001:db8:1:9::/64", Some("2001:db8:1::/48"));
        assert_eq!(
            state.admit_ws_connection(Some(&ninth)).err(),
            Some(AdmissionRefused::AddressFull)
        );
        assert_eq!(
            state.ws_admission_open(&ninth),
            Err(AdmissionRefused::AddressFull)
        );
        // The refused /64 holds nothing, the /48 holds its eight.
        assert_eq!(state.ws_address_connections("2001:db8:1:9::/64"), 0);
        assert_eq!(state.ws_prefix_connections("2001:db8:1::/48"), 8);
        // Another /48 is not affected.
        let elsewhere = client("2001:db8:2:1::/64", Some("2001:db8:2::/48"));
        held.push(state.admit_ws_connection(Some(&elsewhere)).unwrap());
        drop(held);
        assert_eq!(state.ws_prefix_connections("2001:db8:1::/48"), 0);
        assert_eq!(state.ws_connections_open(), 0);
    }

    #[test]
    fn racing_admissions_never_pass_a_limit_and_leave_nothing_behind() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        const MAX: usize = 48;
        const PER_ADDRESS: usize = 6;
        let state = AppState::new(10, admission_config(MAX, PER_ADDRESS));
        let addresses: Vec<_> = (0..20)
            .map(|index| {
                client(
                    &format!("k{}", index % 10),
                    Some(&format!("p{}", index % 2)),
                )
            })
            .collect();
        let held_now = AtomicUsize::new(0);
        let most_held = AtomicUsize::new(0);
        let admitted = AtomicUsize::new(0);
        let refused = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for thread in 0..12usize {
                let (state, addresses) = (&state, &addresses);
                let (held_now, most_held, admitted, refused) =
                    (&held_now, &most_held, &admitted, &refused);
                scope.spawn(move || {
                    let mut mine = std::collections::VecDeque::new();
                    for round in 0..3000usize {
                        let address = &addresses[(thread * 7 + round) % addresses.len()];
                        match state.admit_ws_connection(Some(address)) {
                            Ok(admission) => {
                                let now = held_now.fetch_add(1, Ordering::SeqCst) + 1;
                                most_held.fetch_max(now, Ordering::SeqCst);
                                admitted.fetch_add(1, Ordering::SeqCst);
                                assert!(state.ws_address_connections(&address.key) <= PER_ADDRESS);
                                assert!(
                                    state.ws_prefix_connections(address.prefix.as_deref().unwrap())
                                        <= PER_ADDRESS * 4
                                );
                                mine.push_back(admission);
                            }
                            Err(_) => {
                                refused.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        if (mine.len() > 5 || round % 3 == 0)
                            && let Some(admission) = mine.pop_front()
                        {
                            // Counted down before the slot is given back, so
                            // the count never runs behind the slots.
                            held_now.fetch_sub(1, Ordering::SeqCst);
                            drop(admission);
                        }
                    }
                    held_now.fetch_sub(mine.len(), Ordering::SeqCst);
                });
            }
        });
        assert!(most_held.load(Ordering::SeqCst) <= MAX);
        assert!(admitted.load(Ordering::SeqCst) > 1000);
        assert!(
            refused.load(Ordering::SeqCst) > 0,
            "the limits were reached"
        );
        assert_eq!(state.ws_connections_open(), 0);
        assert_eq!(state.client_broadcast_share_count(), 0);
        for prefix in ["p0", "p1"] {
            assert_eq!(state.ws_prefix_connections(prefix), 0);
        }
    }

    fn one_to_one_rooms(state: &AppState, count: usize) -> Vec<Uuid> {
        (0..count)
            .map(|_| {
                state
                    .try_create_room(Room::new(RoomConfig {
                        room_type: RoomType::OneToOne,
                        ttl_minutes: 60,
                        max_participants: 2,
                    }))
                    .unwrap()
            })
            .collect()
    }

    /// The relay as it runs in production: with the peer address of every
    /// connection, behind a proxy at 127.0.0.1 when `proxied`.
    async fn spawn_relay_with_addresses(state: AppState) -> SocketAddr {
        let app: Router = Router::new()
            .route("/ws/:room_id", get(ws_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        addr
    }

    /// An upgrade with a valid token, answered or refused: the status line
    /// and the headers of the answer. `forwarded_for` is sent as
    /// X-Forwarded-For. The stream is returned open so the caller decides
    /// when it ends.
    async fn upgrade_head(
        addr: SocketAddr,
        room_id: Uuid,
        token: &str,
        forwarded_for: Option<&str>,
    ) -> (String, tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let forwarded = forwarded_for
            .map(|value| format!("X-Forwarded-For: {value}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "GET /ws/{room_id} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\n\
             Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Origin: https://localhost:3000\r\n\
             Sec-WebSocket-Protocol: pinchat.v1, pinchat.v1.jwt.{token}\r\n{forwarded}\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        (String::from_utf8_lossy(&head).to_lowercase(), stream)
    }

    #[test]
    fn upgrades_beyond_the_relay_limit_are_refused_and_admitted_once_a_slot_frees() {
        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let state = AppState::new(100, admission_config(3, 3));
            let rooms = one_to_one_rooms(&state, 2);
            let addr = spawn_relay(state.clone()).await;
            let mut open = Vec::new();
            for (room, peer) in [
                (rooms[0], Uuid::new_v4()),
                (rooms[0], Uuid::new_v4()),
                (rooms[1], Uuid::new_v4()),
            ] {
                let socket = try_open_socket(addr, room, &fresh_token(&state, room, peer))
                    .await
                    .expect("within the limit");
                open.push(socket);
            }
            assert_eq!(state.ws_connections_open(), 3);

            let late = Uuid::new_v4();
            let token = fresh_token(&state, rooms[1], late);
            let (head, _stream) = upgrade_head(addr, rooms[1], &token, None).await;
            assert!(head.starts_with("http/1.1 503"), "{head}");
            assert!(head.contains("retry-after: 30"), "{head}");
            assert_eq!(state.ws_connections_open(), 3);

            // One connection ends: its slot comes free, and the refused
            // client gets in with the token it was refused with, which the
            // refusal did not spend.
            drop(open.remove(0));
            wait_until("the closed connection frees its slot", || {
                state.ws_connections_open() == 2
            })
            .await;
            let mut admitted = try_open_socket(addr, rooms[1], &token)
                .await
                .expect("a slot is free again");
            expect_frame(&mut admitted, "connected").await;
            assert_eq!(state.ws_connections_open(), 3);

            drop(admitted);
            drop(open);
            wait_until("every slot comes back", || state.ws_connections_open() == 0).await;
        });
    }

    #[test]
    fn refused_and_abandoned_upgrades_give_their_slot_back() {
        use tokio::io::AsyncWriteExt;

        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let state = AppState::new(100, admission_config(2, 2));
            let rooms = one_to_one_rooms(&state, 3);
            let addr = spawn_relay(state.clone()).await;

            // Refused after admission: no such room, a token already spent.
            let missing = Uuid::new_v4();
            let peer = Uuid::new_v4();
            let (head, _) =
                upgrade_head(addr, missing, &fresh_token(&state, missing, peer), None).await;
            assert!(head.starts_with("http/1.1 404"), "{head}");
            assert_eq!(state.ws_connections_open(), 0);
            // An identity that still has its socket, then a token already
            // spent.
            let token = fresh_token(&state, rooms[0], peer);
            let socket = try_open_socket(addr, rooms[0], &token).await.unwrap();
            let (head, _) = upgrade_head(addr, rooms[0], &token, None).await;
            assert!(head.starts_with("http/1.1 409"), "{head}");
            assert_eq!(state.ws_connections_open(), 1);
            drop(socket);
            wait_until("a closed connection", || state.ws_connections_open() == 0).await;
            let (head, _) = upgrade_head(addr, rooms[0], &token, None).await;
            assert!(head.starts_with("http/1.1 403"), "{head}");
            assert_eq!(state.ws_connections_open(), 0);

            // The client goes away after its request, before reading the
            // answer, and after the 101 without a word.
            for room in [rooms[1], rooms[2]] {
                let (head, stream) =
                    upgrade_head(addr, room, &fresh_token(&state, room, Uuid::new_v4()), None)
                        .await;
                assert!(head.starts_with("http/1.1 101"), "{head}");
                drop(stream);
            }
            let mut early = tokio::net::TcpStream::connect(addr).await.unwrap();
            let room = rooms[1];
            let token = fresh_token(&state, room, Uuid::new_v4());
            early
                .write_all(
                    format!(
                        "GET /ws/{room} HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n\
                         Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                         Origin: https://localhost:3000\r\n\
                         Sec-WebSocket-Protocol: pinchat.v1, pinchat.v1.jwt.{token}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            drop(early);
            // A request that never ends is never counted.
            let mut partial = tokio::net::TcpStream::connect(addr).await.unwrap();
            partial.write_all(b"GET /ws/").await.unwrap();
            wait_until("abandoned upgrades free their slots", || {
                state.ws_connections_open() == 0
            })
            .await;
            drop(partial);

            // And the relay is whole: two connections fit.
            let a = try_open_socket(
                addr,
                rooms[2],
                &fresh_token(&state, rooms[2], Uuid::new_v4()),
            )
            .await;
            assert!(a.is_ok() || state.ws_connections_open() <= 2);
        });
    }

    #[test]
    fn each_address_behind_the_proxy_is_limited_on_its_own() {
        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let mut config = admission_config(10, 2);
            config.trusted_proxies = vec!["127.0.0.1".to_string()];
            let state = AppState::new(100, config);
            let rooms = one_to_one_rooms(&state, 3);
            let addr = spawn_relay_with_addresses(state.clone()).await;

            let mut held = Vec::new();
            for room in &rooms[..2] {
                let (head, stream) = upgrade_head(
                    addr,
                    *room,
                    &fresh_token(&state, *room, Uuid::new_v4()),
                    Some("198.51.100.7"),
                )
                .await;
                assert!(head.starts_with("http/1.1 101"), "{head}");
                held.push(stream);
            }
            // The third from the same address is refused, with 429.
            let (head, _) = upgrade_head(
                addr,
                rooms[2],
                &fresh_token(&state, rooms[2], Uuid::new_v4()),
                Some("198.51.100.7"),
            )
            .await;
            assert!(head.starts_with("http/1.1 429"), "{head}");
            assert!(head.contains("retry-after: 30"), "{head}");
            // A client that writes another address in front of its own does
            // not get past: the proxy appends the address it saw, and that
            // last entry is the one that counts.
            let (head, _) = upgrade_head(
                addr,
                rooms[2],
                &fresh_token(&state, rooms[2], Uuid::new_v4()),
                Some("203.0.113.9, 198.51.100.7"),
            )
            .await;
            assert!(head.starts_with("http/1.1 429"), "{head}");
            // Another address is not affected.
            let (head, stream) = upgrade_head(
                addr,
                rooms[2],
                &fresh_token(&state, rooms[2], Uuid::new_v4()),
                Some("198.51.100.8"),
            )
            .await;
            assert!(head.starts_with("http/1.1 101"), "{head}");
            held.push(stream);
            drop(held);
            wait_until("every slot comes back", || state.ws_connections_open() == 0).await;
            assert_eq!(state.client_broadcast_share_count(), 0);
        });
    }

    #[test]
    fn without_a_trusted_proxy_x_forwarded_for_is_ignored() {
        run_relay_scenario(std::time::Duration::from_secs(30), || async {
            let state = AppState::new(100, admission_config(10, 2));
            let rooms = one_to_one_rooms(&state, 3);
            let addr = spawn_relay_with_addresses(state.clone()).await;
            let mut held = Vec::new();
            for (index, room) in rooms.iter().enumerate() {
                let (head, stream) = upgrade_head(
                    addr,
                    *room,
                    &fresh_token(&state, *room, Uuid::new_v4()),
                    Some(&format!("192.0.2.{index}")),
                )
                .await;
                held.push((head, stream));
            }
            // Three different claimed addresses, one real one: the third is
            // refused as the second connection too many of 127.0.0.1.
            assert!(held[0].0.starts_with("http/1.1 101"));
            assert!(held[1].0.starts_with("http/1.1 101"));
            assert!(held[2].0.starts_with("http/1.1 429"), "{}", held[2].0);
            drop(held);
            wait_until("every slot comes back", || state.ws_connections_open() == 0).await;
        });
    }

    #[test]
    fn concurrent_upgrades_take_exactly_the_free_slots() {
        run_relay_scenario(std::time::Duration::from_secs(60), || async {
            const MAX: usize = 10;
            let state = AppState::new(100, admission_config(MAX, MAX));
            let rooms = one_to_one_rooms(&state, 15);
            let addr = spawn_relay(state.clone()).await;
            let attempts = rooms.iter().flat_map(|room| {
                let state = state.clone();
                let room = *room;
                (0..2).map(move |_| {
                    let token = fresh_token(&state, room, Uuid::new_v4());
                    async move { upgrade_head(addr, room, &token, None).await }
                })
            });
            let answers = futures_util::future::join_all(attempts).await;
            let admitted = answers
                .iter()
                .filter(|(head, _)| head.starts_with("http/1.1 101"))
                .count();
            let refused = answers
                .iter()
                .filter(|(head, _)| head.starts_with("http/1.1 503"))
                .count();
            assert_eq!(admitted, MAX, "admitted");
            assert_eq!(admitted + refused, 30);
            assert!(state.ws_connections_open() <= MAX);
            drop(answers);
            wait_until("every slot comes back", || state.ws_connections_open() == 0).await;
        });
    }
}
