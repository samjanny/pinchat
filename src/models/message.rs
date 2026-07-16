use chrono::DateTime;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::RoomType;

/// Signal Protocol message header carrying the Diffie-Hellman public key used to
/// trigger a receiving-side ratchet, plus the ECDSA signature that authenticates
/// the ephemeral DH pubkey to the peer's long-term identity key (protocol v1).
///
/// The signature is computed over the canonical tuple
///   "pinchat-drheader-v2" || len(dh_raw):u16_be || dh_raw ||
///   pn:u32_be || n:u32_be || rc:u32_be
/// which binds the signature to the complete semantic header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Protocol version (must equal PINCHAT_PROTOCOL_VERSION).
    pub v: u8,
    /// Base64url-encoded DH public key
    pub dh: String,
    /// Previous chain length (tracks skipped messages)
    pub pn: u32,
    /// Message number in the current chain
    pub n: u32,
    /// Ratchet count for diagnostic purposes
    pub rc: u32,
    /// Base64url-encoded ECDSA signature over the canonical header tuple.
    pub sig: String,
}

/// WebSocket message type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Message {
    /// Encrypted text message to send to other participants
    /// Signal Protocol: header contains DH public key for automatic ratchet on receive.
    /// Header is mandatory in protocol v1.
    Message {
        /// Base64-encoded encrypted payload
        payload: String,
        /// Signal Protocol header with DH public key and signature
        header: MessageHeader,
        sender_id: Uuid,
    },

    /// Encrypted image message to send to other participants
    /// Similar to Message but with larger payload limit and image metadata.
    /// Header is mandatory in protocol v1.
    Image {
        /// Base64-encoded encrypted image data
        payload: String,
        /// Signal Protocol header with DH public key and signature
        header: MessageHeader,
        sender_id: Uuid,
    },

    /// Notification that a user joined the room
    UserJoined {
        user_id: Uuid,
        participant_count: usize,
        /// Server-assigned total-order sequence for group-room lifecycle
        /// events. Absent in one-to-one rooms.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        control_seq: Option<u64>,
    },

    /// Notification that a user left the room
    UserLeft {
        user_id: Uuid,
        participant_count: usize,
        /// Server-assigned total-order sequence for group-room lifecycle
        /// events. Absent in one-to-one rooms.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        control_seq: Option<u64>,
    },

    /// Generic error
    Error { message: String },

    /// Success response (e.g., after connecting)
    /// Includes validated room configuration from server to prevent URL spoofing
    Connected {
        user_id: Uuid,
        room_id: Uuid,
        participant_count: usize,
        /// Validated room type from server
        room_type: RoomType,
        /// Validated TTL from server
        ttl_minutes: u32,
        /// Validated maximum participants
        max_participants: usize,
        /// Maximum image size in bytes from server configuration
        max_image_size: usize,
        /// Room creation timestamp (for accurate countdown calculation)
        created_at: DateTime<Utc>,
        /// Server-signed bearer credential for reclaiming this exact relay
        /// identity during the configured reconnect grace window. Sent only
        /// to this socket in its direct Connected frame, never broadcast.
        resume_token: String,
        /// True when this socket reclaimed a grace-reserved participant ID;
        /// false on the participant's first admission.
        resumed: bool,
        /// Starting cursor for the ordered MLS control stream. Present only
        /// for group rooms. On resume it equals the cursor bound into the
        /// single-use WebSocket JWT; on first admission it is the current
        /// room head, so pre-join history is not replayed.
        #[serde(skip_serializing_if = "Option::is_none")]
        mls_control_cursor: Option<u64>,
    },

    /// ECDH public key exchange (for Perfect Forward Secrecy)
    #[serde(rename = "ecdh_public_key")]
    ECDHPublicKey {
        /// Base64-encoded encrypted ECDH public key
        payload: String,
        /// Connection ID of the sender
        sender_id: Uuid,
    },

    /// MLS (RFC 9420) envelope relayed as opaque bytes.
    ///
    /// The server remains blind to MLS cryptographic contents. It validates
    /// the transport shape and, for PublicMessage, reads only enough canonical
    /// framing to distinguish Proposal from Commit for rate limiting. The
    /// client performs all signature, membership, tree, and key-schedule
    /// processing.
    ///
    /// `ratchet_tree` is a narrow side-channel used by the MVP Add flow
    /// so a joiner can verify tree_hash without a dedicated extension in
    /// GroupInfo. It carries the serialised ratchet-tree bytes for
    /// `mls_welcome` envelopes only; all other wire formats MUST leave it
    /// `None`. When the GroupInfo `ratchet_tree` extension is added, this
    /// field becomes optional and will eventually be deprecated.
    #[serde(rename = "mls")]
    Mls {
        /// Base64url-encoded MLSMessage bytes
        payload: String,
        /// Wire format of the embedded MLSMessage (RFC 9420 §15.1):
        ///   1 = mls_public_message
        ///   2 = mls_private_message
        ///   3 = mls_welcome
        ///   5 = mls_key_package
        wire_format: u16,
        /// Optional ratchet-tree side-channel for `mls_welcome` only.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        ratchet_tree: Option<String>,
        /// Standard MLS KeyPackageRef identifying the Add/Welcome recipient.
        /// Present on Add Commits and their corresponding Welcome only.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        key_package_ref: Option<String>,
        /// PinChat transport correlation digest: base64url SHA-256 over the
        /// exact mls_public_message body paired with this envelope.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        commit_ref: Option<String>,
        /// HMAC-SHA256 proof that a KeyPackage publisher knows the room's
        /// URL-fragment invite secret. Present only on KeyPackage envelopes;
        /// verified end-to-end by the creator before constructing an Add.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        bootstrap_proof: Option<String>,
        /// Server-assigned total-order sequence for group control envelopes.
        /// Present for KeyPackage, Proposal, Commit, and Welcome; absent for
        /// ephemeral MLS PrivateMessages. Group lifecycle events share this
        /// sequence through their own `control_seq` fields.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        control_seq: Option<u64>,
        /// Connection ID of the sender (same framing as ecdh_public_key).
        sender_id: Uuid,
    },

    /// Marks completion of the replay snapshot opened for this group socket.
    /// Live MLS control envelopes after `through_seq` follow on the same
    /// ordered broadcast stream.
    MlsSync { through_seq: u64 },

    /// Direct, non-broadcast rejection of a locally submitted MLS Commit.
    /// This lets the browser destroy its staged candidate instead of waiting
    /// forever for an acceptance echo that the relay deliberately rejected.
    MlsRejected {
        #[serde(skip_serializing_if = "Option::is_none")]
        commit_ref: Option<String>,
        reason: String,
        retry_after_secs: u64,
    },
}

/// Incoming message from the client (before parsing).
///
/// `header` is kept optional at this stage because `ecdh_public_key` and `mls`
/// messages legitimately omit it. The websocket handler enforces header
/// presence and protocol version for `message`/`image` variants.
#[derive(Debug, Deserialize)]
pub struct IncomingMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub payload: Option<String>,
    pub header: Option<MessageHeader>, // Signal Protocol header (1:1 only)
    /// MLS wire_format hint for `mls` envelopes. Ignored for other types.
    #[serde(default)]
    pub wire_format: Option<u16>,
    /// MLS ratchet-tree side-channel for `mls` welcome envelopes only.
    #[serde(default)]
    pub ratchet_tree: Option<String>,
    /// Optional Add/Welcome recipient KeyPackageRef correlation metadata.
    #[serde(default)]
    pub key_package_ref: Option<String>,
    /// Optional SHA-256 Commit correlation metadata.
    #[serde(default)]
    pub commit_ref: Option<String>,
    /// Optional invite-secret possession proof for an MLS KeyPackage.
    #[serde(default)]
    pub bootstrap_proof: Option<String>,
    /// Highest consecutively applied server MLS-control sequence. Used only
    /// by group-room `mlsack` frames.
    #[serde(default)]
    pub control_seq: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v0_header_without_v_or_sig_fails_deserialize() {
        // Pre-v1 wire format had neither `v` nor `sig` — serde rejects it now.
        let v0 = r#"{"dh":"AA","pn":0,"n":1,"rc":0}"#;
        let res: Result<MessageHeader, _> = serde_json::from_str(v0);
        assert!(res.is_err(), "v0 header must fail without v and sig");
    }

    #[test]
    fn message_without_header_fails_deserialize() {
        // In protocol v1 `header` is mandatory on message/image.
        let raw = r#"{"type":"message","payload":"x","sender_id":"00000000-0000-0000-0000-000000000000"}"#;
        let res: Result<Message, _> = serde_json::from_str(raw);
        assert!(res.is_err(), "message without header must fail");
    }

    #[test]
    fn v1_header_roundtrips() {
        let hdr = MessageHeader {
            v: crate::models::PINCHAT_PROTOCOL_VERSION,
            dh: "AA".to_string(),
            pn: 0,
            n: 3,
            rc: 1,
            sig: "BB".to_string(),
        };
        let json = serde_json::to_string(&hdr).unwrap();
        let parsed: MessageHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.v, 1);
        assert_eq!(parsed.dh, "AA");
        assert_eq!(parsed.sig, "BB");
    }

    #[test]
    fn mls_correlation_metadata_roundtrips() {
        let reference = "A".repeat(43);
        let incoming: IncomingMessage = serde_json::from_value(serde_json::json!({
            "type": "mls",
            "payload": "AA",
            "wire_format": 3,
            "ratchet_tree": "AA",
            "key_package_ref": reference,
            "commit_ref": reference,
            "bootstrap_proof": reference,
        }))
        .unwrap();
        assert_eq!(
            incoming.key_package_ref.as_deref(),
            Some(reference.as_str())
        );
        assert_eq!(incoming.commit_ref.as_deref(), Some(reference.as_str()));
        assert_eq!(
            incoming.bootstrap_proof.as_deref(),
            Some(reference.as_str())
        );

        let outgoing = Message::Mls {
            payload: "AA".to_string(),
            wire_format: 3,
            ratchet_tree: Some("AA".to_string()),
            key_package_ref: Some(reference.clone()),
            commit_ref: Some(reference.clone()),
            bootstrap_proof: Some(reference.clone()),
            control_seq: Some(7),
            sender_id: Uuid::nil(),
        };
        let encoded = serde_json::to_value(outgoing).unwrap();
        assert_eq!(encoded["key_package_ref"], reference);
        assert_eq!(encoded["commit_ref"], reference);
        assert_eq!(encoded["bootstrap_proof"], reference);
        assert_eq!(encoded["control_seq"], 7);
    }
}
