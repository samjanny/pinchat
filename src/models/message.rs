use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::RoomType;

/// Signal Protocol message header carrying the Diffie-Hellman public key used to
/// trigger a receiving-side ratchet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Base64url-encoded DH public key
    pub dh: String,
    /// Previous chain length (tracks skipped messages)
    pub pn: u32,
    /// Message number in the current chain
    pub n: u32,
    /// Ratchet count for diagnostic purposes
    pub rc: u32,
}

/// WebSocket message type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Message {
    /// Encrypted text message to send to other participants
    /// Signal Protocol: header contains DH public key for automatic ratchet on receive
    Message {
        /// Base64-encoded encrypted payload
        payload: String,
        /// Optional Signal Protocol header with DH public key
        header: Option<MessageHeader>,
        sender_id: Uuid,
        timestamp: DateTime<Utc>,
    },

    /// Encrypted image message to send to other participants
    /// Similar to Message but with larger payload limit and image metadata
    Image {
        /// Base64-encoded encrypted image data
        payload: String,
        /// Optional Signal Protocol header with DH public key
        header: Option<MessageHeader>,
        sender_id: Uuid,
        timestamp: DateTime<Utc>,
    },

    /// Notification that a user joined the room
    UserJoined {
        user_id: Uuid,
        participant_count: usize,
    },

    /// Notification that a user left the room
    UserLeft {
        user_id: Uuid,
        participant_count: usize,
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
    },

    /// ECDH public key exchange (for Perfect Forward Secrecy)
    #[serde(rename = "ecdh_public_key")]
    ECDHPublicKey {
        /// Base64-encoded encrypted ECDH public key
        payload: String,
        /// Connection ID of the sender
        sender_id: Uuid,
    },

    /// Signal Protocol DH Ratchet message relayed without server-side decryption
    #[serde(rename = "dh_ratchet")]
    DHRatchet {
        /// Base64-encoded ephemeral ECDH public key
        public_key: String,
        /// Base64-encoded ECDSA signature authenticated by the identity key
        signature: String,
        /// Ratchet step number for diagnostics
        ratchet_count: u32,
        /// Reason for triggering the ratchet (e.g., turn-based or timeout-based)
        reason: String,
        /// Connection ID of the sender
        sender_id: Uuid,
    },
}

/// Incoming message from the client (before parsing)
#[derive(Debug, Deserialize)]
pub struct IncomingMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub payload: Option<String>,
    pub header: Option<MessageHeader>, // Signal Protocol header
}
