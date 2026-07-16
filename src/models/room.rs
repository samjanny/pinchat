use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Room type: one-to-one or group
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RoomType {
    OneToOne,
    Group,
}

/// Configuration used to create a new room
#[derive(Debug, Deserialize)]
pub struct RoomConfig {
    pub room_type: RoomType,
    pub ttl_minutes: u32,
    /// Requested maximum participants. Clamped to `[2, 20]` for Group
    /// rooms and always forced to `2` for OneToOne rooms.
    #[serde(default = "default_max_participants")]
    pub max_participants: usize,
}

fn default_max_participants() -> usize {
    20
}

const CREATOR_BOOTSTRAP_TOKEN_BYTES: usize = 32;
const CREATOR_BOOTSTRAP_TOKEN_LEN: usize = 43;

/// Chat room
#[derive(Debug, Clone)]
pub struct Room {
    pub id: Uuid,
    pub room_type: RoomType,
    pub ttl_minutes: u32,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub max_participants: usize,
    pub participant_ids: HashSet<Uuid>,
    /// Stable relay identity reserved for the creator of an MLS group room.
    ///
    /// This is an availability/anti-DoS guard for the current creator-centric
    /// MVP: only this relay participant may submit Commit or Welcome controls.
    /// End-to-end MLS authentication still comes from the leaf-0 signature and
    /// creator-key pin checked by the clients. One-to-one rooms do not use it.
    creator_connection_id: Option<Uuid>,
    /// SHA-256 of the random creator bootstrap capability. The plaintext token
    /// is returned once by room creation and is never retained server-side.
    creator_bootstrap_hash: Option<[u8; 32]>,
    /// Monotonic generation bound into every creator-bootstrap WebSocket
    /// token. Consuming the bootstrap increments it, invalidating tokens that
    /// were signed before the creator's first authenticated MLS ACK.
    creator_bootstrap_generation: u64,
    /// Ordinary group participants remain blocked until the creator has both
    /// opened its ordered-control stream and durably appended the first
    /// lifecycle entry.
    creator_control_ready: bool,
}

impl Room {
    /// Creates a new room.
    ///
    /// One-to-one rooms are always capped at 2 participants regardless of the
    /// `max_participants` field in the config.
    ///
    /// Group rooms rely on the custom MLS / TreeKEM implementation in
    /// `static/js/mls/` (RFC 9420 ciphersuite 0x0002). The caller's requested
    /// `max_participants` is honoured, clamped to the 1..=20 range we tested
    /// against the IETF reference vectors.
    pub fn new(config: RoomConfig) -> Self {
        Self::new_with_creator_bootstrap(config).0
    }

    /// Creates a room and, for an MLS group, returns a one-time-disclosed
    /// capability that can mint fresh short-lived WebSocket JWTs for the
    /// room's stable creator relay identity.
    ///
    /// Only the SHA-256 digest is retained in `Room`. The caller must deliver
    /// the plaintext token to the creator and must not log it.
    pub fn new_with_creator_bootstrap(config: RoomConfig) -> (Self, Option<String>) {
        let max_participants = match config.room_type {
            RoomType::OneToOne => 2,
            RoomType::Group => config.max_participants.clamp(2, 20),
        };

        let now = Utc::now();
        let (
            creator_connection_id,
            creator_bootstrap_hash,
            creator_bootstrap_token,
            creator_control_ready,
        ) = match config.room_type {
            RoomType::OneToOne => (None, None, None, true),
            RoomType::Group => {
                let mut token_bytes = [0u8; CREATOR_BOOTSTRAP_TOKEN_BYTES];
                OsRng.fill_bytes(&mut token_bytes);
                let token = URL_SAFE_NO_PAD.encode(token_bytes);
                let digest: [u8; 32] = Sha256::digest(token_bytes).into();
                (Some(Uuid::new_v4()), Some(digest), Some(token), false)
            }
        };

        (
            Self {
                id: Uuid::new_v4(),
                room_type: config.room_type,
                ttl_minutes: config.ttl_minutes,
                created_at: now,
                last_activity: now,
                max_participants,
                participant_ids: HashSet::new(),
                creator_connection_id,
                creator_bootstrap_hash,
                creator_bootstrap_generation: 1,
                creator_control_ready,
            },
            creator_bootstrap_token,
        )
    }

    /// Constant-time verification of the creator bootstrap capability.
    pub fn verify_creator_bootstrap(&self, token: &str) -> bool {
        let Some(expected_hash) = self.creator_bootstrap_hash else {
            return false;
        };
        if token.len() != CREATOR_BOOTSTRAP_TOKEN_LEN {
            return false;
        }
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(token) else {
            return false;
        };
        if decoded.len() != CREATOR_BOOTSTRAP_TOKEN_BYTES
            || URL_SAFE_NO_PAD.encode(&decoded) != token
        {
            return false;
        }
        let actual_hash: [u8; 32] = Sha256::digest(&decoded).into();
        bool::from(actual_hash.ct_eq(&expected_hash))
    }

    /// Permanently revoke the pre-Connected recovery capability after the
    /// creator proves receipt of ordered group state with its first MLS ACK.
    pub fn consume_creator_bootstrap(&mut self) {
        if self.creator_bootstrap_hash.take().is_some() {
            self.creator_bootstrap_generation = self.creator_bootstrap_generation.saturating_add(1);
        }
    }

    pub fn creator_bootstrap_generation(&self) -> u64 {
        self.creator_bootstrap_generation
    }

    pub fn creator_bootstrap_is_live_at_generation(&self, generation: u64) -> bool {
        self.creator_bootstrap_hash.is_some() && self.creator_bootstrap_generation == generation
    }

    pub fn creator_control_ready(&self) -> bool {
        self.creator_control_ready
    }

    pub fn mark_creator_control_ready(&mut self, connection_id: Uuid) -> bool {
        if self.creator_connection_id != Some(connection_id)
            || !self.participant_ids.contains(&connection_id)
        {
            return false;
        }
        self.creator_control_ready = true;
        true
    }

    /// Returns the stable relay identity assigned to a group-room creator.
    pub fn creator_connection_id(&self) -> Option<Uuid> {
        self.creator_connection_id
    }

    /// Checks whether the room has expired
    ///
    /// Uses Hybrid TTL with two layers of protection:
    /// 1. Absolute TTL: Room ALWAYS expires after ttl_minutes from creation (HARD LIMIT)
    /// 2. Sliding TTL: Before absolute limit, room expires after ttl_minutes of inactivity
    ///
    /// This design:
    /// - Extends lifetime of active conversations (sliding window)
    /// - Prevents "immortal" rooms (absolute hard cap enforced)
    /// - Guarantees automatic data destruction (ephemeral by design)
    pub fn is_expired(&self) -> bool {
        let now = Utc::now();
        let ttl_duration = Duration::minutes(self.ttl_minutes as i64);

        // LAYER 1: Absolute TTL (HARD LIMIT)
        // Room ALWAYS expires after ttl_minutes from creation, regardless of activity
        // This enforces the "ephemeral by design" principle
        let absolute_expiry = self.created_at + ttl_duration;

        #[cfg(debug_assertions)]
        {
            let time_since_creation = now.signed_duration_since(self.created_at);
            let time_since_activity = now.signed_duration_since(self.last_activity);
            tracing::debug!(
                "Room expiry check - ID: {}, TTL: {}min, Created: {} ago, Last activity: {} ago, Absolute expiry: {} from now",
                self.id,
                self.ttl_minutes,
                time_since_creation.num_seconds(),
                time_since_activity.num_seconds(),
                absolute_expiry.signed_duration_since(now).num_seconds()
            );
        }

        // Hard limit: if absolute TTL has passed, room is DEAD
        if now >= absolute_expiry {
            #[cfg(debug_assertions)]
            tracing::debug!("Room {} has EXPIRED (absolute hard limit)", self.id);
            return true;
        }

        // LAYER 2: Sliding TTL (before absolute limit)
        // Before absolute limit is reached, room expires if inactive for ttl_minutes
        let sliding_expiry = self.last_activity + ttl_duration;
        let is_expired = now >= sliding_expiry;

        #[cfg(debug_assertions)]
        if is_expired {
            tracing::debug!("Room {} has EXPIRED (sliding TTL - inactive)", self.id);
        } else {
            tracing::debug!("Room {} is valid (active within sliding TTL)", self.id);
        }

        is_expired
    }

    /// Updates the last-activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Adds a participant to the room
    pub fn add_participant(&mut self, participant_id: Uuid) -> bool {
        if self.participant_ids.contains(&participant_id) {
            return false;
        }
        let is_creator = self.creator_connection_id == Some(participant_id);
        if (is_creator && self.is_full()) || (!is_creator && self.is_full_for_non_creator()) {
            return false;
        }
        self.participant_ids.insert(participant_id)
    }

    /// Removes a participant from the room
    pub fn remove_participant(&mut self, participant_id: &Uuid) -> bool {
        self.participant_ids.remove(participant_id)
    }

    /// Counts active participants
    pub fn participant_count(&self) -> usize {
        self.participant_ids.len()
    }

    /// Checks whether the room is full
    pub fn is_full(&self) -> bool {
        self.participant_ids.len() >= self.max_participants
    }

    /// Checks whether a fresh ordinary participant can be admitted without
    /// consuming the stable group creator's reserved slot.
    ///
    /// HTTP room-page routing deliberately uses `is_full()` instead: it cannot
    /// see the creator capability and must not hide the page from a creator
    /// who still owns the final reserved slot.
    pub fn is_full_for_non_creator(&self) -> bool {
        if self.creator_connection_id.is_some() && !self.creator_control_ready {
            // The creator must establish the first ordered-control boundary.
            // Otherwise an early joiner could publish a one-shot KeyPackage
            // before the creator opens its fresh stream, causing the creator
            // to skip a control the relay will not accept a second time.
            return true;
        }
        self.participant_ids.len() >= self.max_participants
    }
}

/// Response returned when a room is created
#[derive(Debug, Serialize)]
pub struct CreateRoomResponse {
    pub room_id: Uuid,
    pub room_type: RoomType,
    pub ttl_minutes: u32,
    pub max_participants: usize,

    /// WebSocket authentication token (optional)
    /// Included for room creator to avoid second PoW challenge
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_token: Option<String>,

    /// Pre-allocated connection ID for WebSocket (optional)
    /// Matches the connection_id in the JWT token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<Uuid>,

    /// Group-creator capability used to mint replacement one-shot WebSocket
    /// JWTs for the stable creator relay identity until room expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator_bootstrap_token: Option<String>,

    /// Wire-protocol version advertised by this server (v1 gate).
    /// Always sent, regardless of whether ws_token is present, so the client
    /// can reject a v0 server even on the creator-optimization path.
    pub protocol_version: u8,

    /// WebSocket subprotocols the server will negotiate.
    pub supported_subprotocols: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_newly_created_room_is_not_expired() {
        // Test 1:1 room
        let config_1to1 = RoomConfig {
            room_type: RoomType::OneToOne,
            ttl_minutes: 30,
            max_participants: 10,
        };
        let room = Room::new(config_1to1);
        assert!(
            !room.is_expired(),
            "Newly created 1:1 room should not be expired"
        );
        assert!(
            room.creator_connection_id().is_none(),
            "one-to-one rooms must not carry an MLS creator binding"
        );
        assert!(
            !room.verify_creator_bootstrap("A"),
            "one-to-one rooms must not accept creator bootstrap capabilities"
        );

        // Test group room
        let config_group = RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 10,
        };
        let room = Room::new(config_group);
        assert!(
            !room.is_expired(),
            "Newly created group room should not be expired"
        );
        assert!(
            room.creator_connection_id().is_some(),
            "group rooms allocate their stable creator identity at construction"
        );
    }

    #[test]
    fn creator_bootstrap_is_random_canonical_and_verified_constant_time() {
        let (room, token) = Room::new_with_creator_bootstrap(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let token = token.expect("group room returns its creator bootstrap capability");
        let decoded = URL_SAFE_NO_PAD
            .decode(&token)
            .expect("creator bootstrap token is canonical base64url");
        assert_eq!(decoded.len(), CREATOR_BOOTSTRAP_TOKEN_BYTES);
        assert_eq!(URL_SAFE_NO_PAD.encode(decoded), token);
        assert!(room.verify_creator_bootstrap(&token));

        let (other_room, other_token) = Room::new_with_creator_bootstrap(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 4,
        });
        let other_token = other_token.expect("second group bootstrap capability");
        assert_ne!(token, other_token, "creator capabilities must be random");
        assert!(!room.verify_creator_bootstrap(&other_token));
        assert!(!other_room.verify_creator_bootstrap(&token));
        assert!(!room.verify_creator_bootstrap(&(token.clone() + "=")));
    }

    #[test]
    fn group_admission_requires_creator_before_other_participants() {
        let mut room = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 60,
            max_participants: 2,
        });
        let creator = room
            .creator_connection_id()
            .expect("group room has creator identity");
        let first_noncreator = Uuid::new_v4();
        let second_noncreator = Uuid::new_v4();

        assert!(
            !room.is_full(),
            "an empty room still has physical capacity for its creator"
        );
        assert!(
            room.is_full_for_non_creator(),
            "ordinary admission remains closed until the creator establishes the stream"
        );
        assert!(
            !room.add_participant(first_noncreator),
            "a non-creator cannot establish the first group control boundary"
        );
        assert!(
            room.add_participant(creator),
            "the creator establishes the first participant reservation"
        );
        assert!(
            room.is_full_for_non_creator(),
            "creator presence alone does not open ordinary admission"
        );
        assert!(
            room.mark_creator_control_ready(creator),
            "the creator opens admission only after its durable control boundary"
        );
        assert!(
            !room.is_full_for_non_creator(),
            "one ordinary participant can join after creator control readiness"
        );
        assert!(
            room.add_participant(first_noncreator),
            "the first non-creator joins after creator admission"
        );
        assert!(
            !room.add_participant(second_noncreator),
            "the physical room cap still rejects a second non-creator"
        );
        assert_eq!(room.participant_count(), 2);
        assert!(room.is_full());
        assert!(room.is_full_for_non_creator());
    }

    #[test]
    fn group_rooms_honour_requested_max_participants_within_bounds() {
        // Group rooms must keep the caller's requested max_participants,
        // clamped to [2, 20]. Previously group rooms were silently capped
        // to 2; the MLS / TreeKEM implementation lifts that cap.
        for requested in [2usize, 5, 10, 20] {
            let cfg = RoomConfig {
                room_type: RoomType::Group,
                ttl_minutes: 30,
                max_participants: requested,
            };
            let room = Room::new(cfg);
            assert_eq!(
                room.max_participants, requested,
                "group room honours requested max_participants={}",
                requested,
            );
        }

        // Clamp: below 2 → 2, above 20 → 20.
        let low = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 30,
            max_participants: 1,
        });
        assert_eq!(low.max_participants, 2, "group room clamps min to 2");
        let high = Room::new(RoomConfig {
            room_type: RoomType::Group,
            ttl_minutes: 30,
            max_participants: 100,
        });
        assert_eq!(high.max_participants, 20, "group room clamps max to 20");

        // OneToOne still pinned to 2 regardless of input.
        let one_to_one = Room::new(RoomConfig {
            room_type: RoomType::OneToOne,
            ttl_minutes: 30,
            max_participants: 15,
        });
        assert_eq!(
            one_to_one.max_participants, 2,
            "one_to_one rooms are always 2 participants",
        );
    }

    #[test]
    fn test_room_with_minimum_ttl_is_not_expired() {
        let config = RoomConfig {
            room_type: RoomType::OneToOne,
            ttl_minutes: 1, // Minimum TTL
            max_participants: 10,
        };
        let room = Room::new(config);
        assert!(
            !room.is_expired(),
            "Room with 1 minute TTL should not be expired immediately"
        );
    }

    #[test]
    fn test_room_expires_after_ttl() {
        let config = RoomConfig {
            room_type: RoomType::OneToOne,
            ttl_minutes: 30,
            max_participants: 10,
        };
        let mut room = Room::new(config);

        // Manually set created_at to 31 minutes ago
        room.created_at = Utc::now() - Duration::minutes(31);
        room.last_activity = room.created_at;

        assert!(
            room.is_expired(),
            "Room should be expired after TTL has passed"
        );
    }

    #[test]
    fn test_room_with_recent_activity_extends_lifetime_within_absolute_limit() {
        let config = RoomConfig {
            room_type: RoomType::OneToOne,
            ttl_minutes: 30,
            max_participants: 10,
        };
        let mut room = Room::new(config);

        // Set created_at to 20 minutes ago (still within absolute TTL)
        room.created_at = Utc::now() - Duration::minutes(20);
        // Update activity to 5 minutes ago (within sliding TTL)
        room.last_activity = Utc::now() - Duration::minutes(5);

        assert!(
            !room.is_expired(),
            "Room should not be expired if within absolute TTL and activity is recent"
        );
    }

    #[test]
    fn test_room_expires_after_absolute_ttl_regardless_of_activity() {
        let config = RoomConfig {
            room_type: RoomType::OneToOne,
            ttl_minutes: 30,
            max_participants: 10,
        };
        let mut room = Room::new(config);

        // Set created_at to 31 minutes ago (beyond absolute TTL)
        room.created_at = Utc::now() - Duration::minutes(31);
        // Recent activity should not override the absolute TTL boundary
        room.last_activity = Utc::now() - Duration::seconds(1);

        assert!(
            room.is_expired(),
            "Room should expire after the absolute TTL, even with recent activity"
        );
    }

    #[test]
    fn test_room_expires_after_absolute_and_sliding_ttl() {
        let config = RoomConfig {
            room_type: RoomType::OneToOne,
            ttl_minutes: 30,
            max_participants: 10,
        };
        let mut room = Room::new(config);

        // Set created_at to 35 minutes ago (beyond absolute TTL)
        room.created_at = Utc::now() - Duration::minutes(35);
        // Set last_activity to 35 minutes ago (beyond sliding TTL)
        room.last_activity = Utc::now() - Duration::minutes(35);

        assert!(
            room.is_expired(),
            "Room should be expired after both absolute and sliding TTL have passed"
        );
    }

    #[test]
    fn test_room_participant_management() {
        let config = RoomConfig {
            room_type: RoomType::OneToOne,
            ttl_minutes: 30,
            max_participants: 10,
        };
        let mut room = Room::new(config);

        let participant1 = Uuid::new_v4();
        let participant2 = Uuid::new_v4();
        let participant3 = Uuid::new_v4();

        // Add first participant
        assert!(room.add_participant(participant1));
        assert_eq!(room.participant_count(), 1);

        // Add second participant
        assert!(room.add_participant(participant2));
        assert_eq!(room.participant_count(), 2);
        assert!(
            room.is_full(),
            "1:1 room should be full with 2 participants"
        );

        // Try to add third participant (should fail)
        assert!(!room.add_participant(participant3));
        assert_eq!(room.participant_count(), 2);

        // Remove a participant
        assert!(room.remove_participant(&participant1));
        assert_eq!(room.participant_count(), 1);
        assert!(!room.is_full());
    }
}
