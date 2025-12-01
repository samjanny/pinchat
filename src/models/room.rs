use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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
    /// Planned for future group chat expansion
    #[allow(dead_code)]
    #[serde(default = "default_max_participants")]
    pub max_participants: usize,
}

fn default_max_participants() -> usize {
    20
}

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
}

impl Room {
    /// Creates a new room
    pub fn new(config: RoomConfig) -> Self {
        // Group chat support will be enabled after introducing secure group key exchange.
        // Until then, rooms are limited to two participants.
        let max_participants = 2;

        let now = Utc::now();

        Self {
            id: Uuid::new_v4(),
            room_type: config.room_type,
            ttl_minutes: config.ttl_minutes,
            created_at: now,
            last_activity: now,
            max_participants,
            participant_ids: HashSet::new(),
        }
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
        if self.participant_ids.len() >= self.max_participants {
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
