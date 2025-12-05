use crate::challenge_cache::ChallengeCache;
use crate::config::Config;
use crate::models::Room;
use crate::session::SessionStore;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use rand::RngCore;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use uuid::Uuid;

/// Error type for room creation failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomCreationError {
    /// Server has reached maximum room capacity
    AtCapacity,
}

/// Application state shared across all threads
#[derive(Clone)]
pub struct AppState {
    /// Map of active rooms: room_id -> Room
    pub rooms: Arc<DashMap<Uuid, Room>>,

    /// Map of WebSocket connections: connection_id -> room_id
    /// Used to know which room a connection belongs to
    pub connections: Arc<DashMap<Uuid, Uuid>>,

    /// Broadcast channels for each room: room_id -> Sender
    /// Uses tokio::sync::broadcast to distribute messages
    pub broadcast_channels: Arc<DashMap<Uuid, tokio::sync::broadcast::Sender<String>>>,

    /// Anti-replay: Cache of seen message hashes per room
    /// room_id -> Set<(payload_hash, timestamp)>
    /// Prevents same-room replay attacks and protects late joiners
    pub seen_message_hashes: Arc<DashMap<Uuid, HashSet<(String, DateTime<Utc>)>>>,

    /// Per-connection message rate limiting
    /// connection_id -> VecDeque<timestamp>
    /// Tracks message timestamps to enforce rate limits (e.g., 10 msg/sec)
    /// Prevents bandwidth exhaustion and client-side decryption DoS
    pub connection_message_timestamps: Arc<DashMap<Uuid, VecDeque<DateTime<Utc>>>>,

    /// PoW challenge cache indexed by HMAC(IP)
    /// Prevents offline challenge fabrication attacks
    pub challenge_cache: Arc<ChallengeCache>,

    /// Secret key for HMAC-SHA256(IP) hashing
    /// Generated randomly on each server boot to avoid cross-restart correlation
    /// Used by both the challenge cache and rate limiter for consistency
    pub ip_hash_secret: [u8; 32],

    /// Secret key for JWT signing (WebSocket authentication tokens)
    /// Generated randomly on each server boot
    /// Used to sign and verify WebSocket connection tokens
    pub jwt_secret: [u8; 32],

    /// Mutex to ensure atomic check+insert for room creation
    /// Prevents race condition where concurrent requests exceed max_rooms limit
    room_creation_lock: Arc<Mutex<()>>,

    /// Maximum number of concurrent rooms allowed (DoS protection)
    pub max_rooms: usize,

    /// Application configuration (rate limits, TTLs, etc.)
    pub config: Arc<Config>,

    /// Session store for authenticated users
    pub session_store: Arc<SessionStore>,

    /// Secret key for CSRF token signing
    /// Generated randomly on each server boot
    pub csrf_secret: [u8; 32],

    /// Cache of consumed JWT token IDs (jti) for single-use enforcement
    /// Maps jti -> expiration Instant (for cleanup)
    /// Prevents token replay attacks within the validity window
    pub consumed_tokens: Arc<DashMap<Uuid, Instant>>,
}

impl AppState {
    /// Creates a new AppState
    pub fn new(max_rooms: usize, config: Config) -> Self {
        // Generate random 32-byte secret key for HMAC(IP) hashing
        // New key on each server boot to prevent long-term linkage of client IPs
        let mut ip_hash_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ip_hash_secret);

        // Generate random 32-byte secret key for JWT signing
        let mut jwt_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut jwt_secret);

        // Generate random 32-byte secret key for CSRF token signing
        let mut csrf_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut csrf_secret);

        // Create session store with configured TTL
        let session_store = Arc::new(SessionStore::new(config.session_ttl_secs));

        tracing::info!("Generated new HMAC secret key (32 bytes)");
        tracing::info!("Generated new JWT secret key (32 bytes)");
        tracing::info!("Generated new CSRF secret key (32 bytes)");

        Self {
            rooms: Arc::new(DashMap::new()),
            connections: Arc::new(DashMap::new()),
            broadcast_channels: Arc::new(DashMap::new()),
            seen_message_hashes: Arc::new(DashMap::new()),
            connection_message_timestamps: Arc::new(DashMap::new()),
            challenge_cache: Arc::new(ChallengeCache::new(config.challenge_ttl_secs, 10_000)),
            ip_hash_secret,
            jwt_secret,
            room_creation_lock: Arc::new(Mutex::new(())),
            max_rooms,
            config: Arc::new(config),
            session_store,
            csrf_secret,
            consumed_tokens: Arc::new(DashMap::new()),
        }
    }

    /// Attempts to consume a JWT token (single-use enforcement)
    ///
    /// Returns true if the token was successfully consumed (first use),
    /// false if it was already consumed (replay attempt).
    ///
    /// # Arguments
    /// * `jti` - JWT ID to consume
    /// * `ttl_secs` - Token TTL for cleanup scheduling
    pub fn consume_token(&self, jti: Uuid, ttl_secs: u64) -> bool {
        use std::time::Duration;

        let expiration = Instant::now() + Duration::from_secs(ttl_secs);

        // Atomic insert - first writer wins, replays see Occupied immediately
        match self.consumed_tokens.entry(jti) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(expiration);
                true
            }
        }
    }

    /// Cleans up expired consumed tokens
    ///
    /// Should be called periodically to prevent memory growth.
    /// Removes tokens whose expiration time has passed.
    pub fn cleanup_consumed_tokens(&self) -> usize {
        let now = Instant::now();
        let before = self.consumed_tokens.len();

        self.consumed_tokens.retain(|_, expiration| *expiration > now);

        before - self.consumed_tokens.len()
    }

    /// Atomically creates a new room with capacity check
    ///
    /// This method ensures thread-safe room creation by:
    /// 1. Acquiring a lock on room creation
    /// 2. Checking capacity atomically
    /// 3. Inserting the room only if under capacity
    ///
    /// # Returns
    /// - `Ok(room_id)` if room was created successfully
    /// - `Err(RoomCreationError::AtCapacity)` if server is at max capacity
    ///
    /// # Thread Safety
    /// The mutex ensures that check+insert is atomic, preventing race conditions
    /// where concurrent requests could exceed max_rooms limit.
    pub fn try_create_room(&self, room: Room) -> Result<Uuid, RoomCreationError> {
        // Acquire lock for atomic check+insert (critical section)
        let _guard = self.room_creation_lock.lock().unwrap();

        // Atomic capacity check (inside lock)
        if self.rooms.len() >= self.max_rooms {
            return Err(RoomCreationError::AtCapacity);
        }

        // Atomic insert (inside lock)
        let room_id = room.id;

        // Create the broadcast channel for the room with dynamic buffer size
        // Buffer size scales with max_participants to reduce message loss:
        // - Small rooms (1:1): 100 messages buffer
        // - Medium rooms (10 users): 500 messages buffer
        // - Large rooms (50 users): 2500 messages buffer
        //
        // This mitigates buffer overflow when slow clients (for example, on
        // mobile 3G links) cannot consume messages fast enough during bursts.
        let buffer_size = (room.max_participants * 50).max(100);
        let (tx, _) = tokio::sync::broadcast::channel(buffer_size);

        #[cfg(debug_assertions)]
        tracing::debug!(
            "Created broadcast channel with buffer size {} for room with {} max participants",
            buffer_size,
            room.max_participants
        );

        self.rooms.insert(room_id, room);
        self.broadcast_channels.insert(room_id, tx);

        Ok(room_id)
        // Lock released automatically here
    }

    /// Removes a room and all its connections
    pub fn remove_room(&self, room_id: &Uuid) {
        // Remove every connection associated with the room
        self.connections.retain(|_, rid| rid != room_id);

        // Remove the broadcast channel
        self.broadcast_channels.remove(room_id);

        // Remove the message hash cache (anti-replay)
        self.seen_message_hashes.remove(room_id);

        // Remove the room
        self.rooms.remove(room_id);

        #[cfg(debug_assertions)]
        tracing::debug!("Room removed");
    }

    /// Adds a connection to a room
    pub fn add_connection(&self, connection_id: Uuid, room_id: Uuid) -> bool {
        if let Some(mut room) = self.rooms.get_mut(&room_id) {
            if room.add_participant(connection_id) {
                self.connections.insert(connection_id, room_id);
                room.update_activity();
                return true;
            }
        }
        false
    }

    /// Removes a connection from a room
    pub fn remove_connection(&self, connection_id: &Uuid) -> Option<Uuid> {
        if let Some((_, room_id)) = self.connections.remove(connection_id) {
            if let Some(mut room) = self.rooms.get_mut(&room_id) {
                room.remove_participant(connection_id);
                room.update_activity();
            }

            // Cleanup rate limiting timestamps for this connection
            self.connection_message_timestamps.remove(connection_id);

            Some(room_id)
        } else {
            None
        }
    }

    /// Gets the number of participants in a room
    pub fn get_participant_count(&self, room_id: &Uuid) -> usize {
        self.rooms
            .get(room_id)
            .map(|room| room.participant_count())
            .unwrap_or(0)
    }

    /// Counts the total number of active rooms (debug/statistics only)
    #[allow(dead_code)]
    #[cfg(debug_assertions)]
    pub fn total_rooms(&self) -> usize {
        self.rooms.len()
    }

    /// Counts the total number of active connections (debug/statistics only)
    #[allow(dead_code)]
    #[cfg(debug_assertions)]
    pub fn total_connections(&self) -> usize {
        self.connections.len()
    }

    /// Calculates current server usage percentage
    ///
    /// # Returns
    /// Usage percentage (0-100+)
    #[allow(dead_code)]
    pub fn calculate_usage_percent(&self) -> usize {
        if self.max_rooms == 0 {
            return 0;
        }
        (self.rooms.len() * 100) / self.max_rooms
    }
}
