use crate::challenge_cache::ChallengeCache;
use crate::config::Config;
use crate::models::Room;
use crate::session::SessionStore;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use rand::RngCore;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use uuid::Uuid;

/// Error type for room creation failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomCreationError {
    /// Server has reached maximum room capacity
    AtCapacity,
}

#[cfg(test)]
mod resource_bound_tests {
    use super::{MlsControlPayload, MlsControlPayloadInner, ReplayCache};
    use chrono::{Duration, Utc};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn replay_cache_has_bounded_fifo_eviction_and_expiry() {
        let mut cache = ReplayCache::default();
        let now = Utc::now();
        let cutoff = now - Duration::minutes(1);
        assert!(cache.insert_if_new("a".into(), now, cutoff, 2));
        assert!(!cache.insert_if_new("a".into(), now, cutoff, 2));
        assert!(cache.insert_if_new("b".into(), now, cutoff, 2));
        assert!(
            !cache.insert_if_new("b".into(), now, cutoff, 2),
            "a duplicate at capacity must not evict a different entry"
        );
        assert!(cache.contains("a") && cache.contains("b"));
        assert!(cache.insert_if_new("c".into(), now + Duration::seconds(1), cutoff, 2,));
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains("a") && cache.contains("b") && cache.contains("c"));
        assert!(
            cache.insert_if_new("a".into(), now + Duration::seconds(2), cutoff, 2,),
            "oldest entry was evicted without sorting the cache"
        );
        assert_eq!(cache.len(), 2);

        cache.remove("a");
        assert!(cache.insert_if_new("a".into(), now + Duration::seconds(2), cutoff, 2,));
        assert!(cache.contains("a"));

        let future = now + Duration::minutes(3);
        assert!(cache.insert_if_new("fresh".into(), future, future - Duration::minutes(1), 2,));
        assert_eq!(cache.len(), 1, "expired entries are removed incrementally");
    }

    #[test]
    fn mls_control_bytes_follow_the_final_shared_clone() {
        let retained_bytes = 7;
        let global_bytes = Arc::new(AtomicUsize::new(retained_bytes));
        let payload = MlsControlPayload(Arc::new(MlsControlPayloadInner {
            json: "control".to_string(),
            retained_bytes,
            global_bytes: global_bytes.clone(),
        }));
        let replay_clone = payload.clone();

        drop(payload);
        assert_eq!(
            global_bytes.load(Ordering::Acquire),
            retained_bytes,
            "dropping the log clone must not release a live replay clone",
        );
        drop(replay_clone);
        assert_eq!(
            global_bytes.load(Ordering::Acquire),
            0,
            "the final clone releases the global control-log reservation",
        );
    }
}

/// Result of admitting a WebSocket relay identity into a room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionAdmission {
    /// First successful socket for this participant ID.
    New,
    /// A valid resume token reclaimed an ID still reserved in the grace window.
    Resumed,
}

const BROADCAST_CHANNEL_ENTRIES: usize = 8;
const MAX_BROADCAST_ROOM_BYTES: usize = 4 * 1024 * 1024;
const MAX_BROADCAST_GLOBAL_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_MLS_CONTROL_LOG_ENTRIES: usize = 256;
const MAX_MLS_CONTROL_LOG_BYTES: usize = 2 * 1024 * 1024;
const MAX_MLS_CONTROL_LOG_GLOBAL_BYTES: usize = 64 * 1024 * 1024;
// Ordinary MLS envelopes may not consume the final lifecycle slots. A
// UserLeft that cannot be durably sequenced would leave relay membership and
// the authenticated MLS roster disagreeing about who is still authorised.
pub(crate) const MLS_LIFECYCLE_RESERVED_ENTRIES: usize = 32;
const MLS_LIFECYCLE_RESERVED_BYTES: usize = 128 * 1024;
const MAX_PENDING_MLS_WELCOME_CORRELATIONS: usize = 64;
const MAX_CONSUMED_MLS_KEY_PACKAGE_REFS: usize = 4096;

#[derive(Debug)]
struct BroadcastPayloadInner {
    json: String,
    retained_bytes: usize,
    room_bytes: Arc<AtomicUsize>,
    global_bytes: Arc<AtomicUsize>,
}

impl Drop for BroadcastPayloadInner {
    fn drop(&mut self) {
        self.room_bytes
            .fetch_sub(self.retained_bytes, Ordering::AcqRel);
        self.global_bytes
            .fetch_sub(self.retained_bytes, Ordering::AcqRel);
    }
}

/// One shared room-broadcast value. The channel ring and every receiver clone
/// share the same JSON allocation; aggregate byte counters are released only
/// when the final clone disappears.
#[derive(Debug, Clone)]
pub struct BroadcastPayload(Arc<BroadcastPayloadInner>);

impl BroadcastPayload {
    pub fn as_str(&self) -> &str {
        &self.0.json
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastError {
    MissingRoom,
    RoomByteCapacity,
    GlobalByteCapacity,
}

#[derive(Debug, Default)]
pub struct ReplayCache {
    by_hash: HashMap<String, DateTime<Utc>>,
    insertion_order: VecDeque<(String, DateTime<Utc>)>,
}

impl ReplayCache {
    /// Returns true only for a new hash which was inserted. Expiry and
    /// capacity eviction are O(1) amortized; no attacker-controlled sort or
    /// full-set scan occurs on the message path.
    pub fn insert_if_new(
        &mut self,
        hash: String,
        now: DateTime<Utc>,
        cutoff: DateTime<Utc>,
        max_entries: usize,
    ) -> bool {
        while self
            .insertion_order
            .front()
            .map(|(_, timestamp)| *timestamp <= cutoff)
            .unwrap_or(false)
        {
            self.pop_oldest();
        }
        if self.by_hash.contains_key(&hash) {
            return false;
        }
        while self.by_hash.len() >= max_entries {
            if self.insertion_order.is_empty() {
                break;
            }
            self.pop_oldest();
        }
        self.by_hash.insert(hash.clone(), now);
        self.insertion_order.push_back((hash, now));
        true
    }

    pub fn remove(&mut self, hash: &str) {
        if self.by_hash.remove(hash).is_some()
            && self
                .insertion_order
                .back()
                .map(|(queued_hash, _)| queued_hash == hash)
                .unwrap_or(false)
        {
            // Rollback is called immediately after a failed broadcast while
            // the cache guard is still held, so the inserted entry is the
            // queue tail. Removing it avoids leaving a stale timestamp that
            // could later collide with an identical retry timestamp.
            self.insertion_order.pop_back();
        }
    }

    fn pop_oldest(&mut self) {
        let Some((front_hash, timestamp)) = self.insertion_order.pop_front() else {
            return;
        };
        if self.by_hash.get(&front_hash).copied() == Some(timestamp) {
            self.by_hash.remove(&front_hash);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_hash.len()
    }

    #[cfg(test)]
    fn contains(&self, hash: &str) -> bool {
        self.by_hash.contains_key(hash)
    }
}

#[derive(Debug, Default)]
struct RoomTrafficWindow {
    entries: VecDeque<(DateTime<Utc>, Uuid, usize)>,
    retained_bytes: usize,
}

#[derive(Debug)]
struct MlsControlPayloadInner {
    json: String,
    retained_bytes: usize,
    global_bytes: Arc<AtomicUsize>,
}

impl Drop for MlsControlPayloadInner {
    fn drop(&mut self) {
        self.global_bytes
            .fetch_sub(self.retained_bytes, Ordering::AcqRel);
    }
}

/// Shared ordered-control JSON whose global byte reservation follows the
/// final log/replay clone rather than an ACK or room-removal race.
#[derive(Debug, Clone)]
pub struct MlsControlPayload(Arc<MlsControlPayloadInner>);

impl MlsControlPayload {
    pub fn as_str(&self) -> &str {
        &self.0.json
    }
}

impl AsRef<str> for MlsControlPayload {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone)]
struct MlsControlEntry {
    seq: u64,
    appended_at: Instant,
    json: MlsControlPayload,
}

#[derive(Debug, Clone, Copy)]
struct MlsControlAcknowledgement {
    seq: u64,
}

#[derive(Debug, Default)]
struct MlsControlLog {
    head_seq: u64,
    retained_bytes: usize,
    entries: VecDeque<MlsControlEntry>,
    acknowledged: HashMap<Uuid, MlsControlAcknowledgement>,
    key_package_by_sender: HashMap<Uuid, String>,
    key_package_refs: HashMap<String, Uuid>,
    consumed_key_package_refs: HashSet<String>,
    pending_welcome_by_commit: HashMap<(Uuid, String), String>,
    pending_welcome_order: VecDeque<(Uuid, String)>,
}

/// One retained ordered MLS-control entry. Replays expose the sequence
/// separately so the WebSocket layer can send bounded windows and require a
/// cumulative ACK before releasing the next window.
pub struct MlsControlReplayEntry {
    pub seq: u64,
    pub json: MlsControlPayload,
}

/// A stable participant's ordered MLS-control replay window.
pub struct MlsControlStream {
    pub cursor: u64,
    pub through_seq: u64,
    pub replay: Vec<MlsControlReplayEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsControlCursorError {
    MissingRoom,
    CursorAhead,
    CursorExpired,
    CursorRegressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsControlAppendError {
    MissingRoom,
    SequenceExhausted,
    SerializationFailed,
    CapacityExceeded,
    BroadcastCapacity,
    DuplicateKeyPackage,
    CommitCorrelationConflict,
    WelcomeNotCorrelated,
    UnknownKeyPackageRef,
    DuplicateKeyPackageRef,
}

/// Relay-visible admission metadata for an ordered MLS envelope. The relay
/// remains blind to cryptographic contents; these fields only bind the
/// transport-level Add Commit / Welcome pair and enforce one KeyPackage per
/// stable participant admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsControlAdmission {
    Ordinary,
    KeyPackage {
        sender_id: Uuid,
        key_package_ref: String,
    },
    AddCommit {
        sender_id: Uuid,
        commit_ref: String,
        key_package_ref: String,
    },
    Welcome {
        sender_id: Uuid,
        commit_ref: String,
        key_package_ref: String,
    },
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
    pub broadcast_channels: Arc<DashMap<Uuid, tokio::sync::broadcast::Sender<BroadcastPayload>>>,
    broadcast_room_bytes: Arc<DashMap<Uuid, Arc<AtomicUsize>>>,
    broadcast_global_bytes: Arc<AtomicUsize>,

    /// Ordered, bounded replay log for MLS group-control envelopes
    /// (UserJoined/UserLeft, KeyPackage, Proposal, Commit, Welcome). MLS
    /// PrivateMessages deliberately remain ephemeral. Each stable relay
    /// participant acknowledges the highest sequence it has applied; a
    /// resumed socket replays from that cursor.
    mls_control_logs: Arc<DashMap<Uuid, Arc<Mutex<MlsControlLog>>>>,
    mls_control_global_bytes: Arc<AtomicUsize>,

    /// Anti-replay: bounded hash lookup + FIFO insertion queue per room.
    /// Prevents same-room replay attacks without attacker-controlled sorting.
    pub seen_message_hashes: Arc<DashMap<Uuid, ReplayCache>>,
    room_traffic_windows: Arc<DashMap<Uuid, RoomTrafficWindow>>,

    /// Per-connection message rate limiting
    /// connection_id -> VecDeque<timestamp>
    /// Tracks message timestamps to enforce rate limits (e.g., 10 msg/sec)
    /// Prevents bandwidth exhaustion and client-side decryption DoS
    pub connection_message_timestamps: Arc<DashMap<Uuid, VecDeque<DateTime<Utc>>>>,

    /// Per-connection MLS Commit rate limiting (separate, much tighter).
    /// Commits are 10²-10³× more expensive than application messages on
    /// the receiver (TreeKEM path verification + signature + transcript
    /// hash + key schedule), so the global msg_rate_limit is too generous
    /// when applied to broadcast Commits. Capped at a few per minute
    /// (see `commit_rate_limit` in the config) to bound the CPU cost a
    /// single peer can inflict on every other room member. Only structurally
    /// classified Commits consume this budget; Proposals do not.
    pub connection_commit_timestamps: Arc<DashMap<Uuid, VecDeque<DateTime<Utc>>>>,
    pub connection_proposal_timestamps: Arc<DashMap<Uuid, VecDeque<DateTime<Utc>>>>,

    /// Per-connection global frame timestamps.
    /// Applied to EVERY text frame (ECDH, message, image, unknown, malformed),
    /// so attackers cannot bypass the stricter message/image rate limiter by
    /// flooding handshake or garbage frames.
    pub connection_frame_timestamps: Arc<DashMap<Uuid, VecDeque<DateTime<Utc>>>>,

    /// Per-connection protocol-error counter.
    /// Incremented on parse failures, unknown msg_type, and oversized ECDH
    /// payloads. Connection is closed past `config.protocol_error_limit`.
    pub connection_protocol_errors: Arc<DashMap<Uuid, u32>>,

    /// Per-connection ECDH-frame timestamps.
    /// Each `ecdh_public_key` frame the server relays triggers signature
    /// verification + key import + Double Ratchet reinit on the peer client.
    /// Without a stricter cap than `frame_rate_limit`, an authenticated peer
    /// could exhaust the receiver's CPU under cover of normal frame budget.
    pub connection_ecdh_timestamps: Arc<DashMap<Uuid, VecDeque<DateTime<Utc>>>>,

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
            broadcast_room_bytes: Arc::new(DashMap::new()),
            broadcast_global_bytes: Arc::new(AtomicUsize::new(0)),
            mls_control_logs: Arc::new(DashMap::new()),
            mls_control_global_bytes: Arc::new(AtomicUsize::new(0)),
            seen_message_hashes: Arc::new(DashMap::new()),
            room_traffic_windows: Arc::new(DashMap::new()),
            connection_message_timestamps: Arc::new(DashMap::new()),
            connection_commit_timestamps: Arc::new(DashMap::new()),
            connection_proposal_timestamps: Arc::new(DashMap::new()),
            connection_frame_timestamps: Arc::new(DashMap::new()),
            connection_protocol_errors: Arc::new(DashMap::new()),
            connection_ecdh_timestamps: Arc::new(DashMap::new()),
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

        self.consumed_tokens
            .retain(|_, expiration| *expiration > now);

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

        // Ephemeral application traffic is intentionally a small ring. Slow
        // clients are disconnected on lag and group controls are recovered
        // from the separate ordered replay log. Scaling this count by room
        // size previously allowed image-sized payloads to retain hundreds of
        // MiB per room.
        let buffer_size = BROADCAST_CHANNEL_ENTRIES;
        let (tx, _) = tokio::sync::broadcast::channel(buffer_size);

        #[cfg(debug_assertions)]
        tracing::debug!(
            "Created broadcast channel with buffer size {} for room with {} max participants",
            buffer_size,
            room.max_participants
        );

        self.rooms.insert(room_id, room);
        self.broadcast_channels.insert(room_id, tx);
        self.broadcast_room_bytes
            .insert(room_id, Arc::new(AtomicUsize::new(0)));
        self.mls_control_logs
            .insert(room_id, Arc::new(Mutex::new(MlsControlLog::default())));

        Ok(room_id)
        // Lock released automatically here
    }

    /// Removes a room and all its connections
    pub fn remove_room(&self, room_id: &Uuid) {
        // Remove every connection associated with the room and all of its
        // per-connection limiter state. The socket tasks may run their final
        // cleanup after this method; removing the connection mapping first
        // would otherwise make that cleanup a no-op and leak these entries
        // forever across room churn.
        let mut connection_ids: HashSet<Uuid> = self
            .rooms
            .get(room_id)
            .map(|room| room.participant_ids.iter().copied().collect())
            .unwrap_or_default();
        connection_ids.extend(
            self.connections
                .iter()
                .filter(|entry| entry.value() == room_id)
                .map(|entry| *entry.key()),
        );
        for connection_id in connection_ids {
            self.connections.remove(&connection_id);
            self.connection_message_timestamps.remove(&connection_id);
            self.connection_commit_timestamps.remove(&connection_id);
            self.connection_proposal_timestamps.remove(&connection_id);
            self.connection_frame_timestamps.remove(&connection_id);
            self.connection_protocol_errors.remove(&connection_id);
            self.connection_ecdh_timestamps.remove(&connection_id);
        }

        // Remove the broadcast channel
        self.broadcast_channels.remove(room_id);
        self.broadcast_room_bytes.remove(room_id);
        self.mls_control_logs.remove(room_id);

        // Remove the message hash cache (anti-replay)
        self.seen_message_hashes.remove(room_id);
        self.room_traffic_windows.remove(room_id);

        // Remove the room
        self.rooms.remove(room_id);

        #[cfg(debug_assertions)]
        tracing::debug!("Room removed");
    }

    /// Admit one active socket. An existing participant ID may only be
    /// reclaimed by a short-lived WebSocket token explicitly marked as a
    /// resume. A second simultaneously active socket for the same ID is always
    /// rejected, even if it has a valid bearer credential.
    pub fn add_connection(
        &self,
        connection_id: Uuid,
        room_id: Uuid,
        allow_resume: bool,
    ) -> Option<ConnectionAdmission> {
        match self.connections.entry(connection_id) {
            Entry::Occupied(_) => None,
            Entry::Vacant(active_slot) => {
                let mut room = self.rooms.get_mut(&room_id)?;
                let admission = if allow_resume {
                    // Fail closed if the grace reservation disappeared after
                    // the resume upgrade token was minted but before the
                    // WebSocket was admitted. A resume credential must never
                    // silently turn into a fresh participant admission.
                    if !room.participant_ids.contains(&connection_id) {
                        return None;
                    }
                    ConnectionAdmission::Resumed
                } else {
                    if room.participant_ids.contains(&connection_id) {
                        return None;
                    }
                    if !room.add_participant(connection_id) {
                        return None;
                    }
                    ConnectionAdmission::New
                };
                active_slot.insert(room_id);
                room.update_activity();
                Some(admission)
            }
        }
    }

    /// Detach the active socket while retaining its participant reservation.
    /// Per-identity rate-limit state is deliberately retained: a resumed
    /// participant must not gain a fresh Commit/message budget by cycling its
    /// transport. Membership and limiter state are removed together after the
    /// reconnect grace period.
    pub fn detach_connection(&self, connection_id: &Uuid) -> Option<Uuid> {
        if let Some((_, room_id)) = self.connections.remove(connection_id) {
            if let Some(mut room) = self.rooms.get_mut(&room_id) {
                room.update_activity();
            }
            Some(room_id)
        } else {
            None
        }
    }

    /// Remove a grace-reserved participant only if no newer active socket has
    /// reclaimed the same stable ID. Holding the vacant DashMap entry prevents
    /// a reconnect from racing between the active check and room removal.
    pub fn finalize_disconnection(
        &self,
        connection_id: &Uuid,
        expected_room_id: Uuid,
    ) -> Option<usize> {
        match self.connections.entry(*connection_id) {
            Entry::Occupied(_) => None,
            Entry::Vacant(_reservation) => {
                let mut room = self.rooms.get_mut(&expected_room_id)?;
                if !room.remove_participant(connection_id) {
                    return None;
                }
                room.update_activity();
                let participant_count = room.participant_count();
                drop(room);

                self.connection_message_timestamps.remove(connection_id);
                self.connection_commit_timestamps.remove(connection_id);
                self.connection_proposal_timestamps.remove(connection_id);
                self.connection_frame_timestamps.remove(connection_id);
                self.connection_protocol_errors.remove(connection_id);
                self.connection_ecdh_timestamps.remove(connection_id);
                self.forget_mls_control_participant(expected_room_id, connection_id);

                Some(participant_count)
            }
        }
    }

    /// Immediate removal for setup failures and explicit administrative
    /// cleanup paths that must not retain a reconnect reservation.
    pub fn remove_connection(&self, connection_id: &Uuid) -> Option<Uuid> {
        let room_id = self.detach_connection(connection_id)?;
        let _ = self.finalize_disconnection(connection_id, room_id);
        Some(room_id)
    }

    /// Immediately and atomically evict a stable participant whether its
    /// socket is active or currently grace-reserved. Holding the connection
    /// map entry across room removal prevents a resume from reclaiming the ID
    /// between those two state changes.
    pub fn evict_participant(&self, connection_id: &Uuid, expected_room_id: Uuid) -> Option<usize> {
        match self.connections.entry(*connection_id) {
            Entry::Occupied(active) => {
                if *active.get() != expected_room_id {
                    return None;
                }
                let participant_count =
                    self.remove_participant_state(connection_id, expected_room_id)?;
                active.remove();
                Some(participant_count)
            }
            Entry::Vacant(_reservation) => {
                self.remove_participant_state(connection_id, expected_room_id)
            }
        }
    }

    fn remove_participant_state(
        &self,
        connection_id: &Uuid,
        expected_room_id: Uuid,
    ) -> Option<usize> {
        let mut room = self.rooms.get_mut(&expected_room_id)?;
        if !room.remove_participant(connection_id) {
            return None;
        }
        room.update_activity();
        let participant_count = room.participant_count();
        drop(room);

        self.connection_message_timestamps.remove(connection_id);
        self.connection_commit_timestamps.remove(connection_id);
        self.connection_proposal_timestamps.remove(connection_id);
        self.connection_frame_timestamps.remove(connection_id);
        self.connection_protocol_errors.remove(connection_id);
        self.connection_ecdh_timestamps.remove(connection_id);
        self.forget_mls_control_participant(expected_room_id, connection_id);

        Some(participant_count)
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

    fn reserve_bytes(counter: &AtomicUsize, amount: usize, limit: usize) -> bool {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(amount).filter(|next| *next <= limit)
            })
            .is_ok()
    }

    fn tracked_broadcast_payload(
        &self,
        room_id: &Uuid,
        json: String,
    ) -> Result<BroadcastPayload, BroadcastError> {
        let room_bytes = self
            .broadcast_room_bytes
            .get(room_id)
            .map(|entry| entry.value().clone())
            .ok_or(BroadcastError::MissingRoom)?;
        let retained_bytes = json.len();
        if !Self::reserve_bytes(
            room_bytes.as_ref(),
            retained_bytes,
            MAX_BROADCAST_ROOM_BYTES,
        ) {
            return Err(BroadcastError::RoomByteCapacity);
        }
        if !Self::reserve_bytes(
            self.broadcast_global_bytes.as_ref(),
            retained_bytes,
            MAX_BROADCAST_GLOBAL_BYTES,
        ) {
            room_bytes.fetch_sub(retained_bytes, Ordering::AcqRel);
            return Err(BroadcastError::GlobalByteCapacity);
        }
        Ok(BroadcastPayload(Arc::new(BroadcastPayloadInner {
            json,
            retained_bytes,
            room_bytes,
            global_bytes: self.broadcast_global_bytes.clone(),
        })))
    }

    /// Broadcast one ephemeral room frame under both per-room and global byte
    /// budgets. The returned value is the number of active receivers.
    pub fn broadcast_room_message(
        &self,
        room_id: &Uuid,
        json: String,
    ) -> Result<usize, BroadcastError> {
        let tx = self
            .broadcast_channels
            .get(room_id)
            .map(|entry| entry.value().clone())
            .ok_or(BroadcastError::MissingRoom)?;
        let payload = self.tracked_broadcast_payload(room_id, json)?;
        Ok(tx.send(payload).unwrap_or(0))
    }

    /// Aggregate room-level count and byte limiter. Per-connection limits
    /// alone allow a 20-member room to multiply the receiver workload.
    pub fn admit_room_traffic(
        &self,
        room_id: Uuid,
        connection_id: Uuid,
        now: DateTime<Utc>,
        bytes: usize,
    ) -> bool {
        let window_secs = self.config.msg_rate_window_secs;
        let max_messages = self.config.room_msg_rate_limit;
        let max_bytes = self.config.room_byte_rate_limit;
        let cutoff = now - chrono::Duration::seconds(window_secs);
        let mut window = self.room_traffic_windows.entry(room_id).or_default();
        while window
            .entries
            .front()
            .map(|(timestamp, _, _)| *timestamp <= cutoff)
            .unwrap_or(false)
        {
            if let Some((_, _, expired_bytes)) = window.entries.pop_front() {
                window.retained_bytes = window.retained_bytes.saturating_sub(expired_bytes);
            }
        }

        // Reserve at least half of each aggregate bucket for other room
        // participants. Without a sender contribution cap, one member can
        // consume the entire byte window and make the next honest sender look
        // like the offender. A single-member room may use the whole bucket.
        let has_other_participant = self
            .rooms
            .get(&room_id)
            .map(|room| {
                room.participant_ids
                    .iter()
                    .any(|participant_id| *participant_id != connection_id)
            })
            .unwrap_or(false);
        let sender_message_limit = if has_other_participant {
            max_messages.div_ceil(2)
        } else {
            max_messages
        };
        let sender_byte_limit = if has_other_participant {
            max_bytes.div_ceil(2)
        } else {
            max_bytes
        };
        let (sender_messages, sender_bytes) = window
            .entries
            .iter()
            .filter(|(_, sender_id, _)| *sender_id == connection_id)
            .fold(
                (0usize, 0usize),
                |(count, retained), (_, _, entry_bytes)| {
                    (
                        count.saturating_add(1),
                        retained.saturating_add(*entry_bytes),
                    )
                },
            );
        if sender_messages >= sender_message_limit
            || sender_bytes.saturating_add(bytes) > sender_byte_limit
        {
            return false;
        }
        if window.entries.len() >= max_messages
            || window.retained_bytes.saturating_add(bytes) > max_bytes
        {
            return false;
        }
        window.entries.push_back((now, connection_id, bytes));
        window.retained_bytes = window.retained_bytes.saturating_add(bytes);
        true
    }

    /// Validate a resume cursor before minting a short-lived WebSocket token.
    /// A cursor is usable when every sequence after it is still retained.
    pub fn validate_mls_control_cursor(
        &self,
        room_id: &Uuid,
        cursor: u64,
    ) -> Result<(), MlsControlCursorError> {
        let log = self
            .mls_control_logs
            .get(room_id)
            .ok_or(MlsControlCursorError::MissingRoom)?;
        let log = log.lock().unwrap();
        Self::validate_mls_cursor_locked(&log, cursor)
    }

    fn validate_mls_cursor_locked(
        log: &MlsControlLog,
        cursor: u64,
    ) -> Result<(), MlsControlCursorError> {
        if cursor > log.head_seq {
            return Err(MlsControlCursorError::CursorAhead);
        }
        if cursor == log.head_seq {
            return Ok(());
        }
        match log.entries.front() {
            Some(first) if cursor.saturating_add(1) >= first.seq => Ok(()),
            _ => Err(MlsControlCursorError::CursorExpired),
        }
    }

    /// Subscribe to live room traffic and atomically snapshot the MLS group
    /// control replay window. `append_and_broadcast_mls_control` holds the
    /// same mutex while broadcasting, so no control sequence can fall between
    /// the snapshot and the live subscription.
    pub fn open_mls_control_stream(
        &self,
        room_id: &Uuid,
        connection_id: Uuid,
        resume_cursor: Option<u64>,
    ) -> Result<(broadcast::Receiver<BroadcastPayload>, MlsControlStream), MlsControlCursorError>
    {
        let tx = self
            .broadcast_channels
            .get(room_id)
            .ok_or(MlsControlCursorError::MissingRoom)?;
        let log = self
            .mls_control_logs
            .get(room_id)
            .ok_or(MlsControlCursorError::MissingRoom)?;
        let participant_ids: Vec<Uuid> = self
            .rooms
            .get(room_id)
            .filter(|room| room.participant_ids.contains(&connection_id))
            .map(|room| room.participant_ids.iter().copied().collect())
            .ok_or(MlsControlCursorError::MissingRoom)?;
        let mut log = log.lock().unwrap();
        let receiver = tx.subscribe();
        let cursor = resume_cursor.unwrap_or(log.head_seq);
        if log
            .acknowledged
            .get(&connection_id)
            .map(|previous| cursor < previous.seq)
            .unwrap_or(false)
        {
            return Err(MlsControlCursorError::CursorRegressed);
        }
        Self::validate_mls_cursor_locked(&log, cursor)?;
        match log.acknowledged.get_mut(&connection_id) {
            Some(previous) if cursor > previous.seq => {
                previous.seq = cursor;
            }
            Some(_) => {
                // Reopening at the same cursor does not change the backlog.
            }
            None => {
                log.acknowledged
                    .insert(connection_id, MlsControlAcknowledgement { seq: cursor });
            }
        }
        Self::prune_acknowledged_mls_controls(&mut log, &participant_ids);
        let through_seq = log.head_seq;
        let replay = log
            .entries
            .iter()
            .filter(|entry| entry.seq > cursor)
            .map(|entry| MlsControlReplayEntry {
                seq: entry.seq,
                json: entry.json.clone(),
            })
            .collect();
        Ok((
            receiver,
            MlsControlStream {
                cursor,
                through_seq,
                replay,
            },
        ))
    }

    /// Assign and broadcast the next room-global MLS group-control sequence
    /// while holding the log mutex. This preserves the same total order in
    /// both the durable replay log and the live broadcast channel.
    #[cfg(test)]
    pub fn append_and_broadcast_mls_control<F>(
        &self,
        room_id: &Uuid,
        serialize: F,
    ) -> Result<u64, MlsControlAppendError>
    where
        F: FnOnce(u64) -> Option<String>,
    {
        self.append_and_broadcast_mls_control_at(
            room_id,
            Instant::now(),
            false,
            MlsControlAdmission::Ordinary,
            serialize,
        )
    }

    /// Append a lifecycle event using the capacity reserved from ordinary MLS
    /// envelopes. Callers must still fail the room closed if even this
    /// reserved path cannot durably sequence the event.
    pub fn append_and_broadcast_mls_lifecycle<F>(
        &self,
        room_id: &Uuid,
        serialize: F,
    ) -> Result<u64, MlsControlAppendError>
    where
        F: FnOnce(u64) -> Option<String>,
    {
        self.append_and_broadcast_mls_control_at(
            room_id,
            Instant::now(),
            true,
            MlsControlAdmission::Ordinary,
            serialize,
        )
    }

    pub fn append_and_broadcast_mls_envelope<F>(
        &self,
        room_id: &Uuid,
        admission: MlsControlAdmission,
        serialize: F,
    ) -> Result<u64, MlsControlAppendError>
    where
        F: FnOnce(u64) -> Option<String>,
    {
        self.append_and_broadcast_mls_control_at(
            room_id,
            Instant::now(),
            false,
            admission,
            serialize,
        )
    }

    fn append_and_broadcast_mls_control_at<F>(
        &self,
        room_id: &Uuid,
        appended_at: Instant,
        lifecycle: bool,
        admission: MlsControlAdmission,
        serialize: F,
    ) -> Result<u64, MlsControlAppendError>
    where
        F: FnOnce(u64) -> Option<String>,
    {
        let tx = self
            .broadcast_channels
            .get(room_id)
            .map(|entry| entry.value().clone())
            .ok_or(MlsControlAppendError::MissingRoom)?;
        let log = self
            .mls_control_logs
            .get(room_id)
            .ok_or(MlsControlAppendError::MissingRoom)?;
        let mut log = log.lock().unwrap();

        match &admission {
            MlsControlAdmission::Ordinary => {}
            MlsControlAdmission::KeyPackage {
                sender_id,
                key_package_ref,
            } => {
                if log.key_package_by_sender.contains_key(sender_id) {
                    return Err(MlsControlAppendError::DuplicateKeyPackage);
                }
                if log.key_package_refs.contains_key(key_package_ref) {
                    return Err(MlsControlAppendError::DuplicateKeyPackageRef);
                }
                if log.consumed_key_package_refs.contains(key_package_ref) {
                    return Err(MlsControlAppendError::DuplicateKeyPackageRef);
                }
            }
            MlsControlAdmission::AddCommit {
                sender_id,
                commit_ref,
                key_package_ref,
            } => {
                if !log.key_package_refs.contains_key(key_package_ref) {
                    return Err(MlsControlAppendError::UnknownKeyPackageRef);
                }
                if log.consumed_key_package_refs.len() >= MAX_CONSUMED_MLS_KEY_PACKAGE_REFS {
                    return Err(MlsControlAppendError::CapacityExceeded);
                }
                if let Some(existing) = log
                    .pending_welcome_by_commit
                    .get(&(*sender_id, commit_ref.clone()))
                    && existing != key_package_ref
                {
                    return Err(MlsControlAppendError::CommitCorrelationConflict);
                }
            }
            MlsControlAdmission::Welcome {
                sender_id,
                commit_ref,
                key_package_ref,
            } => {
                if log
                    .pending_welcome_by_commit
                    .get(&(*sender_id, commit_ref.clone()))
                    .map(String::as_str)
                    != Some(key_package_ref.as_str())
                {
                    return Err(MlsControlAppendError::WelcomeNotCorrelated);
                }
            }
        }

        let seq = log
            .head_seq
            .checked_add(1)
            .ok_or(MlsControlAppendError::SequenceExhausted)?;
        let json = serialize(seq).ok_or(MlsControlAppendError::SerializationFailed)?;
        let entry_limit = if lifecycle {
            MAX_MLS_CONTROL_LOG_ENTRIES
        } else {
            MAX_MLS_CONTROL_LOG_ENTRIES - MLS_LIFECYCLE_RESERVED_ENTRIES
        };
        let byte_limit = if lifecycle {
            MAX_MLS_CONTROL_LOG_BYTES
        } else {
            MAX_MLS_CONTROL_LOG_BYTES - MLS_LIFECYCLE_RESERVED_BYTES
        };
        if log.entries.len() >= entry_limit
            || log.retained_bytes.saturating_add(json.len()) > byte_limit
        {
            return Err(MlsControlAppendError::CapacityExceeded);
        }
        let broadcast_payload = self
            .tracked_broadcast_payload(room_id, json.clone())
            .map_err(|_| MlsControlAppendError::BroadcastCapacity)?;
        if !Self::reserve_bytes(
            self.mls_control_global_bytes.as_ref(),
            json.len(),
            MAX_MLS_CONTROL_LOG_GLOBAL_BYTES,
        ) {
            return Err(MlsControlAppendError::CapacityExceeded);
        }
        let retained_bytes = json.len();
        let json = MlsControlPayload(Arc::new(MlsControlPayloadInner {
            json,
            retained_bytes,
            global_bytes: self.mls_control_global_bytes.clone(),
        }));
        log.head_seq = seq;
        log.retained_bytes = log.retained_bytes.saturating_add(retained_bytes);
        log.entries.push_back(MlsControlEntry {
            seq,
            appended_at,
            json,
        });

        match admission {
            MlsControlAdmission::Ordinary => {}
            MlsControlAdmission::KeyPackage {
                sender_id,
                key_package_ref,
            } => {
                log.key_package_by_sender
                    .insert(sender_id, key_package_ref.clone());
                log.key_package_refs.insert(key_package_ref, sender_id);
            }
            MlsControlAdmission::AddCommit {
                sender_id,
                commit_ref,
                key_package_ref,
            } => {
                let correlation_key = (sender_id, commit_ref);
                let consumed_key_package_ref = key_package_ref.clone();
                if !log.pending_welcome_by_commit.contains_key(&correlation_key) {
                    while log.pending_welcome_by_commit.len()
                        >= MAX_PENDING_MLS_WELCOME_CORRELATIONS
                    {
                        let Some(expired) = log.pending_welcome_order.pop_front() else {
                            break;
                        };
                        log.pending_welcome_by_commit.remove(&expired);
                    }
                    log.pending_welcome_order.push_back(correlation_key.clone());
                }
                log.pending_welcome_by_commit
                    .insert(correlation_key, key_package_ref);
                log.key_package_refs.remove(&consumed_key_package_ref);
                log.consumed_key_package_refs
                    .insert(consumed_key_package_ref);
            }
            MlsControlAdmission::Welcome {
                sender_id,
                commit_ref,
                ..
            } => {
                let correlation_key = (sender_id, commit_ref);
                log.pending_welcome_by_commit.remove(&correlation_key);
                log.pending_welcome_order
                    .retain(|queued| queued != &correlation_key);
            }
        }

        // A room with no currently subscribed receivers still retains the
        // control entry for a participant that resumes within its grace
        // window. Broadcast failure therefore does not roll the sequence back.
        let _ = tx.send(broadcast_payload);
        Ok(seq)
    }

    /// Record a participant's highest consecutively processed MLS group
    /// control sequence and prune entries acknowledged by every current
    /// participant.
    pub fn acknowledge_mls_control(&self, room_id: &Uuid, connection_id: Uuid, seq: u64) -> bool {
        let participant_ids: Vec<Uuid> = match self.rooms.get(room_id) {
            Some(room) if room.participant_ids.contains(&connection_id) => {
                room.participant_ids.iter().copied().collect()
            }
            _ => return false,
        };
        let Some(log) = self.mls_control_logs.get(room_id) else {
            return false;
        };
        let mut log = log.lock().unwrap();
        if seq > log.head_seq {
            return false;
        }
        match log.acknowledged.get_mut(&connection_id) {
            Some(previous) if seq < previous.seq => return false,
            Some(previous) if seq > previous.seq => {
                previous.seq = seq;
            }
            Some(_) => {
                // Duplicate cumulative ACKs are valid.
            }
            None => {
                log.acknowledged
                    .insert(connection_id, MlsControlAcknowledgement { seq });
            }
        }
        Self::prune_acknowledged_mls_controls(&mut log, &participant_ids);
        true
    }

    /// Return current participants whose cumulative ACK is too far behind the
    /// room head, or whose outstanding backlog has made no progress before
    /// the deadline. Callers remove these participants before appending more
    /// controls so one modified or stalled client cannot freeze the room.
    pub fn lagging_mls_control_participants(
        &self,
        room_id: &Uuid,
        max_unacknowledged: u64,
        max_stall: Duration,
    ) -> Vec<Uuid> {
        self.lagging_mls_control_participants_at(
            room_id,
            max_unacknowledged,
            max_stall,
            Instant::now(),
        )
    }

    fn lagging_mls_control_participants_at(
        &self,
        room_id: &Uuid,
        max_unacknowledged: u64,
        max_stall: Duration,
        now: Instant,
    ) -> Vec<Uuid> {
        let participant_ids: Vec<Uuid> = self
            .rooms
            .get(room_id)
            .map(|room| room.participant_ids.iter().copied().collect())
            .unwrap_or_default();
        let Some(log) = self.mls_control_logs.get(room_id) else {
            return Vec::new();
        };
        let log = log.lock().unwrap();
        participant_ids
            .into_iter()
            .filter(|participant_id| {
                let acknowledged_seq = log
                    .acknowledged
                    .get(participant_id)
                    .map(|ack| ack.seq)
                    .unwrap_or(0);
                let outstanding = log.head_seq.saturating_sub(acknowledged_seq);
                let oldest_unacknowledged_at = log
                    .entries
                    .iter()
                    .find(|entry| entry.seq > acknowledged_seq)
                    .map(|entry| entry.appended_at);
                outstanding > 0
                    && (outstanding >= max_unacknowledged
                        || oldest_unacknowledged_at
                            .map(|appended_at| {
                                now.saturating_duration_since(appended_at) >= max_stall
                            })
                            .unwrap_or(false))
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn append_and_broadcast_mls_control_at_for_test<F>(
        &self,
        room_id: &Uuid,
        appended_at: Instant,
        serialize: F,
    ) -> Result<u64, MlsControlAppendError>
    where
        F: FnOnce(u64) -> Option<String>,
    {
        self.append_and_broadcast_mls_control_at(
            room_id,
            appended_at,
            false,
            MlsControlAdmission::Ordinary,
            serialize,
        )
    }

    #[cfg(test)]
    pub(crate) fn lagging_mls_control_participants_at_for_test(
        &self,
        room_id: &Uuid,
        max_unacknowledged: u64,
        max_stall: Duration,
        now: Instant,
    ) -> Vec<Uuid> {
        self.lagging_mls_control_participants_at(room_id, max_unacknowledged, max_stall, now)
    }

    /// True only while this exact stable participant currently owns the
    /// active socket slot for the room.
    pub fn connection_is_active(&self, room_id: &Uuid, connection_id: &Uuid) -> bool {
        self.connections
            .get(connection_id)
            .map(|mapped_room| *mapped_room == *room_id)
            .unwrap_or(false)
    }

    fn forget_mls_control_participant(&self, room_id: Uuid, connection_id: &Uuid) {
        let participant_ids: Vec<Uuid> = self
            .rooms
            .get(&room_id)
            .map(|room| room.participant_ids.iter().copied().collect())
            .unwrap_or_default();
        let Some(log) = self.mls_control_logs.get(&room_id) else {
            return;
        };
        let mut log = log.lock().unwrap();
        log.acknowledged.remove(connection_id);
        if let Some(key_package_ref) = log.key_package_by_sender.remove(connection_id) {
            log.key_package_refs.remove(&key_package_ref);
        }
        log.pending_welcome_by_commit
            .retain(|(sender_id, _), _| sender_id != connection_id);
        log.pending_welcome_order
            .retain(|(sender_id, _)| sender_id != connection_id);
        Self::prune_acknowledged_mls_controls(&mut log, &participant_ids);
    }

    fn prune_acknowledged_mls_controls(log: &mut MlsControlLog, participants: &[Uuid]) {
        if participants.is_empty() {
            log.entries.clear();
            log.retained_bytes = 0;
            return;
        }
        let Some(prune_through) = participants
            .iter()
            .map(|id| log.acknowledged.get(id).map(|ack| ack.seq))
            .collect::<Option<Vec<_>>>()
            .and_then(|acks| acks.into_iter().min())
        else {
            return;
        };
        while log
            .entries
            .front()
            .map(|entry| entry.seq <= prune_through)
            .unwrap_or(false)
        {
            let acknowledged = log.entries.pop_front().expect("front checked");
            log.retained_bytes = log
                .retained_bytes
                .saturating_sub(acknowledged.json.as_str().len());
        }
    }
}
