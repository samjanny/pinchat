use crate::challenge_cache::ChallengeCache;
use crate::config::Config;
use crate::models::Room;
use crate::session::SessionStore;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use rand::RngCore;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Error type for room creation failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomCreationError {
    /// Server has reached maximum room capacity
    AtCapacity,
}

/// Result of admitting a WebSocket relay identity into a room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionAdmission {
    /// First successful socket for this participant ID.
    New,
    /// A valid resume token reclaimed an ID still reserved in the grace window.
    Resumed,
}

const MAX_MLS_CONTROL_LOG_ENTRIES: usize = 1024;
const MAX_MLS_CONTROL_LOG_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
struct MlsControlEntry {
    seq: u64,
    json: String,
}

#[derive(Debug, Default)]
struct MlsControlLog {
    head_seq: u64,
    retained_bytes: usize,
    entries: VecDeque<MlsControlEntry>,
    acknowledged: HashMap<Uuid, u64>,
}

/// A stable participant's ordered MLS-control replay window.
pub struct MlsControlStream {
    pub cursor: u64,
    pub through_seq: u64,
    pub replay: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsControlCursorError {
    MissingRoom,
    CursorAhead,
    CursorExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsControlAppendError {
    MissingRoom,
    SequenceExhausted,
    SerializationFailed,
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

    /// Ordered, bounded replay log for MLS group-control envelopes
    /// (UserJoined/UserLeft, KeyPackage, Proposal, Commit, Welcome). MLS
    /// PrivateMessages deliberately remain ephemeral. Each stable relay
    /// participant acknowledges the highest sequence it has applied; a
    /// resumed socket replays from that cursor.
    mls_control_logs: Arc<DashMap<Uuid, Arc<Mutex<MlsControlLog>>>>,

    /// Anti-replay: Cache of seen message hashes per room
    /// room_id -> Set<(payload_hash, timestamp)>
    /// Prevents same-room replay attacks and protects late joiners
    pub seen_message_hashes: Arc<DashMap<Uuid, HashSet<(String, DateTime<Utc>)>>>,

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
            mls_control_logs: Arc::new(DashMap::new()),
            seen_message_hashes: Arc::new(DashMap::new()),
            connection_message_timestamps: Arc::new(DashMap::new()),
            connection_commit_timestamps: Arc::new(DashMap::new()),
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
            self.connection_frame_timestamps.remove(&connection_id);
            self.connection_protocol_errors.remove(&connection_id);
            self.connection_ecdh_timestamps.remove(&connection_id);
        }

        // Remove the broadcast channel
        self.broadcast_channels.remove(room_id);
        self.mls_control_logs.remove(room_id);

        // Remove the message hash cache (anti-replay)
        self.seen_message_hashes.remove(room_id);

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
    ) -> Result<(broadcast::Receiver<String>, MlsControlStream), MlsControlCursorError> {
        let tx = self
            .broadcast_channels
            .get(room_id)
            .ok_or(MlsControlCursorError::MissingRoom)?;
        let log = self
            .mls_control_logs
            .get(room_id)
            .ok_or(MlsControlCursorError::MissingRoom)?;
        let mut log = log.lock().unwrap();
        let receiver = tx.subscribe();
        let cursor = resume_cursor.unwrap_or(log.head_seq);
        Self::validate_mls_cursor_locked(&log, cursor)?;
        let through_seq = log.head_seq;
        let replay = log
            .entries
            .iter()
            .filter(|entry| entry.seq > cursor)
            .map(|entry| entry.json.clone())
            .collect();
        log.acknowledged.insert(connection_id, cursor);
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
    pub fn append_and_broadcast_mls_control<F>(
        &self,
        room_id: &Uuid,
        serialize: F,
    ) -> Result<u64, MlsControlAppendError>
    where
        F: FnOnce(u64) -> Option<String>,
    {
        let tx = self
            .broadcast_channels
            .get(room_id)
            .ok_or(MlsControlAppendError::MissingRoom)?;
        let log = self
            .mls_control_logs
            .get(room_id)
            .ok_or(MlsControlAppendError::MissingRoom)?;
        let mut log = log.lock().unwrap();
        let seq = log
            .head_seq
            .checked_add(1)
            .ok_or(MlsControlAppendError::SequenceExhausted)?;
        let json = serialize(seq).ok_or(MlsControlAppendError::SerializationFailed)?;
        log.head_seq = seq;
        log.retained_bytes = log.retained_bytes.saturating_add(json.len());
        log.entries.push_back(MlsControlEntry {
            seq,
            json: json.clone(),
        });

        while log.entries.len() > MAX_MLS_CONTROL_LOG_ENTRIES
            || log.retained_bytes > MAX_MLS_CONTROL_LOG_BYTES
        {
            let Some(expired) = log.entries.pop_front() else {
                break;
            };
            log.retained_bytes = log.retained_bytes.saturating_sub(expired.json.len());
        }

        // A room with no currently subscribed receivers still retains the
        // control entry for a participant that resumes within its grace
        // window. Broadcast failure therefore does not roll the sequence back.
        let _ = tx.send(json);
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
        let previous = log.acknowledged.get(&connection_id).copied().unwrap_or(0);
        if seq < previous {
            return false;
        }
        log.acknowledged.insert(connection_id, seq);
        Self::prune_acknowledged_mls_controls(&mut log, &participant_ids);
        true
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
        Self::prune_acknowledged_mls_controls(&mut log, &participant_ids);
    }

    fn prune_acknowledged_mls_controls(log: &mut MlsControlLog, participants: &[Uuid]) {
        let Some(prune_through) = participants
            .iter()
            .map(|id| log.acknowledged.get(id).copied())
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
            log.retained_bytes = log.retained_bytes.saturating_sub(acknowledged.json.len());
        }
    }
}
