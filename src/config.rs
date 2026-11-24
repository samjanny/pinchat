use std::env;

/// Parses a size string with optional KB/MB suffix into bytes
/// Supports formats: "300KB", "1MB", "307200" (plain bytes)
/// Case-insensitive for suffixes
/// Parses an IPv4 address string into a 4-byte array
/// Supports standard dotted-decimal notation (e.g., "0.0.0.0", "127.0.0.1")
fn parse_ipv4_address(value: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = value.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part.parse().ok()?;
    }
    Some(octets)
}

fn parse_size_with_suffix(value: &str) -> Option<usize> {
    let value = value.trim().to_uppercase();

    if value.ends_with("KB") {
        let num = value.trim_end_matches("KB").trim();
        num.parse::<usize>().ok().map(|n| n * 1024)
    } else if value.ends_with("MB") {
        let num = value.trim_end_matches("MB").trim();
        num.parse::<usize>().ok().map(|n| n * 1024 * 1024)
    } else {
        // Plain number (bytes)
        value.parse::<usize>().ok()
    }
}

/// Why a `PINCHAT_PASSWORD_HASHES` entry cannot be used, if it cannot: it
/// must be an Argon2id hash in PHC string form, with parameters the
/// verifier accepts.
fn check_password_hash(hash: &str) -> Result<(), &'static str> {
    let parsed = argon2::PasswordHash::new(hash).map_err(|_| "not a PHC string ($argon2id$...)")?;
    if parsed.algorithm != argon2::Algorithm::Argon2id.ident() {
        return Err("not an Argon2id hash");
    }
    if parsed.hash.is_none() || parsed.salt.is_none() {
        return Err("salt or hash missing");
    }
    argon2::Params::try_from(&parsed).map_err(|_| "Argon2 parameters out of range")?;
    Ok(())
}

/// Default of `MAX_TOTAL_ROOMS`. The memory sizing below and in "Relay
/// Memory" in SECURITY.md assumes it: 500 rooms at their limits take about
/// 135 MB of a 512 MiB container. A larger host raises it.
pub const DEFAULT_MAX_TOTAL_ROOMS: usize = 500;

/// Default of `MAX_WS_CONNECTIONS`, sized for a relay in a 512 MiB container
/// with `MAX_TOTAL_ROOMS=500` (see "Relay Memory" in SECURITY.md). Measured
/// on one CPU behind a TLS proxy, a connection costs about 22 KB to the
/// relay when idle and up to 256 KiB more in kernel socket buffers when its
/// peer stops reading or keeps sending while the relay waits. With the
/// global budgets, the password checks and 500 rooms at their limits taking
/// about 360 MB, 400 connections at their worst add about 115 MB and leave a
/// margin of about 60 MB. A larger host raises it.
pub const DEFAULT_MAX_WS_CONNECTIONS: usize = 400;
/// Default of `MAX_WS_CONNECTIONS_PER_ADDRESS`: an eighth of the relay, so
/// that it takes at least eight addresses to fill it, while a household or
/// an office behind one address can still keep many rooms open.
pub const DEFAULT_MAX_WS_CONNECTIONS_PER_ADDRESS: usize = DEFAULT_MAX_WS_CONNECTIONS / 8;

/// Default of `MAX_HTTP_CONNECTIONS`: HTTP connections the relay serves at
/// once before they are upgraded to WebSocket (an upgraded connection is
/// counted by `MAX_WS_CONNECTIONS` instead). See `http_server.rs` for what
/// one costs and how long it may stay.
pub const DEFAULT_MAX_HTTP_CONNECTIONS: usize = 256;
/// Default of `MAX_HTTP_CONNECTIONS_PER_ADDRESS`: an eighth of them, as for
/// WebSocket connections. A browser opens up to six at once.
pub const DEFAULT_MAX_HTTP_CONNECTIONS_PER_ADDRESS: usize = DEFAULT_MAX_HTTP_CONNECTIONS / 8;

/// Longest proof-of-work challenge lifetime. The privacy policy states that
/// a challenge and its cookie last at most 5 minutes.
pub const MAX_CHALLENGE_TTL_SECS: u64 = 300;
/// Longest interval between two sweeps of solved challenges. The privacy
/// policy states that the identifier of a solved challenge is deleted within
/// a minute of its expiry.
pub const MAX_CHALLENGE_CLEANUP_INTERVAL_SECS: u64 = 60;

/// Application configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct Config {
    // Server binding configuration
    pub host: [u8; 4],
    pub port: u16,

    // WebSocket connection rate limiting
    pub ws_conn_burst_size: u32,
    pub ws_conn_period_secs: u64,

    // Admission control for WebSocket connections: how many may be open at
    // once in all, and how many for one client address (an IPv6 /64; an
    // IPv6 /48 may hold four times as many). A connection holds its slot
    // from the moment its upgrade is accepted to the end of its closing
    // handshake. An upgrade beyond either limit is refused before anything
    // is allocated for it (503 for the relay, 429 for the address).
    pub max_ws_connections: usize,
    pub max_ws_connections_per_address: usize,

    // HTTP connections served at once before an upgrade, in all and for one
    // client address (an IPv6 /64; an IPv6 /48 may hold four times as many).
    // A connection from a trusted proxy counts only in the total. Beyond the
    // total the relay accepts nothing until a connection ends; beyond the
    // address limit it closes the new connection at once.
    pub max_http_connections: usize,
    pub max_http_connections_per_address: usize,

    // Room/Token creation rate limiting
    pub room_token_burst_size: u32,
    pub room_token_period_secs: u64,

    // Per-connection message rate limiting
    pub msg_rate_limit: usize,
    pub msg_rate_window_secs: i64,
    // Aggregate per-room traffic caps prevent many individually compliant
    // members from multiplying broadcast/decryption work.
    pub room_msg_rate_limit: usize,
    pub room_byte_rate_limit: usize,

    // Per-connection MLS Commit rate limit. Commits are broadcast to every
    // member and trigger TreeKEM verification + transcript hash + signature
    // checks on each receiver, so they're far more expensive than regular
    // application messages. Defaults: 24 commits / 60 seconds. This permits
    // the creator to fill every slot in a 20-member room in one legitimate
    // admission burst while still bounding sustained TreeKEM work.
    pub commit_rate_limit: usize,
    pub commit_rate_window_secs: i64,
    // Standalone MLS Update Proposal rate. Honest clients emit these only
    // during periodic PCS rotation; a much tighter bucket prevents one member
    // from monopolising every recipient's bounded ProposalRef store.
    pub proposal_rate_limit: usize,
    pub proposal_rate_window_secs: i64,

    // Per-connection global frame rate limit (applies to EVERY text frame,
    // including handshakes, unknown types, and malformed JSON, not just
    // message/image). Acts as an anti-flood ceiling that sits above the
    // stricter message/image limit above.
    pub frame_rate_limit: usize,

    // Per-connection protocol-error threshold. Counts parse failures,
    // unknown msg_type values, and oversized ECDH payloads. Connection
    // is closed once this many protocol errors accumulate.
    pub protocol_error_limit: u32,

    // Per-connection ECDH-frame burst limit and window. ECDH frames trigger
    // signature verification + key import + Double Ratchet re-init on the
    // peer client; without a dedicated cap, an authenticated peer could
    // exhaust the receiver's CPU under cover of the (much looser)
    // frame_rate_limit. Real handshakes need 1-2 frames per session and a
    // few more across reconnects, so a small burst over a long window is
    // ample.
    pub ecdh_burst_limit: usize,
    pub ecdh_burst_window_secs: i64,

    // Proof-of-Work configuration
    pub pow_min_difficulty: u8,
    pub pow_max_difficulty: u8,

    // Challenge and token TTLs
    pub challenge_ttl_secs: u64,
    pub jwt_token_ttl_secs: u64,

    // Issuer string stamped on every WebSocket JWT (`iss` claim) and
    // required by the verifier. Operators running multiple PinChat
    // instances behind a shared secret store SHOULD set `JWT_ISSUER` per
    // instance (e.g. "pinchat-eu", "pinchat-us") so tokens from one
    // instance cannot be replayed at another.
    pub jwt_issuer: String,

    // Absolute hard cap on a single WebSocket connection's lifetime, in seconds.
    // Independent of the idle timeout: even an active client is forced to
    // reconnect (and thus restart the handshake) after this duration. Bounds
    // resource usage from clients that keep heartbeating indefinitely.
    pub max_ws_connection_age_secs: u64,

    // Time for which a disconnected participant ID remains reserved. A client
    // presenting its server-signed resume credential can reconnect during this
    // window without producing UserLeft/UserJoined or changing its relay ID.
    // After the window, normal departure processing resumes and MLS removes the
    // member fail-closed.
    pub ws_reconnect_grace_secs: u64,

    // Cleanup intervals
    pub room_cleanup_interval_secs: u64,
    pub challenge_cleanup_interval_secs: u64,

    // Authentication configuration
    pub password_hashes: Vec<String>,
    pub session_ttl_secs: u64,

    // Login rate limiting (brute force protection)
    pub login_burst_size: u32,
    pub login_period_secs: u64,

    // Trusted proxy configuration for X-Forwarded-For
    // When behind a load balancer/reverse proxy, set this to the proxy IPs
    pub trusted_proxies: Vec<String>,

    // Anti-replay cache configuration
    // Maximum number of message hashes to store per room
    // Prevents memory exhaustion from malicious clients
    pub replay_cache_max_per_room: usize,

    // Cookie security configuration
    // When behind a TLS-terminating proxy (nginx, CloudFlare, AWS ALB),
    // set FORCE_SECURE_COOKIES=true to ensure Secure flag is always set
    pub force_secure_cookies: bool,

    // Maximum image size in bytes (before encryption)
    // Parsed from MAX_IMAGE_SIZE env var (supports KB/MB suffixes)
    pub max_image_size: usize,

    // Force HTTP mode (disable TLS even if certificates exist)
    // Useful when running behind a TLS-terminating reverse proxy (nginx, CloudFlare, etc.)
    // SECURITY: Only use this when the proxy handles TLS termination
    pub force_http: bool,

    // Custom website directory for static files
    // When set, the server looks for static files here first, then falls back to /static
    // Useful for serving a custom frontend while keeping the default as fallback
    pub website_dir: Option<String>,

    // Explicitly allow anonymous access when no password hashes are configured
    // SECURITY: defaults to false to avoid accidental fail-open deployments
    pub allow_anonymous: bool,

    // Comma-separated list of allowed CORS origins.
    // Used both for the CorsLayer (HTTP responses) and the WebSocket Origin check.
    // Default: "https://localhost:3000"
    pub cors_allowed_origins: Vec<String>,

    // Fail-closed deployment gate for the experimental custom MLS feature.
    pub group_chat_enabled: bool,
}

impl Config {
    /// Loads configuration from environment variables with sensible defaults
    ///
    /// # Panics
    /// Panics if configuration values are invalid (e.g., min_difficulty > max_difficulty)
    pub fn from_env() -> Self {
        let config = Self {
            // Server binding configuration (default: 127.0.0.1:3000)
            host: env::var("HOST")
                .ok()
                .and_then(|v| parse_ipv4_address(&v))
                .unwrap_or([127, 0, 0, 1]),
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3000),

            // WebSocket connection rate limiting (default: 30 connections per minute)
            ws_conn_burst_size: env::var("WS_CONN_BURST_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            ws_conn_period_secs: env::var("WS_CONN_PERIOD_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),

            max_ws_connections: env::var("MAX_WS_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_MAX_WS_CONNECTIONS),
            max_ws_connections_per_address: env::var("MAX_WS_CONNECTIONS_PER_ADDRESS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_MAX_WS_CONNECTIONS_PER_ADDRESS),
            max_http_connections: env::var("MAX_HTTP_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_MAX_HTTP_CONNECTIONS),
            max_http_connections_per_address: env::var("MAX_HTTP_CONNECTIONS_PER_ADDRESS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_MAX_HTTP_CONNECTIONS_PER_ADDRESS),

            // Room/Token creation rate limiting (default: 100 requests per 10 minutes)
            room_token_burst_size: env::var("ROOM_TOKEN_BURST_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            room_token_period_secs: env::var("ROOM_TOKEN_PERIOD_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600),

            // Per-connection message rate limiting (default: 30 messages per second)
            msg_rate_limit: env::var("MSG_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            msg_rate_window_secs: env::var("MSG_RATE_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            room_msg_rate_limit: env::var("ROOM_MSG_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120),
            room_byte_rate_limit: env::var("ROOM_BYTE_RATE_LIMIT")
                .ok()
                .and_then(|v| parse_size_with_suffix(&v))
                .unwrap_or(8 * 1024 * 1024),

            // MLS Commit rate limit (default: 24 commits per 60 seconds).
            // A fresh 20-member room requires 19 Add commits, so the former
            // default of 12 rejected a valid full-room admission burst.
            commit_rate_limit: env::var("COMMIT_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(24),
            commit_rate_window_secs: env::var("COMMIT_RATE_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            proposal_rate_limit: env::var("PROPOSAL_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),
            proposal_rate_window_secs: env::var("PROPOSAL_RATE_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),

            // Global frame rate limit (default: 4x msg_rate_limit, same window).
            // Applied to every text frame regardless of msg_type so ECDH,
            // unknown types, and malformed JSON cannot bypass the quota.
            frame_rate_limit: env::var("FRAME_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120),

            // Protocol-error threshold (default: 10). A connection emitting
            // more than this many malformed/unknown frames is closed.
            protocol_error_limit: env::var("PROTOCOL_ERROR_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),

            // Proof-of-Work configuration (default: 12-18 bits)
            pow_min_difficulty: env::var("POW_MIN_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(12),
            pow_max_difficulty: env::var("POW_MAX_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(18),

            // Challenge TTL (default: 300 seconds = 5 minutes)
            challenge_ttl_secs: env::var("CHALLENGE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),

            // JWT token TTL (default: 30 seconds)
            jwt_token_ttl_secs: env::var("JWT_TOKEN_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),

            // JWT issuer (default: `crate::jwt::DEFAULT_JWT_ISSUER`).
            // Audit C-2: the verifier requires an exact `iss` match. Leave
            // unset for single-instance deployments; set explicitly when
            // running multiple instances behind a shared HMAC key.
            jwt_issuer: env::var("JWT_ISSUER")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| crate::jwt::DEFAULT_JWT_ISSUER.to_string()),

            // Hard cap on WebSocket connection lifetime (default: 30 minutes).
            // Forces a reconnect that re-runs PoW/JWT and the handshake.
            max_ws_connection_age_secs: env::var("MAX_WS_CONNECTION_AGE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30 * 60),

            // Stable-identity reconnect grace (default: 20 seconds). This is
            // long enough for the normal PoW/JWT retry path while keeping the
            // delay before a genuine MLS Remove bounded.
            ws_reconnect_grace_secs: env::var("WS_RECONNECT_GRACE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),

            // ECDH burst (default: 8 frames per 60 seconds).
            ecdh_burst_limit: env::var("ECDH_BURST_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),
            ecdh_burst_window_secs: env::var("ECDH_BURST_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),

            // Cleanup intervals (default: 60 seconds)
            room_cleanup_interval_secs: env::var("ROOM_CLEANUP_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            challenge_cleanup_interval_secs: env::var("CHALLENGE_CLEANUP_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),

            // Authentication configuration
            // Password hashes are semicolon-separated Argon2id hashes
            password_hashes: env::var("PINCHAT_PASSWORD_HASHES")
                .ok()
                .map(|v| {
                    v.split(';')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),

            // Session TTL (default: 86400 seconds = 24 hours)
            session_ttl_secs: env::var("SESSION_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400),

            // Login rate limiting (default: 5 attempts per 12 minutes).
            // Not 15: a client's hashed address is kept for somewhat longer
            // than the window, and the privacy policy promises at most 15
            // minutes (see rate_limit::Quota::retention).
            login_burst_size: env::var("LOGIN_BURST_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            login_period_secs: env::var("LOGIN_PERIOD_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(720),

            // Trusted proxies for X-Forwarded-For (comma-separated IPs/CIDRs)
            // Example: "10.0.0.1,192.168.1.0/24,172.16.0.0/12"
            trusted_proxies: env::var("TRUSTED_PROXIES")
                .ok()
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),

            // Anti-replay cache max entries per room (default: 1000).
            //
            // The cache is a hash lookup plus a FIFO insertion queue, so
            // expiry and capacity eviction are O(1) amortized: no
            // attacker-controlled sort or full-set scan runs on the message
            // path. The validation cap below stops an operator from
            // multiplying this advisory cache into unbounded room memory.
            //
            // 1000 is chosen for the memory budget, not the algorithm: at
            // roughly 136 bytes per entry across 1000 rooms that is about
            // 136 MB worst case. The previous default of 10000 extrapolated
            // to ~1.4 GB on a VPS, disproportionate for a layer that is
            // advisory anyway, since the authoritative anti-replay defence is
            // the client-side Double Ratchet counter. 1000 entries still
            // tolerate ~17 minutes at the 30 msg/s rate limit before eviction
            // starts mattering for a busy room.
            replay_cache_max_per_room: env::var("REPLAY_CACHE_MAX_PER_ROOM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1000),

            // Force Secure flag on cookies (default: false)
            // Set to true when behind a TLS-terminating proxy
            // Accepts: "true", "1", "yes" (case-insensitive)
            force_secure_cookies: env::var("FORCE_SECURE_COOKIES")
                .ok()
                .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
                .unwrap_or(false),

            // Maximum image size (default: 300KB)
            // Supports: plain bytes, KB suffix, MB suffix
            max_image_size: env::var("MAX_IMAGE_SIZE")
                .ok()
                .and_then(|v| parse_size_with_suffix(&v))
                .unwrap_or(300 * 1024), // 300KB default

            // Force HTTP mode (default: false)
            // Set to true when behind a TLS-terminating reverse proxy
            // Accepts: "true", "1", "yes" (case-insensitive)
            force_http: env::var("FORCE_HTTP")
                .ok()
                .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
                .unwrap_or(false),

            // Custom website directory (default: empty/None)
            // When set, static files are served from this directory first,
            // falling back to the built-in /static directory
            website_dir: env::var("WEBSITE_DIR")
                .ok()
                .filter(|v| !v.trim().is_empty()),

            // Explicitly allow anonymous access (default: false)
            // Accepts: "true", "1", "yes" (case-insensitive)
            allow_anonymous: env::var("ALLOW_ANONYMOUS")
                .ok()
                .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
                .unwrap_or(false),

            // Allowed CORS origins (comma-separated, default: https://localhost:3000)
            cors_allowed_origins: env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "https://localhost:3000".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            group_chat_enabled: env::var("GROUP_CHAT_ENABLED")
                .ok()
                .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
                .unwrap_or(false),
        };

        // Validate configuration
        config.validate();

        config
    }

    /// Validates configuration values
    ///
    /// # Panics
    /// Panics if validation fails
    fn validate(&self) {
        // Validate port range (must be > 0, port 0 is reserved)
        if self.port == 0 {
            panic!("PORT must be greater than 0");
        }

        // Validate PoW difficulty range
        if self.pow_min_difficulty > self.pow_max_difficulty {
            panic!(
                "Invalid PoW difficulty: POW_MIN_DIFFICULTY ({}) must be <= POW_MAX_DIFFICULTY ({})",
                self.pow_min_difficulty, self.pow_max_difficulty
            );
        }

        // Validate difficulty bounds (reasonable values)
        if self.pow_min_difficulty < 10 || self.pow_min_difficulty > 30 {
            panic!(
                "Invalid POW_MIN_DIFFICULTY: {} (must be between 10 and 30)",
                self.pow_min_difficulty
            );
        }
        if self.pow_max_difficulty < 10 || self.pow_max_difficulty > 30 {
            panic!(
                "Invalid POW_MAX_DIFFICULTY: {} (must be between 10 and 30)",
                self.pow_max_difficulty
            );
        }

        // Validate rate limits are non-zero
        if self.ws_conn_burst_size == 0 {
            panic!("WS_CONN_BURST_SIZE must be greater than 0");
        }
        if self.room_token_burst_size == 0 {
            panic!("ROOM_TOKEN_BURST_SIZE must be greater than 0");
        }
        if self.msg_rate_limit == 0 {
            panic!("MSG_RATE_LIMIT must be greater than 0");
        }
        if self.commit_rate_limit == 0 {
            panic!("COMMIT_RATE_LIMIT must be greater than 0");
        }
        if self.room_msg_rate_limit == 0 {
            panic!("ROOM_MSG_RATE_LIMIT must be greater than 0");
        }
        if self.room_byte_rate_limit < 64 * 1024 || self.room_byte_rate_limit > 64 * 1024 * 1024 {
            panic!("ROOM_BYTE_RATE_LIMIT must be between 64KB and 64MB");
        }
        if self.proposal_rate_limit == 0 {
            panic!("PROPOSAL_RATE_LIMIT must be greater than 0");
        }
        if self.frame_rate_limit == 0 {
            panic!("FRAME_RATE_LIMIT must be greater than 0");
        }
        if self.frame_rate_limit < self.msg_rate_limit {
            panic!(
                "FRAME_RATE_LIMIT ({}) must be >= MSG_RATE_LIMIT ({})",
                self.frame_rate_limit, self.msg_rate_limit
            );
        }
        if self.protocol_error_limit == 0 {
            panic!("PROTOCOL_ERROR_LIMIT must be greater than 0");
        }

        if !(1..=100_000).contains(&self.max_ws_connections) {
            panic!("MAX_WS_CONNECTIONS must be between 1 and 100000");
        }
        if !(1..=self.max_ws_connections).contains(&self.max_ws_connections_per_address) {
            panic!("MAX_WS_CONNECTIONS_PER_ADDRESS must be between 1 and MAX_WS_CONNECTIONS");
        }
        if !(1..=100_000).contains(&self.max_http_connections) {
            panic!("MAX_HTTP_CONNECTIONS must be between 1 and 100000");
        }
        if !(1..=self.max_http_connections).contains(&self.max_http_connections_per_address) {
            panic!("MAX_HTTP_CONNECTIONS_PER_ADDRESS must be between 1 and MAX_HTTP_CONNECTIONS");
        }

        // Validate periods are non-zero
        if self.ws_conn_period_secs == 0 {
            panic!("WS_CONN_PERIOD_SECS must be greater than 0");
        }
        if self.room_token_period_secs == 0 {
            panic!("ROOM_TOKEN_PERIOD_SECS must be greater than 0");
        }
        if self.msg_rate_window_secs <= 0 {
            panic!("MSG_RATE_WINDOW_SECS must be greater than 0");
        }
        if self.commit_rate_window_secs <= 0 {
            panic!("COMMIT_RATE_WINDOW_SECS must be greater than 0");
        }
        if self.proposal_rate_window_secs <= 0 {
            panic!("PROPOSAL_RATE_WINDOW_SECS must be greater than 0");
        }

        // Validate TTLs. The challenge bounds are what the privacy policy
        // states (see MAX_CHALLENGE_TTL_SECS); the lower one leaves time to
        // solve a challenge on a slow device.
        if !(10..=MAX_CHALLENGE_TTL_SECS).contains(&self.challenge_ttl_secs) {
            panic!(
                "CHALLENGE_TTL_SECS must be between 10 and {}",
                MAX_CHALLENGE_TTL_SECS
            );
        }
        if !(1..=300).contains(&self.jwt_token_ttl_secs) {
            panic!("JWT_TOKEN_TTL_SECS must be between 1 and 300");
        }
        if self.max_ws_connection_age_secs == 0 {
            panic!("MAX_WS_CONNECTION_AGE_SECS must be greater than 0");
        }
        if self.ws_reconnect_grace_secs == 0 || self.ws_reconnect_grace_secs > 120 {
            panic!("WS_RECONNECT_GRACE_SECS must be between 1 and 120");
        }
        if self.ecdh_burst_limit == 0 {
            panic!("ECDH_BURST_LIMIT must be greater than 0");
        }
        if self.ecdh_burst_window_secs <= 0 {
            panic!("ECDH_BURST_WINDOW_SECS must be greater than 0");
        }

        // Validate cleanup intervals are non-zero
        if self.room_cleanup_interval_secs == 0 {
            panic!("ROOM_CLEANUP_INTERVAL_SECS must be greater than 0");
        }
        if !(1..=MAX_CHALLENGE_CLEANUP_INTERVAL_SECS)
            .contains(&self.challenge_cleanup_interval_secs)
        {
            panic!(
                "CHALLENGE_CLEANUP_INTERVAL_SECS must be between 1 and {}",
                MAX_CHALLENGE_CLEANUP_INTERVAL_SECS
            );
        }

        // Validate session TTL is non-zero
        if self.session_ttl_secs == 0 {
            panic!("SESSION_TTL_SECS must be greater than 0");
        }

        // Every configured hash must be one the login check can use. A
        // value that does not parse (often one mangled by `$` interpolation
        // in a shell or in a .env file without single quotes) used to be
        // skipped at every login, so the server started with a password
        // that could never be accepted. The position is reported, not the
        // value.
        for (index, hash) in self.password_hashes.iter().enumerate() {
            if let Err(problem) = check_password_hash(hash) {
                panic!(
                    "PINCHAT_PASSWORD_HASHES entry {} of {} is not usable: {}",
                    index + 1,
                    self.password_hashes.len(),
                    problem
                );
            }
        }

        // An entry that is neither an address nor a CIDR range never
        // matches. In proxy mode that means X-Forwarded-For is silently
        // ignored and every visitor shares the proxy's rate-limit bucket.
        if let Some(entry) = self
            .trusted_proxies
            .iter()
            .find(|entry| !crate::ip_hash::is_valid_trusted_proxy_entry(entry))
        {
            panic!(
                "TRUSTED_PROXIES entry {:?} is not an IP address or CIDR range",
                entry
            );
        }

        // Validate login rate limiting
        if self.login_burst_size == 0 {
            panic!("LOGIN_BURST_SIZE must be greater than 0");
        }
        if self.login_period_secs == 0 {
            panic!("LOGIN_PERIOD_SECS must be greater than 0");
        }

        // Validate replay cache size
        if self.replay_cache_max_per_room == 0 {
            panic!("REPLAY_CACHE_MAX_PER_ROOM must be greater than 0");
        }
        if self.replay_cache_max_per_room > 10_000 {
            panic!("REPLAY_CACHE_MAX_PER_ROOM cannot exceed 10000");
        }

        // A 2MB raw image expands to roughly 2.8MB after encryption and
        // Base64url framing, remaining below the relay's 4MB per-room
        // retained-broadcast ceiling and the browser's 8MB history/decode
        // budgets. Larger configured values would be accepted at startup but
        // deterministically rejected by the bounded transport.
        if self.max_image_size < 1024 {
            panic!("MAX_IMAGE_SIZE must be at least 1KB (1024 bytes)");
        }
        if self.max_image_size > 2 * 1024 * 1024 {
            panic!("MAX_IMAGE_SIZE cannot exceed 2MB");
        }
        if self.room_byte_rate_limit < self.max_image_size.saturating_mul(2) {
            panic!("ROOM_BYTE_RATE_LIMIT must be at least twice MAX_IMAGE_SIZE");
        }
    }

    /// Preconditions that only make sense together with `FORCE_HTTP=true`,
    /// i.e. when a reverse proxy terminates TLS in front of this process.
    ///
    /// Returns `Some(message)` describing the first violated precondition,
    /// or `None` when the reverse-proxy configuration is coherent. `main`
    /// treats `Some` as fatal outside development mode.
    ///
    /// Why `TRUSTED_PROXIES` is mandatory here: behind a proxy every request
    /// reaches this process from the proxy's own address. With no trusted
    /// proxy configured, `X-Forwarded-For` is ignored by design and every
    /// visitor collapses into a single rate-limit bucket and a single PoW
    /// challenge-cache key. One client can then exhaust the shared room-token
    /// budget for everyone. This was found live in production on 2026-09-08.
    pub fn reverse_proxy_misconfiguration(&self) -> Option<&'static str> {
        if !self.force_http {
            return None;
        }
        if !self.force_secure_cookies {
            return Some(
                "FORCE_HTTP=true requires FORCE_SECURE_COOKIES=true in production. \
                 This prevents session cookies from being sent over insecure transport.",
            );
        }
        if self.trusted_proxies.is_empty() {
            return Some(
                "FORCE_HTTP=true requires TRUSTED_PROXIES to name the reverse proxy. \
                 Without it X-Forwarded-For is ignored and every visitor shares one \
                 rate-limit bucket, so a single client can lock everyone out of room \
                 creation. Set it to the address the proxy connects from, as seen by \
                 this process (for docker-compose behind nginx on the host this is the \
                 compose network gateway, e.g. TRUSTED_PROXIES=172.18.0.1, not 127.0.0.1).",
            );
        }
        None
    }

    /// Returns true if authentication is enabled (password hashes are configured)
    pub fn is_auth_enabled(&self) -> bool {
        !self.password_hashes.is_empty()
    }
}

#[cfg(test)]
impl Config {
    /// A coherent non-proxy configuration for unit tests in any module.
    pub(crate) fn for_tests() -> Self {
        Self {
            host: [127, 0, 0, 1],
            port: 3000,
            ws_conn_burst_size: 100,
            ws_conn_period_secs: 60,
            max_ws_connections: DEFAULT_MAX_WS_CONNECTIONS,
            max_ws_connections_per_address: DEFAULT_MAX_WS_CONNECTIONS_PER_ADDRESS,
            max_http_connections: DEFAULT_MAX_HTTP_CONNECTIONS,
            max_http_connections_per_address: DEFAULT_MAX_HTTP_CONNECTIONS_PER_ADDRESS,
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
            max_ws_connection_age_secs: 1800,
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
            group_chat_enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A coherent non-proxy baseline; tests flip only the fields they are about.
    fn base() -> Config {
        Config::for_tests()
    }

    #[test]
    fn baseline_configuration_is_valid() {
        base().validate();
        let mut c = base();
        c.trusted_proxies = vec!["172.18.0.1".to_string(), "10.0.0.0/8".to_string()];
        c.validate();
    }

    #[test]
    #[should_panic(expected = "TRUSTED_PROXIES entry")]
    fn unparsable_trusted_proxy_entry_is_refused_at_startup() {
        let mut c = base();
        c.trusted_proxies = vec!["172.18.0.1".to_string(), "nginx".to_string()];
        c.validate();
    }

    #[test]
    fn direct_tls_mode_has_no_proxy_preconditions() {
        // Without FORCE_HTTP there is no proxy, so an empty TRUSTED_PROXIES
        // and non-forced cookies are both fine.
        assert_eq!(base().reverse_proxy_misconfiguration(), None);
    }

    #[test]
    fn proxy_mode_requires_secure_cookies_first() {
        let mut c = base();
        c.force_http = true;
        let msg = c.reverse_proxy_misconfiguration().expect("must be flagged");
        assert!(msg.contains("FORCE_SECURE_COOKIES"), "got: {msg}");
    }

    #[test]
    fn proxy_mode_requires_a_trusted_proxy() {
        // The production misconfiguration of 2026-09-08: proxy mode, cookies
        // forced, but nobody trusted for X-Forwarded-For, so every visitor
        // shared one rate-limit bucket.
        let mut c = base();
        c.force_http = true;
        c.force_secure_cookies = true;
        let msg = c.reverse_proxy_misconfiguration().expect("must be flagged");
        assert!(msg.contains("TRUSTED_PROXIES"), "got: {msg}");
        assert!(
            msg.contains("172.18.0.1"),
            "must name the docker-compose value: {msg}"
        );
    }

    #[test]
    fn password_hashes_are_checked_at_startup() {
        let mut c = base();
        c.password_hashes = vec![crate::auth::hash_password("correct horse").unwrap()];
        c.validate();

        for (broken, expected) in [
            // What `$` interpolation leaves of `$argon2id$v=19$m=...$salt$hash`.
            ("=19=47104,t=1,p=1", "not a PHC string"),
            ("placeholder", "not a PHC string"),
            (
                "$argon2i$v=19$m=47104,t=1,p=1$c29tZXNhbHQ$iWh06vD8Fy27wf9npn6FXWiCX4K6pW6Ue1Bnzz07Z8A",
                "not an Argon2id hash",
            ),
            ("$argon2id$v=19$m=47104,t=1,p=1", "salt or hash missing"),
            (
                "$argon2id$v=19$m=1,t=1,p=1$c29tZXNhbHQ$iWh06vD8Fy27wf9npn6FXWiCX4K6pW6Ue1Bnzz07Z8A",
                "parameters out of range",
            ),
        ] {
            let mut c = base();
            c.password_hashes = vec![
                crate::auth::hash_password("correct horse").unwrap(),
                broken.to_string(),
            ];
            let message = std::panic::catch_unwind(|| c.validate())
                .expect_err(broken)
                .downcast::<String>()
                .unwrap();
            assert!(
                message.contains("entry 2 of 2") && message.contains(expected),
                "{broken}: {message}"
            );
            assert!(!message.contains(broken), "the value is not echoed");
        }
    }

    #[test]
    #[should_panic(expected = "CHALLENGE_TTL_SECS must be between 10 and 300")]
    fn a_challenge_may_not_outlive_the_published_five_minutes() {
        let mut c = base();
        c.challenge_ttl_secs = 301;
        c.validate();
    }

    #[test]
    #[should_panic(expected = "CHALLENGE_CLEANUP_INTERVAL_SECS must be between 1 and 60")]
    fn solved_challenges_are_swept_at_least_every_minute() {
        let mut c = base();
        c.challenge_cleanup_interval_secs = 61;
        c.validate();
    }

    #[test]
    #[should_panic(
        expected = "MAX_HTTP_CONNECTIONS_PER_ADDRESS must be between 1 and MAX_HTTP_CONNECTIONS"
    )]
    fn http_connection_limits_are_validated() {
        let mut c = base();
        c.max_http_connections = 10;
        c.max_http_connections_per_address = 11;
        c.validate();
    }

    #[test]
    fn coherent_proxy_mode_passes() {
        let mut c = base();
        c.force_http = true;
        c.force_secure_cookies = true;
        c.trusted_proxies = vec!["172.18.0.1".to_string()];
        assert_eq!(c.reverse_proxy_misconfiguration(), None);
    }
}
