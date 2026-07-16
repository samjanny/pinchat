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

/// Application configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct Config {
    // Server binding configuration
    pub host: [u8; 4],
    pub port: u16,

    // WebSocket connection rate limiting
    pub ws_conn_burst_size: u32,
    pub ws_conn_period_secs: u64,

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
    // frame_rate_limit. Real handshakes need 1–2 frames per session and a
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

            // Login rate limiting (default: 5 attempts per 15 minutes)
            login_burst_size: env::var("LOGIN_BURST_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            login_period_secs: env::var("LOGIN_PERIOD_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(900), // 15 minutes

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

            // Anti-replay cache max entries per room (default: 1000). The
            // implementation uses a hash lookup plus FIFO insertion queue,
            // so expiry/eviction is O(1) amortized rather than sorting
            // attacker-controlled entries on the message path. The hard
            // validation cap below prevents operators from accidentally
            // multiplying this advisory cache into unbounded room memory.
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

        // Validate TTLs are non-zero
        if self.challenge_ttl_secs == 0 {
            panic!("CHALLENGE_TTL_SECS must be greater than 0");
        }
        if self.jwt_token_ttl_secs == 0 {
            panic!("JWT_TOKEN_TTL_SECS must be greater than 0");
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
        if self.challenge_cleanup_interval_secs == 0 {
            panic!("CHALLENGE_CLEANUP_INTERVAL_SECS must be greater than 0");
        }

        // Validate session TTL is non-zero
        if self.session_ttl_secs == 0 {
            panic!("SESSION_TTL_SECS must be greater than 0");
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

    /// Returns true if authentication is enabled (password hashes are configured)
    pub fn is_auth_enabled(&self) -> bool {
        !self.password_hashes.is_empty()
    }
}
