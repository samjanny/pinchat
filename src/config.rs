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

    // Proof-of-Work configuration
    pub pow_min_difficulty: u8,
    pub pow_max_difficulty: u8,

    // Challenge and token TTLs
    pub challenge_ttl_secs: u64,
    pub jwt_token_ttl_secs: i64,

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

            // WebSocket connection rate limiting (default: 5 connections per minute)
            ws_conn_burst_size: env::var("WS_CONN_BURST_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            ws_conn_period_secs: env::var("WS_CONN_PERIOD_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),

            // Room/Token creation rate limiting (default: 20 requests per hour)
            room_token_burst_size: env::var("ROOM_TOKEN_BURST_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
            room_token_period_secs: env::var("ROOM_TOKEN_PERIOD_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),

            // Per-connection message rate limiting (default: 5 messages per second)
            msg_rate_limit: env::var("MSG_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            msg_rate_window_secs: env::var("MSG_RATE_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),

            // Proof-of-Work configuration (default: 15-20 bits)
            pow_min_difficulty: env::var("POW_MIN_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
            pow_max_difficulty: env::var("POW_MAX_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),

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

            // Anti-replay cache max entries per room (default: 10000)
            // With 64-byte hashes, 10k entries = ~640KB per room max
            replay_cache_max_per_room: env::var("REPLAY_CACHE_MAX_PER_ROOM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10000),

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

        // Validate periods are non-zero
        if self.ws_conn_period_secs == 0 {
            panic!("WS_CONN_PERIOD_SECS must be greater than 0");
        }
        if self.room_token_period_secs == 0 {
            panic!("ROOM_TOKEN_PERIOD_SECS must be greater than 0");
        }
        if self.msg_rate_window_secs == 0 {
            panic!("MSG_RATE_WINDOW_SECS must be greater than 0");
        }

        // Validate TTLs are non-zero
        if self.challenge_ttl_secs == 0 {
            panic!("CHALLENGE_TTL_SECS must be greater than 0");
        }
        if self.jwt_token_ttl_secs == 0 {
            panic!("JWT_TOKEN_TTL_SECS must be greater than 0");
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

        // Validate max image size (reasonable bounds: 1KB to 50MB)
        if self.max_image_size < 1024 {
            panic!("MAX_IMAGE_SIZE must be at least 1KB (1024 bytes)");
        }
        if self.max_image_size > 50 * 1024 * 1024 {
            panic!("MAX_IMAGE_SIZE cannot exceed 50MB");
        }
    }

    /// Returns true if authentication is enabled (password hashes are configured)
    pub fn is_auth_enabled(&self) -> bool {
        !self.password_hashes.is_empty()
    }
}
