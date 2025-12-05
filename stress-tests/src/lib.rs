//! PinChat Stress Tests
//!
//! Test suite to verify application resistance against DoS/DDoS attacks and high loads.
//!
//! ## Running Tests
//!
//! ```bash
//! # Start server in test environment
//! PRIVACY_MODE=development POW_MIN_DIFFICULTY=10 cargo run &
//!
//! # Run tests (sequential to avoid interference)
//! cd stress-tests && cargo test -- --test-threads=1
//! ```
//!
//! ## DDoS Tests
//!
//! DDoS tests require TRUSTED_PROXIES to simulate multiple IPs:
//!
//! ```bash
//! TRUSTED_PROXIES=127.0.0.1 cargo run &
//! cd stress-tests && cargo test ddos_tests -- --test-threads=1
//! ```

pub mod helpers;

#[cfg(test)]
mod http_tests;

#[cfg(test)]
mod ws_tests;

#[cfg(test)]
mod pow_tests;

#[cfg(test)]
mod capacity_tests;

#[cfg(test)]
mod concurrent_tests;

#[cfg(test)]
mod ddos_tests;

/// Base URL for test server (HTTPS by default)
pub const BASE_URL: &str = "https://127.0.0.1:3000";

/// WebSocket base URL (WSS by default)
pub const WS_URL: &str = "wss://127.0.0.1:3000";
