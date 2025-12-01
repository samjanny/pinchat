//! Custom rate limit key extractor using HMAC(IP)
//!
//! This module provides a custom key extractor for tower-governor that uses
//! HMAC-SHA256(IP) instead of storing cleartext IP addresses.
//!
//! This ensures consistency with the challenge cache and prevents privacy leaks
//! where rate limiter state would expose client IP addresses.
//!
//! Supports trusted proxy configuration for X-Forwarded-For when running
//! behind a load balancer or reverse proxy.

use crate::ip_hash::{extract_client_ip_with_proxy, hash_ip};
use crate::state::AppState;
use axum::extract::ConnectInfo;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_governor::key_extractor::KeyExtractor;

/// Custom key extractor that uses HMAC(IP) for privacy protection
///
/// Implements the KeyExtractor trait required by tower-governor.
/// Extracts the client IP (considering trusted proxies) and hashes it with HMAC-SHA256.
///
/// # Trusted Proxy Support
/// When `TRUSTED_PROXIES` is configured, the extractor will:
/// 1. Check if the direct TCP connection is from a trusted proxy
/// 2. If so, extract the real client IP from X-Forwarded-For header
/// 3. Otherwise, use the direct TCP connection IP
#[derive(Clone)]
pub struct HmacIpKeyExtractor {
    /// Shared application state (contains secret key and config)
    app_state: Arc<AppState>,
}

impl HmacIpKeyExtractor {
    /// Create a new HMAC IP key extractor
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
}

impl KeyExtractor for HmacIpKeyExtractor {
    type Key = String;

    fn extract<T>(
        &self,
        req: &axum::http::Request<T>,
    ) -> Result<Self::Key, tower_governor::GovernorError> {
        // Extract ConnectInfo from request extensions
        let connect_info = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .ok_or(tower_governor::GovernorError::UnableToExtractKey)?;

        // Extract client IP considering trusted proxies
        let ip = extract_client_ip_with_proxy(
            connect_info,
            req.headers(),
            &self.app_state.config.trusted_proxies,
        );

        // Hash IP with HMAC-SHA256
        let ip_hash = hash_ip(&ip, &self.app_state.ip_hash_secret);

        Ok(ip_hash)
    }
}
