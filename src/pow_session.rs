//! PoW session cookie helpers.
//!
//! Per-IP challenge cache keys are vulnerable to collisions on shared NAT
//! (two users behind the same public IP overwrite each other's challenges,
//! creating a targeted DoS on legitimate users on shared networks).
//!
//! This module issues an opaque, short-lived cookie (`pc_pow`) that is mixed
//! into the cache key so each browser gets its own challenge even when the
//! source IP is shared. The cookie is a random UUID v4, HttpOnly/Secure/
//! SameSite=Strict, and scoped to the PoW flow only — it is not used for
//! tracking and expires alongside the challenge.
//!
//! Fallback: clients that block cookies simply receive a new UUID and a new
//! challenge on every request, which is functionally equivalent to the
//! pre-cookie behaviour for a solitary client.

use axum::http::{header, HeaderMap};
use axum_extra::extract::cookie::{Cookie, SameSite};
use uuid::Uuid;

/// Name of the PoW session cookie.
pub const POW_COOKIE_NAME: &str = "pc_pow";

/// Reads the PoW session cookie from the incoming request headers.
/// Returns `Some(uuid)` only when a well-formed UUID value is present.
pub fn read_pow_cookie(headers: &HeaderMap) -> Option<Uuid> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{}=", POW_COOKIE_NAME);
    for part in raw.split(';') {
        let trimmed = part.trim_start();
        if let Some(value) = trimmed.strip_prefix(&prefix)
            && let Ok(uuid) = Uuid::parse_str(value)
        {
            return Some(uuid);
        }
    }
    None
}

/// Builds a Set-Cookie header value for a fresh PoW session cookie.
/// `ttl_secs` should match the challenge TTL.
pub fn build_pow_cookie(value: Uuid, use_secure: bool, ttl_secs: u64) -> Cookie<'static> {
    Cookie::build((POW_COOKIE_NAME, value.to_string()))
        .path("/")
        .same_site(SameSite::Strict)
        .secure(use_secure)
        .http_only(true)
        .max_age(time::Duration::seconds(ttl_secs as i64))
        .build()
}

/// Derives the challenge-cache key from the HMAC(IP) hash and the PoW cookie.
/// `ip_hash` is already a 256-bit HMAC digest; the cookie is a 128-bit random
/// UUID; concatenating with a separator is collision-safe in practice.
pub fn pow_cache_key(ip_hash: &str, cookie: &Uuid) -> String {
    format!("{}|{}", ip_hash, cookie)
}

/// Resolves the PoW session cookie for an incoming request. Returns a tuple
/// `(uuid, new_cookie)`. `new_cookie` is `Some(Cookie)` only when no valid
/// cookie was present and a fresh one must be emitted in the response.
pub fn resolve_pow_session(
    headers: &HeaderMap,
    use_secure: bool,
    ttl_secs: u64,
) -> (Uuid, Option<Cookie<'static>>) {
    match read_pow_cookie(headers) {
        Some(uuid) => (uuid, None),
        None => {
            let uuid = Uuid::new_v4();
            let cookie = build_pow_cookie(uuid, use_secure, ttl_secs);
            (uuid, Some(cookie))
        }
    }
}

/// Determines if the PoW cookie should carry the Secure flag.
/// Mirrors the logic used for session/CSRF cookies in `handlers::auth`.
pub fn should_use_secure_pow_cookies(force_secure: bool) -> bool {
    if force_secure {
        return true;
    }
    use std::path::Path;
    let cert_exists = Path::new("certs/cert.pem").exists();
    let key_exists = Path::new("certs/key.pem").exists();
    cert_exists && key_exists
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn reads_valid_pow_cookie() {
        let mut headers = HeaderMap::new();
        let uuid = Uuid::new_v4();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("pc_pow={}", uuid)).unwrap(),
        );
        assert_eq!(read_pow_cookie(&headers), Some(uuid));
    }

    #[test]
    fn rejects_malformed_pow_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("pc_pow=not-a-uuid"),
        );
        assert!(read_pow_cookie(&headers).is_none());
    }

    #[test]
    fn picks_pow_cookie_among_many() {
        let mut headers = HeaderMap::new();
        let uuid = Uuid::new_v4();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "csrf_token=abc; pinchat_session=deadbeef; pc_pow={}",
                uuid
            ))
            .unwrap(),
        );
        assert_eq!(read_pow_cookie(&headers), Some(uuid));
    }

    #[test]
    fn pow_cache_keys_are_distinct_per_cookie() {
        let ip = "deadbeef";
        let a = pow_cache_key(ip, &Uuid::new_v4());
        let b = pow_cache_key(ip, &Uuid::new_v4());
        assert_ne!(a, b);
    }
}
