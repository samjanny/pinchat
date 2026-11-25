//! How a proof-of-work challenge travels between the server and the client.
//!
//! A challenge is signed and carries its own expiry (see
//! `challenge_cache.rs`), so the server keeps nothing when it hands one out:
//! the client has to bring it back with its solution. It is set in the
//! `pc_pow` cookie, HttpOnly/Secure/SameSite=Strict, for as long as the
//! challenge is valid, and sent back by the browser with the request that
//! carries the nonce. A client may also send it in the `X-PoW-Challenge`
//! header, which then takes precedence; the homepage does when it creates a
//! room, so a challenge fetched in another tab in the meantime, which
//! replaces the cookie, does not spoil the one it solved.
//!
//! The cookie used to hold a random identifier that was mixed into the key
//! of a server-side cache of challenges, so that clients behind one address
//! did not overwrite each other's challenge. With nothing kept on the
//! server there is nothing to overwrite.
//!
//! A client that blocks cookies and does not send the header gets a new
//! challenge on every request, as before.

use crate::handlers::auth::cookie_value;
use axum::http::HeaderMap;
use axum_extra::extract::cookie::{Cookie, SameSite};

/// Name of the proof-of-work cookie.
pub const POW_COOKIE_NAME: &str = "pc_pow";

/// Header a client may send the challenge it solved in.
pub const POW_CHALLENGE_HEADER: &str = "x-pow-challenge";

/// Longer than any challenge this server issues (about 120 characters).
const MAX_CHALLENGE_LEN: usize = 256;

/// The challenge the client says it solved: the `X-PoW-Challenge` header if
/// there is one, the `pc_pow` cookie otherwise.
pub fn presented_challenge(headers: &HeaderMap) -> Option<&str> {
    let presented = match headers.get(POW_CHALLENGE_HEADER) {
        Some(value) => value.to_str().ok(),
        None => cookie_value(headers, POW_COOKIE_NAME),
    };
    presented.filter(|challenge| challenge.len() <= MAX_CHALLENGE_LEN)
}

/// The `pc_pow` cookie carrying `challenge`, for as long as the challenge is
/// valid (`ttl_secs`, the challenge TTL).
pub fn build_pow_cookie(challenge: &str, use_secure: bool, ttl_secs: u64) -> Cookie<'static> {
    Cookie::build((POW_COOKIE_NAME, challenge.to_string()))
        .path("/")
        .same_site(SameSite::Strict)
        .secure(use_secure)
        .http_only(true)
        .max_age(time::Duration::seconds(ttl_secs as i64))
        .build()
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
    use axum::http::{HeaderValue, header};

    #[test]
    fn reads_the_challenge_from_the_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("csrf_token=abc; pinchat_session=deadbeef; pc_pow=c-1-d12-t"),
        );
        assert_eq!(presented_challenge(&headers), Some("c-1-d12-t"));
    }

    #[test]
    fn reads_the_challenge_from_a_later_cookie_line() {
        // HTTP/2 may send every cookie in a header field of its own.
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("csrf_token=abc"));
        headers.append(header::COOKIE, HeaderValue::from_static("pc_pow=c-1-d12-t"));
        assert_eq!(presented_challenge(&headers), Some("c-1-d12-t"));
    }

    #[test]
    fn the_header_takes_precedence_over_the_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("pc_pow=from-cookie"),
        );
        headers.insert(
            POW_CHALLENGE_HEADER,
            HeaderValue::from_static("from-header"),
        );
        assert_eq!(presented_challenge(&headers), Some("from-header"));
    }

    #[test]
    fn oversized_or_missing_challenges_are_ignored() {
        assert_eq!(presented_challenge(&HeaderMap::new()), None);
        let mut headers = HeaderMap::new();
        headers.insert(
            POW_CHALLENGE_HEADER,
            HeaderValue::from_str(&"a".repeat(MAX_CHALLENGE_LEN + 1)).unwrap(),
        );
        assert_eq!(presented_challenge(&headers), None);
    }

    #[test]
    fn the_cookie_lives_as_long_as_the_challenge() {
        let cookie = build_pow_cookie("c-1-d12-t", true, 300).to_string();
        assert!(cookie.starts_with("pc_pow=c-1-d12-t;"), "{cookie}");
        for attribute in [
            "HttpOnly",
            "Secure",
            "SameSite=Strict",
            "Max-Age=300",
            "Path=/",
        ] {
            assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
        }
    }
}
