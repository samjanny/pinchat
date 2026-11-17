//! Authentication utilities for password verification, session tokens,
//! and CSRF protection.
//!
//! Functions in this module are shared across HTTP handlers and middleware to
//! ensure consistent token construction and verification semantics.

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Verifies a password against any of the configured Argon2id hashes.
/// Returns true if the password matches any hash.
pub fn verify_password(password: &str, hashes: &[String]) -> bool {
    let argon2 = Argon2::default();

    for hash_str in hashes {
        if let Ok(parsed_hash) = PasswordHash::new(hash_str) {
            if argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
            {
                return true;
            }
        }
    }
    false
}

/// Password verifications that may run at the same time.
///
/// One Argon2id verification costs tens of milliseconds of CPU and tens of
/// MiB of memory per configured hash (46 MiB with the parameters
/// `hash_password` uses). Unbounded, a burst of login attempts from many
/// addresses would take that for each of them at once.
const MAX_CONCURRENT_PASSWORD_CHECKS: usize = 2;

/// How long a login attempt waits for one of those slots before it is
/// answered as busy.
const PASSWORD_CHECK_QUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

static PASSWORD_CHECK_SLOTS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_PASSWORD_CHECKS);

/// Outcome of [`verify_password_bounded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordCheck {
    Match,
    Mismatch,
    /// No verification slot became free in time. Nothing was checked.
    Busy,
}

/// Verify a password without stalling the server.
///
/// `verify_password` is synchronous and slow by design. Called directly from
/// a request handler it occupies an async worker thread for the whole hash,
/// and with as many concurrent login attempts as there are workers nothing
/// else runs: WebSocket relays, pings and room cleanup all wait. Here the
/// hash runs on the blocking thread pool, and a semaphore bounds how many
/// run at once.
pub async fn verify_password_bounded(password: String, hashes: Vec<String>) -> PasswordCheck {
    verify_password_within(password, hashes, PASSWORD_CHECK_QUEUE_TIMEOUT).await
}

async fn verify_password_within(
    password: String,
    hashes: Vec<String>,
    queue_timeout: std::time::Duration,
) -> PasswordCheck {
    let Ok(Ok(slot)) = tokio::time::timeout(queue_timeout, PASSWORD_CHECK_SLOTS.acquire()).await
    else {
        return PasswordCheck::Busy;
    };
    // The slot moves into the blocking task. Dropping this future (a client
    // that disconnects) does not stop a hash that is already running, so the
    // slot must stay taken until that hash is done.
    let check = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        verify_password(&password, &hashes)
    });
    match check.await {
        Ok(true) => PasswordCheck::Match,
        Ok(false) => PasswordCheck::Mismatch,
        Err(_) => PasswordCheck::Busy,
    }
}

/// Generates a new random session token (UUID v4)
pub fn generate_session_token() -> Uuid {
    Uuid::new_v4()
}

/// Generates a CSRF token signed with HMAC
pub fn generate_csrf_token(secret: &[u8; 32]) -> String {
    let random_bytes: [u8; 16] = rand::random();
    let random_hex = hex::encode(random_bytes);

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(random_hex.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    format!("{}.{}", random_hex, signature)
}

/// Verifies a CSRF token against the expected secret
pub fn verify_csrf_token(token: &str, secret: &[u8; 32]) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return false;
    }

    let random_hex = parts[0];
    let provided_signature = parts[1];

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(random_hex.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());

    // L-01: use a vetted crate for the constant-time compare instead of the
    // hand-rolled XOR-accumulator below. The HMAC tag length is fixed (64
    // hex chars for SHA-256), and the attacker-provided length is not a
    // secret, so the practical impact of the original early-length-return
    // pattern was nil - but rolling our own is the position we don't want
    // to maintain. `subtle::ConstantTimeEq` for `[u8]` short-circuits on
    // length and otherwise runs in time independent of slice contents.
    provided_signature
        .as_bytes()
        .ct_eq(expected_signature.as_bytes())
        .into()
}

/// Hash a password using Argon2id with OWASP recommended parameters
/// This is primarily used by the generate_hash binary
#[allow(dead_code)]
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);

    // Apply the OWASP 2024 recommended parameters for Argon2id
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(47104, 1, 1, None)?,
    );

    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &[hash.clone()]));
        assert!(!verify_password("wrong_password", &[hash]));
    }

    #[test]
    fn test_csrf_token() {
        let secret: [u8; 32] = rand::random();
        let token = generate_csrf_token(&secret);

        assert!(verify_csrf_token(&token, &secret));
        assert!(!verify_csrf_token("invalid.token", &secret));
        assert!(!verify_csrf_token(&token, &[0u8; 32])); // wrong secret
    }

    #[test]
    fn test_multiple_hashes() {
        let password1 = "password1";
        let password2 = "password2";
        let hash1 = hash_password(password1).unwrap();
        let hash2 = hash_password(password2).unwrap();

        let hashes = vec![hash1, hash2];

        assert!(verify_password(password1, &hashes));
        assert!(verify_password(password2, &hashes));
        assert!(!verify_password("password3", &hashes));
    }

    /// A valid Argon2id hash that is cheap enough for unit tests.
    fn cheap_hash(password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(8, 1, 1, None).unwrap(),
        )
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
    }

    #[tokio::test]
    async fn bounded_check_agrees_with_the_direct_check() {
        let hashes = vec![cheap_hash("other"), cheap_hash("correct horse")];
        assert_eq!(
            verify_password_bounded("correct horse".to_string(), hashes.clone()).await,
            PasswordCheck::Match
        );
        assert_eq!(
            verify_password_bounded("wrong".to_string(), hashes.clone()).await,
            PasswordCheck::Mismatch
        );
        assert_eq!(
            verify_password_bounded("correct horse".to_string(), vec![]).await,
            PasswordCheck::Mismatch
        );
        assert_eq!(
            verify_password_bounded("x".to_string(), vec!["not a hash".to_string()]).await,
            PasswordCheck::Mismatch
        );
    }

    #[tokio::test]
    async fn password_check_does_not_occupy_the_async_worker() {
        // Single-threaded runtime: if the hash ran on the worker, the ticker
        // below could not make progress until it finished.
        let hash = hash_password("production cost").unwrap();
        let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ticker = {
            let ticks = ticks.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    ticks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            })
        };

        let started = std::time::Instant::now();
        let mut ticks_during_hash = 0;
        while ticks_during_hash == 0 && started.elapsed() < std::time::Duration::from_secs(60) {
            let before = ticks.load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                verify_password_bounded("production cost".to_string(), vec![hash.clone()]).await,
                PasswordCheck::Match
            );
            ticks_during_hash = ticks.load(std::sync::atomic::Ordering::Relaxed) - before;
        }
        ticker.abort();
        assert!(
            ticks_during_hash > 0,
            "other tasks must keep running while a password is being hashed"
        );
    }

    #[tokio::test]
    async fn password_checks_beyond_the_concurrency_bound_wait_and_then_give_up() {
        // Occupy every slot, as in-flight verifications would.
        let held = PASSWORD_CHECK_SLOTS
            .acquire_many(MAX_CONCURRENT_PASSWORD_CHECKS as u32)
            .await
            .unwrap();
        let hashes = vec![cheap_hash("pw")];
        assert_eq!(
            verify_password_within(
                "pw".to_string(),
                hashes.clone(),
                std::time::Duration::from_millis(100)
            )
            .await,
            PasswordCheck::Busy,
            "an attempt that finds no free slot must not be reported as a wrong password"
        );

        // A waiting attempt proceeds as soon as a slot is released.
        let waiting = tokio::spawn(verify_password_within(
            "pw".to_string(),
            hashes,
            std::time::Duration::from_secs(30),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!waiting.is_finished());
        drop(held);
        assert_eq!(waiting.await.unwrap(), PasswordCheck::Match);
    }
}
