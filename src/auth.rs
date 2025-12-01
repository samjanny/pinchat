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

    // Constant-time comparison to prevent timing attacks
    constant_time_eq(provided_signature.as_bytes(), expected_signature.as_bytes())
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
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
}
