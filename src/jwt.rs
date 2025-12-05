//! JWT utilities for WebSocket authentication
//!
//! This module provides token-based authentication for WebSocket connections
//! to prevent unauthorized access and DoS attacks.
//!
//! Security flow:
//! 1. Client requests token via `/api/ws-token/{room_id}` with PoW
//! 2. Server validates PoW and generates JWT with 30s expiration
//! 3. Client includes token in WebSocket upgrade
//! 4. Server validates JWT before accepting connection
//!
//! This prevents:
//! - Connection flooding (PoW required for token)
//! - Slot saturation attacks (token rate-limited)
//! - Ciphertext spam (only authenticated clients)

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// JWT claims for WebSocket authentication
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WsTokenClaims {
    /// Room ID this token is valid for
    pub room_id: Uuid,

    /// Pre-allocated connection ID
    /// This ensures unique connection IDs even before WebSocket connects
    pub connection_id: Uuid,

    /// Expiration timestamp (Unix epoch seconds)
    /// Tokens are short-lived (30 seconds) to prevent reuse
    pub exp: u64,

    /// JWT ID for single-use enforcement
    /// Prevents token replay attacks within the validity window
    pub jti: Uuid,
}

impl WsTokenClaims {
    /// Create new JWT claims with specified expiration
    ///
    /// # Arguments
    /// * `room_id` - Room ID this token is valid for
    /// * `ttl_secs` - Time-to-live in seconds (e.g., 30)
    pub fn new(room_id: Uuid, ttl_secs: i64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        Self {
            room_id,
            connection_id: Uuid::new_v4(),
            exp: now + (ttl_secs as u64),
            jti: Uuid::new_v4(),
        }
    }
}

/// Signs JWT claims with secret key
///
/// # Arguments
/// * `claims` - JWT claims to sign
/// * `secret` - 32-byte secret key for HMAC-SHA256
///
/// # Returns
/// Signed JWT token string
pub fn sign_token(
    claims: &WsTokenClaims,
    secret: &[u8; 32],
) -> Result<String, jsonwebtoken::errors::Error> {
    let header = Header::default(); // HS256 (HMAC-SHA256)
    let encoding_key = EncodingKey::from_secret(secret);
    encode(&header, claims, &encoding_key)
}

/// Verifies and decodes JWT token
///
/// # Arguments
/// * `token` - JWT token string
/// * `secret` - 32-byte secret key for HMAC-SHA256
///
/// # Returns
/// Decoded claims if token is valid and not expired
pub fn verify_token(
    token: &str,
    secret: &[u8; 32],
) -> Result<WsTokenClaims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(secret);
    let validation = Validation::default(); // Validates exp automatically

    let token_data = decode::<WsTokenClaims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_sign_and_verify() {
        let secret = [0u8; 32];
        let room_id = Uuid::new_v4();
        let claims = WsTokenClaims::new(room_id, 30); // 30 second TTL
        let connection_id = claims.connection_id;

        // Sign token
        let token = sign_token(&claims, &secret).expect("Failed to sign token");

        // Verify token
        let decoded = verify_token(&token, &secret).expect("Failed to verify token");

        assert_eq!(decoded.room_id, room_id);
        assert_eq!(decoded.connection_id, connection_id);
    }

    #[test]
    fn test_token_wrong_secret() {
        let secret1 = [0u8; 32];
        let secret2 = [1u8; 32];
        let claims = WsTokenClaims::new(Uuid::new_v4(), 30); // 30 second TTL

        // Sign with secret1
        let token = sign_token(&claims, &secret1).expect("Failed to sign");

        // Try to verify with secret2
        let result = verify_token(&token, &secret2);
        assert!(result.is_err(), "Should fail with wrong secret");
    }

    #[test]
    fn test_token_expiration() {
        let secret = [0u8; 32];
        let room_id = Uuid::new_v4();

        // Create expired token (exp in the past)
        let expired_claims = WsTokenClaims {
            room_id,
            connection_id: Uuid::new_v4(),
            exp: 1, // January 1, 1970
            jti: Uuid::new_v4(),
        };

        let token = sign_token(&expired_claims, &secret).expect("Failed to sign");

        // Verify should fail due to expiration
        let result = verify_token(&token, &secret);
        assert!(result.is_err(), "Should fail with expired token");
    }

    #[test]
    fn test_token_has_unique_jti() {
        let room_id = Uuid::new_v4();
        let claims1 = WsTokenClaims::new(room_id, 30);
        let claims2 = WsTokenClaims::new(room_id, 30);

        // Each token should have a unique JTI
        assert_ne!(claims1.jti, claims2.jti, "JTI should be unique per token");
    }
}
