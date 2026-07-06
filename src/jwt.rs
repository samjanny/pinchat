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

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Audience the WebSocket-token issuer always stamps on its tokens.
///
/// Audit C-2 (block-release): pinning the `aud` claim prevents a JWT
/// minted by some other component that happens to share the HMAC secret
/// (e.g. a future admin endpoint, a key-rotation overlap, a co-located
/// internal service) from being accepted by the WebSocket upgrade
/// handler. The verifier MUST require exactly this audience.
pub const WS_TOKEN_AUDIENCE: &str = "pinchat-ws";

/// Default JWT issuer when `JWT_ISSUER` is not set. Operators running
/// multiple PinChat instances behind the same secret store should set
/// `JWT_ISSUER` per instance so tokens are not cross-instance valid.
pub const DEFAULT_JWT_ISSUER: &str = "pinchat";

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

    /// Audience claim (RFC 7519 §4.1.3). Always `WS_TOKEN_AUDIENCE` for
    /// tokens minted by this module. Verifier requires an exact match.
    pub aud: String,

    /// Issuer claim (RFC 7519 §4.1.1). Bound to the deployment via
    /// `JWT_ISSUER` config. Verifier requires an exact match.
    pub iss: String,
}

impl WsTokenClaims {
    /// Create new JWT claims with specified expiration
    ///
    /// # Arguments
    /// * `room_id` - Room ID this token is valid for
    /// * `ttl_secs` - Time-to-live in seconds (e.g., 30)
    /// * `issuer`   - Issuer string this deployment stamps on tokens
    ///   (`Config::jwt_issuer`). Becomes the `iss` claim.
    pub fn new(room_id: Uuid, ttl_secs: u64, issuer: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        Self {
            room_id,
            connection_id: Uuid::new_v4(),
            exp: now + ttl_secs,
            jti: Uuid::new_v4(),
            aud: WS_TOKEN_AUDIENCE.to_string(),
            iss: issuer.to_string(),
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
/// * `expected_issuer` - Deployment-specific issuer (`Config::jwt_issuer`).
///   Tokens whose `iss` differs are rejected.
///
/// # Returns
/// Decoded claims if token is valid, not expired, and matches the expected
/// audience and issuer.
pub fn verify_token(
    token: &str,
    secret: &[u8; 32],
    expected_issuer: &str,
) -> Result<WsTokenClaims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(secret);
    // F-07: pin algorithm explicitly. Validation::default() accepts only HS256
    // in jsonwebtoken 10.x, but that is documentation rather than type-system
    // enforcement; a future minor that widened the default would silently
    // weaken verification. Algorithm::HS256 is the only acceptable algorithm
    // because sign_token uses Header::default() (HS256). Also require `exp`,
    // `aud`, `iss` — without these gates a token missing the claim would
    // skip the corresponding validation in jsonwebtoken.
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);

    // Audit C-2: pin both audience and issuer. set_audience accepts the
    // expected `aud` value(s); set_issuer accepts expected `iss` value(s).
    // A token signed with the same secret but issued by another component
    // (or another PinChat instance) will fail one of these gates and be
    // rejected even though the MAC checks out.
    let aud_set: HashSet<&str> = HashSet::from([WS_TOKEN_AUDIENCE]);
    validation.aud = Some(aud_set.into_iter().map(String::from).collect());
    validation.iss = Some(HashSet::from([expected_issuer.to_string()]));

    let token_data = decode::<WsTokenClaims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ISS: &str = "pinchat-test";

    #[test]
    fn test_token_sign_and_verify() {
        let secret = [0u8; 32];
        let room_id = Uuid::new_v4();
        let claims = WsTokenClaims::new(room_id, 30, TEST_ISS); // 30 second TTL
        let connection_id = claims.connection_id;

        // Sign token
        let token = sign_token(&claims, &secret).expect("Failed to sign token");

        // Verify token
        let decoded = verify_token(&token, &secret, TEST_ISS).expect("Failed to verify token");

        assert_eq!(decoded.room_id, room_id);
        assert_eq!(decoded.connection_id, connection_id);
        assert_eq!(decoded.aud, WS_TOKEN_AUDIENCE);
        assert_eq!(decoded.iss, TEST_ISS);
    }

    #[test]
    fn test_token_wrong_secret() {
        let secret1 = [0u8; 32];
        let secret2 = [1u8; 32];
        let claims = WsTokenClaims::new(Uuid::new_v4(), 30, TEST_ISS); // 30 second TTL

        // Sign with secret1
        let token = sign_token(&claims, &secret1).expect("Failed to sign");

        // Try to verify with secret2
        let result = verify_token(&token, &secret2, TEST_ISS);
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
            aud: WS_TOKEN_AUDIENCE.to_string(),
            iss: TEST_ISS.to_string(),
        };

        let token = sign_token(&expired_claims, &secret).expect("Failed to sign");

        // Verify should fail due to expiration
        let result = verify_token(&token, &secret, TEST_ISS);
        assert!(result.is_err(), "Should fail with expired token");
    }

    #[test]
    fn test_token_has_unique_jti() {
        let room_id = Uuid::new_v4();
        let claims1 = WsTokenClaims::new(room_id, 30, TEST_ISS);
        let claims2 = WsTokenClaims::new(room_id, 30, TEST_ISS);

        // Each token should have a unique JTI
        assert_ne!(claims1.jti, claims2.jti, "JTI should be unique per token");
    }

    // Audit C-2 regression: aud/iss binding ----------------------------------
    //
    // verify_token MUST reject:
    //   (a) a token whose `aud` is anything other than WS_TOKEN_AUDIENCE,
    //       even with a matching secret and issuer — prevents a token minted
    //       for some other surface (admin endpoint, future internal service)
    //       from being replayed at the WS upgrade.
    //   (b) a token whose `iss` does not match the deployment's configured
    //       issuer — prevents cross-instance reuse when two PinChat instances
    //       happen to share an HMAC key during rotation.
    //   (c) a token missing either claim — relies on set_required_spec_claims.

    #[test]
    fn test_token_rejects_wrong_audience() {
        let secret = [11u8; 32];
        let mut claims = WsTokenClaims::new(Uuid::new_v4(), 30, TEST_ISS);
        claims.aud = "some-other-service".to_string();
        let token = sign_token(&claims, &secret).expect("sign");

        let result = verify_token(&token, &secret, TEST_ISS);
        assert!(
            result.is_err(),
            "Token with foreign `aud` must be rejected by aud-pinned verifier"
        );
    }

    #[test]
    fn test_token_rejects_wrong_issuer() {
        let secret = [13u8; 32];
        let claims = WsTokenClaims::new(Uuid::new_v4(), 30, "pinchat-prod-eu");
        let token = sign_token(&claims, &secret).expect("sign");

        // Same secret, different deployment identifier.
        let result = verify_token(&token, &secret, "pinchat-prod-us");
        assert!(
            result.is_err(),
            "Token from foreign issuer must be rejected by iss-pinned verifier"
        );

        // Sanity: matching issuer accepts.
        let ok = verify_token(&token, &secret, "pinchat-prod-eu");
        assert!(ok.is_ok(), "Matching issuer should verify");
    }

    #[test]
    fn test_token_rejects_missing_aud_or_iss() {
        // Build claims without aud/iss, mimicking a token from a verifier-only
        // upgrade that forgot the new fields.
        #[derive(serde::Serialize)]
        struct LegacyClaims {
            room_id: Uuid,
            connection_id: Uuid,
            exp: u64,
            jti: Uuid,
        }

        let secret = [17u8; 32];
        let claims = LegacyClaims {
            room_id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            exp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 30,
            jti: Uuid::new_v4(),
        };
        let header = Header::default();
        let encoding_key = EncodingKey::from_secret(&secret);
        let signed = encode(&header, &claims, &encoding_key).expect("sign");

        let result = verify_token(&signed, &secret, TEST_ISS);
        assert!(
            result.is_err(),
            "Token missing aud/iss must be rejected (set_required_spec_claims gate)"
        );
    }

    // F-07 regression tests --------------------------------------------------
    //
    // verify_token MUST reject:
    //   (a) a token signed with any algorithm other than HS256, even if the
    //       MAC key is correct. Otherwise an attacker who learned the secret
    //       could downgrade the algorithm and we'd have to trust the
    //       jsonwebtoken default-validation surface — which is documentation,
    //       not type-system enforcement.
    //   (b) a token missing the `exp` claim. The default Validation accepts
    //       missing-exp silently, which means an attacker who can mint
    //       claims could omit `exp` and produce a token that never expires.

    #[test]
    fn test_token_rejects_hs384_signature() {
        let secret = [7u8; 32];
        let claims = WsTokenClaims::new(Uuid::new_v4(), 30, TEST_ISS);

        // Forge a token with HS384 (alg confusion attempt). Same secret bytes,
        // just a different algorithm in the header.
        let mut header = Header::default();
        header.alg = Algorithm::HS384;
        let encoding_key = EncodingKey::from_secret(&secret);
        let forged = encode(&header, &claims, &encoding_key).expect("HS384 sign");

        // Production verifier MUST reject this even though the MAC is valid
        // under the same secret.
        let result = verify_token(&forged, &secret, TEST_ISS);
        assert!(
            result.is_err(),
            "HS384-signed token must be rejected by HS256-pinned verifier"
        );
    }

    #[test]
    fn test_token_rejects_missing_exp() {
        // Build a claims struct that mimics WsTokenClaims but without the
        // `exp` field. We use serde_json directly to construct the payload
        // because WsTokenClaims always has `exp: u64`.
        #[derive(serde::Serialize)]
        struct NoExpClaims {
            room_id: Uuid,
            connection_id: Uuid,
            jti: Uuid,
            aud: String,
            iss: String,
        }

        let secret = [3u8; 32];
        let claims = NoExpClaims {
            room_id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            jti: Uuid::new_v4(),
            aud: WS_TOKEN_AUDIENCE.to_string(),
            iss: TEST_ISS.to_string(),
        };
        let header = Header::default(); // HS256
        let encoding_key = EncodingKey::from_secret(&secret);
        let signed = encode(&header, &claims, &encoding_key).expect("sign");

        let result = verify_token(&signed, &secret, TEST_ISS);
        assert!(
            result.is_err(),
            "Token missing `exp` must be rejected (set_required_spec_claims gate)"
        );
    }

    #[test]
    fn test_token_rejects_hs512_signature() {
        // Same family of attack as HS384: a stronger MAC, still wrong algorithm.
        // Pin-to-HS256 must reject. Keeps test triangulation on the alg-pin
        // gate without bringing in the base64 dev-dep needed for alg=none.
        let secret = [9u8; 32];
        let claims = WsTokenClaims::new(Uuid::new_v4(), 30, TEST_ISS);

        let mut header = Header::default();
        header.alg = Algorithm::HS512;
        let encoding_key = EncodingKey::from_secret(&secret);
        let forged = encode(&header, &claims, &encoding_key).expect("HS512 sign");

        let result = verify_token(&forged, &secret, TEST_ISS);
        assert!(
            result.is_err(),
            "HS512-signed token must be rejected by HS256-pinned verifier"
        );
    }
}
