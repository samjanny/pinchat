//! Helper utilities for stress tests
//!
//! Provides common functionality for:
//! - HTTP client configuration
//! - Proof-of-Work solving
//! - Test assertions and utilities

use reqwest::Client;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::{BASE_URL, WS_URL};

/// Response from room creation or token request when PoW is required
#[derive(Debug, Deserialize)]
pub struct PowChallengeResponse {
    pub error: String,
    pub pow_required: Option<bool>,
    pub challenge: Option<String>,
    pub mask: Option<String>,
    pub difficulty: Option<u8>,
}

/// Response from successful room creation
#[derive(Debug, Deserialize)]
pub struct CreateRoomResponse {
    pub room_id: String,
    pub room_type: String,
    pub ttl_minutes: u32,
    pub max_participants: usize,
    pub ws_token: Option<String>,
    pub connection_id: Option<String>,
}

/// Response from successful WebSocket token generation
#[derive(Debug, Deserialize)]
pub struct WsTokenResponse {
    pub token: String,
    pub connection_id: String,
    pub expires_in: u64,
}

/// Room configuration for creation
#[derive(Debug, Serialize)]
pub struct RoomConfig {
    pub room_type: String,
    pub ttl_minutes: u32,
}

impl Default for RoomConfig {
    fn default() -> Self {
        Self {
            room_type: "onetoone".to_string(),
            ttl_minutes: 30,
        }
    }
}

/// Creates a configured HTTP client for testing
/// Accepts self-signed certificates for local development
pub fn create_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true) // Accept self-signed certs
        .build()
        .expect("Failed to create HTTP client")
}

/// Creates a client with custom timeout
/// Accepts self-signed certificates for local development
pub fn create_client_with_timeout(timeout_secs: u64) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true) // Accept self-signed certs
        .build()
        .expect("Failed to create HTTP client")
}

/// Solves a Proof-of-Work challenge
///
/// # Arguments
/// * `challenge` - The challenge string from the server
/// * `mask` - The hexadecimal mask for validation
/// * `max_iterations` - Maximum number of attempts before giving up
///
/// # Returns
/// `Some(nonce)` if a solution is found, `None` if max iterations reached
pub fn solve_pow(challenge: &str, mask: &str, max_iterations: u64) -> Option<u64> {
    let mask_bytes = hex::decode(mask).ok()?;

    for nonce in 0..max_iterations {
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", challenge, nonce));
        let hash = hasher.finalize();

        // Verify: (hash & mask) == mask
        let valid = mask_bytes
            .iter()
            .zip(hash.iter())
            .all(|(mask_byte, hash_byte)| mask_byte == &(mask_byte & hash_byte));

        if valid {
            return Some(nonce);
        }
    }

    None
}

/// Solves a Proof-of-Work challenge with difficulty instead of mask
///
/// # Arguments
/// * `challenge` - The challenge string from the server
/// * `difficulty` - Number of leading bits that must match
/// * `max_iterations` - Maximum number of attempts before giving up
///
/// # Returns
/// `Some(nonce)` if a solution is found, `None` if max iterations reached
pub fn solve_pow_with_difficulty(challenge: &str, difficulty: u8, max_iterations: u64) -> Option<u64> {
    let mask = generate_mask(difficulty);
    solve_pow(challenge, &mask, max_iterations)
}

/// Generates a binary mask based on difficulty level (matches server implementation)
fn generate_mask(difficulty: u8) -> String {
    let difficulty = difficulty.min(255);
    let full_bytes = (difficulty / 8) as usize;
    let remaining_bits = difficulty % 8;

    let mut mask = vec![0xFF; full_bytes];

    if remaining_bits > 0 {
        let partial_byte = 0xFF << (8 - remaining_bits);
        mask.push(partial_byte);
    }

    mask.resize(32, 0x00);
    hex::encode(mask)
}

/// Creates a room with PoW solving
///
/// # Returns
/// `Ok(CreateRoomResponse)` on success, `Err(String)` on failure
pub async fn create_room_with_pow(
    client: &Client,
    config: &RoomConfig,
) -> Result<CreateRoomResponse, String> {
    let url = format!("{}/api/rooms", BASE_URL);

    // First request - get the PoW challenge
    let response = client
        .post(&url)
        .json(config)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == reqwest::StatusCode::PRECONDITION_REQUIRED {
        // Parse challenge
        let challenge_resp: PowChallengeResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse challenge: {}", e))?;

        let challenge = challenge_resp.challenge.ok_or("No challenge in response")?;
        let mask = challenge_resp.mask.ok_or("No mask in response")?;

        // Solve PoW
        let nonce = solve_pow(&challenge, &mask, 10_000_000)
            .ok_or("Failed to solve PoW within iteration limit")?;

        // Second request with nonce
        let response = client
            .post(&url)
            .header("x-pow-nonce", nonce.to_string())
            .json(config)
            .send()
            .await
            .map_err(|e| format!("Second request failed: {}", e))?;

        if response.status().is_success() {
            response
                .json()
                .await
                .map_err(|e| format!("Failed to parse room response: {}", e))
        } else {
            Err(format!("Room creation failed: {}", response.status()))
        }
    } else if response.status().is_success() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse room response: {}", e))
    } else {
        Err(format!("Unexpected response: {}", response.status()))
    }
}

/// Gets a WebSocket token with PoW solving
///
/// # Returns
/// `Ok(WsTokenResponse)` on success, `Err(String)` on failure
pub async fn get_ws_token_with_pow(
    client: &Client,
    room_id: &str,
) -> Result<WsTokenResponse, String> {
    let url = format!("{}/api/ws-token/{}", BASE_URL, room_id);

    // First request - get the PoW challenge
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == reqwest::StatusCode::PRECONDITION_REQUIRED {
        // Parse challenge
        let challenge_resp: PowChallengeResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse challenge: {}", e))?;

        let challenge = challenge_resp.challenge.ok_or("No challenge in response")?;
        let difficulty = challenge_resp.difficulty.ok_or("No difficulty in response")?;

        // Solve PoW
        let nonce = solve_pow_with_difficulty(&challenge, difficulty, 10_000_000)
            .ok_or("Failed to solve PoW within iteration limit")?;

        // Second request with nonce
        let response = client
            .get(&url)
            .header("x-pow-nonce", nonce.to_string())
            .send()
            .await
            .map_err(|e| format!("Second request failed: {}", e))?;

        if response.status().is_success() {
            response
                .json()
                .await
                .map_err(|e| format!("Failed to parse token response: {}", e))
        } else {
            Err(format!("Token generation failed: {}", response.status()))
        }
    } else if response.status().is_success() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))
    } else {
        Err(format!("Unexpected response: {}", response.status()))
    }
}

/// Gets the WebSocket URL for a room
pub fn get_ws_url(room_id: &str, token: &str) -> String {
    format!("{}/ws/{}?token={}", WS_URL, room_id, token)
}

/// Creates a TLS connector that accepts self-signed certificates
pub fn create_tls_connector() -> tokio_tungstenite::Connector {
    let tls_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("Failed to create TLS connector");

    tokio_tungstenite::Connector::NativeTls(tls_connector)
}

/// Connects to a WebSocket URL with self-signed certificate support
pub async fn connect_ws(url: &str) -> Result<
    (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>
        >,
        tokio_tungstenite::tungstenite::http::Response<Option<Vec<u8>>>
    ),
    tokio_tungstenite::tungstenite::Error
> {
    let request = url::Url::parse(url).expect("Invalid URL");
    tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(create_tls_connector()),
    ).await
}

/// Extracts PoW challenge and mask from a 428 response
pub async fn get_pow_challenge_from_response(response: reqwest::Response) -> Option<(String, String)> {
    if response.status() != reqwest::StatusCode::PRECONDITION_REQUIRED {
        return None;
    }

    let challenge_resp: PowChallengeResponse = response.json().await.ok()?;
    let challenge = challenge_resp.challenge?;
    let mask = challenge_resp.mask?;
    Some((challenge, mask))
}

/// Creates a room with PoW solving and custom IP (via X-Forwarded-For)
pub async fn create_room_with_pow_and_ip(
    client: &Client,
    config: &RoomConfig,
    ip: &str,
) -> Result<CreateRoomResponse, String> {
    let url = format!("{}/api/rooms", BASE_URL);

    // First request - get the PoW challenge
    let response = client
        .post(&url)
        .header("X-Forwarded-For", ip)
        .json(config)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == reqwest::StatusCode::PRECONDITION_REQUIRED {
        // Parse challenge
        let challenge_resp: PowChallengeResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse challenge: {}", e))?;

        let challenge = challenge_resp.challenge.ok_or("No challenge in response")?;
        let mask = challenge_resp.mask.ok_or("No mask in response")?;

        // Solve PoW
        let nonce = solve_pow(&challenge, &mask, 10_000_000)
            .ok_or("Failed to solve PoW within iteration limit")?;

        // Second request with nonce
        let response = client
            .post(&url)
            .header("X-Forwarded-For", ip)
            .header("x-pow-nonce", nonce.to_string())
            .json(config)
            .send()
            .await
            .map_err(|e| format!("Second request failed: {}", e))?;

        if response.status().is_success() {
            response
                .json()
                .await
                .map_err(|e| format!("Failed to parse room response: {}", e))
        } else {
            Err(format!("Room creation failed: {}", response.status()))
        }
    } else if response.status().is_success() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse room response: {}", e))
    } else if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        Err("Rate limited (429)".to_string())
    } else {
        Err(format!("Unexpected response: {}", response.status()))
    }
}

/// Asserts that a server is running and accessible
pub async fn assert_server_running(client: &Client) -> Result<(), String> {
    let url = format!("{}/static/index.html", BASE_URL);

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Server not accessible: {}. Make sure the server is running.", e))?;

    if response.status().is_success() || response.status() == reqwest::StatusCode::FOUND {
        Ok(())
    } else {
        Err(format!("Unexpected server response: {}", response.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_solver_low_difficulty() {
        // Test with 4-bit difficulty (should solve quickly)
        let challenge = "test-challenge-123";
        let mask = generate_mask(4);

        let result = solve_pow(challenge, &mask, 1000);
        assert!(result.is_some(), "Should solve 4-bit PoW within 1000 iterations");
    }

    #[test]
    fn test_mask_generation() {
        // 8-bit mask
        let mask_8 = generate_mask(8);
        assert_eq!(&mask_8[0..2], "ff");
        assert_eq!(&mask_8[2..4], "00");

        // 16-bit mask
        let mask_16 = generate_mask(16);
        assert_eq!(&mask_16[0..4], "ffff");
        assert_eq!(&mask_16[4..6], "00");
    }

    #[test]
    fn test_pow_verification() {
        let challenge = "unique-test-challenge";
        let mask = generate_mask(8);

        // Find a valid nonce
        let nonce = solve_pow(challenge, &mask, 100_000).expect("Should find valid nonce");

        // Verify the nonce works
        let mask_bytes = hex::decode(&mask).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", challenge, nonce));
        let hash = hasher.finalize();

        let valid = mask_bytes
            .iter()
            .zip(hash.iter())
            .all(|(mask_byte, hash_byte)| mask_byte == &(mask_byte & hash_byte));

        assert!(valid, "Solved nonce should verify correctly");
    }
}
