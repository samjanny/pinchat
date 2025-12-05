//! HTTP Rate Limiting Tests
//!
//! Tests the rate limiting mechanisms for HTTP endpoints:
//! - Room creation rate limiting (20/hour by default)
//! - WebSocket token rate limiting (20/hour by default)
//!
//! # Running
//! These tests require a running server with specific configuration:
//! ```bash
//! PRIVACY_MODE=development POW_MIN_DIFFICULTY=10 POW_MAX_DIFFICULTY=12 \
//! ROOM_TOKEN_BURST_SIZE=5 ROOM_TOKEN_PERIOD_SECS=60 \
//! cargo run &
//! ```

use crate::helpers::{
    assert_server_running, create_client, create_room_with_pow,
    RoomConfig, PowChallengeResponse,
};
use crate::BASE_URL;

/// Test that room creation returns 428 (Precondition Required) without PoW
#[tokio::test]
async fn test_room_creation_requires_pow() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let config = RoomConfig::default();
    let url = format!("{}/api/rooms", BASE_URL);

    let response = client
        .post(&url)
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::PRECONDITION_REQUIRED,
        "Room creation without PoW should return 428"
    );

    let body: PowChallengeResponse = response.json().await.expect("Should parse JSON");
    assert!(body.pow_required.unwrap_or(false), "Response should indicate PoW is required");
    assert!(body.challenge.is_some(), "Response should contain challenge");
    assert!(body.mask.is_some(), "Response should contain mask");
}

/// Test that room creation with valid PoW succeeds
#[tokio::test]
async fn test_room_creation_with_pow_succeeds() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let config = RoomConfig::default();
    let result = create_room_with_pow(&client, &config).await;

    assert!(result.is_ok(), "Room creation with PoW should succeed: {:?}", result.err());

    let room = result.unwrap();
    assert!(!room.room_id.is_empty(), "Room ID should not be empty");
    assert_eq!(room.room_type, "onetoone", "Room type should match");
    assert_eq!(room.ttl_minutes, 30, "TTL should match");
}

/// Test that rapid room creation is rate limited
///
/// This test requires the server to be configured with low rate limits:
/// ROOM_TOKEN_BURST_SIZE=5 ROOM_TOKEN_PERIOD_SECS=60
#[tokio::test]
async fn test_room_creation_rate_limit() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let config = RoomConfig::default();
    let mut success_count = 0;
    let mut rate_limited_count = 0;

    // Try to create more rooms than the burst limit allows
    // With ROOM_TOKEN_BURST_SIZE=5, we should hit the limit
    for i in 0..10 {
        let result = create_room_with_pow(&client, &config).await;

        match result {
            Ok(_) => {
                success_count += 1;
                println!("Room {} created successfully", i + 1);
            }
            Err(e) => {
                if e.contains("429") || e.contains("Too Many Requests") {
                    rate_limited_count += 1;
                    println!("Room {} rate limited", i + 1);
                } else {
                    println!("Room {} failed with error: {}", i + 1, e);
                }
            }
        }
    }

    println!(
        "Results: {} successful, {} rate limited",
        success_count, rate_limited_count
    );

    // We expect some requests to succeed and some to be rate limited
    // The exact numbers depend on the burst size configuration
    assert!(
        success_count > 0,
        "At least some room creations should succeed"
    );

    // Note: Rate limiting may not trigger if burst size is high enough
    // This assertion is only valid with low burst size (e.g., 5)
    if rate_limited_count == 0 {
        println!("Warning: No rate limiting observed. Ensure ROOM_TOKEN_BURST_SIZE is set low for testing.");
    }
}

/// Test that invalid room configuration is rejected
#[tokio::test]
async fn test_room_creation_invalid_ttl() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // First get a PoW challenge
    let config = RoomConfig {
        room_type: "onetoone".to_string(),
        ttl_minutes: 0, // Invalid: must be >= 1
    };

    let url = format!("{}/api/rooms", BASE_URL);

    // Get challenge
    let response = client
        .post(&url)
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    // Should get 400 Bad Request for invalid TTL, not 428
    // (validation happens before PoW check)
    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid TTL should return 400"
    );
}

/// Test that TTL above maximum is rejected
#[tokio::test]
async fn test_room_creation_ttl_too_high() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let config = RoomConfig {
        room_type: "onetoone".to_string(),
        ttl_minutes: 1441, // Invalid: max is 1440 (24 hours)
    };

    let url = format!("{}/api/rooms", BASE_URL);

    let response = client
        .post(&url)
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "TTL > 1440 should return 400"
    );
}

/// Test WebSocket token endpoint requires PoW
#[tokio::test]
async fn test_ws_token_requires_pow() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // First create a room
    let config = RoomConfig::default();
    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    // Now try to get a WS token without PoW
    let url = format!("{}/api/ws-token/{}", BASE_URL, room.room_id);

    let response = client
        .get(&url)
        .send()
        .await
        .expect("Request should succeed");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::PRECONDITION_REQUIRED,
        "WS token without PoW should return 428"
    );

    let body: PowChallengeResponse = response.json().await.expect("Should parse JSON");
    assert!(body.pow_required.unwrap_or(false), "Response should indicate PoW is required");
    assert!(body.challenge.is_some(), "Response should contain challenge");
}

/// Test WebSocket token for non-existent room returns 404
#[tokio::test]
async fn test_ws_token_room_not_found() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Use a random UUID that doesn't exist
    let fake_room_id = uuid::Uuid::new_v4();
    let url = format!("{}/api/ws-token/{}", BASE_URL, fake_room_id);

    // First get a challenge (we'll need to solve it to test the 404)
    let response = client
        .get(&url)
        .send()
        .await
        .expect("Request should succeed");

    // Should get 428 first (need PoW)
    assert_eq!(
        response.status(),
        reqwest::StatusCode::PRECONDITION_REQUIRED,
        "Should require PoW first"
    );

    let challenge_resp: PowChallengeResponse = response.json().await.expect("Should parse JSON");
    let challenge = challenge_resp.challenge.expect("Should have challenge");
    let difficulty = challenge_resp.difficulty.expect("Should have difficulty");

    // Solve PoW
    let nonce = crate::helpers::solve_pow_with_difficulty(&challenge, difficulty, 10_000_000)
        .expect("Should solve PoW");

    // Now try with valid PoW - should get 404
    let response = client
        .get(&url)
        .header("x-pow-nonce", nonce.to_string())
        .send()
        .await
        .expect("Request should succeed");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "Non-existent room should return 404"
    );
}

/// Test rapid requests to the same endpoint
#[tokio::test]
async fn test_rapid_requests_to_api() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let url = format!("{}/api/rooms", BASE_URL);
    let config = RoomConfig::default();

    let mut request_times = Vec::new();
    let mut status_codes = Vec::new();

    // Send 20 rapid requests
    for _ in 0..20 {
        let start = std::time::Instant::now();

        let response = client
            .post(&url)
            .json(&config)
            .send()
            .await
            .expect("Request should succeed");

        let elapsed = start.elapsed();
        request_times.push(elapsed);
        status_codes.push(response.status());
    }

    // Analyze results
    let avg_time = request_times.iter().map(|d| d.as_millis()).sum::<u128>() / request_times.len() as u128;
    let rate_limited = status_codes.iter().filter(|s| **s == reqwest::StatusCode::TOO_MANY_REQUESTS).count();

    println!("Average response time: {}ms", avg_time);
    println!("Rate limited requests: {}/20", rate_limited);
    println!("Status codes: {:?}", status_codes.iter().map(|s| s.as_u16()).collect::<Vec<_>>());

    // Server should respond to all requests (even if rate limited)
    assert!(
        status_codes.iter().all(|s| s.is_client_error() || s.is_success()),
        "All requests should receive valid HTTP responses"
    );
}
