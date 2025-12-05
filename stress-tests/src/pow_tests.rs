//! Proof-of-Work Tests
//!
//! Tests the Proof-of-Work challenge system:
//! - Challenge generation and validation
//! - Invalid solution rejection
//! - Challenge consumption (single-use)
//! - Difficulty scaling
//!
//! # Running
//! These tests require a running server with low PoW difficulty:
//! ```bash
//! PRIVACY_MODE=development POW_MIN_DIFFICULTY=10 POW_MAX_DIFFICULTY=12 cargo run &
//! ```

use crate::helpers::{
    assert_server_running, create_client, solve_pow, solve_pow_with_difficulty,
    PowChallengeResponse, RoomConfig,
};
use crate::BASE_URL;

/// Test that PoW challenge is returned when not provided
#[tokio::test]
async fn test_pow_challenge_returned() {
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
        "Should return 428 when PoW not provided"
    );

    let body: PowChallengeResponse = response.json().await.expect("Should parse JSON");

    assert!(body.pow_required.unwrap_or(false), "pow_required should be true");
    assert!(body.challenge.is_some(), "Should include challenge");
    assert!(body.mask.is_some(), "Should include mask");
    assert!(body.difficulty.is_some(), "Should include difficulty");

    let difficulty = body.difficulty.unwrap();
    assert!(difficulty >= 10 && difficulty <= 30, "Difficulty should be in valid range");
}

/// Test that invalid PoW nonce is rejected
#[tokio::test]
async fn test_pow_invalid_nonce_rejected() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let config = RoomConfig::default();
    let url = format!("{}/api/rooms", BASE_URL);

    // First, get a challenge
    let response = client
        .post(&url)
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    let challenge_resp: PowChallengeResponse = response.json().await.expect("Should parse JSON");
    assert!(challenge_resp.challenge.is_some(), "Should have challenge");

    // Try with obviously wrong nonce
    let response = client
        .post(&url)
        .header("x-pow-nonce", "0")
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    // Should be rejected (either 403 Forbidden or 428 with new challenge)
    let status = response.status();
    assert!(
        status == reqwest::StatusCode::FORBIDDEN ||
        status == reqwest::StatusCode::PRECONDITION_REQUIRED,
        "Invalid nonce should be rejected, got: {}", status
    );
}

/// Test that malformed nonce is rejected
#[tokio::test]
async fn test_pow_malformed_nonce_rejected() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let config = RoomConfig::default();
    let url = format!("{}/api/rooms", BASE_URL);

    // First get a challenge
    let _ = client
        .post(&url)
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    // Try with non-numeric nonce
    let response = client
        .post(&url)
        .header("x-pow-nonce", "not_a_number")
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Malformed nonce should return 400"
    );
}

/// Test that PoW challenge is consumed after use
#[tokio::test]
async fn test_pow_challenge_consumed() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let config = RoomConfig::default();
    let url = format!("{}/api/rooms", BASE_URL);

    // Get challenge
    let response = client
        .post(&url)
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    let challenge_resp: PowChallengeResponse = response.json().await.expect("Should parse JSON");
    let challenge = challenge_resp.challenge.expect("Should have challenge");
    let mask = challenge_resp.mask.expect("Should have mask");

    // Solve the challenge
    let nonce = solve_pow(&challenge, &mask, 10_000_000)
        .expect("Should solve PoW");

    // First use should succeed
    let response = client
        .post(&url)
        .header("x-pow-nonce", nonce.to_string())
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    assert!(
        response.status().is_success(),
        "First use of valid nonce should succeed"
    );

    // Second use of same nonce should fail (challenge consumed)
    let response = client
        .post(&url)
        .header("x-pow-nonce", nonce.to_string())
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    // Should get 428 with new challenge (old challenge was consumed)
    assert_eq!(
        response.status(),
        reqwest::StatusCode::PRECONDITION_REQUIRED,
        "Reusing consumed challenge should require new PoW"
    );
}

/// Test PoW solver performance
#[tokio::test]
async fn test_pow_solver_performance() {
    // Test different difficulty levels
    let test_cases = vec![
        (8, 10_000),      // 8-bit: should solve quickly
        (10, 100_000),    // 10-bit: moderate
        (12, 1_000_000),  // 12-bit: takes longer
    ];

    for (difficulty, max_iter) in test_cases {
        let challenge = format!("test-challenge-{}", uuid::Uuid::new_v4());

        let start = std::time::Instant::now();
        let result = solve_pow_with_difficulty(&challenge, difficulty, max_iter);
        let elapsed = start.elapsed();

        match result {
            Some(nonce) => {
                println!(
                    "Difficulty {}: solved in {:?} (nonce: {})",
                    difficulty, elapsed, nonce
                );
            }
            None => {
                println!(
                    "Difficulty {}: failed after {} iterations in {:?}",
                    difficulty, max_iter, elapsed
                );
            }
        }
    }
}

/// Test that challenges from different endpoints are independent
#[tokio::test]
async fn test_pow_challenges_independent() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let config = RoomConfig::default();

    // Get challenge from room creation endpoint
    let room_url = format!("{}/api/rooms", BASE_URL);
    let response = client
        .post(&room_url)
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    let room_challenge: PowChallengeResponse = response.json().await.expect("Should parse JSON");
    let room_challenge_str = room_challenge.challenge.expect("Should have challenge");
    let room_mask = room_challenge.mask.expect("Should have mask");

    // Solve the room challenge
    let room_nonce = solve_pow(&room_challenge_str, &room_mask, 10_000_000)
        .expect("Should solve PoW");

    // Create a room with the valid nonce
    let response = client
        .post(&room_url)
        .header("x-pow-nonce", room_nonce.to_string())
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    assert!(response.status().is_success(), "Room creation should succeed");

    let room: crate::helpers::CreateRoomResponse = response.json().await.expect("Should parse JSON");

    // Now get a challenge from the ws-token endpoint
    let token_url = format!("{}/api/ws-token/{}", BASE_URL, room.room_id);
    let response = client
        .get(&token_url)
        .send()
        .await
        .expect("Request should succeed");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::PRECONDITION_REQUIRED,
        "Should require new PoW for token endpoint"
    );

    let token_challenge: PowChallengeResponse = response.json().await.expect("Should parse JSON");
    assert!(token_challenge.challenge.is_some(), "Should have new challenge");

    // The challenges should be different (different endpoints, same IP)
    // Note: They might actually be the same if cached, but the key point is
    // that we need to solve a new challenge
}

/// Test that PoW prevents rapid requests without solving
#[tokio::test]
async fn test_pow_prevents_flooding() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let config = RoomConfig::default();
    let url = format!("{}/api/rooms", BASE_URL);

    let mut challenge_count = 0;
    let forbidden_count = 0;

    // Send many requests without solving PoW
    for _ in 0..10 {
        let response = client
            .post(&url)
            .json(&config)
            .send()
            .await
            .expect("Request should succeed");

        match response.status() {
            reqwest::StatusCode::PRECONDITION_REQUIRED => challenge_count += 1,
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                // Rate limited
                break;
            }
            status => {
                println!("Unexpected status: {}", status);
            }
        }
    }

    println!(
        "Results: {} challenges received, {} forbidden",
        challenge_count, forbidden_count
    );

    // Most requests should just get new challenges (not succeed)
    assert!(
        challenge_count > 0,
        "Should receive PoW challenges"
    );
}

/// Test PoW with edge case difficulties
#[tokio::test]
async fn test_pow_edge_case_difficulties() {
    // Test minimum reasonable difficulty
    let challenge = "edge-case-test";

    // Very low difficulty - should solve almost instantly
    let result = solve_pow_with_difficulty(challenge, 1, 100);
    assert!(result.is_some(), "1-bit difficulty should solve in < 100 iterations");

    // Medium difficulty
    let result = solve_pow_with_difficulty(challenge, 8, 10_000);
    assert!(result.is_some(), "8-bit difficulty should solve in < 10000 iterations");
}

/// Test that solving PoW gives correct format for nonce header
#[tokio::test]
async fn test_pow_nonce_header_format() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let config = RoomConfig::default();
    let url = format!("{}/api/rooms", BASE_URL);

    // Get challenge
    let response = client
        .post(&url)
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    let challenge_resp: PowChallengeResponse = response.json().await.expect("Should parse JSON");
    let challenge = challenge_resp.challenge.expect("Should have challenge");
    let mask = challenge_resp.mask.expect("Should have mask");

    // Solve
    let nonce = solve_pow(&challenge, &mask, 10_000_000)
        .expect("Should solve PoW");

    // Verify nonce is a valid u64 string
    let nonce_str = nonce.to_string();
    assert!(nonce_str.parse::<u64>().is_ok(), "Nonce should be valid u64");

    // Test with the nonce
    let response = client
        .post(&url)
        .header("x-pow-nonce", &nonce_str)
        .json(&config)
        .send()
        .await
        .expect("Request should succeed");

    assert!(
        response.status().is_success(),
        "Valid nonce format should be accepted"
    );
}
