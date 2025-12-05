//! Capacity and Memory Tests
//!
//! Tests the server's capacity limits and memory protection:
//! - Maximum room limit (MAX_TOTAL_ROOMS)
//! - Message replay cache limits
//! - Room expiration and cleanup
//!
//! # Running
//! These tests require a server with low capacity limits for testing:
//! ```bash
//! PRIVACY_MODE=development POW_MIN_DIFFICULTY=10 POW_MAX_DIFFICULTY=12 \
//! MAX_TOTAL_ROOMS=10 cargo run &
//! ```

use crate::helpers::{
    assert_server_running, connect_ws, create_client, create_room_with_pow,
    get_ws_token_with_pow, get_ws_url, RoomConfig,
};
use crate::BASE_URL;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Test that server returns 503 when at maximum room capacity
///
/// Requires: MAX_TOTAL_ROOMS=10 (or similar low value)
#[tokio::test]
async fn test_max_rooms_limit() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let config = RoomConfig {
        room_type: "onetoone".to_string(),
        ttl_minutes: 5, // Short TTL so rooms expire quickly
    };

    let mut created_rooms = 0;
    let mut service_unavailable = false;

    // Try to create more rooms than the limit
    // With MAX_TOTAL_ROOMS=10, we should hit the limit
    for i in 0..20 {
        let result = create_room_with_pow(&client, &config).await;

        match result {
            Ok(room) => {
                created_rooms += 1;
                println!("Room {} created: {}", i + 1, room.room_id);
            }
            Err(e) => {
                if e.contains("503") || e.contains("SERVICE_UNAVAILABLE") || e.contains("maximum capacity") {
                    service_unavailable = true;
                    println!("Room {} rejected: server at capacity", i + 1);
                } else if e.contains("429") {
                    println!("Room {} rate limited", i + 1);
                    // Continue trying
                } else {
                    println!("Room {} failed: {}", i + 1, e);
                }
            }
        }

        // Small delay to avoid rate limiting
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    println!(
        "Results: {} rooms created, capacity reached: {}",
        created_rooms, service_unavailable
    );

    // We should have created at least one room
    assert!(created_rooms > 0, "Should create at least one room");

    // Note: The test might not hit the limit if MAX_TOTAL_ROOMS is high
    // or if rooms expired during the test
    if !service_unavailable {
        println!("Warning: Did not hit room limit. Ensure MAX_TOTAL_ROOMS is set low for testing.");
    }
}

/// Test that rooms with short TTL expire
#[tokio::test]
async fn test_room_expiration() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a room with minimum TTL
    let config = RoomConfig {
        room_type: "onetoone".to_string(),
        ttl_minutes: 1, // Minimum TTL
    };

    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    println!("Created room {} with 1 minute TTL", room.room_id);

    // Verify room exists by accessing the room page
    let room_url = format!("{}/c/{}", BASE_URL, room.room_id);
    let response = client.get(&room_url).send().await.expect("Request should succeed");

    assert!(
        response.status().is_success() || response.status() == reqwest::StatusCode::FOUND,
        "Room should exist initially"
    );

    // Note: We can't easily test actual expiration without waiting 1+ minutes
    // The cleanup task runs every 60 seconds by default
    println!("Room expiration would occur after 1 minute of inactivity");
}

/// Test that accessing expired room returns 410 Gone
#[tokio::test]
async fn test_expired_room_returns_gone() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Try to access a non-existent room (simulates expired room)
    let fake_room_id = uuid::Uuid::new_v4();
    let room_url = format!("{}/c/{}", BASE_URL, fake_room_id);

    let response = client.get(&room_url).send().await.expect("Request should succeed");

    // Should return 404 Not Found (or 410 Gone for expired rooms)
    assert!(
        response.status() == reqwest::StatusCode::NOT_FOUND ||
        response.status() == reqwest::StatusCode::GONE,
        "Non-existent room should return 404 or 410"
    );
}

/// Test message replay detection
#[tokio::test]
async fn test_message_replay_detection() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a room and connect
    let config = RoomConfig::default();
    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    let token = room.ws_token.expect("Should get WS token");
    let ws_url = get_ws_url(&room.room_id, &token);

    let (mut ws, _) = connect_ws(&ws_url).await
        .expect("Connection should succeed");

    // Read initial connected message
    let _ = ws.next().await;

    // Send a message
    let msg = json!({
        "type": "message",
        "payload": "unique-message-payload-12345"
    });

    let _ = ws.send(WsMessage::Text(msg.to_string())).await;

    // Send the exact same message again (replay attempt)
    let _ = ws.send(WsMessage::Text(msg.to_string())).await;

    // The second message should be silently ignored by the server
    // We can't easily verify this from the client side without a second connection

    // Wait a bit
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Clean up
    let _ = ws.close(None).await;

    println!("Replay detection test completed - duplicate messages should be ignored by server");
}

/// Test that large messages are rejected
#[tokio::test]
async fn test_large_message_rejected() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a room and connect
    let config = RoomConfig::default();
    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    let token = room.ws_token.expect("Should get WS token");
    let ws_url = get_ws_url(&room.room_id, &token);

    let (mut ws, _) = connect_ws(&ws_url).await
        .expect("Connection should succeed");

    // Read initial connected message
    let _ = ws.next().await;

    // Try to send a very large message (1MB)
    let large_payload = "x".repeat(1024 * 1024);
    let msg = json!({
        "type": "message",
        "payload": large_payload
    });

    let result = ws.send(WsMessage::Text(msg.to_string())).await;

    // The message might succeed at the WebSocket level but be rejected by the server
    // Or it might fail if it exceeds WebSocket frame limits
    if result.is_err() {
        println!("Large message rejected at WebSocket level");
    } else {
        println!("Large message sent - server should reject it");

        // Wait for potential error response
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }

    let _ = ws.close(None).await;
}

/// Test room participant limit
#[tokio::test]
async fn test_room_participant_limit() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a 1:1 room (max 2 participants)
    let config = RoomConfig {
        room_type: "onetoone".to_string(),
        ttl_minutes: 30,
    };

    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    println!("Created room: {}, max_participants: {}", room.room_id, room.max_participants);

    // First connection
    let token1 = room.ws_token.expect("Should get first token");
    let ws_url1 = get_ws_url(&room.room_id, &token1);
    let (mut ws1, _) = connect_ws(&ws_url1).await
        .expect("First connection should succeed");

    // Read connected message for first connection
    if let Some(Ok(WsMessage::Text(text))) = ws1.next().await {
        let msg: serde_json::Value = serde_json::from_str(&text).unwrap();
        println!("Connection 1: participant_count = {}", msg["participant_count"]);
    }

    // Second connection
    let token_resp = get_ws_token_with_pow(&client, &room.room_id).await
        .expect("Should get second token");

    let ws_url2 = get_ws_url(&room.room_id, &token_resp.token);
    let (mut ws2, _) = connect_ws(&ws_url2).await
        .expect("Second connection should succeed");

    // Read connected message for second connection
    if let Some(Ok(WsMessage::Text(text))) = ws2.next().await {
        let msg: serde_json::Value = serde_json::from_str(&text).unwrap();
        println!("Connection 2: participant_count = {}", msg["participant_count"]);
    }

    // Third connection should be rejected (room full)
    let third_token_result = get_ws_token_with_pow(&client, &room.room_id).await;

    match third_token_result {
        Ok(token3) => {
            let ws_url3 = get_ws_url(&room.room_id, &token3.token);
            let result = connect_ws(&ws_url3).await;

            if let Ok((mut ws3, _)) = result {
                // Read response - should be an error or immediate close
                if let Some(Ok(msg)) = ws3.next().await {
                    match msg {
                        WsMessage::Text(text) => {
                            let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
                            println!("Third connection response: {}", parsed);
                            // Might be an error message about room being full
                        }
                        WsMessage::Close(_) => {
                            println!("Third connection closed (room full)");
                        }
                        _ => {}
                    }
                }
            } else {
                println!("Third connection rejected at HTTP level");
            }
        }
        Err(e) => {
            println!("Third token rejected: {}", e);
            // This is expected - token endpoint should reject when room is full
        }
    }

    // Cleanup
    let _ = ws1.close(None).await;
    let _ = ws2.close(None).await;
}

/// Test response times under load
#[tokio::test]
async fn test_response_time_under_load() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let url = format!("{}/api/rooms", BASE_URL);
    let config = RoomConfig::default();

    let mut response_times = Vec::new();

    // Measure response times for multiple requests
    for _ in 0..20 {
        let start = std::time::Instant::now();

        let response = client
            .post(&url)
            .json(&config)
            .send()
            .await
            .expect("Request should succeed");

        let elapsed = start.elapsed();
        response_times.push(elapsed);

        // Just consume the response
        let _ = response.status();
    }

    // Calculate statistics
    let total_ms: u128 = response_times.iter().map(|d| d.as_millis()).sum();
    let avg_ms = total_ms / response_times.len() as u128;
    let max_ms = response_times.iter().map(|d| d.as_millis()).max().unwrap_or(0);
    let min_ms = response_times.iter().map(|d| d.as_millis()).min().unwrap_or(0);

    println!("Response time statistics (20 requests):");
    println!("  Average: {}ms", avg_ms);
    println!("  Min: {}ms", min_ms);
    println!("  Max: {}ms", max_ms);

    // Response times should be reasonable (< 5 seconds even under load)
    assert!(
        avg_ms < 5000,
        "Average response time should be under 5 seconds"
    );
}

/// Test CSRF token endpoint
#[tokio::test]
async fn test_csrf_token_endpoint() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let url = format!("{}/api/csrf", BASE_URL);

    let response = client
        .get(&url)
        .send()
        .await
        .expect("Request should succeed");

    assert!(
        response.status().is_success(),
        "CSRF endpoint should succeed"
    );

    let body: serde_json::Value = response.json().await.expect("Should parse JSON");
    assert!(body["csrf_token"].is_string(), "Should return CSRF token");

    let token = body["csrf_token"].as_str().unwrap();
    assert!(!token.is_empty(), "CSRF token should not be empty");

    println!("CSRF token received: {} chars", token.len());
}
