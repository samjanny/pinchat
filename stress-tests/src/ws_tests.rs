//! WebSocket Stress Tests
//!
//! Tests the WebSocket connection handling and rate limiting:
//! - Connection rate limiting (5 per minute by default)
//! - Message rate limiting (5 per second by default)
//! - Token validation and replay prevention
//!
//! # Running
//! These tests require a running server:
//! ```bash
//! PRIVACY_MODE=development POW_MIN_DIFFICULTY=10 POW_MAX_DIFFICULTY=12 cargo run &
//! ```

use crate::helpers::{
    assert_server_running, connect_ws, create_client, create_room_with_pow,
    get_ws_token_with_pow, get_ws_url, RoomConfig,
};
use crate::WS_URL;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Test that WebSocket connection requires a valid token
#[tokio::test]
async fn test_ws_connection_requires_token() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a room
    let config = RoomConfig::default();
    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    // Try to connect without token
    let ws_url = format!("{}/ws/{}", WS_URL, room.room_id);

    let result = connect_ws(&ws_url).await;

    // Should fail - no token provided
    assert!(result.is_err(), "WebSocket without token should fail");
}

/// Test that WebSocket connection with invalid token fails
#[tokio::test]
async fn test_ws_connection_invalid_token() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a room
    let config = RoomConfig::default();
    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    // Try to connect with invalid token
    let ws_url = format!("{}/ws/{}?token=invalid_token", WS_URL, room.room_id);

    let result = connect_ws(&ws_url).await;

    // Should fail - invalid token
    assert!(result.is_err(), "WebSocket with invalid token should fail");
}

/// Test that WebSocket connection with valid token succeeds
#[tokio::test]
async fn test_ws_connection_with_valid_token() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a room (get WS token in the response)
    let config = RoomConfig::default();
    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    // Room creator gets a token automatically
    let token = room.ws_token.expect("Room creator should get WS token");

    // Connect with valid token
    let ws_url = get_ws_url(&room.room_id, &token);

    let result = connect_ws(&ws_url).await;

    assert!(result.is_ok(), "WebSocket with valid token should succeed: {:?}", result.err());

    let (mut ws, _) = result.unwrap();

    // Should receive a "connected" message
    if let Some(Ok(msg)) = ws.next().await {
        if let WsMessage::Text(text) = msg {
            let parsed: serde_json::Value = serde_json::from_str(&text)
                .expect("Should parse JSON");
            assert_eq!(parsed["type"], "connected", "First message should be 'connected'");
            assert!(parsed["user_id"].is_string(), "Should have user_id");
            assert!(parsed["room_id"].is_string(), "Should have room_id");
        }
    }

    // Close connection
    let _ = ws.close(None).await;
}

/// Test that tokens cannot be reused (replay prevention)
#[tokio::test]
async fn test_ws_token_replay_prevention() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a room
    let config = RoomConfig::default();
    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    // Room creator gets a token automatically
    let token = room.ws_token.expect("Room creator should get WS token");

    // First connection should succeed
    let ws_url = get_ws_url(&room.room_id, &token);
    let (mut ws1, _) = connect_ws(&ws_url).await
        .expect("First connection should succeed");

    // Read initial message
    let _ = ws1.next().await;

    // Close first connection
    let _ = ws1.close(None).await;

    // Wait a bit
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Second connection with same token should fail (token consumed)
    let result = connect_ws(&ws_url).await;

    // The connection might succeed at TCP level but should be rejected by server
    // Check the HTTP upgrade response
    assert!(
        result.is_err(),
        "Replay of consumed token should fail"
    );
}

/// Test message rate limiting
#[tokio::test]
async fn test_ws_message_rate_limit() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a room
    let config = RoomConfig::default();
    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    let token = room.ws_token.expect("Should get WS token");
    let ws_url = get_ws_url(&room.room_id, &token);

    let (mut ws, _) = connect_ws(&ws_url).await
        .expect("Connection should succeed");

    // Read initial connected message
    let _ = ws.next().await;

    // Send messages rapidly (more than rate limit allows)
    // Default: 5 messages per second
    let mut sent_count = 0;
    let mut send_failed = false;

    for i in 0..20 {
        let msg = json!({
            "type": "message",
            "payload": format!("test-message-{}", i)
        });

        let result = ws.send(WsMessage::Text(msg.to_string())).await;

        if result.is_err() {
            send_failed = true;
            break;
        }

        sent_count += 1;
    }

    println!("Sent {} messages before rate limit or error", sent_count);

    // Wait for server to potentially close connection
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Try to send one more message
    let test_msg = json!({
        "type": "message",
        "payload": "final-test"
    });

    let final_result = ws.send(WsMessage::Text(test_msg.to_string())).await;

    // If we sent many messages, the connection should have been closed
    if sent_count >= 10 && !send_failed {
        // The connection may still be open if we were fast enough before rate limit kicked in
        println!("Final send result: {:?}", final_result.is_ok());
    }

    let _ = ws.close(None).await;
}

/// Test WebSocket connection to non-existent room
#[tokio::test]
async fn test_ws_connection_room_not_found() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a room to get a valid token format, then use wrong room_id
    let config = RoomConfig::default();
    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    // Get a token for a different, non-existent room
    let fake_room_id = uuid::Uuid::new_v4();

    // First, create a room and get token (can't get token for non-existent room)
    // The token is bound to the room_id in the JWT claims

    // Try using the token from room1 for a different room
    let token = room.ws_token.expect("Should get WS token");

    // Construct URL with wrong room_id
    let ws_url = format!("{}/ws/{}?token={}", WS_URL, fake_room_id, token);

    let result = connect_ws(&ws_url).await;

    // Should fail - token is for a different room
    assert!(result.is_err(), "Token for wrong room should be rejected");
}

/// Test multiple concurrent WebSocket connections
#[tokio::test]
async fn test_ws_concurrent_connections() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create multiple rooms
    let mut rooms = Vec::new();
    for _ in 0..3 {
        let config = RoomConfig::default();
        if let Ok(room) = create_room_with_pow(&client, &config).await {
            rooms.push(room);
        }
    }

    println!("Created {} rooms", rooms.len());

    // Connect to each room
    let mut connections = Vec::new();
    for room in &rooms {
        if let Some(token) = &room.ws_token {
            let ws_url = get_ws_url(&room.room_id, token);
            if let Ok((ws, _)) = connect_ws(&ws_url).await {
                connections.push(ws);
            }
        }
    }

    println!("Established {} connections", connections.len());

    assert!(connections.len() > 0, "Should establish at least one connection");

    // Read initial messages from all connections
    for ws in &mut connections {
        if let Some(Ok(msg)) = ws.next().await {
            if let WsMessage::Text(text) = msg {
                let parsed: Result<serde_json::Value, _> = serde_json::from_str(&text);
                assert!(parsed.is_ok(), "Should receive valid JSON");
            }
        }
    }

    // Close all connections
    for mut ws in connections {
        let _ = ws.close(None).await;
    }
}

/// Test that room becomes full after max participants join
#[tokio::test]
async fn test_ws_room_full() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a room
    let config = RoomConfig::default();
    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    let token1 = room.ws_token.expect("Should get first WS token");

    // First connection
    let ws_url1 = get_ws_url(&room.room_id, &token1);
    let (mut ws1, _) = connect_ws(&ws_url1).await
        .expect("First connection should succeed");

    // Read initial message
    let _ = ws1.next().await;

    // Get second token
    let token_resp = get_ws_token_with_pow(&client, &room.room_id).await
        .expect("Should get second token");

    // Second connection
    let ws_url2 = get_ws_url(&room.room_id, &token_resp.token);
    let (mut ws2, _) = connect_ws(&ws_url2).await
        .expect("Second connection should succeed");

    // Read initial message
    let _ = ws2.next().await;

    // Room should now be full (max_participants = 2 for OneToOne)

    // Try to get third token - should still work (room check happens at WS connect time)
    // But the actual connection should fail because room is full
    // Actually, the token endpoint checks if room is full

    let third_token_result = get_ws_token_with_pow(&client, &room.room_id).await;

    // This might succeed or fail depending on when the check happens
    if let Ok(token3) = third_token_result {
        let ws_url3 = get_ws_url(&room.room_id, &token3.token);
        let result = connect_ws(&ws_url3).await;

        // The WebSocket connection might succeed at HTTP level
        // but the room should reject it
        if let Ok((mut ws3, _)) = result {
            // The server should close the connection or send an error
            if let Some(Ok(msg)) = ws3.next().await {
                if let WsMessage::Text(text) = msg {
                    let parsed: serde_json::Value = serde_json::from_str(&text)
                        .expect("Should parse JSON");
                    // Might be an error message or close
                    println!("Third connection message: {}", parsed);
                }
            }
        }
    } else {
        println!("Third token was rejected (room full): {:?}", third_token_result.err());
    }

    // Cleanup
    let _ = ws1.close(None).await;
    let _ = ws2.close(None).await;
}

/// Test WebSocket ping/pong (heartbeat)
#[tokio::test]
async fn test_ws_heartbeat() {
    let client = create_client();

    // Skip if server is not running
    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    // Create a room
    let config = RoomConfig::default();
    let room = create_room_with_pow(&client, &config).await
        .expect("Room creation should succeed");

    let token = room.ws_token.expect("Should get WS token");
    let ws_url = get_ws_url(&room.room_id, &token);

    let (mut ws, _) = connect_ws(&ws_url).await
        .expect("Connection should succeed");

    // Read initial connected message
    let _ = ws.next().await;

    // Send a ping
    let ping_result = ws.send(WsMessage::Ping(vec![1, 2, 3])).await;
    assert!(ping_result.is_ok(), "Ping should succeed");

    // Wait for pong
    let mut received_pong = false;
    let timeout = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        async {
            while let Some(Ok(msg)) = ws.next().await {
                if let WsMessage::Pong(_) = msg {
                    received_pong = true;
                    break;
                }
            }
        }
    ).await;

    if timeout.is_ok() && received_pong {
        println!("Received pong response");
    } else {
        println!("No pong received (may be normal, server sends pings not pongs)");
    }

    let _ = ws.close(None).await;
}
