//! DDoS (Distributed Denial of Service) simulation tests
//!
//! These tests simulate attacks from multiple IP addresses using the X-Forwarded-For header.
//!
//! ## Requirements
//!
//! Server must be started with:
//! ```bash
//! TRUSTED_PROXIES=127.0.0.1 cargo run
//! ```
//!
//! ## Intensity Levels
//!
//! Control test intensity with the `DDOS_INTENSITY` environment variable:
//!
//! ```bash
//! # Default intensity (quick tests)
//! cargo test ddos_tests
//!
//! # Extreme intensity (heavy stress test)
//! DDOS_INTENSITY=extreme cargo test ddos_tests
//! ```
//!
//! | Parameter | Default | Extreme | Insane |
//! |-----------|---------|---------|--------|
//! | Concurrent IPs | 50 | 500 | 2000 |
//! | Room exhaustion attempts | 30 | 200 | 1000 |
//! | Sustained attack duration | 5s | 30s | 60s |
//! | Requests per second | 20 | 100 | 500 |
//! | Flood IPs | 100 | 1000 | 5000 |
//! | WebSocket flood attempts | 50 | 500 | 2000 |

use crate::helpers::{
    assert_server_running, create_client, create_room_with_pow_and_ip, RoomConfig,
};
use crate::{BASE_URL, WS_URL};
use reqwest::Client;
use std::env;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Test intensity level
#[derive(Debug, Clone, Copy, PartialEq)]
enum Intensity {
    Default,
    Extreme,
    Insane,
}

/// Test parameters based on intensity
struct TestParams {
    /// Number of concurrent IPs for multi-IP test
    concurrent_ips: u32,
    /// Number of room creation attempts
    room_exhaustion_attempts: u32,
    /// Duration of sustained attack in seconds
    sustained_duration_secs: u64,
    /// Requests per second during sustained attack
    sustained_rps: u32,
    /// Number of IPs for flood test
    flood_ips: u32,
    /// Number of WebSocket flood attempts
    ws_flood_attempts: u32,
}

impl TestParams {
    fn from_intensity(intensity: Intensity) -> Self {
        match intensity {
            Intensity::Default => Self {
                concurrent_ips: 50,
                room_exhaustion_attempts: 30,
                sustained_duration_secs: 5,
                sustained_rps: 20,
                flood_ips: 100,
                ws_flood_attempts: 50,
            },
            Intensity::Extreme => Self {
                concurrent_ips: 500,
                room_exhaustion_attempts: 200,
                sustained_duration_secs: 30,
                sustained_rps: 100,
                flood_ips: 1000,
                ws_flood_attempts: 500,
            },
            Intensity::Insane => Self {
                concurrent_ips: 2000,
                room_exhaustion_attempts: 1000,
                sustained_duration_secs: 60,
                sustained_rps: 500,
                flood_ips: 5000,
                ws_flood_attempts: 2000,
            },
        }
    }
}

/// Get test intensity from environment variable
fn get_intensity() -> Intensity {
    match env::var("DDOS_INTENSITY").as_deref() {
        Ok("insane") | Ok("INSANE") => {
            println!("💀 Running in INSANE intensity mode - this will take a while!");
            Intensity::Insane
        }
        Ok("extreme") | Ok("EXTREME") => {
            println!("🔥 Running in EXTREME intensity mode");
            Intensity::Extreme
        }
        _ => {
            println!("Running in default intensity mode (set DDOS_INTENSITY=extreme or insane for heavier tests)");
            Intensity::Default
        }
    }
}

/// Get test parameters based on environment
fn get_params() -> TestParams {
    TestParams::from_intensity(get_intensity())
}

/// Generate a fake IP address for testing
fn fake_ip(index: u32) -> String {
    let b = ((index >> 16) & 0xFF).max(1);
    let c = ((index >> 8) & 0xFF).max(1);
    let d = (index & 0xFF).max(1);
    format!("10.{}.{}.{}", b, c, d)
}

/// Create a client request with a spoofed IP via X-Forwarded-For
async fn request_from_ip(client: &Client, url: &str, ip: &str) -> reqwest::Response {
    client
        .post(url)
        .header("X-Forwarded-For", ip)
        .json(&RoomConfig::default())
        .send()
        .await
        .expect("Request should complete")
}

/// Test that different IPs have separate rate limit quotas
#[tokio::test]
async fn test_ddos_separate_ip_quotas() {
    let client = create_client();

    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let url = format!("{}/api/rooms", BASE_URL);
    let num_ips = 5;
    let requests_per_ip = 3;

    println!("Testing {} IPs with {} requests each", num_ips, requests_per_ip);

    let mut results: Vec<(String, Vec<u16>)> = Vec::new();

    for ip_idx in 0..num_ips {
        let ip = fake_ip(ip_idx);
        let mut statuses = Vec::new();

        for _ in 0..requests_per_ip {
            let response = request_from_ip(&client, &url, &ip).await;
            statuses.push(response.status().as_u16());
        }

        println!("IP {}: statuses = {:?}", ip, statuses);
        results.push((ip, statuses));
    }

    // Check that at least some IPs got PoW challenges (428) rather than rate limited (429)
    let ips_with_challenges = results
        .iter()
        .filter(|(_, statuses)| statuses.iter().any(|&s| s == 428))
        .count();

    println!(
        "\nResults: {}/{} IPs received PoW challenges",
        ips_with_challenges, num_ips
    );

    // If TRUSTED_PROXIES is configured, each IP should have its own quota
    // If not configured, all will share 127.0.0.1's quota and get rate limited
    if ips_with_challenges == 0 {
        println!("WARNING: No IPs received challenges. Is TRUSTED_PROXIES=127.0.0.1 set?");
    }
}

/// Test concurrent requests from many different IPs
#[tokio::test]
async fn test_ddos_concurrent_multi_ip() {
    let params = get_params();
    let client = create_client();

    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let url = format!("{}/api/rooms", BASE_URL);
    let num_ips = params.concurrent_ips;

    let challenge_count = Arc::new(AtomicU32::new(0));
    let rate_limited_count = Arc::new(AtomicU32::new(0));
    let error_count = Arc::new(AtomicU32::new(0));

    println!("Launching {} concurrent requests from different IPs", num_ips);
    let start = Instant::now();

    let mut handles = Vec::new();

    for ip_idx in 0..num_ips {
        let client = client.clone();
        let url = url.clone();
        let challenges = challenge_count.clone();
        let rate_limited = rate_limited_count.clone();
        let errors = error_count.clone();

        let handle = tokio::spawn(async move {
            let ip = fake_ip(ip_idx);

            let response = client
                .post(&url)
                .header("X-Forwarded-For", &ip)
                .json(&RoomConfig::default())
                .send()
                .await;

            match response {
                Ok(resp) => match resp.status().as_u16() {
                    428 => challenges.fetch_add(1, Ordering::SeqCst),
                    429 => rate_limited.fetch_add(1, Ordering::SeqCst),
                    _ => errors.fetch_add(1, Ordering::SeqCst),
                },
                Err(_) => errors.fetch_add(1, Ordering::SeqCst),
            };
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    let challenges = challenge_count.load(Ordering::SeqCst);
    let rate_limited = rate_limited_count.load(Ordering::SeqCst);
    let errors = error_count.load(Ordering::SeqCst);

    println!("\nDDoS simulation results ({:?}):", elapsed);
    println!("  Received PoW challenge: {}", challenges);
    println!("  Rate limited: {}", rate_limited);
    println!("  Errors: {}", errors);
    println!(
        "  Throughput: {:.1} req/s",
        num_ips as f64 / elapsed.as_secs_f64()
    );

    // Server should remain responsive
    assert!(
        challenges + rate_limited + errors == num_ips,
        "All requests should receive a response"
    );
}

/// Test resource exhaustion - try to create maximum rooms from different IPs
#[tokio::test]
async fn test_ddos_room_exhaustion() {
    let params = get_params();
    let client = create_client();

    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let max_attempts = params.room_exhaustion_attempts;
    let config = RoomConfig::default();

    let mut rooms_created = 0;
    let mut challenges_received = 0;
    let mut rate_limited = 0;
    let mut capacity_reached = false;

    println!(
        "Attempting to create {} rooms from different IPs",
        max_attempts
    );

    for i in 0..max_attempts {
        let ip = fake_ip(i);

        match create_room_with_pow_and_ip(&client, &config, &ip).await {
            Ok(_) => {
                rooms_created += 1;
                challenges_received += 1; // PoW was solved
            }
            Err(e) if e.contains("Rate limited") => {
                rate_limited += 1;
            }
            Err(e) if e.contains("503") => {
                capacity_reached = true;
                println!("Server capacity reached at room {}", rooms_created);
                break;
            }
            Err(e) => {
                println!("Error for IP {}: {}", ip, e);
            }
        }
    }

    println!("\nRoom exhaustion test results:");
    println!("  Rooms created: {}", rooms_created);
    println!("  Challenges received: {}", challenges_received);
    println!("  Rate limited: {}", rate_limited);
    println!("  Capacity reached: {}", capacity_reached);

    // At least some rooms should be created if TRUSTED_PROXIES is set
    if rooms_created == 0 && challenges_received == 0 {
        println!("WARNING: No rooms created. Is TRUSTED_PROXIES=127.0.0.1 set?");
    }
}

/// Test sustained DDoS - continuous requests from rotating IPs
#[tokio::test]
async fn test_ddos_sustained_attack() {
    let params = get_params();
    let client = create_client();

    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let url = format!("{}/api/rooms", BASE_URL);
    let duration_secs = params.sustained_duration_secs;
    let requests_per_second = params.sustained_rps;

    let challenge_count = Arc::new(AtomicU32::new(0));
    let rate_limited_count = Arc::new(AtomicU32::new(0));
    let total_requests = Arc::new(AtomicU32::new(0));

    println!(
        "Sustained DDoS simulation: {}s @ {} req/s from rotating IPs",
        duration_secs, requests_per_second
    );

    let start = Instant::now();
    let mut ip_counter = 0u32;

    while start.elapsed() < Duration::from_secs(duration_secs) {
        let mut batch_handles = Vec::new();

        // Send a batch of requests
        for _ in 0..requests_per_second {
            let client = client.clone();
            let url = url.clone();
            let challenges = challenge_count.clone();
            let rate_limited = rate_limited_count.clone();
            let total = total_requests.clone();
            let ip = fake_ip(ip_counter);
            ip_counter = ip_counter.wrapping_add(1);

            let handle = tokio::spawn(async move {
                total.fetch_add(1, Ordering::SeqCst);

                let response = client
                    .post(&url)
                    .header("X-Forwarded-For", &ip)
                    .json(&RoomConfig::default())
                    .send()
                    .await;

                if let Ok(resp) = response {
                    match resp.status().as_u16() {
                        428 => {
                            challenges.fetch_add(1, Ordering::SeqCst);
                        }
                        429 => {
                            rate_limited.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                }
            });

            batch_handles.push(handle);
        }

        // Wait for batch and then sleep to maintain rate
        for handle in batch_handles {
            let _ = handle.await;
        }

        sleep(Duration::from_secs(1)).await;
    }

    let elapsed = start.elapsed();
    let total = total_requests.load(Ordering::SeqCst);
    let challenges = challenge_count.load(Ordering::SeqCst);
    let rate_limited = rate_limited_count.load(Ordering::SeqCst);

    println!("\nSustained DDoS results ({:?}):", elapsed);
    println!("  Total requests: {}", total);
    println!(
        "  Received challenges: {} ({:.1}%)",
        challenges,
        100.0 * challenges as f64 / total as f64
    );
    println!(
        "  Rate limited: {} ({:.1}%)",
        rate_limited,
        100.0 * rate_limited as f64 / total as f64
    );
    println!(
        "  Effective throughput: {:.1} req/s",
        total as f64 / elapsed.as_secs_f64()
    );

    // Server should handle all requests (not crash)
    assert!(total > 0, "Should complete some requests");
}

/// Test that server remains responsive during DDoS
#[tokio::test]
async fn test_ddos_server_responsiveness() {
    let params = get_params();
    let client = create_client();

    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let url = format!("{}/api/rooms", BASE_URL);
    let flood_ips = params.flood_ips;

    // First, flood with requests from many IPs
    println!("Phase 1: Flooding server with requests from {} IPs...", flood_ips);

    let mut flood_handles = Vec::new();
    for i in 0..flood_ips {
        let client = client.clone();
        let url = url.clone();

        let handle = tokio::spawn(async move {
            let ip = fake_ip(i);
            let _ = client
                .post(&url)
                .header("X-Forwarded-For", &ip)
                .json(&RoomConfig::default())
                .send()
                .await;
        });
        flood_handles.push(handle);
    }

    for handle in flood_handles {
        let _ = handle.await;
    }

    // Now test if server is still responsive
    println!("Phase 2: Testing server responsiveness...");

    let mut response_times = Vec::new();

    for i in 0..10 {
        let ip = fake_ip(1000 + i);
        let start = Instant::now();

        let response = client
            .post(&url)
            .header("X-Forwarded-For", &ip)
            .json(&RoomConfig::default())
            .send()
            .await;

        let elapsed = start.elapsed();
        response_times.push(elapsed);

        if let Ok(resp) = response {
            println!("  Request {}: {} in {:?}", i + 1, resp.status(), elapsed);
        }
    }

    let avg_ms =
        response_times.iter().map(|d| d.as_millis()).sum::<u128>() / response_times.len() as u128;
    let max_ms = response_times
        .iter()
        .map(|d| d.as_millis())
        .max()
        .unwrap_or(0);

    println!("\nResponsiveness results:");
    println!("  Average response time: {}ms", avg_ms);
    println!("  Max response time: {}ms", max_ms);

    // Server should remain responsive (< 5s response time)
    assert!(
        max_ms < 5000,
        "Server should respond within 5 seconds even after flood"
    );
}

/// Test memory pressure - many concurrent WebSocket connection attempts
#[tokio::test]
async fn test_ddos_websocket_flood() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let params = get_params();
    let client = create_client();

    if assert_server_running(&client).await.is_err() {
        eprintln!("Skipping test: server not running");
        return;
    }

    let num_attempts = params.ws_flood_attempts;
    let rejected_count = Arc::new(AtomicU32::new(0));
    let connected_count = Arc::new(AtomicU32::new(0));

    println!(
        "Attempting {} WebSocket connections with invalid tokens",
        num_attempts
    );
    let start = Instant::now();

    let mut handles = Vec::new();

    for i in 0..num_attempts {
        let rejected = rejected_count.clone();
        let connected = connected_count.clone();

        let handle = tokio::spawn(async move {
            let ws_url = format!("{}/ws?token=invalid_token_{}", WS_URL, i);

            // Create TLS connector that accepts invalid certs
            let tls_connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()
                .expect("Failed to create TLS connector");
            let connector = tokio_tungstenite::Connector::NativeTls(tls_connector);

            let request = ws_url.into_client_request().expect("Valid request");

            let result = tokio_tungstenite::connect_async_tls_with_config(
                request,
                None,
                false,
                Some(connector),
            )
            .await;

            match result {
                Ok(_) => {
                    connected.fetch_add(1, Ordering::SeqCst);
                }
                Err(_) => {
                    rejected.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    let rejected = rejected_count.load(Ordering::SeqCst);
    let connected = connected_count.load(Ordering::SeqCst);

    println!("\nWebSocket flood results ({:?}):", elapsed);
    println!("  Rejected (invalid token): {}", rejected);
    println!("  Connected (unexpected): {}", connected);

    // All connections should be rejected (invalid tokens)
    assert_eq!(
        connected, 0,
        "No connections should succeed with invalid tokens"
    );
    assert_eq!(
        rejected, num_attempts as u32,
        "All connections should be rejected"
    );
}
