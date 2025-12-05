# PinChat Stress Tests

Test suite to verify application resistance against DoS/DDoS attacks and high loads.

## Overview

These tests verify the following protections:

1. **HTTP Rate Limiting** - Limits on room and token creation
2. **WebSocket Rate Limiting** - Limits on connections and messages
3. **Proof-of-Work** - Computational challenges to prevent spam
4. **Capacity Limits** - Maximum number of rooms and participants
5. **Concurrency Tests** - Behavior under simultaneous load
6. **DDoS Simulation** - Multi-IP attack simulation via X-Forwarded-For

## Prerequisites

- Rust 1.70+
- PinChat server running

## Important: Understanding Test Failures

### Why tests may fail with 429 (Too Many Requests)

When running all tests sequentially, you may see many tests fail with `429 Too Many Requests`. **This is expected behavior** and actually proves that the DoS protection is working correctly.

**The reason**: All tests run from the same IP address (127.0.0.1) and share the same rate limit quota. When tests run sequentially:

1. Early tests (e.g., `test_max_rooms_limit`) create 20+ rooms
2. Other tests make additional requests
3. By the time later tests run, the rate limit quota is exhausted
4. Remaining tests receive 429 responses

**In production**, this is not a problem because:
- Different users have different IP addresses
- Each IP has its own separate quota
- A single user would never legitimately make 100+ requests in 10 minutes

### What the test results mean

| Result | Meaning |
|--------|---------|
| Tests pass | The specific functionality works correctly |
| Tests fail with 429 | Rate limiting is working (quota exhausted by earlier tests) |
| Tests fail with other errors | Actual bugs that need investigation |

## Running Tests

**IMPORTANT**: Tests must be run from the `stress-tests/` directory, not from the project root.

### Option 1: Run with production defaults (recommended for validation)

This validates that DoS protections work. Some tests will fail with 429 - this is expected.

```bash
cd stress-tests
cargo test -- --test-threads=1 --nocapture
```

### Option 2: Run with high limits (for full test coverage)

To run all tests without rate limit interference, start the server with relaxed limits:

```bash
# Start server with relaxed limits for testing
ROOM_TOKEN_BURST_SIZE=1000 \
ROOM_TOKEN_PERIOD_SECS=60 \
WS_CONN_BURST_SIZE=100 \
POW_MIN_DIFFICULTY=10 \
POW_MAX_DIFFICULTY=12 \
cargo run
```

Then run tests:

```bash
cd stress-tests
cargo test -- --test-threads=1 --nocapture
```

### Option 3: Run test categories separately

Run each category with a server restart between them to reset rate limits:

```bash
cd stress-tests

# Run one category
cargo test capacity_tests -- --test-threads=1

# Restart server, then run next category
cargo test http_tests -- --test-threads=1

# And so on...
```

### Available test commands

```bash
# Run all tests
cargo test -- --test-threads=1

# Run specific categories
cargo test http_tests -- --test-threads=1
cargo test ws_tests -- --test-threads=1
cargo test pow_tests -- --test-threads=1
cargo test capacity_tests -- --test-threads=1
cargo test concurrent_tests -- --test-threads=1
cargo test ddos_tests -- --test-threads=1  # Requires TRUSTED_PROXIES=127.0.0.1

# Run with detailed output
cargo test -- --test-threads=1 --nocapture
```

## Test Structure

### HTTP Tests (`http_tests.rs`)

| Test | Description |
|------|-------------|
| `test_room_creation_requires_pow` | Verifies that room creation requires PoW |
| `test_room_creation_with_pow_succeeds` | Verifies room creation with valid PoW |
| `test_room_creation_rate_limit` | Verifies rate limiting on room creation |
| `test_room_creation_invalid_ttl` | Verifies rejection of invalid TTL |
| `test_ws_token_requires_pow` | Verifies that token endpoint requires PoW |
| `test_rapid_requests_to_api` | Measures response times under load |

### WebSocket Tests (`ws_tests.rs`)

| Test | Description |
|------|-------------|
| `test_ws_connection_requires_token` | Verifies that WS requires JWT token |
| `test_ws_connection_invalid_token` | Verifies rejection of invalid token |
| `test_ws_connection_with_valid_token` | Verifies connection with valid token |
| `test_ws_token_replay_prevention` | Verifies that tokens are not reusable |
| `test_ws_message_rate_limit` | Verifies message rate limiting |
| `test_ws_room_full` | Verifies participant limit |

### PoW Tests (`pow_tests.rs`)

| Test | Description |
|------|-------------|
| `test_pow_challenge_returned` | Verifies PoW challenge response |
| `test_pow_invalid_nonce_rejected` | Verifies rejection of invalid nonce |
| `test_pow_malformed_nonce_rejected` | Verifies rejection of malformed nonce |
| `test_pow_challenge_consumed` | Verifies single-use of challenges |
| `test_pow_solver_performance` | Measures PoW solver performance |

### Capacity Tests (`capacity_tests.rs`)

| Test | Description |
|------|-------------|
| `test_max_rooms_limit` | Verifies MAX_TOTAL_ROOMS limit |
| `test_room_expiration` | Verifies room expiration |
| `test_message_replay_detection` | Verifies message anti-replay |
| `test_large_message_rejected` | Verifies rejection of oversized messages |
| `test_room_participant_limit` | Verifies participant limit |

### Concurrent Tests (`concurrent_tests.rs`)

| Test | Description |
|------|-------------|
| `test_concurrent_room_creation` | Tests simultaneous room creation |
| `test_concurrent_ws_connections` | Tests simultaneous WS connections |
| `test_sustained_load` | Tests sustained load (10s) |
| `test_request_burst` | Tests request burst |
| `test_alternating_load` | Tests variable load |
| `test_mixed_operations` | Tests mixed operations |

### DDoS Tests (`ddos_tests.rs`)

**Important**: DDoS tests require `TRUSTED_PROXIES=127.0.0.1` to simulate multiple IPs.

| Test | Description |
|------|-------------|
| `test_ddos_separate_ip_quotas` | Verifies each IP has separate rate limit quota |
| `test_ddos_concurrent_multi_ip` | Tests concurrent requests from 50 different IPs |
| `test_ddos_room_exhaustion` | Attempts to exhaust MAX_TOTAL_ROOMS from multiple IPs |
| `test_ddos_sustained_attack` | Simulates 5-second sustained attack from rotating IPs |
| `test_ddos_server_responsiveness` | Verifies server remains responsive after flood |
| `test_ddos_websocket_flood` | Tests WebSocket connection flood with invalid tokens |

#### Running DDoS Tests

```bash
# Start server with TRUSTED_PROXIES enabled
TRUSTED_PROXIES=127.0.0.1 \
ROOM_TOKEN_BURST_SIZE=1000 \
POW_MIN_DIFFICULTY=10 \
cargo run

# Run DDoS tests (default intensity)
cd stress-tests
cargo test ddos_tests -- --test-threads=1 --nocapture

# Run DDoS tests (EXTREME intensity - heavy stress test)
DDOS_INTENSITY=extreme cargo test ddos_tests -- --test-threads=1 --nocapture

# Run DDoS tests (INSANE intensity - maximum stress test)
DDOS_INTENSITY=insane cargo test ddos_tests -- --test-threads=1 --nocapture
```

#### Intensity Levels

Control test intensity with the `DDOS_INTENSITY` environment variable:

| Parameter | Default | Extreme | Insane |
|-----------|---------|---------|--------|
| Concurrent IPs | 50 | 500 | 2000 |
| Room exhaustion attempts | 30 | 200 | 1000 |
| Sustained attack duration | 5s | 30s | 60s |
| Requests per second | 20 | 100 | 500 |
| Flood IPs | 100 | 1000 | 5000 |
| WebSocket flood attempts | 50 | 500 | 2000 |

## Interpreting Results

### Rate Limiting

- **429 Too Many Requests**: Rate limit reached (expected when running full test suite)
- **503 Service Unavailable**: Server at maximum capacity

### Proof-of-Work

- **428 Precondition Required**: PoW required, challenge provided
- **403 Forbidden**: Invalid PoW nonce

### Concurrency Tests

Concurrency tests show:
- **Success rate**: Percentage of completed requests
- **Rate limited**: Limited requests (expected under load)
- **Throughput**: Requests per second

## Environment Variables

### Production Defaults

| Variable | Default | Description |
|----------|---------|-------------|
| `POW_MIN_DIFFICULTY` | 12 | Minimum PoW difficulty (bits) |
| `POW_MAX_DIFFICULTY` | 18 | Maximum PoW difficulty (bits) |
| `ROOM_TOKEN_BURST_SIZE` | 100 | Room/token requests per period |
| `ROOM_TOKEN_PERIOD_SECS` | 600 | Rate limit period (10 min) |
| `WS_CONN_BURST_SIZE` | 30 | WS connections per period |
| `WS_CONN_PERIOD_SECS` | 60 | WS rate limit period (1 min) |
| `MSG_RATE_LIMIT` | 30 | Messages per second per connection |
| `MSG_RATE_WINDOW_SECS` | 1 | Message rate limit window |
| `MAX_TOTAL_ROOMS` | 1000 | Maximum total rooms |

### Recommended Test Configuration

For running all tests without rate limit interference:

```bash
ROOM_TOKEN_BURST_SIZE=1000
ROOM_TOKEN_PERIOD_SECS=60
WS_CONN_BURST_SIZE=100
WS_CONN_PERIOD_SECS=60
POW_MIN_DIFFICULTY=10
POW_MAX_DIFFICULTY=12
MAX_TOTAL_ROOMS=50
```

## Technical Notes

- Tests support **HTTPS/WSS** with self-signed certificates (server default)
- HTTP and WebSocket clients automatically accept invalid certificates
- If the server runs in HTTP (with `FORCE_HTTP=true`), tests will still work
- Tests run sequentially (`--test-threads=1`) to avoid race conditions
- All tests share the same IP, so they share rate limit quota

## Summary

These stress tests serve two purposes:

1. **Validate DoS protections work**: Running with production defaults, many tests will fail with 429. This proves the rate limiting is effective.

2. **Verify functionality**: Running with relaxed limits, all tests should pass, confirming the underlying features work correctly.

Both scenarios provide valuable information about the system's security posture.
