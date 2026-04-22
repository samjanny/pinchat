# PinChat

End-to-end encrypted ephemeral messaging with zero persistence and zero knowledge architecture.

## Overview

PinChat is a secure messaging application designed for privacy-first communication. All messages are encrypted client-side before transmission, ensuring the server operates as a blind relay with no ability to decrypt message content.

### Key Features

- **End-to-End Encryption**: All messages encrypted using AES-GCM 256-bit with keys that never leave the client
- **Perfect Forward Secrecy**: Compromised keys cannot decrypt past messages (Double Ratchet protocol)
- **Post-Compromise Security**: Session automatically recovers security after key compromise
- **Authenticated DH Ratchet**: Every DH public key rotation is signed with the peer's identity key (ECDSA P-256). A live MITM swap triggers a hard session abort (WebSocket close 1008, no auto-reconnect).
- **Zero Persistence**: All data exists only in memory; nothing is written to disk
- **Zero Knowledge**: Server cannot decrypt messages, identify users, or correlate sessions
- **Ephemeral Rooms**: Chat rooms automatically self-destruct after configurable TTL (1-1440 minutes)
- **Anonymous Access**: No registration, no accounts, no tracking
- **Encrypted Media**: Image sharing with the same E2E encryption as text messages
- **MITM Detection**: Short Authentication String (SAS) verification for identity confirmation
- **Subprotocol-based WebSocket auth**: JWT is carried in `Sec-WebSocket-Protocol`, never in the URL — so it never lands in proxy access logs, referrer headers, or middlebox caches.

### Communication Modes

- **1:1 Chat**: Private conversations between two participants
- **Group Chat**: Secure group messaging for up to 20 participants
  - ⚠️ **Currently disabled**: Group chat functionality is temporarily disabled until a robust cryptographic solution is implemented (the current Bootstrap Key approach is insufficient for secure group key management)

## Security Model

### Bootstrap Key

When a room is created, the client generates a 256-bit AES key called the **Bootstrap Key**. This key is appended to the room URL as a fragment:

```
https://host/c/{room_id}#key={base64url_encoded_key}
```

The URL fragment (everything after `#`) is never sent to the server per RFC 3986. This ensures:

1. The server never has access to the Bootstrap Key
2. Only users who receive the complete URL can decrypt messages
3. The key is shared out-of-band (copy/paste, QR code, etc.)

The Bootstrap Key encrypts the initial ECDH key exchange. After the handshake completes, the Double Ratchet takes over for message encryption with Perfect Forward Secrecy.

**Protocol v1 hardening (v0.2.0):** once the Double Ratchet is running the in-memory Bootstrap Key is dropped. On reconnect the key is re-extracted from the URL fragment (which survives transparent WebSocket reconnects). If the fragment is missing — e.g., a browser extension cleared `window.location.hash` — the client surfaces a clear "please re-open the original room link" message instead of attempting a handshake without a bootstrap key.

### Encryption Architecture

```
                                    ENCRYPTION FLOW

    Client A                         Server                          Client B
    --------                         ------                          --------
       |                                |                                |
       |  [Bootstrap Key in URL fragment - never sent to server]        |
       |                                |                                |
       |  1. Generate Identity Key      |                                |
       |     (ECDSA P-256)              |                                |
       |                                |                                |
       |  2. Generate Ephemeral Key     |                                |
       |     (ECDH P-256)               |                                |
       |                                |                                |
       |  3. Encrypt ECDH Public Key    |                                |
       |     with Bootstrap Key         |                                |
       |     (AES-GCM)                  |                                |
       |                                |                                |
       |  4. Sign Ephemeral Key         |                                |
       |     with Identity Key          |                                |
       |                                |                                |
       |======= Handshake Message =====>|======= Handshake Message =====>|
       |                                |                                |
       |                                |  5. Decrypt with Bootstrap Key |
       |                                |                                |
       |                                |  6. Verify Signature           |
       |                                |     (MITM Detection)           |
       |                                |                                |
       |                                |  7. Derive Shared Secret       |
       |                                |     (ECDH)                     |
       |                                |                                |
       |<====== Handshake Message ======|<====== Handshake Message ======|
       |                                |                                |
       |  8. Initialize Double Ratchet  |                                |
       |     - Root Key                 |                                |
       |     - Sending Chain            |                                |
       |     - Receiving Chain          |                                |
       |                                |                                |
       |  9. Encrypt Message            |                                |
       |     (AES-GCM + AAD)            |                                |
       |                                |                                |
       |======= Encrypted Payload =====>|======= Encrypted Payload =====>|
       |        (Blind Relay)           |                                |
       |                                |                                |
```

### Zero Knowledge Guarantees

The server architecture ensures:

1. **No Message Content Access**: All encryption/decryption occurs client-side
2. **No Key Access**: Encryption keys exist only in browser memory and URL fragments (never transmitted to server)
3. **No User Identification**: Each connection receives a random UUID; no cross-room correlation
4. **No Persistent Logs**: In strict privacy mode, zero operational logs are generated
5. **No Metadata Storage**: Room membership and timing data exist only in RAM

### Cryptographic Primitives

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Message Encryption | AES-GCM 256-bit | Authenticated encryption with associated data |
| Key Exchange | ECDH P-256 | Derive shared secrets for Perfect Forward Secrecy |
| Digital Signatures | ECDSA P-256 | Authenticate identity keys (MITM protection) |
| Key Derivation | HKDF-SHA256 | Derive chain keys and message keys |
| Chain Ratchet | HMAC-SHA256 | One-way key progression for PFS |
| SAS Generation | PBKDF2 (100K iterations) | Brute-force resistant verification codes |

### Double Ratchet Protocol

PinChat implements the Signal Protocol Double Ratchet for combined PFS and PCS:

```
                         ROOT KEY (from ECDH)
                               |
              +----------------+----------------+
              |                                 |
        SENDING CHAIN                    RECEIVING CHAIN
              |                                 |
    +---------+---------+             +---------+---------+
    |         |         |             |         |         |
   MK_0      MK_1      MK_2          MK_0      MK_1      MK_2
 (deleted) (deleted) (current)     (deleted) (deleted) (current)


    DH RATCHET: Triggered on direction change
    - New ECDH keypair generated
    - New root key derived
    - Both chains re-initialized
    - Post-Compromise Security achieved
```

## System Architecture

```
+------------------------------------------------------------------+
|                           CLIENT                                  |
|                                                                   |
|  +------------------+  +------------------+  +------------------+ |
|  |  Identity Keys   |  |  Ephemeral Keys  |  |  Double Ratchet  | |
|  |  (ECDSA P-256)   |  |  (ECDH P-256)    |  |  (Signal Proto)  | |
|  +------------------+  +------------------+  +------------------+ |
|           |                    |                     |            |
|           +--------------------+---------------------+            |
|                               |                                   |
|                    +-------------------+                          |
|                    |   CryptoManager   |                          |
|                    | (WebCrypto API)   |                          |
|                    +-------------------+                          |
|                               |                                   |
|                    +-------------------+                          |
|                    |  WebSocket Client |                          |
|                    +-------------------+                          |
+------------------------------------------------------------------+
                               |
                               | TLS 1.3 (Encrypted Transport)
                               |
+------------------------------------------------------------------+
|                           SERVER                                  |
|                                                                   |
|  +------------------+  +------------------+  +------------------+ |
|  |  Axum Framework  |  |  WebSocket Relay |  |  Rate Limiting   | |
|  |  (Rust/Tokio)    |  |  (Blind Relay)   |  |  (tower-governor)| |
|  +------------------+  +------------------+  +------------------+ |
|           |                    |                     |            |
|           +--------------------+---------------------+            |
|                               |                                   |
|                    +-------------------+                          |
|                    |     AppState      |                          |
|                    |  (DashMap - RAM)  |                          |
|                    +-------------------+                          |
|                               |                                   |
|                    +-------------------+                          |
|                    |   Cleanup Task    |                          |
|                    | (Expired Rooms)   |                          |
|                    +-------------------+                          |
+------------------------------------------------------------------+
```

### Backend Stack

- **Runtime**: Rust with Tokio async runtime
- **Framework**: Axum web framework
- **Transport**: WebSocket over TLS (rustls)
- **Storage**: In-memory only (DashMap)
- **Rate Limiting**: tower-governor with HMAC-hashed IPs
- **Anti-Spam**: Proof-of-Work challenge system

### Frontend Stack

- **JavaScript**: Vanilla JS with Alpine.js for reactivity
- **Cryptography**: WebCrypto API (native browser crypto)
- **Styling**: Responsive CSS (no frameworks)

## Quick Start

### Prerequisites

- Rust 1.75 or later
- OpenSSL (for certificate generation)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/samjanny/pinchat.git
cd pinchat
```

2. Generate TLS certificates (required for HTTPS):
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
    -keyout certs/key.pem \
    -out certs/cert.pem \
    -days 365 -nodes \
    -subj "/CN=localhost"
```

3. Build and run:
```bash
cargo run --release
```

4. Access the application:
```
https://localhost:3000
```

Note: Browser will warn about the self-signed certificate. Accept the warning to proceed.

### Docker Deployment

```bash
# Generate certificates first
./generate-certs.sh

# Build and run with Docker Compose
docker-compose up --build
```

### Configuration

Environment variables for customization:

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `127.0.0.1` | Server bind address |
| `PORT` | `3000` | Server port |
| `PRIVACY_MODE` | `strict` | Logging level: `strict`, `minimal`, `development` |
| `FORCE_HTTP` | `false` | Allow HTTP (for reverse proxy setups) |
| `FORCE_SECURE_COOKIES` | `false` | Force Secure cookie flag |
| `MAX_TOTAL_ROOMS` | `1000` | Maximum concurrent rooms |
| `CSP_WS_HOST` | `'self'` | WebSocket CSP origins |
| `WS_CONN_BURST_SIZE` | `30` | WebSocket connections allowed per period |
| `WS_CONN_PERIOD_SECS` | `60` | Window for WebSocket connection rate limiting |
| `ROOM_TOKEN_BURST_SIZE` | `100` | Room/token creations allowed per period |
| `ROOM_TOKEN_PERIOD_SECS` | `600` | Window for room/token rate limiting (10 min) |
| `MSG_RATE_LIMIT` | `30` | Messages per connection per window |
| `MSG_RATE_WINDOW_SECS` | `1` | Window length for per-connection message rate limiting |
| `POW_MIN_DIFFICULTY` | `12` | Minimum PoW difficulty (bits) |
| `POW_MAX_DIFFICULTY` | `18` | Maximum PoW difficulty (bits) |
| `CHALLENGE_TTL_SECS` | `300` | Proof-of-work challenge TTL |
| `JWT_TOKEN_TTL_SECS` | `30` | WebSocket JWT TTL (seconds) |
| `ROOM_CLEANUP_INTERVAL_SECS` | `60` | Room cleanup interval |
| `CHALLENGE_CLEANUP_INTERVAL_SECS` | `60` | PoW cache cleanup interval |
| `PINCHAT_PASSWORD_HASHES` | _empty_ | Semicolon-separated Argon2id hashes; if empty, auth is disabled |
| `SESSION_TTL_SECS` | `86400` | Session lifetime |
| `LOGIN_BURST_SIZE` | `5` | Login attempts allowed per period |
| `LOGIN_PERIOD_SECS` | `900` | Window for login rate limiting |
| `TRUSTED_PROXIES` | _empty_ | Comma-separated proxy IPs/CIDRs for X-Forwarded-For |
| `REPLAY_CACHE_MAX_PER_ROOM` | `10000` | Max anti-replay entries per room |
| `MAX_IMAGE_SIZE` | `300KB` | Max image size (bytes or with KB/MB suffix) |
| `WEBSITE_DIR` | _empty_ | Custom static files directory (fallback: `/static`) |

### Privacy Modes

- **strict**: Zero operational logs, maximum privacy (production default)
- **minimal**: Warnings and errors only
- **development**: Full debug logging (local testing only)

## Security Considerations

### What PinChat Protects Against

- Server-side message interception
- Retrospective decryption of captured traffic
- User identification and correlation
- Metadata analysis from server logs
- Session hijacking (HTTPS + secure cookies)
- Cross-Site Scripting (CSP headers)
- Clickjacking (X-Frame-Options: DENY)

### What PinChat Does NOT Protect Against

- Compromised client devices (malware, keyloggers)
- Screenshots or deliberate recording by participants
- Traffic analysis (IP addresses, timing)
- Social engineering attacks
- Attacks by participants within the same room

### Recommended Practices

- Use a VPN or Tor for IP-level anonymity
- Verify SAS codes via a secondary channel (voice call, Signal)
- Use ephemeral/private browsing mode
- Clear browser data after sensitive conversations

## Browser Extensions

PinChat includes browser extensions for Chrome and Firefox that verify the integrity of files served by the web application against cryptographically signed hashes.

### How It Works

1. The extension fetches a signed hash list from GitHub (out-of-band source)
2. Verifies the ECDSA P-256 signature using an embedded public key
3. **DOM SRI Check**: Verifies `<script>` and `<link>` tags have correct `integrity` attributes
4. **File Hash Verification**: Fetches ALL files from manifest and verifies SHA-256 hashes
5. Displays a warning overlay if any integrity check fails

This dual verification approach catches both HTML tampering (modified SRI attributes) and file tampering (modified JS/CSS), providing protection against server compromise scenarios.

See [extensions/README.md](extensions/README.md) for setup and installation instructions.

## Documentation

- [SECURITY.md](SECURITY.md) - Detailed threat model and cryptographic specifications
- [PROTOCOL.md](PROTOCOL.md) - Protocol specification and message formats

## Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Dates are the repository-local commit dates; entries are curated for user-visible impact
rather than being a 1:1 mirror of `git log`.

### [2026-04-22] — v0.2.0 (protocol v1)

**First explicitly numbered wire-protocol version.** Pre-release clients and
servers are considered "v0 implicit" and are rejected after this release.
Deploy is atomic (server + static JS + HTML together); see `PROTOCOL.md` for
the full reject-code matrix.

#### Security (critical)

- **Authenticated DH ratchet.** The claim that "all ephemeral keys are
  authenticated" in previous `SECURITY.md` was aspirational: the Double Ratchet
  DH rotations were actually unsigned. They are now ECDSA-signed over
  `"pinchat-drheader-v1" || len(dh):u16_be || dh || rc:u32_be`, binding the
  signature to the current ratchet round. A live MITM that swaps the DH
  header mid-session triggers `SIGNATURE_INVALID` → WebSocket close 1008 →
  hard identity teardown → no auto-reconnect.
- **JWT out of the URL.** Previously the WebSocket token travelled in
  `?token=<jwt>`, so it could land in proxy access logs, referrer headers,
  and middlebox caches. Now the client offers
  `Sec-WebSocket-Protocol: pinchat.v1, pinchat.v1.jwt.<token>` and the
  server echoes back only `pinchat.v1` on the 101. `/api/ws-token` and
  `/api/rooms` additionally return `protocol_version` and
  `supported_subprotocols` so a v1 client can reject a v0 server *before*
  attempting the opaque-failure-modes WebSocket upgrade.
- **Bootstrap key zeroed after handshake.** The AES-GCM bootstrap key used
  to be retained in memory for the full session to make re-handshaking
  convenient. It is now dropped; re-handshake goes through
  `resetToBootstrapKey()` which re-extracts from the URL fragment.
  `resetToBootstrapKey()` also destroys the live `DoubleRatchet` instance
  that previous implementations left alive on peer-leave / reconnect.
- **`MAX_SKIP` aligned + global cap.** `MAX_SKIP` was 100 in
  `double-ratchet.js` and `PROTOCOL.md` but 1000 in `crypto.js`. All layers
  now agree on 100. The `skippedKeys` map gained a 1000-entry global
  FIFO-evicted cap plus pruning across DH ratchet boundaries (was
  unbounded across rounds).

#### Added

- Protocol version constant `PINCHAT_PROTOCOL_VERSION = 1` in both Rust and
  JS; header field `v` is mandatory for `message`/`image` envelopes and
  serde rejects v0 shapes.
- `PROTOCOL_OR_AUTH_FAILURE` vs `CONNECTION_EXHAUSTED` separation so the
  client banner distinguishes "refresh the page" from "check your network".
- Async error boundary wrappers around `onMessage`, `onConnected`, and the
  `ECDHKeyExchange.startTimeout` callback — unhandled promise rejections
  from the new teardown paths can no longer escape silently.
- Integration tests for the WebSocket upgrade handshake (bound listener +
  raw TCP): reject paths for missing subprotocol, v0 subprotocol, missing
  JWT, expired JWT, wrong `room_id`, plus the full 101 success case that
  asserts the server never echoes the `pinchat.v1.jwt.*` companion.

#### Removed

- `dh_ratchet` message type (the server previously relayed these; dead
  code after the Signal-style receive-side ratchet). This removed a
  gratuitous traffic-amplification surface.
- `?token=` query-string authentication for `/ws/:room_id`.
- Optional `header` on `message` / `image` envelopes.

### [2026-04-21]

#### Added
- **Proton-style UI refresh** with full light/dark theme toggle. A floating control
  (top-right on every page) persists the choice in `localStorage`; the OS
  `prefers-color-scheme` setting is honored when no explicit preference is stored.
- New design tokens (radius scale, typography scale, softer shadow layers) and an
  `[data-theme="dark"]` block covering every component.

#### Fixed
- **E2E encryption key leak via login redirect URL.** When a `/api/ws-token/*` or
  `/api/rooms` request returned 401, the client previously concatenated
  `window.location.hash` into the `?redirect=` query parameter. Because the
  fragment carries the symmetric room key (`#key=…`), this caused the key to be
  sent to the server — and therefore to any reverse-proxy / CDN / browser-history
  / `Referer` sink. The redirect now strips the fragment, stashes it in
  `sessionStorage` (tab-scoped) before navigating, and `extractKeyFromURL()`
  restores it via `history.replaceState` on the first read after login.

#### Security
- **Fail-closed startup.** The server now refuses to boot when authentication is
  not configured unless `ALLOW_ANONYMOUS=true` is set explicitly (outside
  development), and refuses to boot when `FORCE_HTTP=true` is combined with
  `FORCE_SECURE_COOKIES` unset in production.
- `handlers/ws_token.rs`: collapsed three sequential `DashMap` reads into one
  atomic `get()` to close a read race on room state.
- `handlers/auth.rs`: stopped logging session IDs, CSRF tokens, and raw cookie
  headers via `tracing::debug` to avoid secret material reaching log sinks.
- `jwt.rs` / `handlers/websocket.rs`: widened token TTL from `i64` to `u64`.
- **Reproducible builds.** Dockerfile pinned to `rust:1.85-bookworm` (was nightly),
  `Cargo.lock` committed, image built with `cargo build --release --locked`.

### Earlier

- **Extension manifest v1.2.0** with anti-downgrade sequence numbers, ECDSA
  P-256 signatures, and SRI-in-DOM verification (the extension reads the
  integrity attributes actually parsed by the browser, not a separate fetch).
- Comprehensive DoS/DDoS stress-test suite (`stress-tests/`).
- `WEBSITE_DIR` env var for custom frontends with safe fallback to `/static`.
- SAS verification entropy raised from 36 to 48 bits.
- WebSocket heartbeat ping every 30s; non-root container user; fail-closed
  behaviour on room TTL drift.

See `git log` for a complete per-commit history.

## License

Copyright 2025 Raffaele Mangiacasale <support@pinchat.io>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is an experimental prototype provided strictly for educational and research purposes.

It is NOT designed, intended, or warranted for:
- production use,
- the protection of real-world sensitive, personal, financial, or confidential data,
- safety-critical, life-critical, or mission-critical communications.

Although it uses modern cryptographic techniques, it has not undergone a formal security review or audit, and MAY CONTAIN SERIOUS VULNERABILITIES.

You use this software entirely at your own risk. The authors and contributors provide it “as is”, without any express or implied warranty, including but not limited to any warranty of security, fitness for a particular purpose, or non-infringement. Under no circumstances shall the authors or contributors be liable for any claim, damages, or other liability arising from, out of, or in connection with the software or its use.
