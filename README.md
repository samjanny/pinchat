# PinChat

> ## ⚠️ EXPERIMENTAL TEST PROJECT — NOT FOR HIGH-SECURITY USE
>
> **PinChat is an experimental test/research project.** It has **not** been independently audited, it has **not** received a formal cryptographic review, and it is **not** intended for protecting sensitive, confidential, personal, financial, life-critical, or otherwise high-risk communications. As experimental, unaudited software, it may contain subtle bugs, incorrect assumptions, or security flaws that have not been caught. **Do not trust it for anything that matters.**
>
> Do **not** use PinChat for:
> - whistleblowing, source protection, or activist safety;
> - protecting personal, financial, medical, or legal data;
> - safety-critical or life-critical communications;
> - evading state-level or otherwise capable adversaries;
> - any scenario where a vulnerability in the software could cause real harm.
>
> If you need a serious secure-messaging tool, use an audited, mature application such as **Signal**. PinChat exists for experimentation, learning, and self-hosted low-risk conversations — nothing more.
>
> You use this software entirely at your own risk. See the full [Disclaimer](#disclaimer) at the bottom of this document.

Experimental end-to-end encrypted, ephemeral, browser-based chat.

PinChat is a small self-hostable web application for short-lived private conversations. Messages are encrypted in the browser before being relayed by the server. Room state is designed to live in application memory and expire after a configurable TTL.

> **Security status:** PinChat has not received an independent cryptographic audit. Treat it as experimental software. Do not rely on it for high-risk use cases without review by qualified cryptographers and application-security engineers.

## Overview

PinChat is designed around a narrow goal: make the application server act primarily as an encrypted relay for short-lived chat rooms, without maintaining a persistent message database.

It is **not** an anonymity system, not a formally verified cryptographic protocol, and not a replacement for mature messaging applications such as Signal, WhatsApp, Matrix, Session, SimpleX, or similar systems.

PinChat may be useful for:

- self-hosted temporary chats;
- low-risk private conversations;
- experiments with browser-based E2E encryption;
- learning about encrypted WebSocket relay design;
- situations where avoiding a server-side message database is useful.

PinChat is not recommended for:

- whistleblowing;
- activist safety;
- source protection;
- life-or-death communications;
- evading a state-level adversary;
- situations where metadata exposure is unacceptable;
- situations where participants cannot verify each other.

## Key Features

- **End-to-end encryption:** Messages are encrypted client-side using browser WebCrypto before being relayed by the server.
- **Ephemeral rooms:** Chat rooms expire after a configurable TTL, from 1 to 1440 minutes.
- **In-memory application state:** Room membership and relay state are kept in RAM by the application. Operators must still review reverse proxy logs, crash dumps, swap, container logs, hosting snapshots, and system journals.
- **No accounts by default:** Anonymous rooms do not require user registration.
- **Encrypted media:** Image sharing uses the same client-side encryption path as text messages.
- **MITM detection:** Short Authentication String, or SAS, verification lets participants authenticate the session out of band.
- **Double-Ratchet-inspired key progression:** Message keys advance over time and old message keys are deleted where possible. This is not a claim of full Signal Protocol equivalence.
- **Authenticated DH ratchet:** DH public key rotations are signed with the peer's identity key using ECDSA P-256. A live MITM key swap should trigger a hard session abort.
- **Subprotocol-based WebSocket auth:** JWTs are carried in `Sec-WebSocket-Protocol`, not in the URL, reducing accidental leakage through proxy access logs, referrer headers, or middlebox caches.
- **Rate limiting and anti-spam controls:** Configurable WebSocket, login, room-token, message-rate, and proof-of-work controls.
- **Optional static-asset integrity extension:** Browser extensions impose a per-page, hash-only script CSP before parsing and verify static assets against a signed manifest.

## Current Communication Modes

### 1:1 Chat

PinChat currently supports private one-to-one conversations between two participants.

### Group Chat

Group chat is intentionally disabled.

The previous Bootstrap Key approach is not considered sufficient for robust group key management. Group messaging should not be enabled until the protocol has a proper design for:

- membership changes;
- sender authentication;
- transcript consistency;
- forward secrecy;
- post-compromise recovery;
- removed-member exclusion;
- multi-device behavior, if supported.

## Security Model

### Security Goals

PinChat is designed to help with:

1. **Message confidentiality from the relay server**  
   Message contents are encrypted in the browser before being sent over the WebSocket relay.

2. **No server-side message database**  
   The application does not intentionally persist chat messages to a database.

3. **Ephemeral room lifecycle**  
   Rooms expire after a configured TTL. Expiry removes application-side room state, but cannot delete copies already seen by participants.

4. **Authenticated encryption**  
   Messages use AEAD encryption so tampering should be detected by clients.

5. **Forward-secrecy-oriented key progression**  
   Message keys are advanced and old message keys are deleted on the client side where possible.

6. **Optional human-verifiable authentication**  
   Participants can compare a SAS code over a secondary channel to reduce the risk of active man-in-the-middle attacks.

### Non-Goals

PinChat does not attempt to provide:

- strong anonymity;
- metadata privacy;
- deniability;
- protection from malicious participants;
- protection from compromised clients;
- protection from malicious browser extensions;
- protection from a server that serves malicious JavaScript;
- formal Signal Protocol compatibility;
- a formally proven cryptographic protocol;
- protection from screenshots, copy/paste, or screen recording;
- protection from coercion;
- protection from traffic analysis.

## What "Encrypted" Means In Practice

Headline claims like "end-to-end encrypted" describe a *capability*, not a *guarantee*. The actual security PinChat delivers depends on what the user does and what software is between them and the network. Three realistic configurations:

| Configuration | What you actually get |
|---|---|
| **SAS verified + integrity-extension installed** | Client-side AEAD with the Double Ratchet. The extension blocks scripts outside a packaged per-page hash allowlist and checks assets against a signed manifest. Peer identity has been confirmed out of band. **No external audit** — best-effort assurance only. |
| **SAS verified, no integrity extension** | Client-side AEAD with the Double Ratchet. Peer identity has been confirmed out of band. The server can still serve modified JavaScript on the next reload and you have no automatic way to notice. |
| **SAS skipped** | Client-side AEAD with the Double Ratchet — the traffic is still encrypted and a passive observer cannot read it. However, the server operator (or anyone with active relay access) could have substituted both parties' identity keys at the ECDH exchange and now sits in the middle as an authenticated peer to each side. This is encryption without peer authentication. |

The phrase "server cannot read your messages" is **only true** in the first two rows, and even there it is conditional on no external audit having found a defect. Marketing copy that omits the SAS condition is overstating the property. Use the matrix above when explaining the system to others.

## Threat Model

### Trusted Components

PinChat assumes the following components behave correctly:

- the user's device;
- the user's browser;
- the browser's WebCrypto implementation;
- the JavaScript code actually executed by the browser;
- the participant after they receive plaintext.

If any of these are compromised, PinChat cannot protect the conversation.

### Not Trusted

PinChat attempts to reduce trust in:

- the PinChat application server;
- the network;
- passive packet capture;
- ordinary server-side storage;
- reverse proxies that might otherwise log sensitive URL query parameters.

The server is expected to relay encrypted messages without knowing their plaintext.

### Partially Trusted

Other participants are only partially trusted.

They necessarily receive plaintext. They can copy, screenshot, record, forward, or disclose the conversation.

## Browser JavaScript Caveat

PinChat is a browser-based E2E application. This has an important limitation: the same server that relays encrypted messages also serves the JavaScript that performs encryption.

A malicious or compromised server could serve modified JavaScript that:

- reads plaintext before encryption;
- exfiltrates keys;
- bypasses or fakes SAS verification;
- changes security indicators in the UI;
- weakens protocol behavior;
- changes the code that verifies integrity.

PinChat includes optional browser-extension integrity checks for static assets, but this does not completely remove the web-delivery trust problem.

Users who need stronger assurance should prefer audited native clients with reproducible builds and stable release artifacts.

## Bootstrap Key

When a room is created, the browser generates a 256-bit Bootstrap Key. This key is appended to the room URL as a fragment:

```text
https://host/c/{room_id}#key={base64url_encoded_key}
```

The fragment is the part after `#`. Browsers do not send URL fragments in normal HTTP requests, so the Bootstrap Key is not normally sent to the server during navigation.

This is useful, but it is not magic.

The Bootstrap Key can still leak through:

- the user copying the full URL into an unsafe channel;
- screenshots;
- browser history on the local device;
- malicious browser extensions;
- same-origin JavaScript if the web app is compromised;
- chat apps, note apps, or QR tools used to share the link;
- someone who receives the link and forwards it.

Anyone who gets the full room link can join the room unless participants perform additional verification.

The Bootstrap Key encrypts the initial ECDH key exchange. After the handshake completes, the ratchet-based session encryption takes over for message encryption.

Protocol v1 hardening: once the ratchet is running, the in-memory Bootstrap Key is dropped. The Bootstrap Key bytes are moved out of `window.location.hash` into tab-scoped `sessionStorage` immediately after the first successful import and the URL bar is rewritten without the fragment, so the secret stops appearing in the address bar, browser history, screen-shares, or any same-origin code reading `window.location.hash`. On reconnect, the key is re-extracted from `sessionStorage` (or the URL fragment if the stash is unavailable). If neither source has it any more, for example because a browser extension cleared the storage, the client surfaces a clear “please re-open the original room link” message instead of attempting a handshake without a Bootstrap Key.

When an unauthenticated user clicks an invite link and is redirected to `/login`, a small head-loaded script (`login-stash.js`) detects the fragment, stashes it for the eventual chat page, and scrubs the URL bar before the login form renders. The Bootstrap Key never lingers on the login page either.

## Encryption Architecture

```text
                                      ENCRYPTION FLOW

      Client A                         Server                          Client B
      --------                         ------                          --------

         |                                |                                |
         |  [Bootstrap Key in URL fragment - not sent in HTTP request]     |
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
         |  8. Initialize Ratchet State   |                                |
         |     - Root Key                 |                                |
         |     - Sending Chain            |                                |
         |     - Receiving Chain          |                                |
         |                                |                                |
         |  9. Encrypt Message            |                                |
         |     (AES-GCM + AAD)            |                                |
         |                                |                                |
         |======= Encrypted Payload =====>|======= Encrypted Payload =====>|
         |        (Encrypted Relay)       |                                |
         |                                |                                |
```

## Server-Visible and Server-Hidden Data

PinChat is designed so the application server does not receive the plaintext of chat messages during normal operation.

The server should not receive:

1. message plaintext;
2. derived message encryption keys;
3. the Bootstrap Key through normal HTTP navigation, because it is placed in the URL fragment.

However, this is not a “zero knowledge” system in the formal cryptographic sense.

The server, reverse proxy, hosting provider, CDN, or network observer may still observe metadata, including:

1. source IP addresses, unless hidden by Tor, VPN, or another network layer;
2. connection timing;
3. room IDs in request paths;
4. WebSocket connection events;
5. approximate message sizes;
6. rate-limiting state;
7. proof-of-work challenge state;
8. room membership while a room exists;
9. browser and TLS metadata;
10. deployment logs outside the PinChat application.

PinChat should therefore be described as a browser-based encrypted relay with minimized server-side persistence, not as an anonymous or metadata-private messaging system.

## Cryptographic Primitives

| Component | Algorithm | Purpose |
|---|---|---|
| Message encryption | AES-GCM 256-bit | Authenticated encryption with associated data |
| Key exchange | ECDH P-256 | Derive shared secrets |
| Digital signatures | ECDSA P-256 | Authenticate identity keys and ratchet keys |
| Key derivation | HKDF-SHA256 | Derive root keys, chain keys, and message keys |
| Chain ratchet | HMAC-SHA256 | One-way message-key progression |
| SAS generation | HKDF-SHA256, 96-bit output (SAS v4, dual-key transcript-bound) | Human-comparable verification codes |

These primitives are used through browser WebCrypto on the client side.

The use of modern primitives does not by itself make the protocol secure. Protocol composition, state handling, authentication, message ordering, error handling, implementation bugs, and deployment behavior all matter.

## Ratchet Design

PinChat uses a Double-Ratchet-inspired construction for message-key progression.

```text
                           ROOT KEY
                              |
              +---------------+---------------+
              |                               |
        SENDING CHAIN                   RECEIVING CHAIN
              |                               |
      +-------+-------+               +-------+-------+
      |       |       |               |       |       |
     MK_0    MK_1    MK_2            MK_0    MK_1    MK_2
  (deleted) (deleted) (current)    (deleted) (deleted) (current)

      DH RATCHET:
      - new ECDH keypair generated on ratchet step
      - new root key derived
      - sending and receiving chains updated
```

This design is intended to provide forward-secrecy-oriented behavior under documented assumptions.

It should not be read as a claim of full Signal Protocol equivalence, formal post-compromise security, or audited cryptographic correctness.

## Authentication and SAS Verification

Encryption without authentication is not enough.

PinChat includes a Short Authentication String, or SAS, so participants can compare a small verification code through a separate trusted channel, such as:

- voice call;
- in-person comparison;
- an already-authenticated messenger;
- another channel whose authenticity the users already trust.

If users skip SAS verification, the chat may still be encrypted against passive observers, but it is not strongly authenticated against an active relay/server man-in-the-middle during the initial exchange.

For sensitive conversations, do not skip SAS verification.

The long-term identity keypair used to sign DH header rotations is persisted client-side in IndexedDB (per-origin, never synced, 24-hour TTL) so the SAS that a user has verified out of band stays the same across reconnects, tab refreshes, and short browser restarts. The private side of the keypair is non-extractable both on creation and after round-tripping through IndexedDB structured-clone. Erasing site data (or calling the explicit forget gesture) discards the entry; the next session mints a fresh one and the SAS resets.

## System Architecture

```text
+------------------------------------------------------------------+
|                            CLIENT                                |
|                                                                  |
|  +------------------+  +------------------+  +------------------+ |
|  |  Identity Keys   |  | Ephemeral Keys   |  | Ratchet State    | |
|  |  (ECDSA P-256)   |  | (ECDH P-256)     |  |                  | |
|  +------------------+  +------------------+  +------------------+ |
|           |                    |                     |            |
|           +--------------------+---------------------+            |
|                                |                                  |
|                    +-------------------+                          |
|                    |   CryptoManager   |                          |
|                    |   WebCrypto API   |                          |
|                    +-------------------+                          |
|                                |                                  |
|                    +-------------------+                          |
|                    | WebSocket Client  |                          |
|                    +-------------------+                          |
+------------------------------------------------------------------+
                                 |
                                 | TLS
                                 |
+------------------------------------------------------------------+
|                            SERVER                                |
|                                                                  |
|  +------------------+  +------------------+  +------------------+ |
|  |  Axum Framework  |  | WebSocket Relay  |  | Rate Limiting    | |
|  |  Rust / Tokio    |  |                  |  | tower-governor   | |
|  +------------------+  +------------------+  +------------------+ |
|           |                    |                     |            |
|           +--------------------+---------------------+            |
|                                |                                  |
|                    +-------------------+                          |
|                    |     AppState      |                          |
|                    |  DashMap / RAM    |                          |
|                    +-------------------+                          |
|                                |                                  |
|                    +-------------------+                          |
|                    |   Cleanup Task    |                          |
|                    | Expired Rooms     |                          |
|                    +-------------------+                          |
+------------------------------------------------------------------+
```

### Backend Stack

- Runtime: Rust with Tokio async runtime
- Framework: Axum web framework
- Transport: WebSocket over TLS, or HTTP behind a properly configured TLS reverse proxy
- Storage: application state in memory
- Rate limiting: tower-governor with HMAC-hashed IPs
- Anti-spam: proof-of-work challenge system

### Frontend Stack

- JavaScript: Vanilla JS with Alpine.js for reactivity
- Cryptography: WebCrypto API
- Styling: responsive CSS, no frontend framework build step required

## Quick Start

### Prerequisites

- Rust 1.75 or later
- OpenSSL, for local certificate generation
- A modern browser with WebCrypto support
- Node.js 18+ (only required to run the JS test suites; the client itself is build-less)

### Running tests

```bash
cargo test                  # Rust server-side tests
node tests/run-all-tests.js # JavaScript crypto suites
```

The JS runner has ten suites. Nine (`chain`, `double`, `security`,
`sasgate`, `correctness`, `pfs`, `kat`, `wycheproof`, and `fuzz`) run
without external dependencies. Only `properties` requires `npm ci`, for
`fast-check`; the decrypt-path fuzz harness is dependency-free and seeded.

If the dev-deps are not installed (offline clone, restricted npm
registry, etc.), the runner reports the property suite as `[SKIP]`
with an install hint and continues with a clean exit code 0. The
"core verde, advanced skipped" state is intentional: fresh clones
without npm access still get the cryptographic primitives test
coverage.

For long-running fuzz campaigns (the smoke run is 5s):

```bash
node tests/run-fuzz.js 3600   # 1-hour decrypt-path fuzz
node tests/run-fuzz.js 86400  # 24-hour campaign
```

### Installation

Clone the repository:

```bash
git clone https://github.com/samjanny/pinchat.git
cd pinchat
```

Generate local TLS certificates:

```bash
mkdir -p certs

openssl req -x509 -newkey rsa:4096 \
    -keyout certs/key.pem \
    -out certs/cert.pem \
    -days 365 -nodes \
    -subj "/CN=localhost"
```

Provide operator data for the legal pages:

```bash
cp static/operator.example.json static/operator.json
# edit static/operator.json with your real contact, hosting provider, etc.
```

The legal pages, such as `/static/terms.html` and `/static/privacy.html`, fetch `/static/operator.json` at runtime to fill in operator-specific values such as support email, DPA information, hosting note, and last-updated date.

The file is gitignored and deployment-specific. In production it is typically served from `WEBSITE_DIR`, so the public repository does not need to contain the operator's contact details.

If the file is missing, the legal pages still render but show fallback placeholders.

Build and run:

```bash
cargo run --release
```

Open:

```text
https://localhost:3000
```

Your browser will warn about the self-signed certificate in local development.

## Docker Deployment

Generate certificates first:

```bash
./generate-certs.sh
```

Build and run with Docker Compose:

```bash
docker-compose up --build
```

## Configuration

PinChat is configured through environment variables.

These settings control application behavior only. They do not automatically configure your reverse proxy, CDN, container runtime, system journal, crash dumps, swap, VM snapshots, browser history, or hosting-provider logs.

| Variable | Default | Description |
|---|---:|---|
| `HOST` | `127.0.0.1` | Server bind address |
| `PORT` | `3000` | Server port |
| `PRIVACY_MODE` | `strict` | Application logging profile: `strict`, `minimal`, `development` |
| `FORCE_HTTP` | `false` | Allow HTTP for reverse-proxy deployments |
| `FORCE_SECURE_COOKIES` | `false` | Force the Secure cookie flag |
| `CORS_ALLOWED_ORIGINS` | `https://localhost:3000` | Comma-separated origins for CORS and WebSocket Origin checks. Required in production. Must include your public origin or browsers will fail the WebSocket upgrade with 403. Example: `https://your-domain.com,https://www.your-domain.com` |
| `MAX_TOTAL_ROOMS` | `1000` | Maximum concurrent rooms |
| `CSP_WS_HOST` | `'self'` | WebSocket CSP origins |
| `WS_CONN_BURST_SIZE` | `30` | WebSocket connections allowed per period |
| `WS_CONN_PERIOD_SECS` | `60` | Window for WebSocket connection rate limiting |
| `ROOM_TOKEN_BURST_SIZE` | `100` | Room/token creations allowed per period |
| `ROOM_TOKEN_PERIOD_SECS` | `600` | Window for room/token rate limiting |
| `MSG_RATE_LIMIT` | `30` | Messages per connection per window |
| `MSG_RATE_WINDOW_SECS` | `1` | Window length for per-connection message rate limiting |
| `POW_MIN_DIFFICULTY` | `12` | Minimum proof-of-work difficulty, in bits |
| `POW_MAX_DIFFICULTY` | `18` | Maximum proof-of-work difficulty, in bits |
| `CHALLENGE_TTL_SECS` | `300` | Proof-of-work challenge TTL |
| `JWT_TOKEN_TTL_SECS` | `30` | WebSocket JWT TTL, in seconds |
| `ROOM_CLEANUP_INTERVAL_SECS` | `60` | Room cleanup interval |
| `CHALLENGE_CLEANUP_INTERVAL_SECS` | `60` | Proof-of-work cache cleanup interval |
| `PINCHAT_PASSWORD_HASHES` | empty | Semicolon-separated Argon2id hashes. If empty, password auth is disabled |
| `SESSION_TTL_SECS` | `86400` | Session lifetime |
| `LOGIN_BURST_SIZE` | `5` | Login attempts allowed per period |
| `LOGIN_PERIOD_SECS` | `900` | Window for login rate limiting |
| `TRUSTED_PROXIES` | empty | Comma-separated proxy IPs/CIDRs trusted for `X-Forwarded-For` |
| `REPLAY_CACHE_MAX_PER_ROOM` | `1000` | Maximum anti-replay entries per room. The cache is an advisory layer; the authoritative anti-replay is the Double Ratchet counter, checked client-side. |
| `MAX_IMAGE_SIZE` | `300KB` | Maximum image size, as bytes or with `KB`/`MB` suffix |
| `WEBSITE_DIR` | empty | Custom static files directory. Falls back to `/static` |

## Privacy Modes

PinChat supports three application logging profiles:

- `strict`: suppresses ordinary application logs as much as possible;
- `minimal`: logs warnings and errors only;
- `development`: enables verbose debug logging for local testing.

`strict` mode only affects PinChat application logs.

It does not disable logs from:

- reverse proxies;
- CDNs;
- load balancers;
- container runtimes;
- systemd journals;
- kernel/network logs;
- hosting providers;
- crash dumps;
- browser history;
- participant devices.

Operators are responsible for validating the full deployment stack.

## Security Considerations

### What PinChat Is Designed to Help With

PinChat is designed to help reduce:

- server-side access to message plaintext;
- accidental persistence of chat messages in an application database;
- retrospective plaintext recovery from encrypted WebSocket payloads, assuming endpoint keys were not compromised;
- accidental JWT leakage through URLs by using `Sec-WebSocket-Protocol`;
- simple spam and abuse through rate limiting and proof-of-work;
- some active MITM scenarios when users verify the SAS out of band.

### What PinChat Does Not Protect Against

PinChat does not protect against:

- compromised client devices;
- malicious browser extensions;
- a malicious or compromised server serving modified JavaScript;
- screenshots, copy/paste, or deliberate recording by participants;
- traffic analysis;
- IP-address visibility;
- unsafe room-link sharing;
- social engineering;
- malicious participants in the room;
- metadata visible to the server or deployment infrastructure;
- coercion;
- state-level adversaries.

### Metadata

Even when message contents are encrypted, metadata can still be sensitive.

Depending on deployment and configuration, PinChat or surrounding infrastructure may process or expose:

- source IP addresses;
- User-Agent strings;
- room URLs without fragments;
- room IDs;
- connection timing;
- disconnection timing;
- approximate message sizes;
- rate-limit counters;
- proof-of-work challenge state;
- TLS and TCP metadata;
- reverse proxy request logs;
- hosting-provider telemetry.

PinChat does not claim to hide this metadata.

### RAM-Only Does Not Mean Unrecoverable

PinChat avoids intentional server-side message persistence, but “in memory” does not mean “impossible to recover.”

A live server compromise, memory dump, swap misconfiguration, crash dump, debug logging mistake, container snapshot, VM snapshot, or hosting-provider inspection may expose runtime data.

Operators should disable swap or encrypt it, review crash dump settings, review journald/container logs, and understand their hosting provider’s snapshot/backup behavior.

## Recommended Practices

For more sensitive use:

- use HTTPS;
- verify the SAS out of band;
- share room links only through a trusted channel;
- avoid browser extensions you do not trust;
- use a private browsing session;
- close the tab after the conversation;
- avoid screenshots and copy/paste into untrusted apps;
- consider Tor or a VPN if IP metadata matters;
- do not use a public or shared device;
- keep the browser and operating system updated;
- do not rely on PinChat for high-risk communications.

## Abuse Prevention

PinChat includes rate limiting and proof-of-work mechanisms to make abuse more expensive.

These mechanisms are operational controls, not cryptographic privacy guarantees. Depending on deployment settings, abuse-prevention systems may require processing client IPs or derived identifiers.

## Browser Extensions

PinChat includes browser extensions for Chrome and Firefox that verify files served by the web application against cryptographically signed hashes.

### How It Works

1. The extension fetches a signed hash list from GitHub as an out-of-band source.
2. It verifies the ECDSA P-256 signature using an embedded public key.
3. Before page parsing, it replaces the response CSP with a packaged per-page script-hash allowlist; unknown paths receive `script-src 'none'`.
4. It checks that `<script>` and `<link>` tags have expected `integrity` attributes.
5. It fetches files listed in the manifest and verifies their SHA-256 hashes.
6. It displays a warning overlay if an integrity check fails.

This prevents arbitrary newly injected scripts from running and detects broader
static-file/HTML tampering. It still does not make the delivered HTML immutable
or protect against bugs in already trusted client code.

It is not a complete replacement for:

- native application distribution;
- reproducible builds;
- independent audits;
- careful operational security;
- endpoint security;
- browser security.

See `extensions/README.md` for setup and installation instructions.

## Documentation

- `SECURITY.md` — detailed threat model and cryptographic specifications.
- `PROTOCOL.md` — protocol specification and message formats.
- `CHANGELOG.md` — version history.
- `NOTICE` — third-party asset attribution.

## Changelog

See `CHANGELOG.md` for the full version history.

The changelog format is based on Keep a Changelog.

## Reporting Security Issues

Please do not report security issues through public GitHub issues if the issue could put users at risk.

Use the contact process described in `SECURITY.md`.

When reporting, include:

- affected version or commit;
- deployment mode;
- browser and OS;
- reproduction steps;
- expected impact;
- whether the issue is already public.

## Audit Status

PinChat has not been independently audited.

The code and protocol should be reviewed before serious use. Contributions that reduce custom cryptography, improve documentation, remove ambiguous claims, or clarify the threat model are welcome.

## License

Copyright 2025 Raffaele Mangiacasale  
support@pinchat.io

Licensed under the Apache License, Version 2.0.

You may not use this file except in compliance with the License. You may obtain a copy of the License at:

```text
http://www.apache.org/licenses/LICENSE-2.0
```

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the `LICENSE` file for details.

## Disclaimer

This software is an experimental prototype provided for educational, research, and self-hosting experimentation purposes.

It is not designed, intended, or warranted for:

- high-risk production use;
- protection of real-world sensitive, personal, financial, or confidential data;
- safety-critical, life-critical, or mission-critical communications;
- adversarial environments where metadata exposure creates serious risk.

Although PinChat uses modern cryptographic primitives, it has not undergone a formal independent security review or audit and may contain serious vulnerabilities.

You use this software entirely at your own risk.

The authors and contributors provide it “as is”, without any express or implied warranty, including but not limited to any warranty of security, fitness for a particular purpose, or non-infringement.

Under no circumstances shall the authors or contributors be liable for any claim, damages, or other liability arising from, out of, or in connection with the software or its use.
