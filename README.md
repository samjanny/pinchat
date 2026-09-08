# PinChat

> ## EXPERIMENTAL TEST PROJECT, NOT FOR HIGH-SECURITY USE
>
> **PinChat is an experimental test and research project.** It has **not** been
> independently audited, it has **not** received a formal cryptographic review,
> and it is **not** intended for protecting sensitive, confidential, personal,
> financial, life-critical, or otherwise high-risk communications. As
> experimental, unaudited software it may contain subtle bugs, incorrect
> assumptions, or security flaws that have not been caught. **Do not trust it
> for anything that matters.**
>
> Do **not** use PinChat for whistleblowing, source protection, activist
> safety, personal or financial or medical or legal data, safety-critical
> communications, evading capable adversaries, or any scenario where a
> vulnerability could cause real harm.
>
> If you need a serious secure-messaging tool, use an audited, mature
> application such as **Signal**. PinChat exists for experimentation,
> learning, and self-hosted low-risk conversations, nothing more.
>
> You use this software entirely at your own risk. See the full
> [Disclaimer](#disclaimer) at the bottom of this document.

Experimental end-to-end encrypted, ephemeral, browser-based chat.

PinChat is a small self-hostable web application for short-lived private
conversations. Messages are encrypted in the browser before being relayed by
the server. Room state lives in application memory and expires after a
configurable TTL.

The design goal is narrow: make the application server act as an encrypted
relay for short-lived rooms, without a server-side message database. It is
**not** an anonymity system, not a formally verified protocol, and not a
replacement for Signal, WhatsApp, Matrix, Session, or SimpleX.

## Features

- **End-to-end encryption.** Messages are encrypted client-side with WebCrypto
  before reaching the relay.
- **Ephemeral rooms.** Rooms expire after a configurable TTL, 1 to 1440
  minutes. Application state is kept in RAM.
- **No accounts by default.** Anonymous rooms require no registration.
- **Encrypted media.** Images use the same client-side encryption path as text.
- **SAS verification.** A Short Authentication String lets participants
  authenticate the session out of band and detect an active MITM.
- **Group chat, behind a flag.** Rooms of up to 20 members use an MLS
  (RFC 9420) group built from scratch, validated against the IETF test
  vectors. Off by default (`GROUP_CHAT_ENABLED`); see the section below for
  what it does and does not provide.
- **Double-Ratchet-inspired key progression.** Message keys advance and old
  keys are deleted where possible. This is not a claim of Signal Protocol
  equivalence.
- **Authenticated DH ratchet.** DH public key rotations are signed with the
  peer's ECDSA P-256 identity key. A live key swap triggers a hard abort.
- **Subprotocol WebSocket auth.** JWTs travel in `Sec-WebSocket-Protocol`, not
  in the URL, so they stay out of proxy logs and referrer headers.
- **Rate limiting and proof of work.** Configurable WebSocket, login, room
  token, message rate, and PoW controls.
- **Optional integrity extension.** Browser extensions impose a per-page,
  hash-only script CSP before parsing and verify static assets against a
  signed manifest.

Group chat ships disabled and is enabled per deployment with
`GROUP_CHAT_ENABLED=true`. It is a separate protocol from the 1:1 path: an MLS
group (RFC 9420, ciphersuite 0x0002) in which the room creator, at leaf 0, is
the only member that commits membership changes. Members are admitted with
KeyPackages bound to the room's bootstrap key, every Commit and Welcome is
signed and verified before any state changes, forward secrecy comes from
per-epoch secret trees with consumed keys deleted, and post-compromise
security from periodic re-keying. The relay stays blind to content but, unlike
1:1, sees the group's public key material and its membership changes.

Two limits are structural and worth knowing before enabling it. The creator's
group state lives only in its open tab: if the creator reloads or closes it,
existing members can keep talking in the current epoch but nobody can join or
be removed until a new room is created (the page now warns before unloading).
And there is no out-of-band verification ceremony for groups: admission rests
on the link being the capability plus authenticated leaf keys, not on members
comparing fingerprints. The full list is in `static/js/mls/README.md`.

## What "encrypted" means in practice

Headline claims like "end-to-end encrypted" describe a *capability*, not a
*guarantee*. What PinChat actually delivers depends on what the user does and
what software sits between them and the network.

| Configuration | What you actually get |
|---|---|
| **SAS verified, integrity extension installed** | Client-side AEAD with the Double Ratchet. The extension blocks scripts outside a packaged per-page hash allowlist and checks assets against a signed manifest. Peer identity confirmed out of band. **No external audit**, best-effort assurance only. |
| **SAS verified, no extension** | Client-side AEAD with the Double Ratchet. Peer identity confirmed out of band. The server can still serve modified JavaScript on the next reload and you have no automatic way to notice. |
| **SAS skipped** | Client-side AEAD with the Double Ratchet. Traffic is encrypted and a passive observer cannot read it. But the server operator, or anyone with active relay access, could have substituted both parties' identity keys during the ECDH exchange and now sits in the middle as an authenticated peer to each side. Encryption without peer authentication. |

"The server cannot read your messages" is **only true** in the first two rows,
and even there it is conditional on no audit having found a defect. Any claim
that omits the SAS condition is overstating the property.

### The browser JavaScript problem

The same server that relays encrypted messages also serves the JavaScript that
performs the encryption. A malicious or compromised server could serve
modified code that reads plaintext before encryption, exfiltrates keys, fakes
SAS verification, or alters the security indicators in the UI.

The browser extensions in `extensions/` reduce this exposure but do not
eliminate it. Anyone needing stronger assurance should prefer audited native
clients with reproducible builds.

### Metadata

Message contents are encrypted, metadata is not. The server, reverse proxy,
hosting provider, CDN, or a network observer can still see source IP
addresses, connection and disconnection timing, room IDs in request paths,
approximate message sizes, room membership while a room exists, and TLS and
TCP metadata. Rate-limit and proof-of-work state is also observable.

PinChat is a browser-based encrypted relay with minimised server-side
persistence. It is not an anonymous or metadata-private messaging system.

Note also that "in memory" does not mean "unrecoverable". A live compromise,
memory dump, swap misconfiguration, crash dump, container or VM snapshot, or
hosting-provider inspection may expose runtime data. Operators should disable
or encrypt swap, review crash dump settings and container logs, and understand
their provider's snapshot behaviour.

The full threat model, trust assumptions, security goals and non-goals,
bootstrap key analysis, and known limitations are in
[SECURITY.md](SECURITY.md).

## Cryptographic primitives

| Component | Algorithm | Purpose |
|---|---|---|
| Message encryption | AES-GCM 256 | Authenticated encryption with associated data |
| Key exchange | ECDH P-256 | Derive shared secrets |
| Digital signatures | ECDSA P-256 | Authenticate identity keys and ratchet keys |
| Key derivation | HKDF-SHA256 | Root keys, chain keys, message keys |
| Chain ratchet | HMAC-SHA256 | One-way message-key progression |
| SAS generation | HKDF-SHA256, 96-bit output, v4 dual-key transcript-bound | Human-comparable verification codes |

All of these are used through browser WebCrypto. Modern primitives do not by
themselves make a protocol secure: composition, state handling,
authentication, ordering, error handling, implementation bugs, and deployment
behaviour all matter.

Handshake, ratchet design, message formats, and the SAS derivation are
specified in [PROTOCOL.md](PROTOCOL.md).

## Architecture

**Backend.** Rust with Tokio, Axum, WebSocket over TLS or behind a
TLS-terminating reverse proxy, application state in memory, rate limiting via
tower-governor with HMAC-hashed IPs, proof-of-work anti-spam.

**Frontend.** Vanilla JavaScript with Alpine.js (CSP build), WebCrypto,
responsive CSS. No build step.

## Quick start

### Prerequisites

- Rust 1.75 or later
- OpenSSL, for local certificate generation
- A modern browser with WebCrypto support
- Node.js 18+ to run the JS test suites; the client itself is build-less

### Install and run

```bash
git clone https://github.com/samjanny/pinchat.git
cd pinchat

mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
    -keyout certs/key.pem \
    -out certs/cert.pem \
    -days 365 -nodes \
    -subj "/CN=localhost"

cp static/operator.example.json static/operator.json
# edit static/operator.json with your real contact, hosting provider, etc.

cargo run --release
```

Then open `https://localhost:3000`. The browser will warn about the
self-signed certificate in local development.

`static/operator.json` fills in operator-specific values on the legal pages
(support email, DPA information, hosting note, last-updated date). It is
gitignored and deployment-specific, typically served from `WEBSITE_DIR` in
production. If it is missing the legal pages still render, with placeholders.

### Docker

```bash
./generate-certs.sh
docker-compose up --build
```

### Tests

```bash
cargo test                  # Rust server-side tests
node tests/run-all-tests.js # JavaScript crypto suites
```

The JS runner has ten suites. Nine (`chain`, `double`, `security`, `sasgate`,
`correctness`, `pfs`, `kat`, `wycheproof`, `fuzz`) run without external
dependencies. Only `properties` needs `npm ci` for `fast-check`. Without the
dev dependencies the runner reports that suite as `[SKIP]` and still exits 0,
so a fresh clone with no npm access still gets the primitives coverage.

Longer fuzz campaigns, the default smoke run being 5 seconds:

```bash
node tests/run-fuzz.js 3600   # 1 hour
node tests/run-fuzz.js 86400  # 24 hours
```

## Configuration

PinChat is configured through environment variables. These control application
behaviour only. They do not configure your reverse proxy, CDN, container
runtime, system journal, crash dumps, swap, VM snapshots, browser history, or
hosting-provider logs.

| Variable | Default | Description |
|---|---:|---|
| `HOST` | `127.0.0.1` | Server bind address |
| `PORT` | `3000` | Server port |
| `PRIVACY_MODE` | `strict` | Logging profile: `strict`, `minimal`, `development` |
| `FORCE_HTTP` | `false` | Allow HTTP for reverse-proxy deployments |
| `FORCE_SECURE_COOKIES` | `false` | Force the Secure cookie flag |
| `CORS_ALLOWED_ORIGINS` | `https://localhost:3000` | Comma-separated origins for CORS and the WebSocket Origin check. Required in production: must include your public origin or the WebSocket upgrade fails with 403 |
| `MAX_TOTAL_ROOMS` | `1000` | Maximum concurrent rooms |
| `CSP_WS_HOST` | `'self'` | Extra WebSocket origins allowed by the CSP |
| `WS_CONN_BURST_SIZE` | `30` | WebSocket connections per period |
| `WS_CONN_PERIOD_SECS` | `60` | Window for WebSocket connection rate limiting |
| `ROOM_TOKEN_BURST_SIZE` | `100` | Room and token creations per period |
| `ROOM_TOKEN_PERIOD_SECS` | `600` | Window for room and token rate limiting |
| `MSG_RATE_LIMIT` | `30` | Messages per connection per window |
| `MSG_RATE_WINDOW_SECS` | `1` | Window for per-connection message rate limiting |
| `POW_MIN_DIFFICULTY` | `12` | Minimum proof-of-work difficulty, in bits |
| `POW_MAX_DIFFICULTY` | `18` | Maximum proof-of-work difficulty, in bits |
| `CHALLENGE_TTL_SECS` | `300` | Proof-of-work challenge TTL |
| `JWT_TOKEN_TTL_SECS` | `30` | WebSocket JWT TTL |
| `ROOM_CLEANUP_INTERVAL_SECS` | `60` | Room cleanup interval |
| `CHALLENGE_CLEANUP_INTERVAL_SECS` | `60` | Proof-of-work cache cleanup interval |
| `PINCHAT_PASSWORD_HASHES` | empty | Semicolon-separated Argon2id hashes. Empty disables password auth |
| `SESSION_TTL_SECS` | `86400` | Session lifetime |
| `LOGIN_BURST_SIZE` | `5` | Login attempts per period |
| `LOGIN_PERIOD_SECS` | `900` | Window for login rate limiting |
| `TRUSTED_PROXIES` | empty | Comma-separated proxy IPs or CIDRs trusted for `X-Forwarded-For`. Set this behind a reverse proxy, or every client shares one rate-limit bucket |
| `REPLAY_CACHE_MAX_PER_ROOM` | `1000` | Anti-replay entries per room. Advisory only; the authoritative check is the client-side Double Ratchet counter |
| `MAX_IMAGE_SIZE` | `300KB` | Maximum image size, bytes or with a `KB` or `MB` suffix |
| `WEBSITE_DIR` | empty | Custom static directory, falling back to `/static` |

### Privacy modes

`strict` suppresses ordinary application logs, `minimal` logs warnings and
errors only, `development` enables verbose debug logging for local testing.

This affects PinChat application logs and nothing else. It does not touch
reverse proxies, CDNs, load balancers, container runtimes, systemd journals,
kernel or network logs, hosting providers, crash dumps, browser history, or
participant devices. Validating the full deployment stack is the operator's
job.

## Browser extensions

`extensions/` contains Chrome and Firefox extensions that verify the files
served by the web application against a cryptographically signed manifest.

Before a page is parsed the extension replaces the response CSP with a
packaged per-page script-hash allowlist, so the origin is not trusted for
scripts at all and unknown paths get `script-src 'none'`. It then verifies the
signed manifest, checks the `integrity` attributes present in the DOM, and
re-fetches every listed asset to compare its SHA-256. A mismatch raises a
full-page warning.

This blocks newly injected scripts and detects broader static-file tampering.
It does not make the delivered HTML immutable and it does not protect against
bugs in already-trusted client code. It is not a substitute for native
application distribution, reproducible builds, independent audits, endpoint
security, or careful operational practice.

See [extensions/README.md](extensions/README.md) for setup, installation, and
packaging.

## Recommended practices

For more sensitive use: use HTTPS, verify the SAS out of band, share room
links only through a trusted channel, avoid browser extensions you do not
trust, use a private browsing session, close the tab afterwards, avoid
screenshots and copy-paste into untrusted apps, consider Tor or a VPN if IP
metadata matters, avoid public or shared devices, keep the browser and OS
updated, and do not rely on PinChat for high-risk communications.

## Documentation

- [SECURITY.md](SECURITY.md), threat model and cryptographic specifications
- [PROTOCOL.md](PROTOCOL.md), protocol specification and message formats
- [extensions/README.md](extensions/README.md), integrity verifier extensions
- [CHANGELOG.md](CHANGELOG.md), version history, following Keep a Changelog
- `NOTICE`, third-party asset attribution

## Reporting security issues

Do not report security issues through public GitHub issues if the issue could
put users at risk. Use the contact process in [SECURITY.md](SECURITY.md).

Include the affected version or commit, deployment mode, browser and OS,
reproduction steps, expected impact, and whether the issue is already public.

## Audit status

PinChat has not been independently audited. The code and protocol should be
reviewed before serious use. Contributions that reduce custom cryptography,
improve documentation, remove ambiguous claims, or clarify the threat model
are welcome.

## License

Copyright 2025 Raffaele Mangiacasale
support@pinchat.io

Licensed under the Apache License, Version 2.0. You may not use this file
except in compliance with the License. You may obtain a copy of the License
at `http://www.apache.org/licenses/LICENSE-2.0`.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
`LICENSE` file for details.

## Disclaimer

This software is an experimental prototype provided for educational, research,
and self-hosting experimentation purposes.

It is not designed, intended, or warranted for high-risk production use, for
protection of real-world sensitive or personal or financial or confidential
data, for safety-critical or life-critical or mission-critical communications,
or for adversarial environments where metadata exposure creates serious risk.

Although PinChat uses modern cryptographic primitives, it has not undergone a
formal independent security review or audit and may contain serious
vulnerabilities.

You use this software entirely at your own risk. The authors and contributors
provide it "as is", without any express or implied warranty, including but not
limited to any warranty of security, fitness for a particular purpose, or
non-infringement. Under no circumstances shall the authors or contributors be
liable for any claim, damages, or other liability arising from, out of, or in
connection with the software or its use.
