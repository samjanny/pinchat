# PinChat

[![CI](https://github.com/samjanny/pinchat/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/samjanny/pinchat/actions/workflows/ci.yml)
[![Security audit](https://github.com/samjanny/pinchat/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/samjanny/pinchat/actions/workflows/audit.yml)
[![SRI consistency](https://github.com/samjanny/pinchat/actions/workflows/sri-check.yml/badge.svg?branch=main)](https://github.com/samjanny/pinchat/actions/workflows/sri-check.yml)
[![Docker build](https://github.com/samjanny/pinchat/actions/workflows/docker.yml/badge.svg?branch=main)](https://github.com/samjanny/pinchat/actions/workflows/docker.yml)
[![Release](https://img.shields.io/github/v/release/samjanny/pinchat)](https://github.com/samjanny/pinchat/releases/latest)
[![License](https://img.shields.io/github/license/samjanny/pinchat)](LICENSE)
[![Firefox add-on](https://img.shields.io/amo/v/pinchat-integrity-verifier?label=Firefox%20add-on)](https://addons.mozilla.org/firefox/addon/pinchat-integrity-verifier/)
[![Status: experimental, not audited](https://img.shields.io/badge/status-experimental%2C%20not%20audited-red)](#audit-status)

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
- **No accounts.** Nobody registers. A deployment is either gated by a shared
  site password (`PINCHAT_PASSWORD_HASHES`) or explicitly open
  (`ALLOW_ANONYMOUS=true`); with neither, the server refuses to start outside
  `PRIVACY_MODE=development`.
- **Encrypted media.** Images use the same client-side encryption path as text.
- **SAS verification.** A Short Authentication String lets participants
  authenticate the session out of band and detect an active MITM.
- **Group chat, behind a flag.** Rooms of up to 20 members use an MLS
  (RFC 9420) group built from scratch, whose building blocks are checked
  against the IETF test vectors. It departs from the RFC in a few documented
  places ([static/js/mls/README.md](static/js/mls/README.md)) and does not
  interoperate with other MLS implementations. Off by default (`GROUP_CHAT_ENABLED`); see the section below for
  what it does and does not provide.
- **Double-Ratchet-inspired key progression.** Message keys advance and old
  keys are deleted where possible. This is not a claim of Signal Protocol
  equivalence.
- **Authenticated DH ratchet.** DH public key rotations are signed with the
  peer's ECDSA P-256 identity key. A swapped DH key inside a session
  triggers a hard abort. A peer that comes back with a different identity key
  must be verified again before anything is sent or shown: the "verified"
  state belongs to the key that was compared, not to the room.
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
| **SAS verified, integrity extension installed** | Client-side AEAD with the Double Ratchet. The extension blocks scripts outside a packaged per-page hash allowlist and checks assets against a signed manifest. In Firefox it also checks the page HTML before it is parsed; Chromium gives an extension no way to do that (see [Browser extensions](#browser-extensions)). Peer identity confirmed out of band. **No external audit**, best-effort assurance only. |
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
hosting-provider inspection may expose runtime data. The provided
`docker-compose.yml` gives the container a memory ceiling and no swap on top
of it, which keeps the relay's own memory off a swap device; it does nothing
for the reverse proxy or the rest of the host. Operators should disable or
encrypt swap, review crash dump settings and container logs, and understand
their provider's snapshot behaviour. A reverse proxy that serves several
sites logs a request by the settings of the site that answers it, so turn its
access and error logs off for the proxy as a whole, not only for PinChat's
host names.

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

**Backend.** Rust with Tokio and Axum, over TLS or behind a TLS-terminating
reverse proxy. The WebSocket transport is the relay's own
(`src/ws_transport.rs`), fuzzed in `fuzz/` and run against the Autobahn
conformance suite in `tests/autobahn/`. Application state lives in memory.
Rate limiting uses tower-governor with HMAC-hashed IPs, alongside
proof-of-work anti-spam and a cap on open WebSocket connections.

**Frontend.** Vanilla JavaScript with Alpine.js (CSP build), WebCrypto,
responsive CSS. No build step. The application markup lives in signed
scripts (`static/js/templates/`), not in the HTML pages, and the framework
only reads directives from those: see the guard at the end of
`static/js/alpine-csp.min.js`. Images are stripped of their metadata before
they are sent (`static/js/image-metadata.js`).

## Quick start

### Prerequisites

- Rust 1.88 or later (the Docker image builds with 1.90)
- A Unix-like system such as Linux for a native build. The server uses Unix
  socket APIs and does not compile on Windows; there, use WSL or Docker
- OpenSSL, for local certificate generation
- A modern browser with WebCrypto support
- Node.js 20 or later to run the JS test suites (CI runs 20); the client
  itself is build-less

### Install and run

```bash
git clone https://github.com/samjanny/pinchat.git
cd pinchat

./generate-certs.sh   # self-signed certificate for localhost in certs/

cp .env.example .env
# edit .env: set ALLOW_ANONYMOUS=true for an open local instance, or put an
# Argon2id hash in PINCHAT_PASSWORD_HASHES, made with
#   cargo run --release --bin generate_hash   (asks for the password)

cp static/operator.example.json static/operator.json
# edit static/operator.json with your real contact, hosting provider, etc.

cargo run --release
```

Then open `https://localhost:3000`. The browser will warn about the
self-signed certificate in local development.

The server reads `.env` at startup and fails closed: with no password hash
and without `ALLOW_ANONYMOUS=true` it exits with "Authentication is not
configured". `PRIVACY_MODE=development` lifts that check too, for local work
only.

`static/operator.json` fills in operator-specific values on the legal pages
(support email, DPA information, hosting note, last-updated date). It is
gitignored and deployment-specific, typically served from `WEBSITE_DIR` in
production. If it is missing the legal pages still render, with placeholders.

### Docker

```bash
./generate-certs.sh
cp .env.example .env   # then set HOST=0.0.0.0 and an access mode, as above
docker compose up --build
```

Inside the container the server has to listen on `0.0.0.0`: bound to the
`127.0.0.1` of `.env.example`, it never answers the published port.

When upgrading a running deployment, build first and dry-run the new image
against the real `.env` before switching, since the server refuses to start
on a setting it cannot honour (see the upgrade notes in `CHANGELOG.md`):

```bash
docker compose build
# must print "Starting HTTP server"; the override takes the dry run off the
# network, whose fixed address the running container holds
timeout 8 docker compose -f docker-compose.yml -f docker-compose.dryrun.yml run --rm --no-deps -T pinchat
docker compose up -d
```

Naming files with `-f` turns off the automatic `docker-compose.override.yml`.
If you keep one, name it too, before the dry-run file, or the dry run starts
without its mounts and environment:
`-f docker-compose.yml -f docker-compose.override.yml -f docker-compose.dryrun.yml`.

Behind nginx on a small host, the defaults of nginx and of the kernel give
out before the relay's own limits: see docs/reverse-proxy.md.

### Tests

```bash
cargo test                  # Rust server-side tests
node tests/run-all-tests.js # JavaScript crypto suites
```

The JS runner has 47 suites: the 1:1 ratchet and SAS gate, known-answer and
Wycheproof vectors, the MLS group code, the extension's verdict logic, and the
client's handling of served markup, images and reconnects. A suite name runs
that suite only, for example `node tests/run-all-tests.js double`. All of
them run without external dependencies except `properties`, which needs
`npm ci` for `fast-check`. Without the dev dependencies the runner reports
that suite as `[SKIP]` and still exits 0, so a fresh clone with no npm access
still gets the rest of the coverage.

Longer fuzz campaigns, the default smoke run being 5 seconds:

```bash
node tests/run-fuzz.js 3600   # 1 hour
node tests/run-fuzz.js 86400  # 24 hours
```

Not part of CI, each with its requirements at the top of its file or README:
`tests/extension-browser/run.js` drives the extension in headless Chromium
and Firefox against a hostile origin, `tests/layout-browser/run.js` checks
the pages at phone widths, `fuzz/` fuzzes the WebSocket transport with
cargo-fuzz, and `tests/autobahn/` runs it against the Autobahn suite.

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
| `FORCE_HTTP` | `false` | Allow HTTP for reverse-proxy deployments. Outside `development` it also needs `FORCE_SECURE_COOKIES=true` and a non-empty `TRUSTED_PROXIES`, or the server refuses to start |
| `FORCE_SECURE_COOKIES` | `false` | Force the Secure cookie flag |
| `CORS_ALLOWED_ORIGINS` | `https://localhost:3000` | Comma-separated origins for CORS and the WebSocket Origin check. Required in production: must include your public origin or the WebSocket upgrade fails with 403 |
| `MAX_TOTAL_ROOMS` | `500` | Maximum concurrent rooms, sized for a 512 MiB memory limit (see "Relay Memory" in SECURITY.md); raise it only with more memory |
| `GROUP_CHAT_ENABLED` | `false` | MLS group rooms of up to 20 members. Off, group-room creation answers 404 |
| `MAX_WS_CONNECTIONS` | `400` | WebSocket connections open at once. An upgrade beyond it is refused with 503 and `Retry-After`, before anything is allocated for it; the token and room endpoints refuse with the same answer before the proof of work. Sized for a 512 MiB container |
| `MAX_WS_CONNECTIONS_PER_ADDRESS` | `50` | WebSocket connections open at once from one client address (an IPv6 /64; an IPv6 /48 may hold four times as many). Beyond it: 429 and `Retry-After` |
| `CSP_WS_HOST` | `'self'` | Extra WebSocket origins allowed by the CSP |
| `WS_CONN_BURST_SIZE` | `30` | WebSocket connections per window, per client address, counted only for upgrades that carry a valid token. Also the burst a client may spend at once |
| `WS_CONN_PERIOD_SECS` | `60` | Window over which the WebSocket connection budget refills evenly |
| `ROOM_TOKEN_BURST_SIZE` | `100` | Room and token requests per window, per client address, counted after the session check |
| `ROOM_TOKEN_PERIOD_SECS` | `600` | Window over which the room and token budget refills evenly |
| `MSG_RATE_LIMIT` | `30` | Messages per connection per window |
| `MSG_RATE_WINDOW_SECS` | `1` | Window for per-connection message rate limiting, also used by the per-room and frame limits below |
| `ROOM_MSG_RATE_LIMIT` | `120` | Messages per room per window, all members together |
| `ROOM_BYTE_RATE_LIMIT` | `8MB` | Payload bytes per room per window, MLS traffic counted after Base64url decoding. 64KB to 64MB, and at least twice the encoded size of a `MAX_IMAGE_SIZE` image (about 3.6 times `MAX_IMAGE_SIZE`); the relay refuses to start below that |
| `FRAME_RATE_LIMIT` | `120` | Frames of any type per connection per window, malformed ones included; beyond it the connection is closed. At least `MSG_RATE_LIMIT` |
| `PROTOCOL_ERROR_LIMIT` | `10` | A connection is closed once it has sent this many malformed or unknown frames |
| `ECDH_BURST_LIMIT` | `8` | Key-exchange frames per connection per `ECDH_BURST_WINDOW_SECS`; beyond it the connection is closed |
| `ECDH_BURST_WINDOW_SECS` | `60` | Window for the key-exchange limit |
| `COMMIT_RATE_LIMIT` | `24` | MLS Commits per connection per `COMMIT_RATE_WINDOW_SECS`. 24 lets a creator fill a 20-member room in one burst |
| `COMMIT_RATE_WINDOW_SECS` | `60` | Window for the Commit limit |
| `PROPOSAL_RATE_LIMIT` | `8` | Standalone MLS Update proposals per connection per `PROPOSAL_RATE_WINDOW_SECS` |
| `PROPOSAL_RATE_WINDOW_SECS` | `60` | Window for the proposal limit |
| `POW_MIN_DIFFICULTY` | `12` | Minimum proof-of-work difficulty, in bits |
| `POW_MAX_DIFFICULTY` | `18` | Maximum proof-of-work difficulty, in bits |
| `CHALLENGE_TTL_SECS` | `300` | Proof-of-work challenge TTL |
| `JWT_TOKEN_TTL_SECS` | `30` | WebSocket JWT TTL, 1 to 300 |
| `JWT_ISSUER` | `pinchat` | Issuer the WebSocket JWT must carry. Set it explicitly when several instances share one signing key |
| `MAX_WS_CONNECTION_AGE_SECS` | `1800` | Lifetime of a WebSocket connection. The client then reconnects through proof of work and a new token, and resumes its place with the resume credential: the encrypted session is kept, no new handshake |
| `WS_RECONNECT_GRACE_SECS` | `20` | How long a disconnected participant's place is held for its resume credential, 1 to 120 |
| `ROOM_CLEANUP_INTERVAL_SECS` | `60` | Room cleanup interval |
| `CHALLENGE_CLEANUP_INTERVAL_SECS` | `60` | Proof-of-work cache cleanup interval |
| `PINCHAT_PASSWORD_HASHES` | empty | Semicolon-separated Argon2id hashes. Empty disables password auth, and the server then needs `ALLOW_ANONYMOUS=true` to start |
| `ALLOW_ANONYMOUS` | `false` | Open access with no password. Required when `PINCHAT_PASSWORD_HASHES` is empty, outside `development` |
| `SESSION_TTL_SECS` | `86400` | Session lifetime |
| `LOGIN_BURST_SIZE` | `5` | Login attempts per window, per client address |
| `LOGIN_PERIOD_SECS` | `720` | Window over which the login budget refills evenly. Windows that would keep a hashed client address for more than 15 minutes are shortened at startup; see `.env.example` |
| `TRUSTED_PROXIES` | empty | Comma-separated proxy IPs or CIDRs trusted for `X-Forwarded-For`. Set this behind a reverse proxy, or every client shares one rate-limit bucket |
| `REPLAY_CACHE_MAX_PER_ROOM` | `1000` | Anti-replay entries per room, at most 10000. Advisory only; the authoritative check is the client-side Double Ratchet counter |
| `MAX_IMAGE_SIZE` | `300KB` | Maximum image size, bytes or with a `KB` or `MB` suffix, 1KB to 2MB |
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
re-fetches every listed asset to compare its SHA-256. It also refuses
redirects that would carry an invite link's key off the site. A mismatch
raises a full-page warning.

The two browsers do not give the same guarantee. Firefox lets the extension
hold the page HTML as it arrives and compare it with the signed hash before it
is parsed, so a page the server altered is replaced by a block page. Chromium
gives a Manifest V3 extension no way to do that: there the best state is
"partially verified", meaning only signed scripts can run but the page itself
is not attested. Use Firefox when the server must not be trusted with the
page.

This blocks newly injected scripts and detects broader static-file tampering.
It does not protect against bugs in already-trusted client code, and without
the extension none of it applies. It is not a substitute for native
application distribution, reproducible builds, independent audits, endpoint
security, or careful operational practice.

See [extensions/README.md](extensions/README.md) for every verifier state,
the per-browser table of attacks, setup, installation, and packaging. The
Firefox build is published on
[addons.mozilla.org](https://addons.mozilla.org/firefox/addon/pinchat-integrity-verifier/).

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
- [static/js/mls/README.md](static/js/mls/README.md), the MLS group
  implementation and its limits
- [docs/reverse-proxy.md](docs/reverse-proxy.md), running the relay behind
  nginx on a small host
- [docs/design-decisions.md](docs/design-decisions.md), design decisions and
  their reasons
- [docs/accountability-log-policy.md](docs/accountability-log-policy.md), log
  policy and accountability record
- [tests/README.md](tests/README.md), the JavaScript test suites
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
support@pinchat.im

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
