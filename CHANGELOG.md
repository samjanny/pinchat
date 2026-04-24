# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Dates are the repository-local commit dates; entries are curated for user-visible impact
rather than being a 1:1 mirror of `git log`.

## [2026-04-24] — v0.2.1

Security patch release. Wire protocol unchanged (still v1); no deploy-ordering
constraints vs. v0.2.0 clients.

### Security (high)

- **Double Ratchet — same-chain out-of-order recovery fixed.** When the receiver
  saw a message whose counter was ahead of `Nr` (e.g. message `n=2` before `n=0`
  and `n=1` on the same DH chain), the previous `decryptMessage` ratcheted the
  receiving chain forward N times *without* storing the skipped message keys, so
  the delayed predecessors could never be decrypted. Worse, if a message with
  `n < Nr` arrived (delayed from the sliding-window path), the post-decrypt
  block rewound `Nr`, desynchronising the chain and causing every subsequent
  in-order message to fail AEAD verification — a network-adjacent **session
  DoS**: any server or path that delivered `2, 0, 1` instead of `0, 1, 2`
  silently killed the session. `decryptMessage` now (a) rejects
  `messageNumber < Nr` when there is no stored skipped key, (b) calls
  `skipMessageKeys(messageNumber)` *before* decrypting forward jumps, and
  (c) advances the chain exactly once past the just-decrypted counter.
- **`skipMessageKeys` now keeps the chain counter in sync.** The helper
  ratcheted `chainKeyMaterial` forward but left `chain.messageNumber` stale, so
  from the second iteration onward it derived message keys with a wrong offset
  against the HMAC position. Combined with the fix above, this was a latent
  bug that would have produced incorrect skipped keys as soon as the code
  path was exercised beyond a single skip.
- **`messageKeyWindow` cleanup (PFS).** The `ChainRatchet` sliding window
  retained pre-derived AES-GCM `CryptoKey` handles for future counters after
  the chain ratcheted, violating forward secrecy: a memory compromise between
  two sends exposed the next 16 message keys. Fixes: `deriveMessageKey` now
  filters against `this.messageNumber` (drops the just-consumed counter);
  `deriveMessageKeyForCounter` is single-use (removes the key from the window
  on read); `ratchet()` clears the window after advancing; `reset()` clears it
  explicitly. `DoubleRatchet.destroy()` now calls `reset()` on both chains
  before dropping references, so `CryptoKey` handles do not linger until GC.

### Tests

- `tests/test-double-ratchet.js` **Test 11b** was previously documented as a
  "known limitation" — messages `0, 1` were expected to fail to decrypt after
  receiving `2` first. With the ratchet correctness fix, the test is renamed
  to *Skipped-Key Recovery* and now asserts that the delayed `0, 1` decrypt
  from stored skipped keys, and a replay of the already-consumed `0` is
  rejected.
- Inline `ChainRatchet` / `DoubleRatchet` classes in both test files mirror
  the production changes.

### Packaging

- `static/chat.html`: SRI `integrity` attributes for `crypto.js` and
  `double-ratchet.js` refreshed to match the patched bodies. The signed
  manifest (`hashes.json.signed`) must be regenerated out-of-band before
  production deploy — it requires the maintainer's signing key and is not
  included in this commit.
- `README.md` Changelog section extracted to this dedicated file; README
  now links to it.

## [2026-04-22] — v0.2.0 (protocol v1)

**First explicitly numbered wire-protocol version.** Pre-release clients and
servers are considered "v0 implicit" and are rejected after this release.
Deploy is atomic (server + static JS + HTML together); see `PROTOCOL.md` for
the full reject-code matrix.

### Security (critical)

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

### Added

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

### Removed

- `dh_ratchet` message type (the server previously relayed these; dead
  code after the Signal-style receive-side ratchet). This removed a
  gratuitous traffic-amplification surface.
- `?token=` query-string authentication for `/ws/:room_id`.
- Optional `header` on `message` / `image` envelopes.

## [2026-04-21]

### Added
- **Proton-style UI refresh** with full light/dark theme toggle. A floating control
  (top-right on every page) persists the choice in `localStorage`; the OS
  `prefers-color-scheme` setting is honored when no explicit preference is stored.
- New design tokens (radius scale, typography scale, softer shadow layers) and an
  `[data-theme="dark"]` block covering every component.

### Fixed
- **E2E encryption key leak via login redirect URL.** When a `/api/ws-token/*` or
  `/api/rooms` request returned 401, the client previously concatenated
  `window.location.hash` into the `?redirect=` query parameter. Because the
  fragment carries the symmetric room key (`#key=…`), this caused the key to be
  sent to the server — and therefore to any reverse-proxy / CDN / browser-history
  / `Referer` sink. The redirect now strips the fragment, stashes it in
  `sessionStorage` (tab-scoped) before navigating, and `extractKeyFromURL()`
  restores it via `history.replaceState` on the first read after login.

### Security
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

## Earlier

- **Extension manifest v1.2.0** with anti-downgrade sequence numbers, ECDSA
  P-256 signatures, and SRI-in-DOM verification (the extension reads the
  integrity attributes actually parsed by the browser, not a separate fetch).
- Comprehensive DoS/DDoS stress-test suite (`stress-tests/`).
- `WEBSITE_DIR` env var for custom frontends with safe fallback to `/static`.
- SAS verification entropy raised from 36 to 48 bits.
- WebSocket heartbeat ping every 30s; non-root container user; fail-closed
  behaviour on room TTL drift.

See `git log` for a complete per-commit history.
