# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Dates are the repository-local commit dates; entries are curated for user-visible impact
rather than being a 1:1 mirror of `git log`.

## [2026-05-12] — v0.2.7

Third-pass audit follow-up. Wire protocol unchanged (still v1). No
`static/js/*` files changed, so the extension manifest does not need
regeneration and the in-tree `hashes.json.signed` stays valid — the
extension `GITHUB_TAG` pin remains `v0.2.6` (per the lifecycle rule
documented in the extension code: server-side releases that do not
ship a new extension keep using the previous pinned manifest).

### Security (hygiene)

- **CSRF token compare uses `subtle::ConstantTimeEq` (finding L-01).**
  The hand-rolled XOR-accumulator with an early length-mismatch return
  in `src/auth.rs` worked correctly — the HMAC tag length is fixed at
  64 hex chars for SHA-256 and the attacker-controlled token length is
  not a secret, so the practical impact was nil — but rolling our own
  primitive is a posture we shouldn't maintain. The verifier now uses
  the audited `subtle` crate (already present transitively in the
  dependency tree; promoted to a direct dependency). The Choice-based
  API short-circuits on length mismatch and otherwise runs in time
  independent of slice contents.

### Testing — Known Answer Tests (audit-3 M-03 assurance)

A new `tests/test-kat.js` suite pins the byte-exact output of every
KDF / HMAC step in the ratchet key schedule against an INDEPENDENT
reference implementation (Node's built-in `crypto.hkdfSync` and
`crypto.createHmac`). The reference path goes through completely
different code than the production helpers (WebCrypto via
`crypto.subtle.importKey` + `deriveBits`), so byte-exact equality
across all four KATs is a meaningful cross-implementation check.

- **KAT 1** — HKDF helper byte-exact for three tuples covering the
  root-key bootstrap, initial sending-chain derivation (initiator
  role), and DH-ratchet chain-key advancement under a non-zero salt.
- **KAT 2** — initiator/responder chain labels (`InitiatorToResponder`
  and `ResponderToInitiator`) produce distinct keys for identical IKM
  and salt, AND initiator.sendingChain matches responder.receivingChain
  (the labels-must-line-up symmetry that desynchronises Alice/Bob if
  ever broken).
- **KAT 3** — chain ratchet step `CK_{n+1} = HMAC-SHA256(CK_n,
  "ChainRatchet")` pinned at `CK_1` and `CK_5` from a fixed `CK_0`.
- **KAT 4** — canonical DH-header bytes (`"pinchat-drheader-v1" ||
  u16_be(len(dh)) || dh || u32_be(rc)`) byte-exact against a hand-built
  reference, plus an explicit tag-string assertion so a typo in the
  domain-separation prefix fails loudly.

Scope is deliberately narrow per the audit's own guidance: pin the
deterministic primitives (KDFs, HMACs, canonical encodings) and leave
the ECDH/ECDSA-driven paths to functional round-trip tests in
`test-ratchet-correctness.js`. Tests that require importing a fixed
ECDH/ECDSA private key would defeat the non-extractable property that
v0.2.0 / v0.2.5 deliberately enforced.

### Documentation — claim refinement (audit-3 H-01, H-02)

The third-pass audit pushed back on language like "the server cannot
read your messages" as too absolute given that the actual guarantee
depends on user actions and software outside the chat client itself.
README and SECURITY.md now carry an explicit **claim matrix** that
spells out what is and isn't true under three real configurations:

1. **SAS verified + integrity extension installed.** Client-side
   Double-Ratchet AEAD with SRI-checked JS. No external crypto audit;
   best-effort assurance only.
2. **SAS verified, no integrity extension.** Client-side AEAD plus
   peer identity confirmed out of band, but the server can still
   serve modified JS on the next reload and there is no automatic
   detection.
3. **SAS skipped.** Client-side AEAD is still active — the traffic is
   encrypted — but peer identity is not confirmed, so the server
   operator can mount an active MITM at handshake time and become an
   authenticated peer to each side.

The phrase "server cannot read your messages" is only true in
configurations 1 and 2. The matrix replaces ad-hoc absolute claims and
makes it explicit in user-facing copy that SAS verification is the
gate, not magic.

Deferred to v0.3.0 (already planned): widen SAS to 72 bits / 12 emoji
laid out in 4-column rows, **and** switch the SAS derivation from
PBKDF2-SHA256 100K to HKDF / HMAC. Audit-3 M-02 correctly observed
that PBKDF2 is the wrong tool for SAS — it stretches low-entropy
passwords, but the SAS inputs are uniformly-high-entropy identity
public keys plus room/transcript context. HKDF is the natural
keyed-PRF construction for deriving display bytes from public
material; the 100K iterations were never doing useful work.

## [2026-05-12] — v0.2.6

Second-pass audit follow-up. Three independent fixes that do not touch
the wire format. `hashes.json.signed` must be regenerated and re-signed
before deploy; the extension code that ships in v0.2.6 fetches the
manifest from the **v0.2.6 release tag** (not `main`), so the tag must
be pushed to GitHub *before* users update or install the extension.

### Security

- **IPv6 rate-limit bypass via /64 rotation closed (finding F-13).**
  `hash_ip` (used as identity for the PoW challenge cache and the per-IP
  rate limiters) HMAC'd the full string form of the client address. An
  attacker with a typical residential or VPS /64 allocation could rotate
  through 2^64 host suffixes (SLAAC privacy extensions, manual address
  spawning) and each address would land in a separate cache / rate-limit
  bucket, defeating per-host limits. A new `canonicalize_for_rate_limit`
  helper now zeroes the lower 64 bits of every IPv6 address before
  HMAC; IPv4 is unchanged (the 32-bit space is already host-stable).
  Seven dedicated regression tests cover the canonicalization and the
  HMAC collapse behaviour.

- **Extension manifest URL pinned to release tag (finding F-15).**
  Chrome and Firefox background scripts previously fetched
  `hashes.json.signed` from
  `https://raw.githubusercontent.com/samjanny/pinchat/main/...`. The
  `main` branch is mutable: a GitHub-write compromise (account takeover,
  malicious PR merge, stolen PAT) could overwrite the manifest the
  extensions trust, even without compromising the signing key — though
  the resulting manifest would still need a valid signature to be
  accepted, so the threat is the conjunction of GitHub-write AND
  signing-key compromise. Pinning to `v0.2.6` moves the trust anchor
  onto a tag that cannot be silently rewritten (rebases show up in
  `git log --tags --graph`). Lifecycle is now: every extension release
  bumps `GITHUB_TAG` to its own tag, and server-side releases that do
  not ship a new extension keep using the previous pinned manifest.
  Same constant value and inline comment on both Chrome and Firefox.

### Testing — regression coverage for v0.2.5 fixes (finding F-16)

Three new tests close the gap flagged by the second-pass audit. The
pre-v0.2.5 builds had tests for the *generic patterns* but not for
the specific production code paths the fixes hardened.

- **F-02 regression — `IdentityKeyManager` production path**
  (`tests/test-security.js` test 5). The pre-v0.2.5 generic test (test 3)
  only verified that `subtle.generateKey({ECDSA, P-256}, false, ...)`
  yields a non-extractable private key. Test 5 instantiates the actual
  `IdentityKeyManager`, calls `generateIdentityKeypair()`, asserts that
  `pkcs8` export of the private side rejects, that `raw` export of the
  public side succeeds (65 bytes, uncompressed P-256), and runs a full
  sign+verify roundtrip through `IdentityKeyManager.sign` /
  `IdentityKeyManager.verify`. Catches any future regression that
  reintroduces an extractable intermediate.

- **F-07 regression — JWT algorithm pin + required `exp`** (three
  Rust tests in `src/jwt.rs`):
  - `test_token_rejects_hs384_signature` and
    `test_token_rejects_hs512_signature` forge tokens signed with the
    same MAC secret but a different algorithm in the header, and
    assert `verify_token` rejects them. The HS256-pin enforced by
    `Validation::new(Algorithm::HS256)` is the gate under test.
  - `test_token_rejects_missing_exp` builds a token whose payload
    omits the `exp` claim entirely (using a side struct since
    `WsTokenClaims` always has `exp: u64`), and asserts rejection by
    the `set_required_spec_claims(["exp"])` gate.

- **F-10 regression — encrypt-path rollback on AEAD failure**
  (`tests/test-ratchet-correctness.js`). Warms up a Double Ratchet
  pair, snapshots `Ns` / `ratchetCount` / `sendingChain.messageNumber`
  / `sendingChain.chainKeyMaterial` (byte-copy) / `DHsSignature`,
  monkey-patches `webcrypto.subtle.encrypt` to throw exactly once,
  calls `encryptMessage`, asserts it propagates the throw, then
  byte-compares every snapshotted field against post-failure state.
  Finally restores the real `encrypt` and verifies that the next
  legitimate `encryptMessage` produces the same counter the failed
  one would have produced (chain was not consumed), and that the peer
  decrypts the recovered message.

## [2026-05-12] — v0.2.5

Cryptographic-audit follow-up patch release. Wire protocol unchanged
(still v1). Existing v1 clients remain interoperable with the patched
server, and vice-versa. `hashes.json.signed` must be regenerated and
re-signed out-of-band with the maintainer's signing key before deploy —
`static/js/identity.js`, `static/js/double-ratchet.js` and the
JWT-bearing path in the server binary have changed.

### Security (hygiene)

- **Identity private key no longer transits the JS heap as PKCS#8
  (finding F-02).** `IdentityKeyManager.generateIdentityKeypair` used
  to create the ECDSA P-256 keypair with `extractable: true`, export
  the private side to PKCS#8, re-import it as `extractable: false`,
  and `fill(0)` the buffer. The window between export and re-import
  briefly placed the raw private key bytes in the JS heap as a
  reachable ArrayBuffer; an XSS or hostile extension running during
  identity creation (every 24 h on TTL refresh) could exfiltrate the
  long-term identity key and from there forge ECDSA signatures on DH
  ratchet rotations — bypassing the MITM defense introduced in v0.2.0.
  The new code calls `generateKey(..., false, ['sign', 'verify'])`
  directly: per WebCrypto §13, the public side of an asymmetric ECDSA
  keypair is always extractable regardless of the parameter, so
  peer-exchange and SAS still work; the private side is
  non-extractable from creation and never reachable to JS.

- **JWT verification pins HS256 explicitly (finding F-07).**
  `verify_token` used `Validation::default()`, which in
  `jsonwebtoken 10.x` happens to accept only HS256 — but as
  documentation, not type-system enforcement. A future minor that
  widened the default would silently weaken verification. The path
  is now `Validation::new(Algorithm::HS256)` with
  `set_required_spec_claims(["exp"])` so a token missing the
  expiration claim is rejected outright instead of silently skipping
  the expiry check.

- **Encrypt path gained a `_drSnapshot` rollback for symmetry with
  the decrypt path (finding F-10).** `_encryptMessageImpl` mutates
  `Ns`, the sending chain, and (if a send-side DH ratchet fires)
  `DHs`/`rootKey`/`ratchetCount` across multiple `await` points.
  WebCrypto encrypt failure on valid AES-GCM inputs is practically
  zero, so this is defence-in-depth rather than a bug fix, but the
  asymmetry between encrypt (no snapshot) and decrypt (snapshot +
  `Object.assign` on AEAD failure) was a code-review hazard. Both
  directions now snapshot before mutation and roll back on any
  thrown error.

### Documentation

- **`SECURITY.md` doc-drift reconciled (findings F-05, F-11).**
  - Replay cache default corrected: 10 000 → 1 000 entries
    (`src/config.rs`).
  - Login-stash safety-net TTL corrected: 30 s → 5 min
    (`static/js/login-stash.js`).
  - PBKDF2-100K cost claim recalibrated: the previous "≈10 s on
    consumer hardware" is off by ~100×. Updated to reflect actual
    measurements (~30–100 ms on a modern desktop browser with
    hardware SHA-256; ~25 000 PBKDF2-100K/s on an RTX 4090-class
    GPU). The 48-bit SAS output is the binding constraint, not the
    iteration count; protocol v2 will widen the SAS to 72 bits.
  - SAS stability claim corrected: identity persistence (24 h
    IndexedDB TTL) keeps the PBKDF2 *password* stable across
    reconnects, but the *salt* incorporates per-handshake nonces and
    timestamps, so the emoji code itself still changes on every
    reconnect. `markSASVerified()` keeps the UI from re-prompting
    within a single page lifetime; tab refresh re-prompts. Protocol
    v2 will drop nonces/timestamps from the salt to make SAS truly
    stable for the identity TTL.
  - Bootstrap-key `sessionStorage` direct-path stash documented as
    an **accepted trade-off**: the stash survives for the lifetime
    of the tab because `copyLink()` (v0.2.4) and
    `resetToBootstrapKey()` both depend on it. Mitigation is the
    strict CSP + SRI bound on script execution, plus the
    `extractable: false` import that keeps the live `CryptoKey`
    handle opaque even when an attacker reads the raw fragment from
    `sessionStorage`.
  - Identity-keypair generation pattern updated to describe the
    new single-call path (no PKCS#8 round-trip).

### Outstanding (deferred to v0.3.0 protocol-v2)

- F-01 (widen SAS to 72 bits / 12 emoji, drop per-handshake salt)
- F-03 (bind room_id + sorted identity keys into the DH-header sig)
- F-04 (collapse SAS salt to `(IK_A, IK_B, room_id)` only)
- F-06 (`pn` in AAD)
- F-08 (`v` in AAD)
- F-09 (uniform BE on AAD numeric fields)

All six require a wire-format change; hard cut from v1, no
negotiation. See PROTOCOL.md at the next bump.

## [2026-05-12] — v0.2.4

Single-fix patch release. Wire protocol unchanged; `hashes.json.signed`
re-signed (only `static/js/app.js` and the chat HTML SRI line moved).

### Fixed

- **`Copy link` produced a fragment-less invite URL.** v0.2.3 moved the
  bootstrap secret out of `window.location.hash` into `sessionStorage`
  on first import (C-06), so `window.location.href` no longer carries
  `#key=…` for the rest of the session. The header `Copy link` button
  just read `location.href` and handed peers a URL with no key — they
  loaded the chat page, `extractKeyFromURL` found neither a fragment
  nor a stash for *their* tab, and the handshake never started.
  `copyLink()` now falls back to `sessionStorage['pinchat_hash:'+pathname]`
  when the live hash is empty, reconstructing `origin + pathname +
  search + #key=…` before writing to the clipboard. The URL bar itself
  stays scrubbed — that is intentional anti-leak behaviour from v0.2.3
  and the button is the supported share channel.

## [2026-05-11] — v0.2.3

Security and UX patch release driven by a full audit pass on the 1:1
chat path. Wire protocol unchanged (still v1); existing v1 clients
remain interoperable with the patched server, and vice-versa. The
`hashes.json.signed` manifest needs to be regenerated and re-signed
out-of-band with the maintainer's signing key before deploy — the
shipped JS bytes have changed across this release.

### Security (high)

- **Double Ratchet — concurrent send race fixed.** `encryptMessage()`
  and `decryptMessage()` mutate `Ns`/`Nr`/chain state/`DHs`/`DHr`/
  `rootKey` across multiple `await` points. Two overlapping calls
  (rapid double-tap on Send, paste-then-Enter, send-while-image-upload)
  could observe a half-mutated state: counter already reserved on the
  sending chain but `chainKeyMaterial` not yet ratcheted, so the
  produced message key was `HMAC(CK_0, "MessageKey-1")` instead of
  `HMAC(CK_1, "MessageKey-1")`. The peer could not derive it; AEAD
  failed; the user saw a false MITM warning while the legitimate
  message was rolled back. A promise-mutex now serialises every
  state-mutating call through a single chain shared by both directions
  (the receive-side DH ratchet rotates the sending chain too, so
  per-direction locks would not have been enough). The WebSocket
  inbound dispatch in `websocket.js` also runs through a serial queue
  so application-level handlers in `app.js` observe messages in arrival
  order.
- **Double Ratchet — cross-DH late delivery fixed.** A delayed message
  whose key was already sitting in `this.skippedKeys` (because the
  receiver had ratcheted past it during a peer DH rotation) used to hit
  the `isNewKey` branch first, since `header.dh` no longer matched
  `this.DHrRaw`. That triggered a spurious `performDHRatchetOnReceive`
  on what was actually an old key; AEAD failed and the message was
  silently lost despite its key being on disk. The receive path now
  checks `skippedKeys` *before* the `isNewKey` branch and returns the
  plaintext flagged `_outOfOrder = true` without touching chain state.
- **Double Ratchet DH keypairs imported / generated non-extractable.**
  The handshake ECDH keypair was already created with
  `extractable: false`, but the DH keypairs the Double Ratchet rotates
  on every send-side and receive-side ratchet were `true`. The public
  side of an asymmetric WebCrypto key is always extractable regardless
  of the parameter, so `exportKey('raw', publicKey)` for header
  construction still works; the `true` was only weakening the *private*
  side under XSS / extension compromise. Same change applied to peer
  DH public keys (`this.DHr`) — `skipMessageKeys` now reads raw bytes
  from the existing `this.DHrRaw` cache instead of `exportKey`-ing the
  imported handle.
- **Bootstrap fragment preserved across the `/login` redirect.** The
  `require_auth` middleware used to issue a bare `Redirect::to("/login")`
  when an unauthenticated user clicked `/c/<uuid>#key=<base64>`. After
  the round-trip, the fragment was lost and the user landed on `/` with
  no way back to the room — usability bug *and*, depending on browser,
  the bootstrap secret had transited through `/login`'s URL bar
  visible to anything reading `window.location.hash` on the login page.
  The middleware now redirects to `/login?redirect=<path-and-query>`
  with an open-redirect guard, and a head-loaded `login-stash.js` runs
  before the form renders to move the fragment into `sessionStorage`
  keyed for the chat page and scrub the URL bar.
- **Bootstrap key moved out of the URL bar on the chat page itself.**
  `crypto.js#extractKeyFromURL` now stashes the fragment bytes in
  `sessionStorage` and rewrites the URL via `history.replaceState`
  immediately after the first successful AES-GCM import. Reload still
  works (sessionStorage survives), `resetToBootstrapKey()` still works,
  and the secret is no longer visible in the address bar for the
  entire chat session.
- **JTI conservation in the WebSocket upgrade.** `ws_handler` used to
  call `state.consume_token(jti)` *before* the Origin allowlist check.
  A cross-origin upgrade attempt (hostile script with a stolen session
  cookie, browser navigation race) burned the JTI and locked the
  legitimate client out for the remaining 30 s of TTL. The reorder
  pushes `consume_token` to *last*, after every stateless gate
  (subprotocol, JWT signature, room claim, Origin) has passed. New
  `rejects_bad_origin_preserves_jti` test asserts the property
  directly against `state.consumed_tokens`.

### UX

- **Identity keypair persisted in IndexedDB for SAS continuity.** The
  ECDSA P-256 identity that signs DH headers was previously regenerated
  on every page load, which meant the SAS code a user had verified
  out-of-band stopped matching the next time they reopened the chat.
  Pressure to skip verification followed mechanically. The keypair is
  now stored in `pinchat_identity_v1` / `keys` IndexedDB with a 24-hour
  TTL (aligned with the default `session_ttl_secs`) and a schema
  version field. Private side is non-extractable both on creation and
  after structured-clone round-trip (W3C IndexedDB §6 + WebCrypto §13
  preserve `[[extractable]]`). `IdentityKeyManager.clearStoredIdentity()`
  is the explicit forget gesture for "forget me on this device". A
  `destroy()` call from a session abort no longer wipes the persisted
  identity by default: SAS-mismatch / handshake-abort events point at
  peer substitution, not at compromise of the user's own private key.
  Privacy disclosure updated in `static/privacy.html`.

### Defensive hardening

- **Server-side `REPLAY_CACHE_MAX_PER_ROOM` default 10000 → 1000.**
  The previous default extrapolated to roughly 1.4 GB worst case
  across 1000 rooms on a small VPS, disproportionate given the cache
  is advisory (the authoritative anti-replay is the client-side
  Double Ratchet counter). The new default still buffers about
  17 minutes of traffic at `MSG_RATE_LIMIT = 30 msg/s`. The
  ~"640 KB" comment in the previous version was wrong — the entry
  cost is closer to 136 B (hex SHA-256 String + DateTime + HashSet
  overhead), not 64 B.
- **WebSocket frame rate limiter now counts all non-Close frames.**
  Previously the `frame_rate_limit` counter only fired inside the
  `WsMessage::Text` branch of the receive loop; Binary / Ping / Pong
  floods bypassed the budget even though `tungstenite` still woke the
  recv task for each one. The classifier now matches the frame type up
  front: Close terminates, Text falls through to per-type handling,
  everything else is counted and dropped silently. Lifecycle gates
  (room TTL, max connection age) were also hoisted above the
  type-specific branch so an expired room is severed on the next
  inbound frame regardless of type.

### Hygiene

- **`crypto.js` dead-code purge.** Removed roughly 200 LOC of legacy
  in-class Chain Ratchet path (`sessionKey`, `sendingChain`,
  `receivingChain`, `ratchetActive`, `initializeChainRatchet`,
  `setSessionKey`, `resyncReceivingChain`, `getActiveKey`, `hasKey`)
  and hash-based replay scaffolding (`seenMessageHashes`,
  `hashTimestamps`, `startHashCleanup`, `cleanupOldHashes`,
  `hashPayload`) that has never been written to since the Double
  Ratchet rewrite. A perpetual `setInterval` is also gone.
- **`otherPublicKey` ephemeral imported non-extractable.** The
  stale "Must be extractable for SAS generation" comment in
  `ecdh.js` predated the move of the SAS derivation to identity keys.
- **`arraysEqual` comment de-overpromised.** The helper only ever
  compares public DH key bytes for ratchet-direction detection — no
  secret is being compared and JS engines do not give true wall-clock
  constant-time guarantees. The comment now says so plainly.

### Docs

- `SECURITY.md`: SAS output corrected from 36 bit / 6 emoji to
  48 bit / 8 emoji + hex; new "Identity Key Storage" subsection
  documenting the IndexedDB persistence; Bootstrap Key lifecycle
  updated to reflect the post-import sessionStorage move + URL scrub
  and the login-stash flow.
- `PROTOCOL.md`: AAD-TLV `BigUint64` field endianness specified as
  little-endian (current implementation behaviour, asymmetric with
  the explicit big-endian DH-header signature — a candidate for the
  next protocol bump); Bootstrap Key prose updated to match; stale
  TODO on `skipMessageKeys` replaced by the actual implementation
  behaviour.
- `README.md`: `REPLAY_CACHE_MAX_PER_ROOM` default fixed in the
  configuration table; Bootstrap Key section now describes the
  sessionStorage move and the login-stash flow; SAS section mentions
  the identity-key persistence.

### Tests

- New `tests/test-ratchet-correctness.js` covering the three
  regressions above: 50 concurrent encrypts produce strictly
  sequential counters, 30 concurrent encrypts all decrypt at the
  peer, late delivery across a DH ratchet round decrypts via
  `skippedKeys` with `_outOfOrder = true`, and DH private keys are
  non-extractable across `initialize` / send-side / receive-side
  ratchets.
- New `auth_middleware.rs` tests covering the `?redirect=` carry-through
  for `require_auth`.
- `tests/run-all-tests.js`: registered the new correctness suite.
- Existing legacy `tests/test-double-ratchet.js` and
  `tests/test-chain-ratchet.js` unchanged; they continue to import
  inlined copies of the classes and serve as static spec checks. A
  follow-up will migrate them to `require()` the production sources
  (`crypto.js` / `identity.js` / `double-ratchet.js` now export under
  CommonJS when `module.exports` is present).

### Packaging

- `static/chat.html`: SRI `integrity` attributes refreshed for
  `crypto.js`, `identity.js`, `double-ratchet.js`, `ecdh.js`, and
  `websocket.js`.
- `static/login.html`: new `login-stash.js` loaded synchronously in
  `<head>` with its own SRI integrity attribute.
- `hashes.json.signed` (extension manifest) **must be regenerated
  and re-signed** with the maintainer's offline signing key before
  the production deploy — the shipped JS bytes have changed across
  this release. See `extensions/README.md` and the signing helpers
  under `extensions/` for the procedure.

## [2026-05-07] — v0.2.2

Security patch release. Wire protocol unchanged (still v1); no client-side
changes, no deploy-ordering constraints vs. v0.2.1.

### Security (high)

- **`rustls-webpki` 0.103.8 → 0.103.13.** Pulled in transitively via
  `axum-server` → `tokio-rustls` → `rustls`; closes four advisories that
  reach the TLS-terminating server path:
  - **RUSTSEC-2026-0049** — CRLs were not considered authoritative by their
    Distribution Point because of faulty matching logic.
  - **RUSTSEC-2026-0098** — name constraints for URI names were incorrectly
    accepted, so a constrained CA could issue certificates outside its
    permitted scope.
  - **RUSTSEC-2026-0099** — name constraints were accepted for certificates
    asserting a wildcard name, with the same scope-bypass effect.
  - **RUSTSEC-2026-0104** — reachable panic when parsing a malformed
    Certificate Revocation List (DoS surface on TLS handshake paths that
    consume CRLs).

### CI / tooling

- Added GitHub Actions workflows: Rust CI (fmt + clippy advisory + test),
  cargo-audit (push, PR, weekly cron), SRI consistency gate (recomputes
  asset hashes with CRLF-normalisation matching `extensions/generate-hashes.js`),
  and a Docker build verification.
- One-time `cargo fmt --all` pass across the server crate; recorded in
  `.git-blame-ignore-revs` so `git blame` skips it.

### Known informational warnings (non-blocking)

`cargo audit` still emits two warnings that do not fail the run and are
not exploitable in this codebase:

- **RUSTSEC-2026-0097** — `rand 0.8.5` unsoundness when used with a
  custom logger via `rand::rng()`. We do not register such a logger.
- **RUSTSEC-2025-0134** — `rustls-pemfile 2.2.0` is unmaintained,
  pinned transitively by `axum-server`. Tracked upstream.

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
