# Protocol Specification

This document specifies the PinChat messaging protocol, including message formats, handshake procedures, and cryptographic operations.

**Protocol version: 1** (first explicitly numbered version, introduced in v0.2.0). Pre-release clients that emit headers without a `v` field, or that attempt the WebSocket upgrade with a JWT in the query string, are considered "v0 implicit" and will be rejected.

## Table of Contents

1. [Protocol Overview](#protocol-overview)
2. [Session Establishment](#session-establishment)
3. [Key Exchange Protocol](#key-exchange-protocol)
4. [Double Ratchet Implementation](#double-ratchet-implementation)
5. [Message Formats](#message-formats)
6. [WebSocket Protocol](#websocket-protocol)
7. [Error Handling](#error-handling)

---

## Protocol Overview

### Protocol Stack

```
+--------------------------------------------------+
|              Application Layer                    |
|         (Messages, Images, Commands)              |
+--------------------------------------------------+
|              Double Ratchet Layer                 |
|         (PFS, PCS, Chain Management)              |
+--------------------------------------------------+
|              Cryptographic Layer                  |
|         (AES-GCM, ECDH, ECDSA, HKDF)             |
+--------------------------------------------------+
|              Transport Layer                      |
|         (WebSocket over TLS 1.3)                  |
+--------------------------------------------------+
```

### Protocol Phases

1. **Room Creation**: Server allocates room ID, client generates bootstrap key
2. **Connection**: Client connects via WebSocket with JWT authentication
3. **Key Exchange**: ECDH handshake with identity authentication
4. **Double Ratchet Initialization**: Both parties establish symmetric chains
5. **Messaging**: Encrypted message exchange with automatic ratcheting
6. **Cleanup**: Room expiration and key destruction

---

## Session Establishment

### Room Creation

```
Client                                    Server
   |                                         |
   |-------- POST /api/rooms --------------->|
   |         {type, ttl, max_participants}   |
   |                                         |
   |<------- 201 Created --------------------|
   |         {room_id}                       |
   |                                         |
```

**Request Format**:
```json
{
  "room_type": "one_to_one" | "group",
  "ttl": 60,
  "max_participants": 2
}
```

**Response Format**:
```json
{
  "room_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Bootstrap Key Generation

The Bootstrap Key is a 256-bit AES key that enables the initial encrypted key exchange between participants.

**Generation**:
```javascript
// Client-side generation using WebCrypto CSPRNG
bootstrapKey = crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,  // extractable for URL encoding
    ['encrypt', 'decrypt']
);
```

**URL Distribution**:
```
https://host/c/{room_id}#key={base64url_encoded_key}
```

**Why URL Fragment?**

Per RFC 3986, the URL fragment (everything after `#`) is processed client-side only and never sent to the server in HTTP requests. This ensures:

1. Server cannot intercept the Bootstrap Key
2. Server logs do not contain key material
3. Key distribution is inherently out-of-band

**Post-load lifecycle.** After the first successful import, the client
(`crypto.js#extractKeyFromURL`) moves the fragment bytes into tab-scoped
`sessionStorage` under the key `pinchat_hash:${pathname}` and clears
`window.location.hash` via `history.replaceState`. The key remains
recoverable for reload and reconnect within the tab; it is no longer
visible in the URL bar, browser history, or to any other same-origin
code reading `window.location.hash`. The CryptoKey reference itself is
dropped via `deleteBootstrapKey()` once the Double Ratchet takes over.

If the user is unauthenticated and bounces through `/login`, a small
head-loaded script (`login-stash.js`) detects the fragment, stashes it
in `sessionStorage` keyed for the eventual `/static/chat.html` landing
page, and scrubs the URL bar before the login form renders. This means
the bootstrap secret never lingers on `/login` either.

**Security Note**: The Bootstrap Key must be shared through a secure channel (encrypted messaging, voice call, in-person). If an attacker obtains both the room URL and the Bootstrap Key, they can join the room and participate in the encrypted conversation.

### WebSocket Connection (v1)

JWT is carried in the `Sec-WebSocket-Protocol` header, NOT in the URL query
string. The token therefore never appears in proxy/referrer/middlebox logs.

```
Client                                    Server
   |                                         |
   |-------- GET /api/ws-token/{room} ------>|
   |         Cookie: session=...             |
   |                                         |
   |<------- 200 OK -------------------------|
   |         {token, connection_id,          |
   |          protocol_version: 1,           |
   |          supported_subprotocols:        |
   |            ["pinchat.v1"]}              |
   |                                         |
   |   [Client gates: protocol_version == 1  |
   |    and "pinchat.v1" in supported list,  |
   |    else fatal PROTOCOL_OR_AUTH_FAILURE] |
   |                                         |
   |-------- WS /ws/{room} ----------------->|
   |   Sec-WebSocket-Protocol:               |
   |     pinchat.v1, pinchat.v1.jwt.<jwt>    |
   |                                         |
   |<------- 101 Switching Protocols --------|
   |         Sec-WebSocket-Protocol:         |
   |           pinchat.v1                    |
   |         (token NOT echoed)              |
   |                                         |
```

**Server rejection paths** (pre-upgrade, before `on_upgrade`):
- No `Sec-WebSocket-Protocol` header → **401 Unauthorized**
- No `pinchat.v1` base offered → **426 Upgrade Required**
- No `pinchat.v1.jwt.<token>` companion → **401 Unauthorized**
- Invalid / expired JWT → **401**; wrong room_id → **403**; replayed jti → **403**

### Room Creation Response (v1)

`POST /api/rooms` includes the protocol metadata alongside the creator's
optional `ws_token` so the creator-optimization path can gate identically:

```json
{
  "room_id": "...",
  "room_type": "...",
  "ttl_minutes": 60,
  "max_participants": 2,
  "ws_token": "...",
  "connection_id": "...",
  "protocol_version": 1,
  "supported_subprotocols": ["pinchat.v1"]
}
```

---

## Key Exchange Protocol

### Handshake Message Structure (v2)

The wire message carries only routing/context fields; all key material and the
identity signature are inside the AES-GCM envelope encrypted under the bootstrap
key (from the URL fragment). A passive relay therefore does not receive a stable
identity public key that can act as a cross-room correlator. This property does
not hide transport metadata such as IP addresses, timing, or connection data.

```
ecdh_public_key payload (JSON)
+--------------------------------------------------+
| Field               | Size      | Description    |
+--------------------------------------------------+
| version             | JSON int  | 2 (fail-closed |
|                     |           |  on non-v2)    |
+--------------------------------------------------+
| encryptedEnvelope   | Variable  | AES-GCM(boot,  |
|                     | (base64)  |  envelope,AAD) |
+--------------------------------------------------+
| timestamp           | JSON int  | Unix ms epoch  |
+--------------------------------------------------+
| nonce               | Variable  | Base64url of a |
|                     | (base64)  | 16-byte nonce  |
+--------------------------------------------------+

Envelope plaintext (inside AES-GCM), length-prefixed (u16-be):
  u8(version=2)
  || lp(handshakePublicKey)   65B  - derives S, then DESTROYED
  || lp(ratchetPublicKey)     65B  - becomes Double Ratchet DHs
  || lp(identityPublicKey)    65B  - ECDSA, encrypted (anti-correlation)
  || lp(signature)            64B  - P1363 ECDSA over transcript below

AAD (unchanged): roomId || senderId || timestamp || nonce  (TLV)

Signed transcript (identity key signs this):
  "pinchat-handshake-v2"
    || lp(roomId) || lp(senderId) || lp(timestampAscii) || lp(nonce)
    || lp(handshakePublicKey) || lp(ratchetPublicKey)
```

PFS key separation: the private key that derives the initial shared secret S
(handshakeKeyPair) is NEVER handed to the Double Ratchet and is destroyed after
the handshake. The ratchet retains only ratchetKeyPair, whose private side does
not reconstruct S. This closes the "initial secret recomputable after cleanup"
gap: `extractable:false` prevented key exfiltration but not its use as an ECDH
oracle, so under a later client compromise a retained S-deriving key would still
have let an attacker rebuild the initial chain keys and decrypt captured
initial-chain messages.

Note: this bumps only the E2E handshake envelope to v2. The WebSocket frame
subprotocol (`pinchat.v1`) and `PINCHAT_PROTOCOL_VERSION` are unchanged - the
relay is a blind forwarder of the opaque payload and performs no server-side
crypto.

### Handshake Protocol Flow

The handshake is symmetric: as soon as a 1:1 room reaches two
participants, BOTH clients build and send a single `ecdh_public_key`
frame. There is no init/response pairing on the wire; each side
processes the peer's frame independently.

```
  Alice                     Server (blind relay)                  Bob
    |                              |                               |
    |  1. Generate Identity Keypair (ECDSA, persisted, 24h TTL)    |
    |  2. Generate handshake + ratchet ECDH keypairs               |
    |  3. Sign transcript binding both public keys + context       |
    |  4. Encrypt keys + identity + signature with Bootstrap Key   |
    |     and AAD (room, sender, timestamp, nonce)                  |
    |                              |                               |
    |------ ecdh_public_key ------>|------ ecdh_public_key ------->|
    |<----- ecdh_public_key -------|<----- ecdh_public_key --------|
    |                              |                               |
    |  5. Decrypt envelope and validate AAD/schema                 |
    |  6. Verify signature and import all keys into temporaries    |
    |  7. Atomically commit peer identity, keys, and context       |
    |  8. Derive S = ECDH(own_handshake_priv, peer_handshake_pub)  |
    |  9. Determine role: the lexicographically smaller            |
    |     connection ID becomes Initiator                          |
    | 10. Initialize Double Ratchet with ratchetKeyPair as DHs     |
    |     initialMaterial = HKDF(S, "DoubleRatchet-Init-v1", 96B)  |
```

Steps 1-4 run on both sides (the diagram shows one copy). All parsing,
signature verification, and P-256 point imports complete before step 7; a
malformed or signed off-curve point therefore leaves peer state unchanged.
Role determination requires no extra round trip: both clients compare the
two server-assigned connection IDs as strings, and the smaller one
takes the Initiator chain labels (see Double Ratchet Initialization).

### AAD Structure for Handshake

TLV (Type-Length-Value) encoding prevents parsing ambiguity:

```
AAD = TLV([
    {type: 0x01, value: room_id},      // ROOM_ID
    {type: 0x02, value: sender_id},    // SENDER_ID
    {type: 0x03, value: timestamp},    // TIMESTAMP (8 bytes)
    {type: 0x04, value: nonce}         // NONCE (16 bytes)
])

TLV Format: [type:1 byte][length:2 bytes BE][value:n bytes]
```

### Timestamp Validation

- Maximum age: 60 seconds
- Future tolerance: 30 seconds (clock skew)

---

## Double Ratchet Implementation

### Initialization

```
Input: sharedSecret (32 bytes), isInitiator (boolean)

1. initialMaterial = HKDF(sharedSecret, zeros(32),
                          "DoubleRatchet-Init-v1", 96)
   rootKey = initialMaterial[0..32]

2. If isInitiator:
     sendingChainKey   = initialMaterial[32..64]
     receivingChainKey = initialMaterial[64..96]
   Else:
     sendingChainKey   = initialMaterial[64..96]
     receivingChainKey = initialMaterial[32..64]

3. Initialize sending chain with sendingChainKey
4. Initialize receiving chain with receivingChainKey
5. Clear the caller's sharedSecret buffer after SAS generation
```

### DH Ratchet (Receive-Side)

Triggered when receiving a message with a new DH public key:

```
1. Save previous chain state:
   PN = Ns (previous chain length)
   Ns = 0
   Nr = 0

2. Update peer public key:
   DHr = new_public_key

3. Derive receiving chain:
   DH_out = ECDH(DHs.private, DHr)
   rootKey' = HKDF(rootKey, DH_out, "DoubleRatchet-RootKey", 32)
   receivingChainKey = HKDF(rootKey', zeros(32), "ChainKey", 32)

4. Generate new keypair:
   DHs = new ECDH keypair

5. Derive sending chain:
   DH_out = ECDH(DHs.private, DHr)
   rootKey'' = HKDF(rootKey', DH_out, "DoubleRatchet-RootKey", 32)
   sendingChainKey = HKDF(rootKey'', zeros(32), "ChainKey", 32)

6. Update root key:
   rootKey = rootKey''
   ratchetCount++
```

### DH Ratchet (Send-Side)

Triggered before sending when `hasRatchetedSinceReceive == false`:

```
1. Save previous chain state:
   PN = Ns
   Ns = 0

2. Generate new keypair:
   DHs = new ECDH keypair

3. Derive new sending chain:
   DH_out = ECDH(DHs.private, DHr)
   rootKey' = HKDF(rootKey, DH_out, "DoubleRatchet-RootKey", 32)
   sendingChainKey = HKDF(rootKey', zeros(32), "ChainKey", 32)

4. Update root key:
   rootKey = rootKey'
   ratchetCount++
   hasRatchetedSinceReceive = true
```

### Symmetric Ratchet (Chain Ratchet)

```
// Derive message key
messageKey = HMAC-SHA256(chainKey, "MessageKey-" || counter)

// Advance chain
chainKey' = HMAC-SHA256(chainKey, "ChainRatchet")

// Delete old chain key
chainKey = chainKey'
```

### Skipped-Key Store (Out-of-Order Tolerance)

Out-of-order delivery is handled entirely by the Double Ratchet's
skipped-key store; the ChainRatchet itself derives keys strictly from
its current position. (Earlier revisions documented a 16-entry sliding
window of pre-derived keys inside the ChainRatchet; that mechanism was
vestigial and has been removed.)

- `skipMessageKeys(until)` is invoked when `messageNumber > Nr` (forward
  jump within the current chain) and on receive-side DH ratchet when
  `prevChainLength > Nr` (carry across chain rotation). Skipped keys
  are indexed by `${dh_public_key_base64}:${n}` and bounded globally by
  `MAX_SKIPPED_KEYS_TOTAL = 1000` with FIFO eviction. The receive path
  short-circuits on a `skippedKeys` hit before any ratchet branch fires,
  so a late message from a previous DH chain decrypts via its stored
  key without triggering a spurious DH ratchet.
- Per-chain forward jumps are capped at `MAX_SKIP = 100` (DoS bound).
- Skipped keys are single-use (deleted after successful AEAD), and keys
  from chains more than one ratchet round old are pruned on every DH
  ratchet (PFS).

---

## Message Formats

### Encrypted Message Structure

```
Message Envelope (JSON)
{
  "type": "message",
  "payload": "<base64url>",
  "header": {
    "v": 1,                  // Protocol version (required)
    "dh": "<base64url>",     // Current DH public key
    "pn": 0,                 // Previous chain length
    "n": 5,                  // Message number
    "rc": 2,                 // Ratchet count
    "sig": "<base64url>"     // ECDSA signature (see below)
  }
}
```

**`header` is mandatory** for `message` and `image` types in v1. Server rejects any envelope with missing, malformed, or `v != 1` header.

### DH Header Signature (v2)

To defeat live MITM on the Double Ratchet rotations, every outgoing header carries an ECDSA P-256 signature (`sig`) over the canonical byte sequence:

```
canonical = "pinchat-drheader-v2"
         || len(dh_raw):u16_be || dh_raw
         || pn:u32_be || n:u32_be || rc:u32_be
```

The domain tag is the hardcoded literal `pinchat-drheader-v2`. It is NOT derived from `header.v`, which stays `1`: the wire-protocol version and the signature domain tag are independent identifiers. `v` gates the envelope shape; the tag provides domain separation for the signature input.

Every semantic counter carried in the header is inside the signed tuple, so an active relay cannot flip `pn`, `n`, or `rc` in transit without invalidating the signature. Binding to `rc` means a signature is valid only for its ratchet round; binding to `n` means it is valid only for the single message that carries it, so a signature cannot be lifted onto a different message of the same chain.

Because `n` changes on every message, the signature is recomputed per send rather than cached per DH keypair: `encryptMessage` calls `signCurrentDHs(PN, messageNumber)` immediately after reserving the message number and before emitting the header. The calls in `initialize`, `performDHRatchetOnReceive` and `performSendSideDHRatchet` only prime `DHsSignature` so the field is never null between a keypair rotation and the next send.

On receive: verify before touching chain state. On failure, throw `SIGNATURE_INVALID`, tear down identity, close WebSocket with 1008 Policy Violation, suppress auto-reconnect (user must refresh).

**Not covered by the canonical:** `room_id` and the sorted identity public key pair. The signature proves "the identity-key holder produced this DH public key at this ratchet round and message number", not "within this session". See F-03 in the Backlog for the residual gap and why the v2 tag alone did not close it.

### Payload Structure

```
Payload = IV || Ciphertext || AuthTag

IV:        12 bytes (96 bits)
Ciphertext: Variable length
AuthTag:   16 bytes (128 bits)
```

### Plaintext Envelope (Pre-Encryption)

```json
{
  "ts": 1700000000000,
  "text": "Hello, world!"
}
```

### AAD for Message Encryption

```
AAD = TLV([
    {type: 0x01, value: room_id},           // ROOM_ID
    {type: 0x02, value: sender_id},         // SENDER_ID
    {type: 0x05, value: message_number},    // MESSAGE_NUMBER (8 bytes)
    {type: 0x06, value: msg_type},          // MESSAGE_TYPE ("message" | "image")
    {type: 0x07, value: ratchet_count},     // RATCHET_COUNT (8 bytes)
    {type: 0x08, value: prev_chain_length}  // PREVIOUS_CHAIN_LENGTH (8 bytes)
])
```

Field order is part of the wire format: the TLV sequence is emitted in exactly the order above, with `PREVIOUS_CHAIN_LENGTH` (0x08) appended last. Image messages use the identical field set with `MESSAGE_TYPE = "image"`; there is no separate image AAD.

`pn` entered the AAD with the F-06 fix (see Backlog). Before that an active relay could flip `pn` in transit, the AEAD tag would still verify, and the receiver would burn up to `MAX_SKIP = 100` skipped-key derivations before rejecting.

### Image Message Structure

```json
{
  "type": "image",
  "payload": "<base64url>",
  "header": {
    "v": 1,
    "dh": "<base64url>",
    "pn": 0,
    "n": 6,
    "rc": 2,
    "sig": "<base64url>"
  }
}
```

The header carries the same mandatory `v` and `sig` fields as text
messages; the server rejects an image envelope without them.

### Image Plaintext Envelope

```json
{
  "type": "image",
  "mimeType": "image/jpeg",
  "data": "<base64>",
  "ts": 1700000000000
}
```

---

## WebSocket Protocol

### Message Types

| Type | Direction | Description |
|------|-----------|-------------|
| `ecdh_public_key` | C -> S -> C | Opaque handshake-v2 envelope with separate handshake/ratchet keys (both sides send one) |
| `message` | Bidirectional | Encrypted text message |
| `image` | Bidirectional | Encrypted image |
| `join` | S -> C | Participant joined |
| `leave` | S -> C | Participant left |
| `error` | S -> C | Error notification |
| `room_expired` | S -> C | Room TTL exceeded |

### Server Relay Behavior

The server operates as a blind relay:

1. Receives encrypted message from sender
2. Validates message structure (not content)
3. Broadcasts to all other room participants
4. Does not store, decrypt, or modify payload

### Connection Management

```
// JWT Token Validation
Token contains:
- room_id: Target room
- user_id: Assigned user ID
- exp: Expiration timestamp

// Connection Lifecycle
1. WebSocket upgrade with token
2. Validate token signature and expiration
3. Check room exists and has capacity
4. Assign connection to room
5. Notify other participants (join)
6. Relay messages until disconnect/expiry
7. Notify other participants (leave)
```

---

## Error Handling

### Error Codes

| Code | Description | Action |
|------|-------------|--------|
| `ROOM_NOT_FOUND` | Room does not exist | Redirect to home |
| `ROOM_FULL` | Maximum participants reached | Display error |
| `ROOM_EXPIRED` | TTL exceeded | Close connection |
| `AUTH_FAILED` | Invalid/expired token | Re-authenticate |
| `DECRYPT_FAILED` | Decryption error | Check keys |
| `SIGNATURE_INVALID` | MITM detected | Abort session |
| `RATE_LIMITED` | Too many requests | Wait and retry |

### Recovery Procedures

**Desync Recovery**:
```
If receivedCounter > expectedCounter + MAX_SKIP:
    Throw error (possible DoS)

If receivedCounter > expectedCounter:
    Fast-forward chain to receivedCounter
    Log warning (messages dropped)
```

**Reconnection**:
```
1. Obtain new WebSocket token
2. Reconnect to room
3. Re-perform ECDH handshake
4. Initialize new Double Ratchet
5. Continue messaging
```

---

## SAS Verification Protocol

### SAS Generation (v4, current)

```
1. IKM        = sorted(IK_A_raw || IK_B_raw)
                (identity public keys, lexicographically sorted)
2. BLOCK_x    = handshakePub_x || ratchetPub_x
                (both live ECDH ephemeral keys of side x)
3. transcript = SHA-256( sorted(BLOCK_A, BLOCK_B) )
4. salt       = roomId || "pinchat-sas-v4"
5. info       = "SAS-display-v4" || transcript
6. sas        = HKDF-SHA256(IKM, salt, info, 96 bits)
7. Encode as 16 emoji (64-emoji alphabet, 6 bits each)
   Also display as 24 hex characters (12 dash-separated byte pairs)
```

v4 (handshake v2 key separation) folds BOTH ephemeral public keys per side into
the transcript, so the out-of-band code authenticates the full v2 handshake -
substituting or corrupting either the handshake key or the ratchet key changes
the SAS. v4 is wire-incompatible with v3; both endpoints must run it (a mismatch
surfaces as a non-matching SAS, the correct fail-closed behaviour).

The transcript binding makes the SAS authenticate the live session (the
ephemeral keys that derive the root key), not merely the identity pair,
and prevents offline precomputation by a malicious relay (audit H1; see
SECURITY.md for the full rationale). Because the ephemerals are fresh
per handshake, the displayed code changes on every reconnect: the
"verify once" UX is carried by identity-key persistence plus
peer-identity-change detection in the client, not by SAS stability.

Historical: v1 (pre-v0.3.0) used PBKDF2 with per-handshake nonces and
timestamps in the salt, 48-bit output, 8 emoji. v2 (v0.3.x) switched to
HKDF over the identity keys and roomId only, 72-bit output, 12 emoji.
Both are wire-incompatible with v3 at the display level; a version
mismatch surfaces as non-matching codes (fail closed).

### Verification Flow

```
Alice                                    Bob
  |                                        |
  | [Display SAS: emoji1-emoji2-...]       |
  |                                        |
  |<======= Out-of-band channel ==========>|
  |         (voice call, Signal)           |
  |                                        |
  | [User confirms SAS matches]            |
  |                                        |
  | [Mark identity as verified]            |
  |                                        |
```

---

## Appendix: Constants

### Cryptographic Parameters

| Parameter | Value |
|-----------|-------|
| AES Key Size | 256 bits |
| AES-GCM IV Size | 96 bits |
| AES-GCM Tag Size | 128 bits |
| ECDH Curve | P-256 |
| ECDSA Curve | P-256 |
| ECDSA Hash | SHA-256 |
| HKDF Hash | SHA-256 |
| HMAC Hash | SHA-256 |
| Chain Key Size | 256 bits |
| Message Key Size | 256 bits |
| SAS Output | 96 bits (16 emoji / 24 hex chars) |

### Protocol Limits

| Parameter | Value |
|-----------|-------|
| Max Skip (DoS protection) | 100 messages |
| Max Skipped Keys (global, FIFO eviction) | 1000 |
| Max Message Age | 5 minutes |
| Future Tolerance (clock skew) | 30 seconds |
| Handshake Timeout | 30 seconds |
| Max Room TTL | 1440 minutes |
| Max Participants (group) | 20 |
| Max Image Size | 300 KB |

### AAD Field Types

| Type | Value | Size |
|------|-------|------|
| ROOM_ID | 0x01 | Variable (UTF-8) |
| SENDER_ID | 0x02 | Variable (UTF-8) |
| TIMESTAMP | 0x03 | 8 bytes (BigUint64, **little-endian**) |
| NONCE | 0x04 | 16 bytes |
| MESSAGE_NUMBER | 0x05 | 8 bytes (BigUint64, **little-endian**) |
| MESSAGE_TYPE | 0x06 | Variable (UTF-8) |
| RATCHET_COUNT | 0x07 | 8 bytes (BigUint64, **little-endian**) |
| PREVIOUS_CHAIN_LENGTH | 0x08 | 8 bytes (BigUint64, **little-endian**) |

**Endianness note.** The current reference implementation produces the
BigUint64 fields by writing them through `BigUint64Array(...).buffer`,
which yields the native byte order. On every browser platform PinChat
runs on today this is little-endian; the wire format is therefore
little-endian for those four fields. The DH-header signature canonical
(`pinchat-drheader-v2 || len:u16_be || dh || pn:u32_be || n:u32_be ||
rc:u32_be`) uses an explicit big-endian convention for its `len`, `pn`,
`n` and `rc` fields; that is a separate canonicalisation and the
asymmetry is intentional. Note that the same three counters are encoded
twice with different widths: 8-byte BigUint64 in the AAD, 4-byte u32 in
the signature canonical. A future non-JavaScript client MUST emit AAD
numeric fields in little-endian to remain interoperable. Unifying width
and endianness across both structures is F-09 in the Backlog.

---

## Removed in v1

The following legacy mechanisms from the v0 implicit protocol have been removed:

- **`dh_ratchet` message type**: the Double Ratchet rotation no longer
  requires a dedicated message. DH key rotation piggybacks on every message
  via the signed `{dh, sig}` fields in the header. The server has been
  cleaned of the relay branch that used to forward these messages.
- **JWT in `?token=` query string**: replaced by `Sec-WebSocket-Protocol`
  subprotocol auth. The query-string path is gone.
- **Optional `header` on `message`/`image`**: mandatory in v1. Serde rejects
  any envelope that omits it.

---

## Backlog: wire-format items deferred to a future protocol bump

The third-pass audit's `v0.3.0` proposal was originally a wire-format hard
cut bundling six items. Five turned out to be defense-in-depth without a
concrete current exploit; in v0.3.0 we shipped only the SAS overhaul,
which is a client-coordinated change and does NOT touch the wire.

Of the four items that were still open at that point, two have since
shipped as part of the DH-header signature v2 work. They are kept here
with their status so the history stays legible and so nobody re-files
them.

### Shipped

- **F-06 (SHIPPED)** - `pn` (previous-chain length) is now in the message
  AAD as `PREVIOUS_CHAIN_LENGTH = 0x08`, appended last in the TLV
  sequence. An active relay can no longer flip `pn` in transit: the AEAD
  tag fails. `pn` is additionally inside the DH-header signature
  canonical, so the field is now covered twice and independently.

- **F-03 (PARTIALLY SHIPPED)** - the canonical tag was bumped to
  `"pinchat-drheader-v2"` and the canonical itself widened from
  `dh_raw || rc` to `dh_raw || pn || n || rc`, which closes the
  header-counter tampering surface. What F-03 originally asked for was
  NOT implemented: the canonical still does not bind `room_id`, and it
  still does not bind the sorted identity public key pair. The signature
  proves "the identity-key holder produced this DH public key at this
  ratchet round and message number", not "within this session". Not
  directly exploitable today (DH keys are uniform over 2^256, so the
  binding gap is fragile-not-broken), but a future feature that allowed
  parallel sessions sharing an identity could turn it into a
  cross-session graft. Note the cost of closing it went up: the `v2`
  tag is already spent on the narrower canonical, so a full F-03 needs
  a third domain tag.

### Still open

Both remaining items require a wire-format change, so they ship together
at the next bump (group chat, MLS migration, a non-JS client, or a
concrete attack against one of them). Neither is rated higher than LOW
by any audit pass.

- **F-08** - Add `v` (protocol version) to the message AAD.
  Pure defensive: today the outer envelope rejects `header.v != 1`,
  so the version check is fail-closed at the envelope layer. Adding
  it to AAD prevents a future v2-with-same-AAD-shape from
  cross-decrypting v1 ciphertext.
  AAD field type: `PROTOCOL_VERSION = 0x00`.

- **F-09** - Unify width and endianness throughout. Today the message
  AAD encodes numeric fields as 8-byte BigUint64 via JavaScript's
  `BigUint64Array(...).buffer`, which yields native byte order
  (little-endian on every browser PinChat runs on). The DH-header
  signature canonical encodes the same counters as 4-byte big-endian
  u32. The asymmetry is intentional and documented in the appendix; the
  costs are a usability footgun for any future non-JavaScript client,
  and a width mismatch in which a header counter at or beyond 2^32
  wraps in the signature input while the AAD carries it in full. The
  fix is a one-line change in the AAD encoder plus the corresponding
  PROTOCOL.md table.
