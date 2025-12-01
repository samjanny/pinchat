# Protocol Specification

This document specifies the PinChat messaging protocol, including message formats, handshake procedures, and cryptographic operations.

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

**Security Note**: The Bootstrap Key must be shared through a secure channel (encrypted messaging, voice call, in-person). If an attacker obtains both the room URL and the Bootstrap Key, they can join the room and participate in the encrypted conversation.

### WebSocket Connection

```
Client                                    Server
   |                                         |
   |-------- GET /api/ws-token/{room} ------>|
   |         Cookie: session=...             |
   |                                         |
   |<------- 200 OK -------------------------|
   |         {token: "jwt..."}               |
   |                                         |
   |-------- WS /ws/{room}?token=jwt ------->|
   |                                         |
   |<------- WebSocket Upgrade --------------|
   |                                         |
```

---

## Key Exchange Protocol

### Handshake Message Structure

```
Handshake Message
+--------------------------------------------------+
| Field               | Size      | Description    |
+--------------------------------------------------+
| encryptedKey        | Variable  | ECDH pubkey    |
|                     |           | (AES-GCM enc)  |
+--------------------------------------------------+
| identityPublicKey   | 65 bytes  | ECDSA pubkey   |
|                     | (base64)  | (uncompressed) |
+--------------------------------------------------+
| signature           | 64 bytes  | ECDSA sig on   |
|                     | (base64)  | ephemeral key  |
+--------------------------------------------------+
| timestamp           | 8 bytes   | Unix ms epoch  |
+--------------------------------------------------+
| nonce               | 16 bytes  | Random nonce   |
|                     | (base64)  |                |
+--------------------------------------------------+
```

### Handshake Protocol Flow

```
  Alice (Initiator)                              Bob (Responder)
        |                                              |
        |  1. Generate Identity Keypair (ECDSA)        |
        |  2. Generate Ephemeral Keypair (ECDH)        |
        |  3. Sign ephemeral pubkey with identity      |
        |  4. Encrypt with AAD (room, sender, ts)      |
        |                                              |
        |-------- ECDH_INIT (encrypted, signed) ------>|
        |                                              |
        |                   5. Verify signature        |
        |                   6. Decrypt ephemeral key   |
        |                   7. Generate own keypair    |
        |                   8. Sign own ephemeral      |
        |                   9. Derive shared secret    |
        |                                              |
        |<------- ECDH_RESPONSE (encrypted, signed) ---|
        |                                              |
        | 10. Verify signature                         |
        | 11. Decrypt ephemeral key                    |
        | 12. Derive shared secret                     |
        |                                              |
        |  [Both parties now share secret S]           |
        |                                              |
        | 13. Initialize Double Ratchet               |
        |     Root Key = HKDF(S, "DoubleRatchet-RootKey")
        |                                              |
```

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

1. rootKey = HKDF(sharedSecret, zeros(32), "DoubleRatchet-RootKey", 32)

2. If isInitiator:
     sendingLabel = "InitiatorToResponder"
     receivingLabel = "ResponderToInitiator"
   Else:
     sendingLabel = "ResponderToInitiator"
     receivingLabel = "InitiatorToResponder"

3. sendingChainKey = HKDF(rootKey, zeros(32), sendingLabel, 32)
4. receivingChainKey = HKDF(rootKey, zeros(32), receivingLabel, 32)

5. Initialize sending chain with sendingChainKey
6. Initialize receiving chain with receivingChainKey
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

### Sliding Window (Out-of-Order Tolerance)

- Window size: 16 messages
- Pre-derived keys stored for future messages
- Keys outside window are deleted (PFS)

---

## Message Formats

### Encrypted Message Structure

```
Message Envelope (JSON)
{
  "type": "message",
  "payload": "<base64url>",
  "header": {
    "dh": "<base64url>",    // Current DH public key
    "pn": 0,                 // Previous chain length
    "n": 5,                  // Message number
    "rc": 2                  // Ratchet count
  }
}
```

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
    {type: 0x01, value: room_id},        // ROOM_ID
    {type: 0x02, value: sender_id},      // SENDER_ID
    {type: 0x05, value: message_number}, // MESSAGE_NUMBER (8 bytes)
    {type: 0x06, value: "message"},      // MESSAGE_TYPE
    {type: 0x07, value: ratchet_count}   // RATCHET_COUNT (8 bytes)
])
```

### Image Message Structure

```json
{
  "type": "image",
  "payload": "<base64url>",
  "header": {
    "dh": "<base64url>",
    "pn": 0,
    "n": 6,
    "rc": 2
  }
}
```

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
| `ecdh_init` | C -> S | Initial key exchange |
| `ecdh_response` | C -> S | Key exchange response |
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

### SAS Generation

```
1. Export identity public keys (both parties)
2. Sort keys lexicographically
3. Concatenate: password = key1 || key2
4. Create salt:
   - Sort nonces and timestamps
   - salt = roomId || nonce1 || nonce2 || ts1 || ts2
5. Derive SAS:
   sas = PBKDF2(password, salt, 100000, SHA-256, 48 bits)
6. Encode as 6 emoji (64-emoji alphabet, 6 bits each)
```

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
| PBKDF2 Iterations | 100,000 |
| SAS Output | 36 bits |

### Protocol Limits

| Parameter | Value |
|-----------|-------|
| Max Skip (DoS protection) | 100 messages |
| Sliding Window Size | 16 messages |
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
| TIMESTAMP | 0x03 | 8 bytes (BigUint64) |
| NONCE | 0x04 | 16 bytes |
| MESSAGE_NUMBER | 0x05 | 8 bytes (BigUint64) |
| MESSAGE_TYPE | 0x06 | Variable (UTF-8) |
| RATCHET_COUNT | 0x07 | 8 bytes (BigUint64) |
