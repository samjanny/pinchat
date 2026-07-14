# Signal Protocol Test Suite

This directory contains cryptographic test suites for PinChat's Signal Protocol implementation, verifying the correct behavior of the Double Ratchet algorithm.

## Test Suites

### Chain Ratchet (`test-chain-ratchet.js`)

Tests the symmetric key ratchet (ChainRatchet class) which provides **Perfect Forward Secrecy (PFS)**.

| Test | Description |
|------|-------------|
| Basic Initialization | Chain initializes with 32-byte key, counter=0 |
| Message Key Derivation | Derived keys are unique and counters sequential |
| Deterministic Derivation | Same input always produces same output |
| Chain Ratchet Forward | Chain key changes after ratchet (one-way) |
| Bidirectional Symmetry | Alice.send === Bob.receive symmetry |
| Sliding Window | Pre-derives 16 future keys |
| Out-of-Order Retrieval | Can retrieve keys from window |
| Encrypt/Decrypt | End-to-end encryption with derived keys |
| Chain Reset | All state cleared on reset |
| Invalid Initialization | Rejects invalid key material |

### Double Ratchet (`test-double-ratchet.js`)

Tests the full Double Ratchet algorithm (DH + Symmetric) which provides both **Perfect Forward Secrecy (PFS)** and **Post-Compromise Security (PCS)**.

| Test | Description |
|------|-------------|
| Basic Initialization | Both parties initialize correctly |
| Single Message | Alice sends one message to Bob |
| Multiple Messages | Multiple messages without DH ratchet |
| Ping-Pong Conversation | DH ratchets trigger on direction change |
| Wrong Room ID | AAD mismatch causes decryption failure |
| Message Replay | Replay attacks detected and rejected |
| Long Conversation | 20-message stress test |
| State Destruction | All state cleared on destroy |

### PFS handshake separation (`test-pfs-key-separation.js`)

Drives the production handshake-v2 implementation and Double Ratchet handoff.
It proves the initial secret and captured initial-chain ciphertext are not
recoverable after cleanup for either role, using recorded handshake public
keys. It also covers atomic peer-state commit, signed off-curve points,
downgrade rejection, strict envelope schema, transcript tampering, and cleanup
of all ECDH-manager key references.

### Known-answer tests (`test-kat.js`)

Pins the ratchet KDF schedule, chain progression, authenticated DH-header
encoding, canonical handshake-v2 transcript, and SAS v4. SAS uses fixed valid
P-256 public inputs with expected output `ddecf96d49efde6010c14fca`.

## Running Tests

```bash
# Run all tests
node tests/run-all-tests.js

# Run only chain ratchet tests
node tests/run-all-tests.js chain

# Run only double ratchet tests
node tests/run-all-tests.js double

# Run only the handshake-v2/PFS regression suite
node tests/run-all-tests.js pfs
```

## Test Vectors

The `vectors/` directory contains Signal Protocol test vectors in JSON format for cross-implementation verification.

## Requirements

- Node.js 16+ (for WebCrypto API support via `crypto.webcrypto`)
- No external dependencies (uses built-in `crypto` module)
