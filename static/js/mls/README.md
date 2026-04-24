# MLS / TreeKEM — custom implementation

Branch: `experimental-groups-custom`

This branch implements **MLS (RFC 9420) + TreeKEM** from scratch, with no
vendored cryptographic libraries. The only cryptographic surface we depend
on is the browser's WebCrypto API (HMAC-SHA256, ECDH P-256, AES-GCM), which
is already used by the 1:1 crypto path.

## Ciphersuite

We commit to a single MLS ciphersuite:

    0x0002 — MLS_128_DHKEMP256_AES128GCM_SHA256_P256

Rationale: every primitive is already in the PinChat TCB, natively exposed
through WebCrypto, and the ciphersuite is a first-class citizen of RFC 9420.
See [`ciphersuite.js`](ciphersuite.js) for the full profile.

## Foundation (landed)

| Module                                   | Status | Tests                                        |
| ---------------------------------------- | :----: | -------------------------------------------- |
| [`ciphersuite.js`](ciphersuite.js)       |   ✅   | —                                            |
| [`tree-math.js`](tree-math.js)           |   ✅   | [`test-mls-tree-math.js`](../../../tests/test-mls-tree-math.js) |
| [`codec.js`](codec.js)                   |   ✅   | [`test-mls-codec.js`](../../../tests/test-mls-codec.js)         |
| [`hpke.js`](hpke.js)                     |   ✅   | [`test-mls-hpke.js`](../../../tests/test-mls-hpke.js)           |

The codec matches RFC 9000 QUIC varint vectors; HKDF-SHA256 matches the
RFC 5869 §A.1 vector; DHKEM is validated by Encap/Decap symmetry plus HPKE
Seal/Open AEAD tamper tests.

## Roadmap

Ordered so that each step only depends on what precedes it.

1. **Key schedule** (`key-schedule.js`) — RFC 9420 §8.
   Epoch secret chain: joiner_secret → welcome_secret → epoch_secret →
   {sender_data, encryption, exporter, external, confirmation, membership,
   resumption, init} secrets via `MLS-v1` labeled expand.

2. **Credential + KeyPackage** (`key-package.js`) — RFC 9420 §5, §10.
   A KeyPackage binds an HPKE init key, a signature key (ECDSA P-256), and
   a credential. Signature-chained and serializable via the codec.

3. **Ratchet tree** (`ratchet-tree.js`) — RFC 9420 §7.
   Array-backed tree of LeafNode / ParentNode, with blanking, resolution,
   parent-hash and tree-hash. Tree-hash tests will use RFC 9420 §I vectors.

4. **TreeKEM UpdatePath** (`update-path.js`) — RFC 9420 §7.5–§7.6.
   Path-secret chain + HPKE Seal along the copath resolution.

5. **Welcome / joining** (`welcome.js`) — RFC 9420 §12.4.
   Group-info encryption to the new member's HPKE init key.

6. **Proposals + Commit + framing** (`framing.js`, `proposal.js`) —
   RFC 9420 §6, §12. PublicMessage / PrivateMessage framing with the
   confirmation + membership tags.

7. **Application messages / secret tree** (`secret-tree.js`) — RFC 9420 §9.
   Per-leaf AEAD nonce/key derivation for encryption of application data.

8. **Server relay**. The Rust server gains new broadcast envelope types
   (`group_commit`, `group_welcome`, `group_proposal`, `group_app_message`)
   but remains a blind relay: no key material, no decryption, no membership
   tracking beyond the existing room participant set.

9. **UI wiring**. `chat.html` + `app.js` + `mls-session.js` orchestrator.
   Re-enable group rooms in [`src/models/room.rs`](../../../src/models/room.rs) once
   the crypto + relay are both in place.

## Running the tests

    node tests/run-all-tests.js                   # everything
    node tests/run-all-tests.js mls-tree-math     # single suite
    node tests/run-all-tests.js mls-codec
    node tests/run-all-tests.js mls-hpke
