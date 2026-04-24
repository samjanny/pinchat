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

| Module                                   | Status | Tests                                                                                  |
| ---------------------------------------- | :----: | -------------------------------------------------------------------------------------- |
| [`ciphersuite.js`](ciphersuite.js)       |   ✅   | —                                                                                      |
| [`tree-math.js`](tree-math.js)           |   ✅   | [`test-mls-tree-math.js`](../../../tests/test-mls-tree-math.js)                        |
| [`codec.js`](codec.js)                   |   ✅   | [`test-mls-codec.js`](../../../tests/test-mls-codec.js)                                |
| [`hpke.js`](hpke.js)                     |   ✅   | [`test-mls-hpke.js`](../../../tests/test-mls-hpke.js)                                  |
| [`key-schedule.js`](key-schedule.js)     |   ✅   | [`test-mls-key-schedule.js`](../../../tests/test-mls-key-schedule.js) (IETF vectors)        |
| [`signature.js`](signature.js)           |   ✅   | [`test-mls-crypto-basics.js`](../../../tests/test-mls-crypto-basics.js) (IETF vectors)      |
| [`labeled.js`](labeled.js)               |   ✅   | [`test-mls-crypto-basics.js`](../../../tests/test-mls-crypto-basics.js) (IETF vectors)      |
| [`transcript-hashes.js`](transcript-hashes.js) | ✅ | [`test-mls-transcript-hashes.js`](../../../tests/test-mls-transcript-hashes.js) (IETF vectors) |
| [`nodes.js`](nodes.js)                   |   ✅   | [`test-mls-tree-hash.js`](../../../tests/test-mls-tree-hash.js) (IETF vectors)               |
| [`tree-hash.js`](tree-hash.js)           |   ✅   | [`test-mls-tree-hash.js`](../../../tests/test-mls-tree-hash.js) (IETF vectors)               |
| [`ratchet-tree.js`](ratchet-tree.js)     |   ✅   | [`test-mls-ratchet-tree.js`](../../../tests/test-mls-ratchet-tree.js) (IETF vectors)         |
| [`p256.js`](p256.js)                     |   ✅   | [`test-mls-treekem.js`](../../../tests/test-mls-treekem.js) (WebCrypto round-trip)           |
| [`tree-kem.js`](tree-kem.js)             |   🟡   | [`test-mls-treekem.js`](../../../tests/test-mls-treekem.js) — path-secret chain only         |

The codec matches RFC 9000 QUIC varint vectors; HKDF-SHA256 matches the
RFC 5869 §A.1 vector; DHKEM is validated by Encap/Decap symmetry plus HPKE
Seal/Open AEAD tamper tests. Tree math, key schedule, RefHash, and the
confirmed/interim transcript-hash chain are all verified byte-for-byte
against the IETF reference vectors in
[`tests/vectors/mls/`](../../../tests/vectors/mls/) for ciphersuite 0x0002.

## Roadmap

Ordered so that each step only depends on what precedes it.

1. **Credential + KeyPackage** (`key-package.js`) — RFC 9420 §5, §10.
   A KeyPackage binds an HPKE init key, a signature key (ECDSA P-256), and
   a credential. Signature-chained and serializable via the codec.

2. **Ratchet tree** (`ratchet-tree.js`) — RFC 9420 §7.
   Array-backed tree of LeafNode / ParentNode, with blanking, resolution,
   parent-hash and tree-hash. Verified against the IETF
   `tree-math.json` / `tree-validation.json` vectors.

3. **TreeKEM UpdatePath** (`update-path.js`) — RFC 9420 §7.5–§7.6.
   Path-secret chain + HPKE Seal along the copath resolution; verified
   against `treekem.json`.

4. **Welcome / joining** (`welcome.js`) — RFC 9420 §12.4.
   Group-info encryption to the new member's HPKE init key; verified
   against `welcome.json`.

5. **Proposals + Commit + framing** (`framing.js`, `proposal.js`) —
   RFC 9420 §6, §12. PublicMessage / PrivateMessage framing with the
   confirmation + membership tags.

6. **Application messages / secret tree** (`secret-tree.js`) — RFC 9420 §9.
   Per-leaf AEAD nonce/key derivation for encryption of application data;
   verified against `secret-tree.json`.

7. **Server relay**. The Rust server gains new broadcast envelope types
   (`group_commit`, `group_welcome`, `group_proposal`, `group_app_message`)
   but remains a blind relay: no key material, no decryption, no membership
   tracking beyond the existing room participant set.

8. **UI wiring**. `chat.html` + `app.js` + `mls-session.js` orchestrator.
   Re-enable group rooms in [`src/models/room.rs`](../../../src/models/room.rs)
   once the crypto + relay are both in place.

## Test vectors

IETF-maintained MLS test vectors are cached under
[`tests/vectors/mls/`](../../../tests/vectors/mls/) so the suite runs offline.
Upstream: `mlswg/mls-implementations` on GitHub (directory `test-vectors/`).

## Running the tests

    node tests/run-all-tests.js                      # everything
    node tests/run-all-tests.js mls-tree-math        # single suite
    node tests/run-all-tests.js mls-codec
    node tests/run-all-tests.js mls-hpke
    node tests/run-all-tests.js mls-key-schedule
