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
| [`tree-kem.js`](tree-kem.js)             |   ✅   | [`test-mls-treekem.js`](../../../tests/test-mls-treekem.js) (IETF vectors: 62 update_paths × DeriveSecret/path closure + commit_secret + keypair-pub matches across filtered direct path) |
| [`group-context.js`](group-context.js)   |   ✅   | [`test-mls-key-package.js`](../../../tests/test-mls-key-package.js) (IETF vectors)           |
| [`key-package.js`](key-package.js)       |   ✅   | [`test-mls-key-package.js`](../../../tests/test-mls-key-package.js) (IETF vectors)           |
| [`mls-message.js`](mls-message.js)       |   ✅   | [`test-mls-key-package.js`](../../../tests/test-mls-key-package.js)                          |
| [`group-info.js`](group-info.js)         |   ✅   | [`test-mls-welcome.js`](../../../tests/test-mls-welcome.js) (IETF vectors, signature verify) |
| [`welcome.js`](welcome.js)               |   ✅   | [`test-mls-welcome.js`](../../../tests/test-mls-welcome.js) (IETF vectors, end-to-end decrypt) |
| [`secret-tree.js`](secret-tree.js)       |   ✅   | [`test-mls-secret-tree.js`](../../../tests/test-mls-secret-tree.js) (IETF vectors, 334 asserts) |
| [`framing.js`](framing.js)               |   ✅   | [`test-mls-framing.js`](../../../tests/test-mls-framing.js)                                   |
| [`proposal.js`](proposal.js)             |   ✅   | [`test-mls-proposal.js`](../../../tests/test-mls-proposal.js) (IETF vectors)                  |
| [`commit.js`](commit.js)                 |   ✅   | [`test-mls-proposal.js`](../../../tests/test-mls-proposal.js) (IETF vectors)                  |
| [`public-message.js`](public-message.js) |   ✅   | [`test-mls-public-message.js`](../../../tests/test-mls-public-message.js) (IETF end-to-end)   |
| [`private-message.js`](private-message.js) | ✅   | [`test-mls-private-message.js`](../../../tests/test-mls-private-message.js) (IETF end-to-end) |
| [`group.js`](group.js)                   |   ✅   | [`test-mls-group.js`](../../../tests/test-mls-group.js) + [`test-mls-group-add.js`](../../../tests/test-mls-group-add.js) + [`test-mls-group-add-3leaf.js`](../../../tests/test-mls-group-add-3leaf.js) (N-leaf end-to-end) |

The codec matches RFC 9000 QUIC varint vectors; HKDF-SHA256 matches the
RFC 5869 §A.1 vector; DHKEM is validated by Encap/Decap symmetry plus HPKE
Seal/Open AEAD tamper tests. Tree math, key schedule, RefHash, and the
confirmed/interim transcript-hash chain are all verified byte-for-byte
against the IETF reference vectors in
[`tests/vectors/mls/`](../../../tests/vectors/mls/) for ciphersuite 0x0002.

## End-to-end status

The browser-facing flow runs entirely over MLS for group rooms:

- 1-to-N **Add / Commit / Welcome** with filtered direct-path encryption.
  Creator commits each new member; existing members apply incoming Commits
  via `Group.processCommit`, walking the UpdatePath from the LCA up to root
  and storing parent keypairs for subsequent epochs.
- The orchestrator (`mls-session.js`) tags every application payload with
  one byte (`0x01` text / `0x02` image), so images travel the same MLS
  path as text without falling back to the 1:1 Double Ratchet.
- The Rust server stays a blind relay: it forwards a single `mls`
  envelope kind with `wire_format` and an optional `ratchet_tree`
  side-channel, never inspecting the body.

Verified by `tests/test-mls-group-add-3leaf.js`: a 4-member group is
built one member at a time; every (sender → receiver) pair exchanges
text application messages at every epoch.

## Known gaps (post-MVP)

- **Parent-hash chaining (§7.9).** Commit-source LeafNodes are signed
  with `parent_hash = empty`, and we don't enforce parent_hash on the
  receive side. Both ends are consistent (we sign and verify the same
  field), so signatures still validate — but a malicious member could
  in principle splice subtrees without being caught. In our scenario
  (creator-only commits, ephemeral rooms, blind relay) this is a
  defence-in-depth gap rather than a usable vulnerability, and no IETF
  reference vectors for the parent-hash chain shipped with our local
  vector cache. Fixing it requires implementing
  `original_sibling_tree_hash` plus the top-down chain walk in both
  `commitAddMember` and `processCommit`.
- **Filtered direct path on the wire (§7.6).** `commitAddMember` emits
  the *full* direct path with empty `encrypted_path_secret` lists where
  the copath sibling resolution is empty, instead of dropping those
  entries entirely. Our `processCommit` accepts that shape symmetrically.
  The IETF reference ships filtered paths, so we'd diverge if we ever
  interop with another MLS implementation. For our creator-only-add
  scenario the filter collapses to the full path (every parent on the
  creator's direct path has at least one non-blank receiver subtree),
  so the wire bytes are byte-identical in practice.
- **Update / Remove proposals.** Only `Add` is wired through. PCS
  currently happens at every join (the whole tree re-keys); periodic
  `Update` commits and explicit `Remove` for departing members are not
  implemented.
- **Proposal-by-reference.** All proposals travel inline inside their
  Commit; the proposal store + RefHash dispatch is not wired.
- **`ratchet_tree` GroupInfo extension.** The new joiner currently
  receives the serialised tree as a side-channel field on the Welcome
  envelope; the standardised extension path is unimplemented.
- **`hashes.json.signed`.** Regenerated unsigned (sequence ≥ 31). The
  operator re-signs locally with their ECDSA key.

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
