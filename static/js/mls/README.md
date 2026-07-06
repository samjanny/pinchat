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
| [`group.js`](group.js)                   |   ✅   | [`test-mls-group.js`](../../../tests/test-mls-group.js) + [`test-mls-group-add.js`](../../../tests/test-mls-group-add.js) + [`test-mls-group-add-3leaf.js`](../../../tests/test-mls-group-add-3leaf.js) + [`test-mls-group-remove.js`](../../../tests/test-mls-group-remove.js) (N-leaf Add/Remove + PSK binding) |

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
- **Remove** commits invoked by the creator on `userleft` blank the
  departing member's leaf and its full direct path, then re-key the
  committer's path. The removed member's stale state cannot decrypt
  any subsequent epoch traffic. `processCommit` surfaces a distinct
  `removed from group` error if our own leaf was blanked.
- **Bootstrap-key binding via PSK.** The URL fragment is HKDF-derived
  into a 32-byte PSK that's injected into every epoch transition
  (`KeySchedule.deriveEpoch.pskSecret` and `Welcome.deriveWelcomeSecret`).
  A joiner without the URL key fails the Welcome AEAD tag and never
  reaches GroupInfo, so the relay cannot bootstrap an attacker-only
  group inside a victim's room.
- The orchestrator (`mls-session.js`) tags every application payload with
  one byte (`0x01` text / `0x02` image), so images travel the same MLS
  path as text without falling back to the 1:1 Double Ratchet. KeyPackages
  are bound to the relay's `sender_id` (one leaf per WebSocket sender).
- **Forward secrecy within the epoch.** Application AEAD keys come from
  stateful per-sender chains (`Group._chainKeyNonce`): only the current
  chain position's secret is kept (overwritten as the chain advances),
  consumed keys are deleted, and keys for skipped generations live in a
  bounded single-use cache (256 per chain, FIFO-evicted and zeroed on
  eviction). Replays are rejected because the key for a consumed
  generation no longer exists; the per-epoch `(leaf, generation)` set is
  retained as defense-in-depth. Out-of-order tolerance: up to 256
  generations of forward jump per message. This also makes decryption
  O(1) per message instead of O(generation).
- **E2E sender attribution.** `decryptApplicationMessage` returns the
  signature-verified sender leaf index alongside the plaintext;
  `mls-session.js` pins the first observed `leaf -> sender_id`
  association (the creator seeds it from the KeyPackage envelope) and,
  if the relay later re-stamps a different `sender_id` on that leaf's
  traffic, keeps the pinned identity and raises a UI warning instead of
  trusting the relay's field.
- The Rust server stays a blind relay: it forwards a single `mls`
  envelope kind with `wire_format` and an optional `ratchet_tree`
  side-channel, never inspecting the body.

Verified by `tests/test-mls-group-add-3leaf.js` (N-leaf Add) and
`tests/test-mls-group-remove.js` (Remove + post-remove Add). Together
these exercise PSK rejection, replay rejection, group_id mismatch,
KeyPackage tamper rejection, removal-blanks-leaf, and removed-member
loss-of-access.

## Known gaps (post-MVP)

- **Creator is a single point of failure.** Only the creator commits
  (Add/Remove), its group state lives in memory only, and its role is
  derived from the creator-token optimization, which does not survive
  a page reload. If the creator leaves or reloads, remaining members
  can keep chatting in the current epoch but nobody can join or be
  removed any more; the group must be re-created from a fresh room.
- **Epoch-boundary message loss.** `decryptApplicationMessage`
  requires an exact epoch match, so an application message encrypted
  under epoch n but delivered after the receiver advanced to n+1
  fails with a decrypt error and is lost. The relay's total broadcast
  order keeps the window small (it opens between a Commit landing on
  the relay and a sender processing it), but every Add/Remove can
  drop in-flight messages. Keeping the previous epoch's chains alive
  briefly would close this.
- **No out-of-band verification ceremony.** Group identities are
  fresh per-session signature keys whose credential is the key
  itself; there is no SAS equivalent and no identity continuity
  across reconnects. Peer authentication rests entirely on the URL
  fragment PSK (the link is the capability) plus the TOFU
  `leaf -> sender_id` pinning described above.
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
- **Update proposals.** `Add` and `Remove` are wired through end-to-end
  with tree blanking and re-keying on the committer's path. Periodic
  `Update` commits (member-initiated key rotation without membership
  change) are not yet implemented; PCS therefore advances on every
  Add/Remove rather than on a separate cadence.
- **Joiner-side transcript-hash re-derivation (RFC §5.3).** A new
  joiner cannot independently re-derive
  `confirmed_transcript_hash[n]` because they don't have
  `interim_transcript_hash[n-1]` — that depends on the prior epoch's
  state, which they never observed. The joiner therefore TRUSTS the
  CTH carried in the GroupInfo, gated only by the M-1 binding
  (`GroupInfo.signer === Commit.sender`). A creator that equivocates
  by sending different CTH values to members vs. joiners will be
  detected at the next Commit's transcript-hash chaining, but not at
  Welcome time. This is a fundamental limitation of MLS Welcome.
- **Constant-time HMAC compare.** `verifyMembershipTag` and the
  `confirmation_tag` check use byte-XOR/OR loops that are
  intent-constant-time but JS engines and JIT make zero guarantees.
  WebCrypto offers no `timingSafeEqual` in browsers; this is
  unfixable without a native primitive. Practical exploitation
  requires sub-microsecond timing over a noisy network.
- **Replay state across page reload.** `consumedByLeaf` lives in
  memory only. On reload, the user re-establishes the MLS session
  with a fresh KeyPackage → fresh Welcome → fresh epoch state, so
  the previous epoch's `(leaf, generation)` tuples become irrelevant
  (the encryption_secret has changed). Replay across reload is moot
  in our architecture because we don't survive reloads, we re-join.
- **Tree pruning.** After `Remove`, the target leaf and its direct
  path are blanked but the tree width (`nLeaves`) is not trimmed. A
  subsequent `Add` will fill the next free slot to the right of the
  blank, growing the tree rather than reusing the blanked index.
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
