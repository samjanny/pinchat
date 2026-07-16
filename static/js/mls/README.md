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

PinChat further narrows the ciphersuite's ECDSA signature acceptance to
canonical, completely consumed ASN.1 DER with P-256 scalars in range and a
low-S value. Generated signatures are normalized to low-S; received high-S
signatures are rejected rather than normalized. This removes the equivalent
`(r, s)` / `(r, n-s)` byte-level malleability from MLS authenticated and
transcript structures. Low-S is a PinChat profile restriction, not an MLS
requirement, so high-S signatures from otherwise conforming implementations
are intentionally not interoperable.

## Foundation (landed)

| Module                                   | Status | Tests                                                                                  |
| ---------------------------------------- | :----: | -------------------------------------------------------------------------------------- |
| [`ciphersuite.js`](ciphersuite.js)       |   ✅   | —                                                                                      |
| [`tree-math.js`](tree-math.js)           |   ✅   | [`test-mls-tree-math.js`](../../../tests/test-mls-tree-math.js)                        |
| [`codec.js`](codec.js)                   |   ✅   | [`test-mls-codec.js`](../../../tests/test-mls-codec.js)                                |
| [`hpke.js`](hpke.js)                     |   ✅   | [`test-mls-hpke.js`](../../../tests/test-mls-hpke.js)                                  |
| [`key-schedule.js`](key-schedule.js)     |   ✅   | [`test-mls-key-schedule.js`](../../../tests/test-mls-key-schedule.js) (IETF vectors)        |
| [`signature.js`](signature.js)           |   ✅   | [`test-mls-crypto-basics.js`](../../../tests/test-mls-crypto-basics.js) (IETF vectors) + [`test-mls-signature-canonical.js`](../../../tests/test-mls-signature-canonical.js) (strict DER/low-S + state rollback) |
| [`labeled.js`](labeled.js)               |   ✅   | [`test-mls-crypto-basics.js`](../../../tests/test-mls-crypto-basics.js) (IETF vectors)      |
| [`transcript-hashes.js`](transcript-hashes.js) | ✅ | [`test-mls-transcript-hashes.js`](../../../tests/test-mls-transcript-hashes.js) (IETF vectors) |
| [`nodes.js`](nodes.js)                   |   ✅   | [`test-mls-tree-hash.js`](../../../tests/test-mls-tree-hash.js) (IETF vectors)               |
| [`tree-hash.js`](tree-hash.js)           |   ✅   | [`test-mls-tree-hash.js`](../../../tests/test-mls-tree-hash.js) (IETF vectors)               |
| [`parent-hash.js`](parent-hash.js)       |   ✅   | [`test-mls-parent-hash.js`](../../../tests/test-mls-parent-hash.js) (round-trip + splice rejection) |
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
- **E2E sender attribution and visual identity.**
  `decryptApplicationMessage` returns both the signature-verified sender
  leaf index and the exact LeafNode signature key that authenticated the
  plaintext. `mls-session.js` derives a SHA-256 fingerprint from that key;
  the visible `Creator` / `Member` label contains an 80-bit prefix and its
  tooltip carries the full 256-bit fingerprint. The sidebar is rebuilt only
  from non-blank leaves in the authenticated ratchet tree. Relay
  `sender_id` values remain routing/presence metadata: they cannot create,
  remove, or rename a roster entry or message author. A changed route still
  raises a diagnostic warning without changing the displayed key identity.
- **Previous-epoch grace window.** On every epoch transition the
  outgoing epoch's decrypt-only context (old tree, old secrets, old
  chains) is retained for 60 seconds, so application messages already
  in flight when the Commit landed still decrypt (once; same replay
  and signature checks, enforced under the OLD group context) instead
  of being lost. At most one previous epoch is retained; its key
  material is zeroed at expiry or on the next Commit.
- **Periodic PCS rotation.** Every ~10 minutes (with jitter) the
  creator broadcasts a path-only Commit (empty proposal list plus
  UpdatePath, RFC 9420 compliant) re-keying its own leaf and direct
  path, and folds in any pending member Update proposals. This heals
  leaked epoch-level secrets in membership-stable groups.
- **Parent-hash chaining and imported-tree validation (§§7.3, 7.9).**
  Every Commit computes the top-down parent-hash chain over the
  committer's direct path (`parent-hash.js`), stamps each parent node's
  `parent_hash`, and binds the committer's commit-source LeafNode to it
  before signing. Existing members verify the newly applied path. A
  Welcome joiner performs the stronger whole-tree check required by the
  RFC: every non-blank LeafNode signature is verified with the correct
  source-dependent TBS, every non-blank parent must be reachable through
  exactly one valid parent-hash chain, `unmerged_leaves` metadata is
  checked, and signature/HPKE public keys must be unique. The
  `GroupInfo.signer` binding is fail-closed when no Commit was observed.
  `ParentHashInput.original_sibling_tree_hash` removes unmerged leaves
  from both leaf slots and parent metadata before hashing.
- **Per-member PCS via Update proposals.** Each non-creator member
  periodically sends an `Update` proposal (RFC 9420 §12.1.2): a fresh
  leaf HPKE keypair signed with its existing identity key. The creator
  folds the proposal into its next Commit (installing the new leaf
  and blanking that leaf's direct path) and the proposing member swaps in
  the fresh private key when the Commit lands (`processCommit` reports
  `selfUpdated`). Because the leaf encryption key is separate from the
  signature/identity key, a member whose leaf key was compromised can
  still authenticate the proposal and rotate to a key the attacker does
  not hold, so post-rotation traffic is unrecoverable to the attacker.
  Single-committer is preserved (only the creator commits), so there
  are no concurrent-commit forks.
- The Rust server stays cryptographically blind: it allowlists MLS wire
  formats, enforces canonical bounded Base64url transport fields, restricts
  the `ratchet_tree` side-channel to Welcome, and shallowly reads the signed
  PublicMessage framing only to distinguish Proposal from Commit for rate
  limiting. Signature, membership, tree, and key-schedule validation remains
  entirely client-side.

Verified by `tests/test-mls-group-add-3leaf.js` (N-leaf Add),
`tests/test-mls-group-remove.js` (Remove + post-remove Add),
`tests/test-mls-imported-tree.js` (malicious-committer Welcome trees), and
`tests/test-mls-visual-identity.js` (relay/MLS identity separation).
Together these exercise PSK rejection, replay rejection, group_id
mismatch, KeyPackage and LeafNode tamper rejection, whole-tree
parent-hash validation, key uniqueness, removal-blanks-leaf, and
removed-member loss-of-access. Standalone member Updates are authenticated
and stored by every current member; creator Commits carry their RFC 9420
ProposalRefs, and each recipient re-verifies the exact current-epoch
AuthenticatedContent before applying the referenced leaf update.

## Known gaps (post-MVP)

- **Creator is a single point of failure.** Only the creator commits
  (Add/Remove), its group state lives in memory only, and its role is
  derived from the creator-token optimization, which does not survive
  a page reload. If the creator leaves or reloads, remaining members
  can keep chatting in the current epoch but nobody can join or be
  removed any more; the group must be re-created from a fresh room.
- **No out-of-band verification ceremony.** Group identities are fresh
  per-session signature keys whose credential is the key itself. Their key
  fingerprints prevent the relay from substituting a visual nickname, but
  they do not assert a human name and there is no SAS equivalent or identity
  continuity across a page reload. A live page can reclaim the same relay
  `sender_id` during the short, server-authenticated reconnect grace period,
  while an expired/missing resume credential is rejected fail-closed for
  MLS. Peer admission rests on the URL-fragment PSK (the link is the
  capability), authenticated LeafNodes, and the creator's membership
  decisions; users do not currently compare fingerprints out of band.
- **Filtered direct path on the wire (§7.6).** `commitAddMember` emits
  the *full* direct path with empty `encrypted_path_secret` lists where
  the copath sibling resolution is empty, instead of dropping those
  entries entirely. Our `processCommit` accepts that shape symmetrically.
  The IETF reference ships filtered paths, so we'd diverge if we ever
  interop with another MLS implementation. For our creator-only-add
  scenario the filter collapses to the full path (every parent on the
  creator's direct path has at least one non-blank receiver subtree),
  so the wire bytes are byte-identical in practice.
- **Update proposal identity rotation.** Member Update proposals
  re-key the leaf ENCRYPTION key but must keep the same signature key
  (`verifyUpdateLeafBinding` rejects signature-key rotation). Rotating
  the long-term identity/signature key mid-group is not supported;
  compromise of a member's signature key is an identity compromise
  that MLS PCS does not repair (the attacker can sign as that member
  until removed).
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
- **Tree capacity.** After `Remove`, the target leaf and its direct
  path remain blank at the same indices. A subsequent `Add` reuses the
  leftmost blank leaf before growing the tree. The PinChat group profile
  enforces a maximum of 20 logical leaves in creation, Commit processing,
  and Welcome import.
- **`ratchet_tree` GroupInfo extension.** The new joiner currently
  receives the serialised tree as a side-channel field on the Welcome
  envelope; the standardised extension path is unimplemented. This custom
  side-channel deliberately carries the complete logical node width,
  including trailing blanks, because no separate tree-size field exists.
  It must not be presented as the canonical RFC extension encoding.
- **`hashes.json.signed`.** The operator re-signs locally with their
  ECDSA key whenever a protected static asset changes.

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
