#!/usr/bin/env node

/**
 * MLS TreeKEM path-secret chain test.
 *
 * Covers:
 *   - P-256 scalar base multiplication vs WebCrypto round-trip (sanity).
 *   - HPKE DeriveKeyPair: determinism + encap/decap functional round-trip.
 *   - TreeKEM.pathSecretChain: length matches the direct-path, secrets are
 *     deterministic, neighbouring entries differ, and the derived commit
 *     secret is distinct from the root path secret.
 *   - IETF cross-check: for every (vector, update_path) tuple in
 *     treekem.json (ciphersuite 0x0002), the path_secret chain is
 *     consistent under DeriveSecret(_, "path"), the commit_secret matches
 *     DeriveSecret(root_path_secret, "path"), and HPKE.deriveKeyPair on
 *     each derived node_secret reproduces the encryption_key the
 *     committer placed on the wire (parsed off the UpdatePath struct).
 */

const path = require('path');
const { webcrypto } = require('crypto');

const P256 = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'p256.js'));
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const TreeKEM = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-kem.js'));
const TreeMath = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-math.js'));
const KeySchedule = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-schedule.js'));
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));

let passed = 0;
let failed = 0;

function assert(cond, name, detail) {
    if (cond) {
        console.log(`  OK   ${name}`);
        passed += 1;
    } else {
        console.log(`  FAIL ${name}${detail ? `  — ${detail}` : ''}`);
        failed += 1;
    }
}

function hex(u8) { return Buffer.from(u8).toString('hex'); }

async function main() {
    // ---------------------------------------------------------------------
    // P-256 sanity: 1·G == (Gx, Gy); a WebCrypto-generated key round-trips.
    // ---------------------------------------------------------------------
    console.log('# p256.scalarBaseMul');
    {
        const g = P256.scalarBaseMul(1n);
        assert(
            P256.bytesToBigInt(g.slice(1, 33)) === P256.GX &&
            P256.bytesToBigInt(g.slice(33, 65)) === P256.GY,
            'scalarBaseMul(1) equals the generator G'
        );

        const kp = await webcrypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
        );
        const rawPub = new Uint8Array(await webcrypto.subtle.exportKey('raw', kp.publicKey));
        const jwk = await webcrypto.subtle.exportKey('jwk', kp.privateKey);
        const pad = '='.repeat((4 - (jwk.d.length % 4)) % 4);
        const dBuf = Buffer.from(jwk.d.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
        const scalar = P256.bytesToBigInt(new Uint8Array(dBuf));
        const ourPub = P256.scalarBaseMul(scalar);
        assert(hex(ourPub) === hex(rawPub), 'scalarBaseMul matches WebCrypto for a random scalar');
    }

    // ---------------------------------------------------------------------
    // HPKE.deriveKeyPair: deterministic + functional.
    // ---------------------------------------------------------------------
    console.log('# HPKE.deriveKeyPair');
    {
        const ikm = new TextEncoder().encode('pinchat-mls-treekem-derivekp');
        const a = await HPKE.deriveKeyPair(ikm);
        const b = await HPKE.deriveKeyPair(ikm);
        assert(hex(a.publicKeyBytes) === hex(b.publicKeyBytes), 'deriveKeyPair pub deterministic');
        assert(!Object.prototype.hasOwnProperty.call(a, 'scalar')
            && !Object.prototype.hasOwnProperty.call(b, 'scalar'),
        'deriveKeyPair does not retain a raw private scalar');
        assert(a.privateKey.extractable === false && b.privateKey.extractable === false,
            'deriveKeyPair returns non-extractable private keys');

        const { sharedSecret: ss1, enc } = await HPKE.encap(a.publicKeyBytes);
        const ss2 = await HPKE.decap(enc, a.privateKey, a.publicKeyBytes);
        assert(hex(ss1) === hex(ss2), 'derived keypair encap/decap round-trip');
    }

    // ---------------------------------------------------------------------
    // TreeKEM.pathSecretChain: length + determinism + distinctness.
    // ---------------------------------------------------------------------
    console.log('# TreeKEM.pathSecretChain');
    {
        const leafSecret = new Uint8Array(32);
        for (let i = 0; i < 32; i += 1) leafSecret[i] = i + 1;

        // 8-leaf tree, committer is leaf 3 (node index 6). Direct-path-with-
        // root should be [5, 3, 7] (parent(6)=5, parent(5)=3, parent(3)=7).
        const nLeaves = 8;
        const leafIndex = 3;
        const expectedPath = TreeMath.directPathWithRoot(
            TreeMath.leafToNode(leafIndex), nLeaves
        );
        assert(
            JSON.stringify(expectedPath) === '[5,3,7]',
            'direct path sanity (leaf 3, 8 leaves) == [5,3,7]'
        );

        const chain = await TreeKEM.pathSecretChain(leafSecret, leafIndex, nLeaves);
        assert(chain.length === expectedPath.length, 'chain length matches direct path');
        for (let i = 0; i < chain.length; i += 1) {
            assert(chain[i].nodeIndex === expectedPath[i], `chain[${i}].nodeIndex == ${expectedPath[i]}`);
            assert(chain[i].pathSecret.length === 32, `chain[${i}].pathSecret is 32 bytes`);
            assert(chain[i].keyPair.publicKeyBytes.length === 65, `chain[${i}].keyPair.pub is 65 bytes`);
        }

        // Adjacent path secrets must differ — "path" is a one-way step.
        assert(
            hex(chain[0].pathSecret) !== hex(chain[1].pathSecret),
            'path_secret[0] != path_secret[1]'
        );

        // Deterministic: same inputs produce the same chain (scalar + pub).
        const chain2 = await TreeKEM.pathSecretChain(leafSecret, leafIndex, nLeaves);
        for (let i = 0; i < chain.length; i += 1) {
            assert(
                hex(chain[i].pathSecret) === hex(chain2[i].pathSecret),
                `chain[${i}].pathSecret deterministic`
            );
            assert(
                hex(chain[i].keyPair.publicKeyBytes) === hex(chain2[i].keyPair.publicKeyBytes),
                `chain[${i}].keyPair.pub deterministic`
            );
        }

        // commit_secret differs from the root path_secret.
        const rootPathSecret = chain[chain.length - 1].pathSecret;
        const cs = await TreeKEM.commitSecret(rootPathSecret);
        assert(cs.length === 32, 'commit_secret is 32 bytes');
        assert(hex(cs) !== hex(rootPathSecret), 'commit_secret != root path_secret');
    }

    // ---------------------------------------------------------------------
    // IETF treekem.json cross-check (ciphersuite 0x0002 only).
    //
    // The vector ships:
    //   - ratchet_tree (parsed → derive nLeaves)
    //   - update_paths[]: each carries `sender`, `update_path` (raw bytes
    //                    of the UpdatePath struct), `path_secrets`
    //                    (one entry per leaf, null for the sender's slot
    //                    and for unused trailing slots; non-null entries
    //                    are the path_secret each receiver would decrypt
    //                    at LCA(sender, that_leaf)) and `commit_secret`.
    //
    // We collapse `path_secrets[]` into the sender-side direct-path chain
    // (one entry per parent on directPathWithRoot), then verify:
    //   (a) the chain is closed under DeriveSecret(_, "path"),
    //   (b) commit_secret matches DeriveSecret(root_chain[end], "path"),
    //   (c) for every direct-path entry i, HPKE.deriveKeyPair derives the
    //       same public key the committer wrote into update_path.nodes[i].
    // ---------------------------------------------------------------------
    console.log('# TreeKEM vs IETF treekem.json (cs=0x0002)');
    {
        const v = require(path.join(__dirname, 'vectors', 'mls', 'treekem.json'));
        const ours = v.filter((t) => t.cipher_suite === 2);
        let totalUpdatePaths = 0;
        for (const tc of ours) {
            const treeBytes = new Uint8Array(Buffer.from(tc.ratchet_tree, 'hex'));
            const tree = Nodes.parseRatchetTree(treeBytes);
            const nLeaves = TreeMath.numLeaves(tree.length);
            for (const up of tc.update_paths) {
                totalUpdatePaths += 1;
                const sender = up.sender;
                const directPath = TreeMath.directPathWithRoot(
                    TreeMath.leafToNode(sender), nLeaves,
                );
                // Build the per-direct-path chain by picking, for each parent
                // index, ANY non-null path_secrets[L] whose LCA(sender, L) ==
                // directPath[i]. The vector stores the same value across all
                // such leaves, so picking the first match is sufficient.
                const chain = new Array(directPath.length).fill(null);
                for (let L = 0; L < up.path_secrets.length; L += 1) {
                    if (L === sender) continue;
                    const ps = up.path_secrets[L];
                    if (!ps) continue;
                    if (L >= nLeaves) continue;
                    const lca = TreeMath.commonAncestor(
                        TreeMath.leafToNode(sender),
                        TreeMath.leafToNode(L),
                        nLeaves,
                    );
                    const idx = directPath.indexOf(lca);
                    if (idx < 0) continue;
                    if (chain[idx] === null) {
                        chain[idx] = new Uint8Array(Buffer.from(ps, 'hex'));
                    }
                }
                // Some chain slots may be unobservable from the vector
                // when the resolution of the corresponding copath sibling
                // is empty (every leaf in that subtree is blank). Those
                // levels still exist in the sender's local chain but no
                // receiver can decrypt them, so the vector ships null.
                // We validate what we *can* see and skip the rest.

                // (a) closure under DeriveSecret(_, "path") — only across
                //     consecutive populated entries.
                for (let i = 1; i < chain.length; i += 1) {
                    if (chain[i - 1] === null || chain[i] === null) continue;
                    const next = await KeySchedule.deriveSecret(chain[i - 1], 'path');
                    assert(
                        hex(next) === hex(chain[i]),
                        `DeriveSecret(chain[${i - 1}], "path") == chain[${i}] (sender=${sender}, nLeaves=${nLeaves})`,
                    );
                }

                // (b) commit_secret — only when we know the root chain
                //     entry. Empty rootChain means every recipient leaf
                //     is on the sender's side of the tree (no possible
                //     receivers), which doesn't happen for the standard
                //     vectors but we guard anyway.
                const rootEntry = chain[chain.length - 1];
                if (rootEntry !== null) {
                    const csExpected = new Uint8Array(Buffer.from(up.commit_secret, 'hex'));
                    const csComputed = await TreeKEM.commitSecret(rootEntry);
                    assert(
                        hex(csComputed) === hex(csExpected),
                        `commit_secret matches (sender=${sender}, nLeaves=${nLeaves})`,
                    );
                }

                // (c) keypair public bytes match the on-wire UpdatePath.
                //     RFC 9420 §7.6 lets the committer ship a *filtered*
                //     direct path that omits entries whose copath sibling
                //     resolution is empty. The IETF vectors exercise this
                //     filtering, so the parsed UpdatePath may be shorter
                //     than the full direct path. We compute the filter
                //     from the ratchet tree and only check matching
                //     positions; entries that don't make it onto the wire
                //     have nothing to compare against.
                const upBytes = new Uint8Array(Buffer.from(up.update_path, 'hex'));
                const parsedUp = Nodes.parseUpdatePath(upBytes);
                const RatchetTree = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'ratchet-tree.js'));
                const senderNode = TreeMath.leafToNode(sender);
                const filteredIdx = [];
                for (let i = 0; i < directPath.length; i += 1) {
                    const childOnPath = i === 0 ? senderNode : directPath[i - 1];
                    const sib = TreeMath.sibling(childOnPath, nLeaves);
                    if (RatchetTree.resolution(tree, sib).length > 0) {
                        filteredIdx.push(i);
                    }
                }
                assert(
                    parsedUp.nodes.length === filteredIdx.length,
                    `parsed UpdatePath nodes (${parsedUp.nodes.length}) == filtered direct path (${filteredIdx.length}) for sender=${sender} nLeaves=${nLeaves}`,
                );
                for (let k = 0; k < filteredIdx.length; k += 1) {
                    const i = filteredIdx[k];
                    if (chain[i] === null) continue;
                    const nodeSecret = await KeySchedule.deriveSecret(chain[i], 'node');
                    const kp = await HPKE.deriveKeyPair(nodeSecret);
                    assert(
                        hex(kp.publicKeyBytes) === hex(parsedUp.nodes[k].encryptionKey),
                        `derivedKeyPair[${i}].pub == update_path.nodes[${k}].encryption_key (sender=${sender}, nLeaves=${nLeaves})`,
                    );
                }
            }
        }
        console.log(`  (cross-checked ${totalUpdatePaths} update_paths across ${ours.length} test cases)`);
    }

    console.log('');
    console.log(`treekem: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
