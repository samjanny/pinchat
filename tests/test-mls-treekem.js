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
 *
 * Full cross-check against treekem.json IETF vectors requires UpdatePath
 * serialization which lives in a follow-up module — this test only covers
 * the deterministic derivation math.
 */

const path = require('path');
const { webcrypto } = require('crypto');

const P256 = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'p256.js'));
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const TreeKEM = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-kem.js'));
const TreeMath = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-math.js'));

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
        assert(hex(a.scalar) === hex(b.scalar), 'deriveKeyPair deterministic');
        assert(hex(a.publicKeyBytes) === hex(b.publicKeyBytes), 'deriveKeyPair pub deterministic');

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

    console.log('');
    console.log(`treekem: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
