/**
 * PinChat MLS — secret tree + per-leaf AEAD ratchet (RFC 9420 §9).
 *
 * Shape mirrors the ratchet tree. The root of the secret tree is the
 * `encryption_secret` derived from the key schedule. Internal nodes split
 * into left/right children:
 *
 *   left_secret  = ExpandWithLabel(parent_secret, "tree", "left",  Nh)
 *   right_secret = ExpandWithLabel(parent_secret, "tree", "right", Nh)
 *
 * At each leaf, two independent chains are rooted:
 *   application_secret[0] = DeriveSecret(leaf_secret, "application")
 *   handshake_secret[0]   = DeriveSecret(leaf_secret, "handshake")
 *
 * Per-generation ratchet (§9.1):
 *   key_g     = DeriveTreeSecret(secret_g, "key",    g, Nk)
 *   nonce_g   = DeriveTreeSecret(secret_g, "nonce",  g, Nn)
 *   secret_{g+1} = DeriveTreeSecret(secret_g, "secret", g, Nh)
 *
 * where DeriveTreeSecret(Secret, Label, Generation, Length) is
 *   ExpandWithLabel(Secret, Label, u32_be(Generation), Length).
 *
 * Sender-data AEAD (§9.4.2):
 *   sample        = ciphertext[0..Nh] zero-padded if shorter
 *   sender_data_key   = ExpandWithLabel(sender_data_secret, "key",   sample, Nk)
 *   sender_data_nonce = ExpandWithLabel(sender_data_secret, "nonce", sample, Nn)
 *
 * Every formula above is validated byte-for-byte against the IETF
 * secret-tree.json vectors for cipher_suite = 2.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./key-schedule.js'),
            require('./hpke.js'),
            require('./tree-math.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.SecretTree = factory(root.MLS.KeySchedule, root.MLS.HPKE, root.MLS.TreeMath);
    }
})(typeof self !== 'undefined' ? self : this, function (KeySchedule, HPKE, TreeMath) {
    'use strict';

    const enc = new TextEncoder();
    const LEFT_BYTES = enc.encode('left');
    const RIGHT_BYTES = enc.encode('right');

    function u32be(v) {
        const out = new Uint8Array(4);
        out[0] = (v >>> 24) & 0xff;
        out[1] = (v >>> 16) & 0xff;
        out[2] = (v >>> 8) & 0xff;
        out[3] = v & 0xff;
        return out;
    }

    /**
     * Derive every node secret in the secret tree. Returns an array
     * indexed by node index, of length `nodeWidth(nLeaves)`. Each entry
     * is a 32-byte Uint8Array; blank tree positions still have a
     * secret (the secret tree has no blanks).
     */
    async function buildSecretTree(encryptionSecret, nLeaves) {
        if (nLeaves < 1) throw new Error('secret-tree: nLeaves must be >= 1');
        const width = TreeMath.nodeWidth(nLeaves);
        const secrets = new Array(width);
        const rootIndex = TreeMath.root(nLeaves);
        secrets[rootIndex] = encryptionSecret;

        async function fill(nodeIndex) {
            if (TreeMath.level(nodeIndex) === 0) return;
            const l = TreeMath.left(nodeIndex);
            const r = TreeMath.right(nodeIndex, nLeaves);
            secrets[l] = await KeySchedule.expandWithLabel(
                secrets[nodeIndex], 'tree', LEFT_BYTES, HPKE.Nh,
            );
            secrets[r] = await KeySchedule.expandWithLabel(
                secrets[nodeIndex], 'tree', RIGHT_BYTES, HPKE.Nh,
            );
            await fill(l);
            await fill(r);
        }
        await fill(rootIndex);
        return secrets;
    }

    /**
     * Shortcut: compute just the leaf secret without materialising the
     * whole tree. Walks the direct path from root down to the leaf.
     */
    async function leafSecret(encryptionSecret, leafIndex, nLeaves) {
        if (leafIndex >= nLeaves) {
            throw new Error(`secret-tree: leafIndex ${leafIndex} >= nLeaves ${nLeaves}`);
        }
        if (nLeaves === 1) return encryptionSecret;

        const leafNode = TreeMath.leafToNode(leafIndex);
        const rootIndex = TreeMath.root(nLeaves);

        // Build the ordered list of nodes from root down to the leaf.
        const path = [leafNode];
        let cur = leafNode;
        while (cur !== rootIndex) {
            cur = TreeMath.parent(cur, nLeaves);
            path.push(cur);
        }
        path.reverse(); // root-first

        let secret = encryptionSecret;
        for (let i = 0; i < path.length - 1; i += 1) {
            const parent = path[i];
            const child = path[i + 1];
            const isLeft = child === TreeMath.left(parent);
            secret = await KeySchedule.expandWithLabel(
                secret, 'tree', isLeft ? LEFT_BYTES : RIGHT_BYTES, HPKE.Nh,
            );
        }
        return secret;
    }

    /**
     * Root secret of one leaf's application / handshake chain.
     *   application_secret[0] = DeriveSecret(leaf_secret, "application")
     *   handshake_secret[0]   = DeriveSecret(leaf_secret, "handshake")
     */
    async function leafChainRoot(leafSecretValue, which) {
        if (which !== 'application' && which !== 'handshake') {
            throw new Error(`secret-tree: which must be "application" or "handshake", got "${which}"`);
        }
        return KeySchedule.deriveSecret(leafSecretValue, which);
    }

    /**
     * Advance the per-generation chain to the given generation and derive
     * the AEAD key + nonce at that generation. Used once per AEAD slot.
     *
     * Returns { key, nonce, nextSecret }. For generation g, nextSecret
     * would seed generation g+1 (callers should persist it to avoid
     * recomputing the full chain).
     */
    async function keyNonceAtGeneration(chainRoot, generation) {
        if (generation < 0) throw new Error('secret-tree: generation must be >= 0');
        let secret = chainRoot;
        for (let g = 0; g < generation; g += 1) {
            // Advance chain: secret_{g+1} = DeriveTreeSecret(secret_g, "secret", g, Nh)
            secret = await KeySchedule.expandWithLabel(secret, 'secret', u32be(g), HPKE.Nh);
        }
        const key   = await KeySchedule.expandWithLabel(secret, 'key',   u32be(generation), HPKE.Nk);
        const nonce = await KeySchedule.expandWithLabel(secret, 'nonce', u32be(generation), HPKE.Nn);
        const nextSecret = await KeySchedule.expandWithLabel(
            secret, 'secret', u32be(generation), HPKE.Nh,
        );
        return { key, nonce, nextSecret };
    }

    /**
     * Sender-data key + nonce (RFC 9420 §9.4.2). The sample is the first
     * Nh bytes of the application ciphertext, zero-padded if shorter.
     */
    async function senderDataKeyNonce(senderDataSecret, ciphertext) {
        const sample = new Uint8Array(HPKE.Nh);
        sample.set(ciphertext.slice(0, Math.min(ciphertext.length, HPKE.Nh)), 0);
        const key   = await KeySchedule.expandWithLabel(senderDataSecret, 'key',   sample, HPKE.Nk);
        const nonce = await KeySchedule.expandWithLabel(senderDataSecret, 'nonce', sample, HPKE.Nn);
        return { key, nonce };
    }

    return Object.freeze({
        buildSecretTree,
        leafSecret,
        leafChainRoot,
        keyNonceAtGeneration,
        senderDataKeyNonce,
    });
});
