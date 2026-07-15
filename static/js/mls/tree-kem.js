/**
 * PinChat MLS — TreeKEM path-secret chain (RFC 9420 §7.5).
 *
 * When a member commits an update, it generates a random leaf secret and
 * derives a chain of path secrets along the direct path to the root. Each
 * path secret yields a node secret and (via HPKE DeriveKeyPair) an ECDH
 * keypair that becomes the tree node's encryption_key:
 *
 *   path_secret[0]  = leaf_secret                                (random input)
 *   path_secret[n]  = DeriveSecret(path_secret[n-1], "path")     [MLS §7.5]
 *   node_secret[n]  = DeriveSecret(path_secret[n], "node")
 *   keypair[n]      = HPKE.DeriveKeyPair(node_secret[n])
 *
 * The chain has the same length as the direct path plus the leaf level,
 * i.e. one entry per node on `directPathWithRoot(leaf) ∪ {leaf}`.
 *
 * `commit_secret` — the key schedule input for the next epoch — is
 * DeriveSecret(path_secret_root, "path"), i.e. one more "path" iteration
 * after the root's path_secret. (See RFC 9420 §7.5, final paragraph.)
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./hpke.js'),
            require('./key-schedule.js'),
            require('./tree-math.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.TreeKEM = factory(root.MLS.HPKE, root.MLS.KeySchedule, root.MLS.TreeMath);
    }
})(typeof self !== 'undefined' ? self : this, function (HPKE, KeySchedule, TreeMath) {
    'use strict';

    /**
     * Derive the full path-secret chain starting from `leafSecret`.
     * Inputs:
     *   leafSecret : Uint8Array of length HPKE.Nh (32 bytes)
     *   leafIndex  : leaf index of the committer
     *   nLeaves    : current number of leaves in the group
     *
     * Returns an array of entries, one per node on the direct path from
     * the leaf up to and including the root. Each entry carries:
     *   { nodeIndex, pathSecret, keyPair }
     * where keyPair comes from HPKE.deriveKeyPair.
     *
     * The leaf itself is NOT included in the returned array — the leaf's
     * own keypair is derived separately by the LeafNode update logic.
     */
    async function pathSecretChain(leafSecret, leafIndex, nLeaves) {
        const leafNodeIdx = TreeMath.leafToNode(leafIndex);
        const directPath = TreeMath.directPathWithRoot(leafNodeIdx, nLeaves);

        const chain = [];
        let pathSecret = leafSecret;
        for (const nodeIndex of directPath) {
            // Advance one step up the direct path.
            pathSecret = await KeySchedule.deriveSecret(pathSecret, 'path');
            const nodeSecret = await KeySchedule.deriveSecret(pathSecret, 'node');
            let keyPair;
            try {
                keyPair = await HPKE.deriveKeyPair(nodeSecret);
            } finally {
                // node_secret is a one-shot KEM derivation input; the
                // resulting non-extractable CryptoKey pair is sufficient.
                nodeSecret.fill(0);
            }
            chain.push({ nodeIndex, pathSecret, keyPair });
        }
        return chain;
    }

    /**
     * Derive the leaf keypair from `leafSecret`:
     *   leaf_node_secret = DeriveSecret(leaf_secret, "node")
     *   (leaf_priv, leaf_pub) = DeriveKeyPair(leaf_node_secret)
     *
     * Returned in the same shape as pathSecretChain entries so callers
     * can treat the leaf + direct path uniformly.
     */
    async function leafKeyPairFromSecret(leafSecret, leafIndex) {
        const nodeSecret = await KeySchedule.deriveSecret(leafSecret, 'node');
        let keyPair;
        try {
            keyPair = await HPKE.deriveKeyPair(nodeSecret);
        } finally {
            nodeSecret.fill(0);
        }
        return {
            nodeIndex: TreeMath.leafToNode(leafIndex),
            pathSecret: leafSecret,
            keyPair,
        };
    }

    /**
     * The commit_secret fed into the next epoch's key schedule (RFC 9420
     * §7.5 / §8). Defined as DeriveSecret(path_secret[root], "path") —
     * one more "path" step beyond the root's entry.
     */
    async function commitSecret(rootPathSecret) {
        return KeySchedule.deriveSecret(rootPathSecret, 'path');
    }

    return Object.freeze({
        pathSecretChain,
        leafKeyPairFromSecret,
        commitSecret,
    });
});
