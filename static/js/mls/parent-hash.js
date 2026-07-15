/**
 * PinChat MLS — parent hashes (RFC 9420 §7.9).
 *
 * Parent-hash chaining binds every parent node on a committer's direct
 * path, and the committer's own LeafNode, to the actual shape of the
 * tree below it. Without it a malicious member could splice a subtree
 * from one tree into another and still produce validly-signed
 * LeafNodes / UpdatePaths, because the signatures would not cover the
 * surrounding structure. With it, a receiver recomputes each parent
 * hash from the tree it holds and rejects a mismatch.
 *
 *   struct {
 *       HPKEPublicKey encryption_key;
 *       opaque parent_hash<V>;
 *       opaque original_sibling_tree_hash<V>;
 *   } ParentHashInput;
 *
 *   parent_hash(P, S) = Hash(ParentHashInput {
 *       encryption_key            = P.encryption_key,
 *       parent_hash               = P.parent_hash,
 *       original_sibling_tree_hash= tree_hash(S with P.unmerged_leaves
 *                                             filtered out),
 *   })
 *
 * where P is a parent node on the direct path and S is the child of P
 * that is NOT on the direct path (the copath sibling at that level).
 *
 * The chain is computed top-down: the root's own parent_hash is the
 * empty string (the root has no parent), and each node just below
 * inherits `ParentHash(parent, copath-sibling)`. The committer's leaf
 * carries `ParentHash(its parent, that parent's copath sibling)`.
 *
 * "original" tree hash: §7.9.2 says the sibling subtree hash used here
 * is computed with the parent's unmerged_leaves removed from the
 * sibling subtree (they were added after the parent was last updated,
 * so they must not affect the hash the parent committed to). In this
 * implementation every parent a commit writes has empty unmerged_leaves
 * (§5.3.1), so the filter is a no-op in practice; it is implemented in
 * full anyway so the check stays correct if unmerged handling ever
 * lands.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./codec.js'),
            require('./nodes.js'),
            require('./tree-math.js'),
            require('./tree-hash.js'),
            require('./labeled.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.ParentHash = factory(
            root.MLS.Codec, root.MLS.Nodes, root.MLS.TreeMath,
            root.MLS.TreeHash, root.MLS.Labeled,
        );
    }
})(typeof self !== 'undefined' ? self : this, function (
    Codec, Nodes, TreeMath, TreeHash, Labeled,
) {
    'use strict';

    function equalBytes(a, b) {
        if (!a || !b) return false;
        if (a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    function parentHashInputBytes(encryptionKey, parentHash, siblingTreeHash) {
        const encoder = new Codec.Encoder();
        encoder.writeOpaque(encryptionKey);
        encoder.writeOpaque(parentHash);
        encoder.writeOpaque(siblingTreeHash);
        return encoder.bytes();
    }

    /**
     * tree_hash of the subtree rooted at `siblingNode`, with the given
     * unmerged leaves removed from a working copy. RFC 9420 §7.9 requires
     * both blanking each leaf AND removing it from every ParentNode's
     * unmerged_leaves vector before hashing. `tree` is a padded
     * Array<optional<Node>> of length nodeWidth(nLeaves).
     */
    async function originalSiblingTreeHash(tree, siblingNode, unmergedLeaves, nLeaves) {
        if (!unmergedLeaves || unmergedLeaves.length === 0) {
            return TreeHash.hashNode(tree, siblingNode, nLeaves);
        }
        const removed = new Set(unmergedLeaves);
        const work = tree.map((slot, nodeIdx) => {
            if (!slot) return null;
            if (TreeMath.level(nodeIdx) === 0) {
                return removed.has(TreeMath.nodeToLeaf(nodeIdx)) ? null : slot;
            }
            if (slot.nodeType !== Nodes.NodeType.PARENT) return slot;
            const filtered = (slot.parent.unmergedLeaves || [])
                .filter((leafIdx) => !removed.has(leafIdx));
            if (filtered.length === (slot.parent.unmergedLeaves || []).length) {
                return slot;
            }
            return {
                nodeType: slot.nodeType,
                parent: { ...slot.parent, unmergedLeaves: filtered },
            };
        });
        for (const leafIdx of removed) {
            const nodeIdx = TreeMath.leafToNode(leafIdx);
            if (nodeIdx < work.length) work[nodeIdx] = null;
        }
        return TreeHash.hashNode(work, siblingNode, nLeaves);
    }

    /**
     * ParentHash(parentNode, copathSibling): the value a child on the
     * direct path must carry in its parent_hash field. `parentNode` is
     * the resolved ParentNode struct (must have encryptionKey +
     * parentHash + unmergedLeaves); `siblingNode` is the copath sibling
     * node index at that level.
     */
    async function parentHash(tree, parentNode, siblingNode, nLeaves) {
        const sibHash = await originalSiblingTreeHash(
            tree, siblingNode, parentNode.unmergedLeaves, nLeaves,
        );
        return Labeled.sha256(parentHashInputBytes(
            parentNode.encryptionKey, parentNode.parentHash, sibHash,
        ));
    }

    /**
     * Compute, top-down, the parent_hash each node on `leafIndex`'s
     * direct path (and the leaf itself) must carry, for the tree in its
     * post-update shape. `tree` must already contain the committer's new
     * parent encryption_keys on the direct path (unmerged_leaves = []),
     * because a node's ParentHash depends on its OWN encryption_key.
     *
     * Returns { pathHashes, leafParentHash } where:
     *   - pathHashes[i] is the parent_hash value for directPath[i]
     *     (root-relative order matches `directPathWithRoot`);
     *   - leafParentHash is the value the committer's LeafNode must carry.
     *
     * The root's parent_hash is the empty string; each lower node
     * inherits ParentHash(node-above, its copath sibling).
     */
    async function directPathParentHashes(tree, leafIndex, nLeaves) {
        const leafNode = TreeMath.leafToNode(leafIndex);

        // Single-leaf group: the leaf is the root, there is no parent
        // node and no chain. The leaf's parent_hash is the empty string.
        if (nLeaves === 1 || leafNode === TreeMath.root(nLeaves)) {
            return { pathWithRoot: [], pathHashes: [], leafParentHash: new Uint8Array(0) };
        }

        // Parent nodes strictly above the leaf, from lowest up to root.
        const parentPath = TreeMath.directPathWithRoot(leafNode, nLeaves);
        const topDown = parentPath.slice().reverse(); // [root, ..., lowestParent]

        // parentHashByNode[node] = the parent_hash value stored AT `node`.
        const parentHashByNode = new Map();
        parentHashByNode.set(topDown[0], new Uint8Array(0)); // root: empty

        for (let i = 1; i < topDown.length; i += 1) {
            const node = topDown[i];
            const above = topDown[i - 1];
            const slot = tree[above];
            if (!slot || slot.nodeType !== Nodes.NodeType.PARENT) {
                throw new Error(
                    `parent-hash: node ${above} on direct path is not a parent`,
                );
            }
            const parentNode = {
                encryptionKey: slot.parent.encryptionKey,
                parentHash: parentHashByNode.get(above),
                unmergedLeaves: slot.parent.unmergedLeaves || [],
            };
            const sib = TreeMath.sibling(node, nLeaves);
            const ph = await parentHash(tree, parentNode, sib, nLeaves);
            parentHashByNode.set(node, ph);
        }

        // The committer's leaf inherits ParentHash(its immediate parent,
        // the leaf's copath sibling).
        const leafAbove = parentPath[0];
        const slot = tree[leafAbove];
        if (!slot || slot.nodeType !== Nodes.NodeType.PARENT) {
            throw new Error(`parent-hash: leaf parent ${leafAbove} is not a parent`);
        }
        const leafParentNode = {
            encryptionKey: slot.parent.encryptionKey,
            parentHash: parentHashByNode.get(leafAbove),
            unmergedLeaves: slot.parent.unmergedLeaves || [],
        };
        const leafParentHash = await parentHash(
            tree, leafParentNode, TreeMath.sibling(leafNode, nLeaves), nLeaves,
        );

        const pathHashes = parentPath.map((n) => parentHashByNode.get(n));
        return { pathWithRoot: parentPath, pathHashes, leafParentHash };
    }

    return Object.freeze({
        parentHashInputBytes,
        originalSiblingTreeHash,
        parentHash,
        directPathParentHashes,
        equalBytes,
    });
});
