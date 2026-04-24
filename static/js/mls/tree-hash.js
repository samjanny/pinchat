/**
 * PinChat MLS — tree hash (RFC 9420 §7.8).
 *
 * For a ratchet tree of N leaves, tree_hash(x) is defined recursively:
 *
 *   if x is a leaf (level(x) == 0):
 *       input = u8(NodeType.leaf)
 *             || u32(leaf_index)
 *             || optional<LeafNode>
 *       tree_hash(x) = Hash(input)
 *
 *   if x is a parent:
 *       input = u8(NodeType.parent)
 *             || optional<ParentNode>
 *             || opaque<V>(tree_hash(left(x)))
 *             || opaque<V>(tree_hash(right(x, n)))
 *       tree_hash(x) = Hash(input)
 *
 * `optional<T>` is `u8 present || [T if 1]`. A blank ratchet-tree slot
 * serializes its optional field with present=0 and no body.
 *
 * This module is pure: given an array of `optional<Node>` matching the
 * ratchet-tree wire shape, it returns the hash of each node index (or of
 * just the root).
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./codec.js'),
            require('./nodes.js'),
            require('./tree-math.js'),
            require('./labeled.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.TreeHash = factory(
            root.MLS.Codec, root.MLS.Nodes, root.MLS.TreeMath, root.MLS.Labeled
        );
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, Nodes, TreeMath, Labeled) {
    'use strict';

    function leafHashInput(leafIndex, optLeafNode) {
        const encoder = new Codec.Encoder();
        encoder.writeU8(Nodes.NodeType.LEAF);
        encoder.writeU32(leafIndex);
        Nodes.writeOptional(encoder, optLeafNode, Nodes.writeLeafNode);
        return encoder.bytes();
    }

    function parentHashInput(optParentNode, leftHash, rightHash) {
        const encoder = new Codec.Encoder();
        encoder.writeU8(Nodes.NodeType.PARENT);
        Nodes.writeOptional(encoder, optParentNode, Nodes.writeParentNode);
        encoder.writeOpaque(leftHash);
        encoder.writeOpaque(rightHash);
        return encoder.bytes();
    }

    /**
     * Compute tree_hash(nodeIndex) for the given ratchet tree. `tree` is
     * an Array<optional<Node>> of length nodeWidth(nLeaves).
     */
    async function hashNode(tree, nodeIndex, nLeaves) {
        const lvl = TreeMath.level(nodeIndex);
        const slot = tree[nodeIndex];

        if (lvl === 0) {
            const leafIndex = nodeIndex / 2;
            const leafNode = slot === null || slot === undefined
                ? null
                : slot.leaf;
            return Labeled.sha256(leafHashInput(leafIndex, leafNode));
        }

        const parentNode = slot === null || slot === undefined
            ? null
            : slot.parent;
        const leftHash  = await hashNode(tree, TreeMath.left(nodeIndex), nLeaves);
        const rightHash = await hashNode(tree, TreeMath.right(nodeIndex, nLeaves), nLeaves);
        return Labeled.sha256(parentHashInput(parentNode, leftHash, rightHash));
    }

    /**
     * Compute tree_hash for every node in the tree. Returns a flat array
     * of Uint8Array hashes indexed by node index, matching the shape of
     * the IETF `tree_hashes` test-vector field.
     */
    async function hashAll(tree) {
        const width = tree.length;
        const nLeaves = TreeMath.numLeaves(width);
        const out = new Array(width);
        for (let i = 0; i < width; i += 1) {
            out[i] = await hashNode(tree, i, nLeaves);
        }
        return out;
    }

    /** Convenience: the hash of the root node. */
    async function hashRoot(tree) {
        const nLeaves = TreeMath.numLeaves(tree.length);
        return hashNode(tree, TreeMath.root(nLeaves), nLeaves);
    }

    return Object.freeze({
        hashNode,
        hashAll,
        hashRoot,
    });
});
