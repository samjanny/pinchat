/**
 * PinChat MLS — ratchet-tree container (RFC 9420 §7).
 *
 * Wraps the `vector<optional<Node>>` produced by nodes.js with the
 * operations that depend on the *tree shape*:
 *
 *   - resolution(node)       — §7.7, the ordered set of non-blank
 *                              descendants used by TreeKEM encryption.
 *   - filteredDirectPath     — §7.6, direct path skipping blanked
 *                              intermediate parents (not yet wired;
 *                              placeholder for TreeKEM).
 *   - leafFor / encryptionKey / parentEncryptionKey — shortcut
 *                              accessors that centralise the blank
 *                              handling every higher layer wants.
 *
 * The underlying array is always sized to node_width(n_leaves) so
 * indices align with tree-math.js. A blank slot is represented by
 * `null`; a live slot is `{ nodeType, leaf }` or `{ nodeType, parent }`.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./nodes.js'),
            require('./tree-math.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.RatchetTree = factory(root.MLS.Nodes, root.MLS.TreeMath);
    }
})(typeof self !== 'undefined' ? self : this, function (Nodes, TreeMath) {
    'use strict';

    function nLeavesFromTree(tree) {
        return TreeMath.numLeaves(tree.length);
    }

    function isBlank(tree, nodeIndex) {
        return tree[nodeIndex] === null || tree[nodeIndex] === undefined;
    }

    function isLeaf(nodeIndex) {
        return TreeMath.level(nodeIndex) === 0;
    }

    /**
     * RFC 9420 §7.7 resolution. Returns an ordered list of node indices.
     *
     *   resolution(non-blank leaf n)   = [n]
     *   resolution(non-blank parent p) = [p] ++ [node(l) for l in p.unmerged_leaves]
     *   resolution(blank leaf)         = []
     *   resolution(blank parent p)     = resolution(left(p)) ++ resolution(right(p))
     */
    function resolution(tree, nodeIndex) {
        const nLeaves = nLeavesFromTree(tree);
        const blank = isBlank(tree, nodeIndex);
        const leaf = isLeaf(nodeIndex);

        if (!blank) {
            if (leaf) return [nodeIndex];
            // Parent node: self, then unmerged leaves as node indices.
            const out = [nodeIndex];
            const unmerged = tree[nodeIndex].parent.unmergedLeaves;
            for (const l of unmerged) {
                out.push(TreeMath.leafToNode(l));
            }
            return out;
        }

        if (leaf) return [];
        return resolution(tree, TreeMath.left(nodeIndex))
            .concat(resolution(tree, TreeMath.right(nodeIndex, nLeaves)));
    }

    /** Compute resolutions for every node (used to verify against IETF tables). */
    function resolutions(tree) {
        const out = new Array(tree.length);
        for (let i = 0; i < tree.length; i += 1) out[i] = resolution(tree, i);
        return out;
    }

    /**
     * "Filtered direct path" — direct path with blanked ancestors removed.
     * RFC 9420 §7.6 uses the filtered path to decide which copath
     * resolution to encrypt to when committing. For now we expose the
     * full direct path unchanged; TreeKEM will filter at encryption time.
     */
    function filteredDirectPath(tree, leafIndex) {
        const nLeaves = nLeavesFromTree(tree);
        const dp = TreeMath.directPathWithRoot(TreeMath.leafToNode(leafIndex), nLeaves);
        return dp.filter((node) => !isBlank(tree, node));
    }

    function leafFor(tree, leafIndex) {
        const nodeIdx = TreeMath.leafToNode(leafIndex);
        const slot = tree[nodeIdx];
        if (slot === null || slot === undefined) return null;
        if (slot.nodeType !== Nodes.NodeType.LEAF) {
            throw new Error(`ratchet-tree: node ${nodeIdx} is not a leaf`);
        }
        return slot.leaf;
    }

    function parentAt(tree, nodeIndex) {
        const slot = tree[nodeIndex];
        if (slot === null || slot === undefined) return null;
        if (slot.nodeType !== Nodes.NodeType.PARENT) {
            throw new Error(`ratchet-tree: node ${nodeIndex} is not a parent`);
        }
        return slot.parent;
    }

    /** Blank the node at `nodeIndex`. Mutates the tree. */
    function blank(tree, nodeIndex) {
        tree[nodeIndex] = null;
    }

    /** Blank every node on the direct path of `leafIndex` plus the leaf. */
    function blankDirectPath(tree, leafIndex) {
        const nLeaves = nLeavesFromTree(tree);
        const leafNode = TreeMath.leafToNode(leafIndex);
        tree[leafNode] = null;
        for (const p of TreeMath.directPathWithRoot(leafNode, nLeaves)) {
            tree[p] = null;
        }
    }

    return Object.freeze({
        nLeavesFromTree,
        isBlank,
        isLeaf,
        resolution,
        resolutions,
        filteredDirectPath,
        leafFor,
        parentAt,
        blank,
        blankDirectPath,
    });
});
