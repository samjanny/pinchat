/**
 * PinChat MLS - tree math (RFC 9420 section 4.1 and Appendix C).
 *
 * Array-based complete binary tree arithmetic. All functions here are
 * *pure* - they operate on integer indices only and never touch key material.
 *
 * Node indexing
 * -------------
 * A tree with N leaves has W = 2*(N-1)+1 node indices, laid out as
 *
 *     leaf 0   leaf 1   leaf 2   leaf 3
 *        0   1   2    3    4   5    6
 *           /         \        |
 *        parent(0,2) parent(4,6)
 *                 \      /
 *                  root=3
 *
 * Leaves occupy even indices, parents occupy odd indices.
 *
 * Full trees only
 * ---------------
 * RFC 9420 ratchet trees and secret trees are always full: the number of
 * leaves is a power of two. A group whose membership is not a power of two
 * keeps blank leaves at the right edge; the tree is extended (doubled) when
 * an Add finds no blank leaf and truncated (halved) after a Remove leaves
 * the right subtree without a non-blank leaf (section 7.8, section 12.1.1, section 12.1.3).
 *
 * Earlier MLS drafts used "left-balanced" trees for arbitrary leaf counts,
 * whose roots, parents and siblings differ from RFC 9420 as soon as the
 * count is not a power of two. Every shape-dependent function below
 * therefore refuses a leaf count that is not a power of two instead of
 * silently computing a left-balanced shape. `nodeWidth` and `numLeaves`
 * stay plain arithmetic, because callers use them to size wire vectors.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.MLS = root.MLS || {};
        root.MLS.TreeMath = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // 2^30 leaves is far beyond any MLS group; it keeps every node index a
    // small positive integer for the 32-bit bitwise operators used below.
    const MAX_LEAVES = 1 << 30;

    /**
     * Integer floor-log2. log2(0) is undefined; we return 0 to match the
     * RFC pseudocode convention (only called on positive inputs in practice).
     */
    function log2(x) {
        if (x <= 0) return 0;
        let k = 0;
        while ((x >>> k) > 0) k += 1;
        return k - 1;
    }

    /**
     * Level of a node. Leaves (even indices) are level 0. The level is the
     * number of trailing 1 bits in the index.
     */
    function level(x) {
        if ((x & 1) === 0) return 0;
        let k = 0;
        while (((x >>> k) & 1) === 1) k += 1;
        return k;
    }

    /** True when `n` is a valid RFC 9420 leaf count (a power of two). */
    function isFullTreeLeafCount(n) {
        return Number.isInteger(n) && n >= 1 && n <= MAX_LEAVES
            && (n & (n - 1)) === 0;
    }

    function requireFullTree(nLeaves, operation) {
        if (!isFullTreeLeafCount(nLeaves)) {
            throw new Error(
                `tree-math: ${operation} requires a power-of-two leaf count `
                + `(got ${nLeaves}); RFC 9420 trees are always full`,
            );
        }
    }

    function requireNodeInTree(x, nLeaves, operation) {
        if (!Number.isInteger(x) || x < 0 || x >= nodeWidth(nLeaves)) {
            throw new Error(
                `tree-math: ${operation}: node ${x} outside a ${nLeaves}-leaf tree`,
            );
        }
    }

    /** Total node count for a tree of `nLeaves` leaves. */
    function nodeWidth(nLeaves) {
        if (nLeaves === 0) return 0;
        return 2 * (nLeaves - 1) + 1;
    }

    /** Number of leaves in a tree that has `width` node slots. */
    function numLeaves(width) {
        if (width === 0) return 0;
        return (width >>> 1) + 1;
    }

    /**
     * Leaf count of the smallest full tree holding `nodeCount` nodes. This
     * is how a receiver sizes a ratchet_tree whose trailing blank nodes were
     * omitted on the wire (RFC 9420 section 12.4.3.3).
     */
    function fullTreeLeafCount(nodeCount) {
        if (!Number.isInteger(nodeCount) || nodeCount < 1) {
            throw new Error(`tree-math: invalid node count ${nodeCount}`);
        }
        let n = 1;
        while (nodeWidth(n) < nodeCount) {
            if (n >= MAX_LEAVES) {
                throw new Error(`tree-math: node count ${nodeCount} too large`);
            }
            n *= 2;
        }
        return n;
    }

    /** Root index for a full tree with `nLeaves` leaves. */
    function root(nLeaves) {
        requireFullTree(nLeaves, 'root');
        return (1 << log2(nodeWidth(nLeaves))) - 1;
    }

    /** Left child of intermediate node `x`. */
    function left(x) {
        const k = level(x);
        if (k === 0) throw new Error('left: leaf has no children');
        return x ^ (0x01 << (k - 1));
    }

    /**
     * Right child of intermediate node `x` (RFC 9420 Appendix C). In a full
     * tree the child always exists, so no truncation rule applies. When
     * `nLeaves` is supplied the tree shape is checked as well.
     */
    function right(x, nLeaves) {
        const k = level(x);
        if (k === 0) throw new Error('right: leaf has no children');
        if (nLeaves !== undefined) {
            requireFullTree(nLeaves, 'right');
            requireNodeInTree(x, nLeaves, 'right');
        }
        return x ^ (0x03 << (k - 1));
    }

    /** Parent of `x` in the infinite tree (RFC 9420 Appendix C formula). */
    function parentStep(x) {
        const k = level(x);
        const b = (x >>> (k + 1)) & 1;
        return (x | (1 << k)) ^ (b << (k + 1));
    }

    /** Parent of `x` inside a full `nLeaves`-leaf tree. Throws at the root. */
    function parent(x, nLeaves) {
        if (x === root(nLeaves)) throw new Error('parent: root has no parent');
        requireNodeInTree(x, nLeaves, 'parent');
        return parentStep(x);
    }

    /** Sibling of `x` inside a full tree. Throws if `x` is the root. */
    function sibling(x, nLeaves) {
        const p = parent(x, nLeaves);
        if (x < p) return right(p, nLeaves);
        return left(p);
    }

    /**
     * Direct path: sequence of nodes from `x` up to (but not including) the
     * root. The root is returned separately by `directPathWithRoot`.
     */
    function directPath(x, nLeaves) {
        if (nLeaves === 0) return [];
        const r = root(nLeaves);
        if (x === r) return [];
        const path = [];
        let node = x;
        while (true) {
            const p = parent(node, nLeaves);
            if (p === r) break;
            path.push(p);
            node = p;
        }
        return path;
    }

    /**
     * Direct path including the root as the last element: RFC 9420
     * `direct_path(x)`. The root itself has an empty direct path, so the
     * only leaf of a 1-leaf tree has no parent to update.
     */
    function directPathWithRoot(x, nLeaves) {
        if (nLeaves === 0) return [];
        const r = root(nLeaves);
        if (x === r) return [];
        return directPath(x, nLeaves).concat([r]);
    }

    /**
     * Copath: sibling of each node on the path from `x` up to the child of
     * the root. Matches `directPath` index-for-index: copath[i] is the
     * sibling of `directPathWithRoot[i]` - useful for TreeKEM encryption.
     */
    function copath(x, nLeaves) {
        if (nLeaves === 0) return [];
        const r = root(nLeaves);
        if (x === r) return [];
        const out = [sibling(x, nLeaves)];
        const path = directPath(x, nLeaves);
        for (const node of path) {
            out.push(sibling(node, nLeaves));
        }
        return out;
    }

    /**
     * Lowest common ancestor of two nodes inside a full tree.
     * Used when encrypting an UpdatePath step toward a specific leaf.
     */
    function commonAncestor(x, y, nLeaves) {
        if (x === y) return x;
        const r = root(nLeaves);
        const px = new Set();
        let cur = x;
        px.add(cur);
        while (cur !== r) {
            cur = parent(cur, nLeaves);
            px.add(cur);
        }
        cur = y;
        while (!px.has(cur)) {
            if (cur === r) {
                throw new Error('commonAncestor: trees disagree');
            }
            cur = parent(cur, nLeaves);
        }
        return cur;
    }

    /** Leaf index -> node index mapping. */
    function leafToNode(leafIndex) {
        return leafIndex * 2;
    }

    /** Node index -> leaf index. Throws if the node is not a leaf. */
    function nodeToLeaf(nodeIndex) {
        if ((nodeIndex & 1) !== 0) {
            throw new Error('nodeToLeaf: node is not a leaf');
        }
        return nodeIndex >>> 1;
    }

    /**
     * Return the leaves that descend from `nodeIndex` in a full tree. Used
     * to compute the resolution of a blanked parent node: when a parent is
     * blank, TreeKEM addresses the subtree by its leaf descendants instead.
     */
    function leafDescendants(nodeIndex, nLeaves) {
        requireFullTree(nLeaves, 'leafDescendants');
        if (nodeIndex >= nodeWidth(nLeaves)) return [];
        // A level-k node spans 2^k consecutive leaves starting at
        // (x - (2^k - 1)) / 2.
        const k = level(nodeIndex);
        const first = (nodeIndex - ((1 << k) - 1)) >>> 1;
        const out = [];
        for (let i = 0; i < (1 << k); i += 1) out.push(first + i);
        return out;
    }

    return Object.freeze({
        log2,
        level,
        isFullTreeLeafCount,
        nodeWidth,
        numLeaves,
        fullTreeLeafCount,
        root,
        left,
        right,
        parentStep,
        parent,
        sibling,
        directPath,
        directPathWithRoot,
        copath,
        commonAncestor,
        leafToNode,
        nodeToLeaf,
        leafDescendants,
    });
});
