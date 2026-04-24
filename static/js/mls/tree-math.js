/**
 * PinChat MLS — tree math (RFC 9420 §4.1).
 *
 * Array-based left-balanced binary tree arithmetic. All functions here are
 * *pure* — they operate on integer indices only and never touch key material.
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
 * Leaves occupy even indices, parents occupy odd indices. The root of an
 * N-leaf tree is at index 2^ceil(log2(N)) - 1.
 *
 * Left-balanced trees
 * -------------------
 * When N is not a power of two, the right half of the tree is truncated:
 * some "infinite tree" parent indices would fall past nodeWidth(N). The
 * RFC defines truncation rules for parent/right/sibling so that every
 * operation returns a *valid* in-tree index — we implement those rules
 * here and stress-test them in test-mls-tree-math.js.
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

    /** Root index for a tree with `nLeaves` leaves. */
    function root(nLeaves) {
        const w = nodeWidth(nLeaves);
        if (w === 0) throw new Error('root: empty tree');
        return (1 << log2(w)) - 1;
    }

    /** Left child of node `x` in the infinite tree. Undefined for leaves. */
    function left(x) {
        const k = level(x);
        if (k === 0) throw new Error('left: leaf has no children');
        return x ^ (0x01 << (k - 1));
    }

    /**
     * Right child of node `x`, truncated into an N-leaf tree. If the
     * "infinite" right child lies past the last node, RFC 9420 says to
     * descend into the rightmost in-tree left child instead.
     */
    function right(x, nLeaves) {
        const k = level(x);
        if (k === 0) throw new Error('right: leaf has no children');
        let r = x ^ (0x03 << (k - 1));
        const w = nodeWidth(nLeaves);
        while (r >= w) {
            r = left(r);
        }
        return r;
    }

    /**
     * Parent of `x` in the infinite tree. For an N-leaf tree use
     * `parent(x, n)` which skips over parent slots that fall past the width.
     */
    function parentStep(x) {
        const k = level(x);
        const b = (x >>> (k + 1)) & 1;
        return (x | (1 << k)) ^ (b << (k + 1));
    }

    /** Parent of `x` inside an N-leaf tree. Throws if `x` is the root. */
    function parent(x, nLeaves) {
        if (x === root(nLeaves)) throw new Error('parent: root has no parent');
        const w = nodeWidth(nLeaves);
        let p = parentStep(x);
        while (p >= w) {
            p = parentStep(p);
        }
        return p;
    }

    /** Sibling of `x` inside an N-leaf tree. Throws if `x` is the root. */
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

    /** Direct path including the root as the last element. */
    function directPathWithRoot(x, nLeaves) {
        if (nLeaves === 0) return [];
        const r = root(nLeaves);
        if (x === r) return [r];
        return directPath(x, nLeaves).concat([r]);
    }

    /**
     * Copath: sibling of each node on the path from `x` up to the child of
     * the root. Matches `directPath` index-for-index: copath[i] is the
     * sibling of `directPathWithRoot[i]` — useful for TreeKEM encryption.
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
     * Lowest common ancestor of two nodes inside an N-leaf tree.
     * Used when encrypting an UpdatePath step toward a specific leaf.
     */
    function commonAncestor(x, y, nLeaves) {
        if (x === y) return x;
        const px = new Set();
        let cur = x;
        px.add(cur);
        while (cur !== root(nLeaves)) {
            cur = parent(cur, nLeaves);
            px.add(cur);
        }
        cur = y;
        while (!px.has(cur)) {
            if (cur === root(nLeaves)) {
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
     * Return the set of leaves that descend from `nodeIndex` in an N-leaf
     * tree. Used to compute the resolution of a blanked parent node: when
     * a parent is blank, TreeKEM addresses the subtree by its leaf
     * descendants instead.
     */
    function leafDescendants(nodeIndex, nLeaves) {
        const w = nodeWidth(nLeaves);
        if (nodeIndex >= w) return [];
        if ((nodeIndex & 1) === 0) {
            // Leaf
            return [nodeToLeaf(nodeIndex)];
        }
        return leafDescendants(left(nodeIndex), nLeaves)
            .concat(leafDescendants(right(nodeIndex, nLeaves), nLeaves));
    }

    return Object.freeze({
        log2,
        level,
        nodeWidth,
        numLeaves,
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
