#!/usr/bin/env node

/**
 * MLS tree math test suite.
 *
 * Cross-checks `static/js/mls/tree-math.js` against the RFC 9420 §4.1
 * worked examples, the RFC 9420 Appendix C reference formulas and the IETF
 * tree-math vectors. RFC 9420 trees are always full (a power-of-two leaf
 * count); the shape functions must refuse any other count instead of
 * computing the left-balanced shape of earlier MLS drafts.
 */

const path = require('path');
const TreeMath = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-math.js'));
const IETF_VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'tree-math.json'));

let passed = 0;
let failed = 0;

function assert(cond, name, detail) {
    if (cond) {
        console.log(`  OK   ${name}`);
        passed += 1;
    } else {
        console.log(`  FAIL ${name}${detail ? `  - ${detail}` : ''}`);
        failed += 1;
    }
}

function eq(a, b, name) {
    const ok = JSON.stringify(a) === JSON.stringify(b);
    assert(ok, name, ok ? null : `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

// ---------------------------------------------------------------------------
// Widths and roots
// ---------------------------------------------------------------------------
console.log('# widths / roots');
eq(TreeMath.nodeWidth(1), 1, 'nodeWidth(1)');
eq(TreeMath.nodeWidth(2), 3, 'nodeWidth(2)');
eq(TreeMath.nodeWidth(4), 7, 'nodeWidth(4)');
eq(TreeMath.nodeWidth(8), 15, 'nodeWidth(8)');
eq(TreeMath.nodeWidth(5), 9, 'nodeWidth(5)');

eq(TreeMath.root(1), 0, 'root(1)');
eq(TreeMath.root(2), 1, 'root(2)');
eq(TreeMath.root(4), 3, 'root(4)');
eq(TreeMath.root(8), 7, 'root(8)');
eq(TreeMath.root(32), 31, 'root(32)');

// A full tree that holds a given wire vector (RFC 9420 section 12.4.3.3).
eq(TreeMath.fullTreeLeafCount(1), 1, 'fullTreeLeafCount(1 node)');
eq(TreeMath.fullTreeLeafCount(3), 2, 'fullTreeLeafCount(3 nodes)');
eq(TreeMath.fullTreeLeafCount(4), 4, 'fullTreeLeafCount(4 nodes)');
eq(TreeMath.fullTreeLeafCount(5), 4, 'fullTreeLeafCount(5 nodes)');
eq(TreeMath.fullTreeLeafCount(7), 4, 'fullTreeLeafCount(7 nodes)');
eq(TreeMath.fullTreeLeafCount(8), 8, 'fullTreeLeafCount(8 nodes)');
eq(TreeMath.fullTreeLeafCount(17), 16, 'fullTreeLeafCount(17 nodes)');

// ---------------------------------------------------------------------------
// Leaf counts that are not a power of two have no RFC 9420 shape. The old
// left-balanced math answered root(3)=3, right(3,3)=4 and parent(4,3)=3,
// which differ from the full 4-leaf tree (right(3)=5, parent(4)=5).
// ---------------------------------------------------------------------------
console.log('# non-power-of-two leaf counts are refused');
function rejects(fn) {
    try { fn(); return false; } catch (_e) { return true; }
}
for (const n of [3, 5, 6, 7, 9, 12, 20]) {
    assert(rejects(() => TreeMath.root(n)), `root(${n}) is refused`);
    assert(rejects(() => TreeMath.parent(0, n)), `parent(0,${n}) is refused`);
    assert(rejects(() => TreeMath.right(3, n)), `right(3,${n}) is refused`);
    assert(rejects(() => TreeMath.directPathWithRoot(0, n)),
        `directPathWithRoot(0,${n}) is refused`);
    assert(rejects(() => TreeMath.leafDescendants(1, n)),
        `leafDescendants(1,${n}) is refused`);
    assert(!TreeMath.isFullTreeLeafCount(n), `isFullTreeLeafCount(${n}) is false`);
}
assert(rejects(() => TreeMath.parent(7, 4)), 'parent of a node outside a 4-leaf tree is refused');

// ---------------------------------------------------------------------------
// Level
// ---------------------------------------------------------------------------
console.log('# levels');
eq(TreeMath.level(0), 0, 'level(0)');
eq(TreeMath.level(1), 1, 'level(1)');
eq(TreeMath.level(2), 0, 'level(2)');
eq(TreeMath.level(3), 2, 'level(3)');
eq(TreeMath.level(7), 3, 'level(7)');
eq(TreeMath.level(5), 1, 'level(5)');

// ---------------------------------------------------------------------------
// Children and parents on a full 4-leaf tree (width 7, root 3)
// ---------------------------------------------------------------------------
console.log('# full 4-leaf tree (width 7)');
eq(TreeMath.left(1), 0, 'left(1)');
eq(TreeMath.right(1, 4), 2, 'right(1,4)');
eq(TreeMath.left(5), 4, 'left(5)');
eq(TreeMath.right(5, 4), 6, 'right(5,4)');
eq(TreeMath.left(3), 1, 'left(3)');
eq(TreeMath.right(3, 4), 5, 'right(3,4)');

eq(TreeMath.parent(0, 4), 1, 'parent(0,4)');
eq(TreeMath.parent(2, 4), 1, 'parent(2,4)');
eq(TreeMath.parent(1, 4), 3, 'parent(1,4)');
eq(TreeMath.parent(4, 4), 5, 'parent(4,4)');
eq(TreeMath.parent(5, 4), 3, 'parent(5,4)');

eq(TreeMath.sibling(0, 4), 2, 'sibling(0,4)');
eq(TreeMath.sibling(2, 4), 0, 'sibling(2,4)');
eq(TreeMath.sibling(1, 4), 5, 'sibling(1,4)');
eq(TreeMath.sibling(5, 4), 1, 'sibling(5,4)');

eq(TreeMath.directPath(0, 4), [1], 'directPath(0,4)');
eq(TreeMath.directPathWithRoot(0, 4), [1, 3], 'directPathWithRoot(0,4)');
eq(TreeMath.copath(0, 4), [2, 5], 'copath(0,4)');

eq(TreeMath.directPath(4, 4), [5], 'directPath(4,4)');
eq(TreeMath.copath(4, 4), [6, 1], 'copath(4,4)');

eq(TreeMath.commonAncestor(0, 2, 4), 1, 'commonAncestor(L0,L1)');
eq(TreeMath.commonAncestor(0, 4, 4), 3, 'commonAncestor(L0,L2)');
eq(TreeMath.commonAncestor(0, 6, 4), 3, 'commonAncestor(L0,L3)');

// ---------------------------------------------------------------------------
// Three members live in the full 4-leaf tree (width 7, root 3) with leaf 3
// blank. RFC 9420 Appendix C: right(3)=5, parent(4)=5, direct_path(4)=[5,3].
// ---------------------------------------------------------------------------
console.log('# three members in a full 4-leaf tree');
eq(TreeMath.right(3, 4), 5, 'right(3,4)');
eq(TreeMath.parent(4, 4), 5, 'parent(4,4)');
eq(TreeMath.sibling(4, 4), 6, 'sibling(L2,4) is the blank leaf 3');
eq(TreeMath.directPathWithRoot(4, 4), [5, 3], 'directPathWithRoot(L2,4)');
eq(TreeMath.copath(4, 4), [6, 1], 'copath(L2,4)');

// RFC 9420 Appendix C formulas, written out independently of the module.
console.log('# RFC 9420 Appendix C reference formulas');
(function () {
    const refLevel = (x) => {
        if ((x & 1) === 0) return 0;
        let k = 0;
        while (((x >> k) & 1) === 1) k += 1;
        return k;
    };
    const refRight = (x) => x ^ (0x03 << (refLevel(x) - 1));
    const refLeft = (x) => x ^ (0x01 << (refLevel(x) - 1));
    const refParent = (x) => {
        const k = refLevel(x);
        const b = (x >> (k + 1)) & 0x01;
        return (x | (1 << k)) ^ (b << (k + 1));
    };
    let ok = true;
    for (const n of [1, 2, 4, 8, 16, 32, 64]) {
        const w = 2 * (n - 1) + 1;
        const r = n - 1;
        if (TreeMath.root(n) !== r) ok = false;
        for (let x = 0; x < w; x += 1) {
            if (refLevel(x) > 0) {
                if (TreeMath.left(x) !== refLeft(x)) ok = false;
                if (TreeMath.right(x, n) !== refRight(x)) ok = false;
            }
            if (x !== r) {
                const p = refParent(x);
                if (TreeMath.parent(x, n) !== p) ok = false;
                const s = x < p ? refRight(p) : refLeft(p);
                if (TreeMath.sibling(x, n) !== s) ok = false;
            }
        }
    }
    assert(ok, 'root/left/right/parent/sibling equal Appendix C for n=1..64');
})();

// ---------------------------------------------------------------------------
// Single-leaf tree (degenerate)
// ---------------------------------------------------------------------------
console.log('# 1-leaf tree');
eq(TreeMath.root(1), 0, 'root(1) == 0');
eq(TreeMath.directPath(0, 1), [], 'directPath(0,1) is empty');
eq(TreeMath.directPathWithRoot(0, 1), [], 'directPathWithRoot(0,1) is empty (the leaf is the root)');
eq(TreeMath.copath(0, 1), [], 'copath(0,1) is empty');

// ---------------------------------------------------------------------------
// Invariant check on many tree sizes: for every non-root node x, the sibling
// of its sibling is itself, and x ∈ directPathWithRoot of leaf(x) ⇒ root.
// ---------------------------------------------------------------------------
console.log('# invariants on full trees up to 64 leaves');
let invariantsOk = true;
for (let n = 1; n <= 64; n *= 2) {
    const w = TreeMath.nodeWidth(n);
    const r = TreeMath.root(n);
    for (let x = 0; x < w; x += 1) {
        if (x === r) continue;
        const s = TreeMath.sibling(x, n);
        if (TreeMath.sibling(s, n) !== x) {
            console.log(`    invariant violated: sibling(sibling(${x},${n}))=${TreeMath.sibling(s,n)}`);
            invariantsOk = false;
        }
        const p = TreeMath.parent(x, n);
        if (!(p === TreeMath.parent(s, n))) {
            console.log(`    invariant violated: parent mismatch x=${x} s=${s} n=${n}`);
            invariantsOk = false;
        }
    }
    // Each leaf's direct path must end at the root (a 1-leaf tree has none).
    for (let leaf = 0; leaf < n && n > 1; leaf += 1) {
        const path = TreeMath.directPathWithRoot(TreeMath.leafToNode(leaf), n);
        if (path[path.length - 1] !== r) {
            console.log(`    invariant violated: leaf ${leaf} path does not end at root (n=${n})`);
            invariantsOk = false;
        }
    }
}
assert(invariantsOk, 'sibling/parent/directPath invariants on n=1..64');

// ---------------------------------------------------------------------------
// leafDescendants sanity
// ---------------------------------------------------------------------------
console.log('# leafDescendants');
eq(TreeMath.leafDescendants(3, 4), [0, 1, 2, 3], 'leafDescendants(root, n=4)');
eq(TreeMath.leafDescendants(1, 4), [0, 1], 'leafDescendants(node 1, n=4)');
eq(TreeMath.leafDescendants(5, 4), [2, 3], 'leafDescendants(node 5, n=4)');
eq(TreeMath.leafDescendants(4, 4), [2], 'leafDescendants(leaf 2, n=4)');
eq(TreeMath.leafDescendants(23, 32), [8, 9, 10, 11, 12, 13, 14, 15], 'leafDescendants(node 23, n=32)');

// ---------------------------------------------------------------------------
// IETF reference vectors (mlswg/mls-implementations test-vectors/tree-math.json)
// ---------------------------------------------------------------------------
// Each vector entry gives the full {left, right, parent, sibling} arrays
// indexed by node index, for a tree of n_leaves leaves. A `null` entry
// means the operation is undefined (children of a leaf, parent of the
// root, sibling of the root). Our implementation throws in those cases;
// we catch and treat the throw as null.
console.log('# IETF tree-math.json vectors');
(function () {
    let vectorAsserts = 0;
    let vectorFails = 0;
    const tryOp = (fn) => { try { return fn(); } catch (_e) { return null; } };

    for (const entry of IETF_VECTORS) {
        const n = entry.n_leaves;
        const w = entry.n_nodes;

        if (TreeMath.nodeWidth(n) !== w) vectorFails += 1; else vectorAsserts += 1;
        if (TreeMath.root(n) !== entry.root) vectorFails += 1; else vectorAsserts += 1;

        for (let x = 0; x < w; x += 1) {
            if (tryOp(() => TreeMath.left(x)) !== entry.left[x]) vectorFails += 1; else vectorAsserts += 1;
            if (tryOp(() => TreeMath.right(x, n)) !== entry.right[x]) vectorFails += 1; else vectorAsserts += 1;
            if (tryOp(() => TreeMath.parent(x, n)) !== entry.parent[x]) vectorFails += 1; else vectorAsserts += 1;
            if (tryOp(() => TreeMath.sibling(x, n)) !== entry.sibling[x]) vectorFails += 1; else vectorAsserts += 1;
        }
    }
    assert(
        vectorFails === 0,
        `IETF vectors: ${vectorAsserts} assertions across ${IETF_VECTORS.length} trees`,
        vectorFails === 0 ? null : `${vectorFails} failures`
    );
})();

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log('');
console.log(`tree-math: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
