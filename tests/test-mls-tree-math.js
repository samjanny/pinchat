#!/usr/bin/env node

/**
 * MLS tree math test suite.
 *
 * Cross-checks `static/js/mls/tree-math.js` against the RFC 9420 §4.1
 * worked examples and against a small-tree brute-force reference.
 */

const path = require('path');
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
// Non-power-of-two: a 5-leaf tree has 9 nodes, log2(9)=3 so root is 2^3-1 = 7.
eq(TreeMath.root(5), 7, 'root(5)');
eq(TreeMath.root(3), 3, 'root(3)');

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
// Truncated 3-leaf tree (width 5, root 3)
// Infinite-tree right(3) = 5, but width=5 so right(3,3) must skip the missing
// node and descend to left(5) = 4.
// ---------------------------------------------------------------------------
console.log('# truncated 3-leaf tree (width 5)');
eq(TreeMath.right(3, 3), 4, 'right(3,3) — truncated to leaf');
eq(TreeMath.parent(4, 3), 3, 'parent(4,3) — skips missing parent at 5');
eq(TreeMath.sibling(4, 3), 1, 'sibling(4,3)');
eq(TreeMath.directPathWithRoot(0, 3), [1, 3], 'directPathWithRoot(L0,3)');
eq(TreeMath.directPathWithRoot(4, 3), [3], 'directPathWithRoot(L2,3) — only root on path');
eq(TreeMath.copath(4, 3), [1], 'copath(L2,3)');

// ---------------------------------------------------------------------------
// Single-leaf tree (degenerate)
// ---------------------------------------------------------------------------
console.log('# 1-leaf tree');
eq(TreeMath.root(1), 0, 'root(1) == 0');
eq(TreeMath.directPath(0, 1), [], 'directPath(0,1) is empty');
eq(TreeMath.directPathWithRoot(0, 1), [0], 'directPathWithRoot(0,1) is just the root');
eq(TreeMath.copath(0, 1), [], 'copath(0,1) is empty');

// ---------------------------------------------------------------------------
// Invariant check on many tree sizes: for every non-root node x, the sibling
// of its sibling is itself, and x ∈ directPathWithRoot of leaf(x) ⇒ root.
// ---------------------------------------------------------------------------
console.log('# invariants on trees up to 16 leaves');
let invariantsOk = true;
for (let n = 1; n <= 16; n += 1) {
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
    // Each leaf's direct path must end at the root.
    for (let leaf = 0; leaf < n; leaf += 1) {
        const path = TreeMath.directPathWithRoot(TreeMath.leafToNode(leaf), n);
        if (path[path.length - 1] !== r) {
            console.log(`    invariant violated: leaf ${leaf} path does not end at root (n=${n})`);
            invariantsOk = false;
        }
    }
}
assert(invariantsOk, 'sibling/parent/directPath invariants on n=1..16');

// ---------------------------------------------------------------------------
// leafDescendants sanity
// ---------------------------------------------------------------------------
console.log('# leafDescendants');
eq(TreeMath.leafDescendants(3, 4), [0, 1, 2, 3], 'leafDescendants(root, n=4)');
eq(TreeMath.leafDescendants(1, 4), [0, 1], 'leafDescendants(node 1, n=4)');
eq(TreeMath.leafDescendants(3, 3), [0, 1, 2], 'leafDescendants(root, n=3) — truncated');

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log('');
console.log(`tree-math: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
