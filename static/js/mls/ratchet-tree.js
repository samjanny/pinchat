/**
 * PinChat MLS - ratchet-tree container (RFC 9420 §7).
 *
 * Wraps the `vector<optional<Node>>` produced by nodes.js with the
 * operations that depend on the *tree shape*:
 *
 *   - resolution(node)       - §7.7, the ordered set of non-blank
 *                              descendants used by TreeKEM encryption.
 *   - filteredDirectPath     - §7.6, direct path skipping blanked
 *                              intermediate parents (not yet wired;
 *                              placeholder for TreeKEM).
 *   - leafFor / encryptionKey / parentEncryptionKey - shortcut
 *                              accessors that centralise the blank
 *                              handling every higher layer wants.
 *   - addLeaf / updateLeaf / removeLeaf / extend / truncate - the
 *                              RFC 9420 sections 7.8, 12.1 membership
 *                              operations, checked against the IETF
 *                              tree-operations vectors.
 *   - fromWireNodes          - section 12.4.3.3 wire vector -> full tree.
 *
 * The underlying array is always sized to node_width(n_leaves), with
 * n_leaves a power of two (RFC 9420 trees are full), so indices align
 * with tree-math.js. A blank slot is represented by `null`; a live slot
 * is `{ nodeType, leaf }` or `{ nodeType, parent }`.
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
     * "Filtered direct path" - direct path with blanked ancestors removed.
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

    // --- RFC 9420 membership operations on full trees ----------------------
    //
    // The helpers below never mutate their input: they return a new node
    // array (sharing the unchanged node objects) so a candidate Commit can
    // be abandoned without touching the live epoch.

    function requireFullTreeArray(tree, operation) {
        const nLeaves = nLeavesFromTree(tree);
        if (!Array.isArray(tree) || tree.length === 0
            || !TreeMath.isFullTreeLeafCount(nLeaves)
            || tree.length !== TreeMath.nodeWidth(nLeaves)) {
            throw new Error(
                `ratchet-tree: ${operation} requires a full tree `
                + `(got ${Array.isArray(tree) ? tree.length : 'no'} nodes)`,
            );
        }
        return nLeaves;
    }

    function liveLeafCount(tree) {
        let count = 0;
        for (let nodeIndex = 0; nodeIndex < tree.length; nodeIndex += 2) {
            if (!isBlank(tree, nodeIndex)) count += 1;
        }
        return count;
    }

    /**
     * RFC 9420 section 7.8: double the tree. The old tree becomes the left subtree
     * of a new blank root, the right subtree is all blank.
     */
    function extend(tree) {
        const nLeaves = requireFullTreeArray(tree, 'extend');
        return Nodes.padRatchetTree(tree, TreeMath.nodeWidth(nLeaves * 2));
    }

    /**
     * RFC 9420 section 7.8 / section 12.1.3: while the right subtree of the root has no
     * non-blank leaf, discard the root and the right subtree. A tree whose
     * rightmost non-blank leaf is L ends with 2^d leaves, d the smallest
     * value with 2^d > L.
     */
    function truncate(tree) {
        let nLeaves = requireFullTreeArray(tree, 'truncate');
        let out = tree;
        while (nLeaves > 1) {
            const half = nLeaves / 2;
            let rightHasLeaf = false;
            for (let leafIndex = half; leafIndex < nLeaves; leafIndex += 1) {
                if (!isBlank(out, TreeMath.leafToNode(leafIndex))) {
                    rightHasLeaf = true;
                    break;
                }
            }
            if (rightHasLeaf) break;
            out = out.slice(0, TreeMath.nodeWidth(half));
            nLeaves = half;
        }
        return out === tree ? tree.slice() : out;
    }

    /**
     * RFC 9420 section 12.1.1 Add: use the leftmost blank leaf, extending the tree
     * when there is none; add the new leaf index to the unmerged_leaves of
     * every non-blank parent on its direct path; install the LeafNode.
     */
    function addLeaf(tree, leafNode) {
        requireFullTreeArray(tree, 'addLeaf');
        let out = tree.slice();
        let leafIndex = -1;
        const width = out.length;
        for (let nodeIndex = 0; nodeIndex < width; nodeIndex += 2) {
            if (isBlank(out, nodeIndex)) {
                leafIndex = TreeMath.nodeToLeaf(nodeIndex);
                break;
            }
        }
        if (leafIndex === -1) {
            leafIndex = nLeavesFromTree(out);
            out = extend(out);
        }
        const nLeaves = nLeavesFromTree(out);
        const leafNodeIndex = TreeMath.leafToNode(leafIndex);
        for (const p of TreeMath.directPathWithRoot(leafNodeIndex, nLeaves)) {
            const slot = out[p];
            if (!slot) continue;
            if (slot.nodeType !== Nodes.NodeType.PARENT) {
                throw new Error(`ratchet-tree: node ${p} is not a parent`);
            }
            out[p] = {
                nodeType: Nodes.NodeType.PARENT,
                parent: {
                    ...slot.parent,
                    unmergedLeaves: [
                        ...(slot.parent.unmergedLeaves || []), leafIndex,
                    ],
                },
            };
        }
        out[leafNodeIndex] = { nodeType: Nodes.NodeType.LEAF, leaf: leafNode };
        return { tree: out, leafIndex, nLeaves };
    }

    /**
     * RFC 9420 section 12.1.2 Update: replace the sender's LeafNode and blank the
     * intermediate nodes on its direct path.
     */
    function updateLeaf(tree, leafIndex, leafNode) {
        const nLeaves = requireFullTreeArray(tree, 'updateLeaf');
        const out = tree.slice();
        const leafNodeIndex = TreeMath.leafToNode(leafIndex);
        if (leafNodeIndex >= out.length) {
            throw new Error(`ratchet-tree: leaf ${leafIndex} outside the tree`);
        }
        out[leafNodeIndex] = { nodeType: Nodes.NodeType.LEAF, leaf: leafNode };
        for (const p of TreeMath.directPathWithRoot(leafNodeIndex, nLeaves)) {
            out[p] = null;
        }
        return out;
    }

    /**
     * RFC 9420 section 12.1.3 Remove: blank the leaf and its direct path, then
     * truncate the tree.
     */
    function removeLeaf(tree, leafIndex) {
        requireFullTreeArray(tree, 'removeLeaf');
        const out = tree.slice();
        if (TreeMath.leafToNode(leafIndex) >= out.length) {
            throw new Error(`ratchet-tree: leaf ${leafIndex} outside the tree`);
        }
        blankDirectPath(out, leafIndex);
        return truncate(out);
    }

    /**
     * Rebuild the full in-memory tree from an RFC 9420 section 12.4.3.3 wire
     * vector: the last node MUST be non-blank, and the receiver extends the
     * vector with the minimum number of blanks that gives a full tree.
     */
    function fromWireNodes(nodes) {
        if (!Array.isArray(nodes) || nodes.length === 0) {
            throw new Error('ratchet-tree: empty ratchet_tree');
        }
        if (isBlank(nodes, nodes.length - 1)) {
            throw new Error('ratchet-tree: ratchet_tree ends with a blank node');
        }
        const nLeaves = TreeMath.fullTreeLeafCount(nodes.length);
        return Nodes.padRatchetTree(nodes, TreeMath.nodeWidth(nLeaves));
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
        liveLeafCount,
        extend,
        truncate,
        addLeaf,
        updateLeaf,
        removeLeaf,
        fromWireNodes,
    });
});
