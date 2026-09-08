#!/usr/bin/env node
/**
 * Relay-reported departures go through a liveness challenge (issue #1).
 *
 * The relay's `userleft` is unauthenticated. Before the creator commits a
 * Remove for a member the relay says has left, it pings that member over MLS
 * and removes only if the member stays silent for the grace window. The relay
 * can suppress the reply, but it cannot forge one, and it cannot make the
 * creator act on a single forged frame.
 */
const path = require('path');
const assert = require('assert');

const MLS_DIR = path.join(__dirname, '..', 'static', 'js', 'mls');
global.window = global;
global.self = global;
global.MLS = {
    Codec: require(path.join(MLS_DIR, 'codec.js')),
    TreeMath: require(path.join(MLS_DIR, 'tree-math.js')),
    P256: require(path.join(MLS_DIR, 'p256.js')),
    CipherSuite: require(path.join(MLS_DIR, 'ciphersuite.js')),
    HPKE: require(path.join(MLS_DIR, 'hpke.js')),
    Signature: require(path.join(MLS_DIR, 'signature.js')),
    Labeled: require(path.join(MLS_DIR, 'labeled.js')),
    KeySchedule: require(path.join(MLS_DIR, 'key-schedule.js')),
    TranscriptHashes: require(path.join(MLS_DIR, 'transcript-hashes.js')),
    Nodes: require(path.join(MLS_DIR, 'nodes.js')),
    TreeHash: require(path.join(MLS_DIR, 'tree-hash.js')),
    ParentHash: require(path.join(MLS_DIR, 'parent-hash.js')),
    RatchetTree: require(path.join(MLS_DIR, 'ratchet-tree.js')),
    TreeKEM: require(path.join(MLS_DIR, 'tree-kem.js')),
    GroupContext: require(path.join(MLS_DIR, 'group-context.js')),
    KeyPackage: require(path.join(MLS_DIR, 'key-package.js')),
    MLSMessage: require(path.join(MLS_DIR, 'mls-message.js')),
    GroupInfo: require(path.join(MLS_DIR, 'group-info.js')),
    Welcome: require(path.join(MLS_DIR, 'welcome.js')),
    Framing: require(path.join(MLS_DIR, 'framing.js')),
    Proposal: require(path.join(MLS_DIR, 'proposal.js')),
    Commit: require(path.join(MLS_DIR, 'commit.js')),
    PublicMessage: require(path.join(MLS_DIR, 'public-message.js')),
    SecretTree: require(path.join(MLS_DIR, 'secret-tree.js')),
    PrivateMessage: require(path.join(MLS_DIR, 'private-message.js')),
    Group: require(path.join(MLS_DIR, 'group.js')),
};
require(path.join(__dirname, '..', 'static', 'js', 'mls-session.js'));

const { MLSSession } = global;
const { WireFormat } = global.MLS.MLSMessage;
const PSK = new Uint8Array(32).fill(0x5a);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Creator + one joined member, with the relay played by hand. */
async function makeGroup({ livenessGraceMs } = {}) {
    const creatorOut = [];
    const joinerOut = [];
    const creatorEvents = [];
    const joinerEvents = [];
    const creator = new MLSSession({
        role: 'creator',
        send: (envelope) => { creatorOut.push(envelope); return true; },
        cancelPendingControl: () => true,
        onEvent: (event) => creatorEvents.push(event),
        pskSecret: PSK,
        relaySenderId: 'creator-self',
        livenessGraceMs,
    });
    await creator.start();
    const pins = creator.bootstrapPins;
    const joiner = new MLSSession({
        role: 'joiner',
        send: (envelope) => { joinerOut.push(envelope); return true; },
        onEvent: (event) => joinerEvents.push(event),
        pskSecret: PSK,
        expectedGroupId: pins.groupId,
        expectedCreatorKeyHash: pins.creatorKeyHash,
        relaySenderId: 'joiner-1',
    });
    await joiner.start();
    const keyPackage = joinerOut.find((e) => e.wire_format === WireFormat.MLS_KEY_PACKAGE);
    await creator.onRelayEnvelope({ ...keyPackage, sender_id: 'joiner-1' });
    const commit = creatorOut.find((e) => e.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    await creator.onRelayEnvelope({ ...commit, sender_id: 'creator-self' });
    await joiner.onRelayEnvelope({ ...commit, sender_id: 'creator-self' });
    const welcome = creatorOut.find((e) => e.wire_format === WireFormat.MLS_WELCOME);
    await joiner.onRelayEnvelope({ ...welcome, sender_id: 'creator-self' });
    assert.strictEqual(creator.state, 'joined');
    assert.strictEqual(joiner.state, 'joined');
    return { creator, joiner, creatorOut, joinerOut, creatorEvents, joinerEvents };
}

const privateMessages = (out) => out.filter((e) => e.wire_format === WireFormat.MLS_PRIVATE_MESSAGE);
const commitsAfter = (out, n) => out.slice(n).filter((e) => e.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);

let passed = 0;
let failed = 0;
function check(name, condition, detail) {
    if (condition) { console.log(`  [OK] ${name}`); passed++; }
    else { console.log(`  [X]  ${name}${detail ? ' :: ' + detail : ''}`); failed++; }
}

async function main() {
    console.log('# MLS liveness challenge before relay-driven Remove');

    // 1. A reported departure produces a ping, not a Remove.
    {
        const g = await makeGroup({ livenessGraceMs: 10000 });
        const outBefore = g.creatorOut.length;
        await g.creator.requestRemovalAfterLivenessCheck('joiner-1');
        const pings = privateMessages(g.creatorOut.slice(outBefore));
        check('creator emits an authenticated ping instead of a Remove',
            pings.length === 1 && commitsAfter(g.creatorOut, outBefore).length === 0);
        check('a liveness-check-started event names the suspected member',
            g.creatorEvents.some((e) => e.kind === 'liveness-check-started' && e.senderId === 'joiner-1'));

        // 2. The member answers; the creator cancels the removal.
        const joinerOutBefore = g.joinerOut.length;
        await g.joiner.onRelayEnvelope({ ...pings[0], sender_id: 'creator-self' });
        const pongs = privateMessages(g.joinerOut.slice(joinerOutBefore));
        check('the addressed member replies with an authenticated pong', pongs.length === 1);
        check('the ping never surfaces as a chat message to the member',
            !g.joinerEvents.some((e) => e.kind === 'message' || e.kind === 'image'));

        const outBeforePong = g.creatorOut.length;
        await g.creator.onRelayEnvelope({ ...pongs[0], sender_id: 'joiner-1' });
        check('creator reports liveness-confirmed',
            g.creatorEvents.some((e) => e.kind === 'liveness-confirmed' && e.senderId === 'joiner-1'));
        check('challenge is cleared after the answer', g.creator._livenessChallenges.size === 0);
        await sleep(30);
        check('no Remove is committed after a confirmed member',
            commitsAfter(g.creatorOut, outBeforePong).length === 0
            && g.creator._leafBySenderId.get('joiner-1') === 1);
        g.creator._clearLivenessChallenges();
    }

    // 3. Silence for the grace window produces the Remove.
    {
        const g = await makeGroup({ livenessGraceMs: 40 });
        const outBefore = g.creatorOut.length;
        await g.creator.requestRemovalAfterLivenessCheck('joiner-1');
        check('no Remove before the grace window elapses',
            commitsAfter(g.creatorOut, outBefore).length === 0);
        await sleep(160);
        const removes = commitsAfter(g.creatorOut, outBefore);
        check('an unanswered challenge times out', g.creatorEvents.some((e) => e.kind === 'liveness-timeout'));
        check('and a Remove Commit candidate is then emitted',
            removes.length === 1 && g.creator._pendingCommit?.kind === 'remove');
        g.creator._clearLivenessChallenges();
    }

    // 4. Ordinary authenticated traffic from the member also cancels it.
    {
        const g = await makeGroup({ livenessGraceMs: 60 });
        await g.creator.requestRemovalAfterLivenessCheck('joiner-1');
        const jb = g.joinerOut.length;
        await g.joiner.sendMessage('still here');
        const msg = privateMessages(g.joinerOut.slice(jb))[0];
        await g.creator.onRelayEnvelope({ ...msg, sender_id: 'joiner-1' });
        check('any authenticated message from the suspected leaf cancels the challenge',
            g.creator._livenessChallenges.size === 0
            && g.creatorEvents.some((e) => e.kind === 'liveness-confirmed'));
        await sleep(120);
        check('no Remove follows once liveness was proven',
            g.creator._leafBySenderId.get('joiner-1') === 1 && g.creator._pendingCommit === null);
        g.creator._clearLivenessChallenges();
    }

    // 5. A duplicate userleft while a challenge is pending is idempotent.
    {
        const g = await makeGroup({ livenessGraceMs: 10000 });
        const outBefore = g.creatorOut.length;
        await g.creator.requestRemovalAfterLivenessCheck('joiner-1');
        await g.creator.requestRemovalAfterLivenessCheck('joiner-1');
        check('repeated departure reports do not send a second ping',
            privateMessages(g.creatorOut.slice(outBefore)).length === 1
            && g.creator._livenessChallenges.size === 1);
        g.creator._clearLivenessChallenges();
    }

    // 6. A ping not from the creator is ignored by members.
    {
        const g = await makeGroup({ livenessGraceMs: 10000 });
        await g.creator.requestRemovalAfterLivenessCheck('joiner-1');
        const ping = privateMessages(g.creatorOut).at(-1);
        // Route the creator's ping as if a different relay id sent it: the
        // MLS sender leaf is what counts, so it is still answered.
        const jb = g.joinerOut.length;
        await g.joiner.onRelayEnvelope({ ...ping, sender_id: 'someone-else' });
        check('relay sender_id spoofing does not change who may ask',
            privateMessages(g.joinerOut.slice(jb)).length === 1);
        g.creator._clearLivenessChallenges();
    }

    console.log(`\nmls-liveness: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => { console.error(err); process.exit(1); });
