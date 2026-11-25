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

async function waitFor(condition, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (!condition() && Date.now() < deadline) await sleep(5);
}

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

/** Admit one more member into a group built by makeGroup. */
async function addJoiner(g, senderId) {
    const out = [];
    const events = [];
    const pins = g.creator.bootstrapPins;
    const session = new MLSSession({
        role: 'joiner',
        send: (envelope) => { out.push(envelope); return true; },
        onEvent: (event) => events.push(event),
        pskSecret: PSK,
        expectedGroupId: pins.groupId,
        expectedCreatorKeyHash: pins.creatorKeyHash,
        relaySenderId: senderId,
    });
    await session.start();
    const creatorBefore = g.creatorOut.length;
    const keyPackage = out.find((e) => e.wire_format === WireFormat.MLS_KEY_PACKAGE);
    await g.creator.onRelayEnvelope({ ...keyPackage, sender_id: senderId });
    const commit = g.creatorOut.slice(creatorBefore)
        .find((e) => e.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    await g.creator.onRelayEnvelope({ ...commit, sender_id: 'creator-self' });
    await g.joiner.onRelayEnvelope({ ...commit, sender_id: 'creator-self' });
    await session.onRelayEnvelope({ ...commit, sender_id: 'creator-self' });
    const welcome = g.creatorOut.slice(creatorBefore)
        .find((e) => e.wire_format === WireFormat.MLS_WELCOME);
    await session.onRelayEnvelope({ ...welcome, sender_id: 'creator-self' });
    assert.strictEqual(session.state, 'joined');
    return { session, out, events };
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

    // 4. M-01: only a pong carrying the challenge's nonce proves presence.
    // Ordinary traffic from the suspected leaf may have been written before
    // the departure and held back, so it does not cancel the challenge, and
    // neither does a pong for some other nonce.
    {
        const g = await makeGroup({ livenessGraceMs: 120 });
        const jb = g.joinerOut.length;
        await g.joiner.sendMessage('written before leaving');
        const early = privateMessages(g.joinerOut.slice(jb))[0];
        await g.creator.requestRemovalAfterLivenessCheck('joiner-1');
        await g.creator.onRelayEnvelope({ ...early, sender_id: 'joiner-1' });
        check('a late ordinary message from the suspected leaf is not a presence proof',
            g.creator._livenessChallenges.size === 1
            && !g.creatorEvents.some((e) => e.kind === 'liveness-confirmed')
            && g.creatorEvents.some((e) => e.kind === 'message'
                && e.text === 'written before leaving'));
        const wrongNonce = new Uint8Array(17);
        wrongNonce[0] = 0x04;
        const jb2 = g.joinerOut.length;
        await g.joiner._serializeOperation(
            () => g.joiner._sendApplicationPayload(wrongNonce),
        );
        const stalePong = privateMessages(g.joinerOut.slice(jb2))[0];
        await g.creator.onRelayEnvelope({ ...stalePong, sender_id: 'joiner-1' });
        check('a pong with another nonce does not cancel the challenge',
            g.creator._livenessChallenges.size === 1);
        await sleep(300);
        check('silence after the ping still ends in a Remove',
            g.creatorEvents.some((e) => e.kind === 'liveness-timeout')
            && g.creator._pendingCommit?.kind === 'remove');
        g.creator._clearLivenessChallenges();
    }

    // 4b. M-07: a ping that never left the tab cannot justify a Remove. The
    // creator retries until the ping is sent and waits a full grace window
    // after that.
    {
        const g = await makeGroup({ livenessGraceMs: 40 });
        const outBefore = g.creatorOut.length;
        g.creator._localCommitBusy = true; // blocks pings like a pending Commit
        await g.creator.requestRemovalAfterLivenessCheck('joiner-1');
        await sleep(200); // several grace windows, every ping blocked
        check('no Remove while every ping attempt was blocked',
            commitsAfter(g.creatorOut, outBefore).length === 0
            && !g.creatorEvents.some((e) => e.kind === 'liveness-timeout')
            && g.creator._livenessChallenges.get('joiner-1')?.pingSent === false
            && privateMessages(g.creatorOut.slice(outBefore)).length === 0);
        g.creator._localCommitBusy = false;
        // The retry armed while blocked fires on its own, sends the ping and
        // arms the next window at this length, long enough that the answer
        // below cannot race it.
        g.creator._livenessGraceMs = 10000;
        const blockedToken = g.creator._livenessChallenges.get('joiner-1')?.armToken;
        await waitFor(
            () => g.creator._livenessChallenges.get('joiner-1')?.pingSent === true,
            5000,
        );
        await g.creator._serializeOperation(async () => {});
        const pings = privateMessages(g.creatorOut.slice(outBefore));
        check('the ping is sent once the creator is free again',
            pings.length === 1
            && g.creator._livenessChallenges.get('joiner-1')?.pingSent === true
            && commitsAfter(g.creatorOut, outBefore).length === 0);
        // A timer that fired before the retry re-armed cannot be called back:
        // its operation still runs, after the ping. It must not take the
        // ping for one the member had a whole window to answer.
        await g.creator._serializeOperation(
            () => g.creator._expireLivenessChallenge('joiner-1', blockedToken),
        );
        check('a timer left from the blocked attempts ends nothing',
            blockedToken !== undefined
            && g.creator._livenessChallenges.get('joiner-1')?.pingSent === true
            && !g.creatorEvents.some((e) => e.kind === 'liveness-timeout')
            && commitsAfter(g.creatorOut, outBefore).length === 0);
        const answeredToken = g.creator._livenessChallenges.get('joiner-1')?.armToken;
        const jb = g.joinerOut.length;
        await g.joiner.onRelayEnvelope({ ...pings[0], sender_id: 'creator-self' });
        const pong = privateMessages(g.joinerOut.slice(jb))[0];
        await g.creator.onRelayEnvelope({ ...pong, sender_id: 'joiner-1' });
        check('the answer to that ping keeps the member',
            g.creator._livenessChallenges.size === 0
            && g.creator._leafBySenderId.get('joiner-1') === 1
            && g.creator._pendingCommit === null);
        // Nor does a timer left from the answered challenge end the next
        // challenge for the same member.
        await g.creator.requestRemovalAfterLivenessCheck('joiner-1');
        const next = g.creator._livenessChallenges.get('joiner-1');
        await g.creator._serializeOperation(
            () => g.creator._expireLivenessChallenge('joiner-1', answeredToken),
        );
        check('a timer left from an answered challenge does not end the next one',
            answeredToken !== undefined
            && next?.pingSent === true
            && g.creator._livenessChallenges.get('joiner-1') === next
            && !g.creatorEvents.some((e) => e.kind === 'liveness-timeout')
            && g.creator._pendingCommit === null);
        g.creator._clearLivenessChallenges();
    }

    // 4c. M-01: a member re-encrypting another member's signed message at
    // that sender's next generations. Every member holds every sender's
    // SecretTree chain, so only the signed generation inside the content
    // stops the copy. The copy is refused, the sender's real next message
    // still decrypts, and the copy cannot answer a liveness challenge.
    {
        const g = await makeGroup({ livenessGraceMs: 80 });
        const mal = await addJoiner(g, 'mallory');
        const { MLS } = global;
        const aLeaf = g.joiner.group.myLeafIndex;
        const jb = g.joinerOut.length;
        await g.joiner.sendMessage('I approve the transfer');
        const original = privateMessages(g.joinerOut.slice(jb))[0];
        const scratch = mal.session.group.forkForPendingCommit();
        const decoded = await MLS.PrivateMessage.decryptPrivateMessage({
            pm: MLS.PrivateMessage.parsePrivateMessage(
                MLS.Codec.base64UrlToBytes(original.payload),
            ),
            senderDataSecret: scratch.epochSecrets.senderDataSecret,
            nLeaves: scratch.nLeaves,
            keyNonceProvider: (l, w, gen) => scratch._chainKeyNonce(l, w, gen),
        });
        scratch.destroySecrets();
        await g.creator.onRelayEnvelope({ ...original, sender_id: 'joiner-1' });
        await mal.session.onRelayEnvelope({ ...original, sender_id: 'joiner-1' });
        const forge = async () => {
            const group = mal.session.group;
            const pm = await MLS.PrivateMessage.encryptPrivateMessage({
                groupId: group.groupId,
                epoch: group.epoch,
                contentType: MLS.Framing.ContentType.APPLICATION,
                authenticatedData: new Uint8Array(0),
                payloadBytes: decoded.content.payloadBytes,
                auth: { signature: decoded.content.auth.signature },
                senderData: {
                    leafIndex: aLeaf,
                    generation: group._chainStates.get(`${aLeaf}:application`).nextGeneration,
                    reuseGuard: new Uint8Array([9, 9, 9, 9]),
                },
                paddingLen: 0,
                senderDataSecret: group.epochSecrets.senderDataSecret,
                nLeaves: group.nLeaves,
                keyNonceProvider: (l, w, gen) => group._chainKeyNonce(l, w, gen),
            });
            return {
                type: 'mls',
                wire_format: WireFormat.MLS_PRIVATE_MESSAGE,
                payload: MLS.Codec.bytesToBase64Url(
                    MLS.PrivateMessage.privateMessageBytes(pm),
                ),
            };
        };
        const messagesBefore = g.creatorEvents.filter((e) => e.kind === 'message').length;
        await g.creator.onRelayEnvelope({ ...(await forge()), sender_id: 'mallory' });
        const shown = g.creatorEvents.filter((e) => e.kind === 'message');
        check('a re-encrypted copy at the next generation is refused',
            shown.length === messagesBefore
            && g.creatorEvents.some((e) => e.kind === 'error'
                && e.reason.includes('signed generation')));
        const jb2 = g.joinerOut.length;
        await g.joiner.sendMessage('WAIT - I revoke that');
        const real = privateMessages(g.joinerOut.slice(jb2))[0];
        await g.creator.onRelayEnvelope({ ...real, sender_id: 'joiner-1' });
        check("the sender's real next message is still accepted",
            g.creatorEvents.filter((e) => e.kind === 'message').at(-1)?.text
                === 'WAIT - I revoke that');
        await g.creator.requestRemovalAfterLivenessCheck('joiner-1');
        await g.creator.onRelayEnvelope({ ...(await forge()), sender_id: 'mallory' });
        check('a forged copy does not answer the liveness challenge',
            g.creator._livenessChallenges.size === 1
            && !g.creatorEvents.some((e) => e.kind === 'liveness-confirmed'));
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
