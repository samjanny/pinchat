#!/usr/bin/env node

/**
 * MLS session orchestration — creator/Joiner Welcome flow.
 *
 * This deliberately exercises MLSSession rather than calling Group join
 * helpers directly. It covers the Commit buffering and committer binding
 * that the browser uses before accepting a Welcome.
 */

const path = require('path');

const MLS_DIR = path.join(__dirname, '..', 'static', 'js', 'mls');

// mls-session.js is browser-oriented and expects the modules to have been
// loaded into self.MLS in the order used by chat.html. Expose the CommonJS
// versions through the same namespace so this test follows the browser path.
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

let passed = 0;
let failed = 0;

function assert(condition, name, detail = '') {
    if (condition) {
        console.log(`  OK   ${name}`);
        passed += 1;
    } else {
        console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
        failed += 1;
    }
}

function equalBytes(a, b) {
    return Buffer.from(a).equals(Buffer.from(b));
}

function bytesTag(bytes) {
    return Buffer.from(bytes || []).toString('base64url');
}

function captureLiveGroup(session) {
    const group = session.group;
    return {
        reference: group,
        epoch: group.epoch,
        nLeaves: group.nLeaves,
        tree: bytesTag(global.MLS.Nodes.ratchetTreeBytes(group.ratchetTree)),
        treeHash: bytesTag(group.treeHash),
        confirmedTranscriptHash: bytesTag(group.confirmedTranscriptHash),
        interimTranscriptHash: bytesTag(group.interimTranscriptHash),
        senderRatchetGeneration: group.senderRatchetGeneration,
        epochSecrets: Object.fromEntries(Object.entries(group.epochSecrets)
            .map(([name, value]) => [name, bytesTag(value)])),
        leafPrivateKey: group.leafKeyPair.privateKey,
        leafPublicKey: group.leafKeyPair.publicKey,
        leafPublicKeyBytes: bytesTag(group.leafKeyPair.publicKeyBytes),
        chainStateCount: group._chainStates.size,
        consumedCount: group.consumedByLeaf.size,
        previousEpoch: group._prevEpoch,
    };
}

function liveGroupMatches(session, before) {
    const after = captureLiveGroup(session);
    return after.reference === before.reference
        && after.epoch === before.epoch
        && after.nLeaves === before.nLeaves
        && after.tree === before.tree
        && after.treeHash === before.treeHash
        && after.confirmedTranscriptHash === before.confirmedTranscriptHash
        && after.interimTranscriptHash === before.interimTranscriptHash
        && after.senderRatchetGeneration === before.senderRatchetGeneration
        && JSON.stringify(after.epochSecrets) === JSON.stringify(before.epochSecrets)
        && after.leafPrivateKey === before.leafPrivateKey
        && after.leafPublicKey === before.leafPublicKey
        && after.leafPublicKeyBytes === before.leafPublicKeyBytes
        && after.chainStateCount === before.chainStateCount
        && after.consumedCount === before.consumedCount
        && after.previousEpoch === before.previousEpoch;
}

function mutateProposalEnvelope(envelope, mutate) {
    const pmBytes = global.MLS.Codec.base64UrlToBytes(envelope.payload);
    const pm = global.MLS.PublicMessage.parsePublicMessage(
        pmBytes,
        (decoder, contentType) => {
            if (contentType !== global.MLS.Framing.ContentType.PROPOSAL) {
                throw new Error(`expected Proposal, got content_type ${contentType}`);
            }
            return global.MLS.Proposal.readProposal(decoder);
        },
    );
    mutate(pm);
    return {
        ...envelope,
        payload: global.MLS.Codec.bytesToBase64Url(
            global.MLS.PublicMessage.publicMessageBytes(pm),
        ),
    };
}

async function rewriteAndResignUpdateEnvelope(session, envelope, mutateLeaf) {
    const pmBytes = global.MLS.Codec.base64UrlToBytes(envelope.payload);
    const pm = global.MLS.PublicMessage.parsePublicMessage(
        pmBytes,
        (decoder, contentType) => {
            if (contentType !== global.MLS.Framing.ContentType.PROPOSAL) {
                throw new Error(`expected Proposal, got content_type ${contentType}`);
            }
            return global.MLS.Proposal.readProposal(decoder);
        },
    );
    const leaf = pm.content.parsed.leafNode;
    mutateLeaf(leaf);
    leaf.signature = await global.MLS.Group.signLeafNodeInCommit(
        session.identity.signaturePrivateKey,
        leaf,
        session.group.groupId,
        session.group.myLeafIndex,
    );
    pm.content.payload = global.MLS.Proposal.proposalBytes(pm.content.parsed);
    const wireFormat = global.MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE;
    pm.auth = {
        signature: await global.MLS.PublicMessage.signFramedContent(
            session.identity.signaturePrivateKey,
            wireFormat,
            pm.content,
            session.group._buildGroupContextStruct(),
        ),
    };
    pm.membershipTag = await global.MLS.PublicMessage.computeMembershipTag(
        session.group.epochSecrets.membershipKey,
        wireFormat,
        pm.content,
        pm.auth,
        session.group._buildGroupContextStruct(),
    );
    return {
        ...envelope,
        payload: global.MLS.Codec.bytesToBase64Url(
            global.MLS.PublicMessage.publicMessageBytes(pm),
        ),
    };
}

function parseCommitEnvelope(envelope) {
    const pmBytes = global.MLS.Codec.base64UrlToBytes(envelope.payload);
    return global.MLS.PublicMessage.parsePublicMessage(
        pmBytes,
        (decoder, contentType) => {
            if (contentType !== global.MLS.Framing.ContentType.COMMIT) {
                throw new Error(`expected Commit, got content_type ${contentType}`);
            }
            return global.MLS.Commit.readCommit(decoder);
        },
    );
}

async function echoPendingCommit(session, envelope, senderId = 'creator-self') {
    await session.onRelayEnvelope({ ...envelope, sender_id: senderId });
}

async function createExchange({ acceptCommit = true, creatorSend = null } = {}) {
    const creatorOut = [];
    const joinerOut = [];
    const creatorEvents = [];
    const joinerEvents = [];
    const creator = new MLSSession({
        role: 'creator',
        send: (envelope) => {
            creatorOut.push(envelope);
            return creatorSend ? creatorSend(envelope) : true;
        },
        onEvent: (event) => creatorEvents.push(event),
    });
    await creator.start();
    const beforeAdd = captureLiveGroup(creator);
    const pins = creator.bootstrapPins;
    const joiner = new MLSSession({
        role: 'joiner',
        send: (envelope) => joinerOut.push(envelope),
        onEvent: (event) => joinerEvents.push(event),
        expectedGroupId: pins.groupId,
        expectedCreatorKeyHash: pins.creatorKeyHash,
    });

    await joiner.start();
    const keyPackage = joinerOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_KEY_PACKAGE,
    );
    await creator.onRelayEnvelope({ ...keyPackage, sender_id: 'joiner-1' });

    const commit = creatorOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE,
    );
    if (acceptCommit && commit) {
        await echoPendingCommit(creator, commit);
    }

    return {
        creator,
        joiner,
        creatorOut,
        joinerOut,
        creatorEvents,
        joinerEvents,
        beforeAdd,
        commit,
        welcome: creatorOut.find(
            (envelope) => envelope.wire_format === WireFormat.MLS_WELCOME,
        ),
    };
}

async function main() {
    console.log('# MLS session — Welcome join orchestration');

    // A locally-authored Add is only a candidate until the relay echoes the
    // exact Commit. Before that ACK, neither the live epoch nor membership
    // maps may change and the Welcome must not be released.
    const exchange = await createExchange({ acceptCommit: false });
    assert(Boolean(exchange.commit), 'creator emitted an Add Commit');
    assert(!exchange.welcome, 'creator withholds Welcome before Commit echo');
    assert(liveGroupMatches(exchange.creator, exchange.beforeAdd),
        'unacknowledged Add leaves live MLS state byte-for-byte unchanged');
    assert(exchange.creator.state === 'awaiting-keypackage'
        && exchange.creator._leafBySenderId.size === 0,
    'unacknowledged Add leaves session membership state unchanged');
    assert(Boolean(exchange.creator._pendingCommit),
        'unacknowledged Add is retained as PendingCommit');
    assert(exchange.creator.shouldHandleOwnEnvelope({
        ...exchange.commit, sender_id: 'creator-self',
    }), 'only the exact pending Commit is recognized as an own-echo ACK');
    const mismatchedPayload = exchange.commit.payload.slice(0, -1)
        + (exchange.commit.payload.endsWith('A') ? 'B' : 'A');
    assert(!exchange.creator.shouldHandleOwnEnvelope({
        ...exchange.commit, payload: mismatchedPayload, sender_id: 'creator-self',
    }), 'non-matching own PublicMessage is not accepted as Commit ACK');

    await echoPendingCommit(exchange.creator, exchange.commit);
    exchange.welcome = exchange.creatorOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_WELCOME,
    );
    assert(Boolean(exchange.welcome), 'creator emitted a Welcome');
    assert(exchange.creator._pendingCommit === null,
        'Commit echo atomically clears PendingCommit');
    assert(exchange.creator.group.epoch === exchange.beforeAdd.epoch + 1n,
        'Commit echo atomically installs candidate epoch');

    // WebSocketManager reports a synchronous send rejection with `false`.
    // The candidate must be discarded without changing the live Group or
    // consuming the sender-to-leaf binding.
    const sendFailure = await createExchange({
        acceptCommit: false,
        creatorSend: (envelope) => (
            envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE ? false : true
        ),
    });
    assert(Boolean(sendFailure.commit) && !sendFailure.welcome,
        'transport-rejected Add emits neither an accepted Commit nor Welcome');
    assert(liveGroupMatches(sendFailure.creator, sendFailure.beforeAdd),
        'transport-rejected Add leaves live MLS state byte-for-byte unchanged');
    assert(sendFailure.creator._pendingCommit === null
        && sendFailure.creator._leafBySenderId.size === 0,
    'transport-rejected Add clears candidate and preserves membership maps');
    const sendFailureError = sendFailure.creatorEvents.find(
        (event) => event.kind === 'error'
            && event.reason.includes('transport rejected envelope'),
    );
    assert(Boolean(sendFailureError),
        'transport-rejected Commit surfaces a fail-closed error');

    // app.js reports userleft without awaiting the Remove promise. If that
    // races an already-pending local Commit, retain the revocation request
    // and stage it immediately after the first Commit is accepted.
    const removalRace = await createExchange();
    const removalRaceOutBefore = removalRace.creatorOut.length;
    await removalRace.creator.commitUpdate();
    const racingUpdate = removalRace.creatorOut
        .slice(removalRaceOutBefore)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    await removalRace.creator.removeMemberBySenderId('joiner-1');
    assert(removalRace.creator._deferredRemovals.has('joiner-1'),
        'Remove racing a PendingCommit is retained rather than dropped');
    await echoPendingCommit(removalRace.creator, racingUpdate, 'creator-race-self');
    const racingPublicMessages = removalRace.creatorOut
        .slice(removalRaceOutBefore)
        .filter((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    const deferredRemoveCommit = racingPublicMessages[1];
    assert(Boolean(deferredRemoveCommit)
        && removalRace.creator._pendingCommit?.kind === 'remove',
    'deferred Remove is staged after preceding Commit acceptance');
    await echoPendingCommit(
        removalRace.creator, deferredRemoveCommit, 'creator-race-self',
    );
    assert(!removalRace.creator._leafBySenderId.has('joiner-1'),
        'deferred Remove applies after its own relay echo');

    await exchange.joiner.onRelayEnvelope({
        ...exchange.commit,
        sender_id: 'creator-1',
    });
    await exchange.joiner.onRelayEnvelope({
        ...exchange.welcome,
        sender_id: 'creator-1',
    });

    assert(exchange.joiner.state === 'joined', 'joiner reaches joined state');
    assert(exchange.joiner.group.epoch === exchange.creator.group.epoch,
        'creator and joiner are in the same epoch');
    assert(equalBytes(
        exchange.joiner.group.epochSecrets.encryptionSecret,
        exchange.creator.group.epochSecrets.encryptionSecret,
    ), 'creator and joiner share encryption_secret');
    assert(exchange.joinerEvents.some((event) => event.kind === 'joined'),
        'joiner emits authenticated joined event');

    // Exercise the steady-state browser path after the Welcome.  This is
    // intentionally routed through MLSSession.onRelayEnvelope: Group-level
    // tests do not cover the PublicMessage body parser used for dispatch.
    const epochBeforeCreatorUpdate = exchange.creator.group.epoch;
    const stateBeforeCreatorUpdate = captureLiveGroup(exchange.creator);
    const creatorOutBeforeUpdate = exchange.creatorOut.length;
    await exchange.creator.commitUpdate();
    const creatorUpdateCommit = exchange.creatorOut
        .slice(creatorOutBeforeUpdate)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    assert(Boolean(creatorUpdateCommit),
        'creator emits a steady-state Update Commit after join');
    assert(exchange.creator.group.epoch === epochBeforeCreatorUpdate,
        'steady-state Update remains pending before its relay echo');
    assert(liveGroupMatches(exchange.creator, stateBeforeCreatorUpdate),
        'pending steady-state Update leaves live tree and secrets unchanged');

    // A peer may send under the old epoch while our Commit is in flight.
    // Queue it without touching the live receive ratchet; once the Commit is
    // accepted, the candidate's previous-epoch grace context decrypts it.
    const joinerOutBeforeInFlight = exchange.joinerOut.length;
    const creatorEventsBeforeInFlight = exchange.creatorEvents.length;
    await exchange.joiner.sendMessage('old-epoch in flight');
    const inFlightApplication = exchange.joinerOut
        .slice(joinerOutBeforeInFlight)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PRIVATE_MESSAGE);
    await exchange.creator.onRelayEnvelope({
        ...inFlightApplication,
        sender_id: 'joiner-1',
    });
    assert(exchange.creator._deferredEnvelopes.length === 1
        && !exchange.creatorEvents.slice(creatorEventsBeforeInFlight)
            .some((event) => event.kind === 'message'),
    'peer traffic is deferred without ratchet mutation while Commit is pending');
    await echoPendingCommit(exchange.creator, creatorUpdateCommit);
    assert(exchange.creatorEvents.slice(creatorEventsBeforeInFlight).some(
        (event) => event.kind === 'message' && event.text === 'old-epoch in flight',
    ), 'deferred old-epoch traffic decrypts after atomic Commit acceptance');
    await exchange.joiner.onRelayEnvelope({
        ...creatorUpdateCommit,
        sender_id: 'creator-1',
    });
    assert(exchange.creator.group.epoch === epochBeforeCreatorUpdate + 1n,
        'creator advances for steady-state Update Commit');
    assert(exchange.joiner.group.epoch === exchange.creator.group.epoch,
        'joiner applies steady-state Commit through MLSSession');
    assert(equalBytes(
        exchange.joiner.group.epochSecrets.encryptionSecret,
        exchange.creator.group.epochSecrets.encryptionSecret,
    ), 'steady-state Commit keeps creator and joiner secrets aligned');
    assert(exchange.joinerEvents.some((event) => event.kind === 'commit-applied'),
        'joiner emits commit-applied for post-join Commit');

    // Exercise the Proposal branch of the same router.  The joiner publishes
    // an Update proposal, the creator buffers it, and the next creator Commit
    // folds it in.  Delivering that Commit also verifies that the pending
    // self-update keypair is activated on the joiner.
    const joinerOutBeforeProposal = exchange.joinerOut.length;
    await exchange.joiner.proposeUpdate();
    const updateProposal = exchange.joinerOut
        .slice(joinerOutBeforeProposal)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    assert(Boolean(updateProposal), 'joiner emits a standalone Update proposal');

    // A valid inner LeafNode signature is not enough to authenticate a
    // standalone proposal. Tampering either outer authenticator must reject
    // the proposal before it reaches the creator's pending-Update buffer.
    const badSignatureProposal = mutateProposalEnvelope(updateProposal, (pm) => {
        pm.auth.signature = Uint8Array.from(pm.auth.signature);
        pm.auth.signature[0] ^= 0x01;
    });
    const signatureEventsBefore = exchange.creatorEvents.length;
    await exchange.creator.onRelayEnvelope({
        ...badSignatureProposal,
        sender_id: 'joiner-1',
    });
    const signatureError = exchange.creatorEvents
        .slice(signatureEventsBefore)
        .find((event) => event.kind === 'error');
    assert(
        Boolean(signatureError)
            && signatureError.reason.includes('FramedContent signature invalid'),
        'tampered Update FramedContent signature is rejected',
        signatureError ? signatureError.reason : 'no error event',
    );
    assert(exchange.creator._pendingUpdateProposals.size === 0,
        'signature-invalid Update is never buffered');

    const badMembershipProposal = mutateProposalEnvelope(updateProposal, (pm) => {
        pm.membershipTag = Uint8Array.from(pm.membershipTag);
        pm.membershipTag[0] ^= 0x01;
    });
    const membershipEventsBefore = exchange.creatorEvents.length;
    await exchange.creator.onRelayEnvelope({
        ...badMembershipProposal,
        sender_id: 'joiner-1',
    });
    const membershipError = exchange.creatorEvents
        .slice(membershipEventsBefore)
        .find((event) => event.kind === 'error');
    assert(
        Boolean(membershipError)
            && membershipError.reason.includes('membership_tag invalid'),
        'tampered Update membership_tag is rejected',
        membershipError ? membershipError.reason : 'no error event',
    );
    assert(exchange.creator._pendingUpdateProposals.size === 0,
        'membership-invalid Update is never buffered');

    // Even a completely re-signed proposal is invalid if it does not rotate
    // the sender's leaf key or if it collides with another live tree key.
    const joinerCurrentLeaf = global.MLS.RatchetTree.leafFor(
        exchange.joiner.group.ratchetTree,
        exchange.joiner.group.myLeafIndex,
    );
    const reusedLeafKeyProposal = await rewriteAndResignUpdateEnvelope(
        exchange.joiner,
        updateProposal,
        (leaf) => {
            leaf.encryptionKey = Uint8Array.from(joinerCurrentLeaf.encryptionKey);
        },
    );
    const reusedKeyEventsBefore = exchange.creatorEvents.length;
    await exchange.creator.onRelayEnvelope({
        ...reusedLeafKeyProposal,
        sender_id: 'joiner-1',
    });
    const reusedKeyError = exchange.creatorEvents
        .slice(reusedKeyEventsBefore)
        .find((event) => event.kind === 'error');
    assert(
        Boolean(reusedKeyError)
            && reusedKeyError.reason.includes('must differ from the current leaf'),
        'authenticated Update that reuses current leaf key is rejected',
        reusedKeyError ? reusedKeyError.reason : 'no error event',
    );
    assert(exchange.creator._pendingUpdateProposals.size === 0,
        'non-rotating authenticated Update is never buffered');

    const creatorCurrentLeaf = global.MLS.RatchetTree.leafFor(
        exchange.creator.group.ratchetTree,
        exchange.creator.group.myLeafIndex,
    );
    const collidingLeafKeyProposal = await rewriteAndResignUpdateEnvelope(
        exchange.joiner,
        updateProposal,
        (leaf) => {
            leaf.encryptionKey = Uint8Array.from(creatorCurrentLeaf.encryptionKey);
        },
    );
    const collisionEventsBefore = exchange.creatorEvents.length;
    await exchange.creator.onRelayEnvelope({
        ...collidingLeafKeyProposal,
        sender_id: 'joiner-1',
    });
    const collisionError = exchange.creatorEvents
        .slice(collisionEventsBefore)
        .find((event) => event.kind === 'error');
    assert(
        Boolean(collisionError)
            && collisionError.reason.includes('duplicate encryption_key'),
        'authenticated Update with colliding tree key is rejected',
        collisionError ? collisionError.reason : 'no error event',
    );
    assert(exchange.creator._pendingUpdateProposals.size === 0,
        'key-colliding authenticated Update is never buffered');

    await exchange.creator.onRelayEnvelope({
        ...updateProposal,
        sender_id: 'joiner-1',
    });
    assert(exchange.creatorEvents.some(
        (event) => event.kind === 'update-proposal-received'
            && event.senderLeafIndex === 1,
    ), 'creator parses and buffers member Update proposal through MLSSession');

    const creatorOutBeforeFold = exchange.creatorOut.length;
    await exchange.creator.commitUpdate();
    const foldedUpdateCommit = exchange.creatorOut
        .slice(creatorOutBeforeFold)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    assert(Boolean(foldedUpdateCommit), 'creator emits Commit containing member Update');
    assert(exchange.creator._pendingUpdateProposals.size === 1,
        'folded Update stays queued until Commit acceptance');
    await echoPendingCommit(exchange.creator, foldedUpdateCommit);
    await exchange.joiner.onRelayEnvelope({
        ...foldedUpdateCommit,
        sender_id: 'creator-1',
    });
    assert(exchange.joiner.group.epoch === exchange.creator.group.epoch,
        'joiner applies Commit containing its Update proposal');
    assert(equalBytes(
        exchange.joiner.group.epochSecrets.encryptionSecret,
        exchange.creator.group.epochSecrets.encryptionSecret,
    ), 'folded Update keeps creator and joiner secrets aligned');
    assert(exchange.joiner._pendingSelfUpdate === null,
        'joiner activates and clears pending self-update after Commit');

    // The LeafNode signature does not contain the epoch. Replaying this
    // once-valid proposal after the Commit would therefore roll the member
    // back to its previous HPKE key unless the outer PublicMessage epoch and
    // authenticators are checked before buffering.
    const replayEventsBefore = exchange.creatorEvents.length;
    await exchange.creator.onRelayEnvelope({
        ...updateProposal,
        sender_id: 'joiner-1',
    });
    const replayError = exchange.creatorEvents
        .slice(replayEventsBefore)
        .find((event) => event.kind === 'error');
    assert(Boolean(replayError) && replayError.reason.includes('wrong epoch'),
        'previous-epoch Update proposal replay is rejected',
        replayError ? replayError.reason : 'no error event');
    assert(exchange.creator._pendingUpdateProposals.size === 0,
        'replayed Update is never buffered');

    const creatorOutBeforeReplayGuard = exchange.creatorOut.length;
    await exchange.creator.commitUpdate();
    const replayGuardCommit = exchange.creatorOut
        .slice(creatorOutBeforeReplayGuard)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    const replayGuardPm = parseCommitEnvelope(replayGuardCommit);
    assert(replayGuardPm.content.parsed.proposals.length === 0,
        'next Commit does not include the rejected replay');
    await echoPendingCommit(exchange.creator, replayGuardCommit);
    await exchange.joiner.onRelayEnvelope({
        ...replayGuardCommit,
        sender_id: 'creator-1',
    });
    assert(exchange.joiner.group.epoch === exchange.creator.group.epoch,
        'replay-guard path-only Commit keeps members aligned');

    // Remove follows the same PendingCommit path: keep both the MLS state
    // and sender/leaf routing intact until the exact relay echo arrives.
    const stateBeforeRemove = captureLiveGroup(exchange.creator);
    const creatorOutBeforeRemove = exchange.creatorOut.length;
    await exchange.creator.removeMemberBySenderId('joiner-1');
    const removeCommit = exchange.creatorOut
        .slice(creatorOutBeforeRemove)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    assert(Boolean(removeCommit), 'creator emits a Remove Commit candidate');
    assert(liveGroupMatches(exchange.creator, stateBeforeRemove)
        && exchange.creator._leafBySenderId.get('joiner-1') === 1,
    'unacknowledged Remove preserves MLS state and member routing');
    await echoPendingCommit(exchange.creator, removeCommit);
    assert(exchange.creator.group.epoch === stateBeforeRemove.epoch + 1n
        && !exchange.creator._leafBySenderId.has('joiner-1')
        && !exchange.creator._senderIdByLeaf.has(1),
    'Remove applies atomically and clears routing only after Commit echo');

    // Also cover a proposal that was valid when received but sat in the
    // queue while some other local Commit advanced the creator. Its outer
    // authentication already succeeded, so the queue must retain and check
    // that authenticated epoch at fold time rather than trusting the still-
    // valid inner LeafNode signature.
    const queuedExchange = await createExchange();
    await queuedExchange.joiner.onRelayEnvelope({
        ...queuedExchange.commit,
        sender_id: 'creator-queued',
    });
    await queuedExchange.joiner.onRelayEnvelope({
        ...queuedExchange.welcome,
        sender_id: 'creator-queued',
    });
    const queuedJoinerOutBefore = queuedExchange.joinerOut.length;
    await queuedExchange.joiner.proposeUpdate();
    const queuedProposal = queuedExchange.joinerOut
        .slice(queuedJoinerOutBefore)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    await queuedExchange.creator.onRelayEnvelope({
        ...queuedProposal,
        sender_id: 'joiner-1',
    });
    assert(queuedExchange.creator._pendingUpdateProposals.size === 1,
        'current-epoch Update is buffered before an intervening Commit');
    const queuedEpoch = queuedExchange.creator.group.epoch;
    await queuedExchange.creator.group.commitUpdate();
    assert(queuedExchange.creator.group.epoch === queuedEpoch + 1n,
        'intervening local Commit advances beyond buffered proposal epoch');
    const queuedCreatorOutBefore = queuedExchange.creatorOut.length;
    await queuedExchange.creator.commitUpdate();
    const staleQueueGuardCommit = queuedExchange.creatorOut
        .slice(queuedCreatorOutBefore)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    const staleQueueGuardPm = parseCommitEnvelope(staleQueueGuardCommit);
    assert(staleQueueGuardPm.content.parsed.proposals.length === 0,
        'previously validated but now stale Update is not folded');
    assert(queuedExchange.creator._pendingUpdateProposals.size === 1,
        'stale queued Update remains until replacement Commit is accepted');
    await echoPendingCommit(queuedExchange.creator, staleQueueGuardCommit,
        'creator-queued-self');
    assert(queuedExchange.creator._pendingUpdateProposals.size === 0,
        'stale authenticated Update is removed from the queue');

    const noCommitExchange = await createExchange();
    let noCommitError = '';
    try {
        await noCommitExchange.joiner.onRelayEnvelope({
            ...noCommitExchange.welcome,
            sender_id: 'creator-2',
        });
    } catch (err) {
        noCommitError = err.message;
    }
    assert(
        noCommitError.includes('without a buffered Commit'),
        'Welcome without buffered Commit is rejected fail-closed',
        noCommitError,
    );
    assert(noCommitExchange.joiner.state === 'awaiting-welcome',
        'failed Welcome does not advance joiner state');

    // Creator-centric policy must also hold before Group.join is entered.
    // First establish a real leaf-1 member, then let that member construct an
    // otherwise valid Add + Welcome for a fresh session.  The buffered Commit
    // is authentic and GroupInfo.signer matches it, but neither is leaf 0.
    const unauthorizedExchange = await createExchange();
    await unauthorizedExchange.joiner.onRelayEnvelope({
        ...unauthorizedExchange.commit,
        sender_id: 'creator-3',
    });
    await unauthorizedExchange.joiner.onRelayEnvelope({
        ...unauthorizedExchange.welcome,
        sender_id: 'creator-3',
    });
    const targetOut = [];
    const targetEvents = [];
    const target = new MLSSession({
        role: 'joiner',
        send: (envelope) => targetOut.push(envelope),
        onEvent: (event) => targetEvents.push(event),
        expectedGroupId: unauthorizedExchange.creator.bootstrapPins.groupId,
        expectedCreatorKeyHash:
            unauthorizedExchange.creator.bootstrapPins.creatorKeyHash,
    });
    await target.start();
    const unauthorized = await unauthorizedExchange.joiner.group.commitAddMember({
        keyPackageBytes: target.keyPackageBundle.keyPackageBytes,
    });
    const unauthorizedCommitBody = global.MLS.MLSMessage.parseMLSMessage(
        unauthorized.commitMessage,
    ).body;
    const unauthorizedWelcomeBody = global.MLS.MLSMessage.parseMLSMessage(
        unauthorized.welcomeMessage,
    ).body;
    await target.onRelayEnvelope({
        type: 'mls',
        payload: global.MLS.Codec.bytesToBase64Url(unauthorizedCommitBody),
        wire_format: WireFormat.MLS_PUBLIC_MESSAGE,
        sender_id: 'non-creator-1',
    });
    let nonCreatorError = '';
    try {
        await target.onRelayEnvelope({
            type: 'mls',
            payload: global.MLS.Codec.bytesToBase64Url(unauthorizedWelcomeBody),
            wire_format: WireFormat.MLS_WELCOME,
            ratchet_tree: global.MLS.Codec.bytesToBase64Url(
                global.MLS.Nodes.ratchetTreeBytes(
                    unauthorizedExchange.joiner.group.ratchetTree,
                ),
            ),
            sender_id: 'non-creator-1',
        });
    } catch (err) {
        nonCreatorError = err.message;
    }
    assert(
        nonCreatorError.includes('only creator leaf 0 may commit a Welcome epoch'),
        'MLSSession rejects Welcome paired with non-creator Commit',
        nonCreatorError,
    );
    assert(target.state === 'awaiting-welcome' && target.group === null,
        'non-creator Welcome leaves target unjoined');
    assert(target._pendingCommitBytes === null,
        'rejected non-creator Welcome clears buffered Commit');

    // A PSK alone is insufficient to identify the intended MLS group. A
    // joiner with an old/bare link must fail before publishing a KeyPackage.
    const unpinnedOut = [];
    const unpinned = new MLSSession({
        role: 'joiner',
        send: (envelope) => unpinnedOut.push(envelope),
        onEvent: () => {},
    });
    let missingPinsError = '';
    try {
        await unpinned.start();
    } catch (err) {
        missingPinsError = err.message;
    }
    assert(missingPinsError.includes('missing authenticated group_id / creator-key pins'),
        'joiner without bootstrap pins fails closed before handshake', missingPinsError);
    assert(unpinned.state === 'idle' && unpinnedOut.length === 0,
        'unpinned joiner does not publish a KeyPackage');

    // Model a party that knows the same PSK but starts a fresh MLS group with
    // itself as leaf 0. The Commit and Welcome are internally valid and pass
    // the creator-only index rule, but the trusted creator's group_id pin must
    // keep the victim out of the alternative group.
    const trustedCreator = new MLSSession({
        role: 'creator', send: () => {}, onEvent: () => {},
    });
    await trustedCreator.start();
    const attackerOut = [];
    const alternateCreator = new MLSSession({
        role: 'creator',
        send: (envelope) => attackerOut.push(envelope),
        onEvent: () => {},
    });
    await alternateCreator.start();
    const victimOut = [];
    const victim = new MLSSession({
        role: 'joiner',
        send: (envelope) => victimOut.push(envelope),
        onEvent: () => {},
        expectedGroupId: trustedCreator.bootstrapPins.groupId,
        expectedCreatorKeyHash: trustedCreator.bootstrapPins.creatorKeyHash,
    });
    await victim.start();
    const victimKeyPackage = victimOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_KEY_PACKAGE,
    );
    await alternateCreator.onRelayEnvelope({
        ...victimKeyPackage,
        sender_id: 'alternate-creator',
    });
    const alternateCommit = attackerOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE,
    );
    await echoPendingCommit(
        alternateCreator, alternateCommit, 'alternate-creator-self',
    );
    const alternateWelcome = attackerOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_WELCOME,
    );
    await victim.onRelayEnvelope({
        ...alternateCommit,
        sender_id: 'alternate-creator',
    });
    let alternateGroupError = '';
    try {
        await victim.onRelayEnvelope({
            ...alternateWelcome,
            sender_id: 'alternate-creator',
        });
    } catch (err) {
        alternateGroupError = err.message;
    }
    assert(alternateGroupError.includes('group_id does not match invite bootstrap pin'),
        'same-PSK alternative group is rejected by group_id pin', alternateGroupError);
    assert(victim.state === 'awaiting-welcome' && victim.group === null,
        'alternative-group Welcome leaves victim unjoined');

    console.log('');
    console.log(`mls-session-join: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
