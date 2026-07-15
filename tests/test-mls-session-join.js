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

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((res, rej) => {
        resolve = res;
        reject = rej;
    });
    return { promise, resolve, reject };
}

async function signatureKeyFingerprint(group, leafIndex) {
    const leaf = global.MLS.RatchetTree.leafFor(
        group.ratchetTree, leafIndex,
    );
    const digest = await global.MLS.Labeled.sha256(leaf.signatureKey);
    return Buffer.from(digest).toString('hex');
}

function latestRoster(events) {
    return events.filter((event) => event.kind === 'roster').at(-1);
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

function collectGroupSecretRefs(group) {
    const refs = [
        ...Object.values(group.epochSecrets || {}),
        group.pskSecret,
    ];
    const collectChains = (chainStates) => {
        if (!(chainStates instanceof Map)) return;
        for (const state of chainStates.values()) {
            refs.push(state.secret);
            for (const value of state.skipped.values()) {
                refs.push(value.key, value.nonce);
            }
        }
    };
    collectChains(group._chainStates);
    if (group._prevEpoch) {
        refs.push(group._prevEpoch.senderDataSecret);
        collectChains(group._prevEpoch.chainStates);
    }
    return refs.filter((value) => value instanceof Uint8Array);
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

async function rewriteCommitEnvelope(session, envelope, rewriteCommit) {
    const pm = parseCommitEnvelope(envelope);
    const rewrittenCommit = rewriteCommit(pm.content.parsed);
    const content = {
        ...pm.content,
        payload: global.MLS.Commit.commitBytes(rewrittenCommit),
        parsed: rewrittenCommit,
    };
    const wireFormat = global.MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE;
    const groupContext = session.group._buildGroupContextStruct();
    const auth = {
        ...pm.auth,
        signature: await global.MLS.PublicMessage.signFramedContent(
            session.identity.signaturePrivateKey,
            wireFormat,
            content,
            groupContext,
        ),
    };
    const membershipTag = await global.MLS.PublicMessage.computeMembershipTag(
        session.group.epochSecrets.membershipKey,
        wireFormat,
        content,
        auth,
        groupContext,
    );
    const body = global.MLS.PublicMessage.publicMessageBytes({
        content, auth, membershipTag,
    });
    return {
        ...envelope,
        payload: global.MLS.Codec.bytesToBase64Url(body),
        commit_ref: global.MLS.Codec.bytesToBase64Url(
            await global.MLS.Labeled.sha256(body),
        ),
    };
}

async function rewriteCommitEnvelopeProposalList(session, envelope, proposalOrRefs) {
    return rewriteCommitEnvelope(session, envelope, (commit) => ({
        ...commit,
        proposals: proposalOrRefs,
    }));
}

async function echoPendingCommit(session, envelope, senderId = 'creator-self') {
    await session.onRelayEnvelope({ ...envelope, sender_id: senderId });
}

async function completeExchangeJoin(exchange, senderId = 'creator-test') {
    await exchange.joiner.onRelayEnvelope({
        ...exchange.commit,
        sender_id: senderId,
    });
    await exchange.joiner.onRelayEnvelope({
        ...exchange.welcome,
        sender_id: senderId,
    });
}

async function createExchange({
    acceptCommit = true, creatorSend = null, pskSecret = null,
} = {}) {
    const creatorOut = [];
    const joinerOut = [];
    const creatorEvents = [];
    const joinerEvents = [];
    const creator = new MLSSession({
        role: 'creator',
        send: (envelope) => {
            creatorOut.push(envelope);
            return creatorSend ? creatorSend(envelope, creator) : true;
        },
        onEvent: (event) => creatorEvents.push(event),
        pskSecret,
    });
    await creator.start();
    const beforeAdd = captureLiveGroup(creator);
    const pins = creator.bootstrapPins;
    const joiner = new MLSSession({
        role: 'joiner',
        send: (envelope) => joinerOut.push(envelope),
        onEvent: (event) => joinerEvents.push(event),
        pskSecret,
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
    const exchange = await createExchange({
        acceptCommit: false,
        pskSecret: new Uint8Array(32).fill(0x4d),
    });
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

    const supersededGroup = exchange.beforeAdd.reference;
    const supersededSecretRefs = [
        ...Object.values(supersededGroup.epochSecrets),
        ...[...supersededGroup._chainStates.values()].map((state) => state.secret),
    ].filter((value) => value instanceof Uint8Array);
    await echoPendingCommit(exchange.creator, exchange.commit);
    exchange.welcome = exchange.creatorOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_WELCOME,
    );
    assert(Boolean(exchange.welcome), 'creator emitted a Welcome');
    assert(typeof exchange.commit.key_package_ref === 'string'
        && exchange.commit.key_package_ref === exchange.welcome.key_package_ref
        && exchange.commit.key_package_ref === exchange.joiner._keyPackageRef,
    'Add Commit and Welcome carry the joiner KeyPackageRef');
    assert(typeof exchange.commit.commit_ref === 'string'
        && exchange.commit.commit_ref === exchange.welcome.commit_ref,
    'Add Commit and Welcome carry the same payload-derived commit_ref');
    assert(exchange.creator._pendingCommit === null,
        'Commit echo atomically clears PendingCommit');
    assert(exchange.creator.group.epoch === exchange.beforeAdd.epoch + 1n,
        'Commit echo atomically installs candidate epoch');
    assert(Object.keys(supersededGroup.epochSecrets).length === 0
        && supersededGroup._chainStates.size === 0
        && supersededSecretRefs.every((bytes) => bytes.every((byte) => byte === 0)),
    'accepted PendingCommit erases the superseded Group secret copy');

    // WebSocketManager reports a synchronous send rejection with `false`.
    // The candidate must be discarded without changing the live Group or
    // consuming the sender-to-leaf binding.
    let rejectedCandidate = null;
    let rejectedCandidateSecretRefs = [];
    const sendFailure = await createExchange({
        acceptCommit: false,
        creatorSend: (envelope, creator) => {
            if (envelope.wire_format !== WireFormat.MLS_PUBLIC_MESSAGE) return true;
            rejectedCandidate = creator._pendingCommit.candidateGroup;
            rejectedCandidateSecretRefs = [
                ...Object.values(rejectedCandidate.epochSecrets),
                ...[...rejectedCandidate._chainStates.values()]
                    .map((state) => state.secret),
                ...(rejectedCandidate._prevEpoch
                    ? [rejectedCandidate._prevEpoch.senderDataSecret,
                        ...[...rejectedCandidate._prevEpoch.chainStates.values()]
                            .map((state) => state.secret)]
                    : []),
            ].filter((value) => value instanceof Uint8Array);
            return false;
        },
    });
    assert(Boolean(sendFailure.commit) && !sendFailure.welcome,
        'transport-rejected Add emits neither an accepted Commit nor Welcome');
    assert(liveGroupMatches(sendFailure.creator, sendFailure.beforeAdd),
        'transport-rejected Add leaves live MLS state byte-for-byte unchanged');
    assert(sendFailure.creator._pendingCommit === null
        && sendFailure.creator._leafBySenderId.size === 0,
    'transport-rejected Add clears candidate and preserves membership maps');
    assert(rejectedCandidate
        && Object.keys(rejectedCandidate.epochSecrets).length === 0
        && rejectedCandidate._chainStates.size === 0
        && rejectedCandidate._prevEpoch === null
        && rejectedCandidateSecretRefs.every(
            (bytes) => bytes.every((byte) => byte === 0),
        ),
    'transport rejection erases all speculative candidate secrets');
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

    const unrelatedRef = global.MLS.Codec.bytesToBase64Url(
        new Uint8Array(32).fill(0x5a),
    );
    await exchange.joiner.onRelayEnvelope({
        ...exchange.commit,
        key_package_ref: unrelatedRef,
        sender_id: 'creator-1',
    });
    assert(exchange.joiner._pendingWelcomeCommits.size === 0,
        'Add Commit for another KeyPackage does not occupy the join buffer');

    let badCommitRefError = '';
    try {
        await exchange.joiner.onRelayEnvelope({
            ...exchange.commit,
            commit_ref: unrelatedRef,
            sender_id: 'creator-1',
        });
    } catch (err) {
        badCommitRefError = err.message;
    }
    assert(badCommitRefError.includes('does not match PublicMessage payload')
        && exchange.joiner._pendingWelcomeCommits.size === 0,
    'mismatched commit_ref is rejected before buffering');

    await exchange.joiner.onRelayEnvelope({
        ...exchange.commit,
        sender_id: 'creator-1',
    });
    assert(exchange.joiner._pendingWelcomeCommits.size === 1,
        'matching Add Commit is buffered by commit_ref');
    await exchange.joiner.onRelayEnvelope({
        ...exchange.welcome,
        key_package_ref: unrelatedRef,
        sender_id: 'creator-1',
    });
    assert(exchange.joiner.state === 'awaiting-welcome'
        && exchange.joiner._pendingWelcomeCommits.size === 1,
    'unrelated Welcome neither joins nor consumes matching Commit');

    let wrongWelcomeRefError = '';
    try {
        await exchange.joiner.onRelayEnvelope({
            ...exchange.welcome,
            commit_ref: unrelatedRef,
            sender_id: 'creator-1',
        });
    } catch (err) {
        wrongWelcomeRefError = err.message;
    }
    assert(wrongWelcomeRefError.includes('without its matching buffered Commit')
        && exchange.joiner._pendingWelcomeCommits.size === 1,
    'Welcome with wrong commit_ref is rejected without consuming candidate');

    // The GroupInfo epoch must be the direct successor of the exact buffered
    // Commit epoch. Exercise the fail-closed join boundary and then restore
    // the test fixture to prove that a rejected attempt did not consume it.
    const correlatedCandidate = exchange.joiner._pendingWelcomeCommits
        .get(exchange.commit.commit_ref);
    const correlatedEpoch = correlatedCandidate.epoch;
    correlatedCandidate.epoch += 1n;
    let skippedEpochError = '';
    try {
        await exchange.joiner.onRelayEnvelope({
            ...exchange.welcome,
            sender_id: 'creator-1',
        });
    } catch (err) {
        skippedEpochError = err.message;
    }
    assert(skippedEpochError.includes(
        'Welcome epoch does not immediately follow correlated Commit epoch',
    ) && exchange.joiner.state === 'awaiting-welcome'
        && exchange.joiner.group === null
        && exchange.joiner._pendingWelcomeCommits.size === 1,
    'Welcome with a non-successor epoch is rejected without consuming candidate');
    correlatedCandidate.epoch = correlatedEpoch;

    const consumedBootstrapBundle = exchange.joiner.keyPackageBundle;
    const consumedKeyPackageRefBytes = exchange.joiner._keyPackageRefBytes;
    await exchange.joiner.onRelayEnvelope({
        ...exchange.welcome,
        sender_id: 'creator-1',
    });

    assert(exchange.joiner.state === 'joined', 'joiner reaches joined state');
    assert(exchange.joiner._pendingWelcomeCommits.size === 0,
        'successful join clears obsolete Welcome correlation state');
    assert(exchange.joiner.keyPackageBundle === null
        && exchange.joiner._keyPackageRefBytes === null
        && exchange.joiner._keyPackageRef === null
        && consumedKeyPackageRefBytes.every((byte) => byte === 0),
    'successful join releases one-shot init-key bundle and wipes lookup reference');
    assert(consumedBootstrapBundle.initKeyPair.privateKey.extractable === false
        && exchange.joiner.group.identity.signaturePrivateKey.extractable === false
        && exchange.joiner.group.leafKeyPair.privateKey.extractable === false,
    'joined state retains only required non-extractable member key handles');
    assert(exchange.joiner.group.epoch === exchange.creator.group.epoch,
        'creator and joiner are in the same epoch');
    assert(equalBytes(
        exchange.joiner.group.epochSecrets.epochAuthenticator,
        exchange.creator.group.epochSecrets.epochAuthenticator,
    ), 'creator and joiner share epoch_authenticator');
    assert(exchange.joinerEvents.some((event) => event.kind === 'joined'),
        'joiner emits authenticated joined event');

    // Visual identity must come exclusively from each authenticated
    // LeafNode.signature_key. Relay sender_id values are routing metadata and
    // may neither name roster entries nor application messages.
    const creatorFingerprint = await signatureKeyFingerprint(
        exchange.joiner.group, 0,
    );
    const joinerFingerprint = await signatureKeyFingerprint(
        exchange.joiner.group, 1,
    );
    const creatorRoster = latestRoster(exchange.creatorEvents);
    const joinerRoster = latestRoster(exchange.joinerEvents);
    assert(creatorRoster && joinerRoster
        && creatorRoster.members.length === 2
        && joinerRoster.members.length === 2,
    'creator and joiner emit complete authenticated two-member rosters');
    assert(creatorRoster.members.map((member) => member.fingerprint).join(',')
        === joinerRoster.members.map((member) => member.fingerprint).join(',')
        && creatorRoster.members[0].fingerprint === creatorFingerprint
        && creatorRoster.members[1].fingerprint === joinerFingerprint,
    'all members derive the same roster identities from MLS signature keys');
    assert(creatorRoster.members.every((member) => member.senderId === undefined
        && /^[0-9a-f]{64}$/.test(member.fingerprint)
        && /^[0-9a-f]{4}( [0-9a-f]{4}){4}$/.test(member.shortFingerprint)
        && member.displayName.includes(member.shortFingerprint)),
    'authenticated roster contains full/80-bit fingerprints and no relay identity');
    assert(creatorRoster.members.find((member) => member.isSelf).leafIndex === 0
        && joinerRoster.members.find((member) => member.isSelf).leafIndex === 1,
    'each roster marks its own authenticated leaf');

    const creatorOutBeforeIdentityMessage = exchange.creatorOut.length;
    const joinerEventsBeforeIdentityMessage = exchange.joinerEvents.length;
    await exchange.creator.sendMessage('identity is the MLS key');
    const identityMessage = exchange.creatorOut
        .slice(creatorOutBeforeIdentityMessage)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PRIVATE_MESSAGE);
    await exchange.joiner.onRelayEnvelope({
        ...identityMessage,
        // Model a relay changing the route label after it supplied
        // "creator-1" on the correlated Commit + Welcome.
        sender_id: 'relay-chosen-fake-name',
    });
    const authenticatedMessage = exchange.joinerEvents
        .slice(joinerEventsBeforeIdentityMessage)
        .find((event) => event.kind === 'message');
    assert(authenticatedMessage
        && authenticatedMessage.senderIdentity.fingerprint === creatorFingerprint
        && authenticatedMessage.senderIdentity.displayName
            === joinerRoster.members[0].displayName,
    'application event identity is derived from the signature-verified leaf key');
    assert(authenticatedMessage.senderId === undefined
        && !authenticatedMessage.senderIdentity.displayName.includes('creator-1')
        && !authenticatedMessage.senderIdentity.displayName
            .includes('relay-chosen-fake-name'),
    'relay sender_id cannot enter the displayed application identity');
    assert(authenticatedMessage.attributionWarning === true,
        'relay route relabeling is surfaced without changing key identity');

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
        exchange.joiner.group.epochSecrets.epochAuthenticator,
        exchange.creator.group.epochSecrets.epochAuthenticator,
    ), 'steady-state Commit keeps creator and joiner epoch state aligned');
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
    assert(exchange.joiner._proposalStore.size === 1
        && exchange.joiner._pendingSelfUpdates.size === 1,
    'proposal author stores authenticated content and its key by ProposalRef');
    const authoredReferenceKey = [...exchange.joiner._proposalStore.keys()][0];
    const authoredProposalEntry = exchange.joiner._proposalStore.get(
        authoredReferenceKey,
    );

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
    assert(exchange.creator._proposalStore.size === 1
        && exchange.creator._proposalStore.has(authoredReferenceKey),
    'creator stores the same authenticated ProposalRef as the author');

    const creatorOutBeforeFold = exchange.creatorOut.length;
    await exchange.creator.commitUpdate();
    const foldedUpdateCommit = exchange.creatorOut
        .slice(creatorOutBeforeFold)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    assert(Boolean(foldedUpdateCommit), 'creator emits Commit containing member Update');
    const foldedUpdatePm = parseCommitEnvelope(foldedUpdateCommit);
    const foldedProposalOrRef = foldedUpdatePm.content.parsed.proposals[0];
    assert(foldedUpdatePm.content.parsed.proposals.length === 1
        && foldedProposalOrRef.type
            === global.MLS.Proposal.ProposalOrRefType.REFERENCE
        && equalBytes(foldedProposalOrRef.reference, authoredProposalEntry.reference),
    'member Update travels in Commit as its AuthenticatedContent ProposalRef');
    assert(exchange.creator._pendingUpdateProposals.size === 1,
        'folded Update stays queued until Commit acceptance');
    await echoPendingCommit(exchange.creator, foldedUpdateCommit);
    assert(exchange.creator._proposalStore.size === 0,
        'creator consumes the old-epoch proposal store only after Commit echo');
    await exchange.joiner.onRelayEnvelope({
        ...foldedUpdateCommit,
        sender_id: 'creator-1',
    });
    assert(exchange.joiner.group.epoch === exchange.creator.group.epoch,
        'joiner applies Commit containing its Update proposal');
    assert(equalBytes(
        exchange.joiner.group.epochSecrets.epochAuthenticator,
        exchange.creator.group.epochSecrets.epochAuthenticator,
    ), 'folded Update keeps creator and joiner epoch state aligned');
    assert(exchange.joiner._pendingSelfUpdate === null,
        'joiner activates and clears pending self-update after Commit');
    assert(exchange.joiner._proposalStore.size === 0
        && exchange.joiner._pendingSelfUpdates.size === 0,
    'accepted referenced Update consumes joiner proposal and private-key stores');

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

    // A malicious creator can sign a fresh Commit around arbitrary proposal
    // bytes. Once the previous Commit consumed the proposal store, the old
    // reference is unknown and cannot be reused.
    const staleReferencedCommit = await rewriteCommitEnvelopeProposalList(
        exchange.creator,
        replayGuardCommit,
        [{
            type: global.MLS.Proposal.ProposalOrRefType.REFERENCE,
            reference: Uint8Array.from(authoredProposalEntry.reference),
        }],
    );
    const joinerBeforeUnknownReference = captureLiveGroup(exchange.joiner);
    const unknownReferenceEventsBefore = exchange.joinerEvents.length;
    await exchange.joiner.onRelayEnvelope({
        ...staleReferencedCommit,
        sender_id: 'creator-1',
    });
    const unknownReferenceError = exchange.joinerEvents
        .slice(unknownReferenceEventsBefore)
        .find((event) => event.kind === 'error');
    assert(Boolean(unknownReferenceError)
        && unknownReferenceError.reason.includes('unknown ProposalRef'),
    'consumed ProposalRef is one-shot and rejected as unknown');
    assert(liveGroupMatches(exchange.joiner, joinerBeforeUnknownReference)
        && exchange.joiner._proposalStore.size === 0,
    'unknown ProposalRef rejection leaves all recipient state unchanged');

    // Reinsert the old authenticated message to model a stale/corrupt local
    // cache and prove that processCommit re-verifies its original epoch
    // instead of trusting store metadata or only the inner LeafNode signature.
    exchange.joiner._proposalStore.set(
        authoredReferenceKey, authoredProposalEntry,
    );
    const joinerBeforeStaleReference = captureLiveGroup(exchange.joiner);
    const staleReferenceEventsBefore = exchange.joinerEvents.length;
    await exchange.joiner.onRelayEnvelope({
        ...staleReferencedCommit,
        sender_id: 'creator-1',
    });
    const staleReferenceError = exchange.joinerEvents
        .slice(staleReferenceEventsBefore)
        .find((event) => event.kind === 'error');
    assert(Boolean(staleReferenceError)
        && staleReferenceError.reason.includes('wrong epoch'),
    'fresh creator-signed Commit cannot replay an old authenticated ProposalRef',
    staleReferenceError ? staleReferenceError.reason : 'no error event');
    assert(liveGroupMatches(exchange.joiner, joinerBeforeStaleReference)
        && exchange.joiner._proposalStore.get(authoredReferenceKey)
            === authoredProposalEntry,
    'rejected stale ProposalRef leaves MLS and proposal-store state unchanged');

    // Inline Update semantics authenticate the committer, not the member
    // named by the LeafNode signature key. This profile therefore rejects
    // inline member Updates even when the creator re-signs the outer Commit.
    const inlineUpdateCommit = await rewriteCommitEnvelopeProposalList(
        exchange.creator,
        replayGuardCommit,
        [{
            type: global.MLS.Proposal.ProposalOrRefType.PROPOSAL,
            proposal: authoredProposalEntry.proposal,
        }],
    );
    const joinerBeforeInlineUpdate = captureLiveGroup(exchange.joiner);
    const inlineUpdateEventsBefore = exchange.joinerEvents.length;
    await exchange.joiner.onRelayEnvelope({
        ...inlineUpdateCommit,
        sender_id: 'creator-1',
    });
    const inlineUpdateError = exchange.joinerEvents
        .slice(inlineUpdateEventsBefore)
        .find((event) => event.kind === 'error');
    assert(Boolean(inlineUpdateError)
        && inlineUpdateError.reason.includes('inline Update proposals are not permitted'),
    'creator-signed inline Update targeting another member is rejected');
    assert(liveGroupMatches(exchange.joiner, joinerBeforeInlineUpdate)
        && exchange.joiner._proposalStore.get(authoredReferenceKey)
            === authoredProposalEntry,
    'rejected inline Update leaves MLS and proposal-store state unchanged');

    await echoPendingCommit(exchange.creator, replayGuardCommit);
    await exchange.joiner.onRelayEnvelope({
        ...replayGuardCommit,
        sender_id: 'creator-1',
    });
    assert(exchange.joiner.group.epoch === exchange.creator.group.epoch,
        'replay-guard path-only Commit keeps members aligned');
    assert(exchange.joiner._proposalStore.size === 0,
        'accepted path-only Commit consumes all stale old-epoch proposals');

    // Remove follows the same PendingCommit path: keep both the MLS state
    // and sender/leaf routing intact until the exact relay echo arrives.
    await exchange.joiner.proposeUpdate();
    assert(exchange.joiner._proposalStore.size === 1
        && exchange.joiner._pendingSelfUpdates.size === 1,
    'joiner has current-epoch proposal/private-key state to erase on removal');
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

    // An outer signature and membership_tag are necessary but not sufficient
    // for terminal teardown. The removed member must first validate all public
    // UpdatePath/tree structure that it can check without the new path secret.
    const malformedRemove = await rewriteCommitEnvelope(
        exchange.creator,
        removeCommit,
        (commit) => ({
            ...commit,
            path: { ...commit.path, nodes: [] },
        }),
    );
    const joinerBeforeMalformedRemove = captureLiveGroup(exchange.joiner);
    const malformedRemoveEventsBefore = exchange.joinerEvents.length;
    await exchange.joiner.onRelayEnvelope({
        ...malformedRemove,
        sender_id: 'creator-1',
    });
    const malformedRemoveError = exchange.joinerEvents
        .slice(malformedRemoveEventsBefore)
        .find((event) => event.kind === 'error');
    assert(Boolean(malformedRemoveError)
        && malformedRemoveError.reason.includes('UpdatePath nodes')
        && exchange.joiner.state === 'joined'
        && liveGroupMatches(exchange.joiner, joinerBeforeMalformedRemove),
    'creator-authenticated malformed Remove is rejected without teardown');

    const removedGroup = exchange.joiner.group;
    const removedSecretRefs = collectGroupSecretRefs(removedGroup);
    const removedSessionPsk = exchange.joiner.pskSecret;
    exchange.joiner._deferredEnvelopes.push({ type: 'test-deferred' });
    exchange.joiner._deferredRemovals.add('test-deferred-member');
    await echoPendingCommit(exchange.creator, removeCommit);
    assert(exchange.creator.group.epoch === stateBeforeRemove.epoch + 1n
        && !exchange.creator._leafBySenderId.has('joiner-1')
        && !exchange.creator._senderIdByLeaf.has(1),
    'Remove applies atomically and clears routing only after Commit echo');
    const rosterAfterRemove = latestRoster(exchange.creatorEvents);
    assert(rosterAfterRemove.members.length === 1
        && rosterAfterRemove.members[0].fingerprint === creatorFingerprint,
    'authenticated roster removes a member only after accepted Remove');

    const validRemoveEventsBefore = exchange.joinerEvents.length;
    await exchange.joiner.onRelayEnvelope({
        ...removeCommit,
        sender_id: 'creator-1',
    });
    const removalEvents = exchange.joinerEvents.slice(validRemoveEventsBefore);
    const terminalRemoval = removalEvents.find((event) => event.kind === 'removed');
    assert(Boolean(terminalRemoval)
        && terminalRemoval.removedLeafIndex === 1
        && terminalRemoval.committerLeafIndex === 0
        && terminalRemoval.epoch === exchange.creator.group.epoch.toString()
        && !removalEvents.some((event) => event.kind === 'error'),
    'valid creator Remove emits one authenticated terminal event');
    assert(exchange.joiner.state === 'removed'
        && exchange.joiner.group === null
        && exchange.joiner.identity === null
        && exchange.joiner.keyPackageBundle === null
        && exchange.joiner.pskSecret === null
        && exchange.joiner.expectedGroupId === null
        && exchange.joiner.expectedCreatorKeyHash === null,
    'removed MLSSession drops all group, identity, bootstrap, and KeyPackage state');
    assert(exchange.joiner._proposalStore.size === 0
        && exchange.joiner._pendingUpdateProposals.size === 0
        && exchange.joiner._pendingSelfUpdates.size === 0
        && exchange.joiner._pendingSelfUpdate === null
        && exchange.joiner._pendingWelcomeCommits.size === 0
        && exchange.joiner._deferredEnvelopes.length === 0
        && exchange.joiner._deferredRemovals.size === 0
        && exchange.joiner._leafBySenderId.size === 0
        && exchange.joiner._senderIdByLeaf.size === 0
        && exchange.joiner._identityBySignatureKey.size === 0,
    'removed MLSSession clears every pending, routing, and identity cache');
    assert(Object.keys(removedGroup.epochSecrets).length === 0
        && removedGroup._chainStates.size === 0
        && removedGroup._prevEpoch === null
        && removedGroup.leafKeyPair === null
        && removedGroup.identity === null
        && removedGroup.parentKeyPairs.size === 0
        && removedSecretRefs.every(
            (bytes) => bytes.every((byte) => byte === 0),
        )
        && removedSessionPsk.every((byte) => byte === 0),
    'terminal removal zeroes retained symmetric Group and session secrets');
    let removedSendRejected = false;
    try {
        await exchange.joiner.sendMessage('must not send after removal');
    } catch (err) {
        removedSendRejected = err.message.includes('removed');
    }
    assert(removedSendRejected,
        'terminal removed state rejects all later application sends');

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

    // Two joiners may publish KeyPackages before the first Add is accepted.
    // The creator serializes the Commits, while each awaiting joiner must
    // retain only the Commit/Welcome pair addressed to its own KeyPackageRef.
    const multiCreatorOut = [];
    const multiCreator = new MLSSession({
        role: 'creator',
        send: (envelope) => multiCreatorOut.push(envelope),
        onEvent: () => {},
    });
    await multiCreator.start();
    const multiPins = multiCreator.bootstrapPins;
    const multiAOut = [];
    const multiBOut = [];
    const multiA = new MLSSession({
        role: 'joiner',
        send: (envelope) => multiAOut.push(envelope),
        onEvent: () => {},
        expectedGroupId: multiPins.groupId,
        expectedCreatorKeyHash: multiPins.creatorKeyHash,
    });
    const multiB = new MLSSession({
        role: 'joiner',
        send: (envelope) => multiBOut.push(envelope),
        onEvent: () => {},
        expectedGroupId: multiPins.groupId,
        expectedCreatorKeyHash: multiPins.creatorKeyHash,
    });
    await multiA.start();
    await multiB.start();
    const multiAKp = multiAOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_KEY_PACKAGE,
    );
    const multiBKp = multiBOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_KEY_PACKAGE,
    );
    await multiCreator.onRelayEnvelope({ ...multiAKp, sender_id: 'multi-a' });
    await multiCreator.onRelayEnvelope({ ...multiBKp, sender_id: 'multi-b' });
    const multiCommitA = multiCreatorOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE,
    );
    await multiA.onRelayEnvelope({ ...multiCommitA, sender_id: 'multi-creator' });
    await multiB.onRelayEnvelope({ ...multiCommitA, sender_id: 'multi-creator' });
    assert(multiA._pendingWelcomeCommits.size === 1
        && multiB._pendingWelcomeCommits.size === 0,
    'first simultaneous Add is buffered only by its intended joiner');

    await echoPendingCommit(multiCreator, multiCommitA, 'multi-creator');
    const multiWelcomeA = multiCreatorOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_WELCOME,
    );
    const multiCommits = multiCreatorOut.filter(
        (envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE,
    );
    const multiCommitB = multiCommits[1];
    assert(Boolean(multiWelcomeA) && Boolean(multiCommitB),
        'creator serializes second simultaneous Add after first acceptance');
    await multiA.onRelayEnvelope({ ...multiWelcomeA, sender_id: 'multi-creator' });
    await multiB.onRelayEnvelope({ ...multiWelcomeA, sender_id: 'multi-creator' });
    assert(multiA.state === 'joined' && multiB.state === 'awaiting-welcome',
        'first Welcome joins only its KeyPackage owner');

    await multiA.onRelayEnvelope({ ...multiCommitB, sender_id: 'multi-creator' });
    await multiB.onRelayEnvelope({ ...multiCommitB, sender_id: 'multi-creator' });
    assert(multiB._pendingWelcomeCommits.size === 1,
        'second joiner buffers its own correlated Add after ignoring first');

    // Transport metadata is only a routing hint. Even if it is rewritten to
    // target B and name B's buffered Commit, the actual Welcome must contain
    // B's standard MLS KeyPackageRef before any join secrets are processed.
    let crossTargetWelcomeError = '';
    try {
        await multiB.onRelayEnvelope({
            ...multiWelcomeA,
            key_package_ref: multiB._keyPackageRef,
            commit_ref: multiCommitB.commit_ref,
            sender_id: 'multi-creator',
        });
    } catch (err) {
        crossTargetWelcomeError = err.message;
    }
    assert(crossTargetWelcomeError.includes(
        'targeted Welcome does not contain our KeyPackageRef',
    ) && multiB.state === 'awaiting-welcome'
        && multiB._pendingWelcomeCommits.size === 1,
    'rewritten Welcome metadata cannot retarget another joiner or consume state');

    await echoPendingCommit(multiCreator, multiCommitB, 'multi-creator');
    const multiWelcomes = multiCreatorOut.filter(
        (envelope) => envelope.wire_format === WireFormat.MLS_WELCOME,
    );
    const multiWelcomeB = multiWelcomes[1];
    await multiB.onRelayEnvelope({ ...multiWelcomeB, sender_id: 'multi-creator' });
    assert(multiA.state === 'joined' && multiB.state === 'joined'
        && multiCreator.group.epoch === multiA.group.epoch
        && multiA.group.epoch === multiB.group.epoch,
    'both simultaneous joiners converge after independently correlated Welcomes');
    assert(equalBytes(
        multiCreator.group.epochSecrets.epochAuthenticator,
        multiA.group.epochSecrets.epochAuthenticator,
    ) && equalBytes(
        multiA.group.epochSecrets.epochAuthenticator,
        multiB.group.epochSecrets.epochAuthenticator,
    ), 'three-member simultaneous-join flow converges cryptographically');

    // ProposalRef resolution is local to every recipient, not just the
    // creator and proposal author. Exercise a passive third member so a
    // regression that reintroduces creator-only buffering fails closed.
    const multiAOutBeforeProposal = multiAOut.length;
    await multiA.proposeUpdate();
    const multiProposal = multiAOut
        .slice(multiAOutBeforeProposal)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    await multiCreator.onRelayEnvelope({
        ...multiProposal,
        sender_id: 'multi-a',
    });
    await multiB.onRelayEnvelope({
        ...multiProposal,
        sender_id: 'multi-a',
    });
    const multiReferenceKey = [...multiA._proposalStore.keys()][0];
    assert(multiA._proposalStore.has(multiReferenceKey)
        && multiCreator._proposalStore.has(multiReferenceKey)
        && multiB._proposalStore.has(multiReferenceKey),
    'proposal author, creator, and passive member store the same ProposalRef');

    const multiCreatorOutBeforeUpdate = multiCreatorOut.length;
    await multiCreator.commitUpdate();
    const multiReferenceCommit = multiCreatorOut
        .slice(multiCreatorOutBeforeUpdate)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    await echoPendingCommit(multiCreator, multiReferenceCommit, 'multi-creator');
    await multiA.onRelayEnvelope({
        ...multiReferenceCommit,
        sender_id: 'multi-creator',
    });
    await multiB.onRelayEnvelope({
        ...multiReferenceCommit,
        sender_id: 'multi-creator',
    });
    assert(multiCreator.group.epoch === multiA.group.epoch
        && multiA.group.epoch === multiB.group.epoch
        && equalBytes(
            multiCreator.group.epochSecrets.epochAuthenticator,
            multiB.group.epochSecrets.epochAuthenticator,
        ),
    'passive member resolves referenced Update and converges');
    assert(multiA._proposalStore.size === 0
        && multiCreator._proposalStore.size === 0
        && multiB._proposalStore.size === 0,
    'all members consume the ProposalRef store after accepted Commit');

    // The mutex must not deadlock an in-memory transport that resolves the
    // Commit send only after synchronously feeding its exact acceptance echo
    // back to the same session.
    let synchronousEchoSent = false;
    const synchronousEcho = await createExchange({
        acceptCommit: false,
        creatorSend: (envelope, creator) => {
            if (!synchronousEchoSent
                && envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE) {
                synchronousEchoSent = true;
                return creator.onRelayEnvelope({
                    ...envelope,
                    sender_id: 'creator-synchronous-self',
                });
            }
            return true;
        },
    });
    assert(synchronousEchoSent
        && synchronousEcho.creator._pendingCommit === null
        && synchronousEcho.creator.group.epoch
            === synchronousEcho.beforeAdd.epoch + 1n
        && Boolean(synchronousEcho.welcome),
    'exact synchronous Commit echo bypasses the queue only for atomic acceptance');

    // Every public MLSSession entry point shares one operation mutex. An
    // application encryption crosses signature, SecretTree, and AEAD awaits;
    // a periodic Commit requested in the middle must not fork a candidate
    // from that half-advanced send ratchet.
    const sendRace = await createExchange();
    await completeExchangeJoin(sendRace, 'creator-send-race');
    const sendRaceGroup = sendRace.creator.group;
    const originalEncrypt = sendRaceGroup.encryptApplicationMessage.bind(
        sendRaceGroup,
    );
    const encryptEntered = deferred();
    const releaseEncrypt = deferred();
    sendRaceGroup.encryptApplicationMessage = async (payload) => {
        encryptEntered.resolve();
        await releaseEncrypt.promise;
        // Do not copy this test hook into the PendingCommit candidate.
        delete sendRaceGroup.encryptApplicationMessage;
        return originalEncrypt(payload);
    };
    const sendRaceOutBefore = sendRace.creatorOut.length;
    const inFlightSend = sendRace.creator.sendMessage('serialize send first');
    await encryptEntered.promise;
    const commitAfterSend = sendRace.creator.commitUpdate();
    await Promise.resolve();
    await Promise.resolve();
    assert(sendRace.creator._pendingCommit === null
        && !sendRace.creatorOut.slice(sendRaceOutBefore).some(
            (envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE,
        ),
    'Commit waits while an application ratchet operation is in flight');
    releaseEncrypt.resolve();
    await inFlightSend;
    await commitAfterSend;
    const serializedSendOutput = sendRace.creatorOut.slice(sendRaceOutBefore);
    const serializedApplication = serializedSendOutput.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_PRIVATE_MESSAGE,
    );
    const serializedCommit = serializedSendOutput.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE,
    );
    assert(Boolean(serializedApplication) && Boolean(serializedCommit)
        && serializedSendOutput.indexOf(serializedApplication)
            < serializedSendOutput.indexOf(serializedCommit),
    'application transport handoff completes before queued Commit construction');
    await sendRace.joiner.onRelayEnvelope({
        ...serializedApplication,
        sender_id: 'creator-send-race',
    });
    await echoPendingCommit(
        sendRace.creator, serializedCommit, 'creator-send-race-self',
    );
    await sendRace.joiner.onRelayEnvelope({
        ...serializedCommit,
        sender_id: 'creator-send-race',
    });
    assert(sendRace.creator.group.epoch === sendRace.joiner.group.epoch
        && equalBytes(
            sendRace.creator.group.epochSecrets.epochAuthenticator,
            sendRace.joiner.group.epochSecrets.epochAuthenticator,
        ),
    'send/Commit interleaving converges on one authenticated epoch');

    // Concurrent UI sends must serialize the stateful SecretTree chain too,
    // not merely allocate distinct generation numbers. Every ciphertext must
    // remain decryptable in FIFO order after the preceding Commit.
    const burstOutBefore = sendRace.creatorOut.length;
    const burstEventsBefore = sendRace.joinerEvents.length;
    const burstCount = 12;
    await Promise.all(Array.from({ length: burstCount }, (_, index) =>
        sendRace.creator.sendMessage(`serialized burst ${index}`)));
    const burst = sendRace.creatorOut.slice(burstOutBefore).filter(
        (envelope) => envelope.wire_format === WireFormat.MLS_PRIVATE_MESSAGE,
    );
    for (const envelope of burst) {
        await sendRace.joiner.onRelayEnvelope({
            ...envelope,
            sender_id: 'creator-send-race',
        });
    }
    const burstMessages = sendRace.joinerEvents.slice(burstEventsBefore).filter(
        (event) => event.kind === 'message'
            && event.text.startsWith('serialized burst '),
    );
    assert(burst.length === burstCount && burstMessages.length === burstCount
        && burstMessages.every(
            (event, index) => event.text === `serialized burst ${index}`,
        ),
    'concurrent session sends consume the SecretTree chain exactly once each');

    // Receive-side authentication is part of the same critical section. If
    // a Commit snapshot overtook a decrypt, its previous-epoch grace state
    // would forget that the ciphertext had already been consumed and could
    // accept a replay after the Commit lands.
    const receiveRace = await createExchange();
    await completeExchangeJoin(receiveRace, 'creator-receive-race');
    const joinerOutBeforeRaceMessage = receiveRace.joinerOut.length;
    await receiveRace.joiner.sendMessage('consume before snapshot');
    const receiveRaceMessage = receiveRace.joinerOut
        .slice(joinerOutBeforeRaceMessage)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PRIVATE_MESSAGE);
    const receiveRaceGroup = receiveRace.creator.group;
    const originalDecrypt = receiveRaceGroup.decryptApplicationMessage.bind(
        receiveRaceGroup,
    );
    const decryptEntered = deferred();
    const releaseDecrypt = deferred();
    receiveRaceGroup.decryptApplicationMessage = async (wrapped) => {
        decryptEntered.resolve();
        await releaseDecrypt.promise;
        // Do not copy this test hook into the PendingCommit candidate.
        delete receiveRaceGroup.decryptApplicationMessage;
        return originalDecrypt(wrapped);
    };
    const receiveEventsBefore = receiveRace.creatorEvents.length;
    const inFlightReceive = receiveRace.creator.onRelayEnvelope({
        ...receiveRaceMessage,
        sender_id: 'joiner-1',
    });
    await decryptEntered.promise;
    const receiveRaceOutBefore = receiveRace.creatorOut.length;
    const commitAfterReceive = receiveRace.creator.commitUpdate();
    await Promise.resolve();
    await Promise.resolve();
    assert(receiveRace.creator._pendingCommit === null,
        'Commit waits for in-flight receive authentication and ratchet commit');
    releaseDecrypt.resolve();
    await inFlightReceive;
    await commitAfterReceive;
    const receiveRaceCommit = receiveRace.creatorOut
        .slice(receiveRaceOutBefore)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    assert(receiveRace.creatorEvents.slice(receiveEventsBefore).filter(
        (event) => event.kind === 'message'
            && event.text === 'consume before snapshot',
    ).length === 1,
    'in-flight message authenticates exactly once before Commit snapshot');
    await echoPendingCommit(
        receiveRace.creator, receiveRaceCommit, 'creator-receive-race-self',
    );
    await receiveRace.creator.onRelayEnvelope({
        ...receiveRaceMessage,
        sender_id: 'joiner-1',
    });
    const receiveRaceEvents = receiveRace.creatorEvents.slice(receiveEventsBefore);
    assert(receiveRaceEvents.filter(
        (event) => event.kind === 'message'
            && event.text === 'consume before snapshot',
    ).length === 1 && receiveRaceEvents.some(
        (event) => event.kind === 'error'
            && (event.reason.includes('replayed')
                || event.reason.includes('expired application message')),
    ),
    'accepted candidate preserves receive consumption and rejects old-epoch replay');

    // A member Update can finish constructing authenticated old-epoch bytes
    // while a creator Commit arrives. The inbound Commit must wait until the
    // proposal and its private key are installed atomically, then consume
    // them as stale when it advances the epoch.
    const proposalRace = await createExchange();
    await completeExchangeJoin(proposalRace, 'creator-proposal-race');
    const proposalRaceEpoch = proposalRace.joiner.group.epoch;
    const proposalRaceCreatorOutBefore = proposalRace.creatorOut.length;
    await proposalRace.creator.commitUpdate();
    const proposalRaceCommit = proposalRace.creatorOut
        .slice(proposalRaceCreatorOutBefore)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    const proposalRaceGroup = proposalRace.joiner.group;
    const originalPropose = proposalRaceGroup.proposeUpdate.bind(
        proposalRaceGroup,
    );
    const proposalBuilt = deferred();
    const releaseProposal = deferred();
    proposalRaceGroup.proposeUpdate = async () => {
        const proposed = await originalPropose();
        proposalBuilt.resolve();
        await releaseProposal.promise;
        delete proposalRaceGroup.proposeUpdate;
        return proposed;
    };
    const proposalRaceOutBefore = proposalRace.joinerOut.length;
    const inFlightProposal = proposalRace.joiner.proposeUpdate();
    await proposalBuilt.promise;
    const incomingDuringProposal = proposalRace.joiner.onRelayEnvelope({
        ...proposalRaceCommit,
        sender_id: 'creator-proposal-race',
    });
    await Promise.resolve();
    await Promise.resolve();
    assert(proposalRace.joiner.group.epoch === proposalRaceEpoch
        && proposalRace.joiner._proposalStore.size === 0,
    'incoming Commit cannot overtake an in-flight local Update proposal');
    releaseProposal.resolve();
    await inFlightProposal;
    await incomingDuringProposal;
    const serializedProposal = proposalRace.joinerOut
        .slice(proposalRaceOutBefore)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    assert(Boolean(serializedProposal)
        && proposalRace.joiner.group.epoch === proposalRaceEpoch + 1n
        && proposalRace.joiner._proposalStore.size === 0
        && proposalRace.joiner._pendingSelfUpdates.size === 0
        && proposalRace.joiner._pendingSelfUpdate === null,
    'proposal completes first and subsequent Commit atomically clears stale state');
    assert(!proposalRace.joinerEvents.some(
        (event) => event.kind === 'error'
            && event.reason.includes('proposeUpdate failed'),
    ), 'serialized proposal/Commit race produces no mixed-epoch proposal error');
    await echoPendingCommit(
        proposalRace.creator, proposalRaceCommit, 'creator-proposal-race-self',
    );

    // Transport rejection rolls back proposal-store bookkeeping, and the
    // promise mutex remains usable by the next attempt.
    const rollbackProposal = await createExchange();
    await completeExchangeJoin(rollbackProposal, 'creator-proposal-rollback');
    const normalProposalSend = rollbackProposal.joiner.send;
    rollbackProposal.joiner.send = (envelope) => {
        if (envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE) return false;
        return normalProposalSend(envelope);
    };
    const rollbackEventsBefore = rollbackProposal.joinerEvents.length;
    await rollbackProposal.joiner.proposeUpdate();
    assert(rollbackProposal.joiner._proposalStore.size === 0
        && rollbackProposal.joiner._pendingSelfUpdates.size === 0
        && rollbackProposal.joiner._pendingSelfUpdate === null,
    'transport-rejected Update proposal rolls back all pending local state');
    assert(rollbackProposal.joinerEvents.slice(rollbackEventsBefore).some(
        (event) => event.kind === 'error'
            && event.reason.includes('transport rejected envelope'),
    ), 'transport-rejected Update proposal reports a fail-closed error');
    rollbackProposal.joiner.send = normalProposalSend;
    const retryProposalOutBefore = rollbackProposal.joinerOut.length;
    await rollbackProposal.joiner.proposeUpdate();
    assert(rollbackProposal.joinerOut.slice(retryProposalOutBefore).some(
        (envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE,
    ) && rollbackProposal.joiner._proposalStore.size === 1
        && rollbackProposal.joiner._pendingSelfUpdates.size === 1,
    'operation mutex recovers after rejection and accepts the next proposal');

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
        noCommitError.includes('without its matching buffered Commit'),
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
    let nonCreatorError = '';
    try {
        await target.onRelayEnvelope({
            type: 'mls',
            payload: global.MLS.Codec.bytesToBase64Url(unauthorizedCommitBody),
            wire_format: WireFormat.MLS_PUBLIC_MESSAGE,
            key_package_ref: target._keyPackageRef,
            commit_ref: global.MLS.Codec.bytesToBase64Url(
                await global.MLS.Labeled.sha256(unauthorizedCommitBody),
            ),
            sender_id: 'non-creator-1',
        });
    } catch (err) {
        nonCreatorError = err.message;
    }
    assert(
        nonCreatorError.includes('was not sent by creator leaf 0'),
        'MLSSession rejects correlated Add Commit from non-creator leaf',
        nonCreatorError,
    );
    assert(target.state === 'awaiting-welcome' && target.group === null,
        'non-creator Add leaves target unjoined');
    assert(target._pendingWelcomeCommits.size === 0,
        'rejected non-creator Add is never buffered');

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
    let alternateGroupError = '';
    try {
        await victim.onRelayEnvelope({
            ...alternateCommit,
            sender_id: 'alternate-creator',
        });
    } catch (err) {
        alternateGroupError = err.message;
    }
    assert(alternateGroupError.includes('unexpected group_id'),
        'same-PSK alternative Add is rejected by group_id pin', alternateGroupError);
    assert(victim.state === 'awaiting-welcome' && victim.group === null,
        'alternative-group Add leaves victim unjoined');

    console.log('');
    console.log(`mls-session-join: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
