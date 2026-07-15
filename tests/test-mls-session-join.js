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

async function createExchange() {
    const creatorOut = [];
    const joinerOut = [];
    const creatorEvents = [];
    const joinerEvents = [];
    const creator = new MLSSession({
        role: 'creator',
        send: (envelope) => creatorOut.push(envelope),
        onEvent: (event) => creatorEvents.push(event),
    });
    await creator.start();
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

    return {
        creator,
        joiner,
        creatorOut,
        joinerOut,
        creatorEvents,
        joinerEvents,
        commit: creatorOut.find(
            (envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE,
        ),
        welcome: creatorOut.find(
            (envelope) => envelope.wire_format === WireFormat.MLS_WELCOME,
        ),
    };
}

async function main() {
    console.log('# MLS session — Welcome join orchestration');

    const exchange = await createExchange();
    assert(Boolean(exchange.commit), 'creator emitted an Add Commit');
    assert(Boolean(exchange.welcome), 'creator emitted a Welcome');

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
    const creatorOutBeforeUpdate = exchange.creatorOut.length;
    await exchange.creator.commitUpdate();
    const creatorUpdateCommit = exchange.creatorOut
        .slice(creatorOutBeforeUpdate)
        .find((envelope) => envelope.wire_format === WireFormat.MLS_PUBLIC_MESSAGE);
    assert(Boolean(creatorUpdateCommit),
        'creator emits a steady-state Update Commit after join');
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
