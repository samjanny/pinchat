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
    const joiner = new MLSSession({
        role: 'joiner',
        send: (envelope) => joinerOut.push(envelope),
        onEvent: (event) => joinerEvents.push(event),
    });

    await creator.start();
    await joiner.start();
    const keyPackage = joinerOut.find(
        (envelope) => envelope.wire_format === WireFormat.MLS_KEY_PACKAGE,
    );
    await creator.onRelayEnvelope({ ...keyPackage, sender_id: 'joiner-1' });

    return {
        creator,
        joiner,
        creatorOut,
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

    console.log('');
    console.log(`mls-session-join: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
