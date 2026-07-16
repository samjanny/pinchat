#!/usr/bin/env node

/**
 * Browser WebSocket reconnect credential regression tests.
 *
 * Exercises the production WebSocketManager with small browser/fetch mocks:
 * the server-issued credential stays in page memory, is attached to token
 * refreshes, is stripped before application dispatch, and fails closed for
 * group-style callers when the server rejects it.
 */

const assert = require('assert');
const path = require('path');

const storage = new Map();
global.sessionStorage = {
    getItem: (key) => storage.has(key) ? storage.get(key) : null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: (key) => storage.delete(key),
};

const listeners = new Map();
global.window = {
    PINCHAT_PROTOCOL_VERSION: 1,
    location: {
        protocol: 'https:',
        host: 'pinchat.test',
        pathname: '/chat/test-room',
        search: '',
        hash: '',
        href: '',
    },
    addEventListener: (name, callback) => listeners.set(name, callback),
    removeEventListener: (name) => listeners.delete(name),
};

class FakeWebSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSED = 3;
    static instances = [];

    constructor(url, protocols) {
        this.url = url;
        this.protocols = protocols;
        this.protocol = 'pinchat.v1';
        this.readyState = FakeWebSocket.OPEN;
        this.closedWith = null;
        this.sent = [];
        FakeWebSocket.instances.push(this);
    }

    close(code, reason) {
        this.closedWith = { code, reason };
        this.readyState = FakeWebSocket.CLOSED;
    }

    send(payload) {
        this.sent.push(payload);
    }
}

global.WebSocket = FakeWebSocket;
global.ProofOfWork = class {
    static generateMask() { return 'unused'; }
    async solve() { throw new Error('PoW should not run in this test'); }
};

const csrfToken = `${'a'.repeat(32)}.${'b'.repeat(64)}`;
const resumeToken = `${'A'.repeat(32)}.${'B'.repeat(32)}.${'C'.repeat(32)}`;

function response(status, body) {
    return {
        status,
        ok: status >= 200 && status < 300,
        async json() { return body; },
    };
}

function successToken(token, overrides = {}) {
    return response(200, {
        token,
        connection_id: 'relay-id',
        expires_in: 30,
        protocol_version: 1,
        supported_subprotocols: ['pinchat.v1'],
        ...overrides,
    });
}

let queuedResponses = [];
let fetchCalls = [];
global.fetch = async (url, options = {}) => {
    fetchCalls.push({ url, options });
    if (queuedResponses.length === 0) {
        throw new Error(`Unexpected fetch: ${url}`);
    }
    return queuedResponses.shift();
};

require(path.join(__dirname, '..', 'static', 'js', 'websocket.js'));
const { WebSocketManager } = window;

let passed = 0;
function check(condition, message) {
    assert.ok(condition, message);
    console.log(`  OK   ${message}`);
    passed += 1;
}

function deferred() {
    let resolve;
    const promise = new Promise((res) => { resolve = res; });
    return { promise, resolve };
}

async function main() {
    console.log('# WebSocket stable-identity resume');

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('single-flight-upgrade-token'),
    ];
    fetchCalls = [];
    const socketsBeforeSingleFlight = FakeWebSocket.instances.length;
    const singleFlightManager =
        new WebSocketManager('single-flight-room');
    await Promise.all([
        singleFlightManager.connect(),
        singleFlightManager.connect(),
    ]);
    check(
        fetchCalls.length === 2
        && FakeWebSocket.instances.length
            === socketsBeforeSingleFlight + 1,
        'concurrent connect calls share one token request and one socket',
    );

    queuedResponses = [];
    fetchCalls = [];
    const connectingGuardManager =
        new WebSocketManager('connecting-guard-room');
    connectingGuardManager.ws = {
        readyState: FakeWebSocket.CONNECTING,
    };
    const socketsBeforeConnectingGuard =
        FakeWebSocket.instances.length;
    await connectingGuardManager.connect();
    check(
        fetchCalls.length === 0
        && FakeWebSocket.instances.length
            === socketsBeforeConnectingGuard,
        'an existing CONNECTING socket suppresses a duplicate admission',
    );

    const cancelledToken = deferred();
    const cancelledConnectManager =
        new WebSocketManager('cancelled-connect-room');
    cancelledConnectManager.requestWsToken =
        async () => cancelledToken.promise;
    const socketsBeforeCancelledConnect =
        FakeWebSocket.instances.length;
    const cancelledConnect =
        cancelledConnectManager.connect();
    await Promise.resolve();
    cancelledConnectManager.disconnect();
    cancelledToken.resolve('must-not-be-used');
    await cancelledConnect;
    check(
        FakeWebSocket.instances.length
            === socketsBeforeCancelledConnect
        && cancelledConnectManager.ws === null,
        'disconnect cancels an in-flight token request before socket creation',
    );

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('initial-upgrade-token'),
    ];
    fetchCalls = [];

    const manager = new WebSocketManager('test-room');
    let delivered = null;
    let resumeError = null;
    manager.onMessage = async (message) => { delivered = message; };
    manager.onError = (error) => { resumeError = error.message; };
    await manager.connect();

    const socket = FakeWebSocket.instances.at(-1);
    check(Boolean(socket), 'connect creates a WebSocket after protocol-gated token issuance');
    socket.onopen();
    socket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: 'relay-id',
            room_type: 'group',
            resumed: false,
            resume_token: resumeToken,
            mls_control_cursor: 0,
        }),
    });
    await manager._inboundQueue;

    check(manager.resumeToken === resumeToken,
        'Connected captures the server-signed resume credential in page memory');
    check(delivered && !Object.prototype.hasOwnProperty.call(delivered, 'resume_token'),
        'resume bearer is removed before application dispatch');
    check(!Array.from(storage.keys()).some((key) => key.includes('resume')),
        'resume bearer is not persisted in sessionStorage');

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('resumed-upgrade-token'),
    ];
    fetchCalls = [];
    const refreshed = await manager.requestWsToken();
    check(refreshed === 'resumed-upgrade-token',
        'resume credential obtains a fresh single-use upgrade token');
    check(fetchCalls[1].options.headers['X-PinChat-Resume-Token'] === resumeToken,
        'token refresh sends the resume credential only in its dedicated header');
    check(fetchCalls[1].options.headers['X-PinChat-MLS-Control-Seq'] === '0',
        'group resume token binds the highest applied MLS control sequence');

    const creatorBootstrap = 'A'.repeat(43);
    const creatorConnectionId =
        '11111111-1111-4111-8111-111111111111';

    const oneToOneCreatorRoom = 'onetoone-creator-room';
    storage.set(
        `ws_token_${oneToOneCreatorRoom}`,
        'onetoone-preissued-upgrade-token',
    );
    storage.set(
        `ws_connection_${oneToOneCreatorRoom}`,
        creatorConnectionId,
    );
    storage.set(`ws_room_type_${oneToOneCreatorRoom}`, 'onetoone');
    storage.set(`ws_protocol_version_${oneToOneCreatorRoom}`, '1');
    storage.set(
        `ws_subprotocols_${oneToOneCreatorRoom}`,
        JSON.stringify(['pinchat.v1']),
    );
    queuedResponses = [];
    fetchCalls = [];
    const oneToOneCreator = new WebSocketManager(oneToOneCreatorRoom);
    await oneToOneCreator.connect();
    const oneToOneCreatorSocket = FakeWebSocket.instances.at(-1);
    check(
        oneToOneCreatorSocket.protocols.includes(
            'pinchat.v1.jwt.onetoone-preissued-upgrade-token',
        )
        && fetchCalls.length === 0
        && !oneToOneCreator._fatalAuthFailure,
        '1:1 creator accepts its pre-issued identity without an MLS bootstrap capability',
    );
    check(
        !storage.has(`ws_connection_${oneToOneCreatorRoom}`)
        && !storage.has(`ws_room_type_${oneToOneCreatorRoom}`),
        '1:1 creator preallocation is erased after copying the one-shot JWT',
    );

    storage.set(
        'ws_creator_bootstrap_creator-recovery-room',
        creatorBootstrap,
    );
    storage.set(
        'ws_connection_creator-recovery-room',
        creatorConnectionId,
    );
    storage.set('ws_room_type_creator-recovery-room', 'group');
    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('creator-recovery-upgrade-token', {
            connection_id: creatorConnectionId,
            mls_control_cursor: 0,
        }),
    ];
    fetchCalls = [];
    const creatorRecovery =
        new WebSocketManager('creator-recovery-room');
    await creatorRecovery.connect();
    const creatorRecoverySocket = FakeWebSocket.instances.at(-1);
    check(fetchCalls[1].options.headers[
        'X-PinChat-Creator-Bootstrap'
    ] === creatorBootstrap
        && creatorRecovery.expectedCreatorConnectionId
            === creatorConnectionId
        && creatorRecovery.lastMlsControlSeq === 0,
    'pre-Connected creator recovery re-mints the same relay identity and cursor');
    check(storage.get(
        'ws_creator_bootstrap_creator-recovery-room',
    ) === creatorBootstrap,
    'creator bootstrap bearer remains tab-scoped until Connected is authenticated');
    creatorRecoverySocket.onopen();
    creatorRecoverySocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: creatorConnectionId,
            room_type: 'group',
            resumed: true,
            resume_token: resumeToken,
            mls_control_cursor: 0,
        }),
    });
    await creatorRecovery._inboundQueue;
    check(creatorRecovery.resumeToken === resumeToken
        && creatorRecovery.creatorBootstrapToken === null
        && !storage.has(
            'ws_creator_bootstrap_creator-recovery-room',
        )
        && !storage.has('ws_connection_creator-recovery-room')
        && !storage.has('ws_room_type_creator-recovery-room'),
    'first Connected replaces and erases the creator bootstrap credential');

    const mismatchedCreatorRoom = 'creator-mismatch-room';
    storage.set(
        `ws_creator_bootstrap_${mismatchedCreatorRoom}`,
        creatorBootstrap,
    );
    storage.set(
        `ws_connection_${mismatchedCreatorRoom}`,
        creatorConnectionId,
    );
    storage.set(`ws_room_type_${mismatchedCreatorRoom}`, 'group');
    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('mismatched-creator-token', {
            connection_id:
                '22222222-2222-4222-8222-222222222222',
        }),
    ];
    fetchCalls = [];
    const socketsBeforeCreatorMismatch = FakeWebSocket.instances.length;
    const mismatchedCreator =
        new WebSocketManager(mismatchedCreatorRoom);
    let creatorMismatchError = null;
    mismatchedCreator.onError = (error) => {
        creatorMismatchError = error.message;
    };
    await mismatchedCreator.connect();
    check(mismatchedCreator._fatalAuthFailure
        && creatorMismatchError === 'CREATOR_IDENTITY_MISMATCH'
        && FakeWebSocket.instances.length
            === socketsBeforeCreatorMismatch
        && !storage.has(
            `ws_creator_bootstrap_${mismatchedCreatorRoom}`,
        )
        && !storage.has(`ws_connection_${mismatchedCreatorRoom}`)
        && !storage.has(`ws_room_type_${mismatchedCreatorRoom}`),
    'creator identity mismatch fails closed and erases bootstrap metadata');

    const advancedCreatorRoom = 'creator-advanced-cursor-room';
    storage.set(
        `ws_creator_bootstrap_${advancedCreatorRoom}`,
        creatorBootstrap,
    );
    storage.set(
        `ws_connection_${advancedCreatorRoom}`,
        creatorConnectionId,
    );
    storage.set(`ws_room_type_${advancedCreatorRoom}`, 'group');
    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('advanced-creator-token', {
            connection_id: creatorConnectionId,
            mls_control_cursor: 1,
        }),
    ];
    fetchCalls = [];
    const socketsBeforeAdvancedCursor = FakeWebSocket.instances.length;
    const advancedCreator = new WebSocketManager(advancedCreatorRoom);
    let advancedCursorError = null;
    advancedCreator.onError = (error) => {
        advancedCursorError = error.message;
    };
    await advancedCreator.connect();
    check(
        advancedCreator._fatalAuthFailure
        && advancedCursorError === 'CREATOR_BOOTSTRAP_CURSOR_INVALID'
        && FakeWebSocket.instances.length === socketsBeforeAdvancedCursor
        && !storage.has(
            `ws_creator_bootstrap_${advancedCreatorRoom}`,
        )
        && !storage.has(`ws_connection_${advancedCreatorRoom}`)
        && !storage.has(`ws_room_type_${advancedCreatorRoom}`),
        'creator bootstrap cannot skip already-confirmed MLS control history',
    );

    const connectedCreatorMismatchRoom =
        'creator-connected-mismatch-room';
    storage.set(
        `ws_token_${connectedCreatorMismatchRoom}`,
        'creator-connected-mismatch-token',
    );
    storage.set(
        `ws_creator_bootstrap_${connectedCreatorMismatchRoom}`,
        creatorBootstrap,
    );
    storage.set(
        `ws_connection_${connectedCreatorMismatchRoom}`,
        creatorConnectionId,
    );
    storage.set(
        `ws_room_type_${connectedCreatorMismatchRoom}`,
        'group',
    );
    storage.set(
        `ws_protocol_version_${connectedCreatorMismatchRoom}`,
        '1',
    );
    storage.set(
        `ws_subprotocols_${connectedCreatorMismatchRoom}`,
        JSON.stringify(['pinchat.v1']),
    );
    queuedResponses = [];
    fetchCalls = [];
    const connectedCreatorMismatch =
        new WebSocketManager(connectedCreatorMismatchRoom);
    let connectedCreatorMismatchError = null;
    connectedCreatorMismatch.onError = (error) => {
        connectedCreatorMismatchError = error.message;
    };
    await connectedCreatorMismatch.connect();
    const connectedCreatorMismatchSocket =
        FakeWebSocket.instances.at(-1);
    connectedCreatorMismatchSocket.onopen();
    connectedCreatorMismatchSocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id:
                '22222222-2222-4222-8222-222222222222',
            room_type: 'group',
            resumed: false,
            resume_token: resumeToken,
            mls_control_cursor: 0,
        }),
    });
    await connectedCreatorMismatch._inboundQueue;
    check(
        connectedCreatorMismatch._fatalAuthFailure
        && connectedCreatorMismatchError
            === 'ROOM_PROTOCOL_VIOLATION'
        && connectedCreatorMismatchSocket.closedWith?.code === 1008
        && !storage.has(
            `ws_creator_bootstrap_${connectedCreatorMismatchRoom}`,
        )
        && !storage.has(
            `ws_connection_${connectedCreatorMismatchRoom}`,
        )
        && !storage.has(
            `ws_room_type_${connectedCreatorMismatchRoom}`,
        ),
        'Connected creator identity mismatch erases bootstrap metadata before shutdown',
    );

    const rejectedCreatorRoom = 'creator-bootstrap-rejected-room';
    storage.set(
        `ws_creator_bootstrap_${rejectedCreatorRoom}`,
        creatorBootstrap,
    );
    storage.set(
        `ws_connection_${rejectedCreatorRoom}`,
        creatorConnectionId,
    );
    storage.set(`ws_room_type_${rejectedCreatorRoom}`, 'group');
    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        response(409, {
            code: 'CREATOR_BOOTSTRAP_REJECTED',
            error: 'invalid creator capability',
        }),
    ];
    fetchCalls = [];
    const socketsBeforeCreatorRejection = FakeWebSocket.instances.length;
    const rejectedCreator = new WebSocketManager(rejectedCreatorRoom);
    let creatorRejectionError = null;
    rejectedCreator.onError = (error) => {
        creatorRejectionError = error.message;
    };
    await rejectedCreator.connect();
    check(
        rejectedCreator._fatalAuthFailure
        && creatorRejectionError === 'CREATOR_BOOTSTRAP_REJECTED'
        && FakeWebSocket.instances.length
            === socketsBeforeCreatorRejection
        && !storage.has(
            `ws_creator_bootstrap_${rejectedCreatorRoom}`,
        )
        && !storage.has(`ws_connection_${rejectedCreatorRoom}`)
        && !storage.has(`ws_room_type_${rejectedCreatorRoom}`),
        'permanently rejected creator bootstrap is erased and fails closed',
    );

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('ordered-control-token'),
    ];
    const orderedManager = new WebSocketManager('ordered-control-room');
    const orderedTypes = [];
    let orderedError = null;
    orderedManager.onMessage = async (message) => {
        orderedTypes.push(message.type);
    };
    orderedManager.onError = (error) => { orderedError = error.message; };
    await orderedManager.connect();
    const orderedSocket = FakeWebSocket.instances.at(-1);
    orderedSocket.onopen();
    orderedSocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: 'ordered-relay-id',
            room_type: 'group',
            resumed: false,
            resume_token: resumeToken,
            mls_control_cursor: 0,
        }),
    });
    orderedSocket.onmessage({
        data: JSON.stringify({
            type: 'mlssync',
            through_seq: 0,
        }),
    });
    await orderedManager._inboundQueue;
    check(orderedTypes.join(',') === 'connected,mlssync',
        'group application startup waits behind the replay-complete marker');

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('replay-gated-control-token'),
    ];
    const replayGateManager =
        new WebSocketManager('replay-gated-control-room');
    replayGateManager.roomType = 'group';
    const replayedOwnAddCommit = {
        type: 'mls',
        payload: 'accepted-add-awaiting-own-echo',
        wire_format: 1,
        commit_ref: 'R'.repeat(43),
        key_package_ref: 'K'.repeat(43),
    };
    check(replayGateManager.send(replayedOwnAddCommit)
        && replayGateManager._pendingMlsControls.size === 1,
    'an Add Commit sent before disconnect remains tracked for replay');
    const addGeneratedDuringReplay = {
        type: 'mls',
        payload: 'add-generated-from-replayed-key-package',
        wire_format: 1,
        commit_ref: 'A'.repeat(43),
        key_package_ref: 'J'.repeat(43),
    };
    const removeGeneratedDuringReplay = {
        type: 'mls',
        payload: 'remove-generated-from-replayed-user-left',
        wire_format: 1,
        commit_ref: 'D'.repeat(43),
    };
    const welcomeGeneratedDuringReplay = {
        type: 'mls',
        payload: 'welcome-generated-from-replayed-own-add',
        wire_format: 3,
        ratchet_tree: 'accepted-ratchet-tree',
        commit_ref: replayedOwnAddCommit.commit_ref,
        key_package_ref: replayedOwnAddCommit.key_package_ref,
    };
    const replayGeneratedAccepted = [];
    replayGateManager.onMessage = async (message) => {
        if (message.type === 'mls' && message.wire_format === 5) {
            replayGeneratedAccepted.push(
                replayGateManager.send(addGeneratedDuringReplay),
            );
        }
        if (message.type === 'userleft') {
            replayGeneratedAccepted.push(
                replayGateManager.send(removeGeneratedDuringReplay),
            );
        }
        if (message.type === 'mls'
            && message.payload === replayedOwnAddCommit.payload) {
            replayGeneratedAccepted.push(
                replayGateManager.send(welcomeGeneratedDuringReplay),
            );
        }
    };
    await replayGateManager.connect();
    const replayGateSocket = FakeWebSocket.instances.at(-1);
    replayGateSocket.onopen();
    replayGateSocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: 'replay-gated-relay-id',
            room_type: 'group',
            resumed: false,
            resume_token: resumeToken,
            mls_control_cursor: 0,
        }),
    });
    await replayGateManager._inboundQueue;
    replayGateSocket.onmessage({
        data: JSON.stringify({
            type: 'mls',
            payload: 'replayed-joiner-key-package',
            wire_format: 5,
            sender_id: 'joining-peer',
            control_seq: 1,
        }),
    });
    replayGateSocket.onmessage({
        data: JSON.stringify({
            type: 'userleft',
            user_id: 'departed-during-replay',
            participant_count: 1,
            control_seq: 2,
        }),
    });
    replayGateSocket.onmessage({
        data: JSON.stringify({
            ...replayedOwnAddCommit,
            sender_id: 'replay-gated-relay-id',
            control_seq: 3,
        }),
    });
    await replayGateManager._inboundQueue;
    const replayOnlyFrames =
        replayGateSocket.sent.map((raw) => JSON.parse(raw));
    const replayGeneratedPayloads = [
        addGeneratedDuringReplay.payload,
        removeGeneratedDuringReplay.payload,
        welcomeGeneratedDuringReplay.payload,
    ];
    check(replayGeneratedAccepted.length === 3
        && replayGeneratedAccepted.every(Boolean)
        && replayGateManager._pendingMlsControls.size === 3
        && !replayOnlyFrames.some((frame) =>
            replayGeneratedPayloads.includes(frame.payload))
        && !replayOnlyFrames.some((frame) =>
            frame.payload === replayedOwnAddCommit.payload),
    'KeyPackage/Add, UserLeft/Remove, and own-Commit/Welcome controls stay queued during replay');
    check(replayOnlyFrames.length === 3
        && replayOnlyFrames.every((frame) => frame.type === 'mlsack')
        && replayOnlyFrames.map((frame) => frame.control_seq).join(',')
            === '1,2,3',
    'only cumulative MLS ACKs are emitted before replay completes');

    replayGateSocket.onmessage({
        data: JSON.stringify({
            type: 'mlssync',
            through_seq: 3,
        }),
    });
    await replayGateManager._inboundQueue;
    const replayCompletedFrames =
        replayGateSocket.sent.map((raw) => JSON.parse(raw));
    check(!replayGateManager._mlsControlSyncing
        && replayGeneratedPayloads.every((payload) =>
            replayCompletedFrames.some((frame) => frame.payload === payload))
        && !replayCompletedFrames.some((frame) =>
            frame.payload === replayedOwnAddCommit.payload),
    'authenticated mlssync releases only controls still pending after replay');
    check(replayGateManager.cancelPendingMlsControl(
        removeGeneratedDuringReplay,
    )
        && replayGateManager._pendingMlsControls.size === 2
        && !replayGateManager.cancelPendingMlsControl(
            removeGeneratedDuringReplay,
        ),
    'exact pending MLS controls can be cancelled once and only once');

    const keyPackageEnvelope = {
        type: 'mls',
        payload: 'key-package-body',
        wire_format: 5,
    };
    check(orderedManager.send(keyPackageEnvelope)
        && orderedManager._pendingMlsControls.size === 1,
    'locally sent MLS control remains pending until its sequenced own echo');
    orderedSocket.onmessage({
        data: JSON.stringify({
            ...keyPackageEnvelope,
            sender_id: 'ordered-relay-id',
            control_seq: 1,
        }),
    });
    await orderedManager._inboundQueue;
    const sentFrames = orderedSocket.sent.map((raw) => JSON.parse(raw));
    check(orderedManager.lastMlsControlSeq === 1
        && orderedManager._pendingMlsControls.size === 0
        && sentFrames.some((frame) =>
            frame.type === 'mlsack' && frame.control_seq === 1),
    'control cursor advances and ACKs only after application processing');

    orderedSocket.onmessage({
        data: JSON.stringify({
            type: 'userleft',
            user_id: 'departed-peer',
            participant_count: 1,
            control_seq: 2,
        }),
    });
    await orderedManager._inboundQueue;
    const lifecycleFrames = orderedSocket.sent.map((raw) => JSON.parse(raw));
    check(orderedManager.lastMlsControlSeq === 2
        && orderedTypes.at(-1) === 'userleft'
        && lifecycleFrames.some((frame) =>
            frame.type === 'mlsack' && frame.control_seq === 2),
    'group UserLeft shares the ordered replay cursor and is ACKed after handling');

    const retryEnvelope = {
        type: 'mls',
        payload: 'commit-awaiting-acceptance',
        wire_format: 1,
        commit_ref: 'A'.repeat(43),
    };
    check(orderedManager.send(retryEnvelope),
        'a second local MLS control is accepted by the live socket');
    const resumedSocket = new FakeWebSocket('wss://pinchat.test/ws/retry', []);
    orderedManager.ws = resumedSocket;
    orderedManager._connectionGeneration += 1;
    orderedManager._retryPendingMlsControls();
    check(resumedSocket.sent.map((raw) => JSON.parse(raw)).some((frame) =>
        frame.payload === retryEnvelope.payload),
    'unconfirmed MLS control is retransmitted after a new connection syncs');

    orderedManager.ws = orderedSocket;
    // This test swaps only the socket object to exercise retransmission; it
    // does not install a real second generation's handlers. Restore the
    // original generation before continuing to deliver frames to the
    // original socket closure.
    orderedManager._connectionGeneration -= 1;
    orderedSocket.readyState = FakeWebSocket.OPEN;
    orderedSocket.onmessage({
        data: JSON.stringify({
            type: 'mlsrejected',
            commit_ref: retryEnvelope.commit_ref,
            reason: 'commit_rate_limited',
            retry_after_secs: 60,
        }),
    });
    await orderedManager._inboundQueue;
    check(orderedManager._pendingMlsControls.size === 1,
        'rate-limited Commit stays tracked for retry instead of being lost');
    const retryTracked = [...orderedManager._pendingMlsControls.values()]
        .find((entry) =>
            entry.envelope.commit_ref === retryEnvelope.commit_ref);
    const sendsBeforeBackoffRetry = orderedSocket.sent.length;
    check(orderedManager.deferPendingMlsControl(
        retryEnvelope.commit_ref, 60,
    ), 'rate-limit response installs a retry-not-before deadline');
    orderedManager._retryPendingMlsControls();
    check(orderedSocket.sent.length === sendsBeforeBackoffRetry,
        'pending Commit is not retransmitted before retry_after elapses');
    retryTracked.retryNotBefore = 0;
    orderedManager._retryPendingMlsControls();
    check(orderedSocket.sent.length === sendsBeforeBackoffRetry + 1
        && JSON.parse(orderedSocket.sent.at(-1)).payload
            === retryEnvelope.payload,
    'pending Commit becomes retransmittable after its backoff deadline');

    const rejectedWelcomeEnvelope = {
        type: 'mls',
        payload: 'welcome-with-lost-correlation',
        wire_format: 3,
        ratchet_tree: 'welcome-tree',
        key_package_ref: 'W'.repeat(43),
        commit_ref: 'E'.repeat(43),
    };
    check(orderedManager.send(rejectedWelcomeEnvelope)
        && orderedManager._pendingMlsControls.size === 2,
    'post-acceptance Welcome is tracked while awaiting its own relay echo');
    orderedSocket.onmessage({
        data: JSON.stringify({
            type: 'mlsrejected',
            commit_ref: rejectedWelcomeEnvelope.commit_ref,
            reason: 'welcome_not_correlated',
            retry_after_secs: 0,
        }),
    });
    await orderedManager._inboundQueue;
    check(orderedManager._pendingMlsControls.size === 1
        && !orderedManager.cancelPendingMlsControl(
            rejectedWelcomeEnvelope,
        ),
    'permanently non-correlated Welcome is removed from transport retry state');

    const offlineWelcomeManager = new WebSocketManager(
        'offline-welcome-room',
    );
    offlineWelcomeManager.roomType = 'group';
    offlineWelcomeManager._connectionGeneration = 7;
    const offlineWelcome = {
        type: 'mls',
        payload: 'welcome-after-accepted-add',
        wire_format: 3,
        ratchet_tree: 'ratchet-tree',
        key_package_ref: 'K'.repeat(43),
        commit_ref: 'C'.repeat(43),
    };
    check(offlineWelcomeManager.send(offlineWelcome)
        && offlineWelcomeManager._pendingMlsControls.size === 1,
    'Welcome created after Commit acceptance is retained across a transient disconnect');
    const welcomeRetrySocket = new FakeWebSocket(
        'wss://pinchat.test/ws/offline-welcome', [],
    );
    offlineWelcomeManager.ws = welcomeRetrySocket;
    offlineWelcomeManager._connectionGeneration += 1;
    offlineWelcomeManager._retryPendingMlsControls();
    check(welcomeRetrySocket.sent.map((raw) => JSON.parse(raw)).some(
        (frame) => frame.payload === offlineWelcome.payload
            && frame.ratchet_tree === offlineWelcome.ratchet_tree),
    'post-acceptance Welcome is retried byte-for-byte after transport sync');
    offlineWelcomeManager._confirmMlsControl(offlineWelcome);
    check(offlineWelcomeManager._pendingMlsControls.size === 0,
        'retried Welcome remains pending until its exact own echo');

    const offlineOneToOne = new WebSocketManager('offline-onetoone-room');
    offlineOneToOne.roomType = 'onetoone';
    check(offlineOneToOne.send({ type: 'message', payload: 'not queued' }) === false,
        'ordinary disconnected traffic is not silently queued');

    orderedSocket.onmessage({
        data: JSON.stringify({
            type: 'mls',
            payload: 'gap',
            wire_format: 5,
            sender_id: 'peer',
            control_seq: 4,
        }),
    });
    await orderedManager._inboundQueue;
    check(orderedSocket.closedWith && orderedSocket.closedWith.code === 1008
        && orderedError === 'ROOM_PROTOCOL_VIOLATION',
    'a gap in the server MLS control sequence closes the group fail-closed');

    manager.onResumeRejected = () => false;
    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        response(409, { code: 'RESUME_REJECTED' }),
    ];
    const rejected = await manager.requestWsToken();
    check(rejected === null && manager._fatalAuthFailure,
        'resume rejection fails closed when a fresh relay identity is forbidden');
    check(manager.resumeToken === null && resumeError === 'RESUME_REJECTED',
        'rejected bearer is erased and surfaced as a distinct terminal error');

    const oneToOne = new WebSocketManager('one-to-one-room');
    oneToOne.resumeToken = resumeToken;
    oneToOne.onResumeRejected = () => true;
    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        response(409, { code: 'RESUME_REJECTED' }),
        response(200, { csrf_token: csrfToken }),
        successToken('fresh-identity-token'),
    ];
    fetchCalls = [];
    const fresh = await oneToOne.requestWsToken();
    check(fresh === 'fresh-identity-token' && !oneToOne._fatalAuthFailure,
        'explicit 1:1 policy may fall back to a fresh relay identity');
    check(fetchCalls[1].options.headers['X-PinChat-Resume-Token'] === resumeToken
        && !Object.prototype.hasOwnProperty.call(
            fetchCalls[3].options.headers,
            'X-PinChat-Resume-Token',
        ),
    'fresh-identity retry cannot replay the rejected resume bearer');

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('invalid-connected-token'),
    ];
    const invalidConnectedManager =
        new WebSocketManager('invalid-connected-room');
    let invalidConnectedError = null;
    let invalidConnectedDispatches = 0;
    invalidConnectedManager.onError = (error) => {
        invalidConnectedError = error.message;
    };
    invalidConnectedManager.onMessage = async () => {
        invalidConnectedDispatches += 1;
    };
    await invalidConnectedManager.connect();
    const invalidConnectedSocket = FakeWebSocket.instances.at(-1);
    invalidConnectedSocket.onopen();
    invalidConnectedSocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: 'invalid-connected-relay-id',
            room_type: 'group',
            resumed: false,
            resume_token: 'malformed',
            mls_control_cursor: 0,
        }),
    });
    await invalidConnectedManager._inboundQueue;
    check(invalidConnectedSocket.closedWith
        && invalidConnectedSocket.closedWith.code === 1008
        && invalidConnectedError === 'RESUME_TOKEN_INVALID',
    'malformed server resume credential closes the transport fail-closed');
    check(invalidConnectedDispatches === 0,
        'invalid Connected frame is never dispatched to application state');

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('duplicate-connected-token'),
    ];
    const duplicateConnectedManager =
        new WebSocketManager('duplicate-connected-room');
    let duplicateConnectedError = null;
    let duplicateConnectedDispatches = 0;
    duplicateConnectedManager.onError = (error) => {
        duplicateConnectedError = error.message;
    };
    duplicateConnectedManager.onMessage = async () => {
        duplicateConnectedDispatches += 1;
    };
    await duplicateConnectedManager.connect();
    const duplicateConnectedSocket = FakeWebSocket.instances.at(-1);
    duplicateConnectedSocket.onopen();
    const validConnectedFrame = {
        type: 'connected',
        user_id: 'duplicate-connected-relay-id',
        room_type: 'group',
        resumed: false,
        resume_token: resumeToken,
        mls_control_cursor: 0,
    };
    duplicateConnectedSocket.onmessage({
        data: JSON.stringify(validConnectedFrame),
    });
    await duplicateConnectedManager._inboundQueue;
    duplicateConnectedSocket.onmessage({
        data: JSON.stringify(validConnectedFrame),
    });
    await duplicateConnectedManager._inboundQueue;
    check(duplicateConnectedSocket.closedWith
        && duplicateConnectedSocket.closedWith.code === 1008
        && duplicateConnectedError === 'ROOM_PROTOCOL_VIOLATION'
        && duplicateConnectedDispatches === 1,
    'a second Connected frame is rejected before duplicate application dispatch');

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('protocol-gate-token'),
    ];
    const protocolManager = new WebSocketManager('group-protocol-room');
    let protocolError = null;
    let protocolDispatches = 0;
    protocolManager.onError = (error) => { protocolError = error.message; };
    protocolManager.onMessage = async () => { protocolDispatches += 1; };
    await protocolManager.connect();
    const protocolSocket = FakeWebSocket.instances.at(-1);
    protocolSocket.onopen();
    protocolSocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: 'group-relay-id',
            room_type: 'group',
            resumed: false,
            resume_token: resumeToken,
            mls_control_cursor: 0,
        }),
    });
    await protocolManager._inboundQueue;
    protocolSocket.onmessage({
        data: JSON.stringify({
            type: 'message',
            payload: 'legacy-1-to-1-frame',
        }),
    });
    check(protocolSocket.closedWith && protocolSocket.closedWith.code === 1008
        && protocolError === 'ROOM_PROTOCOL_VIOLATION',
    'group client closes on a relay-delivered 1:1 protocol frame');
    check(protocolDispatches === 1,
        'cross-protocol frame is rejected before application dispatch');

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('expected-room-type-token'),
    ];
    const roomTypePinnedManager = new WebSocketManager(
        'room-type-pinned-room', { expectedRoomType: 'group' },
    );
    let roomTypePinnedError = null;
    roomTypePinnedManager.onError = (error) => {
        roomTypePinnedError = error.message;
    };
    await roomTypePinnedManager.connect();
    const roomTypePinnedSocket = FakeWebSocket.instances.at(-1);
    roomTypePinnedSocket.onopen();
    roomTypePinnedSocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: 'room-type-pinned-relay-id',
            room_type: 'onetoone',
            resumed: false,
            resume_token: resumeToken,
        }),
    });
    await roomTypePinnedManager._inboundQueue;
    check(roomTypePinnedSocket.closedWith?.code === 1008
        && roomTypePinnedError === 'ROOM_PROTOCOL_VIOLATION',
    'Connected room type must match the authenticated invite/bootstrap expectation');

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('terminal-mls-state-token'),
    ];
    const terminalManager = new WebSocketManager('terminal-mls-room');
    let terminalError = null;
    terminalManager.onError = (error) => { terminalError = error.message; };
    terminalManager.onMessage = async (message) => {
        if (message.type === 'mls') {
            const error = new Error('authenticated Commit cannot apply');
            error.mlsFatalState = true;
            throw error;
        }
    };
    await terminalManager.connect();
    const terminalSocket = FakeWebSocket.instances.at(-1);
    terminalSocket.onopen();
    terminalSocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: 'terminal-relay-id',
            room_type: 'group',
            resumed: false,
            resume_token: resumeToken,
            mls_control_cursor: 0,
        }),
    });
    await terminalManager._inboundQueue;
    check(terminalManager.send({
        type: 'mls',
        payload: 'earlier-welcome-awaiting-echo',
        wire_format: 3,
        ratchet_tree: 'terminal-tree',
        key_package_ref: 'T'.repeat(43),
        commit_ref: 'U'.repeat(43),
    }) && terminalManager._pendingMlsControls.size === 1,
    'terminal-state fixture retains an unrelated pending MLS control');
    terminalSocket.onmessage({
        data: JSON.stringify({
            type: 'mls',
            payload: 'authenticated-malformed-commit',
            wire_format: 1,
            sender_id: 'creator-route',
            control_seq: 1,
        }),
    });
    // Queue the same sequence again before the first handler rejects. A
    // terminal failure must prevent already-queued work from later ACKing the
    // sequence after MLSSession has destroyed its state.
    terminalSocket.onmessage({
        data: JSON.stringify({
            type: 'mls',
            payload: 'authenticated-malformed-commit',
            wire_format: 1,
            sender_id: 'creator-route',
            control_seq: 1,
        }),
    });
    await terminalManager._inboundQueue;
    const terminalFrames = terminalSocket.sent.map((raw) => JSON.parse(raw));
    check(terminalManager.lastMlsControlSeq === 0
        && !terminalFrames.some((frame) =>
            frame.type === 'mlsack' && frame.control_seq === 1)
        && terminalSocket.closedWith?.code === 1008
        && terminalManager._pendingMlsControls.size === 0
        && terminalError === 'MLS_STATE_DESYNC',
    'terminal MLS failure clears retries and neither advances nor ACKs its control');

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('retry-budget-mls-control-token'),
    ];
    const retryBudgetManager =
        new WebSocketManager('retry-budget-mls-room');
    let retryBudgetError = null;
    retryBudgetManager.onError = (error) => {
        retryBudgetError = error.message;
    };
    retryBudgetManager.onMessage = async (message) => {
        if (message.type === 'mls') {
            throw new Error('one-shot platform operation failed');
        }
    };
    await retryBudgetManager.connect();
    const retryBudgetSocket = FakeWebSocket.instances.at(-1);
    retryBudgetSocket.onopen();
    retryBudgetSocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: 'retry-budget-relay-id',
            room_type: 'group',
            resumed: false,
            resume_token: resumeToken,
            mls_control_cursor: 0,
        }),
    });
    await retryBudgetManager._inboundQueue;
    for (let attempt = 0; attempt < 3; attempt += 1) {
        // Model replay of the unchanged sequence on each resumed socket
        // without rebuilding the whole token exchange in this unit test.
        retryBudgetSocket.readyState = FakeWebSocket.OPEN;
        retryBudgetSocket.onmessage({
            data: JSON.stringify({
                type: 'mls',
                payload: 'AA',
                wire_format: 5,
                sender_id: 'peer-retry',
                control_seq: 1,
            }),
        });
        await retryBudgetManager._inboundQueue;
    }
    const retryBudgetFrames =
        retryBudgetSocket.sent.map((raw) => JSON.parse(raw));
    check(retryBudgetManager.lastMlsControlSeq === 0
        && !retryBudgetFrames.some((frame) =>
            frame.type === 'mlsack' && frame.control_seq === 1)
        && retryBudgetSocket.closedWith?.code === 1008
        && retryBudgetError === 'MLS_STATE_DESYNC',
    'untyped ordered MLS failure exhausts a bounded replay budget and fails closed');

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('rejected-mls-control-token'),
    ];
    const rejectedManager = new WebSocketManager('rejected-mls-control-room');
    const rejectedDispatches = [];
    rejectedManager.onMessage = async (message) => {
        rejectedDispatches.push(message.control_seq || message.type);
        if (message.type === 'mls' && message.control_seq === 1) {
            const error = new Error('deterministically invalid MLS control');
            error.mlsControlRejected = true;
            throw error;
        }
    };
    await rejectedManager.connect();
    const rejectedSocket = FakeWebSocket.instances.at(-1);
    rejectedSocket.onopen();
    rejectedSocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: 'rejected-control-relay-id',
            room_type: 'group',
            resumed: false,
            resume_token: resumeToken,
            mls_control_cursor: 0,
        }),
    });
    await rejectedManager._inboundQueue;
    for (const controlSeq of [1, 2]) {
        rejectedSocket.onmessage({
            data: JSON.stringify({
                type: 'mls',
                payload: 'AA',
                wire_format: 5,
                sender_id: `peer-${controlSeq}`,
                control_seq: controlSeq,
            }),
        });
        await rejectedManager._inboundQueue;
    }
    const rejectedFrames = rejectedSocket.sent.map((raw) => JSON.parse(raw));
    check(rejectedManager.lastMlsControlSeq === 2
        && rejectedSocket.closedWith === null
        && rejectedDispatches.includes(1)
        && rejectedDispatches.includes(2)
        && rejectedFrames.some((frame) =>
            frame.type === 'mlsack' && frame.control_seq === 1)
        && rejectedFrames.some((frame) =>
            frame.type === 'mlsack' && frame.control_seq === 2),
    'deterministically rejected MLS control is ACKed and does not pin the next sequence');

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('bounded-inbound-token'),
    ];
    const queueManager = new WebSocketManager('bounded-inbound-room');
    let queueError = null;
    const queueGate = deferred();
    queueManager.onError = (error) => { queueError = error.message; };
    queueManager.onMessage = async (message) => {
        if (message.type === 'message') await queueGate.promise;
    };
    await queueManager.connect();
    const queueSocket = FakeWebSocket.instances.at(-1);
    queueSocket.onopen();
    queueSocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: 'bounded-relay-id',
            room_type: 'onetoone',
            resumed: false,
            resume_token: resumeToken,
        }),
    });
    await queueManager._inboundQueue;
    const queuedFrame = JSON.stringify({
        type: 'message',
        payload: 'queued',
    });
    for (let index = 0; index < 129; index += 1) {
        queueSocket.onmessage({ data: queuedFrame });
    }
    check(queueSocket.closedWith?.code === 1009
        && queueError === 'INBOUND_QUEUE_OVERFLOW'
        && queueManager._queuedInboundMessages === 128,
    'browser inbound queue fails closed at its bounded message budget');
    queueGate.resolve();
    await queueManager._inboundQueue;

    queuedResponses = [
        response(200, { csrf_token: csrfToken }),
        successToken('one-to-one-protocol-gate-token'),
    ];
    const directManager = new WebSocketManager('one-to-one-protocol-room');
    let directError = null;
    let directDispatches = 0;
    directManager.onError = (error) => { directError = error.message; };
    directManager.onMessage = async () => { directDispatches += 1; };
    await directManager.connect();
    const directSocket = FakeWebSocket.instances.at(-1);
    directSocket.onopen();
    directSocket.onmessage({
        data: JSON.stringify({
            type: 'connected',
            user_id: 'direct-relay-id',
            room_type: 'onetoone',
            resumed: false,
            resume_token: resumeToken,
        }),
    });
    await directManager._inboundQueue;
    directSocket.onmessage({
        data: JSON.stringify({
            type: 'mls',
            payload: 'group-frame',
            wire_format: 2,
        }),
    });
    check(directSocket.closedWith && directSocket.closedWith.code === 1008
        && directError === 'ROOM_PROTOCOL_VIOLATION',
    '1:1 client closes on a relay-delivered MLS frame');
    check(directDispatches === 1,
        'MLS frame in a 1:1 room is rejected before application dispatch');

    console.log(`\n${passed} assertions passed`);
}

main().catch((error) => {
    console.error('FAILED:', error);
    process.exit(1);
});
