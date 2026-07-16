/**
 * Module for managing the WebSocket connection with reconnection logic
 */

/**
 * Fetch a fresh CSRF token from /api/csrf and return it. The endpoint
 * also sets the csrf_token cookie, so the X-CSRF-Token header sent on
 * the subsequent /api/ws-token POST will match the cookie when the
 * server verifies the double-submit pair.
 */
async function _fetchCsrfTokenForWs() {
    const r = await fetch('/api/csrf', { credentials: 'same-origin' });
    if (!r.ok) throw new Error(`CSRF token fetch failed: ${r.status}`);
    const data = await r.json();
    if (!/^[a-f0-9]{32}\.[a-f0-9]{64}$/.test(data.csrf_token)) {
        throw new Error('CSRF token format invalid');
    }
    return data.csrf_token;
}

function _isValidWsResumeToken(value) {
    return typeof value === 'string'
        && value.length >= 64
        && value.length <= 2048
        && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);
}

function _isValidCreatorBootstrapToken(value) {
    return typeof value === 'string'
        && /^[A-Za-z0-9_-]{43}$/.test(value)
        && /[AEIMQUYcgkosw048]$/.test(value);
}

function _isValidRelayConnectionId(value) {
    return typeof value === 'string'
        && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
            .test(value);
}

const _COMMON_RELAY_MESSAGE_TYPES = new Set([
    'connected', 'userjoined', 'userleft', 'error',
]);
const MAX_INBOUND_QUEUE_MESSAGES = 128;
const MAX_INBOUND_QUEUE_CHARS = 8 * 1024 * 1024;
const MAX_PENDING_MLS_CONTROLS = 64;
const MAX_MLS_CONTROL_REPLAY_ATTEMPTS = 3;

function _isMessageAllowedForRoom(roomType, messageType) {
    if (_COMMON_RELAY_MESSAGE_TYPES.has(messageType)) return true;
    if (roomType === 'group') {
        return messageType === 'mls'
            || messageType === 'mlssync'
            || messageType === 'mlsrejected';
    }
    if (roomType === 'onetoone') {
        return messageType === 'ecdh_public_key'
            || messageType === 'message'
            || messageType === 'image';
    }
    return false;
}

class WebSocketManager {
    constructor(roomId, { expectedRoomType = null } = {}) {
        this.roomId = roomId;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000; // Base delay in ms
        this.isManuallyDisconnected = false;

        // Terminal session flags (v1).
        // _fatalAuthFailure: explicit protocol/auth mismatch → no auto-reconnect,
        //                    page refresh required (set by requestWsToken gate,
        //                    onopen subprotocol mismatch, SIGNATURE_INVALID).
        // _connectionExhausted: transient transport failure after N retries
        //                    → user-initiated reconnect gets a fresh budget.
        this._fatalAuthFailure = false;
        this._connectionExhausted = false;
        this._connectPromise = null;
        this._connectAttemptGeneration = 0;

        // C-01: serial dispatch queue for inbound messages. The DoubleRatchet
        // has its own internal mutex, but app.js#handleWebSocketMessage also
        // mutates non-cryptographic state (participantCount, peerUserId,
        // ecdhHandshakeStatus, …) and must observe messages in arrival order.
        // Errors do not poison the queue — see the .catch() in onmessage.
        this._inboundQueue = Promise.resolve();
        this._queuedInboundMessages = 0;
        this._queuedInboundChars = 0;

        // Token caching for reconnection (avoids PoW on every reconnect)
        this.cachedToken = null;
        this.tokenExpiresAt = 0;
        // Server-signed, room/member-bound reconnect credential. It is kept
        // in page memory only: persisting it across a reload would preserve a
        // relay identity while the corresponding in-memory MLS state is gone.
        this.resumeToken = null;
        // A group creator receives a separate tab-scoped bootstrap bearer at
        // room creation. Unlike the short, single-use upgrade JWT, it can
        // re-mint that room's preallocated creator connection ID if navigation
        // is slow or the first transport dies before Connected supplies the
        // normal resume credential. It is erased immediately on Connected.
        this.creatorBootstrapToken = null;
        this.expectedCreatorConnectionId = null;
        // Stable relay identity and ordered MLS-control cursor. The cursor is
        // kept in page memory with the MLS state and is bound into every
        // resume JWT. It advances only after application processing succeeds.
        this.connectionId = null;
        this.lastMlsControlSeq = 0;
        this._mlsControlSyncing = false;
        this._connectionGeneration = 0;
        // Exact locally-sent KeyPackage/Proposal/Commit/Welcome envelopes
        // awaiting their server-sequenced own echo. They are retained even
        // when a transient disconnect happens immediately before send(), then
        // retried only after resumed replay completes. This is especially
        // important for a Welcome produced after its Add Commit is already
        // accepted: that epoch cannot safely be rolled back.
        this._pendingMlsControls = new Map();
        // Unexpected local crypto/platform failures replay the immutable
        // control from the unchanged cursor. Bound those retries so a
        // persistent browser failure cannot create an infinite reconnect
        // loop; exhaustion terminates the MLS session fail-closed.
        this._mlsControlRetryAttempts = new Map();
        // Set from the first server-authenticated Connected frame and pinned
        // for the lifetime of this page. It gates every subsequent relay
        // message before application dispatch.
        if (expectedRoomType !== null
            && expectedRoomType !== 'group'
            && expectedRoomType !== 'onetoone') {
            throw new Error('WebSocketManager: invalid expected room type');
        }
        this.expectedRoomType = expectedRoomType;
        this.roomType = null;

        // Callbacks
        this.onConnected = null;
        this.onDisconnected = null;
        this.onMessage = null;
        this.onError = null;
        this.onPowProgress = null; // Callback for PoW progress updates
        // Return true to fall back to a brand-new relay identity when resume
        // has expired. Group rooms return false because silently doing so
        // would detach sender_id from the still-live MLS leaf.
        this.onResumeRejected = null;
        // Called before the UI error callback whenever continuing would risk
        // using MLS secrets after a terminal transport/protocol failure.
        this.onTerminalSecurityFailure = null;

        // Close WebSocket on page unload to prevent rate limit issues on refresh
        this._boundBeforeUnload = () => this._handleBeforeUnload();
        window.addEventListener('beforeunload', this._boundBeforeUnload);
    }

    /**
     * Handle page unload - close WebSocket cleanly
     * This prevents rate limit exhaustion when user refreshes the page
     * @private
     */
    _handleBeforeUnload() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            // Use code 1000 (normal closure) to signal intentional disconnect
            this.ws.close(1000, 'Page unload');
        }
    }

    _failRoomProtocol(reason) {
        console.error('[WS] Room protocol violation:', reason);
        this._fatalAuthFailure = true;
        this.resumeToken = null;
        if (this.creatorBootstrapToken !== null
            || this.expectedCreatorConnectionId !== null) {
            this._clearCreatorBootstrapState();
        }
        try {
            if (this.ws) this.ws.close(1008, 'Room protocol violation');
        } catch (_) { /* ignore close races */ }
        this._notifyTerminalSecurityFailure(reason);
        if (this.onError) {
            try {
                this.onError(new Error('ROOM_PROTOCOL_VIOLATION'));
            } catch (error) {
                // A UI callback must not re-enter this failure path through
                // the outer WebSocket message parser's catch block.
                console.error('[WS] onError failed during protocol shutdown:', error);
            }
        }
    }

    _failMlsState(reason) {
        console.error('[WS] Terminal MLS state failure:', reason);
        this._fatalAuthFailure = true;
        this.resumeToken = null;
        this._pendingMlsControls.clear();
        this._mlsControlRetryAttempts.clear();
        try {
            if (this.ws) this.ws.close(1008, 'MLS state desynchronized');
        } catch (_) { /* ignore close races */ }
        this._notifyTerminalSecurityFailure(reason);
        if (this.onError) {
            try {
                this.onError(new Error('MLS_STATE_DESYNC'));
            } catch (error) {
                console.error('[WS] onError failed during MLS shutdown:', error);
            }
        }
    }

    _failInboundQueue(reason) {
        console.error('[WS] Inbound queue capacity exceeded:', reason);
        this._fatalAuthFailure = true;
        this.resumeToken = null;
        try {
            if (this.ws) this.ws.close(1009, 'Inbound queue capacity exceeded');
        } catch (_) { /* ignore close races */ }
        this._notifyTerminalSecurityFailure(reason);
        if (this.onError) {
            try {
                this.onError(new Error('INBOUND_QUEUE_OVERFLOW'));
            } catch (error) {
                console.error('[WS] onError failed during queue shutdown:', error);
            }
        }
    }

    _clearCreatorBootstrapState() {
        this.creatorBootstrapToken = null;
        this.expectedCreatorConnectionId = null;
        sessionStorage.removeItem(
            `ws_creator_bootstrap_${this.roomId}`,
        );
        sessionStorage.removeItem(`ws_connection_${this.roomId}`);
        sessionStorage.removeItem(`ws_room_type_${this.roomId}`);
    }

    _notifyTerminalSecurityFailure(reason) {
        if (!this.onTerminalSecurityFailure) return;
        try {
            this.onTerminalSecurityFailure(reason);
        } catch (error) {
            console.error('[WS] terminal security cleanup failed:', error);
        }
    }

    _isMlsControlEnvelope(message) {
        return message && message.type === 'mls'
            && (message.wire_format === 1
                || message.wire_format === 3
                || message.wire_format === 5);
    }

    _isOrderedGroupControl(message) {
        return this.roomType === 'group' && message
            && (this._isMlsControlEnvelope(message)
                || message.type === 'userjoined'
                || message.type === 'userleft');
    }

    _mlsControlKey(message) {
        return JSON.stringify([
            message.wire_format,
            message.payload || '',
            message.ratchet_tree || '',
            message.key_package_ref || '',
            message.commit_ref || '',
            message.bootstrap_proof || '',
        ]);
    }

    _confirmMlsControl(message) {
        if (!this._isMlsControlEnvelope(message)) return;
        this._pendingMlsControls.delete(this._mlsControlKey(message));
    }

    /**
     * Stop retrying one exact locally-generated MLS control envelope.
     *
     * This is intentionally keyed by the complete immutable correlation
     * material used for store-and-retry, rather than by only CommitRef or
     * KeyPackageRef. Callers can therefore abandon a candidate control
     * without accidentally cancelling another concurrent admission.
     *
     * @param {object} message
     * @returns {boolean} True only when a pending exact envelope was removed
     */
    cancelPendingMlsControl(message) {
        if (!this._isMlsControlEnvelope(message)) return false;
        return this._pendingMlsControls.delete(this._mlsControlKey(message));
    }

    _cancelPendingWelcomeByCommitRef(commitRef) {
        if (typeof commitRef !== 'string') return 0;
        let removed = 0;
        for (const [key, entry] of this._pendingMlsControls) {
            if (entry.envelope.wire_format === 3
                && entry.envelope.commit_ref === commitRef) {
                this._pendingMlsControls.delete(key);
                removed += 1;
            }
        }
        return removed;
    }

    _sendMlsControlAck(seq) {
        if (!Number.isSafeInteger(seq) || seq <= 0
            || !this.ws || this.ws.readyState !== WebSocket.OPEN) return;
        try {
            this.ws.send(JSON.stringify({
                type: 'mlsack',
                control_seq: seq,
            }));
        } catch (error) {
            // The cursor remains in memory and is bound into the next resume
            // token, so losing this best-effort ACK cannot roll state back.
            console.warn('[WS] Failed to send MLS control ACK:', error);
        }
    }

    _retryPendingMlsControls() {
        if (this._mlsControlSyncing
            || !this.ws || this.ws.readyState !== WebSocket.OPEN) return;
        for (const entry of this._pendingMlsControls.values()) {
            if (entry.retryNotBefore > Date.now()) continue;
            if (entry.lastSentGeneration >= this._connectionGeneration) continue;
            try {
                this.ws.send(JSON.stringify(entry.envelope));
                entry.lastSentGeneration = this._connectionGeneration;
            } catch (error) {
                console.warn('[WS] Failed to retry pending MLS control:', error);
                break;
            }
        }
    }

    deferPendingMlsControl(commitRef, retryAfterSecs) {
        if (typeof commitRef !== 'string'
            || !Number.isSafeInteger(retryAfterSecs)
            || retryAfterSecs <= 0) return false;
        const retryNotBefore = Date.now()
            + Math.min(retryAfterSecs, 3600) * 1000;
        let matched = false;
        for (const entry of this._pendingMlsControls.values()) {
            if (entry.envelope.commit_ref !== commitRef) continue;
            entry.retryNotBefore = Math.max(
                entry.retryNotBefore || 0,
                retryNotBefore,
            );
            entry.lastSentGeneration = Math.min(
                entry.lastSentGeneration,
                this._connectionGeneration - 1,
            );
            matched = true;
        }
        if (matched) {
            const timer = setTimeout(
                () => this._retryPendingMlsControls(),
                Math.max(0, retryNotBefore - Date.now()),
            );
            if (typeof timer?.unref === 'function') timer.unref();
        }
        return matched;
    }

    /**
     * Requests WebSocket authentication token
     *
     * The token endpoint requires PoW. This method will:
     * 1. Request token (may fail if no PoW challenge cached)
     * 2. If 428 (Precondition Required), solve PoW challenge
     * 3. Retry token request with PoW solution
     *
     * @returns {Promise<string|null>} JWT token or null if failed
     */
    async requestWsToken() {
        try {
            // CSRF: /api/ws-token is now POST with double-submit token
            // gating. Fetch a fresh cookie/header pair every call — the
            // /api/csrf endpoint sets a Set-Cookie alongside its JSON
            // response so the cookie/header always agree.
            const csrfToken = await _fetchCsrfTokenForWs();
            const tokenHeaders = (powNonce = null) => {
                const headers = {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                };
                if (powNonce !== null) headers['X-Pow-Nonce'] = powNonce.toString();
                if (this.resumeToken) {
                    if (!_isValidWsResumeToken(this.resumeToken)) {
                        throw new Error('Stored WebSocket resume credential is malformed');
                    }
                    headers['X-PinChat-Resume-Token'] = this.resumeToken;
                    if (this.roomType === 'group') {
                        if (!Number.isSafeInteger(this.lastMlsControlSeq)
                            || this.lastMlsControlSeq < 0) {
                            throw new Error('Stored MLS control cursor is malformed');
                        }
                        headers['X-PinChat-MLS-Control-Seq']
                            = String(this.lastMlsControlSeq);
                    }
                } else if (this.creatorBootstrapToken) {
                    if (!_isValidCreatorBootstrapToken(
                        this.creatorBootstrapToken,
                    )
                        || !_isValidRelayConnectionId(
                            this.expectedCreatorConnectionId,
                        )) {
                        throw new Error(
                            'Stored group creator bootstrap credential is malformed',
                        );
                    }
                    headers['X-PinChat-Creator-Bootstrap']
                        = this.creatorBootstrapToken;
                }
                return headers;
            };

            const handleResumeRejection = async (response) => {
                if (response.status !== 409) return { handled: false, token: null };
                let body = null;
                try { body = await response.json(); } catch (_) { /* malformed error */ }
                if (body?.code === 'CREATOR_BOOTSTRAP_REJECTED') {
                    this._clearCreatorBootstrapState();
                    this._fatalAuthFailure = true;
                    if (this.onError) {
                        this.onError(new Error(
                            'CREATOR_BOOTSTRAP_REJECTED',
                        ));
                    }
                    return { handled: true, token: null };
                }
                if (!body || (body.code !== 'RESUME_REJECTED'
                    && body.code !== 'MLS_CONTROL_RESYNC_REQUIRED')) {
                    return { handled: false, token: null };
                }
                this.resumeToken = null;
                if (body.code === 'MLS_CONTROL_RESYNC_REQUIRED') {
                    if (this.creatorBootstrapToken !== null) {
                        this._clearCreatorBootstrapState();
                    }
                    this._fatalAuthFailure = true;
                    if (this.onError) {
                        this.onError(new Error('MLS_CONTROL_RESYNC_REQUIRED'));
                    }
                    return { handled: true, token: null };
                }
                const allowFreshIdentity = this.onResumeRejected
                    ? await this.onResumeRejected()
                    : false;
                if (allowFreshIdentity) {
                    return { handled: true, token: await this.requestWsToken() };
                }
                this._fatalAuthFailure = true;
                if (this.onError) this.onError(new Error('RESUME_REJECTED'));
                return { handled: true, token: null };
            };

            // First attempt: request token (may succeed if PoW already solved for room creation)
            let response = await fetch(`/api/ws-token/${this.roomId}`, {
                method: 'POST',
                credentials: 'same-origin',
                headers: tokenHeaders(),
            });

            let resumeResult = await handleResumeRejection(response);
            if (resumeResult.handled) return resumeResult.token;

            // If 401 Unauthorized, redirect to login with return URL (relative path only)
            if (response.status === 401) {
                console.log('Authentication required, redirecting to login...');
                // SECURITY: Never include window.location.hash in the returnUrl.
                // The fragment holds the E2E encryption key (#key=...) and must never
                // leave the client. Stash it in sessionStorage (tab-scoped) so it can
                // be restored after login; the server-facing redirect carries path+query only.
                if (window.location.hash) {
                    const _stashKey = `pinchat_hash:${window.location.pathname}`;
                    sessionStorage.setItem(_stashKey, window.location.hash);
                    setTimeout(() => sessionStorage.removeItem(_stashKey), 30000);
                }
                const returnUrl = encodeURIComponent(window.location.pathname + window.location.search);
                window.location.href = `/login?redirect=${returnUrl}`;
                return null;
            }

            // If 428 Precondition Required, we need to solve PoW first
            if (response.status === 428) {
                console.log('PoW challenge required for WebSocket token');

                const challengeData = await response.json();

                if (!challengeData.challenge || !challengeData.difficulty) {
                    console.error('Invalid challenge data:', challengeData);
                    return null;
                }

                console.log(`Solving PoW challenge (difficulty: ${challengeData.difficulty})...`);

                // Notify UI that PoW is starting
                if (this.onPowProgress) {
                    this.onPowProgress(0);
                }

                // Generate mask from difficulty (server doesn't send mask to reduce payload)
                const mask = ProofOfWork.generateMask(challengeData.difficulty);

                // Solve PoW challenge using ProofOfWork class
                const solver = new ProofOfWork(challengeData.challenge, mask);
                const nonce = await solver.solve((attempts) => {
                    // Update progress every 100,000 attempts
                    if (this.onPowProgress) {
                        this.onPowProgress(attempts);
                    }
                });

                console.log('PoW solved, retrying token request with solution...');

                // Notify UI that PoW is complete
                if (this.onPowProgress) {
                    this.onPowProgress(-1); // -1 indicates completion
                }

                // Retry token request with PoW solution. The CSRF
                // double-submit pair is single-use semantically (verified
                // server-side) but cookie + header are still both valid
                // until the cookie expires; reuse the same csrfToken
                // captured at the top of this method.
                response = await fetch(`/api/ws-token/${this.roomId}`, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: tokenHeaders(nonce),
                });

                resumeResult = await handleResumeRejection(response);
                if (resumeResult.handled) return resumeResult.token;

                if (!response.ok) {
                    // Handle 401 after PoW (session may have expired)
                    if (response.status === 401) {
                        console.log('Authentication required, redirecting to login...');
                        if (window.location.hash) {
                            const _stashKey = `pinchat_hash:${window.location.pathname}`;
                            sessionStorage.setItem(_stashKey, window.location.hash);
                            setTimeout(() => sessionStorage.removeItem(_stashKey), 30000);
                        }
                        const returnUrl = encodeURIComponent(window.location.pathname + window.location.search);
                        window.location.href = `/login?redirect=${returnUrl}`;
                        return null;
                    }
                    const error = await response.json();
                    console.error('Failed to obtain WebSocket token after PoW:', error);
                    return null;
                }
            }

            if (!response.ok) {
                // Handle 401 (shouldn't reach here, but just in case)
                if (response.status === 401) {
                    console.log('Authentication required, redirecting to login...');
                    if (window.location.hash) {
                        const _stashKey = `pinchat_hash:${window.location.pathname}`;
                        sessionStorage.setItem(_stashKey, window.location.hash);
                        setTimeout(() => sessionStorage.removeItem(_stashKey), 30000);
                    }
                    const returnUrl = encodeURIComponent(window.location.pathname + window.location.search);
                    window.location.href = `/login?redirect=${returnUrl}`;
                    return null;
                }
                const error = await response.json();
                console.error('Failed to obtain WebSocket token:', error);
                return null;
            }

            const data = await response.json();

            // v1 gate: verify the server advertises a compatible protocol version
            // and the pinchat.v1 subprotocol. This catches client-v1-vs-server-v0
            // mismatches BEFORE we attempt a WebSocket upgrade (where browser
            // failure modes are opaque — opaque onerror + 1006 close).
            const expectedV = window.PINCHAT_PROTOCOL_VERSION || 1;
            if (
                data.protocol_version !== expectedV ||
                !Array.isArray(data.supported_subprotocols) ||
                !data.supported_subprotocols.includes('pinchat.v1')
            ) {
                console.error(
                    '[WS] Server protocol mismatch: got',
                    data.protocol_version,
                    data.supported_subprotocols,
                    'expected v',
                    expectedV
                );
                this._fatalAuthFailure = true;
                if (this.onError) this.onError(new Error('PROTOCOL_OR_AUTH_FAILURE'));
                return null;
            }

            if (this.creatorBootstrapToken) {
                if (data.connection_id
                        !== this.expectedCreatorConnectionId) {
                    console.error(
                        '[WS] Creator bootstrap returned a different relay identity',
                    );
                    this._clearCreatorBootstrapState();
                    this._fatalAuthFailure = true;
                    if (this.onError) {
                        this.onError(new Error('CREATOR_IDENTITY_MISMATCH'));
                    }
                    return null;
                }
                if (data.mls_control_cursor !== undefined) {
                    if (!Number.isSafeInteger(data.mls_control_cursor)
                        || data.mls_control_cursor !== 0
                        || this.connectionId !== null) {
                        console.error(
                            '[WS] Creator bootstrap returned an invalid MLS cursor',
                        );
                        this._clearCreatorBootstrapState();
                        this._fatalAuthFailure = true;
                        if (this.onError) {
                            this.onError(new Error(
                                'CREATOR_BOOTSTRAP_CURSOR_INVALID',
                            ));
                        }
                        return null;
                    }
                    // No Connected frame has ever been received in this tab.
                    // The server cursor is the fresh-admission boundary it
                    // recorded before the lost Connected, so adopting it does
                    // not skip any MLS state this browser had authenticated.
                    this.lastMlsControlSeq = data.mls_control_cursor;
                }
                this.roomType = 'group';
            }

            // Cache token and expiration for reconnection
            // Use 29s instead of 30s to provide safety margin
            this.cachedToken = data.token;
            this.tokenExpiresAt = Date.now() + 29000;

            console.log('✅ WebSocket token cached (valid for 29s)');

            return data.token;

        } catch (error) {
            console.error('Error requesting WebSocket token:', error);
            return null;
        }
    }

    /**
     * Connects to the WebSocket
     *
     * Security: Requires JWT token obtained from /api/ws-token/{room_id}
     * The token proves that the client has solved PoW and is authorized to connect.
     *
     * Performance optimization: Reuses cached token if still valid (< 29s)
     * to avoid solving PoW on every reconnection attempt.
     */
    async connect() {
        if (this._fatalAuthFailure) {
            console.error('[WS] connect() blocked: session is in fatal auth/protocol failure — page refresh required');
            return;
        }
        if (this._connectPromise) return this._connectPromise;
        if (this.ws && (this.ws.readyState === WebSocket.CONNECTING
            || this.ws.readyState === WebSocket.OPEN)) {
            console.warn('WebSocket connection already active');
            return;
        }

        const connectAttemptGeneration = ++this._connectAttemptGeneration;
        const attempt = this._connectOnce(connectAttemptGeneration);
        this._connectPromise = attempt;
        try {
            return await attempt;
        } finally {
            if (this._connectPromise === attempt) {
                this._connectPromise = null;
            }
        }
    }

    async _connectOnce(connectAttemptGeneration) {
        // Enforcement gate: once we've detected a terminal auth/protocol failure
        // (v1 gate mismatch, SIGNATURE_INVALID, subprotocol mismatch on onopen),
        // refuse to attempt a new connection. The user must refresh the page.
        if (this._fatalAuthFailure) {
            console.error('[WS] connect() blocked: session is in fatal auth/protocol failure — page refresh required');
            return;
        }
        if (connectAttemptGeneration !== this._connectAttemptGeneration) return;

        if (this.ws && (this.ws.readyState === WebSocket.CONNECTING
            || this.ws.readyState === WebSocket.OPEN)) {
            console.warn('WebSocket connection already active');
            return;
        }

        this.isManuallyDisconnected = false;

        // Drop the short-lived, single-use creator upgrade material after it
        // is copied into this attempt. The stable connection ID and separate
        // bootstrap bearer remain until Connected establishes a normal resume
        // credential.
        const clearCreatorOneShotMetadata = () => {
            sessionStorage.removeItem(`ws_token_${this.roomId}`);
            sessionStorage.removeItem(`ws_protocol_version_${this.roomId}`);
            sessionStorage.removeItem(`ws_subprotocols_${this.roomId}`);
        };

        let token;

        // PATH 1: Creator optimization — token was pre-issued by /api/rooms.
        const creatorToken = sessionStorage.getItem(`ws_token_${this.roomId}`);
        const creatorConnectionId = sessionStorage.getItem(`ws_connection_${this.roomId}`);
        const creatorBootstrapToken = sessionStorage.getItem(
            `ws_creator_bootstrap_${this.roomId}`,
        );
        const creatorRoomType = sessionStorage.getItem(
            `ws_room_type_${this.roomId}`,
        );
        const creatorProtoVersion = sessionStorage.getItem(`ws_protocol_version_${this.roomId}`);
        const creatorSubprotocols = sessionStorage.getItem(`ws_subprotocols_${this.roomId}`);

        const clearAllCreatorMetadata = () => {
            clearCreatorOneShotMetadata();
            this._clearCreatorBootstrapState();
        };

        if (creatorConnectionId || creatorBootstrapToken || creatorRoomType) {
            const validConnectionId =
                _isValidRelayConnectionId(creatorConnectionId);
            const validRoomType = creatorRoomType === 'group'
                || creatorRoomType === 'onetoone';
            const validGroupBootstrap = creatorRoomType === 'group'
                && _isValidCreatorBootstrapToken(creatorBootstrapToken);
            const validOneToOneMetadata = creatorRoomType === 'onetoone'
                && creatorBootstrapToken === null;
            if (!validConnectionId || !validRoomType
                || (!validGroupBootstrap && !validOneToOneMetadata)) {
                clearAllCreatorMetadata();
                this._fatalAuthFailure = true;
                if (this.onError) {
                    this.onError(new Error('CREATOR_BOOTSTRAP_INVALID'));
                }
                return;
            }
            if (creatorRoomType === 'group') {
                this.expectedCreatorConnectionId = creatorConnectionId;
                this.creatorBootstrapToken = creatorBootstrapToken;
            }
        }

        if (creatorToken && creatorConnectionId) {
            // Same v1 gate as the /api/ws-token path so a v0 server can't slip
            // through just because it pre-issued a token on room creation.
            const expectedV = window.PINCHAT_PROTOCOL_VERSION || 1;
            const protoOk =
                creatorProtoVersion !== null &&
                parseInt(creatorProtoVersion, 10) === expectedV;
            let subsOk = false;
            try {
                const subs = JSON.parse(creatorSubprotocols || '[]');
                subsOk = Array.isArray(subs) && subs.includes('pinchat.v1');
            } catch (_) {
                subsOk = false;
            }

            if (!protoOk || !subsOk) {
                // Clear invalid metadata BEFORE surfacing the error; otherwise a
                // manual reconnect would read the same stale entries and emit
                // PROTOCOL_OR_AUTH_FAILURE forever without progress.
                clearCreatorOneShotMetadata();
                console.error('[WS] Creator metadata failed v1 gate; cleared and aborting');
                this._fatalAuthFailure = true;
                if (this.onError) this.onError(new Error('PROTOCOL_OR_AUTH_FAILURE'));
                return;
            }

            console.log('✅ Using creator WebSocket token (no PoW needed)');
            token = creatorToken;
            this.cachedToken = creatorToken;
            this.tokenExpiresAt = Date.now() + 29000;
            clearCreatorOneShotMetadata();  // success path: single-use
            if (creatorRoomType === 'onetoone') {
                sessionStorage.removeItem(`ws_connection_${this.roomId}`);
                sessionStorage.removeItem(`ws_room_type_${this.roomId}`);
            }
        } else if (creatorToken) {
            // A connection ID paired with a valid bootstrap token is a
            // complete recovery path even after the one-shot JWT expires.
            // Reaching this branch means that pair was absent, so an orphaned
            // one-shot value must fail closed instead of silently creating a
            // random non-creator relay identity.
            clearAllCreatorMetadata();
            this._fatalAuthFailure = true;
            if (this.onError) {
                this.onError(new Error('CREATOR_BOOTSTRAP_INVALID'));
            }
            return;
        } else if (creatorRoomType === 'onetoone') {
            // A 1:1 creator identity is only an optimization for the initial
            // one-shot JWT. If that JWT expired before navigation, discard the
            // preallocation and use the ordinary PoW token path.
            sessionStorage.removeItem(`ws_connection_${this.roomId}`);
            sessionStorage.removeItem(`ws_room_type_${this.roomId}`);
        }

        if (!token) {
            if (this.cachedToken && this.tokenExpiresAt > Date.now()) {
                console.log('Reusing cached WebSocket token (no PoW required)');
                token = this.cachedToken;
            } else {
                console.log('Requesting new WebSocket token (requires PoW)...');
                token = await this.requestWsToken();
                if (connectAttemptGeneration
                    !== this._connectAttemptGeneration
                    || this.isManuallyDisconnected) {
                    return;
                }

                if (!token) {
                    // If requestWsToken already set _fatalAuthFailure and emitted
                    // PROTOCOL_OR_AUTH_FAILURE, don't overwrite with the generic error.
                    if (this._fatalAuthFailure) return;
                    console.error('Failed to obtain WebSocket token');
                    if (this.onError) {
                        this.onError(new Error('Failed to obtain WebSocket token'));
                    }
                    return;
                }
            }
        }

        // PATH 2: build the WebSocket with JWT carried in Sec-WebSocket-Protocol
        // rather than the URL (so it never lands in proxy/referrer/middlebox logs).
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/${this.roomId}`;

        // Consume the cached token now: jti is single-use on the server, so once
        // the upgrade is attempted the token is gone regardless of success/failure.
        // Clearing here ensures a reconnect always requests a fresh token via PoW.
        this.cachedToken = null;
        this.tokenExpiresAt = 0;

        console.log('Connecting to WebSocket (pinchat.v1 subprotocol auth)');

        try {
            if (connectAttemptGeneration !== this._connectAttemptGeneration
                || this.isManuallyDisconnected) {
                return;
            }
            this.ws = new WebSocket(wsUrl, ['pinchat.v1', `pinchat.v1.jwt.${token}`]);
            this._connectionGeneration += 1;
            const socketGeneration = this._connectionGeneration;
            let connectedFrameSeen = false;

            this.ws.onopen = () => {
                if (socketGeneration !== this._connectionGeneration) return;
                // Subprotocol sanity: server must echo "pinchat.v1" exactly.
                if (this.ws.protocol !== 'pinchat.v1') {
                    console.error('[WS] Unexpected negotiated subprotocol:', this.ws.protocol);
                    try { this.ws.close(1002, 'Protocol mismatch'); } catch (_) {}
                    this._fatalAuthFailure = true;
                    if (this.onError) this.onError(new Error('PROTOCOL_MISMATCH'));
                    return;
                }
                console.log('✅ WebSocket connected (pinchat.v1)');
                this.reconnectAttempts = 0;
                this._connectionExhausted = false;  // successful connection → restore retry budget

                // onConnected is async in app.js (await restartECDHHandshake).
                // Wrap with Promise.resolve().then() so both async errors AND
                // any synchronous throw get surfaced instead of becoming
                // unhandled rejections.
                if (this.onConnected) {
                    void Promise.resolve()
                        .then(() => this.onConnected())
                        .catch((err) => {
                            console.error('[WS] Unhandled error in onConnected:', err);
                            if (this.onError) this.onError(new Error('ON_CONNECTED_FAILED'));
                        });
                }
            };

            this.ws.onclose = (event) => {
                if (socketGeneration !== this._connectionGeneration) return;
                console.log('WebSocket closed:', event.code, event.reason);
                if (this.roomType === 'group') {
                    this._mlsControlSyncing = true;
                }

                if (this.onDisconnected) {
                    this.onDisconnected();
                }

                // Auto-reconnect only for transient drops. Skip on manual
                // disconnect and on terminal auth/protocol failure.
                if (!this.isManuallyDisconnected && !this._fatalAuthFailure) {
                    this.attemptReconnect();
                }
            };

            this.ws.onerror = (error) => {
                if (socketGeneration !== this._connectionGeneration) return;
                console.error('WebSocket error:', error);

                if (this.onError) {
                    this.onError(error);
                }
            };

            this.ws.onmessage = (event) => {
                try {
                    if (socketGeneration !== this._connectionGeneration
                        || this._fatalAuthFailure) {
                        return;
                    }
                    if (typeof event.data !== 'string') {
                        throw new Error('Relay WebSocket frame is not text');
                    }
                    const inboundChars = event.data.length;
                    if (this._queuedInboundMessages
                            >= MAX_INBOUND_QUEUE_MESSAGES
                        || this._queuedInboundChars + inboundChars
                            > MAX_INBOUND_QUEUE_CHARS) {
                        this._failInboundQueue(
                            `${this._queuedInboundMessages} messages / `
                            + `${this._queuedInboundChars} characters already queued`,
                        );
                        return;
                    }
                    const message = JSON.parse(event.data);
                    if (!message || typeof message !== 'object'
                        || typeof message.type !== 'string') {
                        throw new Error('Relay message is not a typed object');
                    }
                    console.log('WebSocket message received:', message.type);

                    // The resume credential is sent only in our direct
                    // Connected frame. Capture it before application dispatch
                    // and remove it from the message object so UI/debug code
                    // cannot accidentally retain or render the bearer token.
                    if (message.type === 'connected') {
                        if (connectedFrameSeen) {
                            this._failRoomProtocol(
                                'duplicate Connected frame on one socket',
                            );
                            return;
                        }
                        if (message.room_type !== 'group'
                            && message.room_type !== 'onetoone') {
                            this._failRoomProtocol(
                                'Connected carries an unsupported room_type',
                            );
                            return;
                        }
                        if (this.expectedRoomType !== null
                            && message.room_type !== this.expectedRoomType) {
                            this._failRoomProtocol(
                                `Connected room_type ${message.room_type} `
                                + `does not match invite/bootstrap expectation `
                                + this.expectedRoomType,
                            );
                            return;
                        }
                        if (this.roomType !== null
                            && this.roomType !== message.room_type) {
                            this._failRoomProtocol('room_type changed across reconnect');
                            return;
                        }
                        if (!_isValidWsResumeToken(message.resume_token)) {
                            this._fatalAuthFailure = true;
                            this.resumeToken = null;
                            if (this.creatorBootstrapToken !== null
                                || this.expectedCreatorConnectionId !== null) {
                                this._clearCreatorBootstrapState();
                            }
                            try { this.ws.close(1008, 'Invalid resume credential'); } catch (_) {}
                            if (this.onError) this.onError(new Error('RESUME_TOKEN_INVALID'));
                            return;
                        }
                        if (message.room_type === 'group') {
                            if (!Number.isSafeInteger(message.mls_control_cursor)
                                || message.mls_control_cursor < 0) {
                                this._failRoomProtocol(
                                    'Connected carries an invalid MLS control cursor',
                                );
                                return;
                            }
                            if (message.resumed === true) {
                                if (message.mls_control_cursor
                                    !== this.lastMlsControlSeq) {
                                    this._failRoomProtocol(
                                        'server resumed from a different MLS control cursor',
                                    );
                                    return;
                                }
                            } else {
                                if (this.connectionId !== null
                                    || this.lastMlsControlSeq !== 0) {
                                    this._failRoomProtocol(
                                        'group reconnect was admitted as a fresh control stream',
                                    );
                                    return;
                                }
                                this.lastMlsControlSeq
                                    = message.mls_control_cursor;
                            }
                            this._mlsControlSyncing = true;
                        } else if (message.mls_control_cursor !== undefined) {
                            this._failRoomProtocol(
                                '1:1 Connected carries group control state',
                            );
                            return;
                        }
                        if (this.expectedCreatorConnectionId !== null
                            && message.user_id
                                !== this.expectedCreatorConnectionId) {
                            this._clearCreatorBootstrapState();
                            this._failRoomProtocol(
                                'creator bootstrap relay identity changed',
                            );
                            return;
                        }
                        if (this.connectionId !== null
                            && message.user_id !== this.connectionId
                            && (message.room_type === 'group'
                                || message.resumed === true)) {
                            this._failRoomProtocol(
                                'stable relay identity changed across reconnect',
                            );
                            return;
                        }
                        this.connectionId = message.user_id;
                        this.roomType = message.room_type;
                        this.resumeToken = message.resume_token;
                        if (this.creatorBootstrapToken !== null) {
                            this._clearCreatorBootstrapState();
                        }
                        delete message.resume_token;
                        connectedFrameSeen = true;
                    } else if (!connectedFrameSeen
                        && message.type !== 'error') {
                        this._failRoomProtocol(
                            'relay message arrived before Connected',
                        );
                        return;
                    } else if (!_isMessageAllowedForRoom(this.roomType, message.type)) {
                        this._failRoomProtocol(
                            `message type ${message.type} is invalid for ${this.roomType || 'uninitialized'} room`,
                        );
                        return;
                    }

                    const isMlsControl = this._isMlsControlEnvelope(message);
                    const isOrderedGroupControl =
                        this._isOrderedGroupControl(message);
                    if (message.type === 'mls') {
                        if (isMlsControl) {
                            if (!Number.isSafeInteger(message.control_seq)
                                || message.control_seq <= 0) {
                                this._failRoomProtocol(
                                    'MLS control envelope is missing its sequence',
                                );
                                return;
                            }
                        } else if (message.wire_format === 2) {
                            if (message.control_seq !== undefined) {
                                this._failRoomProtocol(
                                    'MLS PrivateMessage carries a control sequence',
                                );
                                return;
                            }
                        } else {
                            this._failRoomProtocol(
                                'relay delivered an unsupported MLS wire format',
                            );
                            return;
                        }
                    }
                    if (message.type === 'userjoined'
                        || message.type === 'userleft') {
                        if (this.roomType === 'group') {
                            if (!Number.isSafeInteger(message.control_seq)
                                || message.control_seq <= 0) {
                                this._failRoomProtocol(
                                    'group lifecycle event is missing its sequence',
                                );
                                return;
                            }
                        } else if (message.control_seq !== undefined) {
                            this._failRoomProtocol(
                                '1:1 lifecycle event carries a group control sequence',
                            );
                            return;
                        }
                    }
                    if (message.type === 'mlssync'
                        && (!Number.isSafeInteger(message.through_seq)
                            || message.through_seq < 0)) {
                        this._failRoomProtocol('MLS sync marker is malformed');
                        return;
                    }

                    // C-01 + MLS control ordering: every application handler
                    // runs serially. The control cursor and ACK advance only
                    // after the handler settles successfully.
                    this._queuedInboundMessages += 1;
                    this._queuedInboundChars += inboundChars;
                    this._inboundQueue = this._inboundQueue
                        .then(async () => {
                            if (this._fatalAuthFailure
                                || socketGeneration
                                    !== this._connectionGeneration) {
                                return;
                            }
                            if (isOrderedGroupControl) {
                                const seq = message.control_seq;
                                if (seq <= this.lastMlsControlSeq) {
                                    // Harmless retransmission after an ACK race.
                                    this._mlsControlRetryAttempts.delete(seq);
                                    this._confirmMlsControl(message);
                                    this._sendMlsControlAck(
                                        this.lastMlsControlSeq,
                                    );
                                    return;
                                }
                                if (seq !== this.lastMlsControlSeq + 1) {
                                    this._failRoomProtocol(
                                        `MLS control sequence gap: expected `
                                        + `${this.lastMlsControlSeq + 1}, got ${seq}`,
                                    );
                                    return;
                                }
                                if (this.onMessage) {
                                    await this.onMessage(message);
                                }
                                if (this._fatalAuthFailure
                                    || socketGeneration
                                        !== this._connectionGeneration) {
                                    return;
                                }
                                this.lastMlsControlSeq = seq;
                                this._mlsControlRetryAttempts.delete(seq);
                                this._confirmMlsControl(message);
                                this._sendMlsControlAck(seq);
                                return;
                            }

                            if (message.type === 'mlssync') {
                                if (!this._mlsControlSyncing) {
                                    this._failRoomProtocol(
                                        'unexpected duplicate MLS sync marker',
                                    );
                                    return;
                                }
                                if (message.through_seq
                                    !== this.lastMlsControlSeq) {
                                    this._failRoomProtocol(
                                        `MLS replay ended at ${message.through_seq} `
                                        + `but local cursor is ${this.lastMlsControlSeq}`,
                                    );
                                    return;
                                }
                                if (this.onMessage) {
                                    await this.onMessage(message);
                                }
                                if (this._fatalAuthFailure
                                    || socketGeneration
                                        !== this._connectionGeneration) {
                                    return;
                                }
                                this._mlsControlSyncing = false;
                                this._retryPendingMlsControls();
                                return;
                            }

                            if (this.onMessage) {
                                await this.onMessage(message);
                            }
                            if (message.type === 'mlsrejected'
                                && message.reason
                                    === 'welcome_not_correlated'
                                && message.retry_after_secs === 0) {
                                this._cancelPendingWelcomeByCommitRef(
                                    message.commit_ref,
                                );
                            }
                        })
                        .catch((err) => {
                            console.error('[WS] Unhandled error in onMessage:', err);
                            if (socketGeneration
                                    !== this._connectionGeneration
                                || this._fatalAuthFailure) {
                                return;
                            }
                            if (err?.mlsFatalState === true) {
                                this._failMlsState(err.message);
                                return;
                            }
                            if (isOrderedGroupControl
                                && err?.mlsControlRejected === true) {
                                // MLSSession has conclusively rejected an
                                // unauthenticated/malformed control without
                                // mutating accepted state. The relay sequence
                                // is immutable, so replay cannot repair it:
                                // advance the cumulative cursor and continue
                                // with subsequent authentic controls.
                                const seq = message.control_seq;
                                if (seq === this.lastMlsControlSeq + 1) {
                                    this.lastMlsControlSeq = seq;
                                    this._mlsControlRetryAttempts.delete(seq);
                                    this._confirmMlsControl(message);
                                    this._sendMlsControlAck(seq);
                                }
                                return;
                            }
                            if (isOrderedGroupControl) {
                                const seq = message.control_seq;
                                const attempts = (
                                    this._mlsControlRetryAttempts.get(seq) || 0
                                ) + 1;
                                this._mlsControlRetryAttempts.set(
                                    seq, attempts,
                                );
                                if (attempts
                                    >= MAX_MLS_CONTROL_REPLAY_ATTEMPTS) {
                                    this._failMlsState(
                                        `MLS control ${seq} failed `
                                        + `${attempts} replay attempts: `
                                        + `${err.message}`,
                                    );
                                    return;
                                }
                            }
                            if ((isOrderedGroupControl
                                || message.type === 'mlssync'
                                || message.type === 'connected') && this.ws
                                && this.ws.readyState === WebSocket.OPEN) {
                                // Do not acknowledge or skip this sequence.
                                // Reconnect replays it from the unchanged
                                // cursor. A failed sync marker also reconnects:
                                // local deferred membership work must complete
                                // before this tab may become transport-ready.
                                try {
                                    this.ws.close(
                                        1011, 'MLS control processing failed',
                                    );
                                } catch (_) { /* ignore close races */ }
                            }
                        })
                        .finally(() => {
                            this._queuedInboundMessages = Math.max(
                                0, this._queuedInboundMessages - 1,
                            );
                            this._queuedInboundChars = Math.max(
                                0, this._queuedInboundChars - inboundChars,
                            );
                        });
                } catch (error) {
                    console.error('Failed to parse WebSocket message:', error);
                    this._failRoomProtocol('malformed relay message');
                }
            };

        } catch (error) {
            console.error('Failed to create WebSocket:', error);
            if (this.onError) {
                this.onError(error);
            }
        }
    }

    /**
     * Attempts reconnection with exponential backoff.
     *
     * Two kinds of terminal state:
     *  - `_fatalAuthFailure`: explicit protocol/auth mismatch (v1 gate,
     *    SIGNATURE_INVALID, subprotocol echo mismatch). No retry at all —
     *    the user must refresh the page.
     *  - `_connectionExhausted`: transient transport failure after N retries.
     *    The banner tells the user to check their network; a manual Reconnect
     *    click resets the retry budget (see app.js reconnect()).
     */
    attemptReconnect() {
        if (this._fatalAuthFailure) {
            console.error('Fatal auth/protocol failure — no auto-reconnect');
            return;
        }
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            this._connectionExhausted = true;
            if (this.onError) {
                this.onError(new Error('CONNECTION_EXHAUSTED'));
            }
            return;
        }

        this.reconnectAttempts++;

        // Exponential backoff: 1s, 2s, 4s, 8s, 16s
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

        console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);

        setTimeout(() => {
            if (!this.isManuallyDisconnected && !this._fatalAuthFailure) {
                this.connect();
            }
        }, delay);
    }

    /**
     * Sends a message through the WebSocket
     * @param {object} message
     * Ordered MLS controls use store-and-retry semantics: during a transient
     * group disconnect, accepting the envelope into the bounded pending map is
     * success even though no socket write happened yet. The exact envelope is
     * retried after `mlssync` and removed only by its sequenced own echo.
     *
     * @returns {boolean} True if sent or durably retained for this page session
     */
    send(message) {
        let trackedKey = null;
        let insertedTracking = false;
        if (this.roomType === 'group'
            && this._isMlsControlEnvelope(message)) {
            trackedKey = this._mlsControlKey(message);
            const existing = this._pendingMlsControls.get(trackedKey);
            if (existing) {
                // A caller can retry the same control while the current
                // socket is no longer writable. Mark it eligible for the next
                // sync even if it was previously handed to this generation.
                existing.lastSentGeneration = Math.min(
                    existing.lastSentGeneration,
                    this._connectionGeneration - 1,
                );
            } else {
                if (this._pendingMlsControls.size
                    >= MAX_PENDING_MLS_CONTROLS) {
                    console.error('Pending MLS control queue is full');
                    return false;
                }
                this._pendingMlsControls.set(trackedKey, {
                    envelope: { ...message },
                    lastSentGeneration: this._connectionGeneration - 1,
                    retryNotBefore: 0,
                });
                insertedTracking = true;
            }
        }

        let serialized;
        try {
            serialized = JSON.stringify(message);
        } catch (error) {
            if (insertedTracking) this._pendingMlsControls.delete(trackedKey);
            console.error('Failed to serialize WebSocket message:', error);
            return false;
        }

        // While the relay is replaying the ordered group-control log it
        // accepts only cumulative ACKs. Application handlers may generate a
        // new Commit, Proposal, KeyPackage, or Welcome while processing that
        // replay; retain exact MLS controls for the post-mlssync retry, but do
        // not write any application frame into the replay-only transport.
        if (this.roomType === 'group'
            && this._mlsControlSyncing
            && message.type !== 'mlsack') {
            if (trackedKey !== null
                && !this._fatalAuthFailure
                && !this.isManuallyDisconnected) {
                console.warn(
                    'MLS replay in progress; queued MLS control for post-sync retry',
                );
                return true;
            }
            if (insertedTracking) this._pendingMlsControls.delete(trackedKey);
            console.error(
                'MLS replay in progress; application frame was not sent',
            );
            return false;
        }

        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            if (trackedKey !== null
                && !this._fatalAuthFailure
                && !this.isManuallyDisconnected) {
                console.warn('WebSocket disconnected; queued MLS control for retry');
                return true;
            }
            if (insertedTracking) this._pendingMlsControls.delete(trackedKey);
            console.error('WebSocket is not connected');
            return false;
        }

        if (trackedKey !== null) {
            const tracked = this._pendingMlsControls.get(trackedKey);
            if (tracked && tracked.retryNotBefore > Date.now()) {
                return true;
            }
        }

        try {
            this.ws.send(serialized);
            if (trackedKey !== null) {
                const tracked = this._pendingMlsControls.get(trackedKey);
                if (tracked) {
                    tracked.lastSentGeneration = this._connectionGeneration;
                }
            }
            return true;
        } catch (error) {
            if (trackedKey !== null
                && !this._fatalAuthFailure
                && !this.isManuallyDisconnected) {
                const tracked = this._pendingMlsControls.get(trackedKey);
                if (tracked) {
                    tracked.lastSentGeneration = Math.min(
                        tracked.lastSentGeneration,
                        this._connectionGeneration - 1,
                    );
                }
                console.warn('WebSocket send failed; queued MLS control for retry:', error);
                return true;
            }
            if (insertedTracking) this._pendingMlsControls.delete(trackedKey);
            console.error('Failed to send message:', error);
            return false;
        }
    }

    /**
     * Disconnects the WebSocket
     */
    disconnect() {
        this.isManuallyDisconnected = true;
        this._connectAttemptGeneration += 1;

        // Remove beforeunload listener to prevent memory leaks
        if (this._boundBeforeUnload) {
            window.removeEventListener('beforeunload', this._boundBeforeUnload);
        }

        if (this.ws) {
            this.ws.close(1000, 'Manual disconnect');
            this.ws = null;
        }
    }

    /**
     * Disconnect with a specific WebSocket close code + reason, and mark the
     * session as fatal so auto-reconnect is suppressed.
     *
     * Used for SIGNATURE_INVALID (1008 Policy Violation) after a detected MITM
     * attempt: we do NOT want the client to silently reconnect and re-establish
     * a session with a peer whose identity just failed authentication.
     */
    disconnectWithError(code, reason) {
        this.isManuallyDisconnected = true;
        this._fatalAuthFailure = true;
        this._connectAttemptGeneration += 1;
        if (this.roomType === 'group') {
            this._notifyTerminalSecurityFailure(reason);
        }
        if (this._boundBeforeUnload) {
            window.removeEventListener('beforeunload', this._boundBeforeUnload);
        }
        if (this.ws) {
            try {
                this.ws.close(code, reason);
            } catch (_) { /* ignore */ }
            this.ws = null;
        }
    }

    /**
     * Checks whether the WebSocket is connected
     * @returns {boolean}
     */
    isConnected() {
        return this.ws && this.ws.readyState === WebSocket.OPEN;
    }
}

// Export the class
window.WebSocketManager = WebSocketManager;
