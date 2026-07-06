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

class WebSocketManager {
    constructor(roomId) {
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

        // C-01: serial dispatch queue for inbound messages. The DoubleRatchet
        // has its own internal mutex, but app.js#handleWebSocketMessage also
        // mutates non-cryptographic state (participantCount, peerUserId,
        // ecdhHandshakeStatus, …) and must observe messages in arrival order.
        // Errors do not poison the queue — see the .catch() in onmessage.
        this._inboundQueue = Promise.resolve();

        // Token caching for reconnection (avoids PoW on every reconnect)
        this.cachedToken = null;
        this.tokenExpiresAt = 0;

        // Callbacks
        this.onConnected = null;
        this.onDisconnected = null;
        this.onMessage = null;
        this.onError = null;
        this.onPowProgress = null; // Callback for PoW progress updates

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

            // First attempt: request token (may succeed if PoW already solved for room creation)
            let response = await fetch(`/api/ws-token/${this.roomId}`, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                }
            });

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
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Pow-Nonce': nonce.toString(),
                        'X-CSRF-Token': csrfToken,
                    }
                });

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
        // Enforcement gate: once we've detected a terminal auth/protocol failure
        // (v1 gate mismatch, SIGNATURE_INVALID, subprotocol mismatch on onopen),
        // refuse to attempt a new connection. The user must refresh the page.
        if (this._fatalAuthFailure) {
            console.error('[WS] connect() blocked: session is in fatal auth/protocol failure — page refresh required');
            return;
        }

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            console.warn('WebSocket already connected');
            return;
        }

        this.isManuallyDisconnected = false;

        // Helper: drop every creator-optimization entry atomically. Must clear
        // ALL four keys (token, connection_id, protocol_version, subprotocols)
        // so a later connect() can't re-trigger the same fatal path by reading
        // stale v0 metadata.
        const clearCreatorMetadata = () => {
            sessionStorage.removeItem(`ws_token_${this.roomId}`);
            sessionStorage.removeItem(`ws_connection_${this.roomId}`);
            sessionStorage.removeItem(`ws_protocol_version_${this.roomId}`);
            sessionStorage.removeItem(`ws_subprotocols_${this.roomId}`);
        };

        let token;

        // PATH 1: Creator optimization — token was pre-issued by /api/rooms.
        const creatorToken = sessionStorage.getItem(`ws_token_${this.roomId}`);
        const creatorConnectionId = sessionStorage.getItem(`ws_connection_${this.roomId}`);
        const creatorProtoVersion = sessionStorage.getItem(`ws_protocol_version_${this.roomId}`);
        const creatorSubprotocols = sessionStorage.getItem(`ws_subprotocols_${this.roomId}`);

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
                clearCreatorMetadata();
                console.error('[WS] Creator metadata failed v1 gate; cleared and aborting');
                this._fatalAuthFailure = true;
                if (this.onError) this.onError(new Error('PROTOCOL_OR_AUTH_FAILURE'));
                return;
            }

            console.log('✅ Using creator WebSocket token (no PoW needed)');
            token = creatorToken;
            this.cachedToken = creatorToken;
            this.tokenExpiresAt = Date.now() + 29000;
            clearCreatorMetadata();  // success path: single-use
        } else if (creatorToken || creatorConnectionId) {
            // Partial/corrupt creator metadata (one key missing): clean up before
            // falling through to the token-request path.
            clearCreatorMetadata();
        }

        if (!token) {
            if (this.cachedToken && this.tokenExpiresAt > Date.now()) {
                console.log('Reusing cached WebSocket token (no PoW required)');
                token = this.cachedToken;
            } else {
                console.log('Requesting new WebSocket token (requires PoW)...');
                token = await this.requestWsToken();

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
            this.ws = new WebSocket(wsUrl, ['pinchat.v1', `pinchat.v1.jwt.${token}`]);

            this.ws.onopen = () => {
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
                console.log('WebSocket closed:', event.code, event.reason);

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
                console.error('WebSocket error:', error);

                if (this.onError) {
                    this.onError(error);
                }
            };

            this.ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    console.log('WebSocket message received:', message.type);

                    if (this.onMessage) {
                        // C-01: enqueue on the inbound mutex. Each onMessage
                        // call runs strictly after the previous one settles,
                        // guaranteeing in-order delivery to app.js. The
                        // .catch resets the chain so a single handler error
                        // does not block subsequent messages.
                        this._inboundQueue = this._inboundQueue
                            .then(() => this.onMessage(message))
                            .catch((err) => {
                                console.error('[WS] Unhandled error in onMessage:', err);
                            });
                    }
                } catch (error) {
                    console.error('Failed to parse WebSocket message:', error);
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
            this.connect();
        }, delay);
    }

    /**
     * Sends a message through the WebSocket
     * @param {object} message
     * @returns {boolean} True if it was sent successfully
     */
    send(message) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            console.error('WebSocket is not connected');
            return false;
        }

        try {
            this.ws.send(JSON.stringify(message));
            return true;
        } catch (error) {
            console.error('Failed to send message:', error);
            return false;
        }
    }

    /**
     * Disconnects the WebSocket
     */
    disconnect() {
        this.isManuallyDisconnected = true;

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
