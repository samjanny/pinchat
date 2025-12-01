/**
 * Module for managing the WebSocket connection with reconnection logic
 */

class WebSocketManager {
    constructor(roomId) {
        this.roomId = roomId;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000; // Base delay in ms
        this.isManuallyDisconnected = false;

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
            // First attempt: request token (may succeed if PoW already solved for room creation)
            let response = await fetch(`/api/ws-token/${this.roomId}`, {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            // If 401 Unauthorized, redirect to login with return URL (relative path only)
            if (response.status === 401) {
                console.log('Authentication required, redirecting to login...');
                const returnUrl = encodeURIComponent(window.location.pathname + window.location.search + window.location.hash);
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

                // Retry token request with PoW solution
                response = await fetch(`/api/ws-token/${this.roomId}`, {
                    method: 'GET',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Pow-Nonce': nonce.toString(),
                    }
                });

                if (!response.ok) {
                    // Handle 401 after PoW (session may have expired)
                    if (response.status === 401) {
                        console.log('Authentication required, redirecting to login...');
                        const returnUrl = encodeURIComponent(window.location.pathname + window.location.search + window.location.hash);
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
                    const returnUrl = encodeURIComponent(window.location.pathname + window.location.search + window.location.hash);
                    window.location.href = `/login?redirect=${returnUrl}`;
                    return null;
                }
                const error = await response.json();
                console.error('Failed to obtain WebSocket token:', error);
                return null;
            }

            const data = await response.json();

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
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            console.warn('WebSocket already connected');
            return;
        }

        this.isManuallyDisconnected = false;

        // Request a WebSocket authentication token
        // Optimization: Reuse a cached token if still valid or use the creator's token
        let token;

        // Check if we have a cached token from room creation (creator optimization)
        const creatorToken = sessionStorage.getItem(`ws_token_${this.roomId}`);
        const creatorConnectionId = sessionStorage.getItem(`ws_connection_${this.roomId}`);

        if (creatorToken && creatorConnectionId) {
            console.log('✅ Using creator WebSocket token (no PoW needed)');
            token = creatorToken;
            this.cachedToken = creatorToken;
            this.tokenExpiresAt = Date.now() + 29000; // Assume fresh token

            // Clear from sessionStorage after first use (security: one-time use)
            sessionStorage.removeItem(`ws_token_${this.roomId}`);
            sessionStorage.removeItem(`ws_connection_${this.roomId}`);
        } else if (this.cachedToken && this.tokenExpiresAt > Date.now()) {
            console.log('Reusing cached WebSocket token (no PoW required)');
            token = this.cachedToken;
        } else {
            console.log('Requesting new WebSocket token (requires PoW)...');
            token = await this.requestWsToken();

            if (!token) {
                console.error('Failed to obtain WebSocket token');
                if (this.onError) {
                    this.onError(new Error('Failed to obtain WebSocket token'));
                }
                return;
            }
        }

        // Determine the protocol (ws or wss)
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/${this.roomId}?token=${token}`;

        console.log('Connecting to WebSocket with authenticated token');

        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log('✅ WebSocket connected');
                this.reconnectAttempts = 0;

                if (this.onConnected) {
                    this.onConnected();
                }
            };

            this.ws.onclose = (event) => {
                console.log('WebSocket closed:', event.code, event.reason);

                if (this.onDisconnected) {
                    this.onDisconnected();
                }

                // Automatically attempt reconnection if it wasn't manual
                if (!this.isManuallyDisconnected) {
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
                        this.onMessage(message);
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
     * Attempts reconnection with exponential backoff
     */
    attemptReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            if (this.onError) {
                this.onError(new Error('Failed to reconnect after multiple attempts'));
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
     * Checks whether the WebSocket is connected
     * @returns {boolean}
     */
    isConnected() {
        return this.ws && this.ws.readyState === WebSocket.OPEN;
    }
}

// Export the class
window.WebSocketManager = WebSocketManager;
