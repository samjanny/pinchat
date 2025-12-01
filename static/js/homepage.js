/**
 * Homepage - Room creation form (Alpine.js CSP-compatible Global Store)
 */
document.addEventListener('alpine:init', () => {
    Alpine.store('homepage', {
        // State
        roomType: 'onetoone',
        maxParticipants: 10,
        ttlMinutes: 30,
        loading: false,
        loadingMessage: 'Creating...',
        powProgress: '',
        error: '',

        /**
         * Creates a new room
         */
        async createRoom() {
            this.loading = true;
            this.loadingMessage = 'Creating...';
            this.powProgress = '';
            this.error = '';

            try {
                // Generate the encryption key
                const key = await crypto.subtle.generateKey(
                    { name: 'AES-GCM', length: 256 },
                    true,
                    ['encrypt', 'decrypt']
                );

                // Export the key in raw format
                const keyBuffer = await crypto.subtle.exportKey('raw', key);
                const keyArray = new Uint8Array(keyBuffer);
                const keyBase64 = btoa(String.fromCharCode(...keyArray));

                // Convert to Base64url (URL-safe: replaces + with -, / with _, removes =)
                const keyBase64url = keyBase64
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=/g, '');

                // Call the API to create the room (with PoW retry logic)
                const roomData = await this.createRoomWithPoW({
                    room_type: this.roomType,
                    ttl_minutes: this.ttlMinutes,
                    max_participants: this.maxParticipants
                });

                // Save WebSocket token if provided (creator optimization)
                // This allows the room creator to skip the second PoW challenge
                if (roomData.ws_token && roomData.connection_id) {
                    sessionStorage.setItem(`ws_token_${roomData.room_id}`, roomData.ws_token);
                    sessionStorage.setItem(`ws_connection_${roomData.room_id}`, roomData.connection_id);
                    console.log('✅ WebSocket token saved for room creator (no second PoW needed)');
                }

                // Redirect to server endpoint that validates room exists
                // Server will redirect to /static/chat.html with proper parameters
                // This prevents race conditions and handles expired/full rooms
                const roomUrl = new URL(`/c/${roomData.room_id}`, window.location.origin);
                roomUrl.hash = `key=${keyBase64url}`;

                window.location.href = roomUrl.toString();

            } catch (err) {
                this.error = err.message;
                this.loading = false;
                this.powProgress = '';
            }
        },

        /**
         * Creates a room with automatic PoW challenge handling
         */
        async createRoomWithPoW(config, powHeaders = {}) {
            const response = await fetch('/api/rooms', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    ...powHeaders
                },
                body: JSON.stringify(config)
            });

            // Success - room created
            if (response.ok) {
                return await response.json();
            }

            // Authentication required - redirect to login (relative path only)
            if (response.status === 401) {
                console.log('Authentication required, redirecting to login...');
                const returnUrl = encodeURIComponent(window.location.pathname + window.location.search + window.location.hash);
                window.location.href = `/login?redirect=${returnUrl}`;
                throw new Error('Authentication required');
            }

            // PoW required - solve challenge and retry
            if (response.status === 428) {
                const powData = await response.json();

                // Show PoW UI feedback
                const estimatedTime = ProofOfWork.estimateSolveTime(powData.difficulty);
                this.loadingMessage = `Computing challenge (difficulty: ${powData.difficulty})`;
                this.powProgress = `⏳ Estimated time: ${estimatedTime}`;

                // Generate mask from difficulty (server doesn't send mask to reduce payload)
                const mask = ProofOfWork.generateMask(powData.difficulty);

                // Solve the PoW challenge
                const solver = new ProofOfWork(powData.challenge, mask);
                const nonce = await solver.solve((attempts) => {
                    // Update progress every 100,000 attempts
                    this.powProgress = `⏳ Computing... (${Math.floor(attempts / 100000) * 100}k attempts)`;
                });

                this.powProgress = '✓ Challenge solved, creating room...';

                // Retry with PoW solution
                return await this.createRoomWithPoW(config, {
                    'X-PoW-Nonce': nonce.toString(),
                    'X-PoW-Challenge': powData.challenge,
                    'X-PoW-Difficulty': powData.difficulty.toString()
                });
            }

            // Rate limit exceeded
            if (response.status === 429) {
                const retryAfter = response.headers.get('Retry-After') || '3600';
                throw new Error(`Rate limit exceeded. Please try again in ${Math.ceil(retryAfter / 60)} minutes.`);
            }

            // Server at capacity
            if (response.status === 503) {
                throw new Error('Server at maximum capacity. Please try again later.');
            }

            // Other errors
            const error = await response.json();
            throw new Error(error.error || 'Error creating the room');
        }
    });
});
