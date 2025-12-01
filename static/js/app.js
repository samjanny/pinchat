/**
 * Main app - Alpine.js CSP-compatible Global Store for chat room
 */

// Read room ID from URL (only parameter needed)
// Room configuration (type, ttl, max) will be provided by server via WebSocket
const urlParams = new URLSearchParams(window.location.search);

window.ROOM_CONFIG = {
    roomId: urlParams.get('room')
    // roomType, ttlMinutes, maxParticipants will be set by server via WebSocket
};

// Validate room ID is present
if (!window.ROOM_CONFIG.roomId) {
    alert('⚠️ Room ID missing in URL. Redirecting to homepage...');
    window.location.href = '/static/index.html';
}

document.addEventListener('alpine:init', () => {
    Alpine.store('chatRoom', {
        // Configuration (will be populated from server via WebSocket)
        roomId: window.ROOM_CONFIG.roomId,
        roomType: null,              // Will be set by server on 'connected'
        ttlMinutes: null,            // Will be set by server on 'connected'
        maxParticipants: null,       // Will be set by server on 'connected'

        // Connection state
        connected: false,
        connecting: true,
        connectingMessage: 'Connecting...',
        userId: null,
        myNickname: null,  // User's own nickname (generated from userId)
        initialized: false,
        wasConnectedBefore: false,  // Track if we've connected at least once (for reconnection detection)

        // Messages
        messages: [],
        messageInput: '',
        nextMessageId: 0,

        // Participants
        participantCount: 0,

        // Errors
        error: '',
        decryptionError: false,

        // UI
        copied: false,

        // Image sharing
        pendingImage: null,      // {dataUrl, name, size, mimeType, arrayBuffer}
        sendingImage: false,
        fullscreenImage: null,   // URL for fullscreen viewer
        maxImageSize: 300 * 1024,  // Default 300KB, will be overridden by server config

        // TTL timer
        timeRemaining: null,
        expiresAt: null,

        // WebSocket Manager
        wsManager: null,

        // ECDH Key Exchange (for 1:1 rooms with PFS)
        identityManager: null,      // Identity key manager used for authenticated handshakes
        ecdhManager: null,
        ecdhHandshakeStatus: 'none',
        pfsActive: false,
        sas: null,
        sasBackup: null,            // Backup of SAS for reopening verification
        sasVerificationStatus: 'none', // 'none' | 'pending' | 'verified' | 'mismatch' | 'skipped'
        sasCopied: false,           // For copy button feedback
        pendingECDHKey: null,

        // Emoji picker state
        emojiPickerOpen: false,
        selectedEmojiCategory: 'Smileys',
        emojiCategories: [],   // Will be populated from emojiManager
        currentEmojis: [],     // Current category's emoji

        /**
         * Initialization
         */
        async init() {
            // Prevent double initialization (guards against multiple WebSocket connections)
            if (this.initialized) {
                console.warn('Chat room already initialized, skipping duplicate init()');
                return;
            }
            this.initialized = true;

            console.log('Initializing chat room:', this.roomId);

            // Initialize emoji picker categories
            if (window.emojiManager) {
                this.emojiCategories = window.emojiManager.getCategoryNames();
                this.currentEmojis = window.emojiManager.getEmojiForCategory(this.selectedEmojiCategory);
            }

            // Load the encryption key from the URL (bootstrap key)
            const key = await window.cryptoManager.extractKeyFromURL();
            if (!key) {
                this.error = '⚠️ Encryption key not found in the URL. Make sure you have the full link.';
                this.connecting = false;
                return;
            }

            // Room expiration will be calculated when server sends ttlMinutes via WebSocket
            // Start timer interval (will update when expiresAt is set)
            setInterval(() => {
                this.updateTimeRemaining();
            }, 1000);

            // Initialize WebSocket
            this.wsManager = new WebSocketManager(this.roomId);

            this.wsManager.onConnected = async () => {
                // Detect if this is a reconnection (vs initial connection)
                const isReconnection = this.wasConnectedBefore;
                this.wasConnectedBefore = true;

                this.connected = true;
                this.connecting = false;
                this.error = '';

                // If PFS was active and this is a reconnection, restart handshake to resync Chain Ratchet
                // This prevents permanent desynchronization when messages are lost during disconnection
                if (isReconnection && this.pfsActive) {
                    console.log('[RECONNECT] Detected reconnection with active PFS → restarting handshake to resync Chain Ratchet');
                    await this.restartECDHHandshake();
                }
            };

            this.wsManager.onDisconnected = () => {
                this.connected = false;
                this.connecting = false;

                // Warn user about potential message loss if PFS is active
                // Messages sent during disconnection will be lost (ephemeral design)
                if (this.pfsActive) {
                    this.addSystemMessage('⚠️ Connection lost - messages sent during disconnect may be lost');
                }
            };

            this.wsManager.onMessage = (message) => {
                this.handleWebSocketMessage(message);
            };

            this.wsManager.onError = (error) => {
                this.error = '⚠️ Connection error. Retrying automatically...';
            };

            this.wsManager.onPowProgress = (attempts) => {
                if (attempts === 0) {
                    this.connectingMessage = '⏳ Computing challenge...';
                } else if (attempts === -1) {
                    this.connectingMessage = '✓ Challenge solved, connecting...';
                } else {
                    this.connectingMessage = `⏳ Computing... (${Math.floor(attempts / 100000) * 100}k attempts)`;
                }
            };

            // Connect
            this.wsManager.connect();
        },

        /**
         * Handles incoming WebSocket messages
         */
        async handleWebSocketMessage(message) {
            switch (message.type) {
                case 'connected':
                    this.userId = message.user_id;
                    this.myNickname = generateNickname(message.user_id).display;  // Generate user's own nickname
                    this.participantCount = message.participant_count;

                    // Override URL parameters with validated values from server
                    // This prevents URL spoofing attacks where an attacker modifies
                    // type/ttl/max parameters to trigger unintended behavior (e.g., ECDH in group rooms)
                    if (message.room_type) {
                        console.log('[SECURITY] Using validated room_type from server:', message.room_type);
                        this.roomType = message.room_type;
                    }
                    if (message.ttl_minutes) {
                        console.log('[SECURITY] Using validated ttl_minutes from server:', message.ttl_minutes);
                        this.ttlMinutes = message.ttl_minutes;
                        // Recalculate expiration with validated TTL
                        this.expiresAt = Date.now() + (this.ttlMinutes * 60 * 1000);
                    }
                    if (message.max_participants) {
                        console.log('[SECURITY] Using validated max_participants from server:', message.max_participants);
                        this.maxParticipants = message.max_participants;
                    }
                    if (message.max_image_size) {
                        console.log('[CONFIG] Max image size from server:', this.formatFileSize(message.max_image_size));
                        this.maxImageSize = message.max_image_size;
                    }

                    // Use the validated room type for ECDH logic
                    if (this.roomType === 'onetoone' && this.participantCount === 2) {
                        // Reset ECDH status if it was stuck on 'aborted' from previous failed handshake
                        if (this.ecdhHandshakeStatus === 'aborted') {
                            console.log('[ECDH] Resetting status from aborted to none (room ready again)');
                            this.ecdhHandshakeStatus = 'none';
                        }

                        // Start handshake if not already started
                        if (this.ecdhHandshakeStatus === 'none') {
                            console.log('[ECDH] Second participant joined → starting handshake');
                            await this.startECDHHandshake();
                        }
                    }
                    break;

                case 'ecdh_public_key':
                    await this.handleECDHPublicKey(message);
                    break;

                // NOTE: dh_ratchet message type removed - Signal Protocol
                // DH ratchet now happens automatically when receiving a message
                // with a new DH public key in the header

                case 'message':
                    if (message.sender_id !== this.userId) {
                        await this.handleIncomingMessage(message);
                    }
                    break;

                case 'image':
                    if (message.sender_id !== this.userId) {
                        await this.handleIncomingImage(message);
                    }
                    break;

                case 'userjoined':
                    this.participantCount = message.participant_count;
                    this.addSystemMessage('👋 A participant joined the chat');

                    if (this.roomType === 'onetoone' && this.participantCount === 2) {
                        // Reset ECDH status if it was stuck on 'aborted' from previous failed handshake
                        if (this.ecdhHandshakeStatus === 'aborted') {
                            console.log('[ECDH] Resetting status from aborted to none (room ready again)');
                            this.ecdhHandshakeStatus = 'none';
                        }

                        // Start handshake if not already started
                        if (this.ecdhHandshakeStatus === 'none') {
                            console.log('[ECDH] Other participant joined → starting handshake');
                            await this.startECDHHandshake();
                        }
                    }
                    break;

                case 'userleft':
                    this.participantCount = message.participant_count;
                    if (message.user_id !== this.userId) {
                        this.addSystemMessage('👋 A participant left the chat');
                    }

                    // When participant count drops below 2, cleanup ECDH state
                    if (this.participantCount < 2) {
                        if (this.ecdhHandshakeStatus === 'waiting') {
                            // Handshake was in progress → hard abort (peer left)
                            console.log('[ECDH] Resetting status to none (handshake aborted, peer left)');
                            this.handleECDHAborted(true);  // hardReset: peer is gone
                            // Reset status to 'none' so handshake can restart when room becomes ready again
                            this.ecdhHandshakeStatus = 'none';
                        } else if (this.pfsActive) {
                            // PFS was active → hard abort (peer left, need fresh identity with new peer)
                            console.log('[ECDH] PFS was active, peer left → hard reset');
                            this.handleECDHAborted(true);  // hardReset: peer is gone
                            this.ecdhHandshakeStatus = 'none';
                            this.sasBackup = null;
                            this.addSystemMessage('⚠️ Secure connection lost (other participant left)');
                        } else if (this.ecdhHandshakeStatus === 'aborted') {
                            // Status was stuck on 'aborted' → reset to 'none'
                            console.log('[ECDH] Resetting status from aborted to none (room not ready)');
                            this.ecdhHandshakeStatus = 'none';
                            // Reset to bootstrap key for clean state
                            window.cryptoManager.resetToBootstrapKey();
                            this.sas = null;
                        }
                    }
                    break;

                case 'error':
                    this.error = message.message;
                    break;

                default:
                    console.warn('Unknown message type:', message.type);
            }
        },

        /**
         * Handles an incoming encrypted message
         *
         * Signal Protocol: Message header contains sender's DH public key.
         * If this is a NEW key, decryption will trigger DH ratchet automatically.
         */
        async handleIncomingMessage(message) {
            try {
                // Pass header to decryption (contains DH public key for ratchet)
                const plaintext = await window.cryptoManager.decryptMessage(
                    message.payload,
                    message.header,  // Signal Protocol header with DH public key
                    this.roomId,
                    message.sender_id
                );

                const isOwn = message.sender_id === this.userId;

                // Generate nickname from sender UUID (for display)
                const nicknameData = generateNickname(message.sender_id);

                this.messages.push({
                    id: this.nextMessageId++,
                    type: 'message',
                    text: plaintext,
                    timestamp: new Date(message.timestamp),
                    isOwn: isOwn,
                    nickname: nicknameData.display,        // "Cosmic Fox"
                    senderId: message.sender_id            // Full UUID (for tooltip)
                });

                // Scroll to bottom after DOM update
                requestAnimationFrame(() => this.scrollToBottom());

            } catch (error) {
                this.handleSecurityError(error, message.sender_id);
            }
        },

        /**
         * Sends a message
         *
         * Signal Protocol: DH ratchet now happens automatically on receive.
         * Every message includes the sender's DH public key in the header,
         * allowing the receiver to perform DH ratchet when they see a new key.
         */
        async sendMessage() {
            const text = this.messageInput.trim();
            // Block sending if image upload is in progress (prevents Double Ratchet race condition)
            if (!text || !this.connected || this.sendingImage) {
                return;
            }

            try {
                this.messages.push({
                    id: this.nextMessageId++,
                    type: 'message',
                    text: text,
                    timestamp: new Date(),
                    isOwn: true,
                    nickname: this.myNickname,  // Add user's own nickname
                    senderId: this.userId        // Add user's own UUID
                });

                this.messageInput = '';

                // Scroll to bottom after DOM update
                requestAnimationFrame(() => this.scrollToBottom());

                // Encrypt message - returns {payload, header}
                // Header contains DH public key for receiver's DH ratchet
                const encrypted = await window.cryptoManager.encryptMessage(
                    text,
                    this.roomId,
                    this.userId
                );

                // Send message with header (Signal Protocol)
                const sent = this.wsManager.send({
                    type: 'message',
                    payload: encrypted.payload,
                    header: encrypted.header  // Contains DH public key
                });

                if (!sent) {
                    this.messages.pop();
                    this.messageInput = text;
                    this.error = '⚠️ Unable to send the message. Please try again.';
                }

            } catch (error) {
                console.error('Failed to send message:', error);
                this.error = '⚠️ Error encrypting the message.';
            }
        },

        /**
         * Handles image file selection
         */
        async handleImageSelect(event) {
            const file = event.target.files[0];
            if (!file) return;

            // Validate file type
            if (!file.type.startsWith('image/')) {
                this.error = '⚠️ Please select an image file.';
                return;
            }

            // Validate file size
            if (file.size > this.maxImageSize) {
                this.error = `⚠️ Image too large. Maximum size is ${this.formatFileSize(this.maxImageSize)}.`;
                return;
            }

            try {
                // Read file as ArrayBuffer for encryption
                const arrayBuffer = await file.arrayBuffer();

                // Read file as DataURL for preview
                const dataUrl = await new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    reader.onload = () => resolve(reader.result);
                    reader.onerror = reject;
                    reader.readAsDataURL(file);
                });

                this.pendingImage = {
                    dataUrl: dataUrl,
                    name: file.name,
                    size: file.size,
                    mimeType: file.type,
                    arrayBuffer: arrayBuffer
                };

                this.error = '';
            } catch (error) {
                console.error('Failed to read image:', error);
                this.error = '⚠️ Error reading image file.';
            }

            // Reset file input
            event.target.value = '';
        },

        /**
         * Cancels pending image
         */
        cancelImage() {
            this.pendingImage = null;
        },

        /**
         * Sends the pending image
         */
        async sendImage() {
            if (!this.pendingImage || !this.connected || this.sendingImage) {
                return;
            }

            this.sendingImage = true;

            try {
                // Add image message to local list immediately
                const localImageUrl = this.pendingImage.dataUrl;
                this.messages.push({
                    id: this.nextMessageId++,
                    type: 'image',
                    imageUrl: localImageUrl,
                    timestamp: new Date(),
                    isOwn: true,
                    nickname: this.myNickname,
                    senderId: this.userId
                });

                // Scroll to bottom
                requestAnimationFrame(() => this.scrollToBottom());

                // Encrypt image data
                const encrypted = await window.cryptoManager.encryptImage(
                    this.pendingImage.arrayBuffer,
                    this.pendingImage.mimeType,
                    this.roomId,
                    this.userId
                );

                // Send via WebSocket
                const sent = this.wsManager.send({
                    type: 'image',
                    payload: encrypted.payload,
                    header: encrypted.header
                });

                if (!sent) {
                    // Remove local message on failure
                    this.messages.pop();
                    this.error = '⚠️ Unable to send image. Please try again.';
                }

                // Clear pending image
                this.pendingImage = null;

            } catch (error) {
                console.error('Failed to send image:', error);
                this.messages.pop();
                this.error = '⚠️ Error encrypting image.';
            } finally {
                this.sendingImage = false;
            }
        },

        /**
         * Handles incoming encrypted image message
         */
        async handleIncomingImage(message) {
            try {
                // Decrypt image data
                const imageData = await window.cryptoManager.decryptImage(
                    message.payload,
                    message.header,
                    this.roomId,
                    message.sender_id
                );

                // Create blob URL from decrypted data
                const blob = new Blob([imageData.data], { type: imageData.mimeType });
                const imageUrl = URL.createObjectURL(blob);

                // Generate nickname from sender UUID
                const nicknameData = generateNickname(message.sender_id);

                this.messages.push({
                    id: this.nextMessageId++,
                    type: 'image',
                    imageUrl: imageUrl,
                    timestamp: new Date(message.timestamp),
                    isOwn: false,
                    nickname: nicknameData.display,
                    senderId: message.sender_id
                });

                // Scroll to bottom
                requestAnimationFrame(() => this.scrollToBottom());

            } catch (error) {
                this.handleSecurityError(error, message.sender_id);
            }
        },

        /**
         * Opens image in fullscreen viewer
         */
        openImageFullscreen(imageUrl) {
            this.fullscreenImage = imageUrl;
        },

        /**
         * Formats file size for display
         */
        formatFileSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        },

        /**
         * Adds a system message
         */
        addSystemMessage(text) {
            this.messages.push({
                id: this.nextMessageId++,
                type: 'system',
                text: text,
                timestamp: new Date()  // Add timestamp to avoid formatTimestamp errors
            });

            requestAnimationFrame(() => this.scrollToBottom());
        },

        /**
         * Handles security errors from message decryption
         */
        handleSecurityError(error, senderId) {
            console.error('[SECURITY] Message authentication failed:', error);

            let warningMessage = '🔐 Security warning: ';

            switch (error.message) {
                case 'REPLAY_DUPLICATE':
                    warningMessage += 'Duplicate message detected (replay attack blocked)';
                    break;
                case 'REPLAY_TOO_OLD':
                    warningMessage += 'Message too old (late-join replay attack blocked)';
                    break;
                case 'REPLAY_FUTURE':
                    warningMessage += 'Message timestamp from future (clock manipulation detected)';
                    break;
                case 'SENDER_AUTH_FAILED':
                    warningMessage += 'Message authentication failed (sender impersonation or tampering detected)';
                    break;
                default:
                    warningMessage += 'Message could not be verified (possible attack)';
            }

            this.addSystemMessage(warningMessage);
            this.decryptionError = true;
        },

        /**
         * Copies the room link to the clipboard
         */
        async copyLink() {
            const link = window.location.href;

            try {
                await navigator.clipboard.writeText(link);
                this.copied = true;

                setTimeout(() => {
                    this.copied = false;
                }, 2000);

            } catch (error) {
                console.error('Failed to copy link:', error);
                alert('Copy this link:\n\n' + link);
            }
        },

        /**
         * Reconnects the WebSocket
         */
        reconnect() {
            this.connecting = true;
            this.error = '';
            this.wsManager.connect();
        },

        /**
         * Scrolls to the bottom of the messages area
         */
        scrollToBottom() {
            const container = document.querySelector('.messages-container');
            if (container) {
                container.scrollTop = container.scrollHeight;
            }
        },

        /**
         * Updates the remaining time
         */
        updateTimeRemaining() {
            // Don't calculate expiration until we receive ttlMinutes from server
            if (!this.expiresAt) {
                return;
            }

            const remaining = this.expiresAt - Date.now();

            if (remaining <= 0) {
                this.timeRemaining = 0;
                this.error = '⚠️ The room has expired.';
                if (this.wsManager) {
                    this.wsManager.disconnect();
                }
            } else {
                this.timeRemaining = remaining;
            }
        },

        /**
         * Formats the remaining time
         */
        formatTime(ms) {
            const totalSeconds = Math.floor(ms / 1000);
            const hours = Math.floor(totalSeconds / 3600);
            const minutes = Math.floor((totalSeconds % 3600) / 60);
            const seconds = totalSeconds % 60;

            if (hours > 0) {
                return `⏱️ ${hours}h ${minutes}m`;
            } else if (minutes > 0) {
                return `⏱️ ${minutes}m ${seconds}s`;
            } else {
                return `⏱️ ${seconds}s`;
            }
        },

        /**
         * Formats a message timestamp
         */
        formatTimestamp(date) {
            const hours = String(date.getHours()).padStart(2, '0');
            const minutes = String(date.getMinutes()).padStart(2, '0');
            return `${hours}:${minutes}`;
        },

        /**
         * Formats emoji string as HTML grid elements
         * Wraps each emoji character in a <span> for CSS Grid layout
         */
        formatEmojiGrid(emojiString) {
            if (!emojiString) return '';
            // Split the emoji string and wrap each emoji in a span
            return Array.from(emojiString)
                .map(emoji => `<span>${emoji}</span>`)
                .join('');
        },

        /**
         * Starts ECDH handshake for 1:1 rooms
         */
        async startECDHHandshake() {
            // Guard against concurrent/duplicate handshake initialization
            if (this.ecdhHandshakeStatus !== 'none') {
                console.warn('[ECDH] Handshake already started (status:', this.ecdhHandshakeStatus, '), ignoring duplicate call');
                return;
            }

            console.log('[ECDH] Starting handshake for 1:1 room...');

            try {
                this.ecdhHandshakeStatus = 'waiting';  // Set immediately to prevent race condition

                // Initialize the identity manager and reuse it across reconnects
                if (!this.identityManager) {
                    console.log('[Identity] Initializing identity key manager...');
                    this.identityManager = new IdentityKeyManager();
                    await this.identityManager.generateIdentityKeypair();
                    console.log('[Identity] ✅ Identity keypair generated');
                } else {
                    console.log('[Identity] Reusing existing identity manager (SAS verified:', this.identityManager.isSASVerified(), ')');
                }

                // Initialize ECDH manager with identity manager
                this.ecdhManager = new ECDHKeyExchange(window.cryptoManager.key, this.identityManager);

                await this.ecdhManager.generateKeypair();

                // SECURITY: Pass roomId and userId for AAD context binding
                const ecdhResult = await this.ecdhManager.encryptPublicKey(this.roomId, this.userId);

                // Serialize AAD context as JSON string (server expects string payload)
                const payloadJson = JSON.stringify(ecdhResult);

                this.wsManager.send({
                    type: 'ecdh_public_key',
                    payload: payloadJson  // JSON string with {encryptedKey, timestamp, nonce}
                });

                console.log('[ECDH] Public key sent with AAD binding, waiting for other participant...');
                this.addSystemMessage('🔐 Establishing secure connection...');

                // Start handshake timeout (30 seconds)
                // If other participant doesn't respond, reset and allow retry
                this.ecdhManager.startTimeout(() => {
                    console.warn('[ECDH] ⏱️ Handshake timeout - other participant did not respond');

                    // Clean up state
                    this.handleECDHAborted();
                    this.ecdhHandshakeStatus = 'none';
                    this.ecdhManager = null;

                    // Notify user
                    this.addSystemMessage('⚠️ Secure connection timeout - other participant may have left');

                    // If still 2 participants, could retry automatically
                    if (this.participantCount === 2) {
                        console.log('[ECDH] Room still has 2 participants, handshake can be retried manually');
                    }
                });

                // Process pending ECDH key if it arrived while we were initializing
                if (this.pendingECDHKey) {
                    console.log('[ECDH] Processing pending public key that arrived during initialization...');
                    await this.handleECDHPublicKey(this.pendingECDHKey);
                }

            } catch (error) {
                console.error('[ECDH] Handshake failed:', error);
                this.handleECDHAborted();
                // Reset to 'none' to allow handshake restart if room becomes ready again
                this.ecdhHandshakeStatus = 'none';
            }
        },

        /**
         * Restarts ECDH handshake after reconnection
         * This ensures both parties resynchronize their Chain Ratchet state
         */
        async restartECDHHandshake() {
            console.log('[RECONNECT] Restarting ECDH handshake to resynchronize Chain Ratchet...');

            // Check if we had a verified identity before reconnect
            const hadVerifiedIdentity = this.identityManager && this.identityManager.isSASVerified();
            const previousPeerIdentity = this.identityManager ? this.identityManager.peerIdentityPublicKey : null;

            // Reset crypto state (but NOT identity manager - keep for SAS persistence)
            this.pfsActive = false;
            this.ecdhHandshakeStatus = 'none';
            this.sas = null;
            this.sasBackup = null;
            // Don't reset sasVerificationStatus if we had verified identity - will check peer identity later
            if (!hadVerifiedIdentity) {
                this.sasVerificationStatus = 'none';
            }
            this.ecdhManager = null;

            // Keep the identity manager alive for SAS persistence
            // Identity keys persist for the entire session while ephemeral keys are regenerated
            // The peer's identity will be re-verified during handshake
            if (this.identityManager) {
                // Store previous peer identity to detect MITM on reconnect
                this.identityManager.previousPeerIdentity = previousPeerIdentity;
                console.log('[RECONNECT] Keeping identity manager alive (SAS verified:', hadVerifiedIdentity, ')');
            }

            // Reset Chain Ratchet to bootstrap key
            window.cryptoManager.resetToBootstrapKey();

            // Clear pending key if any (avoid processing stale keys from before reconnection)
            this.pendingECDHKey = null;

            // Show user feedback
            this.addSystemMessage('🔄 Reconnected - re-establishing secure connection...');

            // Start new handshake if room is ready (1:1 with 2 participants)
            if (this.roomType === 'onetoone' && this.participantCount === 2) {
                await this.startECDHHandshake();
            } else {
                console.log('[RECONNECT] Room not ready for handshake (roomType:', this.roomType, 'participantCount:', this.participantCount, ')');
            }
        },

        /**
         * Handles received ECDH public key
         */
        async handleECDHPublicKey(message) {
            // Ignore our own ECDH public key echo (server broadcasts to all including sender)
            if (message.sender_id === this.userId) {
                console.log('[ECDH] Ignoring own public key echo');
                return;
            }

            if (this.ecdhHandshakeStatus === 'complete') {
                console.warn('[ECDH] Handshake already complete, ignoring');
                return;
            }

            // Guard: Ignore stale public keys from before reconnection/restart
            // This prevents race condition where old keys arrive after we've reset state
            if (this.ecdhHandshakeStatus === 'none' && !this.ecdhManager) {
                console.warn('[ECDH] Ignoring public key received during handshake restart (state is being reset)');
                return;
            }

            // Guard against receiving key before our own keypair is ready (race condition)
            if (!this.ecdhManager || !this.ecdhManager.keyPair) {
                console.warn('[ECDH] Received public key but not ready yet, storing for later processing...');
                this.pendingECDHKey = message;  // Store full message object (includes sender_id)
                return;
            }

            // Clear pending key if any (we're processing it now)
            this.pendingECDHKey = null;

            console.log('[ECDH] Received other public key');

            try {
                // SECURITY: Parse JSON payload (contains AAD context)
                let payloadData;
                try {
                    payloadData = JSON.parse(message.payload);
                } catch (parseError) {
                    console.error('[ECDH] Failed to parse payload JSON:', parseError);
                    throw new Error('Invalid ECDH message format: payload is not valid JSON');
                }

                // Extract context from parsed payload
                const { encryptedKey, timestamp, nonce, identityPublicKey, signature } = payloadData;

                // Validate the presence of all fields required for the handshake
                if (!encryptedKey || !timestamp || !nonce || !identityPublicKey || !signature) {
                    throw new Error('Invalid ECDH message format: missing encryptedKey, timestamp, nonce, identityPublicKey, or signature');
                }

                // Decrypt and validate AAD (roomId, sender_id, timestamp, nonce)
                // Also verify the signature with the peer's identity key
                await this.ecdhManager.decryptPublicKey(
                    encryptedKey,
                    this.roomId,        // Expected room ID
                    message.sender_id,  // Sender's connection ID
                    timestamp,          // Timestamp from sender
                    nonce,              // Nonce from sender
                    identityPublicKey,  // Peer's identity public key
                    signature           // Signature on ephemeral key
                );

                // Check if the peer's identity key changed (possible MITM on reconnect)
                if (this.identityManager && this.identityManager.previousPeerIdentity) {
                    if (await this.identityManager.hasPeerIdentityChanged(this.identityManager.peerIdentityPublicKey)) {
                        console.warn('[SECURITY] ⚠️ Peer identity key changed after reconnect - possible MITM!');
                        this.sasVerificationStatus = 'none';  // Force re-verification
                        this.identityManager.sasVerified = false;
                        this.addSystemMessage('⚠️ WARNING: Contact\'s identity key changed! Please re-verify the security code.');
                    } else {
                        console.log('[SECURITY] ✅ Peer identity key unchanged - SAS verification persists');
                    }
                    // Clear previous peer identity after comparison
                    this.identityManager.previousPeerIdentity = null;
                }

                // Deriva raw key material (Uint8Array, non CryptoKey)
                const sessionKeyMaterial = await this.ecdhManager.deriveSessionKey();

                // Determine role: lexicographically smaller sender_id becomes initiator
                // This ensures both parties agree on roles without additional communication
                const otherUserId = message.sender_id;
                const isInitiator = this.userId < otherUserId;
                console.log(`[ECDH] Role determination: ${isInitiator ? 'Initiator' : 'Responder'} (my ID: ${this.userId}, other ID: ${otherUserId})`);

                // Initialize Double Ratchet (PFS + PCS) with identity manager and ECDH keypairs
                await window.cryptoManager.initializeDoubleRatchet(
                    this.identityManager,           // Identity manager for signing ephemeral keys
                    sessionKeyMaterial,
                    isInitiator,
                    this.ecdhManager.keyPair,       // Our ECDH keypair (for DH ratchet)
                    this.ecdhManager.otherPublicKey // Peer's public key (for DH ratchet)
                );

                // Genera SAS per verifica MITM (con context binding: roomId + nonces + timestamps)
                // NOTE: Must be called BEFORE destroyEphemeralKeys()
                this.sas = await this.ecdhManager.generateSAS(this.roomId);
                this.sasBackup = this.sas;  // Backup for reopening verification

                // Show the SAS modal only when verification is still required
                // If the identity persisted and was verified, skip the modal because the SAS carries over
                if (this.identityManager && this.identityManager.isSASVerified()) {
                    console.log('[SECURITY] ✅ SAS already verified from previous handshake - skipping modal');
                    this.sasVerificationStatus = 'verified';
                } else {
                    this.sasVerificationStatus = 'pending';  // Show verification modal
                }

                // Destroy ephemeral ECDH keys to maintain Perfect Forward Secrecy
                // After Chain Ratchet initialization, ECDH keys are no longer needed.
                // Keeping them in memory would allow session key re-derivation attacks.
                // This ensures true Perfect Forward Secrecy.

                // Zero out session key material (clear sensitive data from memory)
                sessionKeyMaterial.fill(0);

                // Clear handshake timeout (handshake completed successfully)
                this.ecdhManager.clearTimeout();

                // Delete bootstrap key (kept for reconnection support)
                this.ecdhManager.deleteBootstrapKey();
                window.cryptoManager.deleteBootstrapKey();

                // Destroy ECDH ephemeral keys (PFS requirement - prevents re-derivation)
                this.ecdhManager.destroyEphemeralKeys();

                this.ecdhHandshakeStatus = 'complete';
                this.pfsActive = true;

                console.log('[ECDH] ✅ Handshake complete');
                console.log('[ECDH] 🔐 Double Ratchet active (PFS + PCS)');
                console.log('[ECDH] SAS (for verification):', this.sas);

                this.addSystemMessage('🔐 Secure connection established (Double Ratchet active - PFS + PCS)');

            } catch (error) {
                console.error('[ECDH] Failed to process public key:', error);
                this.handleECDHAborted();
                // Reset to 'none' to allow handshake restart if room becomes ready again
                this.ecdhHandshakeStatus = 'none';
            }
        },

        // NOTE: handleDHRatchet() removed - Signal Protocol
        // DH ratchet now happens automatically in decryptMessage() when
        // receiving a message with a new DH public key in the header.
        // This is the correct Signal Protocol behavior where ratchet
        // happens on RECEIVE, not via separate messages.

        /**
         * Handles ECDH handshake aborted
         *
         * Cleans up ECDH state but does NOT permanently set status to 'aborted'.
         * The caller should reset status to 'none' when appropriate to allow
         * handshake to restart when room becomes ready again.
         *
         * @param {boolean} hardReset - If true, destroys identity manager and SAS verification.
         *                              Use for: user leave, peer change, MITM detection.
         *                              Default false preserves identity for retry.
         */
        handleECDHAborted(hardReset) {
            if (hardReset === undefined) hardReset = false;
            console.warn('[ECDH] Handshake aborted (hardReset:', hardReset, ')');

            // Cleanup ECDH manager
            this.pfsActive = false;
            if (this.ecdhManager) {
                this.ecdhManager = null;
            }

            // Only a hard reset destroys the identity manager
            // Soft aborts preserve identity and SAS to allow retries after transient issues
            if (hardReset && this.identityManager) {
                this.identityManager.destroy();
                this.identityManager = null;
                this.sasVerificationStatus = 'none';
            }

            // Reset to bootstrap key to prevent stale sessionKey
            // This prevents DoS where old sessionKey is incompatible with new participant
            window.cryptoManager.resetToBootstrapKey();
            this.sas = null;

            // Show warning to user
            this.addSystemMessage('⚠️ Secure connection interrupted');

            // Note: ecdhHandshakeStatus is intentionally NOT set here
            // The caller is responsible for setting it to the appropriate state:
            // - 'aborted' temporarily if needed for logic
            // - 'none' when ready to allow restart
        },

        /**
         * Handles SAS code mismatch (user clicked "Code doesn't match")
         *
         * This indicates a potential MITM attack where the SAS codes don't match
         * between the two participants. Closes the SAS verification dialog and
         * shows a security warning to the user.
         */
        handleSasMismatch() {
            console.warn('[SECURITY] SAS code mismatch reported by user - potential MITM attack');

            // Close SAS verification dialog
            this.sas = null;
            this.sasVerificationStatus = 'mismatch';

            // Show system message warning
            this.addSystemMessage('⚠️ WARNING: Possible MITM attack detected! It is recommended to start a new chat.');
        },

        /**
         * Copy SAS emoji to clipboard (CSP-compatible)
         */
        copySasEmoji() {
            if (this.sas && this.sas.emoji) {
                navigator.clipboard.writeText(this.sas.emoji);
                this.sasCopied = true;
                const self = this;
                setTimeout(function() { self.sasCopied = false; }, 2000);
            }
        },

        /**
         * Handles SAS verification success (user clicked "Verified")
         */
        handleSasVerified() {
            console.log('[SECURITY] SAS code verified by user - connection is secure');

            // Mark SAS as verified in identity manager (persists for session)
            if (this.identityManager) {
                this.identityManager.markSASVerified();
            }

            // Close SAS verification dialog
            this.sas = null;
            this.sasVerificationStatus = 'verified';

            // Show confirmation message
            this.addSystemMessage('✅ Key verified - secure connection confirmed');
        },

        /**
         * Handles user skipping SAS verification (user clicked "I don't want to verify")
         */
        handleSasSkipped() {
            console.log('[SECURITY] SAS verification skipped by user');

            // Close SAS verification dialog
            this.sas = null;
            this.sasVerificationStatus = 'skipped';

            // Show info message
            this.addSystemMessage('ℹ️ Key verification skipped - connection security not confirmed');
        },

        /**
         * Reopens the SAS verification modal
         */
        reopenSasVerification() {
            if (this.sasBackup) {
                this.sas = this.sasBackup;
                this.sasVerificationStatus = 'pending';
                console.log('[SECURITY] Reopening SAS verification modal');
            }
        },

        // ========== EMOJI PICKER METHODS ==========

        /**
         * Toggle emoji picker visibility
         */
        toggleEmojiPicker() {
            this.emojiPickerOpen = !this.emojiPickerOpen;
        },

        /**
         * Close emoji picker
         */
        closeEmojiPicker() {
            this.emojiPickerOpen = false;
        },

        /**
         * Select emoji category
         */
        selectEmojiCategory(category) {
            this.selectedEmojiCategory = category;
            if (window.emojiManager) {
                this.currentEmojis = window.emojiManager.getEmojiForCategory(category);
            }
        },

        /**
         * Insert emoji into message input
         */
        insertEmoji(emoji) {
            this.messageInput += emoji;
            // Focus back on input field
            this.$nextTick(() => {
                const inputField = this.$refs.messageInputField;
                if (inputField) {
                    inputField.focus();
                }
            });
        },

        /**
         * Render message text with emoji substitution and code blocks
         * @param {string} text - Raw message text
         * @returns {string} - HTML-safe rendered message
         */
        renderMessage(text) {
            if (!text) return '';
            if (window.emojiManager) {
                return window.emojiManager.renderWithCodeBlocks(text);
            }
            // Fallback: escape HTML and convert newlines
            return text
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/\n/g, '<br>');
        }
    });

    // Initialize the chat room after Alpine is ready
    Alpine.store('chatRoom').init();
});
