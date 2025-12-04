# Security Documentation

This document provides a comprehensive security analysis of PinChat, including the threat model, cryptographic specifications, and security guarantees.

## Table of Contents

1. [Threat Model](#threat-model)
2. [Cryptographic Primitives](#cryptographic-primitives)
3. [Security Properties](#security-properties)
4. [Attack Surface Analysis](#attack-surface-analysis)
5. [Client-Side Integrity Verification](#client-side-integrity-verification)
6. [Responsible Disclosure](#responsible-disclosure)
7. [Cryptographic Audit Status](#cryptographic-audit-status)

---

## Threat Model

### Trust Assumptions

PinChat operates under the following trust model:

| Entity | Trust Level | Rationale |
|--------|-------------|-----------|
| Client Device | Trusted | User's browser must be uncompromised |
| WebCrypto API | Trusted | Browser-native cryptographic implementation |
| Server | Untrusted | Designed to operate as blind relay |
| Network | Untrusted | All traffic assumed interceptable |
| Other Participants | Partially Trusted | Can see decrypted content within their room |

### Adversary Capabilities

We consider adversaries with the following capabilities:

#### Passive Network Adversary
- Can observe all network traffic
- Can record ciphertext for future analysis
- Cannot modify traffic in transit

**Mitigation**: TLS 1.3 transport encryption + E2E encryption renders captured traffic undecryptable.

#### Active Network Adversary (MITM)
- Can intercept and modify network traffic
- Can attempt to substitute cryptographic keys

**Mitigation**:
- TLS certificate validation at transport layer
- Identity key signatures on ephemeral keys
- SAS verification for out-of-band confirmation

#### Malicious Server Operator
- Full control over server infrastructure
- Can modify server code
- Can log all incoming/outgoing data

**Mitigation**:
- All encryption occurs client-side
- Keys never transmitted to server (URL fragment)
- Server operates as blind relay by design

#### Compromised Server
- Attacker gains full server access
- Can extract all data from memory
- Can serve malicious JavaScript

**Mitigation**:
- No keys stored server-side (PFS)
- No message content accessible
- **Subresource Integrity (SRI)** enforced on all static assets
- Browser extension verifies SRI attributes match signed manifest
- CSP prevents inline script injection

### Out of Scope Threats

The following attacks are explicitly not addressed:

1. **Compromised Client Device**: Malware, keyloggers, or screen capture software on user's device
2. **Compromised Browser**: Malicious browser extensions or modified browser builds
3. **Side-Channel Attacks**: Timing attacks, power analysis on client devices
4. **Participant Misconduct**: Screenshots, recording, or deliberate disclosure
5. **Traffic Analysis**: IP addresses, connection timing, message size patterns
6. **Rubber-Hose Cryptanalysis**: Coercion of participants

---

## Cryptographic Primitives

### Bootstrap Key

The Bootstrap Key is a 256-bit AES key generated client-side when a room is created. It serves as the initial shared secret for the ECDH key exchange.

**Distribution**:
```
URL format: https://host/c/{room_id}#key={base64url_encoded_key}
```

**Security Properties**:
- Never transmitted to server (URL fragment per RFC 3986)
- Shared out-of-band (copy/paste, messaging app, QR code)
- Used only for initial handshake encryption
- Retained in memory for re-handshaking (reconnection scenarios)

**Usage**:
- Encrypts ECDH public keys during handshake (AES-GCM with AAD)
- AAD binds encrypted key to room ID, sender ID, timestamp, and nonce
- After Double Ratchet initialization, message encryption uses derived keys

**Lifecycle**:
```
1. Room creator generates Bootstrap Key (256-bit, CSPRNG)
2. Key appended to URL fragment
3. URL shared with participants (out-of-band)
4. Each participant extracts key from fragment
5. Key used to encrypt/decrypt ECDH handshake
6. Double Ratchet takes over for message encryption
7. Bootstrap Key retained for potential re-handshake
```

### Symmetric Encryption

**Algorithm**: AES-GCM (Galois/Counter Mode)
- Key Size: 256 bits
- IV Size: 96 bits (12 bytes)
- Tag Size: 128 bits (16 bytes)
- Mode: Authenticated Encryption with Associated Data (AEAD)

**Usage**:
- Message encryption
- Image/media encryption
- Handshake key encryption

**Security Properties**:
- Confidentiality: Plaintext hidden from adversary
- Integrity: Tampering detected via authentication tag
- Authenticity: AAD binds ciphertext to context (room ID, sender ID, message number)

**IV Generation**:
```
IV = crypto.getRandomValues(12 bytes)
```
IVs are generated using CSPRNG and never reused within a key's lifetime.

### Asymmetric Key Exchange

**Algorithm**: ECDH (Elliptic Curve Diffie-Hellman)
- Curve: P-256 (NIST secp256r1)
- Key Size: 256 bits
- Output: 256-bit shared secret

**Usage**:
- Initial key exchange (handshake)
- DH ratchet key rotation

**Security Properties**:
- Perfect Forward Secrecy: Ephemeral keys are destroyed after use
- Key Agreement: Both parties derive identical shared secret

**Implementation Notes**:
- P-256 chosen for WebCrypto API compatibility
- X25519 preferred but not natively supported in browsers
- Keys marked non-extractable after import

### Digital Signatures

**Algorithm**: ECDSA (Elliptic Curve Digital Signature Algorithm)
- Curve: P-256 (NIST secp256r1)
- Hash: SHA-256
- Signature Size: 64 bytes (DER encoded)

**Usage**:
- Identity key authentication
- Ephemeral key signing (MITM protection)

**Security Properties**:
- Non-repudiation: Only private key holder can produce valid signatures
- Integrity: Any modification invalidates signature

**Implementation Notes**:
- Private key made non-extractable after generation
- Public key remains extractable for peer transmission

### Key Derivation

**Algorithm**: HKDF (HMAC-based Key Derivation Function)
- Hash: SHA-256
- Salt: Context-dependent (32 bytes)
- Info: Domain separation strings

**RFC Compliance**: RFC 5869

**Usage**:
- Root key derivation from ECDH output
- Chain key derivation for Double Ratchet
- Message key derivation

**Domain Separation Labels**:
```
"DoubleRatchet-RootKey"     - Root key derivation
"InitiatorToResponder"      - Initiator's sending chain
"ResponderToInitiator"      - Responder's sending chain
"ChainKey"                  - Chain ratchet progression
"MessageKey-{N}"            - Per-message key derivation
```

### Chain Ratchet

**Algorithm**: HMAC-SHA256 based KDF chain
- Chain Key Size: 256 bits
- Message Key Size: 256 bits

**Operations**:
```
// Message key derivation
MK_n = HMAC-SHA256(CK_n, "MessageKey-" || n)

// Chain progression
CK_{n+1} = HMAC-SHA256(CK_n, "ChainRatchet")
```

**Security Properties**:
- One-way: Cannot derive CK_n from CK_{n+1}
- Independence: Compromise of MK_n does not reveal MK_{n+1}

### SAS Generation

**Algorithm**: PBKDF2-SHA256
- Iterations: 100,000
- Output: 36 bits (6 emoji from 64-character alphabet)

**Input Binding**:
```
Password = sorted(Identity_PubKey_A || Identity_PubKey_B)
Salt = roomId || sorted_nonces || sorted_timestamps
```

**Security Properties**:
- Brute-force resistant: 100K iterations adds computational cost
- Context-bound: SAS changes per room and session
- Deterministic: Both parties compute identical output

---

## Security Properties

### Perfect Forward Secrecy (PFS)

**Definition**: Compromise of long-term secrets does not compromise past session keys.

**Implementation**:
1. Ephemeral ECDH keys generated per session
2. Chain ratchet derives unique key per message
3. Message keys deleted immediately after use
4. Chain keys ratcheted forward (one-way)

**Guarantee**: An attacker who captures ciphertext and later obtains all current keys cannot decrypt historical messages.

### Post-Compromise Security (PCS)

**Definition**: System automatically recovers security properties after key compromise.

**Implementation**:
1. DH ratchet triggered on communication direction change
2. New ECDH keypair generated
3. New root key derived from fresh DH output
4. Both chains re-initialized

**Guarantee**: If an attacker compromises the current session state, security is restored after the next DH ratchet.

### Zero Knowledge Architecture

**Server Guarantees**:

| Property | Guarantee |
|----------|-----------|
| Message Content | Never accessible (client-side encryption) |
| Encryption Keys | Never transmitted (URL fragment) |
| User Identity | Randomized per-connection UUID |
| Cross-Room Correlation | Impossible (fresh UUID per room) |
| Historical Data | None (RAM-only storage) |

### Authenticated Encryption

**AAD (Additional Authenticated Data) Binding**:
```
AAD = TLV_encode([
    ROOM_ID,
    SENDER_ID,
    MESSAGE_NUMBER,
    MESSAGE_TYPE,
    RATCHET_COUNT
])
```

**Protection Against**:
- Cross-room replay attacks
- Message reordering attacks
- Sender impersonation

---

## Attack Surface Analysis

### Transport Layer

| Component | Protection | Attack Vector | Mitigation |
|-----------|------------|---------------|------------|
| TLS 1.3 | Transport encryption | Downgrade attacks | HSTS header (1 year) |
| Certificates | Server authentication | Certificate spoofing | Certificate pinning (recommended) |
| WebSocket | Persistent connection | Connection hijacking | JWT token authentication |

### Application Layer

| Component | Protection | Attack Vector | Mitigation |
|-----------|------------|---------------|------------|
| CSP | Script injection | XSS attacks | Strict CSP (no inline scripts) |
| X-Frame-Options | Clickjacking | UI redressing | DENY policy |
| Cookies | Session hijacking | CSRF | HttpOnly, Secure, SameSite=Strict |
| Rate Limiting | DoS protection | Resource exhaustion | IP-based + PoW |

### Cryptographic Layer

| Component | Protection | Attack Vector | Mitigation |
|-----------|------------|---------------|------------|
| Bootstrap Key | Key exchange | Key interception | URL fragment (never sent to server) |
| Identity Keys | MITM attacks | Key substitution | ECDSA signatures + SAS verification |
| Session Keys | Message confidentiality | Key compromise | Double Ratchet (PFS + PCS) |
| IV/Nonce | Encryption safety | Nonce reuse | CSPRNG, unique per message |

### Server-Side

| Component | Protection | Attack Vector | Mitigation |
|-----------|------------|---------------|------------|
| Memory | Data persistence | Memory dumps | No keys stored, auto-cleanup |
| Logs | User privacy | Log analysis | PRIVACY_MODE=strict (zero logs) |
| IP Addresses | User tracking | IP logging | HMAC-hashed IPs in rate limiter |

---

## Client-Side Integrity Verification

### The Server Compromise Problem

Even with end-to-end encryption, web applications face a fundamental trust issue: users must trust that the server delivers unmodified JavaScript code. A compromised server could serve malicious code that:

- Exfiltrates encryption keys before they're used
- Sends plaintext to a third party before encryption
- Weakens cryptographic parameters
- Bypasses SAS verification

This is known as the "JavaScript delivery problem" and affects all web-based E2E encryption systems.

### Browser Extension Solution with SRI

PinChat provides browser extensions for Chrome and Firefox that verify file integrity using **Subresource Integrity (SRI)** combined with signed manifests.

#### Why SRI?

The previous approach (extension fetches files separately and computes hashes) was vulnerable to bypass attacks: a sophisticated attacker could detect extension requests (via headers, timing) and serve clean files to the extension while serving malicious code to the browser.

With SRI:
1. HTML files contain hardcoded `integrity="sha256-..."` attributes
2. Browser **natively refuses** to execute any JS/CSS that doesn't match the hash
3. Extension verifies the actual DOM contains correct integrity attributes
4. Manifest is signed and hosted on GitHub (out of server's control)

#### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SRI-BASED INTEGRITY VERIFICATION                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   GitHub Repository                    pinchat.io Server                │
│   (Out-of-band source)                 (Potentially compromised)        │
│   ┌──────────────────┐                 ┌──────────────────────────────┐ │
│   │hashes.json.signed│                 │  HTML with SRI attributes    │ │
│   │ ┌──────────────┐ │                 │  <script src="app.js"        │ │
│   │ │ file hashes  │ │                 │   integrity="sha256-ABC..."> │ │
│   │ │ + signature  │ │                 └──────────────┬───────────────┘ │
│   │ └──────────────┘ │                                │                 │
│   └────────┬─────────┘                                │                 │
│            │                                          │                 │
│            │ 1. Fetch signed                          │ 2. User visits  │
│            │    manifest                              │    page         │
│            ▼                                          ▼                 │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                      BROWSER EXTENSION                          │   │
│   │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐  │   │
│   │  │ 2. Verify       │    │ 3. Content      │    │ 4. Compare  │  │   │
│   │  │    ECDSA        │──▶│    script reads │───▶│    DOM SRI  │  │   │
│   │  │    Signature    │    │    actual DOM   │    │    vs       │  │   │
│   │  └─────────────────┘    └─────────────────┘    │    Manifest │  │   │
│   │                                                └──────┬──────┘  │   │
│   └────────────────────────────────────────────────────────┼────────┘   │
│                                                            │            │
│   ┌────────────────────────────────────────────────────────┘            │
│   │                                                                     │
│   ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                        BROWSER ENGINE                           │   │
│   │  ┌─────────────────────────────────────────────────────────┐    │   │
│   │  │ 5. SRI Enforcement: Browser blocks any JS/CSS where     │    │   │
│   │  │    file hash ≠ integrity attribute hash                 │    │   │
│   │  └─────────────────────────────────────────────────────────┘    │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│            ┌──────────────────────┬──────────────────────┐              │
│            ▼                      ▼                      ▼              │
│   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐     │
│   │   ✓ VERIFIED    │    │  ⚠ SRI MISSING │    │  ⚠ SRI MISMATCH │     │
│   │   All checks    │    │  Extension      │    │  Extension      │     │
│   │   passed        │    │  warns user     │    │  warns user     │     │
│   └─────────────────┘    └─────────────────┘    └─────────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Cryptographic Components

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Hash Algorithm | SHA-256 | File integrity verification |
| Signature Algorithm | ECDSA P-256 | Hash list authentication |
| Key Distribution | Embedded in extension | Trust anchor for signature verification |

#### Security Properties

**What This Protects Against**:
- Server compromise serving malicious JavaScript
- CDN/proxy tampering with static files
- DNS hijacking serving fake content
- Supply chain attacks on deployment
- **Bypass attacks** where server detects extension and serves clean files to it

**What This Does NOT Protect Against**:
- Compromised signing key (attacker could sign malicious hashes)
- Malicious browser extension updates
- Users ignoring warning overlays
- Dynamic content manipulation (API responses)
- First-page-load without extension (user must install extension first)

#### Trust Model

```
Trust Chain:
1. User trusts the extension (installed from browser store or self-hosted)
2. Extension contains hardcoded ECDSA public key
3. Hash list signed with corresponding private key
4. Private key held securely by project maintainer
5. Any file modification breaks the signature chain
```

**Key Management**:
- Private key: Stored securely, never committed to repository
- Public key: Embedded in extension source code
- Key rotation: Requires extension update

#### Verification Process

The extension uses a **dual verification** approach:

1. **Fetch Manifest**: Extension retrieves `hashes.json.signed` from GitHub
2. **Verify Signature**: ECDSA P-256 signature validated using embedded public key
3. **DOM SRI Check**: Content script reads `<script>` and `<link>` elements, verifies `integrity` attributes match signed manifest
4. **File Hash Verification**: Fetches ALL files listed in manifest (not just DOM) and computes SHA-256 hashes
5. **Detect Unauthorized Resources**: Inline scripts, external resources, same-origin scripts outside `/static/`, iframes, external forms
6. **Browser Enforcement**: Browser independently blocks any file not matching its SRI hash
7. **Alert**: Visual feedback (badge + overlay) based on verification result

This dual approach catches:
- Lazy-loaded or deferred scripts not yet in DOM
- Server serving modified files (even with correct SRI in HTML)
- Files blocked by browser SRI (hash mismatch detected independently)

#### Defense in Depth

| Layer | Protection | Bypassed by |
|-------|------------|-------------|
| Browser SRI | Blocks tampered files | N/A (native browser security) |
| Extension SRI check | Detects missing/wrong integrity | User ignoring warnings |
| Extension hash verification | Detects file tampering (all manifest files) | User ignoring warnings |
| Manifest signature | Authenticates hash list | Key compromise |
| Out-of-band manifest | Server can't forge hashes | GitHub compromise |
| **Anti-downgrade sequence** | Prevents replay of old manifests | Storage cleared + old manifest |

#### Failure Modes

| Condition | Badge | Action |
|-----------|-------|--------|
| All checks pass | ✓ Green | Safe to proceed |
| Manifest signature invalid | ! Red | **Full-screen warning overlay** |
| **Manifest downgrade detected** | ! Red | **Full-screen warning overlay** |
| SRI attribute missing | ! Red | **Full-screen warning overlay** |
| SRI mismatch with manifest | ! Red | **Full-screen warning overlay** |
| **File hash mismatch** | ! Red | **Full-screen warning overlay** |
| Inline script detected | ! Red | **Full-screen warning overlay** |
| External resource detected | ! Red | **Full-screen warning overlay** |
| Unauthorized same-origin script | ! Red | **Full-screen warning overlay** |
| Network error fetching manifest | ? Yellow | Retry, inform user |
| GitHub unavailable | ? Yellow | Cached result or warning |
| File hash ≠ SRI attribute | N/A | **Browser blocks the file** |

#### Limitations

1. **First-Use Trust**: User must trust the initial extension installation
2. **Update Window**: Between file changes and hash list update, verification may fail
3. **Key Compromise**: If signing key is compromised, protection is void
4. **User Override**: Determined users can dismiss warnings
5. **Extension Required**: Browser SRI protects against file tampering, but without extension, HTML could be modified to remove/change SRI

#### Recommendations

For maximum security:
1. Install extensions from source code review, not pre-built packages
2. Verify the embedded public key matches the project's published key
3. Never dismiss integrity warnings without investigation
4. Report any unexpected verification failures

---

## Responsible Disclosure

### Reporting Security Vulnerabilities

If you discover a security vulnerability in PinChat, please report it responsibly:

1. **Do NOT** disclose the vulnerability publicly before it is fixed
2. **Do NOT** exploit the vulnerability beyond what is necessary to demonstrate it
3. **Do** provide sufficient detail for us to reproduce and fix the issue

### Contact

Report vulnerabilities via:
- GitHub Security Advisories (preferred)
- Email: security@pinchat.io

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested remediation (if any)

### Response Timeline

| Phase | Timeline |
|-------|----------|
| Initial Response | 48 hours |
| Vulnerability Confirmation | 7 days |
| Fix Development | Varies by severity |
| Public Disclosure | After fix deployed + 30 days |

### Severity Classification

| Severity | Criteria | Example |
|----------|----------|---------|
| Critical | Remote code execution, key compromise | Server-side key extraction |
| High | Authentication bypass, data exposure | Session hijacking |
| Medium | Limited data exposure, DoS | Rate limit bypass |
| Low | Information disclosure, minor issues | Verbose error messages |

### Recognition

Security researchers who responsibly disclose valid vulnerabilities will be:
- Credited in release notes (if desired)
- Listed in security acknowledgments

---

## Cryptographic Audit Status

**Current Status**: Not formally audited

This implementation follows established protocols (Signal Double Ratchet) and uses standard cryptographic primitives via the WebCrypto API. However, it has not undergone a formal security audit by an independent third party.

**Security Features Implemented**:
- ✅ Subresource Integrity (SRI) for all static assets
- ✅ Browser extension with SRI verification
- ✅ Signed manifest hosted out-of-band (GitHub)
- ✅ CSP preventing inline script execution

**Recommendations before production use**:
1. Commission a professional cryptographic audit
2. Consider certificate pinning for mobile clients
3. Establish incident response procedures
4. Set up monitoring for manifest signature failures
