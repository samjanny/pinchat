# PinChat — Log Policy & Accountability Record

**Document type:** Internal accountability record (Art. 5(2) GDPR)
**Controller:** {{OPERATOR_NAME}}
**Last updated:** {{LAST_UPDATED}}

<!--
  This is a template. Replace every {{PLACEHOLDER}} with the corresponding
  value from your deployment's operator.json. If an optional placeholder
  is left empty, remove the enclosing sentence, paragraph or section so
  the final document has no orphan headings or empty lines. In particular,
  if {{OPERATOR_LEGAL_RISKS_NOTE}} is empty, delete section 6 in full.
-->

## 1. Legal classification of the Service

{{OPERATOR_LEGAL_FRAMEWORK_NOTE}}

### 1.1 NIS2 classification

{{OPERATOR_NIS2_NOTE}}

### 1.2 Digital Services Act classification

{{OPERATOR_DSA_NOTE}}

## 2. Decision on logging

The Service does not ordinarily retain persistent access logs,
application logs, or any other log files containing personal data
(IP addresses, User-Agent strings, request metadata).

The reverse proxy is configured not to write access logs to disk.
The application server operates in strict privacy mode with no
access logging.

## 3. Rationale

### 3.1 Data minimisation (Art. 5(1)(c) GDPR)

The GDPR requires controllers not to process personal data that are
not necessary for the purposes of the processing. Retaining IP-based
access logs would constitute processing of personal data. Given that
the Service is end-to-end encrypted, ephemeral, and does not require
user accounts, there is no content moderation capability and no
operational need for retrospective log analysis. The Controller has
assessed that no legitimate, proportionate purpose justifies the
routine retention of access logs for this Service.

### 3.2 Privacy by design and by default (Art. 25 GDPR)

The architecture of the Service is designed to minimise data
processing at every layer. Not retaining logs is a deliberate
extension of this principle. The zero-log configuration is a design
choice strongly aligned with data minimisation and privacy by design
obligations, documented in light of all applicable requirements.

### 3.3 Legitimate interest assessment (Art. 6(1)(f) GDPR)

The Controller has assessed that the legitimate interest in retaining
logs for abuse investigation does not outweigh the data subjects'
rights to privacy, given:
- the ephemeral nature of the Service (rooms auto-destruct at TTL);
- the absence of user accounts or persistent identifiers;
- the end-to-end encryption preventing content inspection;
- the availability of real-time enforcement measures (room
  termination, connection blocking) that do not require persistent
  logging.

### 3.4 Cooperation with authorities

{{OPERATOR_JUDICIAL_COOPERATION_NOTE}}

### 3.5 Relevant case law

{{OPERATOR_CASE_LAW_NOTE}}

PinChat is designed so that decryption keys remain client-side and
are not transmitted to the server. Rooms are ephemeral and
server-side persistence is intentionally minimised. As a result, the
service is not architected to provide retrospective access to
plaintext content or to server-side key material that it does not
possess.

### 3.6 Absence of a general log retention obligation

No general obligation exists under the applicable law of the
Controller's jurisdiction for a non-telecom, non-ISP service
operator to routinely retain web access logs. This does not mean
that log retention would be unlawful — an operator with a
legitimate, proportionate purpose could retain minimal logs.
Rather, for this specific Service, no such purpose has been
identified that would outweigh the data minimisation principle.

## 4. Alternative measures

In lieu of persistent logging, the following security measures are
in place:

- Rate limiting on room creation and WebSocket connections
- Proof-of-work challenges to prevent automated abuse
- Automatic room expiry (configurable TTL, max 24 hours)
- Real-time ability to terminate rooms and block connections
- HTTPS/TLS for transport security
- CSRF protection with HMAC-signed tokens
- Argon2id password hashing for beta access authentication
- Single-use short-lived JWT tokens for WebSocket upgrade
- Containerised deployment with non-root privileges and dropped
  Linux capabilities
- End-to-end encryption of all message content (itself a
  conformity measure under Art. 21(2)(h) of the NIS2 Directive)

## 5. Hosting provider caveat

{{OPERATOR_HOSTING_PROVIDER_LOG_NOTE}}

This is disclosed in the public Privacy Policy.

## 6. Risks to monitor

{{OPERATOR_LEGAL_RISKS_NOTE}}

## 7. Review

This policy will be reviewed whenever there is a material change to
the Service's architecture, threat model, or applicable legal
framework, and in any case at least annually.
