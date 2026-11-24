# PinChat - Log Policy & Accountability Record

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

The reverse proxy is configured not to write access or error logs,
and that is set for the proxy as a whole, not only for the Service's
host names: a request that reaches the server by its address, or
with a host name the proxy does not know, is answered by whichever
site is the proxy's default and would otherwise be logged under that
site's settings. Packet logging by the host's firewall is turned off
and the system journal is kept for a limited period.
The application server operates in strict privacy mode with no
access logging. In that mode it still writes start-up notices about
its own configuration and diagnostic error
messages to its log output; they are worded so as not to contain IP
addresses, User-Agent strings, room or connection identifiers, or
request metadata. Where that output ends up (the container runtime's
log driver, its rotation) is a property of the deployment, to be
checked on the host, not of the application.

This is a standing design decision recorded in `design-decisions.md`
(entry 1, "No mandatory-retention mode"), not a deployment setting.
That entry also records the consequence should the assessment in
section 3.6 ever change: a deployment that would be required to retain
connection records stays private and access-restricted rather than
being offered publicly.

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
processing at every layer. Not retaining access logs is a deliberate
extension of this principle. Keeping no access log and no record of
communications is a design choice strongly aligned with data
minimisation and privacy by design obligations, documented in light
of the requirements the Controller has identified.

### 3.3 Legitimate interest assessment (Art. 6(1)(f) GDPR)

The Controller has assessed that the legitimate interest in retaining
logs for abuse investigation does not outweigh the data subjects'
rights to privacy, given:
- the ephemeral nature of the Service (rooms auto-destruct at TTL);
- the absence of user accounts or persistent identifiers;
- the end-to-end encryption preventing content inspection;
- the availability of enforcement measures that do not require
  persistent logging: blocking at the network level and ending rooms.
  The application has no tool for closing one room selectively at
  present, so ending a room means restarting the Service, which ends
  every room in progress.

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

The Controller has not identified a general obligation, under the
law of its jurisdiction, for an operator of this kind to routinely
retain web access logs. This is the Controller's assessment, not a
ruling: the classification of the Service is itself partly open (see
section 1), and an order to preserve specific data that is actually
held can be addressed to the Controller whatever that classification.
The assessment does not mean that log retention would be unlawful -
an operator with a legitimate, proportionate purpose could retain
minimal logs. Rather, for this specific Service, no such purpose has
been identified that would outweigh the data minimisation principle.

## 4. Alternative measures

In lieu of persistent logging, the following security measures are
in place:

- Rate limiting on room creation and WebSocket connections
- Proof-of-work challenges to prevent automated abuse
- Automatic room expiry (configurable TTL, max 24 hours)
- Ability to block connections at the network level and to end rooms
  (at present by restarting the Service)
- HTTPS/TLS for transport security
- CSRF protection with HMAC-signed tokens
- Argon2id password hashing for beta access authentication
- Single-use short-lived JWT tokens for WebSocket upgrade
- Containerised deployment with non-root privileges and dropped
  Linux capabilities
- End-to-end encryption of all message content (cryptography is
  among the measures Art. 21(2)(h) of the NIS2 Directive lists;
  whether that Directive applies to the Service is addressed in
  section 1.1)

## 5. Hosting provider caveat

{{OPERATOR_HOSTING_PROVIDER_LOG_NOTE}}

This is disclosed in the public Privacy Policy.

### 5.1 Memory, swap and dumps on the host

"Held in memory" describes the application, not everything under it.
As recorded on the production host on 2026-11-19:

- The operating system has a swap partition, and it is not encrypted.
  Neither the application's container nor the reverse proxy was
  excluded from it, and small amounts of memory of both had been
  written there.
- The repository's `docker-compose.yml` gives the container a memory
  ceiling with no swap on top of it (`mem_limit` equal to
  `memswap_limit`). On that date this setting had not been deployed.
  Once deployed it covers the application's container only: the
  reverse proxy, the container runtime, its port forwarder and the
  rest of the host can still be swapped unless they are configured
  separately.
- No crash-dump service is installed, and the application's working
  directory is read-only, so a crash of the application leaves no
  dump file.
- Whether the hosting provider takes snapshots or memory dumps of the
  virtual machine cannot be seen from inside it. It is recorded here
  as not verified, not as absent.

The Terms of Service and the Privacy Policy state that swap exists and
do not promise that the application is kept out of it. This section is
to be updated when the deployed configuration changes.

## 6. Risks to monitor

{{OPERATOR_LEGAL_RISKS_NOTE}}

## 7. Review

This policy will be reviewed whenever there is a material change to
the Service's architecture, threat model, or applicable legal
framework, and in any case at least annually.
