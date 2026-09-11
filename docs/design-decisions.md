# PinChat - Design Decisions

Standing decisions about what PinChat is and is not. These are properties of
the system, not deployment settings: a decision recorded here constrains what
may be built, and changing one is a change to the product, not a
configuration tweak.

Each entry states the decision, why it exists, and what it rules out. When a
future change appears to require breaking one of these, the correct response
is to question the change, not to soften the entry.

---

## 1. No mandatory-retention mode

**Decision.** PinChat keeps no persistent record of who connected, when,
from where, or with whom, beyond the ephemeral state a live room needs to
operate. Logging, retention, or per-user identity will not be introduced for
the sole purpose of enabling public operation. If applicable law requires
such retention for a publicly available deployment, that deployment stays
private and access-restricted instead.

**Status.** Active. The public instance at pinchat.io runs behind a shared
password gate; the reverse proxy writes no access log and the application
runs in strict privacy mode.

**Rationale.** The value of the service rests on a claim about the server:
it knows the minimum and forgets it. Turning that into "connections are kept
for twelve months" would not be an implementation detail, it would replace
one of the system's defining properties with its opposite. A service that
retains connection records is a different product, whatever its transport
encryption does.

This is deliberately a refusal rather than a mitigation. Encrypted IP
storage, a separate retention store, or keeping "only one metadata field"
are all ways of accepting the requirement while appearing not to. If a
requirement is incompatible with the threat model, the answer is to not
operate under the conditions that trigger it.

**What this rules out.**

- Access logs, connection logs, or any persistent per-connection record,
  including hashed, encrypted, or otherwise pseudonymised forms.
- Per-user accounts, invitations tied to an identity, or any authentication
  scheme that produces a record of which person connected when. A shared
  secret with no identity behind it is the consistent choice here, not a
  shortcut: an identity-based gate would create exactly the log this entry
  excludes.
- Retaining room identifiers, participant identifiers, or addresses in
  application error output. Error paths report what failed, not who it
  happened to.

**What this does not claim.** A running room holds state on the server:
membership, relay buffers, ordered control envelopes, and in-memory
sessions. That state is what the room needs while it is alive, and it is
gone when the room expires or the process restarts. The decision is about
records that outlive the room, not about pretending the server is stateless.

**Legal position.** No general retention obligation has been identified for
a service of this kind. See section 3.6 of `accountability-log-policy.md`,
which records the controller's assessment that a non-telecom, non-ISP
operator is under no routine web access log retention duty in the
controller's jurisdiction. This entry is therefore a choice made in advance,
not compliance with an existing duty, and it states what happens if that
assessment ever changes.

**Related.** `accountability-log-policy.md` sections 2, 3.6 and 4;
`SECURITY.md` (Zero Knowledge Architecture).
