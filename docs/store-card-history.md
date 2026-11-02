# Store-owned rate-card history

Owner ruling, 2026-11-01: “i dont like disk we have dbs”; “we never save anything
to disk we only save to Stores”. This supersedes the proposed card-pending.json
format and the earlier data-directory / disk-spool decisions. The host must not
write card files. Physical persistence belongs to the configured Store. All five
configured backends remain supported; memory Store is explicitly ephemeral and
cannot survive destruction of its Store instance.

Pricing existed in 1.5.5, but the card history and pending machinery are new in
1.6. The reader retains compatibility with complete busbar.card.v1 Store entries.
The Store record protocol uses the original EntryKey, 64-bit chunk indices,
length and count metadata, and a SHA-256 digest. Complete v1 entries and existing
v2 metadata remain readable as active history. New own-card candidates use metadata
version 3 within `busbar.card.v2`. Their canonical candidate commit confirms the
saved original, while a separate activation intent and matching activation commit
bind its actual pricing cutover to that original's digest. A candidate alone never
activates prices. Amendments keep their explicit correction windows and remain
write-before-apply. Partial or unknown writes retain the same immutable owner.

This is a logical Store schema, not a new ABI or a host disk format. Older 1.6
development binaries that do not understand the current metadata or activation
records refuse them and must not be used to downgrade such a Store. No compatibility with a published 1.5.5 card-history format
is claimed, because that format did not exist.

Source inspection of memory, MySQL, PostgreSQL, SQLite and Valkey generic record
put/get/scan methods and declarations found no schema-name allowlist. V2 keys
are at most 29 bytes and values remain at most the existing 512-byte RecordBytes
limit (MySQL's existing record key column allows 2048 bytes). No backend fork or
new admission-size cap is required. Store success carries that backend's own
durability semantics; a memory Store success is only within that instance's life.

Owner approval on 2026-11-02 supersedes the earlier RAM activation policy: new
prices activate only after the configured Store confirms they were saved.
Generation transactions prepare the exact candidate and confirm its activation
before publishing the App. The final commit publishes confirmed prices and limits
without Store calls; external notifications follow App publication. A refusal,
Pending timeout, unknown result, callback unwind or dropped preparation retains
the old effective prices and the exact pending candidate. Background retries can
confirm custody, but cannot authorize a generation's activation. An exact immutable
readback is positive confirmation of an earlier unknown write.

Boot refuses if it cannot confirm its card. A prepared-only candidate survives
restart as pending and is never mistaken for active history. A first boot with no
confirmed opening serves no prices. Complete Store intents preserve restart
custody; an outage before an intent is complete leaves RAM custody only. No host
file, WAL or spool substitutes for Store confirmation. A peer's pending candidate
does not select this node's card or block unrelated peers.

The config overlay anchor and the governance card Store can be different Store
instances. There is no cross-Store atomic transaction: a desired config may already
be saved when card confirmation fails. The old runtime generation stays active,
and recovery must retain those partial effects and the exact unknown candidate.

Authoritative boot, config reload and plugin reload provide explicit recovery.
A candidate whose activation was never attempted can be retired using a matching
Store retirement intent and commit; its original records remain inert in the
Store. Unknown activation must first be confirmed with its exact metadata. If
that activation is confirmed but the desired config still names the old card,
recovery saves a new activation for the desired card and retains both facts.
Neither background retries nor an ordinary mutation can perform this recovery.

New raw usage eras carry both the effective timestamp and the exact confirmed
entry identity, captured from one node history snapshot. Counts served while a
change is pending keep that original card after confirmation, across day/window
boundaries and equal timestamps. Legacy rows retain their historical fallback;
signed amendments still resolve their intended wall-time window. No derived
money is persisted. Activation dates use the writer's existing wall clock; entry
identity supplies provenance without claiming a new shared-clock authority.

Concurrent openings retain the fleet's lowest-key winner. A node holding another
confirmed opening prices its local pins and eras with its own card; the fleet
retains every original card so exact usage identities still resolve correctly.
