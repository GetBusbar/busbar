# Store-owned rate-card history

Owner ruling, 2026-11-01: “i dont like disk we have dbs”; “we never save anything
to disk we only save to Stores”. This supersedes the proposed card-pending.json
format and the earlier data-directory / disk-spool decisions. The host must not
write card files. Physical persistence belongs to the configured Store. All five
configured backends remain supported; memory Store is explicitly ephemeral and
cannot survive destruction of its Store instance.

Pricing existed in 1.5.5, but the card history and pending machinery are new in
1.6. The reader retains compatibility with complete busbar.card.v1 Store entries.
The v2 Store record protocol uses the original EntryKey, 64-bit chunk indices,
length and count metadata, and a SHA-256 digest. A complete intent records the
original entry and whether it selects the writer's own card. A separate canonical
commit confirms the entry for fleet history. An intent alone is never a confirmed
price. Partial or unknown writes retain the same immutable owner for retry.

This is a logical Store schema, not a new ABI or a host disk format. Older 1.6
development binaries do not understand v2 and must not be used to downgrade a
Store containing it. No compatibility with a published 1.5.5 card-history format
is claimed, because that format did not exist.

Source inspection of memory, MySQL, PostgreSQL, SQLite and Valkey generic record
put/get/scan methods and declarations found no schema-name allowlist. V2 keys
are at most 29 bytes and values remain at most the existing 512-byte RecordBytes
limit (MySQL's existing record key column allows 2048 bytes). No backend fork or
new admission-size cap is required. Store success carries that backend's own
durability semantics; a memory Store success is only within that instance's life.

This is an intermediate implementation retaining the existing activation policy:
configuration generation publication precedes this card notification, and the
node can serve its RAM-applied pending prices while the Store is unavailable.
Strict mode reports that this node's card is pending; a peer's pending intent does
not refuse unrelated admissions. No restart durability is claimed until the
complete intent is in the configured Store, and no canonical confirmation is
claimed until the exact canonical commit is complete. The owner's separate choice
about retaining old prices until Store confirmation remains open. Implementing
that alternative requires a fallible prepare step before config persist/swap;
a failure reported by the existing post-swap InstalledLimits::keep is too late.
