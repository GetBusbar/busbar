# CoreFix: evolve dev into a kind-based core

Status: native primitive persistence and automatic startup migration are wired into dev. Integration and native qualification remain in progress; this is not yet a qualified development candidate.

Source baseline: core `dev` at `db64700e41f1192d72c55c6596e3a09af44ef268`.
Prepared 2026-11-06. The reviewed baseline had fourteen members; `dist/default` is a
separate assembly workspace. The migration-boundary amendment in §10.4 permits
one migration library after folding seams: thirteen existing core members plus that
crate, fourteen workspace members linked into normal Busbar in total. Rebase against
later dev changes before executing a task. Do not restore code, rules, architecture or release workflows
from old design documents. **Dev is the current architecture. This document is a
forward change plan.** 1.5.5 is a migration source, not the target architecture.

The owner requested a source-grounded review of all fourteen crates, a complete
design and tasks executable without rediscovering architectural decisions. This
document defines the forward implementation. The owner has authorized unattended
execution; commits and publication remain separate actions. No QA/main promotion is part of this plan.

## 1. Outcome and non-negotiable boundaries

**This redesign applies to every plugin kind: Plane, Auth, Secret, Store, Transport,
Hook and Export.** Stores expose the largest current ownership problem; completing
the Store work alone does not complete CoreFix. All seven kinds must satisfy the
ownership and acceptance rules below. This is a core redesign and coordinated plugin
adaptation. The owner's later authorization permits one new migration library
for seamless startup upgrades under §10.4; no other new crate is part of this plan.

Core speaks **kinds**, not implementations. Every interaction is
`plugin ↔ core ↔ plugin`. A plugin knows its own protocol/backend and the public
kind/host contracts. It cannot import another plugin, select another implementation,
hold its object, or depend on another plugin's record interpretation.

Every admitted Store implements one complete mandatory persistence contract. Every
plane using the corresponding host-contract version can use every admitted Store.
Adding a plane or auth implementation must require zero Store source changes.
Changing a core credential or accounting rule must require zero Store source changes.
Physical durability and deployment topology are explicit properties, not optional
support for a business feature. An unsuitable database configuration is refused,
not silently assigned weaker correctness.

Core-wide semantics belong in core: identity lifecycle, authorization, exact
accounting, publication, retries, resource limits and migration coordination.
Protocol-specific semantics stay with their plugin: a task protocol decides what
terminal means; core understands a declared terminal flag and generic record effects.
Storage backends receive opaque keys, values and transaction conditions.

"Dumb plugins" means no independent ownership of Busbar product policy or shared
orchestration. Plugins translate between the kind contract and their protocol,
provider, algorithm or backend, then report facts/results/effects. Core decides
authority, lifecycle, routing, budgets, accounting and cross-kind consequences.
Protocol algorithms still belong to their implementation: moving LDAP parsing,
SigV4 canonicalization or A2A state interpretation into core would teach core plugin
details and violate the same rule. A hook may compute its declared ranking; core
owns when it runs, permitted inputs, admissible outputs and application of the result.
Reusable custody/encoding mechanics belong in the existing SDK where appropriate;
shared Busbar decisions have one core owner, not one linked copy per plugin.

Do not build a new ORM, database engine, generic rules language, distributed
transaction coordinator, event bus, plugin-to-plugin RPC layer, or per-kind framework
crate. Do not replace necessary database/client code with locally written protocol
implementations to meet a LOC target. Preserve the approved upstream serde_json
deferral; this project neither removes its existing safeguards nor creates another
exception.

## 2. Evidence and limits of this review

This is a boundary/call-path/design review, not a claim to have proved every line of
the repository. Findings below are based on dev source, manifests and representative
production paths. Independent fresh Astra reviews examined contract/ABI boundaries
and migration/recovery. No full test suite or runtime fault campaign was run for this
document. Proposed acceptance tests are work to execute, not passing results.

> 🧠 **From Hindsight memory (Store-only Busbar persistence and rate-card recovery)** — The recorded owner decision places application persistence through Stores and requires persistence confirmation before price activation, with no local-file fallback. Current source in `root/card_history.rs`, `root/durability/`, and kernel recovery is the implementation baseline; old memory claims about release status or deadlines are not acceptance evidence.

| ID | Verified source / symbol | Design impact |
|---|---|---|
| F01 | `busbar-contract/src/records.rs::RecordStore`; `plugin-loader/src/store_v3.rs` implements both `RecordStore` and `StoreCalls` | Business operations currently cross the backend boundary. Interpose a host facade and replace backend business slots. |
| F02 | Reviewed baseline `busbar-contract/src/abi/store/mod.rs::KIND_SLOTS` was 31 | Replace the business slot shape together with its validators/SDK/fingerprint; §9 records the current unreleased ABI 3 decision. `v4` is a staging label. |
| F03 | `abi/sdk/store/conditional.rs::Request::validate/encode`; `abi/store/money.rs` | Conditional values/preconditions are limited to 512 bytes and that encoded extension to 16 MiB, without a batch-count cap. These are NOT universal bounds on typed Store records or atomic usage batches. |
| F04 | `conditional.rs::Mutation::DeleteRange`; kernel `host_chains.rs` | Atomic exact-length prefix deletion already exists. Never replace it with independently visible page deletes. |
| F05 | `busbar-store-memory/store-memory/src/lib.rs::credential_preconditions`, task/ticket branches; corresponding SQL/Valkey implementations | Shared product rules are duplicated across stores. Move the rules, not five copies of the functions. |
| F06 | `busbar-kernel/src/host_records.rs::ConditionalWrite`; `governance/raw_recovery.rs`; `root/durability/conditional.rs::decide` | Exact candidate custody exists, but several commit/retry paths exist. Consolidate mechanics while preserving their domain ownership. |
| F07 | `records.rs::RecordStore::put_key_with_credential` default performs two writes; `add_usage` default does read/modify/write | These defaults cannot implement the new atomic contract. Remove them; never use them as migration fallbacks. This is a dangerous API default, not proof that current concrete stores use it. |
| F08 | `busbar-kernel/src/host_record_bootstrap.rs::ColdRecordReceipt` | Current code already distinguishes sender quiescence from backend quiescence. Preserve and extend this mechanism rather than invent a second attestation system. |
| F09 | `busbar-kernel-seams/src/migration.rs::MigrationSource/MigrationFigures` | The legacy seam permits unreadable/unsupported input to become empty. Do not use it for authoritative upgrade decisions; replace with explicit error-bearing import results. |
| F10 | `busbar-kernel-audit/src/recipe.rs::Recipe` | Several signed historical formats coexist. Migration must preserve original preimages and recipe identifiers. |
| F11 | `busbar-kernel-wal/src/wal.rs::in_directory`; `busbar/src/root/durability/mod.rs` Store-backed memory journal path | Physical disk machinery remains in the library, while current application durability is Store-backed. Separate reachable runtime from historical import utilities before deleting. |
| F12 | `busbar-core-connector/src/compose.rs`, `guard.rs`; `busbar-kernel-egress/src/ports.rs`; `busbar-kernel-breaker/src/classify.rs` | Useful host I/O and semantic outcome boundaries already exist. Retain them. |
| F13 | `busbar-kernel/src/auth/mod.rs`, `busbar-kernel-identity/src/chain.rs::KEYS_MODULE` | Core-owned identity mechanisms are not third-party implementation special cases. Replace textual operator selection with resolved host enums, not removal of key verification. |
| F14 | `busbar/src/root/{card_history,card_store,kernel}.rs` and `busbar/src/root/durability/` | The binary composition root owns substantial reusable state behavior. Move neutral behavior into kernel modules, leaving concrete wiring in the root. |
| F15 | `busbar-plane-a2a/plane-a2a/src/{statement,conditional_publication}.rs` | Retention declarations and generic conditional effects already exist. Use those paths; do not move A2A rules into kernel. |
| F16 | `busbar-contract/src/services.rs::Caller` | The host distinguishes plugin identity from configured instance identity. Persistent namespaces must preserve the distinction across reloads/renames. |
| F17 | `abi/sdk/plane/conditional.rs`, `services.rs`, `abi/plane/check.rs` import Store condition/retention vocabulary | Move neutral concepts to shared host-record vocabulary inside contract; one kind must not depend on another kind's SDK. |
| F18 | `busbar-store-valkey/store-valkey/src/slots.rs::v3_record_transaction` | Separate EXEC mutations can fail independently while the receipt succeeds. Replace the publication mechanism; a receipt alone cannot repair partial atomicity. |
| F19 | `abi/store/plane.rs::TokenIn`; SQLite `redeem_plane_token` | Redemption currently uses authoritative time within the Store transaction. Preserve this in a neutral time predicate and consistent read. |

Paths in tables are relative to `crates/` unless a sibling repository is named.
Elsewhere, `root/` means `crates/busbar/src/root/`, `governance/` means
`crates/busbar-kernel/src/governance/`, and `abi/` means
`crates/busbar-contract/src/abi/`. New module paths are explicitly proposals.
Deleted historical architecture prose is not evidence of a current invariant.

Sibling dev revisions used for backend evidence (local directory names may differ
from package/repository names):

| Directory under `GetBusbar/` | Dev HEAD |
|---|---|
| `busbar-store-memory` | `d1c5178045bc20cc5bea5da9fba4070a5a96603d` |
| `store-sqlite` | `676d86f65494ea43a6bbc4d9f8fee687571a5d14` |
| `busbar-store-postgres` | `6e873d0cf807dc2bd0f1ca36d93525b715bae28b` |
| `busbar-store-mysql` | `b1bff71519a29e51c45ee744b1142c1e233dbc54` |
| `busbar-store-valkey` | `a4c555baa63bcd09cfd0822f4afb200b6d54da1e` |

The old architecture/layout/internals/storage-model/roadmap, ADR collection,
1.6.0 rulebook/TODO, conformance-release design and superseded gate-integrity plan
were removed with this document. Historical fixtures, evidence and signed formats
remain historical evidence. The release-trust document remains an implementation
reference, not authority to restore retired infrastructure. Historical source comments
may still cite old design section numbers; those citations do not override dev.

## 3. All fourteen crates: disposition

Folding the redundant seams crate leaves thirteen existing core crates. Add one
`busbar-migrations` library normally linked into Busbar (§10.4): fourteen workspace
members in total. This supersedes both the original zero-new-crates target and the
subsequently rejected separate-tool proposal. Do not combine extraction with changes
to persisted formats or replay semantics in one patch.

| Existing crate | Keep | Move/delete | Decision |
|---|---|---|---|
| `busbar` | CLI, process lifecycle, concrete assembly, install/wire adapters, shutdown | Move reusable Store journals, rate-card persistence and recovery algorithms out of `root/`; remove duplicate retry loops after callers migrate | Keep as executable/composition boundary. Never put business logic in generated plugin lists. |
| `busbar-contract` | C ABI shapes, kind contracts, host service contracts, bounded types, SDK encoding and custody helpers, neutral quantities | Remove backend business slots in v4; relocate host-only `RecordStore` facade and domain-only persistence types to kernel when no public users require them; retain necessary wire DTOs until callers migrate | Keep the only Busbar dependency of plugins. Do not put the host persistence engine here. |
| `busbar-kernel` | Host services, admission, authorization, governance, lifecycles and orchestration | Add `persistence/`; fold equivalent commit mechanics into it; keep domain policy in `governance/` and auth; remove obsolete store-business delegation; expose current-target preparation through §10.4's current-target facade | Main serving owner. Historical source transforms and automatic startup migration execution belong to `busbar-migrations`. |
| `busbar-kernel-identity` | Chain evaluation, principal and caller-reference semantics | Replace historical entry adapters only when their callers are ported; keep core-owned key/operator mechanisms explicit | Keep a small pure security boundary. |
| `busbar-kernel-ledger` | Exact counts-to-money projection, dated price history, accounting math | No SQL, backend retries, Store I/O or plugin-name branches; move any persistent writes into kernel orchestration | Keep pure arithmetic separate from persistence. |
| `busbar-kernel-egress` | Attempt lifecycle, pool selection, exhaustion and semantic upstream results | Eliminate duplicate orchestration only where source paths prove equivalence; no persistence engine here | Keep the focused execution boundary. |
| `busbar-kernel-breaker` | Admission/cooldown/half-open state and semantic fault classification | No protocol-number/provider-name interpretation; preserve one classifier | Keep; its independence prevents protocol policy leakage. |
| `busbar-kernel-wal` | Exact record framing, verification, continuation and memory journal logic used by current core | Remove production physical directory/segment management after legacy import is supplied; put bounded legacy-file reading under migration tooling, not runtime fallback | Keep existing crate name in this change. It becomes a journal codec/library; renaming is unnecessary churn. |
| `busbar-kernel-audit` | Canonical signed recipes, chain verification, amendments, exposure rules | Physical persistence belongs to kernel persistence; never rewrite signed historical records | Keep separate cryptographic evidence boundary. |
| `busbar-kernel-seams` | Preserve needed types and trait meanings | Move `slice` to `kernel::slice`, `verb_store` to `kernel::persistence::recovery_api`; replace legacy migration seam through §10.4's migration boundary; delete crate and dependencies | Current production consumers are kernel, admin and binary, which already reach kernel. No separate cycle-breaking role remains for these consumers. Recheck external/internal consumers at execution SHA. |
| `busbar-core-connector` | Host-owned connection lifecycle, TLS, DNS/egress policy, declared transport composition | Remove duplicate host-I/O adapters if identical; keep SQL/RESP codecs in their Store plugins or libraries | Keep host security and platform implementation boundary. |
| `busbar-core-admin` | Administrative HTTP/API codecs, authorization-facing service endpoints and error mapping | State mutation/recovery decisions call kernel APIs; no direct backend writes or duplicate idempotency algorithm | Keep management surface. Preserve statuses and redaction. |
| `busbar-core-oauth2` | Host authorization-server service and maintained OAuth library integration | Shared record commits/replay storage route through kernel persistence; OAuth protocol semantics stay here | Keep existing core service; do not reclassify it as an ordinary plugin merely because a file calls it a plane. |
| `busbar-plugin-loader` (`plugin-loader/`) | Signature/trust checks, loading, ABI validation, leases, cancellation, dispatch and transport bindings | Delete typed backend business forwarding after v4 cutover; retain versioned legacy decoding only for migration where required | Keep unsafe boundary separate. No kernel dependency and no business policy. |
| New `busbar-migrations` | Startup upgrade coordinator, registered edges, historical interpretation and verification | Extract the staged kernel migration tree as specified in §10.4; normal root dependency | One library for all supported edges; no backend/version crates, no kernel-to-migrations dependency. |

Dependency direction after the change:

```text
binary ──> kernel, admin, oauth2, connector, loader
admin/oauth2 ──> kernel ──> identity/ledger/egress/breaker/journal/audit
connector ──> kernel, egress, loader
all of the above ──> contract
every plugin ──> contract + suitable external libraries
loader ──> contract                    (never kernel)
kernel ──> neutral backend trait       (never concrete loader/plugin)
root ──> migrations ──> kernel + contract + existing evidence codecs
kernel/loader/plugins -X-> migrations
```

`dist/default` may name concrete plugin crates to assemble a distribution. That is
selection/wiring, not permission to introduce behavior branches in core. Names are
valid for loading, diagnostics, configuration identity and historical migration
lookup. Decisions about runtime behavior use kind declarations and host policy.

## 4. Target module ownership and call paths

Create `crates/busbar-kernel/src/persistence/` with these modules:

| Module | Responsibility / existing source to consolidate |
|---|---|
| `mod.rs` | `CoreStore` construction, typed host facade, validated backend attachment; replacement for business delegation from `LoadedStore` |
| `commit.rs` | `PreparedCommit`, typed decision/state transition, candidate digest; common portion of `host_records::ConditionalWrite` and root `conditional::decide` |
| `objects.rs` | Bounded immutable chunks and an atomic object manifest; consolidate chunk handling from config/OAuth/journal paths |
| `keys.rs` | Canonical binary framing for internal namespaces, addresses and indexes; preserve historical readers |
| `scan.rs` | Bounded continuation, coherent point/group reads and index validation |
| `partition.rs` | Stable core-owned namespace derivation, preserving full identity in record keys |
| `startup.rs` | Strict logical-format admission, retained bootstrap/registration attempts and durable writer retirement |
| `host_records.rs` | Authorized opaque records and conditional host effects; separate host-private owner namespace |
| `history.rs` | Explicit collection relationships, versioned envelopes, atomic cascades/retention and audit persistence |
| `claims.rs` | Scoped single-use claims with native serialization-time expiry and retained unknown attempts |
| `import_target/` | Current-target row preparation and activation primitives for the startup migration coordinator; no historical source profiles (§10.4) |
| `recovery_api.rs` | Core-facing recovery commands moved from `verb_store`; retain authorization checks |
| `journal/` | Store-backed journal/identity/keyset orchestration moved from `root/durability`; use existing WAL/audit codecs |

Add `governance/persistence/{identity,ledger}.rs` for the business transformations
currently replicated in stores. `CoreStore` delegates typed operations to these
modules. No credential policy in the generic `commit.rs`; no database-specific code
in governance. Keep the existing credential chip/at-rest owner; this is not a new
cryptography subsystem.

Define the neutral asynchronous `PersistenceBackend` trait and owned primitive DTOs
in `busbar-contract/src/persistence.rs`. The loader implements it; kernel consumes
it. This location avoids a loader→kernel dependency. Move shared plugin-facing
conditions, decisions and retention declarations to `busbar-contract/src/host_records.rs`;
Plane and Store SDKs map that vocabulary, rather than importing each other. Keep
host business facade types in kernel. Delete BOTH typed backend surfaces,
`RecordStore` and `StoreCalls`, once their callers have migrated.

`StoreAxis::open` returns a neutral `OpenedBackend` (backend trait + metadata).
`kernel::appbuild::open_config_store` validates it, performs allowed initialization
or migration, constructs one `Arc<CoreStore>` and shares that instance with
governance, host services and root services. Persistence-facing facade methods become
asynchronous. Port off-path callers to await them; preserve synchronous hot-path
cache access. Do not copy `StoreRows`' blocking bridges into the new interface. Any
temporary synchronous administrative bridge uses the existing off-runtime boundary
and is removed before P09 acceptance; no `block_on` on runtime workers.

Plane effects pass through existing host-service authorization and namespace
binding before entering persistence. Plane code cannot submit `CoreStore` methods,
internal namespace bytes, raw database names or other instances' keys. Host-generated
records use a separate private namespace, not a magic string supplied by a plugin.

No retained raw backend handle may permit business callers to bypass the facade.
The loader implementation of `RecordStore` goes away. During porting, compatibility
adapters are core-owned and explicitly selected before opening the dataset; never
fall back to old business writes following a new-path failure.

The history owner accepts an explicit authorized collection graph, not a list of
recognized plugin names. An Upsert collection may parent Upsert or Append collections;
the graph is acyclic and cascades walk it iteratively, with no fixed depth cap.
An Append collection cannot be a parent under the current envelope: its parent field
names an upsert id and has no appended-sequence selector. A future capability needing
that addressing must evolve its owner contract explicitly. Raw plugin host records
remain opaque and independently scoped; this history declaration is a core-internal
port target, not an unversioned extension of `PlaneTail`.

The full sorted owner graph (collection mode, parent and retention) has an immutable
versioned descriptor. Create it in the same candidate as the first data mutation;
guard subsequent operations against it. A changed or omitted relationship refuses
until an explicit owner migration, preventing a reload from omitting children during
deletion. Per-identity life records survive deletion and advance on retirement and
recreation; child operations compare the parent's life, and parent cascades compare
every enumerated child generation. Metadata and raw guarded payloads publish together.
An exact append replay or empty purge validates its observations with one coherent
READ, rather than adding a fake mutation or passing an invalid empty COMMIT.

Single-use claims likewise belong to core. Preserve the existing inclusive expiry
boundary with an exclusive native guard at `expiry + 1` (unbounded for `u64::MAX`).
Replacing an expired claim compares its exact previous value and uses a native lower
time bound after the old expiry, so a clock rewind cannot reopen a still-live claim.
An uncertain attempt carries its original expiry and identity through exact replay;
an expiry failure following uncertainty is reconciliation, never a false no-effect
answer. The owning authentication/ticket service retains its policy and caller grant.

### 4.1 Typed-operation ownership

This mapping covers the current typed Store method families. P00 checks it against
the exact execution SHA; newly added methods must be assigned before porting.

| Current operation family | New host owner / prepared records |
|---|---|
| Key put/get/list/since/delete | Governance identity: key object, tombstone, revision cursor, owner indexes |
| Credential put/list/since/revoke/rewrap; key+credential | Governance identity: owner predicates, two-slot uniqueness, public-id index, confidential envelope, revision |
| Usage get/put/add/batch/correction | Governance ledger: checked ordered arithmetic, bucket records, logical receipts and correction evidence |
| Metering add/batch/list | Governance ledger: attributed counters, price/group-at-use identity and receipt; preserve batch order |
| Audit append/list/tail | Audit recipe owner validates chain/preimage; shared persistence compares sequence/head and appends opaque evidence |
| Denylist add/list | Governance identity: revocation facts and existing hydration/revision publication |
| Plane upsert/get/append/list/parents/delete/purge | Kernel host records/chains: declared relationship/retention metadata and opaque payloads |
| Token redeem/live | Owning host service: single-use/disposition policy translated to time-guarded read/conditional commit |
| Raw record put/get/list/delete/conditional | Scoped host-record service: authority, namespacing, bounds; persistence supplies mechanics |
| Config, price, node/keyset journal and recovery | Their existing host owners: shared object/commit/recovery mechanics, original evidence codecs |

Optional `supports_*` checks and loader `StoreFacts::{exact_counts,usage_correction,
credential_rewrap}` disappear when their corresponding behavior is core-owned.
An adapter never inspects these record families to decide how to write them.

## 5. Neutral Store contract (`v4` staging name; ABI 3)

### 5.1 Mandatory operations

Retain lifecycle/open/close/cancel/release mechanisms. Define dedicated v4 storage
slots rather than encoding business mutations in a `RECORD_GET` extension:

1. `READ`: bounded list of exact addresses, coherent within one call, with optional
   authoritative-time interval guard and returned observation time.
2. `SCAN`: namespace + raw prefix + exclusive key cursor + item/byte bounds.
3. `COMMIT`: immutable conditional candidate with all mutations and receipt.
4. `CLOCK`: declared authoritative wall-clock observation; used for existing
   expiry semantics, not for ordering operations or assigning identities.

Capabilities at open describe format, instance identity, physical durability/failure
model, clock authority, atomic domain and bounds. All four operations are mandatory;
missing support refuses opening. A successful open does not prove the database's
deployment configuration; the adapter verifies required settings and reports facts.

`COMMIT` fields: encoding version, dataset identity, writer epoch, execution epoch, operation id,
predicates, mutations, optional wall-time interval, bounded result receipt bytes.
Predicates are absence or exact expected bytes at an address. Mutations are explicit
Put/Delete/DeleteRange (raw prefix and exact key length), preserving v3 semantics.
An empty value is never overloaded as deletion in new wire shapes. Put may retain
the existing nonempty record constraint; callers use explicit deletion.

The adapter evaluates predicates against one pre-mutation state, validates the
writer epoch and requested time bounds in the same transaction, and applies all
mutations plus the receipt as one atomic operation. All writers of this dataset use
this contract. Reading a predicate then doing an unconditional write is forbidden.
Snapshot isolation without read-dependency protection is insufficient.

Use `(namespace, key)` as the logical address. Namespace is a core-assigned opaque
identifier; keys are byte strings. Namespace-generation observations are exposed as
reserved generic metadata addresses, so final scan guards use ordinary exact-byte
predicates. Only core can construct control addresses. Backends may specialize their
physical representation of this storage metadata but never interpret domain records.

Duplicate predicate addresses and overlapping mutation selectors refuse before
execution. A predicate may refer to an address mutated by that candidate: it observes
the old state. Exact bytes alone do not prevent ABA; core-owned objects carry a
monotonic revision and never-reused incarnation in their compared encoding.

### 5.2 Bounds and consistency

Keep `MAX_RECORD_BYTES = 512` at the existing plugin host-record boundary. Keep the
existing 16-MiB limit on that conditional extension. Neither is a universal storage
value limit: typed credentials, plane bodies and atomic metering/usage batches use
different carriers today. Introduce separately named storage dimensions in v4.

Use counted C spans for v4 predicate/mutation arrays and owned Rust candidates,
with fixed header fields separate from payload accounting. Preserve the existing
`HostCap`/`MAX_BYTES` byte dimensions; do not impose the conditional extension's
16-MiB ceiling on the sum of a formerly variable-length typed batch. Validate each
span and the checked sum against the host's actual memory/admission budget. A raw
conditional candidate legal at exactly its old ceiling must remain expressible:
the core namespace, epochs and receipt framing do not subtract from that allowance.
Resource admission may refuse safely as today; a new lower protocol limit may not
be disguised as overload. P01 must supply translation-size witnesses for raw and
typed entry points before freezing layouts, including core-added index operations.

Do not introduce an arbitrary 100-item cap or
split a current legal transaction because a proposed future database has that cap.
Validate lengths/counts with checked arithmetic before allocation or pointer access.
Resource exhaustion produces a bounded failure; it never authorizes partial success.

Reads used for decisions are authoritative, not arbitrary replica reads. A scan
page is coherent, binary-key ordered, exclusive-cursor based and byte bounded.
Each page returns an explicit continuation or exhausted marker. Multiple pages are
NOT implicitly a database snapshot. The adapter maintains an opaque namespace
generation, updated atomically by every mutation/GC affecting that namespace; a
continued scan checks the generation and returns `StaleScan` if it changed.
Decision-making scans additionally carry the observed generation into the final
commit predicate. If it changed, restart planning within the work budget. This
generation is storage metadata, not interpretation of a plugin record. Display
scans may explicitly allow change between pages.
Administrative export/migration uses a writer-fenced snapshot, not a best-effort scan.

Core assigns namespaces by owner/collection and the existing logical partition
(for example metering bucket), not one namespace for the entire dataset. A global
listing traverses a core-owned partition index; it does not discover partitions by
guessing raw backend keys. Do not add a single global generation lock to every
accounting write. Cross-partition commits remain atomic within the admitted dataset.
Where a coherent multi-partition decision is needed, read and compare every involved
partition generation in that commit; otherwise advertise the listing as non-snapshot.

The canonical assignment uses `kernel::persistence::partition::namespace`: SHA-256
over `busbar.persistence.partition/1\0`, the 16-byte owner family, a big-endian u64
component count and length-framed components. Take its first 16 bytes and set the
high bit of byte zero, making derived namespaces disjoint from ASCII reserved
namespaces. Full owner/partition identity remains in keys or validated metadata;
a hash collision may add contention, never overwrite a different logical record.
Opaque host keys are `framed('R', [base_owner16, schema]) || old_instance_scoped_key`;
their logical-receipt keys are `framed('R', [receipt_owner16, full_op_id16])`.
Accounting U/M/R keys likewise retain their complete owner family before existing
logical components; namespace derivation never replaces the full identity check.
Usage partitions by window, metering by bucket, and opaque host records by authorized
schema plus the exact existing instance prefix. Host-private records use a different
owner family. Logical receipts partition by the original `OpId` node bytes, retaining
the complete node/counter in their keys. Do not allocate one namespace per receipt.
Global accounting pruning enumerates a core-owned per-family partition index. Create
an index entry atomically with its first data write; ordinary writes do not mutate
the index. Retain empty entries until a proven partition-retirement protocol exists,
so deletion cannot introduce an index/creation race. A complete prune compares the
index generation and every selected partition generation in its atomic commit.

Missing records are distinct from malformed records, unavailable reads and unknown
outcomes. Never return an empty credential set or zero ledger on read failure.

DeleteRange remains one atomic logical operation; paging its visible effects is
forbidden. Backend execution may be expensive and must have bounded cancellation
and truthful outcome handling. New core collection deletion should use generation
retirement where equivalent; adapters must still honor existing raw range semantics.

### 5.3 Outcomes and replay

| Outcome | Meaning | Core action |
|---|---|---|
| Applied | Effects and matching receipt committed; exact replay returns the original result | Publish effects/cache change once |
| ConditionConflict | Candidate did not apply | Re-read and replan the same logical operation under a new attempt id |
| TimeGuardFailed | This execution did not apply; serialization time fell outside its allowed interval | Apply the owning domain's expiry rule; preserve any earlier uncertainty |
| Refused | Definitive no-effect rejection | Surface typed reason; no automatic semantic downgrade |
| OpIdConflict | This id is already bound to another candidate | Stop, preserve evidence; never remint to hide it |
| Unknown | Commit may have happened | Retain exact bytes/id; resolve by exact replay/receipt before any replan |
| ExpiredUnknown | Receipt absent and execution authority retired; an earlier application cannot be excluded | Reconcile retained logical evidence; never execute this candidate as new |
| Pending/Overloaded | Host transport/admission state, not a commit verdict | Preserve ownership; use deadline/backpressure policy |

The outcome applies to an attempt, not automatically to its entire history. A
refusal/conflict after an earlier unknown cannot establish that the earlier send
did not apply. Replan only after proving that no send of that candidate applied.

Distinguish the logical operation id and intent digest from transaction-attempt ids.
For accounting, the logical receipt is a normal core record containing intent digest
and result; its absence predicate and creation are atomic with the ledger update.
This prevents recovery from applying a logical delta twice even if planning changes.
The backend transport receipt binds exact candidate bytes and original response.
Do not use a short-lived RPC receipt as the sole accounting history.

Persisting recovery custody is not recursively journaled. A custody write is itself
one immutable idempotent candidate, retained by its current owner until confirmed;
its caller receives durable acceptance only after that confirmation. Business writes
then refer to the persisted custody record. Losing the process before confirmation
cannot be reported as a durable accepted operation. Preserve existing domain handling
for work admitted before a flush. Receipt results contain outcomes/references, not
plaintext credential responses; any necessary sensitive recovery payload uses the
existing protected custody format, with one-time delivery rules retained.

Prepared candidates include all observed bytes, time bounds, result and identity.
Once submitted, they are immutable. Persist necessary recovery custody through the
existing Store-backed recovery mechanism BEFORE acknowledging durable acceptance.
If custody itself has unknown outcome, resolve its idempotent write; do not assume
it exists. Memory-only acceptance must be labelled accordingly and never reported
as crash-durable. Cancellation/reload relinquishes a waiter, not the owned operation.

Preserve at least the current 24-hour transport receipt horizon. Record first-send
time, not last retry time. A timer alone cannot make receipt deletion safe: a queued
backend command can arrive after its sender stopped retrying. Each writer therefore
has registered execution epochs, distinct from the dataset writer epoch. The core
opens/closes them through conditional commits to reserved generic control records;
every data commit checks that its execution epoch is open atomically with execution.
Close/fence an epoch durably before collecting any of its receipts, and retain
receipts for the required horizon as well. Keep a durable retired-epoch floor; never
reuse a writer identity or reopen a retired epoch. Administrative control commits
use the same receipt/fence rules; the final active epoch is retained until an explicit
cold transition, not garbage-collected recursively.

Decision order is: matching receipt → original result; conflicting receipt →
`OpIdConflict`; absent receipt with closed/unknown epoch → `ExpiredUnknown`; otherwise
check writer epoch, temporal guard and predicates, then commit. Check receipts BEFORE
time/epoch expiry so committed results remain reconcilable. Retirement never grants
fresh replay authority. After the horizon retain unresolved debt and reconcile;
`root/durability/conditional::decide`'s unbounded replay loop must not survive extraction.
Logical receipt GC likewise requires a durable low-watermark and rejection of older
identities. TTL alone is insufficient for either receipt class.

### 5.3.1 Execution-fence encoding used by the implementation

`contract::persistence::control` defines the shared generic framing; adapters do
not independently invent it. Reserved namespace `busbar.fence.v1\0` holds dataset
key `d` and writer key `w || writer_id[16]`. The dataset value binds the physical
dataset identity and writer epoch. A writer value holds an irreversible retired
floor and admitted ceiling: only `retired < execution_epoch <= admitted` may execute
without an existing receipt. Unknown keys/versions, deletion/range deletion of
control records, and backwards replacement are refused. Malformed stored control
state is corruption, never an absent grant. Normal replacements include an exact
or absent predicate and are evaluated with the native commit lock/transaction.

A fresh canonical dataset admits exactly one initialization shape: two absent
predicates and two puts for its epoch-1 dataset root and epoch-1 initial writer,
with no unrelated effects, result payload or time guard. This is legal only when
the adapter proves the complete canonical records AND receipts are empty under
that same atomic guard. An absent root in existing/legacy/interrupted state is not
fresh. This bootstrap exception does not permit restoring or reusing an old writer
identity. Core prevents retiring the execution epoch performing the retirement;
it opens a successor first and retires earlier work from the successor.

Reserved namespace `busbar.scan.v1\0\0` holds adapter-maintained namespace generation
records, keyed by the exact 16-byte namespace ID. Absent means generation zero;
a present value is a nonzero little-endian u64. Each applied candidate advances
each mutated namespace exactly once, atomically with its effects and receipt.
Overflow refuses before mutation. Core may predicate/read these values but cannot
write them directly. A guarded scan can therefore supply an ordinary exact-byte
(or absent-at-zero) predicate for a subsequent commit. Replay does not advance
generations again.

### 5.4 Time, identity and fencing

Core owns expiry policy; the Store supplies generic clock/transaction-time evaluation.
The optional interval defines lower-inclusive/upper-exclusive UTC bounds. Evaluate it
at the same serialization point as the read or commit, not in a preceding RPC. Core
chooses the interval to preserve the operation's existing exact-boundary behavior.
Return `TimeGuardFailed` with the authoritative observation without applying effects;
this does not resolve an earlier unknown. Receipt replay precedes this guard.
Do not substitute client timestamps for the existing Store clock on tickets/replay.
Clock observations carry authority identity; monotonic local time is used only for
elapsed deadlines. A clock discontinuity must not resurrect a consumed credential
or operation. Expiration cleanup is not authorization. Existing comparisons at the
exact expiry boundary must be retained by the core rule.

Dataset identity and writer epoch are checked inside every commit, including delayed
requests. Epoch increments are irreversible within the dataset. Process death,
lease timeout and an empty host queue do not establish backend quiescence.
Only new writers enforce new epochs; old writers require actual backend-native fencing at cutover, acquired automatically by §10.4's lifecycle session.
Retirement acknowledgment must wait for every earlier admitted writer that could
still commit under the retired authority. SQL adapters hold shared locks on both
the dataset root and writer-control row through native commit; retirement and epoch
updates require conflicting exclusive locks. PostgreSQL uses `FOR SHARE`, not
`FOR KEY SHARE` (which permits non-key updates). Snapshot/serializable isolation
alone does not establish this barrier. Ordinary writers share these locks rather
than serializing all traffic on an exclusive dataset lock. Observe retirement for
receipt collection only after durable commit; uncommitted floors are not age proof.
Native lock acquisition may precede receipt lookup; semantic authority rejection
must not. MySQL acquires root then sorted writer-locator locks before the receipt
query, deferring control-content checks until after replay. Otherwise an absent
receipt gap lock held by retirement can deadlock with an earlier admitted writer
that needs to insert its receipt before releasing its shared authority lock.
PostgreSQL uses transaction-scoped shared/exclusive namespace admission locks and
fresh READ COMMITTED statements after admission. An earlier MVCC snapshot followed
by a later clock query cannot establish a time-bearing current observation. Locks
cover read predicates, mutated namespaces and their generation records until commit;
the global gate is shared during ordinary work and exclusive only for initialization
or a scan across all generation records. Namespace hash collisions add contention,
never authority. See PostgreSQL's [snapshot semantics](https://www.postgresql.org/docs/18/transaction-iso.html)
and [transaction advisory locks](https://www.postgresql.org/docs/current/explicit-locking.html).
Operation ids are allocated independently of wall time and names; never reuse node
identity/counters after restore. Keep stable persistent instance ids separate from
display labels, runtime incarnation and plugin package identity. Initial migration
maps current label-based prefixes exactly; a rename is an explicit namespace move,
not an empty fresh store.

## 6. Canonical records, large objects and indexes

Do not force typed host objects through the plane's 512-byte `RecordBytes`. Small
host objects use bounded inline values under the storage carrier's separate limit.
Large non-secret config/journal objects use one shared representation:

- A compact manifest contains object version, immutable generation id, total length,
  chunk count and digest. It fits one raw record.
- Use 64-KiB chunks (last may be shorter), independently bounded from plane records.
  Chunks use binary addresses framed by dataset/owner/object/generation/index. Their
  bytes are opaque; sensitive buffers retain zeroizing ownership and redacted Debug.
- Write bounded immutable chunks first. Verify their presence/digest before publishing
  a manifest. A crash before publication leaves unreachable chunks, not partial state.
- Atomically compare and replace the manifest plus affected indexes/receipts. Readers
  read the manifest, fetch immutable chunks and verify the digest. A missing chunk is
  corruption/unavailable, never an empty object.
- GC cannot delete a generation pinned by an active reader or unresolved prepared
  commit. Use persistent retirement epochs and explicit reader/operation liveness;
  a crash does not prove all readers stopped. For the initial implementation, retain
  retired generations until a cold, fenced maintenance sweep. Do not invent unsafe
  online GC to save space. Preserve existing hard quotas and backpressure.

The representation is host-owned,
versioned and independent of SQL columns. Retain public JSON and signed byte semantics
at API boundaries; do not change audit preimages during canonicalization.

Identity indexes: live credential slot `(key,kind,slot)`, public identifier,
credential-by-key, and revision cursor. Ownership predicates and index changes commit
with the identity object. Revocation and rewrap both compare the owner and credential;
rewrap cannot restore a revoked credential. Key tombstoning preserves attribution.
Credentials are an explicit exception to immutable-generation retention: keep their
secret envelope in a dedicated confidential inline record, metadata in a separate
record, and update both under one conditional commit. Revocation replaces the live
secret value with an empty-secret tombstone in the SAME commit as revocation/index/
revision updates; rewrap replaces that value at the same address. Do not leave a
reachable or GC-deferred old secret object behind. Confidential retired in-memory
values and temporary candidates are wiped when custody ends. Receipts store a digest
and original result, not a duplicate secret-bearing candidate; recovery custody
remains protected under existing at-rest rules. Cold-GC deferral applies only to
non-secret immutable objects. Database WALs/backups still have the database's existing
retention behavior; overwriting a live record is not a claim of physical erasure.
Preserve legacy envelopes and AAD binding of id/key_id/kind/public_id in the current
at-rest owner; do not add a second encryption scheme to solve layout problems.

Accounting indexes: bucket/window and complete metering attribution (including price
version and group-at-use). Retain i128 scale-six quantities and independent whole
request counters. Use existing checked math, including existing refund/floor rules.
Do not implement money arithmetic in SQL/Lua. Batch/coalesce as today to avoid one
read round trip per counter; contention retries are bounded and retain debt on exhaustion.
Core identity revision uses one transactional revision record per existing revision
domain; do not replace ordering with clocks or random ids. Do not put all metering
updates behind this identity revision record.

Collections/chains: shared indexes encode parent, sequence, disposition and timestamp
as declared metadata, not decoded protocol payload. A generation/parent guard prevents
a child append racing a parent deletion. An append with a different value at an
occupied sequence remains a fork refusal. The core consumes existing plane declarations
and generic conditional actions; no task/ticket magic names in adapters.

### 6.1 Canonical identity layout implemented for P04

The core identity owner uses the sixteen-byte namespace `busbar.identity1` and
confidential namespace `busbar.secret.v1`. Keys start with a family byte followed
by components framed as u32 big-endian length plus exact bytes. Numeric revision
components are eight-byte big-endian values. No plane key/value bound applies here.

| Family | Components | Value |
|---|---|---|
| `K` | key id | Version-1 metadata envelope containing `VirtualKey` |
| `C` | credential id | Version-1 metadata envelope containing `CredentialMeta` |
| confidential `C` | credential id | Exact existing at-rest envelope bytes; empty after revocation |
| `S` | key id, kind, one-byte slot | Version-1 index pointing to current credential id |
| `P` | kind, public id | Version-1 index pointing to current credential id |
| `R` | `K` or `C`, revision, object id | Version-1 index pointing to that object's latest revision |
| `V` | none | Version byte 1 followed by u64 big-endian identity revision |
| `D` | denied subject | Version-1 denylist metadata |

Metadata envelopes are `{version:1, record:...}` with strict known fields, preserving
the existing dynamically declared scope fields. JSON whitespace/member ordering is
not a format version. Unknown semantic fields/versions refuse writes. Every identity
mutation predicates on the exact previous `V`; every read wave and collected scan
validates the same revision. This revision does not serialize accounting.

Slot replacement retains the old credential's non-secret revoked metadata and its
revision index. This ensures incremental hydration still sees its revocation after
the slot has been reused. Only slot/public indexes identify current occupants; a
replaced credential's former public handle is freed. Revoked credential ids and
tombstoned key ids cannot be reissued. Confidential material is emptied in the same
commit as revocation, never retained as an immutable old generation.

An initial ordered seek is admitted without a prior generation; the first returned
page establishes that generation and all continuation pages require it. Page limits
bound each crossing, not the total number of keys or credentials. Core shares this
guarded pagination implementation across identity and ledger owners.

## 7. Cross-kind effects and security

| Kind / core service | Owns | Host interaction after change |
|---|---|---|
| Plane | Protocol parse/encode, domain interpretation, declared effects and measurements | Host validates caller, scopes resources, commits effects and returns generic outcomes |
| Auth | Authentication mechanism and evidence extraction | Core resolves principal/credential lifecycle and supplies scoped custody handles; no Store access |
| Secret | Provider lookup and provider-specific response path | Existing credential SDK/chip protects import and handoff; no arbitrary persistence capability |
| Store | Native persistence and transaction mechanics | Opaque canonical records; no other plugin identities or semantics |
| Transport | Carrier/framing and declared capabilities | Core connector applies security/policy and composes compatible transport capabilities |
| Hook | Its declared transformation/ranking algorithm | Core owns invocation policy, input projection, budget, output validation and authority |
| Export | Its format/sink protocol | Core provides declared event projection and approved I/O; export failure cannot mutate accounting |
| Admin/OAuth core surfaces | Management/authorization-server protocol | Call kernel services; never raw backend slots |

### 7.1 Required ownership correction for every kind

The following are execution obligations, not a claim that every listed violation
exists in every implementation. Retain an existing correct boundary; remove an
incorrect one at its shared owner. Do not add layers merely to make the rows look
uniform.

| Kind | Core responsibility that plugins must not independently own | Implementation that remains in the plugin |
|---|---|---|
| Plane | Admission, authorization, routing/failover policy, budgets, charging, persistence coordination and shared retention execution | Protocol decoding/encoding, protocol state interpretation and declared effects/measurements |
| Auth | Authentication-chain orchestration, principal resolution, authorization, credential lifecycle and shared replay/custody services | Mechanism-specific verification, provider exchange, claim/evidence extraction and mapping into the kind contract |
| Secret | Secret-reference resolution, custody, access grants, shared refresh/cache lifecycle and protected handoff | Provider lookup, provider path/status interpretation and guarded extraction into the host custody API |
| Store | Domain rules, logical records, accounting/credential transformations, logical migrations and recovery coordination | Native I/O, physical schema, atomic execution, time guards and truthful durability/outcome reporting |
| Transport | Connection policy, destination/TLS enforcement, resource admission, cancellation and composition | Carrier framing, protocol handshakes/state and byte/datagram adaptation using host I/O |
| Hook | Invocation ordering, applicability, authority, limits and application of validated results | The selected scoring/filtering/transformation algorithm within its declared contract |
| Export | Event selection/redaction, access grants, shared scheduling/backpressure and delivery policy | Sink encoding and protocol exchange; reporting delivery results without changing the source event or accounting |

Provider/protocol rules can constrain a shared mechanism. For example, a provider's
expiry or callback binding is an input to refresh/replay coordination; it must not be
lost while consolidating that coordination. Core represents neutral requirements
through kind contracts, rather than recognizing provider names. A plugin's local
protocol state machine is distinct from ownership of the host lifecycle. Likewise,
export retry policy belongs to core while a protocol's own acknowledgement sequence
belongs to its adapter. Preserve those distinctions during implementation.

Adding an implementation of an existing kind requires its plugin and ordinary
registration/configuration changes. It must not require a behavior branch naming
that implementation in core or edits to another kind's implementations. A genuinely
new capability evolves the versioned kind contract and shared core owner explicitly.

Universal composition means satisfying the same kind contracts, not pretending a
datagram-only carrier is a byte stream or arbitrary old ABI binaries are compatible.
Composition uses declared capability requirements, never pairs of package names.
No business capability flags such as `supports_credentials` remain on Store v4.

Host services bind authority to a loader-created caller instance/incarnation; a plugin
cannot supply its own identity. Keep quota accounting, reserved host namespaces,
credential leases, cancellation cleanup, destination guards, DNS-rebinding checks,
TLS/server-name validation and shutdown ownership in the host path. The generic
commit path must not let a plane write identity, price, receipt or migration records.
Signing/secret material does not become a general serializable `Value` for convenience.

The in-process credential chip is a custody API, not hardware isolation against
arbitrary malicious native code. Signed native plugins share a process; this redesign
does not claim a sandbox or HSM security boundary it has not implemented.

Keep ordinary hot-path admission free of synchronous Store round trips. Durable
configuration/price/security mutations publish only after confirmed persistence.
Local request accounting can retain its existing write-behind admission contract;
do not silently advertise global serializable quotas merely because storage is now
serializable. Global quotas need explicit allocation/coordination and a separately
defined latency/availability contract. This redesign preserves current behavior.

Revocation cache freshness is also a separate contract: preserve the current
revision/refresh mechanism and fail-closed paths. Do not call an asynchronously
refreshed fleet instantaneously revoked. A stronger fleet-wide acknowledgement
barrier would require an explicit API/latency change, not an adapter refactor.

## 8. Bootstrap, reload and dependency cycles

Boot order is explicit:

1. Read operator configuration and admitted artifact/trust inputs; normalize supported
   old configuration in memory through §10.4 before current-format parsing/bootstrap.
2. Build host connector and resolve declared bootstrap secrets without Store recursion.
3. Prepare the selected Store's native lifecycle session; identify dataset/physical
   format before ordinary OPEN and without mutating an unknown/newer format.
4. Automatically migrate/resume supported old config and data under §10.4's retained
   startup coordinator and native fence, verify and activate. Unsupported/newer formats
   refuse; pending work keeps serving closed while automatic recovery advances.
5. Construct `CoreStore`; recover uncertain operations; load node identity/keyset,
   price provenance, policy and identity state in dependency order.
6. Open other instances and attach scoped host services. Hydrate before routing work.
7. Publish the complete runtime generation; open admissions.

Detect and reject bootstrap cycles such as Store credentials depending on state held
only in that unopened Store. Do not resolve them with plaintext defaults or disk
fallback. Recovery uses operator-supplied trust/key material where the current code
requires it. A trust floor stored in a Store cannot authorize loading that same Store;
preserve the base-config archive-pin/bootstrap exception already implemented.

Reload constructs a new generation while old operations retain their original
instance and candidate ownership. New settings cannot retarget an in-flight commit
to another database. Change of Store dataset is an explicit migration, not hot reload.
Close waits for or transfers owned operations and reports unresolved debt; it never
silently frees a live ABI lease or treats timeout as rollback.

### 8.1 Initial logical-format admission

`kernel::persistence::startup::Startup` is the retained storage-admission owner,
not a serving-runtime readiness signal. Its `advance` method performs bounded
steps and keeps each exact control attempt across cancellation and unknown replies.
The active manifest occupies `busbar.format1\0\0` / `active`. Its strict 80-byte
`BSCFMT1\0` frame contains descriptor/logical/required-reader/required-writer version
1, dataset identity, dataset writer epoch, registrar writer identity/execution epoch,
and zero reserved flags. Unknown framing, versions or required flags refuse before
registration. This is independent of product SemVer and backend physical versions.

Explicit empty initialization first uses the adapter's whole-dataset empty proof
and exact two-record fence bootstrap, then publishes the manifest conditionally.
A preexisting root without a manifest is incomplete initialization requiring explicit
recovery; normal boot never overwrites it or invents a current format. Losing the
process between these steps does not authorize serving or report durable acceptance.
The initial bootstrap writer becomes a control-only registrar. Each process registers
a fresh random business writer at execution epoch 1, conditional on the exact active
manifest and authority. Process restart never reuses a business writer identity.
The registrar's final active epoch/receipts remain until an explicit cold authority
transition, as required by §5.3; it is not handed to business services as a CoreStore.
Raw `CoreStore::attach` is crate-private. Public construction goes through Startup's
format gate; the loader exposes only `PersistenceAxis` and an opaque opened backend.

Before clean retirement, stop local admission and resolve or transfer all retained
work. The registrar then closes that business writer through one retained conditional
candidate. Only its Applied receipt proves retirement. This does not replace durable
domain recovery, orphan-writer reconciliation, migration fencing, or the external
rollback witness required for restoring snapshots. Those must complete before P09.

Live execution-epoch rollover retains the same shared CoreStore and backend. The
registrar first grants the next execution epoch; only its Applied receipt promotes
local admission. Existing uncertain operations keep their original epoch and remain
owned by their domain. They block retirement of that epoch while new work may use
the next one. Once old work drains, a separate retained registrar attempt advances
the retired floor. Startup reports draining separately from an unknown control
attempt and never retries business work on a domain owner's behalf. Exhausted
epoch or identity counters refuse; they never wrap into reused identities.

## 9. Versioning across many future releases

Keep these versions independent:

| Version | Meaning |
|---|---|
| Product SemVer | Distribution/API release identity |
| Kind ABI major + layout fingerprint | Native calling convention and shape compatibility |
| Host service version/capabilities | Services a plugin requires and the host provides |
| Dataset logical version | Core record layout and behavioral reader/writer requirements |
| Backend physical version | Tables, key layout, indexes and adapter storage implementation |
| Per-object schema version | Owner's encoding of a record family |
| Crypto/audit recipe | Signed/encrypted byte interpretation, independently retained |
| Writer epoch | Which writers may mutate this dataset now |
| Execution epoch / retired floor | Which operation identities may still execute for the first time |

No inference from `1.6.0` to any other version. Native plugins negotiate and validate
kind ABI before invoking slots. Required unknown semantics refuse load; optional
metadata may be ignored only when specified as ignorable. Unknown state that a writer
cannot preserve causes write refusal; never parse/serialize away unknown fields.

The implementation uses neutral Store ABI **3** for the unreleased 1.6.0 doors; `v4`
in staged Rust module/task names describes the redesign, not a shipped ABI major.
Keep the actual slot table, validators, SDK and fingerprint consistent in one
contract change. No shared mechanism-major bump is implied solely by that.
Shared `HostSlots` disk/snapshot entries must retain their offsets when unused WAL
runtime paths are removed: reserve/null them under the existing contract. Shifting
them would require a separately coordinated mechanism change across every kind.

The first redesign supports one active writer format and a non-serving startup cutover. Future
rolling upgrades require a released compatibility descriptor listing reader range,
writer range, preserved unknown fields, and rollback rules. Expand/read-old/write-old
may precede a format cutover; contract/remove-old happens only after all readers and
unresolved operations no longer require the old format. Version overlap is an
explicit tested range, not an assumption that adjacent releases interoperate.

Register directed migration edges with stable id, source/destination format, code
digest, preconditions, resource bounds and verification rule. Freeze an edge once
released. Fixes get a new edge or reconciliation migration, never silently change the
meaning of an existing checkpoint. A migration planner chooses one explicit supported
path; it does not guess intermediate versions from semver. Missing edge means refuse
with the exact unsupported format/capability. Each binary includes the automatic
composed route for every supported source; do not promise every historical version
forever. Retain qualified edges and immutable fixtures with published checksums.

## 10. Migration: 1.5.5, current dev and future datasets

### 10.1 Real source evidence

Use published release binaries/fixtures and exact metadata, not a repository commit
selected by date. Four durable backend fixture manifests contain real 1.5.5 provenance:
SQLite/PostgreSQL/MySQL plugin release v1.0.6 and Valkey v1.0.7. Their source schemas
are respectively 6, 6, 3 and 6. The existing fixtures are incomplete workload coverage:
they include usage and key/audit examples but empty credentials/denylist. Missing
credential, revocation, historical journal and large-record cases need fixtures from
actual supported source writers. Do not invent an A2A legacy format that did not ship
in the selected release manifest.

Treat existing 1.6 dev datasets separately; they may contain later schemas, generic
record/chain namespaces and uncertain recovery operations absent from 1.5.5. Detect
actual physical and logical versions, not the running product version alone.

The existing durable fixtures have two keys, two key-create audit rows, five successful
requests and one failure; their manifests and recorded payload hashes were checked
during this review, not regenerated with old binaries. Current physical schema heads
are SQLite 9, PostgreSQL 9, MySQL 7 and Valkey 9 at the reviewed revisions. Those numbers
do not establish a core logical schema. Capture repository SHAs with the fixture
inventory at P00 and revalidate on drift.

1.5.5's additive write-behind explicitly permits at-least-once delivery. Preserve the
observed source totals; do not claim migration can reconstruct lost volatile work or
deduplicate an old lost-ACK retry without evidence. Record absent provenance as absent,
not fabricated price/group history or a newly invented exactly-once receipt.

Historical import code may understand named old implementations. That is allowed in
the explicit import boundary; runtime core never branches on those names. Backends
decode their physical rows into neutral versioned legacy records. Core transforms
shared meanings once. Plugin-owned record migrations run through a bounded migration
entry and scoped host API, not by teaching Stores the plugin's schema.

For this initial cutover, copy plugin-owned payload bytes and schema identifiers
unchanged; preserve the scoped namespace mapping. No plugin data transformation is
needed merely to remove business methods from the Store ABI. The existing optional
`Door::migrate` concerns configuration, not stored records, and must not be repurposed.
If a plugin payload format actually changes, require an explicitly registered,
versioned migration edge from that owner before admitting its new writer. Its bounded
input/output is `(source schema id, opaque rows, checkpoint)` →
`(destination schema id, opaque rows, next checkpoint)`; core performs writes/checkpointing through the same
coordinator and confines access to that owner's namespace. Freeze the artifact digest
and reject undeclared output/side effects. A future native migration entry needs its
own negotiated ABI extension; do not silently add it to an unchanged host table.
Missing transformation support blocks that upgrade; it never authorizes the Store
to decode the plane or core to contain a copied plugin protocol implementation.

### 10.2 Mandatory migration state machine

```text
Identified → Planned → SourceFenced → SnapshotVerified
           → Copying → TargetVerified → Activated → Retired
                         ↘ Failed (source retained; resume or explicit recovery)
```

Migration manifest contains migration id, source/target dataset ids, source release
and schema evidence, physical/logical versions, artifact/transform digests, writer
fence evidence, source snapshot identifier, per-family checkpoint/count/digest,
operation-receipt treatment, signing/key identifiers (never secrets), and state.
Bind checkpoints to both source identity and transformation digest. Checkpoint and
corresponding target writes commit together. Copying the same page twice is idempotent.
An unknown checkpoint/cutover retains the current state and exact pending candidate;
it is not converted to `Failed` and restarted under a new id. The Store manifest is
the durable authority; ordinary startup creates/resumes it automatically. A diagnostic
report is not a competing mutable authority and contains no secret material.

The coordinator is bounded: pages by items and bytes, no database-sized collections,
finite per-attempt work, explicit retry custody. Planning is read-only. Do not execute
arbitrary SQL supplied by a manifest or load untrusted migration code with elevated
host authority.

Legacy identification/read mode must bypass normal old `open`/`migrate` paths that
can change schemas or scrub rows. Refuse before any source mutation on unknown input.
Current-dev uncertain operations retain original candidate bytes, codec version,
digest domain, first-send time and recorded result. Never re-encode an uncertain old
candidate as a fresh v4 transaction. Resolve under the original frozen semantics
while natively fenced, or import it as unresolved debt that blocks affected writes.
Migration does not extend its replay authority. Historical audit conversion verifies
every source sequence and chain; a target's highest sequence alone cannot prove that
all earlier rows were imported.

**Actual old-write fencing is mandatory and automatic for the initial crossing.**
The backend's §10.4 lifecycle session establishes persistent native enforcement and
drains prior commands/transactions before capture. The normal supported upgrade
requires no manual attestation, helper invocation or administrator-run account change.
Observe/wait/refuse an
unsupported active old fleet rather than interpreting a marker or advisory lock as
a fence. The actual released SQLite/PostgreSQL/MySQL/Valkey behavior in §10.4 shows
why higher version stamps alone cannot prevent an old writer from continuing.

Write into a distinct target namespace/generation; retain the source read-only.
Verify all families before activation: exact counts/scale, identity uniqueness and
tombstones, credential envelopes, indexes, historical audit chains, rate provenance,
chain heads, generic plugin records, operation receipts and unresolved debt. A digest
of transformed records alone does not prove semantic equivalence; compare decoded
invariants and source coverage/counts too.

Unreadable or unsupported source is an error, not an empty opening balance. Conversion
must reject overflow and unknown scales without partial progress becoming active.
Preserve original signed evidence and ciphertext; re-encryption is a separate explicit
operation through the custody owner. No approximate floating-point reconciliation.

Activation is one conditional update of the core dataset manifest and writer epoch
after verification, while all old writers remain fenced. Reopen through the new
facade and hydrate before serving. Never double-write old and new business tables.
If activation response is lost, read/replay its exact operation; do not toggle paths.

Before activation, abort leaves the source intact. After target writes begin, rollback
to the old binary/database is not automatically safe: require a verified reverse edge
or restore a complete pre-cutover snapshot with explicit data-loss/reconciliation
decision. Schema downgrade, partial copy-back and reuse of old operation ids are banned.

Keep source backups until the operator's retention/verification policy permits
removal; implementation agents do not delete customer data as cleanup. All temporary
agent work is a different category and belongs under `/Users/matthew/Developer/tmp/`.

### 10.3 Restore and backend changes

Store-to-Store export/import uses the same canonical logical record stream with
dataset and snapshot identity, byte counts/digests and protected secret envelopes.
It does not copy one backend's physical schema into another. Preserve logical ids,
audit preimages and unexpired receipts; assign a new writer epoch/incarnation before
resuming. Reconcile operations that could have reached an external service; restoring
a database cannot undo external side effects. An outbox can give replayable delivery,
not universal exactly-once execution at third-party systems.

Restore must preserve security rollback floors. A snapshot containing old credentials
does not authorize re-enabling revoked identities. Reconcile against an external
trusted recovery checkpoint or refuse serving until the operator completes the
specified recovery procedure. Do not place the only rollback witness inside the
snapshot being rolled back.

### 10.4 Automatic startup upgrades in one migration library — owner correction

**Add one `busbar-migrations` library as a normal dependency of the Busbar binary.**
The owner rejected the separate-tool proposal: an operator stops the old instance,
installs the new version and runs Busbar normally. Startup detects supported old
configuration and Store formats, migrates automatically, resumes interrupted work,
validates with the actual serving owners and then serves. There is no required
migration command, archive export, private control file, helper executable or approval
step. This decision supersedes the earlier companion/default-off-feature design.

The boundary is source ownership, not exclusion from the executable: thirteen existing
core crates plus one migration library, fourteen workspace members. Kernel owns current
format admission, persistence and recovery; migrations owns historical interpretation,
upgrade planning and coordination; root composes both. Backend plugins own their native
physical formats, sessions, schema transitions and enforcement. No plugin imports
another plugin or kernel, and no Store acquires credential/accounting/plane policy.

#### Normal startup and configuration

Root runs a retained `StartupUpgrade` before ordinary Store `OPEN`/`READY`, business
writer registration or listeners:

1. Capture original configuration/provider documents and source fingerprints. Detect
   the declared configuration format independently of product version. Apply the
   existing core configuration migrators and each admitted plugin's configuration
   migration declaration to a protected in-memory document. Reuse
   `config::migrate::migrate_config_with`, catalog/overlay migration, and root's
   `MigrateHost`; do not invent replacement plugin-specific conversions. A structured
   unresolved choice, unknown version or failed validation refuses; a generic warning
   string is not permission to silently drop a setting. Pure `--validate` stays read-only.
2. Resolve bootstrap Store/Secret/Transport settings from that migrated document using
   existing host connection and secret custody. Admit the current signed Store door
   before any slot call. Plugin acquisition remains the existing configured boot
   policy; migration does not load arbitrary historical code. Authenticate a native
   **preflight session**, which inspects without invoking the old/current destructive
   schema initialization, scrubber or ordinary OPEN path.
3. If the source is current, resume ordinary opening and `RuntimeStartup`. If genuinely
   empty, perform the established empty-dataset initialization. Otherwise choose the
   compiled supported upgrade route from exact source metadata, claim/rejoin its
   durable migration, acquire the native source fence, create an inactive target
   generation and run the existing bounded coordinator. Another new process joins the
   same upgrade/status and waits for ownership; it does not invent another target.
4. Preserve originals and transform bounded source pages into the target through the
   neutral persistence primitives. Checkpoint and page effects commit together.
   Automatically reconcile retained unknown attempts before advancing; if the native
   outcome cannot yet be established, startup remains non-serving and retries/statuses
   boundedly. A restart does not require a `resume` command or mint new replay authority.
5. Verify every family, activate conditionally, independently reopen the same target
   through ordinary OPEN under the pending-upgrade recovery capability. Build and
   hydrate the actual App/CoreStore/journal book **once**, using full authored config
   and the target overlay. Validate and flush recovery work while listeners/producers
   remain closed, finish configuration publication and the migration checkpoint,
   then publish those **same live owners** into serving. Adopt them through the root
   continuation below; do not run the manual recovery command's shutdown tail, retire
   this writer, create a second App, or initialize global owners again.

The migration backend and the ordinary reopened backend are independent native opens
with checked equal dataset/atomic-domain/physical identity. That is the reopen proof;
it does not require two application boots. The migration-only writer may retire after
its exact intents settle, but the fresh ordinary Startup/CoreStore owner used for
recovery remains live and becomes the serving owner. `Retired` in the migration state
machine means its migration work/source transition is finalized, not that the adopted
serving writer has been retired.

Add root `startup_upgrade/continuation.rs` with retained `StartupContinuation` phases
`Reopening → Hydrating → Validating → Finalizing → Ready`. Its `ReadyCandidate` owns
the ordinary `Startup`/`RuntimeStartup` control, the same `Arc<CoreStore>`, `Arc<App>`,
`NodeBook`/runtime journal, installed limits, resolved configuration/overlay and retained
recovery tasks. Both current-format boot and migrated boot converge on this one
application-construction continuation. Initialize `PLUGIN_FLOOR` and `ROOT_CARD` only
on this ordinary reopened CoreStore, once. Do not bind these globals to the temporary
copy target, reset their OnceLocks, or call the app builder again after verification.

The root implementation of `TargetRecoveryProbe` delegates to that continuation and
returns a content-free readiness receipt only after validation; it retains the
candidate for adoption instead of dropping/stopping it. The receipt binds target,
upgrade id, ordinary writer identity/epoch, config fingerprints and verified recovery
heads. Once the coordinator confirms the final checkpoint, root consumes
`take_ready(completion_receipt)` exactly once and moves the candidate into the existing
serve loop. A digest alone cannot synthesize a candidate or authorize a different App.
The same writer, journal and price owners receive the first serving operation.

Readiness uses non-stopping flush/reconciliation operations, including the existing
`RuntimeJournal::flush`, and checks all required pending/refusal state. If a shared
owner currently exposes only a final shutdown drain, split its flush/check logic into
a readiness operation; keep permanent stop/retirement exclusively in shutdown.
Successful startup must never call `shutdown::tail`, `RuntimeJournal::stop_staging`,
`CardStore::stop_background`, final producer-stopping drains or `retire_storage` on
the candidate. Do not reset monotonic stopped flags to work around this. Background
producers start once after publication; recovery work before that point uses the same
retained owners without external request admission.

A timeout/cancel while hydrating, validating or finalizing retains the continuation,
exact pending futures and candidate in root custody and retries the same phase. It
does not re-enter global initialization. A process crash discards process-local
owners, and the next normal process resumes durable migration/recovery once. An
unrecoverable startup failure remains non-serving and uses real shutdown/retirement
only for disposal; that stopped candidate can never be published later.

Locked/read-only operator configuration is migrated in memory on every start without
rewriting the file or bypassing its lock; this is sufficient for the ordinary upgrade
path. Preserve authored secret references rather than writing interpolated secrets.
For writable documents, persist the validated mechanical conversion automatically only
after target validation. Compare original fingerprints immediately before each write,
use the existing protected file owner and atomic same-filesystem replacement with
file/directory durability, preserve permissions and retain the original until the
upgrade's retention rule allows removal. Never truncate the live file in place.

A multi-file conversion is not one atomic filesystem transaction. Record the migration
id, transformation ids and each original/target document digest in the protected Store
upgrade checkpoint before replacing files; retain protected source/target document
material where necessary to complete a partial replacement. On restart recognize each
file as original or converted, finish the same conversion, and refuse a third-party
edit instead of overwriting it. Keep file secrets in existing protected custody, never
in a public manifest/log. A file-write failure leaves the database conversion intact
and the original compatible input usable through in-memory normalization; it must not
roll the Store backwards. A changed bootstrap dataset/secret binding blocks serving
until the new input is reconciled. These files remain operator configuration, not a
local application-state fallback.

#### Neutral pre-open Store lifecycle port

Add `contract::persistence::lifecycle` with owned types and a `PreparedStore` capability,
and add `PersistenceAxis::prepare(door, label, settings)` alongside the current opener.
Loader alone maps it to Store ABI calls. Add a mandatory Store `BOOTSTRAP` slot to the
unreleased ABI **3**, after the four neutral primitive slots, with a versioned tagged
request/response envelope. Update the table size, layout fingerprint, SDK validation,
loader dispatch and all five doors together. Shared lifecycle slot offsets and other
kinds do not change. No ABI 4 and no silent acceptance of the previous fingerprint.
Concretely, `KIND_SLOTS` becomes 5 and `slot::BOOTSTRAP = LIFECYCLE_SLOTS + 4`;
extend `NAMES`, `OPS` and `LAYOUT_SHAPES` together. The bootstrap codec starts at 1,
rejects unknown tags/reserved flags and uses checked aggregate/page bounds. Add typed
non-secret `Busy`, `Pending`, `UnsupportedFormat`, `MissingCapability`, `SourceChanged`
and corruption results rather than converting connection uncertainty into no-effect.

`BOOTSTRAP` is legal on an admitted/bound door before ordinary lifecycle OPEN. Its
first call establishes only a native inspection session. The session owns all native
connections, input/secret custody and teardown; multiple channels, such as a snapshot
stream and control connection, must bind to the same inspected native instance. An
opaque session token is never an operator-supplied boolean or a transferable lease.
For SQL, a held source snapshot and control/fence work may need separate native
connections. Cloning the existing SDK `Wire` shares its connection; it does not create
another one. Schedule each genuinely independent connection through the existing host
task/transport owner, never a nested private executor inside an active Wire operation.
Use the existing async ticket/cancellation/lease mechanism, bounded caller-owned
buffers and short-buffer replay rules. The concrete request variants are:

| Request | Result and obligations |
|---|---|
| `Inspect { bounds }` | `Empty`, `Current`, `Legacy`, `InProgress`, `Unsupported` or `Busy`, with source physical/codec descriptor, native dataset identity, exact catalog fingerprint, current logical/admission marker if present, and native upgrade capabilities. No schema writes. Unknown/nonempty is never Empty. |
| `BeginOrResume { expected_source, route_digest, target_format, operation_id }` | Atomically claim or read the one durable upgrade for that source, acquire/drain native ownership, install or recover persistent old-write enforcement, and return stable upgrade/source/target ids plus opaque authority and progress. A mismatching route/target refuses. The operation id is retained across an unknown reply; native DDL steps are journaled/reconciled by their owner. |
| `SourcePage { upgrade, snapshot, family, cursor, bounds }` | Protected bounded native rows/key-value frames, original bytes/expiry metadata, next cursor, source coverage and snapshot identity. Reuse `legacy_row` and existing physical reader codecs. No credential/accounting interpretation and no target writes. Group/indexed reads needed by current transforms use a versioned selector within this request, not an all-database allocation. |
| `Target { upgrade }` | A migration-only backend capability for the inactive generation. It uses the existing READ/SCAN/COMMIT/CLOCK slots and candidate semantics; do not add another mutation API. Loader binds this capability to the session/target generation and exposes no serving CoreStore. |
| `CheckFence { upgrade }` | Recheck actual native instance, persistent enforcement, old-session/transaction drain and immutable source identity. Loss of ownership stops copy/activation; wall-clock expiry or a saved success response cannot renew it. |
| `Finish { upgrade, activation_receipt }` | Verify confirmed core activation against native target/control records and finalize the native physical selector idempotently. Return `RecoveryReady`, permitting only the identified cold-recovery reopen while the core checkpoint remains pending. Ordinary serving OPEN requires the later completed checkpoint. Keep the old-write fence and retained source. |

SDK/loader instance phases are `Bound → Prepared → Upgrading → RecoveryReady → Open`.
Current/empty sources take their validated shorter route. Only BOOTSTRAP and teardown
are legal in Prepared; the four primitives become legal for the returned inactive
target capability in Upgrading. READY and business access remain closed. Existing
CLOSE/teardown must work even when ordinary OPEN never ran, retaining any detached
native operation until settled; process loss is recovered from the durable upgrade,
not a serialized process-local session token.

Source inspection and the durable upgrade control area are backend-owned physical
mechanics. The library's existing `Manifest`, exact intent and logical checkpoints
remain authoritative for semantic progress. Bind the native record to that plan and
all source/target identities; do not create two independently mutable semantic state
machines. Native target creation may precede semantic copying but never grants serving
rights. For nontransactional DDL, record/check each native step and reconcile its actual
catalogue before returning; unknown completion is not rollback.

Ordinary OPEN either consumes a validated current session or independently verifies
its native current-format selector. A pending target may be opened only for the
checkpoint-bound cold recovery owner. Root passes that target through existing kernel
admission barriers; target state cannot become a business backend before those checks.
Raw plugin calls remain trusted native code, but plugins still receive no cross-kind
business authority. `Store::open` must not perform logical transformations internally.

#### Native fencing: reuse actual released behavior, never assume a marker works

The supported default upgrade is a stopped-old-instance, single-node deployment. No
manual quiescence attestation is required. Backend ownership must nevertheless handle
an old queued command, reconnect or concurrent new starter safely. Observe old sessions
and wait/refuse for an active unsupported old fleet; do not kill unrelated applications
or silently regard zero visible clients as a permanent fence.

Read the actual released writers before choosing enforcement. The inspected local
release tags show SQLite v1.0.6 `lib.rs::migrate` unconditionally stamps user_version 6
and PostgreSQL v1.0.6 `migrate_locked` inserts schema 6 without rejecting a newer marker;
MySQL v1.0.6 startup upserts schema 3; Valkey v1.0.7 `migrate` accepts every version >=6.
Consequently none supplies a sufficient higher-version downgrade fence. PostgreSQL's
existing migration advisory lock can coordinate old opens, but not ongoing business
writes. Retain any useful native lock; supplement it with enforcement at every legacy
mutation surface, including the schema/revision tables touched on old startup.

| Backend | Automatic enforcement and capture implementation |
|---|---|
| Memory | A fresh process has no persistent historical dataset. Report genuine empty/current state, migrate config and initialize normally. For an owned in-process old generation, take its actual exclusive state lock, stop/drain its writers, retain the source generation and atomically select the new one. Do not claim to recover lost volatile state after a process exit. |
| SQLite | Use the same database connection/transaction machinery to obtain native write exclusion and drain preceding writers. In a transaction install persistent aborting INSERT/UPDATE/DELETE guards on the recognized legacy tables, including old-open mutation paths; preserve original source rows and supported built-in triggers. Re-read the complete admitted catalog and snapshot only after enforcement. Old prepared/new connections must fail their writes after release; source `PRAGMA user_version` alone is insufficient. Target primitives live in distinct physical tables/generation. WAL/rollback-journal and Windows file behavior need real native witnesses. |
| PostgreSQL | Reuse the native session and old migration lock, then transactionally lock all admitted source relations against writes, drain prior transactions and install persistent reject-write guards covering ordinary DML and any supported legacy TRUNCATE/DDL route. Preserve source tables rather than relying on rename invalidating cached OIDs. Record the guarded catalog and immutable snapshot; target primitives use separate relations. No superuser/global-account operation is assumed; establish required schema-local privileges from the configured authority. |
| MySQL | Use existing native client/metadata locks and InnoDB transaction semantics. Install persistent reject-write guards on all old DML/startup surfaces, including `store_meta`/sequence writes, under a resumable native DDL journal. Trigger/DDL statements are not one rollbackable transaction: a crash after a subset leaves those guards enforced, then restart completes/reconciles the set before capture. Drain transactions/XA/prepared work that can touch the source and take the consistent source only after all guards are effective. A rename or GET_LOCK alone is not a fence. |
| Valkey | Use a single owned native session with exact instance/topology binding. On the supported dedicated Busbar scope, install a durable ACL policy that forbids legacy writes/scripting paths to the source while permitting source reads and the new target/control namespace. Account for every selector/effective grant; preserve unrelated scopes/accounts. Recheck/drain existing connections and queued MULTI/EXEC/EVAL work: disabling authentication alone does not stop an already authenticated client. Persist the policy through native restart/failover before activation. Capture an immutable native snapshot including binary data and required expiry metadata; normal SCAN/GET is not an archival view. Reuse proven native snapshot/reader logic inside the backend, removing subprocess dependence. |

A backend must prove a cut with this property: every old write that returned a native
success before the cut is present in the frozen source; after the cut no old write
can return success against discarded/unobserved state. Wait for pre-cut transactions
or include their committed outcome before freezing. A failed old EXEC can contain
partially applied commands, so freeze the resulting actual state after the complete
command/queue has resolved; never infer rollback from its error. Every native read
and replay checks the frozen source identity. Unsupported concurrent old producers
keep startup closed; migration cannot reconstruct 1.5.5 write-behind work that never
reached storage or repair its historical at-least-once ambiguity.

For SQL/SQLite, the guard installation must be tested against the exact released
mutation/initialization statements, including cached plans and reconnect; arbitrary
hostile DBA actions are outside this coordination protocol. Do not alter unrelated
schemas. On resume, admit only the precisely recorded guard DDL/catalog delta, not
arbitrary new triggers. Keep guards after activation so reopening an old binary cannot
write behind the new format. Original data is retained until the existing retention
policy authorizes cleanup, not deleted to make an old writer fail.

For Valkey, both the dedicated Busbar key scope and a full-authority standalone
default account use the automatic path. The broad account retains reads and unrelated
read/write scopes while the durable ACL excludes writes to the legacy `busbar:`
namespace and admits the new `busbar:v4:` namespace. Native read/write commands
require both permissions in one matching pattern. Bind resumed client ownership to
the server run as well as its client ID, since IDs can repeat after restart.
Insufficient ACL/persistence authority or unsupported topology produces a precise
refusal before conversion; do not invent a manual helper, alter other accounts or
substitute a marker. Preserve exact whole-policy checks and retained source data.
Native expirations continue independently of client writes. Preserve a snapshot cut
and original absolute expiry metadata using a supported native snapshot codec; never
load the snapshot through ordinary expiry-filtering reads and call it exact. Bind
capture to the same native instance even if replication handshake changes an id.
Unknown RDB/module/hash-field-expiry encodings refuse rather than omit data. Use the
specific parser-library integration below; do not start a handwritten RDB parser or
silently relax source profiles. The isolated official-engine/module extraction used
for fixture evidence remains an oracle, not an operator prerequisite, production
module install, bundled second server, Python supervisor or Windows support gap.

**RDB dependency decision (primary source inspected 2026-11-06):** reuse only package
`rdb-parser` from `nmvk/valkey-rdb-tools`, baseline commit
`364d0e0379414ae9e44281e61510b424c9526624`, in the Valkey backend. It has no dependencies
on the project's Arrow/Parquet/CLI/Python packages. It is a small community upstream,
not an official Valkey component or a proven enterprise library; the choice is based
on the inspected format/byte APIs and requires the bounded qualification below.

| Candidate inspected | Decision |
|---|---|
| [`valkey-rdb-tools` parser](https://github.com/nmvk/valkey-rdb-tools/tree/364d0e0379414ae9e44281e61510b424c9526624/crates/rdb-parser) | Select parser-only reuse: native REDIS 1–11/VALKEY 80 admission, byte-valued keys/fields, absolute key/HASH_2 expiry, CRC and LZF support. Do not inherit its analytics skip policy. |
| [`rdb` 0.4](https://docs.rs/rdb/0.4.0/rdb/) | Reject for this path: its documented Redis format range is not VALKEY 80, streams/modules can disappear and field TTLs are not returned. |
| [`redis/librdb`](https://github.com/redis/librdb) | Established upstream alternative for Redis, but the inspected [header parser](https://github.com/redis/librdb/blob/main/src/lib/parser.c) accepts REDIS, not VALKEY 80; C/platform and native-format adaptation would be broader than the selected Rust parser's bounded fixes. Do not claim its Rust wrapper makes it Valkey-compatible. |

W05 integrates `RdbReader` behind `historical/snapshot.rs`, feeding the existing neutral
source-row/page contract. Pin the final dependency revision through the existing
dependency-patch process; no floating branch, wholesale copied decoder, new Busbar
crate or new parser fork architecture. The inspected baseline needs these finite
upstream-oriented changes before it is admissible:

1. Add constructor-supplied limits **before** its eager AUX preamble: cumulative
   metadata, allocation/live bytes, string/compact-block bytes, collection elements,
   work and input bounds. Its current fixed 512-MiB per-allocation limit and element
   chunking are not an aggregate budget. Enforce budgets before reserve/decompression,
   use fallible checked allocations, and bound compact collection expansion too.
2. Add a strict opcode/profile policy and raw metadata events. UnknownType is terminal
   for Busbar; FUNCTION/MODULE_AUX/stream/slot sections cannot silently disappear.
   Admit only explicit source-profile encodings and approved metadata; preserve every
   original byte in the immutable snapshot. Reject unknown modules/functions and any
   unimplemented family even if the generic parser would skip it. Preserve AUX bytes
   without lossy UTF-8 conversion or duplicate-key overwrite; provenance cannot rely
   on the baseline's `BTreeMap<String,String>` rendering.
3. Keep binary key/field/value bytes in existing protected custody and wipe parser
   temporary, decompression and compact-decoder buffers on success/error/cancellation.
   Move decoded outputs into protected source rows without debug/JSON logging. Add
   only the needed byte-custody hooks/wrappers, not another secret-storage system.
4. LZF stays the library's decoder. Validate compressed and claimed expanded sizes
   against the remaining budget before allocation, exact decoded length and malformed
   backreferences; retain its expansion guard. Complete the whole snapshot through
   EOF and CRC verification when a nonzero checksum is present. Bind a checksum-disabled
   snapshot to the native capture's exact byte length/digest rather than claiming CRC
   verification. Trailing/truncated/corrupt input cannot finalize migration.

The need for these changes is visible in the baseline [reader](https://github.com/nmvk/valkey-rdb-tools/blob/364d0e0379414ae9e44281e61510b424c9526624/crates/rdb-parser/src/reader.rs),
[byte/expiry types](https://github.com/nmvk/valkey-rdb-tools/blob/364d0e0379414ae9e44281e61510b424c9526624/crates/rdb-parser/src/types.rs)
and [LZF implementation](https://github.com/nmvk/valkey-rdb-tools/blob/364d0e0379414ae9e44281e61510b424c9526624/crates/rdb-parser/src/lzf.rs);
this is a bounded integration choice, not a claim those changes already exist.
Qualify actual supported source fixtures against the existing official-engine oracle:
binary/NUL/non-UTF-8 strings and hash fields, compact/plain encodings, expired keys,
absolute millisecond TTLs, CRC/truncation, oversized lengths and LZF boundaries.
The parser exposing HASH_2 TTL does not itself add Busbar HFE support: preserve the
current native volatile-field refusal until the source-row format, transform and
verification all carry those TTLs exactly. No universal-RDB or all-Valkey-version
claim follows from the library's broader advertised header range.

These mechanisms are qualification requirements, not claimed proofs. Relevant native
semantics: [SQLite trigger errors](https://www.sqlite.org/lang_createtrigger.html),
[PostgreSQL relation locks](https://www.postgresql.org/docs/15/explicit-locking.html),
[MySQL trigger metadata locks](https://dev.mysql.com/doc/dev/mysql-server/latest/group__Data__Dictionary.html),
and [Valkey ACL rule and existing-session behavior](https://valkey.io/commands/acl-setuser/).
The all-five stopped-old-instance witnesses below decide completion.

#### Implementation constraints still requiring acceptance

The automatic path does not imply that the binary can create database privileges.
Released Valkey configurations can permit application writes while denying ACL
administration or persistent ACL configuration. Those deployments cannot establish
durable exclusion of a reconnecting released writer using the application's existing
authority. The implementation must refuse before conversion when the required native
capability is absent. Actual Valkey 8.1.9 cases qualify scoped and broad full-authority
bootstrap, persisted policy through a configuration-only server restart, resumed
ownership, and refusal without ACL authority. These bounded results do not assert
that every released configuration has sufficient privileges or qualify other stores.

Source bytes use an encrypted anonymous/delete-on-close transient spool with an
ephemeral process-owned key. Startup reconstructs that spool after a crash from the
retained native source. There is no required export file or operator migration command.
Archive and logical grouping indexes currently retain O(rows) metadata. The explicit
startup limits `limits.migration_index_bytes` (256 MiB per index by default) and
`limits.migration_value_bytes` (64 MiB per working frame/page/semantic buffer by default)
bound allocations; neither is a total-process RSS guarantee. Some conversion stages
charge coexisting input and output against the same semantic budget, so this setting
is not a maximum logical document size. Dataset row count and
total spool bytes have no additional application-size ceiling. Exhausting an index
budget is a reported resource refusal, never permission to omit rows. These limits
are captured before reading the Store overlay and are not mutable runtime patches.

Configuration publication must complete before the native migration is marked
Complete. A fixed kind-owned locator identifies an interrupted configuration inventory
across process IDs, runtime upgrade IDs and partially converted files. Ephemeral Stores
retain conversions in memory and preserve authored source files; they cannot be
described as providing durable checkpoint custody. Filesystem security and durability
changes require their actual platform qualification; a macOS check proves no Windows
runtime behavior.

Windows publication retains the original handle, its write exclusion and operator
lock through replacement. The staged file retains a write-through handle with delete
authority, exact security metadata and confirmed contents. Rename that handle with
`FileRenameInfoEx`: POSIX replacement for an existing destination, exclusive rename
for missing-file recovery, within the verified parent and volume. Flush before and
after the rename and verify the published identity, security and bytes. Do not close
the original handle merely to make legacy `MoveFileExW` replacement succeed. The
[native POSIX rename contract](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4217551b-d2c0-42cb-9dc1-69a716cf6d0c)
preserves existing handles; [write-through file operations](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
provide the documented NTFS metadata-flush basis. Unsupported native operations
refuse; there is no copy/delete fallback or unguarded destination interval.

#### Exact source ownership and APIs

Frozen plane bindings come from the complete admitted declaration inventory, including
dormant planes. Historical generic record keys contain a reversible instance prefix;
retain that owner when importing them. Historical SQL and Valkey history/token rows
identify only a kind, not its owning plane. The currently enabled configuration is
therefore not evidence that it owns old rows. Keep globally unambiguous history/token
bindings, and leave conflicting kinds unresolved: an actual source row requiring one
must refuse migration without changing ownership. An unused conflicting declaration
alone need not block migration. Convert and validate the exact frozen overlay against
retained authored documents and the captured environment; never reread a partially
published file or use a newly selected plane to reinterpret historical ownership.

| Existing source | Final owner/action |
|---|---|
| Kernel `persistence/migration/{mod,coordinator,manifest,intent,fence,verification,witness}.rs` and `legacy/**` | Move to `busbar-migrations/src/`, with `mod.rs` becoming `lib.rs`; preserve checkpoint/candidate bytes, source profiles and fixture digests. Replace external helper fence input with a contract lifecycle-session adapter. Move migration-only tests here. Give the library its own contract seal. |
| Kernel `persistence/migration/activation.rs` | Keep migration-specific plan/id/state adaptation in migrations. Move current-format bootstrap/control/activation preparation and validation into kernel `persistence/import_target/{mod,target,records,journal}.rs`, without a feature gate. Use kernel-owned `TargetIdentity`, `ActivationRequest`, `ActivationChange`, `ImportError`, not migrations types. Coordinator still commits activation plus checkpoint together. |
| Kernel current identity/ledger/host-record/journal/recovery owners | Keep current encoders and validation private; `import_target` wraps their existing migration row/authorization helpers, bounded candidate codec and verified journal/recovery proofs. No copied encoders, public raw attach, source schema switches or plugin names in this facade. Decoders needed by current signed/ciphertext/pending evidence remain with their owner. |
| Kernel `config/migrate*.rs`, historical migration tables and current config parsing | Move historical-only orchestration/conversions into `busbar-migrations::config`, retaining current config DTOs/validation and neutral declared plugin migration ports in kernel/contract. Change root call sites; do not introduce a kernel-to-migrations edge. Split mixed modules by actual callers; keep a current-data decoder if serving still needs it. |
| Root `store_migration.rs` and `store_migration/recovery.rs` | Refactor into `root/startup_upgrade/{mod,continuation,recovery}.rs`: automatic composition, actual independent native reopen, one App hydration and adoption of the same ready owners. Split useful readiness checks from the manual command's destructive shutdown/retirement tail. Library never depends on binary, loader or concrete plugins. |
| Contract `persistence/{legacy_row,source_fence,archive}.rs`, new `lifecycle.rs` and Store ABI/SDK | Neutral bounded source/identity/enforcement vocabulary shared by backend and host. Replace helper-path/attestation assumptions with actual lifecycle results. Keep only archive encoding still required for immutable snapshots/fixtures; no ordinary startup archive file requirement. |
| Native SQL/SQLite/Valkey reader/export implementations | Move reusable native logic behind each Store's lifecycle session using its existing client and host transport libraries. Keep physical profiles/catalogues native; feed neutral protected rows to migrations. Remove external CLI/helper wrappers after their behavior is supplied by this automatic path. |

`busbar-migrations` is `publish = false` and depends on kernel, contract and existing
WAL/audit/ledger codecs as needed. `crates/busbar/Cargo.toml` and
`dist/default/Cargo.toml` depend on it normally. There is no migration feature gate,
second executable or plugin selected as a migration implementation. Kernel, loader
and plugins have no dependency back into migrations; move cross-boundary tests rather
than creating a dev-dependency cycle. Loader owns only the neutral ABI crossing.

Reuse the current strict serving admission projection. It identifies an unfinished
upgrade and permits only its authenticated cold-recovery owner; it need not decode
historical source schemas. Root's migration library automatically handles resumable
work before asking `RuntimeStartup` to serve. Unknown/newer format, wrong source,
unsupported path, invalid authority or unresolved debt always keeps admission closed.
After process death, fresh native sessions recover persistent fences and exact intent
from the same durable ids. Lease loss/cancellation never releases old-writer enforcement,
clears protected intent, changes the target or restarts under a fresh operation id.

Remove the recently added manual-only surface once its useful native logic is reused:
`root/store_migration/probe.rs`, private helper control-file parsing, subprocess/pinned
helper orchestration, `--migration-source`/`--migration-control` requirements, backend
legacy-export binary targets and Valkey export supervisors/module-install packaging
that have no remaining required consumer. Preserve fixtures, source hashes, native
codec logic and evidence. Do not retain an advanced tool product merely because it
was already written. Existing useful read-only status or explicit operator recovery
commands may call the same library, but are not prerequisites for normal upgrade.

#### Long-term support, artifact trust and maintenance cost

The normal 1.6.0 binary carries the supported 1.5.5 configuration/data route, exact
released plugin/schema provenance and separately admitted dev profiles. Future binary
releases carry the compiled route from every supported source format to their target;
the startup planner follows that route automatically. Adjacent edges may compose
inside the process using retained intermediate generations. Do not require an operator
to run twenty old binaries. Same-format product updates need no invented edge.

An older edge must not silently start emitting a newer target encoding because a
kernel helper changed. When the logical format actually changes, freeze the retired
edge's destination codec/verification in the migration library with that format's
fixtures; the final edge alone uses the current `import_target` facade. Intermediate
generations stay non-serving and are validated by their frozen edge rules. Only the
final current target enters actual `RuntimeStartup` and current domain recovery.
Retained unknown operations still carry their original bytes/semantics through this
chain and cannot become newly authorized work in an intermediate generation.

Keep `crates/busbar-migrations/routes.json` consistent with compiled registrations:
source/target formats, edge and semantic digests, provenance/fixtures, native backend
capabilities and limits. It is data, not executable instructions. Sign migration code
as part of the ordinary Busbar release and native lifecycle code as part of ordinary
Store artifacts. Current native ABI/fingerprint admission still applies; no arbitrary
code/download/path supplied by stored state is loaded. Preserve source, lockfiles,
fixtures and checksums with release assets for provenance and recovery.

Freeze released edge meanings and checkpoint interpretation. Security fixes build new
signed artifacts; changed transform semantics require a new edge or explicit compatible
resume/reconciliation transition. An interrupted upgrade automatically resumes only
under matching semantics or such a tested transition, never by silently accepting a
new digest. Preserve original audit bytes, ciphertext, exact count scale, keyset/price
provenance and unknown candidate custody. Artifact revocation applies even if an old
checksum matches; maintain a safe supported replacement/resume path.

There is no approved numeric support window to invent. Preserve all published supported
sources, including 1.5.5 now, until an explicit product policy changes that support.
Removal needs an announced support decision, a tested route for every remaining
supported source and pending upgrade, and retained immutable evidence; it cannot be
justified by crate size. Current-input evidence decoders remain as long as current
records need them. Twenty logical formats normally mean a linear set of adjacent
edges/fixtures, not every source-target pair and not a crate per version/backend.
The migration library and linked binary necessarily retain the cost of supported
historical code; this owner-approved design contains that cost outside serving modules,
it does not claim to eliminate it. CI exercises supported composed routes as well as
individual changed edges; graph reachability is not semantic equivalence.

#### Execution and minimal acceptance witnesses

P08b builds this automatic path in buildable slices: finalize the contract lifecycle
and current-target facade; port all five native lifecycle sessions; move the coordinator
and historical code to the new library; integrate root config/Store startup and real
recovery; remove redundant manual helper surfaces. Coordinate file ownership with
ongoing work; do not revert its fixes. Keep source fixtures/persisted checkpoint meaning
unchanged unless a separately identified transition is necessary. No extra agents or
review campaign. Locally use fmt/clippy and targeted tests; CI runs full native suites.

| Witness | Required result |
|---|---|
| Ordinary upgrade on all five Stores | Stop a real supported old instance, run the ordinary new binary with the same supported configuration, automatically migrate/validate and serve. No migration flag, artifact export, manual fence, secret rewrite or extra executable. Memory proves its stated ephemeral behavior. |
| Original semantics and actual recovery | Nonempty credentials/revocations, exact accounting, audit/journal/keyset/rate provenance and opaque plugin records survive; independent native reopen and full config/overlay hydrate once. The same App/CoreStore/book are adopted into serving, globals bind once, journal staging remains enabled and the first serving write succeeds. No shutdown tail or serving-writer retirement occurs during readiness. |
| Native cut and competing processes | Real old queued transaction/EXEC, cached statement, reconnect and two new starters cannot create lost acknowledged writes, duplicate upgrades or early serving. Exercise persistent guards through restart and Valkey policy persistence; unsupported topology/authority refuses precisely. |
| Crash/cancellation/resume | Crash at native DDL/fence/capture, page checkpoint, activation, config replacement and cold recovery. Ordinary restart resumes the same ids/bytes or waits with custody intact; it never requires manual `resume`, infers rollback, regenerates unknown candidates or releases the fence. |
| Config and version safety | Locked/read-only configs normalize in memory; writable conversion is atomic per file and recoverable across files. Concurrent edits, unknown source/newer formats, wrong edge or changed native source refuse before destructive work or serving. Validation-only invocations do not migrate. |
| Boundary and native qualification | Fourteen-member graph has one migration library and no reverse/plugin-to-plugin edges. Same normal artifacts pass native Linux x86_64/aarch64 (including armv8.0), both macOS architectures and Windows MSVC upgrade tests through existing CI; no helper packaging remains necessary. |

These are implementation acceptance requirements, not passing results asserted by this
amendment. All five supported default configurations must qualify before completion;
a native capability gap is unfinished work, not a reason to replace seamless startup
with an invented operator procedure or weaken the fence.

## 11. Backend adaptation and global deployment

| Store | Required implementation |
|---|---|
| Memory | One atomic guard over records/receipts/epoch; prepare allocations before mutation; explicit ephemeral metadata. Same functional contract, no crash durability claim. |
| SQLite | Canonical binary records; FULL-sync transaction behavior as current configuration requires; conditions/mutations/receipt/epoch in one transaction; bundled rusqlite retained. |
| PostgreSQL | Serializable transaction or proven equivalent predicate locking, including absence/ranges; parameterized binary keys; complete retry on proven serialization abort only. Keep maintained codec/driver integration compatible with host I/O. |
| MySQL | Transactional table engine, binary collations/keys, absent-row and range protection; receipt in same commit; physical DDL migration retains marker/recovery discipline. |
| Valkey | Candidate mapping: read-only validation and authoritative TIME in one script, then one final authoritative MSET containing values/deletion tombstones/receipt/namespace generation. All keys share the atomic cluster domain. Unqualified until full range, size, error, persistence and failover witnesses pass. |

Valkey's current conditional path queues data/index commands and then the receipt.
A runtime error can leave a receipt after partial effects; reporting Unknown does not
make a replayed receipt prove atomicity. A concrete failure is ACL revocation after
queueing: a data HDEL can fail while index deletion and receipt writing still execute.
The candidate v4 mapping performs all validation/range selection before its final
MSET. There is no fallible authoritative write after it. Deletion tombstones are
written by that same command. A WATCH→TIME→EXEC network sequence does not satisfy the
time guard; TIME and final publication must share atomic script execution. Avoid an
independent authoritative zset whose update could fail separately. Scan generations
and all physical cleanup obey the same atomic visibility rule.

This candidate is NOT a proof that Valkey can meet the whole baseline. Existing raw
DeleteRange may select arbitrarily many stored rows; expanding that to one MSET can
hit script argument/native limits. P07 must demonstrate the entire admitted range
and candidate envelope or stop Valkey cutover with the exact failing witness. Do not
invent a hidden range cap, split visible deletion, claim Lua rolls back writes, or
mark a partial implementation conforming. Existing Stores remain required for the
complete cutover; an unresolved Valkey limitation blocks completion, not acceptance.

Valkey replication does not guarantee preservation of acknowledged writes across all
failovers, even with WAIT. Local persistence qualification is not global quorum
qualification. Dataset configuration must state its failure domain; a deployment
requiring no loss of acknowledged accounting/revocations cannot use a topology that
does not provide it. Do not weaken the requirement or call the adapter proven until
the native fault cases pass. Primary references:
[Valkey transactions](https://valkey.io/topics/transactions/),
[Valkey atomic MSET](https://valkey.io/commands/mset/),
[Valkey 8.0 EXEC implementation](https://raw.githubusercontent.com/valkey-io/valkey/8.0/src/multi.c),
[Valkey replication](https://valkey.io/topics/replication/),
[PostgreSQL isolation](https://www.postgresql.org/docs/current/transaction-iso.html).

All plugins may reach the same authoritative database from multiple regions. This
does not create atomic transactions across independent regional databases. No
last-writer-wins reconciliation for billing or revocation. Quorum loss cannot cause
an unfenced second authority. Failover must retain receipt/data consistency and the
writer epoch; otherwise admit recovery-only operation until reconciled.

Ten additional design cases, not implementations or promises of support:

| Backend | What the design must account for |
|---|---|
| FoundationDB | Transaction size/time limits; mapped transaction contract must still meet admitted Busbar bounds |
| etcd | Strong compare/transaction semantics but request/storage-volume constraints |
| DynamoDB | Direct transactions: 100 actions, 4 MB aggregate, 400 KB items; do not satisfy the baseline. Global-table replication is not the same transaction contract |
| Cosmos DB | Direct batches: 100 operations, 2 MB request, single partition; do not satisfy the baseline. Do not depend on preview cross-partition features |
| MongoDB | Snapshot transactions require additional read/absence conflict protection |
| CockroachDB | Serializable retries and multi-region locality/failure configuration |
| TiKV | Snapshot isolation needs appropriate read-dependency protection |
| RocksDB | Local transactional durability, not a distributed HA promise |
| SQL Server | Indexed range/absence protection and correct isolation |
| S3 | Object atomicity alone is insufficient; archive/export target, not a full Store without an existing transactional system |

The current 16-MiB candidate and atomic range contract exceeds some native APIs.
Those are negative compatibility tests for the design, not permission to introduce
backend-specific business support. No worker builds a database-on-top-of-a-database
to claim ten additional green backends. See also
[DynamoDB global transaction limits](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html).

The direct API limits above come from [DynamoDB TransactWriteItems](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html)
and [Cosmos DB limits](https://learn.microsoft.com/en-us/azure/cosmos-db/concepts-limits).
The other rows identify qualification dimensions, not certifications or claims that
the default configuration meets Busbar's contract. Favor a maintained native client
whose integration fits host I/O over bespoke wire code; capability limits are not
fixed by hand-writing a database protocol.

## 12. Execution packets

All packets use the current dev checkout or isolated worktrees under the approved
temporary root. One writer per file set. Do not start parallel backend porting before
contract and canonical-layout packets are accepted. Use Sol/medium for specified
coding, Luna for commands/inventory only; architectural discrepancies go to the
controller with exact source, expected behavior and failing result. Do not guess,
weaken a test or repeatedly retry an unsupported assumption.

Every packet supplies: changed files, removed implementation, targeted test names and
results, remaining dependent work, and exact commit only if commit was authorized.
Local validation is fmt/clippy and targeted tests only; CI runs full suites. No
automatic push, promotion or release from this document.

Implementation order: P00 → P01 → P02 → P03, then the identity/ledger/host slices
P04–P06 and migration P08. P07 may proceed independently per backend once P01/P02
shapes are frozen. Complete P09's cold-recovery interface before P08b extraction;
P09's final cutover waits for that extraction and all required backend/migration work.
P10 removes
transitional paths and qualifies the assembled result. Do not merge a packet that
leaves dev unable to build: stage neutral modules alongside v3, then switch callers
in buildable slices. No customer dataset is switched by an intermediate refactor.

### P00 — Baseline and work ownership (mechanical)

Record core and five Store SHAs, all fourteen manifests, dirty paths, existing test
commands and fixture digests in a temporary task receipt. Check for drift from this
document. No source modifications. Establish file ownership for subsequent packets.
Acceptance: no unrelated work overwritten; actual source/fixture versions pinned.

### P01 — Contract and host-only facade separation

Files: `busbar-contract/src/{records,store_calls}.rs`, new v4 shapes under `abi/store/`,
`abi/sdk/store/`, `plugin-loader/src/dispatch/kinds/store.rs`, v4 loader binding,
`busbar-kernel/src/persistence/mod.rs`, `busbar-kernel/src/appbuild.rs`.
Also add neutral `contract::{persistence,host_records}` modules and remove Plane/host
imports of Store SDK condition/retention types. Keep shared HostSlots offsets intact.
Implement §§4–5 with typed outcomes and mandatory baseline. Keep v3 loader only as
an explicit migration/transition input. Remove unsafe atomic trait defaults.
Acceptance: layout/version mismatch refuses before call; duplicate/oversized inputs
refuse without mutation; raw backend cannot be passed as the business facade; raw
and typed workload size witnesses show no reduction from hidden framing/expansion.
Do not switch production data paths yet.

### P02 — Common object, index and commit mechanisms

Depends P01. Files: new persistence `{commit,objects,keys,scan}.rs`; extract common
parts from `host_records`, config/OAuth chunk code and root `conditional`.
Implement immutable candidate custody, logical vs attempt receipts, guarded scans,
separate plane/storage bounds, confidential inline records, non-secret chunked
objects, execution-epoch retirement and bounded cancellation. Keep existing owner-specific pending
queues until their callers are ported, then delete the duplicate mechanics.
Acceptance: lost reply + restart does not reapply; chunks without manifest are
invisible; missing chunk is an error; changed collection guard prevents stale commit;
closed-epoch delayed commands cannot reapply after receipt GC; confidential records
are replaced/wiped on retirement rather than waiting for non-secret object GC.

### P03 — Memory and SQLite primitives

Depends P01–P02. One writer per backend repo. Implement v4 records/epoch/receipts/time,
without key/credential/task/accounting policy. Keep import readers separate.
Acceptance: same candidate/outcome behavior on both; SQLite restart preserves applied
receipt and object manifest; range delete remains atomic. No facade fallback to v3.

### P04 — Identity vertical slice, then complete identity

Depends P03. Files: `busbar-kernel/src/governance/persistence/identity.rs`, `governance/state.rs`,
`at_rest.rs` integration, persistence facade, relevant admin callers.
First implement revoke credential, then mint/key+credential, rotate/rewrap, key
tombstone, indexes, revision hydration and denylist. Reuse existing custody and
crypto. Delete corresponding business implementations from the two ported Stores
only after canonical migration readers retain needed legacy decoding.
Acceptance: concurrent rewrap cannot revive revocation; no two active slot owners;
unknown commit never publishes success; attribution survives key deletion; empty vs
missing vs failed is preserved. Auth plugins need no backend-specific edits.

### P05 — Ledger, recovery and publication

Depends P02/P03. Files: governance `{exact_debt,metering_flush,raw_recovery,recovery,
ledger_correction}.rs`, new governance persistence ledger; kernel-ledger math reused;
root `{card_history,card_store}` behavior moved to kernel owners.
Retain coalescing, exact scale6, receipt horizons, price provenance and pending-state
ownership. Do not issue synchronous Store reads from ordinary admission.
Acceptance: overflow/refund/correction boundaries, duplicate logical operation,
uncertain restart and first-send retention tests. New price remains inactive until
its persistence decision is Applied.

### P06 — All-kind ownership and host integration

Depends P02/P03. Files: kernel `host_{services,records,chains,units,work}`, `store/plane_view`,
OAuth shared storage and affected root services. Use declarations for retention,
parent relationships and generic effects. Delete task/ticket branches in adapters.
Keep domain semantics in originating plugins. Port public host schema only through
versioned descriptors; preserve instance isolation and quota accounting.
Acceptance: a synthetic neutral plane built against the public contract performs
records/chains on both Stores without adding its name to core; cross-instance writes
refuse; parent deletion races cannot create visible orphan children; reload retains
old operation custody. Existing A2A/OAuth behavior tests remain applicable.

This packet also owns the mandatory non-Store changes in §7.1. Complete it by kind:

- Plane: route shared orchestration/effects through kernel host services; retain
  protocol semantics in each plane.
- Auth: use kernel auth/governance owners and the existing credential SDK; remove
  duplicated host policy/custody/replay coordination without moving verifier logic.
- Secret: use the existing credential chip and shared guarded extraction; keep
  provider decisions local and eliminate parallel secret lifecycle machinery.
- Transport: route connection security, admission and shared cancellation through
  core connector/loader; retain carrier state and framing locally.
- Hook: keep declared algorithms; centralize invocation policy, authority and
  output validation in kernel host services.
- Export: centralize event projection and host delivery policy; retain sink encoding
  and protocol exchange locally, preserving queue bounds and failure behavior.
- Store: coordinate with P03/P07; use the same kind-ownership rule, not an exception.

Use existing kernel/connector/loader/contract modules, not seven new SDK/framework
crates. At P00 record concrete affected symbols for each kind against current dev;
implement only evidenced ownership violations or required contract adaptation.
For each kind return the host owner, code removed/consolidated, remaining adapter
responsibilities and targeted behavior evidence. "Stores are done" cannot close P06.

### P07 — Remaining backend ports

Depends accepted P01/P02, may run per-backend concurrently with P04–P06 after shapes
freeze. PostgreSQL, MySQL, Valkey own disjoint repositories. Implement §11 exactly.
Default maintained clients/codecs; replacing private drivers is a separate proven
integration within this packet, not a prerequisite for moving business policy.
Acceptance: shared primitive cases + each backend's targeted failure cases. Valkey
must demonstrate no receipt after partial data mutation under injected command errors.
No backend marked complete from happy-path tests alone.

### P08 — Migration coordinator and historical readers

Depends P01–P03; preserve needed historical decoders before deleting typed APIs.
Complete the staged coordinator, exact intent/reconciliation, transforms, native
physical readers and real recovery witnesses. Their final ownership/integration is
P08b. Use actual published source fixtures with full credential/denylist coverage;
never infer lost historical receipts or use old OPEN to obtain a source snapshot.
Acceptance: checkpoint/activation crashes retain exact custody; wrong source/digest,
newer formats, unknown scales and unreadable sources never activate.

### P08b — One library and automatic startup upgrade

Implement §10.4: `crates/busbar-migrations/`, kernel `persistence/import_target/`,
contract/SDK/loader pre-open lifecycle and all five native implementations, root
`startup_upgrade` plus configuration integration. The normal binary links the library;
no companion or migration feature gate. P09 supplies the actual cold-recovery interface
before this integration; final cutover requires P08b.

Move historical-only config/data logic to its new owner, preserve current target
encoders and serving barriers, then remove superseded manual helper/CLI wrappers.
Adopt the root continuation's same live App/CoreStore/book after one ordinary reopen
and hydration; never reuse the manual recovery shutdown tail for startup readiness.
Use the selected pinned Valkey parser-only dependency with its required bounded
integration changes and strict source profiles; no handwritten decoder or bundled
second server/Python in ordinary startup.
Update unreleased Store ABI 3's layout fingerprint with all doors, without ABI 4.
Do not restore deleted typed APIs, add another crate or copy the recovery pipeline.
Acceptance: §10.4's six witnesses, all five default supported configurations upgrading
through the ordinary command without manual steps, and the fourteen-member graph.

### P09 — Complete cutover, root extraction and seams removal

Depends P04–P08 for all five Stores. Construct CoreStore on every normal boot; remove
v3 business forwarding from serving paths. Move root algorithms into kernel using
injected neutral ports; keep concrete connector/loader wiring in root. Move seams
types as §3 specifies, update root/admin imports and delete the seams workspace member.
Preserve public ABI definitions consumed by plugins until the versioned transition
is complete; internal Rust imports are not a reason to retain duplicate algorithms.
P09's cold-recovery interface work may precede P08b; final completion also requires
P08b. Acceptance: 13 existing core members plus one normally linked migrations member;
loader still has no kernel dependency, no production plugin depends on kernel/another plugin,
no business Store slots in the neutral ABI.

### P10 — Qualification and removal of obsolete paths

Run existing full native CI suites through the project's current CI entry points;
do not revive retired GitHub Actions. Use targeted local regressions only. Remove
temporary adapters, dead methods, replaced retries and unreachable runtime disk WAL
paths. Retain import bridges and old signed decoders required by declared support.
Compare total production LOC/dependency surface across core and plugins with the
same counter and source exclusions. Report source changes separately from generated,
test and moved code. No savings claim based solely on smaller plugin repositories.

Acceptance is the complete checklist in §13, not a number of removed lines.

## 13. Required witnesses and completion checklist

These tests describe executable outcomes; implement them beside the owning code.
Use current test harnesses rather than a new test framework crate. A fake backend
is useful for deterministic faults; it does not replace real backend CI cases.

| ID | Scenario | Required result |
|---|---|---|
| T01 | New unnamed plane against each Store | Same host-contract semantics, no implementation-name branches added |
| T02 | Concurrent key mint / same credential slot | One valid owner, no split key/credential state |
| T03 | Revoke racing rewrap/delete/reload | No resurrection, no unconfirmed success, indexes consistent |
| T04 | Commit applied but reply lost; process restart | Exact result resolved, logical delta applied once |
| T05 | Same op id with different body | Conflict, no overwrite or reminted retry |
| T06 | Retry after receipt horizon | Unresolved state retained/refused, never re-applied as new |
| T07 | i128 extremes, scale0→6, signed refunds, whole request counts | Existing exact semantics or explicit overflow refusal; no rounding |
| T08 | Concurrent scan membership change and stale predicate | Candidate conflicts; no phantom-based authorization |
| T09 | Parent drop racing child append; sequence fork | No visible orphan and no accepted divergent history |
| T10 | Crash after chunks, before manifest / missing chunk | Old object or new complete object; never partial/empty fallback |
| T11 | Lost migration activation reply / rerun checkpoint | Single active generation, idempotent copy, source retained |
| T12 | Old writer survives migration lock | Persistent native enforcement stops its writes; new epoch/advisory lock alone is not counted as proof |
| T13 | Wrong source snapshot/keyset/version or unreadable legacy row | No activation or zero-balance fallback |
| T14 | Historical audit/ciphertext import | Original signatures/preimages verify; secrets remain protected |
| T15 | Store config changes while operation pending | Operation remains bound to original dataset; no cross-database replay |
| T16 | Lease/callback cancellation and plugin unload | Exactly one completion/custody owner; no use-after-release |
| T17 | Cross-instance/reserved namespace or forged caller | Host refuses before backend access |
| T18 | Stale replica/quorum loss/failover | Declared guarantees preserved or serving refused; no silent second authority |
| T19 | ABI mismatch/unknown required field/newer writer format | Refuse before mutation; no lossy field stripping |
| T20 | Restore snapshot containing revoked identity and old op counters | Recovery barrier; no automatic credential revival/id reuse |
| T21 | Valkey runtime mutation error/index loss/replay | Never report Applied for partial authoritative data |
| T22 | 512-byte boundary, near-16-MiB candidate, many tiny mutations, range deletion | Same accepted semantics; checked bounds, no partial batch splitting |
| T23 | Admission/flush under contention and Store outage | No new synchronous Store dependency on ordinary admission; bounded debt/backpressure |
| T24 | Historical config and current-dev dataset upgrade | Owner settings and current behavior preserved; correct source-specific migration path |
| T25 | Delayed command after closed epoch and receipt GC | No first execution; ExpiredUnknown; no wall-clock-based resurrection |
| T26 | Expiry crossed while queued; replay after expiry | New execution checks serialization time; matching applied receipt still resolves |
| T27 | Credential revoke/rewrap with object GC disabled | Live secret bytes replaced in the atomic commit; no retained immutable secret generation |
| T28 | ABA owner delete/recreate and stale credential mutation | Persisted incarnation/revision rejects stale ownership despite equal visible values |
| T29 | Maximum legal raw candidate plus core framing; large typed atomic batch | Both preserved under their own carrier limits; no new aggregate or item-count regression |
| T30 | Plugin unload after read/commit cancellation; short output buffer | Lease/pending ownership safe, secrets wiped, short-buffer retry cannot duplicate effects |
| T31 | Migration from each actual 1.5.5 writer with nonempty credentials/denylist | Correct AAD, revocation/index state and source totals; no invented historical receipts |
| T32 | No-kernel-dependency loader and shared host-record vocabulary | Contract/Plane SDK imports no Store SDK business types; loader still implements a neutral contract trait |
| T33 | New implementation of each existing kind using its public contract | No implementation-name behavior branch in core; no edits/dependencies in another plugin kind; ordinary registration remains allowed |
| T34 | All seven kinds' policy/custody/lifecycle integration | Each shared rule has one host owner; protocol algorithms retain their behavior; no duplicate plugin-owned Busbar authority |
| T35 | Ordinary startup upgrade/resume across all five Stores | Normal binary automatically migrates supported config/data and validates through real recovery, with no helper/flag/manual fence; native guards prevent unsafe serving (§10.4) |

Completion requires all five adapters through the neutral Store contract, all required migration paths
qualified, all fourteen original crate dispositions accounted for, and the final
fourteen-member graph (thirteen existing core crates plus one linked migration library) verified. Every kind in
§7.1 must have its P06 ownership and behavior
evidence; Store completion alone is insufficient. Validate native-platform ABI and assembled product in CI.
No unqualified deployment may be reported green merely because a Store compiled.
Resource/fault/throughput evidence must name its actual configuration and source SHA.

## 14. Adversarial design decisions and rejection rules

| Tempting shortcut | Why it fails | Required treatment |
|---|---|---|
| Move five implementations into one SDK crate | Same policy duplication, now hidden; every plugin still ships it | One host owner; SDK only carries neutral mechanics |
| Replace every operation with GET then SET | Lost updates, invalid uniqueness, replayed charges | Conditional atomic commit |
| Treat timeout/cancel as rollback | Backend can still commit | Unknown custody and exact replay |
| Use process-local locks for global invariants | Other nodes do not share the lock | Database predicates/fences |
| Rename schema and consider old writers fenced | Released binaries may ignore or overwrite markers | External fence and backend drain |
| Assume a 1.5.5 tag fully describes deployed plugins | Plugin releases and stored formats differ | Published fixture/artifact provenance |
| Mutate source during validation or ordinary OPEN before admission | Destroys rollback options and writes before authority established | Read-only validation/preflight; retained automatic startup migration under native authority (§10.4) |
| Put all data in one ever-growing JSON object | Bounds, contention and rewrite amplification | Bounded records/objects and scoped indexes |
| Use TTL to forget replay identities | Old operations can reapply | Horizon plus durable retirement/rejection rule |
| Delete chunks after a fixed delay | Slow reader/prepared commit may still reference them | Initially cold fenced GC; no unsafe online shortcut |
| Call async replication globally durable | Failover can lose acknowledged data and revocations | Deployment-specific qualification/refusal |
| Make all fourteen crates one crate | Removes useful unsafe/crypto/domain boundaries without fixing contracts | Keep focused boundaries; remove only redundant seams |
| Scatter historical transforms through kernel and plugins | Core modules and backend policy copies grow with support history | One linked migration library, neutral native lifecycle, narrow current-target facade and actual recovery (§10.4) |
| Use old docs as authority over current code | Restores abandoned implementation/design | Dev evidence plus explicitly approved forward decisions |

If a worker finds an absent symbol, incompatible behavior, failing assumption or a
backend unable to implement the specified transaction, stop that dependent packet
and report the exact evidence to the controller. Continue independent authorized
work. Do not produce a fallback design, weaken acceptance, erase source data, invent
a compatibility claim or add another helper crate. Unproven runtime properties remain
unproven until the corresponding CI/fault witness exists.
