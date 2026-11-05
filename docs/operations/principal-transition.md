# Principal continuity when upgrading identity formats

An auth plugin that declares a changed principal format, including OIDC-v2 and GitHub-v2, requires an explicit
Store-backed continuity receipt before ordinary serving starts. A retained 1.5.5 Store needs a
cold operator transition. A genuinely new namespace needs a creation receipt. An empty key scan,
an ephemeral Store, or a successful `--migrate-config` is not creation evidence.

Principal strings are identity, not display names. Establish each old-to-new mapping from the
historical provider and its actual new output; do not derive it from a username, email address,
or today's provider configuration alone. There is no automatic legacy alias or fallback lookup.
Console consumes the resulting identity and governance state; it does not provision this baseline
or migrate a Store behind the operator's back.

## Command interface

Use the intended binary, admitted plugins, configuration, providers and original Store namespace.
The maintenance path opens the bootstrap Store and reconstructs its effective overlay before
running; an input file cannot select a replacement Store. Except for `initialize-fresh-and-serve`,
these actions print JSON and exit before ordinary serving workers and listeners start.

```sh
busbar --config CONFIG --providers PROVIDERS --principal-transition - --transition-action inspect
busbar --config CONFIG --providers PROVIDERS --principal-transition specification.json --transition-action prepare > plan.json
busbar --config CONFIG --providers PROVIDERS --principal-transition plan.json --transition-action check
busbar --config CONFIG --providers PROVIDERS --principal-transition plan.json --transition-action apply --transition-attestation cold.json
busbar --config CONFIG --providers PROVIDERS --principal-transition plan.json --transition-action verify
```

`inspect` takes the literal `-`, not a document or stdin. Other inputs must be regular JSON files,
at most 8 MiB. `--transition-attestation` is required only for `apply`. Do not combine maintenance
with other serving/validation flags; only `--config` (or `-c`) and `--providers` are accepted beside
its flags. The action for unchanged-output authorization is `reauthorize`.

Inspection returns the admitted `requirements`, Store and effective-configuration fingerprints,
receipt hashes and readiness, and retained key/group preimage hashes. It can include key IDs and
provider/group identifiers, but does not print raw credentials. Treat saved inspection and plan
files as operator inventory. `principal_format_ready` is a continuity check, not an overall
readiness or fresh-namespace certificate.

## Retained 1.5.5 Store: cold transition

1. Preserve a recoverable copy of the original Store and configuration using the backend's
   supported backup procedure. Keep the historical auth artifact and provenance needed to prove
   each mapping. Install and authorize the intended plugin artifacts normally.
2. Stop **every** sender sharing the namespace, including old processes, recovery tasks,
   corrections and flushers. Independently settle or abort already submitted backend commands.
   Process death, plugin unload and lease expiry do not establish backend quiescence. Keep the
   namespace cold through inspection, preparation, application and verification.
3. Inspect the original Store with the intended configuration. Establish an existing public
   namespace witness through the backend/provisioner: `schema`, `key_hex` and `value_hex` identify
   an exact existing row. It must be outside the principal-transition schema and have a nonempty
   value. A matching configuration hash alone does not identify the backend namespace.
4. Prepare an operator specification with the fields below. Preserve the emitted plan unchanged,
   run `check`, then supply a fresh cold attestation to `apply`. A plan that has not started and
   crosses an enforcement window must be prepared again before starting.
5. Run `verify` against the same plan and Store. Only a matching completed receipt and exact
   poststate pass. Reopen the durable Store in ordinary startup and check actual authentication,
   existing-key use, quota enforcement and denial behavior before admitting traffic.

The specification has `version: 1`, an operator `id`, `bindings`, optional `rotations` and
`unaffected` arrays, `complete_legacy_inventory_sha256`, the exact inspected `requirements`,
`store_config_sha256`, `effective_config_sha256`, the namespace `witness`, and a nonzero `cutover`
Unix time in seconds. Evidence digests refer to real retained operator evidence; filling in a
syntactically valid digest does not establish its truth.

Each binding contains `old_principal`, `new_principal`, `provider`,
`historical_provenance_sha256` and `old_product_sha256`. Sources and destinations must be unique
and disjoint. Inventory all affected retained keys, tombstones, personal groups and denials,
including held principals with no remaining key or group. Unknown/orphan groups, ambiguous
historical issuers, destination collisions and static role/hook references requiring a policy
decision refuse the operation. Resolve the policy disposition explicitly before preparing a plan.

### Role policy is part of the cold plan

Copy `inspect.role_bindings_before` into the specification as `role_bindings_before`. This is
an exact inventory of the effective `auth.role_bindings` map, including unrelated providers.
Supply `role_dispositions` for **every configured role of every format-tracked provider**.
Each disposition contains `provider`, `old_role`, `new_role`,
`historical_provenance_sha256` and `old_product_sha256`. A different `new_role` moves the
complete existing grant; the same value explicitly attests unchanged role output. A JSON `null`
destination retires a dormant or unprovable grant. Such retirement does not establish identity
continuity for retained SELF keys, budgets or subject holds: those still require principal bindings.
Never silently discard an active grant because ownership evidence is unavailable.

For example, a proved GitHub organization mapping can use this disposition (the digests must
identify your actual historical evidence and artifact):

```json
{
  "provider": "work-github",
  "old_role": "github:org/historical-org-name",
  "new_role": "github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:42",
  "historical_provenance_sha256": "<64 lowercase hexadecimal characters>",
  "old_product_sha256": "<64 lowercase hexadecimal characters>"
}
```

The transition preserves the grant object, including pool restrictions, group, admin scope,
verb grants and plane grants. Omitted pool restrictions and an explicit empty list remain distinct.
It rejects missing source roles, duplicate source/target mappings, occupied destinations,
missing evidence digests and incomplete role inventories before writing. Unrelated provider
policy remains unchanged. Role changes use the existing Store document overlay under the same
pending fence, plan hash, quiescence requirements and retry rules as principal and usage changes.
A role-only deployment may supply empty `bindings` with nonempty `role_dispositions`.
The host treats role names as opaque; operator evidence establishes their actual meaning.

### GitHub historical ownership evidence is required

Released 1.5.5 stored `github:<login>` subjects and asserted organization roles as
`github:org/<slug>`. It did not retain the GitHub numeric user or organization ID needed to prove
ownership after a rename or name reuse. Its role output did **not** assert username-shaped
`github:<login>` or invented `github:id/...` grants. Converting those dormant configuration keys
into new user grants would create authority and is not an upgrade. Explicitly retire them or
resolve their intended policy separately; do not relabel them as proven historical grants.

For each retained subject, archived trusted provider/provisioning records must establish the
historical login's **positive unsigned 64-bit user ID**, exact provider and API domain. For each
organization grant, they must establish the historical slug's **positive unsigned 64-bit org ID**
and the same domain. A successful lookup of today's login/slug is insufficient: that name may
belong to a different account. A current OAuth login alone cannot recover missing historical ID
proof. The transition does not manufacture it. Keep the namespace cold until missing evidence
or a deliberate policy disposition is resolved.

The new principal/user role is
`github-v2:<base64url-without-padding(canonical-API-base)>:user:<numeric-ID>`;
organization roles use `:org:<numeric-ID>`. The domain is the plugin's canonical configured
API URL (including a GHES API path), with normalized URL spelling and no trailing slash,
credentials, query, fragment, whitespace or control characters. Bind the evidence to the exact
inspected provider, admitted product/settings and identity-domain fingerprints. Obtain the new
strings from the intended plugin's actual output and compare them to the archived IDs/domain;
do not construct a destination merely from the old name. A rename retains the numeric identity;
a different account acquiring the old login or slug receives none of its old grants or state.

An unrelated retained SELF principal requires an explicit `unaffected` entry naming `principal`,
`provider`, `requirement_sha256`, `keys_sha256`, `group_sha256` and `provenance_sha256`. Inspection
supplies preimage hashes, not historical provenance. Omission or mismatched provenance refuses;
it does not grant permission to discard the state. A historical deletion can be classified as a
successful rotation only with an explicit `rotations` entry: `retired_key_id`, `successor_key_id`,
`retired_key_sha256`, `successor_key_sha256` and `evidence_sha256`. A live successor alone is not
rotation proof.

The `apply` attestation contains `version: 1`, `epoch` (a fresh nonzero 16-byte value encoded as
32 hex characters), `plan_sha256`, `sender_quiesced: true`, `backend_quiesced: true`,
`recovery_and_corrections_settled: true`, `actor` and `reason`. Copy `plan_sha256` from the
successful `check` JSON output. Do not recompute it from the saved file or implement a separate
canonicalization algorithm.
Epochs are single-use; obtain a new attestation after re-establishing quiescence on recovery.

### What is preserved

The plan retains exact key, denylist, group and overlay preimages. Active mapped keys change only
their principal subject and personal-group references: key IDs, verification material, generation,
expiry, limits and other grants remain intact. Deleted key rows stay intact. Personal-group policy
is copied exactly to the mapped principal; historical groups remain. Usage carry writes exact raw
ledger values into the new enforcement buckets rather than resetting quota or repricing usage.
Source history remains available. Existing revocations remain and mapped denials/disabled or
revoked subject holds carry forward, preventing fresh SELF issuance or refresh from bypassing them.
Do not replace retained keys with newly minted credentials to work around a refusal.

### Interrupted application and uncertain replies

A durable pending receipt fences ordinary startup before listeners. A timeout or lost reply from
a usage, key, overlay or conditional-record write can mean the backend committed the write.
Keep senders stopped, settle backend commands independently, preserve the original plan and
configuration/artifacts, obtain a **new** cold attestation, and repeat `check` and `apply` with the
exact same plan; then `verify`. Absolute writes and exact preimage/postimage checks support resume
without carrying usage twice. An already completed matching application verifies its poststate.

Do not remove the fence, initialize a fresh baseline over it, or prepare a different plan to skip
partial work. A changed witness, conflicting preimage, malformed receipt or configuration binding
requires operator reconciliation of that mismatch; there is no force/unfence action. Retain the
original plan and evidence for recovery. Retained-state `prepare`, `check`, `apply` and `verify`
require unlocked configuration, even when no overlay exists. `inspect`, initialization and
`reauthorize` accept locked configuration only when there is no retained overlay. Reconcile the
configuration mode and exact Store-overlay recovery before proceeding.

## New durable namespace

The namespace owner must establish actual creation, exclusive operational control and a public
namespace witness. Build a `FreshNamespace` JSON receipt with `version: 1`, inspected
`store_config_sha256` and `requirements`, the `witness`, `creation_evidence_sha256`,
`newly_created_namespace: true`, `sender_quiesced: true`, `backend_quiesced: true`,
`ephemeral_instance: false`, `exclusive_instance: false`, `actor` and `reason`.

```sh
busbar --config CONFIG --providers PROVIDERS --principal-transition fresh.json --transition-action initialize-fresh
```

This writes a completed baseline and exits. A subsequent ordinary process reopens the same durable
namespace. It requires conditional Store records and refuses an existing, pending or malformed
baseline. It is not a migration of a retained namespace and does not prove freshness by scanning
for keys. The `exclusive_instance` flag is the separate ephemeral assertion below; durable
creation/control evidence belongs in the provisioner's evidence and witness.

## New ephemeral instance: initialize and serve on the same open

A separate initialization process cannot provision a later ephemeral Store open. First inspect
with the same binary/configuration to obtain `store_config_sha256`, `requirements` and durability
metadata. That inspection process does not create a reusable in-memory baseline.

For the actual newly created instance, provide a fresh JSON creation receipt containing the same
fields as above but `witness: null`, `ephemeral_instance: true` and `exclusive_instance: true`.
The operator must truthfully attest actual instance creation and exclusive ownership with
`creation_evidence_sha256`, the quiescence booleans, `actor` and `reason`.

```sh
busbar --config CONFIG --providers PROVIDERS --principal-transition fresh.json --transition-action initialize-fresh-and-serve
```

The action requires actual admitted/per-open ephemeral Store metadata, not a module name that
sounds temporary. It initializes and continues ordinary startup on the **same opened Store**.
All ordinary auth/plugin/configuration checks still apply; the initialization JSON success line
alone does not establish readiness. Missing creation/exclusive assertions, a durable Store, or an
existing/pending/malformed receipt refuses. Each genuinely new ephemeral instance needs its own
truthful creation attestation; never point this flow at retained state.

## Later artifact updates and identity-domain changes

After completion, continuity follows the declared stable identity domain: tracked provider name,
canonical plugin identity, principal format/declaration and declared domain values. Routine artifact
or TTL/settings updates that preserve that domain use ordinary auth revalidation. An unrelated
unmarked provider can be rotated/removed normally. Removing a tracked provider or marker,
renaming it, substituting the canonical plugin, or changing OIDC issuer/audience/client domain
values refuses ordinary startup. Pending transitions remain bound to exact artifacts/settings
and effective configuration.

If new artifacts/settings provably leave every identity output unchanged, the operator-only cold
`reauthorize` action accepts a receipt with `version: 1`, `baseline_sha256`,
`previous_requirements_sha256`, new inspected `requirements`, `identity_outputs_unchanged: true`,
`continuity_evidence_sha256`, `witness` and an embedded cold `attestation`. Its
`attestation.plan_sha256` names the baseline. It requires a completed baseline, fresh quiescence
and unchanged lineage/format; it cannot authorize a genuine principal-output remap. Copy
`baseline_sha256` from `inspect.principal_receipt_baseline_sha256`,
`previous_requirements_sha256` from `inspect.principal_receipt_requirements_sha256`, and
`requirements` from `inspect.requirements`.

```sh
busbar --config CONFIG --providers PROVIDERS --principal-transition reauthorization.json --transition-action reauthorize
```

A genuine principal-output remap requires another cold `prepare` → `check` → `apply` → `verify`
transition. Preparation binds the exact completed predecessor and conditional replacement protects
it. Map active held principals for each changed domain using the predecessor's `held_principals`,
even when they lack live keys/groups. Historical hold strings are retained evidence, not additional
aliases to map. Prove newly affected historical tombstones rather than treating prior unaffected
status as permanent exemption.
Predecessor plans, historical groups, tombstones and denial holds remain part of the chain.
The same pending-fence and lost-reply recovery rules apply to each successive transition.
