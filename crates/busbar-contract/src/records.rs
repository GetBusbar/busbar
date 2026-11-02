// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MONEY-PATH DURABLE RECORD SHAPES — the data types a `db` plugin (SQLite built-in, Postgres,

/// Atomic correction vocabulary for the existing raw usage ledger.
pub mod correction;

/// A kind-tagged scope reference — e.g. `{ kind: "pool", value: "fast" }`. The generic
/// admission-topology substrate: everywhere busbar used
/// to name "which pool" with a bare `String`, it now names "which scope, of what kind" with this
/// pair. `kind` is a plain `String`, deliberately NEVER a closed enum — a closed set here would
/// repeat the exact mistake this type exists to fix one level up (a hardcoded field per new thing
/// routed through admission). Each admission call site that cares about a specific kind (pool
/// admission, budget scoping) is the thing that knows which kind string it expects; `ScopeRef`
/// itself stays kind-agnostic, structurally unable to privilege "pool" over any future kind (a
/// tool plane's tool or server, an agent plane's delegate-target agent, …).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ScopeRef {
    pub kind: String,
    pub value: String,
}

impl ScopeRef {
    /// Build a `kind: "pool"` scope — today's only kind, and the one every wire-compat shim in
    pub fn pool(value: impl Into<String>) -> Self {
        ScopeRef {
            kind: "pool".to_string(),
            value: value.into(),
        }
    }
}

/// THE SCOPE-KIND WIRE CONVENTION. A [`ScopeRef`] kind beyond the built-in `pool` (core's own
pub mod scope_kinds {
    /// The frozen wire-field name for a scope `kind` — `allowed_{kind}s`.
    pub fn wire_field_for(kind: &str) -> String {
        format!("allowed_{kind}s")
    }

    /// The scope kind a wire field carries, or `None` if the field is not an `allowed_*` scope
    pub fn kind_for_wire_field(field: &str) -> Option<String> {
        field
            .strip_prefix("allowed_")
            .and_then(|rest| rest.strip_suffix('s'))
            .map(|k| k.to_string())
    }
}

/// The KIND-PARTITIONED wire shape for [`VirtualKey::allowed_scopes`] (1.6.0): each scope kind gets
mod virtual_key_wire {
    use super::{scope_kinds, ScopeRef, VirtualKey};
    use std::collections::BTreeMap;

    /// The mirror struct that IS the persistence wire contract for [`VirtualKey`]. Field names,
    /// order and defaults must stay in lockstep with the in-memory struct; the only divergence is
    /// the scope partition documented on the module.
    #[derive(serde::Serialize, serde::Deserialize)]
    pub(super) struct VirtualKeyWire {
        pub id: String,
        pub generation_hash: String,
        pub name: String,
        #[serde(default)]
        pub allowed_pools: Option<Vec<String>>,
        /// The per-kind plane scope grants, each under its `allowed_{kind}s` wire field. Flattened
        /// so a registered kind's field sits inline exactly where its named field used to
        /// (`allowed_agents`/…, one per plane-declared kind), and an empty map emits nothing — so a
        /// pool-only key's wire shape is byte-identical to the pre-generalization one.
        #[serde(flatten)]
        pub allowed_by_kind: BTreeMap<String, Vec<String>>,
        pub enabled: bool,
        pub created_at: u64,
        #[serde(default)]
        pub group: Option<String>,
        #[serde(default)]
        pub labels: std::collections::BTreeMap<String, String>,
        #[serde(default)]
        pub expires_at: Option<u64>,
        #[serde(default)]
        pub deleted_at: Option<u64>,
        #[serde(default)]
        pub revision: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub idp_subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub binding_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub minted_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub idp_provider: Option<String>,
    }

    /// The per-kind wire partition: `(allowed_pools, {allowed_{kind}s → values})`. The map carries
    pub(super) type ScopePartition = (Option<Vec<String>>, BTreeMap<String, Vec<String>>);

    /// Partition `allowed_scopes` into the per-kind wire fields. Total and lossless: every
    pub(super) fn partition_scopes(scopes: &Option<Vec<ScopeRef>>) -> ScopePartition {
        let Some(list) = scopes else {
            return (None, BTreeMap::new());
        };
        let mut pools = Vec::new();
        let mut by_kind: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for sr in list {
            if sr.kind == "pool" {
                pools.push(sr.value.clone());
            } else {
                by_kind
                    .entry(scope_kinds::wire_field_for(&sr.kind))
                    .or_default()
                    .push(sr.value.clone());
            }
        }

        (Some(pools), by_kind)
    }

    /// Reassemble the per-kind wire fields into kind-tagged scopes. All three absent = the
    pub(super) fn assemble_scopes(
        pools: Option<Vec<String>>,
        by_kind: BTreeMap<String, Vec<String>>,
    ) -> Option<Vec<ScopeRef>> {
        let scope_fields: Vec<(String, Vec<String>)> = by_kind
            .into_iter()
            .filter_map(|(field, values)| {
                scope_kinds::kind_for_wire_field(&field).map(|kind| (kind, values))
            })
            .collect();
        if pools.is_none() && scope_fields.is_empty() {
            return None;
        }
        let mut list = Vec::new();
        list.extend(pools.into_iter().flatten().map(ScopeRef::pool));

        for (kind, values) in scope_fields {
            list.extend(values.into_iter().map(|value| ScopeRef {
                kind: kind.clone(),
                value,
            }));
        }
        Some(list)
    }

    impl serde::Serialize for VirtualKey {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let (allowed_pools, allowed_by_kind) = partition_scopes(&self.allowed_scopes);
            VirtualKeyWire {
                id: self.id.clone(),
                generation_hash: self.generation_hash.clone(),
                name: self.name.clone(),
                allowed_pools,
                allowed_by_kind,
                enabled: self.enabled,
                created_at: self.created_at,
                group: self.group.clone(),
                labels: self.labels.clone(),
                expires_at: self.expires_at,
                deleted_at: self.deleted_at,
                revision: self.revision,
                idp_subject: self.idp_subject.clone(),
                binding_mode: self.binding_mode.clone(),
                minted_by: self.minted_by.clone(),
                idp_provider: self.idp_provider.clone(),
            }
            .serialize(s)
        }
    }

    impl<'de> serde::Deserialize<'de> for VirtualKey {
        fn deserialize<D>(d: D) -> Result<VirtualKey, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let w = VirtualKeyWire::deserialize(d)?;
            Ok(VirtualKey {
                id: w.id,
                generation_hash: w.generation_hash,
                name: w.name,
                allowed_scopes: assemble_scopes(w.allowed_pools, w.allowed_by_kind),
                enabled: w.enabled,
                created_at: w.created_at,
                group: w.group,
                labels: w.labels,
                expires_at: w.expires_at,
                deleted_at: w.deleted_at,
                revision: w.revision,
                idp_subject: w.idp_subject,
                binding_mode: w.binding_mode,
                minted_by: w.minted_by,
                idp_provider: w.idp_provider,
            })
        }
    }
}

/// A virtual key issued by busbar (distinct from upstream provider keys) - a PURE AUTH binding
/// (1.5.0): identity + pool grants + at most one `groups:` binding. Keys carry NO inline
/// limits: every cap (requests / tokens / budget / concurrent) lives on the bound group's chain,
/// so policy is mutable in config/store without re-issuing the credential.
/// Serde note: `Serialize`/`Deserialize` are HAND-IMPLEMENTED in [`virtual_key_wire`] (the
/// kind-partitioned scope wire, 1.6.0 P0) - keep the wire mirror struct's fields/defaults in
/// lockstep with this struct when adding a field.
///
/// `Default` (1.6.0) is a construction convenience only — `..Default::default()` lets a call site
/// name the fields it cares about and leave the rest at their zero value (empty id, `enabled:
/// false`, no scopes, `None` attribution). It is NEVER a valid stored key on its own; every real
/// mint sets `id`/`generation_hash`/`enabled` explicitly.
#[derive(Clone, PartialEq, Default)]
pub struct VirtualKey {
    pub id: String,
    /// A ROTATION FINGERPRINT, not a lookup credential. For a 1.5.0 signed-token key this is the
    /// non-authenticating `binding:<id>:<generation>` marker (the token itself is the credential);
    /// `verify_token` reads it ONLY after resolving the key by `sub`, to compare against the
    /// token's `generation` claim and detect a stale (pre-rotation) token. It is never looked up
    /// BY, so it deliberately carries no uniqueness constraint. (Named `generation_hash` rather
    /// than `key_hash` for exactly this reason — the 1.4.x hashed-secret shape this field used to
    /// double as a lookup key for was retired in 1.5.0; see `docs/migration-1.5.md`.)
    pub generation_hash: String,
    pub name: String,
    /// Scopes this key may target, kind-tagged (`ScopeRef`). `None` = ALL scopes of every kind (the
    /// grant was omitted at mint); `Some(list)` = exactly those scopes; `Some([])` = NO scopes (an
    /// empty list is the empty set, never "all"). On the WIRE this partitions by kind into
    /// `allowed_pools` / `allowed_agents` / one field per plane-declared kind (the pool-only shape
    /// stays byte-identical to the pre-generalization `allowed_pools: Option<Vec<String>>`): see
    /// [`virtual_key_wire`].
    pub allowed_scopes: Option<Vec<ScopeRef>>,
    pub enabled: bool,
    pub created_at: u64,
    /// The `groups:` bucket this key charges through (at most one; the chain walks `parent` up
    /// from here). `None` = no group: the key is authed + UNLIMITED (access only).
    pub group: Option<String>,
    /// Optional operator-supplied labels attached at mint (e.g. `{"team": "growth"}`), echoed onto
    /// per-key metric series so external dashboards can `sum by (team)` WITHOUT busbar knowing what
    /// "team" means. Never interpreted by enforcement. BTreeMap for a deterministic label order.
    pub labels: std::collections::BTreeMap<String, String>,
    /// Principal-level hard expiry (distinct from a signed token's own `exp` claim — this is the
    /// KEY's, checked on every resolution regardless of which token names it). `None` = never.
    pub expires_at: Option<u64>,
    /// TOMBSTONE marker. `None` = live. `Some(ts)` = this key was hard-deleted at `ts`: `enabled`
    /// is false, every credential row for it has been destroyed, and the id will never be
    /// reissued — but the row itself (id/name/group/labels) is KEPT so anything that attributes by
    /// key id (billing, audit) keeps resolving forever. See [`RecordStore::delete_key`].
    pub deleted_at: Option<u64>,
    /// Store-global monotonic revision, bumped on every mutation to this row. Used by
    /// [`RecordStore::list_keys_since`] for incremental hydration. `0` for a row a pre-revision backend
    /// never stamped (treated as "always changed" by a delta consumer, which is safe — a bare
    /// full-scan degrades to correct-but-inefficient, never incorrect).
    pub revision: u64,
    /// The IdP SUBJECT recorded at mint for a PERSONAL (user-bound) token — ATTRIBUTION ONLY (1.6.0).
    /// `None` for every key minted before this field existed and for app/service tokens (which are
    /// not tied to a live human). This is the honest, buildable half of "user-bound": it records WHO
    /// minted the personal token so per-user budget/audit can attribute to a named person. It is NOT
    /// a per-use IdP introspection floor (standard OIDC cannot provide that; see the auth design
    /// review C1) — busbar never re-checks this subject against the IdP on use. Trailing `Option` for
    /// backward-compatible deserialize (existing keys read `None`).
    pub idp_subject: Option<String>,
    /// The BINDING MODE this key was minted under (1.6.0): `"time-bound"` (app/service token, no
    /// identity tie), `"user-bound"` (personal, records `idp_subject`, short-lived + client
    /// re-exchange), or `"both"`. `None` = a key minted before binding modes existed (treated as the
    /// legacy time-bound-by-`exp` behavior). Mirrors the `auth.policy` `BindingMode` wire spelling;
    /// kept a `String` here because the protocol-agnostic api crate carries no config enum.
    pub binding_mode: Option<String>,
    /// PROVENANCE: the principal id (an app-admin's key/subject) that minted this key (1.6.0). Set on
    /// APP/service tokens, whose defining feature is that they OUTLIVE their minter — offboarding the
    /// minter revokes only the minter's personal token, never these (auth design H2/H3). Recorded so
    /// an operator can "list all tokens minted-by X" for re-attestation and so per-role MINT-CEILING
    /// accounting can count how many an app-admin has minted. `None` for self-minted personal tokens
    /// and pre-field keys. Provenance, NOT an automatic revocation trigger.
    pub minted_by: Option<String>,
    /// KERNEL-ONLY PROVENANCE (Q128 u31): the identity-provider instance that minted a self-serve
    /// key, so another provider asserting the same subject is refused. Persisted with the row and
    /// NEVER served: no admin key view carries it, and the key's `labels` stay exactly what the
    /// operator set (1.5.5 wrote a self-serve key with empty labels, v1.5.5
    /// crates/busbar/src/governance/state.rs:487). `None` for every other key and for a self-serve
    /// key minted before the field existed (it adopts the first provider that logs in).
    pub idp_provider: Option<String>,
}

impl VirtualKey {
    /// Whether this key may target the scope `(kind, value)`.
    pub fn scope_allowed(&self, kind: &str, value: &str) -> bool {
        match &self.allowed_scopes {
            None => true,
            Some(list) => list.iter().any(|s| s.kind == kind && s.value == value),
        }
    }

    /// `false` once this key has been tombstoned (`delete_key`). Every admin-mutation existence
    pub fn is_live(&self) -> bool {
        self.deleted_at.is_none()
    }
}

impl std::fmt::Debug for VirtualKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualKey")
            .field("id", &self.id)
            .field(
                "generation_hash",
                &if self.generation_hash.is_empty() {
                    "<absent>"
                } else {
                    "<redacted; present>"
                },
            )
            .field("name", &self.name)
            .field("allowed_scopes", &self.allowed_scopes)
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .field("group", &self.group)
            .field("labels", &self.labels)
            .field("expires_at", &self.expires_at)
            .field("deleted_at", &self.deleted_at)
            .field("revision", &self.revision)
            .field("idp_subject", &self.idp_subject)
            .field("binding_mode", &self.binding_mode)
            .field("minted_by", &self.minted_by)
            .field("idp_provider", &self.idp_provider)
            .finish()
    }
}

/// A credential kind's storage form for [`CredentialMeta::secret_form`]/[`CredentialSecret::secret`]:
/// whether a `secret` value exists at all, and if so whether it is recoverable (the store hands the
/// plaintext back, needed for symmetric schemes like SigV4 HMAC where verification requires the same
/// value the client signed with) or a one-way digest (verified by re-hashing the presented value,
/// never handed back). A future kind MUST pick one explicitly — there is no default — so a digest-only
/// scheme can never accidentally inherit a recoverable kind's plaintext-storage pattern by omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecretForm {
    /// No `secret` value at all (the credential's `public_id` alone is the whole check — not used by
    /// any kind today, reserved for a future presence-only credential shape).
    None,
    /// The store returns the plaintext `secret` on demand (SigV4: HMAC verification needs the exact
    /// value the client signed with, so it cannot be hashed).
    Recoverable,
    /// The store never returns the plaintext; a presented value is checked by re-deriving and
    /// comparing a one-way digest.
    Digest,
}

/// A credential verified by ROW LOOKUP from a wire-supplied public identifier — the generalized
/// replacement for the AWS-specific `AwsCredential`/`aws_credentials`, which was vendor-shaped
/// rather than designed: it only ever held SigV4 credentials under an AWS-specific name. A kind
/// belongs here ONLY if its verification path resolves a row FROM a wire-supplied
/// public identifier — bearer/signed-token auth is deliberately NEVER represented here:
/// `GovState::verify_token` never looks up a row, it only compares [`VirtualKey::generation_hash`]
/// (a post-resolution fingerprint) against the token's own `generation` claim. Today's only `kind`
/// is the request-signing auth's (`public_id` = its access key id); a future auth mechanism (mTLS,
/// HTTP Basic, …) is a new `kind` value on this SAME type, not a new type/table/trait-method set —
/// that repeatable-accretion pattern is exactly what this generalization exists to close off.
///
/// NEVER carries the secret — see [`CredentialSecret`] for the one place that does. Used by every
/// listing/admin-API path, so a `SELECT *`-shaped bug in a backend cannot leak a secret through this
/// type: there is no field to leak.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CredentialMeta {
    pub id: String,
    /// The owning `VirtualKey.id`.
    pub key_id: String,
    /// Allowlisted by callers, not this type — today only the request-signing auth's kind. The
    /// admission rule for adding a new value: only if that kind's verification path resolves a row
    /// from a wire-supplied public identifier (see the type doc).
    pub kind: String,
    /// 0 or 1. Bounds credential cardinality to exactly two rows per `(key_id, kind)`, which is what
    /// makes safe OVERLAP-WINDOW rotation possible: mint into the free slot, hand out the new
    /// credential, then revoke the old slot once callers have migrated — never a window with zero
    /// live credentials of that kind, and never an unbounded pile of old ones either.
    pub slot: u8,
    /// The non-secret, wire-supplied lookup handle (sigv4: the AccessKeyId carried in the
    /// `Authorization` header's `Credential=` field).
    pub public_id: String,
    pub secret_form: SecretForm,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: Option<u64>,
    /// `Some(ts)` once this SPECIFIC credential has been revoked (independent of the owning key —
    /// this is what makes "rotate a leaked SigV4 secret without touching the key's bearer token or
    /// re-minting anything" possible). Distinct from the key-level revocation denylist, which blocks
    /// EVERY credential of a subject at once; this blocks only this one row.
    pub revoked_at: Option<u64>,
    pub revoke_reason: Option<String>,
    /// Store-global monotonic revision — see [`VirtualKey::revision`].
    #[serde(default)]
    pub revision: u64,
}

impl CredentialMeta {
    /// Whether this credential currently admits (not revoked, not expired as of `now`).
    pub fn is_live(&self, now: u64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|exp| now < exp)
    }
}

/// [`CredentialMeta`] plus the actual secret material. Reachable from exactly two places: the verify
/// path's hydration (SigV4 admission needs the plaintext in-process — the hot path is FORBIDDEN from
/// a synchronous store call, so this is what the boot/refresh hydrate carries) and the one-time mint
/// response. `secret` carries the versioned envelope format `"v1:<scheme>:<payload>"` (e.g.
/// `"v1:plain:…"` today; a future `"v1:aead:<kid>:<nonce>:<ct>"` for at-rest encryption needs no
/// schema change, just a new scheme tag) — never LOG it raw.
///
/// DOES carry `Serialize`/`Deserialize` — this is the successor to `AwsCredential` (which also
/// carried the plaintext secret and also derived serde), not to the old `AwsKeyEntry` (a purely
/// in-memory type that withheld it): a real plugin `RecordStore` crosses the plugin ABI as JSON over a
/// ptr+len boundary (see `plugin-abi`), and this type is exactly what a backend both persists and
/// returns across that wire, so the derive is load-bearing, not optional. The leak surface this
/// closes is DEBUG-LOGGING (`tracing` records via `Debug`, never serde), so that is where the
/// redaction lives: the manual `Debug` below never prints `secret`, mirroring
/// `VirtualKey`'s own `generation_hash` — same pattern, same reasoning, applied consistently.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CredentialSecret {
    pub meta: CredentialMeta,
    /// SECRET-EQUIVALENT for a `Recoverable`-form credential — never log it. Format
    /// `"v1:<scheme>:<payload>"`.
    pub secret: String,
}

impl CredentialSecret {
    /// Extract the raw plaintext for a `"v1:plain:<payload>"`-scheme secret — the ONLY scheme that
    pub fn plaintext(&self) -> Option<&str> {
        self.secret.strip_prefix("v1:plain:")
    }
}

impl std::fmt::Debug for CredentialSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialSecret")
            .field("meta", &self.meta)
            .field(
                "secret",
                &if self.secret.is_empty() {
                    "<absent>"
                } else {
                    "<redacted; present>"
                },
            )
            .finish()
    }
}

/// THE CANONICAL RESERVED UNIT NAMES (1.6.0 M1b). The reserved four pricing tiers are no longer a
pub const UNIT_INPUT: &str = "input";
pub const UNIT_OUTPUT: &str = "output";
pub const UNIT_CACHE_READ: &str = "cache_read";
pub const UNIT_CACHE_WRITE: &str = "cache_write";

/// The reserved four, in canonical order — the set the pricer prices via the `RateNanos` tiers and
pub const RESERVED_UNITS: [&str; 4] = [UNIT_INPUT, UNIT_OUTPUT, UNIT_CACHE_READ, UNIT_CACHE_WRITE];

/// One model's accumulated billable-unit counts inside a [`UsageLedger`]. RAW counts, never money:
/// every dollar figure is DERIVED at read time as `units x current rate card` (units are the ledger;
/// dollars are always derived, never stored as truth).
///
/// (1.6.0 M1b) `usage_units` is the SOLE neutral usage representation: the reserved four
/// (`input`/`output`/`cache_read`/`cache_write`) ride as ordinary map keys BESIDE every open
/// (non-reserved) keyed count. Opaque `key → count` DATA the store never interprets. An
/// all-empty row serializes to `{"model":…}` (the map is skipped when empty); a 1.5.x persisted row
/// with the old scalar `tokens` field is read through plugin-loader's legacy adapter on a 1.5.x
/// store, and upgraded on disk by the store plugin's own `migrate()`.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ModelTokens {
    pub model: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub usage_units: std::collections::BTreeMap<String, u64>,
}

impl ModelTokens {
    /// This model's count for one reserved tier (0 if absent).
    pub fn tier(&self, unit: &str) -> u64 {
        self.usage_units.get(unit).copied().unwrap_or(0)
    }

    /// Total units across every key (saturating — counts are upstream-controlled).
    pub fn total(&self) -> u64 {
        self.usage_units
            .values()
            .fold(0u64, |acc, v| acc.saturating_add(*v))
    }

    /// All four tiers zero AND no open units (nothing to persist / flush).
    pub fn is_zero(&self) -> bool {
        self.usage_units.values().all(|v| *v == 0)
    }
}

/// The TOKEN LEDGER for one (bucket, window): the request count plus per-(model, tier) token
/// counts. This replaces the old scalar `Usage { spend_cents, tokens, requests }` - no dollar
/// field crosses the store boundary; spend is recomputed from `ledger x rate_card` at read time,
/// so correcting a rate is a config edit, never a data migration.
///
/// `models` is a Vec (not a map): the models one bucket actually used is small, order is
/// deterministic, and consumers do a few multiply-adds over it.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct UsageLedger {
    /// ADMISSION count: every admitted request, NEVER refunded - the `requests`-limit truth. A
    /// failed request still consumed a request slot, so a caller cannot escape the requests cap by
    /// hammering failures.
    pub requests: u64,
    /// BILLABLE request count: admitted requests MINUS the non-2xx refunds - the flat-fee base
    /// (the fee bills 2xx only), so budget SPEND derives from this, not from `requests`.
    /// `#[serde(default)]` so a pre-split persisted row deserializes with 0; the engine's
    /// `hydrate_budgets` seeds it from `requests` for such a row.
    #[serde(default)]
    pub billable_requests: u64,
    pub models: Vec<ModelTokens>,
}

impl UsageLedger {
    /// This model's summed billable units (across every unit key), if the model is present.
    pub fn tokens_for(&self, model: &str) -> Option<u64> {
        self.models
            .iter()
            .find(|m| m.model == model)
            .map(ModelTokens::total)
    }

    /// Total TOKENS across every model — the reserved token classes only (the scalar `tokens`
    pub fn total_tokens(&self) -> u64 {
        RESERVED_UNITS
            .iter()
            .fold(0u64, |acc, u| acc.saturating_add(self.total_tier(u)))
    }

    /// Summed count of one reserved tier across every model — the durable counterpart of the
    fn total_tier(&self, unit: &str) -> u64 {
        self.models
            .iter()
            .fold(0u64, |acc, m| acc.saturating_add(m.tier(unit)))
    }

    /// UNCACHED-INPUT tokens across every model — the durable counterpart of the `tokens_input`
    pub fn total_input(&self) -> u64 {
        self.total_tier(UNIT_INPUT)
    }

    /// OUTPUT tokens across every model — the durable counterpart of the `tokens_output` cap.
    pub fn total_output(&self) -> u64 {
        self.total_tier(UNIT_OUTPUT)
    }

    /// CACHE-READ tokens across every model — the durable counterpart of the `tokens_cache_read`
    pub fn total_cache_read(&self) -> u64 {
        self.total_tier(UNIT_CACHE_READ)
    }

    /// Apply one signed per-model unit delta, flooring every counter at 0 (a refund can never
    pub fn apply_model_delta(&mut self, delta: &ModelTokensDelta) {
        let entry = match self.models.iter_mut().find(|m| m.model == delta.model) {
            Some(m) => m,
            None => {
                self.models.push(ModelTokens {
                    model: delta.model.clone(),
                    ..Default::default()
                });
                self.models.last_mut().expect("just pushed")
            }
        };

        for (key, d) in &delta.usage_units {
            let cur = entry.usage_units.entry(key.clone()).or_insert(0);
            *cur = cur.saturating_add_signed(*d);
        }
    }

    /// Apply a whole [`UsageDelta`] (admission requests + billable requests + every model row),
    pub fn apply_delta(&mut self, delta: &UsageDelta) {
        self.requests = self.requests.saturating_add_signed(delta.requests);
        self.billable_requests = self
            .billable_requests
            .saturating_add_signed(delta.billable_requests);
        for m in &delta.models {
            self.apply_model_delta(m);
        }
    }
}

/// One model's signed unit delta inside a [`UsageDelta`] — the fleet-additive flush primitive's
/// per-model payload. (1.6.0 M1b) The signed twin of [`ModelTokens::usage_units`]: one name-keyed
/// map carrying the reserved four AND every open unit. `#[serde(default, skip_serializing_if)]` so
/// an all-zero delta serializes to `{"model":…}`.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ModelTokensDelta {
    pub model: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub usage_units: std::collections::BTreeMap<String, i64>,
}

impl ModelTokensDelta {
    /// Every unit delta zero (nothing to send for this model).
    pub fn is_zero(&self) -> bool {
        self.usage_units.values().all(|d| *d == 0)
    }
}

/// The additive cross-node reconciliation payload for one (bucket, window): a signed requests
/// delta plus per-(model, tier) signed TOKEN deltas. No dollar delta crosses the wire - each node
/// derives spend locally from its own rate card.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct UsageDelta {
    /// Signed delta of the admission (never-refunded) request count.
    pub requests: i64,
    /// Signed delta of the billable (fee-base, refundable) request count.
    #[serde(default)]
    pub billable_requests: i64,
    pub models: Vec<ModelTokensDelta>,
}

impl UsageDelta {
    /// Nothing to flush (both request deltas zero and every model delta zero).
    pub fn is_zero(&self) -> bool {
        self.requests == 0 && self.billable_requests == 0 && self.models.iter().all(|m| m.is_zero())
    }
}

/// One per-(key, model, provider) metering accumulation from a completed response — RAW consumption
/// counts, never money. Spend is DERIVED at read time from the operator's configured prices, and a
/// third party with its own (special/negotiated) price catalog reconstructs cost from these counts:
/// input, output, cache-read, and cache-creation tokens all price differently, so each is carried
/// separately (design: expose the inputs of the cost computation, not just busbar's own result).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MeteringDelta {
    pub key_id: String,
    /// The UTC-day bucket this response is attributed to; derived from the request's pinned
    /// header-arrival epoch, same as the budget charges.
    pub bucket: u64,
    /// The SERVING lane's configured model name (post-failover — the lane that actually answered).
    pub model: String,
    /// The serving lane's provider name.
    pub provider: String,
    /// Uncached input tokens (the normalized additive-cache convention, per `billing::TokenUsage`).
    pub tokens_input: u64,
    pub tokens_output: u64,
    pub tokens_cache_read: u64,
    /// Renamed from `tokens_cache_creation`: the identical concept as `TierTokens::cache_write`
    /// above, just named differently because this type was added later without matching its
    /// sibling. Renamed to match while everything on this seam is still unreleased.
    pub tokens_cache_write: u64,
    /// The number of completed responses this delta accumulates. On the wire (not derivable by the
    /// store) because a delta produced by a write-behind flush can coalesce more than one response
    /// under the same (key, bucket, model, provider) key — the store cannot infer that count from
    /// the token fields alone (a zero-token flat-fee response contributes to `requests` but nothing
    /// else).
    pub requests: u64,
    /// BILLABLE portion of `requests` (admitted minus non-2xx refunds) — the durable ledger was
    /// missing this despite `UsageDelta`/`UsageLedger` (the rate-limit ledger) carrying it, so the
    /// billing ledger could not distinguish a charged request from a refunded/cached one without
    /// re-deriving it. `#[serde(default)]` so a pre-field persisted delta still deserializes.
    #[serde(default)]
    pub billable_requests: u64,
    /// The key's `group` AT THE TIME this response was served, denormalized onto the row so
    /// group-level rollups stay correct even if the key is later regrouped or PII-scrubbed. Empty
    /// string = no group, matching `VirtualKey::group`'s `None`.
    #[serde(default)]
    pub key_group_at_use: String,
    /// Which price table was in force when this usage occurred, so a later price-table correction
    /// cannot silently re-price historical buckets with no record that it happened. Empty = not
    /// tracked (a pre-field persisted delta, or an operator not using versioned pricing).
    #[serde(default)]
    pub pricing_version: String,
    /// **WHEN THIS CELL'S PRICE STARTED**, in wall-clock milliseconds: the `effective_from` of the
    /// dated rate-card entry in force when these counts were accrued (DECISION #79).
    ///
    /// A TIMESTAMP, NEVER A VERSION, and the difference is the whole of why this field is not
    /// [`Self::pricing_version`]. A version names an entry, so it can only ever resolve FORWARD: a
    /// signed back-dated correction appended later could never reach a row that already named the
    /// entry it corrects. An INSTANT resolves against entries that did not exist when the row was
    /// written, which is what keeps the history recoverable backward and what makes "the ratecard
    /// was wrong" a repairable statement rather than a lost one.
    ///
    /// It is also the only thing that gives a UTC-DAY bucket an instant finer than the day. A
    /// metering cell is an aggregate over `(key, bucket, model, provider)`; with nothing between
    /// midnight and midnight to resolve at, a card published at noon either repriced the whole day
    /// or none of it, and both are wrong. This joins the accrual key, so a card edit SPLITS the
    /// day's cell at the edit and each half prices at the card it was earned under. Cardinality
    /// grows by the number of card edits in a day and by nothing else.
    ///
    /// `#[serde(default)]`, so a delta persisted before this field existed reads back `0` — which
    /// is the OPENING entry's own `effective_from` and covers every instant by construction. An
    /// undated row therefore resolves to the card the deployment opened with, never to the newest
    /// card ever authored, which is the same reading the 1.5.5 migration gives a pre-history row.
    #[serde(default)]
    pub priced_from_ms: u64,
    /// **EVERY LEDGERED CLASS THE TOKEN COLUMNS DO NOT HOLD** (#71), by class name: a plane's
    /// declared classes (`tool_calls`, `bytes`, audio seconds, …), an open class of the pools plane (a
    /// rerank's search units), and a plane's reserved session count (`per_session`). The SAME counts
    /// the budget book's accrual received, mirrored onto this row by that one accrual
    /// (`GovState::record_usage`) — so the admin usage read prices exactly what the budget book
    /// prices. Additive, like every counter here. `#[serde(default, skip_serializing_if = empty)]`: a
    /// row that carries none (every 1.5.5 row, all pools-only token traffic) is byte-identical.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub usage_units: std::collections::BTreeMap<String, u64>,
}

/// One accumulated metering row read back for a bucket (the raw material of `GET usage` by_model /
/// by_key aggregations — the service aggregates in memory; buckets are bounded by (keys × models)).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MeteringRow {
    pub key_id: String,
    pub model: String,
    pub provider: String,
    pub tokens_input: u64,
    pub tokens_output: u64,
    pub tokens_cache_read: u64,
    /// Renamed from `tokens_cache_creation` — see [`MeteringDelta::tokens_cache_write`].
    pub tokens_cache_write: u64,
    pub requests: u64,
    #[serde(default)]
    pub billable_requests: u64,
    #[serde(default)]
    pub key_group_at_use: String,
    #[serde(default)]
    pub pricing_version: String,
    /// The instant this row's price started — see [`MeteringDelta::priced_from_ms`]. The read
    /// resolves the dated rate-card history AT THIS INSTANT, so the row prices against the card it
    /// was earned under rather than against the newest card ever authored.
    #[serde(default)]
    pub priced_from_ms: u64,
    /// Every ledgered class the token columns do not hold — see [`MeteringDelta::usage_units`].
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub usage_units: std::collections::BTreeMap<String, u64>,
}

/// One admin AUDIT record, as it crosses the store seam for DURABLE persistence. Mirrors the engine's
/// in-memory `admin::audit::AuditEntry` field-for-field (the hash chain is computed engine-side; a
/// store persists these verbatim and returns them verbatim, preserving the chain across a restart).
/// A store is a dumb durable sink here — it never interprets or recomputes the digest. Plain data, no
/// secret (audit records carry action/resource/outcome/principal metadata, never a credential).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    /// Monotonic sequence number (1-based within a process lineage; continues across restart).
    pub seq: u64,
    /// Unix seconds the mutation was attempted.
    pub ts: u64,
    /// `noun.verb` action (e.g. `hook.register`, `plugin.install`).
    pub action: String,
    /// The resource acted on (e.g. `hook:compress`). Never a secret.
    pub resource: String,
    /// Stable outcome token (`applied` | `rejected`).
    pub outcome: String,
    /// The authenticated principal id that attempted the mutation.
    pub principal: String,
    /// The preceding entry's `hash` (empty for the first entry of a lineage).
    pub prev_hash: String,
    /// The tamper-evidence digest over this entry's fields (computed + verified engine-side).
    pub hash: String,
}

/// The result type every `RecordStore` method returns.
pub type RecordStoreResult<T> = Result<T, RecordStoreError>;

/// A durable-store failure, carried as a human-readable message. Deliberately backend-agnostic: a
/// plugin converts its own driver error (rusqlite, a Postgres driver, …) into this at the seam, so
/// this contract crate stays free of any storage dependency. The message must never carry a secret.
#[derive(Debug)]
pub struct RecordStoreError(pub String);

impl std::fmt::Display for RecordStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "store error: {}", self.0)
    }
}
impl std::error::Error for RecordStoreError {}

impl From<String> for RecordStoreError {
    fn from(s: String) -> Self {
        RecordStoreError(s)
    }
}
impl From<&str> for RecordStoreError {
    fn from(s: &str) -> Self {
        RecordStoreError(s.to_string())
    }
}

/// Whether a plane record is in a TERMINAL (final) state or still ACTIVE. This is the sidecar column
/// that lets [`RecordStore::purge_plane_records_before`] honor a per-kind retention contract that opaque
/// `body` bytes cannot express: the `task` kind drops only TERMINAL rows older than the cutoff (an
/// interrupted task waiting on a human is exactly the old row that must survive), while the `call`
/// kind drops ALL rows older than the cutoff. Encoding "terminal" in the opaque body would hide it
/// from the backend's own retention query, so it rides as a TYPED column on the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlaneDisposition {
    /// The record may still change (a live/interrupted task, an open ledger entry) — retention must
    /// keep it regardless of age for kinds whose purge contract is terminal-only.
    Active,
    /// The record has reached a final state — eligible to be dropped once older than a purge cutoff.
    Terminal,
}

/// WHICH rows a plane-record purge may drop: every row older than the cutoff ([`Retention::Age`]),
/// or only the rows whose [`PlaneDisposition`] is [`PlaneDisposition::Terminal`]
/// ([`Retention::TerminalOnly`]). The kind's own retention contract picks it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum Retention {
    /// Every row older than the cutoff.
    #[default]
    Age,
    /// Only TERMINAL rows older than the cutoff; an ACTIVE row is kept regardless of age.
    TerminalOnly,
}

impl Retention {
    /// The retention as its wire code: [`Retention::Age`] `0`, [`Retention::TerminalOnly`] `1`.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Retention::Age => 0,
            Retention::TerminalOnly => 1,
        }
    }

    /// The retention a wire code names; an unknown code names none.
    #[must_use]
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Retention::Age),
            1 => Some(Retention::TerminalOnly),
            _ => None,
        }
    }

    /// Whether a purge under this rule drops a row of `disposition` written at `ts`, against the
    #[must_use]
    pub fn drops(self, ts: u64, before: u64, disposition: PlaneDisposition) -> bool {
        ts < before
            && match self {
                Retention::Age => true,
                Retention::TerminalOnly => disposition == PlaneDisposition::Terminal,
            }
    }
}

/// One durable PLANE RECORD — the neutral envelope the eight kind-tagged verbs read and write. Only
/// [`PlaneRecord::body`] is opaque (the protocol-specific row, serialized by the caller); every other
/// field is a TYPED sidecar column so the store can index, order and retention-sweep without ever
/// decoding the body. This is the retention-landmine fix: `{ kind, id, parent, seq, ts, disposition }`
/// stay typed even though the body is bytes, so `purge_plane_records_before` can honor a
/// terminal-only-vs-all-older distinction per kind that the pre-collapse, per-method API encoded
/// structurally.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlaneRecord {
    /// The record's KIND — `"task"`, `"task_event"`, `"call"`, `"demotion"`, … — the tag that
    /// replaces a protocol-named method. Kept a plain `String`, never a closed enum, for the same
    /// reason [`ScopeRef::kind`] is.
    pub kind: String,
    /// The record's identity within its kind (a `task_id`, an upstream `server`, …). Upsert keys on
    /// `(kind, id)`; append-only kinds carry the child id here.
    pub id: String,
    /// The PARENT this record hangs off, for append-only child kinds (a `task_event`'s task, a
    /// `call`'s principal). `None` for top-level kinds (`task`, `demotion`).
    pub parent: Option<String>,
    /// Monotonic sequence within `parent`, oldest-first ordering for append-only kinds. `0` for
    /// upsert kinds that have no per-parent chain.
    pub seq: u64,
    /// The record's timestamp (Unix seconds) — the axis `purge_plane_records_before` compares against.
    pub ts: u64,
    /// Whether retention may drop this row once older than a cutoff — see [`PlaneDisposition`].
    pub disposition: PlaneDisposition,
    /// The OPAQUE protocol row (a plane crate's serialized record). The store persists and
    /// returns it verbatim and never decodes it — the sidecar columns above carry everything the
    /// store needs to key, order and sweep.
    pub body: Vec<u8>,
}

impl PlaneRecord {
    /// This record as the borrowed view a store write takes.
    #[must_use]
    pub fn view(&self) -> PlaneRecordRef<'_> {
        PlaneRecordRef {
            kind: &self.kind,
            id: &self.id,
            parent: self.parent.as_deref(),
            seq: self.seq,
            ts: self.ts,
            disposition: self.disposition,
            body: &self.body,
        }
    }
}

/// A [`PlaneRecord`] BORROWED: what [`RecordStore::upsert_plane_record`] and
/// [`RecordStore::append_plane_record`] take, so the store door hands a store the host's ABI memory
/// as it is, with no copy on the request path. A store that keeps the
/// record copies it itself ([`PlaneRecordRef::to_record`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaneRecordRef<'a> {
    /// See [`PlaneRecord::kind`].
    pub kind: &'a str,
    /// See [`PlaneRecord::id`].
    pub id: &'a str,
    /// See [`PlaneRecord::parent`].
    pub parent: Option<&'a str>,
    /// See [`PlaneRecord::seq`].
    pub seq: u64,
    /// See [`PlaneRecord::ts`].
    pub ts: u64,
    /// See [`PlaneRecord::disposition`].
    pub disposition: PlaneDisposition,
    /// See [`PlaneRecord::body`].
    pub body: &'a [u8],
}

impl PlaneRecordRef<'_> {
    /// The owned record, for a store that keeps it.
    #[must_use]
    pub fn to_record(&self) -> PlaneRecord {
        PlaneRecord {
            kind: self.kind.to_string(),
            id: self.id.to_string(),
            parent: self.parent.map(str::to_string),
            seq: self.seq,
            ts: self.ts,
            disposition: self.disposition,
            body: self.body.to_vec(),
        }
    }
}

/// How [`RecordStore::list_plane_records`] narrows a kind's records — the neutral form of "everything of
/// this kind" vs "one parent's chain of this kind". The parent is borrowed where the caller holds it
/// (the store door passes the host's ABI string straight through) and owned where it came off a
/// wire.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlaneSelector<'a> {
    /// EVERY record of the kind, unfiltered.
    All,
    /// Only records whose [`PlaneRecord::parent`] equals this value, oldest-first by `seq`.
    Parent(std::borrow::Cow<'a, str>),
}

impl PlaneSelector<'_> {
    /// This selector owning its parent, for a request that outlives the caller's borrow.
    #[must_use]
    pub fn to_static(&self) -> PlaneSelector<'static> {
        match self {
            Self::All => PlaneSelector::All,
            Self::Parent(p) => PlaneSelector::Parent(std::borrow::Cow::Owned(p.to_string())),
        }
    }
}

/// The durable governance store — the `db` plugin contract. A backend (the built-in `SqliteStore`,
pub trait RecordStore: Send + Sync + 'static {
    /// UPSERT `key` by `key.id` — the mint path and every in-place update (rename, enable/disable,
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()>;
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>>;
    /// EVERY key, live or tombstoned (`deleted_at` set or not) — deliberately UNFILTERED, so this
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>>;
    /// TOMBSTONE `id`: the row is NOT removed. An implementation must, atomically:
    /// 1. Destroy every credential row for this key (see [`RecordStore::list_credentials`]) — secret
    ///    material must not outlive the key.
    /// 2. Set `enabled = false`, `deleted_at = now()`.
    /// 3. Leave every other field (`id`/`name`/`group`/`labels`) untouched, so anything that
    ///    attributes by key id — billing/metering rows, audit records — keeps resolving forever.
    ///    The id is never reissued.
    ///
    /// This is a CONTRACT CHANGE from an earlier hard-delete semantics: a raw row removal would
    /// make `usage_metering`-shaped durable ledgers (in a real backend) either orphan their
    /// `key_id` or require a CASCADE that destroys billing evidence — tombstoning avoids both by
    /// construction. Idempotent: deleting an already-tombstoned key is a no-op, not an error.
    ///
    /// An id that names NO ROW AT ALL is a loud error, and that is a DIFFERENT case from the
    /// idempotent one above. "Already tombstoned" means the operator's intent is satisfied and the
    /// evidence is on disk. "No such id" means it is not, and the likeliest cause is a typo or a
    /// stale id — where returning `Ok(())` tells an operator a key was revoked when nothing was
    /// touched. Same reasoning [`RecordStore::revoke_credential`] gives for its own default; the two are
    /// deliberately settled the same way.
    fn delete_key(&self, id: &str) -> RecordStoreResult<()>;

    /// Every key with `revision > since` — the INCREMENTAL hydration delta, used instead of a full
    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        Ok(self
            .list_keys()?
            .into_iter()
            .filter(|k| k.revision == 0 || k.revision > since)
            .collect())
    }

    /// The TOKEN LEDGER for one (bucket, window). `bucket_id` is a key's own budget bucket (its
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger>;

    /// Atomically compare raw pre-states and commit every replacement with its applied receipt.
    fn apply_usage_correction(
        &self,
        request: &correction::Request,
    ) -> RecordStoreResult<correction::Decision> {
        let _ = request;
        Err(RecordStoreError("usage corrections unsupported".into()))
    }

    /// Whether this implementation supplies atomic raw-usage correction acceptance.
    fn supports_usage_correction(&self) -> bool {
        false
    }

    /// Write-behind ABSOLUTE set of a bucket's window ledger. SETS (replaces) the whole
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()>;

    /// Write-behind ADDITIVE accumulate of a bucket's window ledger: adds the signed requests
    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        let mut cur = self.get_usage(bucket_id, window_start)?;
        cur.apply_delta(delta);
        self.put_usage(bucket_id, window_start, &cur)
    }

    /// Apply this complete usage batch atomically under the caller's immutable operation identity.
    fn add_usage_batch_deduped(
        &self,
        op: crate::abi::store::OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        let _ = (op, cells);
        Err(RecordStoreError("deduped usage batches unsupported".into()))
    }

    /// Whether this implementation accepts caller-owned immutable usage batch identities.
    fn supports_usage_batch_deduped(&self) -> bool {
        false
    }

    /// Whether this implementation accepts caller-owned immutable metering batch identities.
    fn supports_metering_batch_deduped(&self) -> bool {
        false
    }

    /// Apply the immutable metering body once under `op`. Replaying the same id and body
    fn add_metering_batch_deduped(
        &self,
        op: crate::abi::store::OpId,
        deltas: &[MeteringDelta],
    ) -> RecordStoreResult<()> {
        let _ = (op, deltas);
        Err(RecordStoreError(
            "deduped metering batches unsupported".into(),
        ))
    }

    /// Accumulate one completed response's RAW consumption into the per-(key, bucket, model,
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()>;

    /// Every metering row accumulated in `bucket` (a metering-bucket day start), for the usage read's
    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>>;

    /// Persist a row-looked-up credential (today: only the request-signing auth's kind) — see
    fn put_credential(&self, _secret: &CredentialSecret) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support row-looked-up credentials".to_string(),
        ))
    }

    /// Update only the envelope of an existing, unrevoked Recoverable credential, atomically
    fn rewrap_credential(
        &self,
        _expected: &CredentialSecret,
        _replacement: &str,
    ) -> RecordStoreResult<bool> {
        Err(RecordStoreError(
            "this Store does not support credential rewrap CAS".into(),
        ))
    }

    /// ATOMIC key+credential mint. Persist the bearer `VirtualKey` row AND its paired credential row
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        self.put_key(key)?;
        self.put_credential(secret)?;
        Ok(())
    }

    /// Every credential row for `key_id`, metadata only, never the secret. The admin/listing
    fn list_credentials(&self, _key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        Ok(Vec::new())
    }

    /// Revoke ONE credential by id (independent of the owning key — see
    fn revoke_credential(&self, _id: &str, _reason: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support credential revocation".to_string(),
        ))
    }

    /// Every credential row with `revision > since`, SECRET included — the incremental hydration
    fn list_credentials_since(&self, _since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        Ok(Vec::new())
    }

    /// Append one 1.5.5 admin AUDIT row. No production path writes these rows any more (1.6.0's
    fn append_audit(&self, _entry: &AuditRecord) -> RecordStoreResult<()> {
        Ok(())
    }

    /// Every persisted audit record, oldest-first (by `seq`) — the boot RESTORE source when a durable
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        Ok(Vec::new())
    }

    /// Add `sub` to the REVOCATION DENYLIST (1.5.0 signed-token keys): a minted token is stateless,
    fn add_denylist(&self, _sub: &str, _reason: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support the revocation denylist".to_string(),
        ))
    }

    /// Every denied subject id (for the boot hydrate of the in-memory denylist set). DEFAULTED to
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        Ok(Vec::new())
    }

    /// The most-recent `limit` audit records, oldest-first - the BOUNDED boot restore source. The
    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        let mut all = self.list_audit()?;
        let limit = limit as usize;
        if all.len() > limit {
            all.drain(0..all.len() - limit);
        }
        Ok(all)
    }

    /// UPSERT one plane record by `(record.kind, record.id)`, for any registered record kind.
    fn upsert_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }

    /// The opaque `body` of the record identified by `(kind, id)`, or `None` when absent.
    fn get_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        Ok(None)
    }

    /// APPEND one child plane record within `record.parent`, keyed and ordered by `record.seq`. The
    fn append_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }

    /// The opaque bodies of a kind's records, narrowed by `selector` — every record of the kind
    fn list_plane_records(
        &self,
        _kind: &str,
        _selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }

    /// Every distinct [`PlaneRecord::parent`] with at least one record of `kind` (the boot
    fn list_plane_record_parents(&self, _kind: &str) -> RecordStoreResult<Vec<String>> {
        Ok(Vec::new())
    }

    /// RETENTION: drop records of `kind` older than `before`, returning how many went. WHICH
    fn purge_plane_records_before(&self, _kind: &str, _before: u64) -> RecordStoreResult<u64> {
        Ok(0)
    }

    /// RETENTION, with the predicate named: drop records of `kind` older than `before` under
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        match retention {
            Retention::Age => self.purge_plane_records_before(kind, before),
            Retention::TerminalOnly => Ok(0),
        }
    }

    /// DELETE the record identified by `(kind, id)`; absent is a no-op. DEFAULTED to `Ok(())`.
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<()> {
        Ok(())
    }

    /// TEST-AND-SET one single-use token of `kind`, valid until `expires_at`; `true` means THIS call
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
    }

    /// IS THIS TOKEN STILL LIVE? A MULTI-USE, TIME-AND-STATE-BOUNDED CAPABILITY, and deliberately
    fn plane_token_live(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
    }
}

/// The per-request context a plane handler receives: the resolved caller identity attached to each
/// request by the auth middleware, in a form any plane can name without reaching for a
/// core-private governance type. `key` is `None` when governance is disabled (so downstream
/// enforcement is a no-op). This is a request-scoped, in-process value — not a plugin-ABI type — so
/// it is `pub` purely so an out-of-tree plane can name it; the one field it carries is the
/// already-public [`VirtualKey`].
#[derive(Clone, Debug, Default)]
pub struct PlaneRequestCtx {
    /// The resolved virtual key (or synthesized principal key), shared via `Arc`: attaching it to the
    /// request and threading it through governance/routing is then a refcount bump, never a clone of
    /// the key's `String` fields. `None` when governance is disabled (enforcement is a no-op).
    pub key: Option<std::sync::Arc<VirtualKey>>,
}

impl PlaneRequestCtx {
    /// The resolved caller key, or `None` when governance is disabled. Borrows through the `Arc` so a
    pub fn key(&self) -> Option<&VirtualKey> {
        self.key.as_deref()
    }

    /// Whether this request carries a resolved key (governance enabled). `false` is the no-op posture:
    pub fn is_governed(&self) -> bool {
        self.key.is_some()
    }
}

#[cfg(test)]
#[path = "tests/records_tests.rs"]
mod tests;
