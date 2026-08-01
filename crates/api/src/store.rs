// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The durable-store CONTRACT — the data types a `db` plugin (SQLite built-in, Postgres, Redis, …)
//! reads and writes, plus the `Store` trait itself and its error type. The plain records that cross
//! the seam live here too, so a plugin crate can name them without depending on the engine.
//!
//! These are the same records the admin API and governance enforcement speak, moved here so the
//! contract — not the engine — owns them. No I/O, no engine state: pure data.

/// A kind-tagged scope reference — e.g. `{ kind: "pool", value: "fast" }`. The generic
/// admission-topology substrate (see `generic-admission-topology-SPEC.md`): everywhere busbar used
/// to name "which pool" with a bare `String`, it now names "which scope, of what kind" with this
/// pair. `kind` is a plain `String`, deliberately NEVER a closed enum — a closed set here would
/// repeat the exact mistake this type exists to fix one level up (a hardcoded field per new thing
/// routed through admission). Each admission call site that cares about a specific kind (pool
/// admission, budget scoping) is the thing that knows which kind string it expects; `ScopeRef`
/// itself stays kind-agnostic, structurally unable to privilege "pool" over any future kind (an
/// MCP tool, an MCP server, an A2A delegate-target agent, …).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ScopeRef {
    pub kind: String,
    pub value: String,
}

impl ScopeRef {
    /// Build a `kind: "pool"` scope — today's only kind, and the one every wire-compat shim in
    /// this generalization translates a bare pool-name string into/out of.
    pub fn pool(value: impl Into<String>) -> Self {
        ScopeRef {
            kind: "pool".to_string(),
            value: value.into(),
        }
    }
}

/// The wire (de)serializer for [`VirtualKey::allowed_scopes`], keeping the JSON/YAML shape
/// BYTE-IDENTICAL to the pre-generalization `allowed_pools: Option<Vec<String>>` for the
/// pool-only case (gap #1 of the spec): on the wire this is still a plain `allowed_pools` array of
/// bare strings (or absent/null), never a `{kind, value}` object. The in-memory
/// `Option<Vec<ScopeRef>>` is translated transparently at the serde boundary. Every entry that
/// reaches this field is `kind: "pool"` by construction (a future second kind gets its OWN named
/// wire field, e.g. `allowed_mcp_servers`, per the spec — never mixed into this one), so the
/// translation is a straight `ScopeRef.value` <-> bare-string mapping in both directions.
mod allowed_scopes_wire {
    use super::ScopeRef;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S>(v: &Option<Vec<ScopeRef>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bare: Option<Vec<&str>> = v
            .as_ref()
            .map(|list| list.iter().map(|sr| sr.value.as_str()).collect());
        bare.serialize(s)
    }

    pub(super) fn deserialize<'de, D>(d: D) -> Result<Option<Vec<ScopeRef>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bare: Option<Vec<String>> = Option::deserialize(d)?;
        Ok(bare.map(|list| list.into_iter().map(ScopeRef::pool).collect()))
    }
}

/// A virtual key issued by busbar (distinct from upstream provider keys) - a PURE AUTH binding
/// (1.5.0, S1): identity + pool grants + at most one `groups:` binding. Keys carry NO inline
/// limits: every cap (requests / tokens / budget / concurrent) lives on the bound group's chain,
/// so policy is mutable in config/store without re-issuing the credential.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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
    /// Scopes this key may target, kind-tagged (`ScopeRef`). `None` = ALL scopes of every kind
    /// (the grant was omitted at mint); `Some(list)` = exactly those scopes; `Some([])` = NO
    /// scopes (C6: an empty list is the empty set, never "all"). Today every entry is `kind:
    /// "pool"` (the only registered kind); on the WIRE this still serializes/deserializes as the
    /// pre-generalization `allowed_pools: Option<Vec<String>>` — see `allowed_scopes_wire`.
    #[serde(default, rename = "allowed_pools", with = "allowed_scopes_wire")]
    pub allowed_scopes: Option<Vec<ScopeRef>>,
    pub enabled: bool,
    pub created_at: u64,
    /// The `groups:` bucket this key charges through (at most one; the chain walks `parent` up
    /// from here). `None` = no group: the key is authed + UNLIMITED (access only).
    #[serde(default)]
    pub group: Option<String>,
    /// Optional operator-supplied labels attached at mint (e.g. `{"team": "growth"}`), echoed onto
    /// per-key metric series so external dashboards can `sum by (team)` WITHOUT busbar knowing what
    /// "team" means. Never interpreted by enforcement. BTreeMap for a deterministic label order.
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
    /// Principal-level hard expiry (distinct from a signed token's own `exp` claim — this is the
    /// KEY's, checked on every resolution regardless of which token names it). `None` = never.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// TOMBSTONE marker. `None` = live. `Some(ts)` = this key was hard-deleted at `ts`: `enabled`
    /// is false, every credential row for it has been destroyed, and the id will never be
    /// reissued — but the row itself (id/name/group/labels) is KEPT so anything that attributes by
    /// key id (billing, audit) keeps resolving forever. See [`Store::delete_key`].
    #[serde(default)]
    pub deleted_at: Option<u64>,
    /// Store-global monotonic revision, bumped on every mutation to this row. Used by
    /// [`Store::list_keys_since`] for incremental hydration. `0` for a row a pre-revision backend
    /// never stamped (treated as "always changed" by a delta consumer, which is safe — a bare
    /// full-scan degrades to correct-but-inefficient, never incorrect).
    #[serde(default)]
    pub revision: u64,
}

impl VirtualKey {
    /// Whether this key may target the scope `(kind, value)` (C6: `allowed_scopes` omitted = all
    /// scopes of every kind; an explicit list is exhaustive PER KIND; an explicit empty list is NO
    /// scopes at all). The generalized replacement for the pool-only `pool_allowed` — every
    /// existing call site checking pool admission calls this as `scope_allowed("pool", pool_name)`,
    /// which is the exact same membership test over a differently-shaped list, so behavior for a
    /// pool-only config is unchanged.
    pub fn scope_allowed(&self, kind: &str, value: &str) -> bool {
        match &self.allowed_scopes {
            None => true,
            Some(list) => list.iter().any(|s| s.kind == kind && s.value == value),
        }
    }

    /// `false` once this key has been tombstoned (`delete_key`). Every admin-mutation existence
    /// check (PATCH, rotate, revoke, GET-by-id-for-display, and DELETE's own idempotency check)
    /// MUST call this — not just check `Option::is_some()` — now that `delete_key` no longer
    /// removes the row: a raw `get_key(id).is_some()` is true FOREVER for an id that ever existed,
    /// tombstoned or not. The row surviving is deliberate (billing/audit attribution keeps
    /// resolving it), but a tombstoned key must present as "not found" to every admin surface that
    /// used to mean "gone" by a row's absence.
    pub fn is_live(&self) -> bool {
        self.deleted_at.is_none()
    }
}

// MANUAL Debug that REDACTS `generation_hash`. A derived `Debug` would print the SHA-256 of the key's
// secret in PLAINTEXT — a latent credential leak any time a `VirtualKey` (or `GovCtx`, which embeds
// one and whose derived Debug delegates here transitively) is debug-logged. The hash is the stored
// authenticator (a presented secret is matched by hashing it and looking up this value), so it is
// secret-equivalent and must never reach a log. Print presence only, never the value — mirroring
// `config::GovernanceCfg`/`auth::AuthMiddleware`. All non-secret fields are shown verbatim so the
// struct stays diagnosable.
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
/// replacement for the AWS-specific `AwsCredential`/`aws_credentials` (found, mid-audit, to be
/// vendor-shaped rather than designed: it only ever held SigV4 credentials under an AWS-specific
/// name). A kind belongs here ONLY if its verification path resolves a row FROM a wire-supplied
/// public identifier — bearer/signed-token auth is deliberately NEVER represented here:
/// `GovState::verify_token` never looks up a row, it only compares [`VirtualKey::generation_hash`]
/// (a post-resolution fingerprint) against the token's own `generation` claim. Today's only `kind`
/// is `"sigv4"` (`public_id` = AccessKeyId); a future auth mechanism (mTLS, HTTP Basic, …) is a new
/// `kind` value on this SAME type, not a new type/table/trait-method set — that repeatable-accretion
/// pattern is exactly what this generalization exists to close off.
///
/// NEVER carries the secret — see [`CredentialSecret`] for the one place that does. Used by every
/// listing/admin-API path, so a `SELECT *`-shaped bug in a backend cannot leak a secret through this
/// type: there is no field to leak.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CredentialMeta {
    pub id: String,
    /// The owning `VirtualKey.id`.
    pub key_id: String,
    /// Allowlisted by callers, not this type — today only `"sigv4"`. The admission rule for adding
    /// a new value: only if that kind's verification path resolves a row from a wire-supplied
    /// public identifier (see the type doc).
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

// MANUAL Debug even though this type has no secret field — `derive(Debug)` would be equally safe
// here today, but writing it out is what makes it a compile-time-visible decision if a future field
// addition ever needs the same discipline as `CredentialSecret`'s. Kept deliberately boring.
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
/// in-memory type that withheld it): a real plugin `Store` crosses the plugin ABI as JSON over a
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
    /// exists today (HMAC verification needs the exact bytes the client signed with, so it cannot
    /// be at rest in any transformed form for a `Recoverable`-form credential). Returns `None` for
    /// any other version/scheme tag (e.g. a future `"v1:aead:…"` at-rest-encrypted form, which a
    /// caller must decrypt through a dedicated path, not this one) — callers MUST NOT fall back to
    /// using `secret` verbatim on a `None`, since that would use ciphertext (or an unrecognized
    /// future format) as if it were the plaintext HMAC key.
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

/// Per-model token counts split by PRICING TIER (input / output / cache-read / cache-write) - the
/// four token classes providers price differently. RAW counts, never money: every dollar figure is
/// DERIVED at read time as `tokens x current rate card` (tokens are the ledger; dollars are always
/// derived, never stored as truth).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct TierTokens {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

impl TierTokens {
    /// All four tiers zero (nothing to persist / flush).
    pub fn is_zero(&self) -> bool {
        self.input == 0 && self.output == 0 && self.cache_read == 0 && self.cache_write == 0
    }

    /// Total tokens across all tiers (saturating - counts are upstream-controlled).
    pub fn total(&self) -> u64 {
        self.input
            .saturating_add(self.output)
            .saturating_add(self.cache_read)
            .saturating_add(self.cache_write)
    }
}

/// One model's accumulated tier-token counts inside a [`UsageLedger`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModelTokens {
    pub model: String,
    pub tokens: TierTokens,
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
    /// The accumulated tier tokens for `model`, if any.
    pub fn tokens_for(&self, model: &str) -> Option<&TierTokens> {
        self.models
            .iter()
            .find(|m| m.model == model)
            .map(|m| &m.tokens)
    }

    /// Total tokens across every model and tier (the old scalar `tokens` view).
    pub fn total_tokens(&self) -> u64 {
        self.models
            .iter()
            .fold(0u64, |acc, m| acc.saturating_add(m.tokens.total()))
    }

    /// Apply one signed per-model tier delta, flooring every counter at 0 (a refund can never
    /// drive a durable counter negative). Allocates a model entry only on first sight.
    pub fn apply_model_delta(&mut self, delta: &ModelTokensDelta) {
        let entry = match self.models.iter_mut().find(|m| m.model == delta.model) {
            Some(m) => m,
            None => {
                self.models.push(ModelTokens {
                    model: delta.model.clone(),
                    tokens: TierTokens::default(),
                });
                self.models.last_mut().expect("just pushed")
            }
        };
        let t = &mut entry.tokens;
        t.input = t.input.saturating_add_signed(delta.tokens.input);
        t.output = t.output.saturating_add_signed(delta.tokens.output);
        t.cache_read = t.cache_read.saturating_add_signed(delta.tokens.cache_read);
        t.cache_write = t
            .cache_write
            .saturating_add_signed(delta.tokens.cache_write);
    }

    /// Apply a whole [`UsageDelta`] (admission requests + billable requests + every model row),
    /// flooring at 0.
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

/// Signed per-tier token delta (the fleet-additive flush primitive's per-model payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct TierTokensDelta {
    pub input: i64,
    pub output: i64,
    pub cache_read: i64,
    pub cache_write: i64,
}

impl TierTokensDelta {
    /// All four tiers zero (nothing to send).
    pub fn is_zero(&self) -> bool {
        self.input == 0 && self.output == 0 && self.cache_read == 0 && self.cache_write == 0
    }
}

/// One model's signed tier delta inside a [`UsageDelta`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModelTokensDelta {
    pub model: String,
    pub tokens: TierTokensDelta,
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
        self.requests == 0
            && self.billable_requests == 0
            && self.models.iter().all(|m| m.tokens.is_zero())
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
    /// sibling — a naming-drift finding from the credentials-generalization audit, fixed here since
    /// everything on this seam is still unreleased.
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
    /// group-level rollups stay correct even if the key is later regrouped or PII-scrubbed (see
    /// [`Store::scrub_key`]). Empty string = no group, matching `VirtualKey::group`'s `None`.
    #[serde(default)]
    pub key_group_at_use: String,
    /// Which price table was in force when this usage occurred, so a later price-table correction
    /// cannot silently re-price historical buckets with no record that it happened. Empty = not
    /// tracked (a pre-field persisted delta, or an operator not using versioned pricing).
    #[serde(default)]
    pub pricing_version: String,
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

/// The result type every `Store` method returns.
pub type StoreResult<T> = Result<T, StoreError>;

/// A durable-store failure, carried as a human-readable message. Deliberately backend-agnostic: a
/// plugin converts its own driver error (rusqlite, a Postgres driver, …) into this at the seam, so
/// this contract crate stays free of any storage dependency. The message must never carry a secret.
#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "store error: {}", self.0)
    }
}
impl std::error::Error for StoreError {}

impl From<String> for StoreError {
    fn from(s: String) -> Self {
        StoreError(s)
    }
}
impl From<&str> for StoreError {
    fn from(s: &str) -> Self {
        StoreError(s.to_string())
    }
}

/// The durable governance store — the `db` plugin contract. A backend (the built-in `SqliteStore`,
/// or a plugin `PostgresStore`/`ValkeyStore`/`MySqlStore`/…) implements this to persist the bounded
/// ENFORCEMENT state: virtual keys + row-looked-up credentials (today: SigV4), and per-key usage
/// counters per budget window.
///
/// The engine keeps the AUTHORITATIVE enforcement counters in memory and treats this store as a
/// write-behind durability layer (boot-hydrate + periodic flush), so every method here is off the
/// request hot path — a plain synchronous call is fine, and a backend that needs async I/O runs it
/// on its own runtime behind the sync signature. The credential/hydration-delta methods are
/// DEFAULTED so a backend with no credential support (or a lightweight test double) need not
/// implement them — see each method's own doc for its specific default behavior and why it's safe.
pub trait Store: Send + Sync + 'static {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()>;
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>>;
    /// EVERY key, live or tombstoned (`deleted_at` set or not) — deliberately UNFILTERED, so this
    /// one method serves both the admin-listing caller (which filters `deleted_at.is_none()`
    /// itself before rendering) and [`Store::list_keys_since`]'s default incremental-hydration
    /// fallback (which needs to SEE tombstones to evict cached credentials — see that method's
    /// doc). A backend must not filter here; filtering belongs at the call site that actually wants
    /// a "live only" view.
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>>;
    /// TOMBSTONE `id`: the row is NOT removed. An implementation must, atomically:
    /// 1. Destroy every credential row for this key (see [`Store::list_credentials`]) — secret
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
    /// PII erasure (nulling `name`/`labels`) is a SEPARATE, explicit operation — see
    /// [`Store::scrub_key`] — so "this key is gone" and "this key's personal data is gone" stay
    /// independently auditable.
    fn delete_key(&self, id: &str) -> StoreResult<()>;
    /// PII-erasure-only: null `name` and `labels` on an ALREADY-tombstoned key (`deleted_at` set).
    /// Every other field, and every attribution that reads this row by id, is untouched — this
    /// exists to satisfy "erase personal data" without touching financial/billing records, which is
    /// what a right-to-erasure request actually needs. Errors if `id` is unknown or not yet
    /// tombstoned (scrubbing a live key would be silent, un-auditable data loss on an active
    /// principal — go through `delete_key` first).
    ///
    /// DEFAULTED to an error so a backend that has not implemented it fails loud rather than
    /// silently no-op-ing a compliance-relevant request.
    fn scrub_key(&self, _id: &str) -> StoreResult<()> {
        Err(StoreError(
            "this Store does not support scrub_key".to_string(),
        ))
    }
    /// Every key with `revision > since` — the INCREMENTAL hydration delta, used instead of a full
    /// [`Store::list_keys`] reload on each staleness tick. UNLIKE `list_keys`, this does NOT filter
    /// tombstones: a hydrator needs to observe a newly-tombstoned key (via its `deleted_at` now
    /// being `Some`) so it can evict that key's cached credentials from its in-process map — see
    /// [`Store::list_credentials_since`] for why that eviction cannot rely on the credential rows'
    /// own deltas. `since = 0` returns every key (the boot/full-load case).
    ///
    /// DEFAULTED to a full-scan-and-filter over `list_keys` — CORRECT for any backend (it degrades
    /// to "always changed" for a row the backend hasn't stamped with a real `revision`, per
    /// `VirtualKey::revision`'s doc, and `list_keys` is unfiltered so tombstones are always visible
    /// here) but not incremental; a backend that wants real delta-fetch efficiency overrides this
    /// with an indexed `WHERE revision > ?`-shaped query.
    fn list_keys_since(&self, since: u64) -> StoreResult<Vec<VirtualKey>> {
        Ok(self
            .list_keys()?
            .into_iter()
            .filter(|k| k.revision > since)
            .collect())
    }
    /// The TOKEN LEDGER for one (bucket, window). `bucket_id` is a key's own budget bucket (its
    /// key id) OR a budget-group bucket - same shape either way. An untouched (bucket, window)
    /// reads as the empty ledger. NO dollar field crosses this seam: spend is derived at read time
    /// from `ledger x rate_card`.
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger>;

    /// Write-behind ABSOLUTE set of a bucket's window ledger. SETS (replaces) the whole
    /// requests + per-model token record. Single-writer semantics only: with multiple busbar nodes
    /// sharing one store, an absolute overwrite loses the other nodes' accruals - the fleet flush
    /// path uses [`Store::add_usage`] instead.
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()>;

    /// Write-behind ADDITIVE accumulate of a bucket's window ledger: adds the signed requests
    /// delta plus each per-(model, tier) TOKEN delta (possibly negative, e.g. a refund) to the
    /// durable record. This is the FLEET-HONEST flush primitive: N nodes each flushing their
    /// delta-since-last-flush sum to the true fleet total, where `put_usage`'s absolute overwrite
    /// would be last-writer-wins. Counters are floored at 0. No dollar delta crosses the wire.
    ///
    /// DEFAULT: a read-modify-write fallback (get + apply + put) for stores without a native
    /// atomic add - correct for a single writer; a real shared backend overrides with an atomic
    /// accumulate (SQL `UPDATE x = x + delta` UPSERT / redis `HINCRBY`).
    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        let mut cur = self.get_usage(bucket_id, window_start)?;
        cur.apply_delta(delta);
        self.put_usage(bucket_id, window_start, &cur)
    }

    /// Accumulate one completed response's RAW consumption into the per-(key, bucket, model,
    /// provider) metering row (UPSERT/add; +1 request). Metering is observability — best-effort,
    /// never consulted for enforcement.
    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()>;

    /// Every metering row accumulated in `bucket` (a metering-bucket day start), for the usage read's
    /// by-model / by-key aggregations.
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>>;

    /// Retention sweep for the (bucket_id, window_start) token ledger: purge every window whose
    /// `window_start < before`. Returns the number of windows purged. Called only from a background
    /// sweeper on a config interval — NEVER from the request path.
    ///
    /// DEFAULTED to `Ok(0)` (a no-op that reports nothing purged): a backend has no obligation to
    /// bound its own storage this way (e.g. an in-memory store already self-sweeps via a different
    /// mechanism — see `MemoryStore`'s amortized eviction), and an in-tree default that silently did
    /// nothing real would be misleading if it claimed to purge. Real durable backends (Postgres,
    /// MySQL, Valkey, SQLite) each override this with whatever's idiomatic for their storage shape
    /// (a native TTL, a partition drop, a chunked `DELETE`, …).
    fn purge_windows_before(&self, _before: u64) -> StoreResult<u64> {
        Ok(0)
    }

    /// Retention purge for the DURABLE billing ledger (`MeteringRow`/`MeteringDelta`): purge every
    /// row in `bucket`. Unlike [`Store::purge_windows_before`], this must NEVER be wired to an
    /// automatic sweeper — billing evidence is opt-in-purge-only, exactly like [`Store::delete_key`]
    /// tombstones rather than removes for the same reason. The engine's admin surface is the only
    /// intended caller, and only behind an explicit, audit-logged operator action.
    ///
    /// DEFAULTED to `Ok(0)`, same reasoning as `purge_windows_before`.
    fn purge_metering_before(&self, _bucket: &str) -> StoreResult<u64> {
        Ok(0)
    }

    /// Persist a row-looked-up credential (today: only `kind = "sigv4"`) — see [`CredentialSecret`]
    /// and the [`Store::list_credentials`] doc for the generalized-from-AWS-specific rationale.
    /// UPSERTs on `(key_id, kind, slot)`: minting into an occupied LIVE slot (not `revoked_at`) MUST
    /// fail rather than silently destroy a working credential mid-overlap-window — an explicit slot
    /// pointed at a live credential is almost certainly an operator mistake, not an intended
    /// rotation. `secret.meta.id`/`secret.meta.key_id`/`secret.meta.kind`/`secret.meta.slot` name
    /// the row; the rest of `secret.meta` plus `secret.secret` is the full row to write.
    ///
    /// DEFAULTED so the (many) lightweight test-double stores need not implement the credential
    /// surface — only a real backend does. The default is a no-op-shaped error so a misconfigured
    /// store that silently dropped a credential cannot pass as success.
    fn put_credential(&self, _secret: &CredentialSecret) -> StoreResult<()> {
        Err(StoreError(
            "this Store does not support row-looked-up credentials".to_string(),
        ))
    }

    /// ATOMIC key+credential mint. Persist the bearer `VirtualKey` row AND its paired credential row
    /// together or not at all. A real transactional backend overrides this to wrap both writes in one
    /// transaction. DEFAULT fallback: sequential writes (for test doubles with no transaction).
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> StoreResult<()> {
        self.put_key(key)?;
        self.put_credential(secret)?;
        Ok(())
    }

    /// Every credential row for `key_id`, metadata only (never the secret — see
    /// [`Store::lookup_credential_secret`] for the one place that returns it). The admin/listing
    /// surface.
    ///
    /// DEFAULTED to empty: a store with no credential support simply has none to list.
    fn list_credentials(&self, _key_id: &str) -> StoreResult<Vec<CredentialMeta>> {
        Ok(Vec::new())
    }

    /// Resolve `(kind, public_id)` to its full secret material — the verify-path / hydration
    /// lookup. `None` for an unknown `(kind, public_id)` pair (never an error: an unrecognized
    /// AccessKeyId is a normal, expected outcome of the SigV4 admit path, not a store failure).
    ///
    /// DEFAULTED to `Ok(None)`: a store with no credential support resolves nothing, so that
    /// credential kind's ingress is simply unavailable — never an auth bypass.
    fn lookup_credential_secret(
        &self,
        _kind: &str,
        _public_id: &str,
    ) -> StoreResult<Option<CredentialSecret>> {
        Ok(None)
    }

    /// Revoke ONE credential by id (independent of the owning key — see
    /// [`CredentialMeta::revoked_at`]). Idempotent. DEFAULTED to a loud error, matching
    /// [`Store::add_denylist`]'s reasoning: a silent no-op here would let an operator believe a
    /// leaked SigV4 secret was killed when it was not.
    fn revoke_credential(&self, _id: &str, _reason: &str) -> StoreResult<()> {
        Err(StoreError(
            "this Store does not support credential revocation".to_string(),
        ))
    }

    /// Every credential row with `revision > since`, SECRET included — the incremental hydration
    /// delta for the in-process verify-path cache (which must never make a synchronous store call,
    /// so it needs the actual secret material in hand, not just metadata). `since = 0` returns every
    /// row (boot/full-load).
    ///
    /// CONTRACT a hydration consumer MUST implement, not just this method: revision-based deltas
    /// CANNOT observe a hard delete (a deleted row produces no further delta — it simply stops
    /// appearing). Since [`Store::delete_key`]'s tombstone destroys every credential row for that
    /// key, a delta-only consumer that ONLY reacts to credential-row deltas would keep serving a
    /// deleted key's SigV4 credential from cache forever — an authentication bypass. The fix is on
    /// the CONSUMER side: whenever a [`Store::list_keys_since`] delta shows a key's `deleted_at`
    /// newly set, the consumer MUST evict every cached credential for that key id itself, rather
    /// than waiting for (or relying on) a corresponding credential-row delta that will never come.
    ///
    /// DEFAULTED to a full-scan-and-filter over an internal full-credential enumeration; a backend
    /// with no credential support returns empty (nothing to hydrate). Concrete backends should
    /// override for real delta-fetch efficiency once they have their own storage to query.
    fn list_credentials_since(&self, _since: u64) -> StoreResult<Vec<CredentialSecret>> {
        Ok(Vec::new())
    }

    /// Append one admin AUDIT record for DURABLE persistence (design: the audit log's durable home is
    /// the configured store — memory = ephemeral, sqlite/postgres/redis = durable). The engine keeps
    /// the hot in-memory hash-chained ring for reads and write-THROUGHs each appended entry here, so a
    /// hard crash loses ~0 entries and the ring's size bound stops pruning HISTORY (the store keeps it
    /// all). Append-only, ordered by `seq`; a store never rewrites or recomputes the digest.
    ///
    /// DEFAULTED to `Ok(())` (a no-op) so this is BACKWARD-COMPATIBLE: every existing store plugin —
    /// including already-signed dynamic-library artifacts that predate this method — keeps working
    /// unchanged, simply providing no durable audit (the RAM default's behavior). A backend that wants
    /// durable audit overrides this + [`Store::list_audit`].
    fn append_audit(&self, _entry: &AuditRecord) -> StoreResult<()> {
        Ok(())
    }

    /// Every persisted audit record, oldest-first (by `seq`) — the boot RESTORE source when a durable
    /// store is configured (the store becomes the source of truth; the hash chain is verified after
    /// load). DEFAULTED to an empty list so a store with no durable-audit support restores nothing
    /// (the RAM default) rather than forcing every backend to implement it.
    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        Ok(Vec::new())
    }

    /// Add `sub` to the REVOCATION DENYLIST (1.5.0 signed-token keys): a minted token is stateless,
    /// so revoking it means recording its subject id here. The verify path reads the denylist
    /// (`list_denylist` hydrates an in-memory set at boot; `add_denylist` updates it live) and
    /// rejects any token whose `sub` is present. Idempotent (adding an already-denied sub is a
    /// no-op). `reason` is operator metadata (audit only), never a secret.
    ///
    /// DEFAULTED to a no-op error so a store predating denylist support fails LOUD if asked to
    /// revoke (a silent success would leave a "revoked" token still valid). A real backend
    /// overrides this + `list_denylist`.
    fn add_denylist(&self, _sub: &str, _reason: &str) -> StoreResult<()> {
        Err(StoreError(
            "this Store does not support the revocation denylist".to_string(),
        ))
    }

    /// Every denied subject id (for the boot hydrate of the in-memory denylist set). DEFAULTED to
    /// empty so a store with no denylist support has nothing to deny.
    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        Ok(Vec::new())
    }

    /// The most-recent `limit` audit records, oldest-first - the BOUNDED boot restore source. The
    /// engine's ring is size-bounded, so restoring the whole (never-pruned) durable history is
    /// wasteful and, over the plugin ABI, can exceed the response size cap or OOM on a large log.
    /// Restore reads only the tail it will keep (plus the head is verified within that tail).
    ///
    /// DEFAULTED to a `list_audit` fallback + tail-truncation so every existing backend keeps working:
    /// a store that has not overridden this still restores correctly (it just materializes the full
    /// list once before truncating). A durable backend SHOULD override this with a `LIMIT`ed query so
    /// the bound is enforced at the source (in the DB / across the ABI), which is the whole point.
    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
        let mut all = self.list_audit()?;
        let limit = limit as usize;
        if all.len() > limit {
            all.drain(0..all.len() - limit);
        }
        Ok(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> VirtualKey {
        VirtualKey {
            id: "vk_1".to_string(),
            generation_hash: "deadbeefdeadbeef".to_string(),
            name: "test".to_string(),
            allowed_scopes: Some(vec![ScopeRef::pool("p")]),
            enabled: true,
            created_at: 42,
            group: Some("growth".to_string()),
            labels: std::collections::BTreeMap::from([("team".to_string(), "growth".to_string())]),
            expires_at: None,
            deleted_at: None,
            revision: 1,
        }
    }

    fn sample_credential() -> CredentialSecret {
        CredentialSecret {
            meta: CredentialMeta {
                id: "cred_1".to_string(),
                key_id: "vk_1".to_string(),
                kind: "sigv4".to_string(),
                slot: 0,
                public_id: "AKIA_TEST".to_string(),
                secret_form: SecretForm::Recoverable,
                created_at: 42,
                updated_at: 42,
                expires_at: None,
                revoked_at: None,
                revoke_reason: None,
                revision: 1,
            },
            secret: "v1:plain:s3cr3t-signing-key".to_string(),
        }
    }

    /// C6 pool-grant semantics on the runtime encoding: omitted (`None`) = ALL pools; an explicit
    /// list is exhaustive; an explicit EMPTY list is NO pools (never "all"). Exercised through
    /// `scope_allowed("pool", ...)`, the generalized replacement for the old `pool_allowed` - this
    /// is the "zero behavior change for pool-only configs" property the generalization promises.
    #[test]
    fn scope_allowed_pool_kind_c6_semantics() {
        let mut k = sample_key();
        k.allowed_scopes = None;
        assert!(k.scope_allowed("pool", "anything"), "omitted = all scopes");
        k.allowed_scopes = Some(vec![ScopeRef::pool("fast")]);
        assert!(k.scope_allowed("pool", "fast"));
        assert!(!k.scope_allowed("pool", "cold"));
        k.allowed_scopes = Some(Vec::new());
        assert!(
            !k.scope_allowed("pool", "fast"),
            "an explicit [] is the EMPTY set - no scopes, never all"
        );
    }

    /// A DIFFERENT kind never matches a `pool`-kind grant, and vice versa - `ScopeRef` is
    /// kind-agnostic and `scope_allowed` is a strict `(kind, value)` membership test, not a bare
    /// value match (gap #4: kind stays a plain string, never privileging "pool").
    #[test]
    fn scope_allowed_is_kind_specific() {
        let mut k = sample_key();
        k.allowed_scopes = Some(vec![ScopeRef::pool("fast")]);
        assert!(k.scope_allowed("pool", "fast"));
        assert!(
            !k.scope_allowed("mcp_server", "fast"),
            "same value, different kind: must not match"
        );
    }

    /// THE contract test: a config using only `allowed_pools` (bare strings, no `kind` wrapper)
    /// produces a BYTE-IDENTICAL wire shape before and after the `ScopeRef` generalization - the
    /// entire point of the wire-compat design (spec gap #1). The in-memory representation is
    /// `allowed_scopes: Vec<ScopeRef>`, but the JSON on the wire is still the plain
    /// `"allowed_pools":["fast","slow"]` array of bare strings a pre-generalization admin API
    /// client already knows how to read and write.
    #[test]
    fn allowed_pools_wire_shape_is_byte_identical_to_pre_generalization() {
        let mut k = sample_key();
        k.allowed_scopes = Some(vec![ScopeRef::pool("fast"), ScopeRef::pool("slow")]);
        let json = serde_json::to_string(&k).unwrap();
        assert!(
            json.contains(r#""allowed_pools":["fast","slow"]"#),
            "wire field must be the bare-string array under the `allowed_pools` name, no `kind` \
             wrapper anywhere: {json}"
        );
        assert!(
            !json.contains("kind"),
            "no ScopeRef {{kind, value}} shape may leak onto the wire: {json}"
        );

        // The pre-generalization wire shape a real (already-deployed) admin API client sends -
        // must deserialize into the exact ScopeRef list this test set up.
        let legacy_wire = r#"{"id":"vk_1","generation_hash":"h","name":"n","allowed_pools":["fast","slow"],"enabled":true,"created_at":1}"#;
        let back: VirtualKey = serde_json::from_str(legacy_wire).unwrap();
        assert_eq!(
            back.allowed_scopes,
            Some(vec![ScopeRef::pool("fast"), ScopeRef::pool("slow")])
        );

        // Round-trip: serialize → deserialize → identical scopes (and the C6 None/empty cases,
        // which must ALSO stay wire-identical).
        let round: VirtualKey = serde_json::from_str(&json).unwrap();
        assert_eq!(round.allowed_scopes, k.allowed_scopes);

        let mut none_grant = sample_key();
        none_grant.allowed_scopes = None;
        let json_none = serde_json::to_string(&none_grant).unwrap();
        assert!(
            json_none.contains(r#""allowed_pools":null"#),
            "omitted grant serializes as bare `null`, same as before: {json_none}"
        );

        let mut empty_grant = sample_key();
        empty_grant.allowed_scopes = Some(Vec::new());
        let json_empty = serde_json::to_string(&empty_grant).unwrap();
        assert!(
            json_empty.contains(r#""allowed_pools":[]"#),
            "explicit-empty grant serializes as a bare `[]`, same as before: {json_empty}"
        );
    }

    /// The redacting `Debug` - the guard for the structured-logging surface, since
    /// `tracing` records fields via `Debug`/`Display`, never serde - must NEVER emit the secret-
    /// equivalent `generation_hash` / `secret_access_key`. This is the leak the finding is about: any place a
    /// record reaches a log must show presence only.
    #[test]
    fn debug_redacts_secret_equivalents() {
        let key = sample_key();
        let key_dbg = format!("{key:?}");
        assert!(
            !key_dbg.contains("deadbeefdeadbeef"),
            "VirtualKey Debug leaked generation_hash: {key_dbg}"
        );
        assert!(key_dbg.contains("<redacted; present>"));

        let cred = sample_credential();
        let cred_dbg = format!("{cred:?}");
        assert!(
            !cred_dbg.contains("s3cr3t-signing-key"),
            "CredentialSecret Debug leaked the secret: {cred_dbg}"
        );
        // The AccessKeyId (public_id) is NOT secret and stays visible for diagnosability, via the
        // embedded CredentialMeta's ordinary (derived) Debug.
        assert!(cred_dbg.contains("AKIA_TEST"));
    }

    /// The `Serialize`/`Deserialize` on `VirtualKey` is a load-bearing PERSISTENCE contract (a
    /// redis-shaped store round-trips it as JSON): it MUST stay faithful, so it is emphatically NOT
    /// redacted. This pins that contract so a well-meaning "redact the Serialize too" change (which
    /// would silently corrupt every redis-persisted key) fails loudly here instead. The
    /// logging-surface leak is closed by the redacting `Debug` above, not by lossy serialization.
    /// `CredentialSecret` deliberately has NO `Serialize` at all (see its doc) — persisting the raw
    /// `secret` string is a backend-owned concern, not this crate's, so there is no equivalent
    /// round-trip test for it here.
    #[test]
    fn serialize_roundtrip_is_faithful_for_persistence() {
        let key = sample_key();
        let json = serde_json::to_string(&key).unwrap();
        assert!(
            json.contains("deadbeefdeadbeef"),
            "persistence must keep generation_hash"
        );
        let back: VirtualKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);

        // CredentialSecret DOES round-trip faithfully too — it crosses the plugin ABI wire and is
        // what a backend persists, so its Serialize/Deserialize is load-bearing (see the type doc);
        // the leak surface it must NOT have is Debug (covered by the redaction test above), not
        // serde.
        let cred = sample_credential();
        let json = serde_json::to_string(&cred).unwrap();
        assert!(
            json.contains("s3cr3t-signing-key"),
            "persistence must keep the secret material"
        );
        let back: CredentialSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, back);
    }

    /// The minimal pure-auth JSON round-trips, and the optional fields default: a row with no
    /// `allowed_pools` / `group` / `labels` / `expires_at` / `deleted_at` / `revision` deserializes
    /// to all-pools / no-group / no labels / never-expires / live / revision-0. Guards the
    /// redis-style JSON persistence for the 1.5.0 pure-auth key shape, including the fields added by
    /// the credentials-generalization redesign.
    #[test]
    fn virtual_key_minimal_json_defaults_optionals() {
        let minimal =
            r#"{"id":"vk_1","generation_hash":"h","name":"n","enabled":true,"created_at":1}"#;
        let k: VirtualKey = serde_json::from_str(minimal).unwrap();
        assert_eq!(k.allowed_scopes, None, "absent grant = all pools");
        assert_eq!(k.group, None);
        assert!(k.labels.is_empty());
        assert_eq!(k.expires_at, None);
        assert_eq!(k.deleted_at, None);
        assert_eq!(k.revision, 0);
    }

    /// `CredentialMeta::is_live` is the exact predicate the SigV4 admit path consults (in addition
    /// to the KEY-level `enabled`/denylist checks, which are unaffected by per-credential
    /// revocation): not revoked, and not expired as of `now`.
    #[test]
    fn credential_meta_is_live_checks_revocation_and_expiry() {
        let mut m = sample_credential().meta;
        assert!(m.is_live(100), "fresh credential, no expiry: live");
        m.expires_at = Some(200);
        assert!(m.is_live(100), "before expiry: live");
        assert!(!m.is_live(200), "at expiry: not live");
        assert!(!m.is_live(300), "past expiry: not live");
        m.expires_at = None;
        m.revoked_at = Some(50);
        assert!(
            !m.is_live(100),
            "revoked (even with no expiry set): not live"
        );
    }

    /// The ledger's additive delta application: model rows materialize on first sight, tiers
    /// accumulate independently, and negative deltas floor every counter at 0.
    #[test]
    fn usage_ledger_applies_deltas_and_floors_at_zero() {
        let mut l = UsageLedger::default();
        l.apply_delta(&UsageDelta {
            requests: 2,
            billable_requests: 2,
            models: vec![ModelTokensDelta {
                model: "gpt-5".to_string(),
                tokens: TierTokensDelta {
                    input: 100,
                    output: 50,
                    cache_read: 10,
                    cache_write: 5,
                },
            }],
        });
        assert_eq!(l.requests, 2);
        let t = l.tokens_for("gpt-5").unwrap();
        assert_eq!(
            (t.input, t.output, t.cache_read, t.cache_write),
            (100, 50, 10, 5)
        );
        assert_eq!(l.total_tokens(), 165);

        // A second model materializes its own row; the first is untouched.
        l.apply_delta(&UsageDelta {
            requests: 1,
            billable_requests: 1,
            models: vec![ModelTokensDelta {
                model: "haiku".to_string(),
                tokens: TierTokensDelta {
                    input: 7,
                    output: 3,
                    cache_read: 0,
                    cache_write: 0,
                },
            }],
        });
        assert_eq!(l.models.len(), 2);
        assert_eq!(l.tokens_for("gpt-5").unwrap().input, 100);

        // Over-refund floors at 0, never negative.
        l.apply_delta(&UsageDelta {
            requests: -10,
            billable_requests: -10,
            models: vec![ModelTokensDelta {
                model: "haiku".to_string(),
                tokens: TierTokensDelta {
                    input: -1000,
                    output: -1,
                    cache_read: 0,
                    cache_write: 0,
                },
            }],
        });
        assert_eq!(l.requests, 0);
        let h = l.tokens_for("haiku").unwrap();
        assert_eq!((h.input, h.output), (0, 2));
    }

    /// The default trait `add_usage` (read-modify-write fallback) accumulates through
    /// get_usage/put_usage, so a store double implementing only those two is fleet-usable
    /// (single-writer).
    #[test]
    fn default_add_usage_accumulates_via_get_put() {
        use std::sync::Mutex;
        #[derive(Default)]
        struct Double(Mutex<std::collections::HashMap<(String, u64), UsageLedger>>);
        impl Store for Double {
            fn put_key(&self, _: &VirtualKey) -> StoreResult<()> {
                Ok(())
            }
            fn get_key(&self, _: &str) -> StoreResult<Option<VirtualKey>> {
                Ok(None)
            }
            fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
                Ok(Vec::new())
            }
            fn delete_key(&self, _: &str) -> StoreResult<()> {
                Ok(())
            }
            fn get_usage(&self, b: &str, w: u64) -> StoreResult<UsageLedger> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .get(&(b.to_string(), w))
                    .cloned()
                    .unwrap_or_default())
            }
            fn put_usage(&self, b: &str, w: u64, l: &UsageLedger) -> StoreResult<()> {
                self.0.lock().unwrap().insert((b.to_string(), w), l.clone());
                Ok(())
            }
            fn add_metering(&self, _: &MeteringDelta) -> StoreResult<()> {
                Ok(())
            }
            fn list_metering(&self, _: u64) -> StoreResult<Vec<MeteringRow>> {
                Ok(Vec::new())
            }
        }
        let s = Double::default();
        let d = UsageDelta {
            requests: 1,
            billable_requests: 1,
            models: vec![ModelTokensDelta {
                model: "m".to_string(),
                tokens: TierTokensDelta {
                    input: 5,
                    output: 5,
                    cache_read: 0,
                    cache_write: 0,
                },
            }],
        };
        s.add_usage("bucket", 0, &d).unwrap();
        s.add_usage("bucket", 0, &d).unwrap();
        let l = s.get_usage("bucket", 0).unwrap();
        assert_eq!(l.requests, 2);
        assert_eq!(l.tokens_for("m").unwrap().input, 10);
    }

    #[test]
    fn virtual_key_is_live_reflects_deleted_at() {
        let mut k = sample_key();
        assert!(k.is_live(), "deleted_at: None must be live");
        k.deleted_at = Some(99);
        assert!(!k.is_live(), "deleted_at: Some(_) must not be live");
    }

    #[test]
    fn credential_secret_plaintext_extracts_v1_plain_only() {
        let mut c = sample_credential();
        assert_eq!(c.plaintext(), Some("s3cr3t-signing-key"));
        c.secret = "v1:aead:opaque-ciphertext".to_string();
        assert_eq!(
            c.plaintext(),
            None,
            "a non-plain scheme must never be treated as plaintext"
        );
        c.secret = String::new();
        assert_eq!(c.plaintext(), None);
    }

    #[test]
    fn tier_tokens_is_zero_requires_every_field_zero() {
        assert!(TierTokens::default().is_zero());
        assert!(!TierTokens {
            input: 1,
            ..Default::default()
        }
        .is_zero());
        assert!(!TierTokens {
            output: 1,
            ..Default::default()
        }
        .is_zero());
        assert!(!TierTokens {
            cache_read: 1,
            ..Default::default()
        }
        .is_zero());
        assert!(!TierTokens {
            cache_write: 1,
            ..Default::default()
        }
        .is_zero());
    }

    #[test]
    fn tier_tokens_delta_is_zero_requires_every_field_zero() {
        assert!(TierTokensDelta::default().is_zero());
        assert!(!TierTokensDelta {
            input: 1,
            ..Default::default()
        }
        .is_zero());
        assert!(!TierTokensDelta {
            output: -1,
            ..Default::default()
        }
        .is_zero());
        assert!(!TierTokensDelta {
            cache_read: 1,
            ..Default::default()
        }
        .is_zero());
        assert!(!TierTokensDelta {
            cache_write: 1,
            ..Default::default()
        }
        .is_zero());
    }

    #[test]
    fn usage_delta_is_zero_requires_requests_billable_and_every_model_zero() {
        assert!(UsageDelta::default().is_zero());
        assert!(!UsageDelta {
            requests: 1,
            ..Default::default()
        }
        .is_zero());
        assert!(!UsageDelta {
            billable_requests: 1,
            ..Default::default()
        }
        .is_zero());
        assert!(!UsageDelta {
            models: vec![ModelTokensDelta {
                model: "m".to_string(),
                tokens: TierTokensDelta {
                    input: 1,
                    ..Default::default()
                },
            }],
            ..Default::default()
        }
        .is_zero());
    }

    #[test]
    fn store_error_display_wraps_the_inner_message() {
        let e = StoreError("disk full".to_string());
        assert_eq!(e.to_string(), "store error: disk full");
    }

    struct AuditDouble(Vec<AuditRecord>, Vec<VirtualKey>);
    impl Store for AuditDouble {
        fn put_key(&self, _: &VirtualKey) -> StoreResult<()> {
            Ok(())
        }
        fn get_key(&self, _: &str) -> StoreResult<Option<VirtualKey>> {
            Ok(None)
        }
        fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
            Ok(self.1.clone())
        }
        fn delete_key(&self, _: &str) -> StoreResult<()> {
            Ok(())
        }
        fn get_usage(&self, _: &str, _: u64) -> StoreResult<UsageLedger> {
            Ok(UsageLedger::default())
        }
        fn put_usage(&self, _: &str, _: u64, _: &UsageLedger) -> StoreResult<()> {
            Ok(())
        }
        fn add_metering(&self, _: &MeteringDelta) -> StoreResult<()> {
            Ok(())
        }
        fn list_metering(&self, _: u64) -> StoreResult<Vec<MeteringRow>> {
            Ok(Vec::new())
        }
        fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
            Ok(self.0.clone())
        }
    }

    fn audit_record(seq: u64) -> AuditRecord {
        AuditRecord {
            seq,
            ts: 0,
            action: "test.action".to_string(),
            resource: "test:res".to_string(),
            outcome: "applied".to_string(),
            principal: "vk_1".to_string(),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    /// The DEFAULTED `list_keys_since` fallback: `revision > since`, exclusive of `since` itself
    /// (a row whose revision EQUALS `since` was already seen by that watermark and must not
    /// re-appear, or a poller loops on the same row forever).
    #[test]
    fn default_list_keys_since_excludes_the_watermark_itself() {
        let mut a = sample_key();
        a.id = "vk_a".to_string();
        a.revision = 5;
        let mut b = sample_key();
        b.id = "vk_b".to_string();
        b.revision = 6;
        let s = AuditDouble(Vec::new(), vec![a, b]);
        let since5: Vec<_> = s.list_keys_since(5).unwrap();
        assert_eq!(
            since5.len(),
            1,
            "revision == since must be EXCLUDED, not included"
        );
        assert_eq!(since5[0].id, "vk_b");
        assert_eq!(s.list_keys_since(4).unwrap().len(), 2);
        assert_eq!(s.list_keys_since(6).unwrap().len(), 0);
    }

    /// The DEFAULTED `list_audit_tail` fallback: keep only the last `limit` records (drain the
    /// HEAD, `all.len() - limit` of them), never off-by-one on the boundary.
    #[test]
    fn default_list_audit_tail_keeps_exactly_the_last_limit_records() {
        let records: Vec<_> = (1..=5).map(audit_record).collect();
        let s = AuditDouble(records, Vec::new());
        // Exactly at the cap: nothing trimmed.
        let exact = s.list_audit_tail(5).unwrap();
        assert_eq!(exact.len(), 5);
        // Under the cap: keep the tail-most `limit` records (drop the oldest, i.e. lowest seq).
        let tail = s.list_audit_tail(3).unwrap();
        assert_eq!(tail.len(), 3);
        assert_eq!(
            tail.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![3, 4, 5],
            "must keep the NEWEST records, dropping the oldest from the head"
        );
        // limit above the total count: everything is kept, no panic on the subtraction.
        assert_eq!(s.list_audit_tail(100).unwrap().len(), 5);
    }
}
