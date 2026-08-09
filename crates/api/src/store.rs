// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The durable-store CONTRACT — the data types a `db` plugin (SQLite built-in, Postgres, Valkey, …)
//! reads and writes, plus the `Store` trait itself and its error type. The plain records that cross
//! the seam live here too, so a plugin crate can name them without depending on the engine.
//!
//! These are the same records the admin API and governance enforcement speak, moved here so the
//! contract — not the engine — owns them. No I/O, no engine state: pure data.

/// A kind-tagged scope reference — e.g. `{ kind: "pool", value: "fast" }`. The generic
/// admission-topology substrate: everywhere busbar used
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

    /// Build a `kind: "mcp_server"` scope (1.5.5) - grants a caller access to a registered MCP
    /// server as a whole. Carried on the wire by its OWN named field (`allowed_mcp_servers`),
    /// never mixed into `allowed_pools`.
    pub fn mcp_server(value: impl Into<String>) -> Self {
        ScopeRef {
            kind: "mcp_server".to_string(),
            value: value.into(),
        }
    }

    /// Build a `kind: "mcp_tool"` scope (1.5.5) - grants a caller access to one namespaced
    /// `{server}_{tool}` bound identity. Carried on the wire by its OWN named field
    /// (`allowed_mcp_tools`), never mixed into `allowed_pools`.
    pub fn mcp_tool(value: impl Into<String>) -> Self {
        ScopeRef {
            kind: "mcp_tool".to_string(),
            value: value.into(),
        }
    }
}

/// The KIND-PARTITIONED wire shape for [`VirtualKey::allowed_scopes`] (1.5.5 P0,
/// `mcp-oauth-1.5.5-DESIGN.md` §6.2): each registered scope kind gets its OWN named wire field -
/// `allowed_pools` (kind `pool`), `allowed_mcp_servers` (kind `mcp_server`), `allowed_mcp_tools`
/// (kind `mcp_tool`) - each a plain array of bare value strings, never a `{kind, value}` object.
/// The in-memory `Option<Vec<ScopeRef>>` is partitioned by kind on write and reassembled on read.
///
/// Wire-compat invariants, all pinned by tests:
/// - the pool-only shape stays BYTE-IDENTICAL to the pre-generalization
///   `allowed_pools: Option<Vec<String>>` (absent grant = `null`, explicit `[]` = empty set);
///   the MCP fields are OMITTED unless that kind has entries, so a pre-1.5.5 row/reader never
///   sees them;
/// - a kind with NO registered wire field is a HARD serialize error - never silently remapped
///   into `allowed_pools` (the pre-P0 defect: an `mcp_server` grant became a POOL grant on any
///   store round-trip - a lost MCP grant AND a pool-access escalation) and never silently dropped
///   (which would WIDEN a `Some([unknown])` = no-scopes grant toward the `None` = all wildcard);
/// - reassembly is canonical-by-kind (pools, then servers, then tools). `scope_allowed` is a pure
///   membership test, so cross-kind order is never consulted.
///
/// Rows are persisted THROUGH this shape by JSON-round-tripping store backends (valkey-shaped),
/// which is exactly where the pre-P0 kind collapse corrupted grants.
mod virtual_key_wire {
    use super::{ScopeRef, VirtualKey};

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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed_mcp_servers: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed_mcp_tools: Option<Vec<String>>,
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
    }

    /// The per-kind wire partition: `(allowed_pools, allowed_mcp_servers, allowed_mcp_tools)`.
    pub(super) type ScopePartition = (
        Option<Vec<String>>,
        Option<Vec<String>>,
        Option<Vec<String>>,
    );

    /// Partition `allowed_scopes` into the per-kind wire fields. `Err` names the offending kind:
    /// an unregistered kind must fail the WRITE, loudly, at the boundary - see the module doc.
    pub(super) fn partition_scopes(
        scopes: &Option<Vec<ScopeRef>>,
    ) -> Result<ScopePartition, String> {
        let Some(list) = scopes else {
            return Ok((None, None, None));
        };
        let mut pools = Vec::new();
        let mut servers = Vec::new();
        let mut tools = Vec::new();
        for sr in list {
            match sr.kind.as_str() {
                "pool" => pools.push(sr.value.clone()),
                "mcp_server" => servers.push(sr.value.clone()),
                "mcp_tool" => tools.push(sr.value.clone()),
                other => {
                    return Err(format!(
                        "scope kind '{other}' has no registered wire field: refusing to \
                         serialize (a kind is never silently remapped into allowed_pools or \
                         dropped - give it its own named wire field first)"
                    ));
                }
            }
        }
        // `allowed_pools` is ALWAYS present for an explicit grant (even empty) so `Some([])` =
        // no-scopes survives the trip; the MCP fields are additive and omitted when empty.
        Ok((
            Some(pools),
            (!servers.is_empty()).then_some(servers),
            (!tools.is_empty()).then_some(tools),
        ))
    }

    /// Reassemble the per-kind wire fields into kind-tagged scopes. All three absent = the
    /// omitted-grant wildcard (`None`); any present field makes the grant an explicit
    /// (fail-closed, exhaustive-across-kinds) list.
    pub(super) fn assemble_scopes(
        pools: Option<Vec<String>>,
        servers: Option<Vec<String>>,
        tools: Option<Vec<String>>,
    ) -> Option<Vec<ScopeRef>> {
        if pools.is_none() && servers.is_none() && tools.is_none() {
            return None;
        }
        let mut list = Vec::new();
        list.extend(pools.into_iter().flatten().map(ScopeRef::pool));
        list.extend(servers.into_iter().flatten().map(ScopeRef::mcp_server));
        list.extend(tools.into_iter().flatten().map(ScopeRef::mcp_tool));
        Some(list)
    }

    impl serde::Serialize for VirtualKey {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let (allowed_pools, allowed_mcp_servers, allowed_mcp_tools) =
                partition_scopes(&self.allowed_scopes).map_err(serde::ser::Error::custom)?;
            VirtualKeyWire {
                id: self.id.clone(),
                generation_hash: self.generation_hash.clone(),
                name: self.name.clone(),
                allowed_pools,
                allowed_mcp_servers,
                allowed_mcp_tools,
                enabled: self.enabled,
                created_at: self.created_at,
                group: self.group.clone(),
                labels: self.labels.clone(),
                expires_at: self.expires_at,
                deleted_at: self.deleted_at,
                revision: self.revision,
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
                allowed_scopes: assemble_scopes(
                    w.allowed_pools,
                    w.allowed_mcp_servers,
                    w.allowed_mcp_tools,
                ),
                enabled: w.enabled,
                created_at: w.created_at,
                group: w.group,
                labels: w.labels,
                expires_at: w.expires_at,
                deleted_at: w.deleted_at,
                revision: w.revision,
            })
        }
    }
}

/// A virtual key issued by busbar (distinct from upstream provider keys) - a PURE AUTH binding
/// (1.5.0): identity + pool grants + at most one `groups:` binding. Keys carry NO inline
/// limits: every cap (requests / tokens / budget / concurrent) lives on the bound group's chain,
/// so policy is mutable in config/store without re-issuing the credential.
/// Serde note: `Serialize`/`Deserialize` are HAND-IMPLEMENTED in [`virtual_key_wire`] (the
/// kind-partitioned scope wire, 1.5.5 P0) - keep the wire mirror struct's fields/defaults in
/// lockstep with this struct when adding a field.
#[derive(Clone, PartialEq)]
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
    /// scopes (an empty list is the empty set, never "all"). On the WIRE this partitions by kind
    /// into `allowed_pools` / `allowed_mcp_servers` / `allowed_mcp_tools` (the pool-only shape
    /// stays byte-identical to the pre-generalization `allowed_pools: Option<Vec<String>>`):
    /// see [`virtual_key_wire`].
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
    /// key id (billing, audit) keeps resolving forever. See [`Store::delete_key`].
    pub deleted_at: Option<u64>,
    /// Store-global monotonic revision, bumped on every mutation to this row. Used by
    /// [`Store::list_keys_since`] for incremental hydration. `0` for a row a pre-revision backend
    /// never stamped (treated as "always changed" by a delta consumer, which is safe — a bare
    /// full-scan degrades to correct-but-inefficient, never incorrect).
    pub revision: u64,
}

impl VirtualKey {
    /// Whether this key may target the scope `(kind, value)`.
    ///
    /// - `allowed_scopes` OMITTED (`None`) = ALL scopes of EVERY kind.
    /// - an explicit list is EXHAUSTIVE ACROSS ALL KINDS — **not** "exhaustive per kind".
    /// - an explicit EMPTY list is NO scopes at all (never "all").
    ///
    /// # Cross-kind semantics are fail-closed, and frozen
    ///
    /// A key whose `allowed_scopes` lists only `pool` entries grants **NOTHING** for any other kind.
    /// When a later release introduces a new kind (`mcp_server` in 1.5.5, `agent` in 1.5.6), an
    /// existing key that named only pools does not silently acquire access to every server or agent —
    /// it acquires access to NONE of them, and an operator must add entries to grant any.
    ///
    /// The alternative reading — an unlisted kind is "unconstrained", therefore allowed — is
    /// fail-OPEN: it would turn every existing pool-scoped key into a wildcard over a brand-new
    /// kind, silently, on upgrade. Pinned by `scope_allowed_cross_kind_is_fail_closed` because
    /// these semantics ship in 1.5.3 and freeze with it: only an OMITTED list is a wildcard.
    ///
    /// The generalized replacement for the pool-only `pool_allowed` — every existing call site
    /// checking pool admission calls this as `scope_allowed("pool", pool_name)`, which is the exact
    /// same membership test over a differently-shaped list, so behavior for a pool-only config is
    /// unchanged.
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
/// replacement for the AWS-specific `AwsCredential`/`aws_credentials`, which was vendor-shaped
/// rather than designed: it only ever held SigV4 credentials under an AWS-specific name. A kind
/// belongs here ONLY if its verification path resolves a row FROM a wire-supplied
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
    /// UPSERT `key` by `key.id` — the mint path and every in-place update (rename, enable/disable,
    /// regroup, rotate) go through here.
    ///
    /// ONE precondition, and it is not negotiable: **a `put_key` whose `key.deleted_at` is `None`
    /// MUST NOT overwrite a stored row whose `deleted_at` is `Some(_)`.** Return an error instead.
    /// [`VirtualKey::deleted_at`] says the id is never reissued and [`Store::delete_key`] says the
    /// tombstone is permanent, so silently clearing one resurrects a key an operator revoked — the
    /// exact outcome [`Store::delete_key`] exists to prevent, reached through the other door.
    ///
    /// Writing a key that CARRIES a tombstone (`key.deleted_at.is_some()`) is unaffected: hydration
    /// and test fixtures legitimately write tombstoned rows, and neither clears anything.
    ///
    /// This has to be enforced in the store, not by the caller. Core's callers do check
    /// `deleted_at` before writing, but that check is a read-then-write: a `delete_key` committing
    /// between the `get_key` and the `put_key` slips straight through it. Only the backend can make
    /// the test and the write atomic, so only the backend can actually close it.
    ///
    /// `put_key` is otherwise an ABSOLUTE SET, not a compare-and-set: it takes no expected
    /// `revision`, so two concurrent writers are last-writer-wins on the whole row. That is a known
    /// and accepted limitation of this signature (adding a precondition parameter is a breaking
    /// trait change); it is recorded here so no caller mistakes the tombstone guard above for
    /// general optimistic concurrency, which it is not.
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
    /// An id that names NO ROW AT ALL is a loud error, and that is a DIFFERENT case from the
    /// idempotent one above. "Already tombstoned" means the operator's intent is satisfied and the
    /// evidence is on disk. "No such id" means it is not, and the likeliest cause is a typo or a
    /// stale id — where returning `Ok(())` tells an operator a key was revoked when nothing was
    /// touched. Same reasoning [`Store::revoke_credential`] gives for its own default; the two are
    /// deliberately settled the same way.
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
    /// accumulate (SQL `UPDATE x = x + delta` UPSERT / valkey `HINCRBY`).
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
    ///
    /// To spell out what "idempotent" does and does not cover, because backends have read it both
    /// ways: revoking an ALREADY-REVOKED id is `Ok(())`, and an id that names NO ROW is an ERROR.
    /// A backend must therefore read the row count its UPDATE actually affected, or check for the
    /// row explicitly — a statement that matched nothing looks identical to one that matched, and
    /// this is precisely the case where those two must not be confused.
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
    /// the configured store — memory = ephemeral, sqlite/postgres/valkey = durable). The engine keeps
    /// the hot in-memory hash-chained ring for reads and write-THROUGHs each appended entry here, so a
    /// hard crash loses ~0 entries and the ring's size bound stops pruning HISTORY (the store keeps it
    /// all). Append-only, ordered by `seq`; a store never rewrites or recomputes the digest.
    ///
    /// A record arriving on a `seq` that ALREADY HAS ONE is settled by comparing the two:
    /// - byte-identical to the stored record → `Ok(())`. This is the write-through retrying after a
    ///   timeout or a reconnect, and it is the common case; failing it would make a healthy engine
    ///   look broken.
    /// - DIFFERENT from the stored record → error. Two different records claiming one chain
    ///   position is a forked or tampered log, and it is the single most important thing an audit
    ///   store can tell an operator.
    ///
    /// Overwriting is never correct: it is how the second case gets destroyed instead of reported,
    /// and it contradicts "a store never rewrites the digest" directly. Silently keeping the first
    /// is not correct either — it collapses both cases into one and drops a genuinely different
    /// record on the floor, which is the same silent-loss shape, just quieter.
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
#[path = "tests/store_tests.rs"]
mod tests;