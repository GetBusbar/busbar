// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::Serialize;

/// One admin audit record. `outcome` is a stable token tooling can branch on. The record is
/// HASH-CHAINED for tamper-EVIDENCE: `hash` is the SHA-256 of bytes fixed by this record's own
/// `scheme` (the recipe is on `hash`), and `prev_hash` is the preceding entry's `hash`. Recomputing
/// the chain detects any altered/reordered/deleted entry (detection, not prevention; a compromised
/// host can still rewrite the whole chain; prevention is shipping the log off-box to a SIEM).
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct AuditEntry {
    /// Monotonic sequence number (1-based). It continues across restart: the chain is one durable log.
    pub seq: u64,
    /// Unix seconds when the mutation was attempted.
    pub ts: u64,
    /// The action, `noun.verb` (e.g. `hook.register`, `hook.delete`).
    pub action: String,
    /// The resource acted on (e.g. `hook:compress`). Never a secret.
    pub resource: String,
    /// Stable outcome token: `applied` (mutation committed) | `rejected` (validation/conflict, nothing
    /// changed).
    pub outcome: String,
    /// WHO: the authenticated principal id that attempted the mutation (`admin` for the operator
    /// token; a virtual-key id or an external module's principal id otherwise). Attribution, never a
    /// credential.
    pub principal: String,
    /// The preceding entry's `hash` (empty for the first entry of the process, or the oldest retained
    /// entry whose predecessor was pruned).
    pub prev_hash: String,
    /// The tamper-evidence digest: lowercase hex SHA-256 over the bytes this record's `scheme` names.
    /// Integers are written in decimal ASCII and strings as their UTF-8 bytes unless stated.
    ///
    /// Scheme 1: `prev_hash|seq|ts|action|resource|outcome|principal`, the fields joined by `|`
    /// (1.5.5's formula).
    ///
    /// Scheme 2: `prev_hash|seq` as in scheme 1, then one zero byte (0x00), then `ts`, `action`,
    /// `resource`, `outcome` and `principal`, each as its byte length (8 bytes, big-endian) followed
    /// by its bytes; `ts` is its 8-byte big-endian value, so its length is 8.
    ///
    /// Scheme 3 (ADMIN-API-1.6 section 7.2): `prev_hash|seq` as before, then the row suffix: one 0x03
    /// byte, `ts` as scheme 2 writes it, `action`, `resource`, `outcome` and `principal` each
    /// length-prefixed, then `config_generation`, `request_id`, `idempotency_key`, `kind` and
    /// `instance` (each length-prefixed: a single 0x00 byte when absent, 0x01 and the bytes when
    /// present), `sections_changed` (an 8-byte big-endian count, then each name length-prefixed),
    /// `severity` and `message` (length-prefixed) and `data` as one length-prefixed field holding its
    /// canonical JSON (members in ascending order of their names' UTF-8 bytes, no whitespace,
    /// minimal string escapes), so every member of `data` is inside the digest.
    pub hash: String,
    /// WHICH RECIPE `hash` was sealed under: 1 (the 1.5.5 pipe join), 2 (length-prefixed fields) or 3 (the row fields);
    /// all are stated on `hash`. A record is sealed under 3 when it is written through the row path
    /// (`AUDIT.record_by` and `emit_row_now`: every admin request's rows), under 1 otherwise when its
    /// `action`, `resource` and `outcome` carry no `|`, and under 2 when they do, so its fields always
    /// read back exactly. A
    /// record without this field is scheme 1. A verifier checks each record under its own scheme.
    #[serde(default = "audit_scheme_default")]
    pub scheme: u8,
    /// The config generation after the change, as a decimal string: on every applied row of a
    /// config-changing request, null otherwise.
    #[serde(default)]
    pub config_generation: Option<String>,
    /// The config sections the change touched (empty when it touched none, or none is known).
    #[serde(default)]
    pub sections_changed: Vec<String>,
    /// The admin request's id (its `X-Request-Id`), null for a row no request caused.
    #[serde(default)]
    pub request_id: Option<String>,
    /// The request's `Idempotency-Key`, null when it carried none.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// The engine kind of the instance an engine event is about.
    #[serde(default)]
    pub kind: Option<String>,
    /// The instance an engine event is about.
    #[serde(default)]
    pub instance: Option<String>,
    /// `info`, `warning` or `error`.
    #[serde(default = "audit_severity_default")]
    pub severity: String,
    /// Core-written text for the row; empty for rows from before scheme 3.
    #[serde(default)]
    pub message: String,
    /// Members typed per action. Always an object; `{}` when the action has none.
    #[serde(default)]
    pub data: AuditData,
    /// TRUE only for entries THIS process appended live (the seam's live emit). Seeded entries — restored from the durable store — are FALSE. `#[serde(skip)]` gives
    /// the right default (false) on the encoded/store-seeding paths; the live-append sites set it true
    /// explicitly. It carries no ring logic now that the durable rebase is retired; the boot-verify
    /// golden still asserts restored entries come back seeded (`false`).
    ///
    /// It is now WRITE-ONLY outside tests (every fill site sets it; only the boot-verify golden and the
    /// seam round-trip witness read it back), so its read is `cfg(test)`; the field is retained as the
    /// seam↔ring provenance marker those witnesses assert on.
    #[serde(skip)]
    pub recorded_here: bool,
}

pub const AUDIT_SCHEME_PIPE: u8 = 1;

pub const AUDIT_SCHEME_LENGTH_PREFIXED: u8 = 2;

pub const AUDIT_SCHEME_ROW: u8 = 3;

/// The severities a row may carry.
pub const SEVERITIES: [&str; 3] = ["info", "warning", "error"];

fn audit_severity_default() -> String {
    SEVERITIES[0].to_string()
}

impl Default for AuditEntry {
    fn default() -> Self {
        Self {
            seq: 0,
            ts: 0,
            action: String::new(),
            resource: String::new(),
            outcome: String::new(),
            principal: String::new(),
            prev_hash: String::new(),
            hash: String::new(),
            scheme: AUDIT_SCHEME_PIPE,
            config_generation: None,
            sections_changed: Vec::new(),
            request_id: None,
            idempotency_key: None,
            kind: None,
            instance: None,
            severity: audit_severity_default(),
            message: String::new(),
            data: AuditData::default(),
            recorded_here: false,
        }
    }
}

/// A row's `data`: one JSON object, held in the canonical form scheme 3 digests (see
/// `audit::canonical`). It serializes as the object itself.
/// Why [`AuditData::from_json`] refused a text: it is not one JSON object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAnObject;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditData(String);

impl Default for AuditData {
    fn default() -> Self {
        Self("{}".to_string())
    }
}

impl AuditData {
    /// Canonicalize the JSON object `text`. `Err` when it is not one JSON object.
    pub fn from_json(text: &str) -> Result<Self, NotAnObject> {
        crate::audit::canonical::canonical_object(text)
            .map(Self)
            .map_err(|()| NotAnObject)
    }

    /// The canonical bytes, as text: exactly what scheme 3 digests.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for AuditData {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value: sonic_rs::Value =
            sonic_rs::from_str(&self.0).map_err(serde::ser::Error::custom)?;
        value.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for AuditData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <sonic_rs::Value as serde::Deserialize>::deserialize(deserializer)?;
        let text = sonic_rs::to_string(&value).map_err(serde::de::Error::custom)?;
        Self::from_json(&text)
            .map_err(|NotAnObject| serde::de::Error::custom("`data` must be a JSON object"))
    }
}

#[cfg(feature = "openapi-schema")]
impl schemars::JsonSchema for AuditData {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "AuditData".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "object",
            "additionalProperties": true,
            "description": "Members typed per action (the `x-busbar-audit-actions` catalogue); `{}` when the action has none."
        })
    }
}

fn audit_scheme_default() -> u8 {
    AUDIT_SCHEME_PIPE
}

pub use crate::audit::vocab::{OUTCOME_APPLIED, OUTCOME_DEGRADED, OUTCOME_REJECTED};

pub use crate::audit::MAX_AUDIT_ENTRIES;

pub struct AuditLog {
    _private: (),
}

impl AuditLog {
    /// Write one admin audit row under hash scheme 3, stamped with the request in flight (its id, its
    /// `Idempotency-Key`, and on an applied row the config generation and sections it changed).
    pub fn record_by(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        crate::audit::auditlog::emit_row_now(crate::audit::auditlog::AuditRowInput {
            action: action.to_string(),
            resource: resource.to_string(),
            outcome: outcome.to_string(),
            principal: principal.to_string(),
            ..Default::default()
        });
    }

    /// Write a fully specified row (an engine event, say) under hash scheme 3.
    pub fn record_row(&self, row: crate::audit::auditlog::AuditRowInput) {
        crate::audit::auditlog::emit_row_now(row);
    }
}

pub static AUDIT: AuditLog = AuditLog { _private: () };

/// Additive metadata for a live admin ring page. All new exact positions are decimal strings.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct AuditPage {
    pub items: Vec<AuditEntry>,
    /// Actual lowest/highest returned sequence, null for an empty page.
    pub returned_from: Option<String>,
    pub returned_to: Option<String>,
    /// Lowest/highest sequence in the unfiltered ring under the same lock as items.
    pub retained_from: Option<String>,
    pub retained_to: Option<String>,
    pub retention_limit: String,
    /// `live_offset` (legacy): concurrent appends/evictions may duplicate or skip rows across pages.
    /// `keyset`: a page resumes strictly after the last `seq`, so no row is duplicated or skipped.
    pub semantics: String,
    /// Always false: this live filtered inventory does not prove complete audit coverage.
    pub complete: bool,
    /// More matching rows existed in this observation.
    pub truncated: bool,
}
