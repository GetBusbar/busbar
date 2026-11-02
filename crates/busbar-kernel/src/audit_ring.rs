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
    /// Monotonic sequence number (1-based), unique within a process lifetime.
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
    /// token; a virtual-key id or an external module's principal id otherwise; `anonymous` for the
    /// explicit open admin posture). Attribution, never a credential.
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
    pub hash: String,
    /// WHICH RECIPE `hash` was sealed under: 1 (the 1.5.5 pipe join) or 2 (length-prefixed fields);
    /// both are stated on `hash`. A record is sealed under 1 when its `action`, `resource` and
    /// `outcome` carry no `|`, and under 2 otherwise, so its fields always read back exactly. A
    /// record without this field is scheme 1. A verifier checks each record under its own scheme.

    #[serde(default = "audit_scheme_default")]
    pub scheme: u8,
    /// TRUE only for entries THIS process appended live (the seam's live emit). Seeded entries — restored from the durable store — are FALSE. `#[serde(skip)]` gives
    /// the right default (false) on the encoded/store-seeding paths; the live-append sites set it true
    /// explicitly. It carries no ring logic now that the durable rebase is retired; the boot-verify
    /// golden still asserts restored entries come back seeded (`false`).
    ///
    /// It is now WRITE-ONLY outside tests (every fill site sets it; only the boot-verify golden and the
    /// seam round-trip witness read it back), so its read is `cfg(test)`; the field is retained as the
    /// seam↔ring provenance marker those witnesses assert on.
    #[serde(skip)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub recorded_here: bool,
}

pub const AUDIT_SCHEME_PIPE: u8 = 1;

pub const AUDIT_SCHEME_LENGTH_PREFIXED: u8 = 2;

fn audit_scheme_default() -> u8 {
    AUDIT_SCHEME_PIPE
}

pub use crate::audit::vocab::{OUTCOME_APPLIED, OUTCOME_DEGRADED, OUTCOME_REJECTED};

pub use crate::audit::MAX_AUDIT_ENTRIES;

pub struct AuditLog {
    _private: (),
}

impl AuditLog {
    pub fn record_by(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        crate::audit::auditlog::emit_admin_hostless_now(action, resource, outcome, principal);
    }
}

pub static AUDIT: AuditLog = AuditLog { _private: () };
