// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin plane's durable state, expressed as a record leg rather than as a store this crate
//! holds.
//!
//! A plane performs no input and no output. Everything it needs to remember across units is a
//! kernel-held record, reached only through a leg of the route plan. The admin plane remembers one
//! thing: WHAT WAS CHANGED, BY WHOM, AND WHETHER IT TOOK. That is the audit stream, and this module
//! is its declaration — the schema, the operations it admits, and the bytes one record frames to.
//!
//! ## Append and scan, and deliberately nothing else
//!
//! The audit stream is the answer to "what happened". An answer whose middle can be replaced is not
//! an answer, so there is no put, no delete and no redeem: a record is added, or the stream is read
//! back. Retention is the store's, applied to whole rows by age, and it is not an operation a plane
//! may name.

use busbar_contract::ids::RecordSchemaId;

/// The admin mutation log: what was changed, by whom, and whether it took.
pub const SCHEMA_AUDIT: RecordSchemaId = RecordSchemaId::new("audit");

/// The record schemas this plane keeps kernel-held durable records under.
pub const RECORD_SCHEMAS: &[RecordSchemaId] = &[SCHEMA_AUDIT];

/// Add one record to a schema's append-only side.
pub const OP_APPEND: &str = "append";

/// Read every record of a schema under one parent.
pub const OP_SCAN: &str = "scan";

/// Every operation any of this plane's schemas declares.
pub const OPERATIONS: &[&str] = &[OP_APPEND, OP_SCAN];

/// THE ONE SCOPE OF THE AUDIT CHAIN: the whole log.
///
/// A chain elsewhere is scoped per principal or per task because it is request-rate and serves
/// many tenants;
/// the admin mutation log is one operator-rate sequence for the whole process, so its scope is a
/// constant. Naming it anyway is what lets ONE verifier walk every stream.
pub const AUDIT_SCOPE: &str = "admin";

/// Which operations one schema declares.
///
/// A leg naming an operation its schema does not declare is refused by the kernel, so the answer
/// has to be a declaration rather than a convention.
#[must_use]
pub fn operations_for(schema: RecordSchemaId) -> &'static [&'static str] {
    match schema.as_str() {
        s if s == SCHEMA_AUDIT.as_str() => OPERATIONS,
        _ => &[],
    }
}

// ── THE AUDIT RECORD'S OWN BYTES ────────────────────────────────────────────────────────────────
//
// A plane declares its record, and a record is a schema plus the bytes one instance of it frames
// to. The schema is above; the bytes are here.

/// THE AUDIT RECORD'S PRE-FRAMED CONTENT SUFFIX: `|ts|action|resource|outcome|principal`.
///
/// Five fields joined by vertical bars, WITH a leading bar, because the chain's prelude ends with a
/// field and the bar between them is owed by this side. The framing is pipe-separated and the scope
/// is not in the digest, both of which are wire facts of the records already on disk rather than
/// choices: a chain appended through this suffix reproduces the previous release's digest input
/// byte for byte, which is what lets a deployed store verify without a migration.
#[must_use]
pub fn audit_suffix(
    ts: u64,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) -> Vec<u8> {
    format!("|{ts}|{action}|{resource}|{outcome}|{principal}").into_bytes()
}

/// The five fields of one audit record, read back out of its suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFields {
    /// Unix seconds the mutation was attempted at.
    pub ts: u64,
    /// The action, `noun.verb`.
    pub action: String,
    /// The resource acted on.
    pub resource: String,
    /// The stable outcome token.
    pub outcome: String,
    /// Who attempted it.
    pub principal: String,
}

/// Read one audit suffix back into its five fields — the inverse of [`audit_suffix`].
///
/// The leading bar is stripped and the five fields split; the framing contract guarantees that no
/// field carries a bar of its own.
#[must_use]
pub fn parse_audit_suffix(content: &[u8]) -> AuditFields {
    let s = String::from_utf8_lossy(content);
    let f: Vec<&str> = s.trim_start_matches('|').splitn(5, '|').collect();
    AuditFields {
        ts: f.first().and_then(|v| v.parse().ok()).unwrap_or(0),
        action: f.get(1).copied().unwrap_or_default().to_string(),
        resource: f.get(2).copied().unwrap_or_default().to_string(),
        outcome: f.get(3).copied().unwrap_or_default().to_string(),
        principal: f.get(4).copied().unwrap_or_default().to_string(),
    }
}

/// Recognise a row a store held BEFORE the neutral envelope existed, and return the same four parts
/// the envelope carries: the sequence, the previous hash, the hash, and the content suffix.
///
/// The previous release wrote this stream as a FLAT row with its five fields beside its three chain
/// fields. Those rows are still on disk in every deployment that ran it, and their digests were
/// sealed over exactly the bytes [`audit_suffix`] rebuilds — so recognising the old shape here
/// costs one decode and saves every one of those deployments a re-seal it must never be asked to
/// perform.
#[must_use]
pub fn legacy_row(body: &[u8]) -> Option<(u64, String, String, Vec<u8>)> {
    #[derive(serde::Deserialize)]
    struct LegacyAuditRow {
        seq: u64,
        ts: u64,
        action: String,
        resource: String,
        outcome: String,
        principal: String,
        prev_hash: String,
        hash: String,
    }
    let row: LegacyAuditRow = serde_json::from_slice(body).ok()?;
    let content = audit_suffix(
        row.ts,
        &row.action,
        &row.resource,
        &row.outcome,
        &row.principal,
    );
    Some((row.seq, row.prev_hash, row.hash, content))
}

#[cfg(test)]
#[path = "tests/records.rs"]
mod tests;
