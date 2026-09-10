// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN MUTATION LOG, mounted on the kernel-held record leg.
//!
//! Every admin mutation is recorded, success AND failure, so a credential probing the surface or an
//! operator asking "who changed what" leaves a trail. The RECORD is the audit unit's, the ring that
//! serves the read is the audit unit's, the schema and the bytes are the admin plane's, and the leg
//! that lands them on a store is [`crate::root::records`]. What is left for this file is the
//! composition: bind the three together, copy forward what a previous release wrote, seed the ring
//! from the persisted tail, and hand the engine a durable path it can record through without
//! knowing any of the above.
//!
//! ## Why the mount is here and not in the engine
//!
//! The engine cannot build this. A leg is admitted by the kernel and lands on the published store
//! protocol; a crate that is neither the root may not name both. What the engine keeps is the ONE
//! chokepoint every mutation is recorded through and a slot for the durable path — which is the
//! right split, because the chokepoint is a rule about the engine and the durable path is a fact
//! about the deployment.
//!
//! ## Fire-and-forget, loudly
//!
//! A durable write failure NEVER fails the mutation it records. A gateway whose control plane stops
//! when its audit backend blinks has converted an observability dependency into an availability
//! one. The failure is surfaced at `error!` on the TRANSITION into the failing state (a store
//! outage recurs once per mutation, and a line per mutation is how an operator stops reading the
//! log) and held at `debug!` thereafter; a success clears the latch so a later outage errors again.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector};
use busbar_plane_admin::records as audit_record;
use busbar_unit_audit::legacy::{verify_window, AuditEntry, DurableSeam, Framing};

use crate::root::records::{DeclaredSchemas, LegError, RecordLeg};

/// The admin mutation log's durable path: one record leg, over the store the loader resolved.
///
/// It holds the chain position for the log's single scope and nothing else. The records live in the
/// store, which is the whole reason a durable log exists.
pub struct AuditStream {
    leg: RecordLeg,
}

impl std::fmt::Debug for AuditStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditStream")
    }
}

impl AuditStream {
    /// Bind the stream to a store.
    ///
    /// The framing is pipe-separated and the scope is NOT in the digest. Both are wire facts of the
    /// records already on disk rather than choices: folding the scope into the prelude would frame
    /// one extra field before the sequence and make every already-persisted admin record report a
    /// digest mismatch at its next boot.
    #[must_use]
    pub fn over(store: Arc<dyn busbar_api::Store>) -> Self {
        AuditStream {
            leg: RecordLeg::new(
                store,
                Box::new(DeclaredSchemas::of(
                    audit_record::RECORD_SCHEMAS,
                    audit_record::operations_for,
                )),
                audit_record::SCHEMA_AUDIT,
                Framing::PipeSeparated,
                false,
                Some(audit_record::legacy_row),
            ),
        }
    }

    /// READ THE PERSISTED LOG BACK, oldest-first, as the typed rows the ring is seeded from.
    ///
    /// A row the leg could not decode is counted and skipped by the leg and reported here. On this
    /// surface an undecodable row may be tamper evidence rather than a format mismatch, so it is
    /// never lost silently — but it also never aborts the restore, because aborting would leave the
    /// chain unseeded and fork it at sequence one on the next mutation.
    ///
    /// # Errors
    ///
    /// The store refused the enumeration or a read.
    pub fn restore(&self) -> Result<Vec<AuditEntry>, LegError> {
        let restored = self.leg.restore()?;
        if restored.unreadable > 0 {
            tracing::error!(
                unreadable = restored.unreadable,
                "a persisted admin audit record could NOT be decoded on restore; it is being \
                 SKIPPED and counted rather than aborting the whole restore. The evidence in those \
                 rows is lost — reported here, never skipped silently, because on the admin audit \
                 log an undecodable row may be tamper evidence."
            );
        }
        for brk in &restored.chain_breaks {
            tracing::error!(
                break_detail = %brk,
                "admin audit CHAIN VERIFICATION FAILED on restore — the persisted records do not \
                 verify against their own hash chain. They are still restored and the chain \
                 resumes from the broken tail."
            );
        }
        Ok(restored
            .rows
            .iter()
            .map(|row| {
                let fields = audit_record::parse_audit_suffix(&row.content);
                AuditEntry {
                    seq: row.seq,
                    ts: fields.ts,
                    action: fields.action,
                    resource: fields.resource,
                    outcome: fields.outcome,
                    principal: fields.principal,
                    prev_hash: row.prev_hash.clone(),
                    hash: row.hash.clone(),
                    // Restored, never appended here. The ring's own loader clears this too; setting
                    // it correctly at the source means the two never have to agree about it.
                    recorded_here: false,
                }
            })
            .collect())
    }
}

/// ONE-TIME DATA MIGRATION: copy the previous release's durable audit TABLE into the records the leg
/// reads, preserving each row's sequence, links and digest EXACTLY.
///
/// The copied fields reproduce the leg's own body byte for byte, so the migrated chain verifies
/// identically. THE MIGRATION COPIES BYTES; IT NEVER RE-SEALS. A migration that re-sealed would
/// produce a chain that verifies perfectly and proves nothing, because every digest in it would
/// have been computed by the process doing the migrating.
///
/// IDEMPOTENT and SELF-LIMITING: a store already holding audit records under the leg's schema — a
/// migrated store, or one recorded to since — is left untouched, and so is a store with no old rows
/// at all. Only a store whose audit lives SOLELY in the old table is copied, once.
///
/// The FULL history is read, oldest-first FROM GENESIS, never the bounded tail: the records are
/// never pruned and the restore verifies from the genesis anchor, so a migrated chain must start at
/// sequence one.
///
/// # Errors
///
/// The store refused a read or a write. The migration retries on the next boot, because the
/// idempotency check still finds the schema empty.
pub fn migrate_previous_release_table(store: &dyn busbar_api::Store) -> Result<usize, LegError> {
    let kind = audit_record::SCHEMA_AUDIT.as_str();
    let scope = audit_record::AUDIT_SCOPE;
    // IDEMPOTENCY GATE. Checking the scope's RECORDS rather than merely the enumerated parents means
    // a prior boot that seeded only an empty scope cannot block a real migration.
    let existing = store
        .list_plane_records(kind, &PlaneSelector::Parent(scope.to_string()))
        .map_err(|e| LegError::Store(e.0))?;
    if !existing.is_empty() {
        return Ok(0);
    }
    let rows = store.list_audit().map_err(|e| LegError::Store(e.0))?;
    if rows.is_empty() {
        return Ok(0);
    }
    for row in &rows {
        let content = audit_record::audit_suffix(
            row.ts,
            &row.action,
            &row.resource,
            &row.outcome,
            &row.principal,
        );
        let body = serde_json::to_vec(&serde_json::json!({
            "seq": row.seq,
            "prev_hash": row.prev_hash,
            "hash": row.hash,
            "content": content,
        }))
        .map_err(|e| LegError::Body(e.to_string()))?;
        store
            .append_plane_record(&PlaneRecord {
                kind: kind.to_string(),
                id: scope.to_string(),
                parent: Some(scope.to_string()),
                seq: row.seq,
                ts: row.ts,
                disposition: PlaneDisposition::Active,
                body,
            })
            .map_err(|e| LegError::Store(e.0))?;
    }
    Ok(rows.len())
}

/// The durable path the engine's one chokepoint records through.
///
/// It carries the SAME timestamp the ring sealed — never a second clock read, which would let two
/// copies of one mutation end up a second apart and impossible to reconcile later.
struct LegSeam {
    stream: AuditStream,
    /// Whether the last durable write failed. A store outage recurs once per mutation, and a line
    /// per mutation is how an operator learns to stop reading the log.
    failing: AtomicBool,
}

impl DurableSeam for LegSeam {
    fn emit(&self, ts: u64, action: &str, resource: &str, outcome: &str, principal: &str) {
        let suffix = audit_record::audit_suffix(ts, action, resource, outcome, principal);
        match self.stream.leg.append(
            audit_record::AUDIT_SCOPE,
            audit_record::OP_APPEND,
            ts,
            &suffix,
        ) {
            Ok(_) => self.failing.store(false, Ordering::Relaxed),
            Err(e) => {
                if self.failing.swap(true, Ordering::Relaxed) {
                    tracing::debug!(
                        error = %e,
                        "the durable admin audit record could NOT be written; its evidence is \
                         being LOST. The chain position is unchanged, so the chain stays contiguous."
                    );
                } else {
                    tracing::error!(
                        error = %e,
                        "the durable admin audit record could NOT be written: this mutation is \
                         being served and its evidence is being LOST on that path. The chain \
                         position is unchanged, so the chain stays contiguous — what is missing is \
                         this record, not the ones after it."
                    );
                }
            }
        }
    }
}

/// BUILD the admin mutation log's durable path: copy forward what a previous release wrote, read
/// the persisted log back, verify it, and hand back the seam plus the tail the engine seeds its
/// ring from.
///
/// Called ONCE at boot, as the first thing durable-state hydration is given, so the first mutation
/// of this process chains onto the last mutation of the previous one.
///
/// A durable backend the deployment did not configure is not an error and not a warning: it is the
/// documented in-memory behaviour, and the log is then ephemeral by construction. `None` comes
/// back, the engine's slot stays empty, and the ring still records and still serves reads.
///
/// A restored window that does not VERIFY is reported here and handed over ANYWAY. Refusing would
/// let a detected tamper stop all further evidence being recorded, which is the wrong way round:
/// the break is the thing to alarm on, not the thing to stop on.
#[must_use]
pub fn mount(
    store: Option<Arc<dyn busbar_api::Store>>,
) -> Option<(Box<dyn DurableSeam>, Vec<AuditEntry>)> {
    let store = store?;
    // The one-time copy forward. A failure is LOUD but never fatal: the restore below then finds
    // only what the leg's own schema already holds, and the migration retries on the next boot.
    match migrate_previous_release_table(store.as_ref()) {
        Ok(0) => {}
        Ok(n) => tracing::info!(
            records = n,
            "copied the previous release's durable audit table onto the record leg"
        ),
        Err(e) => tracing::error!(
            error = %e,
            "could not copy the previous release's durable audit table onto the record leg; the \
             restore will seed only what the leg already holds and the copy retries on the next boot"
        ),
    }
    let stream = AuditStream::over(store);
    let restored = match stream.restore() {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not read the durable admin audit records to seed the ring; the ring starts \
                 empty and the chain resumes from the persisted tail on the next successful read"
            );
            Vec::new()
        }
    };
    // A WINDOW, not a whole chain: the store keeps the rest, so the oldest restored record's
    // predecessor may legitimately have been pruned and only its own digest can be checked.
    if let Err(brk) = verify_window(&restored) {
        tracing::error!(
            break_detail = %brk,
            "the restored admin audit window did not verify; the ring is seeded anyway, because a \
             detected tamper must not be able to stop all further evidence being recorded"
        );
    }
    if !restored.is_empty() {
        tracing::info!(
            records = restored.len(),
            "admin audit restored from the durable record leg"
        );
    }
    let seam: Box<dyn DurableSeam> = Box::new(LegSeam {
        stream,
        failing: AtomicBool::new(false),
    });
    Some((seam, restored))
}

#[cfg(test)]
#[path = "tests/audit_stream.rs"]
mod tests;
