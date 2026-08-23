// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN AUDIT CHAIN, ON THE NEUTRAL JOURNAL SEAM: the admin-mutation log's hash-chained records
//! written through the SAME store-backed [`crate::plane_host::journal`] the MCP call log and the A2A
//! task provenance chain use, addressed by a registered `kind_id`.
//!
//! ## Why the record shape lives here and not in the seam
//!
//! Core owns the ONE chain — one append, one digest, one verifier ([`crate::audit`]). What a stream
//! still owns is its RECORD: which fields it carries, which framing they digest under, and the decode
//! bridge that turns a stored body back into a chain record. This file is that ownership for the admin
//! audit stream, exactly as [`crate::plane::calllog`] is for the MCP call stream and
//! [`crate::plane::taskstore`] is for the A2A task-event stream. Unlike those two it is NOT a plane —
//! the admin audit chain is core (owner's ruling: auditing is core) — so nothing here is feature-gated
//! away; the stream is always registered and always available.
//!
//! ## THE ONE DIVERGENCE FROM THE OTHER TWO STREAMS: the scope is NOT in the digest
//!
//! The admin audit chain has exactly ONE scope (the whole log, the constant `admin`), so its digest
//! never distinguished a scope and its persisted records were sealed WITHOUT one in the digest input.
//! The MCP call chain digests the principal and the A2A task chain digests the task id; this stream
//! registers with `digests_scope = FALSE`. The prelude the host frames is then exactly
//! `frame_prelude(PipeSeparated, prev_hash, None, seq)` = `prev_hash|seq`, and the plane's suffix
//! `|ts|action|resource|outcome|principal` byte-concatenates onto it to reproduce the legacy
//! [`crate::admin::audit::AuditEntry`] digest input byte-for-byte. Registering with `digests_scope = 1`
//! would fold the scope into the prelude and make EVERY already-persisted admin record report
//! `DigestMismatch` at the next boot.
//!
//! ## The claim, and the RAM default
//!
//! TAMPER-EVIDENCE, not tamper-prevention — a chain detects an altered/reordered/inserted/removed
//! record after the fact; it does not stop one. With no durable store configured (`store: memory`) the
//! seam keeps chain positions in RAM and persists nothing, exactly as the legacy ring did.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::admin::audit::{AuditEntry, MAX_AUDIT_ENTRIES};
use crate::audit::journal::NeutralBody;
use crate::audit::{verify_chain, ChainBreak, Framing};
use crate::plane::store::{decode, encode, PlaneStore, KIND_AUDIT};
use crate::plane_host::journal::PlaneJournalRecord;
use busbar_api::{PlaneSelector, StoreError, StoreResult};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{
    Framing as AbiFraming, JournalStreamDesc, ReframeOut, Seq, StatusClass, POD_VERSION,
};
use core::mem::MaybeUninit;

/// The host-assigned `kind_id` the admin `audit` durable stream is registered under and addressed by
/// on every scoped op. Process-global, distinct from the A2A `task_event` stream's id (1) and the MCP
/// `call` stream's id (2).
pub(crate) const KIND_ID_AUDIT: u32 = 3;

/// THE ONE SCOPE OF THIS CHAIN: the whole admin log. The MCP call chain scopes per principal and the
/// A2A chain per task; the admin log is one operator-rate sequence for the whole process, so its scope
/// is a constant — and the scope is deliberately NOT in the digest (see the module header).
const ADMIN_LOG: &str = "admin";

/// The admin audit stream's framing facts, held here (the record's, not the seam's). `PipeSeparated`
/// because that is how the records already on disk were written; the scope does NOT participate in the
/// digest — the one divergence from the task/call streams (see the module header).
const AUDIT_FRAMING: Framing = Framing::PipeSeparated;
const AUDIT_DIGESTS_SCOPE: bool = false;

/// The admin `audit` stream's FFI reframe slot: delegates the raw-buffer work to the audited
/// [`crate::plane_host::journal::reframe_bridge`] (so this file stays `deny(unsafe)`) over the native
/// [`reframe_audit`] decode, which handles BOTH the neutral body and a legacy `serde(AuditRecord)` row.
extern "C-unwind" fn reframe_audit_ffi(
    _host: HostCtx,
    _kind_id: u32,
    body_ptr: *const u8,
    body_len: usize,
    out: *mut MaybeUninit<ReframeOut>,
    prev_buf: *mut u8,
    prev_cap: usize,
    hash_buf: *mut u8,
    hash_cap: usize,
    suffix_buf: *mut u8,
    suffix_cap: usize,
) -> StatusClass {
    crate::plane_host::journal::reframe_bridge(
        body_ptr,
        body_len,
        out,
        prev_buf,
        prev_cap,
        hash_buf,
        hash_cap,
        suffix_buf,
        suffix_cap,
        reframe_audit,
    )
}

/// REGISTER the admin `audit` durable stream with the host (once, at boot, before the migration):
/// `PipeSeparated` framing with the scope OUT of the digest (`digests_scope = 0`), under
/// [`KIND_ID_AUDIT`]. The admin log has one scope, so its position cache is bounded by construction —
/// it registers uncapped through the ABI `journal_register`, exactly as the A2A task table does. The
/// host attaches the durable sink from `app.governance` at register time.
pub(crate) fn register_audit_stream(app: &Arc<crate::state::App>) {
    register_audit_stream_as(KIND_ID_AUDIT, app);
}

/// Register the `audit` stream under an ARBITRARY `kind_id` — production pins [`KIND_ID_AUDIT`], a TEST
/// drives over a FRESH id so parallel tests never share one process-global chain.
pub(crate) fn register_audit_stream_as(kind_id: u32, app: &Arc<crate::state::App>) {
    let kind = KIND_AUDIT.as_bytes();
    let desc = JournalStreamDesc {
        size: core::mem::size_of::<JournalStreamDesc>() as u32,
        version: POD_VERSION,
        framing: AbiFraming::PipeSeparated,
        digests_scope: 0,
        kind_id,
        _reserved: 0,
        kind_ptr: kind.as_ptr(),
        kind_len: kind.len(),
    };
    crate::plane_host::with_dispatch_scope(app, |host, vt| {
        (vt.journal_register
            .expect("journal_register is a wired host slot"))(
            host,
            &desc as *const JournalStreamDesc,
            reframe_audit_ffi,
        );
    });
}

/// Pack a set of stored bodies into the [`journal_seed`](crate::plane_host::journal) wire shape:
/// `u32` count LE, then per body a `u32` length LE + its bytes — the inverse of the host's unpack.
fn pack_bodies(bodies: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(bodies.len() as u32).to_le_bytes());
    for b in bodies {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// The admin audit's pre-framed content SUFFIX (Option A leading `|`): `|ts|action|resource|outcome|
/// principal`. With `digests_scope = false` the host frames the prelude `prev_hash|seq`, and
/// `prelude ⧺ suffix` reproduces the legacy [`AuditEntry`] digest input `prev_hash | seq | ts | action
/// | resource | outcome | principal` byte-for-byte, so a chain appended through the seam verifies
/// byte-identically against records written before the seam existed.
pub(crate) fn audit_suffix(
    ts: u64,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) -> Vec<u8> {
    format!("|{ts}|{action}|{resource}|{outcome}|{principal}").into_bytes()
}

/// Parse a `PipeSeparated` admin audit SUFFIX back into its typed fields — the inverse of
/// [`audit_suffix`], for reconstructing an [`AuditEntry`] from a stored neutral body. The leading `|`
/// is stripped and the five fields are split; the framing contract guarantees no field carries a `|`.
#[allow(dead_code)] // read-back bridge: no production caller until the audit read path is cut over
fn parse_audit_suffix(content: &[u8]) -> (u64, String, String, String, String) {
    let s = String::from_utf8_lossy(content);
    let f: Vec<&str> = s.trim_start_matches('|').splitn(5, '|').collect();
    (
        f.first().and_then(|v| v.parse().ok()).unwrap_or(0),
        f.get(1).copied().unwrap_or_default().to_string(),
        f.get(2).copied().unwrap_or_default().to_string(),
        f.get(3).copied().unwrap_or_default().to_string(),
        f.get(4).copied().unwrap_or_default().to_string(),
    )
}

/// THE DECODE BRIDGE (reframe): turn one stored `audit` body back into a chain record.
///
/// Handles BOTH the NEW neutral `{seq, prev_hash, hash, content}` body the seam persists AND an OLD
/// `serde(AuditRecord)` row a store held before the cleave — so a deployed store spanning the upgrade
/// both VERIFIES and READS BACK. The neutral body is tried first (the shape every post-cleave append
/// writes); a legacy row lacks the required `content` field and falls through to the typed decode,
/// whose fields rebuild the identical suffix. `scope` is the constant `admin` log, supplied by the
/// caller and never read from the body.
fn reframe_audit(scope: &str, body: &[u8]) -> StoreResult<PlaneJournalRecord> {
    if let Ok(nb) = decode::<NeutralBody>(body) {
        return Ok(PlaneJournalRecord::from_parts(
            scope.to_string(),
            nb.seq,
            nb.prev_hash,
            nb.hash,
            nb.content,
            AUDIT_FRAMING,
            AUDIT_DIGESTS_SCOPE,
        ));
    }
    let row: busbar_api::AuditRecord = decode(body)?;
    let content = audit_suffix(
        row.ts,
        &row.action,
        &row.resource,
        &row.outcome,
        &row.principal,
    );
    Ok(PlaneJournalRecord::from_parts(
        scope.to_string(),
        row.seq,
        row.prev_hash,
        row.hash,
        content,
        AUDIT_FRAMING,
        AUDIT_DIGESTS_SCOPE,
    ))
}

/// READ-BACK DECODE BRIDGE to a TYPED record: reconstruct an [`AuditEntry`] from the NEW neutral body
/// OR an OLD `serde(AuditRecord)` body. Digest-faithful — the rebuilt fields feed the SAME bytes the
/// stored `hash` was sealed over, so a chain read back through it `verify_chain`-passes byte-identically.
/// `recorded_here` comes back FALSE: this is the store-seeding path, never a live append. `scope` is the
/// constant `admin` log, never read from the body.
#[allow(dead_code)] // read-back bridge: no production caller until the audit read path is cut over
pub(crate) fn audit_entry_from_body(_scope: &str, body: &[u8]) -> StoreResult<AuditEntry> {
    if let Ok(nb) = decode::<NeutralBody>(body) {
        let (ts, action, resource, outcome, principal) = parse_audit_suffix(&nb.content);
        return Ok(AuditEntry {
            seq: nb.seq,
            ts,
            action,
            resource,
            outcome,
            principal,
            prev_hash: nb.prev_hash,
            hash: nb.hash,
            recorded_here: false,
        });
    }
    let row: busbar_api::AuditRecord = decode(body)?;
    Ok(AuditEntry {
        seq: row.seq,
        ts: row.ts,
        action: row.action,
        resource: row.resource,
        outcome: row.outcome,
        principal: row.principal,
        prev_hash: row.prev_hash,
        hash: row.hash,
        recorded_here: false,
    })
}

/// What a boot restore actually found. Every number is reported rather than summed: they mean
/// different things to an operator, and a single number hides the one that is bad news.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AuditRestored {
    /// Records read back (the admin log has one scope, so this is the full restored ring bound).
    pub(crate) records: usize,
    /// Chains that FAILED to verify. Tamper evidence. The records are still restored and the chain
    /// still resumes from the broken tail — refusing would let anyone who can write to the store erase
    /// history by corrupting one record — but the break is reported.
    pub(crate) chain_breaks: Vec<ChainBreak>,
}

/// THE ADMIN AUDIT LOG'S DURABLE SEAM WRAPPER. A thin wrapper over the generic host-side journal (the
/// seq-authority, position cache and store-resume all live there now); this keeps only the admin RECORD
/// and the operator vocabulary its restore emits.
pub(crate) struct PlaneAuditLog {
    /// The host-side durable stream this log's chain is addressed by. Production is always
    /// [`KIND_ID_AUDIT`]; a TEST constructs a log over a FRESH id so parallel tests never share one
    /// process-global chain.
    kind_id: u32,
    /// THE READ MODEL. A bounded ring of the most-recent [`MAX_AUDIT_ENTRIES`] records, held newest-
    /// LAST (seq-ascending) so [`list_filtered`](PlaneAuditLog::list_filtered)'s `rev()` reads newest-
    /// first — the same shape and bound as the legacy [`crate::admin::audit::AuditLog`] ring it will
    /// replace as the `GET /audit` read source. Guarded by its OWN `Mutex` (independent of the seam's
    /// mint serialization point) and inserted BY SEQ, so the newest-first order holds even when a
    /// mint's release-to-push window interleaves with another recorder's.
    ring: Mutex<VecDeque<AuditEntry>>,
}

/// THE PROCESS-WIDE admin audit READ MODEL on the seam. Process state, not config-derived state, so it
/// lives as a global rather than on the swappable `App` snapshot — exactly like
/// [`crate::admin::audit::AUDIT`] and [`crate::plane::calllog::CALLS`], and for the same reason: a
/// config apply must not fork the chain by opening a SECOND ring at seq 1 under a chain that already
/// has one.
#[allow(dead_code)] // fed by the record_by seam emitter (A7.2b); read once GET /audit cuts over (A7.3c)
pub(crate) static AUDIT_LOG: std::sync::LazyLock<PlaneAuditLog> =
    std::sync::LazyLock::new(PlaneAuditLog::new);

impl Default for PlaneAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaneAuditLog {
    pub(crate) fn new() -> Self {
        Self {
            kind_id: KIND_ID_AUDIT,
            ring: Mutex::new(VecDeque::new()),
        }
    }

    /// TEST ONLY: a log addressed by a specific host-side stream id, so parallel tests never share one
    /// process-global chain.
    #[cfg(test)]
    pub(crate) fn with_kind_id(kind_id: u32) -> Self {
        Self {
            kind_id,
            ring: Mutex::new(VecDeque::new()),
        }
    }

    /// Insert one entry into the read-model ring in SEQ ORDER, pruning the oldest past
    /// [`MAX_AUDIT_ENTRIES`]. Sorted insert (O(n) at the 1000-entry bound) closes the seam's
    /// release-to-push window: the seam mints seq under the journal `positions` mutex, but the push
    /// here happens after that lock is released, so two records can arrive out of mint order — a
    /// by-seq insert restores order so [`list_filtered`](PlaneAuditLog::list_filtered)'s `rev()`
    /// newest-first holds.
    #[allow(dead_code)] // fed by the record_by seam emitter (A7.2b) / boot restore (A7.3b)
    pub(crate) fn push_entry(&self, entry: AuditEntry) {
        let mut q = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let pos = q.iter().position(|e| e.seq > entry.seq).unwrap_or(q.len());
        q.insert(pos, entry);
        while q.len() > MAX_AUDIT_ENTRIES {
            q.pop_front();
        }
    }

    /// A page of entries newest-first, optionally filtered by exact `action` and/or `resource`:
    /// skip `offset`, then take `limit`. `None` filters match everything. Copied VERBATIM from
    /// [`crate::admin::audit::AuditLog::list_filtered`] — the read surface `GET /audit` is cut over to
    /// once the ring is seeded and fed, byte-identical to the legacy ring it replaces.
    #[allow(dead_code)] // no production caller until the audit read path is cut over to the seam
    pub(crate) fn list_filtered(
        &self,
        offset: usize,
        limit: usize,
        action: Option<&str>,
        resource: Option<&str>,
    ) -> Vec<AuditEntry> {
        let q = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        q.iter()
            .rev()
            .filter(|e| action.is_none_or(|a| e.action == a))
            .filter(|e| resource.is_none_or(|r| e.resource == r))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// BOOT MIGRATION BRIDGE. The admin audit rows live in a SEPARATE durable table
    /// (`append_audit`/`list_audit`), not in the neutral `plane_records`. Read the durable tail
    /// (`list_audit_tail`), reframe each [`busbar_api::AuditRecord`] into the neutral body the seam
    /// persists, and SEED the host-side chain position from them so a later append continues the same
    /// chain from the persisted tail rather than forking at seq 1. A break is REPORTED and the chain
    /// still resumes from the broken tail. A read hiccup is surfaced as an error the caller logs.
    pub(crate) fn restore_legacy_table(
        &self,
        host: HostCtx,
        store: &dyn busbar_api::Store,
    ) -> StoreResult<AuditRestored> {
        let records = store.list_audit_tail(MAX_AUDIT_ENTRIES as u64)?;
        let mut out = AuditRestored::default();
        if records.is_empty() {
            return Ok(out);
        }
        let bodies: Vec<Vec<u8>> = records
            .iter()
            .map(|r| {
                let content = audit_suffix(r.ts, &r.action, &r.resource, &r.outcome, &r.principal);
                encode(&NeutralBody {
                    seq: r.seq,
                    prev_hash: r.prev_hash.clone(),
                    hash: r.hash.clone(),
                    content,
                })
            })
            .collect::<StoreResult<_>>()?;
        out.records = bodies.len();
        if let Some(brk) = self.seed_chain(host, ADMIN_LOG, &bodies)? {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_AUDITLOG_CHAIN_VERIFY_FAILED,
                break_detail = %brk,
                "admin audit CHAIN VERIFICATION FAILED on restore — the persisted records do not \
                 verify against their own hash chain. They are still restored and the chain resumes \
                 from the broken tail; refusing to restore them would let anyone able to write to the \
                 store DELETE audit history by corrupting one record."
            );
            out.chain_breaks.push(brk);
        }
        Ok(out)
    }

    /// BOOT RESTORE from the neutral `plane_records` (the shape the seam writes once dual-write is on):
    /// enumerate the scopes the store holds `audit` records for (the admin log's single `admin` scope),
    /// resume the chain from its persisted tail, and REPORT what was found. A break is reported and the
    /// chain still resumes from the broken tail.
    #[allow(dead_code)] // no production caller until the audit read path is cut over to the seam
    pub(crate) fn restore_from_store(
        &self,
        host: HostCtx,
        store: &dyn PlaneStore,
    ) -> StoreResult<AuditRestored> {
        let scopes = store.list_plane_record_parents(KIND_AUDIT)?;
        let mut out = AuditRestored::default();
        for scope in &scopes {
            let bodies =
                store.list_plane_records(KIND_AUDIT, &PlaneSelector::Parent(scope.clone()))?;
            out.records += bodies.len();
            if let Some(brk) = self.seed_chain(host, scope, &bodies)? {
                crate::diagnostics::diag_error!(
                    crate::diagnostics::PLANE_AUDITLOG_CHAIN_VERIFY_FAILED,
                    break_detail = %brk,
                    "admin audit CHAIN VERIFICATION FAILED on restore — the persisted records do not \
                     verify against their own hash chain. They are still restored and the chain \
                     resumes from the broken tail."
                );
                out.chain_breaks.push(brk);
            }
        }
        Ok(out)
    }

    /// SEED the admin chain's host-side position from its raw stored bodies through the durable seam.
    /// On a break the RICH [`ChainBreak`] is recomputed locally (read-only, touching no position) so the
    /// operator diagnostic still names WHICH break and WHERE; a clean verify returns `None`.
    fn seed_chain(
        &self,
        host: HostCtx,
        scope: &str,
        bodies: &[Vec<u8>],
    ) -> StoreResult<Option<ChainBreak>> {
        let packed = pack_bodies(bodies);
        let hdr =
            crate::plane_host::journal::seed_scoped_via_seam(host, self.kind_id, scope, &packed)
                .map_err(|()| {
                    StoreError("admin audit chain seed failed at the durable seam".to_string())
                })?;
        if hdr.broke == 0 {
            return Ok(None);
        }
        let records: Vec<PlaneJournalRecord> = bodies
            .iter()
            .map(|b| reframe_audit(scope, b))
            .collect::<StoreResult<_>>()?;
        Ok(verify_chain(&records).err())
    }
}

/// THE ONE PRODUCTION EMITTER for a mutation recorded through the seam. Mint the seq/prev_hash/hash
/// through the ONE core chain (host-side, under [`KIND_ID_AUDIT`]) and persist the neutral body.
///
/// FIRE-AND-FORGET, loudly. A durable-store write failure must NEVER fail the mutation it records: the
/// log is EVIDENCE, not ADMISSION, and a gateway whose control plane stops when its audit backend
/// blinks has converted an observability dependency into an availability dependency — the same call the
/// legacy audit sink made, for the same reason. The failure is surfaced at `error!` on the TRANSITION
/// into the failing state (a store outage recurs per mutation) and held at `debug!` thereafter; a
/// success clears the latch so a future outage re-errors. The chain position is left untouched on
/// failure, so the next mutation reuses the sequence and the chain stays contiguous.
#[allow(dead_code)] // wired at the converted admin/plane call sites; no caller until then
pub(crate) fn emit(host: HostCtx, scope: &str, suffix: Vec<u8>) {
    static WRITE_FAILED_LATCHED: AtomicBool = AtomicBool::new(false);
    let seq = crate::plane_host::journal::journal_append_scoped(
        host,
        KIND_ID_AUDIT,
        scope.as_ptr(),
        scope.len(),
        suffix.as_ptr(),
        suffix.len(),
    );
    if seq == Seq::NONE {
        if !WRITE_FAILED_LATCHED.swap(true, Ordering::Relaxed) {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_AUDITLOG_WRITE_FAILED,
                "the durable admin audit record could NOT be written through the journal seam: this \
                 mutation is being served and its evidence is being LOST on that path. The chain \
                 position is unchanged, so the chain stays contiguous — what is missing is this \
                 record, not the ones after it."
            );
        } else {
            crate::diagnostics::diag_debug!(
                crate::diagnostics::PLANE_AUDITLOG_WRITE_FAILED,
                "the durable admin audit record could NOT be written through the journal seam; its \
                 evidence is being LOST. The chain position is unchanged, so the chain stays contiguous."
            );
        }
    } else {
        WRITE_FAILED_LATCHED.store(false, Ordering::Relaxed);
    }
}

/// BOOT: register the admin `audit` stream, then MIGRATE the legacy durable audit table into the
/// host-side chain position (so the seam continues the same chain). Driven with a live `HostCtx` over
/// `app`. A restore read hiccup / chain-verify break is logged inside [`PlaneAuditLog`]; a store read
/// error is surfaced here as the boot diagnostic.
pub(crate) fn register_and_migrate(app: &Arc<crate::state::App>, store: &dyn busbar_api::Store) {
    register_audit_stream(app);
    let log = PlaneAuditLog::new();
    crate::plane_host::with_dispatch_scope(app, |host, _vt| {
        if let Err(e) = log.restore_legacy_table(host, store) {
            crate::diagnostics::diag_warn!(
                crate::diagnostics::BOOT_AUDIT_RESTORE_READ_FAILED,
                error = %e.0,
                "could not read the durable audit log to seed the journal seam; the seam chain \
                 starts fresh and will continue from the legacy tail on the next successful read"
            );
        }
    });
}

/// MIRROR one admin-audit record onto the durable journal seam beside its legacy-ring write. Mints the
/// timestamp plane-side (the same clock the ring uses at the same logical point) and appends the
/// scopeless suffix under the constant `admin` scope, opening a fresh dispatch scope to reach the
/// host-side chain. Fire-and-forget (see [`emit`]): it NEVER fails the mutation it records. The one call
/// a plane-side audit site adds while the ring stays authoritative for reads (the dual-write window).
#[allow(dead_code)] // called from the plane-gated audit sites; no caller with every plane compiled out
pub(crate) fn mirror(
    app: &crate::state::App,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) {
    let ts = crate::plane_host::clock_now_secs_over(app);
    let suffix = audit_suffix(ts, action, resource, outcome, principal);
    crate::plane_host::with_dispatch_scope(app, |host, _| emit(host, ADMIN_LOG, suffix));
}

// ── TEST HARNESS — the chain position is host-side now, so a test drives it over a host ────────────

/// TEST ONLY: a fresh, process-unique `audit` stream id, well above the production ids (1/2/3) and the
/// `plane_host::journal` test range (base 10_000), the A2A `task_event` range (100_000) and the MCP
/// `call` range (200_000).
#[cfg(test)]
pub(crate) fn fresh_test_kind_id() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(300_000);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

/// TEST ONLY: a `PlaneAuditLog` + an app whose governance store is `store`, with the `audit` stream
/// registered against it under a FRESH host-side id so parallel tests are isolated.
#[cfg(test)]
pub(crate) struct AuditTestHarness {
    pub(crate) log: PlaneAuditLog,
    pub(crate) app: Arc<crate::state::App>,
}

#[cfg(test)]
impl AuditTestHarness {
    pub(crate) fn over(store: Arc<dyn busbar_api::Store>) -> Self {
        let kind_id = fresh_test_kind_id();
        let gov =
            Arc::new(crate::governance::GovState::new(store, None).expect("gov store constructs"));
        let app = crate::test_support::TestApp::new().governance(gov).build();
        register_audit_stream_as(kind_id, &app);
        Self {
            log: PlaneAuditLog::with_kind_id(kind_id),
            app,
        }
    }

    /// Drive one synchronous chain op with a live `HostCtx` over this harness's app.
    pub(crate) fn host<R>(&self, f: impl FnOnce(HostCtx) -> R) -> R {
        crate::plane_host::with_dispatch_scope(&self.app, |h, _| f(h))
    }

    pub(crate) fn restore_from_store(&self, store: &dyn PlaneStore) -> StoreResult<AuditRestored> {
        self.host(|host| self.log.restore_from_store(host, store))
    }

    /// Append one record through the SEAM over THIS harness's isolated stream id and return the MINTED
    /// `(seq, prev_hash, hash)`. The production [`emit`] pins [`KIND_ID_AUDIT`] (which a parallel test
    /// must not share) and surfaces only fire-and-forget; a test drives the same chain-mint path over
    /// its own id and reads back the link the append sealed.
    pub(crate) fn emit_full(&self, scope: &str, suffix: Vec<u8>) -> (u64, String, String) {
        self.host(|host| {
            crate::plane_host::journal::journal_append_scoped_full(
                host,
                self.log.kind_id,
                scope,
                &suffix,
            )
            .expect("seam append")
        })
    }
}

#[cfg(test)]
mod auditlog_tests {
    use super::*;
    use crate::audit::{digest, frame_prelude, Framing};

    /// THE BYTE-IDENTITY GATE: the plane's pre-framed suffix, appended RAW after the host prelude
    /// framed with `digests_scope = false`, reproduces the legacy [`AuditEntry`] digest byte-for-byte.
    /// A perturbation of the suffix, the prelude framing, or the `digests_scope` flag would fail this.
    fn assert_roundtrip(
        seq: u64,
        prev_hash: &str,
        ts: u64,
        act: &str,
        res: &str,
        out: &str,
        pr: &str,
    ) {
        // The seam's digest input: frame_prelude(PipeSeparated, prev_hash, None=no scope, seq) ⧺ suffix.
        let mut input = frame_prelude(Framing::PipeSeparated, prev_hash, None, seq);
        input.extend_from_slice(&audit_suffix(ts, act, res, out, pr));
        let via_seam = busbar_api::sha256_hex(&input);

        // The legacy digest: the AuditEntry's own `digest_fields` through the ONE canonicaliser.
        let entry = AuditEntry {
            seq,
            ts,
            action: act.to_string(),
            resource: res.to_string(),
            outcome: out.to_string(),
            principal: pr.to_string(),
            prev_hash: prev_hash.to_string(),
            hash: String::new(),
            recorded_here: true,
        };
        let legacy = digest(&entry);
        assert_eq!(
            via_seam, legacy,
            "seam digest (digests_scope=false) must byte-equal the legacy AuditEntry digest"
        );
    }

    #[test]
    fn suffix_plus_scopeless_prelude_equals_legacy_audit_digest() {
        // Genesis (empty prev_hash) — the leading `|` before `seq` the empty prev_hash produces is
        // load-bearing; and a linked record.
        assert_roundtrip(
            1,
            "",
            1_700_000_000,
            "hook.register",
            "hook:compress",
            "applied",
            "admin",
        );
        assert_roundtrip(
            2,
            "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa",
            1_700_000_060,
            "hook.delete",
            "hook:compress",
            "applied",
            "admin",
        );
    }

    /// THE CONVERSION GATE: a converted site's record, appended through the SEAM, carries the SAME hash
    /// the legacy admin ring computes for the same fields at the same chain position — genesis AND the
    /// inter-record link. Feeds a fixed `ts` on both sides (the seam suffix built directly, the legacy
    /// `AuditEntry` filled directly) so the comparison isolates the digest, not the clock.
    #[test]
    fn a_converted_sites_seam_record_matches_the_legacy_ring_hash() {
        let h =
            AuditTestHarness::over(std::sync::Arc::new(busbar_store_memory::MemoryStore::new()));
        let (ts, act, res, out, pr) = (
            1_700_000_123u64,
            "hook.register",
            "hook:x",
            "applied",
            "admin",
        );

        // Append through the seam (the converted-site path) and read the link each append sealed.
        let (seq1, prev1, hash1) = h.emit_full(ADMIN_LOG, audit_suffix(ts, act, res, out, pr));
        let (seq2, prev2, hash2) = h.emit_full(
            ADMIN_LOG,
            audit_suffix(ts + 60, "hook.delete", res, out, pr),
        );

        // The legacy ring's records for the SAME fields at the SAME chain positions.
        let mk = |seq, ts, action: &str, prev: String| AuditEntry {
            seq,
            ts,
            action: action.to_string(),
            resource: res.to_string(),
            outcome: out.to_string(),
            principal: pr.to_string(),
            prev_hash: prev,
            hash: String::new(),
            recorded_here: true,
        };
        assert_eq!((seq1, prev1.as_str()), (1, ""), "genesis position");
        assert_eq!(hash1, digest(&mk(1, ts, act, String::new())));
        assert_eq!((seq2, prev2), (2, hash1.clone()), "record 2 links record 1");
        assert_eq!(hash2, digest(&mk(2, ts + 60, "hook.delete", hash1)));
    }
}
