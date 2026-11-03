// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::audit::journal::NeutralBody;
use crate::audit::stream_registry::{self, Decode, StreamRecord};
use crate::audit::{verify_chain, ChainBreak, Framing};
use crate::audit_ring::{AuditEntry, MAX_AUDIT_ENTRIES};
use crate::store::plane_view::{decode, encode, PlaneStore, PlaneStoreView, KIND_AUDIT};
use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStoreError, RecordStoreResult,
};

pub(crate) const KIND_ID_AUDIT: u32 = 3;

const ADMIN_LOG: &str = "admin";

const AUDIT_FRAMING: Framing = Framing::PipeSeparated;
const AUDIT_DIGESTS_SCOPE: bool = false;

pub(crate) fn register_audit_stream(app: &Arc<crate::state::App>) {
    register_audit_stream_as(KIND_ID_AUDIT, app);
}

pub(crate) fn register_audit_stream_as(kind_id: u32, app: &Arc<crate::state::App>) {
    stream_registry::register(
        kind_id,
        KIND_AUDIT.to_string(),
        AUDIT_FRAMING,
        AUDIT_DIGESTS_SCOPE,
        Decode::Native(reframe_audit),
        usize::MAX,
        app.governance
            .as_ref()
            .map(|gov| PlaneStoreView::narrow(gov.store())),
    );
}

pub(crate) fn audit_suffix(
    ts: u64,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) -> Vec<u8> {
    format!("|{ts}|{action}|{resource}|{outcome}|{principal}").into_bytes()
}

const SAFE_SUFFIX_MARKER: u8 = 0x00;

pub(crate) fn audit_suffix_safe(
    ts: u64,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(SAFE_SUFFIX_MARKER);
    push_lp(&mut out, &ts.to_be_bytes());
    push_lp(&mut out, action.as_bytes());
    push_lp(&mut out, resource.as_bytes());
    push_lp(&mut out, outcome.as_bytes());
    push_lp(&mut out, principal.as_bytes());
    out
}

pub(crate) fn admin_suffix(
    ts: u64,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) -> (Vec<u8>, u8) {
    if [action, resource, outcome].iter().any(|f| f.contains('|')) {
        (
            audit_suffix_safe(ts, action, resource, outcome, principal),
            crate::audit_ring::AUDIT_SCHEME_LENGTH_PREFIXED,
        )
    } else {
        (
            audit_suffix(ts, action, resource, outcome, principal),
            crate::audit_ring::AUDIT_SCHEME_PIPE,
        )
    }
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take_lp(rest: &mut &[u8]) -> Vec<u8> {
    let Some((len_bytes, after_len)) = rest.split_first_chunk::<8>() else {
        *rest = &[];
        return Vec::new();
    };
    let len = u64::from_be_bytes(*len_bytes) as usize;
    let Some(field) = after_len.get(..len) else {
        *rest = &[];
        return Vec::new();
    };
    *rest = &after_len[len..];
    field.to_vec()
}

fn parse_audit_suffix(content: &[u8]) -> (u64, String, String, String, String, u8) {
    if let Some(rest) = content.strip_prefix(&[SAFE_SUFFIX_MARKER]) {
        let mut rest = rest;
        let ts_bytes = take_lp(&mut rest);
        let mut ts_buf = [0u8; 8];
        let n = ts_bytes.len().min(8);
        ts_buf[..n].copy_from_slice(&ts_bytes[..n]);
        let ts = u64::from_be_bytes(ts_buf);
        let action = String::from_utf8_lossy(&take_lp(&mut rest)).into_owned();
        let resource = String::from_utf8_lossy(&take_lp(&mut rest)).into_owned();
        let outcome = String::from_utf8_lossy(&take_lp(&mut rest)).into_owned();
        let principal = String::from_utf8_lossy(&take_lp(&mut rest)).into_owned();
        return (
            ts,
            action,
            resource,
            outcome,
            principal,
            crate::audit_ring::AUDIT_SCHEME_LENGTH_PREFIXED,
        );
    }

    let s = String::from_utf8_lossy(content);
    let f: Vec<&str> = s.trim_start_matches('|').splitn(5, '|').collect();
    (
        f.first().and_then(|v| v.parse().ok()).unwrap_or(0),
        f.get(1).copied().unwrap_or_default().to_string(),
        f.get(2).copied().unwrap_or_default().to_string(),
        f.get(3).copied().unwrap_or_default().to_string(),
        f.get(4).copied().unwrap_or_default().to_string(),
        crate::audit_ring::AUDIT_SCHEME_PIPE,
    )
}

fn reframe_audit(scope: &str, body: &[u8]) -> RecordStoreResult<StreamRecord> {
    let nb: NeutralBody = decode(body)?;
    Ok(StreamRecord::from_parts(
        scope.to_string(),
        nb.seq,
        nb.prev_hash,
        nb.hash,
        nb.content,
        AUDIT_FRAMING,
        AUDIT_DIGESTS_SCOPE,
    ))
}

pub(crate) fn audit_entry_from_body(_scope: &str, body: &[u8]) -> RecordStoreResult<AuditEntry> {
    let nb: NeutralBody = decode(body)?;
    let (ts, action, resource, outcome, principal, scheme) = parse_audit_suffix(&nb.content);
    Ok(AuditEntry {
        seq: nb.seq,
        ts,
        action,
        resource,
        outcome,
        principal,
        prev_hash: nb.prev_hash,
        hash: nb.hash,
        scheme,
        recorded_here: false,
    })
}

/// What a boot restore actually found. Every number is reported rather than summed: they mean
/// different things to an operator, and a single number hides the one that is bad news.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AuditRestored {
    /// Records read back (the admin log has one scope, so this is the full restored ring bound).
    pub(crate) records: usize,
    /// Rows the store returned that could NOT be decoded — a body from a store format no released
    /// build wrote, or a corrupt/tampered row. COUNTED and SKIPPED per-record (never aborting the
    /// restore), and reported LOUDLY at the skip site with a coded diagnostic. On this
    /// tamper-evidence surface an unreadable row may be tamper evidence, not a mere format mismatch.
    pub(crate) unreadable: usize,
    /// Chains that FAILED to verify. Tamper evidence. The records are still restored and the chain
    /// still resumes from the broken tail — refusing would let anyone who can write to the store erase
    /// history by corrupting one record — but the break is reported.
    pub(crate) chain_breaks: Vec<ChainBreak>,
}

pub struct PlaneAuditLog {
    kind_id: u32,

    ring: Mutex<VecDeque<AuditEntry>>,
}

pub static AUDIT_LOG: std::sync::LazyLock<PlaneAuditLog> =
    std::sync::LazyLock::new(PlaneAuditLog::new);

#[cfg(any(test, feature = "test-support"))]
static ACCEPTED_ENTRY_TEST_HOOK: std::sync::OnceLock<fn(&AuditEntry)> = std::sync::OnceLock::new();

#[cfg(any(test, feature = "test-support"))]
pub fn install_accepted_entry_test_hook(hook: fn(&AuditEntry)) {
    let _ = ACCEPTED_ENTRY_TEST_HOOK.set(hook);
}

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

    #[cfg(test)]
    pub(crate) fn with_kind_id(kind_id: u32) -> Self {
        Self {
            kind_id,
            ring: Mutex::new(VecDeque::new()),
        }
    }

    pub(crate) fn push_entry(&self, entry: AuditEntry) {
        #[cfg(any(test, feature = "test-support"))]
        let observed = entry.recorded_here.then(|| entry.clone());
        let mut q = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let pos = q.iter().position(|e| e.seq > entry.seq).unwrap_or(q.len());
        q.insert(pos, entry);
        while q.len() > MAX_AUDIT_ENTRIES {
            q.pop_front();
        }
        drop(q);
        #[cfg(any(test, feature = "test-support"))]
        if core::ptr::eq(self, &*AUDIT_LOG) {
            if let Some(entry) = observed {
                if let Some(hook) = ACCEPTED_ENTRY_TEST_HOOK.get() {
                    hook(&entry);
                }
            }
        }
    }

    pub fn list_filtered(
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

    pub(crate) fn restore_from_store(
        &self,
        store: &dyn PlaneStore,
    ) -> RecordStoreResult<AuditRestored> {
        let restored = self.read_and_seed(store);
        if restored.is_err() {
            if let Some(stream) = stream_registry::handle(self.kind_id) {
                stream.journal.forget(ADMIN_LOG);
            }
        }
        restored
    }

    fn read_and_seed(&self, store: &dyn PlaneStore) -> RecordStoreResult<AuditRestored> {
        let scopes = store.list_plane_record_parents(KIND_AUDIT)?;
        let mut out = AuditRestored::default();
        for scope in &scopes {
            let bodies = store
                .list_plane_records(KIND_AUDIT, &PlaneSelector::Parent(scope.as_str().into()))?;

            let mut good_bodies: Vec<Vec<u8>> = Vec::with_capacity(bodies.len());
            for body in bodies {
                match audit_entry_from_body(scope, &body) {
                    Ok(entry) => {
                        self.push_entry(entry);
                        good_bodies.push(body);
                    }
                    Err(e) => {
                        out.unreadable += 1;
                        crate::diagnostics::diag_error!(
                            crate::diagnostics::PLANE_AUDIT_ROW_UNREADABLE,
                            scope = %scope,
                            error = %e,
                            "a persisted admin audit record could NOT be decoded on restore; it is \
                             being SKIPPED and counted rather than aborting the whole restore. The \
                             evidence in this one row is lost — reported here, never skipped \
                             silently, because on the admin audit log an undecodable row may be \
                             tamper evidence."
                        );
                    }
                }
            }
            out.records += good_bodies.len();
            if let Some(brk) = self.seed_chain(scope, &good_bodies)? {
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

    fn seed_chain(&self, scope: &str, bodies: &[Vec<u8>]) -> RecordStoreResult<Option<ChainBreak>> {
        let broke = stream_registry::seed(self.kind_id, scope, bodies).map_err(|()| {
            RecordStoreError("admin audit chain seed failed at the durable seam".to_string())
        })?;
        if !broke {
            return Ok(None);
        }
        let records: Vec<StreamRecord> = bodies
            .iter()
            .map(|b| reframe_audit(scope, b))
            .collect::<RecordStoreResult<_>>()?;
        Ok(verify_chain(&records).err())
    }
}

const MAX_PENDING_AUDIT: usize = 256;

/// One admin-audit mutation waiting for its durable write. `scope` plus the
/// already pre-framed `suffix` are everything a retry needs to replay the write byte-identically to
/// what would have been sent the first time — nothing is re-derived, so a recovered record is
/// indistinguishable from one that landed on the first try.
/// Only host-originated export-operation failures are excluded from Events redispatch. This
/// transient tag never comes from record text and never changes the persisted audit format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventOrigin {
    Mutation,
    ExportFailure,
}

impl EventOrigin {
    fn for_plugin_refusal(refusal: PluginRefusal, kind: &str) -> Self {
        if refusal == PluginRefusal::Op && kind == busbar_contract::plugin::Kind::Export.root() {
            Self::ExportFailure
        } else {
            Self::Mutation
        }
    }

    fn redispatch(self) -> bool {
        self != Self::ExportFailure
    }
}

#[derive(Clone)]
struct PendingAudit {
    scope: String,
    suffix: Vec<u8>,
    origin: EventOrigin,
}

struct PendingAuditQueue {
    rows: Mutex<PendingAuditRows>,

    dropped: AtomicU64,
    cap: usize,
}

struct PendingAuditRows {
    queued: VecDeque<PendingAudit>,
    draining: bool,
}

struct PendingAuditDrain<'a> {
    queue: &'a PendingAuditQueue,
    active: bool,
}

impl Drop for PendingAuditDrain<'_> {
    fn drop(&mut self) {
        if self.active {
            self.queue
                .rows
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .draining = false;
        }
    }
}

impl PendingAuditQueue {
    const fn new(cap: usize) -> Self {
        Self {
            rows: Mutex::new(PendingAuditRows {
                queued: VecDeque::new(),
                draining: false,
            }),
            dropped: AtomicU64::new(0),
            cap,
        }
    }

    fn enqueue(&self, p: PendingAudit) {
        let mut q = self.rows.lock().unwrap_or_else(|e| e.into_inner());
        let evicted = q.queued.len() >= self.cap;
        if evicted {
            q.queued.pop_front();
        }
        q.queued.push_back(p);
        drop(q);
        if evicted {
            self.record_gap();
        }
    }

    fn record_gap(&self) {
        let dropped_total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        crate::diagnostics::diag_error!(
            crate::diagnostics::PLANE_AUDITLOG_WRITE_FAILED,
            gap_detected = true,
            dropped_total,
            "the admin audit recovery queue is full (bound {MAX_PENDING_AUDIT}); the OLDEST \
                 queued record was evicted to admit this new failure and its evidence is now \
                 PERMANENTLY LOST — a DETECTED GAP in the audit trail, not a delayed recovery. \
                 {dropped_total} record(s) lost to this gap since boot."
        );
    }

    fn drain_with(
        &self,
        mint: impl Fn(&str, &[u8]) -> Result<(u64, String, String), ()>,
        mut on_recovered: impl FnMut(&PendingAudit, u64, String, String),
    ) {
        {
            let mut q = self.rows.lock().unwrap_or_else(|e| e.into_inner());
            if q.draining {
                return;
            }
            q.draining = true;
        }
        let mut owner = PendingAuditDrain {
            queue: self,
            active: true,
        };
        loop {
            let p = {
                let mut q = self.rows.lock().unwrap_or_else(|e| e.into_inner());
                let Some(p) = q.queued.pop_front() else {
                    q.draining = false;
                    owner.active = false;
                    return;
                };
                p
            };
            match mint(&p.scope, &p.suffix) {
                Ok((seq, prev_hash, hash)) => on_recovered(&p, seq, prev_hash, hash),
                Err(()) => {
                    let mut q = self.rows.lock().unwrap_or_else(|e| e.into_inner());

                    let evicted = q.queued.len() >= self.cap;
                    if !evicted {
                        q.queued.push_front(p);
                    }
                    q.draining = false;
                    owner.active = false;
                    drop(q);
                    if evicted {
                        self.record_gap();
                    }
                    return;
                }
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.rows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queued
            .len()
    }

    #[cfg(test)]
    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

static PENDING_AUDIT: PendingAuditQueue = PendingAuditQueue::new(MAX_PENDING_AUDIT);

fn enqueue_pending_audit(scope: &str, suffix: Vec<u8>, origin: EventOrigin) {
    PENDING_AUDIT.enqueue(PendingAudit {
        scope: scope.to_string(),
        suffix,
        origin,
    });
}

fn report_unwritten(latch: &AtomicBool) {
    if !latch.swap(true, Ordering::Relaxed) {
        crate::diagnostics::diag_error!(
            crate::diagnostics::PLANE_AUDITLOG_WRITE_FAILED,
            "the durable admin audit record could NOT be written through the journal seam: this \
             mutation is being served and its evidence is QUEUED for recovery rather than lost — it \
             will be retried the next time this stream writes successfully. The chain position is \
             unchanged, so the chain stays contiguous — what is missing FOR NOW is this record, not \
             the ones after it."
        );
    } else {
        crate::diagnostics::diag_debug!(
            crate::diagnostics::PLANE_AUDITLOG_WRITE_FAILED,
            "the durable admin audit record could NOT be written through the journal seam; its \
             evidence is QUEUED for recovery. The chain position is unchanged, so the chain stays \
             contiguous."
        );
    }
}

fn normalize_queued_append(
    result: RecordStoreResult<(u64, String, String)>,
) -> Result<(u64, String, String), ()> {
    result.map_err(|_| ())
}

fn drain_pending_audit() {
    static WRITE_FAILED_LATCHED: AtomicBool = AtomicBool::new(false);
    PENDING_AUDIT.drain_with(
        |scope, suffix| match normalize_queued_append(stream_registry::append_full(
            KIND_ID_AUDIT,
            scope,
            suffix,
        )) {
            Ok(written) => {
                WRITE_FAILED_LATCHED.store(false, Ordering::Relaxed);
                Ok(written)
            }
            Err(_) => {
                report_unwritten(&WRITE_FAILED_LATCHED);
                Err(())
            }
        },
        |p, seq, prev_hash, hash| {
            let (ts, action, resource, outcome, principal, scheme) = parse_audit_suffix(&p.suffix);
            let entry = AuditEntry {
                seq,
                ts,
                action,
                resource,
                outcome,
                principal,
                prev_hash,
                hash,
                scheme,
                recorded_here: true,
            };
            AUDIT_LOG.push_entry(entry.clone());
            if p.origin.redispatch() {
                deliver_audit_event(&entry);
            }
        },
    );
}

fn deliver_audit_event(entry: &AuditEntry) {
    use busbar_contract::abi::export::ExportStream;

    crate::export::plugin::deliver(ExportStream::Events, &entry.action, |projection| {
        Arc::new(project_audit_event(projection, entry))
    });
}

fn project_audit_event(
    projection: crate::export::projection::Projection,
    entry: &AuditEntry,
) -> serde_json::Value {
    use busbar_contract::abi::export::{ExportField as F, ExportStream};

    let mut record =
        crate::export::projection::ProjectedRecord::new(projection, ExportStream::Events);
    record
        .set(F::Seq, entry.seq)
        .set(F::Ts, entry.ts)
        .set(F::PrevHash, entry.prev_hash.as_str())
        .set(F::Kind, entry.action.as_str())
        .set(F::Actor, entry.principal.as_str())
        .set(F::Resource, entry.resource.as_str())
        .set(F::Outcome, entry.outcome.as_str());
    record.finish()
}

pub(crate) fn migrate_legacy_table_to_plane_records(
    store: &dyn busbar_contract::records::RecordStore,
) -> RecordStoreResult<usize> {
    let records = store.list_audit()?;
    let Some(legacy_tail) = records.last() else {
        return Ok(0);
    };

    let existing: std::collections::BTreeMap<u64, String> = store
        .list_plane_records(KIND_AUDIT, &PlaneSelector::Parent(ADMIN_LOG.into()))?
        .iter()
        .filter_map(|body| audit_entry_from_body(ADMIN_LOG, body).ok())
        .map(|e| (e.seq, e.hash))
        .collect();

    let copied_through = match existing.keys().next_back() {
        None => 0,
        Some(&top) => top.min(legacy_tail.seq),
    };
    if copied_through > 0 {
        let legacy_at = records.iter().find(|r| r.seq == copied_through);
        if legacy_at.map(|r| &r.hash) != existing.get(&copied_through) {
            return Err(busbar_contract::records::RecordStoreError(format!(
                "the admin audit plane_records disagree with the legacy audit table at seq \
                 {copied_through}: the legacy records above it are not copied, because two chains \
                 cannot be joined without re-sealing"
            )));
        }
    }
    let mut copied = 0;
    for r in records.iter().filter(|r| r.seq > copied_through) {
        let content = audit_suffix(r.ts, &r.action, &r.resource, &r.outcome, &r.principal);
        let body = encode(&NeutralBody {
            seq: r.seq,
            prev_hash: r.prev_hash.clone(),
            hash: r.hash.clone(),
            content,
        })?;

        store.append_plane_record(
            PlaneRecord {
                kind: KIND_AUDIT.to_string(),
                id: ADMIN_LOG.to_string(),
                parent: Some(ADMIN_LOG.to_string()),
                seq: r.seq,
                ts: r.ts,
                disposition: PlaneDisposition::Active,
                body,
            }
            .view(),
        )?;
        copied += 1;
    }
    Ok(copied)
}

pub(crate) fn register_and_migrate(
    app: &Arc<crate::state::App>,
    store: &Arc<dyn busbar_contract::records::RecordStore>,
) {
    register_audit_stream(app);

    match migrate_legacy_table_to_plane_records(store.as_ref()) {
        Ok(0) => {}
        Ok(n) => tracing::info!(
            records = n,
            "migrated the legacy durable audit table into the neutral plane_records seam"
        ),
        Err(e) => crate::diagnostics::diag_error!(
            crate::diagnostics::BOOT_AUDIT_MIGRATE_FAILED,
            error = %e.0,
            "could not migrate the legacy durable audit table into plane_records; the durable audit \
             seam will restore only what plane_records already holds and the migration retries on the \
             next boot"
        ),
    }

    let plane_store = PlaneStoreView::narrow(store.clone());
    match AUDIT_LOG.restore_from_store(plane_store.as_ref()) {
        Ok(restored) if restored.records > 0 || restored.unreadable > 0 => tracing::info!(
            records = restored.records,
            unreadable = restored.unreadable,
            chain_breaks = restored.chain_breaks.len(),
            "admin audit restored from the durable plane_records seam"
        ),
        Ok(_) => {}
        Err(e) => crate::diagnostics::diag_warn!(
            crate::diagnostics::BOOT_AUDIT_RESTORE_READ_FAILED,
            error = %e.0,
            "could not read the durable audit plane_records to seed the journal seam; the seam \
             read model starts empty, and the next admin audit write reads the persisted tail back \
             and continues the chain from it (a write the store still cannot serve is queued)"
        ),
    }

    open_plugin_refusals();
}

pub(crate) fn emit_admin_hostless(
    ts: u64,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) {
    emit_admin_hostless_from(
        ts,
        action,
        resource,
        outcome,
        principal,
        EventOrigin::Mutation,
    );
}

fn emit_admin_hostless_from(
    ts: u64,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
    origin: EventOrigin,
) {
    let (suffix, _) = admin_suffix(ts, action, resource, outcome, principal);

    drain_pending_audit();

    enqueue_pending_audit(ADMIN_LOG, suffix, origin);
    drain_pending_audit();
}

pub fn emit_admin_hostless_now(action: &str, resource: &str, outcome: &str, principal: &str) {
    let ts = busbar_kernel::store::now();
    emit_admin_hostless(ts, action, resource, outcome, principal);
}

/// What the host refused, or flagged, while a plugin started, bound or served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginRefusal {
    /// The trust policy left a plugin in the plugins directory unloaded.
    Trust,
    /// The trust policy LOADED a plugin no key vouches for (unsigned, tampered, third-party or
    /// signed by a retired release key), under an explicit `plugins.trust` opt-in: it serves,
    /// UNVERIFIED.
    Unverified,
    /// The connection table refused a need the instance declared at `open` or `refresh`.
    Need,
    /// The instance's `open` or `refresh` answered with a diagnostic its Statement declares, at
    /// warn or error: it loaded, flagged.
    Open,
    /// Another op of the instance answered with a diagnostic its Statement declares, at error: a
    /// refusal it met while serving (an IdP destination it refused, say).
    Op,
}

impl PluginRefusal {
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Trust | Self::Unverified => "plugin.trust",
            Self::Need => "plugin.need",
            Self::Open => "plugin.open",
            Self::Op => "plugin.op",
        }
    }

    #[must_use]
    pub const fn outcome(self) -> &'static str {
        match self {
            Self::Trust | Self::Need | Self::Op => busbar_contract::vocab::OUTCOME_REJECTED,
            Self::Open | Self::Unverified => busbar_contract::vocab::OUTCOME_DEGRADED,
        }
    }
}

pub const PLUGIN_REFUSAL_PRINCIPAL: &str = "host";

const REFUSAL_PART_MAX: usize = 64;

const MAX_HELD_REFUSALS: usize = 256;

const HELD_OVER_ACTION: &str = "plugin.refusals";

#[must_use]
pub fn plugin_refusal_resource(kind: &str, subject: &str, reason: &str) -> String {
    fn word(part: &str) -> String {
        let clamped: String = part
            .chars()
            .take(REFUSAL_PART_MAX)
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if clamped.is_empty() {
            "_".to_string()
        } else {
            clamped
        }
    }
    format!("plugin:{}/{}#{}", word(kind), word(subject), word(reason))
}

/// One refusal waiting for the chain: when it was raised, and the record it seals as.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HeldRefusal {
    ts: u64,
    refusal: PluginRefusal,
    resource: String,
    origin: EventOrigin,
}

struct RefusalHold {
    held: Mutex<Hold>,
}

struct Hold {
    rows: Vec<HeldRefusal>,

    over: u64,
    phase: Phase,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The chain is not open: every refusal is held.
    Closed,
    /// An open is sealing the held rows: every refusal is held behind them.
    Sealing,
    /// The chain is open: every refusal is sealed at once.
    Open,
}

impl RefusalHold {
    const fn new() -> Self {
        Self {
            held: Mutex::new(Hold {
                rows: Vec::new(),
                over: 0,
                phase: Phase::Closed,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Hold> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn raise(&self, row: HeldRefusal, seal: impl FnOnce(&HeldRefusal)) {
        let mut held = self.lock();
        if held.phase != Phase::Open {
            if held.rows.len() < MAX_HELD_REFUSALS {
                held.rows.push(row);
            } else {
                held.over += 1;
            }
            return;
        }
        drop(held);
        seal(&row);
    }

    fn open(&self, mut seal: impl FnMut(&HeldRefusal), mut over: impl FnMut(u64)) {
        let mut held = self.lock();
        if held.phase != Phase::Closed {
            return;
        }
        held.phase = Phase::Sealing;

        let opened = OpenOnDrop(self);
        loop {
            let rows = std::mem::take(&mut held.rows);
            let dropped = std::mem::take(&mut held.over);
            if rows.is_empty() && dropped == 0 {
                held.phase = Phase::Open;
                break;
            }
            drop(held);
            rows.iter().for_each(&mut seal);
            if dropped > 0 {
                over(dropped);
            }
            held = self.lock();
        }
        drop(held);
        std::mem::forget(opened);
    }
}

struct OpenOnDrop<'a>(&'a RefusalHold);

impl Drop for OpenOnDrop<'_> {
    fn drop(&mut self) {
        self.0.lock().phase = Phase::Open;
    }
}

static PLUGIN_REFUSALS: RefusalHold = RefusalHold::new();

fn seal_refusal(row: &HeldRefusal) {
    emit_admin_hostless_from(
        row.ts,
        row.refusal.action(),
        &row.resource,
        row.refusal.outcome(),
        PLUGIN_REFUSAL_PRINCIPAL,
        row.origin,
    );
}

pub fn record_plugin_refusal(refusal: PluginRefusal, kind: &str, subject: &str, reason: &str) {
    let origin = EventOrigin::for_plugin_refusal(refusal, kind);
    PLUGIN_REFUSALS.raise(
        HeldRefusal {
            ts: busbar_kernel::store::now(),
            refusal,
            resource: plugin_refusal_resource(kind, subject, reason),
            origin,
        },
        seal_refusal,
    );
}

pub(crate) fn open_plugin_refusals() {
    PLUGIN_REFUSALS.open(seal_refusal, |over| {
        emit_admin_hostless_now(
            HELD_OVER_ACTION,
            &format!("plugin:held/over#{over}"),
            busbar_contract::vocab::OUTCOME_REJECTED,
            PLUGIN_REFUSAL_PRINCIPAL,
        );
    });
}

#[cfg(test)]
pub(crate) fn fresh_test_kind_id() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(300_000);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

#[cfg(any(test, feature = "test-support"))]
pub fn register_test_audit_stream(app: &Arc<crate::state::App>) {
    register_audit_stream(app);
    open_plugin_refusals();
}

#[cfg(test)]
pub(crate) fn ensure_global_audit_stream_registered() {
    static REGISTERED: std::sync::Once = std::sync::Once::new();
    REGISTERED.call_once(|| {
        stream_registry::register(
            KIND_ID_AUDIT,
            KIND_AUDIT.to_string(),
            AUDIT_FRAMING,
            AUDIT_DIGESTS_SCOPE,
            Decode::Native(reframe_audit),
            usize::MAX,
            None,
        );
        open_plugin_refusals();
    });
}

#[cfg(test)]
pub(crate) struct AuditTestHarness {
    pub(crate) log: PlaneAuditLog,
}

#[cfg(test)]
impl AuditTestHarness {
    pub(crate) fn over(store: Arc<dyn busbar_contract::records::RecordStore>) -> Self {
        let kind_id = fresh_test_kind_id();
        stream_registry::register(
            kind_id,
            KIND_AUDIT.to_string(),
            AUDIT_FRAMING,
            AUDIT_DIGESTS_SCOPE,
            Decode::Native(reframe_audit),
            usize::MAX,
            Some(PlaneStoreView::narrow(store)),
        );
        Self {
            log: PlaneAuditLog::with_kind_id(kind_id),
        }
    }

    pub(crate) fn restore_from_store(
        &self,
        store: &dyn PlaneStore,
    ) -> RecordStoreResult<AuditRestored> {
        self.log.restore_from_store(store)
    }

    pub(crate) fn emit_full(&self, scope: &str, suffix: Vec<u8>) -> (u64, String, String) {
        stream_registry::append_full(self.log.kind_id, scope, &suffix).expect("seam append")
    }
}

#[cfg(test)]
#[path = "tests/auditlog_tests.rs"]
mod tests;
