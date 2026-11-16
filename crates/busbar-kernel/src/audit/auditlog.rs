// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::audit::journal::NeutralBody;
use crate::audit::stream_registry::{self, Decode, StreamRecord};
use crate::audit::{verify_chain, ChainBreak, Framing};
use crate::audit_ring::{AuditData, AuditEntry, MAX_AUDIT_ENTRIES};
use crate::host_records_async::{AsyncHistory, HistoryCollection, HistoryMode, HistoryOutcome};
use crate::persistence::facade::CoreStore;
use crate::store::plane_view::{encode, KIND_AUDIT};
use busbar_contract::records::Retention;
use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStoreError, RecordStoreResult,
};

/// Stable core-owned audit lineage, independent of a plugin instance name.
pub const PERSISTENCE_OWNER: &str = "busbar.core.admin-audit";

pub(crate) const KIND_ID_AUDIT: u32 = 3;

const ADMIN_LOG: &str = "admin";

const AUDIT_FRAMING: Framing = Framing::PipeSeparated;
const AUDIT_DIGESTS_SCOPE: bool = false;

pub(crate) fn register_audit_stream(app: &Arc<crate::state::App>) {
    register_audit_stream_as(KIND_ID_AUDIT, app);
}

pub(crate) fn register_audit_stream_as(kind_id: u32, app: &Arc<crate::state::App>) {
    // The legacy registry retains framing/read-cache ownership only. It receives
    // no synchronous backend sink and never authorizes durable publication.
    stream_registry::register(
        kind_id,
        KIND_AUDIT.to_string(),
        AUDIT_FRAMING,
        AUDIT_DIGESTS_SCOPE,
        Decode::Native(reframe_audit),
        usize::MAX,
    );
    if let Some(store) = app
        .governance
        .as_ref()
        .and_then(|gov| gov.core_store_handle().ok())
    {
        if let Err(error) = install_native(kind_id, store) {
            tracing::error!("{error}");
        }
    }
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

/// Everything an audit row says besides its position in the chain (ADMIN-API-1.6 section 7.2).
/// The five legacy fields come first; the rest are the scheme 3 fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditRowInput {
    pub action: String,
    pub resource: String,
    pub outcome: String,
    pub principal: String,
    pub config_generation: Option<String>,
    pub sections_changed: Vec<String>,
    pub request_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub kind: Option<String>,
    pub instance: Option<String>,
    /// `info`, `warning` or `error`; empty is `info`.
    pub severity: String,
    pub message: String,
    pub data: AuditData,
}

/// The first byte of a scheme 3 suffix. Scheme 1 starts with `|` and scheme 2 with 0x00.
const ROW_SUFFIX_MARKER: u8 = 0x03;

fn push_opt(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => push_lp(out, &[0]),
        Some(text) => {
            let mut field = Vec::with_capacity(text.len() + 1);
            field.push(1);
            field.extend_from_slice(text.as_bytes());
            push_lp(out, &field);
        }
    }
}

/// The bytes scheme 3 seals for one row (the recipe is on `AuditEntry::hash`).
pub(crate) fn row_suffix(ts: u64, row: &AuditRowInput) -> Vec<u8> {
    let mut out = vec![ROW_SUFFIX_MARKER];
    push_lp(&mut out, &ts.to_be_bytes());
    push_lp(&mut out, row.action.as_bytes());
    push_lp(&mut out, row.resource.as_bytes());
    push_lp(&mut out, row.outcome.as_bytes());
    push_lp(&mut out, row.principal.as_bytes());
    push_opt(&mut out, row.config_generation.as_deref());
    push_opt(&mut out, row.request_id.as_deref());
    push_opt(&mut out, row.idempotency_key.as_deref());
    push_opt(&mut out, row.kind.as_deref());
    push_opt(&mut out, row.instance.as_deref());
    out.extend_from_slice(&(row.sections_changed.len() as u64).to_be_bytes());
    for section in &row.sections_changed {
        push_lp(&mut out, section.as_bytes());
    }
    let severity = if row.severity.is_empty() {
        crate::audit_ring::SEVERITIES[0]
    } else {
        row.severity.as_str()
    };
    push_lp(&mut out, severity.as_bytes());
    push_lp(&mut out, row.message.as_bytes());
    push_lp(&mut out, row.data.as_str().as_bytes());
    out
}

/// A sealed suffix read back: its `ts`, the scheme it was sealed under and the row.
pub(crate) struct ParsedSuffix {
    pub(crate) ts: u64,
    pub(crate) scheme: u8,
    pub(crate) row: AuditRowInput,
}

fn lossy(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn take_opt(rest: &mut &[u8]) -> Option<String> {
    let field = take_lp(rest);
    match field.split_first() {
        Some((1, text)) => Some(String::from_utf8_lossy(text).into_owned()),
        _ => None,
    }
}

fn ts_of(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    buf[..n].copy_from_slice(&bytes[..n]);
    u64::from_be_bytes(buf)
}

/// Read a sealed suffix of any scheme. A scheme 1 or 2 suffix reads with the row defaults
/// (severity `info`, no `data`); a damaged scheme 3 suffix reads as far as it goes and never panics.
pub(crate) fn parse_suffix_entry(content: &[u8]) -> ParsedSuffix {
    let Some(mut rest) = content.strip_prefix(&[ROW_SUFFIX_MARKER]) else {
        let (ts, action, resource, outcome, principal, scheme) = parse_audit_suffix(content);
        return ParsedSuffix {
            ts,
            scheme,
            row: AuditRowInput {
                action,
                resource,
                outcome,
                principal,
                severity: crate::audit_ring::SEVERITIES[0].to_string(),
                ..Default::default()
            },
        };
    };
    let ts = ts_of(&take_lp(&mut rest));
    let action = lossy(take_lp(&mut rest));
    let resource = lossy(take_lp(&mut rest));
    let outcome = lossy(take_lp(&mut rest));
    let principal = lossy(take_lp(&mut rest));
    let config_generation = take_opt(&mut rest);
    let request_id = take_opt(&mut rest);
    let idempotency_key = take_opt(&mut rest);
    let kind = take_opt(&mut rest);
    let instance = take_opt(&mut rest);
    let count = match rest.split_first_chunk::<8>() {
        Some((count, after)) => {
            rest = after;
            u64::from_be_bytes(*count)
        }
        None => {
            rest = &[];
            0
        }
    };
    let mut sections_changed = Vec::new();
    for _ in 0..count {
        if rest.is_empty() {
            break;
        }
        sections_changed.push(lossy(take_lp(&mut rest)));
    }
    let severity = lossy(take_lp(&mut rest));
    let message = lossy(take_lp(&mut rest));
    let data = AuditData::from_json(&lossy(take_lp(&mut rest))).unwrap_or_default();
    ParsedSuffix {
        ts,
        scheme: crate::audit_ring::AUDIT_SCHEME_ROW,
        row: AuditRowInput {
            action,
            resource,
            outcome,
            principal,
            config_generation,
            sections_changed,
            request_id,
            idempotency_key,
            kind,
            instance,
            severity,
            message,
            data,
        },
    }
}

/// The entry for a sealed suffix at its chain position.
fn entry_of(
    seq: u64,
    prev_hash: String,
    hash: String,
    parsed: ParsedSuffix,
    recorded_here: bool,
) -> AuditEntry {
    let ParsedSuffix { ts, scheme, row } = parsed;
    AuditEntry {
        seq,
        ts,
        action: row.action,
        resource: row.resource,
        outcome: row.outcome,
        principal: row.principal,
        prev_hash,
        hash,
        scheme,
        config_generation: row.config_generation,
        sections_changed: row.sections_changed,
        request_id: row.request_id,
        idempotency_key: row.idempotency_key,
        kind: row.kind,
        instance: row.instance,
        severity: row.severity,
        message: row.message,
        data: row.data,
        recorded_here,
    }
}

/// Every action the engine writes to the admin audit (ADMIN-API-1.6 section 7.2). The set is closed:
/// `action=` matches these names and their nouns, and `components.x-busbar-audit-actions` publishes
/// it. Sorted by byte order. `keyset.rotated`, `plugin.health`, `plugin.reloaded`, `store.connected`
/// and `store.disconnected` are the engine events section 17 writes; they are published ahead of
/// their emitters.
pub const AUDIT_ACTIONS: &[&str] = &[
    "admin.forbidden",
    "admin.rate_limited",
    "admin.restart",
    "auth.admin_chain_put",
    "auth.cache_flush",
    "auth.operator.accepted",
    "auth.operator.inert",
    "auth.operator.refused",
    "config.apply",
    "config.document",
    "config.egress_proxy",
    "config.reload",
    "config.rollback",
    "config.settings",
    "credential.at_rest.open",
    "credential.at_rest.rewrap",
    "diagnostic.raised",
    "group.create",
    "group.delete",
    "group.patch",
    "group.provision",
    "group.replace",
    "hook.delete",
    "hook.register",
    "hook.replace",
    "hook.settings",
    "key.create",
    "key.delete",
    "key.patch",
    "key.revoke",
    "key.rotate",
    "keyset.rotated",
    "node.boot",
    "node.drain",
    "overlay.reset",
    "plugin.health",
    "plugin.install",
    "plugin.need",
    "plugin.op",
    "plugin.open",
    "plugin.refusals",
    "plugin.reload",
    "plugin.reloaded",
    "plugin.remove",
    "plugin.rollback",
    "plugin.trust",
    "signing_key.report",
    "store.connected",
    "store.disconnected",
];

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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedAuditBody {
    seq: u64,
    prev_hash: String,
    hash: String,
    content: Vec<u8>,
}
fn decode_audit_body(body: &[u8]) -> RecordStoreResult<NeutralBody> {
    let value: PersistedAuditBody = serde_json::from_slice(body)
        .map_err(|_| RecordStoreError("unknown or damaged native audit body".into()))?;
    Ok(NeutralBody {
        seq: value.seq,
        prev_hash: value.prev_hash,
        hash: value.hash,
        content: value.content,
    })
}

fn reframe_audit(scope: &str, body: &[u8]) -> RecordStoreResult<StreamRecord> {
    let nb = decode_audit_body(body)?;
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
    let nb = decode_audit_body(body)?;
    Ok(entry_of(
        nb.seq,
        nb.prev_hash,
        nb.hash,
        parse_suffix_entry(&nb.content),
        false,
    ))
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

#[derive(PartialEq, Eq)]
struct AuditIdentity {
    scope: String,
    seq: u64,
    prev_hash: String,
    hash: String,
    content: Vec<u8>,
}

struct KeptAuditEntry {
    entry: AuditEntry,
    identity: AuditIdentity,
}

pub struct PlaneAuditLog {
    kind_id: u32,

    ring: Mutex<VecDeque<KeptAuditEntry>>,

    /// Pulsed by `push_entry` so `GET /audit?wait=` wakes on the next mutation.
    appended: tokio::sync::Notify,
}

/// One keyset read of the live ring (`GET /audit`): rows strictly after `after` in `seq` order.
#[derive(Default)]
pub struct AuditQuery<'a> {
    /// Resume strictly after this `seq` (ascending: greater; descending: smaller). `None` starts at
    /// the oldest (ascending) or newest (descending) retained row.
    pub after: Option<u64>,
    pub descending: bool,
    pub limit: usize,
    /// Each entry is an exact `noun.verb` or a bare `noun` that matches every `noun.*`. Empty admits all.
    pub actions: &'a [&'a str],
    pub resource: Option<&'a str>,
    /// `info`, `warning` or `error`: exact.
    pub severity: Option<&'a str>,
    /// The engine kind of the instance a row is about: exact.
    pub kind: Option<&'a str>,
    /// The instance a row is about: exact.
    pub instance: Option<&'a str>,
}

/// Whether `action` is admitted by an `action=` filter: an entry with a dot is an exact action name,
/// a dot-free entry is a noun and admits its whole family.
pub(crate) fn action_admitted(filter: &[&str], action: &str) -> bool {
    filter.is_empty()
        || filter.iter().any(|f| {
            if f.contains('.') {
                action == *f
            } else {
                action.split('.').next() == Some(*f)
            }
        })
}

/// Whether `query`'s action, resource, severity, kind and instance filters admit `entry`.
fn query_admits(query: &AuditQuery<'_>, entry: &AuditEntry) -> bool {
    action_admitted(query.actions, &entry.action)
        && query.resource.is_none_or(|r| entry.resource == r)
        && query.severity.is_none_or(|s| entry.severity == s)
        && query.kind.is_none_or(|k| entry.kind.as_deref() == Some(k))
        && query
            .instance
            .is_none_or(|i| entry.instance.as_deref() == Some(i))
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
            appended: tokio::sync::Notify::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_kind_id(kind_id: u32) -> Self {
        Self {
            kind_id,
            ring: Mutex::new(VecDeque::new()),
            appended: tokio::sync::Notify::new(),
        }
    }

    fn push_entry(&self, entry: AuditEntry, scope: &str, content: Vec<u8>, restoring: bool) {
        let identity = AuditIdentity {
            scope: scope.to_owned(),
            seq: entry.seq,
            prev_hash: entry.prev_hash.clone(),
            hash: entry.hash.clone(),
            content,
        };
        #[cfg(any(test, feature = "test-support"))]
        let observed = entry.recorded_here.then(|| entry.clone());
        let mut q = self.ring.lock().unwrap_or_else(|e| e.into_inner());

        if restoring && q.iter().any(|kept| kept.identity == identity) {
            return;
        }
        let pos = q
            .iter()
            .position(|e| e.entry.seq > entry.seq)
            .unwrap_or(q.len());
        q.insert(pos, KeptAuditEntry { entry, identity });
        while q.len() > MAX_AUDIT_ENTRIES {
            q.pop_front();
        }
        drop(q);
        self.appended.notify_waiters();
        #[cfg(any(test, feature = "test-support"))]
        if core::ptr::eq(self, &*AUDIT_LOG) {
            if let Some(entry) = observed {
                if let Some(hook) = ACCEPTED_ENTRY_TEST_HOOK.get() {
                    hook(&entry);
                }
            }
        }
    }

    /// One bounded, same-lock observation of the live ring. Offsets are not snapshots.
    pub fn list_page(
        &self,
        offset: usize,
        limit: usize,
        action: Option<&str>,
        resource: Option<&str>,
    ) -> crate::audit_ring::AuditPage {
        let q = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let limit = limit.clamp(1, MAX_AUDIT_ENTRIES);
        let mut items: Vec<_> = q
            .iter()
            .rev()
            .map(|kept| &kept.entry)
            .filter(|e| action.is_none_or(|a| e.action == a))
            .filter(|e| resource.is_none_or(|r| e.resource == r))
            .skip(offset)
            .take(limit + 1)
            .cloned()
            .collect();
        let has_more = items.len() > limit;
        items.truncate(limit);
        crate::audit_ring::AuditPage {
            returned_from: items.last().map(|e| e.seq.to_string()),
            returned_to: items.first().map(|e| e.seq.to_string()),
            retained_from: q.front().map(|e| e.entry.seq.to_string()),
            retained_to: q.back().map(|e| e.entry.seq.to_string()),
            retention_limit: MAX_AUDIT_ENTRIES.to_string(),
            semantics: "live_offset".into(),
            // An offset/filter observation cannot establish complete audit coverage.
            complete: false,
            truncated: has_more,
            items,
        }
    }

    /// A future that completes at the next append. Create it (and `enable` it) before the read it
    /// guards, so an append between the read and the await is not missed.
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.appended.notified()
    }

    /// One bounded keyset read of the live ring: rows strictly after `query.after` in `seq` order.
    /// `Err(oldest_available)` when an ascending read resumes below what the ring still holds, so
    /// rows between were lost (the caller answers 410 `cursor_expired`); the value is the `seq` a
    /// cursor must carry to start at the oldest retained row.
    pub fn list_after(&self, query: &AuditQuery<'_>) -> Result<crate::audit_ring::AuditPage, u64> {
        let q = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let limit = query.limit.clamp(1, MAX_AUDIT_ENTRIES);
        let oldest = q.front().map(|kept| kept.entry.seq);
        if let (false, Some(after), Some(oldest)) = (query.descending, query.after, oldest) {
            if after.saturating_add(1) < oldest {
                return Err(oldest - 1);
            }
        }
        let admitted = |e: &&AuditEntry| query_admits(query, e);
        let mut items: Vec<AuditEntry> = if query.descending {
            q.iter()
                .rev()
                .map(|kept| &kept.entry)
                .filter(|e| query.after.is_none_or(|a| e.seq < a))
                .filter(admitted)
                .take(limit + 1)
                .cloned()
                .collect()
        } else {
            q.iter()
                .map(|kept| &kept.entry)
                .filter(|e| query.after.is_none_or(|a| e.seq > a))
                .filter(admitted)
                .take(limit + 1)
                .cloned()
                .collect()
        };
        let has_more = items.len() > limit;
        items.truncate(limit);
        let (lowest, highest) = if query.descending {
            (items.last(), items.first())
        } else {
            (items.first(), items.last())
        };
        Ok(crate::audit_ring::AuditPage {
            returned_from: lowest.map(|e| e.seq.to_string()),
            returned_to: highest.map(|e| e.seq.to_string()),
            retained_from: q.front().map(|e| e.entry.seq.to_string()),
            retained_to: q.back().map(|e| e.entry.seq.to_string()),
            retention_limit: MAX_AUDIT_ENTRIES.to_string(),
            semantics: "keyset".into(),
            // An ascending read that reached the tail is caught up; a descending list is a
            // finite inventory and proves nothing about coverage.
            complete: !query.descending && !has_more,
            truncated: has_more,
            items,
        })
    }

    /// `list_after`, but an ascending read is answered from the Store when this node has one: the
    /// admin chain is one deployment-wide log, so a row another node appended, or one older than the
    /// ring's 1000 rows or than this process, is served too. Falls back to the ring when no Store
    /// is attached or it cannot be read.
    pub async fn list_after_store(
        &self,
        query: &AuditQuery<'_>,
    ) -> Result<crate::audit_ring::AuditPage, u64> {
        if query.descending {
            return self.list_after(query);
        }
        let Some(native) = native_owner(self.kind_id).filter(|n| n.ready.load(Ordering::Acquire))
        else {
            return self.list_after(query);
        };
        let Ok(records) = native.history.list(KIND_AUDIT, &PlaneSelector::All).await else {
            return self.list_after(query);
        };
        let mut rows: Vec<AuditEntry> = records
            .iter()
            .filter(|record| record.kind == KIND_AUDIT)
            .filter_map(|record| audit_entry_from_body(&record.id, &record.body).ok())
            .collect();
        rows.sort_by_key(|entry| entry.seq);
        rows.dedup_by_key(|entry| entry.seq);
        let retained_from = rows.first().map(|entry| entry.seq);
        let retained_to = rows.last().map(|entry| entry.seq);
        if let (Some(after), Some(oldest)) = (query.after, retained_from) {
            if after.saturating_add(1) < oldest {
                return Err(oldest - 1);
            }
        }
        let limit = query.limit.clamp(1, MAX_AUDIT_ENTRIES);
        let mut items: Vec<AuditEntry> = rows
            .into_iter()
            .filter(|entry| query.after.is_none_or(|after| entry.seq > after))
            .filter(|entry| query_admits(query, entry))
            .take(limit + 1)
            .collect();
        let has_more = items.len() > limit;
        items.truncate(limit);
        Ok(crate::audit_ring::AuditPage {
            returned_from: items.first().map(|e| e.seq.to_string()),
            returned_to: items.last().map(|e| e.seq.to_string()),
            retained_from: retained_from.map(|seq| seq.to_string()),
            retained_to: retained_to.map(|seq| seq.to_string()),
            retention_limit: MAX_AUDIT_ENTRIES.to_string(),
            semantics: "keyset".into(),
            complete: !has_more,
            truncated: has_more,
            items,
        })
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
            .map(|kept| &kept.entry)
            .filter(|e| action.is_none_or(|a| e.action == a))
            .filter(|e| resource.is_none_or(|r| e.resource == r))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
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

/// Confirmation observers for one administrative execution, independent of queue custody.
#[derive(Default)]
pub struct AuditRequest {
    confirmations: Mutex<Vec<Arc<AtomicBool>>>,
    context: Mutex<RequestAudit>,
    failed: AtomicBool,
}

tokio::task_local! {
    static AUDIT_REQUEST: Arc<AuditRequest>;
}

/// Capture the current request when an existing owner transfers execution to another task.
pub fn current_request() -> Option<Arc<AuditRequest>> {
    AUDIT_REQUEST.try_with(Arc::clone).ok()
}

/// Carry the same audit observers across an owned asynchronous execution.
pub async fn scope_request<F: std::future::Future>(
    request: Option<Arc<AuditRequest>>,
    future: F,
) -> F::Output {
    match request {
        Some(request) => AUDIT_REQUEST.scope(request, future).await,
        None => future.await,
    }
}

/// Carry the same observers onto an existing blocking worker.
pub fn scope_request_sync<T>(request: Option<Arc<AuditRequest>>, work: impl FnOnce() -> T) -> T {
    match request {
        Some(request) => AUDIT_REQUEST.sync_scope(request, work),
        None => work(),
    }
}

/// What one admin request tells the rows it causes (ADMIN-API-1.6 section 7.2).
#[derive(Default)]
struct RequestAudit {
    idempotency_key: Option<String>,
    /// Reads the config generation the request's change published; called when an applied row is
    /// written, after the change committed.
    generation: Option<Arc<dyn Fn() -> u64 + Send + Sync>>,
    sections: Vec<String>,
}

fn with_context(set: impl FnOnce(&mut RequestAudit)) {
    if let Some(request) = current_request() {
        set(&mut request.context.lock().unwrap_or_else(|e| e.into_inner()));
    }
}

/// The `Idempotency-Key` of the request in flight; its rows carry it.
pub fn note_idempotency_key(key: &str) {
    with_context(|ctx| ctx.idempotency_key = Some(key.to_string()));
}

/// Where the request in flight reads the config generation its change published. Set only for a
/// config-changing request: its applied rows then carry `config_generation`.
pub fn note_generation_source(source: Arc<dyn Fn() -> u64 + Send + Sync>) {
    with_context(|ctx| ctx.generation = Some(source));
}

/// The config sections the request in flight changed; its applied rows carry them.
pub fn note_sections_changed(sections: Vec<String>) {
    with_context(|ctx| ctx.sections = sections);
}

/// Fill what `row` leaves unset from the request in flight: its id, its `Idempotency-Key`, and, on an
/// applied row only (a rejected one changed nothing), the generation and sections it changed.
pub(crate) fn stamp_request_context(row: &mut AuditRowInput) {
    if row.request_id.is_none() {
        row.request_id = crate::admin::gate::request_id_in_scope();
    }
    let Some(request) = current_request() else {
        return;
    };
    let (key, generation, sections) = {
        let ctx = request.context.lock().unwrap_or_else(|e| e.into_inner());
        (
            ctx.idempotency_key.clone(),
            ctx.generation.clone(),
            ctx.sections.clone(),
        )
    };
    if row.idempotency_key.is_none() {
        row.idempotency_key = key;
    }
    if row.outcome == busbar_contract::vocab::OUTCOME_APPLIED {
        if row.config_generation.is_none() {
            row.config_generation = generation.map(|read| read().to_string());
        }
        if row.sections_changed.is_empty() {
            row.sections_changed = sections;
        }
    }
}

/// Write one row under hash scheme 3, stamped with the request in flight.
pub fn emit_row_now(mut row: AuditRowInput) {
    stamp_request_context(&mut row);
    let suffix = row_suffix(busbar_kernel::store::now(), &row);
    drain_pending_audit();
    enqueue_pending_audit(ADMIN_LOG, suffix, EventOrigin::Mutation);
    drain_pending_audit();
}

fn request_failed() {
    if let Some(request) = current_request() {
        request.failed.store(true, Ordering::Release);
    }
}

fn request_confirmation() -> Option<Arc<AtomicBool>> {
    let request = current_request()?;
    let mut confirmations = request
        .confirmations
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if confirmations.len() >= MAX_PENDING_AUDIT {
        request.failed.store(true, Ordering::Release);
        return None;
    }
    let confirmation = Arc::new(AtomicBool::new(false));
    confirmations.push(confirmation.clone());
    Some(confirmation)
}

/// Run one request and confirm its exact emitted events before publishing the result.
/// Cancellation drops only observers: queued originals retain their native replay custody.
pub async fn confirmed_request<F: std::future::Future>(
    future: F,
) -> (F::Output, RecordStoreResult<()>) {
    let request = Arc::new(AuditRequest::default());
    let result = scope_request(Some(request.clone()), future).await;
    let confirmations = request
        .confirmations
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let confirmed = || {
        confirmations
            .iter()
            .all(|event| event.load(Ordering::Acquire))
    };
    let drained = if confirmed() {
        Ok(())
    } else {
        flush_pending().await
    };
    let publication = if request.failed.load(Ordering::Acquire) {
        Err(RecordStoreError(
            "request audit enqueue was not confirmed".into(),
        ))
    } else if confirmed() {
        Ok(())
    } else {
        drained.and(Err(RecordStoreError(
            "request audit publication remains unconfirmed".into(),
        )))
    };
    (result, publication)
}

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
    /// Logical identity is installed before any native planning or send.
    operation: [u8; 16],
    /// Exact source envelope survives unknown outcomes and cancelled drains.
    prepared: Option<PreparedAudit>,
    /// Observers never own, cancel or replace this queued original.
    confirmation: Option<Arc<AtomicBool>>,
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
        if self.try_enqueue(p).is_err() {
            self.record_gap();
        }
    }

    fn try_enqueue(&self, p: PendingAudit) -> RecordStoreResult<()> {
        let mut q = self.rows.lock().unwrap_or_else(|e| e.into_inner());
        if q.queued.len() >= self.cap {
            request_failed();
            return Err(RecordStoreError(
                "the admin audit recovery queue is full".into(),
            ));
        }
        q.queued.push_back(p);
        Ok(())
    }

    fn record_gap(&self) {
        request_failed();
        let dropped_total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        crate::diagnostics::diag_error!(
            crate::diagnostics::PLANE_AUDITLOG_WRITE_FAILED,
            gap_detected = true,
            dropped_total,
            "the admin audit recovery queue is full (bound {MAX_PENDING_AUDIT}); the new \
                 event cannot be queued and its evidence is PERMANENTLY LOST — a DETECTED GAP in the audit trail, not a delayed recovery. \
                 {dropped_total} record(s) lost to this gap since boot."
        );
    }

    #[cfg(test)]
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

fn pending_audit(
    scope: &str,
    suffix: Vec<u8>,
    origin: EventOrigin,
) -> RecordStoreResult<PendingAudit> {
    let mut operation = [0; 16];
    busbar_contract::crypto::fill(&mut operation).map_err(|error| {
        request_failed();
        RecordStoreError(format!("admin audit operation entropy: {error}"))
    })?;
    Ok(PendingAudit {
        scope: scope.to_string(),
        suffix,
        origin,
        operation,
        prepared: None,
        confirmation: request_confirmation(),
    })
}

fn enqueue_pending_audit(scope: &str, suffix: Vec<u8>, origin: EventOrigin) {
    match pending_audit(scope, suffix, origin) {
        Ok(pending) => PENDING_AUDIT.enqueue(pending),
        Err(_) => PENDING_AUDIT.record_gap(),
    }
}

#[cfg(test)]
fn normalize_queued_append(
    result: RecordStoreResult<(u64, String, String)>,
) -> Result<(u64, String, String), ()> {
    result.map_err(|_| ())
}

fn drain_pending_audit() {
    let Some(native) = native_owner(KIND_ID_AUDIT) else {
        return;
    };
    if !native.ready.load(Ordering::Acquire) {
        return;
    }
    {
        let mut queue = PENDING_AUDIT
            .rows
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if queue.draining || queue.queued.is_empty() {
            return;
        }
        queue.draining = true;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        PENDING_AUDIT
            .rows
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .draining = false;
        return;
    };
    runtime.spawn(async move {
        let _owner = PendingAuditDrain {
            queue: &PENDING_AUDIT,
            active: true,
        };
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            drain_native(&PENDING_AUDIT, &AUDIT_LOG, native),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!("{error}"),
            Err(_) => tracing::warn!(
                "native audit drain timed out; original operation and envelope remain queued"
            ),
        }
    });
}

/// Resolve retained audit originals during orderly shutdown or an explicit retry.
/// Success means this observed queue drained; new callers may enqueue afterwards.
pub async fn flush_pending() -> RecordStoreResult<()> {
    let native = native_owner(KIND_ID_AUDIT)
        .ok_or_else(|| RecordStoreError("native audit owner is not installed".into()))?;
    drain_native(&PENDING_AUDIT, &AUDIT_LOG, native).await
}

/// Recheck after producers have stopped and `flush_pending` has succeeded.
pub fn has_unsettled_audit() -> bool {
    let queue = PENDING_AUDIT
        .rows
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    !queue.queued.is_empty()
}

fn deliver_audit_event(entry: &AuditEntry) {
    use busbar_contract::export_stream::ExportStream;

    crate::export::plugin::deliver(ExportStream::Events, &entry.action, |projection| {
        project_audit_event(projection, entry)
    });
}

fn project_audit_event(
    projection: crate::export::projection::Projection,
    entry: &AuditEntry,
) -> crate::export::projection::Rendered {
    use busbar_contract::abi::export::ExportField as F;
    use busbar_contract::export_stream::ExportStream;

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

pub(crate) async fn register_and_restore(
    app: &Arc<crate::state::App>,
    store: Arc<CoreStore>,
) -> RecordStoreResult<()> {
    register_audit_stream(app);
    let native = install_native(KIND_ID_AUDIT, store)?;
    if native.ready.load(Ordering::Acquire) {
        return drain_native(&PENDING_AUDIT, &AUDIT_LOG, native).await;
    }
    let restored = restore_native(&AUDIT_LOG, &native).await?;
    native.ready.store(true, Ordering::Release);
    if restored.records == 0 && restored.unreadable == 0 && restored.chain_breaks.is_empty() {
        tracing::debug!(
            records = restored.records,
            unreadable = restored.unreadable,
            chain_breaks = restored.chain_breaks.len(),
            "admin audit restored from canonical native storage"
        );
    } else {
        tracing::info!(
            records = restored.records,
            unreadable = restored.unreadable,
            chain_breaks = restored.chain_breaks.len(),
            "admin audit restored from canonical native storage"
        );
    }
    open_plugin_refusals();
    drain_pending_audit();
    Ok(())
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

/// `emit_admin_hostless_now` that reports the queue's answer (SHUTDOWN-HANG §5): a full queue or
/// an entropy failure is returned to the caller, which keeps and names the refused record,
/// instead of becoming an anonymous gap. Sync; takes only the queue's own lock.
pub(crate) fn try_emit_admin_hostless_now(
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) -> RecordStoreResult<()> {
    let (suffix, _) = admin_suffix(
        busbar_kernel::store::now(),
        action,
        resource,
        outcome,
        principal,
    );
    drain_pending_audit();
    let pending = pending_audit(ADMIN_LOG, suffix, EventOrigin::Mutation)?;
    PENDING_AUDIT.try_enqueue(pending)?;
    drain_pending_audit();
    Ok(())
}

/// Return success only after this event was accepted and its native append confirmed.
pub(crate) async fn emit_admin_hostless_confirmed(
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) -> RecordStoreResult<()> {
    let (suffix, _) = admin_suffix(
        busbar_kernel::store::now(),
        action,
        resource,
        outcome,
        principal,
    );
    let pending = pending_audit(ADMIN_LOG, suffix, EventOrigin::Mutation)?;
    PENDING_AUDIT.try_enqueue(pending)?;
    flush_pending().await
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
    /// The image's D_ERRORS declaration was malformed (PLUGIN-ERROR-CODES §2.4): it loaded without error codes,
    /// flagged.
    ErrorCodes,
}

impl PluginRefusal {
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Trust | Self::Unverified => "plugin.trust",
            Self::Need => "plugin.need",
            Self::Open => "plugin.open",
            Self::Op => "plugin.op",
            Self::ErrorCodes => "plugin.error_codes_refused",
        }
    }

    #[must_use]
    pub const fn outcome(self) -> &'static str {
        match self {
            Self::Trust | Self::Need | Self::Op => busbar_contract::vocab::OUTCOME_REJECTED,
            Self::Open | Self::Unverified | Self::ErrorCodes => {
                busbar_contract::vocab::OUTCOME_DEGRADED
            }
        }
    }
}

/// The fixed `want` of every refused D_ERRORS declaration (PLUGIN-ERROR-CODES §2.4).
pub const ERROR_CODES_WANT: &str = "1..=256 numbers, each 1..=9999, strictly ascending; name ^[a-z][a-z0-9-]{0,63}$ not ending '-'";

/// A malformed D_ERRORS declaration (IF §50, PLUGIN-ERROR-CODES §2.4): the image is admitted without codes. One
/// WARN line (BUSBAR-6018, `field`, `have`, `want`) and one `plugin.error_codes_refused` row (outcome `degraded`),
/// held like every plugin refusal until the audit chain opens. `have` is the registry's fault text (counts,
/// numbers and positions only, never a plugin byte); `file` and `library_sha256` name the image.
pub fn record_error_codes_refused(kind: &str, file: &str, library_sha256: &str, have: &str) {
    let diag = crate::diagnostics::PLUGIN_ERROR_CODES_REFUSED.banner();
    tracing::warn!(
        diag = %diag,
        kind,
        file,
        library_sha256,
        field = "errors",
        have,
        want = ERROR_CODES_WANT,
        "plugin error numbers refused; the plugin is admitted and runs without error codes"
    );
    let refusal = PluginRefusal::ErrorCodes;
    PLUGIN_REFUSALS.raise(
        HeldRefusal {
            ts: busbar_kernel::store::now(),
            action: refusal.action(),
            outcome: refusal.outcome(),
            resource: plugin_refusal_resource(kind, file, have),
            origin: EventOrigin::for_plugin_refusal(refusal, kind),
        },
        seal_refusal,
    );
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
    action: &'static str,
    outcome: &'static str,
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
        row.action,
        &row.resource,
        row.outcome,
        PLUGIN_REFUSAL_PRINCIPAL,
        row.origin,
    );
}

pub fn record_plugin_refusal(refusal: PluginRefusal, kind: &str, subject: &str, reason: &str) {
    let origin = EventOrigin::for_plugin_refusal(refusal, kind);
    PLUGIN_REFUSALS.raise(
        HeldRefusal {
            ts: busbar_kernel::store::now(),
            action: refusal.action(),
            outcome: refusal.outcome(),
            resource: plugin_refusal_resource(kind, subject, reason),
            origin,
        },
        seal_refusal,
    );
}

pub(crate) fn open_plugin_refusals() {
    open_operator_rows();
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
pub async fn register_test_audit_stream(app: &Arc<crate::state::App>) {
    let store = app
        .governance
        .as_ref()
        .expect("native audit test governance")
        .core_store_handle()
        .expect("native audit test Store");
    if let Some(previous) = native_owner(KIND_ID_AUDIT) {
        if !Arc::ptr_eq(&previous.store, &store) {
            // A test's new deployment must finish the prior deployment's real
            // native queue before replacing its global test registration.
            flush_pending()
                .await
                .expect("prior native audit originals resolve");
            native_owners()
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&KIND_ID_AUDIT);
        }
    }
    register_and_restore(app, store)
        .await
        .expect("native audit test restore");
    flush_pending()
        .await
        .expect("native audit test setup drains");
}

#[cfg(test)]
pub(crate) async fn ensure_global_audit_stream_registered() {
    static REGISTERED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    REGISTERED
        .get_or_init(|| async {
            stream_registry::register(
                KIND_ID_AUDIT,
                KIND_AUDIT.to_string(),
                AUDIT_FRAMING,
                AUDIT_DIGESTS_SCOPE,
                Decode::Native(reframe_audit),
                usize::MAX,
            );
            let native = match native_owner(KIND_ID_AUDIT) {
                Some(native) => native,
                None => install_native(KIND_ID_AUDIT, crate::real_store::core().await)
                    .expect("native audit test owner"),
            };
            if !native.ready.load(Ordering::Acquire) {
                restore_native(&AUDIT_LOG, &native)
                    .await
                    .expect("native audit test restore");
                native.ready.store(true, Ordering::Release);
            }
            open_plugin_refusals();
        })
        .await;
    flush_pending()
        .await
        .expect("native audit test setup drains");
}

#[cfg(test)]
#[path = "tests/auditlog_tests.rs"]
mod tests;

struct NativeAudit {
    store: Arc<CoreStore>,
    history: AsyncHistory,
    heads: Mutex<std::collections::BTreeMap<String, (u64, String)>>,
    driving: tokio::sync::Mutex<()>,
    ready: AtomicBool,
}
#[derive(Clone)]
struct PreparedAudit {
    native: Arc<NativeAudit>,
    envelope: PlaneRecord,
    entry: AuditEntry,
}
fn native_owners() -> &'static Mutex<std::collections::HashMap<u32, Arc<NativeAudit>>> {
    static OWNERS: std::sync::OnceLock<Mutex<std::collections::HashMap<u32, Arc<NativeAudit>>>> =
        std::sync::OnceLock::new();
    OWNERS.get_or_init(Mutex::default)
}
fn native_owner(kind: u32) -> Option<Arc<NativeAudit>> {
    native_owners()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&kind)
        .cloned()
}
fn install_native(kind: u32, store: Arc<CoreStore>) -> RecordStoreResult<Arc<NativeAudit>> {
    let mut owners = native_owners()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(held) = owners.get(&kind) {
        if !Arc::ptr_eq(&held.store, &store) {
            return Err(RecordStoreError(
                "audit owner cannot retarget retained operations to another CoreStore attachment"
                    .into(),
            ));
        }
        return Ok(held.clone());
    }
    let history = AsyncHistory::authorized(
        store.clone(),
        PERSISTENCE_OWNER,
        [HistoryCollection {
            kind: KIND_AUDIT,
            mode: HistoryMode::Append,
            retention: Retention::Age,
            parent: None,
        }],
    )
    .map_err(native_error)?;
    let native = Arc::new(NativeAudit {
        store,
        history,
        heads: Mutex::default(),
        driving: tokio::sync::Mutex::new(()),
        ready: AtomicBool::new(false),
    });
    owners.insert(kind, native.clone());
    Ok(native)
}
fn native_error(error: crate::host_records_async::HistoryError) -> RecordStoreError {
    RecordStoreError(format!("native audit persistence: {error:?}"))
}

/// Read both canonical representations. Old pipe-record fields keep their exact
/// preimages; modern neutral bodies keep their original suffix recipe. This
/// performs no migration writes, resealing, or hash repair.
async fn restore_native(
    log: &PlaneAuditLog,
    native: &NativeAudit,
) -> RecordStoreResult<AuditRestored> {
    let mut scopes: std::collections::BTreeMap<String, Vec<Vec<u8>>> =
        std::collections::BTreeMap::new();
    let legacy = crate::persistence::history::Audit::authorized(&native.store, PERSISTENCE_OWNER)
        .list()
        .await
        .map_err(native_error)?;
    for record in legacy {
        scopes
            .entry(ADMIN_LOG.into())
            .or_default()
            .push(encode(&NeutralBody {
                seq: record.seq,
                prev_hash: record.prev_hash,
                hash: record.hash,
                content: audit_suffix(
                    record.ts,
                    &record.action,
                    &record.resource,
                    &record.outcome,
                    &record.principal,
                ),
            })?);
    }
    for record in native
        .history
        .list(KIND_AUDIT, &PlaneSelector::All)
        .await
        .map_err(native_error)?
    {
        if record.kind != KIND_AUDIT || record.parent.as_deref() != Some(record.id.as_str()) {
            return Err(RecordStoreError(
                "canonical audit envelope has an invalid scope identity".into(),
            ));
        }
        if let Ok(body) = decode_audit_body(&record.body) {
            if body.seq != record.seq {
                return Err(RecordStoreError(
                    "canonical audit envelope and original sequence disagree".into(),
                ));
            }
        }
        scopes.entry(record.id).or_default().push(record.body);
    }
    let mut restored = AuditRestored::default();
    let mut heads = std::collections::BTreeMap::new();
    let mut ambiguous = false;
    for (scope, bodies) in scopes {
        let mut decoded: std::collections::BTreeMap<u64, Vec<(Vec<u8>, NeutralBody)>> =
            std::collections::BTreeMap::new();
        for body in bodies {
            match decode_audit_body(&body) {
                Ok(neutral) => {
                    let rows = decoded.entry(neutral.seq).or_default();
                    if !rows.iter().any(|(_, held)| {
                        held.prev_hash == neutral.prev_hash
                            && held.hash == neutral.hash
                            && held.content == neutral.content
                    }) {
                        rows.push((body, neutral));
                    }
                }
                Err(error) => {
                    restored.unreadable += 1;
                    crate::diagnostics::diag_error!(crate::diagnostics::PLANE_AUDIT_ROW_UNREADABLE,error=%error,"canonical audit body is unreadable; its original remains stored and continuation is refused");
                }
            }
        }
        let mut accepted = Vec::new();
        for rows in decoded.values() {
            if rows.len() > 1 {
                ambiguous = true;
            }
            for (body, neutral) in rows {
                let entry = audit_entry_from_body(&scope, body)?;
                log.push_entry(entry, &scope, neutral.content.clone(), true);
                accepted.push(body.clone());
                restored.records += 1;
            }
        }
        if let Some((_, rows)) = decoded.last_key_value() {
            if rows.len() == 1 {
                let neutral = &rows[0].1;
                heads.insert(scope.clone(), (neutral.seq, neutral.hash.clone()));
            }
        }
        if let Some(broken) = log.seed_chain(&scope, &accepted)? {
            crate::diagnostics::diag_error!(crate::diagnostics::PLANE_AUDITLOG_CHAIN_VERIFY_FAILED,break_detail=%broken,"canonical audit chain does not verify; original records are retained as evidence");
            restored.chain_breaks.push(broken);
        }
    }
    if ambiguous || restored.unreadable != 0 {
        return Err(RecordStoreError("canonical audit evidence has ambiguous positions or unreadable bodies; continuation requires explicit recovery".into()));
    }
    *native
        .heads
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = heads;
    Ok(restored)
}

fn prepare_native(
    pending: &PendingAudit,
    native: Arc<NativeAudit>,
) -> RecordStoreResult<PreparedAudit> {
    let (previous, prev_hash) = native
        .heads
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&pending.scope)
        .cloned()
        .unwrap_or_default();
    let seq = previous
        .checked_add(1)
        .ok_or_else(|| RecordStoreError("audit sequence overflow".into()))?;
    let framed = StreamRecord::from_parts(
        pending.scope.clone(),
        seq,
        prev_hash.clone(),
        String::new(),
        pending.suffix.clone(),
        AUDIT_FRAMING,
        AUDIT_DIGESTS_SCOPE,
    );
    let hash = crate::audit::digest(&framed);
    let parsed = parse_suffix_entry(&pending.suffix);
    let ts = parsed.ts;
    let body = encode(&NeutralBody {
        seq,
        prev_hash: prev_hash.clone(),
        hash: hash.clone(),
        content: pending.suffix.clone(),
    })?;
    Ok(PreparedAudit {
        native,
        envelope: PlaneRecord {
            kind: KIND_AUDIT.into(),
            id: pending.scope.clone(),
            parent: Some(pending.scope.clone()),
            seq,
            ts,
            disposition: PlaneDisposition::Active,
            body,
        },
        entry: entry_of(seq, prev_hash, hash, parsed, true),
    })
}
async fn drain_native(
    queue: &PendingAuditQueue,
    log: &PlaneAuditLog,
    native: Arc<NativeAudit>,
) -> RecordStoreResult<()> {
    let _driving = native.driving.lock().await;
    if !native.ready.load(Ordering::Acquire) {
        return Err(RecordStoreError(
            "canonical audit restore has not completed".into(),
        ));
    }
    loop {
        let Some(mut pending) = queue
            .rows
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .queued
            .front()
            .cloned()
        else {
            return Ok(());
        };
        if pending.prepared.is_none() {
            pending.prepared = Some(prepare_native(&pending, native.clone())?);
            let mut held = queue.rows.lock().unwrap_or_else(|error| error.into_inner());
            let first = held
                .queued
                .front_mut()
                .ok_or_else(|| RecordStoreError("audit queue ownership changed".into()))?;
            if first.operation != pending.operation {
                return Err(RecordStoreError("audit queue original changed".into()));
            }
            first.prepared.clone_from(&pending.prepared);
        }
        let prepared = pending.prepared.as_ref().expect("retained audit original");
        if !Arc::ptr_eq(&prepared.native, &native) {
            return Err(RecordStoreError(
                "audit attempt belongs to another native attachment".into(),
            ));
        }
        let outcome = native
            .history
            .append_with_id(pending.operation, prepared.envelope.view())
            .await;
        match outcome {
            Ok(HistoryOutcome::Applied) => {}
            Ok(HistoryOutcome::Conflict) | Err(crate::host_records_async::HistoryError::Fork) => {
                // This original definitely had no effects. Rebase only its
                // framing after refreshing the canonical head; preserve suffix.
                restore_native(log, &native).await?;
                let mut operation = [0; 16];
                busbar_contract::crypto::fill(&mut operation)
                    .map_err(|_| RecordStoreError("audit operation entropy unavailable".into()))?;
                let mut held = queue.rows.lock().unwrap_or_else(|error| error.into_inner());
                let first = held
                    .queued
                    .front_mut()
                    .ok_or_else(|| RecordStoreError("audit queue ownership changed".into()))?;
                if first.operation != pending.operation {
                    return Err(RecordStoreError("audit queue original changed".into()));
                }
                first.operation = operation;
                first.prepared = None;
                return Err(RecordStoreError(
                    "audit head changed; original event retained for another guarded attempt"
                        .into(),
                ));
            }
            Ok(outcome) => {
                return Err(RecordStoreError(format!(
                    "audit original remains pending or refused: {outcome:?}"
                )));
            }
            Err(error) => return Err(native_error(error)),
        }
        native
            .heads
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                pending.scope.clone(),
                (prepared.entry.seq, prepared.entry.hash.clone()),
            );
        log.push_entry(
            prepared.entry.clone(),
            &pending.scope,
            pending.suffix.clone(),
            false,
        );
        if pending.origin.redispatch() {
            deliver_audit_event(&prepared.entry);
        }
        {
            let mut held = queue.rows.lock().unwrap_or_else(|error| error.into_inner());
            if held
                .queued
                .front()
                .is_none_or(|first| first.operation != pending.operation)
            {
                return Err(RecordStoreError(
                    "confirmed audit original lost queue ownership".into(),
                ));
            }
            held.queued.pop_front();
        }
        if let Some(confirmation) = &pending.confirmation {
            confirmation.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
#[path = "tests/auditlog_native_tests.rs"]
mod native_tests;

/// THE `auth.operator` AUDIT FAMILY (OPERATOR-FROM-ADMITTED-AUTH §3.10): which operator credential a
/// boot accepted, which claimant it ignored, and every refusal. Held like a plugin refusal until the
/// audit chain opens, so process start can raise them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorAudit {
    /// The first boot build accepted the operator credential (one row per backed definition).
    Accepted,
    /// A claimant that is not first-party and that nothing references: ignored.
    Inert,
    /// A referenced claimant that is not first-party.
    RefusedThirdParty,
    /// Two first-party claimants.
    RefusedAmbiguous,
    /// A row whose Statement does not read.
    RefusedUnreadable,
    /// A build or validate whose judged operator differs from the bound one.
    RefusedChanged,
    /// An operator-backed definition held anywhere but config.yaml.
    RefusedFilePolicy,
    /// A 1.5 `token:` on the operator credential.
    RefusedToken,
}

impl OperatorAudit {
    const fn action(self) -> &'static str {
        match self {
            Self::Accepted => "auth.operator.accepted",
            Self::Inert => "auth.operator.inert",
            _ => "auth.operator.refused",
        }
    }

    const fn outcome(self) -> &'static str {
        match self {
            Self::Accepted => busbar_contract::vocab::OUTCOME_APPLIED,
            Self::Inert => busbar_contract::vocab::OUTCOME_DEGRADED,
            _ => busbar_contract::vocab::OUTCOME_REFUSED,
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Inert => "inert",
            Self::RefusedThirdParty => "third_party",
            Self::RefusedAmbiguous => "ambiguous",
            Self::RefusedUnreadable => "unreadable",
            Self::RefusedChanged => "changed",
            Self::RefusedFilePolicy => "file_policy",
            Self::RefusedToken => "token",
        }
    }
}

static OPERATOR_ROWS: RefusalHold = RefusalHold::new();

/// Raise one `auth.operator` row naming `subject` (a row, a definition or `operator`) and `detail`
/// (the referrer, the door, the principal and signer): held until the audit chain opens.
pub fn record_operator(event: OperatorAudit, subject: &str, detail: &str) {
    OPERATOR_ROWS.raise(
        HeldRefusal {
            ts: busbar_kernel::store::now(),
            action: event.action(),
            outcome: event.outcome(),
            resource: plugin_refusal_resource(event.reason(), subject, detail).replacen(
                "plugin:",
                "operator:",
                1,
            ),
            origin: EventOrigin::Mutation,
        },
        seal_refusal,
    );
}

fn open_operator_rows() {
    OPERATOR_ROWS.open(seal_refusal, |over| {
        emit_admin_hostless_now(
            OperatorAudit::RefusedChanged.action(),
            &format!("operator:held/over#{over}"),
            busbar_contract::vocab::OUTCOME_REJECTED,
            PLUGIN_REFUSAL_PRINCIPAL,
        );
    });
}

/// The `auth.operator` rows still held for the audit chain, as `"<action> <resource>"`. Tests of the
/// admin write doors (core-admin) read them through `test-support`.
#[cfg(any(test, feature = "test-support"))]
pub fn held_operator_rows() -> Vec<String> {
    OPERATOR_ROWS
        .lock()
        .rows
        .iter()
        .map(|row| format!("{} {}", row.action, row.resource))
        .collect()
}

#[cfg(test)]
#[path = "tests/audit_keyset_tests.rs"]
mod keyset_tests;

#[cfg(test)]
#[path = "tests/audit_row_tests.rs"]
mod row_tests;
