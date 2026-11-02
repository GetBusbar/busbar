// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN AUDIT CHAIN, ON THE NEUTRAL JOURNAL SEAM: the admin-mutation log's hash-chained records
//! written through the SAME store-backed [`crate::audit::stream_registry`] every other registered
//! stream (each plane's own call/event log) uses, addressed by a registered `kind_id`.
//!
//! ## Why the record shape lives here and not in the seam
//!
//! Core owns the ONE chain — one append, one digest, one verifier ([`crate::audit`]). What a stream
//! still owns is its RECORD: which fields it carries, which framing they digest under, and the decode
//! bridge that turns a stored body back into a chain record. This file is that ownership for the admin
//! audit stream, exactly as each plane owns its own stream's record shape in its own module. Unlike
//! those it is NOT a plane — the admin audit chain is core (owner's ruling: auditing is core) — so
//! nothing here is feature-gated away; the stream is always registered and always available.
//!
//! ## THE ONE DIVERGENCE FROM A PLANE'S OWN STREAM: the scope is NOT in the digest
//!
//! The admin audit chain has exactly ONE scope (the whole log, the constant `admin`), so its digest
//! never distinguished a scope and its persisted records were sealed WITHOUT one in the digest input.
//! A plane's own stream typically digests a per-scope key (a principal, a task id, …); this stream
//! registers with `digests_scope = FALSE`. The prelude the host frames is then exactly
//! `frame_prelude(PipeSeparated, prev_hash, None, seq)` = `prev_hash|seq`, and — for a body already on
//! disk — the plane's legacy suffix `|ts|action|resource|outcome|principal` byte-concatenates onto it
//! to reproduce the legacy [`crate::audit_ring::AuditEntry`] digest input byte-for-byte. Registering
//! with `digests_scope = 1` would fold the scope into the prelude and make EVERY already-persisted
//! admin record report `DigestMismatch` at the next boot.
//!
//! ## THE SUFFIX ITSELF: the 1.5.5 pipe join wherever it reads back exactly
//!
//! `GET /audit` serves each record's `hash`, and 1.5.5 published it as `sha256(prev_hash | seq | ts |
//! action | resource | outcome | principal)` (v1.5.5 `crates/busbar/src/admin/audit.rs:61-73`). THE
//! DESIGN §7 keeps that byte ("with no change to a 1.5.5 byte; `GET /audit` is unchanged"), so a new
//! write ([`emit_admin_hostless`], through [`admin_suffix`]) seals the legacy pipe suffix
//! ([`audit_suffix`], scheme 1) whenever it splits back apart exactly.
//!
//! `|`-joined free text is FORGEABLE on read-back: a `|` inside `action`/`resource`/`outcome` shifts
//! the fields after it once [`parse_audit_suffix`] splits the suffix back apart, while the stored
//! `hash` still matches (it seals the exact bytes either way). The last field, `principal`, keeps any
//! `|` it carries (the split stops at five fields). So a record whose `action`, `resource` or
//! `outcome` carries a `|` is sealed under [`audit_suffix_safe`] instead (scheme 2: every field
//! length-prefixed, so no field's bytes can move a boundary). Reads take either — the marker byte says
//! which.
//!
//! ## The claim, and the RAM default
//!
//! TAMPER-EVIDENCE, not tamper-prevention — a chain detects an altered/reordered/inserted/removed
//! record after the fact; it does not stop one. With no durable store configured (`store: memory`) the
//! seam keeps chain positions in RAM and persists nothing, exactly as the legacy ring did.

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

/// The host-assigned `kind_id` the admin `audit` durable stream is registered under and addressed by
/// on every scoped op. Process-global, distinct from each plane's own registered stream ids (e.g. a
/// task-event stream's id (1) and a call stream's id (2)).
pub(crate) const KIND_ID_AUDIT: u32 = 3;

/// THE ONE SCOPE OF THIS CHAIN: the whole admin log. A plane's own stream typically scopes per
/// principal or per some other per-request key; the admin log is one operator-rate sequence for the
/// whole process, so its scope is a constant — and the scope is deliberately NOT in the digest (see
/// the module header).
const ADMIN_LOG: &str = "admin";

/// The admin audit stream's framing facts, held here (the record's, not the seam's). `PipeSeparated`
/// because that is how the records already on disk were written; the scope does NOT participate in the
/// digest — the one divergence from the task/call streams (see the module header).
///
/// UNLIKE [`crate::audit_ring::AuditEntry::scheme`], this stays a plain constant rather than growing
/// a per-record tag of its own, and deliberately: it frames only the PRELUDE
/// (`prev_hash`/`seq` — see `frame_prelude`), and neither field is ever caller-influenced text, so
/// there is no boundary here for a caller-controlled `|` to move. The collision this whole change
/// closes lives in the CONTENT suffix instead — `ts`/`action`/`resource`/`outcome`/`principal` — and
/// that suffix already carries its own per-record scheme, self-described in the bytes: a leading
/// [`SAFE_SUFFIX_MARKER`] means [`crate::audit_ring::AUDIT_SCHEME_LENGTH_PREFIXED`]
/// ([`audit_suffix_safe`], a record whose `action`/`resource`/`outcome` carries a `|`); its absence
/// means [`crate::audit_ring::AUDIT_SCHEME_PIPE`] ([`audit_suffix`], the 1.5.5 digest — see
/// [`admin_suffix`]). [`parse_audit_suffix`] reads that marker back into
/// [`AuditEntry::scheme`](crate::audit_ring::AuditEntry::scheme) on restore, so this stream can
/// always say which rules a given record's CONTENT was actually sealed under — same property,
/// different byte the tag rides on.
const AUDIT_FRAMING: Framing = Framing::PipeSeparated;
const AUDIT_DIGESTS_SCOPE: bool = false;

/// REGISTER the admin `audit` durable stream (once, at boot, before the migration): `PipeSeparated`
/// framing with the scope OUT of the digest (`digests_scope = 0`), under [`KIND_ID_AUDIT`], decoded in
/// core by [`reframe_audit`]. The admin log has one scope, so its position cache is bounded by
/// construction — it registers uncapped. The durable sink is `app.governance`'s store.
pub(crate) fn register_audit_stream(app: &Arc<crate::state::App>) {
    register_audit_stream_as(KIND_ID_AUDIT, app);
}

/// Register the `audit` stream under an ARBITRARY `kind_id` — production pins [`KIND_ID_AUDIT`], a TEST
/// drives over a FRESH id so parallel tests never share one process-global chain.
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

/// The admin audit's LEGACY pre-framed content SUFFIX (Option A leading `|`): `|ts|action|resource|
/// outcome|principal`. With `digests_scope = false` the host frames the prelude `prev_hash|seq`, and
/// `prelude ⧺ suffix` reproduces the legacy [`AuditEntry`] digest input `prev_hash | seq | ts | action
/// | resource | outcome | principal` byte-for-byte, so a chain appended through the seam verifies
/// byte-identically against records written before the seam existed.
///
/// FORGEABLE when a field before the last carries a `|`: a `|` inside `action`/`resource`/`outcome`
/// shifts every field after it when the suffix is next split back apart in [`parse_audit_suffix`] —
/// the stored `hash` still matches (it is sealed over the exact same bytes either way), so
/// [`crate::audit::verify_chain`] reports the chain intact while the READ-BACK fields are wrong. So
/// [`admin_suffix`] chooses this shape only when none of those three fields carries a `|`, and
/// [`audit_suffix_safe`] otherwise. Call sites: [`admin_suffix`],
/// [`migrate_legacy_table_to_plane_records`] (which must reproduce bytes an already-sealed `hash`
/// was computed over verbatim).
pub(crate) fn audit_suffix(
    ts: u64,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) -> Vec<u8> {
    format!("|{ts}|{action}|{resource}|{outcome}|{principal}").into_bytes()
}

/// Sentinel first byte of a [`audit_suffix_safe`] suffix. A LEGACY [`audit_suffix`] body always
/// starts with the literal `|` (`0x7C`, Option A) even when every field is empty, so this byte can
/// never collide with a legacy suffix and the two formats are unambiguous to tell apart on read.
const SAFE_SUFFIX_MARKER: u8 = 0x00;

/// THE SAFE admin audit content SUFFIX for NEW writes: `SAFE_SUFFIX_MARKER` then `ts`/`action`/
/// `resource`/`outcome`/`principal` each LENGTH-PREFIXED (`u64` big-endian byte length, then the raw
/// bytes). Field boundaries are determined ENTIRELY by the length prefixes, so no byte any field
/// contains — including `|` — can move a boundary; a caller who controls one field's bytes cannot
/// make [`parse_audit_suffix`] recover a different action/resource/outcome/principal than what was
/// actually sealed. [`admin_suffix`] chooses it for a record whose pipe join would not split back
/// exactly.
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

/// THE SUFFIX A NEW ADMIN RECORD IS SEALED UNDER, and the [`AuditEntry::scheme`] that names it.
///
/// The 1.5.5 pipe join ([`audit_suffix`], scheme 1) whenever `action`, `resource` and `outcome` carry
/// no `|`: the minted `hash` is then exactly 1.5.5's served formula `sha256(prev_hash | seq | ts |
/// action | resource | outcome | principal)` (v1.5.5 `crates/busbar/src/admin/audit.rs:61-73`; THE
/// DESIGN §7 "`GET /audit` is unchanged"), and [`parse_audit_suffix`] splits it back exactly (a `|`
/// in `principal`, the last field, stays in it). Otherwise the length-prefixed suffix
/// ([`audit_suffix_safe`], scheme 2), whose recipe [`AuditEntry`]'s scheme-2 digest reproduces, so a
/// served record always recomputes under the scheme it declares (Q128 p12#1).
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

/// Append one length-prefixed field (`u64` big-endian byte length, then the bytes) — the write-side
/// half of [`audit_suffix_safe`]'s framing.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Take one length-prefixed field off the front of `rest` (`u64` big-endian byte length, then the
/// bytes), advancing `rest` past it. A truncated/malformed tail (short on the length prefix, or the
/// declared length runs past what remains) yields an empty field and consumes nothing further — the
/// same "decode what you can, never panic" discipline [`parse_audit_suffix`]'s legacy path already
/// uses on missing fields.
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

/// Parse an admin audit SUFFIX back into its typed fields plus the [`AuditEntry::scheme`] the
/// content itself reveals — the inverse of BOTH [`audit_suffix_safe`] (tried first, keyed off
/// [`SAFE_SUFFIX_MARKER`], read back as [`crate::audit_ring::AUDIT_SCHEME_LENGTH_PREFIXED`]) and the
/// legacy [`audit_suffix`] (the fallback, for suffixes a store already holds from before this stream
/// wrote the safe framing, read back as [`crate::audit_ring::AUDIT_SCHEME_PIPE`]), for reconstructing
/// an [`AuditEntry`] from a stored neutral body. The marker byte is itself the on-disk scheme tag for
/// this content shape — which sub-format a body is in IS which scheme it was written under — so the
/// scheme returned here is read off the bytes, never assumed for the whole stream.
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
    // LEGACY fallback: the `|`-joined shape (see [`audit_suffix`]'s doc for why this split is only
    // trusted for old, already-sealed bodies and never chosen for a new write).
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

/// THE DECODE BRIDGE (reframe): turn one stored `audit` body, the neutral `{seq, prev_hash, hash,
/// content}` body the seam persists (and the 1.5.5 table's migration writes), back into a chain
/// record. `scope` is the constant `admin` log, supplied by the caller and never read from the body.
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

/// READ-BACK DECODE BRIDGE to a TYPED record: reconstruct an [`AuditEntry`] from the neutral body.
/// Digest-faithful — the rebuilt fields feed the SAME bytes the stored `hash` was sealed over, so a
/// chain read back through it `verify_chain`-passes byte-identically. `recorded_here` comes back
/// FALSE: this is the store-seeding path, never a live append. `scope` is the constant `admin` log,
/// never read from the body.
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

/// THE ADMIN AUDIT LOG'S DURABLE SEAM WRAPPER. A thin wrapper over the generic host-side journal (the
/// seq-authority, position cache and store-resume all live there now); this keeps only the admin RECORD
/// and the operator vocabulary its restore emits.
pub struct PlaneAuditLog {
    /// The host-side durable stream this log's chain is addressed by. Production is always
    /// [`KIND_ID_AUDIT`]; a TEST constructs a log over a FRESH id so parallel tests never share one
    /// process-global chain.
    kind_id: u32,
    /// THE READ MODEL. A bounded ring of the most-recent [`MAX_AUDIT_ENTRIES`] records, held newest-
    /// LAST (seq-ascending) so [`list_filtered`](PlaneAuditLog::list_filtered)'s `rev()` reads newest-
    /// first — the `GET /audit` read source. Guarded by its OWN `Mutex` (independent of the seam's
    /// mint serialization point) and inserted BY SEQ, so the newest-first order holds even when a
    /// mint's release-to-push window interleaves with another recorder's.
    ring: Mutex<VecDeque<AuditEntry>>,
}

/// THE PROCESS-WIDE admin audit READ MODEL on the seam. Process state, not config-derived state, so it
/// lives as a global rather than on the swappable `App` snapshot: a config apply must not fork the chain by opening a SECOND ring at seq 1 under a chain that already
/// has one.
pub static AUDIT_LOG: std::sync::LazyLock<PlaneAuditLog> =
    std::sync::LazyLock::new(PlaneAuditLog::new);

// The actual accepted publication has one optional behavioral observer. Subscriber storage,
// selection policy, cancellation, and futures belong to the external testkit.
#[cfg(any(test, feature = "test-support"))]
static ACCEPTED_ENTRY_TEST_HOOK: std::sync::OnceLock<fn(&AuditEntry)> = std::sync::OnceLock::new();

/// Observe actual accepted publication at the existing post-lock notification point.
/// The first callback installation stands; the kernel owns no subscriber registry.
#[cfg(any(test, feature = "test-support"))]
pub fn install_accepted_entry_test_hook(hook: fn(&AuditEntry)) {
    let _ = ACCEPTED_ENTRY_TEST_HOOK.set(hook);
}

// Unit tests retain their local spelling over the shared kit implementation.
#[cfg(test)]
pub use crate::test_support::accepted_audit::{observe_accepted_admin_entry, AcceptedAdminAudit};

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

    /// A page of entries newest-first, optionally filtered by exact `action` and/or `resource`:
    /// skip `offset`, then take `limit`. `None` filters match everything. THE read surface
    /// `GET /audit` serves.
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

    /// BOOT RESTORE from the neutral `plane_records` (the shape the seam writes):
    /// enumerate the scopes the store holds `audit` records for (the admin log's single `admin` scope),
    /// resume the chain from its persisted tail, and REPORT what was found. A break is reported and the
    /// chain still resumes from the broken tail.
    ///
    /// A restore that FAILS (the store could not be read, or the seed faulted) leaves the chain
    /// position unseeded. The admin scope is then marked as needing a store resume, so the first
    /// append reads the persisted tail back and continues it rather than opening a second seq-1
    /// record beside the chain the store already holds; a store still down at that append fails the
    /// write, which is queued, never forked (Q128 p12#2; `crate::audit` "a restart continues the same
    /// chain rather than opening a second one under the same scope"; THE DESIGN §7 "the audit chain
    /// verified over retained records").
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

    /// The restore itself: read every admin scope back, push each decodable record into the read
    /// model, and seed the chain position. See [`PlaneAuditLog::restore_from_store`].
    fn read_and_seed(&self, store: &dyn PlaneStore) -> RecordStoreResult<AuditRestored> {
        let scopes = store.list_plane_record_parents(KIND_AUDIT)?;
        let mut out = AuditRestored::default();
        for scope in &scopes {
            let bodies = store
                .list_plane_records(KIND_AUDIT, &PlaneSelector::Parent(scope.as_str().into()))?;
            // Decode each stored body per-record BEFORE seeding the chain, so a single undecodable
            // row is COUNTED and SKIPPED rather than faulting the seam seed and `?`-aborting the
            // WHOLE restore — which would leave the host-side chain position UNSEEDED and fork the
            // governance chain back at seq 1 on the next append (governance durability loss). A
            // chain break is already tolerated below; an unreadable row is the same class of
            // defensive robustness. Only the decodable bodies flow on to `seed_chain`, so one bad
            // row can never fork the chain. The GOOD-row path is byte-identical: with every body
            // decodable, `good_bodies` is `bodies` in order and the seed is byte-for-byte unchanged.
            // The skip is reported LOUDLY at the site with a coded diagnostic (the peer of the
            // chain-break report below), so a silently lost evidence row on this tamper-evidence
            // surface can never be invisible; `unreadable` still carries the count back for the
            // aggregate. This mirrors the per-call log's already-tolerant restore.
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

    /// SEED the admin chain's position from its raw stored bodies through the stream registry.
    /// On a break the RICH [`ChainBreak`] is recomputed locally (read-only, touching no position) so the
    /// operator diagnostic still names WHICH break and WHERE; a clean verify returns `None`.
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

// ── FIX: THE ADMIN-AUDIT RECOVERY QUEUE — a transient durable-write failure must be RECOVERABLE ────
//
// [`emit_admin_hostless`] is FIRE-AND-FORGET by design (see each's own doc): a durable-store
// outage must never fail the mutation it is recording. Without a queue that made the failure
// TERMINAL, not merely reported: the record was gone the instant the call returned, with nothing left
// to retry. [`PendingAuditQueue`] closes that — a failed write is queued (bounded, oldest-evicted) and
// replayed oldest-first the next time the emitter runs and the backend is healthy again, so a
// transient blip becomes a DELAY, not a loss. If the queue itself fills (the backend has been down
// longer than this process is willing to hold evidence in RAM for), the oldest entry is evicted to
// admit the newest failure and that eviction is COUNTED and reported LOUDLY — a DETECTED gap, never a
// silent one.

/// Bound on waiting [`PendingAudit`] rows, excluding the single row owned by the drainer.
/// An order of magnitude short of
/// [`MAX_AUDIT_ENTRIES`] on purpose: this queue exists to bridge a TRANSIENT durable outage, not to
/// become a second, unbounded audit log riding in RAM.
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

#[derive(Clone)]
struct PendingAudit {
    scope: String,
    suffix: Vec<u8>,
    origin: EventOrigin,
}

/// A bounded FIFO of pending admin-audit rows. New arrivals and failed writes share one drain
/// owner, so recovery and live writes cannot overtake each other.
struct PendingAuditQueue {
    rows: Mutex<PendingAuditRows>,
    /// THE WATERMARK: rows evicted from `rows` to admit a newer failure once the queue was already at
    /// `cap` — each one a PERMANENT, DETECTED gap (as opposed to a row still queued, which is merely
    /// delayed). Zero means every failure since boot has either recovered or is still queued.
    dropped: AtomicU64,
    cap: usize,
}

struct PendingAuditRows {
    queued: VecDeque<PendingAudit>,
    draining: bool,
}

/// A logical drain claim, never a queue lock held across a store callback.
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

    /// Queue `p`, evicting the OLDEST row first if already at `cap`. A full queue means the backend
    /// has been down longer than this process holds evidence for, so the newest failure (likelier to
    /// recover soon) is kept over the stalest one — but the eviction is never silent: it is counted on
    /// `dropped` and reported at the coded [`crate::diagnostics::PLANE_AUDITLOG_WRITE_FAILED`] site so
    /// the gap is visible rather than riding only on an aggregate nobody reads.
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

    /// Replay every queued row, oldest first, through `mint`, stopping at the FIRST failure (the
    /// backend is still down) so the rest stay queued IN ORDER rather than being retried out of
    /// sequence. A row that mints successfully is handed to `on_recovered` — production pushes it into
    /// [`AUDIT_LOG`] so a recovered record becomes visible on `GET /audit` exactly as a live one would;
    /// a test can hand it a local collector instead of touching the process-wide ring.
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
                    // Release under the same lock used by enqueue, so a new row either belongs
                    // to this drain or can acquire its own owner. No empty-queue handoff gap.
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
                    // Enqueue may have filled the waiting queue during the store call. The failed
                    // in-flight row is the oldest: apply the existing oldest-eviction policy to it
                    // rather than overfilling the queue when returning it to the front.
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

    /// TEST ONLY: how many rows are currently queued.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.rows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queued
            .len()
    }

    /// TEST ONLY: the watermark — how many rows have been permanently evicted by overflow.
    #[cfg(test)]
    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// THE PROCESS-WIDE admin-audit recovery queue — process state, not config-derived, for the same
/// reason [`AUDIT_LOG`] is a global: a config apply must not open a second, empty queue that forgets
/// what an earlier configuration's outage left pending.
static PENDING_AUDIT: PendingAuditQueue = PendingAuditQueue::new(MAX_PENDING_AUDIT);

/// Queue one event behind every older pending write — see [`PendingAuditQueue::enqueue`].
fn enqueue_pending_audit(scope: &str, suffix: Vec<u8>, origin: EventOrigin) {
    PENDING_AUDIT.enqueue(PendingAudit {
        scope: scope.to_string(),
        suffix,
        origin,
    });
}

/// A durable audit write failed: report that its record remains pending for recovery
/// (recoverable, not terminal) and say so — an error the first time `latch` trips, a debug line
/// while it stays latched. The caller clears `latch` on its next successful write.
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

/// Drain [`PENDING_AUDIT`] through the REAL stream — [`KIND_ID_AUDIT`], hostless (a queued row may
/// outlive the call that queued it). Called by [`emit_admin_hostless`] after enqueueing its event,
/// so a healthy backend recovers older rows before today's mutation is recorded.
/// A row that recovers is rebuilt into an [`AuditEntry`] via [`parse_audit_suffix`] (the same decode
/// [`audit_entry_from_body`] uses) and pushed into [`AUDIT_LOG`], so it becomes visible on
/// `GET /audit` exactly as a live write would — recovery is not merely durable, it is also VISIBLE.
fn drain_pending_audit() {
    static WRITE_FAILED_LATCHED: AtomicBool = AtomicBool::new(false);
    PENDING_AUDIT.drain_with(
        |scope, suffix| match stream_registry::append_full(KIND_ID_AUDIT, scope, suffix) {
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
            if p.origin != EventOrigin::ExportFailure {
                deliver_audit_event(&entry);
            }
        },
    );
}

/// Offer only accepted live records to the existing per-sink projection and admission path.
/// Restore and migration populate the read model without reaching this producer.
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

/// ONE-TIME DATA MIGRATION: copy the legacy durable audit TABLE (`list_audit`/`append_audit`) into the
/// neutral `plane_records` the durable seam now reads at boot, preserving each record's
/// seq/prev_hash/hash and digest EXACTLY. The copied [`busbar_contract::records::AuditRecord`] fields reproduce the
/// seam's neutral body byte-for-byte (the write-side witness proves the seam digest byte-equals the
/// legacy [`AuditEntry`] digest), so the migrated chain [`crate::audit::verify_chain`]-passes
/// identically — the migration copies bytes, it never re-seals.
///
/// IDEMPOTENT and RESUMABLE:
/// - a store with NO legacy audit rows (a fresh deployment, or `store: memory`) is left untouched;
/// - a store whose `plane_records` already hold the legacy chain's last record (a migrated store,
///   OR one the seam has written to since) is left UNTOUCHED — returns `Ok(0)`;
/// - a store whose `plane_records` hold a PREFIX of the legacy chain (a copy an earlier boot left
///   part-way: records are appended one at a time, so a store error stops it after some of them)
///   gets the REST, every legacy record above the highest seq already copied — the copy resumes,
///   it never skips (Q128 p12#3; THE DESIGN §7 "the audit chain verified over retained records");
/// - a store whose `plane_records` disagree with the legacy chain at the seq they share (records
///   the seam wrote over a part-way copy) is NOT merged: two chains cannot be spliced without
///   re-sealing, so the migration copies nothing and returns an error naming the seq, which the boot
///   reports on every boot rather than dropping the uncopied legacy history silently.
///
/// The FULL legacy history is read (`list_audit`, oldest-first FROM GENESIS), never the bounded tail:
/// the durable `plane_records` are never pruned and [`PlaneAuditLog::restore_from_store`] verifies from
/// the GENESIS anchor, so the migrated chain must start at seq 1. A read/write error is surfaced to the
/// caller (logged at boot) and the copy resumes from where it stopped on the next boot.
pub(crate) fn migrate_legacy_table_to_plane_records(
    store: &dyn busbar_contract::records::RecordStore,
) -> RecordStoreResult<usize> {
    // The FULL legacy chain, oldest-first from genesis (seq 1). A fresh / memory store returns empty.
    let records = store.list_audit()?;
    let Some(legacy_tail) = records.last() else {
        return Ok(0);
    };
    // What the seam already holds for the admin scope, as seq -> hash. A body this build cannot
    // decode is left out here; the restore reports it on its own.
    let existing: std::collections::BTreeMap<u64, String> = store
        .list_plane_records(KIND_AUDIT, &PlaneSelector::Parent(ADMIN_LOG.into()))?
        .iter()
        .filter_map(|body| audit_entry_from_body(ADMIN_LOG, body).ok())
        .map(|e| (e.seq, e.hash))
        .collect();
    // RESUME GATE: the highest legacy seq the seam already holds. When the seam holds records past
    // the legacy tail (a migrated store the seam has written to since), the legacy tail is the seq
    // they must share.
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
        // The neutral envelope the seam persists: kind `audit`, id/parent the constant `admin` scope,
        // ordered by the record's own seq. seq/prev_hash/hash cross VERBATIM from the legacy record so
        // the migrated chain is byte-identical to what the seam would have written.
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

/// BOOT: register the admin `audit` stream, run the ONE-TIME legacy-table → `plane_records` migration,
/// then RESTORE the audit log FROM `plane_records` — the ONE durable audit source now. The restore
/// seeds BOTH the host-side chain position (so a later append continues the same chain) AND the
/// process-global [`AUDIT_LOG`] read-model ring `GET /audit` serves, from the persisted SEAM records —
/// replacing the legacy-table restore. A restore chain-verify
/// break is logged inside [`PlaneAuditLog`]; a migration or store read error is surfaced here as the
/// boot diagnostic.
pub(crate) fn register_and_migrate(
    app: &Arc<crate::state::App>,
    store: &Arc<dyn busbar_contract::records::RecordStore>,
) {
    register_audit_stream(app);
    // ONE-TIME DATA MIGRATION: copy any pre-existing legacy audit table into the neutral `plane_records`
    // the seam restore reads. Idempotent — a no-op on a migrated / fresh / memory store. A failure is
    // LOUD but non-fatal: the restore below then finds only what is already in `plane_records`, and the
    // migration retries on the next boot.
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
    // BOOT RESTORE from the neutral `plane_records`: seed the host-side chain position AND `AUDIT_LOG`'s
    // ring from the persisted seam records, so the seam read source is populated from the durable tail
    // at boot exactly as the legacy ring was — but FROM `plane_records`, not the legacy table.
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
    // The tail is restored: the plugin refusals this boot raised before now are sealed after it.
    open_plugin_refusals();
}

/// THE ADMIN-AUDIT CHOKEPOINT EMITTER, hostless. Reached through [`emit_admin_hostless_now`] from
/// [`crate::audit_ring::AuditLog::record_by`] — which is the ONE place an admin mutation is recorded
/// — with one clock read per event. `record_by` is a method on the
/// process-global `AUDIT` static and has NO `app`/host to open a dispatch scope with, so it reaches the
/// chain through the HOSTLESS append ([`stream_registry::append_full`]), which resolves the registered
/// `audit` stream from the process-global stream registry, mints
/// `(seq, prev_hash, hash)` through the ONE core chain, and persists the neutral body — then the minted
/// record is pushed into the process-global [`AUDIT_LOG`] read-model ring.
///
/// FIRE-AND-FORGET, loudly — but RECOVERABLE, not silently terminal (see the [`PendingAuditQueue`]
/// section above). A durable-store write failure (or an unregistered stream, e.g. the RAM-only test
/// harnesses that never boot the migration) must NEVER fail the mutation it records: the log is
/// EVIDENCE, not ADMISSION. A failed write is QUEUED rather than dropped, surfaced at `error!` on the
/// transition into the failing state and held at `debug!` thereafter. The chain position is left
/// untouched on failure so the next mutation reuses the sequence and the chain stays contiguous.
///
/// The suffix is [`admin_suffix`]'s: the 1.5.5 pipe join whenever it reads back exactly, so the hash
/// `GET /audit` serves is 1.5.5's formula, and the pushed entry's `scheme` is the one that suffix was
/// sealed under (Q128 p12#1).
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
    // A recovered backend can empty a full backlog before this arrival needs a waiting slot.
    drain_pending_audit();
    // New events share the recovery FIFO and its drain owner. A busy or failed older write must
    // never let this event append directly around it.
    enqueue_pending_audit(ADMIN_LOG, suffix, origin);
    drain_pending_audit();
}

/// THE NEUTRAL, HOSTLESS AUDIT EMIT for plane call sites. Reads `busbar_kernel::store::now()` ONCE for
/// this event and delegates to [`emit_admin_hostless`] with that single timestamp.
/// This neutral `(action, resource, outcome, principal)` shape IS the future ABI-slot signature: the
/// plane bodies call it without ever naming `crate::audit_ring`, so the core-audit↔plane seam can be cut.
/// Fire-and-forget, loudly, exactly like [`emit_admin_hostless`]: a store write failure NEVER fails the
/// mutation it records.
pub fn emit_admin_hostless_now(action: &str, resource: &str, outcome: &str, principal: &str) {
    let ts = busbar_kernel::store::now();
    emit_admin_hostless(ts, action, resource, outcome, principal);
}

// ── PLUGIN REFUSALS AT BOOT AND BIND: the host audits them on the plugin's behalf ─────────────────
//
// Owner rule: every refusal is audited and explained; nothing silent. A refusal the host makes while
// a plugin starts or binds (a skip by the trust policy, a need the connection table refused, a
// warning the plugin declared and raised at its open) is sealed here, on the one admin chain, through
// [`emit_admin_hostless`]. No plugin writes it: there is no plugin-facing service, and no plugin
// text becomes structure. Every field is host-composed ([`plugin_refusal_resource`]).
//
// Most of these refusals are made before the chain is open (the preflight and the export sinks'
// opens run before `hydrate_all`), so they are HELD, in the order they were raised, and sealed when
// [`register_and_migrate`] has restored the chain's tail ([`open_plugin_refusals`]). Holding is not a
// failure: nothing is logged for it.

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
    /// The record's action.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Trust | Self::Unverified => "plugin.trust",
            Self::Need => "plugin.need",
            Self::Open => "plugin.open",
            Self::Op => "plugin.op",
        }
    }

    /// The record's outcome: a refusal is `rejected`; a flagged open or an unverified load loaded,
    /// `degraded`.
    #[must_use]
    pub const fn outcome(self) -> &'static str {
        match self {
            Self::Trust | Self::Need | Self::Op => busbar_contract::vocab::OUTCOME_REJECTED,
            Self::Open | Self::Unverified => busbar_contract::vocab::OUTCOME_DEGRADED,
        }
    }
}

/// The principal a plugin refusal is recorded under: the host acted; no caller did.
pub const PLUGIN_REFUSAL_PRINCIPAL: &str = "host";

/// The most bytes one part of a refusal's resource keeps.
const REFUSAL_PART_MAX: usize = 64;

/// The most refusals held before the chain opens; past it each is counted, and the count is sealed
/// as one record when the chain opens.
const MAX_HELD_REFUSALS: usize = 256;

/// The action of the record that counts refusals the hold could not keep.
const HELD_OVER_ACTION: &str = "plugin.refusals";

/// A refusal's resource: `plugin:<kind>/<subject>#<reason>`. Each part is clamped to host words
/// (`[A-Za-z0-9._-]`, any other byte `_`, at most [`REFUSAL_PART_MAX`] bytes; empty reads `_`), so no
/// byte a part carries can move a field boundary or smuggle text onto the chain.
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

/// THE HOLD: refusals kept (in raise order, bounded) until the chain opens, sealed at once after.
/// Sealing crosses the audit store, which is plugin code, so it never runs under the hold's lock
/// (THE DESIGN §11.13 M1): the open takes the held rows out and seals them with the lock released,
/// and a refusal raised meanwhile is held behind them and sealed by the open's next round, so the
/// chain still carries every refusal in raise order.
struct RefusalHold {
    held: Mutex<Hold>,
}

/// What [`RefusalHold`] keeps under its lock.
struct Hold {
    /// Not yet sealed, in raise order.
    rows: Vec<HeldRefusal>,
    /// Raised past [`MAX_HELD_REFUSALS`] and not yet reported.
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

    /// Hold `row` while the chain is not open (or its held rows are still being sealed); once it
    /// is, hand it to `seal`.
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

    /// Open the chain: hand every held row to `seal`, in raise order, then the count the hold could
    /// not keep (when any) to `over`, each with the lock released; rows raised meanwhile follow, in
    /// the same order. A second open seals nothing.
    fn open(&self, mut seal: impl FnMut(&HeldRefusal), mut over: impl FnMut(u64)) {
        let mut held = self.lock();
        if held.phase != Phase::Closed {
            return;
        }
        held.phase = Phase::Sealing;
        // An unwinding seal opens the chain rather than holding every later refusal for good.
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

/// Opens a [`RefusalHold`] whose open unwound mid-seal.
struct OpenOnDrop<'a>(&'a RefusalHold);

impl Drop for OpenOnDrop<'_> {
    fn drop(&mut self) {
        self.0.lock().phase = Phase::Open;
    }
}

/// The process's one hold: the chain opens once per process ([`register_and_migrate`]).
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

/// RECORD ONE PLUGIN REFUSAL on the admin chain: `refusal` of the plugin `subject` (its instance
/// label; for a trust skip its tarball's file name) of `kind`, for `reason` (a host code). Held
/// until the chain opens, sealed at once after.
pub fn record_plugin_refusal(refusal: PluginRefusal, kind: &str, subject: &str, reason: &str) {
    // Delivery failures arrive later on dispatcher workers: a thread-local recursion guard
    // cannot cover them. Classify host-known origin before rendering text and retain it through
    // holding and write retries. Ordinary emitter text never supplies this tag.
    let origin =
        if refusal == PluginRefusal::Op && kind == busbar_contract::plugin::Kind::Export.root() {
            EventOrigin::ExportFailure
        } else {
            EventOrigin::Mutation
        };
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

/// OPEN THE CHAIN TO PLUGIN REFUSALS: seal every refusal held so far, in raise order, after the
/// tail the boot restored.
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

// ── TEST HARNESS — a test drives the chain over its own registered stream id ───────────────────────

/// TEST ONLY: a fresh, process-unique `audit` stream id, well above the production ids (1/2/3) and the
/// `plane_host::journal` test range (base 10_000) and each plane's own reserved test-id ranges
/// (100_000, 200_000, …).
#[cfg(test)]
pub(crate) fn fresh_test_kind_id() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(300_000);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

/// Register an already-built fixture App against the real audit streams. The kit owns
/// the App and registration lifetime; this hook contains no fixture construction or singleton.
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_audit_stream(app: &Arc<crate::state::App>) {
    register_audit_stream(app);
    open_plugin_refusals();
}

#[cfg(test)]
pub(crate) fn ensure_global_audit_stream_registered() {
    crate::test_support::audit::ensure_global_audit_stream_registered();
}

/// TEST ONLY: a `PlaneAuditLog` + an app whose governance store is `store`, with the `audit` stream
/// registered against it under a FRESH host-side id so parallel tests are isolated.
#[cfg(test)]
pub(crate) struct AuditTestHarness {
    pub(crate) log: PlaneAuditLog,
}

#[cfg(test)]
impl AuditTestHarness {
    pub(crate) fn over(store: Arc<dyn busbar_contract::records::RecordStore>) -> Self {
        let kind_id = fresh_test_kind_id();
        let gov =
            Arc::new(crate::governance::GovState::new(store, None).expect("gov store constructs"));
        let app = crate::test_support::TestApp::new().governance(gov).build();
        register_audit_stream_as(kind_id, &app);
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

    /// Append one record through the stream registry over THIS harness's isolated stream id and return the MINTED
    /// `(seq, prev_hash, hash)`. The production [`emit_admin_hostless`] pins [`KIND_ID_AUDIT`] (which a parallel test
    /// must not share) and surfaces only fire-and-forget; a test drives the same chain-mint path over
    /// its own id and reads back the link the append sealed.
    pub(crate) fn emit_full(&self, scope: &str, suffix: Vec<u8>) -> (u64, String, String) {
        stream_registry::append_full(self.log.kind_id, scope, &suffix).expect("seam append")
    }
}

#[cfg(test)]
#[path = "tests/auditlog_tests.rs"]
mod tests;
