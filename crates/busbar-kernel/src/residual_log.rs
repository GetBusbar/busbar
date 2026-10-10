// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DURABLE PER-PRINCIPAL RESIDUAL LOG (MONEY LAW, owner 2026-10-02; ARCHITECT ruling 2026-10-02).
//!
//! A usage count no billing class records is WARNed where the reader found it, never billed, and
//! settled here as ONE `usage.residual` row per non-empty residual map. The row is money evidence,
//! so it is DURABLE and NEVER EVICTED: it rides its own per-principal journal stream on the ONE
//! store-backed chain ([`crate::plane_host::journal`], the same seq-authority, write-through sink,
//! boot rehydrate and verifier the call log and the admin audit log use), under the store kind
//! [`KIND_RESIDUAL`]. It does NOT ride the admin audit ring: that ring is operator-rate and holds
//! [`crate::audit::MAX_AUDIT_ENTRIES`] rows in RAM, and a residual is request-rate (one per request
//! on a deployment that runs a Bedrock guardrail on every call), so sharing it would evict both the
//! residuals and every admin mutation behind them ([`crate::audit`]'s stream table: "one chain per
//! PRINCIPAL | request-rate").
//!
//! One chain per principal (the caller the units settled against), `LengthPrefixed`, principal in
//! the digest. Every field the row names is in the digest: the action, the plane, the dialect that
//! reported the units, the serving lane, the request id, every unit and its count, and the outcome
//! `unbilled`. A restart replays the stream from the store ([`register_and_restore`]), so the chain
//! continues where it stopped and every row is read back, not re-derived.
//!
//! The write is EVIDENCE, not admission: a store failure never fails the request it records. It is
//! reported at `error!` on the transition into failing, and the chain position is left untouched,
//! so the chain stays contiguous and only the lost row is missing.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::audit::journal::NeutralBody;
use crate::audit::{verify_chain, ChainBreak, Framing};
use crate::plane::store::{decode, PlaneStore, KIND_RESIDUAL};
use crate::plane_host::journal::PlaneJournalRecord;
use crate::plane_host::USAGE_RESIDUAL_ACTION;
use busbar_contract::abi::hot::host::HostCtx;
use busbar_contract::abi::hot::{
    Framing as AbiFraming, JournalStreamDesc, RawFraming, POD_VERSION,
};
use busbar_contract::records::{PlaneSelector, RecordStoreError, RecordStoreResult};

/// The host-assigned `kind_id` the residual stream is registered under. Distinct from the
/// `task_event` (1), `call` (2) and admin `audit` (3) streams; process-global.
pub(crate) const KIND_ID_RESIDUAL: u32 = 4;

/// Every field self-delimits, so the host's prelude and this suffix byte-concatenate exactly.
const RESIDUAL_FRAMING: Framing = Framing::LengthPrefixed;
/// The principal (the chain SCOPE) is in the digest: one caller's rows can never be made to
/// depend on another's.
const RESIDUAL_DIGESTS_SCOPE: bool = true;

/// The bound on how many principals' chain POSITIONS are cached in RAM. A cache of the store's
/// tail, not the record: an evicted principal resumes from the store on its next row, so the bound
/// evicts no evidence (the call log's bound, for the same reason).
const MAX_TRACKED_PRINCIPALS: usize = 16_384;

/// What one settle hands the log: the facts of the row, before the chain mints its link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualInput {
    /// When the units settled (epoch seconds, the audit clock).
    pub ts: u64,
    /// The plane that settled them.
    pub plane: String,
    /// The dialect that reported them.
    pub dialect: String,
    /// The serving lane.
    pub lane: String,
    /// The request the units came back on.
    pub request_id: u64,
    /// Every unbilled unit and its count. Never empty on a written row.
    pub units: BTreeMap<String, u64>,
}

/// One `usage.residual` row as the chain holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualRecorded {
    /// The caller the units settled against: the chain scope.
    pub principal: String,
    /// This row's position on the principal's chain.
    pub seq: u64,
    /// The input facts.
    pub ts: u64,
    /// Always [`USAGE_RESIDUAL_ACTION`].
    pub action: String,
    /// The plane that settled the units.
    pub plane: String,
    /// The dialect that reported them.
    pub dialect: String,
    /// The serving lane.
    pub lane: String,
    /// The request id.
    pub request_id: u64,
    /// Every unbilled unit and its count.
    pub units: BTreeMap<String, u64>,
    /// Always `unbilled`.
    pub outcome: String,
    /// The link to the previous row (empty at genesis).
    pub prev_hash: String,
    /// This row's sealed digest.
    pub hash: String,
}

fn lp_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u64).to_be_bytes());
    out.extend_from_slice(b);
}

fn lp_num(out: &mut Vec<u8>, v: u64) {
    lp_bytes(out, &v.to_be_bytes());
}

/// The row's pre-framed content SUFFIX, after the prelude (`prev_hash`/`principal`/`seq`): ts,
/// action, plane, dialect, lane, request_id, the unit count, each `(unit, count)`, outcome. Every
/// field is `len:u64-be ⧺ bytes`; a number is its eight big-endian bytes framed the same way.
fn residual_suffix(input: &ResidualInput) -> Vec<u8> {
    let mut out = Vec::new();
    lp_num(&mut out, input.ts);
    lp_bytes(&mut out, USAGE_RESIDUAL_ACTION.as_bytes());
    lp_bytes(&mut out, input.plane.as_bytes());
    lp_bytes(&mut out, input.dialect.as_bytes());
    lp_bytes(&mut out, input.lane.as_bytes());
    lp_num(&mut out, input.request_id);
    lp_num(&mut out, input.units.len() as u64);
    for (unit, count) in &input.units {
        lp_bytes(&mut out, unit.as_bytes());
        lp_num(&mut out, *count);
    }
    lp_bytes(
        &mut out,
        busbar_contract::vocab::OUTCOME_UNBILLED.as_bytes(),
    );
    out
}

/// The parsed fields of a suffix: ts, action, plane, dialect, lane, request id, units, outcome.
type ParsedSuffix = (
    u64,
    String,
    String,
    String,
    String,
    u64,
    BTreeMap<String, u64>,
    String,
);

/// The exact inverse of [`residual_suffix`]. Fails closed on a truncated field or trailing bytes,
/// never reading past the buffer.
fn parse_residual_suffix(content: &[u8]) -> RecordStoreResult<ParsedSuffix> {
    fn take<'a>(content: &'a [u8], off: &mut usize) -> RecordStoreResult<&'a [u8]> {
        let short = || RecordStoreError("truncated residual row field".to_string());
        let len_end = off
            .checked_add(8)
            .filter(|e| *e <= content.len())
            .ok_or_else(short)?;
        let len = u64::from_be_bytes(content[*off..len_end].try_into().map_err(|_| short())?);
        let end = usize::try_from(len)
            .ok()
            .and_then(|l| len_end.checked_add(l))
            .filter(|e| *e <= content.len())
            .ok_or_else(short)?;
        *off = end;
        Ok(&content[len_end..end])
    }
    fn num(content: &[u8], off: &mut usize) -> RecordStoreResult<u64> {
        let b: [u8; 8] = take(content, off)?
            .try_into()
            .map_err(|_| RecordStoreError("residual row number is not 8 bytes".to_string()))?;
        Ok(u64::from_be_bytes(b))
    }
    fn text(content: &[u8], off: &mut usize) -> RecordStoreResult<String> {
        String::from_utf8(take(content, off)?.to_vec())
            .map_err(|_| RecordStoreError("residual row text is not UTF-8".to_string()))
    }
    let mut off = 0usize;
    let ts = num(content, &mut off)?;
    let action = text(content, &mut off)?;
    let plane = text(content, &mut off)?;
    let dialect = text(content, &mut off)?;
    let lane = text(content, &mut off)?;
    let request_id = num(content, &mut off)?;
    let n = num(content, &mut off)?;
    let mut units = BTreeMap::new();
    for _ in 0..n {
        let unit = text(content, &mut off)?;
        let count = num(content, &mut off)?;
        units.insert(unit, count);
    }
    let outcome = text(content, &mut off)?;
    if off != content.len() {
        return Err(RecordStoreError(
            "residual row carries trailing bytes".to_string(),
        ));
    }
    Ok((ts, action, plane, dialect, lane, request_id, units, outcome))
}

/// THE DECODE BRIDGE (reframe): one stored body back into a chain record. `scope` is the store
/// parent (the principal), never read from the body.
fn reframe_residual(scope: &str, body: &[u8]) -> RecordStoreResult<PlaneJournalRecord> {
    let nb = decode::<NeutralBody>(body)?;
    parse_residual_suffix(&nb.content)?;
    Ok(PlaneJournalRecord::from_parts(
        scope.to_string(),
        nb.seq,
        nb.prev_hash,
        nb.hash,
        nb.content,
        RESIDUAL_FRAMING,
        RESIDUAL_DIGESTS_SCOPE,
    ))
}

/// The stream's decode, served by the ONE in-core reframe slot
/// [`crate::plane_host::journal::reframe_slot`] (so this file stays `deny(unsafe)` and spells no
/// FFI slot of its own).
struct ResidualReframe;

impl crate::plane_host::journal::NativeReframe for ResidualReframe {
    fn reframe(scope: &str, body: &[u8]) -> RecordStoreResult<PlaneJournalRecord> {
        reframe_residual(scope, body)
    }
}

/// One stored body back into its typed row: the read-back a replay and an auditor use.
pub(crate) fn residual_record_from_body(
    principal: &str,
    body: &[u8],
) -> RecordStoreResult<ResidualRecorded> {
    let nb = decode::<NeutralBody>(body)?;
    let (ts, action, plane, dialect, lane, request_id, units, outcome) =
        parse_residual_suffix(&nb.content)?;
    Ok(ResidualRecorded {
        principal: principal.to_string(),
        seq: nb.seq,
        ts,
        action,
        plane,
        dialect,
        lane,
        request_id,
        units,
        outcome,
        prev_hash: nb.prev_hash,
        hash: nb.hash,
    })
}

/// Register the residual stream under `kind_id` (production pins [`KIND_ID_RESIDUAL`]; a test
/// passes a fresh id). The host attaches the durable sink from `app.governance` at register time.
pub(crate) fn register_residual_stream_as(kind_id: u32, app: &Arc<crate::state::App>) {
    let kind = KIND_RESIDUAL.as_bytes();
    let desc = JournalStreamDesc {
        size: core::mem::size_of::<JournalStreamDesc>() as u32,
        version: POD_VERSION,
        framing: RawFraming::of(AbiFraming::LengthPrefixed),
        digests_scope: 1,
        kind_id,
        _reserved: 0,
        kind_ptr: kind.as_ptr(),
        kind_len: kind.len(),
    };
    crate::plane_host::with_dispatch_scope(app, |host, _vt| {
        crate::plane_host::journal::journal_register_capped(
            host,
            &desc as *const JournalStreamDesc,
            crate::plane_host::journal::reframe_slot::<ResidualReframe>,
            MAX_TRACKED_PRINCIPALS,
        );
    });
}

/// Pack stored bodies into the `journal_seed` wire shape: `u32` count LE, then per body a `u32`
/// length LE + its bytes.
fn pack_bodies(bodies: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(bodies.len() as u32).to_le_bytes());
    for b in bodies {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// What a replay found. Every number reported, none summed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResidualRestored {
    /// Principals whose chain position was resumed.
    pub principals: usize,
    /// Rows read back across every principal.
    pub records: usize,
    /// Rows the store held that would not decode: counted, skipped, reported at `error!`.
    pub unreadable: usize,
    /// Chains that failed to verify. The rows stay restored; the break is reported.
    pub chain_breaks: Vec<ChainBreak>,
}

/// THE RESIDUAL LOG: a thin wrapper over the host-side per-principal journal stream `kind_id`.
pub struct PlaneResidualLog {
    kind_id: u32,
    /// Principals whose stored tail would not decode at replay: their position is unknown, so an
    /// append is refused rather than minted below the store's real tail (a forked chain).
    unresumable: std::sync::Mutex<std::collections::HashSet<String>>,
}

/// THE PROCESS-WIDE RESIDUAL LOG. Process state, like [`crate::calllog::CALLS`]: a config apply
/// must not reopen a principal's chain at seq 1.
pub static RESIDUALS: std::sync::LazyLock<PlaneResidualLog> =
    std::sync::LazyLock::new(|| PlaneResidualLog::with_kind_id(KIND_ID_RESIDUAL));

impl PlaneResidualLog {
    pub(crate) fn with_kind_id(kind_id: u32) -> Self {
        Self {
            kind_id,
            unresumable: Default::default(),
        }
    }

    fn unresumable_lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<String>> {
        self.unresumable.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// REPLAY: enumerate the principals the store holds rows for, seed each chain position from its
    /// persisted tail, and report what was found.
    pub fn restore_from_store(
        &self,
        host: HostCtx,
        store: &dyn PlaneStore,
    ) -> RecordStoreResult<ResidualRestored> {
        let mut out = ResidualRestored::default();
        for principal in store.list_plane_record_parents(KIND_RESIDUAL)? {
            let raw = store.list_plane_records(
                KIND_RESIDUAL,
                &PlaneSelector::Parent(principal.as_str().into()),
            )?;
            out.principals += 1;
            let mut bodies = Vec::with_capacity(raw.len());
            let mut tail_unreadable = false;
            for body in raw {
                match reframe_residual(&principal, &body) {
                    Ok(_) => {
                        tail_unreadable = false;
                        bodies.push(body);
                    }
                    Err(e) => {
                        tail_unreadable = true;
                        out.unreadable += 1;
                        tracing::error!(
                            principal = %principal,
                            error = %e,
                            "a persisted usage.residual row could NOT be decoded on replay; it is \
                             skipped and counted, and the evidence in it is lost"
                        );
                    }
                }
            }
            out.records += bodies.len();
            if tail_unreadable {
                self.unresumable_lock().insert(principal.clone());
            }
            let packed = pack_bodies(&bodies);
            let hdr = crate::plane_host::journal::seed_scoped_via_seam(
                host,
                self.kind_id,
                &principal,
                &packed,
            )
            .map_err(|()| {
                RecordStoreError("usage.residual chain seed failed at the durable seam".to_string())
            })?;
            if hdr.broke != 0 {
                let records: Vec<PlaneJournalRecord> = bodies
                    .iter()
                    .map(|b| reframe_residual(&principal, b))
                    .collect::<RecordStoreResult<_>>()?;
                if let Err(brk) = verify_chain(&records) {
                    tracing::error!(
                        principal = %brk.scope,
                        break_detail = %brk,
                        "usage.residual CHAIN VERIFICATION FAILED on replay; the rows stay restored \
                         and the chain resumes from the broken tail"
                    );
                    out.chain_breaks.push(brk);
                }
            }
        }
        Ok(out)
    }

    /// RECORD one row with no host (the settle runs on the accrual funnel, which may be off a
    /// dispatch scope). Mints the link on the principal's chain and writes the body through to the
    /// store; on a store failure the position is untouched.
    pub(crate) fn record_hostless(
        &self,
        principal: &str,
        input: ResidualInput,
    ) -> RecordStoreResult<ResidualRecorded> {
        if self.unresumable_lock().contains(principal) {
            return Err(RecordStoreError(
                "this principal's stored usage.residual tail did not decode at replay, so its \
                 chain position is unknown; the append is refused rather than forking the log"
                    .to_string(),
            ));
        }
        let content = residual_suffix(&input);
        let (seq, prev_hash, hash) =
            crate::plane_host::journal::journal_append_scoped_full_hostless(
                self.kind_id,
                principal,
                &content,
            )?;
        Ok(ResidualRecorded {
            principal: principal.to_string(),
            seq,
            ts: input.ts,
            action: USAGE_RESIDUAL_ACTION.to_string(),
            plane: input.plane,
            dialect: input.dialect,
            lane: input.lane,
            request_id: input.request_id,
            units: input.units,
            outcome: busbar_contract::vocab::OUTCOME_UNBILLED.to_string(),
            prev_hash,
            hash,
        })
    }

    /// READ one principal's rows back from the store, oldest first.
    pub fn read_back(
        &self,
        store: &dyn PlaneStore,
        principal: &str,
    ) -> RecordStoreResult<Vec<ResidualRecorded>> {
        store
            .list_plane_records(KIND_RESIDUAL, &PlaneSelector::Parent(principal.into()))?
            .iter()
            .map(|body| residual_record_from_body(principal, body))
            .collect()
    }

    /// VERIFY one principal's persisted chain end to end: `Ok(Ok(n))` is `n` rows verified.
    pub fn verify_principal_chain(
        &self,
        store: &dyn PlaneStore,
        principal: &str,
    ) -> RecordStoreResult<Result<usize, ChainBreak>> {
        let records: Vec<PlaneJournalRecord> = store
            .list_plane_records(KIND_RESIDUAL, &PlaneSelector::Parent(principal.into()))?
            .iter()
            .map(|b| reframe_residual(principal, b))
            .collect::<RecordStoreResult<_>>()?;
        Ok(verify_chain(&records).map(|()| records.len()))
    }
}

/// THE SETTLE: one `usage.residual` row on `log` per non-empty `residual` map; an empty map writes
/// nothing and returns `None`. The kernel spells the row, so a plane hands the counts over and
/// never writes it itself.
pub(crate) fn settle(
    log: &PlaneResidualLog,
    residual: &BTreeMap<String, u64>,
    plane: &str,
    dialect: &str,
    lane: &str,
    request_id: u64,
    principal: &str,
) -> Option<RecordStoreResult<ResidualRecorded>> {
    if residual.is_empty() {
        return None;
    }
    let input = ResidualInput {
        ts: crate::store::now(),
        plane: plane.to_string(),
        dialect: dialect.to_string(),
        lane: lane.to_string(),
        request_id,
        units: residual.clone(),
    };
    Some(log.record_hostless(principal, input))
}

/// THE PRODUCTION EMITTER behind [`crate::plane_host::JournalHost::settle_residual`]: settle on
/// [`RESIDUALS`] and report the result. A failure is raised at `error!` on the transition into
/// failing (then held at `debug!` until a write succeeds), never swallowed silently and never
/// failing the request.
pub fn emit(
    residual: &BTreeMap<String, u64>,
    plane: &str,
    dialect: &str,
    lane: &str,
    request_id: u64,
    principal: &str,
) {
    static FAILING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    use std::sync::atomic::Ordering::Relaxed;
    match settle(
        &RESIDUALS, residual, plane, dialect, lane, request_id, principal,
    ) {
        None => {}
        Some(Ok(row)) => {
            FAILING.store(false, Relaxed);
            tracing::debug!(
                principal = %principal,
                request_id,
                seq = row.seq,
                "usage.residual row appended"
            );
        }
        Some(Err(e)) => {
            if !FAILING.swap(true, Relaxed) {
                tracing::error!(
                    principal = %principal,
                    request_id,
                    plane = %plane,
                    dialect = %dialect,
                    lane = %lane,
                    error = %e,
                    "the durable usage.residual row could NOT be written: the units stay unbilled \
                     and this row's evidence is LOST; the chain position is unchanged"
                );
            } else {
                tracing::debug!(
                    principal = %principal,
                    request_id,
                    error = %e,
                    "the durable usage.residual row could NOT be written"
                );
            }
        }
    }
}

/// BOOT: register the residual stream (the host attaches the governance store as its sink) and
/// REPLAY it from the store, so every principal's chain continues where the last process stopped.
/// With no governance store the stream still registers and keeps its positions in RAM.
/// The replay summary logs at `debug!`: an LLM-only boot on a durable store prints no line 1.5.5
/// never printed (the same neutrality the root boot applies to its seal line).
pub(crate) fn register_and_restore(app: &Arc<crate::state::App>) {
    register_residual_stream_as(KIND_ID_RESIDUAL, app);
    let Some(gov) = app.governance.as_ref() else {
        return;
    };
    let store = crate::plane::store::PlaneStoreView::narrow(gov.store());
    crate::plane_host::with_dispatch_scope(app, |host, _| {
        match RESIDUALS.restore_from_store(host, store.as_ref()) {
            Ok(r) if r.records > 0 || r.unreadable > 0 => tracing::debug!(
                principals = r.principals,
                records = r.records,
                unreadable = r.unreadable,
                chain_breaks = r.chain_breaks.len(),
                "usage.residual log replayed from the durable store"
            ),
            Ok(_) => {}
            Err(e) => tracing::error!(
                error = %e.0,
                "could not replay the durable usage.residual log; chains start from RAM and an \
                 evicted principal resumes from the store on its next row"
            ),
        }
    });
}

/// TEST ONLY: a residual log over a fresh stream id, registered against an app whose governance
/// store is `store`. A "restart" is a second `over` the SAME store.
#[cfg(test)]
pub(crate) struct ResidualTestHarness {
    pub(crate) log: PlaneResidualLog,
    pub(crate) app: Arc<crate::state::App>,
}

#[cfg(test)]
impl ResidualTestHarness {
    pub(crate) fn over(store: Arc<dyn busbar_contract::records::RecordStore>) -> Self {
        let kind_id = crate::calllog::fresh_test_kind_id();
        let gov =
            Arc::new(crate::governance::GovState::new(store, None).expect("gov store constructs"));
        let app = crate::test_support::TestApp::new().governance(gov).build();
        register_residual_stream_as(kind_id, &app);
        Self {
            log: PlaneResidualLog::with_kind_id(kind_id),
            app,
        }
    }

    /// REPLAY this harness's stream from `store`, over a live host.
    pub(crate) fn restore_from_store(
        &self,
        store: &dyn PlaneStore,
    ) -> RecordStoreResult<ResidualRestored> {
        crate::plane_host::with_dispatch_scope(&self.app, |h, _| {
            self.log.restore_from_store(h, store)
        })
    }
}
