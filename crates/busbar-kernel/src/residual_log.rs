// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DURABLE PER-PRINCIPAL RESIDUAL LOG.
//!
//! A usage count no billing class records is WARNed where the reader found it, never billed, and
//! settled here as ONE `usage.residual` row per non-empty residual map. The row is money evidence,
//! so it is DURABLE and NEVER EVICTED: it rides its own per-principal journal stream on the ONE
//! store-backed chain ([`crate::audit::stream_registry`], the same seq-authority, write-through sink,
//! boot rehydrate and verifier the call log and the admin audit log use), under the store kind
//! [`KIND_RESIDUAL`]. It does NOT ride the admin audit ring: that ring is operator-rate and holds
//! [`crate::audit::MAX_AUDIT_ENTRIES`] rows in RAM, and a residual is request-rate (one per request
//! on a deployment whose guardrail reports units on every call), so sharing it would evict both the
//! residuals and every admin mutation behind them ([`crate::audit`]'s stream table: "one chain per
//! PRINCIPAL | request-rate").
//!
//! One chain per principal (the caller the units settled against), `LengthPrefixed`, principal in
//! the digest. Every field the row names is in the digest: the action, the plane, the dialect that
//! reported the units, the serving lane, the request id, every unit and its count, and the outcome
//! `unbilled`. A restart continues every chain where it stopped, and every row is read back, not
//! re-derived. Boot reads no rows ([`register_and_restore`]): it lists the principals the store holds
//! rows for and marks each one's position as living in the store, and each principal's chain is read
//! back and resumed from its stored tail on that principal's first append. The stream is
//! request-rate and never evicted, so a boot that replayed every row of every principal would take
//! longer and peak higher with every day the deployment has run.
//!
//! The write is EVIDENCE, not admission: a store failure never fails the request it records. It is
//! reported at `error!` on the transition into failing, and the chain position is left untouched,
//! so the chain stays contiguous and only the lost row is missing.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::audit::journal::NeutralBody;
use crate::audit::stream_registry::{self, Decode, StreamRecord};
use crate::audit::{verify_chain, ChainBreak, Framing};
use crate::store::plane_view::{decode, PlaneStore, KIND_RESIDUAL};
use busbar_contract::records::{PlaneSelector, RecordStoreError, RecordStoreResult};

/// The audit action of a residual row ([`emit`]): counts reported, never billed.
pub const USAGE_RESIDUAL_ACTION: &str = "usage.residual";

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

thread_local! {
    /// Set when [`reframe_residual`] refuses a body on this thread. [`PlaneResidualLog::try_append`]
    /// clears it before an append and reads it after a failed one: the stream's resume (a principal
    /// with no cached position, read back from the store) runs on the appending thread, so a set flag
    /// says the append failed because a stored row would not decode, not because the durable write
    /// failed.
    static REFRAME_REFUSED: Cell<bool> = const { Cell::new(false) };
}

/// THE DECODE BRIDGE (reframe): one stored body back into a chain record. `scope` is the store
/// parent (the principal), never read from the body.
fn reframe_residual(scope: &str, body: &[u8]) -> RecordStoreResult<StreamRecord> {
    let reframed = decode::<NeutralBody>(body).and_then(|nb| {
        parse_residual_suffix(&nb.content)?;
        Ok(StreamRecord::from_parts(
            scope.to_string(),
            nb.seq,
            nb.prev_hash,
            nb.hash,
            nb.content,
            RESIDUAL_FRAMING,
            RESIDUAL_DIGESTS_SCOPE,
        ))
    });
    if reframed.is_err() {
        REFRAME_REFUSED.with(|refused| refused.set(true));
    }
    reframed
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
/// passes a fresh id), decoded in core by [`reframe_residual`], its position cache bounded at
/// [`MAX_TRACKED_PRINCIPALS`]. The durable sink is `sink` (production: `app.governance`'s store).
pub(crate) fn register_residual_stream_as(kind_id: u32, sink: Option<Arc<dyn PlaneStore>>) {
    stream_registry::register(
        kind_id,
        KIND_RESIDUAL.to_string(),
        RESIDUAL_FRAMING,
        RESIDUAL_DIGESTS_SCOPE,
        Decode::Native(reframe_residual),
        MAX_TRACKED_PRINCIPALS,
        sink,
    );
}

/// What a boot restore found. It reads no rows: each principal's rows are read back, decoded and
/// verified on that principal's first append ([`PlaneResidualLog::record_hostless`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResidualRestored {
    /// Principals the store holds rows for, each now resumed from its stored tail on first append.
    pub principals: usize,
}

/// THE RESIDUAL LOG: a thin wrapper over the host-side per-principal journal stream `kind_id`.
pub struct PlaneResidualLog {
    kind_id: u32,
    /// Principals whose stored tail would not decode on resume: their position is unknown, so an
    /// append is refused rather than minted below the store's real tail (a forked chain).
    unresumable: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Serialises the tolerant resume ([`PlaneResidualLog::resume_past_unreadable`]), the one path
    /// that seeds a position outside the stream's own append.
    resume: tokio::sync::Mutex<()>,
}

/// THE PROCESS-WIDE RESIDUAL LOG. Process state, like [`crate::audit::auditlog::AUDIT_LOG`]: a config apply
/// must not reopen a principal's chain at seq 1.
pub static RESIDUALS: std::sync::LazyLock<PlaneResidualLog> =
    std::sync::LazyLock::new(|| PlaneResidualLog::with_kind_id(KIND_ID_RESIDUAL));

impl PlaneResidualLog {
    pub(crate) fn with_kind_id(kind_id: u32) -> Self {
        Self {
            kind_id,
            unresumable: Default::default(),
            resume: Default::default(),
        }
    }

    fn unresumable_lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<String>> {
        self.unresumable.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// BOOT RESTORE: list the principals the store holds rows for and mark each one's chain position
    /// as living in the store, so its first append reads its rows back and resumes from the stored
    /// tail instead of opening a second chain at seq 1. No row is read here; that cost is paid once
    /// per principal, by the principal, when it next settles.
    pub async fn restore_from_store(
        &self,
        store: &dyn PlaneStore,
    ) -> RecordStoreResult<ResidualRestored> {
        let principals = store.list_plane_record_parents(KIND_RESIDUAL).await?;
        let Some(stream) = stream_registry::handle(self.kind_id) else {
            return Err(RecordStoreError(
                "the usage.residual stream is not registered".to_string(),
            ));
        };
        for principal in &principals {
            stream.journal.forget(principal);
        }
        Ok(ResidualRestored {
            principals: principals.len(),
        })
    }

    /// One append on the stream. `Err` carries whether a stored row refused to decode during the
    /// append's resume (see [`REFRAME_REFUSED`]: the reframe that sets it runs after the resume's
    /// last await, in the poll that returns the error, so it is read on the thread that set it).
    async fn try_append(
        &self,
        principal: &str,
        content: &[u8],
    ) -> Result<(u64, String, String), (RecordStoreError, bool)> {
        REFRAME_REFUSED.with(|refused| refused.set(false));
        stream_registry::append_full(self.kind_id, principal, content)
            .await
            .map_err(|e| (e, REFRAME_REFUSED.with(|refused| refused.replace(false))))
    }

    /// Append `content` on `principal`'s chain. The stream resumes a principal it holds no position
    /// for from the store, and that resume refuses outright if any stored row will not decode; this
    /// log instead skips such rows ([`PlaneResidualLog::resume_past_unreadable`]) and appends.
    async fn append(
        &self,
        principal: &str,
        content: &[u8],
    ) -> RecordStoreResult<(u64, String, String)> {
        match self.try_append(principal, content).await {
            Ok(minted) => return Ok(minted),
            Err((e, false)) => return Err(e),
            Err((_, true)) => {}
        }
        let _serial = self.resume.lock().await;
        // Another writer may have resumed this principal while this one waited.
        match self.try_append(principal, content).await {
            Ok(minted) => return Ok(minted),
            Err((e, false)) => return Err(e),
            Err((_, true)) => {}
        }
        // The stream still holds no position for the principal (a miss is what resumes, and a
        // resume that meets an undecodable row commits nothing), and no other path can seed one
        // while this lock is held, so seeding from the store here cannot rewind a live position.
        self.resume_past_unreadable(principal).await?;
        stream_registry::append_full(self.kind_id, principal, content).await
    }

    /// THE TOLERANT RESUME of one principal whose stored rows do not all decode: read its rows,
    /// skip and report each that will not decode, and seed its position from the rest. A chain that
    /// does not verify still resumes from its tail and is reported. When the TAIL will not decode
    /// the position is unknown, so the principal is marked unresumable and its appends are refused
    /// rather than forking the log.
    async fn resume_past_unreadable(&self, principal: &str) -> RecordStoreResult<()> {
        let store = stream_registry::handle(self.kind_id)
            .and_then(|stream| stream.journal.sink())
            .ok_or_else(|| {
                RecordStoreError("the usage.residual stream has no durable store".to_string())
            })?;
        let selector = PlaneSelector::Parent(principal.into());
        let raw = store.list_plane_records(KIND_RESIDUAL, &selector).await?;
        let mut bodies = Vec::with_capacity(raw.len());
        let mut tail_unreadable = false;
        for body in raw {
            match reframe_residual(principal, &body) {
                Ok(_) => {
                    tail_unreadable = false;
                    bodies.push(body);
                }
                Err(e) => {
                    tail_unreadable = true;
                    tracing::error!(
                        principal = %principal,
                        error = %e,
                        "a persisted usage.residual row could NOT be decoded on resume; it is \
                         skipped, and the evidence in it is lost"
                    );
                }
            }
        }
        if tail_unreadable {
            self.unresumable_lock().insert(principal.to_string());
            return Err(unresumable_error());
        }
        let broke = stream_registry::seed(self.kind_id, principal, &bodies).map_err(|()| {
            RecordStoreError("usage.residual chain seed failed at the durable seam".to_string())
        })?;
        if broke {
            let records: Vec<StreamRecord> = bodies
                .iter()
                .map(|b| reframe_residual(principal, b))
                .collect::<RecordStoreResult<_>>()?;
            if let Err(brk) = verify_chain(&records) {
                tracing::error!(
                    principal = %brk.scope,
                    break_detail = %brk,
                    "usage.residual CHAIN VERIFICATION FAILED on resume; the rows stay in the store \
                     and the chain resumes from the broken tail"
                );
            }
        }
        Ok(())
    }

    /// RECORD one row with no host (the settle runs on the accrual funnel, which may be off a
    /// dispatch scope). Mints the link on the principal's chain and writes the body through to the
    /// store; on a store failure the position is untouched.
    pub(crate) async fn record_hostless(
        &self,
        principal: &str,
        input: ResidualInput,
    ) -> RecordStoreResult<ResidualRecorded> {
        if self.unresumable_lock().contains(principal) {
            return Err(unresumable_error());
        }
        let content = residual_suffix(&input);
        let (seq, prev_hash, hash) = self.append(principal, &content).await?;
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
    pub async fn read_back(
        &self,
        store: &dyn PlaneStore,
        principal: &str,
    ) -> RecordStoreResult<Vec<ResidualRecorded>> {
        let selector = PlaneSelector::Parent(principal.into());
        store
            .list_plane_records(KIND_RESIDUAL, &selector)
            .await?
            .iter()
            .map(|body| residual_record_from_body(principal, body))
            .collect()
    }

    /// VERIFY one principal's persisted chain end to end: `Ok(Ok(n))` is `n` rows verified.
    pub async fn verify_principal_chain(
        &self,
        store: &dyn PlaneStore,
        principal: &str,
    ) -> RecordStoreResult<Result<usize, ChainBreak>> {
        let selector = PlaneSelector::Parent(principal.into());
        let records: Vec<StreamRecord> = store
            .list_plane_records(KIND_RESIDUAL, &selector)
            .await?
            .iter()
            .map(|b| reframe_residual(principal, b))
            .collect::<RecordStoreResult<_>>()?;
        Ok(verify_chain(&records).map(|()| records.len()))
    }
}

fn unresumable_error() -> RecordStoreError {
    RecordStoreError(
        "this principal's stored usage.residual tail did not decode on resume, so its chain \
         position is unknown; the append is refused rather than forking the log"
            .to_string(),
    )
}

/// THE SETTLE: one `usage.residual` row on `log` per non-empty `residual` map; an empty map writes
/// nothing and returns `None`. The kernel spells the row, so a plane hands the counts over and
/// never writes it itself.
pub(crate) async fn settle(
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
    Some(log.record_hostless(principal, input).await)
}

/// THE EMITTER: settle on [`RESIDUALS`] and report the result. A failure is raised at `error!` on the transition into
/// failing (then held at `debug!` until a write succeeds), never swallowed silently and never
/// failing the request.
pub async fn emit(
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
    )
    .await
    {
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
/// RESTORE it from the store, so every principal's chain continues where the last process stopped:
/// each principal's rows are read back on its first append, never all of them here.
/// With no governance store the stream still registers and keeps its positions in RAM.
/// The restore summary logs at `debug!`: an LLM-only boot on a durable store prints no line 1.5.5
/// never printed (the same neutrality the root boot applies to its seal line).
///
/// Boot, before a listener binds: this thread owns the one wait for the store's answer.
pub(crate) fn register_and_restore(app: &Arc<crate::state::App>) {
    let sink = app
        .governance
        .as_ref()
        .and_then(|gov| gov.store_calls())
        .map(crate::store::plane_view::PlaneStoreView::narrow);
    register_residual_stream_as(KIND_ID_RESIDUAL, sink.clone());
    let Some(store) = sink else {
        return;
    };
    match crate::store::plane_view::wait_for(RESIDUALS.restore_from_store(store.as_ref())) {
        Ok(r) if r.principals > 0 => tracing::debug!(
            principals = r.principals,
            "usage.residual log restored from the durable store; each principal resumes from its \
             stored tail on its first append"
        ),
        Ok(_) => {}
        Err(e) => tracing::error!(
            error = %e.0,
            "could not restore the durable usage.residual log; chains start from RAM and an \
             evicted principal resumes from the store on its next row"
        ),
    }
}

/// TEST ONLY: a fresh, process-unique stream id, well above the production ids and the
/// `plane_host::journal` test range (base 10_000) and the `task_event` test range (base 100_000).
#[cfg(test)]
fn fresh_test_kind_id() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(200_000);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

/// TEST ONLY: a residual log over a fresh stream id, registered over `store`. A "restart" is a
/// second `over` the SAME store.
#[cfg(test)]
pub(crate) struct ResidualTestHarness {
    pub(crate) log: PlaneResidualLog,
}

#[cfg(test)]
impl ResidualTestHarness {
    pub(crate) fn over(store: Arc<dyn busbar_contract::records::RecordStore>) -> Self {
        let kind_id = fresh_test_kind_id();
        register_residual_stream_as(
            kind_id,
            Some(crate::store::plane_view::PlaneStoreView::narrow(
                crate::test_support::record_calls::RecordCalls::over(store),
            )),
        );
        Self {
            log: PlaneResidualLog::with_kind_id(kind_id),
        }
    }

    /// RESTORE this harness's stream from `store`.
    pub(crate) fn restore_from_store(
        &self,
        store: &dyn PlaneStore,
    ) -> RecordStoreResult<ResidualRestored> {
        crate::store::plane_view::wait_for(self.log.restore_from_store(store))
    }
}

#[cfg(test)]
#[path = "tests/residual_log_tests.rs"]
mod residual_log_tests;
