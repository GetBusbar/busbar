// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export adapter: `ExportPort` over the export kind's `Proxy` (IF §11.3, §8.5, round 33 §49, round 34 §50).
//!
//! `deliver` encodes one `TEXT` record per line straight into the chain's request buffer, runs the proxy's one
//! step loop and decodes the answer into [`Delivered`] (no intermediate vocabulary). `render` is sync. The
//! describe rules (D_STREAMS, D_SCOPE, D_RECORDER, FB_SPAN_RECORDS, D_DELIVERY) are checked once by
//! [`decode_describe`]; the `open` ceiling by [`ExportAdapter::open`].
//!
//! Gaps against frozen-but-unlanded neighbours, each to be closed by its owner (see the W1-L7 handoff):
//! - L2 owns the shared `PortError`/`OpenError` builder; until it lands, [`ExportAdapter::failed`] builds the
//!   export kind's `PortError` from the answer by the same rule (scrub then cut, facts, `ErrorBook::resolve`).
//! - L2's `open_export` calls [`decode_describe`] on the image's describe and [`ExportAdapter::open`] on the
//!   open answer; the instance's destination count comes from its bound D_DEST_PATH items.

use core::sync::atomic::AtomicBool;
use std::sync::Arc;

use busbar_contract::export_stream::ExportStream;
use busbar_plugin_abi::fail::{fact, failed::F_LIMIT, CallError, FaultReason};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::host_side::driver::Driver;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::{sync_bufs, Pool};
use busbar_plugin_abi::host_side::scrub::fail_text;
use busbar_plugin_abi::kinds::export::export::{
    tag, CustodyRec, Proxy, RecorderRec, ScopeRec, CUSTODY_ACCEPTED, FB_SPAN_RECORDS, M_CONFIRM,
    STREAM_COMPLETIONS, STREAM_CONTENT, STREAM_COSTS, STREAM_COUNT, STREAM_DECISIONS,
    STREAM_EVENTS, STREAM_IDENTITY, STREAM_LOGS, STREAM_METRICS, STREAM_PROMPTS, STREAM_TRACES,
};
use busbar_plugin_abi::records::Records;
use busbar_plugin_abi::records::{tag as generic, RecErr};
use busbar_plugin_abi::types::{KindCode, Status};

use crate::encode::export::{
    decode_ceiling, decode_confirmed, decode_delivered, decode_delivery, encode_batch,
    encode_snapshot,
};
use crate::instance::ErrorBook;
use crate::ports::export::{Custody, Delivered, ExportPort, FamilyIn, RecorderNeeds, ScopeInfo};
use crate::ports::{CallCx, PortError};

// Round 28/29/33: the ten STREAM_* numbers are pinned to core's `ExportStream` (the enum's one home is
// `busbar_contract::export_stream`), so a renumbering on either side is a compile error here.
const _: () = {
    assert!(STREAM_METRICS == ExportStream::Metrics as u32);
    assert!(STREAM_LOGS == ExportStream::Logs as u32);
    assert!(STREAM_TRACES == ExportStream::Traces as u32);
    assert!(STREAM_COSTS == ExportStream::Costs as u32);
    assert!(STREAM_DECISIONS == ExportStream::Decisions as u32);
    assert!(STREAM_EVENTS == ExportStream::Events as u32);
    assert!(STREAM_IDENTITY == ExportStream::Identity as u32);
    assert!(STREAM_PROMPTS == ExportStream::Prompts as u32);
    assert!(STREAM_COMPLETIONS == ExportStream::Completions as u32);
    assert!(STREAM_CONTENT == ExportStream::Content as u32);
    assert!(ExportStream::ALL.len() == STREAM_COUNT as usize);
};

/// What one export image's describe stated (§8.5), decoded and validated once at open.
pub struct Described {
    /// One bit per declared STREAM_* id (`1 << id`), 0 when the image declared none.
    pub streams: u32,
    pub scopes: Vec<ScopeInfo>,
    pub recorder: Option<RecorderNeeds>,
    /// FB_SPAN_RECORDS (round 29).
    pub span_records: bool,
    /// The image declared M_CONFIRM (round 33).
    pub confirm: bool,
    /// The declared bound retained for the core custody scheduler.
    pub pending_capacity: Option<u64>,
}

/// D_STREAMS: one ascending `u8` STREAM_* id per byte, 1..=STREAM_COUNT bytes. Anything else is `Size`.
fn streams_mask(body: &[u8]) -> Result<u32, RecErr> {
    if body.is_empty() || body.len() > STREAM_COUNT as usize {
        return Err(RecErr::Size);
    }
    let mut mask = 0u32;
    let mut prev: Option<u8> = None;
    for &id in body {
        if u32::from(id) >= STREAM_COUNT || prev.is_some_and(|p| id <= p) {
            return Err(RecErr::Size);
        }
        mask |= 1 << id;
        prev = Some(id);
    }
    Ok(mask)
}

/// The export describe (§8.5): D_STREAMS (at most one, valid body), D_SCOPE*, D_RECORDER (at most one),
/// FB_SPAN_RECORDS only with STREAM_TRACES declared, and round 33's D_DELIVERY rules (`decode_delivery`, validation
/// only in 1.6.0). Every violation is a `RecErr` the registry turns into DescribeInvalid.
pub fn decode_describe(
    describe: Records<'_>,
    methods: u64,
    facts: u64,
) -> Result<Described, RecErr> {
    let mut streams = None;
    let mut scopes = Vec::new();
    let mut recorder = None;
    for next in describe {
        let rec = next?;
        match rec.tag {
            tag::D_STREAMS => {
                if streams.is_some() {
                    return Err(RecErr::Size);
                }
                streams = Some(streams_mask(rec.body)?);
            }
            tag::D_SCOPE => {
                let (head, tail) = rec.pod_tail::<ScopeRec>()?;
                if head._r != 0 {
                    return Err(RecErr::Reserved);
                }
                let path = core::str::from_utf8(tail).map_err(|_| RecErr::Utf8)?;
                scopes.push(ScopeInfo {
                    scope: head.scope,
                    path: path.into(),
                });
            }
            tag::D_RECORDER => {
                if recorder.is_some() {
                    return Err(RecErr::Size);
                }
                let r = rec.pod::<RecorderRec>()?;
                recorder = Some(RecorderNeeds {
                    retention_s: r.retention_s,
                    key_gauge_limit: r.key_gauge_limit,
                });
            }
            _ => {}
        }
    }
    let streams = streams.unwrap_or(0);
    let span_records = facts & FB_SPAN_RECORDS != 0;
    if span_records && streams & (1 << STREAM_TRACES) == 0 {
        return Err(RecErr::Size);
    }
    let pending_capacity = decode_delivery(describe, methods)?;
    Ok(Described {
        streams,
        scopes,
        recorder,
        span_records,
        confirm: methods & M_CONFIRM != 0,
        pending_capacity,
    })
}

/// A decoded `deliver` answer as the port's value. No CUSTODY reads ACCEPTED with no recheck (round 33). An
/// APPEND's `dest` is the instance-local handle: at or past `dest_count` bindings it is FAULT BadRecords. APPEND
/// carries no custody (a file sink's is ACCEPTED, decided by core, §8.5).
pub fn delivered_from(
    accepted: u64,
    append: Option<(u32, &[u8])>,
    custody: Option<CustodyRec>,
    dest_count: u32,
) -> Result<Delivered, RecErr> {
    match append {
        Some((dest, tail)) => {
            if dest >= dest_count {
                return Err(RecErr::Size);
            }
            Ok(Delivered::Append {
                dest,
                bytes: (!tail.is_empty()).then(|| tail.to_vec()),
                accepted,
            })
        }
        None => Ok(Delivered::Acked {
            accepted,
            custody: custody.map_or(
                Custody {
                    level: CUSTODY_ACCEPTED,
                    recheck_s: 0,
                },
                |c| Custody {
                    level: c.level,
                    recheck_s: c.recheck_s,
                },
            ),
        }),
    }
}

fn bad_records(e: RecErr) -> PortError {
    PortError::Call(CallError::Fault(FaultReason::BadRecords(e)))
}

/// A batch or snapshot that does not fit the request buffer is core's own doing: a FAILED with core's words, no
/// plugin text and no facts.
fn too_big() -> PortError {
    PortError::Failed {
        code: F_LIMIT,
        text: "the request does not fit the export request buffer".into(),
        retry_after_s: None,
        backend_status: None,
        error: None,
    }
}

/// Core's own words for a content-path failure: the plugin's text never enters an engine record there (§8.5).
const CONTENT_FAILED: &str = "the content sink reported a failure";

/// The export port over one instance's proxy.
pub struct ExportAdapter<N: Needs> {
    proxy: Proxy,
    needs: Arc<N>,
    errors: &'static ErrorBook,
    undeclared_warned: AtomicBool,
    described: Described,
    dest_count: u32,
    ceiling: Option<u32>,
}

impl<N: Needs> ExportAdapter<N> {
    /// Built by `open_export` after the image's describe was decoded and the `open` chain answered `opened`.
    /// Round 33: the optional last CUSTODY of the open answer is the instance's ceiling; a malformed one is FAULT
    /// BadRecords and the open fails. `dest_count` = the instance's bound D_DEST_PATH destinations; `errors` = the
    /// owning image's book (§11.2).
    pub fn open(
        proxy: Proxy,
        needs: Arc<N>,
        errors: &'static ErrorBook,
        described: Described,
        dest_count: u32,
        opened: &Answer<'_>,
    ) -> Result<Self, CallError> {
        let ceiling =
            decode_ceiling(opened).map_err(|e| CallError::Fault(FaultReason::BadRecords(e)))?;
        Ok(Self {
            proxy,
            needs,
            errors,
            undeclared_warned: AtomicBool::new(false),
            described,
            dest_count,
            ceiling,
        })
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    /// The `PortError` of a REFUSED or FAILED answer. `content` = the answer is for STREAM_CONTENT `deliver` or a
    /// `confirm`: core keeps only the code and the facts, its own fixed text, and `error: None` (an ERROR record
    /// there is accepted and dropped, never FAULT; round 34, T13).
    fn failed(&self, a: &Answer<'_>, content: bool) -> PortError {
        let (code, raw) = a.fail().unwrap_or((0, ""));
        let (text, error): (Box<str>, _) = if content {
            (CONTENT_FAILED.into(), None)
        } else {
            let inst = self.proxy.instance();
            (
                fail_text(&inst.scrub, raw).into_owned().into_boxed_str(),
                self.errors.resolve(a.fail_error(), &self.undeclared_warned),
            )
        };
        if a.status == Status::REFUSED {
            PortError::Refused { code, text, error }
        } else {
            PortError::Failed {
                code,
                text,
                retry_after_s: a.fail_fact(fact::FACT_RETRY_AFTER_S),
                backend_status: a.fail_fact(fact::FACT_BACKEND_STATUS),
                error,
            }
        }
    }
}

impl<N: Needs> ExportPort for ExportAdapter<N> {
    fn streams(&self) -> u32 {
        self.described.streams
    }

    fn scopes(&self) -> &[ScopeInfo] {
        &self.described.scopes
    }

    fn recorder(&self) -> Option<RecorderNeeds> {
        self.described.recorder.as_ref().map(|r| RecorderNeeds {
            retention_s: r.retention_s,
            key_gauge_limit: r.key_gauge_limit,
        })
    }

    fn span_records(&self) -> bool {
        self.described.span_records
    }

    fn deliver<'a>(
        &'a self,
        cx: CallCx,
        stream: u32,
        delivery: u64,
        attempt: u32,
        lines: &'a [&'a [u8]],
    ) -> BoxFut<'a, Result<Delivered, PortError>> {
        Box::pin(async move {
            let inst = self.proxy.instance();
            let mut req = Pool::global().acquire(inst.max_out);
            encode_batch(&mut req, lines).map_err(|_| too_big())?;
            let caller = Caller {
                plugin: &inst.identity,
                kind: KindCode::Export,
                name: &inst.name,
                instance: inst.id,
                slot: inst.slot,
                chain: 0,
                deadline: cx.deadline,
                stack: cx.stack,
                out_of_process: false,
                limits: inst.limits,
            };
            let mut drv = Driver::new(&*self.needs, caller);
            let owned = self
                .proxy
                .deliver(&mut drv, req, stream, delivery, attempt)
                .await
                .map_err(PortError::Call)?;
            let a = owned.answer();
            if !a.is_ok() {
                return Err(self.failed(&a, stream == STREAM_CONTENT));
            }
            let (accepted, append, custody) =
                decode_delivered(&a, self.described.confirm).map_err(bad_records)?;
            delivered_from(accepted, append, custody, self.dest_count).map_err(bad_records)
        })
    }

    fn custody_ceiling(&self) -> Option<u32> {
        self.ceiling
    }

    fn pending_capacity(&self) -> Option<u64> {
        self.described.pending_capacity
    }

    fn confirm(&self, cx: CallCx, delivery: u64) -> BoxFut<'_, Result<Custody, PortError>> {
        Box::pin(async move {
            let inst = self.proxy.instance();
            let req = Pool::global().acquire(inst.max_out);
            let caller = Caller {
                plugin: &inst.identity,
                kind: KindCode::Export,
                name: &inst.name,
                instance: inst.id,
                slot: inst.slot,
                chain: 0,
                deadline: cx.deadline,
                stack: cx.stack,
                out_of_process: false,
                limits: inst.limits,
            };
            let mut drv = Driver::new(&*self.needs, caller);
            let owned = self
                .proxy
                .confirm(&mut drv, req, delivery)
                .await
                .map_err(PortError::Call)?;
            let answer = owned.answer();
            if !answer.is_ok() {
                return Err(self.failed(&answer, true));
            }
            let custody = decode_confirmed(&answer).map_err(bad_records)?;
            Ok(Custody {
                level: custody.level,
                recheck_s: custody.recheck_s,
            })
        })
    }

    fn render(
        &self,
        scope: u32,
        snapshot: &[FamilyIn<'_>],
        sink: &mut dyn FnMut(&str, &[u8]),
    ) -> Result<(), PortError> {
        let inst = self.proxy.instance();
        sync_bufs(inst.max_out, |args, out| {
            encode_snapshot(args, snapshot).map_err(|_| too_big())?;
            let a = self
                .proxy
                .render(out, scope, args.bytes())
                .map_err(PortError::Call)?;
            if !a.is_ok() {
                return Err(self.failed(&a, false));
            }
            let mut content_type = None;
            let mut body = None;
            for next in a.records() {
                let rec = next.map_err(bad_records)?;
                match rec.tag {
                    tag::CONTENT_TYPE if content_type.is_none() => {
                        content_type = Some(rec.text().map_err(bad_records)?);
                    }
                    tag::BODY if body.is_none() => body = Some(rec.body),
                    generic::METRIC => {}
                    other => return Err(bad_records(RecErr::Unknown(other))),
                }
            }
            match (content_type, body) {
                (Some(content_type), Some(body)) => {
                    sink(content_type, body);
                    Ok(())
                }
                _ => Err(bad_records(RecErr::Truncated)),
            }
        })
    }
}
