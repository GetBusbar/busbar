// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store adapter: the kernel's `busbar_contract::persistence::PersistenceBackend` over the store kind's `Proxy`
//! (IF §11.3), with the §8.8 encoders and decoders. `info` is read once at open and cached (round 6). An instance
//! whose describe declared `store::F_BLOCKING_FILE` makes every entry as one job on core's store lane
//! (`StoreLane`, round 11), never on a tokio worker; every other store runs inline (I5, B-CHAIN).

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::call::kinds::store::Proxy;
use crate::call::Mono;
use busbar_contract::persistence::{
    control, BackendInfo, Call, ClockObservation, CommitKey, DatasetId, Decision, Durability,
    Failure, Page, PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_contract::plugin::KernelSeal;
use busbar_plugin_abi::fail::fact::{FACT_BACKEND_STATUS, FACT_RETRY_AFTER_S};
use busbar_plugin_abi::fail::refused::R_INVALID;
use busbar_plugin_abi::fail::{CallError, FaultReason};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::caller::{CallStack, Caller};
use busbar_plugin_abi::host_side::driver::{Driver, Instance};
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::{sync_bufs, Pool, PooledOut};
use busbar_plugin_abi::host_side::scrub::fail_text;
use busbar_plugin_abi::kinds::store::store as wire;
use busbar_plugin_abi::records::Full;
use busbar_plugin_abi::types::Status;

use crate::instance::OpenError;
use busbar_ports::codec::store::{self as codec, ScanOutcome};
use busbar_ports::PortError;

/// A store call's chain deadline when the operator set no `limits.timeout_ms` (today's store deadline).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Core's store lane. No pool of its own: tokio's blocking pool supplies the threads; the per-instance
/// `limits.max_inflight` (§12.22) bounds how many jobs one store has in flight.
#[derive(Clone)]
pub(crate) struct StoreLane {
    rt: tokio::runtime::Handle,
}

impl StoreLane {
    pub(crate) fn new(rt: tokio::runtime::Handle) -> Self {
        Self { rt }
    }

    /// Runs `job` on a blocking-pool thread and awaits its `JoinHandle`. A panic that escaped the entry wrapper
    /// (`JoinError`) is `CallError::Fault`. Dropping the returned future detaches the job, which runs to
    /// completion and drops its answer (an unobserved commit, resolved by the kernel's readback).
    pub(crate) fn run<R: Send + 'static>(
        &self,
        job: impl FnOnce() -> Result<R, CallError> + Send + 'static,
    ) -> impl Future<Output = Result<R, CallError>> + Send + 'static {
        let handle = self.rt.spawn_blocking(job);
        async move {
            handle
                .await
                .unwrap_or(Err(CallError::Fault(FaultReason::Panic)))
        }
    }
}

/// A lane job's one poll: an `F_BLOCKING_FILE` store has an empty Need row, so its chain ends in its first poll.
/// Pending is impossible and is a FAULT, returned after the future (and its `ChainGuard`'s inline cancel) dropped.
pub(crate) fn once<R>(chain: impl Future<Output = R>) -> Result<R, CallError> {
    let mut chain = pin!(chain);
    match chain.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(done) => Ok(done),
        Poll::Pending => Err(CallError::Fault(FaultReason::NeedNotAllowed(0))),
    }
}

/// The lane for an instance whose describe facts carry `F_BLOCKING_FILE`, else none (inline).
fn lane_for(facts: u64, rt: &tokio::runtime::Handle) -> Option<StoreLane> {
    (facts & wire::F_BLOCKING_FILE != 0).then(|| StoreLane::new(rt.clone()))
}

/// The store port over one opened instance. Every inline call borrows `state`; a lane call moves one `Arc` of
/// it into its job (I5's stated lane pair).
pub struct StoreAdapter<N: Needs> {
    state: Arc<State<N>>,
}

struct State<N: Needs> {
    /// None only inside `Drop`, which hands a lane instance's last proxy (and so its `close`) to the lane.
    proxy: Option<Proxy>,
    needs: Arc<N>,
    info: BackendInfo,
    lane: Option<StoreLane>,
    seal: Box<dyn KernelSeal + Send + Sync>,
}

/// One store request, owning what the kernel handed over, so a lane job can carry it.
enum Op {
    Read(Arc<Read>),
    Scan(Arc<Scan>),
    Commit(PreparedCandidate, CommitKey),
    Clock(DatasetId),
}

impl<N: Needs> StoreAdapter<N> {
    /// Called by the registry right after INSTANCE and before `open_store` returns (inside the lane job for a lane
    /// store). Retains the store's kernel seal for candidate encoding, makes the one sync `info` call,
    /// refuses a refused, failed or malformed answer and a durability that
    /// disagrees with the describe facts, and picks the lane by `F_BLOCKING_FILE`.
    pub fn new(
        proxy: Proxy,
        needs: Arc<N>,
        rt: &tokio::runtime::Handle,
        seal: Box<dyn KernelSeal + Send + Sync>,
    ) -> Result<Self, OpenError> {
        let inst: &Instance = proxy.instance();
        let facts = inst.facts;
        let info = sync_bufs(inst.max_out, |_, out| {
            let answer = proxy.info(out).map_err(OpenError::Call)?;
            info_answer(&answer, inst)
        })?;
        durability(facts, &info)?;
        let state = State {
            proxy: Some(proxy),
            needs,
            info,
            lane: lane_for(facts, rt),
            seal,
        };
        Ok(Self {
            state: Arc::new(state),
        })
    }
}

impl<N: Needs> PersistenceBackend for StoreAdapter<N> {
    fn info(&self) -> BackendInfo {
        self.state.info
    }

    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        let n = request.addresses.len();
        Box::pin(self.state.call(Op::Read(request), move |a, info| {
            let read = codec::decode_read(a, n).map_err(|_| Failure::Corrupt)?;
            let (ReadResult::Values { observed_at, .. }
            | ReadResult::TimeGuardFailed { observed_at }) = &read;
            authority(info, observed_at, false)?;
            Ok(read)
        }))
    }

    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        let namespace = request.namespace.0;
        Box::pin(self.state.call(Op::Scan(request), move |a, _| {
            match codec::decode_scan(a, namespace).map_err(|_| Failure::Corrupt)? {
                ScanOutcome::Page(page) => Ok(page),
                ScanOutcome::Stale => Err(Failure::StaleScan),
            }
        }))
    }

    fn commit(&self, candidate: PreparedCandidate, key: CommitKey) -> Call<'_, Decision> {
        Box::pin(self.state.call(Op::Commit(candidate, key), |a, info| {
            let decision = codec::decode_decision(a).map_err(|_| Failure::Unknown)?;
            if let Decision::TimeGuardFailed { observed_at } = &decision {
                authority(info, observed_at, true)?;
            }
            Ok(decision)
        }))
    }

    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(self.state.call(Op::Clock(dataset), |a, info| {
            let clock = codec::decode_clock(a).map_err(|_| Failure::Corrupt)?;
            authority(info, &clock, false)?;
            Ok(clock)
        }))
    }
}

impl<N: Needs> State<N> {
    /// Inline, or as one lane job that encodes, drives, polls once and decodes on the lane thread; only the
    /// decoded value crosses back.
    async fn call<T: Send + 'static>(
        self: &Arc<Self>,
        op: Op,
        decode: impl FnOnce(&Answer<'_>, &BackendInfo) -> Result<T, Failure> + Send + 'static,
    ) -> Result<T, Failure> {
        let commit = matches!(op, Op::Commit(..));
        match &self.lane {
            None => self.exec(&op, decode).await,
            Some(lane) => {
                let state = Arc::clone(self);
                lane.run(move || once(state.exec(&op, decode)))
                    .await
                    .unwrap_or_else(|e| Err(call_failure(e, commit)))
            }
        }
    }

    async fn exec<T>(
        &self,
        op: &Op,
        decode: impl FnOnce(&Answer<'_>, &BackendInfo) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        let commit = matches!(op, Op::Commit(..));
        admit(&self.info, op)?;
        let Some(proxy) = &self.proxy else {
            return Err(Failure::Overloaded);
        };
        let inst: &Instance = proxy.instance();
        let req = request(inst.max_out, op, &*self.seal).map_err(|_| Failure::Overloaded)?;
        let mut drv = Driver::new(&*self.needs, caller(inst));
        let answer = match op {
            // The persistence port carries no clock reading: none is handed in, and a store that needs
            // the time asks the host once.
            Op::Read(_) => proxy.read(&mut drv, Mono::NONE, req).await,
            Op::Scan(_) => proxy.scan(&mut drv, Mono::NONE, req).await,
            Op::Commit(..) => proxy.commit(&mut drv, Mono::NONE, req).await,
            Op::Clock(_) => proxy.clock(&mut drv, Mono::NONE, req).await,
        }
        .map_err(|e| call_failure(e, commit))?;
        let answer = answer.answer();
        if let Some(e) = port_error(&answer, inst) {
            tracing::warn!(plugin = %inst.identity, instance = %inst.name, error = ?e, "store call not answered OK");
        }
        if answer.status != Status::OK {
            return Err(status_failure(answer.status, commit));
        }
        decode(&answer, &self.info)
    }
}

impl<N: Needs> Drop for State<N> {
    /// A lane instance's last proxy drops on the lane, so its `Drop for Instance` closes it there (§11.3).
    fn drop(&mut self) {
        if let (Some(lane), Some(proxy)) = (&self.lane, self.proxy.take()) {
            drop(lane.rt.spawn_blocking(move || drop(proxy)));
        }
    }
}

/// The request records of `op` in a pooled buffer of the instance's `max_out` class (§8.8 encoders).
fn request(
    max_out: usize,
    op: &Op,
    seal: &(dyn KernelSeal + Send + Sync),
) -> Result<PooledOut, Full> {
    let mut req = Pool::global().acquire(max_out);
    match op {
        Op::Read(r) => codec::encode_read(&mut req, r)?,
        Op::Scan(s) => codec::encode_scan(&mut req, s)?,
        Op::Commit(c, k) => codec::encode_candidate(&mut req, c, k, seal)?,
        Op::Clock(d) => codec::encode_dataset(&mut req, d)?,
    }
    Ok(req)
}

/// The chain's caller, borrowed from the instance (round 14: no refcount RMW); `Driver::new` mints `chain`.
fn caller(inst: &Instance) -> Caller<'_> {
    let timeout = match inst.limits.timeout_ms {
        0 => DEFAULT_TIMEOUT,
        ms => Duration::from_millis(u64::from(ms)),
    };
    Caller {
        plugin: &inst.identity,
        kind: inst.kind,
        name: &inst.name,
        instance: inst.id,
        slot: inst.slot,
        chain: 0,
        deadline: Instant::now() + timeout,
        stack: CallStack::default(),
        out_of_process: false,
        limits: inst.limits,
    }
}

/// Before any byte is sent: the request names this instance's dataset, a continued scan states its generation
/// unless it allows change, and (round 30) every commit passes `control::admit`, the one choke point.
fn admit(info: &BackendInfo, op: &Op) -> Result<(), Failure> {
    let dataset = match op {
        Op::Read(r) => r.dataset,
        Op::Scan(s) => s.dataset,
        Op::Commit(c, _) => c.candidate().id.dataset,
        Op::Clock(d) => *d,
    };
    if dataset != info.dataset {
        return Err(Failure::Refused);
    }
    match op {
        Op::Scan(s) if s.after.is_some() && s.generation.is_none() && !s.allow_change => {
            Err(Failure::Refused)
        }
        Op::Commit(c, _) => control::admit(c),
        _ => Ok(()),
    }
}

/// A store-authoritative observation must name the clock authority the instance's `info` stated (C-STORE-INFO).
fn authority(info: &BackendInfo, seen: &ClockObservation, commit: bool) -> Result<(), Failure> {
    if seen.authority == info.clock_authority {
        Ok(())
    } else if commit {
        Err(Failure::Unknown)
    } else {
        Err(Failure::Corrupt)
    }
}

/// A chain that ended without an answer. A commit may have executed (the kernel resolves it by readback); a read
/// observed nothing. An undeclared method was never sent.
fn call_failure(e: CallError, commit: bool) -> Failure {
    match e {
        CallError::NotDeclared => Failure::Refused,
        _ if commit => Failure::Unknown,
        _ => Failure::Unavailable,
    }
}

/// REFUSED is before any mutation; FAILED is unevaluated or unknown, so a commit's outcome is Unknown.
fn status_failure(status: Status, commit: bool) -> Failure {
    if status == Status::REFUSED {
        Failure::Refused
    } else if commit {
        Failure::Unknown
    } else {
        Failure::Unavailable
    }
}

/// A REFUSED or FAILED answer as a `PortError` with the scrubbed text and (round 21) the FAILED facts; None for
/// OK. W1-L2 gap: the one shared builder (ports/mod.rs, with `ErrorBook` resolution of `error`) is not on dev,
/// so `error` is None here until it lands and this moves there.
fn port_error(a: &Answer<'_>, inst: &Instance) -> Option<PortError> {
    let (code, text) = a.fail()?;
    let text: Box<str> = fail_text(&inst.scrub, text).into();
    Some(if a.status == Status::REFUSED {
        PortError::Refused {
            code,
            text,
            error: None,
        }
    } else {
        PortError::Failed {
            code,
            text,
            retry_after_s: a.fail_fact(FACT_RETRY_AFTER_S),
            backend_status: a.fail_fact(FACT_BACKEND_STATUS),
            error: None,
        }
    })
}

/// The `info` answer: exactly one INFO, else the open fails (round 6).
fn info_answer(a: &Answer<'_>, inst: &Instance) -> Result<BackendInfo, OpenError> {
    match port_error(a, inst) {
        None if a.is_ok() => {
            codec::decode_info(a).map_err(|_| invalid("the store's `info` answer is malformed"))
        }
        Some(PortError::Refused { code, text, error }) => Err(OpenError::Config {
            code,
            text: text.into(),
            error,
        }),
        Some(PortError::Failed {
            code, text, error, ..
        }) => Err(OpenError::Failed {
            code,
            text: text.into(),
            error,
        }),
        _ => Err(invalid("the store's `info` answer is malformed")),
    }
}

/// Round 12: `info` answers DUR_EPHEMERAL exactly when the describe facts carry `FB_EPHEMERAL`.
fn durability(facts: u64, info: &BackendInfo) -> Result<(), OpenError> {
    if (facts & wire::FB_EPHEMERAL != 0) == (info.durability == Durability::Ephemeral) {
        Ok(())
    } else {
        Err(invalid(
            "the store's `info` durability disagrees with its describe facts",
        ))
    }
}

fn invalid(text: &str) -> OpenError {
    OpenError::Config {
        code: R_INVALID,
        text: text.to_owned(),
        error: None,
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
