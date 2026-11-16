// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-instance port wrapper: `limits.timeout_ms` deadlines and the `limits.max_inflight` semaphore at every port
//! call site (IF §12.22).
//!
//! Every kernel call into a port of any kind (store, secret, auth, hook, export, plane, transport) goes through the
//! instance's [`PortGate`]: the call's deadline becomes min(caller's deadline, call start + `timeout_ms`), and at most
//! `max_inflight` calls of the instance run at once (a `tokio::sync::Semaphore` acquired before the port call, so
//! the loader's budget and the driver are unchanged). The export pump runs each delivery through the same gate, so
//! its per-delivery deadline and in-flight cap are these two rules. 0 in either field = no extra cap.

#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(test)]
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::InstanceLimits;
#[cfg(test)]
use busbar_plugin_abi::types::KindCode;
use busbar_ports::{CallCx, PortError};
use tokio::sync::Semaphore;

use crate::config::min3::InstanceLimitsCfg;

/// One instance's operator limits at its port call sites.
#[derive(Debug)]
pub struct PortGate {
    timeout: Option<Duration>,
    max_inflight: u32,
    inflight: Option<Arc<Semaphore>>,
}

impl PortGate {
    /// From the instance's limits (the copy the loader keeps in `Caller.limits`).
    #[must_use]
    pub fn new(limits: InstanceLimits) -> Self {
        Self::of(limits.timeout_ms, limits.max_inflight)
    }

    /// From `<kind>.<name>.limits` as K7 parsed it.
    #[must_use]
    pub fn from_cfg(cfg: &InstanceLimitsCfg) -> Self {
        Self::of(cfg.timeout_ms, cfg.max_inflight)
    }

    fn of(timeout_ms: u32, max_inflight: u32) -> Self {
        Self {
            timeout: (timeout_ms > 0).then(|| Duration::from_millis(u64::from(timeout_ms))),
            max_inflight,
            inflight: (max_inflight > 0).then(|| Arc::new(Semaphore::new(max_inflight as usize))),
        }
    }

    /// No extra cap (no `limits`).
    #[must_use]
    pub fn unbounded() -> Self {
        Self::of(0, 0)
    }

    /// min(caller's deadline, start + timeout_ms).
    #[must_use]
    pub fn deadline(&self, caller: Instant, start: Instant) -> Instant {
        match self.timeout.and_then(|t| start.checked_add(t)) {
            Some(cap) => caller.min(cap),
            None => caller,
        }
    }

    /// `cx` with its deadline capped from now: the copy a sync port call (no `call` future) is given.
    #[must_use]
    pub fn bound(&self, mut cx: CallCx) -> CallCx {
        cx.deadline = self.deadline(cx.deadline, Instant::now());
        cx
    }

    /// The configured `max_inflight` (0 = unbounded).
    #[must_use]
    pub fn max_inflight(&self) -> u32 {
        self.max_inflight
    }

    /// Calls in flight now (0 when unbounded: nothing is counted).
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.inflight.as_ref().map_or(0, |s| {
            self.max_inflight
                .saturating_sub(u32::try_from(s.available_permits()).unwrap_or(u32::MAX))
        })
    }

    /// Runs one port call under the instance's limits. The deadline is taken at entry, so time spent waiting for
    /// an in-flight permit counts against it; a wait or a call that passes it answers `Call(Deadline)`, and the
    /// port future is dropped (drop = cancel, §10.4). The permit is held until the call's future completes or is
    /// dropped.
    pub async fn call<T, F, Fut>(&self, cx: CallCx, port: F) -> Result<T, PortError>
    where
        F: FnOnce(CallCx) -> Fut,
        Fut: std::future::Future<Output = Result<T, PortError>>,
    {
        let cx = self.bound(cx);
        let at = tokio::time::Instant::from_std(cx.deadline);
        let _permit = match &self.inflight {
            Some(sem) => match tokio::time::timeout_at(at, Arc::clone(sem).acquire_owned()).await {
                Ok(Ok(permit)) => Some(permit),
                // The semaphore is never closed; a closed one refuses like a passed deadline.
                Ok(Err(_)) | Err(_) => return Err(PortError::Call(CallError::Deadline)),
            },
            None => None,
        };
        match tokio::time::timeout_at(at, port(cx)).await {
            Ok(answer) => answer,
            Err(_) => Err(PortError::Call(CallError::Deadline)),
        }
    }
}

/// One gate per (kind, configured instance name), with the limits it was built for.
#[cfg(test)]
type GateMap = HashMap<(KindCode, Box<str>), (InstanceLimits, Arc<PortGate>)>;

/// Every instance's gate, keyed by (kind, configured instance name). A reconfigure that keeps an instance's limits
/// keeps its gate (and so its in-flight count); new limits get a new gate, and calls already holding a permit of
/// the old one finish under it.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct PortGates {
    gates: Mutex<GateMap>,
}

#[cfg(test)]
impl PortGates {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The gate for an instance with these limits (cold: at open and reconfigure; the caller keeps the `Arc`).
    pub fn gate(&self, kind: KindCode, name: &str, limits: InstanceLimits) -> Arc<PortGate> {
        let mut gates = self.gates.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((held, gate)) = gates.get(&(kind, name.into())) {
            if *held == limits {
                return Arc::clone(gate);
            }
        }
        let gate = Arc::new(PortGate::new(limits));
        gates.insert((kind, name.into()), (limits, Arc::clone(&gate)));
        gate
    }

    /// Forgets a closed instance's gate.
    pub fn remove(&self, kind: KindCode, name: &str) {
        self.gates
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(kind, name.into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::host_side::caller::CallStack;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn cx(within: Duration) -> CallCx {
        CallCx {
            deadline: Instant::now() + within,
            request_id: 1,
            stack: CallStack::default(),
        }
    }

    fn limits(timeout_ms: u32, max_inflight: u32) -> InstanceLimits {
        InstanceLimits {
            timeout_ms,
            max_inflight,
            ..InstanceLimits::default()
        }
    }

    /// C-LIMITS timeout_ms (kernel half): the deadline is min(caller, start + timeout_ms), both ways round.
    #[test]
    fn deadline_is_the_earlier_of_caller_and_timeout() {
        let start = Instant::now();
        let gate = PortGate::new(limits(100, 0));
        let far = start + Duration::from_secs(60);
        assert_eq!(
            gate.deadline(far, start),
            start + Duration::from_millis(100)
        );
        let near = start + Duration::from_millis(10);
        assert_eq!(gate.deadline(near, start), near);
        assert_eq!(PortGate::unbounded().deadline(far, start), far);
    }

    /// C-LIMITS timeout_ms: a slow port call is cut at timeout_ms and answers Call(Deadline).
    #[tokio::test]
    async fn timeout_ms_cuts_a_slow_call() {
        let gate = PortGate::new(limits(50, 0));
        let started = Instant::now();
        let seen = Arc::new(Mutex::new(None));
        let seen_in = Arc::clone(&seen);
        let out: Result<(), PortError> = gate
            .call(cx(Duration::from_secs(60)), |cx| async move {
                *seen_in.lock().unwrap_or_else(PoisonError::into_inner) = Some(cx.deadline);
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(())
            })
            .await;
        assert_eq!(out, Err(PortError::Call(CallError::Deadline)));
        assert!(started.elapsed() < Duration::from_secs(10));
        let given = seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .expect("the port ran");
        assert!(
            given <= started + Duration::from_millis(100),
            "the port saw the capped deadline"
        );
    }

    /// A call inside its limits answers what the port answered.
    #[tokio::test]
    async fn a_quick_call_passes_through() {
        let gate = PortGate::new(limits(5_000, 2));
        let out = gate
            .call(cx(Duration::from_secs(5)), |_| async {
                Ok::<_, PortError>(7)
            })
            .await;
        assert_eq!(out, Ok(7));
        assert_eq!(gate.in_flight(), 0);
    }

    /// C-LIMITS max_inflight: never more than max_inflight concurrent calls of one instance.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn max_inflight_caps_concurrent_calls() {
        let gate = Arc::new(PortGate::new(limits(0, 3)));
        let now = Arc::new(AtomicU32::new(0));
        let peak = Arc::new(AtomicU32::new(0));
        let mut calls = Vec::new();
        for _ in 0..12 {
            let (gate, now, peak) = (Arc::clone(&gate), Arc::clone(&now), Arc::clone(&peak));
            calls.push(tokio::spawn(async move {
                gate.call(cx(Duration::from_secs(30)), |_| async {
                    let n = now.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(n, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    now.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, PortError>(())
                })
                .await
            }));
        }
        for call in calls {
            assert_eq!(call.await.expect("join"), Ok(()));
        }
        assert_eq!(peak.load(Ordering::SeqCst), 3);
        assert_eq!(gate.in_flight(), 0);
    }

    /// A call waiting for a permit is still bound by its deadline.
    #[tokio::test]
    async fn waiting_for_a_permit_counts_against_the_deadline() {
        let gate = Arc::new(PortGate::new(limits(0, 1)));
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
        let holder = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                gate.call(cx(Duration::from_secs(30)), |_| async {
                    let _ = hold_rx.await;
                    Ok::<_, PortError>(())
                })
                .await
            })
        };
        while gate.in_flight() == 0 {
            tokio::task::yield_now().await;
        }
        let waited = gate
            .call(cx(Duration::from_millis(30)), |_| async {
                Ok::<_, PortError>(())
            })
            .await;
        assert_eq!(waited, Err(PortError::Call(CallError::Deadline)));
        let _ = hold_tx.send(());
        assert_eq!(holder.await.expect("join"), Ok(()));
    }

    /// Gates are per instance name and survive a reconfigure that keeps the limits.
    #[test]
    fn gates_are_kept_by_instance_and_limits() {
        let gates = PortGates::new();
        let a = gates.gate(KindCode::Export, "hook-out", limits(10, 2));
        let same = gates.gate(KindCode::Export, "hook-out", limits(10, 2));
        assert!(Arc::ptr_eq(&a, &same));
        let other = gates.gate(KindCode::Export, "audit-out", limits(10, 2));
        assert!(!Arc::ptr_eq(&a, &other));
        let changed = gates.gate(KindCode::Export, "hook-out", limits(10, 4));
        assert_eq!(changed.max_inflight(), 4);
        gates.remove(KindCode::Export, "hook-out");
        let fresh = gates.gate(KindCode::Export, "hook-out", limits(10, 4));
        assert!(!Arc::ptr_eq(&changed, &fresh));
    }
}
