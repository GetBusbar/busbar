// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND'S CALLS, AS THE HOST'S TWO HALVES SHARE THEM (the design: hooks on the memory
//! ABI, the off-worker lane and quarantine rulings; the K1 `PlaneCalls` pattern): [`HookCalls`],
//! one opened hook instance on the process dispatcher, and [`HookAxis`], which opens one and which
//! the composition root implements and installs. The kernel names these and nothing behind them.
//! Nothing here crosses the plugin boundary: the hook kind's ABI is `abi::hook`, and its views are
//! built by `abi::host::hook`.
//!
//! Every call runs on the dispatcher's workers, off the caller's own (R1), and is bounded by the
//! call's `budget` — the hook's `timeout_ms` — which is also the crossing watchdog's budget for the
//! instance: a crossing that outlives it quarantines the instance, and the implementation brings a
//! FRESH instance back after a backoff through one trial call (R2). A call made while quarantined
//! waits for the trial window within its own budget, never beyond it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::abi::hook::{DecideOut, TransformOut};
use crate::abi::host::hook::{DecideFrame, NotifyFrame};
use crate::abi::mechanism::call::Outcome;

/// A call in flight: the caller's task awaits it; no thread is parked. Dropping it is a client
/// drop.
pub type Pending<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// How one `decide`/`transform` ended.
#[derive(Debug)]
pub enum Answered<O> {
    /// The plugin answered: its outcome (READY or FAILED; a FAULT is [`Answered::Broken`]), its
    /// `out`, the error text of a FAILED answer, and the frame whose host buffers the answer was
    /// written into (the re-call's, when the first answer was short).
    Answer {
        /// READY or FAILED.
        outcome: Outcome,
        /// The `out`.
        out: O,
        /// The error text, for FAILED.
        error: Option<String>,
        /// The frame to read the host buffers from.
        frame: Arc<DecideFrame>,
    },
    /// The call's budget passed before an answer (the hook's `timeout_ms`).
    TimedOut,
    /// No answer can be had: a FAULT, a REFUSED (the instance is at its `max_inflight`, closed or
    /// quarantined past the budget), or a second short answer. The text says which.
    Broken(String),
}

/// ONE OPENED HOOK INSTANCE'S CALLS, as the kernel makes them.
pub trait HookCalls: Send + Sync {
    /// The instance's plugin name (its Statement's).
    fn name(&self) -> &str;

    /// `decide` over `frame`, with the one short re-call; bounded by `budget`.
    fn decide(&self, frame: Arc<DecideFrame>, budget: Duration) -> Pending<Answered<DecideOut>>;

    /// `transform` over `frame`, with the one short re-call; bounded by `budget`.
    fn transform(
        &self,
        frame: Arc<DecideFrame>,
        budget: Duration,
    ) -> Pending<Answered<TransformOut>>;

    /// `notify` over `frame`, fire-and-forget: every failure is swallowed.
    fn notify(&self, frame: Arc<NotifyFrame>, budget: Duration) -> Pending<()>;

    /// `configure`: push `settings` (a JSON object) at `version` for the instance `name`; `Ok`
    /// only when the plugin acknowledged exactly `version`.
    fn configure(
        &self,
        name: &str,
        settings: &str,
        version: u64,
        budget: Duration,
    ) -> Pending<Result<(), String>>;

    /// `status`: the 1.5.5 status envelope's JSON bytes; `None` when the plugin did not answer.
    fn status(&self, budget: Duration) -> Pending<Option<Vec<u8>>>;

    /// `describe`: the 1.5.5 describe envelope's JSON bytes; `None` when the plugin did not answer.
    fn describe(&self, budget: Duration) -> Pending<Option<Vec<u8>>>;
}

/// What a hook plugin states about itself: its Statement name and its kind tail's facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookFacts {
    /// The Statement's name.
    pub name: String,
    /// [`crate::abi::hook::CLASS_GATE`] | [`crate::abi::hook::CLASS_TAP`].
    pub class: u32,
    /// The prompt access the plugin declares: [`crate::abi::hook::PROMPT_NO`] | `_RO` | `_RW`.
    pub prompt: u32,
    /// The user access the plugin declares: [`crate::abi::hook::USER_NO`] | `_RO`.
    pub user: u32,
    /// Whether the plugin declares itself infallible.
    pub infallible: bool,
    /// The hook words the plugin declares (its tail's `declared_words`).
    pub words: Vec<String>,
}

/// What [`HookAxis::probe`] answers of a module: the facts its Statement states (`None` when it
/// will not load here) and its own validation of the instance's settings, verbatim.
pub type Probed = (Option<HookFacts>, Vec<String>);

/// THE HOOK AXIS, as the kernel asks it (ARCHITECT ruling 2026-09-29, the opener seam; the
/// template is the export kind's `ExportAxis`): every `kind: hook` row the composition root
/// admitted (compiled in or dropped in, one registration), resolved by `module:` name or alias.
/// The root implements it over its plugin registry and the process's one dispatcher and installs
/// it once; the kernel probes and opens hook instances through it and names nothing behind it.
/// The hook kind has no cross-instance `check` op, so the axis has no `check`.
pub trait HookAxis: Send + Sync {
    /// `None` when no `kind: hook` row names `module`; else what [`Probed`] states, asked while the
    /// configuration is resolved (`instance` names the configured hook in any refusal).
    fn probe(&self, module: &str, instance: &str, settings: &serde_json::Value) -> Option<Probed>;

    /// OPEN one instance of `module` with `settings` (the operator's section, secrets resolved),
    /// under the host's instance `label` (unique per opened instance: the name every host service
    /// keys its caller by). `budget` is the instance's call budget (its `timeout_ms`): every call is
    /// bounded by it, and so is the watchdog over its crossings. A management instance
    /// (configure/status/describe) is just another instance.
    ///
    /// # Errors
    /// Why it will not open, naming the module.
    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
        budget: Duration,
    ) -> Result<Arc<dyn HookCalls>, String>;

    /// Whether `module` names a row this build LINKS (as opposed to one dropped in).
    fn linked(&self, module: &str) -> bool;

    /// Whether `module` names a FIRST-PARTY row: linked, or dropped in signed by the release key.
    fn first_party(&self, module: &str) -> bool;
}
