// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::hook::{DecideOut, TransformOut, CLASS_GATE, PROMPT_RW, USER_RO};
use busbar_contract::abi::host::hook::{DecideFrame, NotifyFrame};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::hook::{
    lower_decide_reply, lower_transform_reply, RewriteVerdict, Verdict,
};
use busbar_contract::hook_calls::{Answered, HookAxis, HookCalls, HookFacts, Pending, Probed};
use busbar_contract::hook_wire::{OP_DECIDE, OP_TRANSFORM};

pub const DOUBLE_NAME: &str = "hook-double";

/// One instance's behaviour, read from its settings.
#[derive(serde::Deserialize, Default, Clone)]
struct Behaviour {
    #[serde(default)]
    order: Vec<usize>,
    #[serde(default)]
    reject_if_contains: Option<String>,
    #[serde(default)]
    reject_status: Option<i64>,
    #[serde(default)]
    restrict_tags: Option<Vec<String>>,
    #[serde(default)]
    raw_decide_reply: Option<serde_json::Value>,
    #[serde(default)]
    raw_transform_reply: Option<serde_json::Value>,
    #[serde(default)]
    sleep_ms: Option<u64>,
    #[serde(default)]
    empty_management: bool,
    #[serde(default)]
    nack_configure: bool,
    #[serde(default)]
    panic_decide: bool,
    #[serde(default)]
    panic_transform: bool,
    #[serde(default)]
    fail_decide: Option<String>,
    #[serde(default)]
    fail_transform: Option<String>,
}

struct Gate {
    b: Behaviour,
    decides: AtomicU64,
    notifies: AtomicU64,
}

impl Gate {
    fn screens(&self, projection: &serde_json::Value) -> bool {
        let Some(token) = self.b.reject_if_contains.as_deref() else {
            return false;
        };
        projection["request"]["messages"]
            .as_array()
            .is_some_and(|msgs| {
                msgs.iter()
                    .any(|m| m["text"].as_str().is_some_and(|t| t.contains(token)))
            })
    }

    fn decide(&self, projection: &serde_json::Value) -> Result<serde_json::Value, String> {
        self.decides.fetch_add(1, Ordering::Relaxed);
        if let Some(why) = &self.b.fail_decide {
            return Err(why.clone());
        }
        assert!(!self.b.panic_decide, "hook double panic_decide");
        if let Some(ms) = self.b.sleep_ms {
            std::thread::sleep(Duration::from_millis(ms));
        }
        if let Some(raw) = &self.b.raw_decide_reply {
            return Ok(raw.clone());
        }
        if self.screens(projection) {
            let status = self.b.reject_status.unwrap_or(403);
            return Ok(serde_json::json!({
                "reject": {"status": status, "message": "blocked by test gate"}
            }));
        }
        if let Some(tags) = &self.b.restrict_tags {
            return Ok(serde_json::json!({ "restrict": {"tags_any": tags} }));
        }
        Ok(match self.b.order.is_empty() {
            true => serde_json::json!({}),
            false => serde_json::json!({ "order": self.b.order }),
        })
    }

    fn transform(&self, projection: &serde_json::Value) -> Result<serde_json::Value, String> {
        if let Some(why) = &self.b.fail_transform {
            return Err(why.clone());
        }
        assert!(!self.b.panic_transform, "hook double panic_transform");
        if self.screens(projection) {
            return Ok(serde_json::json!({"reject": {"status": 451, "message": "screened"}}));
        }
        if let Some(raw) = &self.b.raw_transform_reply {
            return Ok(raw.clone());
        }
        Ok(serde_json::json!({
            "rewrite": {"messages": [{"role": "user", "content": "rewritten by test gate"}]}
        }))
    }

    fn status(&self) -> serde_json::Value {
        if self.b.empty_management {
            return serde_json::json!({});
        }
        let decides = self.decides.load(Ordering::Relaxed);
        let taps = self.notifies.load(Ordering::Relaxed);
        serde_json::json!({
            "status": {
                "metrics": [
                    {"name": "test_decides_total", "type": "counter", "value": decides as f64},
                    {"name": "test_notifies_total", "type": "counter", "value": taps as f64}
                ]
            }
        })
    }

    fn describe(&self) -> serde_json::Value {
        if self.b.empty_management {
            return serde_json::json!({});
        }
        serde_json::json!({
            "schema": {"type": "object", "properties": {"order": {"type": "array"}}}
        })
    }
}

struct DoubleCalls {
    gate: Arc<Gate>,
}

pub(super) async fn bounded<T: Send + 'static>(
    budget: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Answered<std::convert::Infallible>> {
    match tokio::time::timeout(budget, tokio::task::spawn_blocking(work)).await {
        Err(_) => Err(Answered::TimedOut),
        Ok(Err(_)) => Err(Answered::Broken(format!(
            "hook plugin '{DOUBLE_NAME}' faulted (the op panicked)"
        ))),
        Ok(Ok(v)) => Ok(v),
    }
}

pub(super) fn unanswered<O>(a: Answered<std::convert::Infallible>) -> Answered<O> {
    match a {
        Answered::TimedOut => Answered::TimedOut,
        Answered::Broken(why) => Answered::Broken(why),
        Answered::Answer { out, .. } => match out {},
    }
}

pub(super) async fn verdict<V: Send + 'static, O>(
    frame: Arc<DecideFrame>,
    budget: Duration,
    reply: impl FnOnce(&DecideFrame) -> V + Send + 'static,
    answer: impl Fn(&DecideFrame, &V) -> (Outcome, O, Option<String>, bool),
    regrow: impl Fn(&DecideFrame, &O) -> Arc<DecideFrame>,
) -> Answered<O> {
    let asked = Arc::clone(&frame);
    let v = match bounded(budget, move || reply(&asked)).await {
        Ok(v) => v,
        Err(a) => return unanswered(a),
    };
    let (outcome, out, error, short) = answer(&frame, &v);
    if !short {
        return Answered::Answer {
            outcome,
            out,
            error,
            frame,
        };
    }
    let grown = regrow(&frame, &out);
    let (outcome, out, error, _) = answer(&grown, &v);
    Answered::Answer {
        outcome,
        out,
        error,
        frame: grown,
    }
}

impl HookCalls for DoubleCalls {
    fn name(&self) -> &str {
        DOUBLE_NAME
    }

    fn decide(&self, frame: Arc<DecideFrame>, budget: Duration) -> Pending<Answered<DecideOut>> {
        let gate = Arc::clone(&self.gate);
        Box::pin(verdict(
            frame,
            budget,
            move |f| lower_decide_reply(gate.decide(&f.projection_json(OP_DECIDE))),
            |f, v| {
                let (outcome, out) = f.answer_decide(v);
                match v {
                    Verdict::Failed(why) => (outcome, out, Some(why.clone()), false),
                    _ => (outcome, out, None, outcome == Outcome::Failed),
                }
            },
            |f, out| f.regrown_decide(out),
        ))
    }

    fn transform(
        &self,
        frame: Arc<DecideFrame>,
        budget: Duration,
    ) -> Pending<Answered<TransformOut>> {
        let gate = Arc::clone(&self.gate);
        Box::pin(verdict(
            frame,
            budget,
            move |f| lower_transform_reply(gate.transform(&f.projection_json(OP_TRANSFORM))),
            |f, v| {
                let (outcome, out) = f.answer_transform(v);
                match v {
                    RewriteVerdict::Failed(why) => (outcome, out, Some(why.clone()), false),
                    _ => (outcome, out, None, outcome == Outcome::Failed),
                }
            },
            |f, out| f.regrown_transform(out),
        ))
    }

    fn notify(&self, frame: Arc<NotifyFrame>, budget: Duration) -> Pending<()> {
        let gate = Arc::clone(&self.gate);
        Box::pin(async move {
            let _ = bounded(budget, move || {
                let _projection = frame.projection_json();
                gate.notifies.fetch_add(1, Ordering::Relaxed);
            })
            .await;
        })
    }

    fn configure(
        &self,
        _name: &str,
        settings: &str,
        version: u64,
        budget: Duration,
    ) -> Pending<Result<(), String>> {
        let gate = Arc::clone(&self.gate);
        let settings = settings.to_string();
        Box::pin(async move {
            let acked = bounded(budget, move || {
                match serde_json::from_str::<serde_json::Value>(&settings) {
                    Ok(serde_json::Value::Object(_)) => Ok(!gate.b.nack_configure),
                    _ => Err("settings: must be a JSON object".to_string()),
                }
            })
            .await;
            match acked {
                Ok(Ok(true)) => Ok(()),
                Ok(Ok(false)) => Err(format!(
                    "hook did not acknowledge settings_version {version}"
                )),
                Ok(Err(why)) => Err(why),
                Err(Answered::TimedOut) => Err(format!(
                    "hook '{DOUBLE_NAME}' did not acknowledge settings version {version} within \
                     its budget"
                )),
                Err(Answered::Broken(why)) => Err(why),
                Err(Answered::Answer { out, .. }) => match out {},
            }
        })
    }

    fn status(&self, budget: Duration) -> Pending<Option<Vec<u8>>> {
        let gate = Arc::clone(&self.gate);
        Box::pin(async move {
            bounded(budget, move || serde_json::to_vec(&gate.status()).ok())
                .await
                .ok()
                .flatten()
        })
    }

    fn describe(&self, budget: Duration) -> Pending<Option<Vec<u8>>> {
        let gate = Arc::clone(&self.gate);
        Box::pin(async move {
            bounded(budget, move || serde_json::to_vec(&gate.describe()).ok())
                .await
                .ok()
                .flatten()
        })
    }
}

pub struct HookAxisDouble {
    rows: Vec<String>,
    linked: Arc<dyn HookAxis>,
}

impl std::fmt::Debug for HookAxisDouble {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookAxisDouble")
            .field("rows", &self.rows)
            .finish_non_exhaustive()
    }
}

impl HookAxisDouble {
    #[must_use]
    pub fn new(modules: &[&str]) -> Arc<Self> {
        let linked =
            super::hook_axis_stand_in(&super::rows::empty()).expect("the build's linked hook rows");
        Arc::new(Self {
            rows: modules.iter().map(|m| m.to_string()).collect(),
            linked,
        })
    }

    fn answers(&self, module: &str) -> bool {
        self.rows.iter().any(|m| m == module)
    }

    fn facts() -> HookFacts {
        HookFacts {
            name: DOUBLE_NAME.to_string(),
            class: CLASS_GATE,
            prompt: PROMPT_RW,
            user: USER_RO,
            infallible: false,
            words: Vec::new(),
        }
    }
}

impl HookAxis for HookAxisDouble {
    fn probe(&self, module: &str, instance: &str, settings: &serde_json::Value) -> Option<Probed> {
        if !self.answers(module) {
            return self.linked.probe(module, instance, settings);
        }
        let problems = match serde_json::from_value::<Behaviour>(settings.clone()) {
            Ok(_) => Vec::new(),
            Err(e) => vec![format!("invalid hook double settings: {e}")],
        };
        Some((Some(Self::facts()), problems))
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
        budget: Duration,
    ) -> Result<Arc<dyn HookCalls>, String> {
        if !self.answers(module) {
            return self.linked.open(module, label, settings, budget);
        }
        let b: Behaviour = match settings {
            serde_json::Value::Null => Behaviour::default(),
            v => serde_json::from_value(v.clone()).map_err(|e| {
                format!("hook plugin '{module}': invalid hook double settings: {e}")
            })?,
        };
        Ok(Arc::new(DoubleCalls {
            gate: Arc::new(Gate {
                b,
                decides: AtomicU64::new(0),
                notifies: AtomicU64::new(0),
            }),
        }))
    }

    fn linked(&self, module: &str) -> bool {
        !self.answers(module) && self.linked.linked(module)
    }

    fn call_budget(&self) -> Duration {
        self.linked.call_budget()
    }

    fn first_party(&self, module: &str) -> bool {
        !self.answers(module) && self.linked.first_party(module)
    }
}
