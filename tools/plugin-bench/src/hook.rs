// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HOOK: `decide` over real requests' views, crossed inline.
//!
//! The view is the kernel's own: a [`RoutingRequest`] projected from an OpenAI chat request (a
//! system prompt, a short earlier exchange, then the user's turn carrying the bulk of the content,
//! 1 KiB / 8 KiB / 100 KiB by default, `--body-sizes`) and three pool members, built by the
//! contract's [`DecideView::build`] into the [`DecideIn`] and answer buffers a [`DecideFrame`]
//! lends. Every thread builds its frame once; each measured op is ONE `decide` crossing
//! ([`Plugin::answer`]) over that frame, with a fresh `request_id`.
//!
//! The instance opens as `HookInstance::open` opens it (the `open` lifecycle call with the hook's
//! settings; a hook has no `ready`). Before any measured call, one probe per request shape goes
//! through the loader's real hook door (`HookInstance::decide` on the dispatcher, a SECOND
//! instance) with a bound child that answers a canned classifier verdict: it proves the shape is
//! one the hook routes on (`Prioritize` for a request within the hook's input bound, `Abstain` for
//! one past it) and records the child payload's size.
//!
//! What the inline crossing cannot carry: a `decide` child call (`hook_child`) is authorised only
//! by a child grant the loader binds to a dispatcher-minted ticket (crate-private), so an inline
//! crossing's child call is refused at once and the hook abstains. The measured op is therefore
//! the FIRST crossing of a real `decide` (decode, the child payload, the host child crossing),
//! which on the real path ends `Pending`; the resume crossing (re-decode, the memoised child
//! answer, its classification and the verdict) is not measured.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use busbar_contract::abi::hook::{slot, DecideIn, DecideOut, VERB_ABSTAIN, VERB_PRIORITIZE};
use busbar_contract::abi::host::hook::{DecideFrame, DecideView};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::hook_calls::{Answered, HookCalls};
use busbar_contract::hooks::{Candidate, PromptProjection, RoutingContext, RoutingRequest};
use busbar_contract::json::{self, json, Value};
use busbar_contract::services::{Caller, HookChildInvocation, Later, Ran, Stored};
use busbar_contract::signal::{Signal, SignalBag, SignalValue};
use busbar_plugin_loader::dispatch::kinds::hook::Hook;
use busbar_plugin_loader::dispatch::{ConnTable, Dispatcher, Frame, Plugin};
use busbar_plugin_loader::hook_door::HookInstance;

use crate::frames::{input, json as json_blob, output};
use crate::stats::Recorder;
use crate::{Config, Scenario, Spec, Target};

const POOL: &str = "bench";
/// The pool's members: (model, provider). The default tiers name them as their candidates.
const MEMBERS: [(&str, &str); 3] = [("small", "oai"), ("mid", "oai"), ("large", "ant")];
/// The classifier's canned answer in the probe: the `hard` tier, above the confidence bar.
const CLASSIFIED: &[u8] =
    br#"{"version":1,"label":"hard","confidence":0.9,"source":"jev","schema":"jev-choice-v1"}"#;
/// The member the `hard` tier prioritises (its index in [`MEMBERS`]).
const HARD: u32 = 2;

struct Opened {
    plugin: Plugin<Hook>,
    _d: Arc<Dispatcher>,
}

// SAFETY: one opened hook instance is shared by the bench threads as core shares it between the
// requests it decides; every measured op is a `Plugin::answer` on it.
unsafe impl Sync for Opened {}
unsafe impl Send for Opened {}

/// A three-tier complexity classification over the pool's members, history of two turns.
fn default_settings() -> Value {
    json!({
        "classifier_model": "classifier",
        "previous_messages": 2,
        "min_confidence": 0.7,
        "tiers": [
            {"label": "easy", "description": "Short factual lookups, greetings and simple rewrites.",
             "examples": ["What is the capital of France?"], "candidates": ["small"]},
            {"label": "medium", "description": "Summaries, explanations and routine code edits.",
             "examples": ["Summarise this paragraph in two sentences."], "candidates": ["mid"]},
            {"label": "hard", "description": "Multi-step reasoning, design and long-document analysis.",
             "examples": ["Find the race in this concurrent queue."], "candidates": ["large"]}
        ]
    })
}

fn settings(cfg: &Config) -> Result<Vec<u8>, String> {
    match &cfg.settings {
        Some(s) => Ok(s.clone()),
        None => json::to_vec(&default_settings()).map_err(|e| e.to_string()),
    }
}

/// Load and open one instance, as `HookInstance::open` opens it.
fn open_inline(target: &Target, settings: &[u8]) -> Result<Arc<Opened>, String> {
    let d = crate::dispatcher();
    let plugin = crate::load::<Hook>(target, crate::bind(&d, "bench-hook", ConnTable::NoNeeds))?;
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    (f.input.generation, f.input.settings) = (1, json_blob(settings));
    let called = plugin.answer(life::OPEN, &mut f);
    if called.outcome != Outcome::Ready {
        return Err(format!(
            "hook open answered {:?}: {}",
            called.outcome,
            String::from_utf8_lossy(called.error.as_deref().unwrap_or_default())
        ));
    }
    Ok(Arc::new(Opened { plugin, _d: d }))
}

/// The classifier child of the probe: the canned verdict, counted, its payload size kept.
#[derive(Debug, Default)]
struct Child {
    calls: AtomicUsize,
    payload: AtomicUsize,
}

impl HookChildInvocation for Child {
    fn request(&self, _: &Caller, payload: Vec<u8>, _: Later) -> Ran {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.payload.store(payload.len(), Ordering::Relaxed);
        if crate::report::verbose() {
            eprintln!(
                "[hook child] payload {} bytes: {}",
                payload.len(),
                String::from_utf8_lossy(&payload[..payload.len().min(300)])
            );
        }
        let mut answer = Stored::ready(200);
        answer.bytes = CLASSIFIED.to_vec();
        Ran::Now(answer)
    }
}

/// One request shape through the loader's real hook door: its verdict, and the child's payload
/// size (`None` when the hook never asked its classifier).
fn probe(target: &Target, settings: &[u8], req: &Request) -> Result<(u32, Option<usize>), String> {
    let d = crate::dispatcher();
    let plugin = crate::load::<Hook>(
        target,
        crate::bind(&d, "bench-hook-probe", ConnTable::NoNeeds),
    )?;
    let hook = HookInstance::open(plugin, d, settings, || Err("no rebind in the probe".into()))
        .map_err(|e| format!("hook open (probe): {e}"))?;
    let child = Arc::new(Child::default());
    let frame = req.frame().with_child(Some(child.clone()));
    let answered = crate::block(hook.decide(frame, std::time::Duration::from_secs(10)));
    match answered {
        Answered::Answer {
            outcome: Outcome::Ready,
            out,
            frame,
            ..
        } => {
            if out.verbs == VERB_PRIORITIZE && frame.order(out.order_written) != [HARD as usize] {
                return Err(format!(
                    "the probe's decide prioritised {:?}, not the hard tier's member",
                    frame.order(out.order_written)
                ));
            }
            let calls = child.calls.load(Ordering::Relaxed);
            Ok((
                out.verbs,
                (calls > 0).then(|| child.payload.load(Ordering::Relaxed)),
            ))
        }
        other => Err(format!("the probe's decide did not answer: {other:?}")),
    }
}

/// Text of about `n` bytes: prose lines with the odd quoted phrase, as prompts carry.
fn prose(n: usize) -> String {
    const LINE: &str = "Please review the function below and explain, step by step, why the \
                        \"retry\" loop never exits when the server answers 503.\n";
    LINE.chars().cycle().take(n).collect()
}

/// One OpenAI chat request's projection, owned: what the plane's `project` hands the kernel.
struct Request {
    system: String,
    messages: Vec<(String, String)>,
    signals: SignalBag,
    total_chars: usize,
}

impl Request {
    fn chat(content: usize) -> Self {
        let system = "You are a careful senior engineer. Answer precisely.".to_string();
        let earlier = vec![
            (
                "user".to_string(),
                "I have a flaky integration test.".to_string(),
            ),
            (
                "assistant".to_string(),
                "Share the code and the failing output and I will take a look.".to_string(),
            ),
        ];
        let used: usize = system.len() + earlier.iter().map(|(_, t)| t.len()).sum::<usize>();
        let mut messages = earlier;
        messages.push((
            "user".to_string(),
            prose(content.saturating_sub(used).max(1)),
        ));
        let total_chars = system.chars().count()
            + messages
                .iter()
                .map(|(_, t)| t.chars().count())
                .sum::<usize>();
        let mut signals = SignalBag::new();
        signals.push(Signal::RequestedModel, SignalValue::Str("auto".into()));
        signals.push(
            Signal::RequestTotalChars,
            SignalValue::U64(total_chars as u64),
        );
        signals.push(
            Signal::RequestMessageCount,
            SignalValue::U64(messages.len() as u64 + 1),
        );
        signals.push(Signal::RequestTextComplete, SignalValue::Bool(true));
        Self {
            system,
            messages,
            signals,
            total_chars,
        }
    }

    /// The kernel's view and the frame lending it, built as the router builds them.
    fn frame(&self) -> Arc<DecideFrame> {
        let req = RoutingRequest {
            request_id: 1,
            pool: POOL,
            ingress_protocol: "openai",
            requested_model: Some("auto"),
            message_count: self.messages.len() + 1,
            tool_count: 0,
            has_tools: false,
            total_chars: self.total_chars,
            system_chars: self.system.chars().count(),
            max_tokens: Some(1024),
            stream: false,
            prompt: Some(PromptProjection {
                system: Some(self.system.as_str().into()),
                messages: self
                    .messages
                    .iter()
                    .map(|(r, t)| (r.as_str().into(), t.as_str().into()))
                    .collect(),
            }),
            identity: None,
            signals: self.signals.clone(),
            session: None,
        };
        let candidates: Vec<Candidate<'_>> = MEMBERS
            .iter()
            .enumerate()
            .map(|(idx, &(model, provider))| Candidate {
                idx,
                model,
                provider,
                weight: 1,
                context_max: Some(200_000),
                tier: None,
                cost_per_mtok: Some([0.15, 1.0, 15.0][idx]),
                tags: &[],
                latency_ms: Some([180.0, 420.0, 900.0][idx]),
                available_concurrency: 64,
                budget_remaining: None,
                rate_headroom: None,
                signals: SignalBag::new(),
            })
            .collect();
        let ctx = RoutingContext {
            pool: POOL,
            budget_remaining: None,
            budget: &[],
        };
        DecideFrame::first(DecideView::build(&req, &candidates, &ctx))
    }
}

pub(crate) fn specs(cfg: &Config, target: &Target) -> Result<Vec<Spec>, String> {
    let settings = settings(cfg)?;
    let opened = open_inline(target, &settings)?;
    let mut specs = Vec::new();
    for &size in &cfg.body_sizes {
        let (verbs, payload) = probe(target, &settings, &Request::chat(size))?;
        if crate::report::verbose() || verbs != VERB_PRIORITIZE {
            eprintln!(
                "[hook probe {}] the real door answers verbs={verbs:#x}, classifier payload {}",
                size_label(size),
                payload.map_or("never sent".into(), |n| format!("{n} bytes"))
            );
        }
        let o = opened.clone();
        specs.push(Spec {
            name: format!("hook.decide openai {}", size_label(size)),
            ops: vec!["decide"],
            primary: 0,
            make: Box::new(move |t| {
                Ok(Box::new(Decide::new(o.clone(), t, size)?) as Box<dyn Scenario>)
            }),
        });
    }
    Ok(specs)
}

fn size_label(n: usize) -> String {
    if n.is_multiple_of(1024) {
        format!("{}KiB", n / 1024)
    } else {
        format!("{n}B")
    }
}

/// One thread's `decide`: the view and its answer buffers built once, reused by every call.
struct Decide {
    opened: Arc<Opened>,
    /// Owns everything `base` points at.
    _frame: Arc<DecideFrame>,
    base: DecideIn,
    next_request: u64,
}

impl Decide {
    fn new(opened: Arc<Opened>, thread: usize, size: usize) -> Result<Self, String> {
        let frame = Request::chat(size).frame();
        let base = frame.input();
        let mut x = Self {
            opened,
            _frame: frame,
            base,
            next_request: ((thread as u64 + 1) << 40) + 1,
        };
        // One unwarmed call, unmeasured, proves the plugin serves this shape.
        let mut probe = Recorder::new(1, 0, u64::MAX, std::time::Instant::now(), 1, false);
        x.unit(&mut probe)
            .map_err(|e| format!("first decide (unmeasured): {e}"))?;
        Ok(x)
    }
}

impl Scenario for Decide {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let mut i = self.base;
        i.request.request_id = self.next_request;
        self.next_request += 1;
        let mut f: Frame<DecideIn, DecideOut> = Frame::new(i, output());
        let plugin = &self.opened.plugin;
        let called = rec.time(0, || plugin.answer(slot::DECIDE, &mut f));
        // Inline, the child call has no grant, so the classifying hook abstains; any other answer
        // (a fault, a pend, an order without its classifier) is not the path being measured.
        if called.outcome != Outcome::Ready || f.out.verbs != VERB_ABSTAIN {
            return Err(format!(
                "decide answered {:?} verbs={:#x} order_written={} faulted={}: {}",
                called.outcome,
                f.out.verbs,
                f.out.order_written,
                plugin.is_faulted(),
                String::from_utf8_lossy(called.error.as_deref().unwrap_or_default())
            ));
        }
        Ok(())
    }
}
