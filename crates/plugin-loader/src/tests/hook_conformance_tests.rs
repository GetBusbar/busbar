// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: hook`, BOTH WAYS** (DECISIONS #2 rule (1); #2's witness steps (1)-(5) walked for the hook
//! kind as for auth). Modelled on `export_conformance_tests`: the hook kind's in-tree fixture — reached
//! by KIND through `[package.metadata.busbar.both-ways]`, so no test source names a plugin instance —
//! driven two ways over one script, and the two compared.
//!
//! * [`run_compiled_in`] — the fixture's `rlib`: its `pub fn open`, each request run through the
//!   `dispatch_compiled_in` twin `export_hook_plugin!` emits beside `busbar_call` (the SDK's
//!   `dispatch_hook_enveloped`).
//! * [`run_dropped_in`] — the same crate's `cdylib`, staged and wired by the loader's real load, each
//!   request sent over its `busbar_call` symbol.
//!
//! [`compiled_in_and_dropped_in_reply_byte_identically`] requires the two WIRES to be byte-identical
//! and the host to read the dropped-in one as the envelope. The linked door (the `rlib`'s
//! `BUSBAR_COLD_ENTRY` through [`crate::PluginRegistry::link`]) and the dropped-in door (the `cdylib`
//! signed into `plugins/`) are compared on the registry row and on the routing policy `open_hook`
//! opens: two decisions (an order, a gate reject), two transforms (a rewrite, a reject) and its
//! settings schema.
//!
//! Hooks are a 1.6.0 FUNCTIONAL fixed point: the envelope moves the wire, never a reply. The RED arm
//! [`the_pre_envelope_busbar_call_is_not_the_compiled_in_twin`] replays the wire as it was before the
//! envelope — the real `cdylib` wired, its `busbar_call` answering the SAME handler's replies BARE —
//! and shows the host reads the same replies out of it while the wire is not the twin's.

use super::both_ways::{both_doors, cdylib, hook_fixture as fixture, statement};
use super::*;
use crate::hook::HookProjectors;
use busbar_api::{
    Candidate, RoutingContext, RoutingDecision, RoutingPolicy, RoutingRequest, TransformOutcome,
};
use busbar_plugin::cold::hook::{ConfigureBody, HookReply, HookRequest};
use busbar_plugin::cold::observe::Envelope;
use std::sync::Arc;
use std::time::Duration;

/// The plugin's config: echo the order `[1, 0]`, reject a prompt carrying the screen token.
const CFG: &str = r#"{"order": [1, 0], "reject_if_contains": "BLOCKME"}"#;

/// The prompt's messages, projected as the engine's wire does.
fn messages(req: &RoutingRequest<'_>) -> serde_json::Value {
    serde_json::json!(req.prompt.as_ref().map(|p| {
        p.messages
            .iter()
            .map(|(r, t)| serde_json::json!({"role": r.as_ref(), "text": t.as_ref()}))
            .collect::<Vec<_>>()
    }))
}

/// The value a reply's `reject` member carries, if it has one.
fn reject(v: &serde_json::Value) -> Option<(u16, String)> {
    let r = v.get("reject")?;
    let status = r.get("status").and_then(|s| s.as_u64()).unwrap_or(403) as u16;
    let message = r.get("message").and_then(|m| m.as_str()).unwrap_or("");
    Some((status, message.to_string()))
}

/// Engine-side projectors, the small fail-closed shape `hook_tests` drives the seam with.
fn projectors() -> Arc<HookProjectors> {
    Arc::new(HookProjectors {
        decide: Box::new(|req, cands, _ctx| {
            serde_json::json!({
                "request": {"pool": req.pool, "messages": messages(req)},
                "candidates": cands.iter().map(|c| serde_json::json!({"idx": c.idx})).collect::<Vec<_>>(),
            })
        }),
        transform: Box::new(|req| serde_json::json!({"request": {"messages": messages(req)}})),
        normalize: Box::new(|v, cands| {
            if let Some((status, message)) = reject(&v) {
                return Ok(RoutingDecision::Reject { status, message });
            }
            let Some(order) = v.get("order").and_then(|o| o.as_array()) else {
                return Ok(RoutingDecision::Abstain);
            };
            let valid: std::collections::HashSet<usize> = cands.iter().map(|c| c.idx).collect();
            Ok(RoutingDecision::from_ranked(
                order.iter().filter_map(|x| x.as_u64().map(|x| x as usize)),
                &valid,
            ))
        }),
        transform_outcome: Box::new(|v| {
            if let Some((status, message)) = reject(&v) {
                return TransformOutcome::Reject { status, message };
            }
            match v
                .get("rewrite")
                .and_then(|r| r.get("messages"))
                .and_then(|m| m.as_array())
            {
                Some(msgs) if !msgs.is_empty() => {
                    TransformOutcome::Rewrite(busbar_api::RewriteReply {
                        messages: msgs.clone(),
                        tools: Vec::new(),
                    })
                }
                _ => TransformOutcome::Abstain,
            }
        }),
        status: Box::new(|_| None),
        describe_schema: Box::new(|v| v.get("schema").cloned()),
    })
}

/// A request carrying one user message.
fn request(text: &str) -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "proto-a",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: text.len(),
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: Some(busbar_api::PromptProjection {
            system: None,
            messages: vec![("user".into(), text.to_string().into())],
        }),
        identity: None,
        signals: Default::default(),
    }
}

/// A candidate at `idx`.
fn candidate(idx: usize) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "prov",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
        signals: Default::default(),
    }
}

/// The routing-policy script, driven on a runtime of its own: the policy's name, two decisions, two transforms and
/// the schema it describes.
fn policy_script(policy: &Arc<dyn RoutingPolicy>) -> String {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime for the script");
    let budget = Duration::from_secs(5);
    let cands = [candidate(0), candidate(1)];
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    rt.block_on(async {
        let mut out = vec![format!("name={}", policy.name())];
        for text in ["hello", "please BLOCKME now"] {
            let d = policy.decide(&request(text), &cands, &ctx, budget).await;
            out.push(format!("decide {text:?} -> {d:?}"));
        }
        for text in ["hello", "BLOCKME"] {
            let t = policy.transform(&request(text), budget).await;
            out.push(format!("transform {text:?} -> {t:?}"));
        }
        out.push(format!("describe -> {:?}", policy.describe(budget).await));
        out.join("\n")
    })
}

/// A projected request carrying one user message, as the engine's wire builds it.
fn projected(text: &str) -> serde_json::Value {
    serde_json::json!({
        "request": {"pool": "p", "messages": [{"role": "user", "text": text}]},
        "candidates": [{"idx": 0}, {"idx": 1}],
    })
}

/// The operations both twin arms run, in order: what the host asks at load (routes, the schema), a
/// pushed configuration, two decisions and two transforms (a pass and a screen each), a notify tap,
/// and the status scrape that reports what the handler counted.
fn script() -> Vec<HookRequest> {
    let mut ops = vec![
        HookRequest::Routes,
        HookRequest::Describe,
        HookRequest::Configure(ConfigureBody {
            hook: "the-hook".into(),
            settings: serde_json::Map::new(),
            settings_version: 7,
            busbar_version: "1.6.0".into(),
        }),
    ];
    for text in ["hello", "please BLOCKME now"] {
        ops.push(HookRequest::Decide {
            payload: projected(text),
        });
        ops.push(HookRequest::Transform {
            payload: projected(text),
        });
    }
    ops.push(HookRequest::Notify {
        payload: projected("tap"),
    });
    ops.push(HookRequest::Status);
    ops
}

/// The COMPILED-IN build: the constructor this crate LINKS, each request through the plugin's own
/// `dispatch_compiled_in` — the entry point it publishes beside `busbar_call` — as wire bytes.
fn run_compiled_in() -> Vec<Vec<u8>> {
    let handler = fixture::open(CFG).expect("the compiled-in constructor");
    script()
        .into_iter()
        .map(|req| {
            serde_json::to_vec(&fixture::dispatch_compiled_in(handler.as_ref(), req))
                .expect("encode the compiled-in envelope")
        })
        .collect()
}

/// The hook fixture's `cdylib`, staged and wired by the loader's real load under `display`. `None`
/// when it is not built in this scoped, non-CI run ([`cdylib`] hard-fails under CI).
fn wired(display: &str) -> Option<RawPlugin> {
    let bytes = std::fs::read(cdylib(super::both_ways::fixture("hook").0)?)
        .expect("read the hook fixture's cdylib");
    let (lib, staged) =
        stage::load_library_from_bytes(&bytes, display).expect("stage the hook fixture's cdylib");
    Some(
        wire_up_raw(
            lib,
            CFG,
            display.to_string(),
            busbar_plugin::cold::kind::HOOK,
            busbar_plugin::cold::kind::HOOK,
            Some(staged),
        )
        .expect("wire up the hook fixture"),
    )
}

/// One request over `raw`'s `busbar_call`, and the bytes it answered — the WIRE, before the host reads
/// it. The buffer is handed back to the plugin's own `busbar_free`.
fn wire(raw: &RawPlugin, req: &HookRequest) -> Vec<u8> {
    let payload = serde_json::to_vec(req).expect("encode the request");
    let (mut out, mut out_len): (*mut u8, usize) = (std::ptr::null_mut(), 0);
    // SAFETY: `raw` is a live, wired plugin; the pointers are valid for the call, and the returned
    // buffer is copied before it is handed back to the plugin's own `free`.
    let status = unsafe {
        (raw.call)(
            raw.handle,
            payload.as_ptr(),
            payload.len(),
            &mut out,
            &mut out_len,
        )
    };
    assert_eq!(status, STATUS_OK, "busbar_call answered status {status}");
    let bytes = unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec();
    unsafe { (raw.free)(out, out_len) };
    bytes
}

/// The DROPPED-IN build: the same script over the `cdylib`'s `busbar_call`, as wire bytes.
fn run_dropped_in() -> Option<Vec<Vec<u8>>> {
    let raw = wired("hook-both-ways-dropped-in")?;
    Some(script().iter().map(|req| wire(&raw, req)).collect())
}

/// What `wires` carry as their replies, re-encoded — for comparing against a host's read.
fn replies(wires: &[Vec<u8>]) -> Vec<String> {
    wires
        .iter()
        .map(|w| {
            let e: Envelope<HookReply> = serde_json::from_slice(w).expect("an envelope");
            serde_json::to_string(&e.result).expect("encode")
        })
        .collect()
}

/// The script over a FRESH wiring of the `cdylib` — fresh, because the handler counts decides and
/// taps — twice: once as wire bytes, once as the host's ONE wire seam (`RawPlugin::transport_call`)
/// reads it, with the shape it latched. `pre_envelope` swaps the `busbar_call` for the RED arm's.
fn host_read(display: &str, pre_envelope: bool) -> Option<(Vec<Vec<u8>>, Vec<String>, u8)> {
    let fresh = || -> Option<RawPlugin> {
        let mut raw = wired(display)?;
        if pre_envelope {
            let handler = fixture::open(CFG).expect("the same constructor");
            *PRE_ENVELOPE_DISPATCH
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(Box::new(move |req| {
                fixture::dispatch_compiled_in(handler.as_ref(), req)
            }));
            raw.call = pre_envelope_call;
            raw.free = pre_envelope_free;
        }
        Some(raw)
    };
    let raw = fresh()?;
    let bytes = script().iter().map(|req| wire(&raw, req)).collect();
    let raw = fresh()?;
    let read = script()
        .iter()
        .map(|req| {
            let reply: HookReply = raw.transport_call(req).expect("the host reads the reply");
            serde_json::to_string(&reply).expect("encode")
        })
        .collect();
    let shape = raw.shape.load(std::sync::atomic::Ordering::Relaxed);
    Some((bytes, read, shape))
}

/// **THE EQUIVALENCE.** The hook fixture, compiled in and dropped in, replies to the same script with
/// byte-identical wires, and the host reads the dropped-in wire as the envelope.
#[test]
fn compiled_in_and_dropped_in_reply_byte_identically() {
    // The fixture logs from its constructor into the process-global record log; see `hook_tests`.
    let _guard = crate::observe::testing::exclusive();
    let compiled = run_compiled_in();
    let Some(dropped) = run_dropped_in() else {
        eprintln!("skip: the hook fixture's cdylib is not built");
        return;
    };
    let text = |ws: &[Vec<u8>]| {
        ws.iter()
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        text(&compiled),
        text(&dropped),
        "compiled-in and dropped-in builds of ONE hook crate must put the same bytes on the wire"
    );
    let (_, read, shape) = host_read("hook-both-ways-host-read", false).expect("built above");
    assert_eq!(
        read,
        replies(&compiled),
        "the host reads what the twin replied"
    );
    assert_eq!(
        shape,
        response_shape::ENVELOPE,
        "the host latched the envelope"
    );
    // Not a vacuous pass: the order, the gate's reject, the rewrite, the ack and both counters.
    let all = read.join("\n");
    for needle in [
        "[1,0]",
        "blocked by test gate",
        "rewritten by test gate",
        "ConfigureAck",
        "test_notifies_total",
    ] {
        assert!(all.contains(needle), "{needle} missing from {all}");
    }
}

/// **THE RED ARM — the wire before the envelope, kept as the witness.** The real `cdylib`, loaded and
/// wired, its `busbar_call` replaced by one replying what the SAME handler replies through the twin,
/// but BARE — the shape every hook spoke at payload schema v1. The host reads the same replies out of
/// it (the hook kind's behaviour did not move), and the wire is NOT the twin's: a `busbar_call` that
/// does not run the enveloped dispatch is a different wire from the compiled-in door's, which the
/// equivalence above refuses.
#[test]
fn the_pre_envelope_busbar_call_is_not_the_compiled_in_twin() {
    // The fixture logs from its constructor into the process-global record log; see `hook_tests`.
    let _guard = crate::observe::testing::exclusive();
    let Some((bare, read, shape)) = host_read("hook-both-ways-pre-envelope", true) else {
        eprintln!("skip: the hook fixture's cdylib is not built");
        return;
    };
    let compiled = run_compiled_in();
    assert_eq!(read, replies(&compiled), "the same replies, read");
    assert_eq!(
        shape,
        response_shape::BARE,
        "the host latched the bare shape"
    );
    assert_ne!(
        bare, compiled,
        "a bare busbar_call is a different wire from the compiled-in twin — this inequality is what \
         `compiled_in_and_dropped_in_reply_byte_identically` exists to refuse"
    );
}

/// The pre-envelope `busbar_call`'s dispatch: the twin over ONE handler the linked constructor
/// opened (its counters are part of the replies), set by [`host_read`] before each wiring. The RED
/// arm is its only writer.
type PreEnvelopeDispatch = Box<dyn Fn(HookRequest) -> Envelope<HookReply> + Send + Sync>;
static PRE_ENVELOPE_DISPATCH: std::sync::Mutex<Option<PreEnvelopeDispatch>> =
    std::sync::Mutex::new(None);

/// A `busbar_call` speaking the wire as it was at hook payload schema v1: the twin's reply for the
/// SAME handler, unwrapped. It never touches the `cdylib`'s handle.
unsafe extern "C-unwind" fn pre_envelope_call(
    _handle: *mut std::os::raw::c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let req: HookRequest =
        serde_json::from_slice(std::slice::from_raw_parts(req, req_len)).expect("decode request");
    let envelope = {
        let dispatch = PRE_ENVELOPE_DISPATCH
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        (dispatch
            .as_ref()
            .expect("the RED arm sets the dispatch first"))(req)
    };
    let boxed: Box<[u8]> = serde_json::to_vec(&envelope.result)
        .expect("encode the bare reply")
        .into_boxed_slice();
    *out_len = boxed.len();
    *out = Box::into_raw(boxed) as *mut u8;
    STATUS_OK
}

/// Free a buffer [`pre_envelope_call`] allocated.
unsafe extern "C-unwind" fn pre_envelope_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len != 0 {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

/// **THE AXIS, BOTH WAYS** (#2 rule (1)). The hook fixture linked and dropped in registers the same
/// row and opens a routing policy that decides and transforms the same.
///
/// RED by planting the door bypass the axis replaces — linked rows handed to `link` and never
/// registered — which leaves the linked registry with no row for the name.
#[test]
fn a_linked_and_a_dropped_in_hook_register_byte_identical_rows() {
    // The fixture logs from its constructor into the process-global record log; see `hook_tests`.
    let _guard = crate::observe::testing::exclusive();
    let manifest = statement(
        "hook",
        "hook-fixture",
        "the-hook",
        busbar_plugin::cold::hook::HOOK_ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors(
        manifest,
        |registry| {
            registry
                .open_hook("the-hook", CFG, "the-hook", projectors())
                .expect("the hook opens through its alias")
        },
        policy_script,
    ) else {
        eprintln!("skip: the hook fixture's cdylib is not built");
        return;
    };
    assert!(
        !linked.0.starts_with("no row"),
        "the linked door registered no row: {}",
        linked.0
    );
    assert!(
        linked.1.contains("Prefer([1, 0])") && linked.1.contains("blocked by test gate"),
        "the linked policy ran the script: {}",
        linked.1
    );
    assert_eq!(linked, dropped, "the two doors must register one row");
}
