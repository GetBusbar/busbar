// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `sampling/createMessage`, SATISFIED — the plane's satisfier over a scripted host: the input
//! bounds on the translation alone, the per-upstream budget's window, and the whole ask driven
//! through its claims and nested completions, PENDING included. What left the plane is read off the
//! fake host's own transcript, because what busbar spent is a claim about bytes a completion server
//! received.

use std::collections::{BTreeMap, VecDeque};
use std::task::Poll;

use serde_json::{json, Value};

use super::*;
use crate::tools_config::{
    DEFAULT_MAX_SAMPLING_MESSAGES, DEFAULT_MAX_SAMPLING_PROMPT_BYTES, DEFAULT_MAX_STOP_SEQUENCES,
    DEFAULT_MAX_STOP_SEQUENCE_BYTES, DEFAULT_TEMPERATURE_MAX_MILLI, DEFAULT_TEMPERATURE_MIN_MILLI,
};

const SERVER: &str = "fs";

/// The model the OPERATOR declares. The completion must run here and nowhere the upstream names.
const MODEL: &str = "sampler-model";

/// The policy under test — every field explicit, so a case that means to move ONE bound never
/// accidentally rides on another's default. `200..=1500` thousandths is `0.2..=1.5`.
fn cfg() -> SamplingCfg {
    SamplingCfg {
        model: MODEL.to_string(),
        max_tokens: 64,
        max_requests_per_minute: 100,
        max_messages: 3,
        max_prompt_bytes: 32,
        max_stop_sequences: 2,
        max_stop_sequence_bytes: 8,
        temperature_min_milli: 200,
        temperature_max_milli: 1500,
    }
}

/// The operator's policy with the shipped defaults on the input bounds and `per_minute` on the
/// budget.
fn declared(per_minute: u32) -> SamplingCfg {
    SamplingCfg {
        model: MODEL.to_string(),
        max_tokens: 64,
        max_requests_per_minute: per_minute,
        max_messages: DEFAULT_MAX_SAMPLING_MESSAGES,
        max_prompt_bytes: DEFAULT_MAX_SAMPLING_PROMPT_BYTES,
        max_stop_sequences: DEFAULT_MAX_STOP_SEQUENCES,
        max_stop_sequence_bytes: DEFAULT_MAX_STOP_SEQUENCE_BYTES,
        temperature_min_milli: DEFAULT_TEMPERATURE_MIN_MILLI,
        temperature_max_milli: DEFAULT_TEMPERATURE_MAX_MILLI,
    }
}

// ---------------------------------------------------------------------------------------------
// THE INPUT-SIDE BOUNDS (owner ruling Q22c / Q35), on the translation alone
// ---------------------------------------------------------------------------------------------

/// `n` user messages of EMPTY text — free on the prompt-bytes bound, so a message-count case never
/// trips it first.
fn messages(n: usize) -> Value {
    let msgs: Vec<Value> = (0..n)
        .map(|_| json!({ "role": "user", "content": { "type": "text", "text": "" } }))
        .collect();
    json!({ "messages": msgs })
}

#[test]
fn one_message_over_the_configured_cap_is_refused_naming_the_key() {
    let c = cfg();
    let params = messages(c.max_messages as usize + 1);
    let err = sampling_chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_messages"),
        "the refusal names the exact key an operator would edit: {err}"
    );
    assert!(err.contains("4 messages"), "{err}");
}

#[test]
fn exactly_the_configured_cap_of_messages_is_allowed() {
    let c = cfg();
    let params = messages(c.max_messages as usize);
    sampling_chat_body(Some(&params), &c, SERVER)
        .expect("exactly the cap is conformant, not a refusal");
}

#[test]
fn the_shipped_default_bounds_message_count_when_the_key_is_omitted() {
    let c = SamplingCfg {
        max_messages: DEFAULT_MAX_SAMPLING_MESSAGES,
        ..cfg()
    };
    let over = messages(DEFAULT_MAX_SAMPLING_MESSAGES as usize + 1);
    let err = sampling_chat_body(Some(&over), &c, SERVER).unwrap_err();
    assert!(err.contains("tools.fs.sampling.max_messages"), "{err}");
    let at = messages(DEFAULT_MAX_SAMPLING_MESSAGES as usize);
    sampling_chat_body(Some(&at), &c, SERVER)
        .expect("the default ceiling admits exactly the default");
}

#[test]
fn a_system_prompt_over_the_configured_byte_cap_is_refused_naming_the_key() {
    let c = cfg();
    let params = json!({ "systemPrompt": "x".repeat(c.max_prompt_bytes as usize + 1) });
    let err = sampling_chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_prompt_bytes"),
        "the refusal names the exact key an operator would edit: {err}"
    );
}

#[test]
fn message_text_that_pushes_the_running_total_over_the_byte_cap_is_refused() {
    let c = cfg();
    let params = json!({
        "messages": [
            { "role": "user", "content": { "type": "text", "text": "x".repeat(c.max_prompt_bytes as usize + 1) } },
        ]
    });
    let err = sampling_chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(err.contains("tools.fs.sampling.max_prompt_bytes"), "{err}");
}

#[test]
fn exactly_the_configured_byte_cap_is_allowed() {
    let c = cfg();
    let params = json!({
        "messages": [
            { "role": "user", "content": { "type": "text", "text": "x".repeat(c.max_prompt_bytes as usize) } },
        ]
    });
    sampling_chat_body(Some(&params), &c, SERVER)
        .expect("exactly the cap is conformant, not a refusal");
}

#[test]
fn the_shipped_default_bounds_prompt_bytes_when_the_key_is_omitted() {
    let c = SamplingCfg {
        max_prompt_bytes: DEFAULT_MAX_SAMPLING_PROMPT_BYTES,
        ..cfg()
    };
    let over =
        json!({ "systemPrompt": "x".repeat(DEFAULT_MAX_SAMPLING_PROMPT_BYTES as usize + 1) });
    let err = sampling_chat_body(Some(&over), &c, SERVER).unwrap_err();
    assert!(err.contains("tools.fs.sampling.max_prompt_bytes"), "{err}");
    let at = json!({ "systemPrompt": "x".repeat(DEFAULT_MAX_SAMPLING_PROMPT_BYTES as usize) });
    sampling_chat_body(Some(&at), &c, SERVER)
        .expect("the default ceiling admits exactly the default");
}

fn params_with_stop(stop: Vec<&str>) -> Value {
    json!({
        "messages": [{ "role": "user", "content": { "type": "text", "text": "hi" } }],
        "stopSequences": stop,
    })
}

#[test]
fn one_stop_sequence_over_the_configured_count_cap_is_refused_naming_the_key() {
    let params = params_with_stop(vec!["a", "b", "c"]);
    let err = sampling_chat_body(Some(&params), &cfg(), SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_stop_sequences"),
        "the refusal names the exact key an operator would edit: {err}"
    );
}

#[test]
fn exactly_the_configured_stop_sequence_count_cap_is_allowed() {
    let params = params_with_stop(vec!["a", "b"]);
    sampling_chat_body(Some(&params), &cfg(), SERVER)
        .expect("exactly the cap is conformant, not a refusal");
}

#[test]
fn the_shipped_default_bounds_stop_sequence_count_when_the_key_is_omitted() {
    let c = SamplingCfg {
        max_stop_sequences: DEFAULT_MAX_STOP_SEQUENCES,
        ..cfg()
    };
    let stop: Vec<String> = (0..=DEFAULT_MAX_STOP_SEQUENCES)
        .map(|i| format!("s{i}"))
        .collect();
    let over = json!({
        "messages": [{ "role": "user", "content": { "type": "text", "text": "hi" } }],
        "stopSequences": stop,
    });
    let err = sampling_chat_body(Some(&over), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_stop_sequences"),
        "{err}"
    );
}

#[test]
fn one_stop_sequence_longer_than_the_configured_byte_cap_is_refused_naming_the_key() {
    let c = cfg();
    let long = "x".repeat(c.max_stop_sequence_bytes as usize + 1);
    let params = params_with_stop(vec![long.as_str()]);
    let err = sampling_chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_stop_sequence_bytes"),
        "the refusal names the exact key an operator would edit: {err}"
    );
}

#[test]
fn a_stop_sequence_exactly_at_the_configured_byte_cap_is_allowed() {
    let c = cfg();
    let at = "x".repeat(c.max_stop_sequence_bytes as usize);
    let params = params_with_stop(vec![at.as_str()]);
    sampling_chat_body(Some(&params), &c, SERVER)
        .expect("exactly the cap is conformant, not a refusal");
}

#[test]
fn the_shipped_default_bounds_stop_sequence_length_when_the_key_is_omitted() {
    let c = SamplingCfg {
        max_stop_sequence_bytes: DEFAULT_MAX_STOP_SEQUENCE_BYTES,
        max_stop_sequences: DEFAULT_MAX_STOP_SEQUENCES,
        ..cfg()
    };
    let long = "x".repeat(DEFAULT_MAX_STOP_SEQUENCE_BYTES as usize + 1);
    let params = params_with_stop(vec![long.as_str()]);
    let err = sampling_chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.max_stop_sequence_bytes"),
        "{err}"
    );
}

fn params_with_temperature(t: f64) -> Value {
    json!({
        "messages": [{ "role": "user", "content": { "type": "text", "text": "hi" } }],
        "temperature": t,
    })
}

#[test]
fn a_temperature_below_the_configured_minimum_is_refused_naming_the_key() {
    let c = cfg();
    let params = params_with_temperature(c.temperature_min() - 0.1);
    let err = sampling_chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.temperature_min_milli")
            && err.contains("tools.fs.sampling.temperature_max_milli"),
        "the refusal names both keys of the range an operator would edit: {err}"
    );
}

#[test]
fn a_temperature_exactly_at_the_configured_minimum_is_allowed() {
    let c = cfg();
    let params = params_with_temperature(c.temperature_min());
    sampling_chat_body(Some(&params), &c, SERVER)
        .expect("exactly the floor is conformant, not a refusal");
}

#[test]
fn a_temperature_above_the_configured_maximum_is_refused_naming_the_key() {
    let c = cfg();
    let params = params_with_temperature(c.temperature_max() + 0.1);
    let err = sampling_chat_body(Some(&params), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.temperature_min_milli")
            && err.contains("tools.fs.sampling.temperature_max_milli"),
        "the refusal names both keys of the range an operator would edit: {err}"
    );
}

#[test]
fn a_temperature_exactly_at_the_configured_maximum_is_allowed() {
    let c = cfg();
    let params = params_with_temperature(c.temperature_max());
    sampling_chat_body(Some(&params), &c, SERVER)
        .expect("exactly the ceiling is conformant, not a refusal");
}

#[test]
fn the_shipped_default_range_is_the_protocols_own_zero_to_two() {
    let c = SamplingCfg {
        temperature_min_milli: DEFAULT_TEMPERATURE_MIN_MILLI,
        temperature_max_milli: DEFAULT_TEMPERATURE_MAX_MILLI,
        ..cfg()
    };
    let over = params_with_temperature(c.temperature_max() + 0.1);
    let err = sampling_chat_body(Some(&over), &c, SERVER).unwrap_err();
    assert!(
        err.contains("tools.fs.sampling.temperature_max_milli"),
        "{err}"
    );
    sampling_chat_body(
        Some(&params_with_temperature(c.temperature_min())),
        &c,
        SERVER,
    )
    .expect("the default floor is admitted");
    sampling_chat_body(
        Some(&params_with_temperature(c.temperature_max())),
        &c,
        SERVER,
    )
    .expect("the default ceiling is admitted");
}

// ---------------------------------------------------------------------------------------------
// THE PER-UPSTREAM BUDGET's local window
// ---------------------------------------------------------------------------------------------

#[test]
fn the_cap_admits_exactly_cap_completions_in_one_window_and_refuses_the_next() {
    let mut window = (0, 0);
    let now = 1_000_000;
    for slot in 0..3 {
        assert_eq!(
            reserve_sample_slot(&mut window, "fs", 3, now),
            Ok(slot),
            "under the cap, the spend is admitted, slot by slot"
        );
    }
    let err = reserve_sample_slot(&mut window, "fs", 3, now)
        .expect_err("the cap is a refusal, not a warning");
    assert!(
        err.contains("tools.fs.sampling.max_requests_per_minute"),
        "the refusal names the exact key an operator would raise: {err}"
    );
    assert_eq!(err, sampling_exhausted("fs", 3));
    assert!(err.starts_with(
        "the per-upstream sampling budget is exhausted: server `fs` has already induced 3 \
         completion(s) this minute"
    ));
}

#[test]
fn the_window_resets_on_the_next_minute() {
    let mut window = (0, 0);
    let now = 1_000_000;
    reserve_sample_slot(&mut window, "fs", 1, now).expect("the first is admitted");
    reserve_sample_slot(&mut window, "fs", 1, now)
        .expect_err("the second in the same minute is refused");
    assert_eq!(
        reserve_sample_slot(&mut window, "fs", 1, now + 60),
        Ok(0),
        "the budget is per minute, and the next minute is a fresh window"
    );
}

#[test]
fn a_slot_is_claimed_under_its_server_and_minute() {
    assert_eq!(sample_slot_key("fs", 1_000_000, 2), "sampling/fs/16666/2");
    assert_ne!(
        sample_slot_key("fs", 1_000_000, 0),
        sample_slot_key("search", 1_000_000, 0),
        "the budget is PER UPSTREAM: one server's slot is not another's"
    );
}

// ---------------------------------------------------------------------------------------------
// THE SATISFIER, driven over a scripted host
// ---------------------------------------------------------------------------------------------

/// A host whose answers are scripted and whose calls are recorded. A claim or completion with no
/// script left is WON / answered with [`completion`].
#[derive(Default)]
struct Scripted {
    now: u64,
    windows: BTreeMap<String, SampleWindow>,
    claims: VecDeque<Poll<SlotClaim>>,
    completions: VecDeque<Poll<Completion>>,
    /// Every claim issued: its number and key.
    claimed: Vec<(u32, String)>,
    /// Every completion issued: its number and body.
    completed: Vec<(u32, Value)>,
    clock_reads: u32,
}

impl SampleHost for Scripted {
    fn now_secs(&mut self, _seq: u32) -> u64 {
        self.clock_reads += 1;
        self.now
    }

    fn reserve(&mut self, server: &str, cap: u32, now: u64) -> Result<u32, String> {
        let window = self
            .windows
            .entry(server.to_string())
            .or_insert((now / 60, 0));
        reserve_sample_slot(window, server, cap, now)
    }

    fn claim(&mut self, seq: u32, key: &str, _ttl_ms: u64) -> Poll<SlotClaim> {
        self.claimed.push((seq, key.to_string()));
        self.claims
            .pop_front()
            .unwrap_or(Poll::Ready(SlotClaim::Won))
    }

    fn complete(&mut self, seq: u32, body: &[u8]) -> Poll<Completion> {
        self.completed
            .push((seq, serde_json::from_slice(body).expect("the body is JSON")));
        self.completions
            .pop_front()
            .unwrap_or_else(|| Poll::Ready(completion("One-line summary.")))
    }
}

/// One chat completion the completion server answers, with a DIFFERENT model string than the
/// operator declared, so the test can tell "relayed from the reply" apart from "copied from config".
fn completion(text: &str) -> Completion {
    Completion::Answered {
        status: 200,
        body: serde_json::to_vec(&json!({
            "id": "cmpl-1",
            "object": "chat.completion",
            "model": "sampler-model-v2",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": text },
                "finish_reason": "stop",
            }],
            "usage": { "prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17 },
        }))
        .expect("json"),
    }
}

/// The upstream's input-required result: one `draft` entry asking for a completion.
fn ask() -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {
            "draft": {
                "method": "sampling/createMessage",
                "params": {
                    "systemPrompt": "You are terse.",
                    "messages": [{ "role": "user", "content": { "type": "text", "text": "Draft a one-line summary of the diff." } }],
                    "maxTokens": 4096,
                    "modelPreferences": { "hints": [{ "name": "the-most-expensive-model" }] },
                },
            },
        },
        "requestState": "upstream-opaque-state-blob",
    })
}

/// A two-entry ask: `draft`, then `title`.
fn ask_pair() -> Value {
    let entry = |text: &str| {
        json!({
            "method": "sampling/createMessage",
            "params": { "messages": [{ "role": "user", "content": { "type": "text", "text": text } }] },
        })
    };
    json!({
        "resultType": "input_required",
        "inputRequests": { "draft": entry("Draft it."), "title": entry("Title it.") },
        "requestState": "s",
    })
}

/// Drive `run` once to a Ready answer.
fn ready(
    run: &mut SampleRun,
    cfg: Option<&SamplingCfg>,
    host: &mut Scripted,
) -> Result<Value, String> {
    match run.drive(SERVER, cfg, host) {
        Poll::Ready(answer) => answer,
        Poll::Pending => panic!("the run pended with nothing scripted to pend"),
    }
}

/// THE CELL. A granted, declared ask is satisfied: one completion runs on the operator's model
/// within the operator's ceilings, and the answer is MRTR's continuation members carrying the
/// protocol's `CreateMessageResult` under the upstream's own `requestState`.
#[test]
fn a_granted_sampling_ask_is_completed_on_the_operators_model_and_answered() {
    let mut host = Scripted {
        now: 1_000_000,
        ..Scripted::default()
    };
    let policy = declared(5);
    let continuation = ready(&mut SampleRun::new(ask()), Some(&policy), &mut host)
        .expect("the granted, declared ask is satisfied");

    assert_eq!(host.completed.len(), 1, "one entry, one completion");
    let spent = &host.completed[0].1;
    assert_eq!(
        spent.get("model").and_then(Value::as_str),
        Some(MODEL),
        "the completion runs on the operator's declared model, never one the upstream named: \
         {spent}"
    );
    assert_eq!(
        spent.get("max_tokens").and_then(Value::as_u64),
        Some(64),
        "the ask's maxTokens is clamped to the operator's ceiling: {spent}"
    );
    assert_eq!(spent.pointer("/messages/0/role"), Some(&json!("system")));
    assert_eq!(
        spent.pointer("/messages/1/content"),
        Some(&json!("Draft a one-line summary of the diff.")),
        "the ask's message is what the model was asked: {spent}"
    );
    assert_eq!(
        continuation,
        json!({
            "inputResponses": {
                "draft": {
                    "role": "assistant",
                    "content": { "type": "text", "text": "One-line summary." },
                    "model": "sampler-model-v2",
                    "stopReason": "endTurn",
                },
            },
            "requestState": "upstream-opaque-state-blob",
        }),
        "the answer relays what the completion actually said, under the upstream's own state"
    );
    // The budget was spent on the ledger BEFORE the model leg, under the server's minute.
    assert_eq!(host.claimed.len(), 1);
    assert_eq!(host.claimed[0].1, "sampling/fs/16666/0");
    assert!(
        host.claimed[0].0 < host.completed[0].0,
        "the slot is claimed before the completion runs"
    );
    assert_eq!(host.clock_reads, 1, "one ask is judged at one instant");
}

/// THE PER-UPSTREAM BUDGET. A two-entry ask against a budget of one: the first entry's completion
/// runs, the second is refused naming the budget key — and the completion server was reached
/// EXACTLY once, because the budget is spent before the model leg.
#[test]
fn the_per_upstream_budget_refuses_the_completion_past_the_cap_before_it_runs() {
    let mut host = Scripted {
        now: 1_000_000,
        ..Scripted::default()
    };
    let err = ready(
        &mut SampleRun::new(ask_pair()),
        Some(&declared(1)),
        &mut host,
    )
    .expect_err("the exhausted budget must refuse");
    assert_eq!(err, sampling_exhausted(SERVER, 1));
    assert!(
        err.contains("tools.fs.sampling.max_requests_per_minute"),
        "{err}"
    );
    assert_eq!(
        host.completed.len(),
        1,
        "the completion past the cap never ran"
    );
    assert_eq!(
        host.completed[0].1.pointer("/messages/0/content"),
        Some(&json!("Draft it.")),
        "entries are answered in order, and only the first reached a completion server"
    );
}

/// THE GRANT ALONE SPENDS NOTHING. No policy is the unsatisfiable answer naming the exact key, and
/// neither the budget nor a completion server is touched.
#[test]
fn a_granted_ask_with_no_policy_refuses_and_names_the_key() {
    let mut host = Scripted::default();
    let err = ready(&mut SampleRun::new(ask()), None, &mut host)
        .expect_err("a grant with no policy must refuse");
    assert!(
        err.contains("`tools.fs.sampling`"),
        "the message is the remedy: {err}"
    );
    assert!(
        err.contains("no `tools.fs.sampling` policy is declared"),
        "{err}"
    );
    assert!(host.claimed.is_empty() && host.completed.is_empty());
    assert!(host.windows.is_empty(), "nothing was spent");
}

/// Busbar's own pipeline refusing the completion (the caller's key does not reach the pool, the
/// caller's budget is spent) is relayed by its reason.
#[test]
fn a_completion_refused_by_busbars_own_pipeline_is_relayed_by_its_reason() {
    let mut host = Scripted {
        completions: VecDeque::from([Poll::Ready(Completion::Answered {
            status: 403,
            body: br#"{"error":{"message":"key may not use pool `sampler-model`"}}"#.to_vec(),
        })]),
        ..Scripted::default()
    };
    let err = ready(&mut SampleRun::new(ask()), Some(&declared(5)), &mut host).unwrap_err();
    assert_eq!(
        err,
        "the sampling completion was refused by busbar's own pipeline (HTTP 403): key may not \
         use pool `sampler-model`"
    );
}

#[test]
fn a_completion_with_a_body_that_is_not_json_or_no_text_is_refused() {
    let mut host = Scripted {
        completions: VecDeque::from([Poll::Ready(Completion::Answered {
            status: 502,
            body: b"bad gateway".to_vec(),
        })]),
        ..Scripted::default()
    };
    let err = ready(&mut SampleRun::new(ask()), Some(&declared(5)), &mut host).unwrap_err();
    assert_eq!(
        err,
        "the sampling completion answered HTTP 502 and a body that is not JSON"
    );
    let mut host = Scripted {
        completions: VecDeque::from([Poll::Ready(Completion::Answered {
            status: 200,
            body: br#"{"choices":[]}"#.to_vec(),
        })]),
        ..Scripted::default()
    };
    let err = ready(&mut SampleRun::new(ask()), Some(&declared(5)), &mut host).unwrap_err();
    assert_eq!(
        err,
        "the sampling completion carried no assistant text to relay"
    );
}

/// Nothing serves the completion's claim: the words a deployment with no completion server has
/// always been refused in.
#[test]
fn an_unserved_completion_answers_the_no_server_refusal() {
    let mut host = Scripted {
        completions: VecDeque::from([Poll::Ready(Completion::Unserved)]),
        ..Scripted::default()
    };
    let err = ready(&mut SampleRun::new(ask()), Some(&declared(5)), &mut host).unwrap_err();
    assert_eq!(err, NO_COMPLETION_SERVER);
    assert_eq!(err, "no default chat protocol is installed");
}

#[test]
fn the_stop_reason_is_mapped_into_the_protocols_vocabulary() {
    for (finish, stop) in [
        ("stop", "endTurn"),
        ("length", "maxTokens"),
        ("stop_sequence", "stopSequence"),
        ("content_filter", "content_filter"),
    ] {
        let done = Completion::Answered {
            status: 200,
            body: serde_json::to_vec(&json!({
                "choices": [{ "message": { "content": "x" }, "finish_reason": finish }],
            }))
            .expect("json"),
        };
        let result = sampling_result(done, &declared(5)).expect("a result");
        assert_eq!(result["stopReason"], json!(stop), "{finish}");
        assert_eq!(
            result["model"],
            json!(MODEL),
            "a reply naming no model reads as the declared one"
        );
    }
}

/// A mixed map is refused rather than partially answered, and before anything is spent on it.
#[test]
fn an_ask_mixing_another_method_is_refused_naming_the_entry() {
    let mut payload = ask();
    payload["inputRequests"]["confirm"] = json!({ "method": "elicitation/create" });
    let mut host = Scripted::default();
    let err = ready(&mut SampleRun::new(payload), Some(&declared(5)), &mut host).unwrap_err();
    assert_eq!(
        err,
        "the upstream's ask mixes `sampling/createMessage` with a method busbar has no satisfier \
         for; the ask terminates here (entry `confirm`)"
    );
    assert!(host.completed.is_empty());
}

#[test]
fn an_ask_with_no_or_empty_input_requests_is_refused() {
    let mut host = Scripted::default();
    let err = ready(
        &mut SampleRun::new(json!({ "requestState": "s" })),
        Some(&declared(5)),
        &mut host,
    )
    .unwrap_err();
    assert!(err.contains("names no `inputRequests` entry"), "{err}");
    let err = ready(
        &mut SampleRun::new(json!({ "inputRequests": {} })),
        Some(&declared(5)),
        &mut host,
    )
    .unwrap_err();
    assert!(err.contains("an empty `inputRequests` map"), "{err}");
}

/// A host call that pends is re-issued UNDER THE NUMBER IT WAS FIRST ISSUED UNDER when the run is
/// driven again, and the budget is not re-spent across the pend.
#[test]
fn a_pending_claim_and_completion_resume_under_their_first_numbers() {
    let mut host = Scripted {
        now: 1_000_000,
        claims: VecDeque::from([Poll::Pending]),
        completions: VecDeque::from([Poll::Pending]),
        ..Scripted::default()
    };
    let mut run = SampleRun::new(ask());
    let policy = declared(5);
    assert!(
        run.drive(SERVER, Some(&policy), &mut host).is_pending(),
        "the claim pends"
    );
    assert!(
        run.drive(SERVER, Some(&policy), &mut host).is_pending(),
        "the completion pends"
    );
    let answer = ready(&mut run, Some(&policy), &mut host).expect("then it answers");
    assert!(answer
        .pointer("/inputResponses/draft/content/text")
        .is_some());
    assert_eq!(host.claimed.len(), 2);
    assert_eq!(
        host.claimed[0], host.claimed[1],
        "the claim was re-issued as it was"
    );
    assert_eq!(host.completed.len(), 2);
    assert_eq!(
        host.completed[0], host.completed[1],
        "the completion was re-issued as it was"
    );
    assert_eq!(
        host.windows[SERVER],
        (16_666, 1),
        "one slot reserved, not two"
    );
    assert_eq!(host.clock_reads, 1);
}

/// A slot spent elsewhere (another node, or this one before a restart) moves the ask to the next
/// slot of the window, and a window spent elsewhere to the cap refuses in the budget's words.
#[test]
fn a_slot_spent_elsewhere_moves_on_and_a_spent_window_refuses() {
    let mut host = Scripted {
        now: 1_000_000,
        claims: VecDeque::from([Poll::Ready(SlotClaim::Lost)]),
        ..Scripted::default()
    };
    ready(&mut SampleRun::new(ask()), Some(&declared(2)), &mut host).expect("slot 1 is free");
    let keys: Vec<&str> = host.claimed.iter().map(|(_, k)| k.as_str()).collect();
    assert_eq!(keys, ["sampling/fs/16666/0", "sampling/fs/16666/1"]);

    let mut host = Scripted {
        now: 1_000_000,
        claims: VecDeque::from([Poll::Ready(SlotClaim::Lost), Poll::Ready(SlotClaim::Lost)]),
        ..Scripted::default()
    };
    let err = ready(&mut SampleRun::new(ask()), Some(&declared(2)), &mut host).unwrap_err();
    assert_eq!(
        err,
        sampling_exhausted(SERVER, 2),
        "a restart does not lift the cap"
    );
    assert!(host.completed.is_empty());
}

/// No store bound: the local half is the whole gate. A ledger that cannot say: refused.
#[test]
fn an_unbound_ledger_admits_on_the_local_half_and_an_unreadable_one_refuses() {
    let mut host = Scripted {
        claims: VecDeque::from([Poll::Ready(SlotClaim::Unbound)]),
        ..Scripted::default()
    };
    ready(&mut SampleRun::new(ask()), Some(&declared(1)), &mut host)
        .expect("the local half admits the first");
    let err = ready(&mut SampleRun::new(ask()), Some(&declared(1)), &mut host).unwrap_err();
    assert_eq!(
        err,
        sampling_exhausted(SERVER, 1),
        "and refuses past the cap"
    );

    let mut host = Scripted {
        claims: VecDeque::from([Poll::Ready(SlotClaim::Unreadable)]),
        ..Scripted::default()
    };
    let err = ready(&mut SampleRun::new(ask()), Some(&declared(5)), &mut host).unwrap_err();
    assert!(
        err.contains("could not be read from busbar's ledger"),
        "{err}"
    );
    assert!(host.completed.is_empty());
}
