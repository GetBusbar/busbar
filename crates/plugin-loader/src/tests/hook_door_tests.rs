// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK AXIS, BOTH WAYS (THE DESIGN §11.4; the SWITCH-OVER card, hook root axis): the hook
//! kind's fixture (`hook_door_plugin`) reached through [`HookRows`] as a LINKED row (its door) and as
//! a DROPPED-IN row (its example `cdylib`'s bytes, admitted against the rendering its door states),
//! probed, opened and called through the contract's [`HookAxis`] / [`HookCalls`] on the one
//! dispatcher. The two transcripts must be equal, line for line: the axis loads both doors through
//! the one loader path and reads nothing of which door a row came in by.
//!
//! RED ARM, KEPT: [`a_hook_that_breaks_the_kind_contract_is_broken_through_both_doors`] opens the
//! fixture's broken door (`decide` answering two verbs) the same two ways: the axis answers
//! [`Answered::Broken`] on both, where the conforming door answers one verb.
//!
//! RED ARM (ARCHITECT Q-SO8): [`a_hook_statement_without_its_kind_tail_is_refused_at_load`] — the
//! conforming plugin with no hook tail does not load; the refusal names the missing tail.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::hook::{CLASS_GATE, PROMPT_NO, USER_NO};
use busbar_contract::abi::host::hook::{DecideFrame, DecideView};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::hook_calls::{Answered, HookAxis, HookFacts};
use busbar_contract::hooks::{RoutingContext, RoutingRequest};
use busbar_contract::SignalBag;
use serde_json::json;

use super::HookRows;
use crate::boot::{Candidate, Origin};
use crate::dispatch::{rendering_of, DispatchConfig, Dispatcher};

use crate::hook_door_conformance_tests::hook_door_plugin;

use hook_door_plugin::{
    BROKEN_NAME, MAX_INFLIGHT, NAME, PANICKING_NAME, REJECT_STATUS, UNTAILED_NAME,
};

/// Every call's budget.
const BUDGET: Duration = Duration::from_secs(5);

/// A request of `messages` messages.
fn request(messages: usize) -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 7,
        pool: "p",
        ingress_protocol: "acme",
        requested_model: None,
        message_count: messages,
        tool_count: 0,
        has_tools: false,
        total_chars: 11,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: SignalBag::new(),
        session: None,
    }
}

/// The `decide` frame of a request of `messages` messages over no candidates.
fn frame(messages: usize) -> Arc<DecideFrame> {
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    DecideFrame::first(DecideView::build(&request(messages), &[], &ctx))
}

/// How a row reaches the axis.
#[derive(Debug, Clone, Copy)]
enum Way {
    Linked,
    Dropped,
}

/// The axis over `door`, its one row reached `way`. A dropped-in row whose example `cdylib`
/// (`example`) is not built is a hard failure naming the command that builds it, never a skip.
fn rows(door: DoorFn, example: &str, way: Way) -> HookRows {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    match way {
        Way::Linked => HookRows::new(&[door], None, dispatcher).expect("the linked row"),
        Way::Dropped => {
            let path = crate::both_ways::example_cdylib(example);
            let bytes = std::fs::read(&path).expect("the example cdylib reads");
            let row = Candidate::from_rendering(
                rendering_of(door).expect("the door renders its Statement"),
                None,
                Origin::Dropped {
                    file: format!("{example}.tar.gz"),
                    bytes: Arc::new(bytes),
                },
            )
            .expect("the rendering states a candidate");
            HookRows::of(vec![row], dispatcher)
        }
    }
}

/// One `decide` answer, as a line.
fn decided(messages: usize, a: &Answered<busbar_contract::abi::hook::DecideOut>) -> String {
    match a {
        Answered::Answer {
            outcome,
            out,
            error,
            ..
        } => format!(
            "decide {messages}: {outcome:?} verbs={:#x} reject_status={} error={error:?}",
            out.verbs, out.reject_status
        ),
        Answered::TimedOut => format!("decide {messages}: timed out"),
        Answered::Broken(why) => format!("decide {messages}: broken ({why})"),
    }
}

/// THE SCRIPT through the axis, one line per answer.
async fn script(rows: &HookRows, module: &str) -> Vec<String> {
    let probed = |settings: serde_json::Value| rows.probe(module, "gate", &settings);
    let mut lines = vec![
        format!(
            "probe bad: {:?}",
            probed(json!({"reject_over_messages": "three"}))
        ),
        format!(
            "probe good: {:?}",
            probed(json!({"reject_over_messages": 3}))
        ),
        format!(
            "probe nobody: {:?}",
            rows.probe("nobody", "gate", &json!({}))
        ),
    ];
    let calls = rows
        .open(
            module,
            "hooks.gate",
            &json!({"reject_over_messages": 3}),
            BUDGET,
        )
        .expect("the hook opens through the axis");
    lines.push(format!("name: {}", calls.name()));
    for messages in [2, 5] {
        lines.push(decided(
            messages,
            &calls.decide(frame(messages), BUDGET).await,
        ));
    }
    lines.push(format!("status: {:?}", calls.status(BUDGET).await));
    lines.push(format!(
        "configure: {:?}",
        calls.configure("gate", "{}", 2, BUDGET).await
    ));
    lines
}

#[tokio::test]
async fn a_linked_and_a_dropped_in_hook_open_through_the_axis_and_decide_identically() {
    let door = hook_door_plugin::conforming::door;
    let linked_rows = rows(door, "hook_door", Way::Linked);
    let linked = script(&linked_rows, NAME).await;
    let dropped_rows = rows(door, "hook_door", Way::Dropped);
    let dropped = script(&dropped_rows, NAME).await;
    assert_eq!(linked, dropped, "the same table, whichever door");
    // The script reached every answer it names: equal empty transcripts would prove nothing.
    let facts = HookFacts {
        name: NAME.to_string(),
        class: CLASS_GATE,
        prompt: PROMPT_NO,
        user: USER_NO,
        infallible: false,
        words: Vec::new(),
    };
    assert!(
        linked[0].contains(&format!("{facts:?}")) && linked[0].contains("must be a number"),
        "{}",
        linked[0]
    );
    assert!(linked[1].ends_with("[]))"), "{}", linked[1]);
    assert_eq!(linked[2], "probe nobody: None");
    assert_eq!(linked[3], format!("name: {NAME}"));
    assert!(
        linked[4].contains("Ready") && linked[4].contains("verbs=0x2 "),
        "{}",
        linked[4]
    );
    assert!(
        linked[5].contains("Ready")
            && linked[5].contains("verbs=0x14 ")
            && linked[5].contains(&format!("reject_status={REJECT_STATUS}")),
        "{}",
        linked[5]
    );
    assert_eq!(linked[6], "status: None", "the fixture refuses `status`");
    assert!(linked[7].starts_with("configure: Err("), "{}", linked[7]);
}

/// THE RED ARM, KEPT: a `decide` answering two verbs at once breaks the hook kind's contract.
/// Through either door the axis answers BROKEN, never a verdict.
#[tokio::test]
async fn a_hook_that_breaks_the_kind_contract_is_broken_through_both_doors() {
    let run = |rows: HookRows| async move {
        let calls = rows
            .open(
                BROKEN_NAME,
                "hooks.gate",
                &json!({"reject_over_messages": 3}),
                BUDGET,
            )
            .expect("the broken hook still opens");
        decided(2, &calls.decide(frame(2), BUDGET).await)
    };
    let broken = hook_door_plugin::broken::door;
    let linked = run(rows(broken, "hook_broken_door", Way::Linked)).await;
    assert!(
        linked.contains("broken (") && linked.contains("FAULT"),
        "{linked}"
    );
    // The conforming door under the broken door's name is not a row: the axis names the module.
    let refused = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked)
        .open(BROKEN_NAME, "hooks.gate", &json!({}), BUDGET)
        .err();
    assert!(
        refused.is_some_and(|e| e.contains(BROKEN_NAME)),
        "an unknown module is refused, named"
    );
    let dropped_rows = rows(broken, "hook_broken_door", Way::Dropped);
    assert_eq!(
        linked,
        run(dropped_rows).await,
        "the same refusal, whichever door"
    );
}

/// PB-81 (a panicking plugin is a fail-closed error): a hook whose `decide` PANICS is caught at
/// its door and answered FAULT, which the axis answers as BROKEN, never a verdict, promptly and
/// without unwinding into the host. The kernel reads every answer that is not READY as an error
/// its `on_error` decides.
#[tokio::test]
async fn a_panicking_hook_is_broken_through_the_axis_never_a_verdict() {
    let axis = rows(hook_door_plugin::panicking::door, "hook_door", Way::Linked);
    let calls = axis
        .open(
            PANICKING_NAME,
            "hooks.gate",
            &json!({"reject_over_messages": 3}),
            BUDGET,
        )
        .expect("the panicking hook opens: only its decide panics");
    let started = std::time::Instant::now();
    let answered = decided(2, &calls.decide(frame(2), BUDGET).await);
    assert!(
        answered.contains("broken (") && answered.contains("FAULT"),
        "{answered}"
    );
    assert!(
        started.elapsed() < BUDGET,
        "a caught panic answers at once, not on the call's budget"
    );
}

#[test]
fn a_linked_row_is_linked_and_first_party_and_a_dropped_in_unsigned_row_is_neither() {
    let door = hook_door_plugin::conforming::door;
    let linked = rows(door, "hook_door", Way::Linked);
    assert!(linked.linked(NAME) && linked.first_party(NAME));
    assert!(!linked.linked("nobody") && !linked.first_party("nobody"));
    let dropped = rows(door, "hook_door", Way::Dropped);
    assert!(!dropped.linked(NAME) && !dropped.first_party(NAME));
}

/// RED ARM (Q-SO8): a hook Statement with no kind tail is refused at load, named; nothing assumes
/// a class or grants for it. The conforming door, which states its tail, opens.
#[test]
fn a_hook_statement_without_its_kind_tail_is_refused_at_load() {
    let untailed = rows(hook_door_plugin::untailed::door, "hook_door", Way::Linked);
    assert_eq!(
        untailed.probe(UNTAILED_NAME, "gate", &json!({"reject_over_messages": 3})),
        Some((None, Vec::new())),
        "an untailed hook states no facts"
    );
    let refused = untailed
        .open(
            UNTAILED_NAME,
            "hooks.gate",
            &json!({"reject_over_messages": 3}),
            BUDGET,
        )
        .err()
        .expect("an untailed hook is refused at load");
    assert!(
        refused.contains(crate::dispatch::kinds::hook::NO_TAIL) && refused.contains(UNTAILED_NAME),
        "{refused}"
    );
    let tailed = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked).open(
        NAME,
        "hooks.gate",
        &json!({"reject_over_messages": 3}),
        BUDGET,
    );
    assert!(tailed.is_ok(), "the tailed door opens");
}

/// RED (C21's hook half; one version per kind): a dropped-in `kind: hook` plugin whose manifest
/// states no Statement speaks the 1.5.5 JSON hook contract. The axis refuses it — and so the boot —
/// naming the plugin and the rebuild, where it used to load it over the JSON lane.
#[test]
fn a_dropped_in_1_5_5_json_hook_plugin_is_refused_naming_the_rebuild() {
    let abi = *crate::supported_abi("hook")
        .iter()
        .min()
        .expect("a hook payload schema");
    let registry = crate::both_ways::dropped(
        "json-hook",
        crate::both_ways::statement("hook", "json-hook", "json-hook", abi),
        b"a 1.5.5 JSON hook library",
    );
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let refused = HookRows::new(&[], Some(&registry), dispatcher)
        .expect_err("a 1.5.5 JSON hook plugin is refused");
    assert!(
        refused.contains(super::JSON_HOOK_REFUSED) && refused.contains("json-hook"),
        "{refused}"
    );
}

/// THE SESSION REACHES A HOOK (ARCHITECT RULING 2026-10-03, Q-FOLD-A2A-2-PROJECT-POOL session
/// half): the request view's opaque session crosses the hook kind's `decide` through the one
/// dispatcher, linked and dropped in alike: the fixture refuses the session its settings name and
/// abstains on any other, and on a request that names none.
#[tokio::test]
async fn a_hook_reads_the_request_session_through_both_doors() {
    let run = |rows: HookRows| async move {
        let calls = rows
            .open(
                NAME,
                "hooks.gate",
                &json!({"reject_over_messages": 3, "reject_session": "ctx-7"}),
                BUDGET,
            )
            .expect("the hook opens");
        let ctx = RoutingContext {
            pool: "p",
            budget_remaining: None,
            budget: &[],
        };
        let mut lines = Vec::new();
        for session in [Some(&b"ctx-7"[..]), Some(&b"ctx-8"[..]), None] {
            let mut req = request(2);
            req.session = session;
            let frame = DecideFrame::first(DecideView::build(&req, &[], &ctx));
            lines.push(decided(2, &calls.decide(frame, BUDGET).await));
        }
        lines
    };
    let door = hook_door_plugin::conforming::door;
    let linked = run(rows(door, "hook_door", Way::Linked)).await;
    assert!(
        linked[0].contains("verbs=0x14 ")
            && linked[0].contains(&format!("reject_status={REJECT_STATUS}")),
        "the named session is refused: {}",
        linked[0]
    );
    assert!(linked[1].contains("verbs=0x2 "), "{}", linked[1]);
    assert!(linked[2].contains("verbs=0x2 "), "{}", linked[2]);
    let dropped_rows = rows(door, "hook_door", Way::Dropped);
    assert_eq!(
        linked,
        run(dropped_rows).await,
        "the same answers, whichever door"
    );
}

/// R1 (Q-LEAK; THE DESIGN: every hook call runs on an off-worker lane carrying 1.5.5's
/// `timeout_ms` guarantee), the LANE'S half: a gate whose `decide` sleeps past the call's budget is
/// cut off at that budget through the axis — `TimedOut`, promptly, never the sleep waited out, and
/// the caller's worker never parked. The kernel's half (the budget is the hook's `timeout_ms`, and a
/// timed-out call is an error its `on_error` decides) is `dlopen_decide_deadline_cuts_off_a_slow_gate`
/// / `dlopen_slow_gate_hits_the_deadline` in busbar-kernel's hook tests. Re-homed with the deletion of
/// the test-hook plugin (OWNER 2026-10-03, no test plugins), whose `sleep_ms` drove both halves.
#[tokio::test]
async fn a_slow_hook_is_cut_off_at_its_budget_through_the_axis() {
    let axis = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked);
    let calls = axis
        .open(
            NAME,
            "hooks.slow",
            &json!({"reject_over_messages": 3, "sleep_ms": 2_000}),
            BUDGET,
        )
        .expect("the slow gate opens");
    let started = std::time::Instant::now();
    let answered = calls.decide(frame(2), Duration::from_millis(100)).await;
    assert!(
        matches!(answered, Answered::TimedOut),
        "a slow gate must exceed the deadline: {}",
        decided(2, &answered)
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the deadline must cut off promptly, not wait out the sleep"
    );
}

/// PB-81, THE QUARANTINE RACE: a call refused at the saturated cap whose wedged instance the
/// watchdog faults before the refusal is looked at (the order a loaded host gave
/// [`the_inflight_cap_saturates_and_fails_on_the_caller_deadline_through_the_axis`] by chance: its
/// freed-slot call answered `broken (hook ... answered Refused)` at 1.00 s). That call was never
/// made — a refusal is no crossing — so it waits for the trial window within its own budget, as a
/// call meeting the fault before it was submitted does, and is answered by the fresh instance.
/// The refused call here is held until the watchdog has faulted the instance, so the order is met
/// every time.
#[tokio::test]
async fn a_call_refused_at_the_cap_as_the_watchdog_faults_the_instance_waits_for_its_trial() {
    let axis = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked);
    // `sleep_ms` past the Call class budget: the watchdog faults the wedged crossings; the odd
    // figure marks this instance's settings for the hold.
    let wedged: Arc<dyn busbar_contract::hook_calls::HookCalls> = axis
        .open(
            NAME,
            "hooks.wedged-race",
            &json!({"reject_over_messages": 3, "sleep_ms": 1_501}),
            BUDGET,
        )
        .expect("the wedged gate opens");
    *crate::hook_door::HOLD_REFUSED_UNTIL_FAULTED_FOR_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(b"\"sleep_ms\":1501".to_vec());
    let mut inflight = Vec::with_capacity(MAX_INFLIGHT as usize);
    for _ in 0..MAX_INFLIGHT {
        let wedged = Arc::clone(&wedged);
        inflight.push(tokio::spawn(async move {
            let _ = wedged.decide(frame(2), Duration::from_millis(50)).await;
        }));
    }
    for h in inflight {
        let _ = h.await;
    }
    // Every unit is held by a wedged crossing (the callers gave up; the crossings run on), so this
    // call is refused at the cap, held until the watchdog faults the instance, then judged.
    let answered = wedged.decide(frame(2), BUDGET).await;
    *crate::hook_door::HOLD_REFUSED_UNTIL_FAULTED_FOR_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    assert!(
        matches!(
            answered,
            Answered::Answer {
                outcome: busbar_contract::abi::mechanism::call::Outcome::Ready,
                ..
            }
        ),
        "a call the cap refused as the instance was quarantined waits for its trial: {}",
        decided(2, &answered)
    );
}

/// PB-81 (`max_inflight` per loaded hook; 1.5.5 pinned `MAX_INFLIGHT_HOOK_CALLS = 64`, a 1.6.0 hook
/// states its own in its Statement): one hook is saturated with `max_inflight` calls that never
/// return inside the test's budget. A further call must fail CLOSED on the caller's own deadline —
/// never wait out the wedge — and once the wedged calls drain, the freed slots let service resume.
/// The cap is backpressure, not a latch. The cap is the dispatcher's, so its proof lives here, over
/// the loader's own hook fixture; it moved from busbar-kernel's M4 suite
/// (`the_inflight_cap_saturates_and_fails_on_the_caller_deadline_through_resolve_one`, which drove
/// the deleted test-hook plugin) with every assertion kept.
#[tokio::test]
async fn the_inflight_cap_saturates_and_fails_on_the_caller_deadline_through_the_axis() {
    let axis = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked);
    let wedged: Arc<dyn busbar_contract::hook_calls::HookCalls> = axis
        .open(
            NAME,
            "hooks.wedged",
            &json!({"reject_over_messages": 3, "sleep_ms": 1_500}),
            BUDGET,
        )
        .expect("the wedged gate opens");

    let mut inflight = Vec::with_capacity(MAX_INFLIGHT as usize);
    for _ in 0..MAX_INFLIGHT {
        let wedged = Arc::clone(&wedged);
        inflight.push(tokio::spawn(async move {
            let _ = wedged.decide(frame(2), Duration::from_millis(50)).await;
        }));
    }
    // Let every spawned call reach the plugin and take its slot.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let start = std::time::Instant::now();
    let saturated = wedged.decide(frame(2), Duration::from_millis(150)).await;
    assert!(
        !matches!(
            saturated,
            Answered::Answer {
                outcome: busbar_contract::abi::mechanism::call::Outcome::Ready,
                ..
            }
        ),
        "with every slot held, a further call must fail rather than wait for one: {}",
        decided(2, &saturated)
    );
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "the wait must be bounded by the caller's own deadline, not by the wedged plugin"
    );

    // The wedged calls returning frees the slots — the cap is backpressure, not a latch.
    for h in inflight {
        let _ = h.await;
    }
    let resumed = wedged.decide(frame(2), BUDGET).await;
    assert!(
        matches!(
            resumed,
            Answered::Answer {
                outcome: busbar_contract::abi::mechanism::call::Outcome::Ready,
                ..
            }
        ),
        "a freed slot must let the next call through: {}",
        decided(2, &resumed)
    );
}

/// THE RULING'S HOOK CASE THROUGH THE AXIS (1.5.5 configs load unchanged): a hook config naming
/// `module: busbar-webrequest` (the 1.5.5 release's manifest name) opens the 1.6.0 hook, DROPPED IN
/// (its signed manifest's `former_names`, through the registry the root builds the axis over) and
/// LINKED (the former names the root's legacy table gives a linked row). RED ARMS, in the same
/// test: without the former names neither way answers the old name.
#[test]
fn a_1_5_5_hook_name_opens_the_1_6_0_hook_both_ways() {
    const OLD: &str = "busbar-webrequest";
    let door = hook_door_plugin::conforming::door;
    let settings = json!({"reject_over_messages": 3});
    let opens = |rows: &HookRows| rows.open(OLD, "hooks.wr", &settings, BUDGET).is_ok();
    let dispatcher = || Arc::new(Dispatcher::new(DispatchConfig::default()));
    // LINKED.
    let former_of = |w: &str| {
        if w == NAME {
            vec![OLD.to_string()]
        } else {
            Vec::new()
        }
    };
    let linked = HookRows::new(&[door], None, dispatcher())
        .expect("the linked row")
        .with_former_names(former_of)
        .expect("no other plugin claims the name");
    assert!(opens(&linked), "linked: '{OLD}' opens the hook");
    assert!(linked.linked(OLD) && linked.first_party(OLD));
    let bare = HookRows::new(&[door], None, dispatcher()).expect("the linked row");
    assert!(!opens(&bare), "RED: a linked row without its former name");
    // DROPPED IN.
    let path = crate::both_ways::example_cdylib("hook_door");
    let lib = std::fs::read(path).expect("the example cdylib reads");
    let abi = crate::supported_abi("hook")[0];
    let stated = hex::encode(rendering_of(door).expect("the door renders its Statement"));
    let manifest = |former: &[&str]| {
        let mut m =
            crate::both_ways::statement("hook", "busbar-hook-webrequest", "webrequest", abi);
        m.statement = Some(stated.clone());
        m.former_names = former.iter().map(|s| s.to_string()).collect();
        m
    };
    let registry = crate::both_ways::dropped("former-hook", manifest(&[OLD]), &lib);
    assert!(registry.answers(OLD, "hook"), "preflight resolves '{OLD}'");
    let dropped = HookRows::new(&[], Some(&registry), dispatcher()).expect("the dropped row");
    assert!(opens(&dropped), "dropped in: '{OLD}' opens the hook");
    let registry = crate::both_ways::dropped("bare-hook", manifest(&[]), &lib);
    let bare = HookRows::new(&[], Some(&registry), dispatcher()).expect("the dropped row");
    assert!(
        !opens(&bare),
        "RED: a dropped-in hook without its former name"
    );
    assert!(!registry.answers(OLD, "hook"));
}

/// THE ONE-OWNER RULE on the hook axis (ARCHITECT): a linked hook given a former name another hook
/// row already answers to is refused, naming both, so the old name never resolves ambiguously.
#[test]
fn a_former_name_two_hooks_claim_is_refused_on_the_axis() {
    let rows = HookRows::new(
        &[
            hook_door_plugin::conforming::door,
            hook_door_plugin::broken::door,
        ],
        None,
        Arc::new(Dispatcher::new(DispatchConfig::default())),
    )
    .expect("two distinct linked hooks");
    let refused = rows
        .with_former_names(|w| {
            if w == NAME {
                vec![BROKEN_NAME.to_string()]
            } else {
                Vec::new()
            }
        })
        .expect_err("a former name that is another hook's name is refused");
    assert!(
        refused.contains(&format!("'{BROKEN_NAME}'")) && refused.contains(NAME),
        "{refused}"
    );
}

/// ARCHITECT Q-P4-12 ON THE HOOK AXIS: a linked hook and a DIFFERENT dropped-in hook answering one
/// word (here the dropped-in plugin's manifest alias spells the linked hook's name) refuse the
/// configuration, naming both; no door outranks the other. GREEN arm: the dropped-in hook under an
/// alias of its own sits beside the linked one.
#[test]
fn a_linked_hook_and_a_different_dropped_in_hook_claiming_one_word_are_refused() {
    let abi = crate::supported_abi("hook")[0];
    let stated = hex::encode(
        rendering_of(hook_door_plugin::broken::door).expect("the door renders its Statement"),
    );
    let dropped = |alias: &str| {
        let mut m = crate::both_ways::statement("hook", "acme-hook-other", alias, abi);
        m.statement = Some(stated.clone());
        crate::both_ways::dropped(&format!("claim-{alias}"), m, b"a hook library")
    };
    let rows = |registry: &crate::PluginRegistry| {
        HookRows::new(
            &[hook_door_plugin::conforming::door],
            Some(registry),
            Arc::new(Dispatcher::new(DispatchConfig::default())),
        )
    };
    let refused = rows(&dropped(NAME)).expect_err("a word two hooks claim is refused");
    assert!(
        refused.contains(&format!("'{NAME}'")) && refused.contains(BROKEN_NAME),
        "{refused}"
    );
    assert!(
        rows(&dropped("acme-other")).is_ok(),
        "distinct words coexist"
    );
}

/// RED (THE DESIGN §11.13 M1: no plugin code, `dlopen` and `open` included, runs under a host
/// lock): a quarantine's trial binds and opens its fresh instance with the hook's state lock let
/// go, so a trial wedged in its bind holds no other caller — the hook still answers whether it is
/// quarantined — and the trial then serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wedged_trial_holds_no_other_caller() {
    use super::{HookInstance, State};
    use crate::dispatch::{ConnTable, NoSink};
    use busbar_contract::hook_calls::HookCalls;
    use std::sync::mpsc;
    let axis = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked);
    let c = axis.find(NAME).expect("the linked row").clone();
    let dispatcher = Arc::clone(&axis.dispatcher);
    let bind = {
        let (c, dispatcher) = (c.clone(), Arc::clone(&dispatcher));
        move || {
            HookRows::bind(
                &c,
                &dispatcher,
                "hooks.trial",
                Arc::new(NoSink),
                ConnTable::NoNeeds,
            )
        }
    };
    let (entered_tx, entered) = mpsc::channel::<()>();
    let (release, released) = mpsc::channel::<()>();
    let gate = std::sync::Mutex::new(Some((entered_tx, released)));
    let first = bind().expect("the hook binds");
    let instance = Arc::new(
        HookInstance::open(
            first,
            Arc::clone(&dispatcher),
            br#"{"reject_over_messages": 3}"#,
            move || {
                // The trial's bind, wedged until the test releases it.
                if let Some((entered, released)) = gate.lock().unwrap().take() {
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                }
                bind()
            },
        )
        .expect("the hook opens"),
    );
    // Faulted, its trial window open now.
    *instance.inner.lock() = State::Quarantined {
        trial_at: std::time::Instant::now(),
        window: super::QUARANTINE_FIRST,
    };
    let trial = {
        let instance = Arc::clone(&instance);
        tokio::spawn(async move {
            let a = instance.decide(frame(2), BUDGET).await;
            let ready = matches!(
                a,
                Answered::Answer {
                    outcome: busbar_contract::abi::mechanism::call::Outcome::Ready,
                    ..
                }
            );
            (ready, decided(2, &a))
        })
    };
    tokio::task::spawn_blocking(move || entered.recv().unwrap())
        .await
        .unwrap();
    let (asked_tx, asked) = mpsc::channel();
    {
        let instance = Arc::clone(&instance);
        std::thread::spawn(move || {
            let _ = asked_tx.send(instance.quarantined());
        });
    }
    let answered = tokio::task::spawn_blocking(move || asked.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap();
    release.send(()).unwrap();
    assert_eq!(
        answered,
        Ok(true),
        "a wedged trial held another caller behind the hook's state lock"
    );
    let (ready, served) = trial.await.unwrap();
    assert!(ready, "the trial's fresh instance serves: {served}");
    assert!(!instance.quarantined());
}

/// THE SETTINGS NEVER PRINT. An opened instance keeps the settings bytes it was opened over (a
/// resolved bag) to re-open a fresh instance on a quarantine trial; its `Debug` names the instance
/// and nothing else, so `{:?}` in a log line, a `tracing` field or a panic cannot carry them.
#[test]
fn an_instance_debug_never_shows_its_settings() {
    let rows = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked);
    let c = rows.find(NAME).expect("the fixture's row").clone();
    let bind = {
        let (c, dispatcher) = (c.clone(), Arc::clone(&rows.dispatcher));
        move || {
            HookRows::bind(
                &c,
                &dispatcher,
                "hooks.gate",
                Arc::new(super::NoSink),
                super::ConnTable::NoNeeds,
            )
        }
    };
    let settings = br#"{"reject_over_messages": 3}"#;
    let opened = super::HookInstance::open(
        bind().expect("the fixture binds"),
        Arc::clone(&rows.dispatcher),
        settings,
        bind,
    )
    .expect("the fixture opens over its settings");
    let shown = format!("{opened:?}");
    assert!(shown.contains(NAME), "the name names the instance: {shown}");
    for leak in ["reject_over_messages", "3}"] {
        assert!(!shown.contains(leak), "`{leak}` printed: {shown}");
    }
}
