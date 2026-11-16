// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W2-SW-HOOK: the hook kind through its port, over a kind-level `HookPort` double (rule 17 Delta 4).

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::sdk::hook::{RewriteVerdict, Verdict};
use busbar_contract::hook_calls::{HookAxis, HookCalls};
use busbar_contract::plugin::TestKernelSeal;
use busbar_contract::plugin_settings::ResolvedSettings;
use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::BoxFut;

use super::*;

fn answer(verb: u32) -> HookAnswer {
    HookAnswer {
        verb,
        reject_status: None,
        order: Vec::new(),
        restrict: Vec::new(),
        message: None,
        rewrite: None,
    }
}

/// A port that answers every call from one canned result.
struct Canned {
    points: u32,
    facts: u64,
    result: Result<HookAnswer, PortError>,
    io: bool,
    stall: bool,
}

impl Canned {
    fn answering(a: HookAnswer) -> Self {
        Self {
            points: point_bit(abi::POINT_ROUTE),
            facts: 0,
            result: Ok(a),
            io: false,
            stall: false,
        }
    }
}

impl HookPort for Canned {
    fn points(&self) -> u32 {
        self.points
    }
    fn facts(&self) -> u64 {
        self.facts
    }
    fn on<'a>(&'a self, _cx: CallCx, _point: u32, _view: &'a HookView<'a>) -> HookCall<'a> {
        if self.stall {
            return HookCall::Io(Box::pin(std::future::pending()));
        }
        if self.io {
            let r = self.result.clone();
            return HookCall::Io(Box::pin(async move { r }));
        }
        HookCall::Done(self.result.clone())
    }
}

fn ask_it(port: &Canned, budget: Duration) -> Called {
    let owned = Owned::default();
    futures::executor::block_on(async {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(ask(port, "h", abi::POINT_ROUTE, &owned, budget))
    })
}

#[test]
fn a_reject_carries_its_status_and_message_to_the_kernel_verdict() {
    let mut a = answer(abi::VERB_REJECT);
    a.reject_status = Some(451);
    a.message = Some("no".into());
    match verdict("h", &a) {
        Verdict::Reject { status, message } => {
            assert_eq!(status, Some(451));
            assert_eq!(message, "no");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn prefer_prioritize_and_restrict_keep_their_lists() {
    let mut a = answer(abi::VERB_PREFER);
    a.order = vec![2, 0];
    assert!(matches!(verdict("h", &a), Verdict::Prefer(o) if o == vec![2, 0]));
    a.verb = abi::VERB_PRIORITIZE;
    assert!(matches!(verdict("h", &a), Verdict::Prioritize(o) if o == vec![2, 0]));
    let mut r = answer(abi::VERB_RESTRICT);
    r.restrict = vec!["eu".into(), "gdpr".into()];
    assert!(matches!(verdict("h", &r), Verdict::Restrict(t) if t == ["eu", "gdpr"]));
    assert!(matches!(
        verdict("h", &answer(abi::VERB_ABSTAIN)),
        Verdict::Abstain
    ));
}

#[test]
fn a_verb_the_point_does_not_take_is_a_failed_verdict() {
    assert!(matches!(
        verdict("h", &answer(abi::VERB_REWRITE)),
        Verdict::Failed(_)
    ));
    assert!(matches!(
        rewrite_verdict("h", &answer(abi::VERB_PREFER)),
        RewriteVerdict::Failed(_)
    ));
}

#[test]
fn a_rewrite_without_a_body_fails_and_with_one_passes_it_on() {
    assert!(matches!(
        rewrite_verdict("h", &answer(abi::VERB_REWRITE)),
        RewriteVerdict::Failed(_)
    ));
    let mut a = answer(abi::VERB_REWRITE);
    a.rewrite = Some(b"{\"messages\":[]}".to_vec());
    assert!(
        matches!(rewrite_verdict("h", &a), RewriteVerdict::Rewrite(b) if b == b"{\"messages\":[]}")
    );
}

#[test]
fn a_sync_and_an_io_answer_both_reach_the_caller() {
    let mut p = Canned::answering(answer(abi::VERB_PREFER));
    assert!(matches!(
        ask_it(&p, Duration::from_secs(1)),
        Called::Answer(_)
    ));
    p.io = true;
    assert!(matches!(
        ask_it(&p, Duration::from_secs(1)),
        Called::Answer(_)
    ));
}

#[test]
fn failed_and_refused_are_the_operators_on_error_and_a_broken_call_is_broken() {
    let failed = PortError::Failed {
        code: 7,
        text: "x".into(),
        retry_after_s: None,
        backend_status: None,
        error: None,
    };
    let mut p = Canned::answering(answer(0));
    p.result = Err(failed);
    assert!(matches!(
        ask_it(&p, Duration::from_secs(1)),
        Called::Failed(_)
    ));
    p.result = Err(PortError::Refused {
        code: 8,
        text: "y".into(),
        error: None,
    });
    assert!(matches!(
        ask_it(&p, Duration::from_secs(1)),
        Called::Failed(_)
    ));
    p.result = Err(PortError::Call(CallError::Deadline));
    assert!(matches!(
        ask_it(&p, Duration::from_secs(1)),
        Called::Broken(_)
    ));
}

#[test]
fn an_io_answer_past_the_budget_is_timed_out() {
    let mut p = Canned::answering(answer(0));
    p.stall = true;
    assert!(matches!(
        ask_it(&p, Duration::from_millis(20)),
        Called::TimedOut
    ));
}

#[test]
fn the_class_follows_the_points_the_port_serves() {
    let gate = PortHook::new("g", Arc::new(Canned::answering(answer(0))));
    assert_eq!(gate.class(), CLASS_GATE);
    let mut tap = Canned::answering(answer(0));
    tap.points = point_bit(abi::POINT_NOTIFY);
    assert_eq!(PortHook::new("t", Arc::new(tap)).class(), CLASS_TAP);
}

#[test]
fn the_grants_follow_the_facts_the_port_asks_for() {
    let mut p = Canned::answering(answer(0));
    p.facts = abi::FB_WANTS_PROMPT | abi::FB_WANTS_IDENTITY;
    let h = PortHook::new("h", Arc::new(p));
    assert_eq!(h.prompt(), PROMPT_RO);
    assert_eq!(h.user(), USER_RO);
    let none = PortHook::new("n", Arc::new(Canned::answering(answer(0))));
    assert_eq!((none.prompt(), none.user()), (PROMPT_NO, USER_NO));
}

#[test]
fn configure_is_a_reconfigure_and_status_answers_nothing() {
    let h = PortHook::new("h", Arc::new(Canned::answering(answer(0))));
    let r = futures::executor::block_on(h.configure(
        "h",
        &ResolvedSettings::from(serde_json::json!({})),
        1,
        Duration::from_secs(1),
    ));
    assert_eq!(r, Err(CONFIGURE_IS_RECONFIGURE.to_owned()));
    assert!(futures::executor::block_on(h.status(Duration::from_secs(1))).is_none());
    assert!(futures::executor::block_on(h.describe(Duration::from_secs(1))).is_none());
}

struct Opener {
    open: fn() -> Result<Arc<dyn HookPort>, OpenError>,
}

impl HookOpener for Opener {
    fn open<'a>(
        &'a self,
        _module: &'a str,
        _name: &'a str,
        _config_json: &'a [u8],
    ) -> BoxFut<'a, Result<Arc<dyn HookPort>, OpenError>> {
        let r = (self.open)();
        Box::pin(async move { r })
    }
    fn words(&self, module: &str) -> Option<Vec<Box<str>>> {
        (module == "hook-ranking").then(|| vec!["ranked".into()])
    }
}

/// Test driver: one open chain on a scoped thread with its own current-thread runtime.
fn drive_open(fut: BoxFut<'_, TimedOpen>) -> Result<TimedOpen, String> {
    std::thread::scope(|s| {
        s.spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .map(|rt| rt.block_on(fut))
                .map_err(|e| e.to_string())
        })
        .join()
        .unwrap_or_else(|_| Err("panicked".into()))
    })
}

fn rows(open: fn() -> Result<Arc<dyn HookPort>, OpenError>) -> PortRows {
    PortRows::new(
        Arc::new(Opener { open }),
        vec!["hook-ranking".into()],
        vec!["hook-ranking".into()],
        Duration::from_secs(5),
        Arc::new(TestKernelSeal),
        Arc::new(drive_open),
    )
}

#[test]
fn the_axis_opens_a_port_probes_its_words_and_reports_linked_first_party() {
    let rows = rows(|| Ok(Arc::new(Canned::answering(answer(0)))));
    let settings = ResolvedSettings::from(serde_json::json!({"a": 1}));
    let probed = rows.probe("hook-ranking", "r", &settings).unwrap();
    assert_eq!(probed.0.unwrap().words, vec!["ranked".to_owned()]);
    assert!(rows.probe("other", "r", &settings).is_none());
    assert!(rows.linked("hook-ranking") && !rows.linked("other"));
    assert!(rows.first_party("hook-ranking") && !rows.first_party("other"));
    let opened = rows
        .open("hook-ranking", "r", &settings, Duration::from_secs(1))
        .unwrap();
    assert_eq!(opened.name(), "r");
}

#[test]
fn a_refused_open_names_the_instance_and_the_code() {
    let rows = rows(|| {
        Err(OpenError::Config {
            code: 4001,
            text: "bad".into(),
            error: None,
        })
    });
    let settings = ResolvedSettings::from(serde_json::json!({}));
    let e = rows
        .open("hook-ranking", "r", &settings, Duration::from_secs(1))
        .map(|_| ())
        .unwrap_err();
    assert!(e.contains("'r'") && e.contains("4001"), "{e}");
}
