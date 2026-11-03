// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::hook::{slot, DecideIn, DecideOut, StatusOut};
use busbar_contract::abi::mechanism::call::{InHead, OutHead};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, ValidateIn};

use super::door_both_ways::{self as both, close, input, line, octets, open, output, same};
use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::{Frame, Plugin};

#[path = "../../tests/fixtures/hook_door_plugin.rs"]
pub(crate) mod hook_door_plugin;

const SETTINGS: &[u8] = br#"{"reject_over_messages": 3}"#;

fn validate(p: &Plugin<Hook>, settings: &[u8]) -> String {
    let mut v: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    v.input.settings = octets(settings);
    line("validate", &p.call(life::VALIDATE, &mut v))
}

fn decide(p: &Plugin<Hook>, messages: u64) -> String {
    let mut d: Frame<DecideIn, DecideOut> = Frame::new(input(), output());
    d.input.request.request_id = 7;
    d.input.request.message_count = messages;
    let c = p.call(slot::DECIDE, &mut d);
    format!(
        "{} verbs={:#x} reject_status={}",
        line(&format!("decide {messages}"), &c),
        d.out.verbs,
        d.out.reject_status
    )
}

fn status(p: &Plugin<Hook>) -> String {
    let mut s: Frame<InHead, StatusOut> = Frame::new(input(), output());
    line("status", &p.call(slot::STATUS, &mut s))
}

fn ranking_path() -> std::path::PathBuf {
    std::env::var_os("BUSBAR_TEST_RANKING_CDYLIB")
        .map(std::path::PathBuf::from)
        .expect("the qualified actual Ranking image")
}

extern "C" fn ranking_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::sdk::door::RawDoorFn;
    static IMAGE: std::sync::OnceLock<(libloading::Library, RawDoorFn)> =
        std::sync::OnceLock::new();
    let image = IMAGE.get_or_init(|| {
        let library =
            crate::dlopen_on_worker(ranking_path().as_os_str()).expect("actual Ranking loads");
        // SAFETY: this typed export belongs to the retained qualified product image.
        let entry = unsafe {
            *library
                .get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                .expect("actual Ranking door")
        };
        (library, entry)
    });
    let door = crate::dispatch::load::enter_door(image.1);
    crate::dispatch::load::validate_door::<Hook>(door).expect("actual Ranking Hook validates");
    // SAFETY: validation checked the descriptor; IMAGE retains its library for every call.
    unsafe { &*door }
}

fn ranking_decide(p: &Plugin<Hook>, with_costs: bool) -> String {
    use busbar_contract::abi::hook::{
        CandidateDynamic, CandidateStatic, CANDIDATE_HAS_COST_PER_MTOK,
    };
    // SAFETY: these wire structs contain only integers, floats and pointers; zero is valid.
    let mut candidates: [CandidateStatic; 2] = unsafe { std::mem::zeroed() };
    // SAFETY: CandidateDynamic likewise consists entirely of zero-valid wire fields.
    let dynamics: [CandidateDynamic; 2] = unsafe { std::mem::zeroed() };
    candidates[1].idx = 1;
    if with_costs {
        for (candidate, cost) in candidates.iter_mut().zip([9.0, 2.0]) {
            candidate.cost_per_mtok = cost;
            candidate.present = CANDIDATE_HAS_COST_PER_MTOK;
        }
    }
    let mut order = [u32::MAX; 2];
    let mut reject = [0u8; 64];
    let mut tags = [0u8; 64];
    let mut d: Frame<DecideIn, DecideOut> = Frame::new(input(), output());
    d.input.request.request_id = 7;
    d.input.candidates = candidates.as_ptr();
    d.input.candidate_dynamics = dynamics.as_ptr();
    d.input.candidates_len = candidates.len();
    d.input.order_buf = order.as_mut_ptr();
    d.input.order_cap = order.len();
    d.input.reject_message_buf = reject.as_mut_ptr();
    d.input.reject_message_cap = reject.len();
    d.input.restrict_tags_buf = tags.as_mut_ptr();
    d.input.restrict_tags_cap = tags.len();
    let called = p.call(slot::DECIDE, &mut d);
    assert!(d.out.order_written <= order.len());
    assert!(d.out.reject_message_written <= reject.len());
    assert!(d.out.restrict_tags_written <= tags.len());
    assert_eq!(d.out.verbs, if with_costs { 1 } else { 2 });
    assert_eq!(
        &order[..d.out.order_written],
        if with_costs { &[1, 0][..] } else { &[][..] }
    );
    // Every scalar result and every written buffer byte participates in the transcript.
    format!(
        "{} result={:?} order={:?} reject={:?} tags={:?}",
        line("decide", &called),
        (
            d.out.verbs,
            d.out.reject_status,
            d.out._reserved,
            d.out.reject_message_written,
            d.out.reject_message_needed,
            d.out.restrict_tags_written,
            d.out.restrict_tags_needed,
            d.out.order_written,
            d.out.order_needed
        ),
        &order[..d.out.order_written],
        &reject[..d.out.reject_message_written],
        &tags[..d.out.restrict_tags_written]
    )
}

fn ranking_script(p: &Plugin<Hook>) -> Vec<String> {
    const GOOD: &[u8] = br#"{"policy":"cheapest"}"#;
    vec![
        validate(p, br#"{"policy":"unknown"}"#),
        validate(p, GOOD),
        line("open, bad settings", &open(p, b"[]")),
        line("open", &open(p, GOOD)),
        ranking_decide(p, false),
        ranking_decide(p, true),
        status(p),
        line("close", &close(p)),
    ]
}

#[test]
fn a_linked_and_a_dropped_in_hook_decide_identically() {
    // Both origins execute the same retained real product descriptor and image.
    let linked = ranking_script(&both::linked::<Hook>(ranking_door).plugin);
    let dropped = both::dropped_from::<Hook>(ranking_door, &ranking_path());
    same(&linked, &ranking_script(&dropped.plugin));
    assert!(linked[0].contains("Failed"), "{}", linked[0]);
    assert!(linked[1].contains("Ready"), "{}", linked[1]);
    assert!(linked[2].contains("Failed"), "{}", linked[2]);
    assert!(linked[3].contains("Ready"), "{}", linked[3]);
    assert!(linked[4].contains("Ready"), "{}", linked[4]);
    assert!(linked[5].contains("Ready"), "{}", linked[5]);
    assert!(linked[6].contains("Refused"), "{}", linked[6]);
    assert!(linked[7].contains("Ready"), "{}", linked[7]);
}

#[test]
fn a_hook_that_answers_two_verbs_is_refused_through_both_doors() {
    let broken = hook_door_plugin::broken::door;
    let run = |p: &Plugin<Hook>| vec![line("open", &open(p, SETTINGS)), decide(p, 2)];
    let linked = run(&both::linked::<Hook>(broken).plugin);
    assert!(linked[0].contains("Ready"), "{}", linked[0]);
    assert!(linked[1].contains("Fault"), "{}", linked[1]);
    let conforming = run(&both::linked::<Hook>(hook_door_plugin::conforming::door).plugin);
    assert!(conforming[1].contains("Ready"), "{}", conforming[1]);
    let dropped = both::dropped::<Hook>(broken, "hook_broken_door");
    same(&linked, &run(&dropped.plugin));
}
