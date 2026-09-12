// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The frame composer's own cells. Every one of them is about BYTES or about ORDER, because those
//! are the two things this module decides; what a poll SAW is the engine's read and arrives here
//! already answered.

use super::*;

/// Split one chunk into the JSON values its SSE `message` events carry.
fn frames(chunk: &str) -> Vec<Value> {
    chunk
        .split("\n\n")
        .filter(|f| !f.trim().is_empty())
        .map(|f| {
            let data = f
                .lines()
                .find_map(|l| l.strip_prefix("data: "))
                .unwrap_or_else(|| panic!("every frame carries one `data:` line: {f}"));
            serde_json::from_str(data).expect("and that line is one JSON value")
        })
        .collect()
}

fn id() -> Value {
    serde_json::json!(7)
}

fn everything() -> Filter {
    Filter {
        tools_list_changed: Some(true),
        prompts_list_changed: Some(true),
        resources_list_changed: Some(true),
        resource_subscriptions: None,
    }
}

fn allowed(generation: u64, keys: [u64; 3]) -> Poll<'static> {
    Poll::Allowed {
        generation,
        keys,
        updates: &[],
    }
}

/// THE FIRST FRAME IS THE ACKNOWLEDGEMENT, and what it carries is the ACCEPTED subset.
///
/// Both halves matter and neither is the other: a first frame that is a list-changed notification
/// breaks the revision's ordering MUST, and an acknowledgement echoing the request tells a client it
/// is subscribed to what will never arrive.
#[test]
fn the_first_frame_is_the_acknowledgement_and_it_carries_the_accepted_subset() {
    let accepted = accept(
        &Filter {
            tools_list_changed: Some(true),
            prompts_list_changed: Some(false),
            resources_list_changed: None,
            resource_subscriptions: Some(vec!["docs://guide".into(), "docs://secret".into()]),
        },
        |uri| uri == "docs://guide",
    );
    let mut listen = Listen::opened(id(), accepted);
    let chunk = listen
        .step(allowed(1, [1, 2, 3]))
        .expect("the acknowledgement is owed first");
    let frame = &frames(&chunk)[0];
    assert_eq!(frame["method"], METHOD_ACKNOWLEDGED);
    assert!(frame.get("id").is_none(), "a notification carries no id");
    assert_eq!(
        frame["params"]["notifications"],
        serde_json::json!({
            "toolsListChanged": true,
            "resourceSubscriptions": ["docs://guide"],
        }),
        "the ACCEPTED subset: a requested `false` and an unrequested category are OMITTED, not \
         answered `false`, and the uri this caller cannot reach is not named back at it"
    );
    assert_eq!(frame["params"]["_meta"][META_SUBSCRIPTION_ID], id());
}

/// A SURVIVING LIST OF NOTHING IS NOT AN EMPTY LIST. "You subscribed to no resources" and "this
/// category has nothing for you" are different statements, and only the second is honest here.
#[test]
fn an_accepted_uri_list_that_empties_is_no_list_at_all() {
    let accepted = accept(
        &Filter {
            resource_subscriptions: Some(vec!["docs://secret".into()]),
            ..Filter::default()
        },
        |_| false,
    );
    assert_eq!(accepted.resource_subscriptions, None);
    assert!(
        Listen::opened(id(), accepted).subscribed().is_none(),
        "and the engine is told to read no announcement ring at all"
    );
}

/// A FILTER THAT CAN DELIVER NOTHING SAYS SO, and a filter that names one uri and nothing else does
/// not: a resource subscription is a category, and forgetting that would refuse a legal stream.
#[test]
fn a_filter_that_can_deliver_nothing_says_so_and_one_that_names_a_uri_does_not() {
    assert!(Filter::default().delivers_nothing());
    assert!(Filter {
        tools_list_changed: Some(false),
        ..Filter::default()
    }
    .delivers_nothing());
    assert!(!Filter {
        resource_subscriptions: Some(vec!["docs://guide".into()]),
        ..Filter::default()
    }
    .delivers_nothing());
    assert!(!everything().delivers_nothing());
}

/// A MOVED GENERATION EMITS ONLY WHAT MOVED AND ONLY WHAT WAS ASKED FOR — two independent
/// narrowings, and a cell that changed only one of them would pass on a composer that had lost the
/// other.
#[test]
fn a_moved_generation_emits_only_the_categories_whose_keys_moved_and_were_asked_for() {
    let accepted = accept(
        &Filter {
            tools_list_changed: Some(true),
            resources_list_changed: Some(true),
            ..Filter::default()
        },
        |_| false,
    );
    let mut listen = Listen::opened(id(), accepted);
    listen.step(allowed(1, [10, 20, 30])).expect("acknowledged");
    // Every key moved, but prompts was never asked for and resources did not move.
    let chunk = listen
        .step(allowed(2, [11, 21, 30]))
        .expect("the stream is open");
    let methods: Vec<String> = frames(&chunk)
        .iter()
        .map(|f| f["method"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        methods,
        vec![Kind::Tools.method().to_string()],
        "tools moved and was asked for; prompts moved and was not; resources was asked for and did \
         not move"
    );
}

/// AN UNMOVED GENERATION IS QUIET WHATEVER THE KEYS SAY. The generation is the gate on the
/// comparison — a snapshot that has not moved cannot have changed a list — and a composer that read
/// the keys anyway would report a hash collision as a change.
#[test]
fn an_unmoved_generation_is_quiet_even_when_the_keys_disagree() {
    let mut listen = Listen::opened(id(), everything());
    listen.step(allowed(4, [1, 2, 3])).expect("acknowledged");
    assert_eq!(
        listen.step(allowed(4, [9, 9, 9])).expect("still open"),
        "",
        "the generation did not move, so nothing is compared and nothing is written"
    );
}

/// THE RELAY WRITES ONE FRAME PER URI, IN THE ORDER IT WAS HANDED, and each one names the uri it is
/// about. The judgement above it is the engine's; what this cell holds is that none of it is
/// re-ordered, dropped or merged on the way to the wire.
#[test]
fn the_relay_writes_one_frame_per_uri_in_the_order_it_was_handed() {
    let mut listen = Listen::opened(
        id(),
        Filter {
            resource_subscriptions: Some(vec!["a".into(), "b".into()]),
            ..Filter::default()
        },
    );
    listen.step(allowed(1, [0; 3])).expect("acknowledged");
    let updates = ["b".to_string(), "a".to_string(), "b".to_string()];
    let chunk = listen
        .step(Poll::Allowed {
            generation: 1,
            keys: [0; 3],
            updates: &updates,
        })
        .expect("still open");
    let uris: Vec<String> = frames(&chunk)
        .iter()
        .map(|f| {
            assert_eq!(
                f["method"],
                busbar_mcp_codec::codec::METHOD_NOTIFY_RESOURCES_UPDATED
            );
            f["params"]["uri"].as_str().unwrap_or_default().to_string()
        })
        .collect();
    assert_eq!(uris, vec!["b", "a", "b"]);
}

/// A LAPSED STANDING ENDS THE STREAM WITH A REFUSAL THAT NAMES THE STEP, and the word comes off the
/// VERDICT rather than off the sentence beside it.
///
/// This is plan line 9's verdict read, asserted where it is performed: an operator filtering a log
/// and a client reading `data.reason` are reading the one vocabulary the fold answers in.
#[test]
fn a_lapsed_standing_refuses_by_name_and_the_name_is_the_verdicts() {
    for (verdict, reason) in [
        (Verdict::IdentityNotLive, "identity_not_live"),
        (Verdict::GenerationMoved, "generation_moved"),
    ] {
        let mut listen = Listen::opened(id(), everything());
        let chunk = listen
            .step(Poll::Refused {
                verdict,
                sentence: "the sentence the refusing side wrote",
            })
            .expect("a refusal is written rather than the socket going quiet");
        let frame = &frames(&chunk)[0];
        assert_eq!(
            frame["id"],
            id(),
            "correlated to the request that opened it"
        );
        assert_eq!(frame["error"]["code"], crate::jsonrpc::CODE_INVALID_REQUEST);
        assert_eq!(
            frame["error"]["message"],
            "the sentence the refusing side wrote"
        );
        assert_eq!(frame["error"]["data"]["reason"], reason);
        assert!(listen.ended(), "and one refusal is the whole of it");
        assert!(listen.step(allowed(9, [9; 3])).is_none(), "ENDED IS ENDED");
    }
}

/// THE BOUND IS A GRACEFUL END AND NOT A REFUSAL. A client that is told "invalid request" when its
/// five minutes ran out will not re-open; a client told the subscription completed will.
#[test]
fn the_bound_closes_the_stream_with_the_revisions_own_completion() {
    let mut listen = Listen::opened(id(), everything());
    let chunk = listen.step(Poll::Complete).expect("a closing frame");
    let frame = &frames(&chunk)[0];
    assert!(frame.get("error").is_none(), "a bound is not a refusal");
    assert_eq!(frame["id"], id());
    assert_eq!(
        frame["result"]["resultType"],
        crate::jsonrpc::RESULT_TYPE_COMPLETE
    );
    assert_eq!(frame["result"]["_meta"][META_SUBSCRIPTION_ID], id());
    assert!(listen.ended());
}

/// AN ID THAT CANNOT BE A SUBSCRIPTION TAG TAGS NOTHING, rather than tagging a value no client can
/// correlate. A `_meta` naming `null` is worse than no `_meta`: it looks like an answer.
#[test]
fn an_id_that_is_not_a_json_rpc_id_tags_nothing() {
    assert_eq!(subscription_meta(&Value::Null), serde_json::json!({}));
    assert_eq!(
        subscription_meta(&serde_json::json!({"a": 1})),
        serde_json::json!({})
    );
    assert_eq!(
        subscription_meta(&serde_json::json!("abc")),
        serde_json::json!({ META_SUBSCRIPTION_ID: "abc" })
    );
    let mut listen = Listen::opened(Value::Null, everything());
    let frame = frames(&listen.step(Poll::Complete).expect("a closing frame"))[0].clone();
    assert!(
        frame["result"].get("_meta").is_none(),
        "the completion states its type and tags nothing: {frame}"
    );
}

/// A LAPSE WHILE THE ACKNOWLEDGEMENT IS STILL OWED CLOSES THE STREAM, and does not acknowledge a
/// subscription that will never deliver. The verdict is read BEFORE the phase, and this is the cell
/// that says so.
#[test]
fn a_standing_that_lapses_before_the_acknowledgement_never_acknowledges() {
    let mut listen = Listen::opened(id(), everything());
    let chunk = listen
        .step(Poll::Refused {
            verdict: Verdict::IdentityNotLive,
            sentence: "gone",
        })
        .expect("a closing frame");
    assert!(
        !chunk.contains(METHOD_ACKNOWLEDGED),
        "an acknowledgement is a promise to deliver: {chunk}"
    );
}

/// EVERY FRAME CARRIES THE TAG AND NO NOTIFICATION CARRIES AN ID. JSON-RPC 2.0 section 4.1 makes the
/// absence of `id` the definition of a notification, and an id here would oblige a client to answer
/// something busbar is not waiting for.
#[test]
fn every_notification_is_tagged_and_none_of_them_carries_an_id() {
    let mut listen = Listen::opened(
        id(),
        Filter {
            resource_subscriptions: Some(vec!["a".into()]),
            ..everything()
        },
    );
    let updates = ["a".to_string()];
    let mut chunk = listen.step(allowed(1, [1, 2, 3])).expect("acknowledged");
    chunk.push_str(
        &listen
            .step(Poll::Allowed {
                generation: 2,
                keys: [4, 5, 6],
                updates: &updates,
            })
            .expect("still open"),
    );
    let frames = frames(&chunk);
    assert_eq!(frames.len(), 5, "acknowledgement, three kinds, one relay");
    for frame in &frames {
        assert_eq!(frame["jsonrpc"], crate::jsonrpc::VERSION);
        assert!(frame.get("id").is_none(), "{frame}");
        assert_eq!(frame["params"]["_meta"][META_SUBSCRIPTION_ID], id());
    }
}

/// THE WIRE ENCODING OMITS WHAT WAS NOT SAID. An emitted `null` reads as a category the server took
/// a position on, and a client that reads one will not fall back.
#[test]
fn the_filters_wire_form_omits_every_member_nobody_stated() {
    assert_eq!(Filter::default().wire(), serde_json::json!({}));
    assert_eq!(
        Filter {
            resources_list_changed: Some(false),
            ..Filter::default()
        }
        .wire(),
        serde_json::json!({ "resourcesListChanged": false }),
        "a stated `false` is stated; an unstated member is absent"
    );
}
