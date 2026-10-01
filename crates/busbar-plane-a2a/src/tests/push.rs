// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Push delivery in plane memory: the retry schedule and what it retries, the per-task order, the
//! bounded queue and its count, the credential's path, and busbar's own callback tokens.

use super::*;
use crate::a2a::task::{Direction, TaskState};
use busbar_contract::abi::host::service::DEST_METADATA;

const MS: u64 = 1_000_000;

/// A task named `id` with a callback, in `state`.
fn task(id: &str, state: TaskState) -> Task {
    let mut t = Task::submitted(id, "ctx", "principal", Direction::Inbound, 0).expect("a task");
    t.push_callback = Some(format!("https://hook.example/cb/{id}?k=v"));
    if state != TaskState::Submitted {
        t.transition_to(TaskState::Working, 1).expect("working");
    }
    if state != TaskState::Working && state != TaskState::Submitted {
        t.transition_to(state, 2).expect("the state");
    }
    t
}

fn delivery(id: &str) -> Delivery {
    Delivery::of(&task(id, TaskState::Working)).expect("a callback")
}

#[test]
fn only_a_transport_error_a_5xx_or_a_429_is_retried() {
    for end in [
        Attempted::Transport,
        Attempted::Status(429),
        Attempted::Status(500),
        Attempted::Status(503),
        Attempted::Status(599),
    ] {
        assert!(end.retryable(), "{end:?}");
    }
    for end in [
        Attempted::Delivered,
        Attempted::Judged(DEST_METADATA),
        Attempted::Status(400),
        Attempted::Status(404),
        Attempted::Status(428),
        Attempted::Status(600),
        Attempted::Status(302),
    ] {
        assert!(!end.retryable(), "{end:?}");
    }
    assert_eq!(Attempted::of_status(204), Attempted::Delivered);
    assert_eq!(Attempted::of_status(300), Attempted::Status(300));
    assert_eq!(Attempted::of_status(199), Attempted::Status(199));
}

#[test]
fn the_wait_is_the_base_moved_by_at_most_twenty_percent() {
    assert_eq!((jittered_ms(250, 0), jittered_ms(250, 255)), (200, 300));
    assert_eq!((jittered_ms(500, 0), jittered_ms(500, 255)), (400, 600));
    for byte in 0..=u8::MAX {
        let w = jittered_ms(250, byte);
        assert!((200..=300).contains(&w), "{byte}: {w}");
    }
}

#[test]
fn a_failing_receiver_gets_three_attempts_at_250_then_500_ms_and_no_fourth() {
    let d = Deliveries::new();
    d.enqueue(delivery("t1"), 0);
    assert_eq!(d.due(0).len(), 1);
    // The low end of the first wait (250 - 20 %), then the high end of the second (500 + 20 %).
    assert_eq!(
        d.settle("t1", Attempted::Status(503), 0, 0),
        Settled::Retry(200 * MS)
    );
    assert!(d.due(199 * MS).is_empty(), "nothing before its time");
    assert_eq!(d.next_tick_ns(), 200 * MS);
    assert_eq!(d.due(200 * MS).len(), 1);
    assert_eq!(
        d.settle("t1", Attempted::Transport, 200 * MS, 255),
        Settled::Retry(800 * MS)
    );
    assert_eq!(d.due(800 * MS).len(), 1);
    assert_eq!(
        d.settle("t1", Attempted::Status(429), 800 * MS, 0),
        Settled::Done(vocab::EV_PUSH_FAILED)
    );
    assert!(d.due(u64::MAX).is_empty(), "no fourth attempt");
    assert_eq!((d.depth("t1"), d.next_tick_ns()), (0, 0));
}

#[test]
fn a_refused_destination_or_a_4xx_ends_the_delivery_at_once() {
    let d = Deliveries::new();
    d.enqueue(delivery("a"), 0);
    d.enqueue(delivery("b"), 0);
    d.enqueue(delivery("c"), 0);
    assert_eq!(d.due(0).len(), 3);
    assert_eq!(
        d.settle("a", Attempted::Judged(DEST_METADATA), 0, 0),
        Settled::Done(vocab::EV_PUSH_REFUSED)
    );
    assert_eq!(
        d.settle("b", Attempted::Status(404), 0, 0),
        Settled::Done(vocab::EV_PUSH_FAILED)
    );
    assert_eq!(
        d.settle("c", Attempted::Delivered, 0, 0),
        Settled::Done(vocab::EV_PUSH_DELIVERED)
    );
    assert_eq!(d.settle("c", Attempted::Delivered, 0, 0), Settled::Unknown);
    assert_eq!(d.next_tick_ns(), 0);
}

#[test]
fn a_tasks_notifications_go_out_in_order_one_at_a_time() {
    let d = Deliveries::new();
    let mut first = delivery("t1");
    first.body = b"first".to_vec();
    let mut second = delivery("t1");
    second.body = b"second".to_vec();
    d.enqueue(first, 0);
    d.enqueue(second, 0);
    d.enqueue(delivery("t2"), 0);
    let due = d.due(0);
    let bodies: Vec<&[u8]> = due
        .iter()
        .filter(|x| x.task_id == "t1")
        .map(|x| x.body.as_slice())
        .collect();
    assert_eq!(bodies, [b"first".as_slice()]);
    assert_eq!(due.len(), 2, "t2 does not wait on t1");
    assert!(
        d.due(0).is_empty(),
        "an open attempt is not handed out twice"
    );
    assert_eq!(
        d.next_tick_ns(),
        0,
        "no tick is wanted while every head is open"
    );
    // A retry holds the task's later notifications behind it.
    d.settle("t1", Attempted::Status(500), 0, 0);
    assert!(d.due(199 * MS).is_empty());
    assert_eq!(d.due(200 * MS)[0].body, b"first");
    d.settle("t1", Attempted::Delivered, 200 * MS, 0);
    assert_eq!(d.due(200 * MS)[0].body, b"second");
}

#[test]
fn a_full_queue_drops_its_oldest_waiting_notification_and_counts_it() {
    let d = Deliveries::new();
    for i in 0..QUEUE_CAPACITY {
        let mut x = delivery("t1");
        x.body = i.to_string().into_bytes();
        assert!(!d.enqueue(x, 0));
    }
    assert_eq!((d.depth("t1"), d.dropped()), (QUEUE_CAPACITY, 0));
    let mut newest = delivery("t1");
    newest.body = b"newest".to_vec();
    assert!(d.enqueue(newest, 0));
    assert_eq!((d.depth("t1"), d.dropped()), (QUEUE_CAPACITY, 1));
    assert_eq!(d.due(0)[0].body, b"1", "the oldest was the one dropped");
    // The head is now open: the next drop takes the oldest WAITING one, never the attempt.
    assert!(d.enqueue(delivery("t1"), 0));
    assert_eq!(d.dropped(), 2);
    assert_eq!(
        d.settle("t1", Attempted::Delivered, 0, 0),
        Settled::Done(vocab::EV_PUSH_DELIVERED)
    );
    assert_eq!(d.due(0)[0].body, b"3");
}

#[test]
fn the_request_is_a_post_to_the_callbacks_path_with_the_credential_only_once_held() {
    let d = Deliveries::new();
    let x = delivery("t1");
    let bare = d.request(&x);
    assert_eq!(bare.method, b"POST");
    assert_eq!(bare.target, b"/cb/t1?k=v");
    assert_eq!(
        bare.fields,
        [(b"content-type".to_vec(), b"application/json".to_vec())]
    );
    assert_eq!(bare.body, x.body);
    d.remember_auth(
        "t1",
        Some(DeliveryAuth {
            scheme: "Bearer".into(),
            credentials: "s3cret".into(),
        }),
    );
    assert_eq!(
        d.request(&x).fields[1],
        (b"authorization".to_vec(), b"Bearer s3cret".to_vec())
    );
    d.remember_auth("t1", None);
    assert_eq!(
        d.request(&x).fields.len(),
        1,
        "a withdrawn credential is not sent"
    );
}

#[test]
fn a_terminal_tasks_last_delivery_forgets_its_credential() {
    let d = Deliveries::new();
    let auth = DeliveryAuth {
        scheme: "Basic".into(),
        credentials: String::new(),
    };
    d.remember_auth("t1", Some(auth));
    let last = Delivery::of(&task("t1", TaskState::Completed)).expect("a callback");
    assert!(last.terminal);
    d.enqueue(last.clone(), 0);
    assert_eq!(d.request(&last).fields[1].1, b"Basic");
    let _ = d.due(0);
    d.settle("t1", Attempted::Delivered, 0, 0);
    assert_eq!(d.request(&last).fields.len(), 1);
}

#[test]
fn the_credential_never_prints() {
    let auth = DeliveryAuth {
        scheme: "Bearer".into(),
        credentials: "s3cret".into(),
    };
    assert!(!format!("{auth:?}").contains("s3cret"));
    assert_eq!(auth.header_value(), "Bearer s3cret");
}

#[test]
fn the_notification_is_the_task_nested_under_task_with_an_rfc3339_timestamp() {
    let t = task("t1", TaskState::Completed);
    let body: serde_json::Value = serde_json::from_slice(&notification_body(&t)).expect("JSON");
    assert_eq!(
        body,
        serde_json::json!({"task": {"id": "t1", "contextId": "ctx", "kind": "task",
            "status": {"state": "completed", "timestamp": "1970-01-01T00:00:02Z"}}})
    );
    assert!(body.get("jsonrpc").is_none());
    let mut silent = t;
    silent.push_callback = None;
    assert_eq!(
        Delivery::of(&silent),
        None,
        "no callback, nothing to deliver"
    );
}

#[test]
fn a_callback_token_names_its_one_task_and_nothing_else() {
    let tokens = Tokens::new();
    let random = [7u8; TOKEN_BYTES];
    let token = tokens.mint("task.a", &random).expect("minted");
    assert_eq!(tokens.task_of(&token).as_deref(), Some("task.a"));
    assert_eq!(
        tokens.mint("task.a", &[9u8; TOKEN_BYTES]),
        Some(token.clone())
    );
    let other = tokens.mint("task.b", &[8u8; TOKEN_BYTES]).expect("minted");
    let (_, b_secret) = other.rsplit_once('.').expect("a token");
    for forged in [
        format!("task.a.{b_secret}"),
        "task.a".to_string(),
        "task.a.".to_string(),
        format!("task.c.{b_secret}"),
        String::new(),
        ".".to_string(),
    ] {
        assert_eq!(tokens.task_of(&forged), None, "{forged}");
    }
    tokens.forget("task.a");
    assert_eq!(tokens.task_of(&token), None, "a forgotten token is refused");
    assert_eq!(tokens.mint("t", &[1u8; TOKEN_BYTES - 1]), None);
    assert_eq!(tokens.mint("", &random), None);
}

#[test]
fn tokens_are_bounded() {
    let tokens = Tokens::new();
    let random = [3u8; TOKEN_BYTES];
    for i in 0..MAX_TOKENS {
        assert!(tokens.mint(&i.to_string(), &random).is_some());
    }
    assert_eq!(tokens.mint("one-more", &random), None);
    assert!(
        tokens.mint("0", &random).is_some(),
        "a held one is still answered"
    );
}

#[test]
fn the_statement_declares_one_outbound_open_web_need_whose_target_the_plane_names() {
    use crate::door::{NEEDS, NEED_OPEN_WEB};
    use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_OPEN_WEB};
    use busbar_contract::abi::mechanism::check::check_needs;
    let st = &crate::plane_door::STATEMENT;
    assert!(!st.needs.is_null());
    assert_eq!((st.needs_len, NEEDS.len()), (1, 1));
    assert!(check_needs(NEEDS).is_ok());
    let need = NEEDS[NEED_OPEN_WEB as usize];
    assert_eq!(
        (need.direction, need.egress_class),
        (DIRECTION_OUTBOUND, EGRESS_OPEN_WEB)
    );
    assert_eq!(
        need.transport.len,
        crate::claims::DOCUMENT_TRANSPORT.len(),
        "the http claim"
    );
    assert_eq!(
        (need.auth.len, need.target_from.len, need.trust_from.len),
        (0, 0, 0),
        "no auth style, no configured target: the plane names each dial's target"
    );
}
