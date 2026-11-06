// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::serve::{neutral, Stated};
use busbar_kernel::plane_driver::{CallerEnd, Rendered};
use std::sync::atomic::Ordering;

fn caller() -> (ActorCaller, mpsc::UnboundedReceiver<(u64, Op)>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (
        ActorCaller {
            out: Emitter { stream: 1, tx },
            stated: std::sync::Mutex::new(None),
            body: std::sync::Mutex::new(None),
            ended: std::sync::atomic::AtomicBool::new(false),
        },
        rx,
    )
}

#[tokio::test]
async fn empty_rendered_response_ends_in_its_initial_head() {
    let (caller, mut rx) = caller();
    neutral::render(
        &caller,
        Rendered {
            status: 200,
            fields: vec![(b"result-code".to_vec(), b"12".to_vec())],
            body: Vec::new(),
        },
    )
    .await;
    match rx.recv().await.unwrap() {
        (
            1,
            Op::Head {
                status,
                fields,
                end,
                ..
            },
        ) => {
            assert_eq!(status, 200);
            assert_eq!(fields, b"result-code: 12\r\n");
            assert!(
                end,
                "a complete empty response must end in its initial head"
            );
        }
        _ => panic!("expected one response head"),
    }
    assert!(caller.ended.load(Ordering::Acquire));
    assert_eq!(caller.stated(), Some(200));
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn bodyful_rendered_response_preserves_head_then_data() {
    let (caller, mut rx) = caller();
    let response = neutral::render(
        &caller,
        Rendered {
            status: 409,
            fields: Vec::new(),
            body: b"opaque refusal".to_vec(),
        },
    );
    let collect = async {
        assert!(matches!(
            rx.recv().await.unwrap(),
            (
                1,
                Op::Head {
                    status: 409,
                    end: false,
                    ..
                }
            )
        ));
        match rx.recv().await.unwrap() {
            (1, Op::Data { bytes, end, done }) => {
                assert_eq!(&bytes[..], b"opaque refusal");
                assert!(!end);
                done.send(true).unwrap();
            }
            _ => panic!("expected the unchanged body"),
        }
    };
    tokio::join!(response, collect);
    assert!(!caller.ended.load(Ordering::Acquire));
}

#[tokio::test]
async fn streaming_head_remains_immediate_and_trailers_end_separately() {
    use neutral::Output;
    let (caller, mut rx) = caller();
    caller.head(200, Vec::new());
    assert!(matches!(
        rx.try_recv().unwrap(),
        (1, Op::Head { end: false, .. })
    ));
    caller.trailers(vec![(b"result-code".to_vec(), b"0".to_vec())]);
    assert!(matches!(rx.try_recv().unwrap(), (1, Op::Trailers { .. })));
    assert!(caller.ended.load(Ordering::Acquire));
    assert!(rx.try_recv().is_err());
}
