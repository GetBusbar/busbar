// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::serve::{neutral, Stated};
use busbar_kernel::plane_driver::{CallerEnd, HeadFields, Rendered};
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

/// Renders `fields` + `body` through the HTTP door's caller and returns its head block and data.
async fn rendered_wire(status: u32, fields: HeadFields, body: &[u8]) -> (Vec<u8>, bool, Bytes) {
    let (caller, mut rx) = caller();
    let response = neutral::render(
        &caller,
        Rendered {
            status,
            fields,
            body: body.to_vec(),
        },
    );
    let collect = async {
        let (block, end) = match rx.recv().await.unwrap() {
            (
                1,
                Op::Head {
                    status: stated,
                    fields,
                    end,
                    ..
                },
            ) => {
                assert_eq!(stated, status);
                (fields, end)
            }
            _ => panic!("expected the response head first"),
        };
        match rx.recv().await.unwrap() {
            (
                1,
                Op::Data {
                    bytes,
                    end: _,
                    done,
                },
            ) => {
                done.send(true).unwrap();
                (block, end, bytes)
            }
            _ => panic!("expected the whole body as the next op"),
        }
    };
    let ((), wire) = tokio::join!(response, collect);
    assert!(rx.try_recv().is_err(), "nothing follows the whole body");
    wire
}

fn lines(block: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(block)
        .split("\r\n")
        .filter(|line| !line.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

#[tokio::test]
async fn bodyful_rendered_refusal_states_its_length() {
    let body = br#"{"type":"error"}"#;
    let (block, end, bytes) = rendered_wire(
        400,
        vec![(b"content-type".to_vec(), b"application/json".to_vec())],
        body,
    )
    .await;
    let lines = lines(&block);
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("content-length:"))
            .collect::<Vec<_>>(),
        ["content-length: 16"],
        "a whole rendered refusal states exactly one length: {lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.starts_with("transfer-encoding:")),
        "a whole rendered refusal is not chunked: {lines:?}"
    );
    assert!(lines.contains(&"content-type: application/json".to_owned()));
    assert!(!end, "the head opens a body");
    assert_eq!(&bytes[..], body);
}

#[tokio::test]
async fn rendered_refusal_naming_its_framing_is_not_relengthed() {
    let body = br#"{"type":"error"}"#;
    for framing in [
        (b"Transfer-Encoding".to_vec(), b"chunked".to_vec()),
        (b"Content-Length".to_vec(), b"16".to_vec()),
    ] {
        let fields = vec![
            (b"content-type".to_vec(), b"application/json".to_vec()),
            framing,
        ];
        let expected = fields
            .iter()
            .flat_map(|(name, value)| {
                [name.as_slice(), &b": "[..], value.as_slice(), &b"\r\n"[..]].concat()
            })
            .collect::<Vec<u8>>();
        let (block, end, bytes) = rendered_wire(400, fields, body).await;
        assert_eq!(
            block,
            expected,
            "stated framing passes through with no added length: {:?}",
            String::from_utf8_lossy(&block)
        );
        assert!(!end);
        assert_eq!(&bytes[..], body);
    }
}
