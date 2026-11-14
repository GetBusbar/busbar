// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[tokio::test]
async fn a_real_third_claim_nested_reply_preserves_opaque_status_fields_and_governance() {
    let _one = PUBLISHING.lock().await;
    let g = governed("nested-neutral-third-claim", true).await;
    let (status, body) = g.post("/call/nest:/framed/nested-opaque", true).await;
    assert_eq!(
        status, 200,
        "the parent's fixed operator response remains unchanged"
    );
    assert_eq!(
        body, "nested:70001:opaque child body:opaque-fields",
        "the actual parent reads the child status and duplicate opaque field bytes through unit.nest"
    );
    assert_eq!(
        g.requests().await,
        2,
        "both units use the parent's key and admission path"
    );
    assert_eq!(g.money.open_units(), 0);
    assert_eq!(g.post.open_units(), 0);
    let book = g.book.lock().unwrap();
    assert_eq!(book.audit_records.len(), 2);
    let parent = book
        .audit_records
        .iter()
        .find(|row| row.what.parent.is_none())
        .unwrap();
    let child = book
        .audit_records
        .iter()
        .find(|row| row.what.parent.is_some())
        .unwrap();
    assert_eq!(child.what.parent, Some(parent.what.unit_key));
    assert_eq!(child.subject, parent.subject);
    assert_eq!(child.origin_kind, "nested");
}

#[tokio::test]
async fn cancelling_a_nested_collector_drops_its_live_producer() {
    use busbar_kernel::plane_driver::CallerEnd as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(Arc::clone(&dropped));
    let (caller, reply) = super::super::IngressCaller::new();
    let unit = async move {
        let _guard = guard;
        caller.head(
            70_001,
            vec![(b"opaque field".to_vec(), b"\0value".to_vec())],
        );
        assert!(caller.write(b"one piece").await);
        std::future::pending::<()>().await;
        None
    };
    let mut collecting = Box::pin(reply.answer_nested(Box::pin(unit)));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(collecting.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(collecting);
    assert!(
        dropped.load(Ordering::Acquire),
        "the nested producer is owned by the collecting future"
    );
}

#[tokio::test]
async fn a_nested_collector_drains_backpressure_and_preserves_every_field_byte() {
    use busbar_kernel::host_services::NestReply;
    use busbar_kernel::plane_driver::CallerEnd as _;
    let (caller, reply) = super::super::IngressCaller::new();
    let fields = vec![
        (b"opaque field".to_vec(), b" \0\xffvalue ".to_vec()),
        (b"opaque field".to_vec(), b"second".to_vec()),
        (b"content-length".to_vec(), b"an opaque value".to_vec()),
    ];
    let sent = fields.clone();
    let unit = async move {
        caller.head(70_001, sent);
        for piece in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            assert!(caller.write(piece).await);
        }
        None
    };
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        reply.answer_nested(Box::pin(unit)),
    )
    .await
    .expect("the one-piece channel drains while its producer runs");
    let NestReply::Answered {
        status,
        fields: got,
        body,
    } = reply
    else {
        panic!("reply not answered")
    };
    assert_eq!(status, 70_001);
    assert_eq!(got, fields);
    assert_eq!(body, b"onetwothree");
}

#[tokio::test]
async fn a_rendered_nested_refusal_is_opaque_and_obeys_the_same_body_bound() {
    use busbar_kernel::host_services::NestReply;
    use busbar_kernel::plane_driver::Rendered;
    for oversized in [false, true] {
        let (_caller, reply) = super::super::IngressCaller::new();
        let fields = vec![(b"opaque field".to_vec(), b"\0value".to_vec())];
        let expected = fields.clone();
        let unit = async move {
            Some(Rendered {
                status: 70_001,
                fields,
                body: if oversized {
                    vec![0; super::super::NEST_REPLY_MAX + 1]
                } else {
                    b"refused".to_vec()
                },
            })
        };
        let reply = reply.answer_nested(Box::pin(unit)).await;
        if oversized {
            assert!(matches!(
                reply,
                NestReply::Failed(super::super::NEST_UNREAD)
            ));
        } else {
            let NestReply::Answered {
                status,
                fields,
                body,
            } = reply
            else {
                panic!("refusal not answered")
            };
            assert_eq!(status, 70_001);
            assert_eq!(fields, expected);
            assert_eq!(body, b"refused");
        }
    }
}

#[tokio::test]
async fn a_whole_nested_refusal_head_keeps_its_rendered_fields_and_states_no_length() {
    use busbar_kernel::host_services::NestReply;
    use busbar_kernel::plane_driver::CallerEnd as _;
    let (caller, reply) = super::super::IngressCaller::new();
    let fields = vec![
        (b"content-type".to_vec(), b"text/plain".to_vec()),
        (b"retry-after".to_vec(), b"1".to_vec()),
    ];
    let sent = fields.clone();
    let body = b"refused:429:over_budget";
    let unit = async move {
        // The HTTP length rule belongs to the HTTP door's caller; a nested caller's head stays
        // the opaque field bytes the refusal rendered.
        caller.head_whole(429, sent, body.len());
        assert!(caller.write(body).await);
        None
    };
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        reply.answer_nested(Box::pin(unit)),
    )
    .await
    .expect("the nested whole answer is collected");
    let NestReply::Answered {
        status,
        fields: got,
        body: collected,
    } = reply
    else {
        panic!("reply not answered")
    };
    assert_eq!(status, 429);
    assert_eq!(got, fields, "no framing field is added on a nested caller");
    assert!(!got
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(b"content-length")));
    assert_eq!(collected, body);
}
