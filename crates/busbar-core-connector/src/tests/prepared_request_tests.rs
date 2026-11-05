// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use tokio::io::AsyncReadExt;

#[test]
fn prepared_request_sends_nothing_until_single_commit_on_same_socket() {
    worker().block_on(async {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (listener, target) = far_end().await;
            let c = serving(Arc::new(AtomicU64::new(0)));
            c.declare_over(OWNER, NeedId(0), "bytes").unwrap();
            let desc = OpenDesc {
                target: &target,
                body: Bytes::from_static(b"credential-bearing-request"),
                ..OpenDesc::default()
            };
            let conn = c.prepare_request(OWNER, NeedId(0), &desc, 1000).unwrap();
            loop {
                match c.facts(OWNER, conn) {
                    Ok(_) => break,
                    Err(ConnError::Pending) => tokio::task::yield_now().await,
                    other => panic!("unexpected facts: {other:?}"),
                }
            }
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 64];
            assert!(
                tokio::time::timeout(Duration::from_millis(20), socket.read(&mut bytes))
                    .await
                    .is_err(),
                "preparation must send no application bytes"
            );
            assert_eq!(
                c.write(OWNER, conn, b"early", true, false),
                Err(ConnError::Pending)
            );
            assert_eq!(
                c.commit_request(OTHER, conn, &desc, false),
                Err(ConnError::NotOwner)
            );
            let changed = OpenDesc {
                target: "127.0.0.1:1",
                ..desc.clone()
            };
            assert_eq!(
                c.commit_request(OWNER, conn, &changed, false),
                Err(ConnError::Refused)
            );
            assert_eq!(
                c.commit_request(OWNER, conn, &desc, true),
                Err(ConnError::AuthRefused)
            );
            c.commit_request(OWNER, conn, &desc, false).unwrap();
            assert_eq!(
                c.commit_request(OWNER, conn, &desc, false),
                Err(ConnError::Refused)
            );
            socket
                .read_exact(&mut bytes[..desc.body.len()])
                .await
                .unwrap();
            assert_eq!(&bytes[..desc.body.len()], &desc.body[..]);
            assert!(
                tokio::time::timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err(),
                "commit must reuse the prepared connection"
            );
            c.close(OWNER, conn).unwrap();
        })
        .await
        .expect("prepared request finishes");
    });
}

#[test]
fn prepared_request_commit_preserves_original_deadline_and_close() {
    worker().block_on(async {
        let (_listener, target) = far_end().await;
        let c = serving(Arc::new(AtomicU64::new(0)));
        c.declare_over(OWNER, NeedId(0), "bytes").unwrap();
        let desc = OpenDesc {
            target: &target,
            timeout_ms: 1,
            ..OpenDesc::default()
        };
        let conn = c.prepare_request(OWNER, NeedId(0), &desc, 1000).unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let extended = OpenDesc {
            timeout_ms: 60_000,
            ..desc.clone()
        };
        assert_eq!(
            c.commit_request(OWNER, conn, &extended, false),
            Err(ConnError::Timeout)
        );
        c.close(OWNER, conn).unwrap();
        assert_eq!(
            c.commit_request(OWNER, conn, &desc, false),
            Err(ConnError::Closed)
        );
    });
}

#[test]
fn prepared_request_late_head_deadline_starts_at_prepare() {
    worker().block_on(async {
        let (_listener, target) = far_end().await;
        let c = serving(Arc::new(AtomicU64::new(0)));
        c.declare_over(OWNER, NeedId(0), "bytes").unwrap();
        // FACTS can prepare before HEAD supplies the request's timeout.
        let desc = OpenDesc {
            target: &target,
            ..OpenDesc::default()
        };
        let conn = c.prepare_request(OWNER, NeedId(0), &desc, 1000).unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let head = OpenDesc {
            timeout_ms: 1,
            ..desc.clone()
        };
        assert_eq!(
            c.commit_request(OWNER, conn, &head, false),
            Err(ConnError::Timeout),
            "HEAD cannot restart the clock after the time spent preparing"
        );
        c.close(OWNER, conn).unwrap();
    });
}
