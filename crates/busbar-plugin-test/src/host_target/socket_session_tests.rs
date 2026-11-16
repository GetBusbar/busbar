// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{
    InstanceLimits, KindCode, Limits, NeedErr, OpenNeed, Security, SocketCaller, SocketSession,
    SocketTargets, TlsMode, TlsProfile, TrustSource,
};
use std::future::{poll_fn, Future};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn targets(addr: std::net::SocketAddr) -> SocketTargets {
    let mut targets = SocketTargets::new(Limits {
        connect: Duration::from_secs(2),
        io: Duration::from_secs(2),
        live: 1,
        idle: 1,
        idle_lifetime: Duration::from_secs(2),
        read: 1024,
    })
    .unwrap();
    targets
        .allow("database", addr, Security::Plaintext)
        .unwrap();
    targets
}
fn caller() -> SocketCaller {
    SocketCaller {
        plugin: "session-test".into(),
        kind: KindCode::Store,
        name: "database".into(),
        limits: InstanceLimits::default(),
    }
}
fn request(dest: &str) -> OpenNeed<'_> {
    OpenNeed {
        dest,
        tls: TlsMode::None,
        egress: 2,
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn run(future: impl Future<Output = ()>) {
    crate::test_rt::TestRuntime::new().unwrap().block_on(future);
}

#[test]
fn session_bytes_eof_and_terminal_state_share_one_runtime() {
    run(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dest = addr.to_string();
        let mut session = SocketSession::open(targets(addr), caller(), deadline(), request(&dest))
            .await
            .unwrap();
        let report = session.report();
        let (mut peer, _) = listener.accept().await.unwrap();
        session.write_all(b"request").await.unwrap();
        let mut request_bytes = [0; 7];
        peer.read_exact(&mut request_bytes).await.unwrap();
        assert_eq!(&request_bytes, b"request");
        peer.write_all(b"answer").await.unwrap();
        let mut answer = [0; 6];
        let mut received = 0;
        while received < answer.len() {
            let n = session.read_into(&mut answer[received..]).await.unwrap();
            assert_ne!(n, 0);
            received += n;
        }
        assert_eq!(&answer, b"answer");
        drop(peer);
        assert_eq!(session.read_into(&mut answer).await.unwrap(), 0);
        assert_eq!(session.read_into(&mut answer).await, Err(NeedErr::Closed));
        assert_eq!(session.write_all(b"late").await, Err(NeedErr::Closed));
        session.close();
        session.close();
        drop(session);
        report.finish().unwrap();
    });
}

#[test]
fn canceling_a_polled_read_closes_the_retained_session() {
    run(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dest = addr.to_string();
        let mut session = SocketSession::open(targets(addr), caller(), deadline(), request(&dest))
            .await
            .unwrap();
        let report = session.report();
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut byte = [0];
        let mut read = Box::pin(session.read_into(&mut byte));
        poll_fn(|cx| {
            assert!(read.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(read);
        assert_eq!(session.read_into(&mut byte).await, Err(NeedErr::Closed));
        assert_eq!(session.write_all(b"late").await, Err(NeedErr::Closed));
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        report.finish().unwrap();
        drop(session);
    });
}

#[test]
fn dropping_an_unpolled_operation_keeps_the_session_open() {
    run(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dest = addr.to_string();
        let mut session = SocketSession::open(targets(addr), caller(), deadline(), request(&dest))
            .await
            .unwrap();
        let report = session.report();
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut byte = [0];
        drop(session.read_into(&mut byte));
        session.write_all(b"x").await.unwrap();
        peer.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'x']);
        drop(session);
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        report.finish().unwrap();
    });
}

#[test]
fn invalid_read_budget_closes_instead_of_leaking_a_live_slot() {
    run(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dest = addr.to_string();
        let mut session = SocketSession::open(targets(addr), caller(), deadline(), request(&dest))
            .await
            .unwrap();
        let report = session.report();
        assert_eq!(session.read_into(&mut []).await, Err(NeedErr::Limit));
        assert_eq!(session.write_all(b"late").await, Err(NeedErr::Closed));
        report.finish().unwrap();
    });
}

#[test]
fn standalone_sessions_reject_other_callers_and_expired_opens() {
    run(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dest = addr.to_string();
        let report = Arc::new(targets(addr));
        let mut wrong = caller();
        wrong.name = "another-instance".into();
        assert!(matches!(
            SocketSession::open_shared(Arc::clone(&report), wrong, deadline(), request(&dest))
                .await,
            Err(NeedErr::Denied)
        ));
        report.finish().unwrap();
        let report = Arc::new(targets(addr));
        assert!(matches!(
            SocketSession::open_shared(
                Arc::clone(&report),
                caller(),
                Instant::now(),
                request(&dest)
            )
            .await,
            Err(NeedErr::Timeout)
        ));
        report.finish().unwrap();
    });
}

#[test]
fn tls_cannot_silently_use_an_explicit_plaintext_target() {
    run(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dest = addr.to_string();
        let report = Arc::new(targets(addr));
        assert!(matches!(
            SocketSession::open_shared(
                Arc::clone(&report),
                caller(),
                deadline(),
                OpenNeed {
                    dest: &dest,
                    tls: TlsMode::Required {
                        sni: "localhost",
                        alpn: "",
                        trust: 0
                    },
                    egress: 2,
                }
            )
            .await,
            Err(NeedErr::Denied)
        ));
        assert!(report.events().is_empty());
        report.finish().unwrap();
    });
}

#[test]
fn standalone_sessions_refuse_profiles_that_require_a_binder() {
    run(async {
        let addr = "127.0.0.1:12345".parse().unwrap();
        let mut target = targets(addr);
        target.targets.clear();
        target
            .allow(
                "database",
                addr,
                Security::Tls(TlsProfile {
                    server_name: "localhost".into(),
                    alpn: vec![],
                    trust: TrustSource::Bound {
                        pointer: "/ca".into(),
                    },
                    client: None,
                }),
            )
            .unwrap();
        let report = Arc::new(target);
        let dest = addr.to_string();
        assert!(matches!(
            SocketSession::open_shared(
                Arc::clone(&report),
                caller(),
                deadline(),
                OpenNeed {
                    dest: &dest,
                    tls: TlsMode::Inband {
                        sni: "localhost",
                        alpn: "",
                        trust: 1,
                        cert: None,
                    },
                    egress: 2
                }
            )
            .await,
            Err(NeedErr::Denied)
        ));
        report.finish().unwrap();
    });
}

#[test]
fn a_failed_upgrade_closes_the_session_without_plaintext_continuation() {
    run(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dest = addr.to_string();
        let mut session = SocketSession::open(targets(addr), caller(), deadline(), request(&dest))
            .await
            .unwrap();
        let report = session.report();
        let (mut peer, _) = listener.accept().await.unwrap();
        assert_eq!(
            session
                .starttls(TlsMode::Required {
                    sni: "localhost",
                    alpn: "",
                    trust: 0,
                })
                .await,
            Err(NeedErr::Invalid)
        );
        assert_eq!(
            session.write_all(b"must not reach peer").await,
            Err(NeedErr::Closed)
        );
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        report.finish().unwrap();
    });
}

#[test]
fn a_failed_network_open_leaves_no_physical_session() {
    run(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let report = Arc::new(targets(addr));
        let dest = addr.to_string();
        assert!(matches!(
            SocketSession::open_shared(Arc::clone(&report), caller(), deadline(), request(&dest))
                .await,
            Err(NeedErr::Unavailable)
        ));
        report.finish().unwrap();
    });
}

#[test]
fn distinct_sessions_allocate_distinct_private_identities() {
    run(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dest = addr.to_string();
        let first = SocketSession::open(targets(addr), caller(), deadline(), request(&dest))
            .await
            .unwrap();
        let second = SocketSession::open(targets(addr), caller(), deadline(), request(&dest))
            .await
            .unwrap();
        let first_report = first.report();
        let second_report = second.report();
        let a = &first_report.events()[0];
        let b = &second_report.events()[0];
        assert_ne!(a.instance, b.instance);
        assert_ne!(a.chain, b.chain);
        drop(first);
        drop(second);
        first_report.finish().unwrap();
        second_report.finish().unwrap();
    });
}
