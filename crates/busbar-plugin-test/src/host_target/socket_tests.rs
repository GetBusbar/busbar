// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::fake_needs::{ConnScript, FakeNeeds};
use crate::sockets::{Limits, Security, SocketTargets};
use busbar_plugin_abi::host_side::caller::{CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::host_side::needs::{ConnId, NeedErr, Needs, OpenNeed, TlsMode};
use busbar_plugin_abi::need::open_flag;
use busbar_plugin_abi::types::KindCode;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn limits() -> Limits {
    Limits {
        connect: Duration::from_secs(2),
        io: Duration::from_secs(2),
        live: 4,
        idle: 4,
        idle_lifetime: Duration::from_secs(10),
        read: 1024,
    }
}
fn caller(chain: u64) -> Caller<'static> {
    Caller {
        plugin: "socket-test",
        kind: KindCode::STORE,
        name: "db",
        instance: 1,
        slot: 0,
        chain,
        deadline: Instant::now() + Duration::from_secs(3),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}
fn open(dest: &str) -> OpenNeed<'_> {
    OpenNeed {
        dest,
        tls: TlsMode::None,
        egress: 2,
    }
}
fn run(f: impl std::future::Future<Output = ()>) {
    crate::test_rt::TestRuntime::new().unwrap().block_on(f);
}
async fn echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut bytes = [0; 1024];
                while let Ok(n) = stream.read(&mut bytes).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&bytes[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, task)
}
fn host(addr: std::net::SocketAddr) -> FakeNeeds {
    let mut sockets = SocketTargets::new(limits()).unwrap();
    sockets.allow("db", addr, Security::Plaintext).unwrap();
    FakeNeeds::new().with_sockets(sockets).unwrap()
}

#[test]
fn actual_bytes_and_reusable_physical_identity() {
    run(async {
        let (addr, server) = echo().await;
        let needs = host(addr);
        let dest = addr.to_string();
        let cx = caller(1);
        let a = needs.open_answer(&cx, open(&dest)).await.unwrap();
        let mut challenge = [0; 32];
        busbar_contract::crypto::fill(&mut challenge).unwrap();
        assert_eq!(
            needs
                .write_answer(&cx, ConnId(a.id), &challenge)
                .await
                .unwrap(),
            32
        );
        let read = needs.read_answer(&cx, ConnId(a.id), 32).await.unwrap();
        assert_eq!(read.bytes.as_slice(), challenge);
        needs.close(&cx, ConnId(a.id), true).await;
        needs.release(&cx);
        let next = caller(2);
        let b = needs.open_answer(&next, open(&dest)).await.unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(a.pooled, b.pooled);
        assert_eq!(b.flags & open_flag::REUSED, open_flag::REUSED);
        needs.close(&next, ConnId(b.id), false).await;
        let c = needs.open_answer(&next, open(&dest)).await.unwrap();
        assert_ne!(c.pooled, b.pooled);
        needs.release(&next);
        needs.socket_report().unwrap().finish().unwrap();
        server.abort();
    });
}

#[test]
fn scripts_and_sockets_share_ids_in_both_open_orders() {
    run(async {
        let (addr, server) = echo().await;
        for live_first in [false, true] {
            let mut needs = host(addr);
            needs.conn("script:1", ConnScript::new().expect(b"x").reply(b"y"));
            let cx = caller(1);
            let dest = addr.to_string();
            let first = if live_first { &dest } else { "script:1" };
            let second = if live_first { "script:1" } else { &dest };
            let a = needs.open_answer(&cx, open(first)).await.unwrap();
            let b = needs.open_answer(&cx, open(second)).await.unwrap();
            assert_ne!(a.id, b.id);
            assert_ne!(a.pooled, b.pooled);
            let (live, script) = if live_first { (a, b) } else { (b, a) };
            needs
                .write_answer(&cx, ConnId(script.id), b"x")
                .await
                .unwrap();
            needs
                .write_answer(&cx, ConnId(live.id), b"z")
                .await
                .unwrap();
            assert_eq!(
                needs
                    .read_answer(&cx, ConnId(script.id), 1)
                    .await
                    .unwrap()
                    .bytes
                    .as_slice(),
                b"y"
            );
            assert_eq!(
                needs
                    .read_answer(&cx, ConnId(live.id), 1)
                    .await
                    .unwrap()
                    .bytes
                    .as_slice(),
                b"z"
            );
            needs.close(&cx, ConnId(script.id), false).await;
            needs.release(&cx);
            needs.socket_report().unwrap().finish().unwrap();
        }
        server.abort();
    });
}

#[test]
fn release_revokes_a_pending_read_without_dropping_its_future() {
    run(async {
        let (addr, server) = echo().await;
        let needs = host(addr);
        let cx = caller(1);
        let a = needs
            .open_answer(&cx, open(&addr.to_string()))
            .await
            .unwrap();
        let read = needs.read_answer(&cx, ConnId(a.id), 1);
        tokio::pin!(read);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(read.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        needs.release(&cx);
        assert!(matches!(read.await, Err(NeedErr::Closed)));
        needs.socket_report().unwrap().finish().unwrap();
        server.abort();
    });
}

#[test]
fn caller_deadline_and_unknown_ownership_are_authoritative() {
    run(async {
        let (addr, server) = echo().await;
        let needs = host(addr);
        let mut cx = caller(1);
        cx.deadline = Instant::now();
        assert!(matches!(
            needs.open_answer(&cx, open(&addr.to_string())).await,
            Err(NeedErr::Timeout)
        ));
        cx = caller(2);
        let a = needs
            .open_answer(&cx, open(&addr.to_string()))
            .await
            .unwrap();
        let mut foreign = cx;
        foreign.chain += 1;
        assert!(matches!(
            needs.read_answer(&foreign, ConnId(a.id), 1).await,
            Err(NeedErr::Invalid)
        ));
        cx.deadline = Instant::now() + Duration::from_millis(20);
        assert!(matches!(
            needs.read_answer(&cx, ConnId(a.id), 1).await,
            Err(NeedErr::Timeout)
        ));
        needs.release(&cx);
        needs.socket_report().unwrap().finish().unwrap();
        server.abort();
    });
}

#[test]
fn targets_refuse_non_loopback_and_invalid_limits() {
    let mut sockets = SocketTargets::new(limits()).unwrap();
    assert!(sockets
        .allow("db", "192.0.2.1:1234".parse().unwrap(), Security::Plaintext)
        .is_err());
    assert!(sockets
        .allow(
            "db",
            "[::ffff:192.0.2.1]:1234".parse().unwrap(),
            Security::Plaintext
        )
        .is_err());
    assert!(sockets
        .allow(
            "db",
            "[::ffff:127.0.0.1]:1234".parse().unwrap(),
            Security::Plaintext
        )
        .is_ok());
    let mut bad = limits();
    bad.live = 0;
    assert!(SocketTargets::new(bad).is_err());
}
