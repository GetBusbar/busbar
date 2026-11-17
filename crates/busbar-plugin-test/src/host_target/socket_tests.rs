// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::fake_needs::{ConnScript, FakeNeeds};
use crate::sockets::{Limits, Security, SocketTargets};
use busbar_plugin_abi::host_side::caller::{CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::host_side::needs::{ConnId, NeedErr, Needs, OpenNeed, TlsMode};
use busbar_plugin_abi::need::open_flag;
use busbar_plugin_abi::types::KindCode;
use std::future::Future;
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
        kind: KindCode::Store,
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

fn certificate() -> (String, String) {
    let busbar_contract::crypto::testing::rcgen::CertifiedKey { cert, signing_key } =
        busbar_contract::crypto::testing::rcgen::generate_simple_self_signed(vec![
            "localhost".into()
        ])
        .unwrap();
    (cert.pem(), signing_key.serialize_pem())
}
async fn tls_echo(
    pem: &str,
    key: &str,
    inband: bool,
    alpn: Vec<Vec<u8>>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
    let config = busbar_contract::crypto::tls::server_config(move |builder| {
        let mut config = builder.with_no_client_auth().with_single_cert(chain, key)?;
        config.alpn_protocols = alpn;
        Ok(config)
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
            tokio::spawn(async move {
                if inband {
                    let mut request = [0; 4];
                    if stream.read_exact(&mut request).await.is_err() {
                        return;
                    }
                    assert_eq!(&request, b"TLS?");
                    stream.write_all(b"OK").await.unwrap();
                }
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
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
fn tls_host(addr: std::net::SocketAddr, pem: &str, name: &str, alpn: Vec<String>) -> FakeNeeds {
    let mut targets = SocketTargets::new(limits()).unwrap();
    targets
        .allow(
            "db",
            addr,
            Security::Tls(crate::sockets::TlsProfile {
                server_name: name.into(),
                alpn,
                trust: crate::sockets::TrustSource::Explicit {
                    roots_pem: pem.into(),
                },
                client: None,
            }),
        )
        .unwrap();
    FakeNeeds::new().with_sockets(targets).unwrap()
}
fn tls_open<'a>(dest: &'a str, name: &'a str, alpn: &'a str) -> OpenNeed<'a> {
    OpenNeed {
        dest,
        tls: TlsMode::Required {
            sni: name,
            alpn,
            trust: 0,
        },
        egress: 2,
    }
}
#[test]
fn verified_tls_rejects_wrong_roots_names_and_alpn() {
    run(async {
        let (pem, key) = certificate();
        let (other, _) = certificate();
        let (addr, server) = tls_echo(&pem, &key, false, vec![]).await;
        let dest = addr.to_string();
        for (roots, name, alpn, works) in [
            (&pem, "localhost", "", true),
            (&other, "localhost", "", false),
            (&pem, "wrong.example", "", false),
            (&pem, "localhost", "required-protocol", false),
        ] {
            let needs = tls_host(
                addr,
                roots,
                name,
                if alpn.is_empty() {
                    vec![]
                } else {
                    vec![alpn.into()]
                },
            );
            let cx = caller(1);
            let got = needs.open_answer(&cx, tls_open(&dest, name, alpn)).await;
            if works {
                let a = got.unwrap();
                needs
                    .write_answer(&cx, ConnId(a.id), b"secret challenge")
                    .await
                    .unwrap();
                assert_eq!(
                    needs
                        .read_answer(&cx, ConnId(a.id), 32)
                        .await
                        .unwrap()
                        .bytes
                        .as_slice(),
                    b"secret challenge"
                );
            } else {
                assert!(matches!(got, Err(NeedErr::Tls)));
            }
            needs.release(&cx);
            needs.socket_report().unwrap().finish().unwrap();
        }
        server.abort();
    });
}
#[test]
fn inband_tls_is_verified_before_reuse_and_mismatches_discard() {
    run(async {
        let (pem, key) = certificate();
        let (addr, server) = tls_echo(&pem, &key, true, vec![]).await;
        let needs = tls_host(addr, &pem, "localhost", vec![]);
        let dest = addr.to_string();
        let cx = caller(1);
        let n = OpenNeed {
            dest: &dest,
            tls: TlsMode::Inband {
                sni: "localhost",
                alpn: "",
                trust: 0,
                cert: None,
            },
            egress: 2,
        };
        let a = needs.open_answer(&cx, n).await.unwrap();
        assert_eq!(a.flags & (open_flag::REUSED | open_flag::TLS_DONE), 0);
        needs
            .write_answer(&cx, ConnId(a.id), b"TLS?")
            .await
            .unwrap();
        assert_eq!(
            needs
                .read_answer(&cx, ConnId(a.id), 2)
                .await
                .unwrap()
                .bytes
                .as_slice(),
            b"OK"
        );
        let host = needs.socket_report().unwrap();
        host.starttls(
            &cx,
            a.id,
            TlsMode::Required {
                sni: "localhost",
                alpn: "",
                trust: 0,
            },
        )
        .await
        .unwrap();
        needs.close(&cx, ConnId(a.id), true).await;
        needs.release(&cx);
        let cx = caller(2);
        let b = needs.open_answer(&cx, n).await.unwrap();
        assert_eq!(a.pooled, b.pooled);
        assert_eq!(
            b.flags & (open_flag::REUSED | open_flag::TLS_DONE),
            open_flag::REUSED | open_flag::TLS_DONE
        );
        needs
            .write_answer(&cx, ConnId(b.id), b"already encrypted")
            .await
            .unwrap();
        assert_eq!(
            needs
                .read_answer(&cx, ConnId(b.id), 32)
                .await
                .unwrap()
                .bytes
                .as_slice(),
            b"already encrypted"
        );
        needs.close(&cx, ConnId(b.id), false).await;
        let c = needs.open_answer(&cx, n).await.unwrap();
        assert!(matches!(
            host.starttls(
                &cx,
                c.id,
                TlsMode::Required {
                    sni: "wrong",
                    alpn: "",
                    trust: 0
                }
            )
            .await,
            Err(NeedErr::Invalid)
        ));
        needs.release(&cx);
        host.finish().unwrap();
        server.abort();
    });
}
#[test]
fn instance_binder_maps_identical_handles_to_its_own_trust_and_revokes_on_unbind() {
    run(async {
        use crate::suites::harness::MemBinder;
        use busbar_ports::binder::ConfigBinder;
        use std::sync::Arc;
        let (pem, key) = certificate();
        let (other, _) = certificate();
        let (addr, server) = tls_echo(&pem, &key, false, vec![]).await;
        let mut targets = SocketTargets::new(limits()).unwrap();
        targets
            .allow(
                "db",
                addr,
                Security::Tls(crate::sockets::TlsProfile {
                    server_name: "localhost".into(),
                    alpn: vec![],
                    trust: crate::sockets::TrustSource::Bound {
                        pointer: "/ca".into(),
                    },
                    client: None,
                }),
            )
            .unwrap();
        let needs = Arc::new(FakeNeeds::new().with_sockets(targets).unwrap());
        let binder = MemBinder::over(needs.clone());
        let json = |pem: &str| {
            busbar_contract::json::to_vec(&std::collections::BTreeMap::from([("ca", pem)])).unwrap()
        };
        let first = binder
            .bind(1, &json(&pem), &[], &["/ca"], &[], &[])
            .unwrap();
        let second = binder
            .bind(2, &json(&other), &[], &["/ca"], &[], &[])
            .unwrap();
        assert_eq!(first, second, "both config views hold handle 1");
        let dest = addr.to_string();
        let n = OpenNeed {
            dest: &dest,
            tls: TlsMode::Required {
                sni: "localhost",
                alpn: "",
                trust: 1,
            },
            egress: 2,
        };
        let cx = caller(1);
        let a = needs.open_answer(&cx, n).await.unwrap();
        let mut other_cx = caller(2);
        other_cx.instance = 2;
        assert!(matches!(
            needs.open_answer(&other_cx, n).await,
            Err(NeedErr::Tls)
        ));
        let bad = OpenNeed {
            tls: TlsMode::Required {
                sni: "localhost",
                alpn: "",
                trust: 2,
            },
            ..n
        };
        assert!(matches!(
            needs.open_answer(&cx, bad).await,
            Err(NeedErr::Denied)
        ));
        binder.unbind(1);
        assert!(matches!(
            needs.write_answer(&cx, ConnId(a.id), b"revoked").await,
            Err(NeedErr::Invalid)
        ));
        needs.release(&cx);
        needs.release(&other_cx);
        needs.socket_report().unwrap().finish().unwrap();
        server.abort();
    });
}
#[test]
fn dropped_operation_and_release_during_tls_leave_no_capacity_lease() {
    run(async {
        let (addr, server) = echo().await;
        let needs = host(addr);
        let cx = caller(1);
        let a = needs
            .open_answer(&cx, open(&addr.to_string()))
            .await
            .unwrap();
        {
            let pending = needs.read_answer(&cx, ConnId(a.id), 1);
            tokio::pin!(pending);
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(pending.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
        }
        needs.release(&cx);
        needs.socket_report().unwrap().finish().unwrap();
        server.abort();
        let (pem, _) = certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let needs = tls_host(addr, &pem, "localhost", vec![]);
        let dest = addr.to_string();
        let cx = caller(3);
        let pending = needs.open_answer(&cx, tls_open(&dest, "localhost", ""));
        tokio::pin!(pending);
        let accepted = tokio::select! {result=&mut pending=>panic!("TLS unexpectedly completed: {}",result.is_ok()),result=listener.accept()=>result.unwrap()};
        needs.release(&cx);
        assert!(matches!(pending.await, Err(NeedErr::Closed)));
        drop(accepted);
        needs.socket_report().unwrap().finish().unwrap();
    });
}
#[test]
fn bounded_reads_eof_capacity_and_required_finish() {
    run(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"abcdef").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let needs = host(addr);
        let cx = caller(1);
        let a = needs
            .open_answer(&cx, open(&addr.to_string()))
            .await
            .unwrap();
        assert!(needs.socket_report().unwrap().finish().is_err());
        assert!(matches!(
            needs.read_answer(&cx, ConnId(a.id), 1025).await,
            Err(NeedErr::Limit)
        ));
        let mut bytes = Vec::new();
        loop {
            let read = needs.read_answer(&cx, ConnId(a.id), 2).await.unwrap();
            if read.eof {
                break;
            }
            assert!(read.bytes.len() <= 2);
            bytes.extend_from_slice(read.bytes.as_slice());
        }
        assert_eq!(bytes, b"abcdef");
        needs.release(&cx);
        needs.socket_report().unwrap().finish().unwrap();
        server.await.unwrap();
    });
}
#[test]
fn unserved_failure_cannot_be_hidden_by_omitting_finish() {
    assert!(std::panic::catch_unwind(|| {
        let targets = SocketTargets::new(limits()).unwrap();
        targets.failure("test-unserved");
    })
    .is_err());
    let targets = SocketTargets::new(limits()).unwrap();
    targets.expect_failure("test-unserved", 1);
    assert!(targets.finish().is_err());
    targets.failure("test-unserved");
    targets.finish().unwrap();
    assert!(std::panic::catch_unwind(|| {
        let targets = SocketTargets::new(limits()).unwrap();
        targets.expect_failure("test-unserved", 1);
        targets.failure("test-unserved");
        targets.failure("test-unserved");
        assert!(targets.finish().is_err());
    })
    .is_err());
}

#[test]
fn reservation_release_before_connect_and_close_release_race_are_safe() {
    run(async {
        let (addr, server) = echo().await;
        let needs = host(addr);
        let cx = caller(1);
        let dest = addr.to_string();
        let target = needs.socket_report().unwrap();
        let opening = target.prepare(&cx, open(&dest), 99, 99).unwrap();
        target.release(&cx);
        assert!(
            target.finish().is_err(),
            "reservation counts until the future actually releases it"
        );
        assert!(matches!(opening.run().await, Err(NeedErr::Closed)));
        target.finish().unwrap();
        for chain in 1..=16 {
            let needs = std::sync::Arc::new(host(addr));
            let cx = caller(chain);
            let first = needs.open_answer(&cx, open(&dest)).await.unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let closing = needs.clone();
            let signal = barrier.clone();
            let thread = std::thread::spawn(move || {
                signal.wait();
                run(async {
                    closing.close(&cx, ConnId(first.id), true).await;
                });
            });
            barrier.wait();
            needs.release(&cx);
            thread.join().unwrap();
            let next = caller(chain + 100);
            let opened = needs.open_answer(&next, open(&dest)).await.unwrap();
            needs
                .write_answer(&next, ConnId(opened.id), b"q")
                .await
                .unwrap();
            assert_eq!(
                needs
                    .read_answer(&next, ConnId(opened.id), 1)
                    .await
                    .unwrap()
                    .bytes
                    .as_slice(),
                b"q"
            );
            needs.release(&next);
            needs.socket_report().unwrap().finish().unwrap();
        }
        server.abort();
    });
}
#[test]
fn capacity_and_pool_keys_never_alias_instances_or_egress() {
    run(async {
        let (addr, server) = echo().await;
        let dest = addr.to_string();
        let mut targets = SocketTargets::new(Limits {
            live: 2,
            ..limits()
        })
        .unwrap();
        targets.allow("db", addr, Security::Plaintext).unwrap();
        let needs = FakeNeeds::new().with_sockets(targets).unwrap();
        let cx = caller(1);
        let a = needs.open_answer(&cx, open(&dest)).await.unwrap();
        let b = needs.open_answer(&cx, open(&dest)).await.unwrap();
        assert!(matches!(
            needs.open_answer(&cx, open(&dest)).await,
            Err(NeedErr::Limit)
        ));
        needs.close(&cx, ConnId(a.id), true).await;
        needs.close(&cx, ConnId(b.id), false).await;
        let mut foreign = caller(2);
        foreign.instance = 2;
        let f = needs.open_answer(&foreign, open(&dest)).await.unwrap();
        assert_eq!(
            f.flags & open_flag::REUSED,
            0,
            "another instance never borrows the idle socket"
        );
        needs.close(&foreign, ConnId(f.id), false).await;
        let c = needs
            .open_answer(
                &cx,
                OpenNeed {
                    egress: 4,
                    ..open(&dest)
                },
            )
            .await
            .unwrap();
        assert_ne!(c.pooled, a.pooled);
        assert_eq!(c.flags & open_flag::REUSED, 0);
        needs.release(&cx);
        needs.release(&foreign);
        needs.socket_report().unwrap().finish().unwrap();
        server.abort();
    });
}
#[test]
fn declared_client_identity_is_bound_and_verified_without_exposing_its_key() {
    run(async {
        use crate::suites::harness::MemBinder;
        use busbar_ports::binder::ConfigBinder;
        use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
        use std::sync::Arc;
        let (server_pem, server_key) = certificate();
        let (client_pem, client_key) = certificate();
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(client_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let verifier =
            busbar_contract::crypto::tls::client_verifier(Arc::new(roots), |b| b).unwrap();
        let chain = CertificateDer::pem_slice_iter(server_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(server_key.as_bytes()).unwrap();
        let config = busbar_contract::crypto::tls::server_config(move |b| {
            b.with_client_cert_verifier(verifier)
                .with_single_cert(chain, key)
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(config)
                .accept(socket)
                .await
                .unwrap();
            assert!(!tls.get_ref().1.peer_certificates().unwrap().is_empty());
            tls.write_all(b"verified").await.unwrap();
        });
        let mut targets = SocketTargets::new(limits()).unwrap();
        targets
            .allow(
                "db",
                addr,
                Security::Tls(crate::sockets::TlsProfile {
                    server_name: "localhost".into(),
                    alpn: vec![],
                    trust: crate::sockets::TrustSource::Explicit {
                        roots_pem: server_pem,
                    },
                    client: Some(crate::sockets::ClientSource {
                        pointer: "/identity".into(),
                    }),
                }),
            )
            .unwrap();
        let mut needs = FakeNeeds::new();
        FakeNeeds::secret(
            &mut needs,
            "/identity",
            format!("{client_pem}{client_key}").as_bytes(),
        );
        let needs = Arc::new(needs.with_sockets(targets).unwrap());
        let binder = MemBinder::over(needs.clone());
        binder
            .bind(
                1,
                br#"{"identity":{"env":"CLIENT_IDENTITY"}}"#,
                &["/identity"],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let cx = caller(1);
        let dest = addr.to_string();
        assert!(matches!(
            needs
                .open_answer(
                    &cx,
                    OpenNeed {
                        dest: &dest,
                        tls: TlsMode::Mutual {
                            sni: "localhost",
                            alpn: "",
                            trust: 0,
                            cert: 2
                        },
                        egress: 2
                    }
                )
                .await,
            Err(NeedErr::Denied)
        ));
        let a = needs
            .open_answer(
                &cx,
                OpenNeed {
                    dest: &dest,
                    tls: TlsMode::Mutual {
                        sni: "localhost",
                        alpn: "",
                        trust: 0,
                        cert: 1,
                    },
                    egress: 2,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            needs
                .read_answer(&cx, ConnId(a.id), 32)
                .await
                .unwrap()
                .bytes
                .as_slice(),
            b"verified"
        );
        needs.release(&cx);
        needs.socket_report().unwrap().finish().unwrap();
        server.await.unwrap();
    });
}

#[test]
fn idle_expiry_tls_mode_mismatch_and_overlap_are_closed() {
    run(async {
        let (addr, server) = echo().await;
        let dest = addr.to_string();
        let mut targets = SocketTargets::new(Limits {
            idle_lifetime: Duration::from_nanos(1),
            ..limits()
        })
        .unwrap();
        targets.allow("db", addr, Security::Plaintext).unwrap();
        let mut needs = FakeNeeds::new().with_sockets(targets).unwrap();
        let cx = caller(1);
        let a = needs.open_answer(&cx, open(&dest)).await.unwrap();
        needs.close(&cx, ConnId(a.id), true).await;
        let b = needs.open_answer(&cx, open(&dest)).await.unwrap();
        assert_ne!(a.pooled, b.pooled);
        assert_eq!(b.flags & open_flag::REUSED, 0);
        assert!(matches!(
            needs
                .open_answer(&cx, tls_open(&dest, "localhost", ""))
                .await,
            Err(NeedErr::Denied)
        ));
        needs.release(&cx);
        needs.socket_report().unwrap().expect_failure("overlap", 1);
        needs.conn(&dest, ConnScript::new());
        assert!(matches!(
            needs.open_answer(&cx, open(&dest)).await,
            Err(NeedErr::Denied)
        ));
        needs.socket_report().unwrap().finish().unwrap();
        server.abort();
    });
}
