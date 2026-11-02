// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Carrier EOF is not TLS close_notify; CONNECT has a stage bound inside the overall open.

use super::*;
use busbar_contract::abi::host::conn::connector::{
    CAUSE_CONNECT, CAUSE_DEADLINE, CAUSE_EXCHANGE, CAUSE_SECURITY,
};
use futures::future::poll_fn;
use std::future::Future;
use std::task::Poll;

fn tls_pair() -> (tokio_rustls::TlsAcceptor, Arc<rustls::ClientConfig>) {
    let (ca, leaf, key) = localhost_cert();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.into()],
            rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
        )
        .unwrap();
    let trust = busbar_contract::transport::trust::EgressTrust {
        extra_anchors: vec![ca],
        ..Default::default()
    };
    (
        tokio_rustls::TlsAcceptor::from(Arc::new(server)),
        Arc::new(crate::tls::client::build_client_config(&trust).unwrap()),
    )
}

fn secure_door() -> Arc<TestDoor> {
    Arc::new(TestDoor::new(
        "sec",
        &["sec"],
        &[],
        Knobs {
            secure_name: Some("localhost"),
            ..Knobs::default()
        },
    ))
}

/// The body is consumed before the peer closes, so an abrupt end cannot be mistaken for a

#[test]
fn tls_eof_requires_close_notify_and_fresh_retains_the_failure() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        for (clean, fresh) in [(false, false), (true, false), (false, true)] {
            let (acceptor, client) = tls_pair();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let far = listener.local_addr().unwrap().to_string();
            let (close, closing) = tokio::sync::oneshot::channel();
            let mut peers = tokio::task::JoinSet::new();
            peers.spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut secure = acceptor.accept(socket).await.unwrap();
                let mut ping = [0; 4];
                secure.read_exact(&mut ping).await.unwrap();
                assert_eq!(&ping, b"ping");
                secure.write_all(b"body").await.unwrap();
                secure.flush().await.unwrap();
                closing.await.unwrap();
                if clean {
                    secure.shutdown().await.unwrap();
                }
            });
            let mut d = dial(&far);
            d.tls = Some(client);
            d.opening = Some((Vec::new(), b"ping".to_vec().into()));
            let mut c = Connection::dial(secure_door(), &crate::support::via(), d).unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), gather(&mut c, 4))
                    .await
                    .expect("the TLS application body arrives"),
                b"body"
            );
            close.send(()).unwrap();
            peers.join_next().await.unwrap().unwrap();
            if fresh {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    poll_fn(|cx| {
                        let reusable = c.fresh(cx);
                        if c.live() {
                            Poll::Pending
                        } else {
                            assert!(!reusable);
                            Poll::Ready(())
                        }
                    }),
                )
                .await
                .expect("the closed socket is observed");
            }
            let answer = tokio::time::timeout(Duration::from_secs(5), next(&mut c))
                .await
                .expect("TLS closure is observed");
            if clean {
                assert_eq!(answer, Ok(None));
                assert_eq!(c.cause(), None);
            } else {
                let Err(Failure::Failed(text)) = answer else {
                    panic!("transport EOF must fail the TLS exchange: {answer:?}");
                };
                assert!(text.contains("close_notify"), "{text}");
                let expected = ConnCause {
                    stage: CAUSE_EXCHANGE,
                    text,
                };
                assert_eq!(c.cause(), Some(&expected));
                assert!(next(&mut c).await.is_err());
                assert_eq!(
                    c.cause(),
                    Some(&expected),
                    "the first cause survives repoll"
                );
            }
        }
    });
}

const CONNECT: &[u8] = b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n";

async fn read_connect(socket: &mut tokio::net::TcpStream) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(socket.read_u8().await.unwrap());
    }
    assert_eq!(head, CONNECT);
}

fn through(
    proxy: std::net::SocketAddr,
    timeout: Duration,
    config: Arc<rustls::ClientConfig>,
) -> (Connection, Arc<TestDoor>) {
    let door = secure_door();
    let mut d = dial("localhost:443");
    d.tls = Some(config);
    d.open_timeout = timeout;
    let c = Planned::locate(door.clone(), crate::support::via(), d)
        .unwrap()
        .dial_through(proxy, CONNECT.to_vec())
        .unwrap();
    (c, door)
}

/// Neither waiting for CONNECT nor the subsequent TLS handshake may extend a short overall

#[test]
fn the_overall_open_deadline_survives_connect_and_the_tls_transition() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        for answer_connect in [false, true] {
            let (_, client) = tls_pair();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = listener.local_addr().unwrap();
            let (stop, stopping) = tokio::sync::oneshot::channel();
            let (seen, observed) = tokio::sync::oneshot::channel();
            let mut peers = tokio::task::JoinSet::new();
            peers.spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                read_connect(&mut socket).await;
                if answer_connect {
                    socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();

                    let mut tls = [0; 5];
                    socket.read_exact(&mut tls).await.unwrap();
                    assert_eq!(tls[0], 22, "the TLS handshake follows CONNECT");
                }
                seen.send(()).unwrap();
                let _ = stopping.await;
            });
            let timeout = Duration::from_millis(300);
            let start = Instant::now();
            let (mut c, door) = through(proxy, timeout, client);
            let answer = tokio::time::timeout(Duration::from_secs(3), next(&mut c))
                .await
                .expect("the caller's short bound is not replaced by CONNECT's ten seconds");
            assert_eq!(answer, Err(Failure::Timeout));
            assert!(start.elapsed() >= timeout, "not before the caller's bound");
            tokio::time::timeout(Duration::from_secs(5), observed)
                .await
                .expect("the peer observed the tested protocol stage")
                .unwrap();
            assert_eq!(door.count("begin"), 0, "no framing before TLS finishes");
            assert_eq!(
                c.cause(),
                Some(&ConnCause {
                    stage: CAUSE_DEADLINE,
                    text: String::new(),
                })
            );
            stop.send(()).unwrap();
            peers.join_next().await.unwrap().unwrap();
        }
    });
}

/// A completed CONNECT no longer owns a timer. A real TLS handshake begun after its ten-second

#[test]
fn tls_after_connect_keeps_the_remaining_long_overall_budget() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        let (acceptor, client) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let mut peers = tokio::task::JoinSet::new();
        peers.spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_connect(&mut socket).await;
            socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            tokio::time::sleep(crate::proxy::CONNECT_HANDSHAKE + Duration::from_secs(1)).await;
            let mut secure = acceptor.accept(socket).await.unwrap();
            secure.write_all(b"after-connect").await.unwrap();
            secure.shutdown().await.unwrap();
        });
        let (mut c, door) = through(proxy, Duration::from_secs(60), client);
        let body = tokio::time::timeout(Duration::from_secs(30), gather(&mut c, 13))
            .await
            .expect("TLS retains the caller's budget after CONNECT");
        assert_eq!(body, b"after-connect");
        assert_eq!(door.count("begin"), 1);
        assert_eq!(next(&mut c).await, Ok(None));
        assert_eq!(c.cause(), None);
        peers.join_next().await.unwrap().unwrap();
    });
}

/// Keeping the caller's longer bound must not remove the existing CONNECT-only cap.
#[test]
fn an_unanswered_connect_still_has_its_own_bound() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        let (_, client) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let mut peers = tokio::task::JoinSet::new();
        peers.spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_connect(&mut socket).await;
            let _ = stopping.await;
        });
        let start = Instant::now();
        let (mut c, door) = through(proxy, Duration::from_secs(60), client);
        let answer = tokio::time::timeout(Duration::from_secs(20), next(&mut c))
            .await
            .expect("CONNECT keeps its own ten-second bound");
        assert_eq!(answer, Err(Failure::Timeout));
        assert!(start.elapsed() >= crate::proxy::CONNECT_HANDSHAKE);
        assert_eq!(door.count("begin"), 0);
        stop.send(()).unwrap();
        peers.join_next().await.unwrap().unwrap();
    });
}

#[test]
fn a_failed_write_whole_records_the_connection_cause() {
    worker().block_on(async {
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let mut c = Planned::carried(crate::support::via(), dial(&closed.to_string()))
            .unwrap()
            .dial_at(closed)
            .unwrap();
        let failure = tokio::time::timeout(
            Duration::from_secs(5),
            poll_fn(|cx| match c.write_whole(b"ping", cx) {
                Err(f) => Poll::Ready(f),
                Ok(_) => Poll::Pending,
            }),
        )
        .await
        .expect("the carrier refuses the closed port");
        assert!(matches!(failure, Failure::Refused(_)), "{failure:?}");
        let cause = c
            .cause()
            .cloned()
            .expect("write_whole retains its failure cause");
        assert_eq!(cause.stage, CAUSE_CONNECT);
        assert!(!cause.text.is_empty());
        assert_eq!(next(&mut c).await, Err(failure));
        assert_eq!(c.cause(), Some(&cause));
    });
}

#[test]
fn an_untrusted_midstream_upgrade_records_the_security_cause() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        let (acceptor, _) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = listener.local_addr().unwrap();
        let mut peers = tokio::task::JoinSet::new();
        peers.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(socket).await;
        });
        let mut c = Planned::carried(crate::support::via(), dial(&far.to_string()))
            .unwrap()
            .dial_at(far)
            .unwrap();
        poll_fn(|cx| c.poll_landed(cx)).await.unwrap();
        let client =
            Arc::new(crate::tls::client::build_client_config(&Default::default()).unwrap());
        let result =
            poll_fn(|cx| c.upgrade_secure(&client, "localhost", Duration::from_secs(5), cx)).await;
        assert!(matches!(result, Err(Failure::Refused(_))), "{result:?}");
        let expected = ConnCause {
            stage: CAUSE_SECURITY,
            text: rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
                .to_string(),
        };
        assert_eq!(c.cause(), Some(&expected));
        assert!(next(&mut c).await.is_err());
        assert_eq!(c.cause(), Some(&expected));
        drop(c);
        peers.join_next().await.unwrap().unwrap();
    });
}

/// The proxy has already buffered a valid 200, but the caller resumes after CONNECT's bound.

#[test]
fn a_buffered_connect_reply_cannot_erase_an_expired_stage_bound() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        let (_, client) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let (seen, mut observed) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let (written, buffered) = tokio::sync::oneshot::channel();
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let mut peers = tokio::task::JoinSet::new();
        peers.spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_connect(&mut socket).await;
            seen.send(()).unwrap();
            released.await.unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            written.send(()).unwrap();
            let _ = stopping.await;
        });
        let (mut c, door) = through(proxy, Duration::from_secs(60), client);
        poll_fn(|cx| {
            assert!(
                c.poll_landed(cx).is_pending(),
                "200 is still held by the fixture"
            );
            std::pin::Pin::new(&mut observed).poll(cx)
        })
        .await
        .unwrap();
        release.send(()).unwrap();
        buffered.await.unwrap();

        tokio::time::sleep(crate::proxy::CONNECT_HANDSHAKE + Duration::from_secs(1)).await;
        assert_eq!(poll_fn(|cx| c.poll_landed(cx)).await, Err(Failure::Timeout));
        assert_eq!(door.count("begin"), 0);
        assert_eq!(c.cause().map(|cause| cause.stage), Some(CAUSE_DEADLINE));
        stop.send(()).unwrap();
        peers.join_next().await.unwrap().unwrap();
    });
}

/// A TLS 1.3 server's first flight contains its Finished. Drive until that real flight is

#[test]
fn a_buffered_tls_finished_cannot_erase_an_expired_overall_bound() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        for late in [false, true] {
            let (acceptor, client) = tls_pair();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let far = listener.local_addr().unwrap().to_string();
            let (seen, mut observed) = tokio::sync::oneshot::channel();
            let (release, released) = tokio::sync::oneshot::channel();
            let (written, buffered) = tokio::sync::oneshot::channel();
            let (stop, stopping) = tokio::sync::oneshot::channel();
            let mut peers = tokio::task::JoinSet::new();
            peers.spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut tls = rustls::ServerConnection::new(acceptor.config().clone()).unwrap();
                let mut bytes = [0; 4096];
                while !tls.wants_write() {
                    let n = socket.read(&mut bytes).await.unwrap();
                    assert!(n > 0);
                    let mut received = &bytes[..n];
                    while !received.is_empty() {
                        assert!(tls.read_tls(&mut received).unwrap() > 0);
                        tls.process_new_packets().unwrap();
                    }
                }
                assert_eq!(
                    tls.protocol_version(),
                    Some(rustls::ProtocolVersion::TLSv1_3)
                );
                let mut flight = Vec::new();
                while tls.wants_write() {
                    tls.write_tls(&mut flight).unwrap();
                }
                seen.send(()).unwrap();
                released.await.unwrap();
                socket.write_all(&flight).await.unwrap();
                written.send(()).unwrap();
                let _ = stopping.await;
            });
            let mut d = dial(&far);
            d.tls = Some(client);
            d.open_timeout = Duration::from_secs(3);
            let door = secure_door();
            let mut c = Connection::dial(door.clone(), &crate::support::via(), d).unwrap();
            let deadline = c.open_deadline.unwrap();
            poll_fn(|cx| {
                assert!(
                    c.poll_piece(cx).is_pending(),
                    "the server flight is still held"
                );
                std::pin::Pin::new(&mut observed).poll(cx)
            })
            .await
            .unwrap();
            release.send(()).unwrap();
            buffered.await.unwrap();
            if late {
                tokio::time::sleep_until(tokio::time::Instant::from_std(
                    deadline + Duration::from_millis(100),
                ))
                .await;
            }
            let answer = tokio::time::timeout(
                Duration::from_secs(5),
                poll_fn(|cx| match c.poll_piece(cx) {
                    Poll::Ready(Err(f)) => Poll::Ready(Err(f)),
                    Poll::Ready(other) => panic!("the peer sends no application data: {other:?}"),
                    Poll::Pending if c.is_open() => Poll::Ready(Ok(())),
                    Poll::Pending => Poll::Pending,
                }),
            )
            .await
            .expect("the buffered flight is judged");
            if late {
                assert_eq!(answer, Err(Failure::Timeout));
                assert_eq!(door.count("begin"), 0);
                assert_eq!(c.cause().map(|cause| cause.stage), Some(CAUSE_DEADLINE));
            } else {
                assert_eq!(answer, Ok(()));
                assert_eq!(door.count("begin"), 1);
                assert_eq!(c.cause(), None);
            }
            stop.send(()).unwrap();
            peers.join_next().await.unwrap().unwrap();
        }
    });
}

/// A synchronous feed-loop spin cannot be interrupted by a Tokio timeout. Run this real TLS

#[test]
fn tls_close_notify_ignores_later_carrier_bytes_without_spinning() {
    const CHILD: &str = "BUSBAR_CONNECTOR_CLOSE_TAIL_CHILD";
    const WITNESS: &str = "BUSBAR_CONNECTOR_CLOSE_TAIL_WITNESS";
    if std::env::var_os(CHILD).is_none() {
        struct Probe {
            child: Option<std::process::Child>,
            dir: std::path::PathBuf,
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                if let Some(child) = self.child.as_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                let _ = std::fs::remove_file(self.dir.join("observed"));
                let _ = std::fs::remove_dir(&self.dir);
            }
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "busbar-connector-close-tail-{}-{nonce}",
            std::process::id(),
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut probe = Probe { child: None, dir };
        let module = module_path!().split_once("::").unwrap().1;
        let test =
            format!("{module}::tls_close_notify_ignores_later_carrier_bytes_without_spinning");
        probe.child = Some(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test, "--nocapture"])
                .env(CHILD, "1")
                .env(WITNESS, probe.dir.join("observed"))
                .spawn()
                .unwrap(),
        );
        let due = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = probe.child.as_mut().unwrap().try_wait().unwrap() {
                assert!(status.success(), "isolated TLS control failed: {status}");
                assert_eq!(
                    std::fs::read(probe.dir.join("observed")).unwrap(),
                    b"tail consumed"
                );
                return;
            }
            assert!(
                Instant::now() < due,
                "TLS close_notify tail made no progress"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        let (acceptor, client) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = listener.local_addr().unwrap().to_string();
        let (close, closing) = tokio::sync::oneshot::channel();
        let (tail, trailing) = tokio::sync::oneshot::channel();
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let mut peers = tokio::task::JoinSet::new();
        peers.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut secure = acceptor.accept(socket).await.unwrap();
            secure.write_all(b"body").await.unwrap();
            secure.flush().await.unwrap();
            closing.await.unwrap();
            secure.get_mut().1.send_close_notify();
            secure.flush().await.unwrap();
            trailing.await.unwrap();
            let (mut socket, _) = secure.into_inner();
            socket
                .write_all(b"bytes after authenticated TLS close")
                .await
                .unwrap();
            let _ = stopping.await;
        });
        let mut d = dial(&far);
        d.tls = Some(client);
        let mut c = Connection::dial(secure_door(), &crate::support::via(), d).unwrap();
        assert_eq!(gather(&mut c, 4).await, b"body");
        close.send(()).unwrap();
        assert_eq!(
            next(&mut c).await,
            Ok(None),
            "the TLS alert is authenticated"
        );
        assert!(!c.read_end, "the underlying carrier is still open");
        tail.send(()).unwrap();

        poll_fn(|cx| match c.read(cx) {
            Ok(true) => Poll::Ready(()),
            Ok(false) => Poll::Pending,
            Err(f) => panic!("post-close carrier bytes are ignored: {f}"),
        })
        .await;
        assert_eq!(next(&mut c).await, Ok(None));
        assert_eq!(c.cause(), None);
        stop.send(()).unwrap();
        peers.join_next().await.unwrap().unwrap();
    });
    std::fs::write(
        std::env::var_os(WITNESS).expect("parent owns witness"),
        b"tail consumed",
    )
    .unwrap();
}
