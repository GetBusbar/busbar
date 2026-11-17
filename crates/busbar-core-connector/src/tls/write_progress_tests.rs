// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real TLS over a controlled test carrier, exercising outer poll result/evidence ordering.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use busbar_contract::crypto::{testing::rcgen, tls};
use busbar_contract::response_delivery::{CarrierFault, CarrierProgressReader};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

use super::write_progress::TrackedTls;

enum Step {
    Bytes(usize),
    Pending,
    Error(io::ErrorKind),
}

#[derive(Default)]
struct Script {
    enabled: bool,
    steps: VecDeque<Step>,
    written: usize,
    waiter: Option<Waker>,
    flush_error: bool,
}

struct ScriptIo {
    io: DuplexStream,
    script: Arc<Mutex<Script>>,
}

impl AsyncRead for ScriptIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for ScriptIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut script = self.script.lock().unwrap();
        if !script.enabled {
            drop(script);
            return Pin::new(&mut self.io).poll_write(cx, bytes);
        }
        match script.steps.pop_front().unwrap_or(Step::Pending) {
            Step::Bytes(limit) => {
                let n = limit.min(bytes.len());
                script.written += n;
                Poll::Ready(Ok(n))
            }
            Step::Pending => {
                script.waiter = Some(cx.waker().clone());
                Poll::Pending
            }
            Step::Error(kind) => Poll::Ready(Err(kind.into())),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slices: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let first = slices
            .iter()
            .find(|slice| !slice.is_empty())
            .map_or(&[][..], |slice| &slice[..]);
        self.poll_write(cx, first)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let script = self.script.lock().unwrap();
        if script.enabled {
            return Poll::Ready(if script.flush_error {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            });
        }
        drop(script);
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

async fn established() -> (
    TrackedTls<ScriptIo>,
    Arc<dyn CarrierProgressReader>,
    Arc<Mutex<Script>>,
) {
    established_with_limit(4).await
}

async fn established_with_limit(
    records: usize,
) -> (
    TrackedTls<ScriptIo>,
    Arc<dyn CarrierProgressReader>,
    Arc<Mutex<Script>>,
) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = cert.der().clone();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    let key = rustls_pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into();
    let server_config = tls::server_config(|builder| {
        builder
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
    })
    .unwrap();
    let client_config = tls::client_config(|builder| {
        Ok(builder.with_root_certificates(roots).with_no_client_auth())
    })
    .unwrap();
    let (client_io, server_io) = tokio::io::duplex(65536);
    let script = Arc::new(Mutex::new(Script::default()));
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    let connector = tokio_rustls::TlsConnector::from(client_config);
    let (client, server) = tokio::join!(
        connector.connect(
            rustls_pki_types::ServerName::try_from("localhost").unwrap(),
            client_io
        ),
        acceptor.accept(ScriptIo {
            io: server_io,
            script: script.clone()
        }),
    );
    let _client = client.unwrap();
    let mut server = server.unwrap();
    server.flush().await.unwrap();
    let (tracked, reader) = TrackedTls::new(server, records).unwrap();
    script.lock().unwrap().enabled = true;
    (tracked, reader, script)
}

fn arm(script: &Mutex<Script>, steps: impl IntoIterator<Item = Step>) {
    let mut script = script.lock().unwrap();
    script.steps = steps.into_iter().collect();
    if let Some(waiter) = script.waiter.take() {
        waiter.wake();
    }
}

#[tokio::test]
async fn plaintext_acceptance_while_socket_pending_never_grants_a_write_receipt() {
    let (mut stream, reader, script) = established().await;
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    arm(&script, [Step::Pending]);
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, b"body"),
        Poll::Ready(Ok(4))
    ));
    let progress = reader.snapshot();
    assert_eq!(progress.accepted_plaintext, 4);
    assert_eq!(progress.written_plaintext, 0);
    assert_eq!(progress.complete_records_plaintext, 0);
    assert_eq!(progress.fault, None);
    assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_pending());
    assert_eq!(reader.snapshot(), progress);
}

#[tokio::test]
async fn same_poll_raw_prefix_then_error_or_zero_retains_progress_for_scalar_and_vectored_writes() {
    for vectored in [false, true] {
        for zero in [false, true] {
            let (mut stream, reader, script) = established().await;
            arm(
                &script,
                [
                    Step::Bytes(6),
                    if zero {
                        Step::Bytes(0)
                    } else {
                        Step::Error(io::ErrorKind::BrokenPipe)
                    },
                ],
            );
            let mut cx = Context::from_waker(futures::task::noop_waker_ref());
            let result = if vectored {
                Pin::new(&mut stream).poll_write_vectored(
                    &mut cx,
                    &[io::IoSlice::new(b"bo"), io::IoSlice::new(b"dy")],
                )
            } else {
                Pin::new(&mut stream).poll_write(&mut cx, b"body")
            };
            let Poll::Ready(Err(error)) = result else {
                panic!("raw failure must be returned in this poll")
            };
            assert_eq!(
                error.kind(),
                if zero {
                    io::ErrorKind::WriteZero
                } else {
                    io::ErrorKind::BrokenPipe
                }
            );
            let progress = reader.snapshot();
            assert_eq!(progress.accepted_plaintext, 4);
            assert_eq!(progress.written_plaintext, 1);
            assert_eq!(progress.complete_records_plaintext, 0);
            if zero {
                assert_eq!(progress.fault, Some(CarrierFault::WriteZero));
            }
            assert_eq!(script.lock().unwrap().written, 6);
            drop(stream);
            assert_eq!(reader.snapshot(), progress);
        }
    }
}

#[tokio::test]
async fn completed_ciphertext_is_not_a_successful_failed_flush() {
    let (mut stream, reader, script) = established().await;
    arm(&script, [Step::Bytes(usize::MAX)]);
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, b"body"),
        Poll::Ready(Ok(4))
    ));
    let before = reader.snapshot();
    assert_eq!(before.complete_records_plaintext, 4);
    script.lock().unwrap().flush_error = true;
    assert!(matches!(
        Pin::new(&mut stream).poll_flush(&mut cx),
        Poll::Ready(Err(_))
    ));
    let after = reader.snapshot();
    assert_eq!(after.written_plaintext, 4);
    assert_eq!(after.complete_records_plaintext, 4);
}

#[tokio::test]
async fn zero_raw_write_never_strands_full_descriptor_capacity_as_pending() {
    for already_buffered in [false, true] {
        for vectored in [false, true] {
            let (mut stream, reader, script) = established_with_limit(1).await;
            let mut cx = Context::from_waker(futures::task::noop_waker_ref());
            if already_buffered {
                arm(&script, [Step::Pending]);
                assert!(matches!(
                    Pin::new(&mut stream).poll_write(&mut cx, b"first"),
                    Poll::Ready(Ok(5))
                ));
            }
            arm(&script, [Step::Bytes(0)]);
            let result = if vectored {
                Pin::new(&mut stream).poll_write_vectored(&mut cx, &[io::IoSlice::new(b"next")])
            } else {
                Pin::new(&mut stream).poll_write(&mut cx, b"next")
            };
            let Poll::Ready(Err(error)) = result else {
                panic!("zero must fail without waiting for a wake")
            };
            assert_eq!(error.kind(), io::ErrorKind::WriteZero);
            let progress = reader.snapshot();
            assert_eq!(
                progress.accepted_plaintext,
                if already_buffered { 5 } else { 4 }
            );
            assert_eq!(progress.written_plaintext, 0);
            assert_eq!(progress.complete_records_plaintext, 0);
            assert_eq!(progress.fault, Some(CarrierFault::WriteZero));
        }
    }
}
