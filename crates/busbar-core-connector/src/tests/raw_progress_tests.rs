// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn handshake_metadata_retains_actual_optional_values_and_original_storage() {
    use busbar_contract::transport::wire::HandshakeInfo;
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let budget = ProcessAdmission::with_limits(1, 64, 8);
    let source = budget.connection_storage(AdmissionClass::Data);
    let info = HandshakeInfo::capture(&source, Some(b"h2"), Some("host")).unwrap();
    assert_eq!(info.alpn(), Some(b"h2".as_slice()));
    assert_eq!(info.server_name(), Some("host"));
    assert_eq!(budget.used(), (6, 6));
    let moved = info;
    assert_eq!(budget.used(), (6, 6));
    drop(moved);
    assert_eq!(budget.used(), (0, 0));
    let absent = HandshakeInfo::capture(&source, None, None).unwrap();
    assert_eq!(absent.alpn(), None);
    assert_eq!(absent.server_name(), None);
    let binary = HandshakeInfo::capture(&source, Some(&[255]), None).unwrap();
    assert_eq!(binary.alpn(), Some([255].as_slice()), "transport validation owns UTF8 refusal");
}

use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use busbar_contract::response_delivery::CarrierFault;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::RawCarrier;

enum Write {
    Pending,
    Count(usize),
    Fail,
}

struct Raw {
    writes: VecDeque<Write>,
    fail_read: bool,
    fail_flush: bool,
}

impl AsyncRead for Raw {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.fail_read {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncWrite for Raw {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.writes.pop_front().unwrap_or(Write::Count(bytes.len())) {
            Write::Pending => Poll::Pending,
            Write::Count(n) => Poll::Ready(Ok(n)),
            Write::Fail => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let length = bufs.iter().map(|b| b.len()).sum::<usize>();
        self.poll_write(cx, &vec![0; length])
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.fail_flush {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn raw(writes: impl IntoIterator<Item = Write>) -> RawCarrier<Raw> {
    RawCarrier::new(Raw {
        writes: writes.into_iter().collect(),
        fail_read: false,
        fail_flush: false,
    })
}

#[test]
fn pending_then_short_vectored_then_error_retains_only_actual_prefix() {
    let mut io = raw([Write::Pending, Write::Count(3), Write::Fail]);
    let progress = io.progress();
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let bufs = [IoSlice::new(b"ab"), IoSlice::new(b"cde")];
    assert!(Pin::new(&mut io)
        .poll_write_vectored(&mut cx, &bufs)
        .is_pending());
    assert_eq!(progress.snapshot().written_plaintext, 0);
    assert!(matches!(
        Pin::new(&mut io).poll_write_vectored(&mut cx, &bufs),
        Poll::Ready(Ok(3))
    ));
    assert!(matches!(
        Pin::new(&mut io).poll_write(&mut cx, b"de"),
        Poll::Ready(Err(_))
    ));
    let snapshot = progress.snapshot();
    assert_eq!(snapshot.accepted_plaintext, 3);
    assert_eq!(snapshot.written_plaintext, 3);
    assert_eq!(snapshot.complete_records_plaintext, 3);
    assert_eq!(snapshot.fault, Some(CarrierFault::Io));
    drop(io);
    assert_eq!(progress.snapshot(), snapshot);
}

#[test]
fn nonempty_zero_is_sticky_failure_but_empty_write_is_not() {
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut empty = raw([Write::Count(0)]);
    assert!(matches!(
        Pin::new(&mut empty).poll_write(&mut cx, b""),
        Poll::Ready(Ok(0))
    ));
    assert_eq!(empty.progress().snapshot().fault, None);
    let mut io = raw([Write::Count(0), Write::Count(1)]);
    assert!(matches!(
        Pin::new(&mut io).poll_write(&mut cx, b"x"),
        Poll::Ready(Err(_))
    ));
    assert_eq!(
        io.progress().snapshot().fault,
        Some(CarrierFault::WriteZero)
    );
    assert!(matches!(
        Pin::new(&mut io).poll_write(&mut cx, b"x"),
        Poll::Ready(Err(_))
    ));
    assert_eq!(
        io.inner.writes.len(),
        1,
        "no actual write after sticky fault"
    );
}

#[tokio::test]
async fn read_and_flush_errors_keep_prior_successful_write_evidence() {
    for read_error in [false, true] {
        let mut io = raw([Write::Count(1)]);
        io.write_all(b"x").await.expect("one actual byte");
        io.inner.fail_read = read_error;
        io.inner.fail_flush = !read_error;
        if read_error {
            assert!(io.read(&mut [0]).await.is_err());
        } else {
            assert!(io.flush().await.is_err());
        }
        let progress = io.progress().snapshot();
        assert_eq!(progress.written_plaintext, 1);
        assert_eq!(progress.fault, Some(CarrierFault::Io));
    }
}

#[tokio::test]
async fn real_tcp_factory_observes_the_socket_write_boundary() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let (client, accepted) =
        tokio::join!(tokio::net::TcpStream::connect(address), listener.accept());
    let mut client = super::tcp(client.expect("connect"));
    let (mut server, _) = accepted.expect("accept");
    let progress = client.progress();
    client.write_all(b"hello").await.expect("socket write");
    let mut bytes = [0; 5];
    server.read_exact(&mut bytes).await.expect("peer read");
    assert_eq!(&bytes, b"hello");
    assert_eq!(progress.snapshot().written_plaintext, 5);
    assert_eq!(progress.snapshot().fault, None);
}
