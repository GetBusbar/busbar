// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARRIER READ (TRANSPORT-TLS T11-dev): the response bytes a carrier read land in this
//! thread's wiping scratch, and nothing of them is left behind once the read is handed on.

use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::support::{worker, TestDoor};

const SENTINEL: &[u8] = b"Authorization: Bearer SENTINEL-T11-0123456789";

/// An echo far end: every byte back.
async fn echo() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 4096];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn dial(target: &str) -> Dial {
    Dial {
        plaintext_accepted: false,
        target: target.to_owned(),
        tls: None,
        alpn: Vec::new(),
        open_timeout: Duration::from_secs(5),
        opening: None,
        head_words: Default::default(),
        anchors: None,
    }
}

/// Whether this thread's carrier-read scratch is all zero.
fn read_scratch_is_zero() -> bool {
    READ_SCRATCH.with(|slot| {
        let held = slot.take().expect("no read holds the scratch now");
        let zero = held.allocation().iter().all(|b| *b == 0);
        slot.set(Some(held));
        zero
    })
}

/// RED on dev (today's stack buffer keeps the response after `read`) and against a guard that
/// forgets its bytes without wiping them: between reads the scratch is all zero.
#[test]
fn carrier_read_scratch_zero_between_reads() {
    worker().block_on(async {
        let far = echo().await;
        let door = Arc::new(TestDoor::identity("bytes"));
        let mut c = Connection::dial(door, &crate::support::via(), dial(&far)).unwrap();
        let mut message = b"HTTP/1.1 200 OK\r\n".to_vec();
        message.extend_from_slice(SENTINEL);
        message.extend_from_slice(b"\r\n\r\n");
        let mut sent = 0;
        let mut got = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            futures::future::poll_fn(|cx| {
                if sent < message.len() {
                    match c.write(&message[sent..], false, false, cx) {
                        Ok(n) => sent += n,
                        Err(Failure::Pending) => {}
                        Err(f) => return Poll::Ready(Err(f)),
                    }
                }
                loop {
                    match c.poll_piece(cx) {
                        Poll::Ready(Ok(Some(p))) => got.extend(p.bytes),
                        Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                        Poll::Ready(Err(f)) => return Poll::Ready(Err(f)),
                        Poll::Pending => break,
                    }
                }
                if got.len() >= message.len() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }),
        )
        .await
        .expect("the echo comes back")
        .expect("the connection works");
        assert_eq!(got, message, "the read path still delivers every byte");
        assert!(
            read_scratch_is_zero(),
            "nothing of the response is left in the read scratch after the read"
        );
    });
}
