// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR'S OUT BUFFER (TRANSPORT-TLS T7): one contiguous run per flush, frame ends kept,
//! nothing the carrier took left readable, memory given back after a burst, and a buffer that
//! cannot grow fails only its own connection.

use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use super::*;
use crate::support::{worker, TestDoor};

const SENTINEL: &[u8] = b"Authorization: Bearer SENTINEL-T7-0123456789";

/// A far end that takes every byte and says nothing.
async fn sink() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 64 * 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A carrier of this test's own, so its crossings are counted for this connection only.
fn counting_via() -> (Arc<TestDoor>, Via) {
    let carrier = Arc::new(TestDoor::identity("t7-carrier"));
    let via = Via {
        door: Arc::clone(&carrier) as Arc<dyn FramerDoor>,
        io: crate::hostio::process(),
    };
    (carrier, via)
}

fn writes(carrier: &TestDoor) -> usize {
    carrier
        .carried
        .lock()
        .unwrap()
        .iter()
        .filter(|op| **op == "write")
        .count()
}

fn dial(target: &str) -> Dial {
    Dial {
        plaintext_accepted: false,
        target: target.to_owned(),
        tls: None,
        alpn: Arc::default(),
        open_timeout: Duration::from_secs(5),
        opening: None,
        head_words: Default::default(),
        anchors: None,
    }
}

async fn open_to_sink(via: &Via) -> Connection {
    let far = sink().await;
    let mut c = Connection::dial(Arc::new(TestDoor::identity("bytes")), via, dial(&far)).unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        futures::future::poll_fn(|cx| {
            let _ = c.poll_ready(cx);
            if c.is_open() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .expect("the connection opens");
    c
}

/// Flush until the carrier took everything queued.
async fn flushed_out(c: &mut Connection) {
    tokio::time::timeout(
        Duration::from_secs(5),
        futures::future::poll_fn(|cx| match c.flush(cx) {
            Err(f) => Poll::Ready(Err(f)),
            Ok(_) if c.out.is_empty() && c.ends.is_empty() => Poll::Ready(Ok(())),
            Ok(_) => Poll::Pending,
        }),
    )
    .await
    .expect("the far end takes the bytes")
    .expect("the flush succeeds");
}

/// A queue whose head was taken and whose new bytes do not fit after its end (where a ring
/// buffer wraps) is still ONE contiguous run: one flush is one carrier write.
#[test]
fn out_wraps_single_write() {
    worker().block_on(async {
        let (carrier, via) = counting_via();
        let mut c = open_to_sink(&via).await;
        c.queue(&[1_u8; 3000], false).unwrap();
        // The carrier took the first 2000 bytes.
        c.out.consume(2000);
        c.flushed += 2000;
        c.queue(&[2_u8; 2500], false).unwrap();
        assert_eq!(c.out.len(), 3500);
        let before = writes(&carrier);
        flushed_out(&mut c).await;
        assert_eq!(
            writes(&carrier) - before,
            1,
            "a wrapped queue is written in one carrier write"
        );
        assert_eq!(c.flushed, c.queued);
    });
}

/// Each frame end the carrier's wire states bounds a write; the absolute counters stay exact.
#[test]
fn out_partial_write_keeps_frame_ends() {
    worker().block_on(async {
        let (carrier, via) = counting_via();
        let mut c = open_to_sink(&via).await;
        let base = c.queued;
        c.queue(&[1_u8; 100], true).unwrap();
        c.queue(&[2_u8; 50], true).unwrap();
        assert_eq!(c.ends.len(), 2);
        assert_eq!(c.ends.front().map(|e| e.0), Some(base + 100));
        let before = writes(&carrier);
        flushed_out(&mut c).await;
        assert_eq!(writes(&carrier) - before, 2, "one write per frame end");
        assert!(c.ends.is_empty());
        assert_eq!(c.flushed, c.queued);
        assert_eq!(c.queued, base + 150);
    });
}

/// RED on dev (and against the front-memmove form): a request head with its `Authorization`
/// stayed readable in the out buffer after the carrier took it.
#[test]
fn out_holds_no_token_after_flush() {
    worker().block_on(async {
        let (_carrier, via) = counting_via();
        let mut c = open_to_sink(&via).await;
        let mut head = b"GET /v1/models HTTP/1.1\r\nHost: upstream\r\n".to_vec();
        head.extend_from_slice(SENTINEL);
        head.extend_from_slice(b"\r\n\r\n");
        c.queue(&head, true).unwrap();
        flushed_out(&mut c).await;
        assert!(c.out.is_empty());
        assert!(
            !c.out
                .allocation()
                .windows(SENTINEL.len())
                .any(|w| w == SENTINEL),
            "the flushed request head is wiped from the out buffer"
        );
    });
}

/// After a burst the drained buffer keeps at most `OUT_KEEP`.
#[test]
fn out_shrinks_after_burst() {
    worker().block_on(async {
        let (_carrier, via) = counting_via();
        let mut c = open_to_sink(&via).await;
        c.queue(&vec![3_u8; 200 * 1024], true).unwrap();
        assert!(c.out.capacity() > OUT_KEEP);
        flushed_out(&mut c).await;
        assert!(c.out.is_empty());
        assert!(
            c.out.capacity() <= OUT_KEEP,
            "a drained buffer gives back what it held above {OUT_KEEP}"
        );
    });
}

/// A buffer that cannot grow refuses this connection's write ("write buffer"); nothing is queued.
#[test]
fn out_overflow_fails_connection() {
    worker().block_on(async {
        let (_carrier, via) = counting_via();
        let mut c = open_to_sink(&via).await;
        let queued = c.queued;
        crate::secure_vec::refuse_growth(true);
        let r = c.queue(&[1_u8; 4096], true);
        crate::secure_vec::refuse_growth(false);
        assert_eq!(r, Err(Failure::Refused("write buffer".into())));
        assert_eq!(c.queued, queued, "nothing was queued");
        assert!(c.out.is_empty());
    });
}
