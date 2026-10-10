// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO THREAD PER CONNECTION (`BUSBAR-1.6.0.md` THE DESIGN, §5 and §11.2): a worker opens 64 composed
//! connections to a real far end on its own runtime, moves bytes on each and closes them, and the
//! process runs no more threads than before; every framer crossing ran on the one worker thread.
//! The RED arm proves the count this reads sees a thread per connection when there is one.
//!
//! A binary of its own, its two tests serialized, so no other test's threads move the count.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_core_connector::compose::{Connection, Dial};
use busbar_core_connector::framer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[allow(dead_code)]
#[path = "../src/tests/support.rs"]
mod support;

use support::{thread_count, worker, TestDoor};

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

async fn echo() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0_u8; 4096];
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

async fn gather(c: &mut Connection, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < want {
        let p = futures::future::poll_fn(|cx| c.poll_piece(cx))
            .await
            .expect("a piece")
            .expect("not ended");
        got.extend(p.bytes);
    }
    got
}

fn dial(target: &str, first: Vec<u8>) -> Dial {
    Dial {
        target: target.to_owned(),
        tls: None,
        alpn: Vec::new(),
        open_timeout: Duration::from_secs(5),
        opening: Some((Vec::new(), first)),
        head_words: Default::default(),
        anchors: None,
    }
}

/// RED arm of the next test: the thread count this file reads DOES see a thread per connection.
#[test]
fn a_thread_per_connection_is_seen_by_the_count() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let before = thread_count();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let rx = Arc::new(std::sync::Mutex::new(rx));
    let held: Vec<_> = (0..16)
        .map(|_| {
            let rx = Arc::clone(&rx);
            std::thread::spawn(move || {
                let _ = rx.lock().unwrap().recv();
            })
        })
        .collect();
    let during = thread_count();
    drop(tx);
    for h in held {
        h.join().unwrap();
    }
    assert!(
        during >= before + 12,
        "sixteen parked threads are counted: {before} -> {during}"
    );
}

/// No thread per connection: 64 connections open, move bytes and close, and the process runs no
/// more threads than before the first; every framer crossing ran on the one worker thread.
#[test]
fn no_thread_per_connection() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let rt = worker();
    let before = thread_count();
    rt.block_on(async {
        let far = echo().await;
        let door = Arc::new(TestDoor::identity("bytes"));
        let mut conns = Vec::new();
        for i in 0..64_u8 {
            conns.push(Connection::dial(door.clone(), dial(&far, vec![i; 3])).unwrap());
        }
        let during = thread_count();
        for (i, c) in conns.iter_mut().enumerate() {
            assert_eq!(gather(c, 3).await, vec![i as u8; 3]);
        }
        for c in conns {
            c.close();
        }
        assert!(
            during <= before,
            "64 open connections, no new thread: {before} -> {during}"
        );
        assert_eq!(door.threads.lock().unwrap().len(), 1, "one worker thread");
    });
}
