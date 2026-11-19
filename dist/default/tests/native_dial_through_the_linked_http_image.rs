// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NATIVE DIAL THROUGH THE LINKED HTTP IMAGE (deletion plan E2, half A): the connector's
//! `NativeConnection` dials a loopback upstream with the default distribution's own http transport image
//! (opened in its client role through the plugin test harness, the same admission and open the boot walk runs),
//! sends one request with a body, and hands the far end's answer back as the connection table's pieces: the head
//! as one field block with its status, the body, the end. Every byte the framer's session charged is returned to
//! its account when the connection is dropped.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::conn::PieceKind;
use busbar_contract::storage::{StorageAccount, StorageDenied, StorageSource};
use busbar_core_connector::native_dial::{
    locate, NativeCarrier, NativeConnection, NativeDial, NativeHead,
};
use busbar_plugin_abi::plane::CARRIER_HTTP;
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;

/// A storage account that counts what is reserved and not yet released.
#[derive(Default)]
struct Counted(AtomicUsize);

impl StorageAccount for Counted {
    fn try_reserve(&self, bytes: usize) -> Result<(), StorageDenied> {
        self.0.fetch_add(bytes, Ordering::SeqCst);
        Ok(())
    }
    fn release(&self, bytes: usize) {
        self.0.fetch_sub(bytes, Ordering::SeqCst);
    }
}

/// One loopback upstream: reads one request (head and its content-length body), keeps it, answers 200 `{"ok":1}`.
fn upstream() -> (u16, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the upstream");
    let port = listener.local_addr().expect("its address").port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&seen);
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("read timeout");
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 4096];
        let head_end = loop {
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let n = stream.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
        let len = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while buf.len() < head_end + len {
            let n = stream.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        *kept.lock().expect("the kept request") = buf;
        let body = br#"{"ok":1}"#;
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-upstream: yes\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(body);
        let _ = stream.flush();
        // Hold the connection open until the dialler closes it.
        let _ = stream.read(&mut chunk);
    });
    (port, seen)
}

#[test]
fn a_request_dialled_through_the_linked_http_image_reaches_the_upstream_and_its_answer_comes_back()
{
    let harness = Harness::admit_linked(&busbar_transport_http::PLUGIN, FakeNeeds::new())
        .expect("the linked http image admits");
    let port = harness
        .open_transport("busbar-transport-http", b"{}")
        .expect("the linked http image opens");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    busbar_core_connector::io::install_process_reactor(runtime.handle().clone());

    let (upstream_port, seen) = upstream();
    let account = Arc::new(Counted::default());
    let storage = StorageSource::new(Arc::clone(&account) as Arc<dyn StorageAccount>);
    let target = format!("http://127.0.0.1:{upstream_port}/v1/chat");
    let located = locate(&target).expect("http is in core's scheme table");
    assert_eq!(located.carrier, CARRIER_HTTP);
    assert!(!located.secure);

    let (status, block, body) = runtime.block_on(async {
        let mut conn = NativeConnection::dial(
            NativeCarrier {
                instance: Arc::from("busbar-transport-http"),
                port,
                carrier: CARRIER_HTTP,
                stall_ms: None,
            },
            NativeDial {
                located,
                addr: format!("127.0.0.1:{upstream_port}")
                    .parse()
                    .expect("an address"),
                also: Vec::new(),
                tls: None,
                anchors: None,
                open_timeout: Duration::from_secs(10),
                storage,
            },
        )
        .expect("the dial begins");
        let mut head = Some(NativeHead {
            method: b"POST".to_vec(),
            target: b"/v1/chat".to_vec(),
            fields: vec![
                ("content-type".to_owned(), b"application/json".to_vec()),
                ("authorization".to_owned(), b"Bearer upstream-key".to_vec()),
            ],
            body_len: Some(7),
            budget: Some(Duration::from_secs(20)),
        });
        let stream = std::future::poll_fn(|cx| conn.poll_send_head(cx, &mut head, true))
            .await
            .expect("the head is sent");
        let mut sent = 0;
        while sent < 7 {
            sent += std::future::poll_fn(|cx| {
                conn.poll_send_body(cx, stream, &br#"{"a":1}"#[sent..], true)
            })
            .await
            .expect("the body is sent");
        }
        let mut buf = vec![0_u8; 64 * 1024];
        let (mut status, mut block, mut body) = (None, Vec::new(), Vec::new());
        loop {
            let piece = tokio::time::timeout(
                Duration::from_secs(20),
                std::future::poll_fn(|cx| conn.poll_read(cx, stream, &mut buf)),
            )
            .await
            .expect("an answer within 20 s")
            .expect("a piece");
            match piece.kind {
                PieceKind::Fields => {
                    status = piece.status_code;
                    block.extend_from_slice(&buf[..piece.len]);
                }
                PieceKind::Body => body.extend_from_slice(&buf[..piece.len]),
                PieceKind::Completion => break,
                PieceKind::HookReply => panic!("a hook reply on a dial"),
            }
        }
        conn.finish(stream);
        assert!(
            conn.reusable(),
            "an ended exchange leaves the connection reusable"
        );
        conn.close();
        (status, block, body)
    });

    assert_eq!(status, Some(200));
    let block = String::from_utf8(block).expect("a text field block");
    assert!(block.contains("x-upstream: yes\r\n"), "{block}");
    assert_eq!(body, br#"{"ok":1}"#);
    let request =
        String::from_utf8(seen.lock().expect("the kept request").clone()).expect("a text request");
    assert!(
        request.starts_with("POST /v1/chat HTTP/1.1\r\n"),
        "{request}"
    );
    let lower = request.to_ascii_lowercase();
    assert!(
        lower.contains("authorization: bearer upstream-key\r\n"),
        "{request}"
    );
    assert!(request.ends_with(r#"{"a":1}"#), "{request}");
    assert_eq!(
        account.0.load(Ordering::SeqCst),
        0,
        "every byte the session charged is returned when the connection is dropped"
    );
}
