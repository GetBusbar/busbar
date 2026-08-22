// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EGRESS-slot tests, driven over the REAL recovery path and the REAL guarded transport against a
//! loopback HTTP mock. The plaintext hop's observed identity is honestly EMPTY (nothing was proved);
//! the SPKI-population path is the same `reqwest::tls::TlsInfo::peer_certificate` seam the a2a
//! transport pin tests already exercise against real TLS.

use super::*;
use crate::plane_host::{recover, with_dispatch_scope, HostState};
use busbar_plugin::hot::host::PlaneHostVtable;
use busbar_plugin::hot::pod::POD_VERSION;
use busbar_plugin::hot::{EgressDesc, EgressKind, EgressOpen, StatusClass};
use std::io::{Read, Write};
use std::net::TcpListener;

/// A dead-simple loopback HTTP/1.1 server that answers every connection with a fixed 200 body. Raw
/// TCP (no axum/tokio) so the test has no ambient runtime and the streaming thread's own runtime is
/// the only one in play — exactly the shape production runs in.
fn spawn_mock(body: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // Drain the request head; we do not vary on it.
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.flush();
        }
    });
    port
}

/// Build an `EgressDesc` borrowing `url`, on an allowlist scope that permits the loopback/plaintext
/// hop (cloud-metadata stays refused regardless — that is the guard, not the scope).
fn http_desc(url: &[u8]) -> EgressDesc {
    EgressDesc {
        size: std::mem::size_of::<EgressDesc>() as u32,
        version: POD_VERSION,
        kind: EgressKind::Http,
        _reserved: 0,
        allowlist_scope: SCOPE_ALLOW_PRIVATE | SCOPE_ALLOW_PLAINTEXT,
        _reserved2: 0,
        target_ptr: url.as_ptr(),
        target_len: url.len(),
        client_identity_ref: 0,
        credential_ref: 0,
        verb_ptr: std::ptr::null(),
        verb_len: 0,
        headers_ptr: std::ptr::null(),
        headers_len: 0,
        body_ptr: std::ptr::null(),
        body_len: 0,
        cred_header_ptr: std::ptr::null(),
        cred_header_len: 0,
        cred_scheme_ptr: std::ptr::null(),
        cred_scheme_len: 0,
    }
}

/// Drive `egress_poll` to EOF, returning everything the stream delivered.
fn drain(vt: &PlaneHostVtable, host: HostCtx, id: EgressId) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8];
    loop {
        let mut written: usize = 0;
        let class = (vt.egress_poll.unwrap())(host, id, buf.as_mut_ptr(), buf.len(), &mut written);
        assert_eq!(class, StatusClass::Ok, "poll must stay Ok until EOF");
        if written == 0 {
            break; // clean end of stream.
        }
        out.extend_from_slice(&buf[..written]);
    }
    out
}

#[test]
fn http_egress_opens_streams_and_close_reclaims() {
    let body: &[u8] = b"hello egress streaming world";
    let port = spawn_mock(body);
    let url = format!("http://127.0.0.1:{port}/");
    let desc = http_desc(url.as_bytes());

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        // SAFETY: live HostState minted by with_dispatch_scope.
        let state: &HostState = unsafe { recover(host) };
        let scope = state.scope;

        // ── OPEN ──────────────────────────────────────────────────────────────────────────────
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        let class = (vt.egress_open.unwrap())(host, &desc as *const EgressDesc, &mut out);
        assert_eq!(class, StatusClass::Ok, "loopback open must succeed");
        // SAFETY: Ok ⇒ the out-param is initialized.
        let open = unsafe { out.assume_init() };
        assert!(!open.id.is_none(), "a real EgressId is handed back");
        assert_eq!(open.head.status_code, 200, "observed status is reported");
        // The connect head is returned; on a plaintext hop the observed SPKI is honestly absent.
        assert_eq!(
            open.head.observed_spki_len, 0,
            "plaintext hop proves no peer identity"
        );

        // The arena registered the closer (leak-safety keystone).
        assert_eq!(scope.registered(), 1, "open registers exactly one arena closer");

        // ── STREAM ────────────────────────────────────────────────────────────────────────────
        let got = drain(vt, host, open.id);
        assert_eq!(got, body, "the full body streams back, chunk by chunk");

        // A poll after EOF stays Ok/0 (idempotent end).
        let mut written = 0usize;
        let mut b = [0u8; 8];
        assert_eq!(
            (vt.egress_poll.unwrap())(host, open.id, b.as_mut_ptr(), b.len(), &mut written),
            StatusClass::Ok
        );
        assert_eq!(written, 0);

        // ── WRITE (Phase-2 for Http) ────────────────────────────────────────────────────────────
        let payload = [1u8, 2, 3];
        assert_eq!(
            (vt.egress_write.unwrap())(host, open.id, payload.as_ptr(), payload.len()),
            StatusClass::Unsupported,
            "a known egress answers Unsupported for the duplex request body (Phase 2)"
        );

        // ── CLOSE + RECLAIM ─────────────────────────────────────────────────────────────────────
        assert_eq!(
            (vt.egress_close.unwrap())(host, open.id),
            StatusClass::Ok,
            "close reclaims the egress"
        );
        // Idempotent: a second close, a poll, and a write all read Gone now.
        assert_eq!((vt.egress_close.unwrap())(host, open.id), StatusClass::Gone);
        assert_eq!(
            (vt.egress_poll.unwrap())(host, open.id, b.as_mut_ptr(), b.len(), &mut written),
            StatusClass::Gone
        );
        assert_eq!(
            (vt.egress_write.unwrap())(host, open.id, payload.as_ptr(), payload.len()),
            StatusClass::Gone
        );
    });
}

#[test]
fn arena_drop_reclaims_an_unclosed_egress() {
    let body: &[u8] = b"leaked-then-reclaimed";
    let port = spawn_mock(body);
    let url = format!("http://127.0.0.1:{port}/");
    let desc = http_desc(url.as_bytes());

    let app = crate::test_support::TestApp::new().build();
    let leaked_id = with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        let class = (vt.egress_open.unwrap())(host, &desc as *const EgressDesc, &mut out);
        assert_eq!(class, StatusClass::Ok);
        // SAFETY: Ok ⇒ initialized.
        let open = unsafe { out.assume_init() };
        // Deliberately DO NOT close — the dispatch future ends with the egress still open.
        open.id
    });
    // The dispatch scope dropped: its arena Closer must have reclaimed the egress, so it is gone.
    assert!(
        !REGISTRY.lock().unwrap().contains_key(&leaked_id.0),
        "arena drop reclaims an egress the plane never closed (no leak)"
    );
}

#[test]
fn open_refuses_a_metadata_target_whatever_the_scope() {
    // Cloud-metadata is refused BEFORE allow_private is consulted, even on a permissive scope.
    let url = b"http://169.254.169.254/latest/meta-data/".to_vec();
    let desc = http_desc(&url);
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        let class = (vt.egress_open.unwrap())(host, &desc as *const EgressDesc, &mut out);
        assert_eq!(
            class,
            StatusClass::Refused,
            "the SSRF chokepoint refuses IMDS regardless of allowlist scope"
        );
    });
}

#[test]
fn open_and_poll_fail_closed_on_null_and_bad_kind() {
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        // Null desc → Refused, out untouched.
        assert_eq!(
            (vt.egress_open.unwrap())(host, std::ptr::null(), &mut out),
            StatusClass::Refused
        );
        // RawConn / Subprocess are honest Phase-2 Unsupported.
        for kind in [EgressKind::RawConn, EgressKind::Subprocess] {
            let url = b"http://example.test/".to_vec();
            let mut d = http_desc(&url);
            d.kind = kind;
            assert_eq!(
                (vt.egress_open.unwrap())(host, &d as *const EgressDesc, &mut out),
                StatusClass::Unsupported
            );
        }
        // Poll of an unknown id → Gone.
        let mut written = 0usize;
        let mut b = [0u8; 4];
        assert_eq!(
            (vt.egress_poll.unwrap())(host, EgressId(999_999), b.as_mut_ptr(), b.len(), &mut written),
            StatusClass::Gone
        );
    });
}
