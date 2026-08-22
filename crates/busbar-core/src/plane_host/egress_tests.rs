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
use busbar_plugin::hot::{
    AuthQuery, AuthResolved, EgressDesc, EgressKind, EgressOpen, StatusClass,
};
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

/// A loopback HTTP/1.1 server that ECHOES the raw request bytes it received back in the response
/// body, so a test can assert exactly what the transport put on the wire (method line, headers,
/// body). Returns the port and a handle to the captured request bytes.
fn spawn_echo_mock() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let seen = &buf[..n];
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                seen.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(seen);
            let _ = stream.flush();
        }
    });
    port
}

/// Pack a header set into the ABI's length-prefixed wire form (`u32 name_len | name | u32 val_len |
/// val`, little-endian), the form [`EgressDesc::headers_ptr`] carries.
fn pack_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in headers {
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out
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
        // RawConn is an honest Phase-2 Unsupported (it joins the pipe tier with no ABI change).
        {
            let url = b"http://example.test/".to_vec();
            let mut d = http_desc(&url);
            d.kind = EgressKind::RawConn;
            assert_eq!(
                (vt.egress_open.unwrap())(host, &d as *const EgressDesc, &mut out),
                StatusClass::Unsupported
            );
        }
        // Subprocess IS wired (the pipe tier), so a non-command target is REFUSED at the host command
        // allowlist (undecodable blob / not an absolute program), never spawned.
        {
            let url = b"http://example.test/".to_vec();
            let mut d = http_desc(&url);
            d.kind = EgressKind::Subprocess;
            assert_eq!(
                (vt.egress_open.unwrap())(host, &d as *const EgressDesc, &mut out),
                StatusClass::Refused
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

/// THE OUTBOUND-REQUEST PROOF: an `egress_open` carrying the enriched `EgressDesc` tail (verb + a
/// packed header set + a body) puts EXACTLY that request on the wire — the echo mock reflects the
/// method line, the plane's header, and the body back, and the poll seam reads them. This is the
/// capability the CLUSTER-3 (b) enrichment unlocked (the seam could only open a bodyless GET before).
#[test]
fn http_egress_sends_verb_headers_and_body() {
    let port = spawn_echo_mock();
    let url = format!("http://127.0.0.1:{port}/rpc");
    let headers = pack_headers(&[("x-plane-header", "plane-value")]);
    let body = br#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
    let verb = b"POST";
    let mut desc = http_desc(url.as_bytes());
    desc.verb_ptr = verb.as_ptr();
    desc.verb_len = verb.len();
    desc.headers_ptr = headers.as_ptr();
    desc.headers_len = headers.len();
    desc.body_ptr = body.as_ptr();
    desc.body_len = body.len();

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        let class = (vt.egress_open.unwrap())(host, &desc as *const EgressDesc, &mut out);
        assert_eq!(class, StatusClass::Ok, "the POST opens");
        // SAFETY: Ok ⇒ initialized.
        let open = unsafe { out.assume_init() };
        let echoed = String::from_utf8_lossy(&drain(vt, host, open.id)).into_owned();
        assert!(echoed.starts_with("POST /rpc "), "the verb + path were sent: {echoed:?}");
        assert!(
            echoed.to_ascii_lowercase().contains("x-plane-header: plane-value"),
            "the plane's header was forwarded verbatim"
        );
        assert!(
            echoed.contains(r#"{"jsonrpc":"2.0","method":"ping","id":1}"#),
            "the request body was sent"
        );
        let _ = (vt.egress_close.unwrap())(host, open.id);
    });
}

/// THE CREDENTIAL-FAITHFULNESS PROOF (CLUSTER-3 (d) + FLAG-4): the documented flow — the plane calls
/// `auth_resolve` to get an OPAQUE `resolved_ref`, then passes that ref (plus the neutral placement:
/// header name + scheme) to `egress_open`. The host reads the plaintext back out of ITS OWN mint
/// registry and injects `Authorization: Bearer <host-owned secret>` on the wire. The plane never held
/// the plaintext: the only credential value it ever saw is the opaque `resolved_ref`, which is NOT the
/// secret the echo mock reflects back.
#[test]
fn egress_open_injects_host_minted_credential_never_plane_plaintext() {
    let port = spawn_echo_mock();
    let url = format!("http://127.0.0.1:{port}/rpc");
    let cred_header = b"authorization";
    let cred_scheme = b"Bearer ";
    let verb = b"POST";

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        // STEP 1: the plane resolves a credential ref → an OPAQUE host-side ref (no plaintext returned).
        let audience = b"aud:upstream";
        let query = AuthQuery {
            size: std::mem::size_of::<AuthQuery>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            credential_ref: 0x1234,
            audience_ptr: audience.as_ptr(),
            audience_len: audience.len(),
        };
        let mut resolved = std::mem::MaybeUninit::<AuthResolved>::uninit();
        assert_eq!(
            (vt.auth_resolve.unwrap())(host, &query as *const AuthQuery, &mut resolved),
            StatusClass::Ok
        );
        // SAFETY: Ok ⇒ initialized.
        let resolved = unsafe { resolved.assume_init() };
        assert_ne!(resolved.resolved_ref, 0x1234, "the plane holds a NEW opaque ref, not the input");

        // STEP 2: the plane opens an egress carrying the opaque ref + the neutral placement.
        let mut desc = http_desc(url.as_bytes());
        desc.verb_ptr = verb.as_ptr();
        desc.verb_len = verb.len();
        desc.credential_ref = resolved.resolved_ref;
        desc.cred_header_ptr = cred_header.as_ptr();
        desc.cred_header_len = cred_header.len();
        desc.cred_scheme_ptr = cred_scheme.as_ptr();
        desc.cred_scheme_len = cred_scheme.len();

        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        assert_eq!(
            (vt.egress_open.unwrap())(host, &desc as *const EgressDesc, &mut out),
            StatusClass::Ok
        );
        // SAFETY: Ok ⇒ initialized.
        let open = unsafe { out.assume_init() };
        let echoed = String::from_utf8_lossy(&drain(vt, host, open.id)).into_owned();
        // The host injected the credential header — with the host-owned plaintext, under the scheme.
        assert!(
            echoed.to_ascii_lowercase().contains("authorization: bearer hostcred:"),
            "the host injected `Authorization: Bearer <host-owned credential>`: {echoed:?}"
        );
        // The plane never carried the plaintext: the ref it holds is NOT the secret on the wire.
        assert!(
            !echoed.contains(&resolved.resolved_ref.to_string())
                || !echoed.to_ascii_lowercase().contains(&format!("bearer {}", resolved.resolved_ref)),
            "the injected credential is the resolved secret, never the bare opaque ref"
        );
        let _ = (vt.egress_close.unwrap())(host, open.id);
    });
}
