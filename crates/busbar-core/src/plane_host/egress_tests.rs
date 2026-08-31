// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EGRESS-slot tests, driven over the REAL recovery path and the REAL guarded transport against a
//! loopback HTTP mock. The plaintext hop's observed identity is honestly EMPTY (nothing was proved);
//! the SPKI-population path is the engine's connect-time observation (`PeerSpki` on the response),
//! which the a2a transport pin tests already exercise against real TLS.

use super::*;
use crate::plane_host::{recover, with_dispatch_scope, HostState};
use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
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
        env_ptr: std::ptr::null(),
        env_len: 0,
        cwd_ptr: std::ptr::null(),
        cwd_len: 0,
        stderr_inherit: 0,
        _reserved3: [0; 7],
        trust_anchor_ref: 0,
        timeout_ms: 0,
        resolved_addr: [0; 16],
        resolved_addr_kind: 0,
        _reserved4: [0; 7],
    }
}

/// Open a governed HTTP egress over the HOST-AUTHORED path — the shared [`open_http`] body the hostless
/// in-core entry (`egress_open_scoped`) funnels through, where the desc's `allowlist_scope` IS host
/// authority. This is how a FIRST-PARTY plane drives the seam, so loopback/plaintext MECHANICS are
/// exercised as production drives them.
///
/// The FFI vtable `egress_open` slot, by contrast, grants the plane NO privilege (FFI-F2) and refuses
/// plane-driven subprocess (FFI-F3) — proven by the hostile-input tests below. Mechanics that need
/// loopback/plaintext therefore run through this host-authored entry, never the untrusted FFI slot.
fn host_authored_open(
    host: HostCtx,
    desc: &EgressDesc,
    out: *mut std::mem::MaybeUninit<EgressOpen>,
) -> StatusClass {
    // SAFETY: `host` is the live HostState minted by `with_dispatch_scope`.
    let scope = unsafe { recover(host) }.scope;
    open_http(scope, desc, desc.allowlist_scope, out)
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
        let class = host_authored_open(host, &desc, &mut out);
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
        assert_eq!(
            scope.registered(),
            1,
            "open registers exactly one arena closer"
        );

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
    let leaked_id = with_dispatch_scope(&app, |host, _vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        let class = host_authored_open(host, &desc, &mut out);
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
            (vt.egress_poll.unwrap())(
                host,
                EgressId(999_999),
                b.as_mut_ptr(),
                b.len(),
                &mut written
            ),
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
        let class = host_authored_open(host, &desc, &mut out);
        assert_eq!(class, StatusClass::Ok, "the POST opens");
        // SAFETY: Ok ⇒ initialized.
        let open = unsafe { out.assume_init() };
        let echoed = String::from_utf8_lossy(&drain(vt, host, open.id)).into_owned();
        assert!(
            echoed.starts_with("POST /rpc "),
            "the verb + path were sent: {echoed:?}"
        );
        assert!(
            echoed
                .to_ascii_lowercase()
                .contains("x-plane-header: plane-value"),
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
        // FFI-F5: the audience is the DESTINATION the credential is minted for; it MUST match the host
        // the egress later opens to (here the loopback mock's host), or injection is refused.
        let audience = b"127.0.0.1";
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
        assert_ne!(
            resolved.resolved_ref, 0x1234,
            "the plane holds a NEW opaque ref, not the input"
        );

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
        assert_eq!(host_authored_open(host, &desc, &mut out), StatusClass::Ok);
        // SAFETY: Ok ⇒ initialized.
        let open = unsafe { out.assume_init() };
        let echoed = String::from_utf8_lossy(&drain(vt, host, open.id)).into_owned();
        // The host injected the credential header — with the host-owned plaintext, under the scheme.
        assert!(
            echoed
                .to_ascii_lowercase()
                .contains("authorization: bearer hostcred:"),
            "the host injected `Authorization: Bearer <host-owned credential>`: {echoed:?}"
        );
        // The plane never carried the plaintext: the ref it holds is NOT the secret on the wire.
        assert!(
            !echoed.contains(&resolved.resolved_ref.to_string())
                || !echoed
                    .to_ascii_lowercase()
                    .contains(&format!("bearer {}", resolved.resolved_ref)),
            "the injected credential is the resolved secret, never the bare opaque ref"
        );
        let _ = (vt.egress_close.unwrap())(host, open.id);
    });
}

/// A loopback server that answers with a chosen status, a `Content-Type`, and (optionally) a
/// `Location`, so a test can assert the RESPONSE headers the host surfaces on the connect head.
fn spawn_header_mock(
    status_line: &'static str,
    content_type: &'static str,
    location: Option<&'static str>,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let mut head = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\nContent-Length: 0\r\nConnection: close\r\n"
            );
            if let Some(loc) = location {
                head.push_str(&format!("Location: {loc}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

/// Decode the host's packed response-header records (`u32 name_len | name | u32 val_len | val`, LE)
/// into `(name, value)` pairs — the plane-side inverse of what the host packs into the head.
fn decode_records(bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        let nl = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + nl > bytes.len() {
            break;
        }
        let name = String::from_utf8_lossy(&bytes[i..i + nl]).into_owned();
        i += nl;
        if i + 4 > bytes.len() {
            break;
        }
        let vl = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + vl > bytes.len() {
            break;
        }
        let value = String::from_utf8_lossy(&bytes[i..i + vl]).into_owned();
        i += vl;
        out.push((name, value));
    }
    out
}

#[test]
fn the_connect_head_surfaces_content_type_and_location_as_neutral_records() {
    // A 302 with a content-type AND a Location: the host surfaces both verbatim as neutral records, so
    // the plane can key SSE-vs-JSON on content-type and refuse the redirect with the target's own
    // Location — the host formats neither.
    let port = spawn_header_mock(
        "302 Found",
        "text/event-stream; charset=utf-8",
        Some("https://elsewhere.example/x"),
    );
    let url = format!("http://127.0.0.1:{port}/");
    let desc = http_desc(url.as_bytes());

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        assert_eq!(host_authored_open(host, &desc, &mut out), StatusClass::Ok);
        // SAFETY: Ok ⇒ initialized.
        let open = unsafe { out.assume_init() };
        assert_eq!(
            open.head.status_code, 302,
            "the 3xx is surfaced, not followed"
        );
        assert!(
            !open.head.resp_headers_ptr.is_null(),
            "response headers are surfaced"
        );
        // SAFETY: the head's resp_headers pointer borrows host-owned bytes valid while the egress is open.
        let bytes = unsafe {
            std::slice::from_raw_parts(open.head.resp_headers_ptr, open.head.resp_headers_len)
        };
        let records = decode_records(bytes);
        let content_type = records
            .iter()
            .find(|(n, _)| n == "content-type")
            .map(|(_, v)| v.as_str());
        let location = records
            .iter()
            .find(|(n, _)| n == "location")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            content_type,
            Some("text/event-stream; charset=utf-8"),
            "content-type is surfaced VERBATIM (the plane lower-cases, not the host)"
        );
        assert_eq!(
            location,
            Some("https://elsewhere.example/x"),
            "the redirect Location is surfaced so the plane can refuse the unguarded target"
        );
        let _ = (vt.egress_close.unwrap())(host, open.id);
    });
}

/// Call `egress_fault` with generous buffers, returning the header plus the decoded cause/url strings.
fn read_fault(
    vt: &PlaneHostVtable,
    host: HostCtx,
) -> Option<(busbar_plugin::hot::pod::EgressFault, String, String)> {
    let mut out = std::mem::MaybeUninit::<busbar_plugin::hot::pod::EgressFault>::uninit();
    let mut cause = vec![0u8; 8192];
    let mut url = vec![0u8; 8192];
    let class = (vt.egress_fault.unwrap())(
        host,
        &mut out,
        cause.as_mut_ptr(),
        cause.len(),
        url.as_mut_ptr(),
        url.len(),
    );
    if class != StatusClass::Ok {
        return None;
    }
    // SAFETY: Ok ⇒ initialized.
    let fault = unsafe { out.assume_init() };
    let cause_s = String::from_utf8_lossy(&cause[..fault.cause_len as usize]).into_owned();
    let url_s = String::from_utf8_lossy(&url[..fault.url_len as usize]).into_owned();
    Some((fault, cause_s, url_s))
}

#[test]
fn a_connect_failure_surfaces_class_connect_with_cause_and_url_kept_separate() {
    use busbar_plugin::hot::EgressFailClass;
    // Bind then DROP a listener to obtain a port nothing is listening on, so the connect is refused.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().unwrap().port()
    };
    let url = format!("http://127.0.0.1:{port}/some/path");
    let desc = http_desc(url.as_bytes());

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        let class = host_authored_open(host, &desc, &mut out);
        assert_eq!(
            class,
            StatusClass::Fault,
            "a refused connect faults the open"
        );
        let (fault, cause, got_url) = read_fault(vt, host).expect("a fault was stashed");
        assert_eq!(
            fault.fail_class,
            EgressFailClass::Connect,
            "a connect failure is the neutral Connect class the plane fails over on"
        );
        // The URL is surfaced SEPARATELY from the cause — a plane keeps or strips it independently.
        assert_eq!(
            got_url, url,
            "the target url is surfaced separately, verbatim"
        );
        assert!(!cause.is_empty(), "the flattened cause is surfaced");
        assert!(
            !cause.contains(&url),
            "the cause is url-FREE so the plane composes the url in itself: {cause:?}"
        );
        // Consumed: a second read finds nothing pending.
        assert!(
            read_fault(vt, host).is_none(),
            "the fault is consumed once read"
        );
    });
}

#[test]
fn a_guard_refusal_surfaces_class_refused_with_the_guards_own_reason() {
    use busbar_plugin::hot::EgressFailClass;
    // A private/loopback target with a scope that permits neither is refused by the guard.
    let url = b"http://127.0.0.1:9/".to_vec();
    let mut desc = http_desc(&url);
    desc.allowlist_scope = 0; // permits neither private nor plaintext.

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        let class = host_authored_open(host, &desc, &mut out);
        assert_eq!(class, StatusClass::Refused, "the guard refuses the hop");
        let (fault, cause, _url) = read_fault(vt, host).expect("a refusal fault was stashed");
        assert_eq!(
            fault.fail_class,
            EgressFailClass::Refused,
            "a guard refusal is the Refused class"
        );
        assert!(
            !cause.is_empty(),
            "the guard's own reason is surfaced as the cause"
        );
    });
}

/// STEP-6 REUSE, proven on the wire: two sequential opens to ONE warm destination ride ONE
/// fixture-recorded connection — the second hop pays no TCP handshake. This is the whole point of
/// the host-side client pool (and of the shared egress runtime under it: a pooled connection's
/// driver must outlive the open that dialed it). The timing line is evidence, not an assertion —
/// wall-clock deltas flake on shared runners; the connection count does not.
#[test]
fn a_repeat_hop_reuses_the_pooled_connection_instead_of_redialing() {
    use busbar_substrate::egress::fixtures::{spawn_http, CannedResponse};
    let fixture = spawn_http(CannedResponse::ok("warm"), 8);
    let url = format!("http://{}/hop", fixture.addr);
    let desc = http_desc(url.as_bytes());
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut timings = Vec::new();
        for round in 1..=2 {
            let started = std::time::Instant::now();
            let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
            let class = host_authored_open(host, &desc, &mut out);
            assert_eq!(class, StatusClass::Ok, "open {round} must succeed");
            // SAFETY: Ok ⇒ the out-param is initialized.
            let open = unsafe { out.assume_init() };
            assert_eq!(open.head.status_code, 200);
            let got = drain(vt, host, open.id);
            timings.push(started.elapsed());
            assert_eq!(got, b"warm", "round {round} streams the body");
            assert_eq!((vt.egress_close.unwrap())(host, open.id), StatusClass::Ok);
        }
        eprintln!(
            "[egress-reuse] first hop (fresh dial) {:?}; second hop (pooled connection) {:?}",
            timings[0], timings[1]
        );
        let records = fixture.records();
        assert_eq!(
            records.len(),
            1,
            "both hops must ride ONE connection — the repeat hop redialed: {records:?}"
        );
        assert_eq!(
            records[0].requests, 2,
            "the one connection must have served both requests"
        );
    });
}

/// FFI-F1 (SSRF pin bypass): a plane-supplied PINNED address gets NO trust — it is judged by the SAME
/// host-side address rule as a resolved one BEFORE connecting. A pinned cloud-metadata address is
/// refused EVEN under a fully permissive host scope (metadata is the guard, not a policy a scope can
/// speak for), and a pinned internal address is refused unless the scope admits private addressing. So
/// a plane can no longer pin `169.254.169.254` (or a `10.x`) past the SSRF chokepoint.
#[test]
fn a_plane_pinned_address_is_judged_and_cannot_bypass_the_ssrf_guard() {
    /// Build an HTTP desc to a benign URL host but with a PLANE-PINNED v4 address + host scope.
    fn pinned_desc(url: &[u8], addr: [u8; 4], scope: u32) -> EgressDesc {
        let mut d = http_desc(url);
        d.allowlist_scope = scope;
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&addr);
        d.resolved_addr = bytes;
        d.resolved_addr_kind = 4;
        d
    }
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, _vt| {
        // A pinned cloud-metadata address, even under the MOST permissive host scope, is refused.
        let url = b"https://safe.example/".to_vec();
        let meta = pinned_desc(
            &url,
            [169, 254, 169, 254],
            SCOPE_ALLOW_PRIVATE | SCOPE_ALLOW_PLAINTEXT,
        );
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        assert_eq!(
            host_authored_open(host, &meta, &mut out),
            StatusClass::Refused,
            "a plane-pinned metadata address is judged and refused even under a permissive scope"
        );
        // A pinned INTERNAL address is refused when the scope does not admit private addressing.
        let internal = pinned_desc(&url, [10, 0, 0, 1], 0);
        assert_eq!(
            host_authored_open(host, &internal, &mut out),
            StatusClass::Refused,
            "a plane-pinned internal address is judged and refused without an allow-private scope"
        );
    });
}

/// FFI-F2 (plane self-grants privilege): the FFI vtable `egress_open` slot does NOT honor the plane's
/// POD `allowlist_scope`. A hostile plane asserting ALLOW_PRIVATE + ALLOW_PLAINTEXT to reach a
/// loopback/plaintext endpoint is REFUSED — the host grants no such privilege over the untrusted seam,
/// so the guard refuses the elevated hop that the plane tried to authorize for itself.
#[test]
fn the_ffi_slot_refuses_a_plane_that_self_grants_private_and_plaintext() {
    // A loopback plaintext target with the plane asserting BOTH privilege bits in its POD.
    let url = b"http://127.0.0.1:9/".to_vec();
    let mut desc = http_desc(&url); // http_desc already sets ALLOW_PRIVATE | ALLOW_PLAINTEXT.
    desc.allowlist_scope = SCOPE_ALLOW_PRIVATE | SCOPE_ALLOW_PLAINTEXT;

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        assert_eq!(
            (vt.egress_open.unwrap())(host, &desc as *const EgressDesc, &mut out),
            StatusClass::Refused,
            "the FFI seam ignores plane-asserted privilege bits — the elevated hop is refused"
        );
    });
}

/// FFI-F5 (credential confused deputy) at the egress seam: a plane resolves a credential for one
/// destination (audience) and then opens an egress to a DIFFERENT host carrying that ref. The host
/// refuses the hop rather than inject provider-A's secret into attacker-host-B.
#[test]
fn egress_refuses_a_credential_bound_to_a_different_destination() {
    let port = spawn_echo_mock();
    let url = format!("http://127.0.0.1:{port}/rpc"); // the hop's real destination host is 127.0.0.1
    let cred_header = b"authorization";
    let cred_scheme = b"Bearer ";

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        // Mint a credential bound to a DIFFERENT destination than the egress will open to.
        let audience = b"provider-a.example";
        let query = AuthQuery {
            size: std::mem::size_of::<AuthQuery>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            credential_ref: 0x9999,
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

        // Now pair that provider-A ref with a hop to 127.0.0.1 — the confused-deputy attempt.
        let mut desc = http_desc(url.as_bytes());
        desc.credential_ref = resolved.resolved_ref;
        desc.cred_header_ptr = cred_header.as_ptr();
        desc.cred_header_len = cred_header.len();
        desc.cred_scheme_ptr = cred_scheme.as_ptr();
        desc.cred_scheme_len = cred_scheme.len();

        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        assert_eq!(
            host_authored_open(host, &desc, &mut out),
            StatusClass::Refused,
            "a credential minted for provider-A must not be injected into a different host"
        );
    });
}
