// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PIPE-tier tests: a governed subprocess byte-duplex opened through the SAME `egress_open` seam, its
//! stdin/stdout driven with `pipe_write`/`pipe_read`, its lifecycle reclaimed by the dispatch arena.
//! `/bin/cat` is the echo-duplex: what the plane writes to stdin comes back on stdout, byte for byte,
//! proving the host moves RAW BYTES (the plane frames on top).

use super::*;
use crate::plane_host::{recover, with_dispatch_scope, HostState};
use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
use busbar_plugin::hot::pod::POD_VERSION;
use busbar_plugin::hot::{EgressDesc, EgressKind, EgressOpen, PipeId, StatusClass};

/// Pack a `program + argv` command into the length-prefixed wire form (`u32 len | bytes`, LE) that
/// [`EgressDesc::target`] carries for a subprocess open. The first token is the program.
fn pack_command(tokens: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for tok in tokens {
        out.extend_from_slice(&(tok.len() as u32).to_le_bytes());
        out.extend_from_slice(tok.as_bytes());
    }
    out
}

/// A subprocess `EgressDesc` borrowing the packed `command` blob, on `scope`.
fn subprocess_desc(command: &[u8], scope: u32) -> EgressDesc {
    EgressDesc {
        size: std::mem::size_of::<EgressDesc>() as u32,
        version: POD_VERSION,
        kind: EgressKind::Subprocess,
        _reserved: 0,
        allowlist_scope: scope,
        _reserved2: 0,
        target_ptr: command.as_ptr(),
        target_len: command.len(),
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
    }
}

/// A packed child-environment record: `u32 name_len | name | u8 kind | u32 value_len | value`.
fn env_record(name: &str, kind: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(kind);
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    out
}

/// Read a subprocess's whole stdout to EOF (the child is expected to exit after printing).
fn read_to_eof(vt: &PlaneHostVtable, host: HostCtx, pipe: PipeId) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    for _ in 0..256 {
        let mut written: usize = 0;
        let class = (vt.pipe_read.unwrap())(host, pipe, buf.as_mut_ptr(), buf.len(), &mut written);
        assert_eq!(class, StatusClass::Ok, "pipe_read stays Ok until EOF");
        if written == 0 {
            break; // EOF
        }
        got.extend_from_slice(&buf[..written]);
    }
    got
}

/// Read up to `want` bytes from the pipe, accumulating across blocking reads until it has them or the
/// stream ends. Asserts every read stays `Ok`.
fn read_at_least(vt: &PlaneHostVtable, host: HostCtx, pipe: PipeId, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    for _ in 0..64 {
        if got.len() >= want {
            break;
        }
        let mut written: usize = 0;
        let class = (vt.pipe_read.unwrap())(host, pipe, buf.as_mut_ptr(), buf.len(), &mut written);
        assert_eq!(class, StatusClass::Ok, "pipe_read stays Ok until EOF");
        if written == 0 {
            break; // EOF
        }
        got.extend_from_slice(&buf[..written]);
    }
    got
}

#[test]
fn subprocess_pipe_echoes_bytes_through_cat() {
    // `/bin/cat` exists on macOS and Linux alike; if a platform lacks it, skip rather than fail.
    if !std::path::Path::new("/bin/cat").exists() {
        return;
    }
    let command = pack_command(&["/bin/cat"]);
    let desc = subprocess_desc(&command, SCOPE_ALLOW_SUBPROCESS);

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        // SAFETY: live HostState minted by with_dispatch_scope.
        let state: &HostState = unsafe { recover(host) };
        let scope = state.scope;

        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        let class = (vt.egress_open.unwrap())(host, &desc as *const EgressDesc, &mut out);
        assert_eq!(class, StatusClass::Ok, "the allowlisted subprocess opens");
        // SAFETY: Ok ⇒ initialized.
        let open = unsafe { out.assume_init() };
        assert!(!open.pipe.is_none(), "a real PipeId is handed back");
        assert!(
            open.id.is_none(),
            "a subprocess is a duplex pipe, not a one-shot egress"
        );
        assert_eq!(
            scope.registered(),
            1,
            "open registers exactly one arena closer"
        );

        // WRITE → the child's stdin; READ ← its stdout. cat echoes byte for byte.
        let payload = b"ping-through-the-duplex\n";
        assert_eq!(
            (vt.pipe_write.unwrap())(host, open.pipe, payload.as_ptr(), payload.len()),
            StatusClass::Ok
        );
        let echoed = read_at_least(vt, host, open.pipe, payload.len());
        assert_eq!(
            &echoed[..payload.len()],
            payload,
            "the duplex echoed the bytes verbatim"
        );

        // A write to an unknown pipe is Gone.
        assert_eq!(
            (vt.pipe_write.unwrap())(host, PipeId(999_999), payload.as_ptr(), payload.len()),
            StatusClass::Gone
        );
    });
}

#[test]
fn subprocess_env_is_cleared_and_selective_never_leaking_the_hosts() {
    // `/usr/bin/env` prints the child's whole environment, one `NAME=value` per line. Under the seam's
    // `env_clear()` + selective `envs`, the child must see ONLY the records the plane named — never the
    // host's own environment (which holds provider keys), so the marker is present and the host's
    // always-present `PATH` is not. This is the CONFIRMED regression this carrier closes.
    if !std::path::Path::new("/usr/bin/env").exists() {
        return;
    }
    let command = pack_command(&["/usr/bin/env"]);
    let env = env_record("BUSBAR_ENV_MARKER", 0, b"present");
    let mut desc = subprocess_desc(&command, SCOPE_ALLOW_SUBPROCESS);
    desc.env_ptr = env.as_ptr();
    desc.env_len = env.len();

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        assert_eq!(
            (vt.egress_open.unwrap())(host, &desc as *const EgressDesc, &mut out),
            StatusClass::Ok
        );
        // SAFETY: Ok ⇒ initialized.
        let open = unsafe { out.assume_init() };
        let printed = String::from_utf8_lossy(&read_to_eof(vt, host, open.pipe)).into_owned();
        assert!(
            printed.contains("BUSBAR_ENV_MARKER=present"),
            "the child sees the variable the plane named; got: {printed:?}"
        );
        assert!(
            !printed.contains("PATH="),
            "env_clear() ran first, so the host's own environment (its PATH, its secrets) never \
             reaches the child; got: {printed:?}"
        );
    });
}

#[test]
fn subprocess_env_resolves_a_secret_reference_host_side() {
    // A `Secret` env record carries the OPAQUE JSON of a host secret-ref; the host resolves it to
    // plaintext at spawn through the built-in resolver, exactly as the in-process stdio spawn does.
    // The `env` module reads a host environment variable — `HOME` is present in any test environment —
    // so the child ends up with the resolved value the plane never held.
    if !std::path::Path::new("/usr/bin/env").exists() {
        return;
    }
    let Ok(home) = std::env::var("HOME") else {
        return; // no HOME to resolve against — skip rather than fail.
    };
    if home.is_empty() {
        return;
    }
    let command = pack_command(&["/usr/bin/env"]);
    // The sugar form the config layer accepts: `{ env: HOME }` ⇒ the `env` secret module, key `HOME`.
    let secret_json = br#"{"env":"HOME"}"#;
    let env = env_record("BUSBAR_INJECTED", 1, secret_json);
    let mut desc = subprocess_desc(&command, SCOPE_ALLOW_SUBPROCESS);
    desc.env_ptr = env.as_ptr();
    desc.env_len = env.len();

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        assert_eq!(
            (vt.egress_open.unwrap())(host, &desc as *const EgressDesc, &mut out),
            StatusClass::Ok
        );
        // SAFETY: Ok ⇒ initialized.
        let open = unsafe { out.assume_init() };
        let printed = String::from_utf8_lossy(&read_to_eof(vt, host, open.pipe)).into_owned();
        assert!(
            printed.contains(&format!("BUSBAR_INJECTED={home}")),
            "the host resolved the secret reference to plaintext and handed it to the child; got: \
             {printed:?}"
        );
    });
}

#[test]
fn open_refuses_a_relative_or_scopeless_command() {
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();

        // Absolute path but the scope forbids the subprocess tier → Refused.
        let cmd = pack_command(&["/bin/cat"]);
        let no_scope = subprocess_desc(&cmd, 0);
        assert_eq!(
            (vt.egress_open.unwrap())(host, &no_scope as *const EgressDesc, &mut out),
            StatusClass::Refused,
            "a scope without the subprocess bit refuses the spawn"
        );

        // Scope permits, but a RELATIVE program name is refused (the host allowlist demands absolute).
        let relative = pack_command(&["cat"]);
        let rel = subprocess_desc(&relative, SCOPE_ALLOW_SUBPROCESS);
        assert_eq!(
            (vt.egress_open.unwrap())(host, &rel as *const EgressDesc, &mut out),
            StatusClass::Refused,
            "a relative program name is never admissible"
        );

        // An empty/undecodable command blob is refused, not spawned.
        let empty = subprocess_desc(&[], SCOPE_ALLOW_SUBPROCESS);
        assert_eq!(
            (vt.egress_open.unwrap())(host, &empty as *const EgressDesc, &mut out),
            StatusClass::Refused
        );
    });
}

#[test]
fn arena_drop_reclaims_and_kills_an_unclosed_subprocess() {
    if !std::path::Path::new("/bin/cat").exists() {
        return;
    }
    let command = pack_command(&["/bin/cat"]);
    let desc = subprocess_desc(&command, SCOPE_ALLOW_SUBPROCESS);

    let app = crate::test_support::TestApp::new().build();
    let leaked = with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        assert_eq!(
            (vt.egress_open.unwrap())(host, &desc as *const EgressDesc, &mut out),
            StatusClass::Ok
        );
        // SAFETY: Ok ⇒ initialized. Deliberately do NOT close — the dispatch ends with it open.
        unsafe { out.assume_init() }.pipe
    });
    // The dispatch scope dropped: its arena Closer killed the child and removed the backend.
    assert!(
        !REGISTRY.lock().unwrap().contains_key(&leaked.0),
        "arena drop reclaims (kills + reaps) a subprocess the plane never closed"
    );
}
