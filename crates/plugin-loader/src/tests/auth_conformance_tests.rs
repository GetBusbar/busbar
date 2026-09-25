// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: auth`, BOTH WAYS — the auth kind's first both-ways witness at any tag** (DECISIONS #2,
//! OWNER-LOCKED: "THE COST OF A REAL AUTH WITNESS, IN ORDER", step (5); the #2 row records that the
//! auth kind had none, v1.5.5 included).
//!
//! Modelled on `export_conformance_tests`: ONE crate — the auth kind's in-tree fixture, reached by
//! KIND through `[package.metadata.busbar.both-ways]` so no test source names a plugin instance —
//! driven two ways over one script, and the two compared.
//!
//! * [`run_compiled_in`] — the fixture's `rlib`: its `pub fn open` (step (3)), each request run
//!   through the `dispatch_compiled_in` twin `export_auth_plugin!` emits beside `busbar_call` (step
//!   (2)), which is `dispatch_auth_enveloped` (step (1)).
//! * [`run_dropped_in`] — the same crate's `cdylib`, staged and wired by the loader's real load, each
//!   request sent over its `busbar_call` symbol.
//!
//! [`compiled_in_and_dropped_in_answer_byte_identically`] requires the two WIRES to be byte-identical
//! and the host to read the dropped-in one as the envelope. The linked door (the `rlib`'s
//! `BUSBAR_COLD_ENTRY` through [`crate::PluginRegistry::link`]) and the dropped-in door (the `cdylib`
//! signed into `plugins/`) are compared the same way on the registry row and the opened module.
//!
//! ## The RED arm stays in the file
//!
//! [`the_pre_envelope_busbar_call_is_not_the_compiled_in_twin`] replays the wire as it was before
//! step (1) — the real `cdylib` loaded and wired, its `busbar_call` answering the SAME module's
//! answers BARE — and shows it is not the twin's wire, although the host reads the same answers out
//! of both. That divergence is what a `busbar_call` that stopped running the enveloped dispatch
//! would look like; the equivalence test is what refuses it.

use super::both_ways::{auth_fixture as fixture, both_doors, cdylib, statement};
use super::*;
use busbar_api::{AuthModule, AuthPlugin};
use busbar_plugin::cold::auth::{AuthRequest, AuthResponse, BeginLoginRequest};
use busbar_plugin::cold::observe::Envelope;

/// The plugin's config: one accepted token and the identity it grants.
const CFG: &str = r#"{"token": "sekret", "id": "alice", "roles": ["platform"]}"#;

/// The candidates the script presents: the accepted token, a wrong one, none.
const CANDIDATES: [&str; 3] = ["sekret", "not-the-token", ""];

/// The operations both arms run, in order: what the host asks at load (name, cacheability, login
/// kind), a verdict per candidate, and a login START — which a verify-only module refuses through
/// the fail-closed adapter both doors share.
fn script() -> Vec<AuthRequest> {
    let mut ops = vec![
        AuthRequest::Name,
        AuthRequest::Cacheable,
        AuthRequest::LoginKind,
    ];
    ops.extend(CANDIDATES.iter().map(|c| AuthRequest::Authenticate {
        credential: (*c).to_string(),
    }));
    ops.push(AuthRequest::BeginLogin(BeginLoginRequest {
        redirect_uri: "https://node.example/auth/token".into(),
        state: "s".into(),
        code_challenge: "c".into(),
        nonce: None,
        scopes: Vec::new(),
    }));
    ops
}

/// The COMPILED-IN build: the constructor this crate LINKS, each request through the plugin's own
/// `dispatch_compiled_in` — the entry point the plugin publishes beside `busbar_call`, so the host
/// needs no edge to the author machinery — and what it answers, as the bytes a wire would carry.
fn run_compiled_in() -> Vec<Vec<u8>> {
    let module = fixture::open(CFG).expect("the compiled-in constructor");
    script()
        .into_iter()
        .map(|req| {
            serde_json::to_vec(&fixture::dispatch_compiled_in(module.as_ref(), req))
                .expect("encode the compiled-in envelope")
        })
        .collect()
}

/// The auth fixture's `cdylib`, staged and wired by the loader's real load under `display`. `None`
/// when it is not built in this scoped, non-CI run ([`cdylib`] hard-fails under CI).
fn wired(display: &str) -> Option<RawPlugin> {
    let bytes = std::fs::read(cdylib(super::both_ways::fixture("auth").0)?)
        .expect("read the auth fixture's cdylib");
    let (lib, staged) =
        stage::load_library_from_bytes(&bytes, display).expect("stage the auth fixture's cdylib");
    Some(
        wire_up_raw(
            lib,
            CFG,
            display.to_string(),
            busbar_plugin::cold::kind::AUTH,
            busbar_plugin::cold::kind::AUTH,
            Some(staged),
        )
        .expect("wire up the auth fixture"),
    )
}

/// One request over `raw`'s `busbar_call`, and the bytes it answered — the WIRE, before the host reads
/// it. The buffer is handed back to the plugin's own `busbar_free`.
fn wire(raw: &RawPlugin, req: &AuthRequest) -> Vec<u8> {
    let payload = serde_json::to_vec(req).expect("encode the request");
    let (mut out, mut out_len): (*mut u8, usize) = (std::ptr::null_mut(), 0);
    // SAFETY: `raw` is a live, wired plugin; the pointers are valid for the call, and the returned
    // buffer is copied before it is handed back to the plugin's own `free`.
    let status = unsafe {
        (raw.call)(
            raw.handle,
            payload.as_ptr(),
            payload.len(),
            &mut out,
            &mut out_len,
        )
    };
    assert_eq!(status, STATUS_OK, "busbar_call answered status {status}");
    let bytes = unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec();
    unsafe { (raw.free)(out, out_len) };
    bytes
}

/// The DROPPED-IN build: the same script over the `cdylib`'s `busbar_call`. Returns the wire bytes and
/// what the host's ONE wire seam (`RawPlugin::transport_call`) reads out of the same answers, with the
/// shape it latched.
fn run_dropped_in() -> Option<(Vec<Vec<u8>>, Vec<String>, u8)> {
    let raw = wired("auth-both-ways-dropped-in")?;
    let bytes = script().iter().map(|req| wire(&raw, req)).collect();
    let read = script()
        .iter()
        .map(|req| {
            let resp: AuthResponse = raw
                .transport_call(req)
                .expect("the host reads the dropped-in answer");
            serde_json::to_string(&resp).expect("encode")
        })
        .collect();
    let shape = raw.shape.load(std::sync::atomic::Ordering::Relaxed);
    Some((bytes, read, shape))
}

/// What each compiled-in envelope carries as its `result`, re-encoded — the answers themselves.
fn answers(wires: &[Vec<u8>]) -> Vec<String> {
    wires
        .iter()
        .map(|w| {
            let e: Envelope<AuthResponse> = serde_json::from_slice(w).expect("an envelope");
            serde_json::to_string(&e.result).expect("encode")
        })
        .collect()
}

/// **THE EQUIVALENCE (#2 step (5)).** The auth fixture, compiled in and dropped in, answers the same
/// script with byte-identical wires, and the host reads the dropped-in wire as the envelope.
#[test]
fn compiled_in_and_dropped_in_answer_byte_identically() {
    let compiled = run_compiled_in();
    let Some((dropped, read, shape)) = run_dropped_in() else {
        eprintln!("skip: the auth fixture's cdylib is not built");
        return;
    };
    assert_eq!(
        compiled
            .iter()
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .collect::<Vec<_>>(),
        dropped
            .iter()
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .collect::<Vec<_>>(),
        "compiled-in and dropped-in builds of ONE auth crate must put the same bytes on the wire"
    );
    assert_eq!(
        read,
        answers(&compiled),
        "the host reads what the twin answered"
    );
    assert_eq!(
        shape,
        response_shape::ENVELOPE,
        "the host latched the envelope"
    );
    // Not a vacuous pass: the accepted token identified, the others passed, login was refused.
    let script_read = read.join("\n");
    assert!(
        script_read.contains("alice") && script_read.contains("Pass"),
        "{script_read}"
    );
}

/// **THE RED ARM — the wire before step (1), kept as the witness.** The real `cdylib`, loaded and
/// wired, its `busbar_call` replaced by one answering what the SAME module answers through the twin,
/// but BARE — the shape every auth plugin spoke before `dispatch_auth_enveloped`. The host reads the
/// same answers out of it (so nothing an operator sees moved, and the v1 floor stays honest), and the
/// wire is NOT the twin's: a `busbar_call` that does not run the enveloped dispatch is a different
/// wire from the compiled-in door's, which the equivalence above refuses.
#[test]
fn the_pre_envelope_busbar_call_is_not_the_compiled_in_twin() {
    let Some(mut raw) = wired("auth-both-ways-pre-envelope") else {
        eprintln!("skip: the auth fixture's cdylib is not built");
        return;
    };
    raw.call = pre_envelope_call;
    raw.free = pre_envelope_free;
    let bare: Vec<Vec<u8>> = script().iter().map(|req| wire(&raw, req)).collect();
    let read: Vec<String> = script()
        .iter()
        .map(|req| {
            let resp: AuthResponse = raw.transport_call(req).expect("the bare answer decodes");
            serde_json::to_string(&resp).expect("encode")
        })
        .collect();
    let compiled = run_compiled_in();
    assert_eq!(read, answers(&compiled), "the same answers, read");
    assert_eq!(
        raw.shape.load(std::sync::atomic::Ordering::Relaxed),
        response_shape::BARE,
        "the host latched the bare shape"
    );
    assert_ne!(
        bare, compiled,
        "a bare busbar_call is a different wire from the compiled-in twin — this inequality is what \
         `compiled_in_and_dropped_in_answer_byte_identically` exists to refuse"
    );
}

/// A `busbar_call` speaking the wire as it was BEFORE step (1): the twin's answer for the SAME
/// module, unwrapped. It never touches the `cdylib`'s handle; it opens the linked constructor once
/// per call, which is what makes the answers the same module's.
unsafe extern "C-unwind" fn pre_envelope_call(
    _handle: *mut std::os::raw::c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let req: AuthRequest =
        serde_json::from_slice(std::slice::from_raw_parts(req, req_len)).expect("decode request");
    let module = fixture::open(CFG).expect("the same constructor");
    let envelope = fixture::dispatch_compiled_in(module.as_ref(), req);
    let boxed: Box<[u8]> = serde_json::to_vec(&envelope.result)
        .expect("encode the bare answer")
        .into_boxed_slice();
    *out_len = boxed.len();
    *out = Box::into_raw(boxed) as *mut u8;
    STATUS_OK
}

/// Free a buffer [`pre_envelope_call`] allocated.
unsafe extern "C-unwind" fn pre_envelope_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len != 0 {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

/// The verify seam's transcript: the runtime identity, whether it is cacheable, and each verdict.
fn verify_script(module: &dyn AuthModule) -> String {
    let verdicts: Vec<String> = CANDIDATES
        .iter()
        .map(|c| {
            let c = (!c.is_empty()).then_some(*c);
            format!("{c:?} -> {:?}", module.authenticate(c))
        })
        .collect();
    format!(
        "name={} cacheable={}\n{}",
        module.name(),
        module.cacheable(),
        verdicts.join("\n")
    )
}

/// **THE AXIS, BOTH WAYS** (#2 rule (1)). The auth fixture registered through the LINKED door (its
/// `rlib`'s `BUSBAR_COLD_ENTRY`, through `PluginRegistry::link`) and the DROPPED-IN door (its
/// `cdylib`, signed into `plugins/`) resolves to the byte-identical registry row, and the module each
/// door's `open_auth` opens verifies the same.
///
/// RED by planting the door bypass the axis replaces — linked rows handed to `link` and never
/// registered — which leaves the linked registry with no row for the name.
#[test]
fn a_linked_and_a_dropped_in_auth_module_register_byte_identical_rows() {
    let manifest = statement(
        "auth",
        "auth-fixture",
        "the-auth",
        busbar_plugin::cold::AUTH_ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors(
        manifest,
        |registry| {
            registry
                .open_auth("the-auth", CFG)
                .expect("the auth module opens through its alias")
        },
        |opened| verify_script(opened.as_ref()),
    ) else {
        eprintln!("skip: the auth fixture's cdylib is not built");
        return;
    };
    assert!(
        !linked.0.starts_with("no row"),
        "the linked door registered no row: {}",
        linked.0
    );
    assert!(
        linked.1.contains("Identify"),
        "the linked module identified the accepted token: {}",
        linked.1
    );
    assert_eq!(linked, dropped, "the two doors must register one row");
}

/// The same both ways through the LOGIN handle: the payload schema `open_login` reports, and the
/// verify transcript of the unified handle.
#[test]
fn a_linked_and_a_dropped_in_login_handle_answer_identically() {
    let manifest = statement(
        "auth",
        "auth-fixture",
        "the-auth",
        busbar_plugin::cold::AUTH_ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors(
        manifest,
        |registry| {
            registry
                .open_login("auth-fixture", CFG)
                .expect("the login handle opens through its name")
        },
        |(handle, abi): &(Box<dyn AuthPlugin>, u32)| {
            format!("abi={abi} {}", verify_script(handle.as_ref()))
        },
    ) else {
        eprintln!("skip: the auth fixture's cdylib is not built");
        return;
    };
    assert!(
        linked.1.contains("Identify"),
        "the linked handle identified the accepted token: {}",
        linked.1
    );
    assert_eq!(
        linked, dropped,
        "the two doors must hand back one login handle"
    );
}
