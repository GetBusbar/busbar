// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: auth`, BOTH WAYS, VERIFY VERDICTS — the auth kind's both-ways proof over the token cases**
//! (DECISIONS #2, OWNER-LOCKED: "THE COST OF A REAL AUTH WITNESS, IN ORDER", step (5); the #2 row
//! records that the auth kind had none at any tag, v1.5.5 included. OWNER FIXTURES ruling: real
//! plugins are the proofs; ARCHITECT 2026-09-27: the shipped admin-auth module is a REAL auth plugin
//! and its both-ways conformance is the AUTH kind proof.)
//!
//! `auth_conformance_tests` proves the login-capable surface both ways, but its token can only be
//! REFUSED (the issuer's keys are unreachable offline). This file drives a second real auth plugin —
//! reached through the `auth-verify` row of `[package.metadata.busbar.both-ways]`, so no test source
//! names a plugin instance — over token cases that reach EVERY verdict, two ways, and compares.
//!
//! * [`run_compiled_in`] — the plugin's `rlib`: its `pub fn open` (step (3)), each request run
//!   through the `dispatch_compiled_in` twin `export_auth_plugin!` emits beside `busbar_call` (step
//!   (2)), which is `dispatch_auth_enveloped` (step (1)).
//! * [`run_dropped_in`] — the same crate's `cdylib`, staged and wired by the loader's real load, each
//!   request sent over its `busbar_call` symbol.
//!
//! [`compiled_in_and_dropped_in_answer_byte_identically`] requires the two WIRES to be byte-identical
//! and the host to read the dropped-in one as the envelope. The linked door (the `rlib`'s
//! `BUSBAR_COLD_ENTRY` through [`crate::PluginRegistry::link`]) and the dropped-in door (the `cdylib`
//! signed into `plugins/`) are compared the same way on the registry row and on the VERIFY VERDICTS
//! the opened module gives for every token case — the accepted token (`Identify`), a wrong opaque
//! token (`Reject`), a token in another scheme's grammar (`Pass`), and no credential (`Pass`).
//!
//! ## The RED arms stay in the file
//!
//! [`the_pre_envelope_busbar_call_is_not_the_compiled_in_twin`] replays the wire as it was before
//! step (1) — the real `cdylib` loaded and wired, its `busbar_call` answering the SAME module's
//! answers BARE — and shows it is not the twin's wire, although the host reads the same answers out
//! of both. [`a_door_judging_another_token_is_told_apart`] opens the dropped-in door over a ROTATED
//! token's digest and shows its verdicts differ from the linked door's: the verdict comparison sees a
//! door that judges differently, so its equality is not vacuous.

use super::both_ways::{auth_verify_fixture as fixture, both_doors_of, cdylib, statement};
use super::*;
use busbar_contract::abi::cold::auth::{AuthRequest, AuthResponse, BeginLoginRequest};
use busbar_contract::abi::cold::observe::Envelope;
use busbar_contract::auth::{AuthModule, AuthPlugin};

/// The both-ways table row this proof reads.
const PROOF: &str = "auth-verify";

/// The operator's token. The plugin is configured with its SHA-256 digest, never the token.
const TOKEN: &str = "the-operator-token";

/// The plugin's config: the accepted token's SHA-256 hex digest.
fn cfg() -> String {
    busbar_contract::redacted::sha256_hex(TOKEN.as_bytes())
}

/// The candidates the script presents: the accepted token, a wrong opaque token, a token shaped in
/// another scheme's grammar (a JWS compact serialization), none.
const CANDIDATES: [&str; 4] = [TOKEN, "not-the-token", "aaa.bbb.ccc", ""];

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
    let module = fixture::open(&cfg()).expect("the compiled-in constructor");
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
    let bytes = std::fs::read(cdylib(super::both_ways::fixture(PROOF).0)?)
        .expect("read the auth fixture's cdylib");
    let (lib, staged) =
        stage::load_library_from_bytes(&bytes, display).expect("stage the auth fixture's cdylib");
    Some(
        wire_up_raw(
            lib,
            &cfg(),
            display.to_string(),
            busbar_contract::abi::cold::kind::AUTH,
            busbar_contract::abi::cold::kind::AUTH,
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
    // Not a vacuous pass: the accepted token identified, the wrong one was rejected, the other
    // scheme's token and the empty candidate deferred.
    let script_read = read.join("\n");
    assert!(
        script_read.contains("Identity")
            && script_read.contains("Reject")
            && script_read.contains("Pass"),
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
    let module = fixture::open(&cfg()).expect("the same constructor");
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
        busbar_contract::abi::cold::AUTH_ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors_of(
        PROOF,
        manifest,
        |registry| {
            registry
                .open_auth("the-auth", &cfg())
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
    assert_every_verdict(&linked.1);
    assert_eq!(linked, dropped, "the two doors must register one row");
}

/// The transcript holds every verdict the token cases call for, so the equality it is compared
/// under covers `Identify`, `Reject` and `Pass` alike.
fn assert_every_verdict(transcript: &str) {
    assert!(
        transcript.contains("Identify")
            && transcript.contains("Reject")
            && transcript.contains("Pass"),
        "the token cases must identify, reject and defer: {transcript}"
    );
}

/// **THE RED ARM OF THE VERDICT COMPARISON.** The dropped-in door opened over a ROTATED token's
/// digest answers the same token cases differently from the linked door opened over the operator's:
/// the accepted token is no longer identified. What the equality above compares is the verdicts,
/// so a door that judged differently is told apart.
#[test]
fn a_door_judging_another_token_is_told_apart() {
    let manifest = statement(
        "auth",
        "auth-fixture",
        "the-auth",
        busbar_contract::abi::cold::AUTH_ABI_VERSION,
    );
    let rotated = busbar_contract::redacted::sha256_hex(b"a-rotated-token");
    let opened = std::sync::atomic::AtomicUsize::new(0);
    let Some([linked, dropped]) = both_doors_of(
        PROOF,
        manifest,
        |registry| {
            // The linked door is opened first, over the operator's digest; the dropped-in one second,
            // over the rotated digest.
            let cfg = match opened.fetch_add(1, std::sync::atomic::Ordering::Relaxed) {
                0 => cfg(),
                _ => rotated.clone(),
            };
            registry
                .open_auth("the-auth", &cfg)
                .expect("the auth module opens through its alias")
        },
        |opened| verify_script(opened.as_ref()),
    ) else {
        eprintln!("skip: the auth fixture's cdylib is not built");
        return;
    };
    assert_eq!(linked.0, dropped.0, "one row either way");
    assert_every_verdict(&linked.1);
    assert!(
        !dropped.1.contains("Identify"),
        "the rotated door identified the operator's token: {}",
        dropped.1
    );
    assert_ne!(
        linked.1, dropped.1,
        "a door judging another token must not compare equal — this inequality is what \
         `a_linked_and_a_dropped_in_auth_module_register_byte_identical_rows` exists to refuse"
    );
}

/// The same both ways through the LOGIN handle: the payload schema `open_login` reports, and the
/// verify transcript of the unified handle.
#[test]
fn a_linked_and_a_dropped_in_login_handle_answer_identically() {
    let manifest = statement(
        "auth",
        "auth-fixture",
        "the-auth",
        busbar_contract::abi::cold::AUTH_ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors_of(
        PROOF,
        manifest,
        |registry| {
            registry
                .open_login("auth-fixture", &cfg())
                .expect("the login handle opens through its name")
        },
        |(handle, abi): &(Box<dyn AuthPlugin>, u32)| {
            format!("abi={abi} {}", verify_script(handle.as_ref()))
        },
    ) else {
        eprintln!("skip: the auth fixture's cdylib is not built");
        return;
    };
    assert_every_verdict(&linked.1);
    assert_eq!(
        linked, dropped,
        "the two doors must hand back one login handle"
    );
}
