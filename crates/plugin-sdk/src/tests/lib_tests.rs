// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-sdk/src/lib.rs`.

use super::*;
use boundary::{call_boundary, close_boundary, free_boundary, open_boundary, BoundaryOutcome};
use busbar_api::VirtualKey;
use busbar_plugin::cold::{STATUS_ERR, STATUS_OK, STATUS_PROTOCOL, STATUS_UNSUPPORTED};
use busbar_store_memory::MemoryStore;
use std::os::raw::c_void;
use std::ptr;

// ── Test shims: drive the SHIPPING boundary exactly as `export_plugin!` expands, per kind. The
//    macro can't be invoked in a lib crate (it stamps `#[no_mangle]` exports), so these thin
//    wrappers route open/call/free/close through the same `boundary::*` helpers the macro uses.
//    A test exercising these exercises the real choke point.

unsafe fn open_impl(
    cfg: *const u8,
    cfg_len: usize,
    out_handle: *mut *mut c_void,
    out_err: *mut *mut u8,
    out_err_len: *mut usize,
    ctor: fn(&str) -> Result<BoxedStore, String>,
) -> i32 {
    open_boundary::<StoreHandle>(cfg, cfg_len, out_handle, out_err, out_err_len, |s| {
        ctor(s).map_err(BoundaryOutcome::Error)
    })
}
unsafe fn call_impl(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    call_boundary(handle, req, req_len, out, out_len, |h, b| {
        store_dispatch(h, b)
    })
}
unsafe fn close_impl(handle: *mut c_void) {
    close_boundary::<StoreHandle>(handle)
}
unsafe fn free_impl(ptr: *mut u8, len: usize) {
    free_boundary(ptr, len)
}
unsafe fn secret_open_impl(
    cfg: *const u8,
    cfg_len: usize,
    out_handle: *mut *mut c_void,
    out_err: *mut *mut u8,
    out_err_len: *mut usize,
    ctor: fn(&str) -> Result<BoxedSecret, String>,
) -> i32 {
    open_boundary::<SecretHandle>(cfg, cfg_len, out_handle, out_err, out_err_len, |s| {
        ctor(s).map_err(BoundaryOutcome::Error)
    })
}
unsafe fn secret_call_impl(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    call_boundary(handle, req, req_len, out, out_len, |h, b| {
        secret_dispatch(h, b)
    })
}
unsafe fn secret_close_impl(handle: *mut c_void) {
    close_boundary::<SecretHandle>(handle)
}
unsafe fn hook_open_impl(
    cfg: *const u8,
    cfg_len: usize,
    out_handle: *mut *mut c_void,
    out_err: *mut *mut u8,
    out_err_len: *mut usize,
    ctor: fn(&str) -> Result<BoxedHook, String>,
) -> i32 {
    open_boundary::<HookHandle>(cfg, cfg_len, out_handle, out_err, out_err_len, |s| {
        ctor(s).map_err(BoundaryOutcome::Error)
    })
}
unsafe fn hook_call_impl(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    call_boundary(handle, req, req_len, out, out_len, |h, b| {
        hook_dispatch(h, b)
    })
}
unsafe fn hook_close_impl(handle: *mut c_void) {
    close_boundary::<HookHandle>(handle)
}

/// A test secret module: settings.name in, "resolved:<name>" bytes out; missing name errors.
struct EchoSecret;
impl busbar_api::SecretModule for EchoSecret {
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> busbar_api::SecretResult<Vec<u8>> {
        match settings.get("name").and_then(|v| v.as_str()) {
            Some(n) => Ok(format!("resolved:{n}").into_bytes()),
            None => Err(busbar_api::SecretError::invalid("settings.name required")),
        }
    }
}

/// A secret module that RECORDS the advisory deadline it was handed, so the test can prove the
/// field survives the dispatch instead of being dropped there.
#[derive(Default)]
struct RecordingSecret(std::sync::Mutex<Option<Option<u64>>>);
impl busbar_api::SecretModule for RecordingSecret {
    fn resolve(
        &self,
        _settings: &serde_json::Map<String, serde_json::Value>,
    ) -> busbar_api::SecretResult<Vec<u8>> {
        Ok(b"no-deadline".to_vec())
    }

    fn resolve_with_deadline(
        &self,
        _settings: &serde_json::Map<String, serde_json::Value>,
        deadline_ms: Option<u64>,
    ) -> busbar_api::SecretResult<Vec<u8>> {
        *self.0.lock().unwrap() = Some(deadline_ms);
        Ok(b"observed".to_vec())
    }
}

/// The wire request has always carried `deadline_ms`; the dispatcher dropped it, so a module that
/// could bound its own upstream call was never told what bound to apply. It now reaches the module.
#[test]
fn secret_dispatch_hands_the_advisory_deadline_to_the_module() {
    let module = RecordingSecret::default();
    let resp = dispatch_secret(
        &module,
        busbar_plugin::cold::SecretRequest::Resolve {
            settings: serde_json::Map::new(),
            deadline_ms: Some(500),
        },
    )
    .expect("resolves");
    match resp {
        busbar_plugin::cold::SecretResponse::Bytes(b) => assert_eq!(b, b"observed"),
        other => panic!("expected Bytes, got {other:?}"),
    }
    assert_eq!(
        *module.0.lock().unwrap(),
        Some(Some(500)),
        "the module must observe the caller's advisory deadline"
    );

    // A caller that set NO bound is still distinguishable from one that set zero.
    let module = RecordingSecret::default();
    dispatch_secret(
        &module,
        busbar_plugin::cold::SecretRequest::Resolve {
            settings: serde_json::Map::new(),
            deadline_ms: None,
        },
    )
    .expect("resolves");
    assert_eq!(*module.0.lock().unwrap(), Some(None));
}

fn secret_ctor(_cfg: &str) -> Result<BoxedSecret, String> {
    Ok(Box::new(EchoSecret))
}

/// SECRET glue: dispatch maps the wire enum to the trait, success and failure.
#[test]
fn secret_dispatch_resolves_and_fails_closed() {
    let mut settings = serde_json::Map::new();
    settings.insert("name".to_string(), serde_json::Value::String("db".into()));
    match dispatch_secret(
        &EchoSecret,
        busbar_plugin::cold::SecretRequest::Resolve {
            settings,
            deadline_ms: None,
        },
    )
    .expect("resolves")
    {
        busbar_plugin::cold::SecretResponse::Bytes(b) => assert_eq!(b, b"resolved:db"),
        other => panic!("expected Bytes, got {other:?}"),
    }
    let err = dispatch_secret(
        &EchoSecret,
        busbar_plugin::cold::SecretRequest::Resolve {
            settings: serde_json::Map::new(),
            deadline_ms: None,
        },
    )
    .unwrap_err();
    assert_eq!(err.kind, busbar_api::SecretErrorKind::Invalid);
    assert!(err.message.contains("settings.name required"));
}

/// SECRET glue: the FFI path (open -> call -> close) round-trips a resolve and surfaces a
/// module failure as a TYPED `SecretResponse::Error` over STATUS_OK — not the untyped
/// STATUS_ERR string channel, so a host can distinguish failure kinds instead of pattern-matching
/// message text.
#[test]
fn secret_ffi_roundtrip_open_call_close() {
    unsafe {
        let mut handle: *mut c_void = ptr::null_mut();
        let mut err: *mut u8 = ptr::null_mut();
        let mut err_len: usize = 0;
        let status = secret_open_impl(
            b"{}".as_ptr(),
            2,
            &mut handle,
            &mut err,
            &mut err_len,
            secret_ctor,
        );
        assert_eq!(status, STATUS_OK);
        assert!(!handle.is_null());

        // resolve success
        let mut settings = serde_json::Map::new();
        settings.insert("name".to_string(), serde_json::Value::String("x".into()));
        let req = serde_json::to_vec(&busbar_plugin::cold::SecretRequest::Resolve {
            settings,
            deadline_ms: None,
        })
        .unwrap();
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let status = secret_call_impl(handle, req.as_ptr(), req.len(), &mut out, &mut out_len);
        assert_eq!(status, STATUS_OK);
        let resp: busbar_plugin::cold::SecretResponse =
            serde_json::from_slice(std::slice::from_raw_parts(out, out_len)).unwrap();
        free_impl(out, out_len);
        match resp {
            busbar_plugin::cold::SecretResponse::Bytes(b) => assert_eq!(b, b"resolved:x"),
            other => panic!("expected Bytes, got {other:?}"),
        }

        // resolve failure -> STATUS_OK carrying a typed SecretResponse::Error (never a panic
        // across the boundary, and never the untyped STATUS_ERR channel for a module-level
        // failure — see this test's own doc comment).
        let req = serde_json::to_vec(&busbar_plugin::cold::SecretRequest::Resolve {
            settings: serde_json::Map::new(),
            deadline_ms: None,
        })
        .unwrap();
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let status = secret_call_impl(handle, req.as_ptr(), req.len(), &mut out, &mut out_len);
        assert_eq!(status, STATUS_OK);
        let resp: busbar_plugin::cold::SecretResponse =
            serde_json::from_slice(std::slice::from_raw_parts(out, out_len)).unwrap();
        free_impl(out, out_len);
        match resp {
            busbar_plugin::cold::SecretResponse::Error { kind, message } => {
                assert_eq!(kind, busbar_api::SecretErrorKind::Invalid);
                assert!(message.contains("settings.name required"), "got {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }

        secret_close_impl(handle);
    }
}

/// A trivial test hook handler: decide prefers `[0]`, configure acks only the pushed version.
struct TestHook;
impl HookHandler for TestHook {
    fn decide(&self, _payload: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({"order": [0]})
    }
    fn status(&self) -> serde_json::Value {
        serde_json::json!({"status": {"metrics": []}})
    }
}

/// HOOK glue: `dispatch_hook` maps each op envelope to the trait — decide returns the reply
/// object, notify returns None, configure ACKs the exact version, describe/status pass through.
#[test]
fn hook_dispatch_maps_ops() {
    use busbar_plugin::cold::hook::{ConfigureBody, HookReply, HookRequest};
    match dispatch_hook(
        &TestHook,
        HookRequest::Decide {
            payload: serde_json::json!({}),
        },
    ) {
        HookReply::Reply(v) => assert_eq!(v, serde_json::json!({"order": [0]})),
        other => panic!("expected Reply, got {other:?}"),
    }
    // notify is fire-and-forget → None.
    assert!(matches!(
        dispatch_hook(
            &TestHook,
            HookRequest::Notify {
                payload: serde_json::json!({})
            }
        ),
        HookReply::None
    ));
    // configure with the default handler (acks) echoes the pushed version.
    match dispatch_hook(
        &TestHook,
        HookRequest::Configure(ConfigureBody {
            hook: "h".into(),
            settings: serde_json::Map::new(),
            settings_version: 42,
            busbar_version: "1.5.0".into(),
        }),
    ) {
        HookReply::ConfigureAck { settings_version } => assert_eq!(settings_version, 42),
        other => panic!("expected ConfigureAck(42), got {other:?}"),
    }
}

/// HOOK glue: the FFI path (open → call → close) round-trips a decide and a status, and a
/// malformed request is a PROTOCOL error, never a crash.
#[test]
fn hook_ffi_roundtrip_open_call_close() {
    fn hook_ctor(_cfg: &str) -> Result<BoxedHook, String> {
        Ok(Box::new(TestHook))
    }
    unsafe {
        let mut handle: *mut c_void = ptr::null_mut();
        let mut err: *mut u8 = ptr::null_mut();
        let mut err_len: usize = 0;
        let st = hook_open_impl(
            b"{}".as_ptr(),
            2,
            &mut handle,
            &mut err,
            &mut err_len,
            hook_ctor,
        );
        assert_eq!(st, STATUS_OK);
        assert!(!handle.is_null());

        let req = serde_json::to_vec(&busbar_plugin::cold::hook::HookRequest::Decide {
            payload: serde_json::json!({}),
        })
        .unwrap();
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let st = hook_call_impl(handle, req.as_ptr(), req.len(), &mut out, &mut out_len);
        assert_eq!(st, STATUS_OK);
        let resp: busbar_plugin::cold::hook::HookReply =
            serde_json::from_slice(std::slice::from_raw_parts(out, out_len)).unwrap();
        free_impl(out, out_len);
        match resp {
            busbar_plugin::cold::hook::HookReply::Reply(v) => {
                assert_eq!(v, serde_json::json!({"order": [0]}))
            }
            other => panic!("expected Reply, got {other:?}"),
        }

        // Malformed/undecodable request → UNSUPPORTED (an old-SDK "I can't decode this variant"
        // signal), with a message, never a crash. Distinct from a caller-protocol violation.
        let junk = b"not json";
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let st = hook_call_impl(handle, junk.as_ptr(), junk.len(), &mut out, &mut out_len);
        assert_eq!(st, STATUS_UNSUPPORTED);
        free_impl(out, out_len);

        hook_close_impl(handle);
    }
}

/// A trivial export sink: declares `[Metrics]` and counts deliveries.
struct TestExport {
    delivered: std::sync::atomic::AtomicU64,
}
impl ExportHandler for TestExport {
    fn streams(&self) -> Vec<ExportStream> {
        vec![ExportStream::Metrics]
    }
    fn deliver(&self, _stream: ExportStream, _payload: &serde_json::Value) {
        self.delivered
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// EXPORT glue: `dispatch_export` maps `Streams` to the declared catalog and `Deliver` to the
/// sink, acking `Delivered` and running the handler exactly once.
#[test]
fn export_dispatch_maps_ops() {
    let sink = TestExport {
        delivered: std::sync::atomic::AtomicU64::new(0),
    };
    match dispatch_export(&sink, ExportRequest::Streams) {
        ExportResponse::Streams(s) => assert_eq!(s, vec![ExportStream::Metrics]),
        other => panic!("expected Streams, got {other:?}"),
    }
    match dispatch_export(
        &sink,
        ExportRequest::Deliver {
            stream: ExportStream::Metrics,
            payload: serde_json::json!({"reqs": 1}),
        },
    ) {
        ExportResponse::Delivered => {}
        other => panic!("expected Delivered, got {other:?}"),
    }
    assert_eq!(sink.delivered.load(std::sync::atomic::Ordering::Relaxed), 1);
}

/// A sink that declares a `GET /metrics` route and serves it via `handle_http`.
struct RoutedExport;
impl ExportHandler for RoutedExport {
    fn streams(&self) -> Vec<ExportStream> {
        vec![ExportStream::Metrics]
    }
    fn routes(&self) -> Vec<Route> {
        vec![Route {
            path: "/metrics".into(),
            method: RouteMethod::Get,
            auth: RouteAuth::None,
        }]
    }
    fn handle_http(&self, req: &HttpEndpointRequest) -> HttpEndpointResponse {
        assert_eq!(req.path, "/metrics");
        HttpEndpointResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: b"busbar_up 1\n".to_vec(),
        }
    }
}

/// EXPORT glue: `dispatch_export` maps `Routes` to the declared routes and `HttpEndpoint` to
/// `handle_http`, relaying the plugin's response — the additive route-registration + dispatch wire.
#[test]
fn export_dispatch_routes_and_http() {
    match dispatch_export(&RoutedExport, ExportRequest::Routes) {
        ExportResponse::Routes(r) => {
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].path, "/metrics");
            assert_eq!(r[0].method, RouteMethod::Get);
        }
        other => panic!("expected Routes, got {other:?}"),
    }
    match dispatch_export(
        &RoutedExport,
        ExportRequest::HttpEndpoint {
            request: HttpEndpointRequest {
                method: "GET".into(),
                path: "/metrics".into(),
                query: String::new(),
                headers: vec![],
                body: vec![],
            },
        },
    ) {
        ExportResponse::Http(resp) => {
            assert_eq!(resp.status, 200);
            assert_eq!(resp.body, b"busbar_up 1\n");
        }
        other => panic!("expected Http, got {other:?}"),
    }
}

/// EXPORT glue: the DEFAULT `handle_http` is a 404 (a sink with no HTTP surface / partial impl).
#[test]
fn export_default_handle_http_is_404() {
    struct Bare;
    impl ExportHandler for Bare {
        fn streams(&self) -> Vec<ExportStream> {
            vec![ExportStream::Metrics]
        }
    }
    assert!(Bare.routes().is_empty());
    let resp = Bare.handle_http(&HttpEndpointRequest {
        method: "GET".into(),
        path: "/whatever".into(),
        query: String::new(),
        headers: vec![],
        body: vec![],
    });
    assert_eq!(resp.status, 404);
}

/// EXPORT: the SDK's declared payload version reads the shared const (compile-time link, not a
/// coincidental literal) and is pinned at v2 (1.5.3 — the projection grammar: expanded stream
/// vocabulary, `audit` removed).
#[test]
fn export_abi_version_reads_the_shared_const_and_is_two() {
    assert_eq!(
        export_abi_version(),
        busbar_plugin::cold::export::EXPORT_ABI_VERSION
    );
    assert_eq!(export_abi_version(), 2);
}

fn mem_ctor(_cfg: &str) -> Result<BoxedStore, String> {
    Ok(Box::new(MemoryStore::new()))
}

fn ctor_that_errors(_cfg: &str) -> Result<BoxedStore, String> {
    Err("nope".to_string())
}

fn key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        generation_hash: "hash".into(),
        name: "n".into(),
        allowed_scopes: None,
        enabled: true,
        created_at: 1,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

/// Drive the FFI helpers exactly as the loader would: open → call (put then get) → close, and
/// free every buffer. Proves the whole serialize → dispatch → deserialize path over the boxed
/// handle, against a real Store.
#[test]
fn ffi_roundtrip_open_call_close() {
    unsafe {
        // open
        let mut handle: *mut c_void = ptr::null_mut();
        let mut err: *mut u8 = ptr::null_mut();
        let mut err_len: usize = 0;
        let cfg = b"{}";
        let st = open_impl(
            cfg.as_ptr(),
            cfg.len(),
            &mut handle,
            &mut err,
            &mut err_len,
            mem_ctor,
        );
        assert_eq!(st, STATUS_OK);
        assert!(!handle.is_null());

        // call: PutKey
        let put = serde_json::to_vec(&StoreRequest::PutKey(key("vk_1"))).unwrap();
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let st = call_impl(handle, put.as_ptr(), put.len(), &mut out, &mut out_len);
        assert_eq!(st, STATUS_OK);
        free_impl(out, out_len);

        // call: GetKey -> Some(key)
        let get = serde_json::to_vec(&StoreRequest::GetKey("vk_1".into())).unwrap();
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let st = call_impl(handle, get.as_ptr(), get.len(), &mut out, &mut out_len);
        assert_eq!(st, STATUS_OK);
        let resp: StoreResponse =
            serde_json::from_slice(std::slice::from_raw_parts(out, out_len)).unwrap();
        match resp {
            StoreResponse::Key(Some(k)) => assert_eq!(k.id, "vk_1"),
            other => panic!("expected key, got {other:?}"),
        }
        free_impl(out, out_len);

        close_impl(handle);
    }
}

/// A malformed/undecodable request payload is an UNSUPPORTED signal (old-SDK "I can't decode this
/// variant") with a message, not a crash — distinct from a caller-protocol violation and from a
/// panic. This is the taxonomy split that closes the loader fail-open.
#[test]
fn ffi_bad_request_is_unsupported() {
    unsafe {
        let mut handle: *mut c_void = ptr::null_mut();
        let mut err: *mut u8 = ptr::null_mut();
        let mut err_len: usize = 0;
        assert_eq!(
            open_impl(
                ptr::null(),
                0,
                &mut handle,
                &mut err,
                &mut err_len,
                mem_ctor
            ),
            STATUS_OK
        );
        let junk = b"not json at all";
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let st = call_impl(handle, junk.as_ptr(), junk.len(), &mut out, &mut out_len);
        assert_eq!(st, STATUS_UNSUPPORTED);
        assert!(!out.is_null());
        free_impl(out, out_len);
        // A NULL handle IS a caller-protocol violation → STATUS_PROTOCOL (no user code runs).
        let st = call_impl(
            ptr::null_mut(),
            junk.as_ptr(),
            junk.len(),
            &mut out,
            &mut out_len,
        );
        assert_eq!(st, STATUS_PROTOCOL);
        close_impl(handle);
    }
}

/// A null `out_handle` on a SUCCESSFUL open is a protocol error, NOT a silent leak. Before the
/// fix `open_impl` boxed the store then dropped the pointer on the floor when `out_handle` was
/// null (STATUS_OK, handle leaked forever). Now it never allocates without a slot: the store is
/// freed and a protocol error is returned with a message. (This drives the store variant; all
/// four `*_open_impl` share the identical guard.)
#[test]
fn ffi_null_out_handle_is_protocol_error_not_leak() {
    unsafe {
        let cfg = b"{}";
        let mut err: *mut u8 = ptr::null_mut();
        let mut err_len: usize = 0;
        let st = open_impl(
            cfg.as_ptr(),
            cfg.len(),
            ptr::null_mut(), // no slot for the handle
            &mut err,
            &mut err_len,
            mem_ctor,
        );
        assert_eq!(st, STATUS_PROTOCOL);
        assert!(!err.is_null());
        let msg = std::str::from_utf8(std::slice::from_raw_parts(err, err_len)).unwrap();
        assert!(msg.contains("out_handle"), "unexpected message: {msg}");
        free_impl(err, err_len);
    }
}

/// `OutBuf::commit` (the successor to `write_buf`) with a null `out` must DROP the owned `Vec`, not
/// leak it: the alloc (`into_boxed_slice`/`Box::into_raw`) lives INSIDE the non-null branch, so the
/// null path never realizes a raw box — the leak is made structurally impossible. `out_len` is left
/// untouched; a non-null slot returns a freeable (ptr, len) pair. Under Miri/ASan this flags the
/// leak the old ordering caused.
#[test]
fn outbuf_commit_null_out_drops_without_leaking_or_writing() {
    unsafe {
        // Null `out`: nothing is written, `out_len` is left untouched, no crash (Vec dropped).
        let mut len_slot: usize = 0xDEAD;
        boundary::OutBuf::new(vec![1u8, 2, 3]).commit(STATUS_OK, ptr::null_mut(), &mut len_slot);
        assert_eq!(
            len_slot, 0xDEAD,
            "out_len must be untouched when out is null"
        );

        // Non-null `out`: the (ptr, len) pair is returned and is freeable (round-trip through
        // free_boundary proves the allocation is intact and owned by the same allocator).
        let mut ptr_slot: *mut u8 = ptr::null_mut();
        let mut len2: usize = 0;
        boundary::OutBuf::new(vec![7u8, 8, 9, 10]).commit(STATUS_OK, &mut ptr_slot, &mut len2);
        assert!(!ptr_slot.is_null());
        assert_eq!(len2, 4);
        assert_eq!(std::slice::from_raw_parts(ptr_slot, len2), &[7, 8, 9, 10]);
        free_impl(ptr_slot, len2);
    }
}

/// The new audit ABI variants dispatch through the trait: `AppendAudit` maps to `append_audit`
/// (Unit response) and `ListAudit` to `list_audit` (Audit response). The RAM default keeps what it
/// is handed for the life of the process, so the record appended is the record listed — proving
/// the ADDITIVE variants are wired end-to-end without breaking the existing dispatch.
#[test]
fn dispatch_handles_audit_variants() {
    use busbar_api::AuditRecord;
    let store = MemoryStore::new();
    let rec = AuditRecord {
        seq: 1,
        ts: 2,
        action: "hook.register".into(),
        resource: "hook:a".into(),
        outcome: "applied".into(),
        principal: "admin".into(),
        prev_hash: String::new(),
        hash: "h".into(),
    };
    match dispatch(&store, StoreRequest::AppendAudit(rec)).unwrap() {
        StoreResponse::Unit => {}
        other => panic!("expected Unit, got {other:?}"),
    }
    match dispatch(&store, StoreRequest::ListAudit).unwrap() {
        StoreResponse::Audit(v) => {
            assert_eq!(
                v.len(),
                1,
                "the RAM store lists the one record it was handed"
            );
            assert_eq!(v[0].hash, "h");
        }
        other => panic!("expected Audit, got {other:?}"),
    }
}

/// The neutral kind-tagged plane-record variants (1.6.0, ADDITIVE) round-trip through the ABI serde
/// and dispatch onto the neutral trait methods. Each request is serialized to the on-wire JSON and
/// deserialized back (proving the ABI enum carries them), then dispatched against the memory store —
/// whose RAM default keeps plane rows for the life of the process. This proves the additive
/// api+abi+sdk wiring compiles and is reachable end-to-end without any caller: a write comes back
/// `Unit` and the read that follows it finds the row, a purge and a redeem answer their counts.
#[test]
fn dispatch_handles_neutral_plane_variants() {
    use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector};

    let store = MemoryStore::new();

    // Round-trip each request through the ABI JSON so the test exercises the wire, not just the enum.
    let roundtrip = |req: &StoreRequest| -> StoreResponse {
        let bytes = serde_json::to_vec(req).expect("neutral request serializes");
        let decoded: StoreRequest =
            serde_json::from_slice(&bytes).expect("neutral request decodes");
        dispatch(&store, decoded).expect("dispatch")
    };

    let rec = PlaneRecord {
        kind: "task".into(),
        id: "t-1".into(),
        parent: None,
        seq: 0,
        ts: 42,
        disposition: PlaneDisposition::Terminal,
        body: vec![1, 2, 3],
    };

    match roundtrip(&StoreRequest::UpsertPlaneRecord {
        kind: rec.kind.clone(),
        id: rec.id.clone(),
        ts: rec.ts,
        disposition: rec.disposition,
        body: rec.body.clone(),
    }) {
        StoreResponse::Unit => {}
        other => panic!("expected Unit, got {other:?}"),
    }
    match roundtrip(&StoreRequest::GetPlaneRecord {
        kind: "task".into(),
        id: "t-1".into(),
    }) {
        StoreResponse::PlaneRecord(b) => {
            assert!(
                b.is_some(),
                "the RAM store keeps the plane record it was handed"
            )
        }
        other => panic!("expected PlaneRecord, got {other:?}"),
    }
    match roundtrip(&StoreRequest::AppendPlaneRecord {
        kind: "call".into(),
        id: "p-1".into(),
        parent: "p-1".into(),
        seq: 7,
        ts: 99,
        disposition: PlaneDisposition::Active,
        body: vec![9],
    }) {
        StoreResponse::Unit => {}
        other => panic!("expected Unit, got {other:?}"),
    }
    match roundtrip(&StoreRequest::ListPlaneRecords {
        kind: "call".into(),
        selector: PlaneSelector::Parent("p-1".into()),
    }) {
        StoreResponse::PlaneRecords(v) => {
            assert_eq!(
                v.len(),
                1,
                "the one record appended under this parent is listed"
            );
            assert_eq!(v[0], vec![9u8], "and it is the body that was appended");
        }
        other => panic!("expected PlaneRecords, got {other:?}"),
    }
    match roundtrip(&StoreRequest::ListPlaneRecordParents {
        kind: "call".into(),
    }) {
        StoreResponse::PlaneRecordParents(v) => {
            assert_eq!(
                v,
                vec!["p-1".to_string()],
                "the parent the append named is listed"
            )
        }
        other => panic!("expected PlaneRecordParents, got {other:?}"),
    }
    match roundtrip(&StoreRequest::PurgePlaneRecordsBefore {
        kind: "task".into(),
        before: 100,
    }) {
        StoreResponse::Purged(n) => {
            assert_eq!(n, 1, "the terminal task row older than the cut is purged")
        }
        other => panic!("expected Purged, got {other:?}"),
    }
    match roundtrip(&StoreRequest::DeletePlaneRecord {
        kind: "demotion".into(),
        id: "srv".into(),
    }) {
        StoreResponse::Unit => {}
        other => panic!("expected Unit, got {other:?}"),
    }
    match roundtrip(&StoreRequest::RedeemPlaneToken {
        kind: "ask".into(),
        token: "n-1".into(),
        expires_at: 200,
        now: 1,
    }) {
        StoreResponse::Redeemed(fresh) => {
            assert!(
                fresh,
                "no durable ledger, so the default reports first redemption"
            )
        }
        other => panic!("expected Redeemed, got {other:?}"),
    }
}

/// A constructor error surfaces as STATUS_ERR with the message in the error buffer.
#[test]
fn ffi_ctor_error_surfaces() {
    unsafe {
        let mut handle: *mut c_void = ptr::null_mut();
        let mut err: *mut u8 = ptr::null_mut();
        let mut err_len: usize = 0;
        let st = open_impl(
            ptr::null(),
            0,
            &mut handle,
            &mut err,
            &mut err_len,
            ctor_that_errors,
        );
        assert_eq!(st, STATUS_ERR);
        assert!(handle.is_null());
        let msg = std::str::from_utf8(std::slice::from_raw_parts(err, err_len)).unwrap();
        assert_eq!(msg, "nope");
        free_impl(err, err_len);
    }
}

/// `auth_abi_version()` reads `busbar_plugin::cold::AUTH_ABI_VERSION` rather than a bare literal,
/// mirroring `secret_abi_version()`/`hook_abi_version()`. The property that buys: a future bump
/// of `AUTH_ABI_VERSION` propagates here automatically instead of silently drifting.
#[test]
fn auth_abi_version_reads_the_shared_const() {
    assert_eq!(auth_abi_version(), busbar_plugin::cold::AUTH_ABI_VERSION);
}

/// Pin the auth payload schema at v2 (1.5.2 login primitives) — the SDK builds v2.
#[test]
fn auth_abi_version_is_two() {
    assert_eq!(auth_abi_version(), 2);
}

// ── ABI v2 login dispatch (SDK server side) ────────────────────────────────────────────────

use busbar_api::{
    AuthModule, AuthOutcome, BeginLogin, CompleteLogin, LoginHop, LoginModule, LoginOutcome,
    Principal,
};
use busbar_plugin::cold::auth::{
    AuthRequest, AuthResponse, BeginLoginRequest, CompleteLoginRequest,
};

/// A verify-only module: implements AuthModule, takes LoginModule's fail-closed defaults.
struct VerifyOnly;
impl AuthModule for VerifyOnly {
    fn name(&self) -> &'static str {
        "verify-only"
    }
    fn authenticate(&self, _c: Option<&str>) -> AuthOutcome {
        AuthOutcome::Pass
    }
}
impl LoginModule for VerifyOnly {}

/// A login-capable module: begin → Authorize, complete → Exchange then Identify.
struct LoginMod;
impl AuthModule for LoginMod {
    fn name(&self) -> &'static str {
        "login-mod"
    }
    fn authenticate(&self, _c: Option<&str>) -> AuthOutcome {
        AuthOutcome::Pass
    }
}
impl LoginModule for LoginMod {
    fn begin_login(&self, req: &BeginLogin) -> LoginOutcome {
        LoginOutcome::Authorize(format!("https://idp/authorize?state={}", req.state))
    }
    fn complete_login(&self, req: &CompleteLogin) -> LoginOutcome {
        if req.token_response.is_some() {
            LoginOutcome::Identify(Principal::from_id("oidc:alice"))
        } else {
            LoginOutcome::Exchange(LoginHop {
                method: "POST".into(),
                url: "https://idp/token".into(),
                form: vec![("client_secret".into(), String::new())],
                secret_form_field: Some("client_secret".into()),
                headers: vec![],
            })
        }
    }
}

fn begin_req() -> AuthRequest {
    AuthRequest::BeginLogin(BeginLoginRequest {
        redirect_uri: "https://busbar/auth/token".into(),
        state: "st".into(),
        code_challenge: "cc".into(),
        nonce: None,
        scopes: vec![],
    })
}

#[test]
fn dispatch_begin_login_maps_authorize_url() {
    let resp = dispatch_auth(&LoginMod, begin_req());
    match resp {
        AuthResponse::AuthorizeUrl(u) => assert!(u.contains("state=st")),
        other => panic!("expected AuthorizeUrl, got {other:?}"),
    }
}

#[test]
fn dispatch_complete_login_token_exchange() {
    let resp = dispatch_auth(
        &LoginMod,
        AuthRequest::CompleteLogin(CompleteLoginRequest {
            code: Some("authcode".into()),
            ..Default::default()
        }),
    );
    match resp {
        AuthResponse::TokenExchange(hop) => {
            assert_eq!(hop.secret_form_field.as_deref(), Some("client_secret"))
        }
        other => panic!("expected TokenExchange, got {other:?}"),
    }
}

#[test]
fn dispatch_complete_login_identity() {
    let resp = dispatch_auth(
        &LoginMod,
        AuthRequest::CompleteLogin(CompleteLoginRequest {
            token_response: Some(busbar_plugin::cold::auth::HttpResponse {
                status: 200,
                body: "{}".into(),
            }),
            ..Default::default()
        }),
    );
    assert!(matches!(resp, AuthResponse::Identity(_)));
}

#[test]
fn login_plugin_handle_preserves_login_capability() {
    // `export_login_plugin!` boxes the ctor's `Box<dyn AuthPlugin>` DIRECTLY as the AuthHandle.
    // A login-capable module keeps its login capability: BeginLogin reaches the real impl.
    let direct: AuthHandle = Box::new(LoginMod);
    assert!(
        matches!(
            dispatch_auth(direct.as_ref(), begin_req()),
            AuthResponse::AuthorizeUrl(_)
        ),
        "export_login_plugin! must NOT mask login: BeginLogin should reach the real LoginModule"
    );
    // Contrast: `export_auth_plugin!` routes through the verify-only adapter, which takes the
    // fail-closed LoginModule default — so the SAME module exported that way is masked to Reject.
    let adapted: AuthHandle = adapt_auth_handle(Box::new(LoginMod));
    assert!(
        matches!(
            dispatch_auth(adapted.as_ref(), begin_req()),
            AuthResponse::Reject
        ),
        "verify-only adapter must mask login (this is why export_login_plugin! bypasses it)"
    );
}

#[test]
fn verify_only_module_defaults_begin_login_reject() {
    // A verify-only module's default LoginModule fails closed on both login ops.
    assert!(matches!(
        dispatch_auth(&VerifyOnly, begin_req()),
        AuthResponse::Reject
    ));
    assert!(matches!(
        dispatch_auth(
            &VerifyOnly,
            AuthRequest::CompleteLogin(CompleteLoginRequest::default())
        ),
        AuthResponse::Reject
    ));
}

// ── THE PLANE-RECORD SIDECAR ON THE WIRE ────────────────────────────────────────────────────────
//
// `ts` and `disposition` are the two typed sidecar columns retention sweeps on, and they have to
// SURVIVE the engine→plugin hop: a store behind the C ABI reconstitutes its `PlaneRecord` from the
// request JSON alone, so anything the wire drops is gone by the time `purge_plane_records_before`
// reads it — an age-based sweep then sees ts 0 on every row and deletes the whole log, and a
// terminal-only sweep sees Active on every row and purges nothing, ever. These decode the on-wire
// JSON (the exact bytes a plugin receives) and assert the reconstituted envelope carries the sidecar.

/// A store that records the envelopes handed to the two write verbs, so a test can inspect what
/// [`dispatch`] reconstituted from the wire. Every non-plane method is a stub: nothing here reads them.
#[derive(Default)]
struct RecordingStore {
    written: std::sync::Mutex<Vec<busbar_api::PlaneRecord>>,
}

impl busbar_api::Store for RecordingStore {
    fn put_key(&self, _key: &VirtualKey) -> Result<(), StoreError> {
        Ok(())
    }
    fn get_key(&self, _id: &str) -> Result<Option<VirtualKey>, StoreError> {
        Ok(None)
    }
    fn list_keys(&self) -> Result<Vec<VirtualKey>, StoreError> {
        Ok(Vec::new())
    }
    fn delete_key(&self, _id: &str) -> Result<(), StoreError> {
        Ok(())
    }
    fn get_usage(
        &self,
        _bucket: &str,
        _window: u64,
    ) -> Result<busbar_api::UsageLedger, StoreError> {
        Ok(busbar_api::UsageLedger::default())
    }
    fn put_usage(
        &self,
        _bucket: &str,
        _window: u64,
        _ledger: &busbar_api::UsageLedger,
    ) -> Result<(), StoreError> {
        Ok(())
    }
    fn add_metering(&self, _delta: &busbar_api::MeteringDelta) -> Result<(), StoreError> {
        Ok(())
    }
    fn list_metering(&self, _bucket: u64) -> Result<Vec<busbar_api::MeteringRow>, StoreError> {
        Ok(Vec::new())
    }
    fn upsert_plane_record(&self, record: &busbar_api::PlaneRecord) -> Result<(), StoreError> {
        self.written
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(record.clone());
        Ok(())
    }
    fn append_plane_record(&self, record: &busbar_api::PlaneRecord) -> Result<(), StoreError> {
        self.written
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(record.clone());
        Ok(())
    }
}

/// Decode `json` as a request and dispatch it against a recording store, returning the ONE envelope
/// the store was handed — i.e. exactly what a plugin behind the ABI would persist.
fn envelope_from_wire(json: serde_json::Value) -> busbar_api::PlaneRecord {
    let store = RecordingStore::default();
    let req: StoreRequest =
        serde_json::from_slice(&serde_json::to_vec(&json).unwrap()).expect("request decodes");
    dispatch(&store, req).expect("dispatch");
    let written = store.written.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(written.len(), 1, "exactly one envelope written");
    written[0].clone()
}

/// An APPENDED record's `ts` (and child `id`) survive the hop.
#[test]
fn appended_plane_record_keeps_its_ts_across_the_wire() {
    let rec = envelope_from_wire(serde_json::json!({
        "AppendPlaneRecord": {
            "kind": "call",
            "id": "vk_owner",
            "parent": "vk_owner",
            "seq": 7,
            "ts": 1_600u64,
            "disposition": "Active",
            "body": [9],
        }
    }));
    assert_eq!(rec.ts, 1_600, "the append wire must carry `ts`");
    assert_eq!(
        rec.id, "vk_owner",
        "the append wire must carry the child id"
    );
    assert_eq!(rec.parent.as_deref(), Some("vk_owner"));
    assert_eq!(rec.seq, 7);
}

/// An UPSERTED record's `disposition` (and `ts`) survive the hop.
#[test]
fn upserted_plane_record_keeps_its_disposition_across_the_wire() {
    let rec = envelope_from_wire(serde_json::json!({
        "UpsertPlaneRecord": {
            "kind": "task",
            "id": "task-abc",
            "ts": 2_000u64,
            "disposition": "Terminal",
            "body": [1, 2, 3],
        }
    }));
    assert_eq!(rec.ts, 2_000, "the upsert wire must carry `ts`");
    assert_eq!(
        rec.disposition,
        busbar_api::PlaneDisposition::Terminal,
        "the upsert wire must carry `disposition`"
    );
}

/// An OLDER engine's request — no sidecar keys at all — still decodes, at the neutral defaults. This
/// is what makes the added fields ADDITIVE rather than a schema break, and it is why the payload
/// schema version does not move.
#[test]
fn a_sidecar_less_request_still_decodes_at_the_neutral_defaults() {
    let rec = envelope_from_wire(serde_json::json!({
        "UpsertPlaneRecord": { "kind": "task", "id": "task-abc", "body": [1] }
    }));
    assert_eq!(rec.ts, 0);
    assert_eq!(rec.disposition, busbar_api::PlaneDisposition::Active);

    let rec = envelope_from_wire(serde_json::json!({
        "AppendPlaneRecord": { "kind": "call", "parent": "p", "seq": 1, "body": [1] }
    }));
    assert_eq!(rec.ts, 0);
    assert_eq!(rec.disposition, busbar_api::PlaneDisposition::Active);
    assert_eq!(rec.id, "", "no id on the wire is an empty child id");
}
