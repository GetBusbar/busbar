// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/abi/sdk/mod.rs` (the former `busbar-plugin-sdk`).

use super::*;
use crate::abi::cold::STATUS_OK;
use std::ptr;

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
        boundary::free_boundary(ptr_slot, len2);
    }
}

/// `auth_abi_version()` reads the auth kind's one version rather than a bare literal: a future bump
/// of `abi::auth::ABI_VERSION` propagates here instead of silently drifting.
#[test]
fn auth_abi_version_reads_the_shared_const() {
    assert_eq!(auth_abi_version(), crate::abi::auth::ABI_VERSION);
}

/// Pin the auth payload schema at v3 (1.6.0: the enveloped wire over v2's login primitives) — the
/// SDK builds v3.
#[test]
fn auth_abi_version_is_three() {
    assert_eq!(auth_abi_version(), 3);
}

// ── ABI v2 login dispatch (SDK server side) ────────────────────────────────────────────────

use crate::abi::cold::auth::{AuthRequest, AuthResponse, BeginLoginRequest, CompleteLoginRequest};
use crate::auth::{
    AuthModule, AuthVerdict, BeginLogin, CompleteLogin, LoginHop, LoginModule, LoginOutcome,
    Principal,
};

/// A verify-only module: implements AuthModule, takes LoginModule's fail-closed defaults.
struct VerifyOnly;
impl AuthModule for VerifyOnly {
    fn name(&self) -> &'static str {
        "verify-only"
    }
    fn authenticate(&self, _c: Option<&str>) -> AuthVerdict {
        AuthVerdict::Pass
    }
}
impl LoginModule for VerifyOnly {}

/// A login-capable module: begin → Authorize, complete → Exchange then Identify.
struct LoginMod;
impl AuthModule for LoginMod {
    fn name(&self) -> &'static str {
        "login-mod"
    }
    fn authenticate(&self, _c: Option<&str>) -> AuthVerdict {
        AuthVerdict::Pass
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
            token_response: Some(crate::abi::cold::auth::HttpResponse {
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
