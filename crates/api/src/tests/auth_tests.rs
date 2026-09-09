// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/api/src/auth.rs`.

use super::*;

#[test]
fn constant_time_eq_basics() {
    assert!(constant_time_eq("secret", "secret"));
    assert!(!constant_time_eq("short", "longer"));
    assert!(!constant_time_eq("secret1", "secret2"));
}

#[test]
fn sha256_hex_is_lowercase_64() {
    let h = sha256_hex(b"busbar");
    assert_eq!(h.len(), 64);
    assert_eq!(h, h.to_lowercase());
}

/// KNOWN-ANSWER VECTORS. The shape assertions above -- 64 chars, lower-case -- are satisfied by a
/// `sha256_hex` that hashed the wrong bytes, truncated and padded, or returned a fixed 64-char hex
/// constant; the second one compares the value to a transform of itself. Every admin and plugin
/// credential compare in the tree routes through this function
/// (`crates/auth-admin-tokens/src/lib.rs:46,51`, `crates/auth-static-plugin/src/lib.rs:90`), and
/// until this test nothing anywhere pinned its actual output. The two vectors are FIPS 180-2's,
/// so they are checkable against any independent implementation rather than against ours.
#[test]
fn sha256_hex_matches_the_published_test_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// `AuthPrincipal::actor_id` is the audit-attribution handle: the principal's own id when one
/// resolved, and the literal `"anonymous"` — never empty, never any other placeholder — for the
/// explicit open-front-door case.
#[test]
fn auth_principal_actor_id_is_the_principal_id_or_anonymous() {
    let identified = AuthPrincipal(Some(Principal::from_id("vk_1")));
    assert_eq!(identified.actor_id(), "vk_1");

    let anon = AuthPrincipal(None);
    assert_eq!(anon.actor_id(), "anonymous");
}

/// `CallerToken`'s manual `Debug` must NEVER print the token contents — presence only, and the two
/// presence states must actually differ (a mutant collapsing both arms to the same literal must
/// fail this).
#[test]
fn caller_token_debug_redacts_and_shows_presence_only() {
    let present = CallerToken(Some("super-secret-bearer-token".to_string()));
    let dbg = format!("{present:?}");
    assert!(!dbg.contains("super-secret-bearer-token"), "{dbg}");
    assert!(dbg.contains("<present>"), "{dbg}");

    let absent = CallerToken(None);
    let dbg = format!("{absent:?}");
    assert!(dbg.contains("<absent>"), "{dbg}");
    assert_ne!(
        format!("{present:?}"),
        format!("{absent:?}"),
        "the present/absent Debug output must actually differ"
    );
}

/// `AuthModule::cacheable` DEFAULTS to `false` — an in-process module is microseconds, and caching
/// its verdicts would only widen the revocation window. A minimal module overriding nothing must
/// get this default, not silently `true`.
#[test]
fn auth_module_cacheable_defaults_to_false() {
    struct Minimal;
    impl AuthModule for Minimal {
        fn name(&self) -> &'static str {
            "minimal"
        }
        fn authenticate(&self, _candidate: Option<&str>) -> AuthOutcome {
            AuthOutcome::Pass
        }
    }
    assert!(!Minimal.cacheable());
}

/// `LoginModule`'s three defaults are ALL fail-closed (`Redirect` kind, `Reject` outcome) so an
/// existing verify-only auth module that implements nothing of `LoginModule` is unaffected and
/// cannot silently start a login flow.
#[test]
fn login_module_defaults_are_fail_closed() {
    struct VerifyOnly;
    impl LoginModule for VerifyOnly {}

    assert_eq!(VerifyOnly.login_kind(), LoginKind::Redirect);
    assert_eq!(
        VerifyOnly.begin_login(&BeginLogin {
            redirect_uri: "https://example.invalid/cb".to_string(),
            state: "s".to_string(),
            code_challenge: "c".to_string(),
            nonce: None,
            scopes: Vec::new(),
        }),
        LoginOutcome::Reject
    );
    assert_eq!(
        VerifyOnly.complete_login(&CompleteLogin::default()),
        LoginOutcome::Reject
    );
}
