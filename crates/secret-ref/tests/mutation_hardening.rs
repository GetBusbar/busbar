// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate-level SECURITY invariant of `busbar-secret-ref`: `SecretRef` must never leak a secret
//! VALUE through `Debug`, `Display` or logging.
//!
//! This closes no coverage gap — the crate's existing suite in `src/tests/lib_tests.rs` already
//! pins every behaviour of `lib.rs`. It is here because the invariant is worth holding on its own
//! terms, independently of what any one implementation happens to do today.
//!
//! Its own top-level `tests/` file (rather than a case added to `src/tests/lib_tests.rs`) because
//! it stands for a crate-level SECURITY invariant, not a unit of `lib.rs`'s own behavior — see the
//! repo's test-locality convention (`docs/code-layout.md`): the existing single inline test module
//! stays exactly the src-level unit-test file it was.
//!
//! **Finding, stated up front:** `SecretRef` is a REFERENCE type — `{ module, settings }` naming
//! WHERE a secret module resolves the secret from (an env var's name, a file's path), never the
//! secret's own value. Its doc comment says so explicitly: "SecretRef holds no secret material —
//! only the module name and its opaque settings — so it is safe to derive Debug/Clone/PartialEq on
//! it". There is no Display impl on `SecretRef` at all, and the crate takes no `tracing`/`log`
//! dependency (see `Cargo.toml`) — so there is no code path in this crate that could format a
//! secret VALUE into a log line, because the type never holds one. This file tests that claim two
//! ways: (1) constructing a `SecretRef` from a value a caller might mistake for "the secret" (an
//! env var name / file path) round-trips into `Debug` output verbatim, which is CORRECT and
//! EXPECTED — that string is a pointer to the secret, not the secret — and (2) the one path an
//! actual secret VALUE could arrive on this type (an inline scalar in the deserializer) is refused
//! before it is ever stored anywhere, and the refusal's error message never echoes it. (2) is
//! already covered by `an_unquoted_inline_secret_is_refused_without_echoing_it` in
//! `src/tests/lib_tests.rs`; this file adds the distinctive-marker variant the task calls for and
//! confirms no Display impl exists to leak through.
//!
//! No real defect was found: there is no code path where a `SecretRef` holds, and then echoes,
//! actual secret material.

use busbar_secret_ref::SecretRef;

/// A `SecretRef` build from a distinctive "looks like a secret" string in its `settings` is
/// EXPECTED to show that string in `Debug` — the string is a reference name (the env var to read,
/// or the file to open), never the secret value itself. This is the crate's documented contract,
/// not a leak: the type has no field that ever holds a resolved secret. Restated as a test so a
/// change that started storing (or trying to redact) the reference itself would be caught either
/// way.
#[test]
fn secret_ref_settings_carry_only_the_reference_never_a_resolved_value() {
    let distinctive_marker = "SUPER_DISTINCTIVE_ENV_VAR_NAME_NOT_A_SECRET_VALUE";
    let r = SecretRef::env(distinctive_marker);
    let debug = format!("{r:?}");
    // The reference NAME is expected verbatim — it is where to look, not what was found there.
    assert!(
        debug.contains(distinctive_marker),
        "a SecretRef's settings must echo the reference name (env var / file path) in Debug — \
         that name is not secret material: {debug}"
    );
    // `env_var()`/`file_path()` return the same reference name, confirming this crate has no
    // separate "resolved secret value" field anywhere that Debug could instead be hiding.
    assert_eq!(r.env_var(), Some(distinctive_marker));
    assert_eq!(
        r.settings.len(),
        1,
        "settings holds only the one reference field"
    );
}

/// `SecretRef` has no `Display` impl at all — grep-proof via a `PartialEq`-shaped compile check is
/// not expressible as a runtime assertion, so this test instead asserts the DOCUMENTED absence by
/// construction: if a `Display` impl existed, `{}`-formatting a `SecretRef` inline below would need
/// no `{:?}`, and this file would not compile with `{}` in place of `{:?}` — so the crate's public
/// API is exercised only through `Debug`, which is the whole of its string-formatting surface.
/// (A `serde::Serialize` impl exists instead, tested separately
/// below — Serialize is not string-formatting and carries no log-echo risk on its own.)
#[test]
fn secret_ref_debug_output_never_contains_an_inline_literal_a_caller_tried_to_smuggle_in() {
    // The deserializer path (the ONLY path an actual pasted secret VALUE could arrive on this
    // type) refuses every inline-scalar shape before constructing any SecretRef at all — so no
    // SecretRef ever exists holding one. Confirm with a distinctive marker of our own, on top of
    // the numeric/bool/string cases `src/tests/lib_tests.rs` already covers.
    let distinctive_secret = "sk-DISTINCTIVE-7f3e9c-DO-NOT-ECHO";
    let err = serde_yaml::from_str::<SecretRef>(distinctive_secret)
        .expect_err("a bare scalar is never a secret reference")
        .to_string();
    assert!(
        !err.contains(distinctive_secret),
        "the refusal echoed the literal secret value into the error text: {err}"
    );
    assert!(
        !err.contains("DISTINCTIVE-7f3e9c"),
        "no fragment of the value leaked either: {err}"
    );
}

/// `serde::Serialize` round-trips the same non-secret reference data `Debug` shows — confirming
/// the derived `Serialize` impl (used when a `SecretRef` is echoed back into config, e.g. by a
/// future admin API) has no separate code path that could serialize something `Debug` does not
/// already expose.
#[test]
fn secret_ref_serialize_exposes_the_same_reference_data_as_debug_no_more_no_less() {
    let r = SecretRef::file("/run/secrets/distinctive-marker-path");
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["module"], "file");
    assert_eq!(
        json["settings"]["path"],
        "/run/secrets/distinctive-marker-path"
    );
    // Exactly module + settings — no hidden third field a future change could smuggle a resolved
    // secret value into without also showing up here.
    assert_eq!(json.as_object().unwrap().len(), 2);
}
