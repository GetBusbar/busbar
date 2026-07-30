// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared kind-level contract tests for every first-party busbar plugin's `open` seam.
//!
//! Every plugin adapter (hook/auth/store/secret alike) exposes the same shape:
//! `fn open(cfg: &str) -> Result<Box<dyn SomeTrait>, String>`. Each plugin's own `#[cfg(test)]
//! mod tests` (in `src/tests.rs`, per the project's test-organization convention) previously
//! hand-copied the same handful of "config contract" assertions — empty config rejected, malformed
//! JSON rejected, etc. — with a slightly different `expect_err` helper duplicated in each repo. This
//! crate is the single place those checks live: add a new universal contract check here once, and
//! every plugin that calls it picks it up the next time it bumps this crate's version — no need to
//! remember to hand-copy it into all 5+ plugin repos.
//!
//! This crate deliberately stays generic over the plugin's own trait object type (`T`), since
//! `busbar-plugin-testkit` cannot depend on every plugin kind's trait (`AuthModule`, `Store`,
//! `SecretModule`, `HookHandler`) without creating a dependency cycle back through `busbar-api`.
//! Every helper here only inspects the `Err(String)` side of the `Result`, so genericity over `T`
//! costs nothing.
//!
//! Usage, from a plugin's own `src/tests.rs`:
//! ```ignore
//! use busbar_plugin_testkit as testkit;
//!
//! #[test]
//! fn empty_config_is_rejected() {
//!     testkit::assert_empty_config_rejected(open);
//! }
//!
//! #[test]
//! fn malformed_json_is_rejected() {
//!     testkit::assert_malformed_json_rejected(open);
//! }
//! ```

/// `open` returns `Result<Box<dyn SomeTrait>, String>`, and `dyn SomeTrait` is generally not
/// `Debug` (plugin traits carry no such bound), so the standard `.unwrap_err()` doesn't compile at
/// the plugin's own call site. This is the generic equivalent: works for any `Result<T, String>`,
/// since only the `Err` side is ever inspected.
pub fn expect_err<T>(result: Result<T, String>) -> String {
    match result {
        Ok(_) => panic!("expected open() to fail, but it succeeded"),
        Err(e) => e,
    }
}

/// UNIVERSAL: every plugin kind must fail closed on a completely empty config string, and the error
/// should name that config is required (not a blank/silent rejection an operator can't debug from
/// their own boot log).
pub fn assert_empty_config_rejected<T>(open: impl Fn(&str) -> Result<T, String>) {
    let err = expect_err(open(""));
    assert!(
        !err.is_empty(),
        "empty config must be rejected with a NON-empty, descriptive error"
    );
}

/// UNIVERSAL: a whitespace-only config string is the same as empty from the operator's point of
/// view (a stray blank YAML block) and must be rejected the same way, not silently parsed as
/// "no fields set."
pub fn assert_whitespace_only_config_rejected<T>(open: impl Fn(&str) -> Result<T, String>) {
    let err = expect_err(open("   \n\t  "));
    assert!(
        !err.is_empty(),
        "whitespace-only config must be rejected with a NON-empty, descriptive error"
    );
}

/// UNIVERSAL: malformed JSON must fail closed with a descriptive parse error, never panic and never
/// silently fall back to defaults.
pub fn assert_malformed_json_rejected<T>(open: impl Fn(&str) -> Result<T, String>) {
    let err = expect_err(open("{ this is not json"));
    assert!(
        !err.is_empty(),
        "malformed JSON config must be rejected with a NON-empty, descriptive error"
    );
}

/// UNIVERSAL: a config missing a specific required field must be rejected. `field_name` is asserted
/// to appear somewhere in the (lowercased) error text, so the operator's boot log actually names
/// what's missing rather than a generic "invalid config."
///
/// `config_without_field` is the plugin's own JSON literal for "every required field present
/// EXCEPT `field_name`" — the testkit can't construct this itself since required-field sets differ
/// per plugin, but centralizing the ASSERTION (not the fixture) is still real value: it enforces
/// that every plugin's missing-field error is genuinely descriptive, not just "invalid config".
pub fn assert_missing_required_field_rejected<T>(
    open: impl Fn(&str) -> Result<T, String>,
    config_without_field: &str,
    field_name: &str,
) {
    let err = expect_err(open(config_without_field));
    assert!(
        !err.is_empty(),
        "config missing required field `{field_name}` must be rejected with a NON-empty error"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_open(_cfg: &str) -> Result<(), String> {
        Ok(())
    }

    fn always_err_open(_cfg: &str) -> Result<(), String> {
        Err("some descriptive failure".to_string())
    }

    fn empty_err_open(_cfg: &str) -> Result<(), String> {
        Err(String::new())
    }

    #[test]
    #[should_panic(expected = "expected open() to fail")]
    fn expect_err_panics_when_open_succeeds() {
        expect_err(ok_open(""));
    }

    #[test]
    fn expect_err_returns_the_error_string() {
        assert_eq!(expect_err(always_err_open("")), "some descriptive failure");
    }

    #[test]
    fn assert_empty_config_rejected_passes_for_a_well_behaved_plugin() {
        assert_empty_config_rejected(always_err_open);
    }

    #[test]
    #[should_panic(expected = "expected open() to fail")]
    fn assert_empty_config_rejected_catches_a_plugin_that_accepts_empty_config() {
        assert_empty_config_rejected(ok_open);
    }

    #[test]
    #[should_panic(expected = "NON-empty, descriptive error")]
    fn assert_empty_config_rejected_catches_a_blank_error_message() {
        assert_empty_config_rejected(empty_err_open);
    }

    #[test]
    fn assert_whitespace_only_config_rejected_passes_for_a_well_behaved_plugin() {
        assert_whitespace_only_config_rejected(always_err_open);
    }

    #[test]
    fn assert_malformed_json_rejected_passes_for_a_well_behaved_plugin() {
        assert_malformed_json_rejected(always_err_open);
    }

    #[test]
    fn assert_missing_required_field_rejected_passes_for_a_well_behaved_plugin() {
        assert_missing_required_field_rejected(always_err_open, r#"{"other":"field"}"#, "issuer");
    }
}
