// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LINKED secret source that answers with an empty or whitespace-only value is refused by the
//! kernel (D-blank-secrets), whatever the source. The axis is process-global, so this test owns
//! its own binary and publishes a neutral linked source there.

use std::sync::Arc;

use busbar_contract::config_time::ConfigScope;
use busbar_contract::json::{self, JsonValueTrait};
use busbar_contract::plugin_settings::Settings;
use busbar_contract::redacted::Secret;
use busbar_contract::secret::{SecretAxis, SecretBytes, SecretCalls, SecretRefused};
use busbar_contract::secret_ref::{SecretRef, Sugars};

const MODULE: &str = "test-blank-linked";

struct Answers;
impl SecretCalls for Answers {
    fn resolve(&self, settings: &[u8]) -> Result<Secret<Vec<u8>>, SecretRefused> {
        let settings: json::Value = json::parse_value(settings).expect("settings json");
        let value: &[u8] = match settings["v"].as_str().expect("v") {
            "spaces" => b"   ",
            "mixed" => b" \t\r\n ",
            "newline" => b"\n",
            "nbsp" => "\u{a0}\u{b}".as_bytes(),
            "control" => b"  s3cr3t\n",
            other => panic!("unexpected case {other}"),
        };
        Ok(Secret::new(value.to_vec()))
    }
}

struct BlankAxis;
impl SecretAxis for BlankAxis {
    fn sugars(&self) -> Sugars {
        Sugars::default()
    }
    fn answers(&self, module: &str) -> bool {
        module == MODULE
    }
    fn linked(&self, module: &str) -> bool {
        module == MODULE
    }
    fn shared(&self, _module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        Ok(Arc::new(Answers))
    }
    fn open(
        &self,
        _module: &str,
        _settings: Option<&Settings>,
        _resolve: &dyn Fn(&SecretRef) -> Result<SecretBytes, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        Ok(Arc::new(Answers))
    }
}

static BLANK_AXIS: BlankAxis = BlankAxis;

fn publish() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        busbar_kernel::preflight::publish_root_rows(busbar_kernel::preflight::RootInstall {
            secret_axis: Some(&BLANK_AXIS),
            ..Default::default()
        });
    });
}

fn reference(case: &str) -> SecretRef {
    json::from_value(&json::json!({"module": MODULE, "settings": {"v": case}}))
        .expect("a canonical source reference")
}

fn resolve(case: &str) -> Result<Secret<String>, String> {
    publish();
    busbar_kernel::config::secret::resolve_linked_string_at_config(
        &reference(case),
        &ConfigScope::config_time(),
    )
}

#[test]
fn linked_source_blank_values_are_refused_naming_the_module_not_the_value() {
    for (case, bytes) in [
        ("spaces", "   "),
        ("mixed", " \t\r\n "),
        ("newline", "\n"),
        ("nbsp", "\u{a0}\u{b}"),
    ] {
        let err = resolve(case).expect_err("a blank linked secret must be refused");
        assert!(
            err.contains("secret module 'test-blank-linked'"),
            "{case}: names the module: {err}"
        );
        assert!(
            err.contains("EMPTY or whitespace-only (BLANK)"),
            "{case}: the kernel's blank refusal: {err}"
        );
        assert!(
            !err.contains("is unset") && !err.contains("after trimming"),
            "{case}: refused by the kernel blank check, not another path: {err}"
        );
        if !bytes.trim_matches(' ').is_empty() {
            assert!(!err.contains(bytes), "{case}: no value bytes: {err}");
        }
    }
}

#[test]
fn linked_source_value_with_content_resolves_unchanged_but_trailing_newline() {
    assert_eq!(
        resolve("control").expect("a value with content resolves"),
        Secret::new("  s3cr3t".to_string())
    );
}
