// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-REF-PATH (ABI-MIN3-INTERFACE §14): D_REF_PATH bindings and `resolve_refs` (§12.7).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K7; re-checked 2026-11-16: the generic Registry check/open plaintext and unresolved-reference clauses run as declared_refs_reach_check_and_open_as_text_and_missing_values_refuse_before_entry below. Remaining: real store-sqlite/export-otlp image operations, undeclared shorthand CONFIG and StraySecret validation (MemBinder::set_sugars is still a stub), resolved-value scrub registration (MemBinder::resolve_now resolves scripted values directly), and the MAX_BINDINGS cap (covered by busbar-kernel plugin_config tests more_than_max_bindings_is_too_many). These need the kernel binder and real images on the boot/validate path, owned by HOST-LAYERING and plugin lanes"]
fn ref_path_bindings() {
    todo!("owner: W1-K7 (C-REF-PATH)")
}

/// Generic registry clauses only: the real store/export images, sugar declaration validation and
/// instance scrub registration remain part of the full case above.
#[test]
fn declared_refs_reach_check_and_open_as_text_and_missing_values_refuse_before_entry() {
    use std::sync::atomic::Ordering;

    use busbar_plugin_loader::instance::OpenError;
    use busbar_plugin_test::{fake_needs::FakeNeeds, suites::harness::Harness};

    let mut needs = FakeNeeds::new();
    needs.secret("/db_path", b"/tmp/x.db");
    needs.secret("/url", b"https://collector.example/v1");
    let h = Harness::admit(fixture::PLUGIN.plugin(), needs).expect("admit ref-path fixture");
    let references = br#"{"db_path":{"env":"DB"},"url":{"env":"U"}}"#;
    let literal = br#"{"db_path":"/tmp/x.db","url":"https://collector.example/v1"}"#;
    for (name, config) in [
        ("references", references.as_slice()),
        ("literal", literal.as_slice()),
    ] {
        h.check(name, config).expect("check sees resolved text");
        drop(
            h.open_secret(name, config)
                .expect("open sees resolved text"),
        );
    }
    assert_eq!(fixture::CHECKS.load(Ordering::SeqCst), 2);
    assert_eq!(fixture::OPENS.load(Ordering::SeqCst), 2);

    let unresolved = Harness::admit(fixture::PLUGIN.plugin(), FakeNeeds::new())
        .expect("admit without scripted values");
    let check = unresolved
        .check("missing", references)
        .expect_err("no resolution");
    let open = unresolved
        .open_secret("missing", references)
        .err()
        .expect("no resolution");
    for error in [check, open] {
        assert!(matches!(error, OpenError::Config { .. }), "{error:?}");
    }
    assert_eq!(
        fixture::CHECKS.load(Ordering::SeqCst),
        2,
        "no check on unresolved input"
    );
    assert_eq!(
        fixture::OPENS.load(Ordering::SeqCst),
        2,
        "no open on unresolved input"
    );
}

mod fixture {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use busbar_plugin_abi::fail::{refused::R_CONFIG, Fail};
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::ChainBytes;
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::Reply;
    use busbar_plugin_abi::Secret;

    pub static CHECKS: AtomicUsize = AtomicUsize::new(0);
    pub static OPENS: AtomicUsize = AtomicUsize::new(0);

    pub struct RefPaths;

    fn plain(config: &[u8]) -> Result<(), Fail> {
        let values = busbar_contract::json::parse::<HashMap<String, String>>(config)
            .map_err(|_| Fail::refused_because(R_CONFIG, "references must resolve before entry"))?;
        if values.len() != 2
            || values.get("db_path").map(String::as_str) != Some("/tmp/x.db")
            || values.get("url").map(String::as_str) != Some("https://collector.example/v1")
        {
            return Err(Fail::refused_because(
                R_CONFIG,
                "unexpected resolved values",
            ));
        }
        Ok(())
    }

    impl Open for RefPaths {
        async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
            OPENS.fetch_add(1, Ordering::SeqCst);
            config.with(plain)?;
            Ok(Self)
        }

        fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            CHECKS.fetch_add(1, Ordering::SeqCst);
            plain(config)
        }

        fn describe(d: &mut Describe<'_>) {
            d.ref_path("/db_path").ref_path("/url");
        }
    }

    impl Secret for RefPaths {
        async fn resolve(&self, _h: &'static Host, _reference: ChainBytes) -> Result<Reply, Fail> {
            Ok(Reply::new())
        }
    }

    busbar_plugin_abi::plugin!(Secret, RefPaths, name: "fixture-ref-paths");
}
