// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.5.5 -> 1 step's own passes (1d), on the tree: what each converts and the line it reports.

use busbar_contract::yaml::{self, Value, ValueExt};

use super::*;
use crate::scratch::facts;

/// Run the passes on `source` (no template slots: R and I are the same document).
fn passes(source: &str, facts: &Facts) -> Result<(Value, Vec<String>), Refusal> {
    let resolved: Value = yaml::from_str(source).expect("fixture parses");
    let mut after = resolved.clone();
    let mut report = Vec::new();
    run(
        after.as_mapping_mut().expect("a mapping"),
        &resolved,
        facts,
        &mut report,
    )?;
    Ok((after, report))
}

fn value(text: &str) -> Value {
    yaml::from_str(text).unwrap()
}

#[test]
fn the_overlay_selector_is_dropped_and_the_lock_kept() {
    for locked in [false, true] {
        for selector in ["false", "true", "{file: /old/overlay.json}", "{}", "null"] {
            let (after, report) = passes(
                &format!("config: {{locked: {locked}, overlay: {selector}}}\n"),
                &facts(),
            )
            .unwrap();
            let config = after.at("config");
            assert!(config.get("overlay").is_none(), "{selector}");
            assert_eq!(config.at("locked").as_bool(), Some(locked));
            assert_eq!(report.len(), 1, "{report:?}");
        }
    }
    let (after, _) = passes("config: {overlay: false, unknown: retained}\n", &facts()).unwrap();
    assert!(
        after.at("config").get("locked").is_none(),
        "no lock invented"
    );
    assert_eq!(after.at("config").at("unknown").as_str(), Some("retained"));
}

#[test]
fn a_zero_cache_write_rate_is_unfolded_into_input() {
    let (after, report) = passes(
        "rate_card:\n  claude: {input_utok: 3, cache_write_utok: 0}\n  opus: {input_utok: 5, \
         cache_write_utok: 7}\n",
        &facts(),
    )
    .unwrap();
    assert!(after
        .at("rate_card")
        .at("claude")
        .get("cache_write_utok")
        .is_none());
    assert_eq!(
        after
            .at("rate_card")
            .at("opus")
            .at("cache_write_utok")
            .as_u64(),
        Some(7)
    );
    assert_eq!(
        report,
        [
            "rate_card.claude.cache_write_utok: 0 removed (1.5.5 spelling of 'no separate write \
          tariff'); cache writes price at input_utok"
        ]
    );
}

#[test]
fn a_metadata_entry_naming_no_host_is_removed_and_reported() {
    let (after, report) = passes(
        "security:\n  blocked_metadata_hosts: ['169.254.169.254', 'db.1', 'metadata.corp']\n",
        &facts(),
    )
    .unwrap();
    assert_eq!(
        after.at("security").at("blocked_metadata_hosts"),
        &value("['169.254.169.254', 'metadata.corp']")
    );
    let lines: Vec<_> = report
        .iter()
        .filter(|line| line.starts_with("security.blocked_metadata_hosts: removed entry 'db.1'"))
        .collect();
    assert_eq!(lines.len(), 1, "{report:?}");
    assert!(lines[0].contains("never matched any destination on 1.5.5"));
}

/// BUSBAR-3411: the retired 1.5.5 cloud-metadata carve-outs are removed whatever they hold, every
/// entry that admitted something named; `blocked_metadata_hosts` stays.
#[test]
fn the_retired_metadata_carve_outs_are_removed_and_each_entry_is_named() {
    let (after, report) = passes(
        "security:\n  blocked_metadata_hosts: ['10.9.9.9']\n  \
         allow_metadata_hosts: ['169.254.169.254', 'imds.corp']\n  allow_all_metadata: true\n\
         providers:\n  gemini:\n    allow_metadata_hosts: ['169.254.170.2']\n  \
         other:\n    allow_metadata_hosts: []\n",
        &facts(),
    )
    .unwrap();
    assert!(after.at("security").get("allow_metadata_hosts").is_none());
    assert!(after.at("security").get("allow_all_metadata").is_none());
    assert_eq!(
        after
            .at("security")
            .at("blocked_metadata_hosts")
            .at(0_usize),
        &Value::from("10.9.9.9")
    );
    for provider in ["gemini", "other"] {
        assert!(after
            .at("providers")
            .at(provider)
            .get("allow_metadata_hosts")
            .is_none());
    }
    for (path, entry) in [
        ("security.allow_metadata_hosts", "169.254.169.254"),
        ("security.allow_metadata_hosts", "imds.corp"),
        ("security.allow_all_metadata", "true"),
        ("providers.gemini.allow_metadata_hosts", "169.254.170.2"),
    ] {
        assert!(
            report
                .iter()
                .any(|line| line
                    .starts_with(&format!("BUSBAR-3411: {path}: removed entry '{entry}'"))),
            "{path} {entry}: {report:?}"
        );
    }
    assert!(
        report
            .iter()
            .any(|line| line
                .starts_with("BUSBAR-3411: providers.other.allow_metadata_hosts: removed"))
    );
}

/// (x)(1): the open units from the facts are priced at 0, the cache-write TTL units at the lane's
/// write rate; a plane lane is left alone; a lane already pricing a unit keeps its price.
#[test]
fn the_open_units_are_priced() {
    let facts = Facts {
        open_units: vec!["web_search".into()],
        ..facts()
    };
    let (after, report) = passes(
        "rate_card:\n  claude: {input_utok: 3, output_utok: 15}\n  \
         opus: {input_utok: 5, units: {web_search: 2}}\n",
        &facts,
    )
    .unwrap();
    assert_eq!(
        after.at("rate_card").at("claude").at("units"),
        &value("{web_search: 0}")
    );
    assert_eq!(
        after.at("rate_card").at("opus").at("units"),
        &value("{web_search: 2}")
    );
    assert_eq!(report.len(), 1, "{report:?}");
    let (after, report) = passes(
        "rate_card:\n  claude: {input_utok: 3}\n",
        &crate::scratch::facts(),
    )
    .unwrap();
    assert!(after.at("rate_card").at("claude").get("units").is_none());
    assert!(report.is_empty());
}

#[test]
fn a_provider_1_5_5_admitted_ungoverned_gains_the_ungoverned_binding() {
    let (after, report) = passes(
        "identity-providers:\n  corp: { module: header, settings: {} }\n  sso: { module: oidc }\n\
         auth:\n  chain: [keys, corp, sso]\n  \
         role_bindings:\n    sso:\n      eng: { allowed_pools: [fast] }\n",
        &facts(),
    )
    .unwrap();
    let bindings = after.at("auth").at("role_bindings");
    assert!(
        bindings.at("keys").is_null(),
        "the signed-key verifier needs no binding"
    );
    assert_eq!(bindings.at("corp").at("*"), &Value::Map(Vec::new()));
    assert_eq!(bindings.at("sso").at("*"), &Value::Map(Vec::new()));
    assert_eq!(
        bindings.at("sso").at("eng").at("allowed_pools"),
        &value("[fast]"),
        "an operator's own binding is kept as written"
    );
    assert!(report.iter().any(
        |line| line.starts_with("auth.role_bindings.corp.\"*\": added")
            && line.contains("every principal it identifies")
    ));
    assert!(report.iter().any(
        |line| line.starts_with("auth.role_bindings.sso.\"*\": added")
            && line.contains("asserts no roles")
    ));
    // Run again over its own output: nothing more is added.
    let (again, report) = passes(&yaml::to_string(&after).unwrap(), &facts()).unwrap();
    assert!(yaml::same_tree(&again, &after));
    assert!(report.is_empty(), "{report:?}");
}

#[test]
fn trust_optins_migrate_only_when_intent_is_unambiguous() {
    for unsigned in [false, true] {
        for third_party in [false, true] {
            let source = format!("plugins: {{trust: {{allow_unsigned: {unsigned}, allow_third_party: {third_party}}}}}");
            let result = passes(&source, &facts());
            if unsigned != third_party {
                assert!(result.is_err(), "one opt-in must require an explicit decision");
            } else {
                let (after, report) = result.unwrap();
                let trust = after.at("plugins").at("trust");
                assert_eq!(trust.at("allow_untrusted").as_bool(), Some(unsigned));
                assert!(trust.get("allow_unsigned").is_none());
                assert!(trust.get("allow_third_party").is_none());
                assert!(report.iter().any(|line| line.contains("allow_untrusted")));
            }
        }
    }
}

#[test]
fn ambiguous_trust_and_unscoped_publishers_refuse_without_mutation() {
    for source in [
        "plugins: {trust: {allow_unsigned: false, allow_untrusted: false}}",
        "plugins: {trust: {allow_third_party: true}}",
        "plugins: {trust: {publishers: [{name: vendor, public_key: deadbeef}]}}",
    ] {
        let resolved = value(source);
        let mut after = resolved.clone();
        assert!(run(after.as_mapping_mut().unwrap(), &resolved, &facts(), &mut Vec::new()).is_err());
        assert_eq!(after, resolved, "refusal preserves input: {source}");
    }
}

#[test]
fn explicit_scoped_publisher_policy_needs_no_migration() {
    let source = "plugins: {trust: {allow_untrusted: false, publishers: [{name: vendor, plugins: [example], keys: [{public_key: deadbeef}]}]}}";
    let (after, _) = passes(source, &facts()).unwrap();
    assert_eq!(after, value(source));
}
