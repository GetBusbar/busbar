use std::collections::{HashMap, HashSet};

use super::*;

fn providers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(name, protocol)| (name.to_string(), protocol.to_string()))
        .collect()
}

fn hooks(names: &[&str]) -> HashSet<String> {
    names.iter().map(|n| n.to_string()).collect()
}

/// CONTROL: a config naming a real `jev`-protocol provider and a real hook boots clean — zero
/// errors. Proves the three refusals below are each triggered by their OWN defect, not by the
/// mere presence of a `decisions:` section.
#[test]
fn a_good_decisions_config_passes_clean() {
    let json = r#"{"models":{"jev":{"provider":"typesafe"}},"hooks":["redact"]}"#;
    let section: DecisionsSection = serde_json::from_str(json).expect("valid shape parses");
    let errors = validate_cross_refs(
        &section,
        &providers(&[("typesafe", PROTOCOL)]),
        &hooks(&["redact"]),
    );
    assert!(errors.is_empty(), "good config refused: {errors:?}");
}

/// DEFECT 1: `decisions.models.<m>.provider` names a provider absent from `providers:`.
#[test]
fn refuses_a_model_naming_an_undefined_provider() {
    let json = r#"{"models":{"jev":{"provider":"ghost"}}}"#;
    let section: DecisionsSection = serde_json::from_str(json).expect("valid shape parses");
    let errors = validate_cross_refs(
        &section,
        &providers(&[("typesafe", PROTOCOL)]),
        &hooks(&[]),
    );
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].contains("decisions.models.jev.provider"),
        "{errors:?}"
    );
    assert!(errors[0].contains("ghost"), "{errors:?}");
    assert!(
        errors[0].contains("typesafe"),
        "{errors:?}: must name the valid choices"
    );
}

/// DEFECT 2: `decisions.hooks` names a hook absent from the top-level `hooks:` registry.
#[test]
fn refuses_a_hook_naming_an_undefined_hook() {
    let json = r#"{"models":{},"hooks":["ghost-hook"]}"#;
    let section: DecisionsSection = serde_json::from_str(json).expect("valid shape parses");
    let errors = validate_cross_refs(&section, &providers(&[]), &hooks(&["redact"]));
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("decisions.hooks"), "{errors:?}");
    assert!(errors[0].contains("ghost-hook"), "{errors:?}");
    assert!(
        errors[0].contains("redact"),
        "{errors:?}: must name the valid choices"
    );
}

/// DEFECT 3 (#51, OWNER-LOCKED): a model whose provider resolves to a dialect the decision plane
/// does not speak (non-jev) must FAIL CLOSED — the exact row #51 cites: "the decisions plane (only
/// jev) handed `anthropic` fails".
#[test]
fn refuses_a_model_whose_provider_speaks_a_non_jev_dialect() {
    let json = r#"{"models":{"jev":{"provider":"claude"}}}"#;
    let section: DecisionsSection = serde_json::from_str(json).expect("valid shape parses");
    let errors = validate_cross_refs(
        &section,
        &providers(&[("claude", "anthropic")]),
        &hooks(&[]),
    );
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].contains("decisions.models.jev.provider"),
        "{errors:?}"
    );
    assert!(errors[0].contains("anthropic"), "{errors:?}");
    assert!(errors[0].contains(PROTOCOL), "{errors:?}");
}

/// An undefined provider is reported ONCE, as the "unknown provider" defect — not also re-reported
/// as a dialect mismatch (there is no protocol to compare when the provider does not exist).
#[test]
fn an_undefined_provider_is_not_also_reported_as_a_dialect_mismatch() {
    let json = r#"{"models":{"jev":{"provider":"ghost"}}}"#;
    let section: DecisionsSection = serde_json::from_str(json).expect("valid shape parses");
    let errors = validate_cross_refs(&section, &providers(&[]), &hooks(&[]));
    assert_eq!(errors.len(), 1, "{errors:?}");
}

#[test]
fn parses_the_ruling_canonical_shape() {
    let json = r#"{"models":{"jev":{"provider":"typesafe","upstream_model":"jev-1.13.0"}}}"#;
    let section: DecisionsSection = serde_json::from_str(json).expect("canonical shape parses");
    let model = section.models.get("jev").expect("the jev model is present");
    assert_eq!(model.provider, "typesafe");
    assert_eq!(model.upstream_model.as_deref(), Some("jev-1.13.0"));
    assert!(section.hooks.is_empty());
    assert!(section.upstream_credentials.is_none());
}

#[test]
fn refuses_an_unknown_top_level_member() {
    let json = r#"{"models":{},"not_a_real_member":1}"#;
    let err = serde_json::from_str::<DecisionsSection>(json)
        .expect_err("deny_unknown_fields refuses a typo'd member");
    assert!(err.to_string().contains("not_a_real_member") || err.to_string().contains("unknown"));
}

#[test]
fn upstream_credentials_accepts_own_and_passthrough() {
    for (word, expect_passthrough) in [("own", false), ("passthrough", true)] {
        let json = format!(r#"{{"models":{{}},"upstream_credentials":"{word}"}}"#);
        let section: DecisionsSection =
            serde_json::from_str(&json).expect("a reserved value parses");
        assert_eq!(
            section.upstream_credentials,
            Some(if expect_passthrough {
                busbar_contract::config::UpstreamCreds::Passthrough
            } else {
                busbar_contract::config::UpstreamCreds::Own
            })
        );
    }
}

#[test]
fn hooks_is_a_plain_name_list() {
    let json = r#"{"models":{},"hooks":["redact","budget-gate"]}"#;
    let section: DecisionsSection = serde_json::from_str(json).expect("hooks list parses");
    assert_eq!(
        section.hooks,
        vec!["redact".to_string(), "budget-gate".to_string()]
    );
}
