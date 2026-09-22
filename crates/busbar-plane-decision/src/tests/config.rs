use super::*;

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
                busbar_api::UpstreamCreds::Passthrough
            } else {
                busbar_api::UpstreamCreds::Own
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
