use super::*;
use crate::ops;

#[test]
fn the_statement_names_the_crate_version() {
    let manifest = include_str!("../../Cargo.toml");
    assert!(
        manifest.contains(&format!("\nversion = \"{VERSION}\"\n")),
        "the Statement's version is the manifest's"
    );
}

#[test]
fn an_empty_blob_is_the_empty_section() {
    let section = read_settings(b"").expect("an empty blob reads");
    assert!(section.models.is_empty());
}

#[test]
fn the_settings_read_as_the_decisions_section() {
    let section = read_settings(br#"{"models":{"jev":{"provider":"typesafe"}}}"#)
        .expect("a well-formed section reads");
    assert_eq!(section.models.len(), 1);
}

#[test]
fn a_member_the_section_does_not_declare_is_refused_in_the_grammars_words() {
    let words = read_settings(br#"{"modles":{}}"#).expect_err("a typo is refused");
    assert!(words.contains("modles"), "{words}");
}

/// The public base URL a deployment fronts the plane at.
const URL: &str = "https://busbar.example";

#[test]
fn exactly_one_model_claims_systemone_and_its_document_under_its_audience() {
    let one = snapshot_spec(1, Some(URL));
    assert_eq!(
        one.claims,
        vec![
            ClaimSpec::new("POST", ops::PATH_SYSTEMONE, claims::TRANSPORT, CLAIM_EXACT),
            ClaimSpec::new(
                "GET",
                driven::METADATA_PATH,
                claims::TRANSPORT,
                CLAIM_EXACT | CLAIM_OPEN
            ),
        ]
    );
    assert_eq!(
        (one.audience.as_deref(), one.resource_metadata.as_deref()),
        (
            Some("https://busbar.example/v1/systemone"),
            Some("https://busbar.example/.well-known/oauth-protected-resource/v1/systemone"),
        )
    );
    assert!(one.admin_routes.is_empty());
}

/// RED ARMS: a generation that binds no audience claims nothing, so no path is mounted without one
/// (the kernel refuses a boot that would): any model count but one, or no public URL.
#[test]
fn a_generation_with_no_audience_claims_nothing() {
    for models in [0, 2, 3] {
        let spec = snapshot_spec(models, Some(URL));
        assert!(spec.claims.is_empty(), "{models} models");
        assert!(spec.audience.is_none(), "{models} models");
    }
    let unfronted = snapshot_spec(1, None);
    assert!(unfronted.claims.is_empty());
    assert!(unfronted.audience.is_none() && unfronted.resource_metadata.is_none());
}

#[test]
fn the_need_is_the_tails() {
    assert_eq!(NEEDS.len(), tail::NEEDS.len());
    assert_eq!(STATEMENT.needs_len, NEEDS.len());
    assert_eq!(STATEMENT.sections_len, 1 + tail::SECTIONS_CONSUMED.len());
}
