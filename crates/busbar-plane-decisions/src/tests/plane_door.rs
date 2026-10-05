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

#[test]
fn exactly_one_model_claims_systemone_and_nothing_else_claims_anything() {
    let one = snapshot_spec(1);
    assert_eq!(
        one.claims,
        vec![ClaimSpec::new(
            "POST",
            ops::PATH_SYSTEMONE,
            claims::TRANSPORT,
            CLAIM_EXACT
        )]
    );
    assert!(one.admin_routes.is_empty());
    for models in [0, 2, 3] {
        assert!(snapshot_spec(models).claims.is_empty(), "{models} models");
    }
}

#[test]
fn the_need_is_the_tails() {
    assert_eq!(NEEDS.len(), tail::NEEDS.len());
    assert_eq!(STATEMENT.needs_len, NEEDS.len());
    assert_eq!(STATEMENT.sections_len, 1 + tail::SECTIONS_CONSUMED.len());
}

/// `validate` reads the blob stage 3g deals (`{decisions: <section>}`): the section inside it is
/// judged (a typo refused), a blob that writes no `decisions:` is the empty section, and the bare
/// section is not the dealt shape.
#[test]
fn validate_reads_the_dealt_blob_at_its_section() {
    assert!(read_dealt(b"").is_ok());
    assert!(read_dealt(br#"{}"#).is_ok());
    assert!(read_dealt(br#"{"decisions":{"models":{"jev":{"provider":"typesafe"}}}}"#).is_ok());
    assert!(read_dealt(br#"{"decisions":{"modles":{}}}"#).is_err());
    assert!(read_dealt(br#"[]"#).is_err());
}
