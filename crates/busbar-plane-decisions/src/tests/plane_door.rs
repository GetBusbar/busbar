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
    // Served on the plain data plane to a keyed caller: no audience, no protected-resource document.
    assert!(one.audience.is_none() && one.resource_metadata.is_none());
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

/// THE SPEC'S BLOB SHAPE (`BUSBAR-1.6.0.md` section 4): the section under its own verb, `{decisions:
/// <section>}`, is read as the section; so is the bare section; and the wrapped section is judged
/// by the same grammar (a typo inside it is refused, naming the member).
#[test]
fn the_section_under_its_verb_reads_as_the_section() {
    let wrapped = read_settings(br#"{"decisions":{"models":{"jev":{"provider":"typesafe"}}}}"#)
        .expect("the {section: value} blob reads");
    assert_eq!(wrapped.models.len(), 1);
    assert!(read_settings(br#"{"decisions":null}"#)
        .expect("an absent section is the empty one")
        .models
        .is_empty());
    let words = read_settings(br#"{"decisions":{"modles":{}}}"#).expect_err("a typo is refused");
    assert!(words.contains("modles"), "{words}");
    // RED ARM: the verb beside another member is no wrapper; it is an unknown member.
    assert!(read_settings(br#"{"decisions":{},"models":{}}"#).is_err());
}
