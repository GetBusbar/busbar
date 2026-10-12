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

/// The models of `json`, over a `typesafe` provider speaking jev and a `nano` one speaking nanojev.
fn models(json: &str) -> Models {
    let providers = [("typesafe", "jev"), ("nano", "nanojev")]
        .into_iter()
        .map(|(p, d)| (p.to_string(), d.to_string()))
        .collect();
    models_of(
        &read_settings(json.as_bytes()).expect("a section"),
        &providers,
    )
    .expect("the models resolve")
}

#[test]
fn each_dialect_with_a_model_claims_its_path_and_none_claims_nothing() {
    let one = snapshot_spec(&models(r#"{"models":{"jev":{"provider":"typesafe"}}}"#));
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
    assert!(
        snapshot_spec(&models(r#"{"models":{}}"#)).claims.is_empty(),
        "no model claims nothing"
    );
    let two = models(r#"{"models":{"a":{"provider":"typesafe"},"b":{"provider":"typesafe"}}}"#);
    assert_eq!(snapshot_spec(&two).claims, one.claims);
    // A nanojev model mounts `/api/evaluate`, whose refusals before `arrive` wear its dialect.
    let mixed = snapshot_spec(&models(
        r#"{"models":{"a":{"provider":"typesafe"},"n":{"provider":"nano"}}}"#,
    ));
    let paths: Vec<_> = mixed
        .claims
        .iter()
        .map(|c| (c.target.as_str(), c.refusal_dialect))
        .collect();
    assert_eq!(paths, [(ops::PATH_SYSTEMONE, 0), (ops::PATH_EVALUATE, 1)]);
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

/// RED (finding 7, DECISIONS D8): every configured decisions model is listed in its generation's
/// snapshot, in name order; a generation with none lists none.
#[test]
fn every_configured_model_is_listed() {
    let spec = snapshot_spec(&models(
        r#"{"models":{"zeta":{"provider":"typesafe"},"alpha":{"provider":"nano"}}}"#,
    ));
    assert_eq!(spec.listed, ["alpha", "zeta"]);
    assert!(snapshot_spec(&models(r#"{"models":{}}"#)).listed.is_empty());
}
