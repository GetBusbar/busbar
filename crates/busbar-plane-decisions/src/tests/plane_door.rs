use super::*;
use crate::ops;

/// `section`'s routes with no provider facts stated.
fn routed(section: &DecisionsSection) -> BTreeMap<String, Routed> {
    routes(section, &BTreeMap::new()).expect("every model's dialect is spoken")
}

/// RED (audit plane-decisions#3): each dialect's claim is published when a model of it is
/// configured, and wears its dialect for a refusal before `arrive`.
#[test]
fn each_dialects_claim_is_published_with_a_model_of_it() {
    let jev = ClaimSpec::new("POST", ops::PATH_SYSTEMONE, claims::TRANSPORT, CLAIM_EXACT);
    let evaluate = ClaimSpec {
        refusal_dialect: 1,
        ..ClaimSpec::new("POST", ops::PATH_EVALUATE, claims::TRANSPORT, CLAIM_EXACT)
    };
    assert_eq!(
        snapshot_spec(&[tail::DIALECT_NANOJEV]).claims,
        vec![evaluate.clone()]
    );
    assert_eq!(
        snapshot_spec(&[tail::DIALECT_NANOJEV, tail::DIALECT_JEV]).claims,
        vec![jev.clone(), evaluate]
    );
    assert_eq!(snapshot_spec(&[tail::DIALECT_JEV]).claims, vec![jev]);
}

/// RED (audit plane-decisions#3): THE DESIGN section 2, "a model's dialect is its override or its
/// provider's protocol"; a dialect the plane does not speak fails closed, naming those it does.
#[test]
fn a_models_dialect_is_its_override_or_its_providers_protocol() {
    let section = read_settings(
        br#"{"models":{"o":{"provider":"p","protocol":"nanojev"},"f":{"provider":"nano"},"j":{"provider":"p"}}}"#,
    )
    .expect("the section reads");
    let facts = BTreeMap::from([
        ("nano".to_string(), "nanojev".to_string()),
        ("p".to_string(), "jev".to_string()),
    ]);
    let r = routes(&section, &facts).expect("every dialect is spoken");
    assert_eq!(
        (r["o"].dialect, r["f"].dialect, r["j"].dialect),
        (
            tail::DIALECT_NANOJEV,
            tail::DIALECT_NANOJEV,
            tail::DIALECT_JEV
        )
    );
    let bogus = read_settings(br#"{"models":{"m":{"provider":"p","protocol":"bogus"}}}"#)
        .expect("the section reads");
    let words = routes(&bogus, &facts).expect_err("an unspoken dialect fails closed");
    assert!(
        words.contains("bogus") && words.contains("jev, nanojev"),
        "{words}"
    );
}

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
fn one_or_more_models_claim_systemone_and_none_claims_nothing() {
    let one = snapshot_spec(&[tail::DIALECT_JEV]);
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
        snapshot_spec(&[]).claims.is_empty(),
        "no model claims nothing"
    );
    for models in [2, 3] {
        let jev = vec![tail::DIALECT_JEV; models];
        assert_eq!(snapshot_spec(&jev).claims, one.claims, "{models} models");
    }
}

#[test]
fn a_generation_lists_every_configured_model_in_name_order() {
    let two =
        read_settings(br#"{"models":{"b":{"provider":"typesafe"},"a":{"provider":"typesafe"}}}"#)
            .expect("the section reads");
    let spec = generation_spec(&routed(&two));
    assert_eq!(spec.listed, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(spec.claims, snapshot_spec(&[0, 0]).claims);

    let one =
        read_settings(br#"{"models":{"jev":{"provider":"typesafe"}}}"#).expect("the section reads");
    let spec = generation_spec(&routed(&one));
    assert_eq!(spec.listed, vec!["jev".to_string()]);
    assert_eq!(spec.claims, snapshot_spec(&[0]).claims);

    let empty = read_settings(b"").expect("an empty blob reads");
    assert!(generation_spec(&routed(&empty)).listed.is_empty());
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
