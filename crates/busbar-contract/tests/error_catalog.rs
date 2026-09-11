//! The catalog is DATA, and these are the cells that hold it to that.
//!
//! A host never asks a plugin what one of its own codes means: it reads the plugin's catalog once
//! and renders from it. That only works if the catalog's JSON is the format (not a convenience
//! rendering of something else), if the one check a host runs before accepting a catalog names
//! every way one can be wrong, and if the bounds on the type survive the READ as well as the write.

use busbar_contract::{
    Advisory, Catalog, CatalogEntry, CatalogFault, ErrorClass, Param, ParamValue, PluginError,
    Template, MAX_ERROR_PARAMS,
};

fn entry(code: &str, templates: &[(&str, &str)]) -> CatalogEntry {
    let mut ts = busbar_contract::bounded::BoundedVec::new();
    for (locale, text) in templates {
        let _ = ts.push(Template {
            locale: (*locale).to_string(),
            text: (*text).to_string(),
        });
    }
    CatalogEntry {
        code: code.to_string(),
        templates: ts,
    }
}

fn catalog(default_locale: &str, entries: Vec<CatalogEntry>) -> Catalog {
    let mut es = busbar_contract::bounded::BoundedVec::new();
    for e in entries {
        let _ = es.push(e);
    }
    Catalog {
        default_locale: default_locale.to_string(),
        entries: es,
    }
}

/// A locale the plugin does not ship falls back to the default locale — and NEVER to the
/// developer message, which is the plugin's words for a log and not a rendering for a caller.
#[test]
fn a_missing_locale_falls_back_to_the_default_and_never_to_the_developer_message() {
    let c = catalog(
        "en",
        vec![entry(
            "vault.token_expired",
            &[
                ("en", "the token expired"),
                ("de", "das Token ist abgelaufen"),
            ],
        )],
    );
    assert_eq!(
        c.template("vault.token_expired", "de"),
        Some("das Token ist abgelaufen")
    );
    assert_eq!(
        c.template("vault.token_expired", "fr"),
        Some("the token expired"),
        "a locale the catalog lacks falls back to the default"
    );
    assert_eq!(
        c.template("vault.never_declared", "en"),
        None,
        "an undeclared code has no rendering at all — the host refuses it rather than inventing one"
    );
}

/// `check()` is the one thing a host runs before it accepts a catalog, and it names each way one
/// is wrong. A catalog that passes this is one every declared code can be rendered from.
#[test]
fn check_names_every_way_a_catalog_is_wrong() {
    assert_eq!(
        catalog("", vec![]).check(),
        Err(CatalogFault::NoDefaultLocale)
    );
    assert_eq!(
        catalog("en", vec![entry("", &[("en", "x")])]).check(),
        Err(CatalogFault::EmptyCode)
    );
    assert_eq!(
        catalog(
            "en",
            vec![entry("a.b", &[("en", "x")]), entry("a.b", &[("en", "y")])]
        )
        .check(),
        Err(CatalogFault::DuplicateCode("a.b".into()))
    );
    assert_eq!(
        catalog("en", vec![entry("a.b", &[("de", "x")])]).check(),
        Err(CatalogFault::MissingDefault("a.b".into())),
        "a code with no template in the default locale is a code that cannot always be rendered"
    );
    assert_eq!(
        catalog("en", vec![entry("a.b", &[("en", "x")])]).check(),
        Ok(())
    );
    assert_eq!(
        Catalog::empty("en").check(),
        Ok(()),
        "a plugin that reports no failure ships an honestly empty catalog, and it is well-formed"
    );
}

/// THE JSON OF THE TYPE IS THE DATA FORMAT. A plugin ships the bytes; the host parses them into
/// the same type it would have built by hand. A round trip is the whole claim.
#[test]
fn the_json_of_the_type_is_the_wire_format() {
    let c = catalog(
        "en",
        vec![entry(
            "store_example.unknown_id",
            &[("en", "no record for {id}")],
        )],
    );
    let bytes = serde_json::to_string(&c).expect("a catalog serialises");
    let read: Catalog = serde_json::from_str(&bytes).expect("and reads back as itself");
    assert_eq!(read, c);
    assert!(
        bytes.contains(r#""default_locale":"en""#)
            && bytes.contains(r#""code":"store_example.unknown_id""#),
        "the field names are the format: {bytes}"
    );
}

/// The five fields survive the round trip, and the class is the one word the taxonomy spells.
#[test]
fn an_error_round_trips_with_its_class_spelled_as_one_word() {
    let e = PluginError::new(ErrorClass::Exhausted, "vault.rate")
        .with_message("slow down")
        .with_param("bucket", ParamValue::Str("prod".into()))
        .with_param("limit", ParamValue::Int(10))
        .with_param("hard", ParamValue::Bool(true));
    let bytes = serde_json::to_string(&e).expect("an error serialises");
    assert!(bytes.contains(r#""class":"exhausted""#), "{bytes}");
    let read: PluginError = serde_json::from_str(&bytes).expect("and reads back as itself");
    assert_eq!(read, e);
    assert_eq!(read.param("limit"), Some(&ParamValue::Int(10)));
    assert_eq!(read.advisory, Advisory::default());
}

/// A bound the writer held is a bound the READER holds too: an over-capacity list is refused on
/// the way in, not silently truncated or silently grown. A catalog arrives as bytes from a cdylib
/// this process did not compile, so the type's capacity has to mean something on a parse.
#[test]
fn an_over_capacity_list_is_refused_on_the_read() {
    let params: Vec<Param> = (0..=MAX_ERROR_PARAMS)
        .map(|i| Param {
            key: format!("k{i}"),
            value: ParamValue::Int(i as i64),
        })
        .collect();
    let json = serde_json::json!({
        "class": "internal",
        "code": "x.y",
        "params": params,
    })
    .to_string();
    let err = serde_json::from_str::<PluginError>(&json)
        .expect_err("a list longer than the declared capacity is not a value of this type");
    assert!(
        err.to_string().contains("at most"),
        "the refusal names the bound: {err}"
    );
}
