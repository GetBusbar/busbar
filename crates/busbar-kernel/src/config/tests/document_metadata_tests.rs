// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::{resolve, ModelCfg, ProviderDeploy};
use std::collections::HashMap;

const NEUTRAL_SECTION: &str = "neutral_section";
const RAW_SECTION: &str = "raw_section";
const NO_CATALOG: &str = "listen: \"127.0.0.1:0\"\npools: {}\n";

fn read_with<'de, D: Deserializer<'de>>(
    de: D,
    table: &[(&'static str, Dest)],
    required: &[&'static str],
) -> Result<DeployCfg, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Catalog {
        #[serde(default)]
        providers: HashMap<String, ProviderDeploy>,
        #[serde(default)]
        models: HashMap<String, ModelCfg>,
        #[serde(default)]
        listen: Option<String>,
        #[serde(default, rename = "pools")]
        _pools: Option<serde_yaml::Value>,
    }
    struct Document<'a> {
        table: &'a [(&'static str, Dest)],
        required: &'a [&'static str],
    }
    impl<'de> Visitor<'de> for Document<'_> {
        type Value = DeployCfg;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("the section metadata test document")
        }
        fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
            let (catalog, lifted) =
                read_document::<_, Catalog>(map, self.required.to_vec(), self.table)?;
            let mut deploy = crate::config::tests::base_deploy();
            deploy.providers = catalog.providers;
            deploy.models = catalog.models;
            if let Some(listen) = catalog.listen {
                deploy.listen = listen;
            }
            lifted.install(&mut deploy);
            Ok(deploy)
        }
    }
    de.deserialize_map(Document { table, required })
}

#[test]
fn test_decisions_section_parses() {
    let table: &[(&'static str, Dest)] = &[(
        "neutral_section",
        Dest::Declared(PlaneMetadata {
            key: "neutral-test-section",
            noun: "pool",
        }),
    )];
    let required: &[&'static str] = &[];
    let read = |text: &str| read_with(serde_yaml::Deserializer::from_str(text), table, required);

    let section = NEUTRAL_SECTION;
    let deploy: DeployCfg = read(&format!(
        "{section}:\n  \
           models:\n    \
             primary: {{ provider: example-upstream, upstream_model: example-1 }}\n\
         providers: {{}}\nmodels: {{}}\npools: {{}}\n",
    ))
    .expect("a document carrying a section a registered plane declares must parse");

    assert!(
        deploy
            .declared
            .0
            .get(section)
            .is_some_and(|c| c.is_present()),
        "the lifted `decisions:` value must land on its carrier, not be dropped on the floor"
    );

    let bare: DeployCfg = read("providers: {}\nmodels: {}\npools: {}\n")
        .expect("a document with no `decisions:` section still parses");
    assert!(
        bare.declared.0.is_empty(),
        "an omitted `decisions:` section leaves the carrier at its Default"
    );
}

#[test]
fn every_owned_declaring_section_lands_in_the_one_map_carrier() {
    let table: &[(&'static str, Dest)] = &[
        (
            "neutral_section",
            Dest::Declared(PlaneMetadata {
                key: "neutral-test-section",
                noun: "pool",
            }),
        ),
        (
            "second_section",
            Dest::Declared(PlaneMetadata {
                key: "neutral-test-second",
                noun: "pool",
            }),
        ),
    ];
    let required: &[&'static str] = &[];
    let read = |text: &str| read_with(serde_yaml::Deserializer::from_str(text), table, required);

    let deploy: DeployCfg = read(
        "neutral_section:\n  a: 1\nsecond_section:\n  b: 2\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect("two owned sections parse");
    let keys: Vec<&str> = deploy.declared.0.keys().copied().collect();
    assert_eq!(keys, ["neutral_section", "second_section"]);
    assert!(deploy.plane_raw.is_empty(), "{:?}", deploy.plane_raw);
    let root = crate::config::resolve(&deploy, &Default::default()).expect("resolves");
    for section in keys {
        assert!(
            root.plane_sections.contains(section),
            "{section} must be a configured plane section"
        );
    }
}

#[test]
fn a_declared_section_is_kept_as_written_for_the_door_beside_its_parse() {
    let table: &[(&'static str, Dest)] = &[
        (
            "neutral_section",
            Dest::Declared(PlaneMetadata {
                key: "neutral-test-section",
                noun: "pool",
            }),
        ),
        (
            "raw_section",
            Dest::Raw(PlaneMetadata {
                key: "neutral-test-raw",
                noun: "pool",
            }),
        ),
    ];
    let required: &[&'static str] = &[];
    let read = |text: &str| read_with(serde_yaml::Deserializer::from_str(text), table, required);

    let deploy: DeployCfg = read(&format!(
        "neutral_section:\n  a: 1\n  fees: {{ per_request: 3 }}\n{RAW_SECTION}:\n  greeting: hi\n\
         providers: {{}}\nmodels: {{}}\npools: {{}}\n",
    ))
    .expect("both sections parse");
    let sections = deploy.door_sections();
    let a: serde_yaml::Value = serde_yaml::from_str("a: 1").unwrap();
    let raw: serde_yaml::Value = serde_yaml::from_str("greeting: hi").unwrap();
    assert_eq!(
        sections.get("neutral_section"),
        Some(&a),
        "kept as written, fees lifted off"
    );
    assert_eq!(
        sections.get(RAW_SECTION),
        Some(&raw),
        "the raw carrier's too"
    );
    assert!(
        !deploy.plane_raw.contains_key("neutral_section"),
        "never raw-carried"
    );
}

#[test]
fn a_declared_section_no_carrier_holds_is_lifted_raw_for_its_plane() {
    let table: &[(&'static str, Dest)] = &[(
        "raw_section",
        Dest::Raw(PlaneMetadata {
            key: "neutral-test-raw",
            noun: "pool",
        }),
    )];
    let required: &[&'static str] = &[];
    let read = |text: &str| read_with(serde_yaml::Deserializer::from_str(text), table, required);

    let deploy: DeployCfg = read(&format!(
        "{RAW_SECTION}:\n  greeting: hi\n  fees: {{ per_request: 3 }}\n\
         providers: {{}}\nmodels: {{}}\npools: {{}}\n",
    ))
    .expect("a section a registered plane declares must parse, whichever carrier holds it");
    let remainder: serde_yaml::Value = serde_yaml::from_str("greeting: hi").unwrap();
    assert_eq!(
        deploy.plane_raw.get(RAW_SECTION),
        Some(&remainder),
        "the section lands raw, its core-owned `fees` lifted off it"
    );
    assert!(deploy.plane_fees.contains_key("neutral-test-raw"));

    let root = crate::config::resolve(&deploy, &Default::default()).expect("resolves");
    assert!(
        root.plane_sections.contains(RAW_SECTION),
        "LAW 7: the plane is configured"
    );
    let resource = root
        .endpoint_resource(RAW_SECTION)
        .expect("its plane's resource");
    assert_eq!(
        resource.downcast_ref::<(&'static str, serde_yaml::Value)>(),
        Some(&(RAW_SECTION, remainder)),
        "the resource is `(section, value)`"
    );

    let bare = read(&format!(
        "{RAW_SECTION}: ~\nproviders: {{}}\nmodels: {{}}\npools: {{}}\n"
    ))
    .expect("parses");
    let root = crate::config::resolve(&bare, &Default::default()).expect("resolves");
    assert!(!root.plane_sections.contains(RAW_SECTION));
    assert!(root.endpoint_resource(RAW_SECTION).is_none());
}

#[test]
fn a_decisions_section_with_no_owning_plane_is_refused_as_an_unknown_key() {
    let table: &[(&'static str, Dest)] = &[];
    let required: &[&'static str] = &[];
    let read = |text: &str| read_with(serde_yaml::Deserializer::from_str(text), table, required);

    let err = read(
        "decisions:\n  \
           models:\n    \
             verdict: { provider: typesafe }\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect_err("a `decisions:` block no registered plane declares must be refused")
    .to_string();
    assert!(
        err.contains("unknown field `decisions`"),
        "the refusal must be serde's unknown-field refusal NAMING the key the operator wrote; got: {err}"
    );

    let bare: DeployCfg = read("providers: {}\nmodels: {}\npools: {}\n")
        .expect("a document with no `decisions:` section still parses");
    let bare_errors = resolve(&bare, &HashMap::new()).err().unwrap_or_default();
    assert!(
        !bare_errors.iter().any(|e| e.contains("unknown field")),
        "an absent `decisions:` section must not be refused; got: {bare_errors:?}"
    );
}

#[test]
fn a_section_a_registered_plane_requires_is_refused_with_the_1_5_5_missing_field_text() {
    let table: &[(&'static str, Dest)] = &[];
    let required: &[&'static str] = &["providers", "models"];
    let read = |text: &str| read_with(serde_yaml::Deserializer::from_str(text), table, required);

    let err = read(NO_CATALOG).expect_err("providers required");
    assert_eq!(err.to_string(), "missing field `providers`");
    let err = read("listen: \"127.0.0.1:0\"\nproviders: {}\n").expect_err("models required");
    assert_eq!(err.to_string(), "missing field `models`");

    let value: serde_yaml::Value = serde_yaml::from_str(NO_CATALOG).unwrap();
    let err = read_with(value, table, required).expect_err("providers required");
    assert_eq!(err.to_string(), "missing field `providers`");
}

#[test]
fn a_plane_requiring_one_section_leaves_the_other_omissible() {
    let table: &[(&'static str, Dest)] = &[];
    let required: &[&'static str] = &["providers"];
    let read = |text: &str| read_with(serde_yaml::Deserializer::from_str(text), table, required);

    let err = read(NO_CATALOG).expect_err("providers required");
    assert_eq!(err.to_string(), "missing field `providers`");
    let deploy = read("providers: {}\n").expect("models is required by no registered plane");
    assert!(deploy.models.is_empty() && deploy.providers.is_empty());
}

#[test]
fn a_section_no_registered_plane_requires_may_be_omitted_and_reads_empty() {
    let table: &[(&'static str, Dest)] = &[];
    let required: &[&'static str] = &[];
    let read = |text: &str| read_with(serde_yaml::Deserializer::from_str(text), table, required);

    let deploy = read(NO_CATALOG).expect("no registered plane requires a catalog section");
    assert!(deploy.providers.is_empty(), "{:?}", deploy.providers.keys());
    assert!(deploy.models.is_empty(), "{:?}", deploy.models.keys());
    let value: serde_yaml::Value = serde_yaml::from_str(NO_CATALOG).unwrap();
    read_with(value, table, required).expect("the in-memory path agrees");

    let carried = read("models:\n  m1: { provider: p1 }\nlisten: \"127.0.0.1:0\"\n")
        .expect("a carried section parses as written");
    assert_eq!(
        carried.models.keys().collect::<Vec<_>>(),
        vec!["m1"],
        "the document's own section is kept, not replaced by the supplied empty one"
    );
    assert!(carried.providers.is_empty());

    let err = read("listen: \"x\"\nno_such_key: 1\n").expect_err("unknown key");
    assert!(
        err.to_string()
            .starts_with("unknown field `no_such_key`, expected one of"),
        "{err}"
    );
}

#[test]
fn any_section_a_registered_plane_requires_is_refused_when_absent() {
    let table: &[(&'static str, Dest)] = &[];
    let required: &[&'static str] = &["pools"];
    let read = |text: &str| read_with(serde_yaml::Deserializer::from_str(text), table, required);

    let err =
        read("listen: \"127.0.0.1:0\"\n").expect_err("pools is required by a registered plane");
    assert_eq!(err.to_string(), "missing field `pools`");
    read("pools: {}\n").expect("carried, so accepted");
}

#[test]
fn a_section_a_plane_owns_beside_its_own_is_lifted_raw_for_it() {
    let table: &[(&'static str, Dest)] = &[
        (
            "beside_declaring",
            Dest::Raw(PlaneMetadata {
                key: "neutral-test-owns-beside",
                noun: "pool",
            }),
        ),
        (
            "beside_owned",
            Dest::Raw(PlaneMetadata {
                key: "beside_owned",
                noun: "entry",
            }),
        ),
    ];
    let required: &[&'static str] = &[];
    let read = |text: &str| read_with(serde_yaml::Deserializer::from_str(text), table, required);

    let deploy: DeployCfg = read(
        "beside_declaring:\n  a: 1\nbeside_owned:\n  receiver: true\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect("a section a registered plane owns must parse");
    let written: serde_yaml::Value = serde_yaml::from_str("receiver: true").unwrap();
    assert_eq!(deploy.plane_raw.get("beside_owned"), Some(&written));
    assert_eq!(deploy.door_sections().get("beside_owned"), Some(&written));
    let bare: DeployCfg = read("beside_declaring:\n  a: 1\nproviders: {}\nmodels: {}\npools: {}\n")
        .expect("the plane's own section alone parses");
    assert!(!bare.plane_raw.contains_key("beside_owned"));
}
