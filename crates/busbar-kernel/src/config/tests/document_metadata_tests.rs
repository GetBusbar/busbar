// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::{resolve, ModelCfg, ProviderDeploy};
use std::collections::HashMap;

const RAW_SECTION: &str = "raw_section";

/// The recognizer a read gets from its admitted plane instance names.
fn names_of(instances: &[&str]) -> SectionNames {
    use crate::config::grammar::{Item, ItemKind, Standing};
    SectionNames::of(
        &Grammar::new(Default::default(), Default::default(), Vec::new()).with_items(
            instances
                .iter()
                .map(|name| Item {
                    kind: ItemKind::Section,
                    name: (*name).to_owned(),
                    module: "plane".to_owned(),
                    image: "linked".to_owned(),
                    standing: Standing::Counts,
                })
                .collect(),
        ),
    )
}

fn read_with<'de, D: Deserializer<'de>>(de: D, instances: &[&str]) -> Result<DeployCfg, D::Error> {
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
        _pools: Option<busbar_contract::yaml::Value>,
    }
    struct Document {
        names: SectionNames,
    }
    impl<'de> Visitor<'de> for Document {
        type Value = DeployCfg;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("the section metadata test document")
        }
        fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
            let (catalog, lifted) = read_document::<_, Catalog>(map, &self.names)?;
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
    de.deserialize_map(Document {
        names: names_of(instances),
    })
}

#[test]
fn a_recognized_section_is_lifted_raw_for_its_plane() {
    let read = |text: &str| {
        busbar_contract::yaml::with_deserializer(text, |d| read_with(d, &[RAW_SECTION]))
    };

    let deploy: DeployCfg = read(&format!(
        "{RAW_SECTION}:\n  greeting: hi\n  fees: {{ per_request: 3 }}\n\
         providers: {{}}\nmodels: {{}}\npools: {{}}\n",
    ))
    .expect("a section an admitted plane is named by must parse");
    let remainder: busbar_contract::yaml::Value =
        busbar_contract::yaml::from_str("greeting: hi").unwrap();
    assert_eq!(
        deploy.instance_sections.get(RAW_SECTION),
        Some(&remainder),
        "the section lands raw, its core-owned `fees` lifted off it"
    );
    assert_eq!(deploy.door_sections().get(RAW_SECTION), Some(&remainder));
    assert!(deploy.plane_fees.contains_key(RAW_SECTION));

    let root = crate::config::resolve(&deploy, &Default::default()).expect("resolves");
    assert!(
        root.plane_sections.contains(RAW_SECTION),
        "LAW 7: the plane is configured"
    );
    let resource = root
        .endpoint_resource(RAW_SECTION)
        .expect("its plane's resource");
    assert_eq!(
        resource.downcast_ref::<(&'static str, busbar_contract::yaml::Value)>(),
        Some(&(RAW_SECTION, remainder.clone())),
        "the resource is `(section, value)`"
    );
    assert_eq!(root.instance_sections().get(RAW_SECTION), Some(&remainder));

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
    let read = |text: &str| busbar_contract::yaml::with_deserializer(text, |d| read_with(d, &[]));

    let err = read(
        "decisions:\n  \
           models:\n    \
             verdict: { provider: typesafe }\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect_err("a `decisions:` block no admitted plane is named by must be refused")
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
fn no_section_is_required_and_an_omitted_one_reads_empty() {
    let read = |text: &str| busbar_contract::yaml::with_deserializer(text, |d| read_with(d, &[]));
    const NO_CATALOG: &str = "listen: \"127.0.0.1:0\"\npools: {}\n";

    let deploy = read(NO_CATALOG).expect("no plane requires a catalog section (r3 section 2.5)");
    assert!(deploy.providers.is_empty(), "{:?}", deploy.providers.keys());
    assert!(deploy.models.is_empty(), "{:?}", deploy.models.keys());
    let value: busbar_contract::yaml::Value = busbar_contract::yaml::from_str(NO_CATALOG).unwrap();
    read_with(busbar_contract::yaml::deserializer(value), &[]).expect("the in-memory path agrees");

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
            .starts_with("no_such_key: unknown field `no_such_key`, expected one of"),
        "{err}"
    );
}

#[test]
fn two_recognized_sections_each_reach_the_door_beside_their_own_pricing() {
    let read = |text: &str| {
        busbar_contract::yaml::with_deserializer(text, |d| {
            read_with(d, &["beside_declaring", "beside_owned"])
        })
    };

    let deploy: DeployCfg = read(
        "beside_declaring:\n  a: 1\n  fees: { per_request: 3 }\nbeside_owned:\n  receiver: true\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect("two sections admitted planes are named by must parse");
    let written: busbar_contract::yaml::Value =
        busbar_contract::yaml::from_str("receiver: true").unwrap();
    assert_eq!(deploy.instance_sections.get("beside_owned"), Some(&written));
    assert_eq!(deploy.door_sections().get("beside_owned"), Some(&written));
    assert!(deploy.plane_fees.contains_key("beside_declaring"));
    let bare: DeployCfg = read("beside_declaring:\n  a: 1\nproviders: {}\nmodels: {}\npools: {}\n")
        .expect("the plane's own section alone parses");
    assert!(!bare.instance_sections.contains_key("beside_owned"));
}

#[test]
fn data_listener_provenance_distinguishes_omitted_explicit_default_and_empty() {
    let read =
        |text: &str| busbar_contract::yaml::with_deserializer(text, |d| read_with(d, &[])).unwrap();
    let omitted = read("providers: {}\nmodels: {}\n");
    assert!(!omitted.listen_explicit);
    let explicit = read(&format!(
        "providers: {{}}\nmodels: {{}}\nlisten: '{}'\n",
        crate::config::DEFAULT_LISTEN_ADDR,
    ));
    assert!(explicit.listen_explicit);
    assert_eq!(omitted.listen, explicit.listen);
    let empty = read("providers: {}\nmodels: {}\nlisten: ''\n");
    assert!(empty.listen_explicit);
    assert!(empty.listen.is_empty());
}

#[test]
fn overlay_data_listener_is_an_explicit_requirement() {
    let mut deploy = crate::config::tests::base_deploy();
    assert!(!deploy.listen_explicit);
    let settings = crate::config::overlay::RootSettings {
        listen: Some(deploy.listen.clone()),
        ..Default::default()
    };
    settings.apply_to_deploy(&mut deploy);
    assert!(deploy.listen_explicit);
}
