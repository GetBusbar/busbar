// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-DESCRIBE-PATHS: the `Describe` methods a plugin calls to say where in its config core must act, driven the
//! way a plugin drives them (`busbar_plugin_abi::plugin::Describe`) and judged by what the host did because the
//! plugin called them: `trust_path` (a PEM CA becomes a trust handle), `ref_path` (a secret reference is resolved
//! before open), `public_url_path` and `caller_upstreams_path` (core writes its values only there) and
//! `item_nested` (a nested describe item reaches the registry typed).
use busbar_plugin_abi::fail::{refused, Fail};
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Endpoints, Open};
use busbar_plugin_abi::records::{Full, Out};
use busbar_plugin_test::suites::harness::{Harness, OpenError};
use busbar_plugin_test::FakeNeeds;

mod paths_fixture {
    use super::*;
    use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
    use busbar_plugin_abi::plugin::Describe;

    /// Opens only when the node at `ca_cert_pem` is a trust handle (`{"$trust": n}`) and the node at `url` is the
    /// resolved reference text.
    pub struct Fixture;

    impl Open for Fixture {
        async fn open(_: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
            let value = json::parse_value(&config.to_vec())
                .map_err(|_| Fail::refused(refused::R_CONFIG))?;
            let trust = value
                .get("ca_cert_pem")
                .and_then(|n| n.as_object())
                .is_some_and(|n| n.get(&"$trust").is_some());
            if !trust {
                return Err(Fail::refused_because(
                    refused::R_CONFIG,
                    "ca_cert_pem is not a trust handle",
                ));
            }
            if value.get("url").and_then(|n| n.as_str()) != Some("https://resolved.example") {
                return Err(Fail::refused_because(
                    refused::R_CONFIG,
                    "url is not the resolved text",
                ));
            }
            Ok(Self)
        }

        fn check(_: &Host, _: &[u8], _: &mut Endpoints<'_>) -> Result<(), Fail> {
            Ok(())
        }

        fn describe(d: &mut Describe<'_>) {
            d.schema(r#"{"type":"object"}"#)
                .trust_path("/ca_cert_pem")
                .ref_path("/url");
        }

        fn settled(&self, _: &mut Out<'_>) -> Result<(), Full> {
            Ok(())
        }
    }

    impl busbar_plugin_abi::Auth for Fixture {}
    busbar_plugin_abi::plugin!(Auth, Fixture, name: "fixture-describe-paths");
}

mod plane_fixture {
    use super::*;
    use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
    use busbar_plugin_abi::plane::{PlaneReq, Target};
    use busbar_plugin_abi::plugin::Describe;
    use busbar_plugin_abi::records::Writer;
    use busbar_plugin_abi::types::Bytes;

    /// Opens only when core wrote `public_url` and `caller_upstreams` where the describe said to.
    pub struct Fixture;

    impl Open for Fixture {
        async fn open(_: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
            let value = json::parse_value(&config.to_vec())
                .map_err(|_| Fail::refused(refused::R_CONFIG))?;
            if value.get("public_url").and_then(|n| n.as_str()) != Some("https://busbar.example") {
                return Err(Fail::refused_because(
                    refused::R_CONFIG,
                    "public_url is not core's value",
                ));
            }
            let names: Vec<&str> = value
                .get("caller_upstreams")
                .and_then(|n| n.as_array())
                .map(|a| a.iter().filter_map(|n| n.as_str()).collect())
                .unwrap_or_default();
            if names != ["alpha", "beta"] {
                return Err(Fail::refused_because(
                    refused::R_CONFIG,
                    "caller_upstreams is not core's list",
                ));
            }
            Ok(Self)
        }

        fn check(_: &Host, _: &[u8], _: &mut Endpoints<'_>) -> Result<(), Fail> {
            Ok(())
        }

        fn describe(d: &mut Describe<'_>) {
            use busbar_plugin_abi::plane::tag as pt;
            use busbar_plugin_abi::records::tag as rt;
            d.schema(r#"{"type":"object"}"#)
                .public_url_path("/public_url")
                .caller_upstreams_path("/caller_upstreams")
                .item_text(pt::D_DIALECT, "fixture-dialect")
                .item_nested(pt::D_DIALECT_AUTH, |n| {
                    n.put_text(rt::TEXT, "fixture-dialect")?;
                    n.put_text(rt::TEXT, "header")?;
                    n.put_text(pt::DA_KEY_HEADER, "x-fixture-key")
                });
        }

        fn settled(&self, _: &mut Out<'_>) -> Result<(), Full> {
            Ok(())
        }
    }

    impl busbar_plugin_abi::Plane for Fixture {
        type Session = ();
        fn request(
            &self,
            _: &Host,
            _: &PlaneReq<'_>,
            _: Bytes<'_>,
            _: &mut Out<'_>,
        ) -> Result<(), Fail> {
            Err(Fail::unsupported())
        }
        fn upstream(
            &self,
            _: &Host,
            _: &mut (),
            _: &Target<'_>,
            _: &mut Out<'_>,
        ) -> Result<(), Fail> {
            Ok(())
        }
        fn piece(
            &self,
            _: &Host,
            _: &mut (),
            _: u32,
            _: u32,
            _: u32,
            _: Bytes<'_>,
            _: &mut Out<'_>,
        ) -> Result<(), Fail> {
            Ok(())
        }
        fn end(&self, _: &Host, _: (), _: &mut Out<'_>) -> Result<(), Fail> {
            Ok(())
        }
    }

    busbar_plugin_abi::plugin!(Plane, Fixture, name: "fixture-describe-plane");
}

const TRUSTED: &[u8] = br#"{"ca_cert_pem":"PEM","url":"https://resolved.example"}"#;

fn paths_harness(needs: FakeNeeds) -> Harness {
    Harness::admit(paths_fixture::PLUGIN.plugin(), needs)
        .unwrap_or_else(|refusal| panic!("the fixture is admitted: {refusal:?}"))
}

fn plane_harness() -> Harness {
    Harness::admit(plane_fixture::PLUGIN.plugin(), FakeNeeds::new())
        .unwrap_or_else(|refusal| panic!("the fixture is admitted: {refusal:?}"))
}

fn is_config(result: &Result<(), OpenError>) -> bool {
    matches!(result, Err(OpenError::Config { code, .. }) if *code == refused::R_CONFIG)
}

#[test]
fn a_declared_trust_path_reaches_open_as_a_handle() {
    let h = paths_harness(FakeNeeds::new());
    h.open("t", TRUSTED)
        .map(drop)
        .expect("the PEM at the declared path is a trust handle");
}

#[test]
fn an_undeclared_trust_node_is_not_bound() {
    let h = paths_harness(FakeNeeds::new());
    let result = h
        .open("t", br#"{"other":"PEM","url":"https://resolved.example"}"#)
        .map(drop);
    assert!(is_config(&result), "{result:?}");
}

#[test]
fn a_declared_ref_path_is_resolved_before_open() {
    let mut needs = FakeNeeds::new();
    needs.secret("/url", b"https://resolved.example");
    let h = paths_harness(needs);
    h.open(
        "t",
        br#"{"ca_cert_pem":"PEM","url":{"module":"file","path":"/x"}}"#,
    )
    .map(drop)
    .expect("the reference at the declared path is resolved");
}

#[test]
fn core_writes_its_values_only_at_the_declared_paths() {
    let h = plane_harness();
    let names: [Box<str>; 2] = [Box::from("alpha"), Box::from("beta")];
    let mut spec = h.spec("p", b"{}");
    spec.public_url = Some("https://busbar.example");
    spec.caller_upstreams = &names;
    h.open_spec(&spec)
        .map(drop)
        .expect("core wrote public_url and caller_upstreams at the declared paths");
}

#[test]
fn a_nested_describe_item_reaches_the_registry_typed() {
    use busbar_ports::codec::plane::{DialectAuthOwned, PresentationOwned};
    let h = plane_harness();
    let rows = h.registry().dialect_auth();
    assert_eq!(
        rows,
        vec![(
            "fixture-describe-plane",
            vec![DialectAuthOwned {
                dialect: "fixture-dialect".into(),
                present: PresentationOwned::Header {
                    key_header: Some("x-fixture-key".into()),
                    own_header: None,
                    passthrough_header: None,
                    families: vec![],
                },
            }]
        )]
    );
}
