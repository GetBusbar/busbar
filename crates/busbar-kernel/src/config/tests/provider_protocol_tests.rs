// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The protocols a provider may name come from what the planes this read admitted declare
//! (DELETE-OLD-INTERFACE v2, step E7): a new-interface plane states them in `describe`
//! (D_DIALECT), and core keeps no list of its own. Judged where the configuration is resolved
//! with those planes: the boot's typed configuration carries no prepared read, so a judgement
//! made later from the configuration alone saw no plane and refused every provider
//! ("unknown protocol 'openai' (supported: )").

use crate::config::{self, providers, Grammar};
use crate::plane_driver::provider_catalog::ProviderPlane;

/// The one admitted provider plane (`llm`), stating `dialects` in its description.
fn plane_declaring(dialects: &[&str]) -> ProviderPlane {
    ProviderPlane {
        instance: "llm".into(),
        image: "busbar-plane-llm".into(),
        dialects: dialects.iter().map(|d| (*d).to_owned()).collect(),
        schema: r#"{"type":"object","additionalProperties":false}"#.into(),
    }
}

/// Resolve one provider `mock` naming `protocol`, reached by one model, under `planes`.
fn resolve(protocol: &str, planes: &[ProviderPlane]) -> Result<(), Vec<String>> {
    let grammar = Grammar::empty();
    let catalog = providers::catalog_from_str(
        &format!("mock:\n  protocol: {protocol}\n  base_url: https://upstream.example\n"),
        &grammar,
    )
    .expect("the catalog parses");
    let deploy = config::deploy_from_yaml_str(
        "providers:\n  mock: {api_key: none}\nmodels:\n  m: {provider: mock}\n",
        &grammar,
    )
    .expect("the deployment parses");
    config::resolve_with_provider_planes(&deploy, &catalog, planes).map(|_| ())
}

/// A provider whose `protocol` an admitted plane declares resolves.
#[test]
fn a_protocol_an_admitted_plane_declares_resolves() {
    let planes = [plane_declaring(&["anthropic", "gemini", "openai"])];
    for protocol in ["openai", "anthropic", "gemini"] {
        if let Err(errors) = resolve(protocol, &planes) {
            panic!("a provider naming '{protocol}' resolves: {errors:?}");
        }
    }
}

/// A protocol no admitted plane declares is refused at resolve, naming the supported ones.
#[test]
fn a_protocol_no_admitted_plane_declares_is_refused_naming_the_supported_ones() {
    let planes = [plane_declaring(&["anthropic", "openai"])];
    let errors = resolve("nope", &planes).expect_err("an undeclared protocol is refused");
    assert!(
        errors.iter().any(|e| e.contains(
            "provider 'mock' uses unknown protocol 'nope' (supported: anthropic, openai)"
        )),
        "{errors:?}"
    );
}

/// The supported set is every admitted plane's declared dialects, each once.
#[test]
fn the_supported_set_is_what_the_admitted_planes_declare() {
    let mut second = plane_declaring(&["openai", "responses"]);
    second.instance = "llm-2".into();
    let planes = [plane_declaring(&["anthropic", "openai"]), second];
    let supported = super::supported_provider_dialects(&planes);
    assert_eq!(supported, ["anthropic", "openai", "responses"]);
    assert_eq!(
        super::provider_protocol_refusal(&supported, "mock", "openai"),
        None
    );
}

/// With no admitted plane declaring any protocol, the refusal says why instead of listing nothing.
#[test]
fn with_no_declaring_plane_the_refusal_says_none_is_supported() {
    let supported = super::supported_provider_dialects(&[]);
    let refusal = super::provider_protocol_refusal(&supported, "mock", "openai")
        .expect("no plane declares 'openai'");
    assert!(
        refusal.contains("supported: none; no admitted plane declares a provider protocol"),
        "{refusal}"
    );
}
