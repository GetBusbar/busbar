// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The protocols a provider may name come from what this read's admitted planes declare
//! (DELETE-OLD-INTERFACE v2, step E7): a new-interface plane states them in `describe`
//! (D_DIALECT), and core keeps no list of its own.

use std::collections::BTreeSet;

use crate::config::grammar::PreparedConfigRead;
use crate::config::Grammar;
use crate::plane_driver::provider_catalog::ProviderPlane;

/// A read whose one admitted provider plane (`llm`) states `dialects` in its description.
fn read_declaring(dialects: &[&str]) -> PreparedConfigRead {
    PreparedConfigRead::new(Grammar::empty()).with_provider_planes(vec![ProviderPlane {
        instance: "llm".into(),
        image: "busbar-plane-llm".into(),
        dialects: dialects
            .iter()
            .map(|d| (*d).to_owned())
            .collect::<BTreeSet<_>>(),
        schema: "{}".into(),
    }])
}

/// A provider whose `protocol` an admitted new-interface plane declares validates: before this
/// step the set was read from the old-interface plane rows alone, empty in the default build, so
/// every provider was refused "unknown protocol 'openai' (supported: )".
#[test]
fn a_protocol_an_admitted_plane_declares_validates() {
    let read = read_declaring(&["anthropic", "gemini", "openai"]);
    let supported = super::supported_provider_dialects(Some(&read));
    for protocol in ["openai", "anthropic", "gemini"] {
        assert!(
            supported.contains(&protocol),
            "the admitted plane declares '{protocol}', so it is supported: {supported:?}"
        );
        assert_eq!(
            super::provider_protocol_refusal(&supported, "mock", protocol),
            None,
            "a provider naming '{protocol}' validates"
        );
    }
}

/// A protocol no admitted plane declares is still refused, and the refusal names the supported ones.
#[test]
fn a_protocol_no_admitted_plane_declares_is_refused_naming_the_supported_ones() {
    let read = read_declaring(&["anthropic", "openai"]);
    let supported = super::supported_provider_dialects(Some(&read));
    let refusal = super::provider_protocol_refusal(&supported, "mock", "nope")
        .expect("a protocol no admitted plane declares is refused");
    assert!(
        refusal.contains("provider 'mock' uses unknown protocol 'nope'"),
        "{refusal}"
    );
    assert!(
        refusal.contains("anthropic") && refusal.contains("openai"),
        "the refusal names every supported protocol: {refusal}"
    );
}

/// With no admitted plane declaring any protocol, a provider is refused and the refusal says why
/// instead of listing nothing.
#[test]
fn with_no_declaring_plane_the_refusal_says_none_is_supported() {
    let read = read_declaring(&[]);
    let supported = super::supported_provider_dialects(Some(&read));
    let refusal = super::provider_protocol_refusal(&supported, "mock", "openai")
        .expect("no plane declares 'openai'");
    assert!(
        refusal.contains("no admitted plane declares a provider protocol"),
        "{refusal}"
    );
}
