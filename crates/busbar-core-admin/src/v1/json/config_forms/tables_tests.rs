// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

fn agrees<T: DeserializeOwned>(name: &str, cases: &[Value]) {
    let mut schema = super::super::schema_document();
    // Retain the full definition graph, without inheriting a document-root shape.
    let definitions = schema["$defs"].take();
    schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema",
        "x-busbar-settings-profile":"integer-token-v1", "$defs":definitions,
        "$ref":format!("#/$defs/{name}")});
    let validator = super::super::validator(&schema);
    for case in cases {
        let actual = serde_json::from_value::<T>(case.clone()).is_ok();
        assert_eq!(validator.is_valid(case), actual, "{name}: {case}");
    }
}

#[test]
fn provider_tables_match_owned_input_deserializers() {
    use busbar_kernel::config::providers::{ProviderDef, ProviderDeploy};
    agrees::<ProviderDeploy>(
        "ProviderDeployment",
        &[
            json!({"api_key":"none"}),
            json!({}),
            json!({"api_key":null}),
            json!({"api_key":{"env":"PROVIDER_KEY"},"base_url":null,"error_map":null,
            "allow_metadata_hosts":null,"health":null}),
            json!({"api_key":"none","future-plane-option":{"opaque":[1,null,true]}}),
            json!({"api_key":"none","health":{"mode":"active","interval_secs":0}}),
            json!({"api_key":"none","health":{"mode":"wrong"}}),
            json!({"api_key":"none","health":{"interval_secs":1.0}}),
            json!({"api_key":"none","health":{"unknown":true}}),
            json!({"api_key":"none","error_map":{"429":"busy"}}),
            json!({"api_key":"none","error_map":{"429":429}}),
        ],
    );
    agrees::<ProviderDef>(
        "ProviderCatalogEntry",
        &[
            json!({"protocol":"opaque","base_url":"http://localhost"}),
            json!({"protocol":"opaque"}),
            json!({"base_url":"http://localhost"}),
            json!({"protocol":null,"base_url":"http://localhost"}),
            json!({"protocol":"opaque","base_url":"http://localhost","error_map":null}),
            json!({"protocol":"opaque","base_url":"http://localhost","allow_metadata_hosts":null}),
            json!({"protocol":"opaque","base_url":"http://localhost","health":null,
            "future-plane-option":{"value":true}}),
        ],
    );
}

#[test]
fn model_table_preserves_nullable_defaults_and_integer_tokens() {
    use busbar_contract::config::ModelCfg;
    agrees::<ModelCfg>(
        "Model",
        &[
            json!({"provider":"p"}),
            json!({}),
            json!({"provider":"p","max_requests":null}),
            json!({"provider":"p","max_requests":-1}),
            json!({"provider":"p","max_requests":i64::MIN}),
            json!({"provider":"p","max_requests":u64::MAX}),
            json!({"provider":"p","max_requests":1.0}),
            json!({"provider":"p","max_concurrent":null,"reasoning":null,"protocol":null}),
            json!({"provider":"p","max_concurrent":0,"default_max_tokens":0}),
            json!({"provider":"p","max_concurrent":-1}),
            json!({"provider":"p","default_max_tokens":u64::from(u32::MAX)+1}),
            json!({"provider":"p","attempt_timeout_ms":u64::MAX}),
            json!({"provider":"p","prompt_caching":true}),
            json!({"provider":"p","unexpected":true}),
        ],
    );
}

#[test]
fn pool_table_preserves_shorthand_reserved_keys_and_custom_serde() {
    use busbar_kernel::config::pools::{PoolCfg, PoolMember};
    agrees::<PoolMember>(
        "PoolMember",
        &[
            json!("a"),
            json!(""),
            json!({"model":"a"}),
            json!({}),
            json!(null),
            json!({"model":"a","weight":0,"tags":[]}),
            json!({"model":"a","weight":1.0}),
            json!({"model":"a","weight":u64::from(u32::MAX)+1}),
            json!({"model":"a","tags":null}),
            json!({"model":"a","cost_per_mtok":1}),
        ],
    );
    agrees::<PoolCfg>(
        "Pool",
        &[
            json!({}),
            json!({"members":["a",{"model":"b","tier":null}]}),
            json!({"members":null}),
            json!({"weights":null}),
            json!({"hooks":null,"breaker":null,"upstream_credentials":null}),
            json!({"hooks":["weighted","gate"]}),
            json!({"hooks":[{"strategy":"custom"},"gate"]}),
            json!({"hooks":[{"strategy":"custom","extra":true}]}),
            json!({"hooks":["weighted","cheapest"]}),
            json!({"hooks":["weighted",{"strategy":"custom"}]}),
            json!({"hooks":["  "]}),
            json!({"hooks":[{"strategy":""}]}),
            json!({"breaker":{"trip":{"threshold":2.0}}}),
            json!({"failover":{"timeout_secs":0,"max_hops":0}}),
            json!({"affinity":{"mode":"sticky"}}),
            json!({"on_exhausted":"least_bad"}),
            json!({"on_exhausted":{"fallback_pool":"cold"}}),
            json!({"on_exhausted":{"fallback_pool":" "}}),
            json!({"on_exhausted":{"queue":{"max_ms":0}}}),
            json!({"on_exhausted":{"queue":{"max_ms":1.0}}}),
            json!({"on_exhausted":{"fallback_pool":"cold","queue":{"max_ms":1}}}),
            json!({"policy":"weighted"}),
        ],
    );
    // PoolsCfg adds a runtime plane-registry lookup. Its grammar is owned by split_section,
    // which is callable without installing a plane and owns reserved-key extraction.
    #[derive(serde::Deserialize)]
    struct PoolsInput(
        #[serde(deserialize_with = "pools_input")]
        #[allow(dead_code)]
        busbar_contract::section::Section<PoolCfg>,
    );
    fn pools_input<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<busbar_contract::section::Section<PoolCfg>, D::Error> {
        busbar_contract::section::split_section(deserializer, "pools", "pool", |_, _| Ok(()))
    }
    agrees::<PoolsInput>(
        "Pools",
        &[
            json!({}),
            json!({"hooks":[],"upstream_credentials":"own","p":{"members":["a"]}}),
            json!({"hooks":null}),
            json!({"hooks":{"members":["a"]}}),
            json!({"upstream_credentials":null}),
            json!({"upstream_credentials":{"members":["a"]}}),
            json!({"p":null}),
            json!({"p":{"members":null,"weights":null,"repeatable":null}}),
            json!({"p":{"members":[{"model":"a","tags":null}]}}),
            json!({"p":{"members":[null]}}),
            json!({"p":{"members":[]}}),
        ],
    );
}
