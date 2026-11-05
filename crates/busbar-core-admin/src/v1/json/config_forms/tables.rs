// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Input tables owned by the kernel and contract, rather than admin readback DTOs.
use serde_json::{json, Map, Value};

fn reference(name: &str) -> Value {
    json!({"$ref": format!("#/$defs/{name}")})
}

fn nullable(value: Value) -> Value {
    json!({"anyOf": [value, {"type": "null"}], "default": null})
}

fn unsigned(maximum: u64) -> Value {
    json!({"type":"integer", "minimum":0, "maximum":maximum,
        "x-busbar-integer-token":"unsigned"})
}

fn defaulted(mut value: Value, default: Value) -> Value {
    value["default"] = default;
    value
}

fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object", "properties":properties, "required":required,
        "additionalProperties":false})
}

pub(super) fn definitions() -> Map<String, Value> {
    let string = json!({"type":"string"});
    let strings = json!({"type":"array", "items":{"type":"string"}});
    let boolean = json!({"type":"boolean"});
    let u64_value = unsigned(u64::MAX);
    let usize_value = unsigned(usize::MAX as u64);
    let u32_value = unsigned(u64::from(u32::MAX));
    let mut defs = Map::new();
    defs.insert(
        "ProviderHealth".into(),
        object(
            json!({
                "mode":{"type":"string","enum":["none","dead","active"],"default":"none"},
                "interval_secs":nullable(u64_value.clone()),
                "timeout_secs":nullable(u64_value.clone())
            }),
            &[],
        ),
    );
    defs.insert(
        "UpstreamCredentials".into(),
        json!({"type":"string","enum":["own","passthrough"]}),
    );
    for (name, deployment) in [
        ("ProviderDeployment", true),
        ("ProviderCatalogEntry", false),
    ] {
        let mut properties = Map::new();
        for name in [
            "protocol",
            "base_url",
            "path",
            "path_base",
            "token_url",
            "scope",
            "subject",
        ] {
            properties.insert(
                name.into(),
                if !deployment && matches!(name, "protocol" | "base_url") {
                    string.clone()
                } else {
                    nullable(string.clone())
                },
            );
        }
        properties.insert("auth".into(), nullable(json!({"type":"string",
            "x-busbar-runtime-validation":"Must name an outbound style declared by an admitted auth plugin."})));
        properties.insert("health".into(), nullable(reference("ProviderHealth")));
        let error_map = json!({"type":"object","additionalProperties":{"type":"string"}});
        properties.insert(
            "error_map".into(),
            if deployment {
                nullable(error_map)
            } else {
                defaulted(error_map, json!({}))
            },
        );
        properties.insert(
            "allow_metadata_hosts".into(),
            if deployment {
                nullable(strings.clone())
            } else {
                defaulted(strings.clone(), json!([]))
            },
        );
        if deployment {
            properties.insert("api_key".into(), reference("SecretRef"));
        }
        let mut schema = object(
            Value::Object(properties),
            if deployment {
                &["api_key"]
            } else {
                &["protocol", "base_url"]
            },
        );
        schema["additionalProperties"] = json!(true);
        schema["x-busbar-opaque-options"] = json!({"owner":"speaking-plane", "validation":"Additional keys are validated against the loaded plane's provider-key descriptor and protocol capabilities; this schema does not enumerate protocol options."});
        schema["x-busbar-runtime-validation"] = json!([
            "Loaded auth styles and plane descriptors",
            "Provider/catalog resolution and credential trust scope",
            "Destination and protocol capability validation"
        ]);
        defs.insert(name.into(), schema);
    }
    let mut model = object(
        json!({
            "provider":string,
            "max_requests": {"type":"integer","minimum":i64::MIN,"maximum":i64::MAX,"default":-1,"x-busbar-integer-token":"signed"},
            "max_concurrent":nullable(usize_value.clone()),
            "default_max_tokens":nullable(u32_value.clone()),
            "upstream_model":nullable(string.clone()),
            "attempt_timeout_ms":nullable(u64_value.clone()),
            "reasoning":nullable(boolean.clone()),
            "prompt_caching":nullable(boolean.clone()),
            "protocol":nullable(string.clone())
        }),
        &["provider"],
    );
    model["x-busbar-runtime-validation"] = json!([
        "Provider and protocol resolution",
        "Positive concurrency/token limits and supported semaphore capacity"
    ]);
    defs.insert("Model".into(), model);
    defs.insert(
        "PoolRichMember".into(),
        object(
            json!({
                "model":string,
                "weight":defaulted(u32_value.clone(),json!(1)),
                "context_max":nullable(usize_value.clone()),
                "tier":nullable(string.clone()),
                "attempt_timeout_ms":nullable(u64_value.clone()),
                "reasoning":nullable(boolean),
                "tags":defaulted(strings.clone(),json!([]))
            }),
            &["model"],
        ),
    );
    defs.insert(
        "PoolMember".into(),
        json!({"oneOf":[string,reference("PoolRichMember")]}),
    );
    defs.insert(
        "PoolBreakerTrip".into(),
        object(
            json!({
                "mode":{"type":"string","enum":["error_rate","consecutive"],"default":"error_rate"},
                "window_secs":defaulted(u64_value.clone(),json!(30)),
                "threshold":{"type":"number","default":0.5},
                "min_requests":defaulted(usize_value.clone(),json!(5)),
                "consecutive_n":defaulted(u32_value.clone(),json!(3))
            }),
            &[],
        ),
    );
    defs.insert(
        "PoolBreaker".into(),
        object(
            json!({
                "base_cooldown_secs":defaulted(u64_value.clone(),json!(15)),
                "max_cooldown_secs":defaulted(u64_value.clone(),json!(120)),
                "trip":nullable(reference("PoolBreakerTrip"))
            }),
            &[],
        ),
    );
    defs.insert(
        "PoolFailover".into(),
        object(
            json!({
                "timeout_secs":defaulted(u64_value.clone(),json!(120)),
                "exclusions":nullable(strings.clone()),
                "max_hops":defaulted(usize_value,json!(3))
            }),
            &[],
        ),
    );
    let nonempty = json!({"type":"string","pattern":"\\S"});
    defs.insert(
        "PoolOnExhausted".into(),
        json!({"oneOf":[
            {"type":"string","enum":["reject","least_bad"]},
            object(json!({"fallback_pool":nonempty}), &["fallback_pool"]),
            object(json!({"queue":object(json!({"max_ms":u64_value}), &["max_ms"])}), &["queue"])
        ]}),
    );
    defs.insert(
        "PoolAffinity".into(),
        object(
            json!({
                "mode":{"type":"string","enum":["session"],"default":"session"},
                "header_name":nullable(string.clone())
            }),
            &[],
        ),
    );
    let hook = json!({"oneOf":[nonempty,object(json!({"strategy":nonempty}), &["strategy"])]});
    let mut hooks = json!({"type":"array","items":hook,
        "contains":{"anyOf":[{"type":"object"},{"enum":["weighted","cheapest","fastest","least_busy","usage"]}]},
        "minContains":0,"maxContains":1});
    hooks = nullable(hooks);
    let mut pool = object(
        json!({
            "members":defaulted(json!({"type":"array","items":reference("PoolMember")}),json!([])),
            "breaker":nullable(reference("PoolBreaker")),
            "failover":nullable(reference("PoolFailover")),
            "on_exhausted":nullable(reference("PoolOnExhausted")),
            "affinity":nullable(reference("PoolAffinity")),
            "hooks":hooks,
            "upstream_credentials":nullable(reference("UpstreamCredentials")),
            "weights":defaulted(json!({"type":"object","additionalProperties":u32_value}),json!({})),
            "tier":nullable(string),
            "attempt_timeout_ms":nullable(unsigned(u64::MAX)),
            "repeatable":defaulted(strings.clone(),json!([]))
        }),
        &[],
    );
    pool["x-busbar-runtime-validation"] = json!([
        "Member/hook/fallback references, admitted modules and trust scope",
        "Breaker, timeout and queue constraints including resolved failover budget",
        "Plane-specific member interchangeability and repeatable operation validation"
    ]);
    defs.insert("Pool".into(), pool.clone());
    // split_section deliberately deserializes each entry through serde_yaml::Value. Its sequence
    // and map visitors normalize null to empty; direct JSON deserialization of PoolCfg does not.
    // Keep that document grammar distinct rather than weakening the direct Pool input schema.
    let mut document_member = defs["PoolRichMember"].clone();
    document_member["properties"]["tags"] = nullable(defaulted(strings.clone(), json!([])));
    defs.insert("PoolDocumentRichMember".into(), document_member);
    defs.insert(
        "PoolDocumentMember".into(),
        json!({"oneOf":[
        {"type":"string"},reference("PoolDocumentRichMember")]}),
    );
    for field in ["members", "weights", "repeatable"] {
        let mut value = pool["properties"][field].take();
        if field == "members" {
            value["items"] = reference("PoolDocumentMember");
        }
        pool["properties"][field] = nullable(value);
    }
    defs.insert("PoolDocument".into(), nullable(pool));
    defs.insert("Pools".into(), json!({"type":"object","properties":{
        "hooks":nullable(defaulted(strings,json!([]))),
        "upstream_credentials":reference("UpstreamCredentials")
    },"additionalProperties":reference("PoolDocument"),
        "x-busbar-reserved-keys":["hooks","upstream_credentials"],
        "x-busbar-runtime-validation":"PoolsCfg requires a registered owning plane; reserved hooks are attached before per-pool hooks, and per-pool upstream_credentials replaces the section default (own when absent)."}));
    defs
}

#[cfg(test)]
#[path = "tables_tests.rs"]
mod tests;
