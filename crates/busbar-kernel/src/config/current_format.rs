// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Current-reader admission only. Historical conversions live in busbar-migrations.
use busbar_contract::yaml::{MappingExt, Value, ValueExt};

/// Reject retired structural forms before serde can discard their meaning.
/// This boundary supplies no historical defaults and performs no conversion.
pub fn detect_legacy_markers(doc: &Value) -> Vec<String> {
    let mut markers = Vec::new();
    let Some(root) = doc.as_mapping() else {
        return markers;
    };
    for key in [
        "governance",
        "group_map",
        "global_hooks",
        "observability",
        "admin_insecure",
    ] {
        if root.contains_key(key) {
            markers.push(format!("`{key}:` is not a current config field"));
        }
    }
    if let Some(auth) = root.get_key("auth").and_then(Value::as_mapping) {
        for key in ["mode", "client_tokens", "upstream_credentials", "methods"] {
            if auth.contains_key(key) {
                markers.push(format!("`auth.{key}:` is not a current config field"));
            }
        }
    }
    if let Some(providers) = root.get_key("providers").and_then(Value::as_mapping) {
        for (name, provider) in providers {
            if provider
                .as_mapping()
                .is_some_and(|p| p.contains_key("api_key_env"))
            {
                markers.push(format!(
                    "providers.{}.api_key_env is not a current field",
                    name.as_str().unwrap_or("<entry>")
                ));
            }
        }
    }
    if let Some(pools) = root.get_key("pools").and_then(Value::as_mapping) {
        for pool in pools.values() {
            let Some(pool) = pool.as_mapping() else {
                continue;
            };
            if let Some(members) = pool.get_key("members").and_then(Value::as_sequence) {
                if members
                    .iter()
                    .any(|m| m.as_mapping().is_some_and(|m| m.contains_key("target")))
                {
                    markers.push("pool member target is not a current field".into());
                }
            }
        }
    }
    markers
}

pub fn legacy_config_error(markers: &[String]) -> String {
    format!(
        "configuration is not in the current format; automatic normalization must resolve these fields before admission:\n  - {}",
        markers.join("\n  - ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OnExhaustedCfg, PoolCfg};

    #[test]
    fn current_exhaustion_keywords_reach_the_canonical_parser() {
        for (keyword, expected) in [
            ("reject", OnExhaustedCfg::Reject),
            ("least_bad", OnExhaustedCfg::LeastBad),
        ] {
            let document: Value = busbar_contract::yaml::from_str(&format!(
                "pools: {{op: {{members: [], on_exhausted: {keyword}}}}}"
            ))
            .unwrap();
            assert!(detect_legacy_markers(&document).is_empty());
            let pool: PoolCfg =
                busbar_contract::yaml::from_value(document.at("pools").at("op").clone()).unwrap();
            assert_eq!(pool.on_exhausted, Some(expected));
        }
        let document: Value = busbar_contract::yaml::from_str(
            "pools: {op: {members: [], on_exhausted: invalid_mode}}",
        )
        .unwrap();
        assert!(detect_legacy_markers(&document).is_empty());
        let error =
            busbar_contract::yaml::from_value::<PoolCfg>(document.at("pools").at("op").clone())
                .unwrap_err();
        assert!(error.to_string().contains("unknown on_exhausted keyword"));
    }
}
