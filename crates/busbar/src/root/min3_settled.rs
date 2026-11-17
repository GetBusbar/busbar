// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core-owned mapping of admitted instances' actual CONFIG answers into the migration writer.

use super::Configured;
use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
use busbar_contract::secure::SecureString;
use busbar_plugin_abi::{records::tag, types::KindCode};
use busbar_plugin_loader::instance::{Described, Settled};

pub(super) fn answer(
    index: u32,
    instance: &Configured,
    described: &Described,
    settled: Settled,
) -> Result<busbar_migrate::Settled, String> {
    let config = json::parse_value(settled.config_json.as_slice())
        .map_err(|_| format!("CONFIG: instance {index} returned invalid CONFIG"))?;
    let registrations: Vec<_> = described.paths(tag::D_UPSTREAM_PATH).collect();
    let core = busbar_kernel::upstreams::core_secret_paths(&config, &registrations)
        .map_err(|errors| format!("CONFIG: instance {index}: {}", errors.join("; ")))?;
    let consumed = busbar_kernel::upstreams::core_field_paths(&config, &registrations)
        .map_err(|errors| format!("CONFIG: instance {index}: {}", errors.join("; ")))?;
    let mut allowed_lifts = std::collections::BTreeSet::new();
    for path in described.paths(tag::D_SECRET_PATH) {
        expand(&config, path, &mut allowed_lifts)?;
    }
    allowed_lifts.retain(|path| {
        !consumed.iter().any(|prefix| {
            path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|tail| tail.starts_with('/'))
        })
    });
    allowed_lifts.extend(core);
    // The literals this instance was handed at its declared secret positions (#441): the settled
    // document may hold none of them in plaintext.
    let known_secrets = json::parse_value(&instance.config)
        .map(|input| {
            let mut positions = std::collections::BTreeSet::new();
            for path in described.paths(tag::D_SECRET_PATH) {
                let _ = expand(&input, path, &mut positions);
            }
            positions
                .iter()
                .filter_map(|position| json::pointer(&input, position))
                .filter_map(|value| value.as_str())
                .filter(|text| !text.is_empty())
                .map(SecureString::from)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let (path, placement) = match instance.kind {
        KindCode::Plane => (
            vec![instance.name.clone()],
            busbar_migrate::BagPlacement::Block,
        ),
        KindCode::Store => (
            vec!["store".to_owned()],
            busbar_migrate::BagPlacement::Settings,
        ),
        KindCode::Secret => (
            vec!["secrets".to_owned(), instance.name.clone()],
            busbar_migrate::BagPlacement::Settings,
        ),
        _ => {
            return Err(format!(
                "CONFIG: instance {index} has no authored settlement path"
            ))
        }
    };
    let core_cfg = settled
        .core_cfg
        .into_iter()
        .map(|fragment| {
            let value = json::parse_value(fragment.value_json.as_slice())
                .map_err(|_| "invalid JSON".to_owned())
                .and_then(|value| json::to_yaml(&value))
                .map_err(|_| format!("CONFIG: instance {index} returned invalid CORE_CFG"))?;
            Ok(busbar_migrate::CoreCfg {
                section: fragment.section,
                name: fragment.name.into(),
                value,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let settings = core::str::from_utf8(settled.config_json.as_slice())
        .map_err(|_| format!("CONFIG: instance {index} returned invalid CONFIG"))?;
    Ok(busbar_migrate::Settled {
        index,
        path,
        placement,
        settings: Some(SecureString::from(settings)),
        core_cfg,
        allowed_lifts,
        known_secrets,
    })
}

fn expand(
    config: &json::Value,
    pattern: &str,
    out: &mut std::collections::BTreeSet<String>,
) -> Result<(), String> {
    let tokens = if pattern.is_empty() {
        Vec::new()
    } else {
        pattern
            .strip_prefix('/')
            .ok_or("CONFIG: malformed described secret pointer")?
            .split('/')
            .map(|token| {
                let mut result = String::new();
                let mut chars = token.chars();
                while let Some(ch) = chars.next() {
                    result.push(match ch {
                        '~' => match chars.next() {
                            Some('0') => '~',
                            Some('1') => '/',
                            _ => {
                                return Err("CONFIG: malformed described secret pointer".to_owned())
                            }
                        },
                        other => other,
                    });
                }
                Ok(result)
            })
            .collect::<Result<Vec<_>, String>>()?
    };
    fn walk(
        node: &json::Value,
        tokens: &[String],
        path: String,
        out: &mut std::collections::BTreeSet<String>,
    ) {
        let Some((head, rest)) = tokens.split_first() else {
            out.insert(path);
            return;
        };
        if let Some(items) = node.as_array() {
            for (index, child) in items.iter().enumerate() {
                if head == "*" || head == &index.to_string() {
                    walk(child, rest, format!("{path}/{index}"), out);
                }
            }
        } else if let Some(child) = node.get(head.as_str()) {
            let escaped = head.replace('~', "~0").replace('/', "~1");
            walk(child, rest, format!("{path}/{escaped}"), out);
        }
    }
    walk(config, &tokens, String::new(), out);
    Ok(())
}

/// Pure post-LIFT validation; no secret resolution, backend read or plugin entry.
pub(super) fn candidate(text: &str, planes: &[(String, Vec<String>)]) -> Result<(), String> {
    use busbar_contract::yaml::ValueExt;
    let resolved = SecureString::from(busbar_kernel::config::interpolate_env(text)?);
    let doc: busbar_contract::yaml::Value = busbar_contract::yaml::from_str(resolved.as_str())
        .map_err(|_| "CONFIG: settled document is invalid YAML".to_owned())?;
    for (name, pointers) in planes {
        let empty = busbar_contract::yaml::Value::Map(Vec::new());
        let bag = doc.get(name.as_str()).unwrap_or(&empty);
        let authored =
            json::to_value(bag).map_err(|_| format!("CONFIG: {name}: settled bag is not JSON"))?;
        let pointers: Vec<_> = pointers.iter().map(String::as_str).collect();
        busbar_kernel::upstreams::declared(
            name,
            &authored,
            &pointers,
            &busbar_kernel::plugin_config::upstream_anchor,
        )
        .map_err(|errors| format!("CONFIG: {name}: {}", errors.join("; ")))?;
    }
    Ok(())
}
