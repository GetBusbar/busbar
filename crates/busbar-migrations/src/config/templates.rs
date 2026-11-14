// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Resolved views support validation; authored substitutions remain substitutions.
use super::migrate_plugins::MigrateHost;
use busbar_contract::yaml::{self, MappingExt, Value as Yaml};
use serde_json::Value;
use std::collections::BTreeMap;
use zeroize::Zeroize;

#[derive(Default)]
pub struct ResolvedTemplates(BTreeMap<String, Option<Value>>);
impl ResolvedTemplates {
    pub fn from_yaml(authored: &str, detection: &str) -> Result<Self, String> {
        let authored: Yaml =
            yaml::from_str(authored).map_err(|_| "authored template is not YAML")?;
        let detection: Yaml =
            yaml::from_str(detection).map_err(|_| "resolved detection is not YAML")?;
        let mut result = Self::default();
        result.record(&authored, &detection, 0)?;
        Ok(result)
    }
    fn record(&mut self, authored: &Yaml, actual: &Yaml, depth: usize) -> Result<(), String> {
        if depth > 128 {
            return Err("template detection exceeds structure budget".into());
        }
        match (authored, actual) {
            (Yaml::Map(a), Yaml::Map(b)) if a.len() == b.len() => {
                for (key, value) in a {
                    self.record(
                        value,
                        b.get_key(key).ok_or("detection changed a mapping key")?,
                        depth + 1,
                    )?;
                }
            }
            (Yaml::Array(a), Yaml::Array(b)) if a.len() == b.len() => {
                for (a, b) in a.iter().zip(b) {
                    self.record(a, b, depth + 1)?;
                }
            }
            (Yaml::Text(template), _) if template.contains("${") => {
                let value = serde_json::to_value(actual)
                    .map_err(|_| "resolved scalar cannot be represented")?;
                if value.is_array() || value.is_object() {
                    return Err("template changed document structure".into());
                }
                match self.0.entry(template.clone()) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(Some(value));
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        if entry.get().as_ref() != Some(&value) {
                            entry.insert(None);
                        }
                    }
                }
            }
            (Yaml::Map(_) | Yaml::Array(_), _) | (_, Yaml::Map(_) | Yaml::Array(_)) => {
                return Err("detection changed document structure".into());
            }
            _ => {}
        }
        Ok(())
    }
    pub fn scalar(&self, template: &str) -> Result<Option<Value>, String> {
        match self.0.get(template) {
            Some(Some(value)) => Ok(Some(value.clone())),
            Some(None) => Err("one authored placeholder has incompatible resolved scalar types; preserve this field explicitly".into()),
            None => Ok(None),
        }
    }
}
impl Drop for ResolvedTemplates {
    fn drop(&mut self) {
        for (mut key, value) in std::mem::take(&mut self.0) {
            key.zeroize();
            if let Some(mut value) = value {
                wipe_json(&mut value);
            }
        }
    }
}
fn wipe_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe_json),
        Value::Object(values) => values.values_mut().for_each(wipe_json),
        _ => {}
    }
}

pub fn resolved_settings(value: &Value, host: &dyn MigrateHost) -> Result<Value, String> {
    Ok(match value {
        Value::String(template) if template.contains("${") => host
            .resolved_authored_scalar(template)?
            .unwrap_or_else(|| value.clone()),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| resolved_settings(value, host))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| Ok((key.clone(), resolved_settings(value, host)?)))
                .collect::<Result<_, String>>()?,
        ),
        _ => value.clone(),
    })
}

/// Preserve scalar quoting after a structural move. A quoted `${N}` that resolves
/// to a string must not become an unquoted numeric YAML scalar after serialization.
pub(super) fn render_authored(yaml: &str, host: &dyn MigrateHost) -> Result<String, String> {
    let mut doc: Yaml = yaml::from_str(yaml).map_err(|_| "converted template is not YAML")?;
    let prefix = format!(
        "__BUSBAR_AUTHORED_{}__",
        hex::encode(busbar_contract::crypto::sha256(yaml.as_bytes()))
    );
    if yaml.contains(&prefix) {
        return Err("authored placeholder marker collision".into());
    }
    let mut replacements = Vec::new();
    fn walk(
        value: &mut Yaml,
        prefix: &str,
        replacements: &mut Vec<(String, String)>,
        host: &dyn MigrateHost,
    ) -> Result<(), String> {
        match value {
            Yaml::Text(template) if template.contains("${") => {
                let Some(resolved) = host.resolved_authored_scalar(template)? else {
                    return Ok(());
                };
                let replacement = if resolved.is_string() {
                    serde_json::to_string(template)
                        .map_err(|_| "authored string could not be preserved")?
                } else {
                    template.clone()
                };
                let marker = format!("{prefix}{}", replacements.len());
                replacements.push((marker.clone(), replacement));
                *template = marker;
            }
            Yaml::Array(values) => {
                for value in values {
                    walk(value, prefix, replacements, host)?;
                }
            }
            Yaml::Map(values) => {
                for (_, value) in values {
                    walk(value, prefix, replacements, host)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(&mut doc, &prefix, &mut replacements, host)?;
    if replacements.is_empty() {
        return Ok(yaml.to_owned());
    }
    let comments: String = yaml
        .lines()
        .take_while(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
        .map(|line| format!("{line}\n"))
        .collect();
    let mut rendered =
        yaml::to_string(&doc).map_err(|_| "authored template could not be rendered")?;
    // Replace longer markers first: slot 1 is a prefix of slot 10.
    replacements.sort_by_key(|(marker, _)| std::cmp::Reverse(marker.len()));
    for (marker, value) in replacements {
        rendered = rendered.replace(&marker, &value);
    }
    Ok(comments + &rendered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::yaml::ValueExt;

    struct Host(ResolvedTemplates);
    impl MigrateHost for Host {
        fn resolved_authored_scalar(&self, text: &str) -> Result<Option<Value>, String> {
            self.0.scalar(text)
        }
        fn migrate(
            &self,
            _: &str,
            _: &str,
            _: &Value,
            _: &str,
        ) -> Result<Option<(String, busbar_contract::abi::sdk::migrate::MigrationAnswer)>, String>
        {
            Ok(None)
        }
        fn repin(&self, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
    }

    #[test]
    fn structural_moves_preserve_authored_numeric_and_string_substitution_types() {
        let host =
            Host(ResolvedTemplates::from_yaml("n: ${N}\ns: '${S}'\n", "n: 4\ns: '4'\n").unwrap());
        let yaml = render_authored("moved: {count: '${N}', label: '${S}'}\n", &host).unwrap();
        let resolved = yaml.replace("${N}", "4").replace("${S}", "4");
        let doc: Yaml = yaml::from_str(&resolved).unwrap();
        assert_eq!(doc.at("moved").at("count").as_u64(), Some(4));
        assert_eq!(doc.at("moved").at("label").as_str(), Some("4"));
        assert!(yaml.contains("${N}") && yaml.contains("${S}"));
    }

    #[test]
    fn ambiguous_placeholder_types_and_structure_changes_are_refused() {
        let templates = ResolvedTemplates::from_yaml("a: ${N}\nb: '${N}'", "a: 4\nb: '4'").unwrap();
        assert!(templates.scalar("${N}").is_err());
        assert!(ResolvedTemplates::from_yaml("a: ${N}", "a: [1, 2]").is_err());
    }
}
