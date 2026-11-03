// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_yaml::Value;

use super::providers;

/// A catalog with its stray keys removed: the new text and one change line per removed key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMigration {
    /// The catalog as it reads now.
    pub yaml: String,
    /// One line per removed key, naming it and why.
    pub changes: Vec<String>,
}

#[derive(Debug)]
pub(super) struct Fields(&'static [&'static str]);
impl std::fmt::Display for Fields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the grammar's fields")
    }
}
impl std::error::Error for Fields {}
impl serde::de::Error for Fields {
    fn custom<M: std::fmt::Display>(_: M) -> Self {
        Fields(&[])
    }
}
pub(super) struct Probe;
impl<'de> serde::Deserializer<'de> for Probe {
    type Error = Fields;
    fn deserialize_any<V: serde::de::Visitor<'de>>(self, _: V) -> Result<V::Value, Fields> {
        Err(Fields(&[]))
    }
    fn deserialize_struct<V: serde::de::Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Fields> {
        Err(Fields(fields))
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map enum identifier
        ignored_any
    }
}

pub(super) fn struct_keys<T>(
    read: impl FnOnce(Probe) -> Result<T, Fields>,
) -> &'static [&'static str] {
    match read(Probe) {
        Err(Fields(fields)) => fields,
        Ok(_) => &[],
    }
}

#[must_use]
pub fn catalog_keys() -> &'static [&'static str] {
    providers::catalog_grammar_keys()
}

pub fn migrate_catalog(raw: &str, shown: &str) -> Result<Option<CatalogMigration>, String> {
    let keys = catalog_keys();
    if keys.is_empty() {
        return Err("the catalog grammar's keys could not be read".to_string());
    }
    let doc: Value = serde_yaml::from_str(raw).map_err(|e| format!("{shown}: not YAML: {e}"))?;
    let Value::Mapping(mut catalog) = doc else {
        return Ok(None);
    };

    // Migration preserves the legacy reader's behavior. An open options map in the current
    // plane grammar does not make a formerly ignored catalog key meaningful in the old input.
    let descriptor =
        crate::plane_driver::door::provider_keys(crate::plane_driver::registry::plane_decls());
    let mut changes = Vec::new();
    for (name, entry) in catalog.iter_mut() {
        let (Some(name), Value::Mapping(entry)) = (name.as_str(), entry) else {
            continue;
        };
        let stray: Vec<Value> = entry
            .keys()
            .filter(|k| {
                !k.as_str().is_some_and(|k| {
                    keys.contains(&k)
                        || descriptor.as_ref().is_some_and(|descriptor| {
                            descriptor.catalog.keys.iter().any(|key| key.name == k)
                        })
                })
            })
            .cloned()
            .collect();
        for key in stray {
            entry.remove(key.clone());
            let shown_key = key
                .as_str()
                .map_or_else(|| super::migrate::one_line(&key), str::to_string);
            changes.push(format!(
                "{shown}: {name}.{shown_key}: removed (1.5.5 ignored this catalog key; \
                 removing it preserves the legacy behavior)"
            ));
        }
    }
    if changes.is_empty() {
        return Ok(None);
    }
    let yaml = serde_yaml::to_string(&Value::Mapping(catalog))
        .map_err(|e| format!("{shown}: could not write the migrated catalog: {e}"))?;
    Ok(Some(CatalogMigration { yaml, changes }))
}

#[cfg(test)]
#[path = "tests/migrate_catalog_tests.rs"]
mod tests;
