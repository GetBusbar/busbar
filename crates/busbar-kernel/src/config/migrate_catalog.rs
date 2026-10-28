// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROVIDERS CATALOG'S STRAY KEYS (owner ruling 2026-10-27): a `providers.yaml` catalog entry
//! refuses a key its grammar ([`ProviderDef`]) does not read. 1.5.5 ignored such a key, so removing
//! it keeps exactly what 1.5.5 did: `busbar --migrate-config` rewrites the catalog without them, one
//! change line each. The keys the grammar reads are read off the grammar itself (its derive's own
//! field list), never written here.

use serde_yaml::Value;

use super::ProviderDef;

/// A catalog with its stray keys removed: the new text and one change line per removed key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMigration {
    /// The catalog as it reads now.
    pub yaml: String,
    /// One line per removed key, naming it and why.
    pub changes: Vec<String>,
}

/// The keys a derived struct reads, as its `Deserialize` derive states them (the `fields` it hands
/// `deserialize_struct`); empty when the type does not read a struct.
fn struct_keys<T: serde::de::DeserializeOwned>() -> &'static [&'static str] {
    #[derive(Debug)]
    struct Fields(&'static [&'static str]);
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
    struct Probe;
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
    match T::deserialize(Probe) {
        Err(Fields(fields)) => fields,
        Ok(_) => &[],
    }
}

/// The keys a catalog entry reads.
#[must_use]
pub fn catalog_keys() -> &'static [&'static str] {
    struct_keys::<ProviderDef>()
}

/// `raw`, a `providers.yaml` catalog (`shown` is how its path is printed), without the keys its
/// entries' grammar does not read. `None` when it has none to remove.
///
/// # Errors
/// The catalog is not YAML, or the grammar's keys cannot be read (nothing is then removed).
pub fn migrate_catalog(raw: &str, shown: &str) -> Result<Option<CatalogMigration>, String> {
    let keys = catalog_keys();
    if keys.is_empty() {
        return Err("the catalog grammar's keys could not be read".to_string());
    }
    let doc: Value = serde_yaml::from_str(raw).map_err(|e| format!("{shown}: not YAML: {e}"))?;
    let Value::Mapping(mut catalog) = doc else {
        return Ok(None);
    };
    let mut changes = Vec::new();
    for (name, entry) in catalog.iter_mut() {
        let (Some(name), Value::Mapping(entry)) = (name.as_str(), entry) else {
            continue;
        };
        let stray: Vec<Value> = entry
            .keys()
            .filter(|k| !k.as_str().is_some_and(|k| keys.contains(&k)))
            .cloned()
            .collect();
        for key in stray {
            entry.remove(key.clone());
            let shown_key = key
                .as_str()
                .map_or_else(|| super::migrate::one_line(&key), str::to_string);
            changes.push(format!(
                "{shown}: {name}.{shown_key}: removed (a catalog entry does not read this key: \
                 1.5.5 ignored it, and 1.6.0 refuses it, so removing it keeps what 1.5.5 did)"
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
