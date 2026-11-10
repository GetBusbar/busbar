// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Apply owner-requested credential conversion to an original authored reference.
//! Selection and credential interpretation belong to the requesting and receiving plugins.
use super::migrate_plugins::MigrateHost;
use busbar_contract::secret_ref::SecretRef;
use serde_yaml::Mapping;

pub(super) fn migrate(
    root: &mut Mapping,
    host: &dyn MigrateHost,
    path: &[String],
    module: &str,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    let Some((first, rest)) = path.split_first() else {
        return;
    };
    let Some(mut slot) = root.get_mut(first.as_str()) else {
        return;
    };
    for key in rest {
        let Some(next) = slot
            .as_mapping_mut()
            .and_then(|map| map.get_mut(key.as_str()))
        else {
            // A borrowed catalog value is not an authored deployment credential.
            return;
        };
        slot = next;
    }
    let site = path.join(".");
    let result = (|| {
        let sources = host.source_declarations()?;
        let reference = busbar_contract::secret_ref::context::deserialize::<SecretRef, _>(
            slot.clone(),
            &sources,
        )
        .map_err(|_| "invalid reference")?;
        let Some(reference) = host.migrate_credential(module, &reference, host.migrating_from())?
        else {
            return Ok::<_, String>(None);
        };
        serde_yaml::to_value(reference.authoring(&busbar_kernel::seal::acquire()))
            .map(Some)
            .map_err(|_| "cannot author migrated reference".into())
    })();
    match result {
        Ok(Some(reference)) => {
            *slot = reference;
            changes.push(format!("{site}: the credential owner converted the historical filename to an explicit source reference anchored to the migration process working directory"));
        }
        Ok(None) => {}
        Err(_) => todos.push(format!("{site}: the credential owner could not migrate the original source; the original reference was preserved. Run migration with the original secret sources and working directory")),
    }
}
