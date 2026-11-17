// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.2: the 1.5.5 module-keyed secret map becomes explicitly named instances.
//! This pass runs only in STEPS[0]. It preserves the instance key and every supported block field.

use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

use crate::Refusal;

pub(crate) fn name_modules(root: &mut Pairs, report: &mut Vec<String>) -> Result<(), Refusal> {
    let Some(Value::Map(instances)) = root.get_key_mut("secrets") else {
        return Ok(()); // The strict parser owns malformed section shapes.
    };
    for (name, block) in instances {
        let (Some(name), Value::Map(fields)) = (name.as_text(), block) else {
            continue; // The strict parser owns malformed names and blocks.
        };
        if fields.get_key("module").is_some() {
            continue; // An explicitly named instance keeps its authored identity.
        }
        if fields.iter().any(|(key, _)| {
            !matches!(
                key.as_text(),
                Some("settings" | "limits" | "insecure_transport")
            )
        }) {
            return Err(Refusal::Config(format!(
                "secrets.{name}: cannot identify a legacy module-keyed block with unknown fields"
            )));
        }
        fields.insert(0, (Value::from("module"), Value::from(name)));
        report.push(format!(
            "secrets.{name}.module: added the legacy module identity; instance name and settings are kept"
        ));
    }
    Ok(())
}
