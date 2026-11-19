// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIG-BUILTIN: the modules 1.5.5 linked into its binary that 1.6.0 ships as separately installed
//! plugins (owner: "No, separate plugins"; they are not linked into the default build). A 1.5.5
//! setup that used one is carried: the entry stays as written, nothing is refused, and one report
//! line per entry names the plugin to install. 1.5.5 could hold the four exporters under `export:`
//! and the webhook-signature auth module under `identity-providers:`; the gRPC and WebSocket
//! transports had no 1.5.5 config form, so nothing here carries them (and 1a still refuses a
//! `transport:` section an unstamped config holds).
//!
//! The line names the instance, the module word and the plugin, never a setting: a signing secret
//! or a webhook url stays a reference in the config and out of the report.

use busbar_contract::yaml::{MappingExt, Value, ValueExt};

/// Each former built-in: the section that names it, its `module:` word, and the plugin that is
/// now installed separately.
const FORMER: [(&str, &str, &str); 5] = [
    ("export", "prometheus", "busbar-export-prometheus"),
    ("export", "otlp", "busbar-export-otlp"),
    ("export", "request-log-webhook", "busbar-export-webhook"),
    ("export", "request-log-file", "busbar-export-file"),
    (
        "identity-providers",
        "webhook-signature",
        "busbar-auth-webhook-signature",
    ),
];

/// 1d: one report line for each entry of `resolved` that names a former built-in. The document is
/// not changed.
pub(crate) fn report_plugins(resolved: &Value, report: &mut Vec<String>) {
    for (section, module, plugin) in FORMER {
        let Some(entries) = resolved.at(section).as_mapping() else {
            continue;
        };
        for (instance, entry) in entries {
            let named = entry
                .as_mapping()
                .and_then(|settings| settings.get_key("module"))
                .and_then(|word| word.as_str());
            if let (Some(instance), Some(word)) = (instance.as_str(), named) {
                if word == module {
                    report.push(format!(
                        "{section}.{instance}: `module: {module}` was built into 1.5.5; in 1.6.0 it is \
                         the separately installed `{plugin}` plugin. The entry is kept as written: \
                         install `{plugin}` for it to load."
                    ));
                }
            }
        }
    }
}
