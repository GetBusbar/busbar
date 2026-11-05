// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned user-input schemas. These are separate from plugin lifecycle settings schemas:
//! SecretRef syntax is parsed before material is resolved and lent to a plugin.

use serde_json::{json, Value};

mod core;
mod host;
#[cfg(test)]
mod integer_token;
#[cfg(test)]
mod store_secret_tests;
mod tables;

pub(super) use core::{
    component_reference as core_reference, insert_components as insert_core_components,
};
#[cfg(test)]
mod tests;

fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/$defs/{name}")})
}
fn nullable(schema: Value) -> Value {
    json!({"anyOf":[schema,{"type":"null"}]})
}
fn strings() -> Value {
    json!({"type":"array","items":{"type":"string"}})
}
fn dictionary(value: Value) -> Value {
    json!({"type":"object","additionalProperties":value})
}
fn object(properties: Value) -> Value {
    json!({"type":"object","properties":properties,"additionalProperties":false})
}

pub(super) fn schema_document() -> Value {
    let mut definitions = tables::definitions();
    core::definitions(&mut definitions);
    host::definitions(&mut definitions);
    let mut secret = busbar_contract::secret_ref::oneof_schema();
    secret["writeOnly"] = json!(true);
    secret["description"] = json!("Core user-input SecretRef grammar. Plugin-declared shorthand is resolved separately; use explicit module/settings for portable forms. Never an inline credential.");
    definitions.insert("SecretRef".into(), secret);
    let store_object = object(json!({
        "module":{"type":"string","default":""},
        "settings":{"type":"object","default":{},"x-busbar-module-settings":true}
    }));
    let mut store = json!({"oneOf":[store_object,{
        "type":"array","prefixItems":[{"type":"string"},{"type":"object","x-busbar-module-settings":true}],
        "items":{},"minItems":0,"maxItems":2,
        "description":"Existing positional parser form: [], [module], or [module, settings]. Omitted trailing fields use the same defaults as the object form."
    }]});
    store["description"] = json!("The singular store wrapper, canonically an object. Its parser also accepts a positional array. Omitted module defaults to an empty string and omitted settings to an empty object; configuration resolution requires a selected store module.");
    store["x-busbar-runtime-validation"] = json!([
        "a store selection is required and its module must resolve to an admitted store",
        "module lifecycle settings after host secret resolution",
        "store changes require a process restart"
    ]);
    definitions.insert("Store".into(), store);
    let secret_module_object = object(json!({
        "settings":{"type":"object","default":{},"x-busbar-module-settings":true}
    }));
    let mut secret_module = json!({"oneOf":[secret_module_object,{
        "type":"array","prefixItems":[{"type":"object","x-busbar-module-settings":true}],
        "items":{},"minItems":0,"maxItems":1,
        "description":"Existing positional parser form: [] or [settings]. Omitted settings default to an empty object."
    }]});
    secret_module["description"] = json!("Module-level initialization settings, keyed by the secret module name or alias under secrets, canonically an object; the parser also accepts a positional array. This is not a named instance and has no inner module field. Per-reference SecretRef settings are a separate input.");
    secret_module["x-busbar-runtime-validation"] = json!([
        "the map key must resolve to an admitted secret module; built-in env/file modules take no module-level configuration",
        "initialization SecretRefs resolve only through the bootstrap env/file resolvers, never another secret plugin",
        "module lifecycle settings after bootstrap secret resolution",
        "secret module initialization changes require a process restart"
    ]);
    definitions.insert("SecretModule".into(), secret_module);
    let mut secrets = dictionary(reference("SecretModule"));
    secrets["default"] = json!({});
    secrets["description"] = json!("Module-keyed secret initialization map. Module selection and bootstrap SecretRef restrictions are runtime validation, not new wrapper fields.");
    let scope = nullable(json!({"enum":["read-only","full"]}));
    definitions.insert(
        "BrowserLogin".into(),
        object(json!({
            "client_id":nullable(json!({"type":"string"})),
            "client_secret":nullable(reference("SecretRef"))
        })),
    );
    let mut identity = object(json!({
        "module":{"type":"string"}, "max_admin_scope":scope,
        "token":nullable(reference("SecretRef")),
        "browser_login":nullable(reference("BrowserLogin")),
        "settings":{"type":"object","default":{},"x-busbar-module-settings":true}
    }));
    identity["required"] = json!(["module"]);
    identity["x-busbar-runtime-validation"] = json!([
        "module resolution",
        "operator token applicability",
        "browser login kind and client-secret requirement",
        "module lifecycle settings after host secret resolution"
    ]);
    definitions.insert("IdentityProvider".into(), identity);
    let modes =
        nullable(json!({"type":"array","items":{"enum":["time-bound","user-bound","both"]}}));
    definitions.insert(
        "MintCeiling".into(),
        object(json!({
            "max_ttl":nullable(json!({"type":"string"})),
            "allowed_pools":nullable(strings()), "binding_modes":modes
        })),
    );
    definitions.insert(
        "AuthPolicy".into(),
        object(json!({
            "self_mint":nullable(json!({"type":"boolean"})), "binding_modes":modes,
            "default_ttl":nullable(json!({"type":"string"})),
            "max_ttl":nullable(json!({"type":"string"})),
            "mint_ceilings":dictionary(reference("MintCeiling"))
        })),
    );
    let verb_names: Vec<_> = crate::verb::admin_rows().map(|row| row.name).collect();
    let mut binding = object(json!({
        "allowed_pools":nullable(strings()),"group":nullable(json!({"type":"string"})),
        "admin_scope":scope,"verbs":{"anyOf":[{"const":"*"},{"type":"array","items":{"enum":verb_names}},{"type":"null"}],
            "x-busbar-runtime-validation":"Names must be declared by this build's admin verb table."}
    }));
    // The owner accepts any nonempty kind between allowed_ and s, except pool (owned above).
    // Dot matches line terminators too: the owning parser uses string prefix/suffix, not ASCII IDs.
    binding["patternProperties"] = json!({"^allowed_(?!pools$)[\\s\\S]+s$":strings()});
    binding["x-busbar-runtime-validation"] = json!([
        "plane grant kinds must be declared by an installed plane",
        "verb names must exist in the closed admin table",
        "group and pool references"
    ]);
    definitions.insert("RoleBinding".into(), binding);
    let mut admin_names = strings();
    admin_names["default"] = json!(busbar_kernel::config::auth::default_admin_auth_names());
    let mut chain = strings();
    chain["default"] = json!([]);
    let mut auth = object(json!({
        "signing_key":nullable(reference("SecretRef")),"chain":chain,"admin_auth":admin_names,
        "role_bindings":dictionary(dictionary(reference("RoleBinding"))),
        "key_ttl":nullable(json!({"type":"string"})),"policy":reference("AuthPolicy")
    }));
    auth["x-busbar-runtime-validation"] = json!([
        "provider names and signing key requirements",
        "duration parsing and policy ceiling consistency",
        "named role grants and plane declarations"
    ]);
    definitions.insert("Auth".into(), auth);
    definitions.insert("Export".into(), export_schema());
    json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "x-busbar-settings-profile":"integer-token-v1",
        "$defs":definitions,
        "type":"object",
        "properties":{
            "auth":nullable(reference("Auth")),
            "identity-providers":dictionary(reference("IdentityProvider")),
            "export":dictionary(reference("Export")),
            "providers":dictionary(reference("ProviderDeployment")),
            "models":dictionary(reference("Model")),
            "pools":reference("Pools"),
            "plugins":reference("Plugins"),
            "oauth_as":nullable(reference("OAuthAS")),
            "groups":dictionary(reference("Group")),
            "hooks":dictionary(reference("HookDefinition")),
            "store":nullable(reference("Store")),
            "secrets":secrets
        },
        "additionalProperties":true,
        "x-busbar-partial":true,
        "description":"User-input forms for the listed host-owned fields. Not a complete boot schema: other top-level blocks and plane-owned settings remain with their declaring parser. The provider catalog is a separate document using ProviderCatalogEntry."
    })
}

fn export_schema() -> Value {
    let capabilities = busbar_kernel::export::configuration_capabilities();
    let streams = capabilities["streams"]
        .as_array()
        .expect("owning producer table is an array");
    let names: Vec<_> = streams.iter().map(|s| s["name"].clone()).collect();
    let fields: std::collections::BTreeSet<_> = streams
        .iter()
        .flat_map(|s| s["produced_fields"].as_array().unwrap())
        .map(|s| s.as_str().unwrap())
        .collect();
    let field_list = json!({"type":"array","minItems":1,"uniqueItems":true,
        "items":{"enum":fields}});
    let mut schema = object(json!({
        "module":{"type":"string"},
        "streams":nullable(json!({"type":"array","minItems":1,"uniqueItems":true,"items":{"enum":names}})),
        "fields":nullable(field_list),
        "durable":{"const":false,"default":false,"description":"true is rejected by the owning resolver; durable spooling is not implemented."},
        "settings":{"type":"object","default":{},"x-busbar-module-settings":true}
    }));
    schema["required"] = json!(["module"]);
    let mut rules = Vec::new();
    for stream in streams {
        let present = json!({"required":["streams"],"properties":{"streams":{"type":"array","contains":{"const":stream["name"]}}}});
        let then = if stream["fields_override"] == false {
            json!({"properties":{"fields":{"type":"null"}}})
        } else {
            let required: Vec<_> = stream["pinned_fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|field| json!({"contains":{"const":field}}))
                .collect();
            json!({"properties":{"fields":{"anyOf":[{"type":"null"},{"type":"array","allOf":required}]}}})
        };
        rules.push(json!({"if":present,"then":then}));
    }
    // Enumerate the finite subscribed sets to prevent fields from a different stream. With omitted
    // streams the module owns the default; runtime admission performs that context-dependent check.
    for mask in 1..(1usize << streams.len()) {
        let selected: Vec<_> = streams
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, s)| s)
            .collect();
        let names: Vec<_> = selected.iter().map(|s| s["name"].clone()).collect();
        let available: std::collections::BTreeSet<_> = selected
            .iter()
            .flat_map(|s| s["produced_fields"].as_array().unwrap())
            .map(|s| s.as_str().unwrap())
            .collect();
        rules.push(json!({"if":{"required":["streams"],"properties":{"streams":{"type":"array","minItems":names.len(),"maxItems":names.len(),"items":{"enum":names}}}},
            "then":{"properties":{"fields":{"anyOf":[{"type":"null"},{"type":"array","items":if available.is_empty() { json!({"not":{}}) } else { json!({"enum":available}) }}]}}}}));
    }
    schema["allOf"] = json!(rules);
    schema["x-busbar-capabilities"] = capabilities;
    schema["x-busbar-runtime-validation"] = json!(["module exists and carries each selected stream", "omitted streams use the module's carried streams; fields are checked against those defaults", "module lifecycle settings after host secret resolution"]);
    schema
}

pub(super) fn extension() -> Value {
    let scope_kinds: std::collections::BTreeSet<_> =
        busbar_kernel::plane_driver::registry::plane_decls()
            .iter()
            .flat_map(|declaration| declaration.scope_kinds.iter().copied())
            .collect();
    json!({"version":1,"context":"user_configuration","schema":schema_document(),
        "declared_plane_scope_kinds":scope_kinds,
        "admin_verbs":crate::verb::admin_rows().map(|row|json!({"name":row.name,"scope":row.scope.as_str(),"bound":row.bound})).collect::<Vec<_>>(),
        "ownership":{
            "plugins":"host PluginsCfg loader, trust/fetch/logs policy; runtime-only first_party_floors excluded",
            "oauth_as":"installed authorization-server owner input_schema; absence is explicitly unsupported",
            "groups":"host GroupCfg, compact LimitCfg and ChildDefault; runtime validation owns tree and pool references",
            "hooks":"deploy HookDefCfg; admin POST/PUT use distinct HookCfg schema",
            "auth":"host AuthDeployCfg and policy prepass",
            "identity-providers":"host IdentityProviderCfg wrapper; module owns settings",
            "export":"host ExportDefCfg and export projection resolver; module owns settings",
            "store":"host StoreCfg singular wrapper; selected store module owns settings",
            "secrets":"host SecretModuleCfg map keyed by module; initialization settings resolve only bootstrap env/file SecretRefs",
            "providers":"host ProviderDeploy grammar; protocol-specific remainder belongs to the plane",
            "provider_catalog":"separate document: map of ProviderCatalogEntry",
            "models":"host ModelCfg",
            "pools":"owning PoolsCfg/PoolCfg grammar; requires the installed pool plane",
            "other_plane_sections":"declaring plane owns its user-input grammar; lifecycle settings_schema is not a substitute"
        },
        "validation":"This generated form contract does not certify boot. Resolve plugin and plane capabilities, references, secret material, duration/URL semantics and cross-field policy using the normal configuration validation path. Plugin lifecycle schemas describe the resolved settings crossing, not raw user SecretRef input."})
}

#[cfg(test)]
pub(super) fn validator(schema: &Value) -> jsonschema::Validator {
    integer_token::validator(schema).expect("generated user-configuration schema compiles")
}
