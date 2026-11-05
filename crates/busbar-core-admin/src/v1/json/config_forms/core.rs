// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual compact group grammar and the distinct authored/runtime hook wrappers.
use super::{nullable, object, reference, strings};
use serde_json::{json, Map, Value};

fn unsigned() -> Value {
    json!({"type":"integer","minimum":0,"maximum":u64::MAX,
        "x-busbar-integer-token":"unsigned","x-busbar-exact-number":{"representation":"json-integer-token","bits":64,"signed":false}})
}

pub(super) fn definitions(defs: &mut Map<String, Value>) {
    let mut branches = Vec::new();
    for metric in [
        "requests",
        "tokens",
        "tokens_input",
        "tokens_output",
        "tokens_cache_read",
        "tokens_cache_write",
        "budget",
        "concurrent",
    ] {
        let mut properties = json!({metric:unsigned()});
        if metric != "concurrent" {
            properties["per"] = json!({"enum":["minute","hour","day","month","total"]});
            properties["pool"] = json!({"type":"string"});
        }
        if metric == "budget" {
            properties["on_exhaust"] = json!({"enum":["block","downgrade"]});
            properties["downgrade_to"] = json!({"type":"string"});
            properties["admission"] = json!({"enum":["exact","estimate"],"description":"Omitted means exact; authored presence is retained in readback."});
            properties["on_exhaustion"] = json!({"enum":["finish-unit","cut-stream"],"description":"In-flight behavior; omitted means finish-unit. Distinct from admission-time on_exhaust."});
        }
        let mut branch = object(properties);
        branch["required"] = if metric == "concurrent" {
            json!([metric])
        } else {
            json!([metric, "per"])
        };
        if metric == "budget" {
            branch["allOf"] = json!([
                {"if":{"required":["on_exhaust"],"properties":{"on_exhaust":{"const":"downgrade"}}},"then":{"required":["pool","downgrade_to"]}},
                {"if":{"required":["downgrade_to"]},"then":{"required":["on_exhaust"],"properties":{"on_exhaust":{"const":"downgrade"}}}}
            ]);
        }
        branches.push(branch);
    }
    defs.insert("Limit".into(), json!({"oneOf":branches,"description":"Exactly one unsigned u64 metric key. Budget is in cents; other units follow the named metric.","x-busbar-runtime-validation":["pool references must exist","downgrade_to must differ from pool","enforcement bucket identities must be unambiguous"]}));
    let limits = json!({"type":"array","items":reference("Limit"),"default":[]});
    defs.insert("ChildDefault".into(), object(json!({"limits":limits})));
    let mut group = object(json!({
        "parent":nullable(json!({"type":"string"})),"enabled":{"type":"boolean","default":true},
        "limits":limits,"child_default":nullable(reference("ChildDefault"))
    }));
    group["x-busbar-runtime-validation"] = json!([
        "parent existence and acyclic tree",
        "pool and downgrade references",
        "canonical configuration validation and current policy"
    ]);
    group["description"] = json!(
        "Complete authored GroupCfg. Null/absent parent and child_default mean absent on full replacement. An empty child_default object is a present empty template and stops ancestor-template lookup. PATCH has separate presence/clear semantics."
    );
    defs.insert("Group".into(), group);

    let phase = json!({"type":"array","items":{"enum":["request","candidate","routing","response"]},"default":[]});
    let mut runtime = object(json!({
        "kind":{"enum":["tap","gate"]},"module":{"type":"string"},"plugin":{"type":"string","deprecated":true},
        "timeout_ms":unsigned(),"on_error":{"type":"string","default":"nothing"},
        "prompt":{"enum":["no","ro","rw"],"default":"no"},"user":{"enum":["no","ro"],"default":"no"},
        "priority":{"type":"integer","minimum":0,"maximum":65535,"x-busbar-integer-token":"unsigned","default":0},
        "on_empty":nullable(json!({"enum":["reject","weighted","first"]})),
        "at":nullable(json!({"enum":["request","candidate","routing","response"]})),
        "settings":{"type":"object","default":{},"x-busbar-module-settings":true},
        "signals":{"type":"array","items":{"enum":busbar_contract::signal::Signal::ALL.iter().map(|signal|signal.name()).collect::<Vec<_>>()},"default":[]},
        "global":{"type":"boolean","default":false},"default":{"type":"boolean","default":false},
        "groups":strings(),"phase":phase
    }));
    runtime["properties"]["timeout_ms"]["default"] = json!(1);
    runtime["required"] = json!(["kind"]);
    runtime["oneOf"] = json!([{"required":["module"],"not":{"required":["plugin"]}},{"required":["plugin"],"not":{"required":["module"]}}]);
    runtime["description"] = json!(
        "HookCfg accepted by admin POST/PUT and overlay. module is canonical; plugin is the legacy input alias. This differs from the deploy HookDefinition wrapper. Settings may contain hidden values and must never be reconstructed from HookView."
    );
    runtime["x-busbar-runtime-validation"] = json!([
        "module resolves to admitted hook",
        "prompt/user grants immutable after registration; tap cannot use rw",
        "fallback references, cycles, default uniqueness and group references",
        "settings schema applies after SecretRef resolution; explicit settings edit requires runtime acknowledgement"
    ]);
    defs.insert("Hook".into(), runtime);
    let mut authored = object(json!({
        "module":{"type":"string"},"settings":{"type":"object","default":{},"x-busbar-module-settings":true},
        "groups":strings(),"phase":phase,"kind":nullable(json!({"enum":["tap","gate"]})),
        "timeout_ms":nullable(unsigned()),"priority":nullable(json!({"type":"integer","minimum":0,"maximum":65535,"x-busbar-integer-token":"unsigned"})),
        "on_empty":nullable(json!({"enum":["reject","weighted","first"]})),"prompt":nullable(json!({"enum":["no","ro","rw"]})),
        "user":nullable(json!({"enum":["no","ro"]})),
        "on_error":nullable(json!({"oneOf":[{"enum":["nothing","weighted","reject","first"]},{"type":"object","properties":{"hook":{"type":"string","pattern":"\\S"}},"required":["hook"],"additionalProperties":false}]}))
    }));
    authored["required"] = json!(["module"]);
    authored["description"] = json!(
        "Actual top-level hooks named-definition input (HookDefCfg). Admin POST/PUT consumes Hook instead. default, signals, global and legacy at are runtime HookCfg fields, not accepted by this deploy wrapper."
    );
    authored["x-busbar-runtime-validation"] = json!([
        "module resolution and settings after secret resolution",
        "hook references, prompt/user grants and normal deploy validation"
    ]);
    defs.insert("HookDefinition".into(), authored);
}

pub(crate) fn component_reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/ConfigInput{name}")})
}

pub(crate) fn insert_components(schemas: &mut Map<String, Value>) {
    let mut defs = Map::new();
    definitions(&mut defs);
    fn rewrite(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(reference)) = map.get_mut("$ref") {
                    if let Some(name) = reference.strip_prefix("#/$defs/") {
                        *reference = format!("#/components/schemas/ConfigInput{name}");
                    }
                }
                for child in map.values_mut() {
                    rewrite(child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    rewrite(child);
                }
            }
            _ => {}
        }
    }
    for (name, mut schema) in defs {
        rewrite(&mut schema);
        schemas.insert(format!("ConfigInput{name}"), schema);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn compiled(name: &str) -> jsonschema::Validator {
        let defs = super::super::schema_document()["$defs"].clone();
        super::super::validator(
            &json!({"$schema":"https://json-schema.org/draft/2020-12/schema","x-busbar-settings-profile":"integer-token-v1","$defs":defs,"$ref":format!("#/$defs/{name}")}),
        )
    }

    #[test]
    fn compact_group_and_limit_forms_match_owning_parser() {
        let groups = compiled("Group");
        for case in [
            json!({}),
            json!({"parent":null,"child_default":null}),
            json!({"child_default":{}}),
            json!({"enabled":null}),
            json!({"limits":null}),
            json!({"limits":[{"budget":9007199254740993_u64,"per":"month","admission":"estimate","on_exhaustion":"cut-stream"}]}),
            json!({"child_default":{"limits":[]}}),
            json!({"unknown":true}),
        ] {
            assert_eq!(
                groups.is_valid(&case),
                serde_json::from_value::<busbar_kernel::config::GroupCfg>(case.clone()).is_ok(),
                "{case}"
            );
        }
        let limits = compiled("Limit");
        for case in [
            json!({"requests":1,"per":"minute"}),
            json!({"tokens_cache_write":1,"per":"total","pool":"a"}),
            json!({"concurrent":1}),
            json!({"concurrent":1,"per":"minute"}),
            json!({"concurrent":1,"pool":"a"}),
            json!({"budget":7}),
            json!({"budget":7,"per":"day","on_exhaust":"downgrade"}),
            json!({"budget":7,"per":"day","pool":"a","on_exhaust":"downgrade","downgrade_to":"b"}),
            json!({"budget":7,"per":"day","downgrade_to":"b"}),
            json!({"requests":1,"per":"day","admission":"exact"}),
            json!({"requests":1,"tokens":1,"per":"day"}),
            json!({"budget":1,"per":"day","admission":null}),
        ] {
            assert_eq!(
                limits.is_valid(&case),
                serde_json::from_value::<busbar_kernel::config::LimitCfg>(case.clone()).is_ok(),
                "{case}"
            );
        }
    }

    #[test]
    fn hook_forms_keep_actual_admin_and_deploy_wrappers_distinct() {
        let runtime = compiled("Hook");
        let authored = compiled("HookDefinition");
        for case in [
            json!({"module":"h"}),
            json!({"module":"h","kind":"gate"}),
            json!({"module":"h","kind":"gate","on_empty":"first","default":true,"signals":["candidate_route_cost"]}),
            json!({"plugin":"legacy","kind":"tap","at":"response"}),
            json!({"module":"h","plugin":"h","kind":"gate"}),
            json!({"module":"h","kind":null}),
            json!({"module":"h","kind":"gate","timeout_ms":null}),
            json!({"module":"h","on_error":{"hook":"fallback"}}),
            json!({"module":"h","on_error":"fallback"}),
            json!({"module":"h","on_error":"nothing"}),
            json!({"module":"h","settings":null}),
            json!({"module":"h","kind":"gate","signals":["unknown"]}),
        ] {
            assert_eq!(
                runtime.is_valid(&case),
                serde_json::from_value::<busbar_kernel::config::HookCfg>(case.clone()).is_ok(),
                "runtime {case}"
            );
            assert_eq!(
                authored.is_valid(&case),
                serde_json::from_value::<busbar_kernel::config::hooks::HookDefCfg>(case.clone())
                    .is_ok(),
                "deploy {case}"
            );
        }
    }
}
