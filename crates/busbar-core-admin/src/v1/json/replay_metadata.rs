// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Schema projection of the canonical credential and durable adjustment outcomes.
use super::RESPONSES_KEY;
use serde_json::{json, Map, Value};

fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}

pub(super) fn complete(paths: &mut Map<String, Value>, schemas: &mut Map<String, Value>) {
    if let Some(codes) = schemas
        .get_mut("Error")
        .and_then(|schema| schema.pointer_mut("/properties/error/properties/code/enum"))
        .and_then(Value::as_array_mut)
    {
        for code in [
            "idempotency_mismatch",
            "mutation_applied",
            "action_in_flight",
        ] {
            if !codes.contains(&json!(code)) {
                codes.push(json!(code));
            }
        }
    }
    schemas.insert("MutationAppliedError".into(),json!({
        "type":"object",
        "properties":{
            "error":{"type":"object","properties":{"code":{"const":"mutation_applied"},"message":{"type":"string"}},"required":["code","message"]},
            "effect":{"const":"applied"},"operation":{"enum":["key.rotate","key.patch","key.delete"]},
            "resource":{"type":"string","description":"Non-secret key:<id> identity"},
            "recovery":{"enum":["rotate_with_new_action","reread_resource"]},"credential_recoverable":{"const":false}
        },
        "required":["error","effect","operation","resource","recovery","credential_recoverable"],
        "description":"The key mutation is known committed; a later cache/readback step failed. This is not a rejected/no-effect mutation. Reconcile the named resource. Rotation's new secret is not recoverable from this response; never repeat the old action to rotate again."
    }));
    schemas.insert("AdjustmentActionView".into(),json!({
        "type":"object","properties":{
            "operation_id":{"type":"string","pattern":"^[0-9a-f]{64}$"},"operation":{"const":"adjust"},
            "actor":{"type":"string"},"target":{"type":"string","description":"Corrected key id"},
            "fingerprint":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"SHA256 of exact request bytes"},
            "reason_hash":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"SHA256 of the reason bytes; no public reason text"},
            "effect":{"enum":["applied","not_applied","unknown"]},"applied":{"type":"boolean"},
            "retry":{"const":"same_action_only"},"recovery":{"enum":["receipt","reconcile_ledger_recovery"]},"count_scale":{"const":6}
        },"required":["operation_id","operation","actor","target","fingerprint","reason_hash","effect","applied","retry","recovery","count_scale"],
        "description":"Durable caller-action receipt. A known rejection can have a non-2xx status with this body; unknown is HTTP 409. Effect and recovery are authoritative, not the HTTP status alone. applied is true exactly when effect=applied. Unknown effects require ledger recovery and never authorize a second delta. This projection intentionally does not echo raw counts or reason."
    }));
    if let Some(legacy) = schemas.get("AdjustReq").cloned() {
        let mut exact = legacy;
        exact["properties"]["delta"] = json!({"type":"object","minProperties":1,"additionalProperties":{
            "anyOf":[{"type":"string"},{"type":"number"}],
            "x-busbar-exact-number":super::contract_metadata::number_profile()["count"],
            "description":"Signed exact Count decimal. New clients send decimal strings. Legacy numeric tokens are accepted losslessly; value must fit signed i128 scale 6. Decimal exponent syntax follows Count::parse; no binary64 rounding."
        }});
        exact["properties"]["delta"]["additionalProperties"]["x-busbar-exact-number"]
            ["representation"] = json!(["decimal-string", "json-number-token"]);
        exact["properties"]["reason"]["description"] = json!("Nonblank UTF-8 reason, at most 4096 bytes; only its hash is retained in the safe action receipt.");
        exact["description"] = json!("Exact-Count adjustment profile selected only by one valid Idempotency-Key header. Key and exact body bytes identify one durable action. Runtime validates count range/scale, entry/epoch, key, pool and nonnegative resulting counts. Without the header only the legacy signed-integer request applies.");
        schemas.insert("ExactAdjustReq".into(), exact);
    }
    if let Some(legacy) = schemas.get_mut("AdjustView") {
        legacy["properties"]["retry"] = json!({"const":"nonretryable_without_idempotency_key"});
    }
    schemas.insert(
        "AdjustmentResponse".into(),
        json!({"anyOf":[reference("AdjustView"),reference("AdjustmentActionView")]}),
    );
    let prefix = crate::v1::contract::ADMIN_PREFIX;
    if let Some(adjust) = paths
        .get_mut(&format!("{prefix}/adjust"))
        .and_then(|methods| methods.get_mut("post"))
    {
        let parameter = json!({"name":"Idempotency-Key","in":"header","required":false,"schema":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[!-~]+$"},"description":"Selects durable exact-Count action profile. Exactly one ASCII graphic value (1..128 bytes). Authenticated actor + adjust + header identify a stable action; SHA256 binds exact body bytes. Receipts/claims do not automatically expire or recycle and survive restart. Identical retries return the retained outcome; changed bytes conflict. Without this header the legacy route is not safe to blindly retry."});
        if let Some(params) = adjust.get_mut("parameters").and_then(Value::as_array_mut) {
            params.push(parameter)
        } else {
            adjust["parameters"] = json!([parameter])
        }
        adjust["requestBody"]["content"]["application/json"]["schema"] = json!({"anyOf":[reference("AdjustReq"),reference("ExactAdjustReq")],"description":"Header-selective profiles: AdjustReq without Idempotency-Key, ExactAdjustReq with it. OpenAPI body union alone cannot validate the cross-header condition."});
        adjust[RESPONSES_KEY]["200"]["content"]["application/json"]["schema"] =
            reference("AdjustmentResponse");
        for status in ["400", "409"] {
            adjust[RESPONSES_KEY][status] = json!({"description":"Typed refusal or durable action outcome. An action outcome body carries effect and reconciliation identity; unknown effect requires recovery, never a new automatic delta.","content":{"application/json":{"schema":{"anyOf":[reference("Error"),reference("AdjustmentActionView")]}}}});
        }
        for status in ["200", "400", "409"] {
            adjust[RESPONSES_KEY][status]["headers"]["x-busbar-receipt-durable"] = json!({"description":"false when the effect is known in this process but final receipt persistence was not confirmed. After restart the retained pre-effect receipt may remain unknown; reconcile before any new action.","schema":{"const":"false"}});
        }
        adjust["description"] = json!("Correct counts at the original card epoch. With Idempotency-Key, the durable exact-Count profile binds actor/action to exact bytes and returns AdjustmentActionView. Without it, retain legacy signed-integer/nonretryable semantics. Applied, not_applied and unknown are distinct outcomes; never infer no effect from a failed response.");
    }
    for (path, method) in [
        ("/keys/{id}/rotate", "post"),
        ("/keys/{id}", "patch"),
        ("/keys/{id}", "delete"),
    ] {
        if let Some(operation) = paths
            .get_mut(&format!("{prefix}{path}"))
            .and_then(|methods| methods.get_mut(method))
        {
            operation[RESPONSES_KEY]["409"]["content"]["application/json"]["schema"] =
                json!({"anyOf":[reference("Error"),reference("MutationAppliedError")]});
        }
    }
}
