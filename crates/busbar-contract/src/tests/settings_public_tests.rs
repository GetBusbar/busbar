// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn only_a_root_property_marked_public_is_public() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "url": { "type": "string", "x-busbar-public": true },
            "timeout_ms": { "type": "integer", "x-busbar-public": true },
            "client_secret": { "type": "string", "x-busbar-secret": true },
            "undeclared": { "type": "string" },
            "quoted": { "type": "string", "x-busbar-public": "true" },
            "nested": { "type": "object", "properties": { "x": { "x-busbar-public": true } } }
        }
    });
    let public = public_settings(&schema);
    assert_eq!(
        public.iter().map(String::as_str).collect::<Vec<_>>(),
        ["timeout_ms", "url"]
    );
    assert!(
        public_settings(&serde_json::Value::Null).is_empty(),
        "no schema: none public"
    );
    let settings = serde_json::json!({
        "url": "https://x", "timeout_ms": 5, "client_secret": "s3cret", "undeclared": "u"
    });
    let view = public_view(settings.as_object().unwrap(), &public);
    assert_eq!(
        serde_json::Value::Object(view),
        serde_json::json!({ "url": "https://x", "timeout_ms": 5 })
    );
}
