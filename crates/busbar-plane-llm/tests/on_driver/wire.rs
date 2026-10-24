// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE ROOT'S RIG SPEAKS TO THIS PLANE: the settings a case's pools become (one far end per
//! dialect, every member a model), each far end's answer, and the one plain request the rig's `fire`
//! posts (an Anthropic Messages request). The rig itself names no plane and no dialect; these are
//! this plane's words, so they live here.

use serde_json::{json, Value};

use crate::rig::{Member, Pool};

/// The far end a member is served by unless its case says otherwise: the Anthropic one.
pub const DEFAULT_PROVIDER: &str = "ant";

/// The target of the rig's plain unit: Anthropic Messages.
pub const FIRE_TARGET: &str = "/v1/messages";

/// The request fields of the rig's plain unit.
pub const FIRE_FIELDS: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("anthropic-version", "2023-06-01"),
];

/// The plane's settings for these pools: one far end per protocol, every member a model.
pub fn settings(pools: &[&Pool]) -> Vec<u8> {
    let mut models = serde_json::Map::new();
    let mut sections = serde_json::Map::new();
    for p in pools {
        let names: Vec<Value> = p.members.iter().map(|m| json!(m.model)).collect();
        sections.insert(p.name.to_string(), json!({ "members": names }));
        for m in &p.members {
            models.insert(m.model.to_string(), json!({ "provider": m.provider }));
        }
    }
    serde_json::to_vec(&json!({
        "providers": {
            "ant": { "protocol": "anthropic", "base_url": "https://anthropic.example" },
            "oai": { "protocol": "openai", "base_url": "https://openai.example" },
            "brk": { "protocol": "bedrock", "base_url": "https://bedrock.example" },
            "goo": { "protocol": "gemini", "base_url": "https://gemini.example" },
            "coh": { "protocol": "cohere", "base_url": "https://cohere.example" },
        },
        "models": models,
        "pools": sections,
    }))
    .expect("settings serialize")
}

/// What a member's far end answers one attempt, in its far end's dialect.
pub fn answer_of(m: &Member) -> Value {
    match m.provider {
        "oai" => json!({
            "id": "chatcmpl-1", "object": "chat.completion", "model": m.label,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        }),
        _ => json!({
            "id": "msg_1", "type": "message", "role": "assistant", "model": m.label,
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    }
}
