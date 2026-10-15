// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK VIEW OF A BODY THE OPERATION'S READER REFUSES, read off the raw body as 1.5.5 read
//! every body (`v1.5.5 crates/busbar/src/proxy/hooks.rs:255-830`: `conversation_turns`,
//! `turn_count`, `block_text`, `system_text_chars`, `total_text_chars`, `body_end_user`,
//! `build_prompt_projection`). 1.5.5's projection never failed: a turn whose role no reader knows
//! (`role: "wizard"`) was screened under its own role and the request went on. A same-dialect
//! request was then relayed verbatim, and only a translation to another dialect read the body and
//! refused it (`v1.5.5 crates/busbar/src/proxy/wire.rs:456`). A body the reader accepts is still
//! projected by the reader ([`super::project`]); this view is for the rest.

use std::borrow::Cow;

use busbar_contract::ir::facts::OPAQUE_CONTENT_MARKER;
use serde_json::Value;

use crate::codec::openai_responses::{
    read_reasoning_encrypted_content, read_reasoning_text, CONTENT_TYPE_OUTPUT_TEXT,
    ITEM_TYPE_FUNCTION_CALL, ITEM_TYPE_REASONING,
};
use crate::codec::proto_codec::{PROTO_ANTHROPIC, PROTO_BEDROCK, PROTO_GEMINI, PROTO_RESPONSES};

/// What the raw body shows a hook.
pub(super) struct RawView {
    pub(super) turn_count: usize,
    pub(super) text_chars: usize,
    pub(super) has_tools: bool,
    pub(super) system: Option<String>,
    pub(super) turns: Vec<(String, String)>,
    pub(super) end_user: Option<String>,
}

/// A block's screenable text.
enum BlockText<'a> {
    Text(Cow<'a, str>),
    Redacted,
    None,
}

impl BlockText<'_> {
    fn chars(&self) -> usize {
        match self {
            BlockText::Text(t) => t.chars().count(),
            BlockText::Redacted => OPAQUE_CONTENT_MARKER.chars().count(),
            BlockText::None => 0,
        }
    }

    fn text(self) -> Option<Cow<'static, str>> {
        match self {
            BlockText::Text(t) => Some(Cow::Owned(t.into_owned())),
            BlockText::Redacted => Some(Cow::Borrowed(OPAQUE_CONTENT_MARKER)),
            BlockText::None => None,
        }
    }
}

/// The body's conversation-turn array: `contents` (gemini), a list `input` (responses), else
/// `messages`.
fn conversation_turns<'a>(v: &'a Value, dialect: &str) -> Option<&'a Vec<Value>> {
    let key = match dialect {
        PROTO_GEMINI => "contents",
        PROTO_RESPONSES => "input",
        _ => "messages",
    };
    v.get(key).and_then(Value::as_array)
}

/// The turn count; a responses bare-string `input` is one turn.
fn turn_count(v: &Value, dialect: &str) -> usize {
    match conversation_turns(v, dialect) {
        Some(turns) => turns.len(),
        None => usize::from(
            dialect == PROTO_RESPONSES && v.get("input").and_then(Value::as_str).is_some(),
        ),
    }
}

/// A block carrying a plain `text` string.
fn generic_block_text(b: &Value) -> BlockText<'_> {
    match b.get("text").and_then(Value::as_str) {
        Some(t) => BlockText::Text(Cow::Borrowed(t)),
        None => BlockText::None,
    }
}

/// A block's text in `dialect`'s wire shapes, reasoning included, opaque reasoning marked.
fn block_text<'a>(b: &'a Value, dialect: &str) -> BlockText<'a> {
    match dialect {
        PROTO_ANTHROPIC => match b.get("type").and_then(Value::as_str) {
            Some("thinking") => match b.get("thinking").and_then(Value::as_str) {
                Some(t) => BlockText::Text(Cow::Borrowed(t)),
                None => BlockText::None,
            },
            Some("redacted_thinking") => BlockText::Redacted,
            _ => generic_block_text(b),
        },
        PROTO_BEDROCK => {
            if let Some(t) = b
                .pointer("/reasoningContent/reasoningText/text")
                .and_then(Value::as_str)
            {
                BlockText::Text(Cow::Borrowed(t))
            } else if b.pointer("/reasoningContent/redactedContent").is_some() {
                BlockText::Redacted
            } else {
                generic_block_text(b)
            }
        }
        PROTO_RESPONSES => match b.get("type").and_then(Value::as_str) {
            Some(ITEM_TYPE_REASONING) => {
                let text = read_reasoning_text(b);
                if !text.is_empty() {
                    BlockText::Text(text)
                } else if read_reasoning_encrypted_content(b).is_some() {
                    BlockText::Redacted
                } else {
                    BlockText::None
                }
            }
            _ => generic_block_text(b),
        },
        _ => generic_block_text(b),
    }
}

/// A gemini Content object's `parts[].text`, joined by newlines.
fn gemini_parts(c: &Value) -> String {
    c.get("parts")
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// A gemini Content object's `parts[].text` characters.
fn gemini_parts_chars(c: &Value) -> usize {
    c.get("parts")
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .map(|t| t.chars().count())
                .sum()
        })
        .unwrap_or(0)
}

/// A content value: a bare string, or blocks whose texts join by newline.
fn flatten_content(c: Option<&Value>, dialect: &str) -> String {
    match c {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|b| block_text(b, dialect).text())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// The system prompt's characters.
fn system_text_chars(v: &Value, dialect: &str) -> usize {
    match dialect {
        PROTO_GEMINI => v.get("systemInstruction").map_or(0, gemini_parts_chars),
        PROTO_RESPONSES => v
            .get("instructions")
            .and_then(Value::as_str)
            .map_or(0, |s| s.chars().count()),
        _ => match v.get("system") {
            Some(Value::String(s)) => s.chars().count(),
            Some(Value::Array(blocks)) => {
                blocks.iter().map(|b| block_text(b, dialect).chars()).sum()
            }
            _ => 0,
        },
    }
}

/// Whether a responses item is a reasoning item.
fn is_reasoning_item(m: &Value) -> bool {
    m.get("type").and_then(Value::as_str) == Some(ITEM_TYPE_REASONING)
}

/// The system prompt and every turn's characters.
fn total_text_chars(v: &Value, dialect: &str, system_chars: usize) -> usize {
    let mut total = system_chars;
    if let Some(turns) = conversation_turns(v, dialect) {
        for m in turns {
            if dialect == PROTO_GEMINI {
                total += gemini_parts_chars(m);
                continue;
            }
            if dialect == PROTO_RESPONSES && is_reasoning_item(m) {
                total += block_text(m, PROTO_RESPONSES).chars();
                continue;
            }
            match m.get("content") {
                Some(Value::String(s)) => total += s.chars().count(),
                Some(Value::Array(blocks)) => {
                    total += blocks
                        .iter()
                        .map(|b| block_text(b, dialect).chars())
                        .sum::<usize>();
                }
                _ if dialect == PROTO_RESPONSES => total += block_text(m, PROTO_RESPONSES).chars(),
                _ => {}
            }
        }
    } else if dialect == PROTO_RESPONSES {
        if let Some(s) = v.get("input").and_then(Value::as_str) {
            total += s.chars().count();
        }
    }
    total
}

/// The end user: `user`, then `metadata.user_id`; empty is none.
fn body_end_user(v: &Value) -> Option<String> {
    v.get("user")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            v.get("metadata")
                .and_then(|m| m.get("user_id"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        })
        .map(str::to_string)
}

/// One turn's `(role, text)`, every turn kept (a turn with nothing readable reads empty).
fn turn(m: &Value, dialect: &str) -> (String, String) {
    let text = if dialect == PROTO_GEMINI {
        gemini_parts(m)
    } else if dialect == PROTO_RESPONSES && (is_reasoning_item(m) || m.get("content").is_none()) {
        // A reasoning item, or an item with no `content`, reads through its block's text.
        block_text(m, PROTO_RESPONSES)
            .text()
            .map(Cow::into_owned)
            .unwrap_or_default()
    } else {
        flatten_content(m.get("content"), dialect)
    };
    let role = match m.get("role").and_then(Value::as_str) {
        Some("model") if dialect == PROTO_GEMINI => "assistant",
        Some(role) => role,
        None if dialect == PROTO_RESPONSES => match m.get("type").and_then(Value::as_str) {
            Some(CONTENT_TYPE_OUTPUT_TEXT | ITEM_TYPE_REASONING | ITEM_TYPE_FUNCTION_CALL) => {
                "assistant"
            }
            _ => "user",
        },
        None => "",
    };
    (role.to_string(), text)
}

/// The raw view of `v` (`Value::Null` for a body that is no JSON object: the empty view).
pub(super) fn raw_view(v: &Value, dialect: &str) -> RawView {
    let system_chars = system_text_chars(v, dialect);
    let system = match dialect {
        PROTO_GEMINI => v.get("systemInstruction").map(gemini_parts),
        PROTO_RESPONSES => v
            .get("instructions")
            .and_then(Value::as_str)
            .map(str::to_string),
        _ => v.get("system").map(|s| flatten_content(Some(s), dialect)),
    }
    .filter(|s| !s.is_empty());
    let turns = match conversation_turns(v, dialect) {
        Some(turns) => turns.iter().map(|m| turn(m, dialect)).collect(),
        None if dialect == PROTO_RESPONSES => v
            .get("input")
            .and_then(Value::as_str)
            .map(|s| vec![("user".to_string(), s.to_string())])
            .unwrap_or_default(),
        None => Vec::new(),
    };
    RawView {
        turn_count: turn_count(v, dialect),
        text_chars: total_text_chars(v, dialect, system_chars),
        has_tools: v
            .get("tools")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty()),
        system,
        turns,
        end_user: body_end_user(v),
    }
}
