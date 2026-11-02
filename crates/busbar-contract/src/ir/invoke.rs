// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INVOKE IR data — the `OpVerb::INVOKE` request/response pair.

use super::SourceScopedExtra;
use crate::operation::OpVerb;
use serde_json::Value;

/// A CALL TO ONE NAMED TARGET. The request half of the `Invoke` operation.
/// Owned request strings, including JSON member names and extras, are wiped when dropped.
#[derive(Debug, Clone, PartialEq)]
pub struct InvokeReq {
    /// THE TOOL BEING CALLED, in the caller's vocabulary — the name as PUBLISHED, which is not
    /// necessarily the name the upstream knows it by. The rename on the way out is
    /// `ProtocolWriter::rewrite_model`'s job on this operation, exactly as it is the model rename's
    /// job on chat: the writer owns the target identifier's egress spelling, so the engine never
    /// learns that a rename happened.
    pub tool: String,
    /// THE ARGUMENTS, verbatim as the caller sent them. An arbitrary JSON object by the protocol's
    /// own definition, so it is carried as a `Value` and not modelled further: busbar validates
    /// arguments against the tool's declared schema, and validating is not the same as reshaping.
    pub arguments: Value,
    /// Unmodelled request members, kept keyed so a cross-protocol hop cannot leak a source-only
    /// key into a foreign dialect. Same discipline as chat's `extra`.
    pub extra: SourceScopedExtra,
}

impl Drop for InvokeReq {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.tool.zeroize();
        wipe_request_json(&mut self.arguments);
        for (mut source, members) in std::mem::take(&mut self.extra) {
            source.zeroize();
            for (mut name, mut value) in members {
                name.zeroize();
                wipe_request_json(&mut value);
            }
        }
    }
}

fn wipe_request_json(value: &mut Value) {
    use zeroize::Zeroize as _;
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_request_json),
        Value::Object(members) => {
            for (mut name, mut value) in std::mem::take(members) {
                name.zeroize();
                wipe_request_json(&mut value);
            }
        }
        _ => {}
    }
}

/// WHAT ONE TOOL CALL PRODUCED. The response half.
#[derive(Debug, Clone, PartialEq)]
pub struct InvokeResp {
    /// The content the tool returned, verbatim. busbar is content-blind on this operation: it
    /// decides WHETHER a call may happen and records THAT it happened, and rewriting a payload is
    /// not a gateway's job.
    pub content: Value,
    /// THE TOOL FAILED, BUT THE CALL DID NOT. See the module note on the two error channels: this
    /// is a successful protocol exchange reporting an unsuccessful tool. It must never be rendered
    /// as a protocol-level error, and a protocol-level error must never be rendered as this.
    pub is_error: bool,
    /// Structured output, when the tool declares an output schema and returned one. `None` when it
    /// does not — and note that busbar does not yet model output schemas at all, so this is
    /// carried rather than validated. Stated here rather than left to be discovered.
    pub structured: Option<Value>,
    /// Unmodelled response members, source-keyed for the same reason as the request's.
    pub extra: SourceScopedExtra,
}

/// THE INVOCATION FAMILY'S WALK — this IR's answer to [`crate::ir::facts::IrFacts`], the
impl crate::ir::facts::IrFacts for InvokeReq {
    fn verb(&self) -> OpVerb {
        OpVerb::INVOKE
    }

    /// An invocation is one exchange. The streaming question belongs to the operations that can
    fn wants_stream(&self) -> bool {
        false
    }

    /// NO END-USER IDENTIFIER, and this is a statement about the protocol rather than an omission:
    fn end_user(&self) -> Option<&str> {
        None
    }

    fn shape(&self) -> crate::ir::facts::Shape {
        let items = crate::ir::facts::IrFacts::content(self);
        let (text_chars, system_chars) = crate::ir::facts::Shape::counts_over(&items);

        crate::ir::facts::Shape {
            turn_count: 1,

            has_tools: true,

            tool_count: 1,
            text_chars,

            system_chars,

            max_tokens: None,
        }
    }

    fn content(&self) -> Vec<crate::ir::facts::ContentItem<'_>> {
        vec![crate::ir::facts::ContentItem::Data {
            // The invocation family's author label — its own word for "the caller", not a chat
            // role.
            author: "user",
            slot: crate::ir::facts::Slot::ToolArgs(0),
            label: self.tool.as_str(),
            value: &self.arguments,
        }]
    }
}
