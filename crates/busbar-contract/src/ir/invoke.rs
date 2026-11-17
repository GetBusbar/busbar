// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INVOKE IR data — the `OpVerb::INVOKE` request/response pair.

use super::SourceScopedExtra;
use crate::operation::OpVerb;
use crate::secret_json::SecretJson;
use serde_json::Value;
use std::collections::BTreeMap;
use zeroize::Zeroize as _;

/// A CALL TO ONE NAMED TARGET. The request half of the `Invoke` operation.
/// Its tool name, its arguments and its extras (names and values) are wiped when dropped. The
/// arguments and extra values are never a JSON tree: they are canonical text in custody
/// ([`SecretJson`], DES-SONIC-WIPE r3), and `Debug` prints their lengths only.
#[derive(Debug, Clone, PartialEq)]
pub struct InvokeReq {
    /// THE TOOL BEING CALLED, in the caller's vocabulary — the name as PUBLISHED, which is not
    /// necessarily the name the upstream knows it by. The rename on the way out is
    /// `ProtocolWriter::rewrite_model`'s job on this operation, exactly as it is the model rename's
    /// job on chat: the writer owns the target identifier's egress spelling, so the engine never
    /// learns that a rename happened.
    pub tool: String,
    /// THE ARGUMENTS, as the caller sent them, in canonical form. An arbitrary JSON document by the
    /// protocol's own definition, so it is carried whole and not modelled further: busbar
    /// validates arguments against the tool's declared schema, and validating is not the same as
    /// reshaping. Read it borrowed ([`SecretJson::view`], [`SecretJson::decode`]).
    pub arguments: SecretJson,
    /// Unmodelled request members, kept keyed so a cross-protocol hop cannot leak a source-only
    /// key into a foreign dialect. Same discipline as chat's `extra`; the values are secret-bearing.
    pub extra: SecretScopedExtra,
}

/// The arguments and extras wipe themselves; the tool name is wiped here.
impl Drop for InvokeReq {
    fn drop(&mut self) {
        self.tool.zeroize();
    }
}

/// Source-scoped request extras whose values are secret-bearing JSON: outer key the source
/// protocol, inner key the member's name. The keys are the caller's `String`s, adopted and wiped
/// on drop; a key a duplicate brings in is wiped at once, at either level (the last value wins).
/// Clones are deep, into new custody; `Debug` prints the number of sources only.
#[derive(Default, Clone, PartialEq)]
pub struct SecretScopedExtra(BTreeMap<String, BTreeMap<String, SecretJson>>);

impl SecretScopedExtra {
    /// Add `value` as `source`'s member `name`, replacing (and wiping) any value already there. A
    /// key already present stays; the one passed in is wiped.
    pub fn insert(&mut self, mut source: String, name: String, value: SecretJson) {
        if let Some(members) = self.0.get_mut(source.as_str()) {
            source.zeroize();
            insert_member(members, name, value);
        } else {
            let mut members = BTreeMap::new();
            members.insert(name, value);
            self.0.insert(source, members);
        }
    }

    /// `source`'s member `name`.
    #[must_use]
    pub fn get(&self, source: &str, name: &str) -> Option<&SecretJson> {
        self.0.get(source)?.get(name)
    }

    /// Every `(source, name, value)`, sources and then names in byte order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str, &SecretJson)> + '_ {
        self.0.iter().flat_map(|(source, members)| {
            members
                .iter()
                .map(move |(name, value)| (source.as_str(), name.as_str(), value))
        })
    }
}

/// `name` → `value` in one source's members; a name already present keeps its key, and the one
/// passed in is wiped.
fn insert_member(members: &mut BTreeMap<String, SecretJson>, mut name: String, value: SecretJson) {
    if let Some(slot) = members.get_mut(name.as_str()) {
        name.zeroize();
        *slot = value;
    } else {
        members.insert(name, value);
    }
}

/// Each entry through [`SecretScopedExtra::insert`], so duplicates are wiped as there.
impl FromIterator<(String, String, SecretJson)> for SecretScopedExtra {
    fn from_iter<I: IntoIterator<Item = (String, String, SecretJson)>>(entries: I) -> Self {
        let mut extra = Self::default();
        for (source, name, value) in entries {
            extra.insert(source, name, value);
        }
        extra
    }
}

impl std::fmt::Debug for SecretScopedExtra {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretScopedExtra")
            .field("sources", &self.0.len())
            .finish()
    }
}

/// The keys are wiped; each value wipes itself.
impl Drop for SecretScopedExtra {
    fn drop(&mut self) {
        for (mut source, members) in std::mem::take(&mut self.0) {
            source.zeroize();
            for (mut name, _value) in members {
                name.zeroize();
            }
        }
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
            value: crate::ir::facts::DataRef::Text(&self.arguments),
        }]
    }
}
