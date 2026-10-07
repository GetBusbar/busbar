//! THE HOOK PROJECTION, sans I/O: what a hook is shown of an arrival (`BUSBAR-1.6.0.md` Part 3,
//! section 12, "Hooks"; THE DESIGN section 11.7), and a request-stage hook's rewrite applied to
//! the arrival in its own dialect.
//!
//! One read, through the operation's own reader, as the previous release's hook seam read it: the
//! size signals (turns, characters, tools), the end user the dialect spells, and the prompt view
//! (the system field and one `(role, text)` entry per wire turn, an in-band system turn at its wire
//! position, a turn with nothing readable still an entry). A JSON object body is projected as far
//! as the reader can read it, a turn or block it cannot read contributing nothing; any other body (a
//! multipart upload, a binary payload) is read by the operation's byte reader, and one it refuses
//! projects the zeroed shape. A projection never refuses a request: the previous release showed a
//! hook the null body for every request body that was not JSON (`v1.5.5`
//! `crates/busbar/src/proxy/engine/mod.rs:955-961`) and served the request.
//!
//! The output-cap signal is the previous release's own read (`max_tokens_for` at `v1.5.5`): the
//! dialect's cap key off the caller's body, an out-of-range cap saturated to `u32::MAX`, never
//! dropped. The IR's cap is the far end's, and a reader drops a cap it cannot carry; the hook
//! signal is the caller's ask.

use busbar_contract::hooks::RewriteReply;
use busbar_contract::ir::facts::{ContentItem, IrFacts, Shape, Slot};
use serde_json::Value;

use super::arrive::Arrived;
use super::attempt::stream_intent;
use super::{decl, handler_of};
use crate::codec::translate::TranslateCodec;

/// The dialect whose output cap the previous release read under `max_output_tokens`.
const RESPONSES: &str = "responses";

/// What a hook is shown of one arrival.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HookView {
    /// The wire turn count.
    pub turn_count: usize,
    /// The screenable text's characters, system included.
    pub text_chars: usize,
    /// The request declares tools.
    pub has_tools: bool,
    /// The caller's output cap, saturated.
    pub max_tokens: Option<u32>,
    /// The caller asked for a stream.
    pub stream: bool,
    /// The dialect's own system field, flattened; `None` when empty or absent.
    pub system: Option<String>,
    /// One `(role, text)` entry per wire turn, in request order.
    pub turns: Vec<(String, String)>,
    /// The end user, as the dialect spells it.
    pub end_user: Option<String>,
}

/// The previous release's output-cap signal: the dialect's cap key (`max_output_tokens` for the
/// responses dialect, `max_tokens` for every other) off the caller's body, saturated.
#[must_use]
pub fn max_tokens_for(v: &Value, dialect: &str) -> Option<u32> {
    let key = if dialect == RESPONSES {
        "max_output_tokens"
    } else {
        "max_tokens"
    };
    v.get(key)
        .and_then(Value::as_u64)
        .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
}

/// The facts the operation's reader reads off `arrived`; `None` when there is no reader, no body to
/// read, or nothing the reader can read.
fn facts(arrived: &Arrived) -> Option<Box<dyn IrFacts + Send + Sync>> {
    let handler = handler_of(arrived)?;
    match &arrived.parsed {
        Some(v) if v.is_object() => readable_facts(handler, v),
        _ if arrived.body.is_empty() => None,
        // A body that is not a JSON object (a multipart upload) is read by the byte reader; one it
        // refuses projects nothing and the request goes on, as the previous release served it.
        _ => handler
            .read_facts(&arrived.body, &arrived.content_type)
            .ok(),
    }
}

/// THE PROJECTION OF WHAT BUSBAR CAN READ of a JSON object body. The previous release's hook
/// projection was read straight off the request and never refused one: a turn or block it could not
/// read contributed nothing, and the request went on. The reader is a tap here: when it refuses the
/// whole body, each top-level array's elements are tried one at a time (and, for an element it
/// refuses, that element's own array members one at a time), the ones it cannot read are left out,
/// and what remains is projected. A body none of whose content reads is `None` (the zeroed shape).
fn readable_facts(
    handler: &dyn busbar_contract::codec::OperationHandler,
    v: &Value,
) -> Option<Box<dyn IrFacts + Send + Sync>> {
    if let Ok(facts) = handler.read_facts_value(v) {
        return Some(facts);
    }
    let obj = v.as_object()?;
    // Every array emptied: the frame each element is tried in alone.
    let mut frame = obj.clone();
    for value in frame.values_mut() {
        if value.is_array() {
            *value = Value::Array(Vec::new());
        }
    }
    let reads_alone = |key: &str, item: &Value| {
        let mut probe = frame.clone();
        probe.insert(key.to_string(), Value::Array(vec![item.clone()]));
        handler.read_facts_value(&Value::Object(probe)).is_ok()
    };
    let mut kept = obj.clone();
    for (key, value) in obj {
        let Some(items) = value.as_array() else {
            continue;
        };
        let readable: Vec<Value> = items
            .iter()
            .filter_map(|item| {
                if reads_alone(key, item) {
                    return Some(item.clone());
                }
                let mut pruned = item.as_object()?.clone();
                for (inner, inner_value) in item.as_object()? {
                    let Some(parts) = inner_value.as_array() else {
                        continue;
                    };
                    let parts: Vec<Value> = parts
                        .iter()
                        .filter(|part| {
                            let mut one = item.as_object().cloned().unwrap_or_default();
                            one.insert(inner.clone(), Value::Array(vec![(*part).clone()]));
                            reads_alone(key, &Value::Object(one))
                        })
                        .cloned()
                        .collect();
                    pruned.insert(inner.clone(), Value::Array(parts));
                }
                let pruned = Value::Object(pruned);
                reads_alone(key, &pruned).then_some(pruned)
            })
            .collect();
        kept.insert(key.clone(), Value::Array(readable));
    }
    handler.read_facts_value(&Value::Object(kept)).ok()
}

/// One bucket's pieces joined with a newline.
fn join(pieces: Vec<String>) -> Option<String> {
    match pieces.len() {
        0 => None,
        1 => pieces.into_iter().next(),
        _ => Some(pieces.join("\n")),
    }
}

/// The prompt view of `ir`: the system slot's text, and one `(role, text)` entry per turn.
fn prompt(ir: &dyn IrFacts) -> (Option<String>, Vec<(String, String)>) {
    let mut system: Vec<String> = Vec::new();
    let mut turns: Vec<(&'static str, Vec<String>)> = Vec::new();
    for item in ir.content() {
        let piece = match &item {
            ContentItem::Text { text, .. } => text.to_string(),
            other => other.screenable_text().into_owned(),
        };
        match item.slot() {
            Slot::System => system.push(piece),
            slot => {
                let i = slot.turn_index().unwrap_or(0);
                while turns.len() <= i {
                    turns.push((item.author(), Vec::new()));
                }
                turns[i].1.push(piece);
            }
        }
    }
    (
        join(system).filter(|s| !s.is_empty()),
        turns
            .into_iter()
            .map(|(role, pieces)| (role.to_string(), join(pieces).unwrap_or_default()))
            .collect(),
    )
}

/// PROJECT one arrival for the hooks. Never refuses: what the operation's reader cannot read is not
/// shown.
#[must_use]
pub fn project(arrived: &Arrived) -> HookView {
    let stream = handler_of(arrived)
        .map(|h| stream_intent(h, arrived.parsed.as_ref()).wants_stream)
        .unwrap_or(false);
    let max_tokens = arrived
        .parsed
        .as_ref()
        .and_then(|v| max_tokens_for(v, arrived.dialect));
    let Some(ir) = facts(arrived) else {
        let shape = Shape::EMPTY;
        return HookView {
            turn_count: shape.turn_count,
            text_chars: shape.text_chars,
            has_tools: shape.has_tools,
            max_tokens,
            stream,
            ..HookView::default()
        };
    };
    let shape = ir.shape();
    let (system, turns) = prompt(&*ir);
    HookView {
        turn_count: shape.turn_count,
        text_chars: shape.text_chars,
        has_tools: shape.has_tools,
        max_tokens,
        stream,
        system,
        turns,
        end_user: ir.end_user().map(str::to_string),
    }
}

/// A rewrite as it crosses: the hook's `{messages, tools}`.
fn read_rewrite(rewrite: &[u8]) -> Option<RewriteReply> {
    let v: Value = serde_json::from_slice(rewrite).ok()?;
    let list = |k: &str| {
        v.get(k)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    Some(RewriteReply {
        messages: list("messages"),
        tools: list("tools"),
    })
}

/// APPLY a request-stage hook's rewrite to `arrived` in its own dialect: the dialect frames the
/// rewrite's messages (and tools) into its conversation container. Answers the rewritten body when
/// it applied; `None` leaves the arrival untouched (the previous release: a rewrite that cannot be
/// applied leaves the request unmodified).
pub fn apply_rewrite(arrived: &mut Arrived, rewrite: &[u8]) -> Option<Vec<u8>> {
    let reply = read_rewrite(rewrite)?;
    if reply.messages.is_empty() {
        return None;
    }
    let dialect = decl(arrived.dialect).and_then(|d| d.dialect())?;
    let mut v = arrived.parsed.clone()?;
    let obj = v.as_object_mut()?;
    if !dialect.apply_rewrite_to_ingress_body(obj, &reply.messages, &reply.tools) {
        return None;
    }
    let bytes = crate::codec::json::to_vec(&v).ok()?;
    arrived.body.clone_from(&bytes);
    arrived.parsed = Some(v);
    Some(bytes)
}
