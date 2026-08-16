// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL CONTRACT — what core knows about a protocol, declared once by the protocol itself.
//!
//! The companion to [`crate::plane`]: a PLANE is the surface that serves a protocol (config section,
//! routes, scope vocabulary); a PROTOCOL is the wire dialect (codec, verbs, egress credentials).
//! Most plugins are one or the other; MCP and A2A are both, which is why they are two kinds sharing
//! one ABI crate rather than one kind forced to cover both.
//!
//! Core routes, mounts, labels and bounds from [`ProtocolDecl`] and from nothing else. Every field
//! replaces either a `match` on a protocol name or a vtable sweep that allocated to read a constant.

/// WHICH INBOUND AUTH SCHEME a protocol's clients present. DECLARED metadata, never a branch: the
/// verification itself stays in core's auth layer, which has the governance key lookup and the
/// shared signing helpers. A plugin says which scheme it speaks; it does not get to verify it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IngressAuth {
    /// A bearer token / API key in a header.
    Bearer,
    /// An AWS SigV4 request signature (Bedrock's ingress shape).
    SigV4,
}

/// THE DIALECT-FREE ERROR ENVELOPE — what core renders when NO protocol resolved.
///
/// **This function is why a zero-plugin build can refuse a request at all.** Before it,
/// `proxy/wire.rs` reached for a concrete dialect's writer to render the generic envelope, which
/// meant core needed at least one dialect linked in order to say *"I do not speak that"* — and the
/// dialect it reached for was whichever one had not been extracted yet, so the choice silently
/// migrated (openai → gemini → …) with each extraction and would eventually have had nowhere left
/// to go. An error body is not a dialect's property, so core owns this one outright.
///
/// The shape is the de-facto interoperable one every SDK's error path already parses; it names no
/// vendor and is stable regardless of which protocols are compiled in.
pub fn unresolved_ingress_error(status: u16, message: &str) -> Vec<u8> {
    // Hand-built rather than `serde_json::json!` so the exact byte shape is visible at the site that
    // promises it, and so this stays renderable if the ABI ever drops its serde dependency.
    let escaped = escape_json_string(message);
    format!(
        r#"{{"error":{{"message":"{escaped}","type":"invalid_request_error","code":{status}}}}}"#
    )
    .into_bytes()
}

/// Minimal RFC 8259 string escaping for the envelope above. Control characters are escaped rather
/// than dropped: a message that reached here may carry upstream-influenced text, and emitting a raw
/// control byte inside a JSON string would produce a body a client cannot parse.
fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/protocol_tests.rs"]
mod tests;
