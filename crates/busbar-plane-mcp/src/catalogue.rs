// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `server/discover`, `prompts/get` and `resources/read` — THE PLANE'S HALF: read the caller's own
//! catalogue slice off [`busbar_contract::catalogue::CatalogueView`] and render the three documents,
//! byte for byte, member for member, the shape `busbar-mcp`'s own `method.rs` built inline before
//! this module existed to build it.
//!
//! PLAN LINE 3. These three are the catalogue-reading methods: unlike `tools/list` and its siblings,
//! which render a whole inventory through `busbar_substrate::catalogue::rendered`, each of these
//! three asks the registry ONE question — "how much can this caller reach", "what is this prompt",
//! "what is at this URI" — and then writes a document. The question is the face's; the document is
//! this crate's, because this crate is the one place the MCP wire is named.
//!
//! ## Where the two filters run, and why here
//!
//! Two passes run over operator and caller text on the way out, and both are on this side of the
//! face: SUBSTITUTION (a `{name}` placeholder filled from the caller's `params.arguments`, or from
//! the bindings a URI template matched) and NORMALISATION (the markup strip that keeps text
//! re-entering a model's instruction stream from carrying instructions of its own). The face carries
//! the registry's text as the registry holds it — see
//! [`busbar_contract::catalogue::PromptTemplate`] — because both passes read the caller's own
//! request, which the face never sees, and both write the wire, which the face does not name.
//!
//! THE ORDER IS SUBSTITUTE FIRST, NORMALISE SECOND, everywhere, and it is the whole safety property:
//! normalising first and substituting after would put caller-controlled bytes into a model's context
//! having passed through no filter at all. The argument value is exactly as injectable as the
//! template it lands in, and it is MORE attacker-controlled, because the template is the operator's
//! and the argument is not.

use busbar_contract::catalogue::{
    Address, CatalogueView, Found, PromptContent, PromptTemplate, Resolution, ResourceBody,
};
use busbar_mcp_codec::sanitize;
use serde_json::Value;

/// WHO IS ANSWERING — the identity and protocol constants a discovery document states about the
/// server itself, gathered into one value.
///
/// Passed in rather than spelled here because every one of them belongs to a different owner: the
/// package version is the BINARY's (this crate's own `CARGO_PKG_VERSION` would name the adapter, not
/// the server), and the two version lists are the CODEC's, read from the same constants the ingress
/// refuses an unsupported version against. A copy of either list here would be a second list that
/// could disagree with the first, and a client told to retry with a version it will be refused for.
#[derive(Clone, Copy, Debug)]
pub struct ServerIdentity<'a> {
    /// The server's advertised name.
    pub name: &'a str,
    /// The server's advertised version.
    pub version: &'a str,
    /// The revision THIS answer is written in.
    pub protocol_version: &'a str,
    /// The revisions this server will ACCEPT — the mandatory field of a `DiscoverResult`, and not
    /// the same statement as [`protocol_version`](Self::protocol_version).
    pub supported_versions: &'a [&'a str],
    /// The SEP-2663 tasks extension id, advertised under `capabilities.extensions`.
    pub tasks_extension_id: &'a str,
}

/// `server/discover` — the MERGED, GRANT-SCOPED catalogue advertisement.
///
/// Under `2026-07-28` there is no `initialize`, so this is the only capability advertisement there
/// is, and the rule that governs every other check under on-demand negotiation governs this one: it
/// is computed PER REQUEST from the caller's own grant, never once and then cached. Two callers
/// discover two different servers. That is the point — a discovery document that described the
/// deployment rather than the caller would enumerate every registered upstream to anyone who asked,
/// which is a map of the operator's internal estate handed out for the price of one token. The face
/// this reads is bound to ONE caller for exactly that reason.
///
/// The counts are of what THIS caller can reach, and the `servers` list names only servers this
/// caller holds at least one capability on.
#[must_use]
pub fn discovery_document(
    view: &dyn CatalogueView,
    identity: &ServerIdentity<'_>,
    methods: &[&str],
) -> Value {
    let tools = view.tools_for();
    let prompts = view.prompts_for();
    let resources = view.resources_for();
    let mut servers: Vec<&str> = tools
        .iter()
        .map(|t| t.server.as_str())
        .chain(prompts.iter().map(|p| p.server.as_str()))
        .chain(resources.iter().map(|r| r.server.as_str()))
        .collect();
    servers.sort_unstable();
    servers.dedup();

    crate::view::cacheable(serde_json::json!({
        "protocolVersion": identity.protocol_version,
        // The versions this server will ACCEPT, which is the mandatory field of a `DiscoverResult`
        // and is not the same statement as `protocolVersion` above (that one names the revision this
        // answer is written in). It is the SAME constant the ingress refuses an unsupported version
        // against, and it is that constant rather than a copy for a reason the conformance suite
        // checks directly: it correlates the `data.supported` list on an
        // `UnsupportedProtocolVersionError` against this list, so two lists that could disagree
        // would be a client told to retry with a version it will be refused for.
        "supportedVersions": identity.supported_versions,
        "serverInfo": { "name": identity.name, "version": identity.version },
        // Advertised as present only when this caller can actually reach one. A capability
        // advertised to a caller who holds nothing under it is an invitation to a refusal.
        "capabilities": {
            // `listChanged: true` on all three, because `subscriptions/listen` DELIVERS all three:
            // the engine's subscription composer narrows a requested filter to exactly
            // {tools,prompts,resources}ListChanged and emits each on the caller's own stream when
            // the grant-scoped catalogue slice moves. This flag is the field a client reads to
            // decide whether change notifications exist AT ALL — advertising `false` beside a
            // working stream is an undeclared surface no conforming client will ever open, and one
            // that probed the method anyway was told by this very document to expect `-32601`, so
            // the stream response read as a hang. The declaration and the delivery are pinned to
            // each other by `discover_declares_the_capabilities_the_listen_stream_delivers`.
            "tools": { "listChanged": true },
            "prompts": { "listChanged": true },
            // `subscribe: true` since the relay landed: `resourceSubscriptions` on
            // `subscriptions/listen` is DELIVERED now — an upstream's own
            // `notifications/resources/updated` is recorded by the client leg and relayed to
            // subscribers whose grant reaches the named resource. The old `false` was pinned to the
            // sentence "busbar is not told when a resource's contents change", and that sentence
            // stopped being true; a declaration and a delivery must keep agreeing in BOTH
            // directions, which is what
            // `discover_declares_the_capabilities_the_listen_stream_delivers` pins.
            "resources": { "listChanged": true, "subscribe": true },
            // Present because `completion/complete` is IMPLEMENTED and answers correctly, which is
            // what the capability declares. It is not a claim that this deployment has suggestions
            // to give — the answer is the empty set, which is a complete answer rather than a stub.
            "completions": {},
            // Present because busbar EMITS `notifications/message` records about its own handling of
            // a request, on the response stream of the request they describe. There is deliberately
            // no `logging/setLevel`: this revision has no session for a level to live in, so the
            // level is named per request in `_meta`.
            "logging": {},
            // SEP-2663, advertised UNCONDITIONALLY — unlike the counts below, which are scoped to
            // what this caller can reach.
            //
            // The asymmetry is deliberate and it is the difference between a CATALOGUE and a
            // PROTOCOL. `tools`/`prompts`/`resources` describe what this caller may see, and a
            // caller whose grant reaches nothing legitimately sees nothing. An extension describes
            // what the SERVER can do with the wire: `tasks/get`, `tasks/update` and `tasks/cancel`
            // are implemented, gated only on the caller's own declaration, and answer correctly for
            // every caller — including one who currently holds no task-supporting tool, for whom the
            // honest answer is "the surface exists, you have nothing on it" rather than "the surface
            // does not exist".
            //
            // It is advertised under `extensions` and NOT as a v1-style `capabilities.tasks` slot,
            // because the extension REPLACED that surface rather than living beside it, and a server
            // advertising both would be claiming two protocols at once.
            "extensions": { identity.tasks_extension_id: {} },
        },
        "methods": methods,
        "servers": servers,
        "counts": {
            "tools": tools.len(),
            "prompts": prompts.len(),
            "resources": resources.len(),
        },
        // Honest, and deliberately advertised: an MCP deployment with an empty registry answers
        // every catalogue with an empty list, and a client that cannot tell "you may see nothing"
        // from "there is nothing" will retry for ever.
        "registryEmpty": view.is_empty(),
    }))
}

/// `prompts/get`'s document: resolve `name` through the face and render the TEMPLATE, sanitized.
///
/// Prompt templates are in the sanitization set explicitly, because a template is exactly as
/// injectable as tool output, and an early draft of this design covered neither.
///
/// `None` when the face holds nothing this caller may see under that name — the caller's own
/// JSON-RPC refusal is its business, not this function's; no error code is named here. Not-found and
/// not-granted are one answer on the face's side, for the reason
/// [`busbar_contract::catalogue`] states.
#[must_use]
pub fn prompt_document(
    view: &dyn CatalogueView,
    name: &str,
    params: Option<&Value>,
) -> Option<Value> {
    let Resolution::One(Found::Prompt(prompt)) = view.resolve(Address::Prompt(name)) else {
        // An `Ambiguous` here would be an implementor answering in an arm a prompt address has no
        // meaning in, and a `Resource` arm would be an implementor answering the wrong question;
        // both read as "nothing this caller may see", which is what the face's own contract says a
        // mismatched arm is.
        return None;
    };
    Some(serde_json::json!({
        "description": sanitize::normalise_opt(prompt.description.as_deref()),
        "messages": prompt_messages(&prompt, params),
    }))
}

/// The `messages` array `prompts/get` returns.
///
/// ONE FUNCTION FOR EVERY CONTENT FORM, and that is the point rather than tidiness: every form must
/// go through the SAME substitute-then-normalise pass. A second rendering path would be a second
/// place to forget the strip, and a new content type that skipped it would be a hole opened by a
/// feature nobody thought of as a text surface. The face hands this a message list that is never
/// empty — a registry holding only a bare template flattens it to one `user` text message on its own
/// side — so there is no second shape to branch on here either.
fn prompt_messages(prompt: &PromptTemplate, params: Option<&Value>) -> Vec<Value> {
    // SUBSTITUTE FIRST, NORMALISE SECOND — see the module header. The caller's argument values pass
    // through the same markup strip the operator's own text does.
    let render = |s: &str| sanitize::normalise(&substitute_arguments(s, params));

    prompt
        .messages
        .iter()
        .map(|m| {
            let content = match &m.content {
                PromptContent::Text { text } => serde_json::json!({
                    "type": "text", "text": render(text),
                }),
                // The base64 payload is NOT normalised. `normalise` strips markup from text that
                // re-enters a model's instruction stream; a media payload is opaque bytes the client
                // was told the type of, and running a text filter over base64 would corrupt it while
                // protecting nothing. It is validated as decodable at BOOT instead.
                PromptContent::Image { data, mime_type } => serde_json::json!({
                    "type": "image", "data": data, "mimeType": mime_type,
                }),
                PromptContent::Audio { data, mime_type } => serde_json::json!({
                    "type": "audio", "data": data, "mimeType": mime_type,
                }),
                PromptContent::Resource {
                    uri,
                    mime_type,
                    text,
                    blob,
                } => {
                    let mut r = serde_json::Map::new();
                    // The URI substitutes: a prompt may take the URI to embed as an ARGUMENT, so a
                    // template that could not substitute here could not express the shape at all. It
                    // is normalised too — a URI carrying an HTML-like tag is not a URI, and this one
                    // is echoed into a model's context.
                    r.insert("uri".into(), render(uri).into());
                    if let Some(m) = mime_type {
                        r.insert("mimeType".into(), m.clone().into());
                    }
                    if let Some(t) = text {
                        r.insert("text".into(), render(t).into());
                    }
                    if let Some(b) = blob {
                        r.insert("blob".into(), b.clone().into());
                    }
                    serde_json::json!({ "type": "resource", "resource": r })
                }
            };
            serde_json::json!({ "role": m.role, "content": content })
        })
        .collect()
}

/// Substitute `{arg}` placeholders in a prompt template from the caller's `params.arguments`.
///
/// The `{name}` spelling is the one the operator-facing templates already use; what was missing was
/// the substitution, so a client that sent arguments got the template back with its placeholders
/// intact and no indication that anything had been ignored.
///
/// TWO RULES, and both are about where the caller's text is allowed to reach.
///
/// 1. THE SUBSTITUTED TEXT IS NORMALISED, NOT THE TEMPLATE — see the module header. So this function
///    only builds the string; the single `normalise` at the call site runs over the RESULT, after
///    substitution.
/// 2. AN UNKNOWN PLACEHOLDER IS LEFT ALONE rather than emptied. `{arg1}` with no `arg1` supplied
///    stays `{arg1}`, which is visible to a human reading the output; silently substituting the
///    empty string would turn "you forgot an argument" into a prompt that reads as complete and
///    means something else.
///
/// Only string arguments substitute. A structured value has no single correct rendering into a text
/// template, and picking one (`JSON.stringify`, say) would let an argument's shape decide what the
/// prompt says.
#[must_use]
pub fn substitute_arguments(template: &str, params: Option<&Value>) -> String {
    let Some(args) = params
        .and_then(|p| p.get("arguments"))
        .and_then(|a| a.as_object())
    else {
        return template.to_string();
    };
    // ONE PASS OVER THE TEMPLATE, never over the result. A pass PER ARGUMENT would substitute into
    // an accumulator that already holds earlier arguments' text, so a `{b}` a caller spelled inside
    // the value of `a` would be filled from `b` — one argument deciding what another means — and,
    // chained, each argument would MULTIPLY the ones before it: ten linked keys in a 300-byte request
    // is 10^10 bytes of string on a request thread. Reading the template once makes the output length
    // the template plus the arguments, whatever those arguments spell.
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        // `{` is ASCII, so this is a char boundary; so is the `}` found below.
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            // An unclosed `{` is the operator's literal text: emit the remainder verbatim.
            out.push_str(&rest[open..]);
            return out;
        };
        let name = &after[..close];
        match args.get(name).and_then(|v| v.as_str()) {
            Some(text) => out.push_str(text),
            // RULE 2: an unknown placeholder is left alone, spelling and all.
            None => {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// `resources/read`'s three terminals, in the plane's own words.
///
/// Three arms rather than an `Option`, for the reason [`Resolution`] has three: a contended address
/// is a question the registry cannot answer, and reporting it as a not-found would let the refusal
/// be bypassed by writing the approval differently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceRead {
    /// The bare `{contents: [...]}` result document, cache-annotated.
    Contents(Value),
    /// More than one approval this caller holds answers the address. Carries the contending
    /// approvals, sorted, the way an operator can act on them.
    Ambiguous(Vec<String>),
    /// No such resource, OR the caller holds no grant for it.
    NotFound,
}

/// `resources/read` — the CONTENT, sanitized. The third injectable surface, beside tool output and
/// prompt templates, and no less injectable for arriving as "data".
///
/// CONCRETE FIRST, TEMPLATE SECOND is the face implementor's rule, not this function's: a URI the
/// operator approved BY NAME must not be answered by a template that happens to match it, and the
/// ordering belongs beside the registry that holds both. What is here is the WRITE — one address,
/// one content block, one filter pass.
#[must_use]
pub fn resource_read(view: &dyn CatalogueView, uri: &str) -> ResourceRead {
    match view.resolve(Address::Resource(uri)) {
        Resolution::One(Found::Resource(body)) => ResourceRead::Contents(crate::view::cacheable(
            serde_json::json!({ "contents": [resource_content(&body)] }),
        )),
        Resolution::Ambiguous(candidates) => ResourceRead::Ambiguous(candidates),
        // A `Prompt` arm would be an implementor answering the wrong question; it reads as
        // "nothing this caller may see", which is what the face's own contract says a mismatched arm
        // is.
        Resolution::One(Found::Prompt(_)) | Resolution::NotFound => ResourceRead::NotFound,
    }
}

/// The `ResourceContents` block for one resolved resource.
///
/// `text` and `blob` are the schema's two ALTERNATIVES, and exactly one is emitted. Registry
/// validation already refuses a declaration carrying both, so the `else` arm here is the honest
/// "neither was declared" — an approved resource with no content, which answers the empty text form
/// rather than an error, because the operator approving a URI and leaving it empty is a statement
/// about content, not a malformed request.
///
/// The URI echoed is the one the face carries, which is the one the CALLER ASKED FOR: a client
/// correlates the content it received with the URI it sent, and answering a parameterised approval
/// with its unexpanded template would hand back an identifier that names every expansion at once.
fn resource_content(body: &ResourceBody) -> Value {
    let mut content = serde_json::Map::new();
    // ECHOED AS ASKED. A client correlates this block to its own request by this field.
    content.insert("uri".into(), body.uri.clone().into());
    if let Some(m) = &body.mime_type {
        content.insert("mimeType".into(), m.clone().into());
    }
    match &body.blob {
        // NOT normalised. A markup strip over base64 corrupts the payload and protects nothing; what
        // protects the client is the boot-time decode check.
        Some(blob) => {
            content.insert("blob".into(), blob.clone().into());
        }
        None => {
            content.insert(
                "text".into(),
                sanitize::normalise(body.text.as_deref().unwrap_or("")).into(),
            );
        }
    }
    Value::Object(content)
}

#[cfg(test)]
#[path = "tests/catalogue.rs"]
mod tests;
