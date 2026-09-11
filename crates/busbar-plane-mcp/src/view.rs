//! THE CATALOGUE VIEW: what this protocol's four listing classes put on the wire.
//!
//! `tools/list`, `prompts/list`, `resources/list` and `resources/templates/list` differ in one word
//! each — the member the array hangs under — and in which fields one entry carries. Everything else
//! is identical: the same cache hints, the same "absent rather than empty" rule for an optional
//! field. They were four handlers and four `render` bodies in the serving crate, which is four
//! places one wire decision could be made differently.
//!
//! IT DOES NOT DECIDE WHICH ENTRIES A CALLER MAY SEE. Entitlement is the scope step's and
//! quarantine is the trust step's; both have run by the time a row reaches here, and a projection
//! that could also exclude would be a second place a grant is interpreted. Nor does it normalise:
//! markup normalisation is a decision about the bytes an operator wrote, taken where those bytes are
//! held, so the view carries the text it is given.

use serde_json::{Map, Value};

/// `cacheScope` on every cacheable result: `private`, always — a fact about this server, not a
/// cautious default.
///
/// Every answer in these classes is scoped to the CALLER'S GRANT: two callers holding two different
/// grants get two different catalogues from the same registry at the same instant. `public` means
/// precisely "any client or intermediary MAY cache this and serve it ACROSS authorization contexts",
/// which here would be a shared proxy serving one caller's authorized catalogue to a caller who holds
/// none of it — the grant boundary crossed by a cache, and a cache is not a place where authorization
/// is re-checked. So `private` on every result, including the ones that happen to be empty today: a
/// value that is only correct while the registry is empty becomes wrong silently.
pub const CACHE_SCOPE: &str = "private";

/// `ttlMs` on every cacheable result: `0` — "consider this immediately stale; re-fetch when you need
/// it".
///
/// A POSITIVE ttl is a promise that the answer will still be true for that long, and this server
/// cannot make it: the registry is versioned and the operator can move it at any moment — an approval
/// revoked, a pin bumped, a rug-pull quarantine landing between two requests. The invalidation channel
/// that exists (`subscriptions/listen`, which is why `listChanged` is advertised `true`) is OPT-IN and
/// per-caller, so a positive ttl would be a promise kept only for the clients that subscribed, and a
/// client that cached for a minute would keep OFFERING a de-approved tool for a minute. Dispatch still
/// refuses the call it produced (the generation re-check is per request and consults no cache), so the
/// cost is a confusing refusal rather than an unauthorized call — which is exactly why the honest
/// answer is `0`: a cache hint that lies is worse than none, and `0` is not the absence of a hint but
/// the schema's own way of stating "no freshness window".
pub const CACHE_TTL_MS: i64 = 0;

/// Stamp the SEP-2549 caching hints onto a result that is CACHEABLE.
///
/// One function so the pair cannot drift apart across the results that carry it: a hint that says
/// `private` in one place and `public` in another is a hint no client can act on.
#[must_use]
pub fn cacheable(value: Value) -> Value {
    let mut value = value;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("cacheScope".into(), CACHE_SCOPE.into());
        obj.insert("ttlMs".into(), CACHE_TTL_MS.into());
    }
    value
}

/// `tools/list`'s result document over an already-entitled, already-unquarantined snapshot.
#[must_use]
pub fn tools_result(tools: Vec<Value>) -> Value {
    cacheable(serde_json::json!({ "tools": tools }))
}

/// `prompts/list`'s result document.
#[must_use]
pub fn prompts_result(prompts: Vec<Value>) -> Value {
    cacheable(serde_json::json!({ "prompts": prompts }))
}

/// `resources/list`'s result document.
#[must_use]
pub fn resources_result(resources: Vec<Value>) -> Value {
    cacheable(serde_json::json!({ "resources": resources }))
}

/// `resources/templates/list`'s result document.
#[must_use]
pub fn resource_templates_result(templates: Vec<Value>) -> Value {
    cacheable(serde_json::json!({ "resourceTemplates": templates }))
}

/// ONE TOOL as the wire carries it.
pub struct ToolView<'a> {
    /// The NAMESPACED name, which is the wire name because it is the routing key — the bound identity
    /// a route is decided on, never the free-text description — and the value an `mcp_tool` grant
    /// carries. The bare upstream name would let two servers collide in one caller's catalogue, so
    /// one server's tool would silently answer for another's.
    pub name: &'a str,
    /// Already markup-normalised; `None` when there is nothing to say.
    pub description: Option<&'a str>,
    /// `None` where the operator declared none. A tool with no declared schema still gets a
    /// schema-shaped answer — clients reject a tool whose `inputSchema` is absent, and `{"type":
    /// "object"}` is the honest "no constraints declared" rather than a fabricated one.
    pub input_schema: Option<&'a Value>,
    /// Absent where the operator approved none, and deliberately with no stand-in: an absent
    /// `outputSchema` means "this tool makes no promise about structured output", where `{}` would
    /// mean "it promises, and the promise is vacuous". The specification reads the PRESENCE of this
    /// key to decide whether a conforming structured result is a MUST, so inventing one invents an
    /// obligation — and dropping a real one leaves a client that would have validated with nothing to.
    pub output_schema: Option<&'a Value>,
    /// The approved schema hash, published because it is the operator's approval and not a secret: a
    /// client that pins what it saw is a client that notices a rug-pull too.
    pub schema_hash: Option<&'a str>,
}

/// One tool, projected.
#[must_use]
pub fn tool(v: &ToolView<'_>) -> Value {
    let mut obj = Map::new();
    obj.insert("name".into(), v.name.into());
    if let Some(d) = v.description {
        obj.insert("description".into(), d.into());
    }
    obj.insert(
        "inputSchema".into(),
        v.input_schema
            .cloned()
            .unwrap_or_else(|| serde_json::json!({ "type": "object" })),
    );
    if let Some(s) = v.output_schema {
        obj.insert("outputSchema".into(), s.clone());
    }
    if let Some(h) = v.schema_hash {
        obj.insert(
            "_meta".into(),
            serde_json::json!({ "io.busbar/schemaHash": h }),
        );
    }
    Value::Object(obj)
}

/// ONE PROMPT as the wire carries it: a namespaced name and, when there is one, a description.
pub struct PromptView<'a> {
    /// The namespaced name, for the same reason a tool's is namespaced.
    pub name: &'a str,
    /// Already markup-normalised.
    pub description: Option<&'a str>,
}

/// One prompt, projected.
#[must_use]
pub fn prompt(v: &PromptView<'_>) -> Value {
    let mut obj = Map::new();
    obj.insert("name".into(), v.name.into());
    if let Some(d) = v.description {
        obj.insert("description".into(), d.into());
    }
    Value::Object(obj)
}

/// ONE RESOURCE, or one resource TEMPLATE — the same four fields under two different first keys. One
/// view because it is one projection: the only difference the wire has is whether the address is a URI
/// the caller hands back verbatim or a template the caller expands, and two structs would be two
/// places the optional-field rule could be spelled differently.
pub struct ResourceView<'a> {
    /// The RAW uri (or uri template), because that is what a client hands back on `resources/read`.
    /// The namespaced form stays the grant value and the map key — both of which must remain unique
    /// per (server, uri) — but it is not what a client has to say.
    pub address: &'a str,
    /// Already markup-normalised.
    pub name: Option<&'a str>,
    /// Already markup-normalised.
    pub description: Option<&'a str>,
    /// The operator's declared media type, where there is one.
    pub mime_type: Option<&'a str>,
}

/// One concrete resource, projected under `uri`.
#[must_use]
pub fn resource(v: &ResourceView<'_>) -> Value {
    address_view("uri", v)
}

/// One resource template, projected under `uriTemplate` — the operator's own template, which the
/// caller expands.
#[must_use]
pub fn resource_template(v: &ResourceView<'_>) -> Value {
    address_view("uriTemplate", v)
}

fn address_view(address_key: &str, v: &ResourceView<'_>) -> Value {
    let mut obj = Map::new();
    obj.insert(address_key.into(), v.address.into());
    if let Some(n) = v.name {
        obj.insert("name".into(), n.into());
    }
    if let Some(d) = v.description {
        obj.insert("description".into(), d.into());
    }
    if let Some(m) = v.mime_type {
        obj.insert("mimeType".into(), m.into());
    }
    Value::Object(obj)
}

#[cfg(test)]
#[path = "tests/view.rs"]
mod tests;
