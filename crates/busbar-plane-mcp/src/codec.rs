// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP WIRE VOCABULARY — the dialect this plane speaks, written down once.
//!
//! Every name here is a fact about the Model Context Protocol's wire and about nothing else: the
//! mount path, the revision string, the five method names, the two `_meta` keys, the JSON-RPC error
//! code table and the notification pair. Definition 16–20 puts a protocol's wire dialects in the
//! protocol's own plane crate, so this is where they live, and the kernel-side declaration that
//! registers MCP with the engine reads them FROM here rather than restating them.
//!
//! That direction is the whole point of the move. Before it, the codec crate held the literals and
//! the plane held a mirror pinned to them by a test; the mirror is gone and the pin is unnecessary,
//! because there is now one definition. A constant that exists once cannot drift.
//!
//! WHAT IS NOT HERE. The `ProtocolDecl` registry row, the request handler and the two operation
//! cells name the engine's handler matrix, which is kernel-side machinery a pure kind may not
//! reach; they stayed behind with the engine. Nothing in this module opens anything, reads a clock
//! or names a kernel crate.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// THE RESOURCE-UPDATED NOTIFICATION'S PARAMETER OBJECT — `{"uri": "<resource>"}`.
///
/// The SDK's `ResourceUpdatedNotificationParam` stayed behind with `rmcp` for the reason
/// [`subscribe`]'s parameter type states: `rmcp` hard-depends on `tokio`, and a plane's ENTIRE
/// transitive closure is scanned with one whole-workspace feature resolve, so naming the SDK here
/// would put a socket-capable runtime back in `busbar-plane-mcp`'s closure. The wire is unchanged —
/// serde ignores the `_meta` this codec never read, and the SDK's constructor left `_meta: None`
/// where it is skipped on serialize, so both directions emit and accept the same bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResourceUpdatedParam {
    /// The URI of the resource that was updated.
    uri: String,
}

impl ResourceUpdatedParam {
    fn new(uri: impl Into<String>) -> Self {
        Self { uri: uri.into() }
    }
}

/// The single mount path. MCP names the operation in the BODY (`method`), not the path — the
/// opposite of OpenAI, and the reason [`handler::McpRequestHandler::resolve_operation`] reads the
/// body.
///
/// `pub` for the same reason [`PROTOCOL_VERSION`] is: `busbar-plane-mcp` declares its transport
/// claims against this path and may not name the server half, so it reads the value here. A path
/// the plane copied instead of read is a plane claiming a route nothing is served at.
pub const PATH_MCP: &str = "/mcp";

/// THE PREFIX THE PROTECTED-RESOURCE METADATA DOCUMENT IS SERVED UNDER (RFC 9728).
///
/// It sits on the CODEC side because two halves read it and they must agree: the server half
/// composes the route it mounts from it, and `busbar-plane-mcp` declares an OPEN claim on the
/// composed path. The composition itself is [`protected_resource_metadata_path`] so that neither
/// half can spell the join differently.
pub const PROTECTED_RESOURCE_WELL_KNOWN: &str = "/.well-known/oauth-protected-resource";

/// THE DISCOVERY PATH FOR A GIVEN MOUNT — `/.well-known/oauth-protected-resource` + the mount.
///
/// RFC 9728's metadata-path construction inserts the well-known segment between the origin
/// and the resource's own path, so the answer is a FUNCTION OF THE MOUNT and not a constant: the
/// mount is operator-configurable, and a hard-coded discovery path would point at the default
/// while the resource moved. One function, read from both sides, is what keeps the served route
/// and the plane's claim the same string.
#[must_use]
pub fn protected_resource_metadata_path(mount_path: &str) -> String {
    format!("{PROTECTED_RESOURCE_WELL_KNOWN}{mount_path}")
}

/// The single MCP protocol revision busbar implements.
///
/// ONE revision, deliberately. The conformance suite runs each scenario per revision and one run
/// does not cover another, so supporting two revisions is two test legs and two wire formats, not a
/// compatibility shim. `2025-11-25` and earlier are stateful: they have an `initialize` handshake,
/// protocol sessions and a GET stream, all of which this revision deleted, and building them means
/// building session machinery this release can otherwise skip entirely.
///
/// It lives on the CODEC side of the split because it is protocol vocabulary — the plane's envelope
/// layer (`busbar_mcp::mcp::envelope`) re-exports it under its historical path, and the conformance
/// suite of `busbar-plane-mcp`, which may not name the server half, reads it here.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// The JSON-RPC method names this dialect serves.
///
/// These used to be read off `rmcp`'s own const-string types, so a name the SDK retired stopped
/// compiling here. `rmcp` hard-depends on `tokio` and could not cross into a pure kind's closure,
/// so THE SDK IS STILL THE ACCEPTANCE TEST — it just holds the pin one crate over. `busbar-mcp`,
/// which keeps the `rmcp` edge, asserts every one of these five against the SDK's const string in
/// its own test binary, so a retired name is a red test rather than a served one. `pub` rather than
/// `pub(crate)` because that assertion is now a cross-crate read.
/// Invoke a tool by name, with arguments.
pub const METHOD_TOOLS_CALL: &str = "tools/call";
/// Register interest in a resource's changes.
pub const METHOD_RESOURCES_SUBSCRIBE: &str = "resources/subscribe";
/// Withdraw that interest.
pub const METHOD_RESOURCES_UNSUBSCRIBE: &str = "resources/unsubscribe";
/// The server's notice that its tool list is no longer what it was.
pub const METHOD_NOTIFY_TOOLS_LIST_CHANGED: &str = "notifications/tools/list_changed";
/// The server's notice that a subscribed resource changed.
pub const METHOD_NOTIFY_RESOURCES_UPDATED: &str = "notifications/resources/updated";

/// THE `_meta` KEY CARRYING A REQUEST'S PROTOCOL VERSION.
///
/// Under this revision negotiation is ON DEMAND — there is no handshake — so every request states
/// its own version, and this key is where it states it. It lives at `params._meta`, NOT at the top
/// level of the JSON-RPC envelope.
///
/// It sits on the CODEC side because THREE readers must agree on the spelling and they are in
/// different crates: the server half requires it inbound, the client half emits it outbound, and
/// `busbar-plane-mcp` names it as a correlation fact key. The two directions were once written
/// down twice and each copy was internally consistent with its own side, so busbar would have
/// refused a request busbar itself sent; one definition is what makes that unrepresentable.
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// THE `_meta` KEY CARRYING THE CLIENT'S CAPABILITIES FOR ONE REQUEST — REQUIRED, and absent is a
/// refusal rather than the empty capability set.
///
/// With no `initialize` there is no earlier message the capabilities could have been stated in, so
/// a request that omits this has never stated them at all, and a server that fills the gap in has
/// decided on the client's behalf what the client can do. Defined here for the same three-reader
/// reason [`META_PROTOCOL_VERSION`] is.
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

// ══ THE ERROR CODES, DEFINED EXACTLY ONCE ═══════════════════════════════════════════════════════
//
// Both halves write these: the server half emits them, and `busbar-plane-mcp` publishes the set it
// may write as part of its own surface. The plane may not name the server half at all, so a code
// it could only COPY is a code the two sides can come to disagree about — and a JSON-RPC code is
// exactly the kind of value that reads plausibly while being wrong. The server half and the plane
// both define their constants AS these, so the compiler holds the equality.

/// The bytes could not be read at all. JSON-RPC standard.
pub const CODE_PARSE_ERROR: i64 = -32700;
/// The envelope was not a request. JSON-RPC standard.
pub const CODE_INVALID_REQUEST: i64 = -32600;
/// The method named is not one this node answers. JSON-RPC standard; MCP pairs it with `404`.
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;
/// The parameters were not admissible — including a missing or incomplete `params._meta`, which is
/// a member of `params` and so is the standard "invalid params" rather than a header defect.
pub const CODE_INVALID_PARAMS: i64 = -32602;
/// Something on this side failed. JSON-RPC standard.
pub const CODE_INTERNAL: i64 = -32603;
/// MCP `HeaderMismatchError`: an HTTP header disagreed with the body it mirrors. Always `400`.
pub const CODE_HEADER_MISMATCH: i64 = -32020;
/// MCP `MissingRequiredClientCapability`: the caller did not declare a capability the answer would
/// have needed.
pub const CODE_MISSING_CLIENT_CAPABILITY: i64 = -32021;
/// MCP `UnsupportedProtocolVersionError`: carries `data.requested` and `data.supported`. Always
/// `400`.
pub const CODE_UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
/// A policy said no. The first code in JSON-RPC's implementation-defined server-error range,
/// because every reserved code is wrong for a specific reason.
pub const CODE_REFUSED: i64 = -32000;
/// The server this call would have reached could not be reached — the call NEVER HAPPENED, which
/// is why it is an extension rather than `-32603` (busbar broke) or `-32602` (the caller erred).
pub const CODE_UPSTREAM_UNAVAILABLE: i64 = -32030;

/// EVERY CODE THIS DIALECT DEFINES. The plane asserts the set it may write is a subset of this, so
/// a code invented on one side of the seam is a red test rather than a wire nobody recognises.
pub const CODES: &[i64] = &[
    CODE_PARSE_ERROR,
    CODE_INVALID_REQUEST,
    CODE_METHOD_NOT_FOUND,
    CODE_INVALID_PARAMS,
    CODE_INTERNAL,
    CODE_HEADER_MISMATCH,
    CODE_MISSING_CLIENT_CAPABILITY,
    CODE_UNSUPPORTED_PROTOCOL_VERSION,
    CODE_REFUSED,
    CODE_UPSTREAM_UNAVAILABLE,
];

/// The codes THIS revision retired, which a conformant node must never write. A retired code is
/// worse than an unknown one: a peer that still recognises it will act on a meaning this node did
/// not intend.
pub const RETIRED_CODES: &[i64] = &[-32002, -32042];

/// THE METHODS THIS DIALECT DISPATCHES. A method absent from here takes the `-32601` / `404` arm.
///
/// On the codec side because it is the one list two crates read: the server half dispatches over it
/// and advertises it on `server/discover`, and `busbar-plane-mcp` carries a row for each. Two lists
/// that can disagree is a client told it may call something it may not — or a method the server
/// answers that the plane reports as an unsupported operation.
///
/// `subscriptions/listen` is spelled here as a literal rather than read off the SDK's const-string
/// type: `rmcp` hard-depends on `tokio` and a plane's entire transitive closure is scanned, so the
/// SDK cannot cross into this crate. THE SDK IS STILL THE ACCEPTANCE TEST — `busbar-mcp`, which
/// keeps the `rmcp` edge, asserts this entry against `SubscriptionsListenRequestMethod::VALUE`,
/// exactly as it does for the five `METHOD_*` constants above.
pub const IMPLEMENTED_METHODS: &[&str] = &[
    "server/discover",
    "tools/list",
    METHOD_TOOLS_CALL,
    "prompts/list",
    "prompts/get",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "completion/complete",
    // SEP-2663. The three v2 tasks methods, and ONLY the three: `tasks/result` and `tasks/list`
    // were REMOVED by the extension's v2 wire — the result is inlined on `tasks/get` and there is
    // no list — so their absence here is what makes them answer `-32601`, which is the conformant
    // answer and not a gap.
    "tasks/get",
    "tasks/update",
    "tasks/cancel",
    // SEP-2575's replacement for the GET stream. It is a METHOD in this revision, so it belongs in
    // this list rather than in the route table.
    METHOD_SUBSCRIPTIONS_LISTEN,
];

/// The wire name of SEP-2575's listen method. See [`IMPLEMENTED_METHODS`] for why it is a literal
/// here and an SDK-pinned assertion one crate over.
pub const METHOD_SUBSCRIPTIONS_LISTEN: &str = "subscriptions/listen";

/// WHICH `params` MEMBER CARRIES A REQUEST'S SUBJECT, for the methods that address one.
///
/// SEP-2243 and SEP-2663 require the subject to be mirrored into the `Mcp-Name` header, so this
/// rule is read from BOTH directions — the server half validates the mirror, the client half
/// composes it — and `busbar-plane-mcp` derives its own name pointers from it. It carried a second
/// copy on the client side once and the two DISAGREED, which sent a `tasks/get` out with no
/// `Mcp-Name` against a server that answers `-32020` to exactly that.
///
/// The methods are ENUMERATED rather than matched on a prefix, and the tasks namespace is why:
/// `tasks/get` carries the header and `tasks/result` — a method this revision REMOVED — does not,
/// so a `tasks/*` prefix rule would answer `-32020` (your headers are wrong) to a request whose
/// only defect is naming a method that no longer exists, which must be `-32601`.
#[must_use]
pub fn name_source_of(method: &str) -> Option<&'static str> {
    match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        "tasks/get" | "tasks/update" | "tasks/cancel" => Some("taskId"),
        _ => None,
    }
}

// ══ THE NOTIFICATION HALF ════════════════════════════════════════════════════════════════════════

/// THE SERVER-ORIGINATED NOTIFICATIONS THIS PROTOCOL CARRIES, and the reason a subscription is worth
/// registering at all.
///
/// ## WHY THIS IS NOT AN `OperationHandler`
///
/// A notification has no id, no answer and no correlation: JSON-RPC 2.0 section 4.1 forbids replying
/// to one. It is therefore not a request/response codec and modelling it as one would give it a
/// response half that must never be produced. It sits beside the codecs, in the protocol's own
/// crate, because the thing it is specific to is the DIALECT — the same reason the JSON-RPC envelope
/// itself is read once, in one place, for every plane that speaks it.
///
/// ## BOTH DIRECTIONS READ THE SAME BYTES
///
/// When busbar is the server it EMITS these to its caller; when busbar is the client it RECEIVES
/// them from an upstream. That is one wire message and two directions of travel, so it is one
/// reader and one writer here rather than a pair per direction — which is exactly the arrangement
/// that stopped the JSON-RPC envelope from being parsed two ways that disagreed.
///
/// ## WHAT A RECEIVED `notifications/tools/list_changed` MAY AND MAY NOT DO
///
/// It is a HINT, and it arrives from a party whose timing and content are not busbar's to trust. It
/// may prompt a re-read of a catalogue through the ordinary approval path; it may never itself
/// install, approve or promote anything, because that would let the party being catalogued decide
/// when its own catalogue is believed. This type carries the message and takes no such action, which
/// is what keeps that decision at the call site that has the approval context.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpNotification {
    /// The peer's tool list is no longer what it was.
    ToolsListChanged,
    /// A subscribed resource changed. The delivery half of [`subscribe::SubscribeOperation`].
    ResourceUpdated {
        /// The resource that changed, in the peer's vocabulary.
        uri: String,
    },
}

#[cfg_attr(not(test), allow(dead_code))]
impl McpNotification {
    /// The wire method name, off `rmcp`'s const-string types.
    pub fn method(&self) -> &'static str {
        match self {
            McpNotification::ToolsListChanged => METHOD_NOTIFY_TOOLS_LIST_CHANGED,
            McpNotification::ResourceUpdated { .. } => METHOD_NOTIFY_RESOURCES_UPDATED,
        }
    }

    /// Read a notification that has ALREADY been established as a JSON-RPC notification envelope by
    /// the engine's JSON-RPC ingress step. That step is named by SHAPE and not by crate, because a
    /// doc comment is a name the `kind-isolation:matrix` scanner counts exactly like a `use`, and
    /// #40(a) admits one dependency here and no other. `None` means "a notification this protocol
    /// does not carry", which is the correct answer to give and the correct thing to do nothing
    /// about: section 4.1 forbids replying, so an unknown notification is dropped rather than
    /// refused.
    pub fn read(method: &str, params: Option<&serde_json::Value>) -> Option<Self> {
        match method {
            METHOD_NOTIFY_TOOLS_LIST_CHANGED => Some(McpNotification::ToolsListChanged),
            METHOD_NOTIFY_RESOURCES_UPDATED => {
                // The SDK's parameter type is the acceptance test here too: a notification that
                // names no resource says a resource changed without saying which, and acting on it
                // would mean guessing.
                let p: ResourceUpdatedParam = serde_json::from_value(params?.clone()).ok()?;
                (!p.uri.is_empty()).then_some(McpNotification::ResourceUpdated { uri: p.uri })
            }
            _ => None,
        }
    }

    /// The complete JSON-RPC notification envelope for this message.
    ///
    /// **There is no `id` member and there must never be one.** Section 4.1 makes the absence of
    /// `id` the definition of a notification; an id would make this a request, and a request obliges
    /// the receiver to answer something busbar is not waiting for.
    pub fn write(&self) -> Bytes {
        let mut envelope = serde_json::json!({ "jsonrpc": "2.0", "method": self.method() });
        if let McpNotification::ResourceUpdated { uri } = self {
            // `params` is emitted only where the message has any, so the notification that carries
            // none stays byte-identical to what the specification describes.
            envelope["params"] = serde_json::to_value(ResourceUpdatedParam::new(uri.clone()))
                .unwrap_or_else(|_| serde_json::json!({ "uri": uri }));
        }
        Bytes::from(serde_json::to_vec(&envelope).unwrap_or_default())
    }
}

#[cfg(test)]
#[path = "tests/codec_tests.rs"]
mod codec_tests;
