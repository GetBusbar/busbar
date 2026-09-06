// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A WIRE VOCABULARY — the pure half of the Agent-to-Agent protocol plugin.
//!
//! `busbar-a2a` held two things behind one name: this vocabulary — the JSON canonicalization a card
//! signature is taken over, the anomaly grammar a refusal is spelled in, the meter-class
//! projection, the durable task and task-event record shapes, and the mount paths and registry key
//! the plane is known by — and the
//! A2A plane that carries them over the network (the axum REST and JSON-RPC routes, the tonic gRPC
//! binding, the reqwest relay leg, the push-notification delivery, the mTLS transport). The plane
//! crate `busbar-plane-a2a` adapts the vocabulary and must not link the server: a plane is a PURE
//! kind whose whole transitive closure is scanned, and the server stack put `hyper`, `reqwest`,
//! `axum`, `tonic` and a socket-capable `tokio` in it.
//!
//! So the vocabulary lives here, naming nothing but `busbar-api`'s durable-record contracts and
//! serde. `busbar-a2a` depends on this crate and re-exports every module that moved under its old
//! path, so `busbar_a2a::record::…`, `busbar_a2a::TaskRow` and `crate::a2a::canonical::…` resolve
//! exactly what they always did. The split is a MOVE: no item changed shape crossing it.

/// The modules that moved keep their `a2a::` parent, so their in-crate paths are the ones the plane
/// half still spells (`super::canonical::…`, `crate::a2a::meter::…`) and the move is invisible to
/// every caller.
///
/// WHAT DID NOT MOVE, and why it reads like it should have: `a2a::idmap`, the request-id remapping
/// table, is a lookup THROUGH the task registry (`taskstore::TASKS::get_scoped`) — it refuses to
/// answer for a task the caller does not own — and that registry is a `tokio::sync`-guarded process
/// singleton. The scoping is the point of the module, so the module stays with the store it scopes
/// against rather than being weakened into a pure map to fit here.
pub mod a2a {
    pub mod anomaly;
    pub mod canonical;
    pub mod meter;
}

pub mod record;

/// THE A2A PLANE'S DURABLE RECORD TYPES, re-exported at the crate root exactly as `busbar-a2a`
/// exposes them — so the parent crate's own root re-export is a forward of this one and there is
/// one definition rather than two spellings of it.
pub use record::{TaskEventRow, TaskRow};

/// THE REGISTRY KEY A2A IS KNOWN BY, in the plane registry and in the plugin contract alike.
///
/// Named ONCE, here, on the pure side of the split, because two declarations read it and both must
/// agree: `busbar-a2a`'s `PLANE_DECL.key` and the `busbar-plane-a2a` contract plane's `KEY`. The
/// plane crate is a pure kind and cannot name `busbar-a2a` at all, so a key spelled on the server
/// side would be a key the plane could only copy — which is how two answers to "what is this plane
/// called" start to differ.
pub const PLANE_KEY: &str = "a2a";

/// THE CONFIGURATION SECTION THIS PLANE OWNS, named here for the same reason [`PLANE_KEY`] is: the
/// plane declaration states it and the contract plane's configuration schema is asserted against it,
/// and those two are on opposite sides of the purity seam.
pub const CONFIG_SECTION: &str = "agents";

/// THE PLANE'S MOUNT, the path prefix the A2A plane's HTTP bindings are served under. Every route
/// this plane serves over HTTP is under it, and the host's plane dispatch matches on it at a segment
/// boundary, so `/a2ax` is somebody else's path.
///
/// It sits on the CODEC side of the split because it is a claim about the wire, and the claim is
/// read from BOTH sides: `busbar_a2a::a2a::serve` composes agent endpoints and the protected-resource
/// metadata path from it, and `busbar-plane-a2a` declares its path claims against it. Two spellings
/// of a mount is a plane claiming a path nothing is served at.
pub const MOUNT_PATH: &str = "/a2a";

/// THE PATH PREFIX THE gRPC BINDING IS SERVED AT, and busbar did not choose it.
///
/// gRPC derives a request path from the `.proto`'s package and service name — `lf.a2a.v1` and
/// `A2AService` in the a2aproject's own canonical `a2a.proto`, vendored by `a2a-pb` — and a client
/// is given an AUTHORITY, never a path prefix, so there is no spelling of this that could live under
/// [`MOUNT_PATH`]. Written as a constant beside the mount it is not under, because "the A2A plane
/// answers here too" is a fact the mount table has to be told or this binding's tokens go unchecked
/// for audience.
pub const GRPC_MOUNT_PATH: &str = "/lf.a2a.v1.A2AService";

// ══ THE ROUTES THIS PLANE SERVES, SPELLED EXACTLY ONCE ══════════════════════════════════════════
//
// Every path below is read from BOTH sides of the purity seam: `busbar-a2a` MOUNTS it, and
// `busbar-plane-a2a` CLAIMS it. The plane may not name `busbar-a2a` at all, so a path it could only
// copy is a path the two halves can come to disagree about — a route the server serves and the
// plane does not claim arrives and finds no plane, and a claim with no route behind it takes bytes
// nothing can answer. The suffixes are relative to [`MOUNT_PATH`] and carry their capture names
// verbatim (`{id}`, `{config_id}`), because the router's `path_params` hand the handlers those
// names and a template that renamed a capture is a different route.

/// `POST` — the message-send operation.
pub const ROUTE_MESSAGE_SEND: &str = "/message:send";
/// `POST` — the same body, the streaming method, an SSE answer.
pub const ROUTE_MESSAGE_STREAM: &str = "/message:stream";
/// `GET` — the task list; its filters ride the query string.
pub const ROUTE_TASKS: &str = "/tasks";
/// `GET` one task, and `POST` the colon-suffixed verbs against it. ONE template, two methods: the
/// router merges methods for one path, and two templates differing only in the capture NAME are one
/// pattern registered twice, which is a startup panic rather than a route.
pub const ROUTE_TASK: &str = "/tasks/{id}";
/// `POST` a push-notification config, `GET` the list.
pub const ROUTE_PUSH_CONFIGS: &str = "/tasks/{id}/pushNotificationConfigs";
/// `GET` and `DELETE` one push-notification config.
pub const ROUTE_PUSH_CONFIG: &str = "/tasks/{id}/pushNotificationConfigs/{config_id}";
/// `GET` — the extended agent card.
pub const ROUTE_EXTENDED_AGENT_CARD: &str = "/extendedAgentCard";
/// One FRONTED agent's endpoint, derived from the agent id so a caller's endpoint is stable and
/// says which agent it reaches.
pub const ROUTE_AGENT: &str = "/agents/{agent_id}";

/// EVERY SUFFIX ABOVE, as one list. The plane asserts its claim for each is [`MOUNT_PATH`] joined to
/// it, so a route added on the server side with no claim behind it is a red test.
pub const MOUNTED_ROUTE_SUFFIXES: &[&str] = &[
    ROUTE_MESSAGE_SEND,
    ROUTE_MESSAGE_STREAM,
    ROUTE_TASKS,
    ROUTE_TASK,
    ROUTE_PUSH_CONFIGS,
    ROUTE_PUSH_CONFIG,
    ROUTE_EXTENDED_AGENT_CARD,
    ROUTE_AGENT,
];

/// THE PROTOCOL'S CANONICAL CARD DISCOVERY PATH, from protocol v0.3 onward. Absolute, not under
/// [`MOUNT_PATH`]: a well-known path is a property of the ORIGIN.
pub const WELL_KNOWN_CARD_PATH: &str = "/.well-known/agent-card.json";

/// THE RFC 9728 PROTECTED-RESOURCE METADATA PATH for this plane — the well-known prefix with the
/// plane's mount appended, exactly as the sibling plane composes its own.
pub const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/a2a";

/// THE SUFFIX A PUSH-NOTIFICATION DELIVERY IS POSTED TO on the caller's own callback base. Not a
/// route busbar serves — it is a route busbar CALLS — but it is spelled here beside the others
/// because the plane claims the mounted `/a2a/push` endpoint that pairs with it.
pub const PUSH_PATH_SUFFIX: &str = "/push";

/// [`MOUNT_PATH`] joined to one of the [`MOUNTED_ROUTE_SUFFIXES`]. One join, called from both sides,
/// so the served route and the plane's claim cannot be two different strings.
#[must_use]
pub fn mounted_route(suffix: &str) -> String {
    format!("{MOUNT_PATH}{suffix}")
}

/// THE A2A-SPECIFIC ERROR CODES, each with the `ErrorInfo.reason` it is reported under.
///
/// The A2A-specific band is `-32001..=-32099`; the standard JSON-RPC codes are NOT here, because
/// the specification's own table leaves their reason UNSET and inventing one would put a word on
/// the wire the specification does not define.
///
/// One table, read from both sides of the purity seam: `busbar-a2a`'s `A2aError` is pinned against
/// it (that enum keeps the `code()`/`reason()` matches, and a test asserts the two agree row for
/// row), and `busbar-plane-a2a` publishes it as the set it may write. It was COPIED across the seam
/// before, with the copy checked by searching the other crate's source text — a check that could
/// only be run from a crate that could read a sibling it does not depend on.
pub const ERRORS: &[(i64, &str)] = &[
    (-32001, "TASK_NOT_FOUND"),
    (-32002, "TASK_NOT_CANCELABLE"),
    (-32003, "PUSH_NOTIFICATION_NOT_SUPPORTED"),
    (-32004, "UNSUPPORTED_OPERATION"),
    (-32005, "CONTENT_TYPE_NOT_SUPPORTED"),
    (-32006, "INVALID_AGENT_RESPONSE"),
    (-32007, "EXTENDED_AGENT_CARD_NOT_CONFIGURED"),
    (-32008, "EXTENSION_SUPPORT_REQUIRED"),
    (-32009, "VERSION_NOT_SUPPORTED"),
];

/// EVERY METHOD NAME THE LOCAL-VERB TABLE ANSWERS, in both dialects.
///
/// A2A v1.0 spells these in `PascalCase` and v0.3 spelled the same operations as slash-separated
/// paths; both are still answered, so both are named here. One list, read from both sides: `busbar-a2a`
/// pins its `verb_of` match against it (a name on this list that the match does not answer is red
/// there), and `busbar-plane-a2a`'s conformance rig asserts it CARRIES each one — a method the server
/// half answers and the plane does not carry arrives as an unsupported operation. The rig scraped this
/// out of the server half's source text before, which needed a crate that cannot depend on it to read
/// its file.
pub const LOCAL_VERB_METHODS: &[&str] = &[
    "ListTasks",
    "tasks/list",
    "CreateTaskPushNotificationConfig",
    "tasks/pushNotificationConfig/set",
    "GetTaskPushNotificationConfig",
    "tasks/pushNotificationConfig/get",
    "ListTaskPushNotificationConfigs",
    "tasks/pushNotificationConfig/list",
    "DeleteTaskPushNotificationConfig",
    "tasks/pushNotificationConfig/delete",
    "SubscribeToTask",
    "tasks/resubscribe",
];

/// The `@type` of the detail entry an A2A error carries in `error.data` — `google.rpc.ErrorInfo`,
/// spelled as the protobuf type URL the specification names.
pub const ERROR_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ErrorInfo";

/// The `ErrorInfo.domain` every A2A error is reported under. The protocol's own, not busbar's: the
/// reason tokens above are the specification's vocabulary and the domain says so.
pub const ERROR_INFO_DOMAIN: &str = "a2a-protocol.org";
