//! The A2A plane: what bytes mean, for one protocol spelled two ways.
//!
//! ## What this crate is
//!
//! An ADAPTER. Every method of the plane kind here is a few lines over a codec that already exists:
//! the envelope shape, the method vocabulary, the error code table and the record kinds. No wire
//! format is written twice, because a wire format written twice is two wire formats that will
//! disagree, and the one that disagrees quietly is the one that reaches a customer.
//!
//! ## What this crate is not
//!
//! It holds no governance, no breaker, no hook seat, no signing key and no arithmetic over a metered
//! quantity. Those are units, and a unit is on the far side of the kernel from a plane. The metering
//! method here returns LOCATORS — the class, where the number is, and the number the codec already
//! read — and never a price, never a hold and never a decision. The routing method returns a plan
//! and never a connection. Nothing in this crate opens a socket, reads a file or reads a clock other
//! than the one the context hands it.
//!
//! ## What it holds across calls
//!
//! Nothing. The plane is a value with no interior mutability, asserted by a test rather than by a
//! comment. What state a streamed answer needs lives in the kernel-held per-connection codec state,
//! which the kernel hands in and takes back.
//!
//! ## Where this adapter had to write something down twice, and why
//!
//! The codec crate holds the envelope reader, the error table and the method vocabulary, and it
//! holds all three where only its own crate can see them. This crate may not widen that visibility.
//! So three things are written once more here — the method table, the error code table, and the
//! envelope's member shape — and each of them is PINNED by a test that reads the codec's own source
//! or the conformance rig's own tables. A copy that is checked is not a second opinion. A copy that
//! is not checked is, and there are none of those here.
//!
//! The full list of places the contract did not fit this protocol is in the notes each module
//! carries: the correlation type that cannot hold a named identifier, the arena that cannot hold a
//! span table, the introspection verb that takes no argument, and the single byte class that cannot
//! separate what was sent from what came back.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// The wire dialect's own modules, keeping the `a2a::` parent they carried in the codec crate so
/// their in-crate paths are the ones every caller already spells.
pub mod a2a {
    pub mod anomaly;
    pub mod canonical;
}

pub mod claims;
pub mod facts;
pub mod frame;
pub mod jsonrpc;
pub mod meta;
pub mod ops;
pub mod plane;
pub mod records;
pub mod surface;

pub use frame::{rewrite, Direction, Frame, Tap, Transform};

// ══ THE A2A WIRE VOCABULARY ══════════════════════════════════════════════════════════════════════
//
// Definition 16-20: everything ONE protocol needs and no other protocol may name — its wire
// dialects, its decode/encode face. Every name below is a fact about the A2A wire and about nothing
// else: the registry key, the config section it owns, the mount, the gRPC service path the protocol
// (not busbar) chose, the eight routes, the well-known card path, the protected-resource metadata
// path, the push suffix, the A2A error band with its `ErrorInfo.reason` tokens, and the local verb
// method names in both dialect spellings.
//
// They lived in a third crate because the PLANE could not name the engine and the engine could
// not link a pure kind. The codec crate is gone (#39) and these came here rather than to the engine
// for one reason: the plane is the thing being named. A key or a route spelled engine-side is a
// string the plane could only copy, and two answers to "what path does this plane serve" is a route
// the server serves and the plane does not claim. The engine reads these; it does not restate them.

/// THE REGISTRY KEY A2A IS KNOWN BY, in the plane registry and in the plugin contract alike.
///
/// Named ONCE, here, on the pure side of the split, because two declarations read it and both must
/// agree: the engine's `PLANE_DECLARATION.key` and this crate's own plane `KEY`. A plane is a pure kind
/// and cannot name the engine at all, so a key spelled on the server
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
/// read from BOTH sides: the engine's serve module composes agent endpoints and the protected-resource
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
// Every path below is read from BOTH sides of the purity seam: the ENGINE mounts it, and this
// crate CLAIMS it. A plane may not name the engine at all, so a path it could only
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
/// One table, read from both sides of the purity seam: the engine's `A2aError` is pinned against
/// it (that enum keeps the `code()`/`reason()` matches, and a test asserts the two agree row for
/// row), and this crate publishes it as the set it may write. It was COPIED across the seam
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
/// paths; both are still answered, so both are named here. One list, read from both sides: the engine
/// pins its `verb_of` match against it (a name on this list that the match does not answer is red
/// there), and this crate's conformance rig asserts it CARRIES each one — a method the server
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

use busbar_contract::ids::LaneId;
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

/// One configured agent this plane may name.
///
/// Every string is borrowed for the life of the program, because a plane's declarations are read at
/// registration and sealed. Configured names reach here through the seam that says so:
/// [`busbar_contract::ids::Registration`]. The composition root builds one at boot, interns every
/// config-derived key through it exactly once, and hands over names that outlive it — so nothing
/// after registration can vary them, and the memory the names occupy is a fixed term rather than
/// one that grows with traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Agent {
    /// The name the operator gave this agent, and the resource the scope unit judges.
    pub id: &'static str,
    /// The priced lane this agent is reached on.
    pub lane: LaneId,
    /// The host to dial.
    pub host: &'static str,
    /// Which of the two transports the hop is made over.
    pub transport: &'static str,
}

/// The A2A plane.
///
/// The one field is a borrowed, immutable list. There is no cell here, no lock and no atomic: the
/// purity test asserts that by walking the type, not by trusting this sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A2aPlane {
    agents: &'static [Agent],
}

impl A2aPlane {
    /// A plane with a configured agent set.
    #[must_use]
    pub const fn new(agents: &'static [Agent]) -> Self {
        Self { agents }
    }

    /// A plane with nothing configured.
    ///
    /// It answers every question the loop asks, and its answer to "where does this go" is a
    /// destination the trust unit refuses. That is the honest answer for a plane with no agent — not
    /// a panic, and not a fabricated host.
    pub const EMPTY: Self = Self::new(&[]);

    /// The configured agents, in declaration order.
    #[must_use]
    pub const fn agents(&self) -> &'static [Agent] {
        self.agents
    }
}

impl Default for A2aPlane {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Plugin for A2aPlane {
    fn key(&self) -> &'static str {
        <Self as busbar_contract::plane::PlaneMeta>::KEY
    }

    fn kind(&self) -> Kind {
        Kind::Plane
    }

    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}
