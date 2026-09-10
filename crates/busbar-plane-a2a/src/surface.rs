//! The served surface, as data: every operation, and every way a caller can address it.
//!
//! ## Why this is a declaration and not a server
//!
//! This plane already says what bytes MEAN. What it could not say, until this module, is how a
//! caller REACHES an operation — which target names it, which request method goes with that target,
//! which member of a posted document names it instead, which service descriptor and method spell it
//! on the framed binding, and whether the answer is one document or a run of them. Every one of
//! those was written inside the protocol's own server, which is what made a wire protocol a crate.
//!
//! They are declared here, in the plane-agnostic vocabulary
//! [`busbar_contract::surface`] defines, and a transport mounts them without knowing what
//! protocol they belong to. Nothing here opens anything, holds anything or reads anything: it is a
//! `const`.
//!
//! ## Three bindings of one agent
//!
//! The specification models this protocol as one agent reachable three ways, and all three are
//! declared:
//!
//! * the **document** binding — a JSON-RPC envelope posted to the plane's own mount, where the
//!   `method` member names the operation. Every operation is reachable this way, in BOTH spellings
//!   the protocol has ever used: the slash-separated wording of the earlier revision and the
//!   title-case verb of the later one. They are two addresses for one operation and are declared as
//!   two dispatches, because that is what they are on the wire.
//! * the **target** binding — HTTP+JSON, where the path and the request method name the operation
//!   between them. Four of its rows are one path serving two operations, told apart by the verb
//!   alone, which is exactly why the vocabulary carries the method on the row.
//! * the **framed** binding — the service descriptor's own. Its RPC names are the title-case
//!   spelling one-for-one, which is a fact worth stating rather than a coincidence to rely on: the
//!   test below asserts it, so a descriptor that gained a differently-named RPC is red here rather
//!   than answering `UNIMPLEMENTED` in production.
//!
//! ## The three open surfaces say so
//!
//! [`Bar::Open`] on the two discovery documents and on the callback, and [`Bar::Credential`]
//! everywhere else. The discovery documents are open because they are what tells a caller which
//! credential to present, and demanding one to read them is circular. The callback is open because
//! the party calling it holds no credential of this node's and must not be issued one; it
//! authenticates itself against the per-task capability this node minted. Open by DECLARATION, so
//! it cannot be confused with open by omission.
//!
//! ## Where the strings come from
//!
//! The two mount points are the codec crate's own constants. The route shapes below them are
//! spelled out here for the reason [`crate::claims`] spells its own out: the codec builds them by
//! formatting rather than by naming a constant per route, and a formatted string is not something a
//! `const` can borrow. Every one of them is PINNED against the codec's own table by the tests, and a
//! copy that is checked is not a second opinion.

use busbar_contract::surface::{Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface};

use crate::ops;

/// The document binding's name, as a published card spells it lower-cased.
pub const BINDING_DOCUMENT: &str = "jsonrpc";

/// The target binding's name.
pub const BINDING_TARGET: &str = "http+json";

/// The framed binding's name.
pub const BINDING_FRAMED: &str = "grpc";

/// The fully-qualified service the framed binding serves.
///
/// The `.proto`'s own, which is why it is the codec's mount-path constant with its leading separator
/// removed rather than a literal: a gRPC client derives its target from the descriptor and cannot be
/// pointed off it, so the service name and the path the node claims must be the same string.
pub const SERVICE: &str = "lf.a2a.v1.A2AService";

/// The member of a posted document that names the operation.
pub const METHOD_MEMBER: &str = "method";

/// The media type every request body of this protocol carries.
pub const MEDIA_JSON: &str = "application/json";

/// The media type a streamed answer carries.
pub const MEDIA_EVENT_STREAM: &str = "text/event-stream";

/// The request method a document is posted with, and the one every write-shaped target row uses.
const POST: &str = "POST";

/// The request method every read-shaped target row uses.
const GET: &str = "GET";

/// The request method the one removal-shaped target row uses.
const DELETE: &str = "DELETE";

/// The plane's own mount, where a posted document is read.
const MOUNT: &str = "/a2a";

/// The same mount with the trailing separator a great many clients send.
///
/// Not cosmetic and not a guess: an HTTP client handed `/a2a` as a BASE URL resolves a request for
/// `/` against it and sends `/a2a/`, which is what the official suite's own JSON-RPC client does.
/// A mount declared only one way leaves the most likely spelling of this endpoint answering 404.
const MOUNT_SLASH: &str = "/a2a/";

/// The single-message target.
const T_MESSAGE_SEND: &str = "/a2a/message:send";

/// The streamed-message target.
const T_MESSAGE_STREAM: &str = "/a2a/message:stream";

/// The task collection.
const T_TASKS: &str = "/a2a/tasks";

/// One task, by identifier.
const T_TASK: &str = "/a2a/tasks/{id}";

/// A task's push-notification configurations, as a collection.
const T_PUSH_CONFIGS: &str = "/a2a/tasks/{id}/pushNotificationConfigs";

/// One of a task's push-notification configurations.
const T_PUSH_CONFIG: &str = "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}";

/// The extended-card target.
const T_EXTENDED_CARD: &str = "/a2a/extendedAgentCard";

/// The discovery document naming the resource this protocol is protected as.
const T_METADATA: &str = "/.well-known/oauth-protected-resource/a2a";

/// The discovery document carrying the agent's own card.
const T_CARD: &str = "/.well-known/agent-card.json";

/// The callback an agent this node dialled posts back to.
const T_PUSH: &str = "/a2a/push";

/// Both spellings of one operation on the document binding, as a pair of dispatches.
const fn document(slashed: &'static str, verb: &'static str) -> [Dispatch; 2] {
    [
        Dispatch::Document {
            binding: BINDING_DOCUMENT,
            method: POST,
            member: METHOD_MEMBER,
            name: slashed,
            bar: Bar::Credential,
        },
        Dispatch::Document {
            binding: BINDING_DOCUMENT,
            method: POST,
            member: METHOD_MEMBER,
            name: verb,
            bar: Bar::Credential,
        },
    ]
}

/// One framed call.
const fn framed(method: &'static str) -> Dispatch {
    Dispatch::Service {
        service: SERVICE,
        method,
        bar: Bar::Credential,
    }
}

/// One credentialed target row.
const fn target(path: &'static str, method: &'static str) -> Dispatch {
    Dispatch::Target {
        path,
        method,
        bar: Bar::Credential,
    }
}

/// One deliberately open target row.
const fn open(path: &'static str, method: &'static str) -> Dispatch {
    Dispatch::Target {
        path,
        method,
        bar: Bar::Open,
    }
}

/// Send one message and wait for the whole answer.
const D_MESSAGE_SEND: &[Dispatch] = &[
    target(T_MESSAGE_SEND, POST),
    document("message/send", "SendMessage")[0],
    document("message/send", "SendMessage")[1],
    framed("SendMessage"),
];

/// Send one message and receive the answer as a run of events.
const D_MESSAGE_STREAM: &[Dispatch] = &[
    target(T_MESSAGE_STREAM, POST),
    document("message/stream", "SendStreamingMessage")[0],
    document("message/stream", "SendStreamingMessage")[1],
    framed("SendStreamingMessage"),
];

/// Read one task back.
const D_TASK_GET: &[Dispatch] = &[
    target(T_TASK, GET),
    document("tasks/get", "GetTask")[0],
    document("tasks/get", "GetTask")[1],
    framed("GetTask"),
];

/// List the tasks this caller may see.
const D_TASK_LIST: &[Dispatch] = &[
    target(T_TASKS, GET),
    document("tasks/list", "ListTasks")[0],
    document("tasks/list", "ListTasks")[1],
    framed("ListTasks"),
];

/// Ask for one task to stop.
///
/// The target row is a POST to the task itself: the collection binding spells a verb on a resource
/// as a post to that resource, which is why this path and [`D_TASK_GET`]'s are one template told
/// apart by the method alone.
const D_TASK_CANCEL: &[Dispatch] = &[
    target(T_TASK, POST),
    document("tasks/cancel", "CancelTask")[0],
    document("tasks/cancel", "CancelTask")[1],
    framed("CancelTask"),
];

/// Re-attach to a task's event stream.
///
/// No target row. The collection binding has no spelling for re-attaching to a stream, so this
/// operation is reachable on the document and framed bindings only — declared as an absence rather
/// than as a route that would answer nothing.
const D_TASK_SUBSCRIBE: &[Dispatch] = &[
    document("tasks/resubscribe", "SubscribeToTask")[0],
    document("tasks/resubscribe", "SubscribeToTask")[1],
    framed("SubscribeToTask"),
];

/// Create a push-notification configuration for a task.
const D_PUSH_CONFIG_CREATE: &[Dispatch] = &[
    target(T_PUSH_CONFIGS, POST),
    document(
        "tasks/pushNotificationConfig/set",
        "CreateTaskPushNotificationConfig",
    )[0],
    document(
        "tasks/pushNotificationConfig/set",
        "CreateTaskPushNotificationConfig",
    )[1],
    framed("CreateTaskPushNotificationConfig"),
];

/// Read one push-notification configuration back.
const D_PUSH_CONFIG_GET: &[Dispatch] = &[
    target(T_PUSH_CONFIG, GET),
    document(
        "tasks/pushNotificationConfig/get",
        "GetTaskPushNotificationConfig",
    )[0],
    document(
        "tasks/pushNotificationConfig/get",
        "GetTaskPushNotificationConfig",
    )[1],
    framed("GetTaskPushNotificationConfig"),
];

/// List a task's push-notification configurations.
const D_PUSH_CONFIG_LIST: &[Dispatch] = &[
    target(T_PUSH_CONFIGS, GET),
    document(
        "tasks/pushNotificationConfig/list",
        "ListTaskPushNotificationConfigs",
    )[0],
    document(
        "tasks/pushNotificationConfig/list",
        "ListTaskPushNotificationConfigs",
    )[1],
    framed("ListTaskPushNotificationConfigs"),
];

/// Delete a push-notification configuration.
const D_PUSH_CONFIG_DELETE: &[Dispatch] = &[
    target(T_PUSH_CONFIG, DELETE),
    document(
        "tasks/pushNotificationConfig/delete",
        "DeleteTaskPushNotificationConfig",
    )[0],
    document(
        "tasks/pushNotificationConfig/delete",
        "DeleteTaskPushNotificationConfig",
    )[1],
    framed("DeleteTaskPushNotificationConfig"),
];

/// Read a card.
///
/// Four addresses, and two of them are open. The two discovery documents and the authenticated
/// extended card are the SAME work — a document this node publishes about itself, handed back — so
/// they are one operation and one price; what differs is who may ask, which is the bar on each row
/// and not a class of its own.
const D_AGENT_CARD: &[Dispatch] = &[
    open(T_METADATA, GET),
    open(T_CARD, GET),
    target(T_EXTENDED_CARD, GET),
    document("agent/getAuthenticatedExtendedCard", "GetExtendedAgentCard")[0],
    document("agent/getAuthenticatedExtendedCard", "GetExtendedAgentCard")[1],
    framed("GetExtendedAgentCard"),
];

/// One push event arriving from an agent this node dialled.
///
/// One address, and it is open. No client sends this: it is what a frame arriving on a connection
/// this node dialled MEANS, and the caller is a fronted agent that holds no credential of this
/// node's.
const D_PUSH_EVENT: &[Dispatch] = &[open(T_PUSH, POST)];

/// One unary operation over JSON.
const fn unary(op: &'static str, dispatch: &'static [Dispatch]) -> Operation {
    Operation {
        op,
        dispatch,
        answering: Answering::Unary,
        request_media: MEDIA_JSON,
        response_media: MEDIA_JSON,
    }
}

/// One streamed operation: a JSON request, an event stream back.
const fn streamed(op: &'static str, dispatch: &'static [Dispatch]) -> Operation {
    Operation {
        op,
        dispatch,
        answering: Answering::Stream,
        request_media: MEDIA_JSON,
        response_media: MEDIA_EVENT_STREAM,
    }
}

/// THE SURFACE.
///
/// The operation order is the order a target is MATCHED in, and it is most-specific-first: the two
/// discovery documents and the callback are exact paths and come before anything patterned; the
/// deeper configuration template comes before the shallower one it would otherwise be shadowed by;
/// the plane's own mount is loosest. A mount that sorted this list would be deciding a precedence
/// the protocol has already decided.
pub const SURFACE: WireSurface = WireSurface {
    bindings: &[
        BindingDecl {
            name: BINDING_DOCUMENT,
            transport: crate::claims::TRANSPORT_HTTP,
            mounts: &[MOUNT, MOUNT_SLASH],
        },
        BindingDecl {
            name: BINDING_TARGET,
            transport: crate::claims::TRANSPORT_HTTP,
            mounts: &[],
        },
        BindingDecl {
            name: BINDING_FRAMED,
            transport: crate::claims::TRANSPORT_GRPC,
            mounts: &[],
        },
    ],
    operations: &[
        // The card first: its two open discovery rows are the tightest exact paths this surface has.
        unary(ops::OP_AGENT_CARD.as_str(), D_AGENT_CARD),
        // The callback, exact and open.
        unary(ops::OP_PUSH_EVENT.as_str(), D_PUSH_EVENT),
        // The named operations of the target binding, exact before patterned.
        unary(ops::OP_MESSAGE_SEND.as_str(), D_MESSAGE_SEND),
        streamed(ops::OP_MESSAGE_STREAM.as_str(), D_MESSAGE_STREAM),
        unary(ops::OP_TASK_LIST.as_str(), D_TASK_LIST),
        // The deepest configuration template first: `{id}/pushNotificationConfigs/{config_id}` is
        // longer than the collection above it, and the collection is longer than `{id}` alone.
        unary(ops::OP_PUSH_CONFIG_GET.as_str(), D_PUSH_CONFIG_GET),
        unary(ops::OP_PUSH_CONFIG_DELETE.as_str(), D_PUSH_CONFIG_DELETE),
        unary(ops::OP_PUSH_CONFIG_CREATE.as_str(), D_PUSH_CONFIG_CREATE),
        unary(ops::OP_PUSH_CONFIG_LIST.as_str(), D_PUSH_CONFIG_LIST),
        unary(ops::OP_TASK_GET.as_str(), D_TASK_GET),
        unary(ops::OP_TASK_CANCEL.as_str(), D_TASK_CANCEL),
        // Reachable on the document and framed bindings only.
        streamed(ops::OP_TASK_SUBSCRIBE.as_str(), D_TASK_SUBSCRIBE),
    ],
};

#[cfg(test)]
#[path = "tests/surface.rs"]
mod tests;
