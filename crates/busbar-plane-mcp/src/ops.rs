//! The operation vocabulary: which method name is which priced operation.
//!
//! This protocol names its operation in the BODY rather than in the path, so the table below is the
//! whole of how a request becomes a unit. One row per method, one class per row, and the class is
//! what the draft declares and what the unit is priced at.
//!
//! ## Why the table is written here rather than read from the codec
//!
//! The codec crate holds this list too, in the constant its dispatch is checked against. That
//! constant is visible to its own crate only, and this crate may not widen it. So the table is
//! written once more here and then PINNED — the tests read the codec's own source and the
//! conformance battery's own suites and assert that neither of them names a method this table does
//! not. A copy that is checked is not a second opinion; a copy that is not checked is.
//!
//! ## Three kinds of row
//!
//! A CLIENT method is one a caller sends and this node answers. A PROVIDER method is one an upstream
//! sends BACK during a call — asking for a completion, for a list of roots, or for something from
//! the caller — which opens a unit of the upstream's own and runs all seven steps over it. A
//! NOTIFICATION is neither: it carries no identifier, obliges no answer, and the specification
//! forbids replying to one.

use busbar_contract::ids::OpClassId;

/// Ask the server what it is and what it supports.
pub const OP_DISCOVER: OpClassId = OpClassId::new("discover");

/// The console-era handshake: what revision this node speaks, and what it can do.
///
/// A class of its own rather than a second spelling of [`OP_DISCOVER`], because the two answer
/// different documents about different things. Discovery is computed PER CALLER from that caller's
/// own grant — two callers discover two different servers — and this one is computed from nothing at
/// all: it names the revision this build implements and the capabilities the build has, which are
/// the same for every caller and are known before a caller is identified.
///
/// Reachable on the console binding alone. See [`crate::surface`] for why that is the protocol's
/// fact rather than this crate's convenience.
pub const OP_INITIALIZE: OpClassId = OpClassId::new("initialize");

/// The console-era liveness verb: an empty answer to an empty question.
///
/// It reads nothing, decides nothing and answers the empty document. It is a class of its own
/// because it is an operation a caller can send and a unit the loop therefore walks — a class it
/// shared with something else would be a unit priced, scoped and recorded as that something else.
pub const OP_PING: OpClassId = OpClassId::new("ping");

/// List the tools this caller may use.
pub const OP_TOOLS_LIST: OpClassId = OpClassId::new("tools_list");

/// Call one tool. This is the operation the whole plane exists for, and the one that is priced.
pub const OP_TOOL_CALL: OpClassId = OpClassId::new("tool_call");

/// List the prompts this caller may use.
pub const OP_PROMPTS_LIST: OpClassId = OpClassId::new("prompts_list");

/// Render one prompt.
pub const OP_PROMPT_GET: OpClassId = OpClassId::new("prompt_get");

/// List the resources this caller may read.
pub const OP_RESOURCES_LIST: OpClassId = OpClassId::new("resources_list");

/// List the resource templates this caller may fill in.
pub const OP_RESOURCE_TEMPLATES_LIST: OpClassId = OpClassId::new("resource_templates_list");

/// Read one resource.
pub const OP_RESOURCE_READ: OpClassId = OpClassId::new("resource_read");

/// Complete a partially written argument.
pub const OP_COMPLETION: OpClassId = OpClassId::new("completion");

/// Read one long-running task back.
pub const OP_TASK_GET: OpClassId = OpClassId::new("task_get");

/// Hand a long-running task what it asked for.
pub const OP_TASK_UPDATE: OpClassId = OpClassId::new("task_update");

/// Ask for one long-running task to stop.
pub const OP_TASK_CANCEL: OpClassId = OpClassId::new("task_cancel");

/// Hold open a stream of catalogue changes.
pub const OP_SUBSCRIPTIONS_LISTEN: OpClassId = OpClassId::new("subscriptions_listen");

/// An upstream asking for a completion, mid-call.
///
/// This is provider-initiated: the upstream sends it, it opens a unit of its own, and what answers
/// it costs money on this node's own budget rather than the upstream's.
pub const OP_SAMPLING: OpClassId = OpClassId::new("sampling");

/// An upstream asking which roots it may work under, mid-call.
pub const OP_ROOTS_LIST: OpClassId = OpClassId::new("roots_list");

/// An upstream asking the caller for something, mid-call.
pub const OP_ELICITATION: OpClassId = OpClassId::new("elicitation");

/// A message that obliges no answer.
pub const OP_NOTIFICATION: OpClassId = OpClassId::new("notification");

/// Read the discovery document that says how to authenticate to this mount.
///
/// This one is named by the TARGET rather than by a method in a document: the request carries no
/// body at all, so there is no envelope to name an operation in. It is the one surface of this
/// plane whose claim declares no scheme, because it is what a caller reads BEFORE it has one.
pub const OP_METADATA: OpClassId = OpClassId::new("metadata");

/// Every operation class this plane's units can be, in declaration order.
pub const OP_CLASSES: &[OpClassId] = &[
    OP_DISCOVER,
    OP_INITIALIZE,
    OP_PING,
    OP_TOOLS_LIST,
    OP_TOOL_CALL,
    OP_PROMPTS_LIST,
    OP_PROMPT_GET,
    OP_RESOURCES_LIST,
    OP_RESOURCE_TEMPLATES_LIST,
    OP_RESOURCE_READ,
    OP_COMPLETION,
    OP_TASK_GET,
    OP_TASK_UPDATE,
    OP_TASK_CANCEL,
    OP_SUBSCRIPTIONS_LISTEN,
    OP_SAMPLING,
    OP_ROOTS_LIST,
    OP_ELICITATION,
    OP_NOTIFICATION,
    OP_METADATA,
];

/// Who sends a method, and whether it obliges an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    /// A caller sends it and this node answers.
    Client,
    /// An upstream sends it back mid-call, opening a unit of its own.
    Provider,
    /// Either side sends it and nobody answers it.
    Notice,
}

/// One row of the vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodRow {
    /// The method name exactly as it appears on the wire.
    pub method: &'static str,
    /// Which operation class a unit carrying it is.
    pub op: OpClassId,
    /// Who sends it.
    pub sender: Sender,
    /// Whether its answer arrives as a run of events rather than as one document.
    pub streaming: bool,
    /// Where in the parameters the thing being named is, where the method names one.
    ///
    /// The codec keeps the same table under its own name, and it is used for the same purpose: to
    /// say what the request is ABOUT without reading the request's content.
    pub name_pointer: Option<&'static str>,
}

/// Every method name this plane reads.
///
/// A name absent from here is a method this plane does not carry, and the decode step says so rather
/// than guessing.
pub const METHODS: &[MethodRow] = &[
    MethodRow {
        method: "server/discover",
        op: OP_DISCOVER,
        sender: Sender::Client,
        streaming: false,
        name_pointer: None,
    },
    // The two console-era verbs. They are rows of the vocabulary because a caller SENDS them and
    // this node ANSWERS them; WHERE it answers them is the surface's declaration and not this
    // table's, and [`crate::surface`] declares both on the console binding alone. A reader who wants
    // to know whether the mounted request surface carries them reads that file, and the answer there
    // is no — which is the same answer `busbar_mcp_codec::codec::IMPLEMENTED_METHODS` gives, pinned
    // by a test below.
    MethodRow {
        method: "initialize",
        op: OP_INITIALIZE,
        sender: Sender::Client,
        streaming: false,
        name_pointer: None,
    },
    MethodRow {
        method: "ping",
        op: OP_PING,
        sender: Sender::Client,
        streaming: false,
        name_pointer: None,
    },
    MethodRow {
        method: "tools/list",
        op: OP_TOOLS_LIST,
        sender: Sender::Client,
        streaming: false,
        name_pointer: None,
    },
    MethodRow {
        method: "tools/call",
        op: OP_TOOL_CALL,
        sender: Sender::Client,
        streaming: false,
        name_pointer: Some("/params/name"),
    },
    MethodRow {
        method: "prompts/list",
        op: OP_PROMPTS_LIST,
        sender: Sender::Client,
        streaming: false,
        name_pointer: None,
    },
    MethodRow {
        method: "prompts/get",
        op: OP_PROMPT_GET,
        sender: Sender::Client,
        streaming: false,
        name_pointer: Some("/params/name"),
    },
    MethodRow {
        method: "resources/list",
        op: OP_RESOURCES_LIST,
        sender: Sender::Client,
        streaming: false,
        name_pointer: None,
    },
    MethodRow {
        method: "resources/templates/list",
        op: OP_RESOURCE_TEMPLATES_LIST,
        sender: Sender::Client,
        streaming: false,
        name_pointer: None,
    },
    MethodRow {
        method: "resources/read",
        op: OP_RESOURCE_READ,
        sender: Sender::Client,
        streaming: false,
        name_pointer: Some("/params/uri"),
    },
    MethodRow {
        method: "completion/complete",
        op: OP_COMPLETION,
        sender: Sender::Client,
        streaming: false,
        name_pointer: None,
    },
    MethodRow {
        method: "tasks/get",
        op: OP_TASK_GET,
        sender: Sender::Client,
        streaming: false,
        name_pointer: Some("/params/taskId"),
    },
    MethodRow {
        method: "tasks/update",
        op: OP_TASK_UPDATE,
        sender: Sender::Client,
        streaming: false,
        name_pointer: Some("/params/taskId"),
    },
    MethodRow {
        method: "tasks/cancel",
        op: OP_TASK_CANCEL,
        sender: Sender::Client,
        streaming: false,
        name_pointer: Some("/params/taskId"),
    },
    MethodRow {
        method: "subscriptions/listen",
        op: OP_SUBSCRIPTIONS_LISTEN,
        sender: Sender::Client,
        streaming: true,
        name_pointer: None,
    },
    // The three an upstream sends BACK, mid-call.
    MethodRow {
        method: "sampling/createMessage",
        op: OP_SAMPLING,
        sender: Sender::Provider,
        streaming: false,
        name_pointer: None,
    },
    MethodRow {
        method: "roots/list",
        op: OP_ROOTS_LIST,
        sender: Sender::Provider,
        streaming: false,
        name_pointer: None,
    },
    MethodRow {
        method: "elicitation/create",
        op: OP_ELICITATION,
        sender: Sender::Provider,
        streaming: false,
        name_pointer: None,
    },
];

/// The name the discovery fetch is reported under, since it has no method member to be read from.
///
/// A unit of every other class carries the method a caller spelled; this one carries what it IS, so
/// a journal row for the discovery fetch is not a row with the method fact missing.
pub const METHOD_METADATA: &str = "well-known/protected-resource-metadata";

/// One notice this plane recognises, and which side of the exchange sends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoticeRow {
    /// The notice name exactly as it appears on the wire.
    pub method: &'static str,
    /// Who sends it. A notice is neither answered nor refused, but it is still SENT by one side, and
    /// which side that is decides which leg may admit it.
    pub sender: Sender,
}

/// The notices this plane recognises, and who sends each.
///
/// A notification obliges no answer, so recognising one is only about knowing whether to act on it.
/// One this plane does not recognise is DROPPED rather than refused, which is what the specification
/// requires and what the codec already does.
///
/// The SENDER column is not decoration. Two of these three are server-originated — the codec's own
/// notification half says so in as many words — and acting on one opens a unit whose plan writes the
/// catalogue. A list with no sender let either side send either notice, so a CALLER could tell this
/// node that the server it fronts had changed its tools, and the party being catalogued was no longer
/// the party deciding when its catalogue is stale.
pub const NOTICES: &[NoticeRow] = &[
    NoticeRow {
        method: "notifications/roots/list_changed",
        sender: Sender::Client,
    },
    NoticeRow {
        method: "notifications/tools/list_changed",
        sender: Sender::Provider,
    },
    NoticeRow {
        method: "notifications/resources/updated",
        sender: Sender::Provider,
    },
];

/// The row for one method name, if this plane carries that method at all.
#[must_use]
pub fn row_for(method: &str) -> Option<&'static MethodRow> {
    METHODS.iter().find(|r| r.method == method)
}

/// The row for one notice name, if this plane recognises that notice at all.
#[must_use]
pub fn notice_for(method: &str) -> Option<&'static NoticeRow> {
    NOTICES.iter().find(|r| r.method == method)
}

/// Whether a name is a notification this plane recognises, whoever sends it.
#[must_use]
pub fn is_known_notification(method: &str) -> bool {
    notice_for(method).is_some()
}

#[cfg(test)]
#[path = "tests/ops.rs"]
mod tests;
