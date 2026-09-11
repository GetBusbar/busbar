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

/// Every operation class this plane's units can be, in declaration order.
pub const OP_CLASSES: &[OpClassId] = &[
    OP_DISCOVER,
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

/// The notification names this plane recognises.
///
/// A notification obliges no answer, so recognising one is only about knowing whether to act on it.
/// One this plane does not recognise is DROPPED rather than refused, which is what the specification
/// requires and what the codec already does.
pub const NOTIFICATIONS: &[&str] = &[
    "notifications/roots/list_changed",
    "notifications/tools/list_changed",
    "notifications/resources/updated",
];

/// The row for one method name, if this plane carries that method at all.
#[must_use]
pub fn row_for(method: &str) -> Option<&'static MethodRow> {
    METHODS.iter().find(|r| r.method == method)
}

/// Whether a name is a notification this plane recognises.
#[must_use]
pub fn is_known_notification(method: &str) -> bool {
    NOTIFICATIONS.contains(&method)
}

/// **THE SETTLED ANSWER'S DOCUMENT, where this plane's FACE carries it.**
///
/// `refusal_of` on the root's mcp leg answers `None` for a unit that SETTLED, with the note that a
/// settled unit's bytes are its answer and the plane writes them. This is the read by which the
/// plane does: the bare result document for one class, when that class's answer is a fact about the
/// deployment's vocabulary rather than about the request. The caller frames it — the identifier is
/// the one the decode step recorded and the envelope is
/// [`crate::jsonrpc::success`]'s — so what is returned here is deliberately NOT an envelope.
///
/// `None` is the ordinary answer and it is not a gap. A class whose answer depends on the caller's
/// grant, on a catalogue snapshot or on an upstream cannot have its bytes on a static table, and
/// saying so by returning nothing is what keeps this from becoming a second place a real answer
/// could be computed. Exactly one of the thirteen client-sent classes is on the table today, and it
/// is the one whose answer this protocol fixes: `completion/complete` offers no completions, which
/// is a property of what this node is rather than of who asked.
#[must_use]
pub fn settled_document(op: OpClassId) -> Option<&'static [u8]> {
    match op {
        OP_COMPLETION => Some(busbar_mcp_codec::codec::RESULT_COMPLETION_EMPTY.as_bytes()),
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests/ops.rs"]
mod tests;
