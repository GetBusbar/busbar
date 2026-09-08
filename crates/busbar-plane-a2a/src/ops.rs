//! The operation vocabulary: which method name is which priced operation.
//!
//! This protocol spells the same ten operations two ways. The older wording is slash-separated and
//! lower-case; the newer one is a verb in title case. They are the SAME operations — a request
//! carrying either name asks for the same thing and is priced the same — so the table below maps
//! both spellings onto one operation class each, and the class is what the draft declares.
//!
//! ## Why the table is written here rather than read from the codec
//!
//! The codec crate holds this vocabulary too, in the function that turns a method name into the
//! verb it answers itself. That function is not reachable from outside its crate: it is visible to
//! its own crate only, and this crate may not widen it. So the table is written once more here and
//! then PINNED — the tests read the codec's own source and the conformance rig's own vocabulary
//! table and assert that neither of them names a method this table does not. A second copy that is
//! checked against the first is not a second opinion; a second copy that is not checked is.
//!
//! ## Two spellings, one class, and why not two classes
//!
//! An operation class PRICES a unit. A deployment that priced "send a message" differently
//! depending on which of the two spellings a caller used would be charging for the caller's choice
//! of vocabulary rather than for the work, and the two spellings do identical work. So the class is
//! the operation, and which spelling arrived is a FACT, not a class.

use busbar_contract::ids::OpClassId;

/// Send one message to an agent and wait for the whole answer.
pub const OP_MESSAGE_SEND: OpClassId = OpClassId::new("message_send");

/// Send one message and receive the answer as a stream of events.
pub const OP_MESSAGE_STREAM: OpClassId = OpClassId::new("message_stream");

/// Read one task back.
pub const OP_TASK_GET: OpClassId = OpClassId::new("task_get");

/// List the tasks this caller may see.
pub const OP_TASK_LIST: OpClassId = OpClassId::new("task_list");

/// Ask for one task to stop.
pub const OP_TASK_CANCEL: OpClassId = OpClassId::new("task_cancel");

/// Re-attach to a task's event stream.
pub const OP_TASK_SUBSCRIBE: OpClassId = OpClassId::new("task_subscribe");

/// Create a push-notification configuration for a task.
pub const OP_PUSH_CONFIG_CREATE: OpClassId = OpClassId::new("push_config_create");

/// Read a push-notification configuration back.
pub const OP_PUSH_CONFIG_GET: OpClassId = OpClassId::new("push_config_get");

/// List a task's push-notification configurations.
pub const OP_PUSH_CONFIG_LIST: OpClassId = OpClassId::new("push_config_list");

/// Delete a push-notification configuration.
pub const OP_PUSH_CONFIG_DELETE: OpClassId = OpClassId::new("push_config_delete");

/// Read the extended agent card, which only an authenticated caller may see.
pub const OP_AGENT_CARD: OpClassId = OpClassId::new("agent_card");

/// One push event arriving from an agent this node dialled.
///
/// This is the provider-initiated class. No client ever sends it: it is what the plane says a frame
/// arriving on an upstream connection MEANS, and the loop runs all seven steps over it exactly as it
/// does over a client's own request.
pub const OP_PUSH_EVENT: OpClassId = OpClassId::new("push_event");

/// Every operation class this plane's units can be, in declaration order.
pub const OP_CLASSES: &[OpClassId] = &[
    OP_MESSAGE_SEND,
    OP_MESSAGE_STREAM,
    OP_TASK_GET,
    OP_TASK_LIST,
    OP_TASK_CANCEL,
    OP_TASK_SUBSCRIBE,
    OP_PUSH_CONFIG_CREATE,
    OP_PUSH_CONFIG_GET,
    OP_PUSH_CONFIG_LIST,
    OP_PUSH_CONFIG_DELETE,
    OP_AGENT_CARD,
    OP_PUSH_EVENT,
];

/// Which spelling of the vocabulary a request used.
///
/// Carried as a fact, never as a class: see the module note on why the spelling does not change the
/// price.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wording {
    /// The slash-separated lower-case wording of the earlier revision.
    Slashed,
    /// The title-case verb wording of the later revision.
    Verb,
}

impl Wording {
    /// The name this wording is reported under, as a fact.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Slashed => "slashed",
            Self::Verb => "verb",
        }
    }
}

/// One row of the vocabulary: a method name, how it is spelled, and what it costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodRow {
    /// The method name exactly as it appears on the wire.
    pub method: &'static str,
    /// Which of the two spellings it is.
    pub wording: Wording,
    /// Which operation class a unit carrying it is.
    pub op: OpClassId,
    /// Whether the answer arrives as a stream of events rather than as one reply.
    pub streaming: bool,
}

/// Every method name this plane reads, in the order the vocabulary tables list them.
///
/// Both spellings of every operation appear. A name absent from here is a method this plane does not
/// claim, and the decode step answers that it does not carry that shape rather than guessing.
pub const METHODS: &[MethodRow] = &[
    MethodRow {
        method: "message/send",
        wording: Wording::Slashed,
        op: OP_MESSAGE_SEND,
        streaming: false,
    },
    MethodRow {
        method: "SendMessage",
        wording: Wording::Verb,
        op: OP_MESSAGE_SEND,
        streaming: false,
    },
    MethodRow {
        method: "message/stream",
        wording: Wording::Slashed,
        op: OP_MESSAGE_STREAM,
        streaming: true,
    },
    MethodRow {
        method: "SendStreamingMessage",
        wording: Wording::Verb,
        op: OP_MESSAGE_STREAM,
        streaming: true,
    },
    MethodRow {
        method: "tasks/get",
        wording: Wording::Slashed,
        op: OP_TASK_GET,
        streaming: false,
    },
    MethodRow {
        method: "GetTask",
        wording: Wording::Verb,
        op: OP_TASK_GET,
        streaming: false,
    },
    MethodRow {
        method: "tasks/list",
        wording: Wording::Slashed,
        op: OP_TASK_LIST,
        streaming: false,
    },
    MethodRow {
        method: "ListTasks",
        wording: Wording::Verb,
        op: OP_TASK_LIST,
        streaming: false,
    },
    MethodRow {
        method: "tasks/cancel",
        wording: Wording::Slashed,
        op: OP_TASK_CANCEL,
        streaming: false,
    },
    MethodRow {
        method: "CancelTask",
        wording: Wording::Verb,
        op: OP_TASK_CANCEL,
        streaming: false,
    },
    MethodRow {
        method: "tasks/resubscribe",
        wording: Wording::Slashed,
        op: OP_TASK_SUBSCRIBE,
        streaming: true,
    },
    MethodRow {
        method: "SubscribeToTask",
        wording: Wording::Verb,
        op: OP_TASK_SUBSCRIBE,
        streaming: true,
    },
    MethodRow {
        method: "tasks/pushNotificationConfig/set",
        wording: Wording::Slashed,
        op: OP_PUSH_CONFIG_CREATE,
        streaming: false,
    },
    MethodRow {
        method: "CreateTaskPushNotificationConfig",
        wording: Wording::Verb,
        op: OP_PUSH_CONFIG_CREATE,
        streaming: false,
    },
    MethodRow {
        method: "tasks/pushNotificationConfig/get",
        wording: Wording::Slashed,
        op: OP_PUSH_CONFIG_GET,
        streaming: false,
    },
    MethodRow {
        method: "GetTaskPushNotificationConfig",
        wording: Wording::Verb,
        op: OP_PUSH_CONFIG_GET,
        streaming: false,
    },
    MethodRow {
        method: "tasks/pushNotificationConfig/list",
        wording: Wording::Slashed,
        op: OP_PUSH_CONFIG_LIST,
        streaming: false,
    },
    MethodRow {
        method: "ListTaskPushNotificationConfigs",
        wording: Wording::Verb,
        op: OP_PUSH_CONFIG_LIST,
        streaming: false,
    },
    MethodRow {
        method: "tasks/pushNotificationConfig/delete",
        wording: Wording::Slashed,
        op: OP_PUSH_CONFIG_DELETE,
        streaming: false,
    },
    MethodRow {
        method: "DeleteTaskPushNotificationConfig",
        wording: Wording::Verb,
        op: OP_PUSH_CONFIG_DELETE,
        streaming: false,
    },
    MethodRow {
        method: "agent/getAuthenticatedExtendedCard",
        wording: Wording::Slashed,
        op: OP_AGENT_CARD,
        streaming: false,
    },
    MethodRow {
        method: "GetExtendedAgentCard",
        wording: Wording::Verb,
        op: OP_AGENT_CARD,
        streaming: false,
    },
];

/// The row for one method name, if this plane carries that method at all.
#[must_use]
pub fn row_for(method: &str) -> Option<&'static MethodRow> {
    METHODS.iter().find(|r| r.method == method)
}

#[cfg(test)]
#[path = "tests/ops.rs"]
mod tests;
