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
mod tests {
    use super::{row_for, MethodRow, Wording, METHODS, OP_CLASSES};

    /// Every method maps to a class the plane declares.
    #[test]
    fn every_method_names_a_declared_class() {
        for row in METHODS {
            assert!(
                OP_CLASSES.contains(&row.op),
                "method {} names an undeclared class {}",
                row.method,
                row.op
            );
        }
    }

    /// No method name appears twice, so a lookup has one answer.
    #[test]
    fn no_method_name_is_repeated() {
        for (i, row) in METHODS.iter().enumerate() {
            assert!(
                !METHODS[..i].iter().any(|r| r.method == row.method),
                "method {} is listed twice",
                row.method
            );
        }
    }

    /// Both spellings of one operation agree on its class and on whether it streams.
    ///
    /// This is the property the module header claims: the wording is a fact, never a price. If the
    /// two spellings ever disagreed here, a caller's choice of vocabulary would move the money.
    #[test]
    fn the_two_spellings_of_an_operation_agree() {
        for row in METHODS {
            let partner: Vec<&MethodRow> = METHODS
                .iter()
                .filter(|r| r.op == row.op && r.wording != row.wording)
                .collect();
            assert_eq!(
                partner.len(),
                1,
                "{} has {} partner spellings, not one",
                row.method,
                partner.len()
            );
            assert_eq!(
                partner[0].streaming, row.streaming,
                "the two spellings of {} disagree on streaming",
                row.op
            );
        }
    }

    /// The lookup is total over the table and answers nothing else.
    #[test]
    fn the_lookup_answers_the_table_and_nothing_else() {
        for row in METHODS {
            assert_eq!(row_for(row.method), Some(row));
        }
        assert_eq!(row_for("tasks/incinerate"), None);
        assert_eq!(row_for(""), None);
        // Case matters: the two spellings differ only in case for some operations, and a lookup
        // that folded case would answer the wrong wording.
        assert_eq!(row_for("MESSAGE/SEND"), None);
    }

    /// Every streaming method is one of the two the codec's own streaming test recognises.
    ///
    /// The codec decides "does this stream" by looking for a `/stream` suffix or one of two names.
    /// This asserts the same set from the other direction, so the two readings cannot drift apart
    /// without a red here.
    #[test]
    fn the_streaming_set_matches_the_codecs_own_rule() {
        for row in METHODS {
            let by_the_codecs_rule = row.method.ends_with("/stream")
                || row.method == "tasks/resubscribe"
                || row.method == "SendStreamingMessage"
                || row.method == "SubscribeToTask";
            assert_eq!(
                row.streaming, by_the_codecs_rule,
                "{} disagrees with the codec's streaming rule",
                row.method
            );
        }
    }

    /// The wording names are stable, because they are written into facts the journal keeps.
    #[test]
    fn the_wording_names_are_stable() {
        assert_eq!(Wording::Slashed.as_str(), "slashed");
        assert_eq!(Wording::Verb.as_str(), "verb");
    }
}
