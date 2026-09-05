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

#[cfg(test)]
mod tests {
    use super::{is_known_notification, row_for, Sender, METHODS, NOTIFICATIONS, OP_CLASSES};

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

    /// No method name is listed twice, so a lookup has one answer.
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

    /// No class is produced by two different methods.
    ///
    /// One class per method here, deliberately: this protocol spells each operation exactly one way,
    /// so two methods sharing a class would mean one of them was mis-filed.
    #[test]
    fn no_class_is_produced_twice() {
        for (i, row) in METHODS.iter().enumerate() {
            assert!(
                !METHODS[..i].iter().any(|r| r.op == row.op),
                "class {} is produced by two methods",
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
        assert_eq!(row_for("this/method/does/not/exist"), None);
        assert_eq!(row_for(""), None);
    }

    /// A notification is not a method, and a method is not a notification.
    ///
    /// The two lists must not overlap: a name in both would be answered and not answered at once.
    #[test]
    fn the_two_lists_do_not_overlap() {
        for name in NOTIFICATIONS {
            assert!(row_for(name).is_none(), "{name} is in both lists");
        }
        for row in METHODS {
            assert!(
                !is_known_notification(row.method),
                "{} is in both lists",
                row.method
            );
        }
    }

    /// Every method the codec's own dispatch table names is one this plane carries.
    ///
    /// The table is visible to its own crate only, so this reads its source. A method the codec
    /// answers and this plane does not carry would arrive here as an unsupported operation.
    #[test]
    fn every_dispatched_method_is_carried() {
        let source = include_str!("../../busbar-mcp/src/mcp/method.rs");
        let start = source
            .find("IMPLEMENTED_METHODS")
            .expect("the codec still names its method table");
        let body = &source[start..];
        let end = body.find("];").expect("the table closes");
        let mut seen = 0usize;
        for piece in body[..end].split('"').skip(1).step_by(2) {
            if piece.contains('/') {
                assert!(
                    row_for(piece).is_some(),
                    "the codec dispatches {piece} and this plane does not carry it"
                );
                seen += 1;
            }
        }
        assert!(
            seen >= 12,
            "only {seen} methods were read out of the codec's table"
        );
    }

    /// The name pointer is the codec's own reading of where a request's subject is.
    ///
    /// The codec answers the same question in a small function; this asserts the two agree, member
    /// for member, by reading that function's source.
    #[test]
    fn the_name_pointers_are_the_codecs_own() {
        let source = include_str!("../../busbar-mcp/src/mcp/envelope.rs");
        let start = source
            .find("pub(crate) fn name_source_of")
            .expect("the codec still answers where a subject is");
        let body = &source[start..];
        let end = body.find("\n}").expect("the function closes");
        let table = &body[..end];
        for row in METHODS {
            let Some(pointer) = row.name_pointer else {
                continue;
            };
            let member = pointer
                .rsplit('/')
                .next()
                .expect("a pointer has a last segment");
            assert!(
                table.contains(&format!("\"{}\"", row.method)),
                "the codec no longer names a subject for {}",
                row.method
            );
            assert!(
                table.contains(&format!("Some(\"{member}\")")),
                "the codec no longer reads {}'s subject from {member}",
                row.method
            );
        }
    }

    /// The three an upstream sends back are the three the plane calls provider-initiated.
    #[test]
    fn the_provider_methods_are_the_three() {
        let provider: Vec<&str> = METHODS
            .iter()
            .filter(|r| r.sender == Sender::Provider)
            .map(|r| r.method)
            .collect();
        assert_eq!(
            provider,
            vec!["sampling/createMessage", "roots/list", "elicitation/create"]
        );
    }
}
