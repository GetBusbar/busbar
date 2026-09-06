//! Tests for `ops.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{is_known_notification, notice_for, row_for, Sender, METHODS, NOTICES, OP_CLASSES};

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
    for notice in NOTICES {
        assert!(
            row_for(notice.method).is_none(),
            "{} is in both lists",
            notice.method
        );
    }
    for row in METHODS {
        assert!(
            !is_known_notification(row.method),
            "{} is in both lists",
            row.method
        );
    }
}

/// Every notice names a side, and no notice is listed twice.
///
/// A notice with no sender is one either side may send, and one of these three opens a unit whose
/// plan writes the catalogue. `Notice` is the third arm of the sender kind and it is the one
/// answer this column may NOT carry: it would mean exactly the "either side" this column exists
/// to stop.
#[test]
fn every_notice_names_the_side_that_sends_it() {
    for (i, notice) in NOTICES.iter().enumerate() {
        assert!(
            !NOTICES[..i].iter().any(|n| n.method == notice.method),
            "the notice {} is listed twice",
            notice.method
        );
        assert_ne!(
            notice.sender,
            Sender::Notice,
            "the notice {} names no side",
            notice.method
        );
        assert_eq!(notice_for(notice.method), Some(notice));
    }
    assert_eq!(notice_for("notifications/something/else"), None);
}

/// The notices a SERVER originates are the two the codec's own notification half carries.
///
/// The roots list is the caller's own, because roots are the caller's; the other two are the
/// server describing its own catalogue. Pinned by value so a row added later has to say which
/// side it came from and be right about it.
#[test]
fn the_server_originated_notices_are_the_two() {
    let from_the_server: Vec<&str> = NOTICES
        .iter()
        .filter(|n| n.sender == Sender::Provider)
        .map(|n| n.method)
        .collect();
    assert_eq!(
        from_the_server,
        vec![
            "notifications/tools/list_changed",
            "notifications/resources/updated"
        ]
    );
}

/// Every method the codec's own dispatch table names is one this plane carries.
///
/// The table itself, iterated. This SCRAPED it out of the server half's source once — an
/// `include_str!` over `../../busbar-mcp/src/…` followed by a hand-rolled parse for quoted
/// pieces containing a slash — which coupled this crate to a sibling its manifest does not name
/// and could only ever see what the parse happened to catch. The table is the codec's now, so
/// the assertion is over the values themselves. A method the codec dispatches and this plane
/// does not carry would arrive here as an unsupported operation.
#[test]
fn every_dispatched_method_is_carried() {
    let mut seen = 0usize;
    for method in busbar_mcp_codec::codec::IMPLEMENTED_METHODS {
        if method.contains('/') {
            assert!(
                row_for(method).is_some(),
                "the codec dispatches {method} and this plane does not carry it"
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
/// The codec answers the same question in a small function; this CALLS it and asserts the two
/// agree, member for member, in BOTH directions. It read that function's source once — an
/// `include_str!` over `../../busbar-mcp/src/…`, then a substring search for the arm — which
/// coupled this crate to a sibling its manifest does not name, and which could only ever check
/// one direction: a method the codec addressed and this plane gave no pointer for read as a
/// pass, because the loop never visited it.
#[test]
fn the_name_pointers_are_the_codecs_own() {
    for row in METHODS {
        let member = row.name_pointer.map(|pointer| {
            pointer
                .rsplit('/')
                .next()
                .expect("a pointer has a last segment")
        });
        assert_eq!(
            busbar_mcp_codec::codec::name_source_of(row.method),
            member,
            "the codec and this plane disagree about where {}'s subject is",
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
