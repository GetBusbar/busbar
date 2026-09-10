//! Tests for `surface.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.

use busbar_contract::surface::{
    check_surface, resolve_document, resolve_target, Answering, Bar, Dispatch,
};

use super::{
    binding_for, row_on, BINDING_CONSOLE, BINDING_DOCUMENT, MEDIA_EVENT_STREAM, MEDIA_JSON,
    METHOD_MEMBER, MOUNT_SLASH, SURFACE,
};
use crate::{claims, ops};

/// A claim key this plane declares no claim on, for the cases whose subject is the NEGATIVE.
///
/// Not another wire's name. A rig that spells a carrier in order to be told "no" is the plane
/// naming a transport instance, and it also goes quietly green the day that carrier is claimed.
/// Every case that uses this asserts [`claims::declares`] is false for it first, so the key is
/// undeclared by the plane's own answer rather than by the reader's assumption.
const UNCLAIMED: &str = "unclaimed";

/// The surface is one a mount will boot on.
///
/// The vocabulary's own check, run here rather than only at boot: every operation reachable, no two
/// reachable the same way, every declared binding known, every mount well formed.
#[test]
fn the_surface_boots() {
    check_surface(&SURFACE).expect("the declared surface passes the vocabulary's own check");
}

/// Every method of the vocabulary is addressed by this surface, and every address is a method of the
/// vocabulary.
///
/// BOTH directions, because each catches a different mistake. A method with no row here is one the
/// decode step can no longer reach — the surface is what it asks — and a row here naming a method
/// the vocabulary does not carry is an address to nothing.
///
/// The three an upstream sends back are excluded in the first direction and named individually, so
/// that "not on the served surface" is an assertion rather than a silence.
#[test]
fn the_surface_and_the_vocabulary_name_the_same_methods() {
    let declared: Vec<&str> = SURFACE
        .operations
        .iter()
        .flat_map(|operation| operation.dispatch.iter())
        .filter_map(|dispatch| match dispatch {
            Dispatch::Document { name, .. } => Some(*name),
            _ => None,
        })
        .collect();
    for row in ops::METHODS {
        if row.sender == ops::Sender::Provider {
            assert!(
                !declared.contains(&row.method),
                "{} is provider-initiated and must not be on the served surface",
                row.method
            );
            continue;
        }
        assert!(
            declared.contains(&row.method),
            "the vocabulary carries {} and no dispatch addresses it",
            row.method
        );
    }
    for name in &declared {
        assert!(
            ops::row_for(name).is_some() || ops::is_known_notification(name),
            "{name} is addressed and is not a method or notification this plane carries"
        );
    }
}

/// The three provider methods are absent, named one at a time.
#[test]
fn the_provider_methods_are_absent() {
    for method in ["sampling/createMessage", "roots/list", "elicitation/create"] {
        assert_eq!(
            resolve_document(&SURFACE, BINDING_DOCUMENT, method),
            None,
            "{method} is addressed on the mounted request surface"
        );
        assert_eq!(
            resolve_document(&SURFACE, BINDING_CONSOLE, method),
            None,
            "{method} is addressed on the console binding"
        );
    }
}

/// THE FILE'S REASON FOR EXISTING: the two console-era verbs are reachable on the console binding
/// and unreachable on the mounted request surface.
///
/// This is the assertion that keeps a `-32601` a `-32601`. The codec's own dispatch table does not
/// carry either name, so the mounted surface answers "no such method" today; a surface that declared
/// them there would turn that into an answer, which is a behaviour change on a wire the published
/// conformance suite pins.
#[test]
fn the_console_era_verbs_are_console_only() {
    for method in ["initialize", "ping"] {
        assert!(
            resolve_document(&SURFACE, BINDING_CONSOLE, method).is_some(),
            "{method} is not reachable on the console binding"
        );
        assert_eq!(
            resolve_document(&SURFACE, BINDING_DOCUMENT, method),
            None,
            "{method} is addressed on the mounted request surface, which answers -32601 today"
        );
        assert!(
            !busbar_mcp_codec::codec::IMPLEMENTED_METHODS.contains(&method),
            "the codec dispatches {method} on the mounted surface after all"
        );
    }
}

/// And the same two, through the joined question the decode step actually asks.
#[test]
fn the_joined_question_answers_per_transport() {
    for method in ["initialize", "ping"] {
        assert!(row_on(method, claims::CONSOLE_TRANSPORT).is_some());
        assert_eq!(row_on(method, claims::TRANSPORT), None);
        assert_eq!(row_on(method, claims::STREAM_TRANSPORT), None);
    }
    // Everything else is reachable on all three, and `tools/list` stands for the set.
    for transport in [
        claims::TRANSPORT,
        claims::STREAM_TRANSPORT,
        claims::CONSOLE_TRANSPORT,
    ] {
        assert_eq!(
            row_on("tools/list", transport).map(|row| row.op),
            Some(ops::OP_TOOLS_LIST)
        );
    }
    // A transport this plane makes no claim on addresses nothing. The key is UNDECLARED by the
    // plane's own answer rather than by being some other wire's name: a test that types a carrier
    // in order to be told "no" is the plane naming a transport instance, and this rig reads the
    // registrations instead.
    assert!(!claims::declares(UNCLAIMED));
    assert_eq!(row_on("tools/list", UNCLAIMED), None);
}

/// Every claim transport this plane declares maps to a binding, and nothing else does.
#[test]
fn every_claimed_transport_has_a_binding() {
    for claim in <crate::McpPlane as busbar_contract::plane::PlaneMeta>::CLAIMS {
        assert!(
            binding_for(claim.transport).is_some(),
            "the claim on {} maps to no binding",
            claim.transport
        );
    }
    assert!(!claims::declares(UNCLAIMED));
    assert_eq!(binding_for(UNCLAIMED), None);
    assert_eq!(binding_for(""), None);
}

/// The mounts are the claim's own path, and the trailing-separator spelling beside it.
///
/// PINNED against `claims::DEFAULT_MOUNT` rather than written twice: the path a claim selects on and
/// the path a mount answers at cannot be allowed to be two strings.
#[test]
fn the_mounts_are_the_claims_own_path() {
    let document = SURFACE
        .bindings
        .iter()
        .find(|binding| binding.name == BINDING_DOCUMENT)
        .expect("the document binding is declared");
    assert_eq!(document.transport, claims::TRANSPORT);
    assert_eq!(document.mounts, &[claims::DEFAULT_MOUNT, MOUNT_SLASH]);
    assert_eq!(MOUNT_SLASH, format!("{}/", claims::DEFAULT_MOUNT));

    let console = SURFACE
        .bindings
        .iter()
        .find(|binding| binding.name == BINDING_CONSOLE)
        .expect("the console binding is declared");
    assert_eq!(console.transport, claims::CONSOLE_TRANSPORT);
    // No mount, because a console binding's frames arrive on a named stream and not at a path.
    assert!(console.mounts.is_empty());
}

/// This protocol addresses nothing by its target, so there is no target row to resolve.
///
/// Asserted rather than assumed: a target row added here would be a route a mount serves without the
/// method member being read at all, which is a second grammar for naming an operation.
#[test]
fn nothing_is_addressed_by_its_target() {
    assert!(resolve_target(&SURFACE, claims::DEFAULT_MOUNT, "POST").is_none());
    assert!(resolve_target(&SURFACE, claims::DEFAULT_METADATA, "GET").is_none());
    for operation in SURFACE.operations {
        for dispatch in operation.dispatch {
            assert!(
                matches!(dispatch, Dispatch::Document { .. }),
                "{} is addressed by something other than a document member",
                operation.op
            );
        }
    }
}

/// The streamed operation is the one the vocabulary calls streaming, and it answers as events.
#[test]
fn the_streamed_operation_is_the_streaming_row() {
    for operation in SURFACE.operations {
        let streaming = ops::METHODS
            .iter()
            .any(|row| row.op.as_str() == operation.op && row.streaming);
        let expected = if streaming {
            Answering::Stream
        } else {
            Answering::Unary
        };
        assert_eq!(
            operation.answering, expected,
            "{} answers the wrong way round",
            operation.op
        );
        assert_eq!(operation.request_media, MEDIA_JSON);
        assert_eq!(
            operation.response_media,
            if streaming {
                MEDIA_EVENT_STREAM
            } else {
                MEDIA_JSON
            }
        );
    }
}

/// Every row demands a credential, and none of them is open.
///
/// The one open surface this plane has is the discovery document, which is declared on the CLAIM and
/// is deliberately not an operation here. An open row on the request surface would be this file
/// carving a hole in the credential bar.
#[test]
fn nothing_on_the_served_surface_is_open() {
    for operation in SURFACE.operations {
        for dispatch in operation.dispatch {
            assert_eq!(
                dispatch.bar(),
                Bar::Credential,
                "{} declares an open address",
                operation.op
            );
        }
    }
}

/// Every operation names a class the plane declares, and every document row reads the same member.
#[test]
fn every_row_is_in_the_declared_vocabulary() {
    for operation in SURFACE.operations {
        assert!(
            ops::OP_CLASSES.iter().any(|op| op.as_str() == operation.op),
            "{} is not a declared operation class",
            operation.op
        );
        for dispatch in operation.dispatch {
            if let Dispatch::Document { member, .. } = dispatch {
                assert_eq!(*member, METHOD_MEMBER);
            }
        }
    }
}
