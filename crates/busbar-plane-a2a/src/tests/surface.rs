//! The declared surface, pinned against the tables it is a declaration OF.
//!
//! Everything here answers one question: is this data still describing the protocol? A declaration
//! that drifted from the codec's route table or from the plane's own method table would mount a
//! surface nobody serves, and it would do it silently — a route that answers 404 and an operation
//! that answers `UNIMPLEMENTED` look, from outside, like a protocol that never had them.

use super::*;
use busbar_contract::surface as sfc;

/// Every path template and mount this surface declares is the codec's own constant, joined the one
/// way the codec joins it.
///
/// The join is what the codec does at run time (`mounted_route`), so writing it out here and
/// asserting equality is the check the module note promises: the literals above may be literals, and
/// they may not be a SECOND answer to where this protocol lives.
#[test]
fn every_target_is_the_codec_route_it_claims_to_be() {
    let mount = busbar_a2a_codec::MOUNT_PATH;
    assert_eq!(MOUNT, mount);
    assert_eq!(MOUNT_SLASH, format!("{mount}/"));
    assert_eq!(
        T_MESSAGE_SEND,
        busbar_a2a_codec::mounted_route(busbar_a2a_codec::ROUTE_MESSAGE_SEND)
    );
    assert_eq!(
        T_MESSAGE_STREAM,
        busbar_a2a_codec::mounted_route(busbar_a2a_codec::ROUTE_MESSAGE_STREAM)
    );
    assert_eq!(
        T_TASKS,
        busbar_a2a_codec::mounted_route(busbar_a2a_codec::ROUTE_TASKS)
    );
    assert_eq!(
        T_TASK,
        busbar_a2a_codec::mounted_route(busbar_a2a_codec::ROUTE_TASK)
    );
    assert_eq!(
        T_PUSH_CONFIGS,
        busbar_a2a_codec::mounted_route(busbar_a2a_codec::ROUTE_PUSH_CONFIGS)
    );
    assert_eq!(
        T_PUSH_CONFIG,
        busbar_a2a_codec::mounted_route(busbar_a2a_codec::ROUTE_PUSH_CONFIG)
    );
    assert_eq!(
        T_EXTENDED_CARD,
        busbar_a2a_codec::mounted_route(busbar_a2a_codec::ROUTE_EXTENDED_AGENT_CARD)
    );
    assert_eq!(
        T_PUSH,
        busbar_a2a_codec::mounted_route(busbar_a2a_codec::PUSH_PATH_SUFFIX)
    );
    assert_eq!(T_CARD, busbar_a2a_codec::WELL_KNOWN_CARD_PATH);
    assert_eq!(T_METADATA, busbar_a2a_codec::METADATA_PATH);
    assert_eq!(
        SERVICE,
        busbar_a2a_codec::GRPC_MOUNT_PATH.trim_start_matches('/')
    );
}

/// The surface passes the contract's own boot check.
///
/// Which is not a formality: it is what says no two operations are addressed the same way, no
/// operation is unreachable, and every template is in the grammar a mount matches against.
#[test]
fn the_surface_boots() {
    sfc::check_surface(&SURFACE).expect("the declared surface is well formed");
}

/// Every method name the plane's own vocabulary carries is reachable on the document binding, and
/// every document name the surface declares is one the vocabulary carries.
///
/// BOTH directions. One would let the surface declare a method the plane cannot decode (a caller is
/// told the operation exists and then that its shape is unsupported), and the other would let the
/// plane carry a method no binding reaches (an operation nothing can address).
#[test]
fn the_document_binding_and_the_method_table_are_the_same_set() {
    let mut declared: Vec<&str> = Vec::new();
    for operation in SURFACE.operations {
        for d in operation.dispatch {
            if let sfc::Dispatch::Document { name, .. } = d {
                declared.push(name);
            }
        }
    }
    declared.sort_unstable();
    let mut carried: Vec<&str> = ops::METHODS.iter().map(|r| r.method).collect();
    carried.sort_unstable();
    assert_eq!(
        declared, carried,
        "the document binding and the method table must name the same methods"
    );
}

/// Each method's operation class in the surface is the class the method table gives it.
#[test]
fn every_document_dispatch_carries_the_vocabularys_own_class() {
    for operation in SURFACE.operations {
        for d in operation.dispatch {
            let sfc::Dispatch::Document { name, .. } = d else {
                continue;
            };
            let row = ops::row_for(name).expect("a declared method is one the vocabulary carries");
            assert_eq!(
                row.op.as_str(),
                operation.op,
                "`{name}` is declared under `{}` and the vocabulary prices it as `{}`",
                operation.op,
                row.op.as_str()
            );
        }
    }
}

/// A streamed operation is streamed in BOTH tables.
///
/// The method table already says which operations hold their direction open, and the surface says it
/// again for the transport's benefit. Two statements of one fact is exactly the shape that drifts,
/// so it is pinned rather than trusted.
#[test]
fn the_answering_kind_agrees_with_the_method_table() {
    for operation in SURFACE.operations {
        for d in operation.dispatch {
            let sfc::Dispatch::Document { name, .. } = d else {
                continue;
            };
            let row = ops::row_for(name).expect("a declared method is one the vocabulary carries");
            let want = if row.streaming {
                sfc::Answering::Stream
            } else {
                sfc::Answering::Unary
            };
            assert_eq!(
                operation.answering, want,
                "`{name}` streams in one table and not the other"
            );
        }
    }
}

/// The framed binding's RPC names are the title-case spelling, one for one.
///
/// Stated as an assertion rather than as a comment because it is the whole reason the framed binding
/// needs no table of its own: a descriptor that gained a differently-named RPC would answer
/// `UNIMPLEMENTED` in production and be invisible here.
#[test]
fn every_framed_method_is_a_carried_method_name() {
    for operation in SURFACE.operations {
        for d in operation.dispatch {
            let sfc::Dispatch::Service { method, .. } = d else {
                continue;
            };
            let row =
                ops::row_for(method).expect("a framed RPC is a method the vocabulary carries");
            assert_eq!(row.wording, ops::Wording::Verb);
            assert_eq!(row.op.as_str(), operation.op);
        }
    }
}

/// Every operation class the plane declares is reachable somewhere on the surface.
#[test]
fn no_operation_class_is_unreachable() {
    for op in ops::OP_CLASSES {
        assert!(
            SURFACE.operations.iter().any(|o| o.op == op.as_str()),
            "`{}` is a declared operation class with no way to address it",
            op.as_str()
        );
    }
}

/// The surface declares exactly the operation classes the plane declares — no more.
#[test]
fn the_surface_invents_no_operation() {
    for operation in SURFACE.operations {
        assert!(
            ops::OP_CLASSES.iter().any(|c| c.as_str() == operation.op),
            "`{}` is addressed by the surface and is not a class this plane declares",
            operation.op
        );
    }
}

/// Every target this surface declares is one the plane's claims cover, and every credentialed row
/// sits under a claim that declares a scheme.
///
/// The claim decides whether a request reaches this plane at all; the surface decides what it means
/// once it has. A target present in one and absent from the other is a route mounted with no
/// audience check, or an audience check over a route nothing serves.
#[test]
fn every_target_sits_under_a_claim() {
    use busbar_contract::grammar::Selector;
    for operation in SURFACE.operations {
        for d in operation.dispatch {
            let sfc::Dispatch::Target { path, bar, .. } = d else {
                continue;
            };
            let claim = crate::claims::CLAIMS
                .iter()
                .find(|c| match c.selector {
                    Selector::ExactPath(p) => p == *path,
                    Selector::PathPattern(segs) => pattern_matches_template(segs, path),
                    _ => false,
                })
                .unwrap_or_else(|| panic!("`{path}` is served and no claim covers it"));
            let claimed_open = claim.scheme.is_none();
            assert_eq!(
                claimed_open,
                *bar == sfc::Bar::Open,
                "`{path}` is open on one side of the seam and credentialed on the other"
            );
        }
    }
}

/// The mounts of the document binding are claimed too.
#[test]
fn every_document_mount_sits_under_a_claim() {
    use busbar_contract::grammar::Selector;
    for binding in SURFACE.bindings {
        for mount in binding.mounts {
            assert!(
                crate::claims::CLAIMS
                    .iter()
                    .any(|c| matches!(c.selector, Selector::ExactPath(p) if p == *mount)),
                "`{mount}` is a declared mount and no claim covers it"
            );
        }
    }
}

/// Whether a claim's path pattern describes the same shape as a surface template.
///
/// The two grammars are different by design — a claim's is the contract's closed selector grammar,
/// a template's is the mount's — so this compares them segment by segment rather than by string.
fn pattern_matches_template(segs: &[busbar_contract::grammar::PathSeg], template: &str) -> bool {
    use busbar_contract::grammar::PathSeg;
    let want: Vec<&str> = template.split('/').filter(|s| !s.is_empty()).collect();
    if want.len() != segs.len() {
        return false;
    }
    segs.iter().zip(want).all(|(seg, got)| match seg {
        PathSeg::Lit(lit) => *lit == got,
        PathSeg::Var => got.starts_with('{') && got.ends_with('}'),
        // A tail segment swallows everything after it, which no template on this surface uses; a
        // claim that grew one would not be describing a template segment for segment, so the honest
        // answer is that this comparison does not apply rather than that it passed.
        PathSeg::Tail => false,
    })
}

/// A target resolves to the operation it addresses, captures and all.
#[test]
fn resolving_a_target_yields_the_operation_and_its_captures() {
    let (operation, _, captures) = sfc::resolve_target(
        &SURFACE,
        "/a2a/tasks/t-1/pushNotificationConfigs/c-9",
        "DELETE",
    )
    .expect("the deepest configuration template is served for DELETE");
    assert_eq!(operation.op, ops::OP_PUSH_CONFIG_DELETE.as_str());
    assert_eq!(captures.len(), 2);
    assert_eq!(captures[0].name, "id");
    assert_eq!(captures[0].value, "t-1");
    assert_eq!(captures[1].name, "config_id");
    assert_eq!(captures[1].value, "c-9");
}

/// One template, two methods, two operations — and the verb is what tells them apart.
#[test]
fn one_template_two_verbs_two_operations() {
    let get = sfc::resolve_target(&SURFACE, "/a2a/tasks/t-1", "GET").expect("a task is readable");
    let post =
        sfc::resolve_target(&SURFACE, "/a2a/tasks/t-1", "POST").expect("a task is cancellable");
    assert_eq!(get.0.op, ops::OP_TASK_GET.as_str());
    assert_eq!(post.0.op, ops::OP_TASK_CANCEL.as_str());
}

/// The collection is reached before the template that would also match it.
///
/// `/a2a/tasks` is an exact path and `/a2a/tasks/{id}` is a template; they do not overlap, but the
/// ORDER is the thing being asserted — a mount that sorted the list would answer the list operation
/// from the task template's row on some other protocol, and this is where that would be caught.
#[test]
fn the_declaration_order_is_the_matching_order() {
    let collection =
        sfc::resolve_target(&SURFACE, "/a2a/tasks", "GET").expect("the collection is listable");
    assert_eq!(collection.0.op, ops::OP_TASK_LIST.as_str());
    let configs = sfc::resolve_target(&SURFACE, "/a2a/tasks/t-1/pushNotificationConfigs", "GET")
        .expect("a task's configurations are listable");
    assert_eq!(configs.0.op, ops::OP_PUSH_CONFIG_LIST.as_str());
}

/// A document member's value resolves to its operation on the document binding.
#[test]
fn resolving_a_document_name_yields_the_operation() {
    for (name, want) in [
        ("message/send", ops::OP_MESSAGE_SEND),
        ("SendMessage", ops::OP_MESSAGE_SEND),
        ("tasks/resubscribe", ops::OP_TASK_SUBSCRIBE),
    ] {
        let (operation, _) = sfc::resolve_document(&SURFACE, BINDING_DOCUMENT, name)
            .unwrap_or_else(|| panic!("`{name}` is served on the document binding"));
        assert_eq!(operation.op, want.as_str());
    }
}

/// A framed call resolves by service and method.
#[test]
fn resolving_a_framed_call_yields_the_operation() {
    let (operation, _) = sfc::resolve_service(&SURFACE, SERVICE, "GetTask")
        .expect("the framed binding serves the task read");
    assert_eq!(operation.op, ops::OP_TASK_GET.as_str());
    assert!(
        sfc::resolve_service(&SURFACE, SERVICE, "NotAnRpc").is_none(),
        "a descriptor method this surface does not declare resolves to nothing"
    );
}

/// Both spellings of the mount are recognised.
#[test]
fn both_spellings_of_the_mount_are_a_mount() {
    assert!(sfc::binding_at(&SURFACE, "/a2a").is_some());
    assert!(sfc::binding_at(&SURFACE, "/a2a/").is_some());
    assert!(sfc::binding_at(&SURFACE, "/a2a?x=1").is_some());
    assert!(sfc::binding_at(&SURFACE, "/a2ax").is_none());
}

/// The three open surfaces are the three that are open, and nothing else is.
#[test]
fn exactly_three_addresses_are_open() {
    let open: Vec<&str> = SURFACE
        .operations
        .iter()
        .flat_map(|o| o.dispatch.iter())
        .filter_map(|d| match d {
            sfc::Dispatch::Target { path, bar, .. } if *bar == sfc::Bar::Open => Some(*path),
            _ => None,
        })
        .collect();
    assert_eq!(open, vec![T_METADATA, T_CARD, T_PUSH]);
    assert!(
        SURFACE
            .operations
            .iter()
            .flat_map(|o| o.dispatch.iter())
            .all(|d| !matches!(
                d,
                sfc::Dispatch::Document { bar, .. } | sfc::Dispatch::Service { bar, .. }
                    if *bar == sfc::Bar::Open
            )),
        "no document or framed address is open"
    );
}
