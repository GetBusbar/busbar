// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DUPLEX SURFACE KIND, over a surface that names no protocol.
//!
//! Beside the three request/answer kinds the battery next door exercises, and every cell here is
//! about the one thing that makes it a KIND rather than a spelling: a mount can tell a session mount
//! from an endpoint, from the declaration alone, before it upgrades anything.
//!
//! Every fixture is deliberately made up, for the reason `wire_surface.rs`'s own are. A duplex
//! surface borrowed from a real protocol would leave "this vocabulary describes any session mount"
//! and "this vocabulary happens to fit the one protocol it was written beside" indistinguishable —
//! and the second is precisely the failure the kind exists to end.

use busbar_contract_transport::surface::{
    check_surface, duplex_bar, duplex_binding_at, mount_is_wellformed, Answering, Bar, BindingDecl,
    Capture, Dispatch, Operation, SurfaceError, WireSurface,
};

/// The wire that carries the fixtures. A made-up registry key: no transport in this tree is named.
const WIRE: &str = "duplex-wire";

/// The binding a session is opened on.
const SESS: &str = "sess";

/// A second binding on the SAME wire that is NOT a session mount: an envelope endpoint.
///
/// The whole point of the pair. A duplex wire addressing by transport key and path alone would open
/// a session here, because this binding is carried by that wire and declares a mount.
const NOT_SESS: &str = "not-sess";

/// A third binding on the same wire whose mount is a PATTERN with a capture in it.
///
/// The case a session mount could not express before and needed to: a published URL with an
/// identifier in it. A session declares no target template — after the upgrade this wire has no
/// target at all — so the binding's own mount is the only place that identifier is ever written
/// down, and a vocabulary of literals would have forced either a different URL or one literal per
/// live call.
const KEYED: &str = "keyed";

const D_SESSION: &[Dispatch] = &[
    Dispatch::Duplex {
        binding: SESS,
        method: "GET",
        bar: Bar::Credential,
    },
    Dispatch::Duplex {
        binding: KEYED,
        method: "GET",
        bar: Bar::Credential,
    },
];

const D_POSTED: &[Dispatch] = &[Dispatch::Document {
    binding: NOT_SESS,
    method: "POST",
    member: "method",
    name: "posted",
    bar: Bar::Open,
}];

const SURFACE: WireSurface = WireSurface {
    bindings: &[
        BindingDecl {
            name: SESS,
            transport: WIRE,
            mounts: &["/open/here"],
        },
        BindingDecl {
            name: KEYED,
            transport: WIRE,
            mounts: &["/open/keyed/{leg}/frames"],
        },
        BindingDecl {
            name: NOT_SESS,
            transport: WIRE,
            mounts: &["/posted/here"],
        },
    ],
    operations: &[
        Operation {
            op: "session",
            dispatch: D_SESSION,
            answering: Answering::Stream,
            request_media: "application/json",
            response_media: "application/json",
        },
        Operation {
            op: "posted",
            dispatch: D_POSTED,
            answering: Answering::Unary,
            request_media: "application/json",
            response_media: "application/json",
        },
    ],
};

#[test]
fn a_declared_duplex_surface_boots() {
    check_surface(&SURFACE).expect("this duplex surface is well formed");
}

/// The mount a session is opened at is addressed, and comes back with the bar its own row declared.
#[test]
fn a_duplex_mount_is_addressed_on_its_own_wire() {
    let (binding, bar, captures) =
        duplex_binding_at(&SURFACE, WIRE, "/open/here").expect("this is a declared session mount");
    assert_eq!(binding.name, SESS);
    assert_eq!(bar, Bar::Credential);
    // An ALL-LITERAL mount captures nothing, which is what every mount declared before patterns
    // existed is. A walk that produced a capture here would be one that had started reading segments
    // of a literal as though somebody had written braces round them.
    assert_eq!(captures, Vec::new());
}

/// A query is not part of the path, so a client that appended one still opens a session.
#[test]
fn a_duplex_mount_is_addressed_past_a_query() {
    let got = duplex_binding_at(&SURFACE, WIRE, "/open/here?model=x");
    assert_eq!(got.map(|(b, _, _)| b.name), Some(SESS));
}

/// THE CELL THE KIND EXISTS FOR: a binding of this very wire, at a declared mount, that declares no
/// duplex row is not a place a session may be opened.
///
/// A wire that addressed by transport key and path alone would upgrade here, and the caller would
/// hold a session on an endpoint whose declaration says it answers one posted document with one
/// answer. It is refused because the surface never said a session could be opened at it.
#[test]
fn a_request_answer_binding_is_not_a_session_mount() {
    assert!(duplex_binding_at(&SURFACE, WIRE, "/posted/here").is_none());
    assert_eq!(duplex_bar(&SURFACE, NOT_SESS), None);
}

/// A session mount belongs to the wire that declared it, and not to whichever wire asked.
#[test]
fn a_duplex_mount_of_another_wire_is_not_this_wires() {
    assert!(duplex_binding_at(&SURFACE, "some-other-wire", "/open/here").is_none());
}

/// A target no binding declares is nowhere, on this kind as on the others.
#[test]
fn an_undeclared_target_opens_nothing() {
    assert!(duplex_binding_at(&SURFACE, WIRE, "/nowhere").is_none());
}

/// The bar fails closed across rows: one credential row on a binding is the binding's answer.
#[test]
fn the_strictest_duplex_bar_on_a_binding_wins() {
    const MIXED: &[Dispatch] = &[
        Dispatch::Duplex {
            binding: SESS,
            method: "GET",
            bar: Bar::Open,
        },
        Dispatch::Duplex {
            binding: SESS,
            method: "CONNECT",
            bar: Bar::Credential,
        },
    ];
    const S: WireSurface = WireSurface {
        bindings: &[BindingDecl {
            name: SESS,
            transport: WIRE,
            mounts: &["/open/here"],
        }],
        operations: &[Operation {
            op: "session",
            dispatch: MIXED,
            answering: Answering::Stream,
            request_media: "application/json",
            response_media: "application/json",
        }],
    };
    check_surface(&S).expect("two methods on one binding are two addresses");
    assert_eq!(duplex_bar(&S, SESS), Some(Bar::Credential));
}

/// A session mount with nowhere to be opened is refused at boot, not advertised and unreachable.
#[test]
fn a_duplex_binding_with_no_mount_is_refused() {
    const S: WireSurface = WireSurface {
        bindings: &[BindingDecl {
            name: SESS,
            transport: WIRE,
            mounts: &[],
        }],
        operations: &[Operation {
            op: "session",
            dispatch: D_SESSION,
            answering: Answering::Stream,
            request_media: "application/json",
            response_media: "application/json",
        }],
    };
    assert_eq!(
        check_surface(&S),
        Err(SurfaceError::NoDuplexMount {
            op: "session",
            binding: SESS,
        })
    );
}

/// A session that says it answers once is a session cut at its first answer, and does not boot.
#[test]
fn a_duplex_row_on_a_unary_operation_is_refused() {
    const S: WireSurface = WireSurface {
        bindings: &[BindingDecl {
            name: SESS,
            transport: WIRE,
            mounts: &["/open/here"],
        }],
        operations: &[Operation {
            op: "session",
            dispatch: D_SESSION,
            answering: Answering::Unary,
            request_media: "application/json",
            response_media: "application/json",
        }],
    };
    assert_eq!(
        check_surface(&S),
        Err(SurfaceError::DuplexNotStreaming { op: "session" })
    );
}

/// A duplex row naming a binding nobody declared is the same refusal a document row gets.
#[test]
fn a_duplex_row_on_an_undeclared_binding_is_refused() {
    const S: WireSurface = WireSurface {
        bindings: &[BindingDecl {
            name: NOT_SESS,
            transport: WIRE,
            mounts: &["/posted/here"],
        }],
        operations: &[Operation {
            op: "session",
            dispatch: D_SESSION,
            answering: Answering::Stream,
            request_media: "application/json",
            response_media: "application/json",
        }],
    };
    assert_eq!(
        check_surface(&S),
        Err(SurfaceError::UnknownBinding {
            op: "session",
            binding: SESS,
        })
    );
}

/// Two duplex rows for one binding and one method are two credential bars for one upgrade, and
/// which one answered would be whichever row the walk reached first.
#[test]
fn two_duplex_rows_at_one_address_are_refused() {
    const TWICE: &[Dispatch] = &[
        Dispatch::Duplex {
            binding: SESS,
            method: "GET",
            bar: Bar::Credential,
        },
        Dispatch::Duplex {
            binding: SESS,
            method: "GET",
            bar: Bar::Open,
        },
    ];
    const S: WireSurface = WireSurface {
        bindings: &[BindingDecl {
            name: SESS,
            transport: WIRE,
            mounts: &["/open/here"],
        }],
        operations: &[Operation {
            op: "session",
            dispatch: TWICE,
            answering: Answering::Stream,
            request_media: "application/json",
            response_media: "application/json",
        }],
    };
    assert_eq!(
        check_surface(&S),
        Err(SurfaceError::DuplicateAddress { op: "session" })
    );
}

/// A binding name and a service name are two namespaces, so a duplex row does not collide with a
/// service row that happens to be spelled the same way.
#[test]
fn a_duplex_address_does_not_collide_with_a_service_of_the_same_name() {
    const BOTH: &[Dispatch] = &[
        Dispatch::Duplex {
            binding: SESS,
            method: "GET",
            bar: Bar::Credential,
        },
        Dispatch::Service {
            service: SESS,
            method: "GET",
            bar: Bar::Credential,
        },
    ];
    const S: WireSurface = WireSurface {
        bindings: &[BindingDecl {
            name: SESS,
            transport: WIRE,
            mounts: &["/open/here"],
        }],
        operations: &[Operation {
            op: "session",
            dispatch: BOTH,
            answering: Answering::Stream,
            request_media: "application/json",
            response_media: "application/json",
        }],
    };
    check_surface(&S).expect("a binding and a service are not one namespace");
}

/// The kind is readable off a row by its arm, and the one bar reader answers for every kind.
#[test]
fn a_row_says_whether_it_opens_a_session() {
    assert!(matches!(D_SESSION[0], Dispatch::Duplex { .. }));
    assert!(!matches!(D_POSTED[0], Dispatch::Duplex { .. }));
    assert_eq!(D_SESSION[0].bar(), Bar::Credential);
}

// ── mount PATTERNS ──────────────────────────────────────────────────────────────────────────────

/// A KEYED MOUNT IS ADDRESSED, AND HANDS BACK WHAT IT CAPTURED.
///
/// The whole reason the mount grammar has a capture in it. Without the third value the mount would
/// hold a session opened at a URL with an identifier in it and have no way to say which one, and the
/// composition above would have to re-parse the path against a second copy of the pattern — the
/// second copy being the one that answers a stranger's session about somebody else's call.
#[test]
fn a_keyed_mount_is_addressed_and_yields_its_capture() {
    let (binding, bar, captures) = duplex_binding_at(&SURFACE, WIRE, "/open/keyed/7f3a/frames")
        .expect("a pattern with a capture is a declared session mount");
    assert_eq!(binding.name, KEYED);
    assert_eq!(bar, Bar::Credential);
    assert_eq!(
        captures,
        vec![Capture {
            name: "leg",
            value: "7f3a"
        }]
    );
}

/// The query is cut before the pattern is matched, on a keyed mount as on a literal one.
#[test]
fn a_keyed_mount_is_addressed_past_a_query() {
    let (binding, _, captures) =
        duplex_binding_at(&SURFACE, WIRE, "/open/keyed/7f3a/frames?since=4")
            .expect("a query is not part of the path");
    assert_eq!(binding.name, KEYED);
    assert_eq!(captures[0].value, "7f3a");
}

/// A CAPTURE IS ONE WHOLE, NON-EMPTY SEGMENT, and neither more nor fewer.
///
/// The three ways a caller could try to be somewhere else. An empty segment would reach a session
/// with no identifier at all, which is the shape that turns a missing argument into a scan of
/// everything; a deeper path is a different route; and the literal tail after the capture still has
/// to be there, or the pattern is a prefix claim over a subtree nobody declared.
#[test]
fn a_capture_is_one_whole_non_empty_segment() {
    for target in [
        "/open/keyed//frames",
        "/open/keyed/7f3a/deeper/frames",
        "/open/keyed/7f3a",
        "/open/keyed/7f3a/frames/",
    ] {
        assert!(
            duplex_binding_at(&SURFACE, WIRE, target).is_none(),
            "`{target}` is not this pattern"
        );
    }
}

/// THE GRAMMAR A MOUNT IS HELD TO, and the one rule it relaxes against a target template.
///
/// The relaxed rule is the empty segment: `/a2a/` is the spelling an HTTP client resolving `/`
/// against a base sends, it has to answer, and it ends in an empty segment. Everything else is held
/// — a mount starts at the root, a capture is a whole segment with a name in it, and a brace that
/// is not a whole capture is a capture somebody meant to write and did not.
#[test]
fn the_mount_grammar_admits_a_trailing_separator_and_refuses_a_half_written_capture() {
    for good in ["/a2a", "/a2a/", "/v1/x/{id}", "/{a}/{b}", "/"] {
        assert!(mount_is_wellformed(good), "`{good}` is a mount");
    }
    for bad in ["a2a", "/v1/{}/x", "/v1/{id/x", "/v1/id}/x", "/v1/a{id}/x"] {
        assert!(!mount_is_wellformed(bad), "`{bad}` is not a mount");
    }
}

/// A MALFORMED MOUNT IS A BOOT REFUSAL, not a route that quietly answers nothing.
#[test]
fn a_malformed_mount_pattern_is_refused_at_boot() {
    const BAD: WireSurface = WireSurface {
        bindings: &[BindingDecl {
            name: SESS,
            transport: WIRE,
            mounts: &["/open/{}/here"],
        }],
        operations: &[Operation {
            op: "session",
            dispatch: &[Dispatch::Duplex {
                binding: SESS,
                method: "GET",
                bar: Bar::Credential,
            }],
            answering: Answering::Stream,
            request_media: "application/json",
            response_media: "application/json",
        }],
    };
    assert_eq!(
        check_surface(&BAD),
        Err(SurfaceError::MalformedTemplate {
            path: "/open/{}/here"
        })
    );
}
