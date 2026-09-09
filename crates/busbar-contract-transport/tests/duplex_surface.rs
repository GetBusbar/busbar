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
    check_surface, duplex_bar, duplex_binding_at, Answering, Bar, BindingDecl, Dispatch, Operation,
    SurfaceError, WireSurface,
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

const D_SESSION: &[Dispatch] = &[Dispatch::Duplex {
    binding: SESS,
    method: "GET",
    bar: Bar::Credential,
}];

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
    let (binding, bar) =
        duplex_binding_at(&SURFACE, WIRE, "/open/here").expect("this is a declared session mount");
    assert_eq!(binding.name, SESS);
    assert_eq!(bar, Bar::Credential);
}

/// A query is not part of the path, so a client that appended one still opens a session.
#[test]
fn a_duplex_mount_is_addressed_past_a_query() {
    let got = duplex_binding_at(&SURFACE, WIRE, "/open/here?model=x");
    assert_eq!(got.map(|(b, _)| b.name), Some(SESS));
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

/// The kind is readable off a row by name, so no mount has to match on the arm and grow a fourth
/// reading of what "duplex" means.
#[test]
fn a_row_says_whether_it_opens_a_session() {
    assert!(D_SESSION[0].is_duplex());
    assert!(!D_POSTED[0].is_duplex());
    assert_eq!(D_SESSION[0].bar(), Bar::Credential);
}
