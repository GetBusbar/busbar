// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECLARED SURFACE, HELD TO THE CLAIMS IT IS SERVED UNDER.
//!
//! Every cell here is about a disagreement that would be SILENT. A mount the plane's own claim would
//! not admit is a route the kernel never sends a session to; a mount two dialects both admit is a
//! session served by whichever one the walk reached first; a bar that came out open is a stranger
//! opening a session that can never be resolved to anybody; and a media type that drifted is the
//! wrong `Content-Type` on every frame this node writes back for the life of the session.
//!
//! The claim side of each of these is READ rather than restated: the assertions run the plane's own
//! [`claims::matches_selector`] over the plane's own [`claims::DIALECT_CLAIMS`], so a claim edited
//! without the surface beside it is what turns these red.

use busbar_contract::transport::surface::{check_surface, Answering, Bar, Dispatch};

use crate::claims;
use crate::dialect;
use crate::surface::{
    BINDING_CARRIER, BINDING_GEMINI_LIVE, BINDING_OPENAI_REALTIME, MEDIA_JSON, SURFACE,
};

/// The dialect a binding name belongs to, by the dialect's own word for itself.
///
/// A NAME, not a row: the carrier's row arrives at boot from its own crate and is not linked in
/// this test process, and a binding is matched against the claim table, which is keyed by name.
fn dialect_of(binding: &str) -> &'static str {
    claims::DIALECT_CLAIMS
        .iter()
        .map(|c| c.dialect)
        .find(|name| *name == binding)
        .unwrap_or_else(|| panic!("the binding `{binding}` is not one of this plane's dialects"))
}

/// THE BOOT CHECK THE MOUNT RUNS, RUN HERE FIRST.
///
/// A surface that would be refused at boot is a node that does not start, and finding that out from
/// a listener is finding it out from the worst possible place. Every rule the check holds —
/// addressable operations, declared bindings, no two rows at one address — is a rule this
/// declaration is subject to.
#[test]
fn the_declared_surface_passes_the_boot_check() {
    assert_eq!(check_surface(&SURFACE), Ok(()));
}

/// THIS PLANE DECLARES A DUPLEX ROUTE, AND DECLARES NOTHING ELSE.
///
/// Two halves, and the second is the one that keeps the declaration from quietly growing a wire
/// shape nobody chose. Every row here opens a SESSION, because a session is the only thing this
/// plane serves: a [`Dispatch::Target`] row would be a request-and-answer route with a request and
/// a response media type, and this plane claims no such route — the two it used to claim are
/// `busbar-plane-llm`'s speech routes now.
///
/// The first half is that the generic walk a duplex wire addresses with — the same
/// `duplex_binding_at` the mount calls, given this plane's own registry key — reaches every mount
/// this plane declared. A declaration a wire cannot address is an endpoint that answers nothing.
#[test]
fn every_declared_row_opens_a_session_and_every_mount_is_addressable_as_one() {
    for op in SURFACE.operations {
        for d in op.dispatch {
            assert!(
                matches!(d, Dispatch::Duplex { .. }),
                "this plane declares its duplex route and nothing else; `{}` carries a row that is \
                 not a session",
                op.op
            );
        }
    }
    for binding in SURFACE.bindings {
        for mount in binding.mounts {
            let (addressed, bar) = busbar_contract::transport::surface::duplex_binding_at(
                &SURFACE,
                claims::WS_TRANSPORT,
                mount,
            )
            .unwrap_or_else(|| {
                panic!("`{mount}` is a declared mount and a duplex wire must address it")
            });
            assert_eq!(addressed.name, binding.name);
            assert_eq!(bar, Bar::Credential);
        }
    }
}

/// EVERY DECLARED MOUNT IS ITS OWN DIALECT'S CLAIM, AND NOBODY ELSE'S.
///
/// Both halves, because each on its own is satisfiable by something wrong. A mount no claim matches
/// is a route the kernel never hands this plane a session on — the surface would advertise an
/// endpoint the front door does not admit. A mount that TWO dialects' claims match is worse: the
/// session opens under one dialect's binding and is routed under whichever claim the declaration
/// order reached first, and the two are only the same answer by luck.
#[test]
fn each_mount_is_matched_by_exactly_its_own_dialect_claim() {
    for binding in SURFACE.bindings {
        let own = dialect_of(binding.name);
        assert!(
            !binding.mounts.is_empty(),
            "the binding `{}` declares no mount, so no session could ever be opened on it",
            binding.name
        );
        for mount in binding.mounts {
            let matched: Vec<&'static str> = claims::DIALECT_CLAIMS
                .iter()
                .filter(|c| claims::matches_selector(&c.claim.selector, mount))
                .map(|c| c.dialect)
                .collect();
            assert_eq!(
                matched,
                vec![own],
                "the mount `{mount}` on binding `{}` must be admitted by its own dialect's claim \
                 and by no other",
                binding.name
            );
        }
    }
}

/// THE CLAIM'S OWN TRANSPORT KEY, NOT A SECOND COPY OF THE WORD.
///
/// The registry key a binding is carried on decides which mount is responsible for it. A binding
/// declared against a key no claim of this plane names would be mounted by a transport the kernel
/// never routes this plane's sessions through, and the endpoint would answer nothing while looking
/// entirely well-formed here.
#[test]
fn every_binding_is_carried_on_the_transport_its_claim_is_declared_against() {
    for binding in SURFACE.bindings {
        let own = dialect_of(binding.name);
        let claim = claims::DIALECT_CLAIMS
            .iter()
            .find(|c| c.dialect == own)
            .expect("every declared binding names a dialect this plane claims");
        assert_eq!(
            binding.transport, claim.claim.transport,
            "the binding `{}` must be carried on the same registry key its claim is declared \
             against",
            binding.name
        );
    }
}

/// THE THREE DUPLEX DIALECTS, AND ONLY THEY, HAVE A BINDING.
///
/// Three dialects, three bindings, three claims: the set is closed and stating it here is what
/// makes a later addition a decision somebody took rather than a row that appeared.
///
/// The membership test is against the CLAIM TABLE and not against `dialect`'s registry, and that is
/// the shape rather than a convenience: two of the three rows are declared by this crate and the
/// third arrives at boot from its own crate, so a registry lookup in this crate's own test process
/// answers `None` for the carrier — correctly, because the carrier's reader is not linked here. A
/// binding is a declaration about what this plane SERVES, and what it serves is what it claims.
#[test]
fn exactly_the_duplex_dialects_are_bound() {
    let mut bound: Vec<&str> = SURFACE.bindings.iter().map(|b| b.name).collect();
    bound.sort_unstable();
    let mut expected = vec![
        BINDING_CARRIER,
        BINDING_GEMINI_LIVE,
        BINDING_OPENAI_REALTIME,
    ];
    expected.sort_unstable();
    assert_eq!(bound, expected);
    for binding in SURFACE.bindings {
        let claimed = claims::DIALECT_CLAIMS
            .iter()
            .find(|c| c.dialect == binding.name)
            .expect("a bound dialect is a claimed dialect");
        assert_eq!(
            claimed.claim.transport,
            claims::WS_TRANSPORT,
            "a session binding is a duplex binding, and every duplex dialect of this plane is \
             claimed on the one duplex transport it declares"
        );
    }
}

/// EVERY BINDING IS BEHIND A CREDENTIAL, AND THE MOUNT READS IT AS ONE.
///
/// A session presents a credential once, on the upgrade, and never again. The bar is therefore the
/// ONLY moment this node can refuse an unauthenticated stranger on a wire that still has a status
/// line, and a row that came out [`Bar::Open`] would open the session and refuse every unit on it
/// instead — a worse answer, arrived at later, with nowhere left to put it.
#[test]
fn both_bindings_demand_a_credential_at_the_upgrade() {
    for binding in SURFACE.bindings {
        let rows: Vec<Bar> = SURFACE
            .operations
            .iter()
            .flat_map(|op| op.dispatch)
            .filter_map(|d| match d {
                // The DUPLEX rows and only those. A document row on one of these bindings would be
                // a request this session will never carry, and reading a bar off one would be
                // reading the credential rule for an upgrade out of a row about a posted document.
                Dispatch::Duplex {
                    binding: b, bar, ..
                } if *b == binding.name => Some(*bar),
                _ => None,
            })
            .collect();
        assert!(
            !rows.is_empty(),
            "the binding `{}` carries no dispatch, so a mount would read neither its bar nor its \
             media type off the declaration",
            binding.name
        );
        assert!(
            rows.iter().all(|bar| *bar == Bar::Credential),
            "every row of `{}` must demand a credential",
            binding.name
        );
        // A bound session presents its credential ONCE, at the upgrade, and the declaration says
        // so on the dialect's own row. Asserted only where the row is reachable: the carrier's row
        // is in its own crate, which is not linked here, and that crate asserts its own.
        if let Some(row) = dialect::dialect(dialect_of(binding.name)) {
            assert!(
                row.authenticates_from_session,
                "a bound session's dialect authenticates once at the open"
            );
        }
    }
}

/// A SESSION ANSWERS IN A RUN OF FRAMES, IN THE DECLARED MEDIA TYPE, IN BOTH DIRECTIONS.
///
/// [`Answering::Unary`] would tell a mount the direction is finished after the first frame it wrote,
/// which cuts a live session at its first answer. And the media type is what a mount puts on every
/// frame it writes back for the whole life of that session, so one wrong string here is not one
/// wrong response.
#[test]
fn the_session_operation_streams_json_both_ways() {
    for op in SURFACE.operations {
        assert_eq!(op.answering, Answering::Stream);
        assert_eq!(op.request_media, MEDIA_JSON);
        assert_eq!(op.response_media, MEDIA_JSON);
    }
}
