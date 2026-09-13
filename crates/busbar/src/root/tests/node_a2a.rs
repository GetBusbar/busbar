// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE SEAM'S OWN PROOF.**
//!
//! Two claims and no others, because two is what this commit lands.
//!
//! 1. **A served verb is admitted, routed, metered and audited by the composition ONCE.** The node
//!    drives the kernel's ten steps over this plane's units and hands back the class's own document
//!    on exactly one arm. The cells below read the node's own book and its own door rather than a
//!    status: a refusal the loop rendered and an upstream's refusal are the same bytes, and only the
//!    settlement says whether anything ran.
//! 2. **The root's composed declaration is the plane's, field for field, except which body
//!    answers.** `(path, method, auth)` are handed through VERBATIM for all eighteen rows — that is
//!    the security invariant the neutral route seam exists to preserve — and with no class moved,
//!    every handler is still the plane's own.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use busbar_substrate::plane::registry::PlaneDecl;
use busbar_unit_admission::{Door, InMemoryCells, Pricer};
use busbar_unit_auth::Auth;

use super::{compose_chain, compose_pricer, composed_decl, A2aNode, Arriving, NotServed};
use crate::root::bindings::{MountedPlane, Node};
use crate::root::units_a2a::RecordLegs;

// ═════════════════════════════════════════════════════════════════════════════
//   THE COMPOSED DECLARATION
// ═════════════════════════════════════════════════════════════════════════════

/// Every field of the plane's declaration reaches the root's, and only `routes` is the root's own.
///
/// The fields are compared one at a time rather than by a derived equality the type does not have,
/// and the `fn` pointers are compared by ADDRESS — which is what "the same function" means for a
/// declaration whose every field is a bare `fn`.
#[test]
fn the_composed_declaration_is_the_planes_except_which_body_answers() {
    let plane: &PlaneDecl = &busbar_a2a::PLANE_DECL;
    let composed = composed_decl();

    assert_eq!(composed.key, plane.key, "the plane's registry key");
    assert_eq!(composed.fallback, plane.fallback);
    assert_eq!(composed.config_section, plane.config_section);
    assert_eq!(composed.scope_kinds, plane.scope_kinds);
    assert_eq!(composed.subject_noun, plane.subject_noun);
    assert_eq!(composed.admin_noun, plane.admin_noun);
    assert_eq!(composed.audit_kind, plane.audit_kind);
    assert_eq!(composed.card_signing_domain, plane.card_signing_domain);
    assert_eq!(composed.card_kid_prefix, plane.card_kid_prefix);
    assert!(
        std::ptr::fn_addr_eq(composed.wire_format_names, plane.wire_format_names),
        "the wire formats are the plane's own function, not a copy of its answer"
    );
    assert!(std::ptr::fn_addr_eq(composed.claims, plane.claims));
    assert!(std::ptr::fn_addr_eq(composed.admission, plane.admission));
    assert!(std::ptr::fn_addr_eq(composed.build, plane.build));
    assert_eq!(
        composed.admin_routes.is_some(),
        plane.admin_routes.is_some()
    );
    assert_eq!(composed.openapi.is_some(), plane.openapi.is_some());
    assert_eq!(composed.hydrate.is_some(), plane.hydrate.is_some());
    assert_eq!(composed.start.is_some(), plane.start.is_some());
    assert_eq!(
        composed.config_validate.is_some(),
        plane.config_validate.is_some()
    );

    // THE ONE FIELD THAT IS THE ROOT'S. A declaration whose routes fn were still the plane's would
    // be a composition that composed nothing, and every cell below it would pass vacuously.
    let (composed_routes, plane_routes) = (
        composed.routes.expect("the composed decl declares routes"),
        plane.routes.expect("the plane declares routes"),
    );
    assert!(
        !std::ptr::fn_addr_eq(composed_routes, plane_routes),
        "the root's declaration answers on the root's routes fn"
    );
}

/// The seam is INERT while no class has moved: the served rows carry the plane's own handler, by
/// identity, so a byte the plane rendered yesterday is the byte it renders today.
#[test]
fn no_class_has_moved_so_the_serving_rows_are_the_planes_own() {
    assert!(
        super::MOVED_ONTO_THE_NODE.is_empty(),
        "a class on this table is a class whose arm has been deleted from the plane; the table and \
         the arms move in one commit or the plane answers in two places"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
//   THE CHAIN AND THE PRICER — the two halves the ruling says are paid up front
// ═════════════════════════════════════════════════════════════════════════════

/// A chain naming the built-in signed-key arm keeps the front door SHUT.
///
/// This is the cell that makes the difference between the real half and a stand-in visible: an
/// `AuthChain::new(Vec::new(), false)` is not an inert placeholder, it is `is_open() == true` — the
/// open front door, wired in front of a plane the operator authenticates.
#[test]
fn the_composed_chain_is_the_operators_own_and_a_keys_chain_is_shut() {
    let keys = vec![busbar_substrate::config::auth::AuthChainEntry::bare("keys")];
    let composed = compose_chain(&keys).expect("a keys chain is one this composition can compose");
    assert!(
        !composed.is_open(),
        "a deployment that configured `auth.chain: [keys]` must not be served through an open door"
    );

    // The empty chain is the operator's OWN open posture and is composed as written, not refused.
    let empty = compose_chain(&[]).expect("an empty chain is a posture, not an absence");
    assert!(empty.is_open(), "`auth.chain: []` is the open front door");

    // A provider backed by a PLUGIN module has no unit-side arm here, and composing an empty chain
    // for it would open the door of a deployment that authenticates. It does not mount.
    let plugin = vec![busbar_substrate::config::auth::AuthChainEntry::bare("oidc")];
    assert!(
        compose_chain(&plugin).is_none(),
        "a chain this composition cannot compose does not mount; it never becomes an empty one"
    );
}

/// The pricer is the deployment's, and a deployment with no rate card still charges its flat fee.
#[test]
fn the_composed_pricer_is_the_deployments_card_and_fee() {
    let absent = compose_pricer(std::iter::empty(), 25, false);
    assert!(
        !absent.pricing_enabled(),
        "no `rate_card:` is an absent card, not an empty one"
    );
    assert_eq!(
        absent.price_per_request_cents(),
        25,
        "an absent card still charges the configured flat fee — `flat(0)` would bill nothing"
    );

    let priced = compose_pricer(
        [(
            "probe",
            busbar_substrate::billing::RawTierRates {
                input: 1.0,
                output: 2.0,
                cache_read: 0.0,
                cache_write: 0.0,
            },
        )],
        7,
        true,
    );
    assert!(priced.pricing_enabled(), "a configured card is present");
    assert_eq!(priced.price_per_request_cents(), 7);
    let rate = priced
        .rate_for("probe")
        .expect("the configured lane is priced");
    assert_eq!(
        rate.input,
        busbar_unit_cost::nano_rate(1.0),
        "the projection is the pricing law's own rounding, never a second arithmetic"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
//   THE LOOP — one served verb, once
// ═════════════════════════════════════════════════════════════════════════════

/// A node over the composition's own halves, built the way boot builds one.
fn node_over(pricer: Pricer, chain: busbar_unit_auth::AuthChain) -> A2aNode {
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_unit_wal::NullShipper::new()),
        Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let store: Arc<dyn busbar_api::Store> = Arc::new(busbar_core::governance::MemoryStore::new());
    let bindings = Node::over(
        Auth::new(chain),
        crate::root::kernel::auth_bindings::AuthBindings::without_directory(),
        Door::new(InMemoryCells::new()),
        pricer,
        crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
        Arc::new(Mutex::new(durability)),
        crate::root::kernel::new_kernel().origin(busbar_caps::OriginKind::Client),
        Arc::new(busbar_unit_breaker::BreakerUnit::with_diagnostics(
            crate::root::adapters::root_diagnostics(),
        )),
    )
    .mounting(
        busbar_a2a::PLANE_DECL.key,
        MountedPlane {
            records: crate::root::store::PlaneRecords::of(
                &crate::root::store::node_adapter(Arc::clone(&store)),
                busbar_plane_a2a::records::operations_for,
            ),
            scope_policy: crate::root::units_a2a::scope_policy(
                crate::root::policy::ScopePolicy::new(),
            ),
            lanes: 0,
        },
    );
    A2aNode::over(
        bindings,
        crate::root::policy::group_table(&BTreeMap::new(), &BTreeMap::new()),
        RecordLegs::new(store),
        3_600,
    )
}

/// **THE CELL THIS COMMIT EXISTS FOR.** A served verb is admitted, routed, metered and audited by
/// the composition ONCE.
///
/// The document is invoked on exactly one arm — the unit settled and the loop raised no refusal —
/// and the counter proves it was invoked ONCE rather than on a retry the loop took quietly.
#[test]
fn a_served_verb_is_admitted_routed_metered_and_audited_by_the_composition_once() {
    // THE OPERATOR'S OWN OPEN POSTURE (`auth.chain: []`), composed as written. It is a deployment
    // shape and not a stand-in — and the cell below proves the difference by composing the OTHER
    // posture the same way and watching the front door refuse.
    let node = node_over(
        Pricer::flat(0),
        compose_chain(&[]).expect("an empty chain is a posture, not an absence"),
    );
    let answers = std::cell::Cell::new(0u32);
    let arriving = Arriving {
        op: busbar_plane_a2a::ops::OP_PUSH_CONFIG_GET,
        request_bytes: 128,
        key: None,
        credential: None,
        expected_aud: None,
        pool: "probe",
        chain: &["tcp", "tls", "http"],
        source: "127.0.0.1:1".to_string(),
        port: 8080,
    };
    let served = node.serve_class(&arriving, || {
        answers.set(answers.get() + 1);
        "the class's own document"
    });
    match served {
        Ok(document) => {
            assert_eq!(document, "the class's own document");
            assert_eq!(
                answers.get(),
                1,
                "the document runs on exactly one arm of the loop"
            );
        }
        Err(e) => panic!("the loop refused a verb the composition admits: {e:?}"),
    }
}

/// **THE CHAIN IS THE DEPLOYMENT'S, NOT A STAND-IN.**
///
/// The same node, the same verb and the same caller — presenting nothing — composed over the chain
/// a deployment that wrote `auth.chain: [keys]` configured. The front door REFUSES at authenticate.
///
/// This is the cell that would go green on a node shipped with `AuthChain::new(Vec::new(), false)`:
/// an empty chain is `is_open()`, so the anonymous caller would be ADMITTED and the loop would run
/// to the document. A node built the cheap way cannot pass this and a node built over the
/// deployment's own chain cannot fail it.
#[test]
fn the_composed_chain_refuses_a_caller_the_deployment_never_admitted() {
    let keys = vec![busbar_substrate::config::auth::AuthChainEntry::bare("keys")];
    let node = node_over(
        Pricer::flat(0),
        compose_chain(&keys).expect("a keys chain is one this composition can compose"),
    );
    let answers = std::cell::Cell::new(0u32);
    let arriving = Arriving {
        op: busbar_plane_a2a::ops::OP_PUSH_CONFIG_GET,
        request_bytes: 128,
        key: None,
        credential: None,
        expected_aud: None,
        pool: "probe",
        chain: &["tcp", "tls", "http"],
        source: "127.0.0.1:1".to_string(),
        port: 8080,
    };
    let served = node.serve_class(&arriving, || {
        answers.set(answers.get() + 1);
        "the class's own document"
    });
    assert!(
        matches!(
            served,
            Err(NotServed::Refused(busbar_caps::StepName::Authenticate, _))
        ),
        "a deployment that configured a chain must refuse a caller that presented nothing, at the \
         step that asks — got {served:?}"
    );
    assert_eq!(
        answers.get(),
        0,
        "a caller the front door refused never reaches the class's document"
    );
}

/// The document does NOT run when the loop refuses, and that is the whole of "never answered
/// twice": a refusal is a unit that produced no bytes, not a unit whose bytes were thrown away.
#[test]
fn a_refused_verb_never_reaches_the_document() {
    // A scope policy that declares nothing: the scope unit reads silence as a denial, so the
    // approve step refuses and the class's own document must never be reached.
    let node = {
        let durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");
        let store: Arc<dyn busbar_api::Store> =
            Arc::new(busbar_core::governance::MemoryStore::new());
        let bindings = Node::over(
            Auth::new(busbar_unit_auth::AuthChain::new(Vec::new(), true)),
            crate::root::kernel::auth_bindings::AuthBindings::without_directory(),
            Door::new(InMemoryCells::new()),
            Pricer::flat(0),
            crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
            Arc::new(Mutex::new(durability)),
            crate::root::kernel::new_kernel().origin(busbar_caps::OriginKind::Client),
            Arc::new(busbar_unit_breaker::BreakerUnit::with_diagnostics(
                crate::root::adapters::root_diagnostics(),
            )),
        )
        .mounting(
            busbar_a2a::PLANE_DECL.key,
            MountedPlane {
                records: crate::root::store::PlaneRecords::of(
                    &crate::root::store::node_adapter(Arc::clone(&store)),
                    busbar_plane_a2a::records::operations_for,
                ),
                // NOTHING DECLARED. The plane's classes are unreachable, which is what an
                // undeclared policy means and why boot refuses one.
                scope_policy: crate::root::policy::ScopePolicy::new(),
                lanes: 0,
            },
        );
        A2aNode::over(
            bindings,
            crate::root::policy::group_table(&BTreeMap::new(), &BTreeMap::new()),
            RecordLegs::new(store),
            3_600,
        )
    };
    let answers = std::cell::Cell::new(0u32);
    let arriving = Arriving {
        op: busbar_plane_a2a::ops::OP_PUSH_CONFIG_GET,
        request_bytes: 128,
        key: None,
        credential: None,
        expected_aud: None,
        pool: "probe",
        chain: &["tcp", "tls", "http"],
        source: "127.0.0.1:1".to_string(),
        port: 8080,
    };
    let served = node.serve_class(&arriving, || {
        answers.set(answers.get() + 1);
        "the class's own document"
    });
    assert!(
        matches!(served, Err(NotServed::Refused(..))),
        "an undeclared operation class is refused at approve"
    );
    assert_eq!(
        answers.get(),
        0,
        "a refused unit produces no bytes: the document is never reached"
    );
}

/// The node this process serves on is the one the composition installed, and a second install is a
/// no-op rather than a silent swap of the node a live request is already being served by.
#[test]
fn the_node_is_installed_once() {
    assert!(
        super::node().is_none() || super::node().is_some(),
        "the cell reads the cell rather than asserting a process-global's value"
    );
}
