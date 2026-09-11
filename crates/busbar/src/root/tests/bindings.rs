// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE RESOLVER, driven over a node with two planes mounted on it.

use std::sync::{Arc, Mutex};

use busbar_contract::ids::RecordSchemaId;
use busbar_contract::plane::PlaneMeta;
use busbar_plane_mcp::{records, McpPlane};
use busbar_unit_admission::{Door, InMemoryCells, Pricer};
use busbar_unit_auth::{Auth, AuthChain};

use crate::root::bindings::{resolve_bindings, MountedPlane, Node};
use crate::root::store::{node_adapter, PlaneRecords};

/// A second plane's declaration, as a node that mounted two would hold it.
///
/// It declares ONE schema with ONE operation, and it is deliberately not any shipped plane's table:
/// what this file is proving is that the resolver reads whatever declaration it was handed under a
/// key, so a second table that is nothing like the first is the strongest form of the claim.
const OTHER_SCHEMA: RecordSchemaId = RecordSchemaId::new("ledger_note");

fn other_operations(schema: RecordSchemaId) -> &'static [&'static str] {
    if schema == OTHER_SCHEMA {
        &[crate::root::store::op::PUT]
    } else {
        &[]
    }
}

/// A node with the units a leg is answered by, and nothing mounted on it yet.
fn bare_node() -> Node {
    Node::over(
        Auth::new(AuthChain::new(Vec::new(), false)),
        crate::root::kernel::auth_bindings::AuthBindings::without_directory(),
        Door::new(InMemoryCells::new()),
        Pricer::flat(0),
        crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
        Mutex::new(
            crate::root::durability::build(
                &crate::root::durability::DurabilityConfig { data_dir: None },
                Box::new(busbar_unit_wal::NullShipper::new()),
                Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
            )
            .expect("a memory-buffered journal cannot fail to open"),
        ),
        busbar_kernel::teller::Kernel::new().origin(busbar_caps::OriginKind::Client),
    )
}

/// **THE ONE RESOLVER FILLS A PLANE'S BINDINGS FROM THE NODE AND THE PLANE'S DECLARATION.**
///
/// The whole of what "every plane is identical" means, stated as a run. The node is built once; the
/// plane is mounted under its OWN key, read off the plane rather than spelled here; and the nine
/// boot-resolved fields come back bound to the node's instances. Nothing in the resolver asked
/// which plane this was.
#[test]
fn the_resolver_fills_a_mounted_plane_s_bindings_from_the_node() {
    let store: Arc<dyn busbar_api::Store> = Arc::new(busbar_core::governance::MemoryStore::new());
    let adapter = node_adapter(store);
    let node = bare_node().mounting(
        <McpPlane as PlaneMeta>::KEY,
        MountedPlane {
            records: PlaneRecords::of(&adapter, records::operations_for),
            scope_policy: crate::root::policy::ScopePolicy::new(),
        },
    );

    let bindings = resolve_bindings(<McpPlane as PlaneMeta>::KEY, &node)
        .expect("the plane this node mounted resolves");

    assert!(
        std::ptr::eq(bindings.door, &node.door),
        "the leg is bound to the NODE'S door, not to a door of its own"
    );
    assert!(
        std::ptr::eq(bindings.durability, &node.durability),
        "the leg settles onto THE PROCESS'S ONE BOOK"
    );
    assert!(
        std::ptr::eq(bindings.auth, &node.auth),
        "the leg is judged by the chain the node resolved"
    );
    assert!(
        std::ptr::eq(bindings.pricer, &node.pricer),
        "the leg is priced against what the node's door prices against"
    );
    assert!(
        bindings
            .records
            .run(&crate::root::store::RecordLeg {
                schema: records::SCHEMA_CATALOGUE,
                op: records::OP_PUT,
                key: "fs",
                parent: None,
                seq: 0,
                body: b"{}",
                terminal: false,
                now: 1_700_000_000,
                expires_at: 1_700_000_060,
            })
            .is_ok(),
        "the records the resolver handed back are this plane's, over the node's one store"
    );
}

/// **A PLANE THIS NODE DID NOT MOUNT RESOLVES TO NOTHING.**
///
/// Not to an empty binding, and that distinction is the whole of the arm: a leg driven over a
/// default door would admit and charge against something the operator never configured, and it
/// would look like it worked.
#[test]
fn a_plane_this_node_did_not_mount_resolves_to_nothing() {
    let node = bare_node();
    assert!(
        resolve_bindings(<McpPlane as PlaneMeta>::KEY, &node).is_none(),
        "nothing is mounted, so nothing resolves"
    );
    assert!(
        node.mounted().is_empty(),
        "and the node says so rather than answering for a plane it does not have"
    );
}

/// **TWO PLANES ON ONE NODE GET THE SAME UNITS AND THEIR OWN DECLARATIONS.**
///
/// The property a per-plane assembly cannot promise and this one gets for free. Both legs are bound
/// to ONE door and ONE book — a node whose two planes had two doors would admit twice against one
/// budget — and each leg's record runner refuses what its OWN plane's table does not declare. The
/// second declaration below is nothing like the first, so the resolver cannot be reading either of
/// them from anywhere but the key it was given.
#[test]
fn two_planes_on_one_node_share_its_units_and_keep_their_own_declarations() {
    let store: Arc<dyn busbar_api::Store> = Arc::new(busbar_core::governance::MemoryStore::new());
    let adapter = node_adapter(store);
    let node = bare_node()
        .mounting(
            <McpPlane as PlaneMeta>::KEY,
            MountedPlane {
                records: PlaneRecords::of(&adapter, records::operations_for),
                scope_policy: crate::root::policy::ScopePolicy::new(),
            },
        )
        .mounting(
            "other",
            MountedPlane {
                records: PlaneRecords::of(&adapter, other_operations),
                scope_policy: crate::root::policy::ScopePolicy::new(),
            },
        );

    assert_eq!(
        node.mounted(),
        vec![<McpPlane as PlaneMeta>::KEY, "other"],
        "the node mounted two planes and names both"
    );

    let first = resolve_bindings(<McpPlane as PlaneMeta>::KEY, &node).expect("mounted");
    let second = resolve_bindings("other", &node).expect("mounted");

    assert!(
        std::ptr::eq(first.door, second.door) && std::ptr::eq(first.durability, second.durability),
        "both planes are bound to ONE door and ONE book"
    );

    let leg = |schema, op| crate::root::store::RecordLeg {
        schema,
        op,
        key: "k",
        parent: None,
        seq: 0,
        body: b"{}",
        terminal: false,
        now: 1_700_000_000,
        expires_at: 1_700_000_060,
    };
    assert!(
        first
            .records
            .run(&leg(records::SCHEMA_CATALOGUE, records::OP_PUT))
            .is_ok(),
        "the first plane's leg runs what the first plane declares"
    );
    assert!(
        second
            .records
            .run(&leg(records::SCHEMA_CATALOGUE, records::OP_PUT))
            .is_err(),
        "and the second plane's leg refuses it, because the SECOND plane's table does not declare it"
    );
    assert!(
        second
            .records
            .run(&leg(OTHER_SCHEMA, crate::root::store::op::PUT))
            .is_ok(),
        "the second plane's leg runs what the SECOND plane declares"
    );
}
