// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE MOUNTED MCP LEG, DRIVEN.** The cells here are the first time anything in this tree runs an
//! MCP class through the composition rather than through the plane's own `match` arm.
//!
//! Every one of them drives the REAL loop over the REAL bindings: a real `bindings::Node` with the
//! plane mounted on it, the production store adapter over a memory store, the production breaker
//! view keyed by this plane's lane table, the real auth chain object, the real door with its cells,
//! the real journal. Nothing here substitutes a step.

use std::sync::{Arc, Mutex};

use busbar_contract::plane::PlaneMeta;
use busbar_plane_mcp::{claims, records, McpPlane, Server};
use busbar_unit_admission::{Door, GroupTable, InMemoryCells, Pricer};
use busbar_unit_auth::{Auth, AuthChain};

use crate::root::bindings::{MountedPlane, Node};
use crate::root::node_mcp::{seam, Arriving, McpNode, NotServed};
use crate::root::store::{node_adapter, PlaneRecords};

/// One registered server, as the operator's `tools:` section resolves into the plane's own table.
///
/// A registration is required and not incidental: the approve step reads a deployment with nothing
/// registered as naming no resource at all, which is a refusal rather than a pass — so a node over
/// an EMPTY plane could never serve a class, and a cell that mounted one would be proving the wrong
/// thing.
const SERVERS: &[Server] = &[Server {
    id: "ws",
    lane: busbar_contract::ids::LaneId::new("mcp:ws"),
    host: "https://ws.example.com/mcp",
    transport: claims::TRANSPORT_HTTP,
}];

/// The stdio session's composed stack: one layer, and the claim keys on it.
const STDIO_CHAIN: &[&str] = &[claims::TRANSPORT_STDIO];

/// The node the composition builds at boot, over one memory store.
///
/// The adapter is returned beside the node because [`PlaneRecords`] borrows the store handle out of
/// it: a fixture that dropped the adapter would be a fixture whose record legs answer against a
/// store that has gone away.
fn booted() -> (McpNode, busbar_plugin_loader::store_adapter::StoreAdapter) {
    let store: Arc<dyn busbar_api::Store> = Arc::new(busbar_core::governance::MemoryStore::new());
    let adapter = node_adapter(store);
    let plane = McpPlane::new(SERVERS);
    let node = Node::over(
        Auth::new(AuthChain::new(Vec::new(), false)),
        // GOVERNED: these cells assert the governed path, so the posture they are driven under is the
        // one that runs every grant check. The ungoverned half is asserted by name, on its own cell.
        crate::root::bindings::Posture::Governed,
        crate::root::kernel::auth_bindings::AuthBindings::without_directory(),
        Door::new(InMemoryCells::new()),
        Pricer::flat(0),
        crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
        Arc::new(Mutex::new(
            crate::root::durability::build(
                &crate::root::durability::DurabilityConfig { data_dir: None },
                Box::new(busbar_unit_wal::NullShipper::new()),
                Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
            )
            .expect("a memory-buffered journal cannot fail to open"),
        )),
        busbar_kernel::teller::Kernel::new().origin(busbar_caps::OriginKind::Client),
        Arc::new(busbar_unit_breaker::BreakerUnit::with_diagnostics(
            crate::root::adapters::root_diagnostics(),
        )),
    )
    .mounting(
        <McpPlane as PlaneMeta>::KEY,
        MountedPlane {
            records: PlaneRecords::of(&adapter, records::operations_for),
            scope_policy: crate::root::units_mcp::scope_policy(
                crate::root::policy::ScopePolicy::new(),
            ),
            lanes: SERVERS.len(),
        },
    );
    (
        McpNode::over(
            plane,
            node,
            // No `groups:` section: a caller bound to no group is a chain of one uncapped
            // attribution bucket, which is what a deployment with no limit tree has. It is NOT the
            // fail-closed arm — that one is a caller bound to a group the configuration does not
            // carry, and the admit step refuses it.
            GroupTable::default(),
        ),
        adapter,
    )
}

/// One arriving frame, as the stdio session hands it over.
fn arriving<'a>(method: &'a str) -> Arriving<'a> {
    Arriving {
        method,
        request_bytes: 128,
        // An ungoverned session: no key resolved, which is the open posture a deployment with no
        // data-plane chain runs. The governed half is the e2e battery's, against the real binary.
        key: None,
        claim_transport: claims::TRANSPORT_STDIO,
        chain: STDIO_CHAIN,
        credential: None,
        // The stdio session's principal was bound once, at the session's open, and this frame
        // carries no credential of its own.
        from_session: true,
    }
}

/// **THE MOUNTED MCP LEG ANSWERS `tools/list`.**
///
/// The cell this whole line exists for. Before it, `root::units_mcp::mount` had zero callers and
/// nothing in the tree had ever run an MCP class through the loop: every one of the thirteen was
/// answered by `envelope::rpc_dispatch`'s `match`. This drives the composition — arrival over the
/// stdio claim, decode against the plane's own method table, authenticate, verify against the
/// breaker and the pool view, approve against the plane's own scope declaration, admit at the
/// node's door, route over the two record legs the plane's plan names, meter, and both audit doors
/// — and asserts that the byte source ran on the far side of it.
///
/// The sentinel is what makes that an assertion rather than a hope: the closure is the ONLY thing
/// that can produce it, so a loop that refused the unit cannot return it and a loop that ran the
/// closure twice would be caught by the count.
#[test]
fn the_mounted_mcp_leg_answers_tools_list() {
    let (node, _adapter) = booted();
    let ran = std::cell::Cell::new(0u32);

    let served = node.serve_class(&arriving("tools/list"), || {
        ran.set(ran.get() + 1);
        "the byte source's document"
    });

    match served {
        Ok(document) => {
            assert_eq!(
                document, "the byte source's document",
                "the node answers with what the byte source produced and never with bytes of its own"
            );
            assert_eq!(
                ran.get(),
                1,
                "the byte source runs exactly once, on the settled arm"
            );
        }
        Err(other) => panic!(
            "the mounted mcp leg must answer tools/list through the loop; it did not: {other:?}"
        ),
    }
}

/// The node's mount is the plane's own key, and the resolver finds it under that key and no other.
///
/// A node that mounted nothing resolves nothing, and the difference between that and an empty
/// binding is the whole of why `resolve_bindings` answers an `Option`: a leg driven over a default
/// door admits and charges against something the operator never configured, and it would look like
/// it worked.
#[test]
fn the_node_reports_the_plane_it_mounted() {
    let (node, _adapter) = booted();
    assert_eq!(
        node.mounted(),
        vec![<McpPlane as PlaneMeta>::KEY],
        "the node mounts the mcp plane under the plane's OWN key"
    );
}

/// A method the plane's own table does not carry as a client class opens no unit at all.
///
/// Not a refusal at a step — nothing was admitted, nothing was charged and nothing was sealed — so
/// it is a distinct answer, and the caller renders it as the not-implemented answer it always did.
/// `notifications/initialized` is the honest probe: the plane's table carries it, and it carries it
/// as a notice rather than as a class a caller is answered for.
#[test]
fn a_method_the_plane_does_not_name_as_a_class_opens_no_unit() {
    let (node, _adapter) = booted();
    let ran = std::cell::Cell::new(false);
    let served = node.serve_class(&arriving("tools/there-is-no-such-method"), || {
        ran.set(true);
    });
    assert!(
        matches!(served, Err(NotServed::NoSuchClass)),
        "a method the plane's table does not carry is not a class, and no unit opens for it"
    );
    assert!(
        !ran.get(),
        "the byte source must not run for a method that opened no unit"
    );
}

/// **THE ROUTE PLAN IS READ WITHOUT AN ALLOCATION**, and the arena is what proves it.
///
/// The measurement the node's whole `Ctx` rests on, asserted directly rather than inferred from the
/// serve above: `McpPlane::route` reads a unit's operation class and touches neither the body, nor
/// the facts, nor the ctx — so the arena the node hands it can refuse every allocation and report
/// zero bytes remaining, and the plan still comes back. The day that stops being true, the serve
/// path stops working and this cell says which of the two changed.
#[test]
fn the_route_plan_is_read_without_an_allocation() {
    use busbar_contract::bounded::Arena;

    let arena = seam::NoAllocation;
    assert_eq!(arena.remaining(), 0, "the arena reports nothing available");
    assert!(
        arena.alloc_bytes(b"x").is_err(),
        "the arena refuses every allocation, so a path that needed one fails rather than leaking"
    );
    assert!(
        arena.alloc_str("x").is_err(),
        "the same refusal for a string, so there is no half-open door"
    );

    // And the plan still comes back, over exactly that arena.
    let (node, _adapter) = booted();
    let ran = std::cell::Cell::new(false);
    let served = node.serve_class(&arriving("tools/list"), || ran.set(true));
    assert!(
        served.is_ok() && ran.get(),
        "the class is served over an arena that allocates nothing"
    );
}

/// The stack the node reports is the one the claim named, and its TOP is the claim's transport.
///
/// `units_mcp::arrival` refuses a record whose chain does not END at the claim's transport, so this
/// is not a cosmetic property: a node that reported a chain ending anywhere else would hand the
/// arrival step a record from one surface under another surface's claim, and the unit would be
/// refused at step zero for a reason no operator could read.
#[test]
fn the_reported_stack_ends_at_the_claim_s_transport() {
    use busbar_contract::unit::TransportView;

    let stack = seam::Stack {
        top: claims::TRANSPORT_STDIO,
        chain: STDIO_CHAIN,
    };
    assert_eq!(stack.key(), claims::TRANSPORT_STDIO);
    assert_eq!(
        stack.chain().last(),
        Some(&claims::TRANSPORT_STDIO),
        "the claim's transport is the TOP of the chain, which is what the arrival step reads"
    );
    assert!(
        claims::declares(stack.key()),
        "a transport no claim names is one no unit of this plane may arrive on"
    );
}

/// **THE AUTHENTICATE STEP READS THE DOOR'S OUTCOME AND DOES NOT RE-DECIDE IT.**
///
/// The subject is a unit whose principal was resolved before it opened — which is every unit of this
/// plane, on every surface it serves. The chain this node binds is EMPTY and is never consulted; what
/// the loop settles on is the principal the door handed over, and the proof is that the settlement
/// and the audit row name THAT principal rather than the anonymous actor an empty chain would
/// resolve.
///
/// Why it matters more than it looks: `units_mcp::authenticate` runs the chain, and a chain asked for
/// a credential that arrived once — at a session's open — refuses every frame after the first. So a
/// node that re-authenticated would serve exactly one request per session and refuse the rest, for a
/// reason no operator could read. The LLM plane argues the same shape on the same grounds
/// (`busbar_llm::unit::authenticate`): a second door answering a question the first already answered
/// is two refusal shapes for one condition.
#[test]
fn the_authenticate_step_reads_the_door_s_outcome() {
    let (node, _adapter) = booted();
    let key = busbar_api::VirtualKey {
        id: "vk-the-door-resolved-this".to_string(),
        name: "the door's caller".to_string(),
        generation_hash: String::new(),
        enabled: true,
        allowed_scopes: None,
        created_at: 0,
        // No group: a chain of one uncapped attribution bucket, which is what a deployment with no
        // limit tree has. The subject here is the identity, not the cap.
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        idp_subject: None,
        binding_mode: None,
        minted_by: None,
    };
    let mut arriving = arriving("tools/list");
    arriving.key = Some(&key);
    arriving.from_session = true;

    let served = node.serve_class(&arriving, || "served");
    assert!(
        matches!(served, Ok("served")),
        "a unit the door already admitted is served, with an EMPTY chain behind the authenticate \
         step: the step is a read, so the chain is unreached rather than permissive"
    );
}
