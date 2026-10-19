// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/mod.rs`.

use super::*;
use busbar_contract::abi::hot::{
    AdmissionId, Decision, Facts, MeterOutcome, RawUsageComponent, Usage, UsageComponent,
    POD_VERSION,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Drive the wired slots through the REAL recovery path over a live `App` from the test-support
/// builder. The three wired fns recover the `HostState` but none of them read `app`, so a minimal
/// `TestApp` suffices; what matters is that `HostCtx` recovers a live `HostState` for the call.
fn with_test_state<R>(f: impl FnOnce(HostCtx, &PlaneHostVtable, &DispatchScope) -> R) -> R {
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        // SAFETY: `host` is the live HostState minted by `with_dispatch_scope`.
        let state: &HostState = unsafe { recover(host) }
            .expect("host generation still live inside with_dispatch_scope");
        let scope = state.scope;
        f(host, vt, scope)
    })
}

#[test]
fn builds_a_full_vtable_with_frozen_preamble() {
    let vt = build_plane_host_vtable();
    assert_eq!(busbar_contract::abi::check_preamble(&vt.abi), Ok(()));
    assert_eq!(vt.size as usize, core::mem::size_of::<PlaneHostVtable>());
    // Every slot the kernel still serves is populated and wired.
    assert!(vt.govern_admit.is_some());
    assert!(vt.clock_now.is_some());
    // The minor-30 HOST SERVICES are granted, served by the kernel itself (the contract holds no
    // entropy source and no clock): a dropped-in plane gets the host's services a linked one does.
    assert!(vt.entropy_fill.is_some());
    assert!(vt.wall_clock.is_some());
    // RETIRED (row 155): the usage-tap fault is data on the plane's answer, counted by the kernel,
    // and the translate cap reaches a plane in its settings; no host serves either slot.
    assert!(vt.tap_fault_latch.is_none());
    assert!(vt.translate_cap.is_none());
}

/// RED (u30 / u36; BUSBAR-1.6.0.md Appendix A B.6, l.3846: `egress_*` and `auth_resolve` deleted;
/// THE DESIGN §5: every dial is the connector's): no egress slot is reachable through the host
/// vtable, and neither is the credential mint whose only redeemer was `egress_open`. A host that
/// served any of them again would hand a plane an outbound path outside the connector.
#[test]
fn no_egress_slot_and_no_credential_mint_is_reachable() {
    let vt = build_plane_host_vtable();
    assert!(vt.egress_open.is_none(), "egress_open");
    assert!(vt.egress_poll.is_none(), "egress_poll");
    assert!(vt.egress_write.is_none(), "egress_write");
    assert!(vt.egress_close.is_none(), "egress_close");
    assert!(vt.egress_fault.is_none(), "egress_fault");
    assert!(vt.auth_resolve.is_none(), "auth_resolve");
}

#[test]
fn wired_clock_now_returns_a_nonzero_nanos_clock() {
    with_test_state(|host, vt, _scope| {
        let now = (vt.clock_now.unwrap())(host);
        assert!(
            now > 0,
            "host clock must be a live nonzero nanosecond reading"
        );
    });
}

#[test]
fn wired_govern_admit_decides_over_the_facts_pod() {
    with_test_state(|host, vt, _scope| {
        let admit = Facts::new(10, 100, 1, 0, 0, b"pool");
        assert_eq!(
            (vt.govern_admit.unwrap())(host, &*admit as *const Facts),
            Decision::Admit,
            "budget covers the request → admit"
        );
        let deny = Facts::new(100, 10, 1, 0, 0, b"pool");
        assert_eq!(
            (vt.govern_admit.unwrap())(host, &*deny as *const Facts),
            Decision::Deny,
            "request exceeds budget → deny"
        );
        // Fail-closed on a null POD.
        assert_eq!(
            (vt.govern_admit.unwrap())(host, core::ptr::null()),
            Decision::Deny
        );
    });
}

/// The GOVERNANCE `govern_admit` slot REGISTERS the real RAII grant in the dispatch arena on an
/// admit and reclaims it on scope-drop; a deny registers nothing. Drives the slot via the vtable.
#[test]
fn wired_govern_admit_registers_grant_in_arena_and_reclaims() {
    with_test_state(|host, vt, scope| {
        assert_eq!(scope.registered(), 0, "arena starts empty");
        // Admit → the grant rides the arena.
        let admit = Facts::new(10, 100, 7, 0, 0, b"pool");
        assert_eq!(
            (vt.govern_admit.unwrap())(host, &*admit as *const Facts),
            Decision::Admit
        );
        assert_eq!(scope.registered(), 1, "an admitted grant is registered");
        // Deny → nothing registered (still just the one from the admit above).
        let deny = Facts::new(100, 10, 7, 0, 0, b"pool");
        assert_eq!(
            (vt.govern_admit.unwrap())(host, &*deny as *const Facts),
            Decision::Deny
        );
        assert_eq!(scope.registered(), 1, "a denied request registers no grant");
        // Explicit reclaim (the abort-path assertion): the arena empties.
        scope.reclaim_all();
        assert_eq!(
            scope.registered(),
            0,
            "reclaim releases the registered grant"
        );
    });
}

/// With governance ENABLED, `govern_admit` drives the real `GovState::try_admit` limit engine and
/// still registers the RAII grant it returns. Exercises the delegation over a live `GovState`.
#[test]
fn wired_govern_admit_drives_the_real_limit_engine() {
    let gov = Arc::new(
        crate::governance::GovState::new(Arc::new(crate::governance::MemoryStore::new()), None)
            .expect("memory store constructs"),
    );
    let app = crate::test_support::TestApp::new().governance(gov).build();
    with_dispatch_scope(&app, |host, vt| {
        // SAFETY: live HostState from `with_dispatch_scope`.
        let state: &HostState = unsafe { recover(host) }
            .expect("host generation still live inside with_dispatch_scope");
        let admit = Facts::new(5, 50, 3, 0, 0, b"pool-a");
        assert_eq!(
            (vt.govern_admit.unwrap())(host, &*admit as *const Facts),
            Decision::Admit,
            "the real limit engine admits an ungrouped (unlimited) chain"
        );
        assert_eq!(
            state.scope.registered(),
            1,
            "the engine's grant is registered in the arena"
        );
    });
}

/// The GOVERNANCE `meter_charge` slot charges a usage through the real metering path (money-scalar
/// breakdown + write-behind accrual), returning `Charged`; a null POD is fail-closed to `Rejected`.
#[test]
fn wired_meter_charge_charges_a_usage_pod() {
    with_test_state(|host, vt, _scope| {
        let usage = Usage {
            size: core::mem::size_of::<Usage>() as u32,
            version: POD_VERSION,
            component: RawUsageComponent::of(UsageComponent::Tokens),
            _reserved: 0,
            amount: 1_000,
            admission: AdmissionId(42),
            key_id_ptr: core::ptr::null(),
            key_id_len: 0,
            model_ptr: core::ptr::null(),
            model_len: 0,
            provider_ptr: core::ptr::null(),
            provider_len: 0,
            units_ptr: core::ptr::null(),
            units_len: 0,
        };
        assert_eq!(
            (vt.meter_charge.unwrap())(host, &usage as *const Usage),
            MeterOutcome::Charged,
            "a well-formed usage charges"
        );
        // A zero-count usage still charges.
        let zero = Usage { amount: 0, ..usage };
        assert_eq!(
            (vt.meter_charge.unwrap())(host, &zero as *const Usage),
            MeterOutcome::Charged
        );
        // Fail-closed on a null POD.
        assert_eq!(
            (vt.meter_charge.unwrap())(host, core::ptr::null()),
            MeterOutcome::Rejected
        );
    });
}

/// THE ONE METRIC-NAME RULE. The predicate a plugin's reported series is admitted by (the
/// envelope fold) — asserted directly, so it cannot drift.
#[test]
fn the_metric_name_rule_is_the_one_predicate() {
    assert!(crate::snapshot::observe::admits_metric_name(
        "plane_host_test"
    ));
    assert!(!crate::snapshot::observe::admits_metric_name(
        "busbar_anything"
    ));
    assert!(!crate::snapshot::observe::admits_metric_name("Bad-Name"));
    assert!(!crate::snapshot::observe::admits_metric_name(""));
}

/// The async guard is `Send` (so a future holding it across `.await` stays `Send`) and the Send
/// route is `Send + 'static` (so it can be moved into `spawn_blocking`). Compile-time proof.
#[test]
fn guards_have_the_right_thread_bounds() {
    fn assert_send<T: Send>() {}
    fn assert_send_static<T: Send + 'static>() {}
    assert_send::<HostDispatch<'static>>();
    assert_send_static::<SendHostDispatch>();
}

/// The OWNED async guard held across an `.await` reclaims its arena when the future completes —
/// the fix for the sync-only closure form (which would drop the scope before the future ran).
#[tokio::test]
async fn host_dispatch_guard_reclaims_across_an_await() {
    let reclaimed = Arc::new(AtomicUsize::new(0));
    let app = crate::test_support::TestApp::new().build();
    {
        let host = HostDispatch::new(&app);
        let f = reclaimed.clone();
        host.scope().register_egress(Box::new(move || {
            f.fetch_add(1, Ordering::SeqCst);
        }));
        // Materialize the HostCtx synchronously and recover a live HostState through it.
        host.with_host(|ctx, vt| {
            assert!(!ctx.is_null(), "a live HostCtx is minted");
            assert!(
                HostGeneration::is_live(ctx.generation()),
                "the minting dispatch's generation is live for the duration of `with_host`"
            );
            assert!(vt.clock_now.is_some());
        });
        // The guard is held ACROSS this await — the scope must not reclaim yet.
        tokio::task::yield_now().await;
        assert_eq!(
            reclaimed.load(Ordering::SeqCst),
            0,
            "held across await, not reclaimed"
        );
    }
    // Guard dropped at the end of the future → the arena reclaimed exactly once.
    assert_eq!(reclaimed.load(Ordering::SeqCst), 1);
}

/// The Send route survives a move into `spawn_blocking`, materializes a live `HostCtx` on the
/// blocking thread, and reclaims its arena when the closure (and the guard) end.
#[tokio::test]
async fn send_host_dispatch_works_inside_spawn_blocking() {
    let reclaimed = Arc::new(AtomicUsize::new(0));
    let app = Arc::new(crate::test_support::TestApp::new().build());
    let host = SendHostDispatch::new(Arc::clone(&app));
    let f = reclaimed.clone();
    let now = tokio::task::spawn_blocking(move || {
        host.scope().register_egress(Box::new(move || {
            f.fetch_add(1, Ordering::SeqCst);
        }));
        // The raw HostCtx is minted and used INSIDE the blocking closure, never across the boundary.
        let now = host.with_host(|ctx, vt| (vt.clock_now.unwrap())(ctx));
        assert_eq!(host.scope().registered(), 1);
        now
        // `host` drops here → the hop arena reclaims on the blocking thread.
    })
    .await
    .expect("blocking hop joins");
    assert!(now > 0, "the host clock read on the blocking thread");
    assert_eq!(
        reclaimed.load(Ordering::SeqCst),
        1,
        "the hop arena reclaimed at closure end"
    );
}

#[test]
fn dispatch_scope_reclaims_a_registered_handle_on_scope_end() {
    let reclaimed = Arc::new(AtomicUsize::new(0));
    let flag = reclaimed.clone();
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, _vt| {
        // SAFETY: live HostState from `with_dispatch_scope`.
        let state: &HostState = unsafe { recover(host) }
            .expect("host generation still live inside with_dispatch_scope");
        let f = flag.clone();
        state.scope.register_egress(Box::new(move || {
            f.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(state.scope.registered(), 1);
        assert_eq!(flag.load(Ordering::SeqCst), 0);
    });
    // The dispatch scope ended → the registered handle was reclaimed exactly once.
    assert_eq!(reclaimed.load(Ordering::SeqCst), 1);
}

// ── A6 use-after-free hardening: a STALE `HostCtx` (its minting dispatch has ended, so its
// `HostGeneration` is no longer live) must be REFUSED at the recovery site, never dereferenced. ──

/// `recover` refuses a `HostCtx` copied out of a dispatch that has already ended — the exact A6
/// shape: a plane that stashed the handle and replayed it after the `HostState` it addressed went
/// out of scope. Before the generation guard, `recover` had no way to detect this and would hand back
/// a dangling `&HostState`; now the generation check catches it BEFORE the pointer is ever read.
#[test]
fn stale_host_ctx_is_refused_not_dereferenced() {
    let app = crate::test_support::TestApp::new().build();
    // `HostCtx` is `Copy`; copy it out of the dispatch that minted it. When `with_dispatch_scope`
    // returns, its `HostGeneration` token has already dropped and popped off this thread's live set.
    let stale_host = with_dispatch_scope(&app, |host, _vt| host);
    assert!(
        !HostGeneration::is_live(stale_host.generation()),
        "the minting dispatch has ended; its generation must no longer be live"
    );
    // SAFETY: `recover` checks the generation BEFORE dereferencing; a stale handle is refused, never
    // read — so calling it here with an ended dispatch's handle is not itself unsound.
    let recovered = unsafe { recover(stale_host) };
    assert!(
        recovered.is_none(),
        "a stale HostCtx (generation no longer live) must be refused, never dereferenced"
    );
}

/// The end-to-end ABI shape of the same guard: a real vtable slot (`clock_now`) handed a stale
/// `HostCtx` fails closed to its documented sentinel (`0`) rather than reading freed stack memory —
/// proving the guard is live on the actual dispatch path a plane calls, not just at the `recover` unit.
#[test]
fn stale_host_ctx_through_a_real_vtable_slot_fails_closed() {
    let app = crate::test_support::TestApp::new().build();
    let stale_host = with_dispatch_scope(&app, |host, _vt| host);
    assert!(!HostGeneration::is_live(stale_host.generation()));
    // A freshly built vtable (not the one the ended dispatch minted) so this call exercises only
    // the stale `HostCtx`, never a stale vtable reference.
    let vt = build_plane_host_vtable();
    let now = (vt.clock_now.unwrap())(stale_host);
    assert_eq!(
        now, 0,
        "a stale handle reads the fail-closed clock, never a dereference"
    );
}

/// THE REACHABILITY PIN for the invoke-family rewrite commit rule, stated at core's own function.
///
/// `apply_rewrite_to_invoke_args` is where a `prompt: rw` hook's reply becomes the `arguments` a
/// plane is handed back, and `transform_over_over` re-serialises that value with `serde_json::to_vec`.
/// Two facts about it decide whether a plane's apply site has a live hole or a dormant one, and both
/// are asserted here rather than read off the source by a plane's own test:
///
/// 1. It admits ANY JSON object as the replacement. It does not know, and cannot check, the TYPE the
///    receiving plane will decode into. For MCP and A2A the target is `serde_json::Value`, so bytes
///    core commits always parse and their "output I cannot read back" arms are unreachable through
///    this host. For a session plane the target is a typed session configuration, which rejects
///    `{"voice": 7}` as a type mismatch — so THAT plane's arm is genuinely reachable through
///    core's real host, and its refusal (its door's `committed_session_config`) is a live fix,
///    not a dormant one.
/// 2. The commit is a WHOLESALE REPLACEMENT, not a merge. A hook that names one field produces
///    `arguments` carrying ONLY that field — every other key the caller (or the plane's own lock)
///    had is gone from the committed bytes. A plane whose target type defaults its absent fields
///    therefore silently blanks its own locked values unless it merges, which is the second half of
///    the voice rule.
#[test]
fn a_committed_invoke_rewrite_installs_any_json_object_verbatim() {
    // The arguments as the plane handed them to the seam: a locked field the hook never names, plus
    // the one it does. `persona` stands in for any string-typed field of a plane's typed config
    // (the doc above names the concrete one); core never learns which plane's type it is.
    let mut args = serde_json::json!({ "instructions": "locked by the plane", "persona": "alloy" });
    let rw = busbar_contract::hooks::RewriteReply {
        messages: vec![serde_json::json!({ "role": "user", "content": { "persona": 7 } })],
        tools: Vec::new(),
    };
    assert!(
        apply_rewrite_to_invoke_args(&mut args, &rw),
        "core COMMITS this rewrite (`applied: true`): the reply carries a JSON object, which is the \
         only thing this fn checks. It never consults the receiving plane's type."
    );
    assert_eq!(
        String::from_utf8(serde_json::to_vec(&args).expect("a Value always serializes"))
            .expect("json is utf-8"),
        r#"{"persona":7}"#,
        "these are the bytes `transform_over_over` hands back. (1) They are not a valid typed \
         config whose `persona` is a string — so a plane decoding into a typed \
         config CAN be handed a committed rewrite it cannot read. (2) `instructions` is GONE: the \
         commit replaced the arguments wholesale rather than patching the one named field."
    );
}

/// THE LIVE RE-RESOLUTION READS THE BINDINGS IN FORCE NOW. `role_bindings` is per-snapshot (rebuilt
/// from the applied config on every apply), so a re-check against the snapshot the principal was
/// admitted on would keep a role-bound subscription alive after its binding was removed. Stands
/// before the swap (the binding is there), lapses after it (the binding is gone).
#[test]
fn a_role_bound_standing_is_rechecked_against_the_live_snapshot_bindings() {
    let mut roles = std::collections::BTreeMap::new();
    roles.insert("eng".to_string(), crate::config::RoleBindingCfg::default());
    let mut rb = crate::config::RoleBindings::new();
    rb.insert("idp".to_string(), roles);
    let principal = crate::auth::Principal {
        id: "alice@example.com".to_string(),
        name: None,
        roles: vec!["eng".to_string()],
        ttl_secs: None,
    };
    let key = crate::governance::synthesize_bound_key("idp", &principal, &rb).expect("bound");
    let handle = Arc::new(crate::state::AppHandle::new(
        crate::test_support::TestApp::new()
            .role_bindings(rb)
            .build(),
    ));
    let standing = live_standing(Arc::clone(&handle));

    let now = standing(&key, 1_700_000_000).expect("the binding stands");
    assert_eq!(now.id, "alice@example.com");

    // A config apply that removes the binding swaps in a snapshot without it.
    handle.swap(crate::test_support::TestApp::new().build());
    assert!(
        standing(&key, 1_700_000_000).is_none(),
        "the binding is gone from the live snapshot, so the principal no longer stands"
    );
}

/// The hook accesses the node journal holds under one ingress label, oldest first. The journal is
/// process-wide, so each test below uses a label no other test uses.
fn hook_accesses_under(op: &str) -> Vec<crate::audit::amend::Access> {
    crate::audit::amend::node_recent()
        .into_iter()
        .filter_map(|a| match a.body {
            crate::audit::amend::AmendBody::Access(x) if x.op_class.as_str() == op => Some(x),
            _ => None,
        })
        .collect()
}

/// A rewrite hook that abstains: only what it was handed matters.
struct AbstainingRewrite;

#[async_trait::async_trait]
impl crate::hooks::RoutingPolicy for AbstainingRewrite {
    async fn decide(
        &self,
        _req: &busbar_contract::hooks::RoutingRequest<'_>,
        _candidates: &[busbar_contract::hooks::Candidate<'_>],
        _ctx: &busbar_contract::hooks::RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> busbar_contract::hooks::PolicyResult {
        Ok(busbar_contract::hooks::RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "abstaining-rewrite"
    }
}

/// THE REWRITE LEG EVERY NON-LLM PLANE FIRES (`plane_host::admission_transform`, reached by the tool, agent and
/// session planes alike) hands the hook the call's arguments, and leaves exactly one access
/// amendment naming the hook — the same record the gate seam leaves.
#[test]
fn the_plane_rewrite_leg_leaves_one_access_amendment_per_hook_handed_the_arguments() {
    const PLANE: &str = "access-rewrite-leg";
    let mut app = crate::test_support::TestApp::new().build();
    let mut containers = crate::state::ContainerRewriteMap::new();
    containers.insert(
        "c".to_string(),
        vec![(
            std::time::Duration::from_millis(500),
            Arc::new(AbstainingRewrite) as Arc<dyn crate::hooks::RoutingPolicy>,
        )],
    );
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .plane_rewrites
        .insert(PLANE, containers);
    let verdict = transform_over_over(&app, PLANE, "c", 1, "tool", br#"{"path":"/x"}"#);
    assert!(matches!(verdict, TransformVerdict::Proceed { .. }));
    let seen = hook_accesses_under(PLANE);
    assert_eq!(seen.len(), 1, "one access per hand-over: {seen:?}");
    assert_eq!(seen[0].name, "abstaining-rewrite");
}

/// THE PORT A PLANE'S OWN HOOK CALL SITES RECORD THROUGH: the host's provided `hook_read` seals the
/// access on the node journal, naming the hook, the caller and the fields that crossed.
#[test]
fn the_host_hook_read_port_seals_one_access_amendment_on_the_node_journal() {
    const OP: &str = "access-host-port";
    let app = crate::test_support::TestApp::new().build();
    let host = crate::test_support::engine_host(&app);
    host.hook_read("port-hook", Some("key-1"), OP, true);
    let seen = hook_accesses_under(OP);
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].name, "port-hook");
    assert_eq!(
        seen[0].subject,
        crate::audit::amend::Subject::PrincipalId("key-1".to_string())
    );
    assert_eq!(
        seen[0].fields,
        vec!["content".to_string(), "identity".to_string()]
    );
}
