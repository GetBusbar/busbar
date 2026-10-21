// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/plane_host/mod.rs`.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The host clock reads the kernel's one clock in nanoseconds, and the seconds and milliseconds
/// veneers are that reading scaled down.
#[test]
fn the_host_clock_is_a_live_nanosecond_reading_scaled_by_its_veneers() {
    let app = crate::test_support::TestApp::new().build();
    let nanos = clock_now_nanos();
    let ms = clock_now_ms_over(&app);
    let secs = clock_now_secs_over(&app);
    assert!(
        nanos > 0,
        "host clock must be a live nonzero nanosecond reading"
    );
    assert!(ms > 0 && secs > 0, "the veneers read the same live clock");
    assert!(
        (ms / 1_000).abs_diff(secs) <= 1,
        "milliseconds and seconds are one clock at two scales: {ms} ms vs {secs} s"
    );
}

/// A guard whose `Drop` counts, standing in for a registered grant.
struct CountsDrop(Arc<AtomicUsize>);

impl Drop for CountsDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// An admission REGISTERS the real RAII grant in the caller's arena (governance off: the empty grant
/// the engine hands back) and the arena reclaims it on scope end.
#[test]
fn an_admission_registers_its_grant_in_the_callers_arena() {
    let app = crate::test_support::TestApp::new().build();
    let scope = DispatchScope::new();
    let caller = busbar_contract::records::PlaneRequestCtx::default();
    assert_eq!(scope.registered(), 0, "arena starts empty");
    assert!(matches!(
        govern_admit_reason_over(&app, &scope, &caller, b"pool"),
        GovAdmit::Admitted
    ));
    assert_eq!(scope.registered(), 1, "an admitted grant is registered");
    scope.reclaim_all();
    assert_eq!(
        scope.registered(),
        0,
        "reclaim releases the registered grant"
    );
}

/// With governance ENABLED the admission drives the real `GovState::try_admit` limit engine and
/// still registers the RAII grant it returns.
#[test]
fn an_admission_drives_the_real_limit_engine() {
    let gov = Arc::new(
        crate::governance::GovState::new(Arc::new(crate::governance::MemoryStore::new()), None)
            .expect("memory store constructs"),
    );
    let app = crate::test_support::TestApp::new().governance(gov).build();
    let scope = DispatchScope::new();
    let caller = busbar_contract::records::PlaneRequestCtx::default();
    assert!(
        matches!(
            govern_admit_reason_over(&app, &scope, &caller, b"pool-a"),
            GovAdmit::Admitted
        ),
        "the real limit engine admits an ungrouped (unlimited) chain"
    );
    assert_eq!(
        scope.registered(),
        1,
        "the engine's grant is registered in the arena"
    );
}

/// A handle registered in a dispatch arena is reclaimed exactly once when the arena ends.
#[test]
fn dispatch_scope_reclaims_a_registered_handle_on_scope_end() {
    let reclaimed = Arc::new(AtomicUsize::new(0));
    {
        let scope = DispatchScope::new();
        scope.register_admission(Box::new(CountsDrop(Arc::clone(&reclaimed))));
        assert_eq!(scope.registered(), 1);
        assert_eq!(reclaimed.load(Ordering::SeqCst), 0);
    }
    assert_eq!(reclaimed.load(Ordering::SeqCst), 1);
}

/// ONE RULE. The predicate every metrics fold asks is asserted directly, so no fold can be "fixed"
/// apart from it.
#[test]
fn both_abi_lanes_ask_the_same_metric_name_question() {
    assert!(crate::snapshot::observe::admits_metric_name(
        "plane_host_test"
    ));
    assert!(!crate::snapshot::observe::admits_metric_name(
        "busbar_anything"
    ));
    assert!(!crate::snapshot::observe::admits_metric_name("Bad-Name"));
    assert!(!crate::snapshot::observe::admits_metric_name(""));
}

/// THE REACHABILITY PIN for the invoke-family rewrite commit rule, stated at core's own function.
///
/// `apply_rewrite_to_invoke_args` is where a `prompt: rw` hook's reply becomes the `arguments` a
/// plane is handed back, and `transform_over_over` re-serialises that value with `serde_json::to_vec`.
/// Two facts about it decide whether a plane's apply site has a live hole or a dormant one, and both
/// are asserted here rather than read off the source by a plane's own test:
///
/// 1. It admits ANY JSON object as the replacement. It does not know, and cannot check, the TYPE the
///    receiving plane will decode into. For a JSON-RPC door plane the target is `serde_json::Value`, so bytes
///    core commits always parse and their "output I cannot read back" arms are unreachable through
///    this host. For a session plane the target is a typed session configuration, which rejects
///    `{"field": 7}` as a type mismatch — so THAT plane's arm is genuinely reachable through
///    core's real host, and its refusal (its door's `committed_session_config`) is a live fix,
///    not a dormant one.
/// 2. The commit is a WHOLESALE REPLACEMENT, not a merge. A hook that names one field produces
///    `arguments` carrying ONLY that field — every other key the caller (or the plane's own lock)
///    had is gone from the committed bytes. A plane whose target type defaults its absent fields
///    therefore silently blanks its own locked values unless it merges, which is the second half of
///    the whole-replacement rule.
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

/// THE REWRITE LEG EVERY PLANE BUT THE MODEL-CALLING ONE FIRES (`plane_host::admission_transform`, reached by the tool, agent and
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
