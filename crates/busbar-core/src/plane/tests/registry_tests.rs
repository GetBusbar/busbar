// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE-KIND SEAM, proven the way the protocol registry proves itself: by folding a
//! declaration core has never heard of through the SAME functions production folds the built-ins
//! through, and showing the difference reaches a production refusal.
//!
//! These tests drive [`merged_boot_plane_decls`] and [`config_sections_from`] directly rather than
//! the process `OnceLock`, for the reason the protocol registry's own tests give: a process
//! singleton can be initialised once per test binary, which would leave the fold's order and skip
//! rules provable only by booting binaries.

use crate::plane::config::{config_sections, config_sections_from, refuse_cross_plane_reference};
use crate::plane::registry::{
    build_dispatch, builtin_plane_decls, install_planes, merged_boot_plane_decls, plane_decl_for,
    PlaneDecl,
};
use std::any::Any;
use std::collections::BTreeMap;

/// THE SHIPPED `[llm, mcp, a2a]` PROCESS PLANE LIST for core's OWN test binary. The three plane
/// crates are dev-dependencies here, so this names their public `PLANE_DECL`s across the honest crate
/// boundary. It lives in this `tests/` module — off the neutral source the plane-purity lint scans —
/// and `super::builtin_plane_decls()` returns it under `#[cfg(test)]`, so the neutral registry names
/// no plane crate while core's tests still boot the same list the shipped `busbar` binary does.
pub(super) static TEST_BUILTIN_PLANE_DECLS: &[&PlaneDecl] = &[
    &busbar_llm::PLANE_DECL,
    &busbar_mcp::PLANE_DECL,
    &busbar_a2a::PLANE_DECL,
];

/// THE MCP PLANE'S DEFAULT per-generation runtime for core's `cfg(test)` fixture — reached by
/// `super::default_mcp_test_runtime()`. It names `busbar_mcp::testkit` here, in this `tests/` module
/// the neutral-purity lint excludes, so that plane symbol stays off the neutral `test_support` source.
pub(super) fn default_mcp_test_runtime() -> std::sync::Arc<dyn Any + Send + Sync> {
    busbar_mcp::testkit::default_mcp_runtime()
}

/// A PLANE BUSBAR DOES NOT HAVE. Nothing in core names it, nothing in core has an enum variant for
/// it, and no `match` anywhere has an arm for it — which is precisely the property under test.
/// Stands in for the `busbar-plane-a2a` crate's own `PLANE_DECL`.
static WIDGET_PLANE: PlaneDecl = PlaneDecl {
    key: "widget",
    fallback: false,
    config_section: "widgets",
    scope_kinds: &["widget"],
    subject_noun: "fronted widget",
    admin_noun: "fronted-widget",
    audit_kind: "widget_thing",
    wire_format_names: || &["widgetrpc"],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_| None,
    routes: None,
    admin_routes: None,
    openapi: None,
    hydrate: None,
    start: None,
    config_validate: None,
    card_signing_domain: None,
    card_kid_prefix: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    reresolve_gates: None,
    #[cfg(feature = "openapi-schema")]
    openapi_schemas: None,
    on_swap: None,
    parse_section: None,
    parse_endpoint: None,
    lower_endpoint: None,
    build_runtime: None,
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
};

fn installed() -> Vec<&'static PlaneDecl> {
    merged_boot_plane_decls(&[&WIDGET_PLANE], builtin_plane_decls())
}

/// THE HEADLINE BEHAVIOUR. A plane registered from OUTSIDE core changes what a production config
/// refusal says — `widgets.foo` in a `hooks:` list is refused as a CROSS-PLANE reach, naming the
/// section, with nothing written for `widget` anywhere in this crate.
///
/// Watched RED before the seam existed: with the built-ins alone the same reference is refused as
/// `NotBare` (a dotted name naming no section busbar knows), which is a different sentence telling
/// the operator to do a different thing.
#[test]
fn an_installed_plane_reaches_the_cross_plane_refusal() {
    let sections = config_sections_from(&installed());

    let refusal = refuse_cross_plane_reference("widgets.reporter", "widgets.audit", &sections)
        .expect_err("a reach onto a registered plane's section is refused");
    assert!(
        refusal.contains("reaches onto the `widgets:` plane"),
        "the refusal must name the registered plane's own section: {refusal}"
    );
    assert!(
        refusal.contains("Did you mean the hook `audit`?"),
        "and must offer the bare name the operator probably meant: {refusal}"
    );

    // THE CONTROL: without the registration, core has no idea `widgets:` is a plane, and the same
    // reference gets the generic not-a-bare-name sentence instead. This is what the seam changed.
    let builtin_only = config_sections_from(builtin_plane_decls());
    let refusal = refuse_cross_plane_reference("widgets.reporter", "widgets.audit", &builtin_only)
        .expect_err("still refused, but for a different reason");
    assert!(
        !refusal.contains("reaches onto"),
        "unregistered: must NOT be diagnosed as a cross-plane reach: {refusal}"
    );
    assert!(
        refusal.contains("is not a bare name"),
        "unregistered: the generic diagnosis: {refusal}"
    );
}

/// CANONICAL LAYERING ORDER, INSTALL-SOURCE-INDEPENDENT, and the built-ins' own operator-visible
/// order is BYTE-IDENTICAL either side of the fold — the hard property the protocol control earned,
/// restated on the plane axis. The fold normalises to the canonical layering order DERIVED FROM THE
/// REGISTRATION DATA (`canonical_key_order`), so the three canonical planes keep their layering order
/// regardless of whether a plane arrived built-in or installed; a plane outside that list (`widget`)
/// sorts stably to the tail rather than jumping ahead.
#[test]
fn installed_planes_fold_ahead_and_the_builtin_order_is_unchanged() {
    let keys: Vec<&str> = installed().iter().map(|d| d.key).collect();
    assert_eq!(keys, vec!["llm", "mcp", "a2a", "widget"]);

    let builtin_keys: Vec<&str> = builtin_plane_decls().iter().map(|d| d.key).collect();
    assert_eq!(
        builtin_keys,
        vec!["llm", "mcp", "a2a"],
        "the layering order Plane::ALL has always reported"
    );
    assert_eq!(
        &keys[..3],
        builtin_keys.as_slice(),
        "the canonical three keep their order at the head; an unknown installed plane goes to the tail"
    );

    // The same property where it is actually operator-visible: the config-section list.
    let sections = config_sections_from(&installed());
    assert_eq!(
        &sections[..3],
        &["pools", "tools", "agents"],
        "the plane sections keep their canonical layering order at the head"
    );
    assert_eq!(
        sections[3], "widgets",
        "an unknown installed plane's section sorts into its canonical (tail) plane slot, \
         after the three built-in planes and before the non-plane sections"
    );
    let mut without_widgets = sections.clone();
    without_widgets.retain(|s| *s != "widgets");
    assert_eq!(
        config_sections_from(builtin_plane_decls()),
        without_widgets,
        "removing the installed plane leaves the built-in grammar byte-identical"
    );
}

/// A SAME-KEY RE-REGISTRATION IS SKIPPED, not asserted on — the `test-support` shape, where a build
/// compiles an extracted plane back in as a built-in while the composition root still installs the
/// crate's own copy. The FIRST (installed) copy wins and the list does not grow.
#[test]
fn a_same_key_registration_is_skipped_and_the_first_copy_wins() {
    static A2A_FROM_THE_CRATE: PlaneDecl = PlaneDecl {
        key: "a2a",
        fallback: false,
        config_section: "agents",
        scope_kinds: &["agent"],
        subject_noun: "fronted agent",
        admin_noun: "fronted-agent",
        audit_kind: "a2a_agent",
        wire_format_names: || &["jsonrpc"],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        card_signing_domain: None,
        card_kid_prefix: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
    };

    let folded = merged_boot_plane_decls(&[&A2A_FROM_THE_CRATE], builtin_plane_decls());
    let keys: Vec<&str> = folded.iter().map(|d| d.key).collect();
    assert_eq!(
        keys,
        vec!["llm", "mcp", "a2a"],
        "one entry per key: the built-in a2a row is skipped, not duplicated — and the survivors are \
         normalised to canonical layering order"
    );
    // The a2a entry lands in its CANONICAL slot (not the head), and it is the INSTALLED copy that
    // survived the dedup, not the built-in one.
    let a2a_entry = folded
        .iter()
        .find(|d| d.key == "a2a")
        .expect("the folded set has an a2a entry");
    assert!(
        std::ptr::eq(*a2a_entry, &A2A_FROM_THE_CRATE),
        "the installed copy is the one that survives"
    );
    // And the grammar does not gain a duplicate section from the doubled registration.
    let sections = config_sections_from(&folded);
    assert_eq!(
        sections.iter().filter(|s| **s == "agents").count(),
        1,
        "`agents:` appears once: {sections:?}"
    );
}

/// ONE SOURCE PER FACT. Every built-in plane KEY resolves to a decl, and what the plane surface
/// answers for that key is exactly what the decl says. This pins the direction after the enum was
/// dissolved: the by-key indirection reads its declaration rather than restating any fact.
#[test]
fn every_plane_key_answers_from_its_declaration() {
    // This is the one registry test that reads the PROCESS plane list (`plane_decl_for`), so it is the
    // one a sibling's `register_test_plane` can perturb: a plane test-kit registers its `&PLANE_DECL`
    // whenever it builds a plane, and that leaked registration would shadow the built-in this asserts
    // against. Isolate the process registry for the assertion so the suite is order-independent — the
    // guard clears the registered set and holds the serial lock, so no sibling registration races or
    // leaks in, and restores it on drop. (Do NOT resolve against the built-ins directly instead: the
    // point is that the PRODUCTION by-key resolver answers from the declaration.)
    let _isolation = busbar_substrate::plane::registry::TestRegistryIsolation::empty();
    for decl in builtin_plane_decls() {
        let resolved = plane_decl_for(decl.key).expect("every built-in key resolves to a decl");
        assert!(std::ptr::eq(resolved, *decl));
        assert_eq!(
            crate::plane::wire_format_names(decl.key),
            (decl.wire_format_names)()
        );
    }
    // The values themselves are unchanged by the rewiring — the operator-visible strings that
    // metrics, audit records and grants are keyed by.
    assert_eq!(crate::plane::fallback_key(), "llm");
    assert_eq!(crate::plane::plane_decl("mcp").audit_kind, "mcp_server");
    assert_eq!(crate::plane::plane_decl("a2a").audit_kind, "a2a_agent");
    assert_eq!(
        crate::plane::plane_decl("a2a").subject_noun,
        "fronted agent"
    );
    assert_eq!(
        crate::plane::plane_decl("mcp").scope_kinds,
        &["mcp_server", "mcp_tool"]
    );
}

/// THE LLM PLANE'S WIRE-FORMAT LIST IS STILL READ OFF THE LIVE PROTOCOL REGISTRY, through the decl's
/// function pointer. This is the join between the two registries, and it is what keeps the
/// superset-IR rule a RULE: a seventh dialect moves this list with nothing edited on the plane axis.
#[test]
fn the_llm_decl_reads_the_protocol_registry() {
    // Publish the extracted-dialect built-ins into the SHARED substrate test registry the OTHER core
    // instance (the plugin dev-dep's) reads, before the LLM `PLANE_DECL`'s `wire_format_names` fn
    // pointer reaches it (see the two-instance note below and `proto::registry::registry`).
    let _ = crate::proto::known_protocols();
    assert_eq!(
        crate::plane::wire_format_names(crate::plane::fallback_key()),
        crate::proto::known_protocols(),
        "the LLM plane's dialects are the registered protocols, not a literal"
    );
    assert!(
        crate::plane::wire_formats(crate::plane::fallback_key()) > 1,
        "and the superset-IR threshold is computed from that list"
    );
}

/// NO TWO PLANES MAY SHARE A SCOPE KIND OR AN AUDIT KIND — the collision rule the enum's docs state,
/// now enforced over the FOLDED list rather than the three hardcoded variants. A registered plane
/// that claimed `agent` as a scope kind would have its grants admit A2A traffic; that is a boot-time
/// refusal's job, and this pins the property the refusal would defend.
#[test]
fn a_registered_plane_cannot_collide_with_a_builtin_vocabulary() {
    let folded = installed();
    let mut scope_kinds: Vec<&str> = folded
        .iter()
        .flat_map(|d| d.scope_kinds.iter().copied())
        .collect();
    let before = scope_kinds.len();
    scope_kinds.sort_unstable();
    scope_kinds.dedup();
    assert_eq!(
        before,
        scope_kinds.len(),
        "scope kinds collide: {scope_kinds:?}"
    );

    let mut audit_kinds: Vec<&str> = folded.iter().map(|d| d.audit_kind).collect();
    let before = audit_kinds.len();
    audit_kinds.sort_unstable();
    audit_kinds.dedup();
    assert_eq!(
        before,
        audit_kinds.len(),
        "audit kinds collide: {audit_kinds:?}"
    );

    let mut sections: Vec<&str> = folded.iter().map(|d| d.config_section).collect();
    let before = sections.len();
    sections.sort_unstable();
    sections.dedup();
    assert_eq!(
        before,
        sections.len(),
        "config sections collide: {sections:?}"
    );
}

/// **THE SCOPE-KIND CODEC ROUND-TRIPS, so encode and decode cannot skew.** `scope_kind_at` (decode)
/// and `scope_kind_index` (encode) each apply the base-first, first-seen dedup independently; if they
/// ever disagreed a `pool` grant could resolve an `mcp_server` target (the entitlement escalation the
/// dedup exists to prevent). This pins `scope_kind_at(scope_kind_index(k)) == k` over the FULL builtin
/// kind set — the neutral base plus every registered plane's declared kinds — so any future encoder
/// that routes through `scope_kind_index` is proven to invert the decoder here.
#[test]
fn the_scope_kind_index_is_the_exact_inverse_of_scope_kind_at() {
    use crate::plane::registry::{scope_kind_at, scope_kind_index};
    // The neutral base kind plus every kind any registered plane declares — the full vocabulary the
    // two functions share. Iterating this (rather than a literal list) means a plane adding a kind
    // is covered with no edit here.
    let kinds: Vec<&'static str> = std::iter::once("pool")
        .chain(
            builtin_plane_decls()
                .iter()
                .flat_map(|d| d.scope_kinds.iter().copied()),
        )
        .collect();
    assert!(kinds.len() > 1, "the builtin kind set must be non-trivial");
    for k in kinds {
        let idx = scope_kind_index(k)
            .unwrap_or_else(|| panic!("'{k}' is a declared kind but has no index"));
        assert_eq!(
            scope_kind_at(idx),
            Some(k),
            "encode/decode skew: index {idx} for '{k}' does not decode back to it"
        );
    }
    // A kind no plane declares is fail-closed on the encode side, matching `scope_kind_at`'s
    // out-of-range `None` on the decode side.
    assert_eq!(
        scope_kind_index("no-plane-declares-this"),
        None,
        "an undeclared kind must have no index (fail-closed)"
    );
}

/// INSTALL BEFORE FIRST READ, enforced. The module header states the invariant: a declaration
/// installed after another layer resolved against the smaller (built-ins-only) set would mean two
/// layers of one process disagree about which planes exist, so [`install_planes`] must refuse to
/// run once the process plane list has been read even once.
///
/// This is the ONLY test in the crate that calls [`install_planes`], deliberately: it is a write to
/// process-global `OnceLock`s, and a second call anywhere else in this binary would make this test's
/// outcome depend on test execution order. [`config_sections`] is called here specifically to force
/// the read `install_planes` must then refuse to follow — it is exercised incidentally by many other
/// tests in this crate's test binary already (any test that reaches
/// `plane::config::config_sections()`), so this call is not what makes the read happen; it is what
/// makes the read happen NO LATER than this test needs it to, regardless of what ran before it.
#[test]
#[should_panic(expected = "install_planes called after the plane list was first read")]
fn install_planes_after_first_read_panics() {
    let _ = config_sections();
    install_planes(&[]);
}

// ---------------------------------------------------------------------------------------------
// THE THREE ADMISSION RATCHETS (Step 2.2). These drive `build_dispatch` — the registry-driven
// fold that assembles the dispatch table from each plane's decl and its runtime object — directly,
// with the SAME real MCP/A2A objects a boot builds, so the security property they pin is the one
// production has rather than one a fixture invented.
// ---------------------------------------------------------------------------------------------

/// A REAL MCP resource, mounting `/mcp` and binding its canonical URI as the audience.
fn mcp_slot() -> busbar_mcp::mcp::McpResource {
    busbar_mcp::mcp::McpResource::from_cfg(&busbar_mcp::mcp::McpCfg {
        canonical_uri: "https://gw.example.com/mcp".to_string(),
        authorization_servers: vec!["https://login.example.com".to_string()],
        ..Default::default()
    })
    .expect("a well-formed mcp resource")
}

/// A REAL A2A plane WITH a receiving side (a `public_url`), so `admission()` is `Some` and the plane
/// mounts both `/a2a` and the gRPC service path.
fn a2a_slot_receiving() -> std::sync::Arc<busbar_a2a::a2a::plane::A2aPlane> {
    use busbar_a2a::a2a::config::{AgentDefCfg, AgentPinCfg, AgentsCfg, PinMechanism};
    let mut cfg = AgentsCfg::default();
    cfg.agents.insert(
        "planner".to_string(),
        AgentDefCfg {
            url: "https://agent.example/planner".to_string(),
            pin: AgentPinCfg {
                mechanism: PinMechanism::Unpinned,
                key: None,
                fingerprint: None,
            },
            reverify_ttl: None,
            recovery_backoff: None,
            protocol_version: None,
            allow_private: false,
            upstream_credentials: None,
            upstream_credential: None,
            egress_scopes: Vec::new(),
            client_identity: None,
            hooks: Vec::new(),
        },
    );
    busbar_a2a::a2a::plane::A2aPlane::from_config(&cfg, Some("https://busbar.example"))
        .expect("a receiving a2a plane")
}

/// The MCP + A2A slot map a boot hands `build_dispatch`, keyed by plane key.
fn builtin_slots<'a>(
    mcp: &'a busbar_mcp::mcp::McpResource,
    a2a: &'a busbar_a2a::a2a::plane::A2aPlane,
) -> BTreeMap<&'static str, &'a dyn Any> {
    let mut slots: BTreeMap<&'static str, &dyn Any> = BTreeMap::new();
    slots.insert("mcp", mcp);
    slots.insert("a2a", a2a);
    slots
}

/// **RATCHET R1 — every declared path is claimed, and every claimed path is audience-checked.**
///
/// For each registered plane, every `(path, wire)` its decl declares against its real object is
/// mounted, and [`super::PlaneDispatch::admission_for`] resolves an audience on it — including the
/// A2A gRPC SECOND claim, `/lf.a2a.v1.A2AService`, whose path a gRPC client cannot be pointed off of.
/// A path a plane answers on but does not claim here is a confused-deputy hole where no token's `aud`
/// is checked, which is the whole reason the claim set — not the router — is what this pins.
///
/// RED, watched: drop the gRPC entry from the A2A decl's `claims` and this fails —
/// `admission_for("/lf.a2a.v1.A2AService/SendMessage")` returns `None` on a path the plane still
/// answers, the exact audience-less door the ratchet forbids.
#[test]
fn r1_every_declared_path_resolves_an_admission() {
    let mcp = mcp_slot();
    let a2a = a2a_slot_receiving();
    let slots = builtin_slots(&mcp, &a2a);
    let dispatch =
        build_dispatch(builtin_plane_decls(), &slots).expect("the dispatch table builds");

    for decl in builtin_plane_decls() {
        let Some(slot) = slots.get(decl.key).copied() else {
            continue;
        };
        for (path, _wire) in (decl.claims)(slot) {
            // A claim's own path, and a path beneath it, both inherit the plane's audience.
            assert!(
                dispatch.admission_for(&path).is_some(),
                "plane `{}` claims `{path}` but it resolves NO admission — an audience-less door",
                decl.key
            );
            let beneath = format!("{path}/probe");
            assert!(
                dispatch.admission_for(&beneath).is_some(),
                "plane `{}`: `{beneath}` under a claimed mount must inherit the audience",
                decl.key
            );
        }
    }

    // The A2A gRPC SECOND claim specifically: it resolves the SAME audience as the canonical `/a2a`
    // mount, which is the property that would vanish the moment the second claim were dropped.
    let grpc = dispatch.admission_for("/lf.a2a.v1.A2AService/SendMessage");
    assert!(
        grpc.is_some(),
        "the gRPC service path must be audience-checked, not left open"
    );
    assert_eq!(
        grpc,
        dispatch.admission_for("/a2a/agents/planner"),
        "both A2A bindings resolve the one audience the plane's card publishes"
    );
}

/// **RATCHET R2 — a mounted plane must bind an admission, or boot refuses.**
///
/// A plane that claims a path but returns `None` for its admission would serve an audience-less —
/// hence unauthenticated — resource. [`build_dispatch`] refuses that at boot with a named error
/// rather than mounting it. This is what stops a future plane lowering its own admission bar to
/// nothing simply by omitting the fact.
///
/// RED, watched: delete the `!claims.is_empty() && admission.is_none()` guard in `build_dispatch`
/// and this fails — the table builds `Ok`, the path is in `mounted_keys()`, and no audience guards
/// it: a door with no lock.
#[test]
fn r2_a_mounted_plane_with_no_admission_refuses_boot() {
    static MOUNTS_BUT_NEVER_ADMITS: PlaneDecl = PlaneDecl {
        key: "widget",
        fallback: false,
        config_section: "widgets",
        scope_kinds: &["widget"],
        subject_noun: "fronted widget",
        admin_noun: "fronted-widget",
        audit_kind: "widget_thing",
        wire_format_names: || &["widgetrpc"],
        // Claims a path — but binds no audience. The shape build_dispatch must refuse.
        claims: |_| vec![("/widget".to_string(), "widgetrpc")],
        admission: |_| None,
        build: |_| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        card_signing_domain: None,
        card_kid_prefix: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
    };
    let unit = ();
    let mut slots: BTreeMap<&'static str, &dyn Any> = BTreeMap::new();
    slots.insert("widget", &unit);

    let err = build_dispatch(&[&MOUNTS_BUT_NEVER_ADMITS], &slots)
        .expect_err("a plane that mounts a path but binds no admission must refuse boot");
    assert!(
        err.contains("widget"),
        "the refusal names the offending plane: {err}"
    );
    assert!(
        err.contains("bound no admission"),
        "the refusal says what is missing: {err}"
    );

    // The CONTROL: a plane that mounts nothing (claims empty) needs no admission and does NOT refuse.
    static MOUNTS_NOTHING: PlaneDecl = PlaneDecl {
        key: "widget",
        fallback: false,
        config_section: "widgets",
        scope_kinds: &["widget"],
        subject_noun: "fronted widget",
        admin_noun: "fronted-widget",
        audit_kind: "widget_thing",
        wire_format_names: || &["widgetrpc"],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        card_signing_domain: None,
        card_kid_prefix: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
    };
    let dispatch = build_dispatch(&[&MOUNTS_NOTHING], &slots)
        .expect("a plane that claims no path needs no admission");
    assert!(dispatch.mounted_keys().is_empty(), "and it mounts nothing");
}

/// **R2-boot — a plane whose `start` returns `Err` REFUSES BOOT.** The start fold
/// [`crate::boot::run_start_hooks`] (which `boot::start_planes` drives over the real plane list)
/// propagates the hook's `Err` with `?`, so a plane that cannot start its background work — an A2A
/// outbound client identity that does not resolve — aborts the boot with its OWN named message rather
/// than yielding a running deployment that silently re-verifies nothing for that agent.
///
/// Driven over an INJECTED decl for the reason `build_dispatch` is: the ratchet is provable without
/// the process plane `OnceLock` (once-per-binary) and without booting real listeners.
///
/// RED, watched: change `start(ctx)?;` to `let _ = start(ctx);` in `boot::run_start_hooks` and this
/// fails — the fold returns `Ok`, the refusal is swallowed, and the named message never reaches the
/// operator. GREEN with the `?`.
#[test]
fn r2_boot_a_plane_whose_start_errs_refuses_boot() {
    static REFUSES_START: PlaneDecl = PlaneDecl {
        key: "refuser",
        fallback: false,
        config_section: "refusers",
        scope_kinds: &["refuser"],
        subject_noun: "refuser",
        admin_noun: "refuser",
        audit_kind: "refuser",
        wire_format_names: || &["refrpc"],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: Some(|_ctx| Err("refuser: outbound client identity did not resolve".to_string())),
        config_validate: None,
        card_signing_domain: None,
        card_kid_prefix: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
    };
    let ctx = crate::plane::registry::BootCtx::stub();

    let err = crate::boot::run_start_hooks(&[&REFUSES_START], &ctx)
        .expect_err("a plane whose start returns Err must refuse boot, not continue");
    assert!(
        err.contains("refuser: outbound client identity did not resolve"),
        "the boot refusal carries the plane hook's own message verbatim: {err}"
    );

    // CONTROL: a plane whose `start` returns `Ok`, and a plane with NO `start` hook (WIDGET_PLANE),
    // do not abort — the fold runs to the end and returns `Ok`.
    static STARTS_CLEAN: PlaneDecl = PlaneDecl {
        key: "clean",
        fallback: false,
        config_section: "cleans",
        scope_kinds: &["clean"],
        subject_noun: "clean",
        admin_noun: "clean",
        audit_kind: "clean",
        wire_format_names: || &["cleanrpc"],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: Some(|_ctx| Ok(())),
        config_validate: None,
        card_signing_domain: None,
        card_kid_prefix: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
    };
    crate::boot::run_start_hooks(&[&STARTS_CLEAN, &WIDGET_PLANE], &ctx)
        .expect("an Ok start and a None-start plane do not refuse boot");
}

/// **R2-boot, the hydrate half.** A plane whose `hydrate` returns `Err` REFUSES BOOT the same way:
/// [`crate::boot::run_hydrate_hooks`] propagates it with `?`, so a plane that cannot restore its
/// durable state does not go on to serve half of it. Same red (`hydrate(ctx)?` → `let _ = ...`).
#[test]
fn r2_boot_a_plane_whose_hydrate_errs_refuses_boot() {
    static REFUSES_HYDRATE: PlaneDecl = PlaneDecl {
        key: "refuser",
        fallback: false,
        config_section: "refusers",
        scope_kinds: &["refuser"],
        subject_noun: "refuser",
        admin_noun: "refuser",
        audit_kind: "refuser",
        wire_format_names: || &["refrpc"],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: Some(|_ctx| Err("refuser: durable task state did not verify".to_string())),
        start: None,
        config_validate: None,
        card_signing_domain: None,
        card_kid_prefix: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
    };
    let ctx = crate::plane::registry::BootCtx::stub();

    let err = crate::boot::run_hydrate_hooks(&[&REFUSES_HYDRATE], &ctx)
        .expect_err("a plane whose hydrate returns Err must refuse boot");
    assert!(
        err.contains("refuser: durable task state did not verify"),
        "the boot refusal carries the plane hook's own message verbatim: {err}"
    );
}

/// **RATCHET R3 — no scope-kind or audit-kind collision across the DISPATCHED set.**
///
/// 2.0 pinned this over the declared list; here it is re-asserted over the planes actually MOUNTED
/// in a built dispatch table. Two planes sharing a scope kind is how one plane's grant admits
/// another plane's traffic, and two sharing an audit kind is how one plane's records answer
/// another's question — a hazard that only bites once both colliding planes have a door.
///
/// RED, watched: register a fourth plane that both MOUNTS and reuses `mcp_server` as a scope kind
/// (a colliding widget in the mount set) and this fails on the scope-kind dedup.
#[test]
fn r3_no_vocabulary_collision_across_the_mounted_set() {
    let mcp = mcp_slot();
    let a2a = a2a_slot_receiving();
    let slots = builtin_slots(&mcp, &a2a);
    let dispatch =
        build_dispatch(builtin_plane_decls(), &slots).expect("the dispatch table builds");

    let mounted_keys = dispatch.mounted_keys();
    let mounted: Vec<&&PlaneDecl> = builtin_plane_decls()
        .iter()
        .filter(|d| mounted_keys.contains(&d.key))
        .collect();

    let mut scope_kinds: Vec<&str> = mounted
        .iter()
        .flat_map(|d| d.scope_kinds.iter().copied())
        .collect();
    let before = scope_kinds.len();
    scope_kinds.sort_unstable();
    scope_kinds.dedup();
    assert_eq!(
        before,
        scope_kinds.len(),
        "scope kinds collide across the mounted set: {scope_kinds:?}"
    );

    let mut audit_kinds: Vec<&str> = mounted.iter().map(|d| d.audit_kind).collect();
    let before = audit_kinds.len();
    audit_kinds.sort_unstable();
    audit_kinds.dedup();
    assert_eq!(
        before,
        audit_kinds.len(),
        "audit kinds collide across the mounted set: {audit_kinds:?}"
    );

    // The mounted set is exactly the two non-fallback planes this boot configured.
    let mut keys = mounted_keys;
    keys.sort_unstable();
    assert_eq!(keys, vec!["a2a", "mcp"]);
}

/// The registry-driven fold reproduces the OLD hardcoded blocks BYTE-FOR-BEHAVIOUR: the same paths
/// claimed with the same wire formats and the same admissions, built by hand through the public
/// `mount`/`admit` API and by `build_dispatch` through the decls, must be equal.
#[test]
fn build_dispatch_matches_the_hand_mounted_table() {
    let mcp = mcp_slot();
    let a2a = a2a_slot_receiving();
    let slots = builtin_slots(&mcp, &a2a);
    let built = build_dispatch(builtin_plane_decls(), &slots).expect("dispatch builds");

    let hand = crate::plane::PlaneDispatch::default()
        .mount("mcp", mcp.mount_path(), crate::plane::WIRE_JSONRPC)
        .admit("mcp", mcp.admission())
        .mount(
            "a2a",
            busbar_a2a::a2a::serve::MOUNT_PATH,
            crate::plane::WIRE_JSONRPC,
        )
        .mount(
            "a2a",
            busbar_a2a::a2a::serve::GRPC_MOUNT_PATH,
            crate::plane::WIRE_GRPC,
        )
        .admit("a2a", a2a.admission().expect("receiving side"));

    assert_eq!(
        built, hand,
        "the registry-driven fold must match the old blocks"
    );
}

/// A DELEGATION-ONLY A2A plane (no `public_url`) mounts nothing and binds no audience — so it is NOT
/// refused by R2 (it claims no path) and its paths stay unclaimed. Byte-identical to the old
/// `a2a_plane.admission().is_some()` gate on the hardcoded block.
#[test]
fn a_delegation_only_a2a_plane_mounts_nothing() {
    use busbar_a2a::a2a::config::{AgentDefCfg, AgentPinCfg, AgentsCfg, PinMechanism};
    let mut cfg = AgentsCfg::default();
    cfg.agents.insert(
        "planner".to_string(),
        AgentDefCfg {
            url: "https://agent.example/planner".to_string(),
            pin: AgentPinCfg {
                mechanism: PinMechanism::Unpinned,
                key: None,
                fingerprint: None,
            },
            reverify_ttl: None,
            recovery_backoff: None,
            protocol_version: None,
            allow_private: false,
            upstream_credentials: None,
            upstream_credential: None,
            egress_scopes: Vec::new(),
            client_identity: None,
            hooks: Vec::new(),
        },
    );
    // No public_url ⇒ no receiving side ⇒ admission() is None.
    let a2a =
        busbar_a2a::a2a::plane::A2aPlane::from_config(&cfg, None).expect("a delegating plane");
    assert!(a2a.admission().is_none());

    let mut slots: BTreeMap<&'static str, &dyn Any> = BTreeMap::new();
    slots.insert("a2a", a2a.as_ref());
    let dispatch = build_dispatch(builtin_plane_decls(), &slots).expect("no path, no refusal");
    assert!(
        dispatch.mounted_keys().is_empty(),
        "a delegation-only deployment claims no path"
    );
    assert!(dispatch.admission_for("/a2a").is_none());
}

/// THE OpenAPI NON-VACUITY FLOOR. A silently-empty OpenAPI contribution reads to the drift guard as
/// "this plane documents nothing", which passes vacuously — so a mounted admin verb could ship with
/// no documented path and nothing would notice. This pins the floor: every plane that contributes
/// admin verbs (`admin_routes: Some`) MUST also contribute at least one OpenAPI path, and both come
/// from the SAME decl the router mounts from, so the document cannot omit a verb the surface serves.
///
/// Watched RED with a stubbed empty contributor (a decl whose `admin_routes` is `Some` but whose
/// `openapi` returns an empty object): the floor fires. The real MCP and A2A decls pass it.
#[test]
fn a_plane_with_admin_verbs_documents_at_least_one_openapi_path() {
    for decl in builtin_plane_decls() {
        if decl.admin_routes.is_none() {
            continue;
        }
        let openapi = decl.openapi.unwrap_or_else(|| {
            panic!(
                "plane `{}` contributes admin verbs but no OpenAPI fn",
                decl.key
            )
        });
        let doc = openapi();
        let count = doc.as_object().map(|o| o.len()).unwrap_or(0);
        assert!(
            count > 0,
            "plane `{}` contributes admin verbs but documents zero OpenAPI paths — a mounted verb \
             would ship undocumented, and the drift guard passes vacuously over an empty fragment",
            decl.key
        );
    }
}
