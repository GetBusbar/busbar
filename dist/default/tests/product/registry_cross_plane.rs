// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::plane_sections::{config_sections_from, refuse_cross_plane_reference};
use busbar_kernel::config::{deploy_from_yaml_str, resolve, RootCfg};
use busbar_kernel::plane_driver::registry::{
    build_dispatch, install_planes, merged_boot_plane_decls, plane_decl_for, BuildCtx, PlaneDecl,
    PlaneDeclaration,
};
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

fn builtin_plane_decls() -> &'static [&'static PlaneDecl] {
    register_planes();
    static PLANES: std::sync::OnceLock<Vec<&'static PlaneDecl>> = std::sync::OnceLock::new();
    PLANES.get_or_init(|| {
        ["pools", "tools", "agents"]
            .into_iter()
            .map(|section| {
                busbar_kernel::plane_driver::registry::plane_decl_for_config_section(section)
                    .unwrap_or_else(|| panic!("the distribution registers the `{section}:` plane"))
            })
            .collect()
    })
}

fn register_planes() {
    crate::dist_root_install::install();
}

fn owning(section: &str) -> &'static PlaneDecl {
    builtin_plane_decls()
        .iter()
        .copied()
        .find(|decl| {
            decl.config_section == section || decl.owned_config_sections.contains(&section)
        })
        .unwrap_or_else(|| panic!("the distribution registers the owner of `{section}:`"))
}

fn fallback() -> &'static PlaneDecl {
    builtin_plane_decls()
        .iter()
        .copied()
        .find(|decl| decl.fallback)
        .expect("the distribution registers its fallback plane")
}

fn door_section(decl: &PlaneDecl) -> &'static str {
    decl.owned_config_sections
        .first()
        .copied()
        .unwrap_or(decl.config_section)
}

fn canonical_keys() -> Vec<&'static str> {
    ["pools", "tools", "agents"]
        .iter()
        .map(|s| owning(s).key)
        .collect()
}

static WIDGET_PLANE: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "widget",
        fallback: false,
        config_section: "widgets",
        scope_kinds: &["widget"],
        subject_noun: "fronted widget",
        admin_noun: "fronted-widget",
        audit_kind: "widget_thing",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &[],
        required_config_sections: &[],
        trust_keys: &[],
        caller_credential_refusal: None,
        served_op_classes: &[],
    },
    wire_format_names: |_| &["widgetrpc"],
    provider_dialects: |_| &[],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_, _| None,
    routes: None,
    admin_routes: None,
    openapi: None,
    hydrate: None,
    start: None,
    config_validate: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    reresolve_gates: None,
    openapi_schemas: None,
    on_swap: None,
    parse_section: None,
    parse_endpoint: None,
    lower_endpoint: None,
    build_runtime: None,
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
    resolve_provider: None,
    door: None,
};

fn installed() -> Vec<&'static PlaneDecl> {
    merged_boot_plane_decls(&[&WIDGET_PLANE], builtin_plane_decls())
}

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

#[test]
fn installed_planes_fold_ahead_and_the_builtin_order_is_unchanged() {
    let keys: Vec<&str> = installed().iter().map(|d| d.key).collect();
    let mut want = canonical_keys();
    want.push("widget");
    assert_eq!(keys, want);

    let builtin_keys: Vec<&str> = builtin_plane_decls().iter().map(|d| d.key).collect();
    assert_eq!(
        builtin_keys,
        canonical_keys(),
        "the layering order Plane::ALL has always reported"
    );
    assert_eq!(
        &keys[..3],
        builtin_keys.as_slice(),
        "the canonical three keep their order at the head; an unknown installed plane goes to the tail"
    );

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

#[test]
fn a_same_key_registration_is_skipped_and_the_first_copy_wins() {
    let agents = owning("agents");
    let from_the_crate: &'static PlaneDecl = Box::leak(Box::new(PlaneDecl {
        declaration: agents.declaration,
        ..WIDGET_PLANE
    }));

    let folded = merged_boot_plane_decls(&[from_the_crate], builtin_plane_decls());
    let keys: Vec<&str> = folded.iter().map(|d| d.key).collect();
    assert_eq!(
        keys,
        canonical_keys(),
        "one entry per key: the built-in `agents:` row is skipped, not duplicated — and the \
         survivors are normalised to canonical layering order"
    );

    let entry = folded
        .iter()
        .find(|d| d.key == agents.key)
        .expect("the folded set has the `agents:` plane's entry");
    assert!(
        std::ptr::eq(*entry, from_the_crate),
        "the installed copy is the one that survives"
    );

    let sections = config_sections_from(&folded);
    assert_eq!(
        sections.iter().filter(|s| **s == "agents").count(),
        1,
        "`agents:` appears once: {sections:?}"
    );
}

#[test]
fn every_plane_key_answers_from_its_declaration() {
    register_planes();
    for decl in builtin_plane_decls() {
        let resolved = plane_decl_for(decl.key).expect("every built-in key resolves to a decl");
        assert_eq!(resolved.key, decl.key);
        assert_eq!(resolved.config_section, decl.config_section);
        assert_eq!(resolved.scope_kinds, decl.scope_kinds);
        assert_eq!(resolved.audit_kind, decl.audit_kind);
        assert_eq!(resolved.subject_noun, decl.subject_noun);
        assert_eq!(
            busbar_kernel::plane_driver::dispatch::wire_format_names(decl.key),
            (decl.wire_format_names)(decl)
        );
    }

    assert_eq!(
        busbar_kernel::plane_driver::dispatch::fallback_key(),
        fallback().key
    );
    for decl in builtin_plane_decls() {
        let by_key = busbar_kernel::plane_driver::dispatch::plane_decl(decl.key);
        assert_eq!(by_key.audit_kind, decl.audit_kind);
        assert_eq!(by_key.subject_noun, decl.subject_noun);
        assert_eq!(by_key.scope_kinds, decl.scope_kinds);
    }
}

fn fallback_protocols() -> Vec<&'static str> {
    register_planes();
    let candidates = crate::root::boot::DOOR_CANDIDATES
        .get()
        .expect("the actual composition root discovers its planes");
    candidates
        .iter()
        .find_map(|candidate| {
            let registration = busbar_plugin_loader::dispatch::kinds::plane::stated_registration(
                candidate,
                Arc::new(|| Err("declaration inspection does not bind a plane".into())),
            )
            .expect("the actual plane states its protocol declaration");
            registration.fallback.then_some(registration.dialects)
        })
        .expect("the actual fallback door declares its protocols")
}

#[test]
fn the_fallback_decl_reads_the_protocol_registry() {
    register_planes();
    assert_eq!(
        busbar_kernel::plane_driver::dispatch::wire_format_names(
            busbar_kernel::plane_driver::dispatch::fallback_key()
        ),
        fallback_protocols(),
        "the fallback plane's dialects are its actual registered protocols"
    );
    assert!(
        busbar_kernel::plane_driver::dispatch::wire_formats(
            busbar_kernel::plane_driver::dispatch::fallback_key()
        ) > 1,
        "and the superset-IR threshold is computed from that list"
    );
}

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

#[test]
fn the_scope_kind_index_is_the_exact_inverse_of_scope_kind_at() {
    register_planes();
    use busbar_kernel::plane_driver::registry::{scope_kind_at, scope_kind_index};

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

    assert_eq!(
        scope_kind_index("no-plane-declares-this"),
        None,
        "an undeclared kind must have no index (fail-closed)"
    );
}

#[test]
fn install_planes_after_first_read_panics() {
    const CHILD: &str = "BUSBAR_REGISTRY_INSTALL_AFTER_READ_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let _ = busbar_kernel::config::plane_sections::config_sections();
        install_planes(&[]);
        panic!("install_planes accepted registration after the first read");
    }
    let test_name = concat!(module_path!(), "::install_planes_after_first_read_panics")
        .split_once("::")
        .expect("the mounted test has a module path")
        .1;
    let output = std::process::Command::new(std::env::current_exe().expect("the test executable"))
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .expect("run the registry first-read case in a fresh process");
    assert!(!output.status.success(), "late registration must panic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("install_planes called after the plane list was first read"),
        "the production registry refuses late installation: {stderr}"
    );
}

static ALPHA_CLAIMS_FOO: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "alpha",
        owned_config_sections: &["foo"],
        fee_units: &[],
        ..WIDGET_PLANE.declaration
    },
    resolve_provider: None,
    ..WIDGET_PLANE
};

static BETA_CLAIMS_FOO: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "beta",
        owned_config_sections: &["foo"],
        fee_units: &[],
        ..WIDGET_PLANE.declaration
    },
    resolve_provider: None,
    ..WIDGET_PLANE
};

static GAMMA_CLAIMS_RATE_CARD: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "gamma",
        owned_config_sections: &["rate_card"],
        fee_units: &[],
        ..WIDGET_PLANE.declaration
    },
    resolve_provider: None,
    ..WIDGET_PLANE
};

#[test]
fn dup_claim_guard_fires_when_two_planes_claim_the_same_section() {
    let decls: Vec<&PlaneDeclaration> = vec![&ALPHA_CLAIMS_FOO, &BETA_CLAIMS_FOO];
    let err = busbar_kernel::plane_driver::registry::check_owned_config_claims(
        &decls,
        busbar_kernel::plane_driver::registry::CORE_OWNED_CONCRETE_SECTIONS,
    )
    .expect_err("two planes claiming section `foo` MUST be refused — one plane's grammar would answer for the other's");
    assert!(
        err.contains("foo") && err.contains("alpha") && err.contains("beta"),
        "the refusal must name the contested section and both claimants, got: {err}"
    );
}

#[test]
fn dup_claim_guard_fires_when_a_plane_claims_a_core_owned_section() {
    let decls: Vec<&PlaneDeclaration> = vec![&GAMMA_CLAIMS_RATE_CARD];
    let err = busbar_kernel::plane_driver::registry::check_owned_config_claims(
        &decls,
        busbar_kernel::plane_driver::registry::CORE_OWNED_CONCRETE_SECTIONS,
    )
    .expect_err("claiming `rate_card` while core still owns it concretely MUST be refused — the grammar would be declared twice");
    assert!(
        err.contains("rate_card") && err.contains("gamma"),
        "the refusal must name the core-owned section and the claimant, got: {err}"
    );
}

static ONE_CLAIMS_GIZMOS: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "gizmo-first-claimant",
        owned_config_sections: &["gizmos"],
        fee_units: &[],
        ..WIDGET_PLANE.declaration
    },
    resolve_provider: None,
    ..WIDGET_PLANE
};

static TWO_CLAIMS_GIZMOS: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "gizmo-second-claimant",
        owned_config_sections: &["gizmos"],
        fee_units: &[],
        ..WIDGET_PLANE.declaration
    },
    resolve_provider: None,
    ..WIDGET_PLANE
};

#[test]
fn dup_claim_guard_admits_a_lone_claim_and_refuses_a_section_collision() {
    busbar_kernel::plane_driver::registry::check_owned_config_claims(
        &[&ONE_CLAIMS_GIZMOS],
        busbar_kernel::plane_driver::registry::CORE_OWNED_CONCRETE_SECTIONS,
    )
    .expect("`gizmos` is not core-owned and has one claimant — the lone claim must be admitted");

    let err = busbar_kernel::plane_driver::registry::check_owned_config_claims(
        &[&ONE_CLAIMS_GIZMOS, &TWO_CLAIMS_GIZMOS],
        busbar_kernel::plane_driver::registry::CORE_OWNED_CONCRETE_SECTIONS,
    )
    .expect_err("two planes claiming `gizmos` MUST be refused — one plane's grammar would answer for the other's");
    assert!(
        err.contains("gizmos")
            && err.contains("gizmo-first-claimant")
            && err.contains("gizmo-second-claimant"),
        "the refusal must name the contested section and both claimants, got: {err}"
    );
}

#[test]
fn dup_claim_guard_passes_for_the_shipped_registry() {
    let decls = merged_boot_plane_decls(&[], builtin_plane_decls());
    busbar_kernel::plane_driver::registry::check_owned_config_claims(
        &decls.iter().map(|d| &d.declaration).collect::<Vec<_>>(),
        busbar_kernel::plane_driver::registry::CORE_OWNED_CONCRETE_SECTIONS,
    )
    .expect("the shipped roster's owned-config claims must pass the dup-claim guard");

    for decl in &decls {
        for owned in decl.owned_config_sections {
            assert!(
                !decls
                    .iter()
                    .any(|other| other.key != decl.key && other.config_section == *owned),
                "plane `{}` claims `{owned}`, which another shipped plane declares as its section",
                decl.key
            );
        }
    }
}

fn resolved(yaml: &str) -> RootCfg {
    register_planes();
    let deploy = deploy_from_yaml_str(yaml).expect("the fixture configuration parses");
    resolve(&deploy, &HashMap::new()).unwrap_or_else(|e| panic!("the fixture resolves: {e:?}"))
}

fn receiving_cfg() -> RootCfg {
    let owner = owning("tools");
    let door = door_section(owner);

    let key = owner.key;
    resolved(&format!(
        "providers: {{}}\nmodels: {{}}\npublic_url: \"https://busbar.example\"\n\
         {door}:\n  canonical_uri: \"https://gw.example.com/{key}\"\n  \
         authorization_servers: [\"https://login.example.com\"]\n\
         agents:\n  planner:\n    url: \"https://agent.example/planner\"\n    \
         pin: {{ mechanism: unpinned }}\n"
    ))
}

fn built_slots(cfg: &RootCfg) -> BTreeMap<&'static str, Arc<dyn Any + Send + Sync>> {
    builtin_plane_decls()
        .iter()
        .filter(|decl| decl.fallback || cfg.plane_sections.contains(decl.config_section))
        .filter_map(|decl| {
            let ctx = BuildCtx {
                endpoint_slot: cfg.endpoint_resources.get(decl.config_section).cloned(),
                plane_defs: &cfg.plane_defs,
                public_url: cfg.public_url.as_deref(),
                prior: None,
                providers: None,
            };
            (decl.build)(decl, &ctx).map(|obj| (decl.key, obj))
        })
        .collect()
}

fn slot_refs<'a>(
    slots: &'a BTreeMap<&'static str, Arc<dyn Any + Send + Sync>>,
) -> BTreeMap<&'static str, &'a dyn Any> {
    slots.iter().map(|(k, v)| (*k, &**v as &dyn Any)).collect()
}

#[test]
fn r1_every_declared_path_resolves_an_admission() {
    let owned = built_slots(&receiving_cfg());
    let slots = slot_refs(&owned);
    let dispatch =
        build_dispatch(builtin_plane_decls(), &slots, false).expect("the dispatch table builds");

    let mut claimed = 0;
    for decl in builtin_plane_decls() {
        let Some(slot) = slots.get(decl.key).copied() else {
            continue;
        };
        let claims = (decl.claims)(slot);
        claimed += claims.len();

        let audiences: Vec<_> = claims
            .iter()
            .map(|(path, _)| dispatch.admission_for(&format!("{path}/probe")))
            .collect();
        assert!(
            audiences.windows(2).all(|w| w[0] == w[1]),
            "plane `{}`: its doors resolve different audiences: {claims:?}",
            decl.key
        );
        for (path, _wire) in claims {
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

    let multi = owning("agents");
    let multi_claims = (multi.claims)(slots[multi.key]);
    assert!(
        multi_claims.len() >= 2,
        "the multi-binding plane claims every binding's door: {multi_claims:?}"
    );
    assert!(claimed >= 3, "every mountable plane claimed its doors");
}

#[test]
fn r2_a_mounted_plane_with_no_admission_refuses_boot() {
    static MOUNTS_BUT_NEVER_ADMITS: PlaneDecl = PlaneDecl {
        declaration: PlaneDeclaration {
            key: "widget",
            fallback: false,
            config_section: "widgets",
            scope_kinds: &["widget"],
            subject_noun: "fronted widget",
            admin_noun: "fronted-widget",
            audit_kind: "widget_thing",
            card_signing_domain: None,
            card_kid_prefix: None,
            owned_config_sections: &[],
            billable_classes: &[],
            fee_units: &[],
            metric_families: &[],
            record_kinds: &[],
            required_config_sections: &[],
            trust_keys: &[],
            caller_credential_refusal: None,
            served_op_classes: &[],
        },
        wire_format_names: |_| &["widgetrpc"],
        provider_dialects: |_| &[],

        claims: |_| vec![("/widget".to_string(), "widgetrpc")],
        admission: |_| None,
        build: |_, _| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
        resolve_provider: None,
        door: None,
    };
    let unit = ();
    let mut slots: BTreeMap<&'static str, &dyn Any> = BTreeMap::new();
    slots.insert("widget", &unit);

    let err = build_dispatch(&[&MOUNTS_BUT_NEVER_ADMITS], &slots, false)
        .expect_err("a plane that mounts a path but binds no admission must refuse boot");
    assert!(
        err.contains("widget"),
        "the refusal names the offending plane: {err}"
    );
    assert!(
        err.contains("bound no admission"),
        "the refusal says what is missing: {err}"
    );

    assert!(
        build_dispatch(&[&MOUNTS_BUT_NEVER_ADMITS], &slots, true).is_err(),
        "a non-door plane with no audience is refused even under a key chain"
    );

    static MOUNTS_NOTHING: PlaneDecl = PlaneDecl {
        declaration: PlaneDeclaration {
            key: "widget",
            fallback: false,
            config_section: "widgets",
            scope_kinds: &["widget"],
            subject_noun: "fronted widget",
            admin_noun: "fronted-widget",
            audit_kind: "widget_thing",
            card_signing_domain: None,
            card_kid_prefix: None,
            owned_config_sections: &[],
            billable_classes: &[],
            fee_units: &[],
            metric_families: &[],
            record_kinds: &[],
            required_config_sections: &[],
            trust_keys: &[],
            caller_credential_refusal: None,
            served_op_classes: &[],
        },
        wire_format_names: |_| &["widgetrpc"],
        provider_dialects: |_| &[],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_, _| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
        resolve_provider: None,
        door: None,
    };
    let dispatch = build_dispatch(&[&MOUNTS_NOTHING], &slots, false)
        .expect("a plane that claims no path needs no admission");
    assert!(dispatch.mounted_keys().is_empty(), "and it mounts nothing");
}

#[test]
fn r2_boot_a_plane_whose_start_errs_refuses_boot() {
    static REFUSES_START: PlaneDecl = PlaneDecl {
        declaration: PlaneDeclaration {
            key: "refuser",
            fallback: false,
            config_section: "refusers",
            scope_kinds: &["refuser"],
            subject_noun: "refuser",
            admin_noun: "refuser",
            audit_kind: "refuser",
            card_signing_domain: None,
            card_kid_prefix: None,
            owned_config_sections: &[],
            billable_classes: &[],
            fee_units: &[],
            metric_families: &[],
            record_kinds: &[],
            required_config_sections: &[],
            trust_keys: &[],
            caller_credential_refusal: None,
            served_op_classes: &[],
        },
        wire_format_names: |_| &["refrpc"],
        provider_dialects: |_| &[],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_, _| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: Some(|_ctx| Err("refuser: outbound client identity did not resolve".to_string())),
        config_validate: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
        resolve_provider: None,
        door: None,
    };
    register_planes();
    let store = crate::LINKED
        .stores
        .iter()
        .find(|store| store.1)
        .expect("the actual distribution links an ephemeral product store");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "store": { "module": store.0 },
        "auth": { "chain": [], "admin_auth": [] },
    }))
    .expect("the actual app deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &HashMap::new())
        .expect("the actual app deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the production root builds the app and opens its real store through the ABI");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, store.0)
        .expect("the configured Store binds the boot rate authority before activation");
    limits.keep().expect("the actual app's limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert!(
        app.governance.is_some(),
        "the actual store supplies governance"
    );
    let app = Arc::new(app);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
    let ctx = busbar_kernel::plane_driver::registry::BootCtx::for_start(&handle, None);

    let err = busbar_kernel::boot::run_start_hooks(&[&REFUSES_START], &ctx)
        .expect_err("a plane whose start returns Err must refuse boot, not continue");
    assert!(
        err.contains("refuser: outbound client identity did not resolve"),
        "the boot refusal carries the plane hook's own message verbatim: {err}"
    );

    static STARTS_CLEAN: PlaneDecl = PlaneDecl {
        declaration: PlaneDeclaration {
            key: "clean",
            fallback: false,
            config_section: "cleans",
            scope_kinds: &["clean"],
            subject_noun: "clean",
            admin_noun: "clean",
            audit_kind: "clean",
            card_signing_domain: None,
            card_kid_prefix: None,
            owned_config_sections: &[],
            billable_classes: &[],
            fee_units: &[],
            metric_families: &[],
            record_kinds: &[],
            required_config_sections: &[],
            trust_keys: &[],
            caller_credential_refusal: None,
            served_op_classes: &[],
        },
        wire_format_names: |_| &["cleanrpc"],
        provider_dialects: |_| &[],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_, _| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: Some(|_ctx| Ok(())),
        config_validate: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
        resolve_provider: None,
        door: None,
    };
    busbar_kernel::boot::run_start_hooks(&[&STARTS_CLEAN, &WIDGET_PLANE], &ctx)
        .expect("an Ok start and a None-start plane do not refuse boot");
}

#[test]
fn r2_boot_a_plane_whose_hydrate_errs_refuses_boot() {
    static REFUSES_HYDRATE: PlaneDecl = PlaneDecl {
        declaration: PlaneDeclaration {
            key: "refuser",
            fallback: false,
            config_section: "refusers",
            scope_kinds: &["refuser"],
            subject_noun: "refuser",
            admin_noun: "refuser",
            audit_kind: "refuser",
            card_signing_domain: None,
            card_kid_prefix: None,
            owned_config_sections: &[],
            billable_classes: &[],
            fee_units: &[],
            metric_families: &[],
            record_kinds: &[],
            required_config_sections: &[],
            trust_keys: &[],
            caller_credential_refusal: None,
            served_op_classes: &[],
        },
        wire_format_names: |_| &["refrpc"],
        provider_dialects: |_| &[],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_, _| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: Some(|_ctx| Err("refuser: durable task state did not verify".to_string())),
        start: None,
        config_validate: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
        resolve_provider: None,
        door: None,
    };
    register_planes();
    let store = crate::LINKED
        .stores
        .iter()
        .find(|store| store.1)
        .expect("the actual distribution links an ephemeral product store");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "store": { "module": store.0 },
        "auth": { "chain": [], "admin_auth": [] },
    }))
    .expect("the actual app deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &HashMap::new())
        .expect("the actual app deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the production root builds the app and opens its real store through the ABI");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, store.0)
        .expect("the configured Store binds the boot rate authority before activation");
    limits.keep().expect("the actual app's limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert!(
        app.governance.is_some(),
        "the actual store supplies governance"
    );
    let app = Arc::new(app);
    let store = busbar_kernel::store::plane_view::PlaneStoreView::narrow(
        app.governance
            .as_ref()
            .expect("the real app has governance")
            .store(),
    );
    let ctx = busbar_kernel::plane_driver::registry::BootCtx::for_hydrate(Some(store), &app);

    let err = busbar_kernel::boot::run_hydrate_hooks(&[&REFUSES_HYDRATE], &ctx)
        .expect_err("a plane whose hydrate returns Err must refuse boot");
    assert!(
        err.contains("refuser: durable task state did not verify"),
        "the boot refusal carries the plane hook's own message verbatim: {err}"
    );
}

#[test]
fn r3_no_vocabulary_collision_across_the_mounted_set() {
    let owned = built_slots(&receiving_cfg());
    let slots = slot_refs(&owned);
    let dispatch =
        build_dispatch(builtin_plane_decls(), &slots, false).expect("the dispatch table builds");

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

    let mut keys = mounted_keys;
    keys.sort_unstable();
    let mut want = vec![owning("tools").key, owning("agents").key];
    want.sort_unstable();
    assert_eq!(keys, want);
}

#[test]
fn build_dispatch_matches_the_hand_mounted_table() {
    let owned = built_slots(&receiving_cfg());
    let slots = slot_refs(&owned);
    let built = build_dispatch(builtin_plane_decls(), &slots, false).expect("dispatch builds");

    let mut hand = busbar_kernel::plane_driver::dispatch::PlaneDispatch::default();
    let mut mounted = 0;
    for decl in builtin_plane_decls() {
        let Some(slot) = slots.get(decl.key).copied() else {
            continue;
        };
        let claims = (decl.claims)(slot);
        if claims.is_empty() {
            continue;
        }
        for (path, wire) in claims {
            hand = hand.mount(decl.key, &path, wire);
            mounted += 1;
        }
        hand = hand.admit(
            decl.key,
            (decl.admission)(slot).expect("a mounted plane binds an admission"),
        );
    }
    assert!(mounted >= 3, "the receiving deployment mounts every door");

    assert_eq!(
        built, hand,
        "the registry-driven fold must match the old blocks"
    );
}

#[test]
fn a_delegation_only_multi_binding_plane_mounts_nothing() {
    let cfg = resolved(
        "providers: {}\nmodels: {}\n\
         agents:\n  planner:\n    url: \"https://agent.example/planner\"\n    \
         pin: { mechanism: unpinned }\n",
    );
    let agents = owning("agents");

    let owned = built_slots(&cfg);
    let slot = owned
        .get(agents.key)
        .map(|v| &**v as &dyn Any)
        .expect("the configured `agents:` plane builds its object");
    assert!((agents.admission)(slot).is_none());

    let mut slots: BTreeMap<&'static str, &dyn Any> = BTreeMap::new();
    slots.insert(agents.key, slot);
    let dispatch =
        build_dispatch(builtin_plane_decls(), &slots, false).expect("no path, no refusal");
    assert!(
        dispatch.mounted_keys().is_empty(),
        "a delegation-only deployment claims no path"
    );
    assert!(dispatch
        .admission_for(&format!("/{}", agents.key))
        .is_none());
}

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
        let doc = openapi(decl);
        let count = doc.as_object().map(|o| o.len()).unwrap_or(0);
        assert!(
            count > 0,
            "plane `{}` contributes admin verbs but documents zero OpenAPI paths — a mounted verb \
             would ship undocumented, and the drift guard passes vacuously over an empty fragment",
            decl.key
        );
    }
}
