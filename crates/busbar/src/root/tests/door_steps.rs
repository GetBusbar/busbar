// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE A DOOR PLANE'S UNIT TAKES (ARCHITECT Q-SW6 amended by Q-FL3, 2026-10-02): a POOL route
//! names a pool of the section's reserved `pools` sub-key and walks its members under that pool's
//! label; a DIRECT route names one of the section's entries and walks it alone under 1.5.5's empty
//! pool label; anything else, or no name, is unknown.

use busbar_contract::abi::plane::{ROUTE_DIRECT, ROUTE_POOL};

use super::DoorPools;

fn pools(yaml: &str) -> DoorPools {
    DoorPools::of(&serde_yaml::from_str(yaml).expect("yaml"))
}

fn routed(p: &DoorPools, class: u8, named: Option<&str>) -> Option<(String, Vec<String>)> {
    p.resolve(class, named.map(str::as_bytes))
}

fn owned(label: &str, members: &[&str]) -> Option<(String, Vec<String>)> {
    Some((
        label.to_string(),
        members.iter().map(|m| (*m).to_string()).collect(),
    ))
}

const SECTION: &str = "a: {}\nb: {}\nhooks: [h]\nupstream_credentials: own\n\
     pools:\n  both:\n    members: [a, {name: b}]";

#[test]
fn a_pool_route_walks_its_named_pools_members_under_its_label() {
    let p = pools(SECTION);
    assert_eq!(
        routed(&p, ROUTE_POOL, Some("both")),
        owned("both", &["a", "b"])
    );
    assert_eq!(
        routed(&p, ROUTE_POOL, Some("a")),
        None,
        "an entry is no pool"
    );
    assert_eq!(routed(&p, ROUTE_POOL, Some("nowhere")), None, "unknown");
    assert_eq!(routed(&p, ROUTE_POOL, None), None, "none named");
}

#[test]
fn a_direct_route_walks_its_entry_alone_under_the_empty_label() {
    let p = pools(SECTION);
    assert_eq!(routed(&p, ROUTE_DIRECT, Some("a")), owned("", &["a"]));
    assert_eq!(
        routed(&p, ROUTE_DIRECT, Some("both")),
        None,
        "a pool is no entry"
    );
    for reserved in ["hooks", "upstream_credentials", "pools"] {
        assert_eq!(routed(&p, ROUTE_DIRECT, Some(reserved)), None, "{reserved}");
    }
    assert_eq!(routed(&p, ROUTE_DIRECT, None), None, "none named");
}

#[test]
fn a_model_serving_sections_entries_are_its_models() {
    let p = pools("models:\n  jev: {provider: p}\nhooks: []");
    assert_eq!(routed(&p, ROUTE_DIRECT, Some("jev")), owned("", &["jev"]));
    assert_eq!(
        routed(&p, ROUTE_DIRECT, Some("models")),
        None,
        "the map is no entry"
    );
}

#[test]
fn a_name_that_is_not_text_or_a_class_unknown_routes_nowhere() {
    let p = pools("m: {}");
    assert_eq!(p.resolve(ROUTE_DIRECT, Some(&[0xff, 0xfe])), None);
    assert_eq!(p.resolve(ROUTE_DIRECT + 1, Some(b"m")), None);
}

/// THE GRANT IS JUDGED OVER THE ROUTE AS NAMED, BEFORE ITS DESTINATION (FOLD-LLM, 2026-10-02; 1.5.5's
/// order: the pool's ACL, then its fallback pool's, and only then an unknown pool's no_destination).
#[test]
fn the_grant_is_judged_over_the_named_pool_then_its_fallback() {
    use busbar_contract::records::{ScopeRef, VirtualKey};
    let p = pools(
        "a: {}\nb: {}\npools:\n  hot:\n    members: [a]\n    on_exhausted: {fallback_pool: cold}\n\
         \x20 cold:\n    members: [b]",
    );
    let key = |scopes: Option<&[&str]>| VirtualKey {
        allowed_scopes: scopes.map(|s| s.iter().map(|n| ScopeRef::pool(*n)).collect()),
        ..VirtualKey::default()
    };
    let granted = |k: Option<&VirtualKey>, class: u8, named: &str| {
        p.granted(Some("pool"), k, class, Some(named.as_bytes()))
    };
    assert!(
        granted(None, ROUTE_POOL, "hot"),
        "ungoverned: nothing to enforce"
    );
    assert!(
        granted(Some(&key(None)), ROUTE_POOL, "hot"),
        "an omitted grant is every pool"
    );
    assert!(
        !granted(Some(&key(Some(&["hot"]))), ROUTE_POOL, "hot"),
        "its fallback is not granted"
    );
    assert!(granted(
        Some(&key(Some(&["hot", "cold"]))),
        ROUTE_POOL,
        "hot"
    ));
    assert!(
        !granted(Some(&key(Some(&[]))), ROUTE_POOL, "hot"),
        "an empty grant is none"
    );
    assert!(
        granted(Some(&key(Some(&["a"]))), ROUTE_DIRECT, "a"),
        "a direct route names its entry"
    );
    assert!(
        !granted(Some(&key(Some(&["hot"]))), ROUTE_POOL, "nowhere"),
        "an unknown pool is refused by its grant first"
    );
    assert!(granted(
        Some(&key(Some(&["nowhere"]))),
        ROUTE_POOL,
        "nowhere"
    ));
    assert!(
        p.granted(None, Some(&key(Some(&["hot"]))), ROUTE_POOL, Some(b"cold")),
        "a plane with no scope kind scopes nothing"
    );
}

/// AN ANONYMOUS UNIT NEVER REACHES A BILLED PATH (ARCHITECT P3 (a)): with no key it is admitted only
/// on an open line, and then as anonymous (a zero hold, no money); every other unkeyed unit is
/// refused; a keyed unit is the only one admitted onto the book.
#[test]
fn an_anonymous_unit_never_reaches_a_billed_path() {
    use super::Admission;
    use busbar_contract::records::VirtualKey;
    let key = std::sync::Arc::new(VirtualKey::default());
    assert_eq!(super::admission(None, true), Admission::Anonymous);
    assert_eq!(super::admission(None, false), Admission::Refused);
    assert_eq!(super::admission(Some(&key), true), Admission::Keyed);
    assert_eq!(super::admission(Some(&key), false), Admission::Keyed);
}

/// A DOOR PLANE'S FACTS name its fee units by their index among its billable classes; a fee unit
/// that is no billable class indexes nothing.
#[test]
fn the_door_facts_index_the_fee_units_among_the_billable_classes() {
    let f = super::door_facts(
        "p",
        &["grant"],
        &["a", "fee", "b"],
        &["fee", "nowhere"],
        "audit",
        Vec::new(),
    );
    assert_eq!(f.plane, "p");
    assert_eq!(f.scope_kind.as_deref(), Some("grant"));
    assert_eq!(&*f.fee_units, &[1]);
    assert_eq!(f.classes.len(), 3);
    assert_eq!(
        super::door_facts("p", &[], &[], &[], "a", Vec::new()).scope_kind,
        None
    );
}

/// A ROUTE'S EGRESS POOL: a pool route walks its own label; a direct route its entry's own cell,
/// named by (plane key, entry), never 1.5.5's shared empty cell.
#[test]
fn a_direct_route_walks_its_entrys_own_cell_and_a_pool_route_its_label() {
    let sep = busbar_kernel::governance::PLANE_LANE_SEP;
    assert_eq!(
        super::egress_pool("p", &(String::new(), vec!["m".to_string()])),
        format!("p{sep}m")
    );
    assert_eq!(
        super::egress_pool("p", &("both".to_string(), vec!["a".to_string()])),
        "both"
    );
}

/// A BLOCKED ADMISSION IS THE REFUSAL THE BUDGET UNIT'S OWN DOOR NAMES: a spend cap and a missing
/// group are over budget, every count cap a rate limit with its window's wait, a frozen group
/// frozen.
#[test]
fn a_blocked_admission_renders_as_the_budget_units_door_does() {
    use busbar_contract::caps::ReasonCode;
    use busbar_kernel::governance::LimitBlocked;
    let limit = |metric: &'static str, retry_after| LimitBlocked::Limit {
        group: "g".into(),
        metric,
        window: Some("day"),
        pool: None,
        downgrade_to: None,
        retry_after,
    };
    let budget = super::refusal_for(&limit("budget", Some(30)));
    assert_eq!(budget.reason(), ReasonCode::OverBudget);
    assert_eq!(budget.retry_after_secs(), Some(30));
    for metric in ["requests", "tokens", "concurrent"] {
        assert_eq!(
            super::refusal_for(&limit(metric, None)).reason(),
            ReasonCode::RateLimited,
            "{metric}"
        );
    }
    assert_eq!(
        super::refusal_for(&LimitBlocked::Disabled("g".into())).reason(),
        ReasonCode::GroupFrozen
    );
    assert_eq!(
        super::refusal_for(&LimitBlocked::MissingGroup("g".into())).reason(),
        ReasonCode::OverBudget
    );
}

/// A UNIT'S PRINCIPAL IS ON THE HOST'S UNIT RECORDS FOR ITS LIFE (so a host service the plane calls
/// inside its crossings, `entitlement.check`, answers for it): written once authenticate passes,
/// struck when its steps drop; a refused unit writes none.
#[test]
fn a_units_principal_is_recorded_from_authenticate_until_its_steps_drop() {
    use busbar_contract::caps::{Authenticate, Pass, PrincipalId};
    use busbar_kernel::host_units::UnitRecords;
    use busbar_kernel::teller::{UnitCtx, Units};
    let facts = super::door_facts("p", &[], &[], &[], "a", Vec::new());
    let pools = DoorPools::default();
    let records = std::sync::Arc::new(UnitRecords::default());
    let key = std::sync::Arc::new(busbar_contract::records::VirtualKey {
        id: "vk_one".into(),
        ..Default::default()
    });
    let seal = busbar_contract::caps::KernelSeal::acquire_for_kernel();
    let ctx = |n: u64| UnitCtx {
        key: busbar_contract::UnitKey::new(n),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let steps = |caller_key: Option<std::sync::Arc<busbar_contract::records::VirtualKey>>| {
        super::DoorSteps::new(
            &facts,
            &pools,
            std::sync::Arc::new(|_: &str| None),
            busbar_kernel::test_support::TestApp::new().build(),
            None,
            super::DoorCaller {
                principal: PrincipalId::new("vk_one"),
                key: caller_key,
                open: false,
                arrived: 0,
                records: Some(std::sync::Arc::clone(&records)),
            },
        )
    };
    let keyed = steps(Some(std::sync::Arc::clone(&key)));
    assert!(records.get(7).is_none(), "nothing before authenticate");
    let _ = keyed.authenticate(&Pass::<Authenticate>::mint(&seal), &ctx(7));
    let held = records.get(7).expect("recorded at authenticate");
    assert_eq!(
        held.principal.as_ref().map(|k| k.id.as_str()),
        Some("vk_one")
    );
    drop(keyed);
    assert!(records.get(7).is_none(), "struck when its steps drop");

    let unkeyed = steps(None);
    let _ = unkeyed.authenticate(&Pass::<Authenticate>::mint(&seal), &ctx(8));
    assert!(records.get(8).is_none(), "a refused unit writes no record");
}

// ── the members' routes (THE DESIGN §6 steps 2-3) ──────────────────────────────────────────────

/// The decisions-shaped plane facts: one dialect `d` whose default style is `bearer`, one outbound
/// need naming `bearer`.
fn styled() -> crate::root::loader::dispatch::kinds::plane::ServedFacts {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![(DIRECTION_OUTBOUND, "bearer")],
        dialects: vec!["d"],
        dialect_auth: vec![(0, "bearer")],
        ..Default::default()
    }
}

fn provider(protocol: &str, style: Option<&str>) -> super::ProviderRoute {
    super::ProviderRoute {
        base_url: "http://127.0.0.1:9".to_string(),
        protocol: protocol.to_string(),
        credential: busbar_contract::secret_ref::SecretRef::none(),
        style: style.map(str::to_string),
        token_url: None,
        scope: None,
        subject: None,
    }
}

/// The routes `section`'s members resolve to over `providers`, or why the load is refused.
fn resolve(
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    let section: serde_yaml::Value = serde_yaml::from_str(section).expect("yaml");
    let providers = providers
        .iter()
        .map(|(n, p)| ((*n).to_string(), p.clone()))
        .collect();
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    let auths = super::OutboundAuths::new(dispatcher, crate::LINKED.auths, None);
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let conns: std::sync::Arc<dyn busbar_contract::conn::PollConns> =
        std::sync::Arc::new(busbar_core_connector::Connector::new());
    let reach = super::DoorReach {
        providers: &providers,
        secrets: &secrets,
        auths: &auths,
        conns,
        stream_ceiling_secs: 1,
    };
    super::member_routes(&section, &DoorPools::of(&section), &styled(), &reach)
}

// The positive binding proof needs a bearer-serving auth plugin LINKED (the default distribution's
// `busbar-auth-header`); the member cannot bind to a style no linked/dropped-in plugin serves. A
// `--no-default-features` build without `auth-header` links none, so the bind is refused there (the
// sibling test proves that refusal), exactly as 1.5.5 bound only when a credential source was present.
#[cfg(feature = "auth-header")]
#[test]
fn a_member_is_bound_under_its_dialects_default_style_on_the_need_that_style_names() {
    let routes = resolve("models: {m: {provider: p}}", &[("p", provider("d", None))])
        .expect("the member resolves");
    let route = &routes["m"];
    assert_eq!(route.need.0, 0);
    assert_eq!(route.provider, "p");
    assert_eq!(route.base_url, "http://127.0.0.1:9");
    assert!(
        route.auth.is_some(),
        "its credential is bound by the plugin serving `bearer`"
    );
}

#[test]
fn a_member_that_cannot_be_reached_refuses_the_load_naming_it() {
    let unknown = resolve("models: {m: {provider: q}}", &[("p", provider("d", None))]);
    assert!(
        unknown
            .as_ref()
            .is_err_and(|e| e.contains("'m'") && e.contains("'q'")),
        "{:?}",
        unknown.err()
    );
    // A dialect the plane states no default for, and no `auth:`: no style.
    let styleless = resolve("models: {m: {provider: p}}", &[("p", provider("x", None))]);
    assert!(
        styleless.as_ref().is_err_and(|e| e.contains("no `auth:`")),
        "{:?}",
        styleless.err()
    );
    // A style no outbound need names.
    let unmatched = resolve(
        "models: {m: {provider: p}}",
        &[("p", provider("d", Some("api-key")))],
    );
    assert!(
        unmatched.as_ref().is_err_and(|e| e.contains("api-key")),
        "{:?}",
        unmatched.err()
    );
}
