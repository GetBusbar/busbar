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

/// RED (ARCHITECT timeout ruling; R2-G "per-member ... timeout"): an entry's reserved `timeout:` is
/// its member's attempt bound, read for every entry alike — a section's own entries and a
/// model-serving section's `models` entries; an entry that writes none has no bound of its own.
#[test]
fn an_entrys_timeout_is_its_members_attempt_bound() {
    let p = pools("a: { timeout: 10s }\nb: {}\npools:\n  both:\n    members: [a, b]");
    assert_eq!(p.timeout_ms("a"), Some(10_000));
    assert_eq!(
        p.timeout_ms("b"),
        None,
        "none written: the walk's own budget"
    );
    assert_eq!(p.timeout_ms("both"), None, "a pool is no entry");
    let m = pools("models:\n  m1: { provider: p, timeout: 2m }\n  m2: { provider: p }");
    assert_eq!(m.timeout_ms("m1"), Some(120_000));
    assert_eq!(m.timeout_ms("m2"), None);
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
    let p = pools("models:\n  m: {provider: p}\nhooks: []");
    assert_eq!(routed(&p, ROUTE_DIRECT, Some("m")), owned("", &["m"]));
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
    use busbar_contract::caps::{Authenticate, PrincipalId};
    use busbar_kernel::host_units::UnitRecords;
    use busbar_kernel::teller::{UnitCtx, Units};
    let facts = super::door_facts("p", &[], &[], &[], "a", Vec::new());
    let pools = DoorPools::default();
    let records = std::sync::Arc::new(UnitRecords::default());
    let key = std::sync::Arc::new(busbar_contract::records::VirtualKey {
        id: "vk_one".into(),
        ..Default::default()
    });
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
                depth: 0,
                credential: None,
            },
        )
    };
    let keyed = steps(Some(std::sync::Arc::clone(&key)));
    assert!(records.get(7).is_none(), "nothing before authenticate");
    let _ = keyed.authenticate(
        &busbar_kernel::test_support::tokens::pass::<Authenticate>(),
        &ctx(7),
    );
    let held = records.get(7).expect("recorded at authenticate");
    assert_eq!(
        held.principal.as_ref().map(|k| k.id.as_str()),
        Some("vk_one")
    );
    drop(keyed);
    assert!(records.get(7).is_none(), "struck when its steps drop");

    let unkeyed = steps(None);
    let _ = unkeyed.authenticate(
        &busbar_kernel::test_support::tokens::pass::<Authenticate>(),
        &ctx(8),
    );
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
        params: super::StyleParams::default(),
    }
}

/// The routes `section`'s members resolve to over `providers` for a plane stating `facts`, or why
/// the load is refused.
fn resolve_for(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    resolve_over(section, providers, facts)
}

/// [`resolve`], over the plane facts `served`.
fn resolve_over(
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    resolve_upgrading(section, providers, served, Vec::new())
}

/// [`resolve_over`], with `upgrades` the linked claims that open at an upgrade.
fn resolve_upgrading(
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    upgrades: Vec<&'static str>,
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    let section: serde_yaml::Value = serde_yaml::from_str(section).expect("yaml");
    let providers = providers
        .iter()
        .map(|(n, p)| ((*n).to_string(), p.clone()))
        .collect();
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    crate::root::connector::install_io(&dispatcher);
    let auths = super::OutboundAuths::new(
        dispatcher,
        crate::LINKED.auths,
        None,
        crate::root::loader::dispatch::ConnTable::NoNeeds,
    );
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let conns: std::sync::Arc<dyn busbar_contract::conn::PollConns> =
        std::sync::Arc::new(busbar_core_connector::Connector::new());
    let reach = super::DoorReach {
        providers: &providers,
        secrets: &secrets,
        auths: std::sync::Arc::new(auths),
        conns,
        stream_ceiling_secs: 1,
        upgrades,
    };
    super::member_routes(&section, &DoorPools::of(&section), served, &reach)
}

/// SEAM-L(n), `spelled_for`: a need over a framer composed over the base URL's carrier dials the
/// same authority and path in that framer's scheme, its secured form for a secured base; a need
/// over any other transport, or a base in no upgradable scheme, dials the base as written.
#[test]
fn a_need_over_an_upgrade_framer_spells_the_base_url_in_its_scheme() {
    let upgrades = ["ws"];
    assert_eq!(
        super::spelled_for("https://api.example/v1", "ws", &upgrades).as_deref(),
        Some("wss://api.example/v1")
    );
    assert_eq!(
        super::spelled_for("http://127.0.0.1:9/v1", "ws", &upgrades).as_deref(),
        Some("ws://127.0.0.1:9/v1")
    );
    assert_eq!(
        super::spelled_for("https://api.example", "http", &upgrades),
        None
    );
    assert_eq!(super::spelled_for("https://api.example", "ws", &[]), None);
    assert_eq!(super::spelled_for("unix:///sock", "ws", &upgrades), None);
}

/// SEAM-L(n), THE MEMBER'S ROUTE: a member bound over an upgrade framer's need dials that need at
/// its base URL in the framer's scheme, its own (http) need at the base as written. RED: the route
/// carried the provider's base URL alone, so the framer's need dialled https. The bearer style is the
/// linked header auth plugin's, so the leg runs where it is linked.
#[cfg(feature = "auth-header")]
#[test]
fn a_member_bound_over_an_upgrade_need_dials_its_spelled_base() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let served = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_OUTBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "bearer"),
        ],
        need_transports: vec!["http", "ws"],
        ..styled()
    };
    let routes = resolve_upgrading(
        "models: {m: {provider: p}}",
        &[("p", provider("d", None))],
        &served,
        vec!["ws"],
    )
    .expect("the member resolves");
    let route = &routes["m"];
    let base = route.base_url.clone();
    let spelled = base.replacen("http://", "ws://", 1);
    assert!(base.starts_with("http://"), "{base}");
    assert_eq!(route.ride(0).map(|r| r.base_url), Some(base.as_str()));
    assert_eq!(route.ride(2).map(|r| r.base_url), Some(spelled.as_str()));
}

/// MULTI-NEED (ARCHITECT Q-L5B-NEEDS 2026-10-03): a member binds EVERY outbound need its style
/// names, one per transport, the first as its own and the rest riding beside it, each opened when
/// a far request names it. The bearer style is the linked header auth plugin's, so the leg runs
/// where it is linked (single-plane rows link none).
#[cfg(feature = "auth-header")]
#[test]
fn a_member_binds_every_need_its_style_names_one_per_transport() {
    use busbar_contract::abi::host::conn::connector::{DIRECTION_INBOUND, DIRECTION_OUTBOUND};
    let served = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_INBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "api-key"),
        ],
        need_transports: vec!["ws", "ws", "http", "ws"],
        ..styled()
    };
    let routes = resolve_over(
        "models: {m: {provider: p}}",
        &[("p", provider("d", None))],
        &served,
    )
    .expect("the member resolves");
    let route = &routes["m"];
    assert_eq!(route.need.0, 1, "its first bound need is its own");
    let rides: Vec<u32> = route.rides.iter().map(|(n, _)| n.0).collect();
    assert_eq!(
        rides,
        [2],
        "the http need rides beside it; the api-key need is not its style"
    );
    assert_eq!(route.ride(3).map(|r| r.need.0), Some(2));
    assert_eq!(route.ride(0).map(|r| r.need.0), Some(1));
    assert!(
        route.ride(4).is_none(),
        "a need its style does not name is no ride"
    );
}

/// The routes `section`'s members resolve to over `providers`, or why the load is refused.
fn resolve(
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    resolve_for(&styled(), section, providers)
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

// ── the minted credential of a member bound under an OAuth grant (TODO row 22) ─────────────────

/// A connection table standing in for the token endpoint: framed needs, each declaration and each
/// open recorded, each open answered by the endpoint's next reply (`expires_in` 2, then 3600), one
/// piece per read.
#[derive(Default)]
pub(crate) struct TokenEndpoint {
    slab: busbar_contract::conn::ConnSlab<()>,
    declared: std::sync::Mutex<Vec<(u32, u32, Option<String>)>>,
    opened: std::sync::Mutex<Vec<Opened>>,
    replies: std::sync::Mutex<Replies>,
    /// The reply body to a request body, when the endpoint answers by what it was asked (an RFC
    /// 8693 exchange's token names its scope); `None` = the minted replies above.
    answer: Option<fn(&str) -> String>,
}

/// What one open carried: the need, the target, the head target, the body.
type Opened = (u32, String, Vec<u8>, String);

/// Each open's reply, piece by piece, with its bytes.
type Replies = std::collections::HashMap<
    busbar_contract::conn::ConnId,
    std::collections::VecDeque<(busbar_contract::conn::Piece, Vec<u8>)>,
>;

fn reply_piece(kind: busbar_contract::conn::PieceKind, len: usize) -> busbar_contract::conn::Piece {
    use busbar_contract::conn::PieceKind;
    busbar_contract::conn::Piece {
        kind,
        stream: busbar_contract::ids::StreamId(0),
        len,
        end: kind != PieceKind::Fields,
        status: None,
        status_code: (kind == PieceKind::Fields).then_some(200),
        status_namespace: None,
        retry_after_secs: None,
        reason: None,
    }
}

impl busbar_contract::conn::DeclaredConns for TokenEndpoint {
    fn declare(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        spec: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        target: Option<&str>,
        _trust: Option<&str>,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.declared
            .lock()
            .unwrap()
            .push((need.0, spec.egress_class, target.map(str::to_owned)));
        if !spec.target_from.is_empty() && target.is_none() {
            return Err(busbar_contract::conn::ConnError::Refused);
        }
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
    ) -> Option<Result<(), busbar_contract::conn::ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn framed(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
    ) -> bool {
        true
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
}

impl busbar_contract::conn::Conns for TokenEndpoint {
    fn open(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        use busbar_contract::conn::PieceKind;
        self.slab.check_need(caller, need)?;
        let mut opened = self.opened.lock().unwrap();
        opened.push((
            need.0,
            desc.target.to_owned(),
            desc.head_target.to_vec(),
            String::from_utf8_lossy(desc.body).into_owned(),
        ));
        let n = opened.len();
        let body = match self.answer {
            Some(answer) => answer(&opened[n - 1].3),
            None => format!(
                r#"{{"access_token":"oracle-minted-{n}","expires_in":{}}}"#,
                if n == 1 { 2 } else { 3600 }
            ),
        };
        let id = self.slab.insert(caller, need, ())?;
        self.replies.lock().unwrap().insert(
            id,
            std::collections::VecDeque::from([
                (reply_piece(PieceKind::Fields, 0), Vec::new()),
                (reply_piece(PieceKind::Body, body.len()), body.into_bytes()),
                (reply_piece(PieceKind::Completion, 0), Vec::new()),
            ]),
        );
        Ok(id)
    }
    fn write(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        b: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Ok(b.len())
    }
    fn read(
        &self,
        c: busbar_contract::conn::InstanceId,
        id: busbar_contract::conn::ConnId,
        _: u64,
        buf: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        self.slab.get(c, id)?;
        let (p, bytes) = self
            .replies
            .lock()
            .unwrap()
            .get_mut(&id)
            .and_then(std::collections::VecDeque::pop_front)
            .ok_or(busbar_contract::conn::ConnError::Closed)?;
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(p)
    }
    fn wait(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: &[busbar_contract::conn::ConnId],
        _: u64,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Pending)
    }
    fn facts(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn close(
        &self,
        c: busbar_contract::conn::InstanceId,
        id: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.replies.lock().unwrap().remove(&id);
        self.slab.remove(c, id).map(|_| ())
    }
}

/// The authorization a `fields` answer presents.
fn presented(answer: Option<&busbar_contract::auth_calls::Fields>) -> Option<String> {
    match answer? {
        busbar_contract::auth_calls::Fields::Ready(fields) => fields.iter().find_map(|f| {
            (f.name == b"authorization")
                .then(|| String::from_utf8_lossy(f.value.expose_secret()).into_owned())
        }),
        _ => None,
    }
}

/// THE MEMBER UNDER `auth: oauth-client-credentials`, BOUND BY THE COMPOSITION (THE DESIGN §6 steps
/// 2-3, §5, §6.5): the auth plugin serving the style is opened over the provider's own settings,
/// so its `loopback-allowed` mint need is declared pinned to the provider's `token_url`; its tick schedule runs
/// without anyone driving it; the member's binding presents nothing until the first mint lands,
/// then the minted bearer, then the refreshed one ahead of the first token's expiry (the oracle
/// cell `egress.auth|oauth-cc|mint-refresh`: the second upstream request carries the refreshed
/// authorization).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_under_an_oauth_grant_presents_its_minted_then_refreshed_bearer() {
    use busbar_contract::abi::host::conn::connector::{
        DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED,
    };
    use busbar_contract::auth_calls::FieldsRequest;
    const TOKEN_URL: &str = "https://login.example.com/tenant/oauth2/v2.0/token";
    let key_file =
        std::env::temp_dir().join(format!("busbar-door-steps-oauth-{}", std::process::id()));
    std::fs::write(&key_file, "oracle-client-0001:oracle:secret:with:colons").expect("key");
    let providers: std::collections::BTreeMap<String, super::ProviderRoute> = [(
        "p".to_string(),
        super::ProviderRoute {
            base_url: "http://127.0.0.1:9".to_string(),
            protocol: "d".to_string(),
            credential: busbar_contract::secret_ref::SecretRef::file(
                key_file.display().to_string(),
            ),
            style: Some("oauth-client-credentials".to_string()),
            params: super::StyleParams {
                token_url: Some(TOKEN_URL.to_string()),
                scope: Some("https://cognitiveservices.azure.com/.default".to_string()),
                subject: None,
            },
        },
    )]
    .into();
    let table = std::sync::Arc::new(TokenEndpoint::default());
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    crate::root::connector::install_io(&dispatcher);
    let linked: [busbar_kernel::preflight::LinkedAuth; 1] =
        [("busbar-auth-oauth", busbar_auth_oauth::door)];
    let auths = super::OutboundAuths::new(
        dispatcher,
        &linked,
        None,
        crate::root::loader::dispatch::ConnTable::Host(std::sync::Arc::clone(&table)
            as std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>),
    );
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let reach = super::DoorReach {
        providers: &providers,
        secrets: &secrets,
        auths: std::sync::Arc::new(auths),
        conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
        stream_ceiling_secs: 1,
        upgrades: Vec::new(),
    };
    let section: serde_yaml::Value =
        serde_yaml::from_str("models: {m: {provider: p}}").expect("yaml");
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![(DIRECTION_OUTBOUND, "oauth-client-credentials")],
        dialects: vec!["d"],
        ..Default::default()
    };
    let routes = super::member_routes(&section, &DoorPools::of(&section), &facts, &reach)
        .expect("the member resolves");
    let _ = std::fs::remove_file(&key_file);
    let binding = routes["m"].auth.clone().expect("its credential is bound");
    assert!(
        table.declared.lock().unwrap().contains(&(
            0,
            EGRESS_LOOPBACK_ALLOWED,
            Some(TOKEN_URL.to_string())
        )),
        "the plugin's mint need, pinned to the provider's token_url: {:?}",
        table.declared.lock().unwrap()
    );

    // The first request waits for the first mint (no empty credential), then carries it.
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        binding
            .auth
            .fields(binding.handle, FieldsRequest::default(), 0),
    )
    .await
    .expect("the first mint lands");
    assert_eq!(
        presented(Some(&first)).as_deref(),
        Some("Bearer oracle-minted-1")
    );
    // The refresh lands ahead of the first token's expiry; the next request carries it.
    let refreshed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let now = binding
                .auth
                .fields_now(binding.handle, &FieldsRequest::default());
            if presented(now.as_ref()).as_deref() == Some("Bearer oracle-minted-2") {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(refreshed.is_ok(), "the refreshed bearer is presented");
    let opened = table.opened.lock().unwrap();
    assert_eq!(opened.len(), 2, "the mint and the refresh: {opened:?}");
    assert!(opened.iter().all(|(need, target, words, _)| *need == 0
        && target == TOKEN_URL
        && words == b"/tenant/oauth2/v2.0/token"));
    assert_eq!(
        opened[1].3,
        "grant_type=client_credentials&client_id=oracle-client-0001&client_secret=\
         oracle%3Asecret%3Awith%3Acolons&scope=https%3A%2F%2Fcognitiveservices.azure.com%2F.default"
    );
}

/// A REGISTRATION SECTION'S MEMBERS (ARCHITECT Q-L3B-ROUTES): where the plane's need states a
/// member-target path (`settings.*.<key>`), each registration is a member reached at its own
/// `<key>` on that need, its metering rows naming the registration, with no provider and no auth
/// binding. A registration that states no target has no route; the reserved words are no member.
#[test]
fn a_registration_member_is_reached_at_its_own_target() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![(DIRECTION_OUTBOUND, "")],
        need_targets: vec!["settings.*.url"],
        ..Default::default()
    };
    let routes = resolve_for(
        &facts,
        "fs: {url: \"http://127.0.0.1:7/rpc\"}\nlocal: {command: run}\nhooks: [h]\n",
        &[],
    )
    .expect("the registrations resolve");
    assert_eq!(routes.keys().collect::<Vec<_>>(), ["fs"]);
    let fs = &routes["fs"];
    assert_eq!(fs.need.0, 0);
    assert_eq!(
        fs.base_url, "http://127.0.0.1:7",
        "its URL's origin; the plane spells the path"
    );
    assert_eq!(fs.provider, "fs");
    assert!(fs.auth.is_none());
    // A plane whose need states no member target reaches no registration.
    let none = resolve_for(&styled(), "fs: {url: \"http://127.0.0.1:7/rpc\"}\n", &[])
        .expect("nothing to resolve");
    assert!(none.is_empty());
}

/// THE TOOL DOOR, SERVED END TO END (the fold's flip; BUSBAR-1.6.0.md Part 3 section 12,
/// "The switch"; TODO P3) — the tool plane's root leg (`qa/teller-steps.json`): a
/// `tools/call` the tool door claims reaches that plane's driver through its route on the data
/// router (mounted at the router's construction), behind the deployment's auth gate, is admitted
/// and charged by the money steps, crosses the plane's door (`arrive`, the ATTEMPT, the far end's
/// answer), leaves through the host chokepoint (the plane's egress walk over the process's
/// connector) to a real tool server on loopback, and comes back a served 200 whose money record is
/// posted: the governance ledger holds the admitted request and the node's book the unit's one line
/// with the tool call the plane reported. The plane is the tool plane's own door, linked (compiled
/// in) and bound through the loader's one load, its need declared on the connector, exactly as its
/// linked row binds it. The dropped-in fold of the same door is the plane crate's own
/// conformance suite (`tests/conformance.rs`, one transcript through both loads).
#[cfg(all(linked_axis_plane_door, linked_axis_node))]
pub(crate) mod tool_door {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::http::StatusCode;
    use busbar_contract::abi::mechanism::door::DoorFn;
    use busbar_contract::caps::ReasonCode;
    use busbar_contract::conn::{DeclaredConns, PollConns};
    use busbar_kernel::cost::CostModel;
    use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
    use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec, PLANE_LANE_SEP};
    use busbar_kernel::plane_driver::{refusal_status, EndPost, PlaneMoney};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::root::loader::dispatch::kinds::plane::Plane;
    use crate::root::loader::dispatch::{
        load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    use crate::root::plane_node::{Node, NodeEndPost};
    use crate::root::serve::planes_tests::{composed_services, money, Published, PUBLISHING};
    use crate::root::serve::{compose_planes, door_routes};

    /// The deployment's dated card history the served unit is pinned to at its door: one entry, no
    /// price (billing off: the counts are the unit's fact and price at nothing).
    static CARD: std::sync::LazyLock<crate::root::kernel::RootHistory> =
        std::sync::LazyLock::new(|| {
            let holder = crate::root::kernel::RootHistory::default();
            holder.apply(
                crate::root::kernel::card_from_config(
                    std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                    0,
                    true,
                ),
                1_000,
            );
            holder
        });

    /// The governance book's admin token.
    pub(crate) const ADMIN_TOKEN: &str = "admintok";

    /// The deployment's public base URL: the door claims its routes under it.
    pub(crate) const PUBLIC_URL: &str = "http://127.0.0.1";

    /// The plane's wire words that its Statement does not carry, as DATA
    /// (`tests/fixtures/tool_door_wire.txt`): one `key = value` per line, `#` a comment.
    pub(crate) fn surface(key: &str) -> &'static str {
        include_str!("fixtures/tool_door_wire.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim() == key).then(|| v.trim())
            })
            .unwrap_or_else(|| panic!("fixtures/tool_door_wire.txt has no `{key}` row"))
    }

    /// The section the tool door owns beside its settings: its endpoint block, as the fixture
    /// states it (the root spells no plane's section).
    pub(crate) fn endpoint_section() -> &'static str {
        surface("endpoint_section")
    }

    /// The door's one endpoint (its endpoint section's fixed path).
    fn endpoint() -> String {
        format!("/{}", endpoint_section())
    }

    /// The revision the door speaks, as a request states it.
    pub(crate) fn protocol_version() -> &'static str {
        surface("protocol_version")
    }

    /// THE TOOL DOOR: of the linked plane doors, the one whose Statement owns the endpoint section
    /// the fixture names (found by binding each, once).
    pub(crate) fn line_door() -> DoorFn {
        static DOOR: std::sync::OnceLock<DoorFn> = std::sync::OnceLock::new();
        *DOOR.get_or_init(|| {
            let section = endpoint_section();
            let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
            crate::root::connector::install_io(&dispatcher);
            crate::LINKED
                .plane_doors
                .iter()
                .copied()
                .find(|&door| {
                    let Ok(row) = LinkedRow::of(door) else {
                        return false;
                    };
                    load_linked::<Plane>(
                        &row,
                        Bind {
                            instance: Arc::from("line-door-probe"),
                            max_inflight_cap: 64,
                            sink: Arc::new(NoSink),
                            dispatcher: dispatcher.adopter(),
                            conns: crate::root::loader::dispatch::ConnTable::Probe,
                        },
                    )
                    .is_ok_and(|plane| plane.served().owns.contains(&section))
                })
                .expect("a linked plane door owns the endpoint section")
        })
    }

    /// A stateless-revision `tools/call` of the one approved tool.
    pub(crate) const CALL: &str = r#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"fs_read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

    /// A stateless-revision `tools/list`: the plane's own to answer.
    const LIST: &str = r#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

    /// The tool server's answer: a tool result.
    const ANSWER: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"from the server"}]}}"#;

    /// The `tools:` section: one server on loopback at `port`, one approved tool.
    pub(crate) fn section(port: u16) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
         tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    /// The one tool the test server serves, as its `tools/list` states it: what verify-on-call
    /// fetches before a call, and what the section approves.
    pub(crate) const TOOL_DESCRIPTION: &str = "reads a file from disk";

    /// That tool's input schema.
    pub(crate) fn tool_schema() -> serde_json::Value {
        serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}})
    }

    /// That tool's digest: the approval the section writes.
    pub(crate) fn tool_digest() -> String {
        surface("tool_digest").to_string()
    }

    /// That tool, listed.
    pub(crate) fn tool_listing() -> serde_json::Value {
        serde_json::json!([
            {"name": "read_file", "description": TOOL_DESCRIPTION, "inputSchema": tool_schema()}
        ])
    }

    /// A POST of `body` (a `tools/call`) to the door's endpoint on `router`, with `token` as its bearer
    /// or with none: the response's status and body.
    pub(crate) async fn send(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
    ) -> (StatusCode, Vec<u8>) {
        send_as(router, token, body, "tools/call", Some("fs_read_file")).await
    }

    /// A POST of `body` naming `method` (and the tool `name`, where it names one) to the door's
    /// endpoint: the response's status and body.
    pub(crate) async fn send_as(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
        method: &str,
        name: Option<&str>,
    ) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = send_headed(router, token, body, method, name).await;
        (status, body)
    }

    /// [`send_as`], with the response's head fields.
    pub(crate) async fn send_headed(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
        method: &str,
        name: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        use tower::ServiceExt as _;
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(endpoint())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header(surface("protocol_header"), protocol_version())
            .header(surface("method_header"), method);
        if let Some(name) = name {
            req = req.header(surface("name_header"), name);
        }
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let req = req
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request");
        let response = router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        (status, headers, bytes.to_vec())
    }

    /// A tool server on loopback answering every request with [`ANSWER`]; what it was sent comes back
    /// on the channel, one request per connection.
    pub(crate) async fn tool_server() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_listing(Arc::new(std::sync::Mutex::new(tool_listing()))).await
    }

    /// [`tool_server`], answering a `tools/list` with the tool list `tools` holds when it is asked
    /// (the list may change under it: the rug-pull).
    pub(crate) async fn tool_server_listing(
        tools: Arc<std::sync::Mutex<serde_json::Value>>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_answering(Arc::new(move |request: &str| {
            if request.contains("\"tools/list\"") {
                let list = tools.lock().map(|t| t.clone()).unwrap_or_default();
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": list}})
                    .to_string()
            } else {
                ANSWER.to_string()
            }
        }))
        .await
    }

    /// A tool server on loopback answering each request (its head and body, as text) with what
    /// `answer` makes of it; every request is heard.
    pub(crate) async fn tool_server_answering(
        answer: Arc<dyn Fn(&str) -> String + Send + Sync>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_replying(Arc::new(move |request: &str| (200, answer(request)))).await
    }

    /// What a test server answers a request with: its status and body. Status [`STALL`] answers
    /// nothing: the request is taken and the connection held open, unanswered.
    pub(crate) type Replies = Arc<dyn Fn(&str) -> (u16, String) + Send + Sync>;

    /// The status a [`Replies`] answers with to take a request and never answer it: a stalled server.
    pub(crate) const STALL: u16 = 0;

    /// A tool server on loopback answering each request with the status and body `answer` makes of
    /// it; every request is heard.
    pub(crate) async fn tool_server_replying(
        answer: Replies,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let sent = sent.clone();
                let answer = Arc::clone(&answer);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let mut got = Vec::new();
                    // The head, then the body its content-length states.
                    loop {
                        let Ok(n) = socket.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        got.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&got).to_string();
                        if let Some(at) = text.find("\r\n\r\n") {
                            let length = text[..at]
                                .lines()
                                .find_map(|l| {
                                    let (name, value) = l.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                                .unwrap_or(0);
                            if got.len() >= at + 4 + length {
                                let _ = sent.send(text);
                                break;
                            }
                        }
                    }
                    let (status, answer) = answer(&String::from_utf8_lossy(&got));
                    if status == STALL {
                        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                        drop(socket);
                        return;
                    }
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                         connection: close\r\n\r\n{answer}",
                        answer.len()
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (port, heard)
    }

    /// A loopback port nothing listens on (bound, then released): a server that is down.
    async fn down_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        listener.local_addr().expect("its address").port()
    }

    /// THE COMPOSED MCP DOOR, served: the data router built with its routes, the governance book with
    /// one minted key, the money steps and the node's book the unit settles on.
    pub(crate) struct Rig {
        pub(crate) router: axum::Router,
        /// The admin router, with the door's stated admin routes mounted.
        pub(crate) admin: axum::Router,
        pub(crate) gov: Arc<GovState>,
        pub(crate) app: Arc<busbar_kernel::state::App>,
        pub(crate) key: Arc<busbar_contract::records::VirtualKey>,
        pub(crate) token: String,
        money_steps: Arc<PlaneMoney>,
        post: Arc<NodeEndPost>,
        pub(crate) book: crate::root::durability::NodeBook,
        pub(crate) plane_key: String,
        /// The record store the kernel's services persist the plane's records in.
        pub(crate) store: Arc<busbar_kernel::governance::MemoryStore>,
        /// The token endpoint the auth plugins' own needs reach: each RFC 8693 exchange is answered
        /// `tok-<its scope, as the form carried it>`, and every request is recorded.
        pub(crate) tokens: Arc<super::TokenEndpoint>,
        /// The door's routes the data router was built with: `(path, method, admission bar)`.
        pub(crate) door_table: Vec<(
            String,
            String,
            busbar_contract::abi::mechanism::route::RouteAuth,
        )>,
        /// The door, as bound: what a new generation is published through (`refresh`).
        pub(crate) plane: crate::root::boot::DoorPlane,
        /// How far the kernel's monotonic clock (`clock.now`) reads ahead of the runtime's.
        pub(crate) clock: Arc<std::sync::atomic::AtomicU64>,
    }

    impl Rig {
        /// The mcp door composed as `instance`, its one server routed to `port` on loopback, its key's
        /// pool grant `allowed_pools` (`None` = every scope).
        fn new(instance: &'static str, port: u16, allowed_pools: Option<Vec<String>>) -> Self {
            Self::with(
                instance,
                port,
                allowed_pools,
                None,
                None,
                Footing::own(),
                &|app| app,
            )
        }

        /// [`Self::new`], its kernel `App` configured further by `configure` before it is built.
        pub(crate) fn with(
            instance: &'static str,
            port: u16,
            allowed_pools: Option<Vec<String>>,
            block: Option<serde_yaml::Value>,
            tools: Option<serde_yaml::Value>,
            footing: Footing<'_>,
            configure: &dyn Fn(
                busbar_kernel::test_support::TestApp,
            ) -> busbar_kernel::test_support::TestApp,
        ) -> Self {
            // THE CONNECTOR, over every linked transport door (the default distribution links the
            // http framer's door), its dials judged by a destination guard that admits loopback.
            let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
                block_private_addresses: footing.guarded,
                ..Default::default()
            })
            .expect("the guard");
            // The process's host services: the kernel's composed services the dispatcher answers the
            // door's service calls with (`entitlement.check` over the unit's recorded principal), the
            // same ones the plane is admitted to, composed whole: a record store (the plane's chained
            // call record is appended to its journal there) and the pool its store calls run on.
            // THE MONEY: a signing governance book with one minted key, the node's book bound.
            let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
            let gov = Arc::new(
                GovState::new_with_signer(
                    Arc::new(MemoryStore::new()),
                    Some(ADMIN_TOKEN.to_string()),
                    Some(signer),
                )
                .expect("governance"),
            );
            // A fleet node reads the first node's book: one key registry, one signing key.
            let (gov, key, token) = match footing.book {
                Some(first) => (
                    Arc::clone(&first.gov),
                    Arc::clone(&first.key),
                    first.token.clone(),
                ),
                None => {
                    let (key, token) = gov
                        .mint_signed(
                            NewKeySpec {
                                name: "agent".to_string(),
                                allowed_pools,
                                ..Default::default()
                            },
                            4_000_000_000,
                            1_700_000_000,
                        )
                        .expect("mint");
                    gov.hydrate_budgets(&CostModel::flat(1), 0)
                        .expect("hydrate");
                    (gov, Arc::new(key), token.expose_secret().to_string())
                }
            };
            let clock = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let (late, store) = records_composed(footing.ledger, Arc::clone(&gov), &clock);
            let dispatcher = Arc::new(Dispatcher::with_services(
                DispatchConfig::default(),
                Arc::clone(&late) as Arc<dyn busbar_contract::services::HostServices>,
            ));
            crate::root::connector::install_io(&dispatcher);
            // Its connection reads through a ticket (the door's `exchange`) wake on the dispatcher.
            let connector = busbar_core_connector::process::build(
                || {
                    crate::root::connector::entries(
                        crate::LINKED_TRANSPORT_DOORS,
                        &busbar_contract::transport::TransportSettings::default(),
                    )
                },
                judge,
                &[],
                dispatcher.conn_waker(),
                busbar_core_connector::pool::PoolPosture::NONE,
            )
            .expect("the connector builds");
            let plane = bound(
                instance,
                &dispatcher,
                crate::root::loader::dispatch::ConnTable::Host(
                    Arc::clone(&connector) as Arc<dyn DeclaredConns>
                ),
            );
            let caller = plane.instance();
            let section_key = plane.served().section;
            assert_eq!(
                section_key,
                surface("section"),
                "the door opens with the section its grammar reads"
            );

            let node = Arc::new(Node::new());
            let book = crate::root::durability::node_book_over(Box::new(|| CARD.pin()));
            node.bind_book(Arc::clone(&book.durability));
            let post = Arc::new(NodeEndPost::new(Arc::clone(&node)));
            let site = Arc::clone(&post);
            let book_money = Arc::clone(&gov);
            let plane_money = move || {
                Arc::new(PlaneMoney::new(
                    Arc::clone(&book_money),
                    Arc::clone(&site) as Arc<dyn EndPost>,
                ))
            };

            // THE COMPOSITION: the door opened with its `tools:` section and the deployment's public
            // base URL, driven, its egress sealed as production seals it (ARCHITECT Q-L3B-ROUTES): the
            // one server's member route is read off its own registration (`url`, the door's need's
            // member target), no provider and no auth binding (the server takes no credential).
            let mut sections = BTreeMap::new();
            // Its endpoint block, when the deployment writes one, under the section it owns.
            if let Some(block) = block {
                sections.insert(plane.served().owns[0], block);
            }
            sections.insert(section_key, tools.unwrap_or_else(|| section(port)));
            let providers = BTreeMap::new();
            let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
            // The build's linked auth rows, and the OAuth plugin (a dropped-in plugin in a
            // deployment) a token-exchange registration's style is served by. Its own need (the
            // `open-web` token endpoint, connection security only) reaches a table standing in for
            // the authorization server.
            let mut linked = crate::LINKED.auths.to_vec();
            linked.push(("busbar-auth-oauth", busbar_auth_oauth::door));
            let tokens = Arc::new(super::TokenEndpoint {
                answer: Some(|body: &str| {
                    let scope = body
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("scope="))
                        .unwrap_or_default();
                    format!(r#"{{"access_token":"tok-{scope}","expires_in":3600}}"#)
                }),
                ..super::TokenEndpoint::default()
            });
            let auths = crate::root::door_steps::OutboundAuths::new(
                Arc::clone(&dispatcher),
                &linked,
                None,
                crate::root::loader::dispatch::ConnTable::Host(
                    Arc::clone(&tokens) as Arc<dyn DeclaredConns>
                ),
            );
            let reach = crate::root::door_steps::DoorReach {
                providers: &providers,
                secrets: &secrets,
                auths: Arc::new(auths),
                conns: Arc::clone(&connector) as Arc<dyn PollConns>,
                stream_ceiling_secs: 600,
                upgrades: Vec::new(),
            };
            let egress = crate::root::serve::DoorEgress {
                reach: &reach,
                journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
            };
            let doors = [(instance.to_string(), plane)];
            // THE KERNEL'S HOOK STAGE over this rig's generation (the App built below): the plane's
            // tail states its hook order, and the stage binds the deployment's per-entry hooks.
            let live_app: Arc<std::sync::OnceLock<Arc<busbar_kernel::state::App>>> = Arc::default();
            let stage = crate::root::serve::HookStage {
                host: {
                    let live_app = Arc::clone(&live_app);
                    Arc::new(move || {
                        busbar_kernel::plane_host::engine_host(
                            live_app
                                .get()
                                .expect("the rig's App is built before any unit"),
                        )
                    })
                },
                gov: Arc::clone(&gov),
            };
            let mut served = compose_planes(
                &doors,
                &dispatcher,
                &late,
                &sections,
                Some(PUBLIC_URL),
                &plane_money,
                Some(&egress),
                Some(&stage),
            )
            .expect("the door plane composes");
            let _ = caller;
            let composed = &mut served.planes[0];
            assert!(
                composed.live.current().egress.is_some(),
                "its egress is sealed"
            );
            let money_steps = Arc::clone(&composed.money);
            let plane_key = composed.facts.plane.clone();
            served.post = Some(Arc::clone(&post));
            let app = configure(
                busbar_kernel::test_support::TestApp::new()
                    .keys_chain()
                    .governance(Arc::clone(&gov))
                    .cost(CostModel::flat(1)),
            )
            .build();
            let _ = live_app.set(Arc::clone(&app));
            // The kernel re-resolves each unit's principal over this generation, as the root
            // attaches it over its live snapshot.
            if let Some(kernel) = late.kernel() {
                let _attached = kernel
                    .attach_standing(busbar_kernel::plane_host::standing_over(Arc::clone(&app)));
            }
            // Its tick schedule and ready-session fan-out, as the process spawns them.
            served.spawn_ticks();
            let [(_, plane)] = doors;
            // THE DATA ROUTER, BUILT WITH THE DOOR'S ROUTES (its construction, no static).
            let doors = door_routes(served, || CARD.pin(), &[], &[]).expect("its claims mount");
            let door_table = doors
                .iter()
                .map(|d| (d.path.clone(), d.method.as_str().to_string(), d.auth))
                .collect();
            let (router, admin, _handle) = busbar_kernel::build_split_routers_serving(
                Arc::clone(&app),
                doors,
                1 << 20,
                0,
                false,
            );
            Rig {
                router,
                admin,
                gov,
                app,
                key,
                token,
                money_steps,
                post,
                book,
                plane_key,
                store,
                tokens,
                door_table,
                plane,
                clock,
            }
        }

        /// The key's admitted requests on the governance ledger.
        pub(crate) fn admitted(&self) -> u64 {
            self.gov
                .usage_for(&self.app.cost, &self.key.id, busbar_kernel::store::now())
                .expect("a read")
                .expect("the key exists")
                .requests
        }

        /// Every unit closed on the money steps and the node (one terminal, no unit left open).
        pub(crate) fn all_ended(&self) -> bool {
            self.money_steps.open_units() == 0 && self.post.open_units() == 0
        }
    }

    /// [`Rig::with`], for a sibling module.
    pub(crate) fn rig_with(
        instance: &'static str,
        port: u16,
        allowed_pools: Option<Vec<String>>,
        configure: &dyn Fn(
            busbar_kernel::test_support::TestApp,
        ) -> busbar_kernel::test_support::TestApp,
    ) -> Rig {
        Rig::with(
            instance,
            port,
            allowed_pools,
            None,
            None,
            Footing::own(),
            configure,
        )
    }

    /// [`Rig::with`] over the `tools:` section `tools`, standing on `footing`, for a sibling module.
    pub(crate) fn rig_on(
        instance: &'static str,
        port: u16,
        tools: serde_yaml::Value,
        footing: Footing<'_>,
    ) -> Rig {
        Rig::with(instance, port, None, None, Some(tools), footing, &|app| app)
    }

    /// [`Rig::with`] over the `tools:` section `tools`, for a sibling module.
    pub(crate) fn rig_tools(
        instance: &'static str,
        port: u16,
        tools: serde_yaml::Value,
        configure: &dyn Fn(
            busbar_kernel::test_support::TestApp,
        ) -> busbar_kernel::test_support::TestApp,
    ) -> Rig {
        Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools),
            Footing::own(),
            configure,
        )
    }

    /// The kernel's host services composed whole for a door plane that writes records: a record store
    /// (an in-memory store: its typed record rows and its plane-record slots, where a chained kind's
    /// journal persists), the runtime's blocking pool the store calls run on, installed as the
    /// process's late services.
    fn records_composed(
        ledger: Ledger,
        signer: Arc<GovState>,
        clock: &Arc<std::sync::atomic::AtomicU64>,
    ) -> (
        Arc<crate::root::serve::LateServices>,
        Arc<busbar_kernel::governance::MemoryStore>,
    ) {
        let store = Arc::new(busbar_kernel::governance::MemoryStore::new());
        let (origin, ahead) = (std::time::Instant::now(), Arc::clone(clock));
        let kernel = busbar_kernel::host_services::KernelServices::new()
            .with_mono_clock(Arc::new(move || {
                u64::try_from(origin.elapsed().as_nanos())
                    .unwrap_or(u64::MAX)
                    .saturating_add(ahead.load(std::sync::atomic::Ordering::SeqCst))
            }))
            .with_signer(signer)
            .with_pool(Arc::new(busbar_kernel::host_services::BlockingPool::new(
                tokio::runtime::Handle::current(),
                busbar_kernel::host_records::QUEUE_CAP,
            )));
        let kernel = Arc::new(match ledger {
            Ledger::Memory => {
                kernel.with_records(Arc::new(Rows::default()), Arc::clone(&store) as _)
            }
            Ledger::Store(claims) => kernel.with_records(Arc::new(Rows::default()), claims),
            Ledger::Unbound => kernel,
        });
        let late = crate::root::serve::LateServices::new();
        late.install_kernel(Arc::clone(&kernel), kernel)
            .expect("installed once");
        (late, store)
    }

    /// What a rig stands on: the record store its host services bind, and whose governance book it
    /// reads (its own, or a first node's: a fleet).
    pub(crate) struct Footing<'a> {
        pub(crate) ledger: Ledger,
        pub(crate) book: Option<&'a Rig>,
        /// The connector's destination guard refuses private addresses (a deployment's
        /// `destinations.block_private_addresses`); `false` admits loopback, where the test servers
        /// listen.
        pub(crate) guarded: bool,
    }

    impl Footing<'_> {
        /// Its own in-memory store and its own book.
        pub(crate) fn own() -> Self {
            Footing {
                ledger: Ledger::Memory,
                book: None,
                guarded: false,
            }
        }
    }

    /// The record store a rig's host services bind.
    pub(crate) enum Ledger {
        /// A fresh in-memory store (the rig's own).
        Memory,
        /// The given store: a handle on a durable journal (a restart or a fleet node).
        Store(Arc<dyn busbar_contract::records::RecordStore>),
        /// None: the host binds no store.
        Unbound,
    }

    /// Typed record rows in memory: the store kind's record slots, for the records services.
    #[derive(Default)]
    struct Rows(
        std::sync::Mutex<
            BTreeMap<
                (busbar_contract::ids::RecordSchemaId, Vec<u8>),
                busbar_contract::kinds::RecordBytes,
            >,
        >,
    );

    impl busbar_kernel::host_records::RecordRows for Rows {
        fn record_put(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
            value: &busbar_contract::kinds::RecordBytes,
        ) -> Result<(), busbar_contract::kinds::StoreError> {
            self.0
                .lock()
                .expect("unpoisoned")
                .insert((schema, key.to_vec()), value.clone());
            Ok(())
        }

        fn record_get(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
        ) -> Result<Option<busbar_contract::kinds::RecordBytes>, busbar_contract::kinds::StoreError>
        {
            Ok(self
                .0
                .lock()
                .expect("unpoisoned")
                .get(&(schema, key.to_vec()))
                .cloned())
        }

        fn record_scan(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            prefix: &[u8],
            limit: u32,
        ) -> Result<
            Vec<(Vec<u8>, busbar_contract::kinds::RecordBytes)>,
            busbar_contract::kinds::StoreError,
        > {
            let rows = self.0.lock().expect("unpoisoned");
            let found = rows
                .iter()
                .filter(|((s, k), _)| *s == schema && k.starts_with(prefix))
                .map(|((_, k), v)| (k.clone(), v.clone()));
            Ok(if limit == 0 {
                found.collect()
            } else {
                found.take(limit as usize).collect()
            })
        }
    }

    /// The mcp door, linked, bound through the loader's one load on `dispatcher`, its need declared on
    /// `conns` (`ConnTable::Probe`: declared on none).
    fn bound(
        instance: &str,
        dispatcher: &Arc<Dispatcher>,
        conns: crate::root::loader::dispatch::ConnTable,
    ) -> crate::root::boot::DoorPlane {
        let row = LinkedRow::of(line_door()).expect("the door states its Statement");
        load_linked::<Plane>(
            &row,
            Bind {
                instance: Arc::from(instance),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns,
            },
        )
        .expect("the linked door binds")
    }

    /// THE EXIT TEST (steps arrival, route, meter, exit): a keyed caller's `tools/call` arrives as one
    /// unit, is SERVED through the mcp door, 200, the server's tool result relayed to the caller under
    /// the caller's own id, exactly one request metered and the unit's money posted on both books, every
    /// unit ended once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_is_served_through_the_tool_door_and_its_money_posted() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-served";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);

        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "served through the door: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 30, "answered under the caller's own id: {body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "from the server",
            "the server's tool result, relayed: {body}"
        );

        // VERIFY-ON-CALL: the server's live tool list was fetched first, over the door's own need.
        let verify = heard
            .recv()
            .await
            .expect("the server was asked for its tool list");
        assert!(verify.starts_with("POST /rpc "), "{verify}");
        assert!(
            verify.contains("\"tools/list\""),
            "the verify fetch: {verify}"
        );
        // THE SERVER HEARD THE PLANE'S REQUEST, through the connector, at its registered path.
        let head = heard.recv().await.expect("the server was dialled");
        assert!(head.starts_with("POST /rpc "), "{head}");
        assert!(head.contains("\"tools/call\""), "the relayed call: {head}");

        // THE MONEY RECORD: the request admitted on the governance ledger, the unit's facts closed on
        // the money steps and the node, and its one line on the node's book carrying the tool call the
        // plane reported, under the (plane key, entry) it was served by.
        assert_eq!(rig.admitted(), 1, "one admitted request");
        assert!(rig.all_ended(), "its facts closed at its end");

        // THE CALL LOG, CHAINED (audit-chain): the call's one record is appended to the plane's call
        // chain in the kernel's record store before the caller was answered (a chained write is
        // durable before its writer hears so).
        {
            use busbar_contract::records::{PlaneSelector, RecordStore as _};
            let kind = surface("record_kind_call");
            let parents = rig.store.list_plane_record_parents(kind).expect("a read");
            assert_eq!(parents.len(), 1, "one chain, the caller's: {parents:?}");
            let chained = rig
                .store
                .list_plane_records(kind, &PlaneSelector::Parent(parents[0].as_str().into()))
                .expect("a read");
            assert_eq!(chained.len(), 1, "the call's one chained record");
        }
        let rows = rig.book.durability.lock().expect("unpoisoned").read_back();
        // The unit's lane is the published tool it called (SEAM-L(j)), as predev ledgered a call.
        let lane = format!("{}{PLANE_LANE_SEP}fs_read_file", rig.plane_key);
        let lines: Vec<_> = rows
            .iter()
            .filter(|p| p.counts.as_ref().is_some_and(|c| c.lane == lane))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "the unit's one line on the node's book: {rows:?}"
        );
        let counts = lines[0].counts.as_ref().expect("its counts");
        assert_eq!(
            lines[0].refusal, None,
            "its classes resolve: {:?}",
            lines[0]
        );
        assert_eq!(
            counts.classes.get(surface("class_tool_calls")).copied(),
            Some(1),
            "the one tool call the plane reported: {counts:?}"
        );
        // THE BYTE CLASS, STATED (THE DESIGN §7, "The plane reports; the kernel writes"; Law 6): the
        // length of the document the server answered with, the plane's second declared class.
        assert_eq!(
            counts.classes.get(surface("class_bytes")).copied(),
            Some(ANSWER.len() as u64),
            "the bytes of the server's answer the plane reported: {counts:?}"
        );
    }

    /// THE AUTHENTICATE STEP: an unkeyed caller on the door's endpoint (it takes a credential) is
    /// refused before anything is charged or dialled, the kernel's reason rendered by the plane.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unkeyed_tools_call_is_refused_before_anything_is_charged_or_dialled() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-unkeyed";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);

        let (status, body) = send(&rig.router, None, CALL).await;
        let refused = u16::try_from(refusal_status(ReasonCode::Unauthenticated)).expect("a status");
        assert_eq!(
            status.as_u16(),
            refused,
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(rig.admitted(), 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "no unit left open");
    }

    /// THE DECODE STEP: a body that is not JSON is refused by the plane's own decode, in its own
    /// words, before the unit is admitted: nothing charged, nothing dialled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_body_that_does_not_decode_is_refused_before_it_is_admitted() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-undecodable";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);

        let (status, body) = send(&rig.router, Some(&rig.token), "{not json").await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the status the plane's decode stated: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("the plane's JSON-RPC");
        assert_eq!(
            body["error"]["code"],
            busbar_contract::jsonrpc::PARSE_ERROR,
            "the plane's own words for the arrival it refused (REFUSAL_ARRIVE): {body}"
        );
        assert_eq!(rig.admitted(), 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
    }

    /// THE APPROVE STEP: a caller whose grant holds no scope of the plane's (an explicit empty pool
    /// grant: no scopes, never all) is refused before it is charged or dialled, in the served
    /// engine's words (BUSBAR-1.6.0.md Part 3 section 12: a new plane's statuses equal current
    /// predev): `404`, the sentence an unknown tool gets, `data.reason` `not_granted`
    /// (scripts/mcp-subject/h2-verify-refusal.sh holds predev to the same).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_outside_the_callers_grant_is_refused_before_it_dials() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-ungranted";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, Some(Vec::new()));

        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(status.as_u16(), 404, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["data"]["reason"], "not_granted", "{body}");
        assert_eq!(body["id"], 30, "the caller's id: {body}");
        assert_eq!(rig.admitted(), 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "no unit left open");
    }

    /// THE ROUTE STEP: a call whose server is down ends inside its own unit — answered as an
    /// upstream failure (ARCHITECT Q3 (c): the re-fetch that could not reach the server is reported
    /// to the kernel as unreachable and the call fails as the tool error), never served, every unit
    /// ended once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_to_a_server_that_is_down_ends_inside_its_unit() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-down";
        let _published = Published(instance);
        let port = down_port().await;
        let rig = Rig::new(instance, port, None);

        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(
            answer["result"]["isError"], true,
            "an upstream failure: {answer}"
        );
        assert!(rig.all_ended(), "the unit ended inside itself");
    }

    /// UPSTREAM CREDENTIALS FROM THE REGISTRATION (ARCHITECT round 4 Q-L3B-SURFACES (d)): a
    /// `upstream_credentials: passthrough` registration's member is bound to the kernel's
    /// caller-credential lending, so the server hears the caller's own verified credential as its
    /// bearer; a registration that states none hears no credential at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_passthrough_registration_presents_the_callers_credential_and_no_other() {
        let _one = PUBLISHING.lock().await;
        let tools = |port: u16, mode: &str| -> serde_yaml::Value {
            serde_yaml::from_str(&format!(
                "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
                 pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n{mode}  \
                 tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
                tool_digest()
            ))
            .expect("a section")
        };
        let instance = "door-passthrough";
        let _published = Published(instance);
        for (mode, lends) in [("  upstream_credentials: passthrough\n", true), ("", false)] {
            let (port, mut heard) = tool_server().await;
            let rig = Rig::with(
                instance,
                port,
                None,
                None,
                Some(tools(port, mode)),
                Footing::own(),
                &|app| app,
            );
            let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
            let (mut call, mut list) = (None, None);
            while let Ok(r) = heard.try_recv() {
                if r.contains("\"tools/call\"") {
                    call = Some(r);
                } else if r.contains("\"tools/list\"") {
                    list = Some(r);
                }
            }
            let bearer = format!("authorization: bearer {}", rig.token.to_ascii_lowercase());
            // The relayed call, and the door's own verify-on-call fetch made inside the caller's
            // unit (ARCHITECT round 5 Q-L3B-DOOR-EXCHANGE: it carries the member's binding, so a
            // passthrough member's is lent the unit's caller credential).
            for (what, heard) in [("call", call), ("verify-on-call list", list)] {
                let heard = heard
                    .unwrap_or_else(|| panic!("{mode:?}: the server heard the {what}"))
                    .to_ascii_lowercase();
                assert_eq!(heard.contains(&bearer), lends, "{mode:?} {what}: {heard}");
                if !lends {
                    assert!(
                        !heard.contains("authorization:"),
                        "{what}: no credential at all: {heard}"
                    );
                }
            }
        }
    }

    /// The caller key's grants become exactly `scopes` (`(grant kind row, value)`, the kinds read
    /// from the wire fixture), on the governance book the gate resolves it from.
    fn grant(rig: &Rig, scopes: &[(&str, &str)]) {
        let mut key = (*rig.key).clone();
        key.allowed_scopes = Some(
            scopes
                .iter()
                .map(|(kind, value)| busbar_contract::records::ScopeRef {
                    kind: surface(kind).to_string(),
                    value: (*value).to_string(),
                })
                .collect(),
        );
        rig.gov.store().put_key(&key).expect("the key is stored");
        rig.gov.refresh().expect("the book refreshes");
    }

    /// The raw (form-encoded) value of `key` in a form body.
    pub(crate) fn form_value(body: &str, key: &str) -> String {
        body.split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
            .unwrap_or_default()
            .to_string()
    }

    /// Every token request the rig's token endpoint was sent: `(target, form body)`.
    pub(crate) fn exchanges(rig: &Rig) -> Vec<(String, String)> {
        rig.tokens
            .opened
            .lock()
            .expect("unpoisoned")
            .iter()
            .map(|(_, target, _, body)| (target.clone(), body.clone()))
            .collect()
    }

    /// The tool server's three tools, listed as the token-exchange section approves them.
    pub(crate) fn three_tools() -> serde_json::Value {
        serde_json::json!([
            {"name": "read_file", "description": TOOL_DESCRIPTION, "inputSchema": tool_schema()},
            {"name": "write_file", "description": "writes a file to disk", "inputSchema": tool_schema()},
            {"name": "stat", "description": "reads a file's metadata", "inputSchema": tool_schema()},
        ])
    }

    /// The environment variable a token-exchange registration names busbar's own subject token by.
    const SUBJECT_VAR: &str = "BUSBAR_DOOR_EXCHANGE_TEST_SUBJECT";

    /// The token endpoint a token-exchange registration names (the rig's token table answers it:
    /// an `open-web` need dials over connection security only).
    pub(crate) const TOKEN_URL: &str = "https://as.example/token";

    /// A `token_exchange:` registration on loopback `port` (`aud:` the server's origin), three
    /// approved tools.
    fn exchange_section(port: u16) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             allow_private: true\n  aud: \"http://127.0.0.1:{port}\"\n  \
             token_exchange:\n    token_url: \"{TOKEN_URL}\"\n    \
             subject_token: {{ env: {SUBJECT_VAR} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n    \
             write_file: {{ schema_hash: \"{}\" }}\n    stat: {{ schema_hash: \"{}\" }}\n",
            tool_digest(),
            surface("write_digest"),
            surface("stat_digest"),
        ))
        .expect("a section")
    }

    /// THE TOKEN EXCHANGE (ARCHITECT round 5 Q-L3B-EXCHANGE (B), Q-L3B-DOOR-EXCHANGE): a
    /// `token_exchange:` registration's member is bound to the RFC 8693 style, so the relayed call
    /// presents the token busbar's own subject token was exchanged for under the CALLER's down-scope
    /// — exactly its tool grants on the server, or for a wildcard grant exactly the tool called —
    /// and the door's own verify-on-call fetch presents the token exchanged for the registration's
    /// approved set. Each exchange is the previous release's request (busbar's subject token, never
    /// the caller's; the `aud:` as the RFC 8707 resource); the host's scope field never reaches the
    /// server.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_exchange_registration_presents_the_token_exchanged_for_the_callers_down_scope()
    {
        let _one = PUBLISHING.lock().await;
        std::env::set_var(SUBJECT_VAR, "busbar-own-subject-token");
        let granted: &[(&str, &str)] = &[
            ("scope_server", "fs"),
            ("scope_tool", "fs_read_file"),
            ("scope_tool", "fs_write_file"),
            ("scope_tool", "git_log"),
        ];
        for (instance, grants, down_scope) in [
            (
                "door-exchange-granted",
                Some(granted),
                "fs_read_file+fs_write_file",
            ),
            ("door-exchange-wildcard", None, "fs_read_file"),
        ] {
            let _published = Published(instance);
            let (port, mut heard) =
                tool_server_listing(Arc::new(std::sync::Mutex::new(three_tools()))).await;
            let rig = rig_tools(instance, port, exchange_section(port), &|app| app);
            if let Some(grants) = grants {
                grant(&rig, grants);
            }
            let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{instance}: {}",
                String::from_utf8_lossy(&body)
            );
            let (mut call, mut list) = (None, None);
            while let Ok(r) = heard.try_recv() {
                if r.contains("\"tools/call\"") {
                    call = Some(r.to_ascii_lowercase());
                } else if r.contains("\"tools/list\"") {
                    list = Some(r.to_ascii_lowercase());
                }
            }
            let call = call.expect("the server heard the call");
            assert!(
                call.contains(&format!("authorization: bearer tok-{down_scope}")),
                "{instance}: the call presents the token for the caller's down-scope: {call}"
            );
            let list = list.expect("the server heard the verify-on-call list");
            assert!(
                list.contains("authorization: bearer tok-fs_read_file+fs_stat+fs_write_file"),
                "{instance}: the door's own fetch presents the registration's token: {list}"
            );
            let field = busbar_contract::abi::auth::SCOPE_REQUEST_FIELD;
            assert!(
                !call.contains(field) && !list.contains(field),
                "the host's scope field never reaches the server"
            );
            let exchanges = exchanges(&rig);
            let scopes: Vec<String> = exchanges
                .iter()
                .map(|(_, r)| form_value(r, "scope"))
                .collect();
            assert_eq!(
                scopes,
                ["fs_read_file+fs_stat+fs_write_file", down_scope],
                "{instance}: one exchange per scope"
            );
            for (target, r) in &exchanges {
                assert_eq!(target, TOKEN_URL);
                assert_eq!(
                    form_value(r, "grant_type"),
                    "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
                );
                assert_eq!(
                    form_value(r, "requested_token_type"),
                    "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
                );
                assert_eq!(form_value(r, "subject_token"), "busbar-own-subject-token");
                assert_eq!(
                    form_value(r, "resource"),
                    format!("http%3A%2F%2F127.0.0.1%3A{port}")
                );
                assert!(
                    !r.contains(&rig.token),
                    "the caller's credential never reaches the authorization server"
                );
            }
            assert!(rig.all_ended(), "every unit ended");
        }
    }

    /// TOOL POOLS THROUGH THE ONE WALK (ARCHITECT round 4 Q-L3B-SURFACES (h)): a call to a pooled
    /// server routes over its pool, so a primary that answers with a failure is failed over to its
    /// verified twin by the kernel's walk when the pool names the tool `repeatable:`, and the caller
    /// hears the twin; a tool the pool does not name is performed at most once: the primary's
    /// failure is the answer, and the twin never hears the call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tool_pool_fails_over_through_the_one_walk_and_repeats_only_what_it_names() {
        let _one = PUBLISHING.lock().await;
        let listing = || {
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                .to_string()
        };
        let calls = |heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>| {
            let mut n = 0;
            while let Ok(r) = heard.try_recv() {
                n += usize::from(r.contains("\"tools/call\""));
            }
            n
        };
        let tools = |bad: u16, good: u16, repeatable: &str| -> serde_yaml::Value {
            let d = tool_digest();
            serde_yaml::from_str(&format!(
                "fs:\n  url: \"http://127.0.0.1:{bad}/rpc\"\n  \
                 pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
                 tools_allow:\n    read_file: {{ schema_hash: \"{d}\" }}\n\
                 fs2:\n  url: \"http://127.0.0.1:{good}/rpc\"\n  \
                 pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
                 tools_allow:\n    read_file: {{ schema_hash: \"{d}\" }}\n\
                 pools:\n  twins: {{ members: [fs, fs2], repeatable: [{repeatable}], \
                 member_granted: true }}\n"
            ))
            .expect("a section")
        };
        let instance = "door-tool-pool";
        let _published = Published(instance);
        for (repeatable, twin_answers) in [("read_file", true), ("", false)] {
            let (bad, mut bad_heard) = tool_server_replying(Arc::new(move |r: &str| {
                if r.contains("\"tools/list\"") {
                    (200, listing())
                } else {
                    (503, "{}".to_string())
                }
            }))
            .await;
            let (good, mut good_heard) = tool_server().await;
            let rig = Rig::with(
                instance,
                bad,
                None,
                None,
                Some(tools(bad, good, repeatable)),
                Footing::own(),
                &|app| app,
            );
            let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
            let body = String::from_utf8_lossy(&body).to_string();
            assert_eq!(
                body.contains("from the server"),
                twin_answers,
                "repeatable [{repeatable}]: {status} {body}"
            );
            assert_eq!(calls(&mut bad_heard), 1, "the primary is called once");
            assert_eq!(
                calls(&mut good_heard),
                usize::from(twin_answers),
                "the twin hears the call only when the pool repeats the tool"
            );
            assert!(rig.all_ended(), "the unit ended inside itself");
        }
    }

    /// VERIFY-ON-CALL (the rug-pull defence on the call path, the served engine's): a call whose
    /// server's last look is older than its `verify_ttl` fetches the live tool list first and is
    /// judged against it. Within the bound the look is reused (one fetch for two calls); a schema
    /// moved under the approval refuses the next call as quarantined before it is sent, with no
    /// operator present; a server that cannot be reached at the fetch refuses fail-closed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_on_call_judges_the_live_list_reuses_a_fresh_look_and_fails_closed() {
        let _one = PUBLISHING.lock().await;
        let tools = |port: u16, ttl: &str| -> serde_yaml::Value {
            serde_yaml::from_str(&format!(
                "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
                 pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  verify_ttl: {ttl}\n  \
                 tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
                tool_digest()
            ))
            .expect("a section")
        };
        let drain = |heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>| {
            let mut got = Vec::new();
            while let Ok(r) = heard.try_recv() {
                got.push(if r.contains("\"tools/list\"") {
                    "list"
                } else if r.contains("\"tools/call\"") {
                    "call"
                } else {
                    "other"
                });
            }
            got
        };

        // ── A FRESH LOOK IS REUSED within `verify_ttl` ───────────────────────────────────────────
        // One instance name for the three compositions: each publishes over the one before.
        let instance = "door-verify-on-call";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools(port, "1h")),
            Footing::own(),
            &|app| app,
        );
        for _ in 0..2 {
            let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        }
        assert_eq!(
            drain(&mut heard),
            vec!["list", "call", "call"],
            "one fetch, two calls"
        );
        drop(rig);

        // ── THE RUG-PULL ON THE CALL PATH: strict-live (`0s`) ─────────────────────────────────────
        let listed = Arc::new(std::sync::Mutex::new(tool_listing()));
        let (port, mut heard) = tool_server_listing(Arc::clone(&listed)).await;
        let rig = Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools(port, "0s")),
            Footing::own(),
            &|app| app,
        );
        let (status, _) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the control: the approved list serves"
        );
        *listed.lock().expect("the list") = serde_json::json!([
            {"name": "read_file", "description": TOOL_DESCRIPTION,
             "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "exfil": {"type": "string"}}}}
        ]);
        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["data"]["reason"], "quarantined", "{body}");
        assert_eq!(
            drain(&mut heard),
            vec!["list", "call", "list"],
            "the drifted call was refused before it was sent"
        );
        drop(rig);

        // ── FAIL CLOSED: the server cannot be reached at the fetch: reported to the kernel as
        // unreachable, and the call fails as an upstream failure, never sent (ARCHITECT Q3 (c)) ──
        let port = down_port().await;
        let rig = Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools(port, "0s")),
            Footing::own(),
            &|app| app,
        );
        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(
            body["result"]["isError"], true,
            "an upstream failure: {body}"
        );
        assert!(rig.all_ended(), "the refused unit ended");
    }

    /// THE RE-CHECK HONOURS THE REGISTRATION'S `timeout:` (ARCHITECT ruling on `timeout:`): an
    /// upstream that accepts the tool-list fetch and never answers it is given up on at the operator's
    /// one-second budget, not at a fixed thirty, and the call fails as an upstream failure, never
    /// sent (ARCHITECT Q3 (c), as the unreachable fetch above), well inside the budget the caller is
    /// waiting on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_tool_list_re_check_gives_up_at_the_registrations_timeout() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-verify-timeout";
        let _published = Published(instance);
        // A server that takes every connection and answers nothing on it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let section: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  verify_ttl: 0s\n  \
             timeout: 1s\n  tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section");
        let rig = Rig::with(
            instance,
            port,
            None,
            None,
            Some(section),
            Footing::own(),
            &|app| app,
        );
        // Bounded here so the RED is a named failure, not the harness's slow-test kill: before the
        // budget was honoured, the fetch to a server that never answers did not return at all.
        let (status, body) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send(&rig.router, Some(&rig.token), CALL),
        )
        .await
        .expect("the re-check gave up inside 10s: the registration's `timeout: 1s` is its budget");
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(
            body["result"]["isError"], true,
            "an upstream failure: {body}"
        );
        assert!(rig.all_ended(), "the refused unit ended");
    }

    /// THE ARGUMENT GUARD (the served engine's argguard): a URL a call's arguments carry to a cloud
    /// metadata endpoint is refused before the call is sent, in the guard's words, with the field it
    /// was found at; the same call carrying an external URL is served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_metadata_url_in_the_arguments_is_refused_before_the_call_is_sent() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-argguard";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);
        let call = |url: &str| {
            serde_json::json!({
                "jsonrpc": "2.0", "id": 31, "method": "tools/call",
                "params": {
                    "name": "fs_read_file",
                    "arguments": { "path": "notes.txt", "fetch": url },
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": protocol_version(),
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }
            })
            .to_string()
        };
        let (status, body) = send(
            &rig.router,
            Some(&rig.token),
            &call("http://169.254.169.254/latest/meta-data/"),
        )
        .await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["code"], -32000, "{body}");
        assert_eq!(
            body["error"]["data"]["reason"], "tool_argument_refused",
            "{body}"
        );
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("tool argument /fetch carries a URL the schema does not declare"),
            "{message}"
        );
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "the refused call never reached the wire: {wire:?}"
        );
        let (status, body) = send(
            &rig.router,
            Some(&rig.token),
            &call("https://docs.example.com/notes"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    }

    /// A UNIT THE PLANE ANSWERS ITSELF (ARCHITECT Q-L3B-LOCAL): a keyed `tools/list` names no entry,
    /// is admitted with no route walk and answered 200 by the plane from its catalogue — nothing
    /// charged (only far-end-reported units bill), nothing dialled, every unit ended.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_listing_is_answered_by_the_plane_with_no_walk_and_no_charge() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-local";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);

        let (status, body) = send_as(&rig.router, Some(&rig.token), LIST, "tools/list", None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "answered by the plane: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 9, "{body}");
        assert_eq!(
            body["result"]["tools"][0]["name"], "fs_read_file",
            "the catalogue's one tool: {body}"
        );
        assert_eq!(rig.admitted(), 0, "a local answer charges nothing");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "every unit ended");
    }

    /// THE PROTECTED-RESOURCE DOCUMENT (ARCHITECT Q-L3B-RFC9728, predev's plain document): the door
    /// states its facts (its audience, and its `mcp:` block's authorization servers and scopes) and
    /// the kernel's RFC 9728 renderer answers an anonymous GET at its metadata path, cacheable — not
    /// a unit: nothing admitted, no unit opened on the money steps or the node, nothing dialled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_metadata_document_is_rendered_from_the_doors_facts_and_is_no_unit() {
        use tower::ServiceExt as _;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-metadata";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let block: serde_yaml::Value = serde_yaml::from_str(&format!(
            "canonical_uri: \"http://127.0.0.1{}\"\n\
                 authorization_servers: [\"https://login.example.com\"]\n\
                 scopes_supported: [\"tools:call\"]\n",
            endpoint()
        ))
        .expect("a block");
        let rig = Rig::with(
            instance,
            port,
            None,
            Some(block),
            None,
            Footing::own(),
            &|app| app,
        );
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/.well-known/oauth-protected-resource{}",
                endpoint()
            ))
            .body(axum::body::Body::empty())
            .expect("a request");
        let response = rig.router.clone().oneshot(req).await.expect("answers");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=3600")
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("a JSON document");
        assert_eq!(
            doc,
            serde_json::json!({
                "resource": format!("http://127.0.0.1{}", endpoint()),
                "authorization_servers": ["https://login.example.com"],
                "scopes_supported": ["tools:call"],
                "bearer_methods_supported": ["header"],
            })
        );
        assert_eq!(rig.admitted(), 0, "nothing admitted");
        assert!(rig.all_ended(), "no unit was opened");
        assert!(heard.try_recv().is_err(), "nothing dialled");
    }

    /// THE CLAIM: without a public base URL the door opens and claims nothing; with one its endpoint
    /// is claimed.
    #[tokio::test]
    async fn the_tool_door_claims_its_endpoint_only_under_a_public_url() {
        let _one = PUBLISHING.lock().await;
        let compose = |instance: &'static str, public_url: Option<&str>| {
            let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
            crate::root::connector::install_io(&dispatcher);
            let plane = bound(
                instance,
                &dispatcher,
                crate::root::loader::dispatch::ConnTable::Probe,
            );
            let mut sections = BTreeMap::new();
            sections.insert(plane.served().section, section(9));
            compose_planes(
                &[(instance.to_string(), plane)],
                &dispatcher,
                &composed_services(),
                &sections,
                public_url,
                &money,
                None,
                None,
            )
            .expect("the door plane composes")
        };
        {
            // One instance's admin routes on the admin table at a time: this one is withdrawn first.
            let bare = "serve-door-tools-claims-bare";
            let _bare = Published(bare);
            let served = compose(bare, None);
            assert!(
                served.planes[0].snapshot.claims.is_empty(),
                "no public base URL, no claim"
            );
        }
        {
            // ITS OWN ENDPOINT BLOCK, no public base URL (ARCHITECT Q-L3B-AUD, predev's rule): the door
            // reads its `mcp:` block beside its settings and states its claims under the canonical URI.
            let block = "serve-door-tools-claims-block";
            let _block = Published(block);
            let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
            crate::root::connector::install_io(&dispatcher);
            let plane = bound(
                block,
                &dispatcher,
                crate::root::loader::dispatch::ConnTable::Probe,
            );
            let mut sections = BTreeMap::new();
            sections.insert(plane.served().section, section(9));
            assert_eq!(
                plane.served().owns,
                [endpoint_section()],
                "the endpoint block it owns beside"
            );
            sections.insert(
            plane.served().owns[0],
            serde_yaml::from_str(
                &format!("canonical_uri: \"https://gw.example{}\"\nauthorization_servers: [\"https://login.example\"]\n", endpoint()),
            )
            .expect("a block"),
        );
            let served = compose_planes(
                &[(block.to_string(), plane)],
                &dispatcher,
                &composed_services(),
                &sections,
                None,
                &money,
                None,
                None,
            )
            .expect("the door plane composes");
            let snapshot = &served.planes[0].snapshot;
            assert_eq!(
                snapshot.audience.as_deref(),
                Some(format!("https://gw.example{}", endpoint()).as_str())
            );
            assert!(
                snapshot
                    .claims
                    .iter()
                    .any(|c| c.verb == "POST" && c.target == endpoint()),
                "the endpoint is claimed under its block"
            );
        }
        let public = "serve-door-tools-claims-public";
        let _public = Published(public);
        let served = compose(public, Some(PUBLIC_URL));
        assert!(
            served.planes[0]
                .snapshot
                .claims
                .iter()
                .any(|c| c.verb == "POST" && c.target == endpoint()),
            "the endpoint is claimed under the public base URL"
        );
    }

    /// A GRANTED ROOTS ASK, through the door (Law 11, U16): the server answers the call with an
    /// input-required result asking for roots; busbar answers nothing itself and sends no retry —
    /// the caller is handed the ask, `inputRequests` verbatim, under busbar's sealed state. One unit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_granted_roots_ask_is_relayed_to_the_caller_and_no_retry_is_sent() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-mrtr-roots";
        let _published = Published(instance);
        let (port, mut heard) = tool_server_answering(Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else {
                r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}},"requestState":"s"}}"#
                    .to_string()
            }
        }))
        .await;
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             grants: {{ roots: true }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section");
        let rig = Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools),
            Footing::own(),
            &|app| app,
        );
        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["inputRequests"]["r"]["method"], "roots/list",
            "the ask reaches the caller verbatim: {body}"
        );
        assert_ne!(body["result"]["requestState"], "s", "{body}");
        let verify = heard
            .try_recv()
            .expect("verify-on-call fetched the tool list");
        assert!(verify.contains("\"tools/list\""), "{verify}");
        let first = heard
            .try_recv()
            .expect("the first round reached the server");
        assert!(!first.contains("inputResponses"), "{first}");
        assert!(
            heard.try_recv().is_err(),
            "busbar sent no retry of its own: it answers nothing on the caller's behalf"
        );
        assert_eq!(rig.admitted(), 1, "one unit, one charge");
    }
}

/// THE DOOR PLANE'S BOUNDARY, AT THE COMPOSITION ROOT (ARCHITECT Q-L3B-KHARNESS: a door plane's
/// claims are mounted by the composition root at the data router's construction, Q-SW1, so these
/// assertions live where the mount does; the kernel keeps no HOT-route assumption).
#[cfg(all(linked_axis_plane_door, linked_axis_node))]
pub(crate) mod door_boundary {
    use std::sync::Arc;

    use busbar_contract::abi::mechanism::route::RouteAuth;
    use busbar_kernel::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use busbar_kernel::plane::registry::{BuildCtx, PlaneDecl};
    use busbar_kernel::test_support::{LaneSpec, MockServer, MockServerState, TestApp};

    use super::tool_door::{
        rig_tools, rig_with, section, tool_server, tool_server_listing, ADMIN_TOKEN, PUBLIC_URL,
    };
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The mcp door's registry row, folded from its Statement as the composition root folds it.
    pub(crate) fn row() -> &'static PlaneDecl {
        use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
        busbar_kernel::plane::door::fold(
            registration(linked_probe(
                super::tool_door::line_door(),
                "door-boundary-row",
            ))
            .expect("the linked door binds"),
        )
        .expect("the door folds")
    }

    /// The door's row in the process's plane registry, as the composition root installs it beside
    /// the linked rows (a registration, not an isolation: the served request reads the registry on
    /// another worker while the test awaits it).
    pub(crate) fn registry(row: &'static PlaneDecl) {
        busbar_kernel::plane::registry::register_test_plane(row);
    }

    /// The kernel's plane dispatch for the door, as `build_dispatch` configures it from the folded
    /// row: its slot built over `section` and the public base URL, every path it claims mounted,
    /// the admission it declares bound.
    pub(crate) fn dispatched(
        mut app: TestApp,
        row: &'static PlaneDecl,
        slot: &Arc<dyn std::any::Any + Send + Sync>,
    ) -> TestApp {
        for (path, wire) in (row.claims)(&**slot) {
            app.mount_plane(row.key, &path, wire);
        }
        if let Some(admission) = (row.admission)(&**slot) {
            app.admit_plane(row.key, admission);
        }
        app.install_plane_runtime(row.key, Arc::clone(slot));
        app
    }

    /// The door's slot over the `tools:` section of a server on `port`, under [`PUBLIC_URL`].
    fn slot(row: &'static PlaneDecl, port: u16) -> Arc<dyn std::any::Any + Send + Sync> {
        slot_over(row, section(port))
    }

    /// The door's slot over the `tools:` section `value`, under [`PUBLIC_URL`].
    pub(crate) fn slot_over(
        row: &'static PlaneDecl,
        value: serde_yaml::Value,
    ) -> Arc<dyn std::any::Any + Send + Sync> {
        let tools = busbar_kernel::plane::door::DoorSection::new(row.config_section, value);
        (row.build)(&BuildCtx {
            endpoint_slot: None,
            agent_defs: &(),
            tool_defs: &tools,
            public_url: Some(PUBLIC_URL),
            prior: None,
        })
        .expect("the door builds from its section")
    }

    /// THE POSITIVE CASE: the door's slot is the one object its claims and admission read, and every
    /// path it claims is a route the composition root mounted on the data router.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plane_slot_holds_the_one_built_object_of_each_configured_plane() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-boundary-slot";
        let _published = Published(instance);
        let (port, _heard) = tool_server().await;
        let row = row();
        registry(row);
        let slot = slot(row, port);
        let rig = rig_with(instance, port, None, &|app| dispatched(app, row, &slot));
        let held = rig
            .app
            .plane_slot(row.key)
            .expect("the configured door has a slot")
            .clone();
        assert!(Arc::ptr_eq(&held, &slot), "one construction, read back");
        assert!(
            (row.admission)(&*held).is_some(),
            "the slot is the door's own object: its admission reads it"
        );
        let claims = (row.claims)(&*held);
        assert!(!claims.is_empty(), "the door claims its paths");
        for (path, _) in claims {
            assert!(
                rig.door_table.iter().any(|(p, _, _)| *p == path),
                "`{path}`, claimed off the door's slot, must be a route the root mounted: {:?}",
                rig.door_table
            );
        }
    }

    /// THE PLANE-BOUNDARY RATCHET (1.6.0), driven by the ROUTER TABLE rather than by a hand-listed
    /// sample: an access token minted for the door plane's resource is admissible on that plane and
    /// nowhere else. The walk covers every core route the kernel mounts and every route the
    /// composition root mounts for the door, so a route added later JOINS the assertion. There is no
    /// skip arm: a path whose shape this test cannot turn into a concrete request PANICS.
    ///
    /// The admissible set is what the door claims (its non-public routes), never a list written
    /// here; `declared_public` is the mirror ratchet: a route mounted `RouteAuth::None` answers
    /// everyone, so adding one must be a deliberate act that shows up here. The test's NAME is pinned
    /// by `qa/design-bindings.json` (PB-33) and the structure-lint choke-point table.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_audience_bound_token_is_confined_to_its_door_plane_through_the_composition() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-boundary-confined";
        let _published = Published(instance);
        let (port, _heard) = tool_server().await;
        let upstream = MockServer::new(Arc::new(MockServerState::new())).await;
        let row = row();
        registry(row);
        let slot = slot(row, port);
        let (audience, metadata) = (row.admission)(&*slot)
            .map(|a| (a.audience, a.resource_metadata))
            .expect("the door binds an audience under the public base URL");
        let base_url = upstream.base_url();
        let rig = rig_with(instance, port, None, &|app| {
            dispatched(
                app.lane(
                    LaneSpec::new(
                        "test-model",
                        busbar_kernel::proto::PROTO_ANTHROPIC,
                        &base_url,
                    )
                    .api_key("busbar-upstream-key"),
                )
                .pool("pa", &[(0, 1)]),
                row,
                &slot,
            )
        });

        // The two tokens of one unrestricted key: the plain data-plane one, and its sibling minted for
        // the door's resource.
        let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
        let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
        let generation = verifier
            .verify(&rig.token, 1_700_000_000, None)
            .expect("plain claims")
            .generation;
        let bound_token = signer.mint_for_audience(
            &rig.key.id,
            4_000_000_000,
            generation.as_deref(),
            &audience,
            Some("client-1"),
        );

        // Every route the data router answers: the kernel's core table and the door's.
        let mut routes = busbar_kernel::base_data_route_method_view(&rig.app);
        routes.extend(rig.door_table.iter().cloned());
        let admissible: Vec<String> = rig
            .door_table
            .iter()
            .filter(|(_, _, auth)| *auth != RouteAuth::None)
            .map(|(p, _, _)| p.clone())
            .collect();
        assert!(!admissible.is_empty(), "the door mounts its endpoint");
        let metadata_path = metadata
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|at| rest[at..].to_string()))
            .expect("the metadata document's path");
        let declared_public: Vec<String> = vec![
            "/healthz".to_string(),
            "/auth/token".to_string(),
            metadata_path,
        ];
        for public in &declared_public {
            assert!(
                routes
                    .iter()
                    .any(|(path, _, auth)| path == public && *auth == RouteAuth::None),
                "{public} is declared unauthenticated-by-design but no route mounts it with \
                 RouteAuth::None — the bypass set this names is not the one the router built"
            );
        }
        let boot_plugin_paths: Vec<String> = busbar_kernel::boot_route_paths_of(&rig.app);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = rig.router.clone();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        fn concrete(pattern: &str) -> String {
            let mut out = String::new();
            for seg in pattern.split('/').skip(1) {
                out.push('/');
                if seg.starts_with('{') && seg.ends_with('}') {
                    out.push_str(match seg {
                        "{name}" => "pa",
                        "{provider}" => "anthropic",
                        "{model}" => "test-model",
                        other => panic!(
                            "route pattern segment {other} has no fixture value: give it one, \
                             never skip the route"
                        ),
                    });
                } else {
                    out.push_str(seg);
                }
            }
            if out.is_empty() {
                "/".to_string()
            } else {
                out
            }
        }
        let body = serde_json::json!({
            "model": "pa",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        })
        .to_string();
        let send = |method: reqwest::Method, url: String, bearer: Option<String>| {
            let mut req = client.request(method, url).body(body.clone());
            if let Some(b) = bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            req.send()
        };

        let (mut checked, mut door_checked) = (0usize, 0usize);
        for (pattern, verb, auth) in &routes {
            let path = concrete(pattern);
            if *auth == RouteAuth::None {
                assert!(
                    declared_public.contains(pattern),
                    "{pattern} is mounted RouteAuth::None but is not in declared_public — an \
                     unauthenticated route must be a deliberate, reviewed act"
                );
                continue;
            }
            let method = reqwest::Method::from_bytes(verb.as_bytes()).unwrap();
            let url = format!("http://{addr}{path}");
            if admissible.contains(pattern) {
                // THE DOOR ARM: the audience-bound token is the one that WORKS here and the plain
                // data-plane token is the one that must buy nothing.
                let anon = send(method.clone(), url.clone(), None).await.unwrap();
                assert_eq!(anon.status(), 401, "anonymous on the door, {verb} {path}");
                assert!(
                    anon.headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(
                            |v| v.starts_with("Bearer ") && v.contains("resource_metadata=")
                        ),
                    "a 401 on an OAuth protected resource carries a Bearer challenge naming its \
                     resource_metadata, {verb} {path}"
                );
                let bound = send(method.clone(), url.clone(), Some(bound_token.clone()))
                    .await
                    .unwrap();
                assert_ne!(
                    bound.status(),
                    401,
                    "the bound token is admitted, {verb} {path}"
                );
                let plain = send(method.clone(), url.clone(), Some(rig.token.clone()))
                    .await
                    .unwrap();
                assert_eq!(
                    plain.status(),
                    401,
                    "a plain key is inadmissible, {verb} {path}"
                );
                door_checked += 1;
                continue;
            }
            // Auth failures are protocol-shaped, so the baseline is the no-credential response.
            let anon = send(method.clone(), url.clone(), None)
                .await
                .unwrap()
                .status();
            let bound = send(method.clone(), url.clone(), Some(bound_token.clone()))
                .await
                .unwrap()
                .status();
            assert_eq!(
                bound, anon,
                "an audience-bound door token is no credential on {verb} {path}"
            );
            let plain = send(method, url, Some(rig.token.clone()))
                .await
                .unwrap()
                .status();
            assert_ne!(
                plain, anon,
                "the plain sibling is admitted on {verb} {path}"
            );
            checked += 1;
        }
        assert_eq!(
            door_checked,
            routes
                .iter()
                .filter(|(p, _, _)| admissible.contains(p))
                .count(),
            "every admissible mounted route was walked"
        );
        assert!(
            door_checked > 0,
            "the door's half of the boundary was asserted"
        );
        assert!(
            checked >= 4,
            "the walk covered only {checked} guarded core routes — it is not seeing the router"
        );
        for path in &boot_plugin_paths {
            let url = format!("http://{addr}{path}");
            let anon = client.get(&url).send().await.unwrap().status();
            let bound = client
                .get(&url)
                .header("authorization", format!("Bearer {bound_token}"))
                .send()
                .await
                .unwrap()
                .status();
            assert_eq!(
                bound, anon,
                "a bound token is no credential on plugin route {path}"
            );
        }
        handle.abort();
        upstream.shutdown().await;
    }

    /// One admin request on `rig`'s admin router: its status and JSON body.
    async fn admin(
        rig: &super::tool_door::Rig,
        method: &str,
        path: &str,
    ) -> (u16, serde_json::Value) {
        use tower::ServiceExt as _;
        let req = axum::http::Request::builder()
            .method(method)
            .uri(format!("/api/v1/admin{path}"))
            .header("x-admin-token", ADMIN_TOKEN)
            .body(axum::body::Body::empty())
            .expect("a request");
        let router = busbar_core_admin::build_router(Arc::clone(&rig.app));
        let response = router.oneshot(req).await.expect("answers");
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body");
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    /// THE TRUST VERBS, SERVED BY THE DOOR (ARCHITECT Q-L3B-VERBS), the sequence an operator walks
    /// over the admin router: `connect` fetches the server's live tool list over the door's need and
    /// finds it as approved; `health` serves; the upstream changes a schema under the approval
    /// (the rug-pull) and `connect` finds the server quarantined with the moved tool named; `changes`
    /// reads the same fact back contacting nothing; `health` stops serving; a `tools/call` is refused
    /// AS a quarantine and never reaches the wire; an unregistered name is `404` on every verb.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_trust_verbs_report_the_drift_an_operator_has_to_work() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-trust-verbs";
        let _published = Published(instance);
        let schema =
            serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}});
        let description = "reads a file from disk";
        let listed = Arc::new(std::sync::Mutex::new(serde_json::json!([
            {"name": "read_file", "description": description, "inputSchema": schema}
        ])));
        let (port, mut heard) = tool_server_listing(Arc::clone(&listed)).await;
        let digest = super::tool_door::surface("tool_digest");
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{digest}\" }}\n"
        ))
        .expect("a section");
        let row = row();
        registry(row);
        let slot = slot_over(row, tools.clone());
        // The operator credential's row on the auth axis, as boot links it: the admin chain the
        // admin router authenticates `x-admin-token` with.
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        busbar_kernel::preflight::install_auth_axis(crate::root::dispatch::auth_axis);
        let chain = vec![busbar_kernel::config::operator_provider().to_string()];
        let rig = rig_tools(instance, port, tools, &|app| {
            dispatched(app.admin_chain(chain.clone()), row, &slot)
        });

        // ── CONNECT ───────────────────────────────────────────────────────────────────────────────
        let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
        assert_eq!(
            status, 200,
            "connect is mounted and served by the door: {body}"
        );
        assert_eq!(body["state"], "approved", "{body}");
        assert_eq!(body["observed_tools"], 1, "{body}");
        assert_eq!(body["capabilities"][0]["status"], "approved", "{body}");
        assert_eq!(body["capabilities"][0]["approved_digest"], digest, "{body}");
        assert!(
            heard.try_recv().is_ok_and(|r| r.contains("\"tools/list\"")),
            "the server was asked for its tool list"
        );

        // ── A CALL WITHIN `verify_ttl` OF THE CONNECT reuses its look (the served engine's settle
        // stamped the freshness clock on every observation): the server hears the call alone. ──
        // The caller's token bound to the door's resource (its audience-bound mount admits no other).
        let audience = (row.admission)(&*slot).expect("an audience").audience;
        let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
        let generation = TokenVerifier::single(signer.kid(), signer.verifying_key())
            .verify(&rig.token, 1_700_000_000, None)
            .expect("plain claims")
            .generation;
        let bound = signer.mint_for_audience(
            &rig.key.id,
            4_000_000_000,
            generation.as_deref(),
            &audience,
            Some("client-1"),
        );
        let (status, body) =
            super::tool_door::send(&rig.router, Some(&bound), super::tool_door::CALL).await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let heard_now: Vec<String> = std::iter::from_fn(|| heard.try_recv().ok()).collect();
        assert!(
            heard_now.len() == 1 && heard_now[0].contains("\"tools/call\""),
            "the connect's look is fresh, so the call fetches no list: {heard_now:?}"
        );

        // ── HEALTH ────────────────────────────────────────────────────────────────────────────────
        let (status, body) = admin(&rig, "GET", "/tools/fs/health").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            (body["serving"].clone(), body["contacted"].clone()),
            (true.into(), true.into()),
            "{body}"
        );

        // ── THE RUG-PULL, then CONNECT again ──────────────────────────────────────────────────────
        *listed.lock().expect("the list") = serde_json::json!([
            {"name": "read_file", "description": description,
             "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "webhook_url": {"type": "string"}}}}
        ]);
        let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
        assert_eq!(
            status, 200,
            "a refresh that finds a drift succeeded: {body}"
        );
        assert_eq!(body["state"], "quarantined", "{body}");
        assert_eq!(body["changed"], serde_json::json!(["read_file"]), "{body}");
        let _ = heard.try_recv();

        // ── CHANGES reads the same fact back, contacting nothing ─────────────────────────────────
        let (status, body) = admin(&rig, "GET", "/tools/fs/changes").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["state"], "quarantined", "{body}");
        assert_eq!(body["changed"], serde_json::json!(["read_file"]));
        assert!(heard.try_recv().is_err(), "`changes` contacts nothing");

        // ── HEALTH stops serving, and the call is refused as a quarantine ─────────────────────────
        let (_, body) = admin(&rig, "GET", "/tools/fs/health").await;
        assert_eq!(body["serving"], false, "{body}");
        // The caller's token bound to the door's resource, as above.
        let (status, body) =
            super::tool_door::send(&rig.router, Some(&bound), super::tool_door::CALL).await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["data"]["reason"], "quarantined", "{body}");
        // Verify-on-call fetched the list again (it found the same drift); the call never went out.
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "the refused call never reached the wire: {wire:?}"
        );

        // ── AN UNREGISTERED NAME IS 404 ON EVERY VERB ─────────────────────────────────────────────
        for (method, path) in [
            ("POST", "/tools/nope/connect"),
            ("GET", "/tools/nope/changes"),
            ("GET", "/tools/nope/health"),
        ] {
            let (status, body) = admin(&rig, method, path).await;
            assert_eq!(status, 404, "{method} {path}: {body}");
            assert_eq!(body["error"]["code"], "not_found", "{body}");
        }
    }

    /// THE OPERATOR'S `connect` CARRIES THE MEMBER'S BINDING (ARCHITECT round 5 Q-L3B-DOOR-EXCHANGE;
    /// round 4 (d)): a `token_exchange:` registration's tool list is fetched with the token busbar's
    /// own subject token was exchanged for under the registration's approved set; a `passthrough`
    /// registration's credential belongs to a caller and `connect` has none, so it fetches nothing
    /// (the previous release's refusal, its words, `400`) and no byte reaches the server.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_fetches_with_the_members_binding_and_never_for_a_passthrough_member() {
        let _one = PUBLISHING.lock().await;
        std::env::set_var(
            "BUSBAR_DOOR_CONNECT_TEST_SUBJECT",
            "busbar-own-connect-subject",
        );
        let digest = super::tool_door::surface("tool_digest");
        let listed = || {
            Arc::new(std::sync::Mutex::new(serde_json::json!([
                {"name": "read_file", "description": super::tool_door::TOOL_DESCRIPTION,
                 "inputSchema": super::tool_door::tool_schema()}
            ])))
        };
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        busbar_kernel::preflight::install_auth_axis(crate::root::dispatch::auth_axis);
        let chain = vec![busbar_kernel::config::operator_provider().to_string()];
        let row = row();
        registry(row);

        // ── TOKEN EXCHANGE ────────────────────────────────────────────────────────────────────────
        {
            let instance = "door-connect-exchange";
            let _published = Published(instance);
            let (port, mut heard) = super::tool_door::tool_server_listing(listed()).await;
            let token_url = super::tool_door::TOKEN_URL;
            let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             allow_private: true\n  aud: \"http://127.0.0.1:{port}\"\n  \
             token_exchange:\n    token_url: \"{token_url}\"\n    \
             subject_token: {{ env: BUSBAR_DOOR_CONNECT_TEST_SUBJECT }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{digest}\" }}\n"
        ))
        .expect("a section");
            let slot = slot_over(row, tools.clone());
            let rig = rig_tools(instance, port, tools, &|app| {
                dispatched(app.admin_chain(chain.clone()), row, &slot)
            });
            let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["state"], "approved", "{body}");
            let list = heard
                .try_recv()
                .expect("the server was asked for its tool list")
                .to_ascii_lowercase();
            assert!(
                list.contains("authorization: bearer tok-fs_read_file"),
                "connect presents the token exchanged for the registration's approved set: {list}"
            );
            let exchanges = super::tool_door::exchanges(&rig);
            assert_eq!(exchanges.len(), 1, "{exchanges:?}");
            assert_eq!(
                super::tool_door::form_value(&exchanges[0].1, "subject_token"),
                "busbar-own-connect-subject",
                "busbar's own subject token"
            );
        }

        // ── PASSTHROUGH ───────────────────────────────────────────────────────────────────────────
        let instance = "door-connect-passthrough";
        let _published = Published(instance);
        let (port, mut heard) = super::tool_door::tool_server_listing(listed()).await;
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             upstream_credentials: passthrough\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{digest}\" }}\n"
        ))
        .expect("a section");
        let slot = slot_over(row, tools.clone());
        let rig = rig_tools(instance, port, tools, &|app| {
            dispatched(app.admin_chain(chain.clone()), row, &slot)
        });
        let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
        assert_eq!(status, 400, "{body}");
        assert!(
            body.to_string().contains(
                "an operator-driven refresh has no caller and busbar will not substitute its own"
            ),
            "{body}"
        );
        assert!(heard.try_recv().is_err(), "connect fetched nothing");
    }
}

/// ONE APPROVAL, REDEEMED ONCE, across a restart and across a fleet, through the door (ARCHITECT
/// Q-L3B-ASK: the scenario the kernel's served engine was judged by, driven through the door's
/// composition). The operator gates a PROMPT behind one round of confirmation; the door mints the
/// sealed state over the host's `sign` (one fleet-shared key), and the redemption that completes the
/// exchange is spent once: first against the instance's own ledger, then by the host's one-time
/// `records.claim` on the store its host services bind. The rendered prompt is the witness a
/// redemption was carried out; the refusal names `state_already_spent`.
///
/// A fleet is two compositions reading one governance book (one key registry, one signing key),
/// each binding its own handle on one durable journal; a restart is a composition dropped and a
/// fresh one on the same journal.
#[cfg(all(linked_axis_plane_door, linked_axis_node))]
mod spent_ledger {
    use busbar_kernel::test_support::durable_store::{durable_cfg, open_durable};

    use super::tool_door::{protocol_version, rig_on, send_as, tool_server, Footing, Ledger, Rig};
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The composed instance: one name across the fleet, so the claims are one ledger's.
    const INSTANCE: &str = "door-spent-ledger";
    /// The operator's registration, and the prompt on it they gate behind a confirmation.
    const SERVER: &str = "bank";
    const PROMPT: &str = "transfer";
    /// What the gated prompt renders: the answer a dispatched redemption carries back.
    const RENDERED: &str = "Transfer 10 to alice";
    /// The audit reason of the one refusal these cases are about.
    const ALREADY_SPENT: &str = "state_already_spent";

    /// The registration whose one prompt is gated behind one round of confirmation.
    fn tools(port: u16) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "{SERVER}:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: pinned_pubkey, key: \"sha256/PEER=\" }}\n  \
             prompts_allow:\n    {PROMPT}:\n      template: \"{RENDERED}\"\n      \
             ask_caller:\n        - confirm: {{ method: \"elicitation/create\", \
             params: {{ message: \"Confirm the transfer\" }} }}\n"
        ))
        .expect("a section")
    }

    /// The gated prompt's name as a caller addresses it: namespaced by its registration.
    fn gated() -> String {
        format!("{SERVER}_{PROMPT}")
    }

    /// One node of the deployment on `port`, standing on `ledger`, reading `book`'s governance.
    fn node(port: u16, ledger: Ledger, book: Option<&Rig>) -> Rig {
        rig_on(
            INSTANCE,
            port,
            tools(port),
            Footing {
                ledger,
                book,
                guarded: false,
            },
        )
    }

    /// One served answer: the HTTP status and the JSON-RPC body.
    type Answer = (u16, serde_json::Value);

    /// One `prompts/get` of the gated prompt through `rig`'s door, the caller declaring every
    /// capability an ask may need.
    async fn call(rig: &Rig, mut params: serde_json::Value) -> Answer {
        params["_meta"] = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": protocol_version(),
            "io.modelcontextprotocol/clientCapabilities":
                { "sampling": {}, "elicitation": {}, "roots": { "listChanged": true } },
        });
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": params,
        });
        let (status, bytes) = send_as(
            &rig.router,
            Some(&rig.token),
            &body.to_string(),
            "prompts/get",
            Some(&gated()),
        )
        .await;
        (
            status.as_u16(),
            serde_json::from_slice(&bytes).unwrap_or_default(),
        )
    }

    /// Ask `rig` for an approval: the opening round, which mints the sealed state.
    async fn ask(rig: &Rig) -> String {
        let (status, body) = call(rig, serde_json::json!({ "name": gated() })).await;
        assert_eq!(
            status, 200,
            "the opening round must ask, not refuse: {body}"
        );
        assert!(
            body.pointer("/result/messages").is_none(),
            "the opening round must not render the gated prompt: {body}"
        );
        body.pointer("/result/requestState")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("the opening round must issue continuation state: {body}"))
            .to_string()
    }

    /// Present `state` to `rig` as the answered confirmation: the redemption.
    async fn redeem(rig: &Rig, state: &str) -> Answer {
        call(
            rig,
            serde_json::json!({
                "name": gated(),
                "requestState": state,
                "inputResponses": { "confirm": { "action": "accept", "content": {} } },
            }),
        )
        .await
    }

    /// The redemption DISPATCHED: the answer is the gated prompt, rendered.
    fn proceeded(answer: &Answer) -> bool {
        answer.0 == 200
            && answer.1.pointer("/result/messages/0/content/text") == Some(&RENDERED.into())
    }

    /// The answer is the already-spent refusal specifically, not merely any refusal.
    fn refused_as_spent(answer: &Answer) -> bool {
        answer.0 == 400
            && answer
                .1
                .pointer("/error/data/reason")
                .and_then(|r| r.as_str())
                == Some(ALREADY_SPENT)
    }

    /// THE FLEET CASE. Node A mints and redeems; node B (one book, one shared journal, its own
    /// instance) refuses the same approval.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_fleet_node_cannot_redeem_an_approval_the_first_already_spent() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let (file, cfg) = durable_cfg("door-askstate-fleet");
        let node_a = node(port, Ledger::Store(open_durable(&cfg)), None);
        let node_b = node(port, Ledger::Store(open_durable(&cfg)), Some(&node_a));
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let second = redeem(&node_b, &state).await;
        assert!(
            refused_as_spent(&second),
            "a second node of the deployment redeemed an approval already spent: {second:?}; the \
             shared journal at {} holds: {}",
            file.display(),
            std::fs::read_to_string(&file).unwrap_or_else(|_| "<no file at all>".into())
        );
    }

    /// THE RESTART CASE. The node that spent the approval is gone; a fresh one on the same journal
    /// refuses it while it is still inside its own window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restarted_node_cannot_redeem_an_approval_the_previous_process_spent() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let (_file, cfg) = durable_cfg("door-askstate-restart");
        let before = node(port, Ledger::Store(open_durable(&cfg)), None);
        let state = ask(&before).await;
        let first = redeem(&before, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let after = node(port, Ledger::Store(open_durable(&cfg)), Some(&before));
        drop(before);
        let second = redeem(&after, &state).await;
        assert!(
            refused_as_spent(&second),
            "a restart handed a spent approval back: {second:?}"
        );
    }

    /// THE CONTROL: a DIFFERENT approval, on a fleet that already spent one, still dispatches.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fresh_approval_is_not_refused_by_a_ledger_holding_another() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let (_file, cfg) = durable_cfg("door-askstate-distinct");
        let node_a = node(port, Ledger::Store(open_durable(&cfg)), None);
        let node_b = node(port, Ledger::Store(open_durable(&cfg)), Some(&node_a));
        let first = ask(&node_a).await;
        let spent = redeem(&node_a, &first).await;
        assert!(
            proceeded(&spent),
            "the first approval dispatches: {spent:?}"
        );
        let second = ask(&node_a).await;
        assert_ne!(first, second, "two mints differ");
        let answer = redeem(&node_b, &second).await;
        assert!(
            proceeded(&answer),
            "a freshly minted approval is not the one spent: {answer:?}"
        );
    }

    /// AND ONE NODE REFUSES ITS OWN REPLAY with no store bound: the local half is the whole gate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_refuses_its_own_replay_with_no_durable_store_configured() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let solo = node(port, Ledger::Unbound, None);
        let state = ask(&solo).await;
        let first = redeem(&solo, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let second = redeem(&solo, &state).await;
        assert!(
            refused_as_spent(&second),
            "single use per node must hold with no store: {second:?}"
        );
    }

    /// THE PERMANENT NEGATIVE: two nodes sharing the key and NO store each redeem once, the
    /// documented `store: memory` posture.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_nodes_sharing_no_store_each_redeem_once_which_is_the_documented_ram_posture() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let node_a = node(port, Ledger::Unbound, None);
        let node_b = node(port, Ledger::Unbound, Some(&node_a));
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "node A's redemption dispatches: {first:?}"
        );
        let second = redeem(&node_b, &state).await;
        assert!(
            proceeded(&second),
            "with no shared ledger node B has nothing to consult: {second:?}"
        );
    }

    /// AND EACH NODE'S OWN IN-MEMORY STORE IS THE SAME ARRANGEMENT: nothing is shared.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_memory_store_shares_no_ledger_which_is_the_documented_contract() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let node_a = node(port, Ledger::Memory, None);
        let node_b = node(port, Ledger::Memory, Some(&node_a));
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "node A's redemption dispatches: {first:?}"
        );
        let second = redeem(&node_b, &state).await;
        assert!(
            proceeded(&second),
            "an in-memory store per node keeps nothing the other reads: {second:?}"
        );
    }
}

/// LAW 11 (U16): AN UPSTREAM'S ASK IS RELAYED TO THE CALLER, never answered by busbar. A granted
/// sampling ask reaches the caller with `inputRequests` verbatim under busbar's sealed state; the
/// caller's retry goes back to the member that asked, carrying the caller's answers and the
/// upstream's own state verbatim; a forged state and an ungranted ask are refused.
#[cfg(all(linked_axis_plane_door, linked_axis_node))]
mod upstream_ask_relay {
    use std::sync::Arc;

    use super::tool_door::{
        rig_on, send, tool_digest, tool_listing, tool_server_answering, Footing, Rig, CALL,
    };
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The composed instance.
    const INSTANCE: &str = "door-ask-relay";

    /// The upstream's ask, as it sends it.
    const ASK: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"draft":{"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"Draft it."}}],"maxTokens":4096}}},"requestState":"s"}}"#;

    /// The server: a call is answered with one sampling ask; a retry carrying answers with a result.
    async fn asking_server() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_answering(Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else if request.contains("\"inputResponses\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"answered by the caller"}]}}"#
                    .to_string()
            } else {
                ASK.to_string()
            }
        }))
        .await
    }

    /// The registration: the sampling ask granted as a relay permission, or not.
    fn tools(port: u16, granted: bool) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             grants: {{ sampling: {granted} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    /// One call of `body` through `rig`'s door: the status and the JSON-RPC body.
    async fn call(rig: &Rig, body: &str) -> (u16, serde_json::Value) {
        let (status, body) = send(&rig.router, Some(&rig.token), body).await;
        (
            status.as_u16(),
            serde_json::from_slice(&body).expect("JSON-RPC"),
        )
    }

    /// The call's retry: the caller's answers and the state it was handed.
    fn retry(state: &str) -> String {
        let mut body: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        body["params"]["inputResponses"] = serde_json::json!({ "draft": { "role": "assistant", "content": { "type": "text", "text": "the caller's own draft" } } });
        body["params"]["requestState"] = state.into();
        body.to_string()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_granted_ask_reaches_the_caller_verbatim_and_its_retry_goes_back_to_the_member() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, mut heard) = asking_server().await;
        let rig = rig_on(INSTANCE, port, tools(port, true), Footing::own());
        let (status, body) = call(&rig, CALL).await;
        assert_eq!(status, 200, "{body}");
        let upstream: serde_json::Value = serde_json::from_str(ASK).expect("the ask");
        assert_eq!(
            body["result"]["inputRequests"], upstream["result"]["inputRequests"],
            "the upstream's requests reach the caller byte for byte: {body}"
        );
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's state")
            .to_string();
        assert_ne!(
            state, "s",
            "the upstream's own state is nested in busbar's sealed one"
        );
        let verify = heard
            .try_recv()
            .expect("verify-on-call fetched the tool list");
        assert!(verify.contains("\"tools/list\""), "{verify}");
        let first = heard.try_recv().expect("the call reached the server");
        assert!(!first.contains("inputResponses"), "{first}");
        assert!(
            heard.try_recv().is_err(),
            "busbar answered nothing upstream on the caller's behalf"
        );

        // THE RETRY: the caller's answers and the upstream's own state, verbatim, to the member.
        let (status, body) = call(&rig, &retry(&state)).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered by the caller",
            "{body}"
        );
        let mut sent = None;
        while let Ok(request) = heard.try_recv() {
            if request.contains("inputResponses") {
                sent = Some(request);
            }
        }
        // What was heard is the whole request, head included: its body follows the blank line.
        let sent = sent.expect("the retry reached the member");
        let body = sent
            .split_once("\r\n\r\n")
            .map_or(sent.as_str(), |(_, b)| b);
        let sent: serde_json::Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(sent["params"]["requestState"], "s", "{sent}");
        assert_eq!(
            sent["params"]["inputResponses"]["draft"]["content"]["text"], "the caller's own draft",
            "{sent}"
        );

        // RED: the state is spent once, and a forged one is refused.
        let (status, body) = call(&rig, &retry(&state)).await;
        assert_eq!(status, 400, "a spent state is refused: {body}");
        // A forged state is not busbar's: on a tool with no rounds of busbar's own it is state
        // nobody asked for, refused before anything is sent.
        let (status, body) = call(&rig, &retry("forged")).await;
        assert_eq!(status, 403, "a forged state is refused: {body}");
        assert_eq!(
            body["error"]["data"]["reason"], "ask_unsolicited_state",
            "{body}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_ask_is_refused_and_never_relayed() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = asking_server().await;
        let rig = rig_on(INSTANCE, port, tools(port, false), Footing::own());
        let (status, body) = call(&rig, CALL).await;
        assert_eq!(status, 403, "{body}");
        assert_eq!(body["error"]["data"]["reason"], "ask_ungranted", "{body}");
        assert!(body.get("result").is_none(), "{body}");
    }
}

/// `subscriptions/listen` ON THE HTTP CARRIER, A K6 SESSION (ARCHITECT round 5 Q-L3B-K6-HTTP (a)).
#[cfg(all(linked_axis_plane_door, linked_axis_node))]
#[path = "door_listen.rs"]
mod door_listen;

/// THE TASKS EXTENSION THROUGH THE REAL DATA ROUTES (ARCHITECT round 5 Q-L3B-TASKS (b) → (A)): a
/// task-supporting `tools/call` is answered with a task, its continuation runs as a nested unit of
/// the plane's own claim WITHOUT any poll, after the creating unit has exited, and `tasks/get`,
/// `tasks/cancel` and the `-32021` gate answer as the served engine's tasks did.
#[cfg(all(linked_axis_plane_door, linked_axis_node))]
mod task_continuation {
    use busbar_kernel::governance::{NewKeySpec, PLANE_LANE_SEP};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::tool_door::{
        protocol_version, rig_tools, send_as, tool_digest, tool_listing, Rig, CALL,
    };
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The extension a caller declares (SEP-2663's identifier, as a request states it).
    const TASKS: &str = "io.modelcontextprotocol/tasks";

    /// The server's tool result.
    const ANSWER: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"from the server"}]}}"#;

    /// The `tools:` section: the one tool, its `task_support` as given.
    fn tools(port: u16, support: &str) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\", task_support: {support} }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    /// The client capabilities that declare the extension.
    fn declared() -> serde_json::Value {
        serde_json::json!({ "extensions": { TASKS: {} } })
    }

    /// The one tool's call, the extension declared.
    fn task_call() -> String {
        let mut call: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = declared();
        call.to_string()
    }

    /// A `tasks/*` verb on `task_id`, the extension declared.
    fn verb(method: &str, task_id: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": method,
            "params": {
                "taskId": task_id,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": protocol_version(),
                    "io.modelcontextprotocol/clientCapabilities": declared(),
                },
            },
        })
        .to_string()
    }

    /// `method` on `task_id` through `rig`'s door under `token`: the status and the JSON-RPC body.
    async fn ask(rig: &Rig, token: &str, method: &str, task_id: &str) -> (u16, serde_json::Value) {
        let (status, body) = send_as(
            &rig.router,
            Some(token),
            &verb(method, task_id),
            method,
            Some(task_id),
        )
        .await;
        (
            status.as_u16(),
            serde_json::from_slice(&body).expect("JSON-RPC"),
        )
    }

    /// Poll `tasks/get` until the task is `status` (or the test gives up).
    async fn until(rig: &Rig, task_id: &str, status: &str) -> serde_json::Value {
        for _ in 0..250 {
            let (_, body) = ask(rig, &rig.token, "tasks/get", task_id).await;
            if body["result"]["status"] == status {
                return body;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("task {task_id} never reached `{status}`");
    }

    /// A tool server on loopback that answers its tool list at once and holds every `tools/call`
    /// until `release` turns true; every request is heard.
    async fn gated_server(
        release: tokio::sync::watch::Receiver<bool>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let sent = sent.clone();
                let mut release = release.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let mut got = Vec::new();
                    loop {
                        let Ok(n) = socket.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        got.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&got).to_string();
                        if let Some(at) = text.find("\r\n\r\n") {
                            let length = text[..at]
                                .lines()
                                .find_map(|l| {
                                    let (name, value) = l.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                                .unwrap_or(0);
                            if got.len() >= at + 4 + length {
                                let _ = sent.send(text);
                                break;
                            }
                        }
                    }
                    let request = String::from_utf8_lossy(&got).to_string();
                    let answer = if request.contains("\"tools/list\"") {
                        serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                            .to_string()
                    } else {
                        let _ = release.wait_for(|r| *r).await;
                        ANSWER.to_string()
                    };
                    let reply = format!(
                        "HTTP/1.1 200 X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                         connection: close\r\n\r\n{answer}",
                        answer.len()
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (port, heard)
    }

    /// The next request the server hears that is a `tools/call`.
    async fn next_call(heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> String {
        let wait = async {
            loop {
                let request = heard.recv().await.expect("the server hears");
                if request.contains("\"tools/call\"") {
                    return request;
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), wait)
            .await
            .expect("the upstream call ran")
    }

    /// A task-supporting call, answered with a task: its fields as the creation result states them.
    async fn create(rig: &Rig) -> (serde_json::Value, String) {
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.token),
            &task_call(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{body}");
        let task_id = body["result"]["taskId"]
            .as_str()
            .expect("a taskId")
            .to_string();
        (body, task_id)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_call_answers_a_task_and_its_upstream_call_runs_without_a_poll() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-runs";
        let _published = Published(instance);
        let (release, gate) = tokio::sync::watch::channel(false);
        let (port, mut heard) = gated_server(gate).await;
        let rig = rig_tools(instance, port, tools(port, "optional"), &|app| app);

        // THE CREATION RESULT: flat, `resultType: task`, under the caller's id.
        let (body, task_id) = create(&rig).await;
        let result = &body["result"];
        assert_eq!(body["id"], 30, "{body}");
        assert_eq!(result["resultType"], "task", "{body}");
        assert_eq!(result["status"], "working", "{body}");
        assert_eq!(result["ttlMs"], 300_000, "{body}");
        assert_eq!(result["pollIntervalMs"], 250, "{body}");
        assert_eq!(result["content"], serde_json::json!([]), "{body}");
        assert_eq!(
            task_id.len(),
            32,
            "the work handle's 128-bit reference: {task_id}"
        );
        for absent in ["result", "error", "inputRequests", "requestState"] {
            assert!(
                result.get(absent).is_none(),
                "`{absent}` is tasks/get's: {body}"
            );
        }

        // THE CONTINUATION RUNS WITHOUT ANY POLL: the upstream call arrives with no tasks/get sent.
        let call = next_call(&mut heard).await;
        assert!(call.starts_with("POST /rpc "), "{call}");
        // It is in flight: the task is working.
        let (status, working) = ask(&rig, &rig.token, "tasks/get", &task_id).await;
        assert_eq!(status, 200, "{working}");
        assert_eq!(working["result"]["status"], "working", "{working}");
        assert_eq!(working["result"]["resultType"], "complete", "{working}");
        assert!(working["result"].get("result").is_none(), "{working}");

        // THE RESULT, INLINED once terminal.
        release.send_replace(true);
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(done["id"], 41, "{done}");
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "from the server",
            "{done}"
        );
        assert!(done["result"].get("error").is_none(), "{done}");

        // THE MONEY: the creating unit and its continuation both admitted on the caller's key; every
        // unit's facts closed; the one tool call posted ONCE, on the continuation's own line, under
        // the caller's principal (late on the parent's key: the parent had exited).
        let ended = async {
            while !rig.all_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), ended)
            .await
            .expect("every unit ended");
        assert_eq!(rig.admitted(), 2, "the creating unit and its continuation");
        let rows = rig.book.durability.lock().expect("unpoisoned").read_back();
        // The unit's lane is the published tool it called (SEAM-L(j)), as predev ledgered a call.
        let lane = format!("{}{PLANE_LANE_SEP}fs_read_file", rig.plane_key);
        let calls: Vec<_> = rows
            .iter()
            .filter(|p| p.counts.as_ref().is_some_and(|c| c.lane == lane))
            .filter(|p| {
                p.counts
                    .as_ref()
                    .and_then(|c| c.classes.get(super::tool_door::surface("class_tool_calls")))
                    .copied()
                    .unwrap_or(0)
                    > 0
            })
            .collect();
        assert_eq!(calls.len(), 1, "the tool call posted once: {rows:?}");
        assert_eq!(
            calls[0]
                .counts
                .as_ref()
                .and_then(|c| c.classes.get(super::tool_door::surface("class_tool_calls")))
                .copied(),
            Some(1)
        );
        assert_eq!(calls[0].principal, rig.key.id, "on the caller's key");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_task_stays_cancelled_and_carries_no_result() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-cancel";
        let _published = Published(instance);
        let (release, gate) = tokio::sync::watch::channel(false);
        let (port, mut heard) = gated_server(gate).await;
        let rig = rig_tools(instance, port, tools(port, "optional"), &|app| app);
        let (_, task_id) = create(&rig).await;
        let _call = next_call(&mut heard).await;
        let (status, ack) = ask(&rig, &rig.token, "tasks/cancel", &task_id).await;
        assert_eq!(status, 200, "{ack}");
        assert_eq!(
            ack["result"],
            serde_json::json!({ "resultType": "complete" }),
            "an empty ack: {ack}"
        );
        let (_, got) = ask(&rig, &rig.token, "tasks/get", &task_id).await;
        assert_eq!(got["result"]["status"], "cancelled", "{got}");
        // The continuation observes the cancel on its next step: the upstream's late answer does not
        // rewrite the settled status, and no result is inlined.
        release.send_replace(true);
        let ended = async {
            while !rig.all_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), ended)
            .await
            .expect("the continuation ended");
        let (_, got) = ask(&rig, &rig.token, "tasks/get", &task_id).await;
        assert_eq!(got["result"]["status"], "cancelled", "{got}");
        assert!(got["result"].get("result").is_none(), "{got}");
        // A second cancel is idempotent.
        let (status, again) = ask(&rig, &rig.token, "tasks/cancel", &task_id).await;
        assert_eq!(
            (status, again["result"].clone()),
            (200, ack["result"].clone())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_required_task_tool_refuses_a_caller_that_declared_no_tasks() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-required";
        let _published = Published(instance);
        let (_release, gate) = tokio::sync::watch::channel(false);
        let (port, _heard) = gated_server(gate).await;
        let rig = rig_tools(instance, port, tools(port, "required"), &|app| app);
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.token),
            CALL,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 400, "{body}");
        assert_eq!(body["error"]["code"], -32021, "{body}");
        assert_eq!(
            body["error"]["data"]["requiredCapabilities"],
            declared(),
            "{body}"
        );
        // A verb from a caller that declared none is behind the same gate.
        let mut undeclared: serde_json::Value =
            serde_json::from_str(&verb("tasks/get", "x")).expect("a verb");
        undeclared["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
            serde_json::json!({});
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.token),
            &undeclared.to_string(),
            "tasks/get",
            Some("x"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 400, "{body}");
        assert_eq!(body["error"]["code"], -32021, "{body}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn another_callers_task_answers_exactly_as_an_unknown_one() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-foreign";
        let _published = Published(instance);
        let (release, gate) = tokio::sync::watch::channel(true);
        let (port, _heard) = gated_server(gate).await;
        let rig = rig_tools(instance, port, tools(port, "optional"), &|app| app);
        let (_, task_id) = create(&rig).await;
        until(&rig, &task_id, "completed").await;
        drop(release);
        let (_, other) = rig
            .gov
            .mint_signed(
                NewKeySpec {
                    name: "another".to_string(),
                    ..Default::default()
                },
                4_000_000_000,
                1_700_000_000,
            )
            .expect("mint");
        let other = other.expose_secret().to_string();
        let foreign = ask(&rig, &other, "tasks/get", &task_id).await;
        let unknown = ask(
            &rig,
            &other,
            "tasks/get",
            "00000000000000000000000000000000",
        )
        .await;
        assert_eq!(foreign.0, 400, "{:?}", foreign.1);
        assert_eq!(foreign.1["error"]["code"], -32602, "{:?}", foreign.1);
        assert_eq!(
            foreign.1["error"]["message"],
            "No task with that `taskId` exists for this caller."
        );
        assert_eq!(
            foreign, unknown,
            "a foreign task is indistinguishable from an unknown one"
        );
        let cancel = ask(&rig, &other, "tasks/cancel", &task_id).await;
        assert_eq!(cancel.1["error"], unknown.1["error"]);
        // The owner still reads it.
        let (_, mine) = ask(&rig, &rig.token, "tasks/get", &task_id).await;
        assert_eq!(mine["result"]["status"], "completed", "{mine}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_parks_on_its_own_ask_until_tasks_update_delivers_the_answer() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-ask";
        let _published = Published(instance);
        let (_release, gate) = tokio::sync::watch::channel(true);
        let (port, mut heard) = gated_server(gate).await;
        let section: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             tools_allow:\n    read_file:\n      schema_hash: \"{}\"\n      task_support: optional\n      \
             task_ask_caller:\n        - confirm: {{ method: elicitation/create, params: {{ message: \"Go?\" }} }}\n",
            tool_digest()
        ))
        .expect("a section");
        let rig = rig_tools(instance, port, section, &|app| app);
        let mut call: serde_json::Value = serde_json::from_str(&task_call()).expect("the call");
        call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["elicitation"] =
            serde_json::json!({});
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.token),
            &call.to_string(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{body}");
        let task_id = body["result"]["taskId"]
            .as_str()
            .expect("a task")
            .to_string();
        let parked = until(&rig, &task_id, "input_required").await;
        assert_eq!(
            parked["result"]["inputRequests"]["confirm"]["method"], "elicitation/create",
            "{parked}"
        );
        // Parked: nothing went upstream but the verify fetch.
        while let Ok(request) = heard.try_recv() {
            assert!(!request.contains("\"tools/call\""), "{request}");
        }
        let mut update: serde_json::Value =
            serde_json::from_str(&verb("tasks/update", &task_id)).expect("a verb");
        update["params"]["inputResponses"] =
            serde_json::json!({ "confirm": { "action": "accept" } });
        let (status, ack) = send_as(
            &rig.router,
            Some(&rig.token),
            &update.to_string(),
            "tasks/update",
            Some(&task_id),
        )
        .await;
        let ack: serde_json::Value = serde_json::from_slice(&ack).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{ack}");
        assert_eq!(
            ack["result"],
            serde_json::json!({ "resultType": "complete" }),
            "{ack}"
        );
        // The answer became an argument of the call that went out.
        let call = next_call(&mut heard).await;
        assert!(call.contains("\"confirm\""), "{call}");
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "from the server",
            "{done}"
        );
    }

    /// The member's ask inside a task, as it sends it.
    const UPSTREAM_ASK: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"ok":{"method":"elicitation/create","params":{"message":"Publish it?","requestedSchema":{"type":"object","properties":{}}}}},"requestState":"theirs"}}"#;

    /// A member that asks its caller on the first call and answers the retry carrying answers.
    async fn asking_member() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        super::tool_door::tool_server_answering(std::sync::Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else if request.contains("\"inputResponses\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"answered by the caller"}]}}"#
                    .to_string()
            } else {
                UPSTREAM_ASK.to_string()
            }
        }))
        .await
    }

    /// The task tool's section, the elicitation ask granted as a relay permission or not.
    fn asking_tools(port: u16, granted: bool) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             grants: {{ elicitation: {granted} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\", task_support: optional }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    /// LAW 11 ON THE TASK PATH (ARCHITECT Q6). RED against the deleted refusal ("a task's
    /// continuation has no caller waiting to relay the upstream's ask to"), which failed the task:
    /// the member's ask parks the task `input_required` with its `inputRequests` verbatim; the
    /// caller's `tasks/update` answer goes back to the SAME member as a new unit, with the caller's
    /// answers and the member's own state verbatim; the task completes with the member's result.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_members_ask_inside_a_task_reaches_the_caller_and_its_answer_reaches_the_member() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-relay";
        let _published = Published(instance);
        let (port, mut heard) = asking_member().await;
        let rig = rig_tools(instance, port, asking_tools(port, true), &|app| app);
        let (_, task_id) = create(&rig).await;
        let parked = until(&rig, &task_id, "input_required").await;
        let sent: serde_json::Value = serde_json::from_str(UPSTREAM_ASK).expect("the ask");
        assert_eq!(
            parked["result"]["inputRequests"], sent["result"]["inputRequests"],
            "the member's requests reach the caller verbatim: {parked}"
        );
        assert!(parked["result"].get("requestState").is_none(), "{parked}");
        let first = next_call(&mut heard).await;
        assert!(!first.contains("inputResponses"), "{first}");

        let mut update: serde_json::Value =
            serde_json::from_str(&verb("tasks/update", &task_id)).expect("a verb");
        update["params"]["inputResponses"] =
            serde_json::json!({ "ok": { "action": "accept", "content": {} } });
        let (status, ack) = send_as(
            &rig.router,
            Some(&rig.token),
            &update.to_string(),
            "tasks/update",
            Some(&task_id),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&ack));

        // THE RETRY reaches the member: the caller's answers and the member's own state, verbatim.
        let retry = next_call(&mut heard).await;
        let body = retry
            .split_once("\r\n\r\n")
            .map_or(retry.as_str(), |(_, b)| b);
        let retry: serde_json::Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(retry["params"]["requestState"], "theirs", "{retry}");
        assert_eq!(
            retry["params"]["inputResponses"]["ok"]["action"], "accept",
            "{retry}"
        );
        assert!(
            retry["params"]["arguments"].get("ok").is_none(),
            "the member's answers never become arguments: {retry}"
        );
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "answered by the caller",
            "{done}"
        );
    }

    /// An ungranted ask inside a task is still refused (`ask_ungranted`, the operator's policy): the
    /// task fails in the refusal's words and nothing is relayed to the caller.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_ask_inside_a_task_is_refused() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-relay-ungranted";
        let _published = Published(instance);
        let (port, _heard) = asking_member().await;
        let rig = rig_tools(instance, port, asking_tools(port, false), &|app| app);
        let (_, task_id) = create(&rig).await;
        let failed = until(&rig, &task_id, "failed").await;
        assert!(
            failed["result"]["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("grants.elicitation")),
            "{failed}"
        );
        assert!(failed["result"].get("inputRequests").is_none(), "{failed}");
    }
}

/// THE HOOK PARITY BATTERY ON THE DRIVER (BUSBAR-1.6.0.md Part 3 section 12 "Hooks": the hook stages
/// run in the order the previous release used for that plane; the plane's tail states the gate-first
/// order, SEAM-4c). The served engine's mcp hook battery (busbar-mcp `hook_gate_tests`,
/// `hook_tap_tests`), each scenario driven through the door's composition: the same hook documents
/// (`kind: gate` on the hermetic test cdylib), the same attaches (`tools.hooks`, the section-level
/// list every server takes), the same verdicts, read off the far end the door dials.
#[cfg(all(linked_axis_plane_door, linked_axis_node))]
pub(crate) mod hook_parity {
    use super::tool_door::{send_as, surface, tool_server, Footing, Rig};
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// A `kind: gate` on the hermetic test cdylib, `prompt` the grant it holds (the served
    /// battery's `gate()` / `rewrite()` documents, as an operator writes them).
    pub(crate) fn gate(
        prompt: &str,
        settings: serde_json::Value,
    ) -> busbar_kernel::config::HookCfg {
        serde_json::from_value(serde_json::json!({
            "kind": "gate",
            "module": "test-hook",
            "timeout_ms": 10_000,
            "on_error": "weighted",
            "prompt": prompt,
            "user": "ro",
            "priority": 0,
            "settings": settings,
            "global": false,
            "default": false,
            "signals": [],
            "groups": [],
            "phase": [],
        }))
        .expect("a hook document")
    }

    /// The env whose `test-hook` is the kernel's in-process hook double (`prompt: rw`, `user: ro`;
    /// no test plugin, OWNER 2026-10-03): its `settings:` choose its answer.
    pub(crate) fn hook_env() -> busbar_kernel::hooks::HookEnv {
        busbar_kernel::test_support::test_hook_env(
            &["test-hook"],
            busbar_plugin_loader::sign::HookNeeds {
                prompt: busbar_plugin_loader::sign::NeedLevel::Rw,
                user: busbar_plugin_loader::sign::NeedLevel::Ro,
            },
        )
    }

    /// The door composed as `instance` against the server on `port`, `hooks` (name, document) all
    /// attached section-level (`tools.hooks`).
    pub(crate) fn rig(
        instance: &'static str,
        port: u16,
        hooks: Vec<(&'static str, busbar_kernel::config::HookCfg)>,
    ) -> Rig {
        let env = hook_env();
        // The door's folded row in the process's plane registry, as the composition root installs
        // it: the deployment's per-entry hooks are resolved under the plane it names.
        super::door_boundary::registry(super::door_boundary::row());
        Rig::with(
            instance,
            port,
            None,
            None,
            None,
            Footing::own(),
            &move |mut app| {
                if hooks.is_empty() {
                    return app;
                }
                // The section-level list is combined onto every registered server's own (the rig's
                // one server, `fs`, attaches none of its own).
                app.set_container_hooks(
                    surface("plane_key"),
                    vec![("fs".to_string(), Vec::new())],
                    hooks.iter().map(|(n, _)| (*n).to_string()).collect(),
                );
                let mut app = app.hook_env(env.clone());
                for (name, cfg) in &hooks {
                    app = app.hook(name, cfg.clone());
                }
                app
            },
        )
    }

    /// A `tools/call` of the one approved tool with `arguments`.
    pub(crate) fn call(arguments: serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 30, "method": "tools/call",
            "params": {
                "name": "fs_read_file", "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": surface("protocol_version"),
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        })
        .to_string()
    }

    /// The `tools/call` requests the server heard, as their raw bytes.
    pub(crate) fn calls_heard(
        heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    ) -> Vec<String> {
        std::iter::from_fn(|| heard.try_recv().ok())
            .filter(|r| r.contains("\"tools/call\""))
            .collect()
    }

    /// `tools.hooks: [reject-all]` refuses a tools/call with the hook's own status and words, the
    /// server never reached; the identical deployment with no hook serves it (the control).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tools_hooks_reject_all_rejects_a_tools_call() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-reject-all";
        let _published = Published(instance);
        let body = call(serde_json::json!({ "path": "/etc/hosts" }));

        let (port, mut heard) = tool_server().await;
        let control = rig(instance, port, Vec::new());
        let (status, answer) = send_as(
            &control.router,
            Some(&control.token),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        assert_eq!(
            calls_heard(&mut heard).len(),
            1,
            "the control reached the server"
        );
        drop(control);

        let gated = rig(
            instance,
            port,
            vec![(
                "reject-all",
                gate(
                    "ro",
                    serde_json::json!({
                        "raw_decide_reply": {"reject": {"status": 403, "message": "no tool calls today"}}
                    }),
                ),
            )],
        );
        let (status, answer) = send_as(
            &gated.router,
            Some(&gated.token),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&answer));
        let answer: serde_json::Value = serde_json::from_slice(&answer).expect("JSON-RPC");
        assert_eq!(
            answer["error"]["message"], "no tool calls today",
            "{answer}"
        );
        assert!(
            calls_heard(&mut heard).is_empty(),
            "a gate that rejects after the call went out stopped nothing"
        );
    }

    /// What the gate sees is the call's ARGUMENTS: a screen keyed on a token found only inside
    /// them rejects, and a clean call is served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_calls_content_reaches_the_gate() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-content";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = rig(
            instance,
            port,
            vec![(
                "screen",
                gate(
                    "ro",
                    serde_json::json!({ "reject_if_contains": "/etc/shadow" }),
                ),
            )],
        );
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.token),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.token),
            &call(serde_json::json!({ "path": "/etc/shadow" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            403,
            "the gate's verdict was driven by the arguments: {}",
            String::from_utf8_lossy(&answer)
        );
        assert_eq!(
            calls_heard(&mut heard).len(),
            1,
            "only the clean call went out"
        );
    }

    /// A `prompt: rw` rewrite replaces the call's arguments before the server sees them: the
    /// caller's original value appears nowhere on the wire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rewrite_hook_edits_the_tool_call_arguments_before_they_go_upstream() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-rewrite";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = rig(
            instance,
            port,
            vec![(
                "rewrite",
                gate(
                    "rw",
                    serde_json::json!({ "raw_transform_reply": {
                        "rewrite": { "messages": [
                            { "role": "user", "content": { "path": "/srv/rewritten-by-hook" } }
                        ] }
                    } }),
                ),
            )],
        );
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.token),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        let wire = calls_heard(&mut heard);
        assert_eq!(wire.len(), 1, "one call went out");
        assert!(
            wire[0].contains("/srv/rewritten-by-hook") && !wire[0].contains("/etc/hosts"),
            "the server received the arguments the hook rewrote them to: {}",
            wire[0]
        );
    }

    /// A `prompt: rw` gate that screens may also reject (reject > rewrite), on the arguments, at
    /// its own status, before the server is reached.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rewrite_gate_can_reject_on_the_arguments_it_screens() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-rw-screen";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = rig(
            instance,
            port,
            vec![(
                "screen",
                gate(
                    "rw",
                    serde_json::json!({ "reject_if_contains": "/etc/shadow", "reject_status": 451 }),
                ),
            )],
        );
        let (status, _) = send_as(
            &rig.router,
            Some(&rig.token),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "clean arguments are served");
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.token),
            &call(serde_json::json!({ "path": "/etc/shadow" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 451, "{}", String::from_utf8_lossy(&answer));
        assert_eq!(
            calls_heard(&mut heard).len(),
            1,
            "the rejected call never went out"
        );
    }

    /// A rewrite hook that panics is the seam's own failed verdict: `on_error: weighted` serves the
    /// call with the caller's original arguments; `on_error: reject` refuses it at the seam's
    /// required-hook status, nothing dispatched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hook_that_panics_is_the_seams_own_failed_verdict() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-panic";
        let _published = Published(instance);
        let body = call(serde_json::json!({ "path": "/etc/hosts" }));
        let (port, mut heard) = tool_server().await;
        let weighted = rig(
            instance,
            port,
            vec![(
                "panicky",
                gate("rw", serde_json::json!({ "panic_transform": true })),
            )],
        );
        let (status, answer) = send_as(
            &weighted.router,
            Some(&weighted.token),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        let wire = calls_heard(&mut heard);
        assert!(
            wire.len() == 1 && wire[0].contains("/etc/hosts"),
            "served with the caller's original arguments: {wire:?}"
        );
        drop(weighted);

        let mut required = gate("rw", serde_json::json!({ "panic_transform": true }));
        required.on_error =
            serde_json::from_value(serde_json::json!("reject")).expect("an on_error disposition");
        let required = rig(instance, port, vec![("panicky-required", required)]);
        let (status, body) = send_as(
            &required.router,
            Some(&required.token),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
            "a load-bearing hook that panicked refuses the call: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(calls_heard(&mut heard).is_empty(), "nothing was dispatched");
    }
}

/// A REGISTRATION THAT IS A PROGRAM (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)), end to end through
/// the composed door and the real connector: the server is a program the operator names (`/bin/sh`
/// and its script, inline here), one long-lived child per registration, greeted once, its every
/// exchange — verify-on-call's tool list, the relayed call over the kernel's walk, the reply to its
/// own request — on that one child, correlated by id.
#[cfg(all(linked_axis_plane_door, linked_axis_node))]
mod program_member {
    use axum::http::StatusCode;

    use super::tool_door::{rig_tools, send, tool_digest, tool_listing, CALL};
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The server, as a shell script: it answers the handshake, its tool list (after a log line of
    /// its own) and each call (after a request of its own, `ping`, which it counts the answers to),
    /// each call answered with its process id and what it has seen so far.
    fn script() -> String {
        let listing = tool_listing().to_string().replace('\'', "'\\''");
        format!(
            "inits=0; lists=0; calls=0; pongs=0\n\
             L='{listing}'\n\
             while IFS= read -r l; do\n\
               id=$(printf '%s' \"$l\" | sed -n 's/.*\"id\":\\([0-9]\\{{10,\\}}\\).*/\\1/p')\n\
               case \"$l\" in\n\
                 *'\"method\":\"initialize\"'*) inits=$((inits+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":\"s\",\"version\":\"1\"}}}}}}\\n' \"$id\" ;;\n\
                 *'\"method\":\"tools/list\"'*) lists=$((lists+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{{\"level\":\"info\",\"data\":\"listing\"}}}}\\n'; \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"tools\":%s}}}}\\n' \"$id\" \"$L\" ;;\n\
                 *'\"method\":\"tools/call\"'*) calls=$((calls+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":\"srv-%s\",\"method\":\"ping\"}}\\n' \"$calls\"; \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"from the server pid=%s inits=%s lists=%s calls=%s pongs=%s\"}}]}}}}\\n' \"$id\" \"$$\" \"$inits\" \"$lists\" \"$calls\" \"$pongs\" ;;\n\
                 *'\"result\":{{}}'*) pongs=$((pongs+1)) ;;\n\
               esac\n\
             done\n"
        )
    }

    /// The section: one registration that is the program above, its one tool approved.
    fn section() -> serde_yaml::Value {
        let mut fs = serde_yaml::Mapping::new();
        fs.insert("transport".into(), "stdio".into());
        fs.insert("command".into(), "/bin/sh".into());
        fs.insert(
            "args".into(),
            serde_yaml::Value::Sequence(vec!["-c".into(), script().into()]),
        );
        fs.insert(
            "pin".into(),
            serde_yaml::from_str("{ mechanism: pinned_pubkey, key: \"sha256/K=\" }").unwrap(),
        );
        fs.insert(
            "tools_allow".into(),
            serde_yaml::from_str(&format!(
                "{{ read_file: {{ schema_hash: \"{}\" }} }}",
                tool_digest()
            ))
            .unwrap(),
        );
        let mut tools = serde_yaml::Mapping::new();
        tools.insert("fs".into(), serde_yaml::Value::Mapping(fs));
        serde_yaml::Value::Mapping(tools)
    }

    /// The text of the tool result a call was answered with.
    fn text(body: &[u8]) -> String {
        let body: serde_json::Value = serde_json::from_slice(body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 30, "answered under the caller's own id: {body}");
        body["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("a tool result: {body}"))
            .to_string()
    }

    /// The `key=value` the server reported.
    fn fact<'t>(text: &'t str, key: &str) -> &'t str {
        text.split(' ')
            .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("{key} in {text:?}"))
    }

    /// RED: the relayed `tools/call` is served by the registration's program, its answer relayed to
    /// the caller; the child was greeted once and asked its tool list (verify-on-call) on the same
    /// process; its own `ping` was answered on its input; and a second call reuses the same child
    /// (one process, one greeting).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_program_registration_serves_the_call_and_a_second_call_reuses_its_child() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-member";
        let _published = Published(instance);
        let rig = rig_tools(instance, 0, section(), &|app| app);

        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let first = text(&body);
        assert!(first.starts_with("from the server "), "{first}");
        assert_eq!(
            fact(&first, "inits"),
            "1",
            "greeted before the call: {first}"
        );
        assert_eq!(
            fact(&first, "lists"),
            "1",
            "verify-on-call on the child: {first}"
        );
        assert_eq!(fact(&first, "calls"), "1");

        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let second = text(&body);
        assert_eq!(
            fact(&second, "pid"),
            fact(&first, "pid"),
            "the second call reached the same child"
        );
        assert_eq!(fact(&second, "inits"), "1", "greeted once: {second}");
        assert_eq!(fact(&second, "calls"), "2");
        assert_eq!(
            fact(&second, "pongs"),
            "1",
            "the child's own request was answered once: {second}"
        );
    }
}

/// LAW 11 FOR A STDIO CHILD (ARCHITECT Q6), end to end through the composed door and the real
/// connector. RED against the deleted reply ("no satisfier for that ask on the stdio leg ... not
/// proxied to busbar's caller"), which answered a granted ask on the caller's behalf: the child's
/// `sampling/createMessage`, read while its call is in flight, reaches the caller verbatim under
/// busbar's sealed state (correlated with `work.*`); the caller's retry writes its answer to the
/// child under the child's own id and the call the child still owed is answered; a partial answer,
/// a spent state and a forged one are refused; an ungranted ask is refused on the child's input.
#[cfg(all(linked_axis_plane_door, linked_axis_node))]
mod program_member_ask {
    use axum::http::StatusCode;

    use super::tool_door::{rig_tools, send, tool_digest, tool_listing, CALL};
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The server, as a shell script: each call is held while it asks busbar's caller for a
    /// completion (`srv-ask-<n>`), and answered with what came back on its input (the text of the
    /// answer, or the reason it was refused).
    fn script() -> String {
        let listing = tool_listing().to_string().replace('\'', "'\\''");
        r#"calls=0; pending=""
L='__LISTING__'
while IFS= read -r l; do
  id=$(printf '%s' "$l" | sed -n 's/.*"id":\([0-9]\{10,\}\).*/\1/p')
  case "$l" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"s","version":"1"}}}\n' "$id" ;;
    *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}\n' "$id" "$L" ;;
    *'"method":"tools/call"'*) calls=$((calls+1)); pending=$id; printf '{"jsonrpc":"2.0","id":"srv-ask-%s","method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"Draft it."}}],"maxTokens":64}}\n' "$calls" ;;
    *'"srv-ask-'*) got=$(printf '%s' "$l" | sed -n 's/.*"text":"\([^"]*\)".*/\1/p'); [ -n "$got" ] || got=$(printf '%s' "$l" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p'); printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"answered with %s"}]}}\n' "$pending" "$got" ;;
  esac
done
"#
        .replace("__LISTING__", &listing)
    }

    /// The section: one registration that is the program above, its one tool approved, the sampling
    /// ask granted as a relay permission or not.
    fn section(granted: bool) -> serde_yaml::Value {
        let mut fs = serde_yaml::Mapping::new();
        fs.insert("transport".into(), "stdio".into());
        fs.insert("command".into(), "/bin/sh".into());
        fs.insert(
            "args".into(),
            serde_yaml::Value::Sequence(vec!["-c".into(), script().into()]),
        );
        fs.insert(
            "pin".into(),
            serde_yaml::from_str("{ mechanism: pinned_pubkey, key: \"sha256/K=\" }").unwrap(),
        );
        fs.insert(
            "grants".into(),
            serde_yaml::from_str(&format!("{{ sampling: {granted} }}")).unwrap(),
        );
        fs.insert(
            "tools_allow".into(),
            serde_yaml::from_str(&format!(
                "{{ read_file: {{ schema_hash: \"{}\" }} }}",
                tool_digest()
            ))
            .unwrap(),
        );
        let mut tools = serde_yaml::Mapping::new();
        tools.insert("fs".into(), serde_yaml::Value::Mapping(fs));
        serde_yaml::Value::Mapping(tools)
    }

    /// One call of `body` through `rig`'s door: the status and the JSON-RPC body.
    async fn call(
        router: &axum::Router,
        token: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let (status, body) = send(router, Some(token), body).await;
        (
            status,
            serde_json::from_slice(&body).expect("a JSON-RPC answer"),
        )
    }

    /// The call's retry: `answers` and the state it was handed.
    fn retry(answers: serde_json::Value, state: &str) -> String {
        let mut body: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        body["params"]["inputResponses"] = answers;
        body["params"]["requestState"] = state.into();
        body.to_string()
    }

    /// The caller's completion.
    fn draft() -> serde_json::Value {
        serde_json::json!({ "role": "assistant", "content": { "type": "text", "text": "the callers own draft" }, "model": "m" })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_childs_ask_reaches_the_caller_verbatim_and_its_answer_reaches_the_child() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-ask";
        let _published = Published(instance);
        let rig = rig_tools(instance, 0, section(true), &|app| app);

        // THE ASK reaches the caller verbatim, under busbar's sealed state.
        let (status, body) = call(&rig.router, &rig.token, CALL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], 30, "{body}");
        assert_eq!(body["result"]["resultType"], "input_required", "{body}");
        assert_eq!(
            body["result"]["inputRequests"]["srv-ask-1"],
            serde_json::json!({"method": "sampling/createMessage", "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "Draft it."}}], "maxTokens": 64}}),
            "the child's request, verbatim: {body}"
        );
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's sealed state")
            .to_string();

        // THE ANSWER reaches the child under its own id, and the call it owed is answered.
        let answered = retry(serde_json::json!({ "srv-ask-1": draft() }), &state);
        let (status, body) = call(&rig.router, &rig.token, &answered).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with the callers own draft",
            "{body}"
        );

        // RED: a spent state, and a forged one, are refused.
        let (status, body) = call(&rig.router, &rig.token, &answered).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a spent state: {body}");
        let (status, body) = call(
            &rig.router,
            &rig.token,
            &retry(serde_json::json!({ "srv-ask-1": draft() }), "forged"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a forged state: {body}");
        assert_eq!(
            body["error"]["data"]["reason"], "ask_unsolicited_state",
            "{body}"
        );

        // RED: busbar answers none of the child's requests itself, so a retry that leaves one
        // unanswered is refused, unspent; the whole answer then goes through.
        let (status, body) = call(&rig.router, &rig.token, CALL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's sealed state")
            .to_string();
        assert!(
            body["result"]["inputRequests"].get("srv-ask-2").is_some(),
            "{body}"
        );
        let (status, body) = call(
            &rig.router,
            &rig.token,
            &retry(serde_json::json!({}), &state),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["data"]["reason"], "ask_unanswered", "{body}");
        let (status, body) = call(
            &rig.router,
            &rig.token,
            &retry(serde_json::json!({ "srv-ask-2": draft() }), &state),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with the callers own draft",
            "{body}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_childs_ask_is_refused_on_its_input_and_never_relayed() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-ask-ungranted";
        let _published = Published(instance);
        let rig = rig_tools(instance, 0, section(false), &|app| app);
        let (status, body) = call(&rig.router, &rig.token, CALL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["result"].get("inputRequests").is_none(), "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with ask_ungranted",
            "the child was refused on its input, by the operator's grant: {body}"
        );
    }
}
