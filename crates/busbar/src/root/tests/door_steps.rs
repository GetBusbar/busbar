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

/// [`resolve_over`], with `upgrades` the linked framers composed over the data carrier.
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
    let auths = super::OutboundAuths::new(
        dispatcher,
        crate::LINKED.auths,
        None,
        crate::root::loader::dispatch::ConnTable::NoNeeds,
    );
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    let conns: std::sync::Arc<dyn busbar_contract::conn::PollConns> =
        std::sync::Arc::new(busbar_core_connector::Connector::new());
    let reach = super::DoorReach {
        providers: &providers,
        secrets: std::sync::Arc::clone(&secrets),
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
struct TokenEndpoint {
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
        fault: None,
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
    let linked: [busbar_kernel::preflight::LinkedAuth; 1] =
        [("busbar-auth-oauth", busbar_auth_oauth::door)];
    let auths = super::OutboundAuths::new(
        dispatcher,
        &linked,
        None,
        crate::root::loader::dispatch::ConnTable::Host(std::sync::Arc::clone(&table)
            as std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>),
    );
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    let reach = super::DoorReach {
        providers: &providers,
        secrets: std::sync::Arc::clone(&secrets),
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

// ── `upstream_credential:` — busbar's own credential for a registration, re-resolved per hop ────

/// No provider: a registration is reached at its own target.
static NO_PROVIDERS: std::collections::BTreeMap<String, super::ProviderRoute> =
    std::collections::BTreeMap::new();

/// The door's reach over the build's linked auth plugins (`busbar-auth-header` serves `bearer`
/// and `api-key`) and the built-in secret modules.
fn own_reach() -> super::DoorReach<'static> {
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    super::DoorReach {
        providers: &NO_PROVIDERS,
        secrets: std::sync::Arc::new(
            busbar_kernel::config::secret::SecretResolver::builtins_only(),
        ),
        auths: std::sync::Arc::new(super::OutboundAuths::new(
            dispatcher,
            crate::LINKED.auths,
            None,
            crate::root::loader::dispatch::ConnTable::NoNeeds,
        )),
        conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
        stream_ceiling_secs: 1,
        upgrades: Vec::new(),
    }
}

/// A secret file of this test's own (a file, not an env var: `set_var` is process-global and the
/// cells run in parallel), holding `value`.
fn own_secret(name: &str, value: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "busbar-door-steps-cred-{name}-{}",
        std::process::id()
    ));
    std::fs::write(&path, value).expect("write the test secret");
    path
}

/// ROTATE the secret at `path` to `value` the way an operator's secret store does: written aside,
/// then renamed over it, so a reader sees the old value or the new one, whole.
fn rotate(path: &std::path::Path, value: &str) {
    let aside = path.with_extension("rotating");
    std::fs::write(&aside, value).expect("write the rotated secret");
    std::fs::rename(&aside, path).expect("swap it in");
}

/// The registration `planner` stating `upstream_credential: {secret: {file: <path>}<placement>,
/// lease_ttl_ms: 60000}` (`placement` the YAML after the secret, or empty for none).
fn registration(path: &std::path::Path, placement: &str) -> serde_yaml::Value {
    serde_yaml::from_str(&format!(
        "url: 'https://agent.vendor/planner'\nupstream_credential: {{secret: {{file: '{}'}}{placement}, \
         lease_ttl_ms: 60000}}",
        path.display()
    ))
    .expect("yaml")
}

/// What a binding's handle `handle` presents on one request: each field, its name lower-cased.
fn presents(
    auth: &dyn busbar_contract::auth_calls::OutboundAuth,
    handle: u64,
) -> Vec<(String, String)> {
    match auth.fields_now(
        handle,
        &busbar_contract::auth_calls::FieldsRequest::default(),
    ) {
        Some(busbar_contract::auth_calls::Fields::Ready(fields)) => fields
            .iter()
            .map(|f| {
                (
                    String::from_utf8_lossy(&f.name).to_ascii_lowercase(),
                    String::from_utf8_lossy(f.value.expose_secret()).into_owned(),
                )
            })
            .collect(),
        other => panic!("a header binding answers on the spot: {other:?}"),
    }
}

/// Why the load was refused (a binding is not `Debug`: it holds an auth instance).
fn refused(bound: Result<Option<busbar_kernel::plane_driver::AuthBinding>, String>) -> String {
    match bound {
        Err(why) => why,
        Ok(_) => panic!("the load was not refused"),
    }
}

/// Ported from `busbar-a2a` `creds_tests::a_minted_lease_carries_the_secret_only_through_the_header_it_was_placed_at`:
/// `placement: bearer` (and no placement at all) binds the `bearer` style, so the secret is
/// presented only as `authorization: Bearer <secret>`, the trailing newline a file secret picks up
/// trimmed by the resolver (a header value with an embedded newline is a header-splitting bug).
/// RED: a registration stating no `upstream_credential` binds nothing, so nothing is presented.
#[test]
fn a_bearer_placement_presents_the_secret_only_as_the_bearer() {
    let path = own_secret("bearer", "s3cr3t-vendor-token\n");
    let reach = own_reach();
    for placement in [", placement: bearer", ""] {
        let binding =
            super::upstream_credential_binding("planner", &registration(&path, placement), &reach)
                .expect("it binds")
                .expect("an upstream credential is a binding");
        assert!(
            !binding.passthrough,
            "busbar's own credential, never the caller's"
        );
        let handle = binding
            .per_request
            .as_ref()
            .expect("re-resolved per hop")
            .handle_now()
            .expect("it resolves");
        assert_eq!(
            presents(&*binding.auth, handle),
            vec![(
                "authorization".to_string(),
                "Bearer s3cr3t-vendor-token".to_string()
            )],
            "placement `{placement}`"
        );
    }
    let bare: serde_yaml::Value =
        serde_yaml::from_str("url: 'https://agent.vendor/planner'").expect("yaml");
    assert!(
        super::upstream_credential_binding("planner", &bare, &reach)
            .expect("no block is no error")
            .is_none(),
        "no upstream_credential: nothing is bound, so nothing is presented"
    );
    let _ = std::fs::remove_file(&path);
}

/// Ported from `busbar-a2a` `creds_tests::a_named_header_placement_carries_the_value_verbatim`:
/// `placement: {header: X-API-Key}` binds the `api-key` style over that header, the secret
/// verbatim, and no `authorization`; a placement naming no header refuses the load.
#[test]
fn a_named_header_placement_presents_the_secret_verbatim_in_that_header() {
    let path = own_secret("apikey", "abc123");
    let reach = own_reach();
    let binding = super::upstream_credential_binding(
        "planner",
        &registration(&path, ", placement: {header: X-API-Key}"),
        &reach,
    )
    .expect("it binds")
    .expect("a binding");
    let handle = binding
        .per_request
        .as_ref()
        .expect("re-resolved per hop")
        .handle_now()
        .expect("it resolves");
    assert_eq!(
        presents(&*binding.auth, handle),
        vec![("x-api-key".to_string(), "abc123".to_string())]
    );
    let err = refused(super::upstream_credential_binding(
        "planner",
        &registration(&path, ", placement: {header: ''}"),
        &reach,
    ));
    assert!(err.contains("member 'planner'"), "{err}");
    let _ = std::fs::remove_file(&path);
}

/// Ported from `busbar-a2a` `creds_tests::an_unresolvable_handle_fails_closed_and_names_the_agent`:
/// a secret that does not resolve when the generation is sealed refuses the load naming the member
/// (fail closed); one that stops resolving after it is refused per hop: the handle answers none.
#[test]
fn an_unresolvable_credential_fails_closed_and_names_the_member() {
    let reach = own_reach();
    let missing = std::path::Path::new("/nonexistent/busbar/agent/secret");
    let err = refused(super::upstream_credential_binding(
        "planner",
        &registration(missing, ""),
        &reach,
    ));
    assert!(
        err.contains("member 'planner'") && err.contains("cannot resolve"),
        "{err}"
    );

    let path = own_secret("vanish", "tok");
    let binding = super::upstream_credential_binding("planner", &registration(&path, ""), &reach)
        .expect("it binds")
        .expect("a binding");
    let per = binding.per_request.as_ref().expect("re-resolved per hop");
    assert!(
        per.handle_now().is_some(),
        "it resolves while the file is there"
    );
    std::fs::remove_file(&path).expect("remove it");
    assert_eq!(per.handle_now(), None, "gone: nothing is presented");
}

/// An `OutboundAuth` counting its `open_outbound` calls over the real one.
struct CountingOpens {
    inner: std::sync::Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
    opened: std::sync::atomic::AtomicUsize,
}

impl busbar_contract::auth_calls::OutboundAuth for CountingOpens {
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String> {
        self.opened
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.open_outbound(style, credential, settings)
    }

    fn fields_now(
        &self,
        handle: u64,
        request: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        self.inner.fields_now(handle, request)
    }

    fn fields(
        &self,
        handle: u64,
        request: busbar_contract::auth_calls::FieldsRequest,
        deadline_ns: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        self.inner.fields(handle, request, deadline_ns)
    }
}

/// A `bearer` [`super::PerHop`] over the secret at `path`, opened by `auth` as the composition
/// opens it.
fn per_hop(path: &std::path::Path, auth: std::sync::Arc<CountingOpens>) -> super::PerHop {
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    let secret = busbar_contract::secret_ref::SecretRef::file(path.display().to_string());
    let value = secrets.resolve_string(&secret).expect("it resolves");
    let settings = serde_json::json!({});
    let handle = {
        use busbar_contract::auth_calls::OutboundAuth as _;
        auth.open_outbound("bearer", value.as_bytes(), &settings)
            .expect("it opens")
    };
    super::PerHop {
        secret,
        secrets,
        auth: auth as std::sync::Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
        style: "bearer",
        settings,
        held: std::sync::Mutex::new((
            busbar_contract::abi::sdk::digest::sha256(value.as_bytes()),
            handle,
        )),
    }
}

/// The real `bearer` auth instance the build links.
fn bearer_auth() -> std::sync::Arc<CountingOpens> {
    let (inner, _) = own_reach()
        .auths
        .serving("bearer", &serde_json::json!({}))
        .expect("a lookup")
        .expect("the linked header plugin serves `bearer`");
    std::sync::Arc::new(CountingOpens {
        inner,
        opened: std::sync::atomic::AtomicUsize::new(0),
    })
}

/// RE-RESOLVED ON EVERY HOP (as the previous plane minted a lease from the secret per hop): a hop
/// after the secret's source changed presents the NEW value, re-opening the binding exactly once
/// for the rotation; an unchanged secret never re-opens it, however many hops ask (handles grow by
/// rotations, never by hops).
#[test]
fn a_rotated_secret_is_presented_on_the_next_hop_and_an_unchanged_one_never_reopens() {
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let path = own_secret("rotate", "old-token");
    let auth = bearer_auth();
    let per = per_hop(&path, std::sync::Arc::clone(&auth));
    let opens = || auth.opened.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(opens(), 1, "the composition's one open");

    let first = per.handle_now().expect("it resolves");
    for _ in 0..16 {
        assert_eq!(
            per.handle_now(),
            Some(first),
            "the same handle hop after hop"
        );
    }
    assert_eq!(opens(), 1, "an unchanged secret never re-opens the binding");
    assert_eq!(
        presents(&*auth, first),
        vec![("authorization".to_string(), "Bearer old-token".to_string())]
    );

    rotate(&path, "new-token");
    let next = per.handle_now().expect("it resolves");
    assert_ne!(next, first, "the rotation re-opened the binding");
    assert_eq!(opens(), 2, "one re-open for one rotation");
    assert_eq!(
        presents(&*auth, next),
        vec![("authorization".to_string(), "Bearer new-token".to_string())],
        "the very next hop presents the new value"
    );
    assert_eq!(per.handle_now(), Some(next));
    assert_eq!(
        opens(),
        2,
        "and the new value, unchanged, never re-opens it"
    );
    let _ = std::fs::remove_file(&path);
}

/// HOPS RACING A ROTATION each present ONE COMPLETE VALUE, the old or the new, never a mix: the
/// handle a hop is given was opened over one whole value, and it is swapped under one lock.
#[test]
fn hops_racing_a_rotation_each_present_one_whole_value() {
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let path = own_secret("race", "value-old-0000000000");
    let auth = bearer_auth();
    let per = std::sync::Arc::new(per_hop(&path, std::sync::Arc::clone(&auth)));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hops: Vec<_> = (0..4)
        .map(|_| {
            let (per, auth, stop) = (
                std::sync::Arc::clone(&per),
                std::sync::Arc::clone(&auth),
                std::sync::Arc::clone(&stop),
            );
            std::thread::spawn(move || {
                let mut seen = std::collections::BTreeSet::new();
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    let Some(handle) = per.handle_now() else {
                        continue;
                    };
                    for (_, value) in presents(&*auth, handle) {
                        seen.insert(value);
                    }
                }
                seen
            })
        })
        .collect();
    for i in 0..64 {
        let value = if i % 2 == 0 {
            "value-new-1111111111"
        } else {
            "value-old-0000000000"
        };
        rotate(&path, value);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let whole = [
        "Bearer value-old-0000000000".to_string(),
        "Bearer value-new-1111111111".to_string(),
    ];
    for hop in hops {
        for value in hop.join().expect("a hop thread") {
            assert!(whole.contains(&value), "a mixed or partial value: {value}");
        }
    }
    let _ = std::fs::remove_file(&path);
}

/// Ported from `busbar-a2a` `creds_tests::the_lease_never_renders_the_secret_in_a_debug_line`:
/// the per-hop binding holds a reference and a digest, never the value, and its debug line shows
/// neither the value nor the digest.
#[test]
fn the_per_hop_binding_never_renders_the_secret_in_a_debug_line() {
    let path = own_secret("debug", "SUPER-SECRET-VALUE");
    let per = per_hop(&path, bearer_auth());
    let rendered = format!("{per:?}");
    assert!(
        !rendered.contains("SUPER-SECRET-VALUE"),
        "the binding rendered its secret: {rendered}"
    );
    let digest = busbar_contract::abi::sdk::digest::sha256(b"SUPER-SECRET-VALUE");
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !rendered.contains(&hex) && !rendered.contains(&format!("{:?}", digest[0..4].to_vec())),
        "the binding rendered its digest: {rendered}"
    );
    assert!(rendered.contains("<redacted"), "{rendered}");
    assert!(
        !rendered.contains(&path.display().to_string()),
        "nor where the secret lives: {rendered}"
    );
    let _ = std::fs::remove_file(&path);
}
/// A REGISTRATION MEMBER RIDES EVERY MEMBER-TARGET NEED its plane states (ARCHITECT root ruling,
/// 2026-10-07, reusing the providers' rides, Q-L5B-NEEDS): its first is its own, each
/// other one rides beside it at the target the registration names there (another origin dials that
/// origin), and a far request naming any of them opens on it. A registration naming no target for
/// a need does not ride it. RED: only the first member-target need was bound, so a far request
/// naming the second had no destination.
#[test]
fn a_registration_member_rides_every_member_target_need() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
        ],
        need_targets: vec!["", "settings.*.url", "settings.*.url", "settings.*.alt"],
        ..Default::default()
    };
    let routes = resolve_for(
        &facts,
        "fs: {url: \"http://127.0.0.1:7/rpc\", alt: \"http://127.0.0.1:8/x\"}\n\
         one: {url: \"http://127.0.0.1:9/rpc\"}\n",
        &[],
    )
    .expect("the registrations resolve");
    let fs = &routes["fs"];
    assert_eq!(fs.need.0, 1, "the first member-target need is its own");
    let rides: Vec<u32> = fs.rides.iter().map(|(n, _)| n.0).collect();
    assert_eq!(
        rides,
        [2, 3],
        "every other member-target need rides beside it"
    );
    assert_eq!(fs.ride(3).map(|r| r.need.0), Some(2));
    assert_eq!(
        fs.ride(3).map(|r| r.base_url),
        Some("http://127.0.0.1:7"),
        "the same target, the same origin"
    );
    assert_eq!(
        fs.ride(4).map(|r| r.base_url),
        Some("http://127.0.0.1:8"),
        "a need whose target is another origin dials that origin"
    );
    assert!(fs.ride(1).is_none(), "the open need is no member's");
    let one = &routes["one"];
    let rides: Vec<u32> = one.rides.iter().map(|(n, _)| n.0).collect();
    assert_eq!(
        rides,
        [2],
        "a registration naming no `alt` does not ride its need"
    );
}

/// A connection table that records what the composition seals on it: each need's anchors and
/// private reach, and each auth binding, by need and target. It opens nothing.
#[derive(Default)]
struct Sealing {
    anchored: std::sync::Mutex<Vec<(u32, String)>>,
    reached: std::sync::Mutex<Vec<(u32, String, String)>>,
    bound: std::sync::Mutex<Vec<(u32, String)>>,
}

impl busbar_contract::conn::Conns for Sealing {
    fn open(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
        _: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Refused)
    }
    fn write(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn read(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: u64,
        _: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn wait(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: &[busbar_contract::conn::ConnId],
        _: u64,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
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
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
}

impl busbar_contract::conn::PollConns for Sealing {
    fn poll_read(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: &mut std::task::Context<'_>,
        _: &mut [u8],
    ) -> std::task::Poll<Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError>>
    {
        std::task::Poll::Ready(Err(busbar_contract::conn::ConnError::Closed))
    }
    fn anchor(
        &self,
        _: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        _: &str,
        target: &str,
        _: &busbar_contract::transport::trust::Anchors,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.anchored
            .lock()
            .unwrap()
            .push((need.0, target.to_string()));
        Ok(())
    }
    fn seal_reach(
        &self,
        _: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        target: &str,
        reach: bool,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        if reach {
            self.reached
                .lock()
                .unwrap()
                .push((need.0, member.to_string(), target.to_string()));
        }
        Ok(())
    }
}

impl busbar_contract::conn::DeclaredConns for Sealing {
    fn declare(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
        _: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        Ok(())
    }
    fn declared(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
    ) -> Option<Result<(), busbar_contract::conn::ConnError>> {
        Some(Ok(()))
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
    fn bind_auth(
        &self,
        _: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        origin: &str,
        _: busbar_contract::conn::ConnAuth,
    ) {
        self.bound
            .lock()
            .unwrap()
            .push((need.0, origin.to_string()));
    }
}

/// An auth binding that is only ever bound: it answers no fields.
struct Bound;

/// A fields answer that never arrives.
struct Never;

impl std::future::Future for Never {
    type Output = busbar_contract::auth_calls::Fields;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Pending
    }
}

impl busbar_contract::auth_calls::Fielding for Never {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::Fields> {
        None
    }
}

impl busbar_contract::auth_calls::OutboundAuth for Bound {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(1)
    }
    fn fields_now(
        &self,
        _: u64,
        _: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        None
    }
    fn fields(
        &self,
        _: u64,
        _: busbar_contract::auth_calls::FieldsRequest,
        _: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        Box::new(Never)
    }
}

/// THE MEMBER'S ANCHORS, REACH AND BINDING HOLD ON EVERY NEED IT RIDES (ARCHITECT root ruling,
/// 2026-10-07): the composition seals the registration's trust anchors and private reach on
/// its own need and on each need riding beside it, at the base each dials, and the door's own
/// requests on any member-target need it rides carry its auth binding. RED: only the member's own
/// need was sealed and bound, so a far request (or the door's own request) on its second
/// transport went out unpinned, unreached and unauthenticated.
#[test]
fn a_registration_members_anchors_reach_and_binding_hold_on_every_need_it_rides() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    use busbar_kernel::plane_driver::{AuthBinding, MemberRoute, ResponseKeep};
    let served = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
        ],
        need_targets: vec!["", "settings.*.url", "settings.*.url"],
        ..Default::default()
    };
    let route = MemberRoute {
        need: busbar_contract::conn::NeedId(1),
        base_url: "https://far.example".to_string(),
        auth: Some(AuthBinding {
            auth: std::sync::Arc::new(Bound),
            handle: 1,
            style_flags: 0,
            points: busbar_contract::abi::auth::AuthPoints(0),
            passthrough: false,
            per_request: None,
        }),
        provider: "fs".to_string(),
        keep: ResponseKeep::default(),
        rides: vec![(busbar_contract::conn::NeedId(2), ResponseKeep::default())],
        anchors: busbar_contract::transport::trust::Anchors {
            private_reach: true,
            ..Default::default()
        },
        spelled: Vec::new(),
    };
    let routes = std::collections::BTreeMap::from([("fs".to_string(), route)]);
    let table = std::sync::Arc::new(Sealing::default());
    let instance = busbar_contract::conn::InstanceId(7);
    super::bind_member_fetches(
        &served,
        &routes,
        instance,
        &*table,
        &std::sync::Arc::new(busbar_kernel::host_units::UnitRecords::default()),
    );
    assert_eq!(
        *table.bound.lock().unwrap(),
        [
            (1, "https://far.example".to_string()),
            (2, "https://far.example".to_string())
        ],
        "the door's own requests on either need carry the member's binding"
    );
    let section: serde_yaml::Value =
        serde_yaml::from_str("fs: {url: \"https://far.example/rpc\"}").expect("yaml");
    let facts = super::door_facts("p", &[], &[], &[], "audit", Vec::new());
    let node = std::sync::Arc::new(crate::root::plane_node::Node::new());
    let post = std::sync::Arc::new(crate::root::plane_node::NodeEndPost::new(node));
    super::compose_egress(
        &facts,
        &DoorPools::of(&section),
        instance,
        std::sync::Arc::clone(&table) as std::sync::Arc<dyn busbar_contract::conn::PollConns>,
        &routes,
        post as std::sync::Arc<dyn busbar_kernel_egress::ports::Journal>,
        1,
    )
    .expect("the egress composes");
    assert_eq!(
        *table.anchored.lock().unwrap(),
        [
            (1, "https://far.example".to_string()),
            (2, "https://far.example".to_string())
        ],
        "the anchors are sealed on both needs"
    );
    assert_eq!(
        *table.reached.lock().unwrap(),
        [
            (1, "fs".to_string(), "https://far.example".to_string()),
            (2, "fs".to_string(), "https://far.example".to_string())
        ],
        "the registration's private reach is sealed on both needs"
    );
}
