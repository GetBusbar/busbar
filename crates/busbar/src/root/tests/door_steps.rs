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
    let section: serde_yaml::Value = serde_yaml::from_str(section).expect("yaml");
    let providers = providers
        .iter()
        .map(|(n, p)| ((*n).to_string(), p.clone()))
        .collect();
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    let auths = super::OutboundAuths::new(dispatcher, crate::LINKED.auths, None, None);
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let conns: std::sync::Arc<dyn busbar_contract::conn::PollConns> =
        std::sync::Arc::new(busbar_core_connector::Connector::new());
    let reach = super::DoorReach {
        providers: &providers,
        secrets: &secrets,
        auths: std::sync::Arc::new(auths),
        conns,
        stream_ceiling_secs: 1,
        catalog: None,
    };
    super::member_routes(&section, &DoorPools::of(&section), served, &reach)
}

/// MULTI-NEED (ARCHITECT Q-L5B-NEEDS 2026-10-03): a member binds EVERY outbound need its style
/// names, one per transport, the first as its own and the rest riding beside it, each opened when
/// a far request names it.
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
    assert_eq!(route.ride(3).map(|(n, _)| n.0), Some(2));
    assert_eq!(route.ride(0).map(|(n, _)| n.0), Some(1));
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
        Some(std::sync::Arc::clone(&table)
            as std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>),
    );
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let reach = super::DoorReach {
        providers: &providers,
        secrets: &secrets,
        auths: std::sync::Arc::new(auths),
        conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
        stream_ceiling_secs: 1,
        catalog: None,
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
