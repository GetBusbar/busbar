// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one record every route states (inbound admission C5): who may call it, what the key is
//! judged against, whether money moves, and whether it keeps state per caller. Every field is
//! stated; none has a default. A record that leaves one out or contradicts itself refuses its
//! plugin at load ([`RouteRecord::validate`]), so a route without an admission cannot be mounted
//! because it cannot be declared.
//!
//! This is the decoded form the engine consumes. It is held by the route's `Mounted` and read from
//! there on each request: nothing here is per request and nothing is a table.

use std::sync::Arc;

use busbar_plugin_abi::plane::{
    AUTH_OPERATOR, AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_SIGNED_INGRESS, AUTH_TICKET,
    ROUTE_ADMIN, ROUTE_CATALOG, ROUTE_LINE, ROUTE_RECOVERY, ROUTE_UPGRADE,
};

/// The method bit of `GET` in a route's method mask.
pub const METHOD_GET: u32 = busbar_contract::route::METHOD_GET;

/// Field 0: which sequence the route runs. One word, never bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteClass {
    Data,
    Catalog,
    Admin,
    Line,
    Recovery,
    Upgrade,
}

impl RouteClass {
    /// The class today's `RouteRec.flags` word states. More than one ROUTE_* bit is no class.
    pub fn from_flags(flags: u32) -> Option<Self> {
        match flags {
            0 => Some(Self::Data),
            ROUTE_CATALOG => Some(Self::Catalog),
            ROUTE_ADMIN => Some(Self::Admin),
            ROUTE_LINE => Some(Self::Line),
            ROUTE_RECOVERY => Some(Self::Recovery),
            ROUTE_UPGRADE => Some(Self::Upgrade),
            _ => None,
        }
    }

    pub const fn word(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Catalog => "catalog",
            Self::Admin => "admin",
            Self::Line => "line",
            Self::Recovery => "recovery",
            Self::Upgrade => "upgrade",
        }
    }
}

/// Field 1: the set of callers a route admits. The bit values are the interface's `AUTH_*`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Who(u32);

impl Who {
    pub const PRINCIPAL: Self = Self(AUTH_PRINCIPAL);
    pub const OPTIONAL: Self = Self(AUTH_OPTIONAL);
    pub const PUBLIC: Self = Self(AUTH_PUBLIC);
    pub const TICKET: Self = Self(AUTH_TICKET);
    pub const SIGNED_INGRESS: Self = Self(AUTH_SIGNED_INGRESS);
    pub const OPERATOR: Self = Self(AUTH_OPERATOR);
    const ALL: u32 = AUTH_PRINCIPAL
        | AUTH_OPTIONAL
        | AUTH_PUBLIC
        | AUTH_TICKET
        | AUTH_SIGNED_INGRESS
        | AUTH_OPERATOR;

    /// The set a route's auth mask states; `None` for an empty mask or a bit that names no caller.
    pub const fn from_mask(mask: u32) -> Option<Self> {
        if mask == 0 || mask & !Self::ALL != 0 {
            None
        } else {
            Some(Self(mask))
        }
    }

    pub const fn mask(self) -> u32 {
        self.0
    }

    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn has(self, member: Self) -> bool {
        self.0 & member.0 == member.0
    }

    pub const fn is(self, exactly: Self) -> bool {
        self.0 == exactly.0
    }

    /// Every member yields a principal a unit can be opened for: a verified principal, or a ticket
    /// core minted for one. A public, optional or signed caller has none; an operator's is the
    /// admin chain's, which opens no unit.
    pub const fn yields_principal(self) -> bool {
        self.0 & !(AUTH_PRINCIPAL | AUTH_TICKET) == 0
    }

    /// A request on this route can be answered "not verified", so a challenge can apply to it.
    pub const fn can_challenge(self) -> bool {
        self.0 & (AUTH_PRINCIPAL | AUTH_OPTIONAL | AUTH_TICKET | AUTH_OPERATOR) != 0
    }
}

impl std::fmt::Debug for Who {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for (bit, word) in [
            (AUTH_PRINCIPAL, "principal"),
            (AUTH_OPTIONAL, "optional"),
            (AUTH_PUBLIC, "public"),
            (AUTH_TICKET, "ticket"),
            (AUTH_SIGNED_INGRESS, "signed-ingress"),
            (AUTH_OPERATOR, "operator"),
        ] {
            if self.0 & bit != 0 {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(word)?;
                first = false;
            }
        }
        Ok(())
    }
}

/// The scope kind core owns: a key's `allowed_pools`, walked by core.
pub const KIND_POOL: &str = "pool";

/// Field 2: what the key is judged against. `walk`: the name the plane hands core's walk is judged
/// under this kind (llm `pool`, MCP `mcp_server`, A2A `agent`). `selected`: the plane picks finer
/// resources from the request and core judges each under its kind (MCP `mcp_tool`). Both empty is
/// "none", which the record must say outright ([`RouteRecord::scope_stated`]).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Scope {
    pub walk: Option<Box<str>>,
    pub selected: Arc<[Box<str>]>,
}

impl Scope {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn walk(kind: &str) -> Self {
        Self {
            walk: Some(kind.into()),
            selected: Arc::from(Vec::new()),
        }
    }

    pub fn selected(kinds: &[&str]) -> Self {
        Self {
            walk: None,
            selected: kinds.iter().map(|kind| Box::<str>::from(*kind)).collect(),
        }
    }

    pub fn walk_and_selected(kind: &str, kinds: &[&str]) -> Self {
        Self {
            walk: Some(kind.into()),
            selected: kinds.iter().map(|kind| Box::<str>::from(*kind)).collect(),
        }
    }

    pub fn is_none(&self) -> bool {
        self.walk.is_none() && self.selected.is_empty()
    }

    /// Every kind the scope names, the walk's first.
    pub fn kinds(&self) -> impl Iterator<Item = &str> {
        self.walk
            .as_deref()
            .into_iter()
            .chain(self.selected.iter().map(|kind| &**kind))
    }
}

/// Field 3: whether money moves. `Unit`: limits and money run, and a 2xx head before money was
/// admitted is the plane's FAULT, not a served request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Money {
    None,
    Unit,
}

/// Field 4: whether the route keeps state per caller. A `Distinct` route is not served where the
/// chain can yield a shared subject (`anonymous`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CallerState {
    Shared,
    Distinct,
}

/// A route's challenge names the plane's public URL and the operator configured none (or one
/// that is not a header value): the route is not mounted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoPublicUrl;

/// `{public_url}` in a challenge text: replaced once, at mount, with the plane instance's own
/// public URL (its `D_PUBLIC_URL_PATH` setting), never per request.
pub const CHALLENGE_PUBLIC_URL: &str = "{public_url}";

/// One route's record, decoded at load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRecord {
    pub class: RouteClass,
    pub who: Who,
    /// The header this route's credential arrives in (lowercase); `None` is "the chain's own".
    pub cred_header: Option<Box<str>>,
    /// The fixed `WWW-Authenticate` text a protocol's specification requires on this route's 401.
    pub challenge: Option<Box<str>>,
    pub scope: Scope,
    /// The record said "scope none" in so many words. A decoder that found no scope item at all
    /// leaves this false and [`RouteRecord::validate`] refuses the record.
    pub scope_stated: bool,
    pub money: Money,
    pub caller_state: CallerState,
}

/// What the route's plane image implements, as far as the record's rules ask.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PlaneMethods {
    pub render: bool,
    pub select_resources: bool,
    pub upstream: bool,
}

/// Why a record refuses its plugin at load. Each names the field at fault; the loader adds the
/// plugin and the route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordRefused {
    /// The auth set is empty, or mixes members that cannot share a route.
    Who,
    /// A public, optional or signed-ingress route states a scope or money.
    OpenRouteCarriesScopeOrMoney,
    /// A catalog route that does not walk a kind, or moves money, or whose plane has no `render`.
    Catalog,
    /// A scope names a selected kind and the plane has no `select_resources`.
    SelectedWithoutSelector,
    /// A scope names a walk kind and the plane has no `upstream`.
    WalkWithoutUpstream,
    /// The record neither names a scope nor says "none".
    ScopeNotStated,
    /// Money moves and some member of the auth set yields no principal.
    MoneyWithoutPrincipal,
    /// Operator callers on a route that is not admin, or an admin route with other callers.
    OperatorAdmin,
    /// An admin route states a scope kind or money.
    AdminCarriesScopeOrMoney,
    /// An upgrade route whose methods are not exactly GET.
    UpgradeMethods,
    /// A line or recovery route that is not principal-only.
    InternalAuth,
    /// A credential header on a route with no credential to read from it.
    CredHeader,
    /// A challenge on a route that can never answer 401, or one that is not a header value.
    Challenge,
    /// Per-caller state on a route that identifies no caller.
    DistinctWithoutCaller,
    /// A kind is named twice, is empty, or is not a plain lowercase name.
    Kind(Box<str>),
}

impl std::fmt::Display for RecordRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Who => f.write_str("auth: the caller set is empty or mixes callers that cannot share a route"),
            Self::OpenRouteCarriesScopeOrMoney => f.write_str(
                "scope, money: a public, optional or signed-ingress route must state scope none and money none",
            ),
            Self::Catalog => f.write_str(
                "class: a catalog route must walk a scope kind, move no money, and its plane must implement render",
            ),
            Self::SelectedWithoutSelector => {
                f.write_str("scope: selected kinds need the plane's select_resources")
            }
            Self::WalkWithoutUpstream => f.write_str("scope: a walk kind needs the plane's upstream"),
            Self::ScopeNotStated => f.write_str("scope: not stated (name a kind, or say none)"),
            Self::MoneyWithoutPrincipal => {
                f.write_str("money: a unit needs every caller of the route to yield a principal")
            }
            Self::OperatorAdmin => {
                f.write_str("auth, class: operator callers and the admin class go together, alone")
            }
            Self::AdminCarriesScopeOrMoney => {
                f.write_str("scope, money: an admin route states scope none and money none")
            }
            Self::UpgradeMethods => f.write_str("methods: an upgrade route is GET only"),
            Self::InternalAuth => f.write_str("auth: a line or recovery route is principal-only"),
            Self::CredHeader => {
                f.write_str("credential header: the route reads no credential a header could carry")
            }
            Self::Challenge => f.write_str(
                "challenge: the route never answers 401, or the text is not a header value",
            ),
            Self::DistinctWithoutCaller => {
                f.write_str("caller state: distinct needs a route that identifies its caller")
            }
            Self::Kind(kind) => write!(f, "scope: kind {kind:?} is repeated or not a plain name"),
        }
    }
}

impl std::error::Error for RecordRefused {}

fn plain_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// A header value core may send: visible ASCII and spaces, no control byte (so no line break).
fn header_value(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| (0x20..0x7f).contains(&byte))
}

impl RouteRecord {
    /// The rules the loader enforces. A violation refuses the plugin, naming the route.
    pub fn validate(&self, methods: u32, plane: PlaneMethods) -> Result<(), RecordRefused> {
        let who = self.who;
        // Who: members that stand alone, and the one pair that shares a route (a key or a ticket).
        let alone = [
            Who::PUBLIC,
            Who::OPTIONAL,
            Who::SIGNED_INGRESS,
            Who::OPERATOR,
        ];
        if who.mask() == 0
            || alone
                .iter()
                .any(|member| who.has(*member) && !who.is(*member))
        {
            return Err(RecordRefused::Who);
        }
        // Scope: stated, each kind a plain name, none twice.
        if self.scope.is_none() && !self.scope_stated {
            return Err(RecordRefused::ScopeNotStated);
        }
        let mut seen: Vec<&str> = Vec::new();
        for kind in self.scope.kinds() {
            if !plain_kind(kind) || seen.contains(&kind) {
                return Err(RecordRefused::Kind(kind.into()));
            }
            seen.push(kind);
        }
        // Operator and admin go together, alone, and carry neither scope kind nor money.
        if who.has(Who::OPERATOR) != (self.class == RouteClass::Admin) {
            return Err(RecordRefused::OperatorAdmin);
        }
        if self.class == RouteClass::Admin && (!self.scope.is_none() || self.money == Money::Unit) {
            return Err(RecordRefused::AdminCarriesScopeOrMoney);
        }
        // A route that names no principal has nothing to judge and nobody to charge.
        if (who.is(Who::PUBLIC) || who.is(Who::OPTIONAL) || who.is(Who::SIGNED_INGRESS))
            && (!self.scope.is_none() || self.money == Money::Unit)
        {
            return Err(RecordRefused::OpenRouteCarriesScopeOrMoney);
        }
        if self.class == RouteClass::Catalog
            && (self.scope.walk.is_none()
                || !self.scope.selected.is_empty()
                || self.money == Money::Unit
                || !plane.render
                || !who.is(Who::PRINCIPAL))
        {
            return Err(RecordRefused::Catalog);
        }
        if !self.scope.selected.is_empty() && !plane.select_resources {
            return Err(RecordRefused::SelectedWithoutSelector);
        }
        if self.scope.walk.is_some() && !plane.upstream {
            return Err(RecordRefused::WalkWithoutUpstream);
        }
        if self.money == Money::Unit && !who.yields_principal() {
            return Err(RecordRefused::MoneyWithoutPrincipal);
        }
        if self.class == RouteClass::Upgrade && methods != METHOD_GET {
            return Err(RecordRefused::UpgradeMethods);
        }
        if matches!(self.class, RouteClass::Line | RouteClass::Recovery) && !who.is(Who::PRINCIPAL)
        {
            return Err(RecordRefused::InternalAuth);
        }
        if self.cred_header.is_some()
            && !(who.has(Who::PRINCIPAL) || who.is(Who::SIGNED_INGRESS) || who.is(Who::OPTIONAL))
        {
            return Err(RecordRefused::CredHeader);
        }
        if let Some(header) = &self.cred_header {
            if header.is_empty()
                || !header
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(RecordRefused::CredHeader);
            }
        }
        if let Some(challenge) = &self.challenge {
            if !who.can_challenge()
                || !header_value(challenge)
                || challenge.matches(CHALLENGE_PUBLIC_URL).count() > 1
            {
                return Err(RecordRefused::Challenge);
            }
        }
        if self.caller_state == CallerState::Distinct
            && (who.is(Who::PUBLIC) || who.is(Who::SIGNED_INGRESS))
        {
            return Err(RecordRefused::DistinctWithoutCaller);
        }
        Ok(())
    }

    /// The challenge core sends on this route's 401, with the plane instance's public URL written
    /// in. `Err` when the text asks for a public URL the operator did not configure: that route
    /// is not mounted (the operator's configuration does not meet its need).
    pub fn mounted_challenge(
        &self,
        public_url: Option<&str>,
    ) -> Result<Option<Box<str>>, NoPublicUrl> {
        let Some(challenge) = &self.challenge else {
            return Ok(None);
        };
        if !challenge.contains(CHALLENGE_PUBLIC_URL) {
            return Ok(Some(challenge.clone()));
        }
        let url = public_url.ok_or(NoPublicUrl)?.trim_end_matches('/');
        let text = challenge.replacen(CHALLENGE_PUBLIC_URL, url, 1);
        if header_value(&text) {
            Ok(Some(text.into_boxed_str()))
        } else {
            Err(NoPublicUrl)
        }
    }

    /// The record a plane image built before the route record states, read from what it does
    /// declare: its flags, its auth mask and resource kinds, and whether its seat walks core's
    /// catalog. It is the 1.6 pre-record meaning, written down once: a principal data route with
    /// resource kinds selects them; one on a seat with a catalog walks `pool`; a principal route
    /// moves money; nothing keeps per-caller state unless the plane says so (`distinct`).
    /// Removed with the last image that predates the record.
    pub fn from_declared(
        flags: u32,
        auth: u32,
        cred_header: Option<&str>,
        resource_kinds: &[Box<str>],
        walk_kind: Option<&str>,
        distinct: bool,
    ) -> Option<Self> {
        let class = RouteClass::from_flags(flags)?;
        let who = Who::from_mask(auth)?;
        let principal = who.yields_principal();
        let scope = match class {
            RouteClass::Admin => Scope::none(),
            RouteClass::Catalog => Scope::walk(walk_kind.unwrap_or(KIND_POOL)),
            RouteClass::Data | RouteClass::Upgrade | RouteClass::Line | RouteClass::Recovery
                if principal =>
            {
                Scope {
                    walk: walk_kind.map(Box::from),
                    selected: resource_kinds.iter().cloned().collect(),
                }
            }
            RouteClass::Data | RouteClass::Upgrade | RouteClass::Line | RouteClass::Recovery => {
                Scope::none()
            }
        };
        let money = match class {
            RouteClass::Catalog | RouteClass::Admin => Money::None,
            RouteClass::Data | RouteClass::Upgrade | RouteClass::Line | RouteClass::Recovery => {
                if principal {
                    Money::Unit
                } else {
                    Money::None
                }
            }
        };
        Some(Self {
            class,
            who,
            cred_header: cred_header.map(|header| header.to_ascii_lowercase().into_boxed_str()),
            challenge: None,
            scope,
            scope_stated: true,
            money,
            caller_state: if distinct && principal {
                CallerState::Distinct
            } else {
                CallerState::Shared
            },
        })
    }
}

/// One plane image's claim on scope kinds, for the rule that a kind other than `pool` belongs to
/// the one image that declares it.
pub struct KindClaim<'a> {
    pub image: &'a str,
    pub kinds: &'a [Box<str>],
}

/// The first kind two images both declare, with the two images. `pool` is core's and any image
/// may walk it.
pub fn contested_kind<'a>(claims: &[KindClaim<'a>]) -> Option<(&'a str, &'a str, &'a str)> {
    for (index, first) in claims.iter().enumerate() {
        for second in &claims[index + 1..] {
            if first.image == second.image {
                continue;
            }
            for kind in first.kinds {
                if &**kind != KIND_POOL && second.kinds.iter().any(|other| other == kind) {
                    return Some((&**kind, first.image, second.image));
                }
            }
        }
    }
    None
}

/// The route record on the wire: two describe items of the plane kind beside `D_ROUTE`,
/// `D_ROUTE_CRED_HEADER` and `D_ROUTE_RESOURCES`. A plane image that declares neither for a route
/// predates the record and is read by [`RouteRecord::from_declared`]; an image that declares the
/// admission item for one route must declare it for every route (the loader's rule), and from
/// then on nothing about that image is inferred.
pub mod wire {
    /// `D_ROUTE_ADMISSION`: 16 bytes (four little-endian words: route, scope, money, callers),
    /// then the walk kind as text (empty when the scope has no walk).
    pub const D_ROUTE_ADMISSION: u16 = 0x019A;
    /// `D_ROUTE_CHALLENGE`: 8 bytes (route, zero), then the challenge text.
    pub const D_ROUTE_CHALLENGE: u16 = 0x019B;

    /// The scope word: exactly `SCOPE_NONE`, or one or both of the others. `SCOPE_SELECTED`: the
    /// kinds are the route's `D_ROUTE_RESOURCES`.
    pub const SCOPE_NONE: u32 = 1;
    pub const SCOPE_WALK: u32 = 2;
    pub const SCOPE_SELECTED: u32 = 4;
    pub const MONEY_NONE: u32 = 1;
    pub const MONEY_UNIT: u32 = 2;
    pub const CALLERS_SHARED: u32 = 1;
    pub const CALLERS_DISTINCT: u32 = 2;

    /// The fixed part of a `D_ROUTE_ADMISSION` body.
    pub const ADMISSION_FIXED: usize = 16;

    /// A decoded `D_ROUTE_ADMISSION` body.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AdmissionItem<'a> {
        pub route: u32,
        pub scope: u32,
        pub money: u32,
        pub callers: u32,
        pub walk_kind: &'a str,
    }

    fn word(body: &[u8], index: usize) -> Option<u32> {
        let bytes = body.get(index * 4..index * 4 + 4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// `None`: the body is short or its tail is not text.
    pub fn decode_admission(body: &[u8]) -> Option<AdmissionItem<'_>> {
        Some(AdmissionItem {
            route: word(body, 0)?,
            scope: word(body, 1)?,
            money: word(body, 2)?,
            callers: word(body, 3)?,
            walk_kind: std::str::from_utf8(body.get(ADMISSION_FIXED..)?).ok()?,
        })
    }

    /// The body of a `D_ROUTE_ADMISSION` item.
    pub fn encode_admission(item: &AdmissionItem<'_>) -> Vec<u8> {
        let mut body = Vec::with_capacity(ADMISSION_FIXED + item.walk_kind.len());
        for word in [item.route, item.scope, item.money, item.callers] {
            body.extend_from_slice(&word.to_le_bytes());
        }
        body.extend_from_slice(item.walk_kind.as_bytes());
        body
    }
}

impl RouteRecord {
    /// The record of a route whose image declares its admission item. Every field is read from
    /// what the image stated; a word outside its vocabulary, a walk kind without the walk bit or
    /// the bit without a kind, and selected without kinds are `None` (the loader refuses the
    /// image, naming the route). The result still passes through [`RouteRecord::validate`].
    pub fn from_wire(
        flags: u32,
        auth: u32,
        cred_header: Option<&str>,
        resource_kinds: &[Box<str>],
        admission: &wire::AdmissionItem<'_>,
        challenge: Option<&str>,
    ) -> Option<Self> {
        let class = RouteClass::from_flags(flags)?;
        let who = Who::from_mask(auth)?;
        let walks = admission.scope & wire::SCOPE_WALK != 0;
        let selects = admission.scope & wire::SCOPE_SELECTED != 0;
        let none = admission.scope == wire::SCOPE_NONE;
        if admission.scope == 0
            || admission.scope & !(wire::SCOPE_NONE | wire::SCOPE_WALK | wire::SCOPE_SELECTED) != 0
            || (admission.scope & wire::SCOPE_NONE != 0 && !none)
            || walks == admission.walk_kind.is_empty()
            || selects == resource_kinds.is_empty()
        {
            return None;
        }
        let money = match admission.money {
            wire::MONEY_NONE => Money::None,
            wire::MONEY_UNIT => Money::Unit,
            _ => return None,
        };
        let caller_state = match admission.callers {
            wire::CALLERS_SHARED => CallerState::Shared,
            wire::CALLERS_DISTINCT => CallerState::Distinct,
            _ => return None,
        };
        Some(Self {
            class,
            who,
            cred_header: cred_header.map(|header| header.to_ascii_lowercase().into_boxed_str()),
            challenge: challenge.map(Box::from),
            scope: Scope {
                walk: walks.then(|| Box::from(admission.walk_kind)),
                selected: if selects {
                    resource_kinds.iter().cloned().collect()
                } else {
                    Arc::from(Vec::new())
                },
            },
            scope_stated: true,
            money,
            caller_state,
        })
    }
}

impl RouteRecord {
    /// This record as the admission item a plane would state for it: the inverse of
    /// [`RouteRecord::from_wire`], used by the reference plane so both sides of the wire are
    /// proved against each other without a plane image.
    pub fn admission_item(&self, route: u32) -> wire::AdmissionItem<'_> {
        let mut scope = 0;
        if self.scope.walk.is_some() {
            scope |= wire::SCOPE_WALK;
        }
        if !self.scope.selected.is_empty() {
            scope |= wire::SCOPE_SELECTED;
        }
        if scope == 0 {
            scope = wire::SCOPE_NONE;
        }
        wire::AdmissionItem {
            route,
            scope,
            money: match self.money {
                Money::None => wire::MONEY_NONE,
                Money::Unit => wire::MONEY_UNIT,
            },
            callers: match self.caller_state {
                CallerState::Shared => wire::CALLERS_SHARED,
                CallerState::Distinct => wire::CALLERS_DISTINCT,
            },
            walk_kind: self.scope.walk.as_deref().unwrap_or(""),
        }
    }
}

/// The one kind a seat's walk judges a key under: the walk kind its routes' records state. Every
/// route of one plane instance that walks hands core's walk names from one name space, so they
/// state one kind; `Err` names two that differ (the loader refuses the image). `Ok(None)`: no
/// route of the seat walks, and the walk judges nothing by kind (only an unrestricted key passes
/// a walk such a seat should never start).
///
/// This replaces root's inference of `pool` from a seat carrying a catalog: the plane says it.
pub fn seat_walk_kind<'a>(
    records: impl IntoIterator<Item = &'a RouteRecord>,
) -> Result<Option<&'a str>, (&'a str, &'a str)> {
    let mut found: Option<&'a str> = None;
    for record in records {
        let Some(kind) = record.scope.walk.as_deref() else {
            continue;
        };
        match found {
            None => found = Some(kind),
            Some(first) if first == kind => {}
            Some(first) => return Err((first, kind)),
        }
    }
    Ok(found)
}
