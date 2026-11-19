// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native DATA authorization retains the original physical request, selected resources and
//! real verification. Registration and monetary admission cannot reconstruct this proof.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use busbar_contract::records::VirtualKey;
use busbar_contract::services::Caller;
use busbar_plugin_abi::plane::AUTH_PRINCIPAL;
use busbar_ports::CallCx;

use super::admission_table::{admission_of, Admission, NotMounted, Offered, Policy, Verified};
use super::native_chain::{NativeChain, NativePreparedAnswer, PreparedNativeIdentity};
use super::route_record::{CallerState, Money, RouteRecord};
use crate::host_services::{InvocationContext, ServingGeneration};
use crate::inbound::native::{
    AuthorizedPhysicalData, DataPreparation, DataPreparationDenied, DataPreparationSuccess,
    PhysicalExecutionOwner, RequestBinding, RouteBinding, RouteTarget,
};
use crate::plane_driver::port::PortSeat;
use crate::plane_driver::port_admission::{AdmittedUnit, Pending};
use crate::plane_driver::port_routes::Mounted;
use crate::plane_driver::request_admission::{
    AdmittedRequest, RequestAllocation, RequestPoolReceipt, RequestRoutes,
};
use crate::refusal::ClientRefusal;
use crate::resource_admission::{ResourceInventory, SelectedResources};
use crate::state::{AdmissionLease, App};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataRefused {
    Unsupported,
    Binding,
    Cancelled,
    Capacity,
    Credential,
    Policy,
    /// The key is disabled (refusal row 3): a verified caller, refused 403.
    Disabled,
    /// The request's body ran past the cap (refusal row 6): 413, to a verified caller.
    TooLarge,
    /// The request carried trailers (refusal row 8): 400, to a verified caller.
    Trailers,
    /// The key does not hold what the request selected (refusal row 10): 403.
    Scope,
    Replay,
    Unit,
    Unavailable,
}

impl DataRefused {
    /// The row of the refusal table this reason is answered by; `None` for a reason that is the
    /// engine's own fault or the request's end (no answer exists to write: the request is
    /// cancelled). `presented`: a credential carrier of the route was on the head.
    pub fn refusal(self, presented: bool) -> Option<super::admission_table::Refusal> {
        use super::admission_table::Refusal;
        match self {
            Self::Credential | Self::Policy => Some(Refusal::Unverified { presented }),
            Self::Disabled => Some(Refusal::KeyDisabled),
            Self::Scope => Some(Refusal::ScopeDenied),
            Self::TooLarge => Some(Refusal::BodyTooLarge),
            Self::Trailers => Some(Refusal::Trailers),
            Self::Replay => Some(Refusal::Replayed),
            // A verifier that could not answer is not a denial: 503, never 401 (row 2a).
            Self::Unavailable => Some(Refusal::VerifierUnavailable),
            Self::Unsupported | Self::Binding | Self::Cancelled | Self::Capacity | Self::Unit => {
                None
            }
        }
    }

    /// The caller was verified before this refusal, so its plane may render the answer.
    pub fn after_verification(self) -> bool {
        matches!(
            self,
            Self::Disabled | Self::Scope | Self::TooLarge | Self::Trailers
        )
    }
}

/// Actual immutable candidate owners. Root assembles these; none is a plugin proof.
pub struct DataRouteOwners {
    pub generation: Arc<ServingGeneration>,
    /// The configured resources a selecting route selects from; `None` for a route that selects
    /// none (it declares no resource kinds).
    pub inventory: Option<Arc<ResourceInventory>>,
    pub chain: Arc<NativeChain>,
    pub keys: Arc<crate::door::UnitKeyMint>,
    pub routes: Arc<RequestRoutes>,
}

/// One canonical physical route and its candidate's actual native owners. No App Arc cycle.
pub struct NativeDataRoute {
    binding: Arc<RouteBinding>,
    caller: Caller,
    owners: DataRouteOwners,
    cost: Arc<crate::cost::CostModel>,
    /// The carriers every request on this route withholds from the plane ([`withheld_carriers`]).
    withheld: Arc<[Box<str>]>,
    /// The audience the route's plane is bound to (its `canonical_uri`): a bearer that states an
    /// audience must state this one.
    audience: Option<Arc<str>>,
    challenge: Option<Box<str>>,
    record: RouteRecord,
    admission: Admission,
}

/// How the listener plan mounts one declared route ([`NativeDataRoute::planned`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Planned {
    /// Bind a [`NativeDataRoute`] with the route's chain: the listener verifies, then serves by
    /// the route's admission (with a unit, or verified and not billed).
    Data,
    /// Bind a `NativeUpgradeRoute` with the route's chain.
    Upgrade,
    /// Mount with no completion: the route's record admits nobody in particular.
    Public,
    /// The admin plan's: not a data listener's route.
    Admin,
    /// Not mounted, for a reason that is the operator's configuration.
    NotMounted(NotMounted),
    /// The image's declaration is unusable (the loader refuses such an image).
    Unusable(&'static str),
}

const OTHER_PATH_PUBLIC: &str = "a public route is served by the listener's public class";
const OTHER_PATH_TICKET: &str = "a ticket route is served by the listener's ticket class";
const OTHER_PATH_SIGNED: &str = "a signed route is served by the listener's signed-ingress class";
const OTHER_PATH_UPGRADE: &str = "an upgrade route is served by the native upgrade path";
const OTHER_PATH_OPERATOR: &str = "an admin route is served by the admin door";

impl NativeDataRoute {
    /// The actual inventory this canonical route selects from after verification
    /// ([`PendingData::select`]); `None` when it selects nothing. A reconstructed inventory with
    /// equal entries is not the same authorization owner.
    pub fn inventory(&self) -> Option<&Arc<ResourceInventory>> {
        self.owners.inventory.as_ref()
    }

    /// Whether this route's plane selects resources for each request (it declares resource kinds,
    /// and binding retained their inventory). A route that selects none is admitted through the
    /// plane's own `request`: the key's grant of the pool or model it names is judged in the
    /// request walk, and money is admitted there.
    pub fn selects(&self) -> bool {
        self.owners.inventory.is_some()
    }

    /// The record of `mounted` on `seat`: the record its image declared, read once here.
    ///
    /// An image built before the route record states its four fields is read by what it does
    /// declare ([`RouteRecord::from_declared`]): the walk kind is the seat's own stated scope
    /// kind, and a plane bound to an audience (its `canonical_uri`) keeps a session per caller.
    pub fn record_of(seat: &PortSeat, mounted: &Mounted) -> Option<RouteRecord> {
        // A record the image stated wins, whole: nothing about that route is inferred. The
        // loader decoded it with `RouteRecord::from_wire` and validated it before the route
        // was mounted.
        if let Some(stated) = &mounted.record {
            return Some(stated.clone());
        }
        RouteRecord::from_declared(
            mounted.flags,
            mounted.auth,
            mounted.cred_header.as_deref(),
            &mounted.resource_kinds,
            seat.request_routes.scope_kind(),
            seat.audience.is_some(),
        )
    }

    /// The admission of `mounted` on `seat` under this configuration, or why the route is not
    /// mounted. Every reason is the operator's configuration (design C6); a route's class is never
    /// one. `Err(None)`: the image's declaration names no class or no caller (the loader refuses
    /// that image; reaching here with one is the engine's fault and the route is not served).
    pub fn admission(
        seat: &PortSeat,
        mounted: &Mounted,
        chain: &NativeChain,
        offered: Offered,
    ) -> Result<(RouteRecord, Admission), Option<NotMounted>> {
        let record = Self::record_of(seat, mounted).ok_or(None)?;
        let offered = Offered {
            chain_yields_shared: chain.admits_anonymous(),
            ..offered
        };
        let admission = super::admission_table::mounted(&record, offered).map_err(Some)?;
        Ok((record, admission))
    }

    /// How the listener plan mounts `mounted` on `seat`: the one decision the plan makes about a
    /// declared route. `chain`: the chain the route would be judged by (its own instances where
    /// it declares a credential header, else the data chain), `None` when no configured instance
    /// reads its credential. Every route is mounted by its admission or left unmounted for a
    /// reason that is the operator's configuration, logged once and listed by the admin API.
    pub fn planned(
        seat: &PortSeat,
        mounted: &Mounted,
        chain: Option<&NativeChain>,
        upgrade_transport: bool,
        signature_verifier: bool,
    ) -> Planned {
        let Some(record) = Self::record_of(seat, mounted) else {
            return Planned::Unusable("the route's declaration names no class or no caller");
        };
        let offered = Offered {
            verifier_reads_header: chain.is_some(),
            chain_yields_shared: chain.is_some_and(NativeChain::admits_anonymous),
            upgrade_transport,
            signature_verifier,
            challenge_unresolved: record.mounted_challenge(seat.public_url()).is_err(),
        };
        match super::admission_table::mounted(&record, offered) {
            Err(why) => Planned::NotMounted(why),
            Ok(
                Admission::Walk
                | Admission::Selected
                | Admission::PrincipalOnly
                | Admission::Catalog
                | Admission::Optional,
            ) => Planned::Data,
            Ok(Admission::Upgrade) => Planned::Upgrade,
            Ok(Admission::Public) => Planned::Public,
            // A plane's admin routes are mounted on the admin door by the admin plan.
            Ok(Admission::Operator) => Planned::Admin,
            // No native verifier exists for a ticket or a sender's signature: such a route is
            // left unmounted and says so, until its verifier is linked.
            Ok(Admission::Ticket) => Planned::NotMounted(NotMounted::NoVerifierReadsItsHeader),
            Ok(Admission::SignedIngress) => Planned::NotMounted(NotMounted::NoSignatureVerifier),
            Ok(Admission::Internal) => Planned::NotMounted(NotMounted::Internal),
        }
    }

    /// Whether this path can admit `mounted` on `seat` at all, before any owner exists: the
    /// route-shape half of [`Self::bind`]. Err names what it lacks. A route this path cannot admit
    /// is never served unadmitted: the listener leaves it unmounted.
    ///
    /// This path owns every admission whose caller the route's chain verifies: a walk, a
    /// selection, a principal-only route, a catalog, and an optional route's request that presents
    /// a credential. A plane bound to an audience is served: a bearer that states an audience is
    /// judged on the head ([`refuse_foreign_audience`]). A deployment with `oauth_as` is served
    /// for every credential its chain's instances verify; a token core itself minted is still
    /// refused by [`refuse_bound_carriers`] until core's own token verifier is a chain member
    /// (it must not be accepted unverified). A route with hooks is served: its hooks run inside
    /// the admitted session (`PortDriver::serve_inner` binds them).
    pub fn admits(_app: &App, seat: &PortSeat, mounted: &Mounted) -> Result<(), &'static str> {
        let Some(record) = Self::record_of(seat, mounted) else {
            return Err("the route's declaration names no class or no caller");
        };
        match admission_of(&record) {
            Admission::Walk
            | Admission::Selected
            | Admission::PrincipalOnly
            | Admission::Catalog
            | Admission::Optional => {}
            Admission::Public => return Err(OTHER_PATH_PUBLIC),
            Admission::Ticket => return Err(OTHER_PATH_TICKET),
            Admission::SignedIngress => return Err(OTHER_PATH_SIGNED),
            Admission::Upgrade => return Err(OTHER_PATH_UPGRADE),
            Admission::Operator => return Err(OTHER_PATH_OPERATOR),
            Admission::Internal => return Err("an internal route is not on a listener"),
        }
        if mounted.effective != mounted.auth {
            return Err("the operator's auth choice for this route is not the route's own");
        }
        // A route that declares resource kinds is admitted only through its plane's selection;
        // a route that declares none is admitted through the plane's `request` (no selection).
        if !record.scope.selected.is_empty()
            && seat.driver.port().facts() & busbar_plugin_abi::plane::FB_RESOURCE_ADMISSION == 0
        {
            return Err("the route declares resource kinds its plane does not select");
        }
        Ok(())
    }

    pub fn bind(
        app: &App,
        seat: &PortSeat,
        binding: Arc<RouteBinding>,
        owners: DataRouteOwners,
    ) -> Result<Arc<Self>, DataRefused> {
        let RouteTarget::Plane(target) = binding.target() else {
            return Err(DataRefused::Unsupported);
        };
        let mounted = target.mounted();
        if Self::admits(app, seat, mounted).is_err() || !owners.chain.is_data() {
            return Err(DataRefused::Unsupported);
        }
        let Some(record) = Self::record_of(seat, mounted) else {
            return Err(DataRefused::Unsupported);
        };
        // A route that keeps state per caller is never bound under a chain whose callers share
        // one subject: the plan leaves it unmounted, and a plan that did not is refused here.
        if record.caller_state == CallerState::Distinct && owners.chain.admits_anonymous() {
            return Err(DataRefused::Unsupported);
        }
        if !seat.driver.caller().same_incarnation(target.caller())
            || !Arc::ptr_eq(seat.driver.core(), owners.generation.core())
            || !seat
                .driver
                .routes()
                .data
                .iter()
                .any(|route| route == mounted)
            // A route selects exactly when it declares resource kinds, from its own inventory.
            || mounted.resource_kinds.is_empty() != owners.inventory.is_none()
            || owners.inventory.as_ref().is_some_and(|inventory| {
                inventory.instance() != target.caller().incarnation()
                    || inventory.epoch() != owners.chain.epoch()
            })
            || !owners.chain.matches_names(target.auth_instances())
        {
            return Err(DataRefused::Binding);
        }
        let withheld = withheld_carriers(&owners.chain, mounted.cred_header.as_deref());
        let admission = admission_of(&record);
        Ok(Arc::new(Self {
            caller: target.caller().clone(),
            binding,
            owners,
            cost: Arc::clone(&app.cost),
            withheld,
            audience: seat.audience.as_deref().map(Arc::from),
            // A challenge that names a public URL the operator did not configure is a route the
            // plan leaves unmounted (`NotMounted::NoPublicUrlForItsChallenge`); bound anyway, it
            // answers with core's generic challenge.
            challenge: record.mounted_challenge(seat.public_url()).unwrap_or(None),
            record,
            admission,
        }))
    }

    /// The route token this completion was bound to.
    pub fn binding(&self) -> &Arc<RouteBinding> {
        &self.binding
    }

    /// The route's record, as bound.
    pub fn record(&self) -> &RouteRecord {
        &self.record
    }

    /// The `WWW-Authenticate` text of this route's 401: its record's challenge with the plane
    /// instance's public URL written in at bind, or `None` for core's generic one.
    pub fn challenge(&self) -> Option<&str> {
        self.challenge.as_deref()
    }

    /// The route's admission, as bound.
    pub fn route_admission(&self) -> Admission {
        self.admission
    }

    /// Whether a served request on this route opens a unit. A route that does not is answered by
    /// the "verified, not billed" authority ([`DataAuthorization`] completed with no allocation).
    pub fn billed(&self) -> bool {
        self.record.money == Money::Unit
    }

    /// The carriers every request on this route withholds from the plane.
    pub fn withheld(&self) -> &Arc<[Box<str>]> {
        &self.withheld
    }

    /// Consumes the original physical preparation latch, then verifies the credential. Nothing of
    /// the request is lent to the plane here: only a verified [`PendingData`] lends it, for
    /// selection ([`PendingData::lend_selection`]). Root retains the completion owner for the
    /// exact authorization or denied result.
    pub async fn prepare(
        self: &Arc<Self>,
        preparation: DataPreparation,
        cx: CallCx,
    ) -> Result<PendingData, DataPreparationFailed> {
        let binding = preparation.binding().clone();
        let result = async {
            // One reading for this step's two deadlines: the binding's own and the call's. No lock
            // and no await sits between the reading and the second check.
            let live_at = binding
                .check_live_now()
                .map_err(|_| DataRefused::Cancelled)?;
            if !Arc::ptr_eq(binding.route(), &self.binding)
                || cx.request_id != binding.invocation().request_id().get()
                || binding.deadline().is_some_and(|at| cx.deadline > at)
                || live_at >= cx.deadline
            {
                return Err(DataRefused::Binding);
            }
            let snapshot = binding.snapshot().map_err(|_| DataRefused::Capacity)?;
            if !snapshot.request().same_request(binding.request()) {
                return Err(DataRefused::Binding);
            }
            let cred_header = match self.binding.target() {
                RouteTarget::Plane(route) => route.mounted().cred_header.as_deref(),
                RouteTarget::Core(_) | RouteTarget::Unrouted => None,
            };
            refuse_bound_carriers(&snapshot, &self.owners.chain, cred_header)?;
            if let Some(audience) = self.audience.as_deref() {
                refuse_foreign_audience(&snapshot, &self.owners.chain, audience)?;
            }
            let prepared = self
                .owners
                .chain
                .prepare_snapshot(cx, snapshot)
                .await
                .map_err(|_| DataRefused::Unavailable)?;
            binding.check_live().map_err(|_| DataRefused::Cancelled)?;
            let NativePreparedAnswer::Identity(prepared) = prepared else {
                return Err(DataRefused::Credential);
            };
            Ok(prepared)
        }
        .await;
        match result {
            Ok(prepared) => Ok(PendingData {
                preparation,
                route: self.clone(),
                selected: None,
                prepared,
                deadline: cx.deadline,
            }),
            Err(reason) => Err(preparation_failed(
                preparation,
                self.clone(),
                None,
                None,
                reason,
            )),
        }
    }
}

/// The governed key a verified identity is admitted as, valid at `now` (enabled, not deleted, not
/// expired): the key the identity's provider and groups earn through the role bindings. The
/// principal `anonymous` earns its key the same way, from `role_bindings.anonymous`: it has no
/// built-in key, so an open relay reaches what its binding grants and is limited by the group its
/// binding names. No binding, no key: the caller is not verified. DATA and the upgrade route both
/// use it.
pub(crate) fn governed_key(
    app: &App,
    prepared: &PreparedNativeIdentity,
    chain: &NativeChain,
    now: u64,
) -> Result<Arc<VirtualKey>, DataRefused> {
    // The anonymous principal exists only on a chain that names `anonymous`.
    if prepared.is_anonymous() && !chain.admits_anonymous() {
        return Err(DataRefused::Binding);
    }
    let identity = prepared.identity();
    // The provider of the anonymous principal is the member that named it: `anonymous`, so its
    // binding is `role_bindings.anonymous`.
    let (_, gov) = super::resolve_identity_from_bindings(
        &app.role_bindings,
        super::ChainVerdict::Identified {
            module: prepared.provider_text(),
            principal: super::Principal {
                id: identity.subject().to_owned(),
                name: None,
                roles: identity.groups().map(str::to_owned).collect(),
                ttl_secs: identity.cache_s().map(u64::from),
            },
            resolved: None,
            signed_authority: None,
        },
    )
    .map_err(|_| DataRefused::Policy)?;
    let resolved = gov.key.ok_or(DataRefused::Policy)?;
    // Deleted or past its stored expiry: the identity earns no key, so the caller is not verified
    // (the one 401). Disabled: a verified caller whose key the operator switched off (403).
    if resolved.deleted_at.is_some() || resolved.expires_at.is_some_and(|until| now >= until) {
        return Err(DataRefused::Policy);
    }
    if !resolved.enabled {
        return Err(DataRefused::Disabled);
    }
    Ok(resolved)
}

/// The audience check of a plane bound to one (MCP's `canonical_uri`, RFC 8707), on the head and
/// before any verifier runs: a bearer that states an audience must state this plane's. A JWT
/// minted for another resource, or for none, is refused as any bad credential is. A token core
/// minted is judged by its verifier, which has the signature and the claims. A credential that is
/// not a JWT (a gateway key) states no audience: the chain alone judges it. Every occurrence of
/// `authorization` is scanned, not a decoy first bearer.
pub(crate) fn refuse_foreign_audience(
    snapshot: &crate::inbound::request_snapshot::ChargedRequestSnapshot,
    chain: &NativeChain,
    audience: &str,
) -> Result<(), DataRefused> {
    // An open chain reads no credential, so there is none to bind.
    if chain.is_open() {
        return Ok(());
    }
    snapshot
        .with_auth_input(|request| {
            for field in request.headers {
                if !field.name.get().eq_ignore_ascii_case("authorization") {
                    continue;
                }
                let Ok(value) = std::str::from_utf8(field.value.get()) else {
                    continue;
                };
                let Some((scheme, token)) = value.split_once(' ') else {
                    continue;
                };
                if !scheme.eq_ignore_ascii_case("Bearer") {
                    continue;
                }
                match super::audience::inspect_bearer(token.trim(), audience) {
                    super::audience::Binding::Mismatch => return Err(DataRefused::Credential),
                    super::audience::Binding::Bound
                    | super::audience::Binding::Deferred
                    | super::audience::Binding::Opaque => {}
                }
            }
            Ok(())
        })
        .map_err(|_| DataRefused::Capacity)?
}

/// The credential carriers a native route is judged on, lowercase and once each: `authorization` (the
/// bearer the scan below reads), every D_CRED_HEADER its chain's instances declare, and the route's own
/// D_ROUTE_CRED_HEADER. Built once when the route is bound and kept by the route's completion (released
/// with its slot); every request on the route withholds exactly these from the plane.
pub fn withheld_carriers(chain: &NativeChain, cred_header: Option<&str>) -> Arc<[Box<str>]> {
    let mut carriers: Vec<Box<str>> = Vec::new();
    for name in std::iter::once("authorization")
        .chain(chain.carriers())
        .chain(cred_header)
    {
        if !carriers
            .iter()
            .any(|known| known.eq_ignore_ascii_case(name))
        {
            carriers.push(name.to_ascii_lowercase().into_boxed_str());
        }
    }
    carriers.into()
}

/// The restrictive scan of every credential carrier a native route reads (`authorization`, the
/// chain's own headers and the route's `D_ROUTE_CRED_HEADER`), before any verifier runs: a
/// DPoP-bound or core-signed token is refused on these routes. Every occurrence is scanned, not a
/// decoy first bearer. DATA and the upgrade route run this same scan.
pub(crate) fn refuse_bound_carriers(
    snapshot: &crate::inbound::request_snapshot::ChargedRequestSnapshot,
    chain: &NativeChain,
    cred_header: Option<&str>,
) -> Result<(), DataRefused> {
    // The open relay (`anonymous` alone) reads no credential, so no carrier is judged.
    if chain.is_open() {
        return Ok(());
    }
    snapshot
        .with_auth_input(|request| {
            for field in request.headers {
                let name = field.name.get();
                let Ok(value) = std::str::from_utf8(field.value.get()) else {
                    continue;
                };
                let token = if name.eq_ignore_ascii_case("authorization") {
                    let Some((scheme, token)) = value.split_once(' ') else {
                        continue;
                    };
                    if scheme.eq_ignore_ascii_case("DPoP") {
                        return Err(DataRefused::Credential);
                    }
                    if !scheme.eq_ignore_ascii_case("Bearer") {
                        continue;
                    }
                    token.trim()
                } else if chain.reads_header(name)
                    || cred_header.is_some_and(|header| header.eq_ignore_ascii_case(name))
                {
                    value
                } else {
                    continue;
                };
                if super::dpop::is_dpop_bound(token)
                    || token.starts_with(crate::governance::signing::TOKEN_PREFIX)
                {
                    return Err(DataRefused::Credential);
                }
            }
            Ok(())
        })
        .map_err(|_| DataRefused::Capacity)?
}

/// A request whose credential verified, before key policy and its replay claim.
pub struct PendingData {
    preparation: DataPreparation,
    route: Arc<NativeDataRoute>,
    selected: Option<Arc<SelectedResources>>,
    prepared: Arc<PreparedNativeIdentity>,
    deadline: Instant,
}
impl PendingData {
    /// Lend the verified request to its plane's resource selector and keep what it selected:
    /// the only lending before the plane's `request`, and only after the credential verified.
    /// `selector` is lent the frozen request and the carriers it must withhold
    /// ([`crate::resource_admission::select_resources`]). A route that selects nothing is
    /// refused here: it is admitted with no selection.
    pub fn select(
        mut self,
        selector: impl FnOnce(
            &crate::resource_admission::FrozenRequest,
            &[Box<str>],
        ) -> crate::resource_admission::Selection,
    ) -> Result<Self, DataPreparationFailed> {
        let result = (|| {
            let RouteTarget::Plane(target) = self.route.binding.target() else {
                return Err(DataRefused::Binding);
            };
            let Some(inventory) = self.route.owners.inventory.as_ref() else {
                return Err(DataRefused::Binding);
            };
            if self.selected.is_some() {
                return Err(DataRefused::Binding);
            }
            let binding = self.preparation.binding();
            let frozen = crate::resource_admission::FrozenRequest::from_snapshot(
                binding.invocation(),
                target.mounted().route,
                Arc::clone(self.prepared.snapshot()),
            );
            let wire = selector(&frozen, self.route.withheld())
                .map_err(|_| DataRefused::Capacity)?
                .map_err(|_| DataRefused::Unavailable)?;
            let selected = inventory
                .select_wire(frozen, target.mounted(), &wire)
                .map_err(|_| DataRefused::Binding)?;
            if selected.invocation() != binding.invocation()
                || !Arc::ptr_eq(selected.inventory(), inventory)
                || !selected
                    .request()
                    .matches_snapshot(self.prepared.snapshot())
                || selected.request().route() != self.route.binding.line().route.rung
            {
                return Err(DataRefused::Binding);
            }
            Ok(selected)
        })();
        match result {
            Ok(selected) => {
                self.selected = Some(Arc::new(selected));
                Ok(self)
            }
            Err(reason) => Err(preparation_failed(
                self.preparation,
                self.route,
                None,
                Some(self.prepared),
                reason,
            )),
        }
    }

    /// The request's own input refused it (a body over the cap, request trailers), found while
    /// its body was read. The caller is verified by now, so the answer is that row, rendered by
    /// the route's plane; an unverified caller never reaches here and receives the one 401, so
    /// the order of the refusal table holds although the body arrived first.
    pub fn refuse_input(self, refusal: super::admission_table::Refusal) -> DataPreparationFailed {
        use super::admission_table::Refusal;
        let reason = match refusal {
            Refusal::BodyTooLarge => DataRefused::TooLarge,
            Refusal::Trailers => DataRefused::Trailers,
            // No other row is an input's own: nothing is answered, the request is cancelled.
            _ => DataRefused::Binding,
        };
        preparation_failed(
            self.preparation,
            self.route,
            self.selected,
            Some(self.prepared),
            reason,
        )
    }

    /// Consumes the completion right before awaiting replay. Publication after this lease
    /// is not cancellation; reset/deadline and an uncertain replay still grant no effects.
    pub async fn complete(self) -> Result<DataAuthorization, DataPreparationFailed> {
        let binding = self.preparation.binding().clone();
        let result = async {
            // One reading for this step's two deadlines: the binding's own and the pending one.
            let live_at = binding
                .check_live_now()
                .map_err(|_| DataRefused::Cancelled)?;
            if live_at >= self.deadline {
                return Err(DataRefused::Cancelled);
            }
            // A selecting route is completed only with its selection; a route that selects
            // nothing never carries one.
            if self.route.selects() != self.selected.is_some() {
                return Err(DataRefused::Binding);
            }
            let mut key = None;
            // The reason the gate's closure refused for: the gate reports only that it did.
            let mut refused = DataRefused::Policy;
            let lease = binding
                .handle()
                .admit_current(binding.app(), binding.invocation(), |app| {
                    let now = crate::store::now();
                    self.prepared.fresh(now).map_err(|_| DataRefused::Policy)?;
                    if !self.prepared.belongs_to(&self.route.owners.chain)
                        || self.selected.as_ref().is_some_and(|selected| {
                            !selected
                                .request()
                                .matches_snapshot(self.prepared.snapshot())
                                || selected.epoch() != self.route.owners.chain.epoch()
                        })
                        || app.config_generation.load(Ordering::Acquire)
                            != self.route.owners.chain.epoch()
                    {
                        return Err(DataRefused::Binding);
                    }
                    let resolved = governed_key(app, &self.prepared, &self.route.owners.chain, now)
                        .inspect_err(|reason| refused = *reason)?;
                    // With a selection the key's scope is judged against it here; with none, the
                    // request walk judges the key's grant of the pool or model the plane names
                    // (`RequestRoutes::scope_admits`), before any money.
                    if self
                        .selected
                        .as_ref()
                        .is_some_and(|selected| !selected.scope_allowed(&resolved))
                    {
                        refused = DataRefused::Scope;
                        return Err(DataRefused::Scope);
                    }
                    key = Some(resolved);
                    Ok(())
                })
                .map_err(|_| refused)?;
            match self.prepared.claim_classified().await {
                super::native_admin::NativeReplayClaim::Claimed => {}
                super::native_admin::NativeReplayClaim::Duplicate => {
                    return Err(DataRefused::Replay)
                }
                super::native_admin::NativeReplayClaim::Unknown(_) => {
                    return Err(DataRefused::Unavailable);
                }
                super::native_admin::NativeReplayClaim::Inconsistent => {
                    return Err(DataRefused::Binding)
                }
            }
            // The replay claim above may have waited: a second reading is needed, and it is this
            // step's one reading for both deadlines.
            let live_at = binding
                .check_live_now()
                .map_err(|_| DataRefused::Cancelled)?;
            if live_at >= self.deadline {
                return Err(DataRefused::Cancelled);
            }
            Ok((lease, key.ok_or(DataRefused::Policy)?))
        }
        .await;
        let (lease, key) = match result {
            Ok(parts) => parts,
            Err(reason) => {
                return Err(preparation_failed(
                    self.preparation,
                    self.route,
                    self.selected,
                    Some(self.prepared),
                    reason,
                ))
            }
        };
        let preparation = self.preparation.authorize().map_err(|_| {
            DataPreparationFailed::Unknown(UnknownDataPreparation {
                _preparation: None,
                _prepared: Some(self.prepared.clone()),
                reason: DataRefused::Cancelled,
            })
        })?;
        Ok(DataAuthorization {
            preparation,
            binding,
            route: self.route,
            selected: self.selected,
            prepared: self.prepared,
            lease,
            key,
            deadline: self.deadline,
        })
    }
}

pub enum DataPreparationFailed {
    Denied(PreparedDataDenial),
    Unknown(UnknownDataPreparation),
}
impl std::fmt::Debug for DataPreparationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataPreparationFailed")
            .field("reason", &self.reason())
            .finish()
    }
}
impl DataPreparationFailed {
    pub fn reason(&self) -> DataRefused {
        match self {
            Self::Denied(denied) => denied.decision,
            Self::Unknown(unknown) => unknown.reason,
        }
    }
}

pub struct PreparedDataDenial {
    preparation: DataPreparationDenied,
    _route: Arc<NativeDataRoute>,
    _selected: Option<Arc<SelectedResources>>,
    _prepared: Option<Arc<PreparedNativeIdentity>>,
    decision: DataRefused,
}
impl PreparedDataDenial {
    pub(crate) fn preparation(&self) -> &DataPreparationDenied {
        &self.preparation
    }
    pub fn binding(&self) -> &Arc<RequestBinding> {
        self.preparation.binding()
    }
    pub fn decision(&self) -> DataRefused {
        self.decision
    }
}

pub struct UnknownDataPreparation {
    _preparation: Option<DataPreparation>,
    _prepared: Option<Arc<PreparedNativeIdentity>>,
    reason: DataRefused,
}

fn preparation_failed(
    preparation: DataPreparation,
    route: Arc<NativeDataRoute>,
    selected: Option<Arc<SelectedResources>>,
    prepared: Option<Arc<PreparedNativeIdentity>>,
    reason: DataRefused,
) -> DataPreparationFailed {
    // Every reason the refusal table answers keeps the right to that answer: a denial, a refusal
    // after verification, and a verifier that could not answer (503, never a cancelled request).
    if reason.refusal(false).is_some() {
        match preparation.deny() {
            Ok(preparation) => DataPreparationFailed::Denied(PreparedDataDenial {
                preparation,
                _route: route,
                _selected: selected,
                _prepared: prepared,
                decision: reason,
            }),
            Err(_) => DataPreparationFailed::Unknown(UnknownDataPreparation {
                _preparation: None,
                _prepared: prepared,
                reason: DataRefused::Cancelled,
            }),
        }
    } else {
        DataPreparationFailed::Unknown(UnknownDataPreparation {
            _preparation: Some(preparation),
            _prepared: prepared,
            reason,
        })
    }
}

/// Privately minted after actual policy and replay, not from a public identity callback.
///
/// ```compile_fail,E0599
/// use std::sync::Arc;
/// use busbar_kernel::auth::{native_admin::PreparedIdentity, native_data::DataAuthorization};
/// fn fabricate(identity: Arc<PreparedIdentity>) -> DataAuthorization {
///     DataAuthorization::from_identity(identity)
/// }
/// ```
pub struct DataAuthorization {
    preparation: DataPreparationSuccess,
    binding: Arc<RequestBinding>,
    route: Arc<NativeDataRoute>,
    selected: Option<Arc<SelectedResources>>,
    prepared: Arc<PreparedNativeIdentity>,
    lease: AdmissionLease,
    key: Arc<VirtualKey>,
    deadline: Instant,
}
impl DataAuthorization {
    pub(crate) fn preparation(&self) -> &DataPreparationSuccess {
        &self.preparation
    }
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }

    /// The route this authorization was made on.
    pub fn route(&self) -> &Arc<NativeDataRoute> {
        &self.route
    }

    /// The governed key the verified identity earned, valid when it was judged.
    pub fn key(&self) -> &Arc<VirtualKey> {
        &self.key
    }

    /// The verified identity: what the plane is given in place of the credential.
    pub fn identity(&self) -> &busbar_ports::auth::Identity {
        self.prepared.identity()
    }

    /// The charged snapshot the identity was verified on.
    pub fn snapshot(&self) -> &Arc<crate::inbound::request_snapshot::ChargedRequestSnapshot> {
        self.prepared.snapshot()
    }

    /// The identity is the subject every caller of an open chain shares.
    pub fn is_shared(&self) -> bool {
        self.prepared.is_anonymous()
    }
}

/// The data chain's judgement of a request no route matched (design C4, question 4): the facts
/// the admission decision needs to answer 404 or 405 to a verified caller and the one 401 to
/// anyone else. Nothing is lent to any plane and nothing is claimed: an unknown path consumes no
/// replay claim and opens no unit.
pub async fn judge_unrouted(
    app: &App,
    chain: &Arc<NativeChain>,
    binding: &Arc<RequestBinding>,
    cx: CallCx,
) -> (Option<Verified>, Option<Policy>) {
    let Ok(snapshot) = binding.snapshot() else {
        return (Some(Verified::Unavailable), None);
    };
    if refuse_bound_carriers(&snapshot, chain, None).is_err() {
        return (Some(Verified::Denied), None);
    }
    let prepared = match chain.prepare_snapshot(cx, snapshot).await {
        Ok(NativePreparedAnswer::Identity(prepared)) => prepared,
        Ok(_) => return (Some(Verified::Denied), None),
        Err(_) => return (Some(Verified::Unavailable), None),
    };
    if binding.check_live().is_err() {
        return (Some(Verified::Unavailable), None);
    }
    let verified = Verified::Identity {
        shared: prepared.is_anonymous(),
    };
    let policy = match governed_key(app, &prepared, chain, crate::store::now()) {
        Ok(_) => Policy::Valid,
        Err(DataRefused::Disabled) => Policy::Disabled,
        Err(_) => Policy::NoKey,
    };
    (Some(verified), Some(policy))
}

/// Separate from the money phase: a successful grant cannot open effects while the
/// actual callback identity and physical execution transition are still unchecked.
pub(crate) struct NativeDataEffectGate {
    binding: Arc<RequestBinding>,
    ready: AtomicBool,
    deadline: Instant,
}
impl NativeDataEffectGate {
    fn new(binding: Arc<RequestBinding>, deadline: Instant) -> Self {
        Self {
            binding,
            deadline,
            ready: AtomicBool::new(false),
        }
    }
    pub(crate) fn effects_allowed(&self) -> bool {
        self.ready.load(Ordering::Acquire)
            && Instant::now() < self.deadline
            && self.binding.check_executing().is_ok()
    }
}

struct Registration {
    context: InvocationContext,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.context.retire();
    }
}

/// Owns the newly inserted record and exact original request, never an arbitrary existing context.
pub struct NativeDataAllocation {
    authorization: DataAuthorization,
    physical: PhysicalExecutionOwner,
    registration: Arc<Registration>,
    gate: Arc<NativeDataEffectGate>,
    allocation: RequestAllocation,
    audit: Arc<crate::teller::native_data_audit::NativeAuditState>,
}
impl NativeDataAllocation {
    pub fn register(physical: AuthorizedPhysicalData) -> Result<Self, DataRefused> {
        let (authorization, physical) = physical.into_parts();
        // One reading for both deadlines: the binding's own and the authorization's.
        let live_at = authorization
            .binding
            .check_live_now()
            .map_err(|_| DataRefused::Cancelled)?;
        if live_at >= authorization.deadline {
            return Err(DataRefused::Cancelled);
        }
        let plan = &authorization.route;
        let unit = plan.owners.keys.mint();
        let gate = Arc::new(NativeDataEffectGate::new(
            authorization.binding.clone(),
            authorization.deadline,
        ));
        let units = plan.owners.generation.core().units();
        let record = units
            .pre_admitted_data(
                unit.get(),
                &plan.caller,
                crate::host_units::UnitRecord {
                    principal: Some(authorization.key.clone()),
                    depth: 0,
                },
                gate.clone(),
            )
            .ok_or(DataRefused::Unit)?;
        let context = match InvocationContext::new(
            plan.owners.generation.clone(),
            plan.caller.clone(),
            unit.get(),
        ) {
            Ok(context) => context,
            Err(_) => {
                units.ended_if_record(unit.get(), &record);
                return Err(DataRefused::Unit);
            }
        };
        let registration = Arc::new(Registration { context });
        let allocation = RequestAllocation::new(
            registration.context.clone(),
            plan.cost.clone(),
            authorization.prepared.snapshot().now_s(),
        )
        .map_err(|_| DataRefused::Unit)?;
        let allocation = match &authorization.selected {
            Some(selected) => allocation.with_selection(Arc::clone(selected)),
            None => allocation,
        };
        let audit = crate::teller::native_data_audit::NativeAuditState::new(
            registration.context.clone(),
            authorization.key.clone(),
            authorization.binding.clone(),
        )
        .map_err(|_| DataRefused::Capacity)?;
        Ok(Self {
            audit,
            authorization,
            physical,
            registration,
            gate,
            allocation,
        })
    }

    pub fn request(&self) -> &crate::limits::process_admission::RequestLease {
        self.authorization.binding.request()
    }

    /// Transfer the original allocation's one-shot audit registration to Node custody.
    pub fn take_audit_registration(
        &mut self,
    ) -> Result<crate::teller::native_data_audit::NativeAuditRegistration, DataRefused> {
        self.audit
            .take_registration()
            .map_err(|_| DataRefused::Unit)
    }

    pub fn context(&self) -> &InvocationContext {
        &self.registration.context
    }

    /// Wrap the existing same-Task monetary callback. The opaque DATA carrier, not a
    /// free Pending or InvocationContext, unlocks the resource-scoped preparatory phase.
    pub fn into_pending(
        self,
        commit: impl FnOnce(RequestPoolReceipt) -> Result<AdmittedUnit, ClientRefusal> + Send + 'static,
    ) -> NativeDataPending {
        self.into_pending_using(
            move |receipt, ()| commit(receipt),
            |allocation, routes, commit| {
                Pending::new(allocation, routes, None, move |receipt| commit(receipt, ()))
            },
            |pending| pending,
        )
    }

    /// Wire the original candidate's route and budgets before exposing the preparatory Task.
    pub fn into_pending_runtime(
        self,
        seat: &PortSeat,
        journal: Option<Arc<dyn crate::plane_driver::HookJournal>>,
        commit: impl FnOnce(RequestPoolReceipt) -> Result<AdmittedUnit, ClientRefusal> + Send + 'static,
    ) -> Result<NativeDataPending, DataRefused> {
        if !seat
            .driver
            .caller()
            .same_incarnation(&self.authorization.route.caller)
            || !Arc::ptr_eq(
                &seat.request_routes,
                &self.authorization.route.owners.routes,
            )
        {
            return Err(DataRefused::Binding);
        }
        let route = seat
            .retain_route(
                self.context(),
                self.authorization.route.binding.line().route.rung,
            )
            .ok_or(DataRefused::Binding)?;
        let budget = seat.channel_budget.unit();
        let rates = self
            .authorization
            .binding
            .handle()
            .selected_rate_admission();
        Ok(self.into_pending_using(
            move |receipt, ()| commit(receipt),
            move |allocation, routes, commit| {
                Pending::new(allocation, routes, journal, move |receipt| {
                    commit(receipt, ())
                })
            },
            move |pending| {
                pending
                    .with_route(route)
                    .with_channel_budget(budget)
                    .with_current_rates(rates)
            },
        ))
    }

    fn into_pending_using<D: Send + 'static>(
        self,
        commit: impl FnOnce(RequestPoolReceipt, D) -> Result<AdmittedUnit, ClientRefusal>
            + Send
            + 'static,
        build: impl FnOnce(RequestAllocation, Arc<RequestRoutes>, DataCommit<D>) -> Pending,
        configure: impl FnOnce(Pending) -> Pending,
    ) -> NativeDataPending {
        let Self {
            authorization,
            physical,
            registration,
            gate,
            allocation,
            audit,
        } = self;
        let execution = Arc::new(OnceLock::new());
        let retained = execution.clone();
        let context = registration.context.clone();
        let routes = authorization.route.owners.routes.clone();
        let route = authorization.route.clone();
        let selected = authorization.selected.clone();
        let prepared = authorization.prepared.clone();
        let binding = authorization.binding.clone();
        let deadline = authorization.deadline;
        let custody = Arc::new(Mutex::new(DataCommitCustody {
            phase: DataCommitPhase::Awaiting,
            bundle: Some(DataCommitBundle {
                authorization,
                physical,
                registration,
            }),
            refusal: None,
        }));
        let commit_custody = custody.clone();
        let commit_audit = audit.clone();
        let pending = build(
            allocation,
            routes,
            Box::new(move |receipt, declaration| {
                let refuse = || ClientRefusal {
                    status: 503,
                    code: busbar_plugin_abi::fail::refused::R_POLICY,
                    text: "native data admission refused".into(),
                };
                {
                    let mut custody = commit_custody.lock().map_err(|_| refuse())?;
                    let bundle = custody.bundle.as_ref().ok_or_else(refuse)?;
                    // The binding's liveness is asked last and answers the reading it judged at;
                    // the authorization's deadline is judged at that same reading. It is taken
                    // after every lock these checks take: no deadline is judged before a lock.
                    if custody.phase != DataCommitPhase::Awaiting
                        || !commit_audit.node_ready()
                        || !bundle.registration.context.is_live()
                        || !bundle
                            .authorization
                            .binding
                            .check_live_now()
                            .is_ok_and(|live_at| live_at < bundle.authorization.deadline)
                    {
                        return Err(refuse());
                    }
                    custody.phase = DataCommitPhase::Committing;
                }
                // The original physical owner remains installed while the callback runs.
                // No custody lock crosses monetary work or a plugin/Store call.
                let admitted = match commit(receipt, declaration) {
                    Ok(admitted) => admitted,
                    Err(decision) => {
                        let mut custody = commit_custody.lock().map_err(|_| refuse())?;
                        custody.phase = DataCommitPhase::ExpectedPreMoneyRefusal;
                        custody.refusal = Some(decision.clone());
                        return Err(decision);
                    }
                };
                let bundle = {
                    let mut custody = commit_custody.lock().map_err(|_| refuse())?;
                    custody.phase = DataCommitPhase::MoneyAccepted;
                    let bundle = custody.bundle.as_ref().ok_or_else(refuse)?;
                    if !admitted
                        .request
                        .context()
                        .same_unit(&bundle.registration.context)
                        || !bundle.registration.context.is_live()
                        || Instant::now() >= bundle.authorization.deadline
                        || admitted.unit.ctx.key != admitted.request.unit()
                        || !Arc::ptr_eq(admitted.request.key(), &bundle.authorization.key)
                    {
                        return Err(refuse());
                    }
                    commit_audit.bind_money(&admitted).map_err(|_| refuse())?;
                    let bundle = custody.bundle.take().ok_or_else(refuse)?;
                    custody.phase = DataCommitPhase::ExecutingTransferred;
                    bundle
                };
                let proof = DataExecutionAdmission {
                    authorization: bundle.authorization,
                    physical: bundle.physical,
                    registration: bundle.registration,
                    money: admitted.request.clone(),
                };
                if proof.physical.start_execution(&proof).is_err() {
                    return Err(refuse());
                }
                commit_audit.executing().map_err(|_| refuse())?;
                retained.set(proof).map_err(|_| refuse())?;
                gate.ready.store(true, Ordering::Release);
                Ok(admitted)
            }),
        );
        NativeDataPending {
            audit,
            custody,
            pending: Arc::new(configure(pending)),
            execution,
            context,
            route,
            selected,
            prepared,
            binding,
            deadline,
        }
    }
}

struct DataCommitBundle {
    authorization: DataAuthorization,
    physical: PhysicalExecutionOwner,
    registration: Arc<Registration>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DataCommitPhase {
    Awaiting,
    Committing,
    MoneyAccepted,
    ExecutingTransferred,
    ExpectedPreMoneyRefusal,
    RefusalTransferred,
}

struct DataCommitCustody {
    phase: DataCommitPhase,
    bundle: Option<DataCommitBundle>,
    refusal: Option<ClientRefusal>,
}

pub(crate) struct DataRefusalCustody {
    authorization: DataAuthorization,
    _registration: Arc<Registration>,
}
impl DataRefusalCustody {
    pub(crate) fn matches(&self, binding: &Arc<RequestBinding>) -> bool {
        Arc::ptr_eq(&self.authorization.binding, binding)
    }
}

type DataCommit<D> =
    Box<dyn FnOnce(RequestPoolReceipt, D) -> Result<AdmittedUnit, ClientRefusal> + Send>;

pub struct NativeDataPending {
    audit: Arc<crate::teller::native_data_audit::NativeAuditState>,
    binding: Arc<RequestBinding>,
    deadline: Instant,
    route: Arc<NativeDataRoute>,
    selected: Option<Arc<SelectedResources>>,
    prepared: Arc<PreparedNativeIdentity>,
    pending: Arc<Pending>,
    execution: Arc<OnceLock<DataExecutionAdmission>>,
    context: InvocationContext,
    custody: Arc<Mutex<DataCommitCustody>>,
}
impl NativeDataPending {
    pub(crate) fn take_refusal(
        &self,
        decision: &ClientRefusal,
    ) -> Result<(PhysicalExecutionOwner, DataRefusalCustody), DataRefused> {
        let mut custody = self.custody.lock().map_err(|_| DataRefused::Unit)?;
        // Either money itself refused this decision, or the session refused before money was
        // ever asked (the key's grant, the plane's own refusal of its input): the commit never
        // ran, and once the bundle leaves here it never can.
        let before_money = match custody.phase {
            DataCommitPhase::ExpectedPreMoneyRefusal => custody.refusal.as_ref() == Some(decision),
            DataCommitPhase::Awaiting => custody.refusal.is_none(),
            _ => false,
        };
        if !before_money || self.execution.get().is_some() || self.pending.admitted().is_some() {
            return Err(DataRefused::Unit);
        }
        let bundle = custody.bundle.take().ok_or(DataRefused::Unit)?;
        custody.phase = DataCommitPhase::RefusalTransferred;
        Ok((
            bundle.physical,
            DataRefusalCustody {
                authorization: bundle.authorization,
                _registration: bundle.registration,
            },
        ))
    }

    pub fn is_live(&self) -> bool {
        // The binding's liveness answers the reading it judged at (after its lock); the pending
        // deadline is judged at that same reading.
        self.context.is_live()
            && self
                .binding
                .check_live_now()
                .is_ok_and(|live_at| live_at < self.deadline)
    }

    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
    /// The carriers the route's chain judged: withheld from the plane.
    pub fn withheld(&self) -> &Arc<[Box<str>]> {
        self.route.withheld()
    }
    /// The resources the plane selected after verification; `None` on a route that selects none.
    pub fn selected(&self) -> Option<&SelectedResources> {
        self.selected.as_deref()
    }
    /// The plane route (rung) this request was admitted on.
    pub fn route(&self) -> u32 {
        self.route.binding.line().route.rung
    }
    pub fn identity(&self) -> &busbar_ports::auth::Identity {
        self.prepared.identity()
    }
    pub fn snapshot(&self) -> &Arc<crate::inbound::request_snapshot::ChargedRequestSnapshot> {
        self.prepared.snapshot()
    }
    pub(crate) fn accepts(
        &self,
        driver: &crate::plane_driver::port::PortDriver,
        route: u32,
    ) -> bool {
        self.audit.node_ready()
            && self.is_live()
            && self.route.caller.same_incarnation(driver.caller())
            && Arc::ptr_eq(self.route.owners.generation.core(), driver.core())
            && self.route.binding.line().route.rung == route
            && self
                .selected
                .as_ref()
                .is_none_or(|selected| selected.request().route() == route)
    }

    pub(crate) fn pending(&self) -> &Arc<Pending> {
        &self.pending
    }
    pub fn context(&self) -> &InvocationContext {
        &self.context
    }
    /// Whether this runtime belongs to the exact original invocation of `owner`.
    pub fn owned_by(&self, owner: &crate::teller::native_data_audit::NativeAuditOwner) -> bool {
        self.context.same_unit(owner.invocation())
    }
    pub fn execution(&self) -> Option<&DataExecutionAdmission> {
        self.execution.get()
    }

    /// Lend the same accepted monetary owner for the registered response's terminal join.
    pub fn admitted(&self) -> Option<&AdmittedUnit> {
        self.execution.get()?;
        self.pending.admitted()
    }
}

/// Actual DATA + physical + exact-context + monetary completion. No public constructor.
pub struct DataExecutionAdmission {
    authorization: DataAuthorization,
    physical: PhysicalExecutionOwner,
    registration: Arc<Registration>,
    money: AdmittedRequest,
}
impl DataExecutionAdmission {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.authorization.binding
    }
    pub fn selected(&self) -> Option<&SelectedResources> {
        self.authorization.selected.as_deref()
    }
    pub fn context(&self) -> &InvocationContext {
        &self.registration.context
    }
    pub fn identity(&self) -> &busbar_ports::auth::Identity {
        self.authorization.prepared.identity()
    }
    pub fn principal(&self) -> &Arc<VirtualKey> {
        &self.authorization.key
    }
    pub fn lease(&self) -> &AdmissionLease {
        &self.authorization.lease
    }
    pub fn money(&self) -> &AdmittedRequest {
        &self.money
    }
}

#[cfg(test)]
#[path = "tests/native_data_tests.rs"]
mod tests;
