// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native DATA authorization retains the original physical request, selected resources and
//! real verification. Registration and monetary admission cannot reconstruct this proof.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use busbar_contract::records::VirtualKey;
use busbar_contract::services::Caller;
use busbar_ports::CallCx;

use super::admission_table::{admission_of, Admission, NotMounted, Offered, Policy, Verified};
use super::native_chain::{NativeChain, NativePreparedAnswer, PreparedNativeIdentity};
use super::native_ticket::{
    Presented as TicketPresented, Serving, TicketDesk, TicketJudged, TicketRefused,
};
use super::route_record::{CallerState, Money, RouteRecord, Who};
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
    /// An upgrade route's request does not ask to switch to websocket (§12.27 step 1): 400, to a
    /// verified caller.
    NotAnUpgrade,
    /// The listener has no transport that can carry the upgrade (§12.27 step 1): 501, to a verified
    /// caller.
    NoUpgradeTransport,
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
            Self::NotAnUpgrade => Some(Refusal::NotAnUpgrade),
            Self::NoUpgradeTransport => Some(Refusal::NoUpgradeTransport),
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
            Self::Disabled
                | Self::Scope
                | Self::TooLarge
                | Self::Trailers
                | Self::NotAnUpgrade
                | Self::NoUpgradeTransport
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
    /// Core's public URL as the route's plane instance is given it (`PortSeat::public_url`), kept
    /// at bind: the origin a DPoP proof's `htu` names ([`Self::proof_url`]).
    public_url: Option<Arc<str>>,
    challenge: Option<Box<str>>,
    record: RouteRecord,
    admission: Admission,
    /// The ticket desk of the route's plane instance; `None` where core's ticket store is shut.
    /// A ticket route redeems at it ([`Self::prepare_ticket`]); every route of the instance
    /// enters its authorized principals in it, so a mint made while they are served is bound to
    /// their key ([`PendingData::complete`]).
    ticket: Option<Arc<TicketDesk>>,
}

/// The class a request is handed to its plane as (`PlaneReq.auth`): a ticket's, where a ticket
/// admitted it, else a principal's.
const fn auth_class(ticket: bool) -> u32 {
    if ticket {
        busbar_plugin_abi::plane::AUTH_TICKET
    } else {
        busbar_plugin_abi::plane::AUTH_PRINCIPAL
    }
}

/// How the listener plan mounts one declared route ([`NativeDataRoute::planned`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Planned {
    /// Bind a [`NativeDataRoute`] with the route's chain: the listener verifies, then serves by
    /// the route's admission (with a unit, or verified and not billed).
    Data,
    /// Bind a `NativeUpgradeRoute` with the route's chain.
    Upgrade,
    /// Bind a `NativeSignedRoute` (`auth::native_signed_route`) with the route's own chain as its
    /// signature verifier: the listener reads the bounded body, verifies it, then serves with no
    /// unit. Only where a signature verifier is configured for the route (`Offered`).
    Signed,
    /// The admin plan's: not a data listener's route.
    Admin,
    /// Not mounted, for a reason that is the operator's configuration.
    NotMounted(NotMounted),
}

const OTHER_PATH_SIGNED: &str = "a signed route is served by the listener's signed-ingress class";
const OTHER_PATH_OPERATOR: &str = "an admin route is served by the admin door";
const NO_CONFIGURED_MODEL: &str =
    "no configured model routes to this plane, so the route has nothing to reach";

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

    /// The admission of `mounted` on `seat` under this configuration, or why the route is not
    /// mounted. Every reason is the operator's configuration (design C6); a route's class is never
    /// one. The record is the one its plane stated (`Mounted::record`): nothing is inferred.
    pub fn admission(
        seat: &PortSeat,
        mounted: &Mounted,
        chain: &NativeChain,
        offered: Offered,
    ) -> Result<(RouteRecord, Admission), NotMounted> {
        let record = &mounted.record;
        let offered = Offered {
            challenge_unresolved: record.mounted_challenge(seat.public_url()).is_err(),
            ..offered
        };
        let admission = super::admission_table::mounted(record, offered)?;
        Ok((record.clone(), admission))
    }

    /// How the listener plan mounts `mounted` on `seat`: the one decision the plan makes about a
    /// declared route. `chain_reads_its_credential`: some configured instance reads the route's
    /// credential (its own header's readers, else the data chain).
    /// Every route is mounted by its admission or left unmounted for a
    /// reason that is the operator's configuration, logged once and listed by the admin API.
    pub fn planned(
        seat: &PortSeat,
        mounted: &Mounted,
        chain_reads_its_credential: bool,
        upgrade_transport: bool,
        signature_verifier: bool,
    ) -> Planned {
        let record = &mounted.record;
        let offered = Offered {
            verifier_reads_header: chain_reads_its_credential,
            upgrade_transport,
            signature_verifier,
            // Core's ticket store is open exactly where the boot gave the instance a desk.
            ticket_store: seat.driver.ticket_desk().is_some(),
            challenge_unresolved: record.mounted_challenge(seat.public_url()).is_err(),
        };
        match super::admission_table::mounted(record, offered) {
            Err(why) => Planned::NotMounted(why),
            Ok(
                Admission::Walk
                | Admission::Selected
                | Admission::PrincipalOnly
                | Admission::Catalog
                | Admission::Optional,
            ) => Planned::Data,
            // A ticket route is bound like a data route: core's ticket verifier judges a
            // presented ticket inside the route's own preparation, and its chain judges a request
            // with none where the record also admits a principal. `mounted` above already left it
            // unmounted where no ticket store is open.
            Ok(Admission::Ticket) => Planned::Data,
            Ok(Admission::Upgrade) => Planned::Upgrade,
            // A public route is bound like a data route (its chain is never run: the listener
            // serves it by its admission) so no second mounting path exists.
            Ok(Admission::Public) => Planned::Data,
            // A plane's admin routes are mounted on the admin door by the admin plan.
            Ok(Admission::Operator) => Planned::Admin,
            // The table mounted it, so a signature verifier that covers and bounds its body is
            // configured (`offered.signature_verifier`, the answer of
            // `NativeSignedRoute::offered`): its whole path exists, and it is the signed class's.
            Ok(Admission::SignedIngress) => Planned::Signed,
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
    /// for every credential its chain's instances verify, and on an audience-bound plane an
    /// access token of its own authorization server must also still stand in that server's
    /// store (`native_keys::as_standing`). A token core itself signed is verified by the chain's
    /// built-in member `keys` (`native_keys::judge`) where the chain names it, and refused by
    /// [`refuse_bound_carriers`] where it does not; it is never accepted unverified. A
    /// DPoP-bound token is admitted only with its proof of possession proven for the request
    /// (`native_dpop::judge`, in [`Self::prepare`]); unproven it is refused. A route with a hook bound is
    /// admitted exactly where its hooks run ([`Self::hooks_run`]): a route that selects no
    /// resource and verifies every caller by its chain, whether or not it opens a unit, and a
    /// catalog. Any other stays unmounted and says so; serving it unhooked would skip a policy
    /// the operator configured.
    pub fn admits(_app: &App, seat: &PortSeat, mounted: &Mounted) -> Result<(), &'static str> {
        let record = &mounted.record;
        match admission_of(record) {
            Admission::Walk
            | Admission::Selected
            | Admission::PrincipalOnly
            | Admission::Catalog
            | Admission::Optional
            | Admission::Public
            // An upgrade request is admitted as any request is (owner decision 18): the same chain,
            // key, replay claim, unit and money on its head; its answer may be a 101.
            | Admission::Upgrade => {}

            // A ticket is core's own credential, judged by core's ticket verifier in this path's
            // preparation. Without a ticket store nothing could mint or redeem one: the route is
            // not mounted, never answered 401 forever.
            Admission::Ticket => {
                if seat.driver.ticket_desk().is_none() {
                    return Err(NotMounted::NoTicketStore.reason());
                }
            }
            Admission::SignedIngress => return Err(OTHER_PATH_SIGNED),
            Admission::Operator => return Err(OTHER_PATH_OPERATOR),
            Admission::Internal => return Err("an internal route is not on a listener"),
        }
        if mounted.effective != mounted.auth {
            return Err("the operator's auth choice for this route is not the route's own");
        }
        // A route whose record selects kinds is admitted only through its plane's selection; one
        // that selects none is admitted through the plane's `request`. That the plane implements
        // `select_resources` for a selecting route is the loader's rule (the record could not be
        // declared otherwise); plane 2.0 retired the fact bit that restated it.
        if seat.driver.has_hooks(mounted.route) {
            Self::hooks_run(record)?;
        }
        // The route's 401 must carry the challenge its protocol requires. A challenge that names
        // the public URL where the operator configured none cannot be written: the route is not
        // mounted (design C6), it is never served with core's generic challenge in its place.
        if record.mounted_challenge(seat.public_url()).is_err() {
            return Err(NotMounted::NoPublicUrlForItsChallenge.reason());
        }
        // A plane that states dialects (model wire protocols) walks configured models: its walk
        // route is served only while a configured model routes to it (docs/decisions.md: "No
        // `decisions:` models means no active decision route"). With none, the walk has nothing
        // to reach; the route is not mounted and a request to it is answered as one to no route.
        if admission_of(record) == Admission::Walk
            && !seat.driver.port().dialects().is_empty()
            && !seat.request_routes.routes_models()
        {
            return Err(NO_CONFIGURED_MODEL);
        }
        Ok(())
    }

    /// Whether a route with a hook bound is served WITH its hook, by what its record says a served
    /// request is built from. Err names why it stays unmounted: a hook-bound route is never served
    /// unhooked.
    ///
    /// A request that opens a unit and selects no resource runs its hooks inside the session,
    /// after the key's grant of the walk is judged and before its money is asked
    /// (`plane_driver::port_serve`): a refusing hook has spoken before any unit is opened. A
    /// route that opens no unit and verifies every caller by its chain runs them the same way,
    /// under the verified request itself ([`Self::hook_invocation`]): the same hooks, in the same
    /// order, shown the same facts, a refusing hook answering at its own status; there is no
    /// money to ask after them. A catalog runs no session and reaches no upstream: no hook is
    /// bound to a listing (v1.5.5 listed models with hooks configured), and it is served as it
    /// is without one.
    ///
    /// A route that admits a caller who presents nothing (public, or optional) stays unmounted
    /// with a hook bound: such a request has no verified caller for a hook to be called under.
    pub fn hooks_run(record: &RouteRecord) -> Result<(), &'static str> {
        use super::admission_table::{plan, Authority, VerifyBy};
        let admission = admission_of(record);
        // A selected request runs under its descriptor's authority alone
        // (`NativeDataEffectGate::hooks_allowed`): its hooks would never be called, whether
        // or not the route opens a unit.
        if admission == Admission::Selected {
            return Err(
                "a route with a hook bound whose plane selects resources is not served: a selected request runs no hook",
            );
        }
        let Some(sequence) = plan(admission, record.money) else {
            return Err("a route with a hook bound is not served by the native data path");
        };
        match sequence.serves {
            Authority::Walk | Authority::Billed | Authority::Catalog => Ok(()),
            // No unit, and every request verified by the route's chain: the hooks run under
            // the verified request.
            Authority::Unbilled if sequence.verify == VerifyBy::Chain => Ok(()),
            Authority::Unbilled | Authority::Public => Err(
                "a route with a hook bound that admits a caller who presents no credential is not served: such a request has no verified caller to run a hook under",
            ),
            Authority::Upgrade | Authority::Operator => {
                Err("a route with a hook bound is not served by the native data path")
            }
        }
    }

    /// The invocation a verified request on a route that opens no unit runs its hooks under.
    /// `Ok(None)`: no hook is bound to `route` on `seat`, and the request pays nothing for the
    /// feature (no number is minted, nothing is registered, the session is handed no
    /// invocation). `Ok(Some)`: the request is registered under its verified key for the
    /// lifetime of the returned owner; its context goes to the session as its invocation.
    ///
    /// The invocation hears hooks and allows nothing else: no effect, no nested unit, and no
    /// money can be asked under it (`UnitRecords::admitted_unbilled`).
    ///
    /// # Errors
    /// The seat is not this route's, the route moves money (its hooks run inside its pending
    /// admission), the request is cancelled or past its deadline, or it cannot be registered.
    /// The request is then not served: a hook-bound route is never served unhooked.
    pub fn hook_invocation(
        &self,
        seat: &PortSeat,
        route: u32,
        authorization: &DataAuthorization,
    ) -> Result<Option<UnbilledInvocation>, DataRefused> {
        if !seat.driver.caller().same_incarnation(&self.caller)
            || !std::ptr::eq(&*authorization.route, self)
        {
            return Err(DataRefused::Binding);
        }
        if !seat.driver.has_hooks(route) || self.admission == Admission::Catalog {
            return Ok(None);
        }
        if self.billed() {
            return Err(DataRefused::Binding);
        }
        let live_at = authorization
            .binding
            .check_live_now()
            .map_err(|_| DataRefused::Cancelled)?;
        if live_at >= authorization.deadline {
            return Err(DataRefused::Cancelled);
        }
        let records = Arc::new(crate::plane_driver::port_hooks::HookRecords::default());
        let gate = Arc::new(NativeDataEffectGate::unbilled(
            authorization.binding.clone(),
            authorization.deadline,
            Arc::clone(&records),
        ));
        let unit = self.owners.keys.mint();
        let units = self.owners.generation.core().units();
        let record = units
            .admitted_unbilled(
                unit.get(),
                &self.caller,
                crate::host_units::UnitRecord {
                    principal: Some(authorization.key.clone()),
                    depth: 0,
                },
                Some(gate),
            )
            .ok_or(DataRefused::Unit)?;
        let context = match InvocationContext::new(
            self.owners.generation.clone(),
            self.caller.clone(),
            unit.get(),
        ) {
            Ok(context) => context,
            Err(_) => {
                units.ended_if_record(unit.get(), &record);
                return Err(DataRefused::Unit);
            }
        };
        Ok(Some(UnbilledInvocation {
            registration: Registration { context },
            records,
        }))
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
        let record = mounted.record.clone();
        // The challenge of this route's 401, with the plane instance's public URL written in:
        // once, here, where the route is mounted on its listener. `admits` above already refused
        // a challenge that cannot be resolved.
        let Ok(challenge) = record.mounted_challenge(seat.public_url()) else {
            return Err(DataRefused::Unsupported);
        };
        if !seat.driver.caller().same_incarnation(target.caller())
            || !Arc::ptr_eq(seat.driver.core(), owners.generation.core())
            || !seat
                .driver
                .routes()
                .data
                .iter()
                .chain(seat.driver.routes().upgrade.iter())
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
        // The desk is the seat's own: the one its plane's MINT is bound through. `admits` above
        // refused a ticket route on a seat with none.
        let ticket = seat.driver.ticket_desk().cloned();
        if ticket
            .as_ref()
            .is_some_and(|desk| desk.instance() != seat.who.instance)
        {
            return Err(DataRefused::Binding);
        }
        Ok(Arc::new(Self {
            ticket,
            caller: target.caller().clone(),
            binding,
            owners,
            cost: Arc::clone(&app.cost),
            withheld,
            audience: seat.audience.as_deref().map(Arc::from),
            public_url: seat.public_url().map(Arc::from),
            challenge,
            record,
            admission,
        }))
    }

    /// The URL whose origin a DPoP proof on this route must name (RFC 9449 s4.3 (9)): where the
    /// request was received, core's public URL. An audience (RFC 8707) names the resource, and its
    /// origin can differ; it is stated only where no public URL is configured.
    pub(crate) fn proof_url(&self) -> Option<&str> {
        self.public_url.as_deref().or(self.audience.as_deref())
    }

    /// The route token this completion was bound to.
    pub fn binding(&self) -> &Arc<RouteBinding> {
        &self.binding
    }

    /// Whether a request on this route must present a credential to be verified: its admission
    /// runs the chain on every request, the chain admits no caller that presents nothing, and
    /// every member of the chain states the header its credential arrives in (so a head with
    /// none of them cannot be verified by any member).
    /// The listener answers a head that presents none without taking its body.
    pub fn requires_credential(&self) -> bool {
        matches!(
            self.admission,
            Admission::Walk | Admission::Selected | Admission::PrincipalOnly | Admission::Catalog
        ) && !self.owners.chain.admits_anonymous()
            && self.owners.chain.reads_only_declared_headers()
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
        // A ticket route: core's ticket verifier judges the head first. The chain below runs
        // only for a request that presents no ticket, on a route whose record also admits a
        // principal; a presented ticket that is refused never reaches it.
        let preparation = if self.admission == Admission::Ticket {
            match self.prepare_ticket(preparation, cx).await {
                TicketStep::Chain(preparation) => preparation,
                TicketStep::Judged(judged) => return judged,
            }
        } else {
            preparation
        };
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
            let chain = &self.owners.chain;
            let audience = self.audience.as_deref();
            // The sender constraint first ([`judge_sender`]). A chain that names `keys` lets a
            // core-signed token through to core's own verifier below.
            let snapshot = judge_sender(
                binding.app(),
                snapshot,
                chain,
                cred_header,
                self.proof_url(),
                chain.admits_keys(),
            )
            .await?;
            if let Some(audience) = audience {
                refuse_foreign_audience(&snapshot, chain, audience)?;
            }
            // The engine's own token, judged by the engine: verified under the governance of
            // the generation this request was admitted by, for this route's audience exactly
            // (none, on a route bound to none). No instance of the chain is handed it.
            let core = super::native_keys::judge(
                &snapshot,
                chain,
                cred_header,
                binding.app().governance.as_deref(),
                audience,
                snapshot.now_s(),
            )?;
            if let Some(core) = core {
                binding.check_live().map_err(|_| DataRefused::Cancelled)?;
                return Ok((chain.core_identity(cx, snapshot, core), true));
            }
            // An access token of this deployment's own authorization server, on an
            // audience-bound plane: its issuer's store must still hold it for this resource.
            // The chain below still verifies it.
            let minted_here = match audience {
                Some(audience) => {
                    super::native_keys::as_standing(binding.app(), &snapshot, chain, audience)
                        .await?
                }
                None => false,
            };
            let prepared = chain
                .prepare_snapshot(cx, snapshot)
                .await
                .map_err(|_| DataRefused::Unavailable)?;
            binding.check_live().map_err(|_| DataRefused::Cancelled)?;
            let NativePreparedAnswer::Identity(prepared) = prepared else {
                return Err(DataRefused::Credential);
            };
            Ok((prepared, minted_here))
        }
        .await;
        match result {
            Ok((prepared, minted_here)) => Ok(PendingData {
                preparation,
                route: self.clone(),
                selected: None,
                prepared,
                minted_here,
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

    /// Step 2 of a ticket route (`VerifyBy::TicketOrChain`): the head is judged by core's ticket
    /// verifier at the desk of the route's plane instance. No instance of the chain is run and
    /// nothing of the request is lent to anyone.
    ///
    /// * A ticket, alone on the head, that the desk admits: the request is verified as the
    ///   ticket's subject under its issuer's governed key as that key stands now
    ///   ([`NativeChain::ticket_identity`]). The ticket is spent: it admits this one request.
    /// * A ticket the desk refuses (spent, expired, another door or instance, its issuer no
    ///   longer standing, presented beside another credential): the one 401. A store that could
    ///   not answer: 503. Neither falls through to the chain.
    /// * No ticket: the chain judges the request where the record also admits a principal
    ///   ([`TicketStep::Chain`]); where it admits a ticket alone, nobody does (the one 401).
    async fn prepare_ticket(
        self: &Arc<Self>,
        preparation: DataPreparation,
        cx: CallCx,
    ) -> TicketStep {
        let binding = preparation.binding().clone();
        let judged = async {
            // A ticket route bound with no desk admits nobody: it is never served by its chain
            // in the ticket's place.
            let Some(desk) = self.ticket.as_ref() else {
                return Err(DataRefused::Unsupported);
            };
            // The same binding and deadline checks as the chain's preparation, on one reading.
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
            let verifier = desk.verifier();
            match verifier.presented(snapshot.headers()) {
                TicketPresented::NoTicket => return Ok(None),
                // A ticket beside a credential in another carrier this route reads: which one
                // the caller means cannot be said, and the ticket is not spent on a guess.
                TicketPresented::Ticket(_)
                    if snapshot.headers().any(|(name, _)| {
                        !name.eq_ignore_ascii_case("authorization")
                            && self
                                .withheld
                                .iter()
                                .any(|carrier| carrier.eq_ignore_ascii_case(name))
                    }) =>
                {
                    tracing::info!(reason = TicketRefused::Ambiguous.reason(), "ticket refused");
                    return Err(DataRefused::Credential);
                }
                // The verifier refuses a ticket beside another `authorization` line itself.
                TicketPresented::Ticket(_) | TicketPresented::Ambiguous => {}
            }
            // The one place the ticket is spent. The verifier re-asks the issuer's standing and
            // answers the standing key.
            let judged = verifier
                .verify(&self.record, snapshot.headers(), snapshot.now_s())
                .await;
            binding.check_live().map_err(|_| DataRefused::Cancelled)?;
            match judged {
                TicketJudged::NoTicket => Ok(None),
                // The store could not answer: not a denial (503, never 401).
                TicketJudged::Refused(TicketRefused::Unavailable) => Err(DataRefused::Unavailable),
                TicketJudged::Refused(
                    TicketRefused::RouteTakesNoTicket
                    | TicketRefused::Ambiguous
                    | TicketRefused::Invalid
                    | TicketRefused::Expired
                    | TicketRefused::Replayed,
                ) => Err(DataRefused::Credential),
                TicketJudged::Admitted(verified) => {
                    // Admitted at this route's own plane instance, or not at all.
                    if verified.instance() != desk.instance() {
                        return Err(DataRefused::Binding);
                    }
                    Ok(Some(
                        self.owners.chain.ticket_identity(cx, snapshot, &verified),
                    ))
                }
            }
        }
        .await;
        match judged {
            Ok(Some(prepared)) => TicketStep::Judged(Ok(PendingData {
                preparation,
                route: self.clone(),
                selected: None,
                prepared,
                // A ticket is not a token: no audience scope of a minted token is asked of it.
                minted_here: false,
                deadline: cx.deadline,
            })),
            Ok(None) if self.record.who.has(Who::PRINCIPAL) => TicketStep::Chain(preparation),
            // The record admits a ticket alone and none is presented: nobody verifies the caller.
            Ok(None) => TicketStep::Judged(Err(preparation_failed(
                preparation,
                self.clone(),
                None,
                None,
                DataRefused::Credential,
            ))),
            Err(reason) => TicketStep::Judged(Err(preparation_failed(
                preparation,
                self.clone(),
                None,
                None,
                reason,
            ))),
        }
    }
}

/// What a ticket route's first step leaves ([`NativeDataRoute::prepare_ticket`]).
enum TicketStep {
    /// No ticket is presented and the record also admits a principal: the route's chain judges
    /// the request, with the preparation it was not spent on.
    Chain(DataPreparation),
    /// The request was judged here: admitted by its ticket, or refused.
    Judged(Result<PendingData, DataPreparationFailed>),
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
    // A request a core ticket admitted: the issuer's key, already judged as it stands now by the
    // ticket verifier, judged again here at the gate's own reading. No role binding grants it
    // anything, and it is never the anonymous principal.
    if let Some(key) = prepared.ticket_key() {
        return if key.deleted_at.is_some()
            || key.expires_at.is_some_and(|until| now >= until)
            || !key.enabled
        {
            Err(DataRefused::Policy)
        } else {
            Ok(Arc::clone(key))
        };
    }
    // The anonymous principal exists only on a chain that names `anonymous`.
    if prepared.is_anonymous() && !chain.admits_anonymous() {
        return Err(DataRefused::Binding);
    }
    // A caller whose core-signed token `keys` verified is admitted as that token's own key, as
    // it stands now (unexpired, its audience this route's, not revoked, held, rotated, deleted
    // or disabled): no role binding grants it anything. It exists only on a chain naming `keys`.
    if let Some(core) = prepared.core_key() {
        if !chain.admits_keys() {
            return Err(DataRefused::Binding);
        }
        return core.standing_in(app, now);
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
/// before any verifier runs, exactly as the request path it replaces judged it (`auth/mod.rs`,
/// the `audience::Binding` match): a bearer must be bound to this plane. A JWT whose `aud` names
/// the plane goes on to the chain, which still verifies it. A JWT minted for another resource or
/// for none, and a credential that states no audience at all (an opaque key), are refused as any
/// bad credential is: on an audience-bound plane an unbound credential is never enough. A token
/// core minted is judged by its verifier, which has the signature and the claims. Every
/// carrier the chain reads is scanned, as the request path judged its carried credential
/// (`auth::carried_credential`): the bearer on `authorization`, and the value of every header a
/// chain instance declares (D_CRED_HEADER), so a plain key or a foreign token is never admitted
/// by moving it to another carrier. Every occurrence is scanned, not a decoy first one.
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
                let name = field.name.get();
                let token = if name.eq_ignore_ascii_case("authorization") {
                    let Ok(value) = std::str::from_utf8(field.value.get()) else {
                        continue;
                    };
                    let Some((scheme, token)) = value.split_once(' ') else {
                        continue;
                    };
                    if !scheme.eq_ignore_ascii_case("Bearer") {
                        continue;
                    }
                    token
                } else if chain.reads_header(name) {
                    // An empty line presents nothing; a value that is not text states no
                    // audience at all.
                    if field.value.get().is_empty() {
                        continue;
                    }
                    let Ok(value) = std::str::from_utf8(field.value.get()) else {
                        return Err(DataRefused::Credential);
                    };
                    value
                } else {
                    continue;
                };
                match super::audience::inspect_bearer(token.trim(), audience) {
                    super::audience::Binding::Mismatch | super::audience::Binding::Opaque => {
                        return Err(DataRefused::Credential)
                    }
                    super::audience::Binding::Bound | super::audience::Binding::Deferred => {}
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
/// decoy first bearer. The upgrade route, the unrouted judgement, a keyed core route, and a DATA
/// route whose chain does not name `keys` run this scan on a head with no proven DPoP
/// presentation ([`judge_sender`]); a DATA route whose chain names `keys`
/// runs [`refuse_sender_bound`] and hands a core-signed token to core's own verifier
/// (`native_keys::judge`), never to an instance.
pub(crate) fn refuse_bound_carriers(
    snapshot: &crate::inbound::request_snapshot::ChargedRequestSnapshot,
    chain: &NativeChain,
    cred_header: Option<&str>,
) -> Result<(), DataRefused> {
    scan_bound_carriers(snapshot, chain, cred_header, true)
}

/// The sender constraint of one request (RFC 9449, `native_dpop::judge`), judged the one way at
/// every native site a chain verifies a head on: a plane's data and upgrade routes, the unrouted
/// judgement and a keyed core route. A bound token presented as a bearer is refused; a DPoP
/// presentation goes on only when its proof of possession is proven for this request at
/// `proof_url` (the origin of the URL the request was received at, and the path as received), and
/// then as the head's one credential, restated as a bearer; an unbound head is scanned by
/// [`refuse_sender_bound`] where `core_tokens_verified` (the caller hands a core-signed token to
/// core's own verifier, `native_keys::judge`), else by [`refuse_bound_carriers`]. A
/// sender-constrained presentation is never accepted unproven. Answers the head everything after
/// judges.
pub(crate) async fn judge_sender(
    app: &App,
    snapshot: Arc<crate::inbound::request_snapshot::ChargedRequestSnapshot>,
    chain: &NativeChain,
    cred_header: Option<&str>,
    proof_url: Option<&str>,
    core_tokens_verified: bool,
) -> Result<Arc<crate::inbound::request_snapshot::ChargedRequestSnapshot>, DataRefused> {
    match super::native_dpop::judge(app, snapshot, chain, cred_header, proof_url).await? {
        super::native_dpop::Sender::Proven(proven) => Ok(proven),
        super::native_dpop::Sender::Unconstrained(snapshot) => {
            if core_tokens_verified {
                refuse_sender_bound(&snapshot, chain, cred_header)?;
            } else {
                refuse_bound_carriers(&snapshot, chain, cred_header)?;
            }
            Ok(snapshot)
        }
    }
}

/// [`refuse_bound_carriers`] without its refusal of a core-signed token: every sender-constrained
/// presentation (the `DPoP` scheme, a token carrying `cnf.jkt`) is still refused, on every
/// occurrence of every carrier. Only a data route's preparation proves a DPoP proof (`native_dpop`);
/// a presentation that reaches this check unproven is never accepted.
pub(crate) fn refuse_sender_bound(
    snapshot: &crate::inbound::request_snapshot::ChargedRequestSnapshot,
    chain: &NativeChain,
    cred_header: Option<&str>,
) -> Result<(), DataRefused> {
    scan_bound_carriers(snapshot, chain, cred_header, false)
}

fn scan_bound_carriers(
    snapshot: &crate::inbound::request_snapshot::ChargedRequestSnapshot,
    chain: &NativeChain,
    cred_header: Option<&str>,
    refuse_core_signed: bool,
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
                    || (refuse_core_signed
                        && token.starts_with(crate::governance::signing::TOKEN_PREFIX))
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
    /// The credential is this engine's own: a core-signed token `keys` verified, or an access
    /// token this deployment's authorization server still holds for the route's audience.
    minted_here: bool,
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
            // An upgrade request core refuses before any 101 (`listener_native_upgrade.rs`).
            Refusal::NotAnUpgrade => DataRefused::NotAnUpgrade,
            Refusal::NoUpgradeTransport => DataRefused::NoUpgradeTransport,
            // A head screened as presenting no credential that its chain nevertheless verified:
            // the screen was wrong, the body is gone, and a caller with a good credential must
            // not be told it is bad. The engine's fault: the request is cancelled, and it says so.
            Refusal::Unverified { .. } => {
                tracing::error!(
                    "a request answered on its head as unverifiable was then verified by its \
                     chain; cancelled"
                );
                DataRefused::Binding
            }
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
                    // An engine-minted token on an audience-bound plane must carry the scope
                    // the route's record requires: a restricted key with no grant of any kind
                    // the record names is refused here (403), before the plane is asked. The
                    // names it may use are still judged by the selection and the walk.
                    if self.minted_here
                        && self.route.audience.is_some()
                        && !super::native_keys::holds_record_scope(&self.route.record, &resolved)
                    {
                        refused = DataRefused::Scope;
                        return Err(DataRefused::Scope);
                    }
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
        // Issuance is an authenticated act: from here until this authorization is dropped (the
        // end of the request's serve) a ticket its plane mints for this subject is bound to this
        // key. Only a principal its route's chain verified is entered. A request a ticket
        // admitted is not (a ticket never mints the next one), nor is the anonymous principal
        // (every caller of an open relay shares it: a ticket for it would name nobody).
        let issuing = self
            .route
            .ticket
            .as_ref()
            .filter(|_| self.prepared.ticket_key().is_none() && !self.prepared.is_anonymous())
            .map(|desk| desk.serving(self.prepared.identity().subject(), &key));
        Ok(DataAuthorization {
            _issuing: issuing,
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
    /// The principal's entry in its plane instance's ticket desk, held for the life of the
    /// request; `None` where no ticket store is open, and for a request that may not have a
    /// ticket minted for it ([`PendingData::complete`]).
    _issuing: Option<Serving>,
}
impl DataAuthorization {
    /// The record the plane stored with the ticket that admitted this request (empty when it
    /// stored none); `None` when a principal's credential did, not a ticket.
    pub fn ticket_record(&self) -> Option<&[u8]> {
        self.prepared.ticket_record()
    }

    /// Whether this authorization was made on `route` of `driver`'s plane instance.
    pub(crate) fn made_on(
        &self,
        driver: &crate::plane_driver::port::PortDriver,
        route: u32,
    ) -> bool {
        self.route.caller.same_incarnation(driver.caller())
            && self.route.binding.line().route.rung == route
    }

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

/// Who presented a request on a core route or on no route: the engine's own token judged by the
/// engine (`keys`, under this generation's governance, bound to no audience: a core route is bound
/// to none), exactly as a data route judges it, else the chain's instances. A key the operator
/// minted is the same caller on `/stats`, on an unknown path and on a plane's route.
async fn core_or_chain(
    app: &App,
    chain: &Arc<NativeChain>,
    cx: CallCx,
    snapshot: Arc<crate::inbound::request_snapshot::ChargedRequestSnapshot>,
) -> Result<NativePreparedAnswer, DataRefused> {
    let now = snapshot.now_s();
    if let Some(core) =
        super::native_keys::judge(&snapshot, chain, None, app.governance.as_deref(), None, now)?
    {
        return Ok(NativePreparedAnswer::Identity(
            chain.core_identity(cx, snapshot, core),
        ));
    }
    chain
        .prepare_snapshot(cx, snapshot)
        .await
        .map_err(|_| DataRefused::Unavailable)
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
    // A DPoP proof here names core's public URL: no plane's route matched.
    let snapshot = match judge_sender(
        app,
        snapshot,
        chain,
        None,
        app.public_url.as_deref(),
        chain.admits_keys(),
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(DataRefused::Unavailable) => return (Some(Verified::Unavailable), None),
        Err(_) => return (Some(Verified::Denied), None),
    };
    let prepared = match core_or_chain(app, chain, cx, snapshot).await {
        Ok(NativePreparedAnswer::Identity(prepared)) => prepared,
        Err(DataRefused::Unavailable | DataRefused::Capacity) => {
            return (Some(Verified::Unavailable), None)
        }
        Ok(_) | Err(_) => return (Some(Verified::Denied), None),
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
    /// The request selected no resource. One that did runs under its descriptor's authority
    /// alone: no hook is run for it, before its money or after.
    hooks: bool,
    /// A verified request that opens no unit: where its hooks' records are kept. `None` for a
    /// request that opens one (its refusal custody or its journal keeps them).
    records: Option<Arc<crate::plane_driver::port_hooks::HookRecords>>,
}
impl NativeDataEffectGate {
    fn new(binding: Arc<RequestBinding>, deadline: Instant, hooks: bool) -> Self {
        Self {
            binding,
            deadline,
            ready: AtomicBool::new(false),
            hooks,
            records: None,
        }
    }
    /// The gate of a verified request that opens no unit ([`UnbilledInvocation`]). It is never
    /// made ready, so no effect is ever allowed under it; its hooks are heard while the
    /// physical request is live and inside `deadline`, and their records are kept in `records`.
    fn unbilled(
        binding: Arc<RequestBinding>,
        deadline: Instant,
        records: Arc<crate::plane_driver::port_hooks::HookRecords>,
    ) -> Self {
        Self {
            binding,
            deadline,
            ready: AtomicBool::new(false),
            hooks: true,
            records: Some(records),
        }
    }
    pub(crate) fn records(&self) -> Option<Arc<crate::plane_driver::port_hooks::HookRecords>> {
        self.records.clone()
    }
    pub(crate) fn effects_allowed(&self) -> bool {
        self.ready.load(Ordering::Acquire)
            && Instant::now() < self.deadline
            && self.binding.check_executing().is_ok()
    }
    /// Whether core may call the route's hooks for this request
    /// ([`InvocationContext::hooks_allowed`], which has already judged the request's phase).
    /// `before_money`: the walk is resolved and the money not yet asked, so the physical
    /// execution transition has not happened: the request must still be live and inside its
    /// deadline. After money, a hook is heard exactly while effects are.
    pub(crate) fn hooks_allowed(&self, before_money: bool) -> bool {
        self.hooks
            && if before_money {
                self.binding
                    .check_live_now()
                    .is_ok_and(|live_at| live_at < self.deadline)
            } else {
                self.effects_allowed()
            }
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

/// One verified request on a route that opens no unit, registered so the route's hooks have a
/// request to run under ([`NativeDataRoute::hook_invocation`]). Dropping it ends the
/// registration: no hook is heard under it afterwards. It holds no money and opens nothing.
pub struct UnbilledInvocation {
    registration: Registration,
    records: Arc<crate::plane_driver::port_hooks::HookRecords>,
}
impl UnbilledInvocation {
    /// The session's invocation (`ServeIn::invocation`).
    pub fn context(&self) -> &InvocationContext {
        &self.registration.context
    }
    /// The records of the hooks that ran for this request, in the order they ran: what its
    /// audit record names its hooks from. No unit holds them.
    pub fn hooks(&self) -> Vec<busbar_kernel_audit::record::HookApplied> {
        self.records.rows()
    }
    /// The hook that refused the request, by its configured name; `None` when no hook did.
    pub fn refused_by(&self) -> Option<busbar_contract::kept::Text> {
        self.records.refused_by()
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
            authorization.selected.is_none(),
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
    /// The records of the hooks that ran for the refused request, the refusing hook's among
    /// them ([`NativeDataPending::take_refusal`]). Held by the refusal itself: no unit opened.
    hooks: Vec<busbar_kernel_audit::record::HookApplied>,
}
impl DataRefusalCustody {
    /// The hooks that ran for the refused request, in the order they ran.
    pub(crate) fn hooks(&self) -> &[busbar_kernel_audit::record::HookApplied] {
        &self.hooks
    }

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
        drop(custody);
        // The records of the hooks that ran before the refusal, the refusing hook's among them.
        // The stage held them for a unit that never opened; the refusal takes them, once, and
        // the request's own audit record is written from them: handed to the node's journal
        // under the number the request is registered and recorded under (no unit is opened for
        // it and none is needed), and kept on the refusal.
        let hooks = self.audit.take_hook_records();
        if !hooks.is_empty() {
            if let Some(journal) = self.pending.journal() {
                journal.hooks_ran(&crate::plane_driver::HooksRan {
                    unit: busbar_contract::UnitKey::new(self.context.unit()),
                    hooks: &hooks,
                });
            }
        }
        Ok((
            bundle.physical,
            DataRefusalCustody {
                authorization: bundle.authorization,
                _registration: bundle.registration,
                hooks,
            },
        ))
    }

    /// Where the hook stage of this request puts its records when the request is refused
    /// before its unit opens: the request's own audit custody. [`Self::take_refusal`] takes
    /// them from it.
    pub(crate) fn refusal_records(&self) -> Arc<crate::plane_driver::port_hooks::HookRecords> {
        self.audit.hook_records()
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
    /// The class the request is handed to its plane as (`PlaneReq.auth`): `AUTH_TICKET` where a
    /// core ticket admitted it, else `AUTH_PRINCIPAL`.
    pub(crate) fn auth_class(&self) -> u32 {
        auth_class(self.prepared.ticket_record().is_some())
    }
    /// `PlaneReq.ticket_record`: the record the plane stored with the ticket that admitted this
    /// request; empty when it stored none or no ticket did.
    pub(crate) fn ticket_record(&self) -> &[u8] {
        self.prepared.ticket_record().unwrap_or_default()
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

/// Verify the caller of a core route that requires a key (`/stats`, a plugin's own keyed route)
/// with the data chain: the credential on the head, the key the identity earns valid now, the
/// replay claim. The same three steps a plane's principal route runs; no plane, no selection, no
/// unit.
pub async fn verify_core_key(
    chain: &Arc<NativeChain>,
    binding: &Arc<RequestBinding>,
    cx: CallCx,
) -> Result<crate::inbound::native::CoreKeyAuthorization, DataRefused> {
    let live_at = binding
        .check_live_now()
        .map_err(|_| DataRefused::Cancelled)?;
    if !chain.is_data()
        || cx.request_id != binding.invocation().request_id().get()
        || binding.deadline().is_some_and(|at| cx.deadline > at)
        || live_at >= cx.deadline
    {
        return Err(DataRefused::Binding);
    }
    let snapshot = binding.snapshot().map_err(|_| DataRefused::Capacity)?;
    // A core route's DPoP proof names core's public URL.
    let app = binding.app();
    let snapshot = judge_sender(
        app,
        snapshot,
        chain,
        None,
        app.public_url.as_deref(),
        chain.admits_keys(),
    )
    .await?;
    let prepared = match core_or_chain(app, chain, cx, snapshot).await? {
        NativePreparedAnswer::Identity(prepared) => prepared,
        _ => return Err(DataRefused::Credential),
    };
    binding.check_live().map_err(|_| DataRefused::Cancelled)?;
    let mut key = None;
    let mut refused = DataRefused::Policy;
    let lease = binding
        .handle()
        .admit_current(binding.app(), binding.invocation(), |app| {
            let now = crate::store::now();
            prepared.fresh(now).map_err(|_| DataRefused::Policy)?;
            if !prepared.belongs_to(chain)
                || app.config_generation.load(Ordering::Acquire) != chain.epoch()
            {
                refused = DataRefused::Binding;
                return Err(DataRefused::Binding);
            }
            key = Some(
                governed_key(app, &prepared, chain, now).inspect_err(|reason| refused = *reason)?,
            );
            Ok(())
        })
        .map_err(|_| refused)?;
    match prepared.claim_classified().await {
        super::native_admin::NativeReplayClaim::Claimed => {}
        super::native_admin::NativeReplayClaim::Duplicate => return Err(DataRefused::Replay),
        super::native_admin::NativeReplayClaim::Unknown(_) => return Err(DataRefused::Unavailable),
        super::native_admin::NativeReplayClaim::Inconsistent => return Err(DataRefused::Binding),
    }
    binding.check_live().map_err(|_| DataRefused::Cancelled)?;
    Ok(crate::inbound::native::CoreKeyAuthorization::new(
        Arc::clone(binding),
        key.ok_or(DataRefused::Policy)?,
        lease,
    ))
}

#[cfg(test)]
#[path = "tests/native_data_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/native_data_hooks_tests.rs"]
mod hooks_tests;
