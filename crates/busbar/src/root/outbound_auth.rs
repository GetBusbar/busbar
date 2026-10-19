// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND HALF OF THE HOST AUTH HANDLE, COMPOSED (`BUSBAR-1.6.0.md` THE DESIGN §6, "Auth
//! points and guest lists", items 5 and 7; §11.6; the coordinator's ruling: ONE host auth handle,
//! ONE `auth.call` for both directions).
//!
//! Each member's binding (the auth instance serving its style and the handle `open_outbound`
//! answered) is held here under a binding id, by the plane instance, the need and the
//! registration it serves ([`OutboundBindings::register`], at each generation's egress seal). Two
//! seams are armed with it at boot ([`arm`]):
//!
//! * the connector's [`BindingRefs`]: a dial naming a registration begins its framing with that
//!   registration's binding, its handle MINTED for the framer that presents it (owner-scoped and
//!   generation-scoped, `auth_handle::mint_auth_ref`) and the points its style needs;
//! * the loader's [`OutboundServer`]: the framer's `auth.call` on that handle is served here. The
//!   unit it presents is verified against the unit's own secret; the binding's handle for the
//!   unit's live attempt, the plane's scope, a passthrough member's lent credential and the
//!   plane's waiver are read from the unit's record (`plane_driver::attempt_auth`), never from the
//!   transport; and the binding's auth is called with the head the framer is about to encode. Its
//!   lines go back to the framer; the verdict and the secrets do not.
//!
//! THE KERNEL MAKES NO OUTBOUND AUTH CALL; the root composes the kernel's record with the loader's
//! handle, so no kernel-to-loader edge is added. Binding ids carry [`OUTBOUND_ID`], so an outbound
//! binding's id is never an inbound line's.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use busbar_contract::abi::auth::{AuthPoint, FIELD_SENSITIVE, STYLE_NEEDS_HEADERS};
use busbar_contract::abi::host::service::{UnitRef, LINE_NONE};
use busbar_contract::auth_calls::{Fields, FieldsRequest};
use busbar_contract::conn::{InstanceId, NeedId};
use busbar_core_connector::framer::{AuthBinding as FramerBinding, BindingRefs};
use busbar_kernel::plane_driver::attempt_auth::{self, AttemptAuth, AuthOutcome};
use busbar_kernel::plane_driver::AuthBinding;

use crate::root::loader::dispatch::auth_handle;
use crate::root::loader::dispatch::auth_serve::{
    Answer, AuthAsk, AuthServed, OutboundServer, OwnRequest, ServedField, Wiped, OUTBOUND_REFUSED,
};

/// The tag every outbound binding id carries (its top bit: the loader's `RefSpace::Binding`, one
/// allocator for both spaces): an inbound line's id never does.
pub const OUTBOUND_ID: u64 = 1 << 63;

/// The tag every plugin-own request unit carries ([`OutboundServer::record_request`]): a kernel
/// unit key never does, so a request unit never names a unit's walk.
pub const OWN_REQUEST: u64 = 1 << 62;

/// The words of a call whose unit is not one the host handed the calling framer for this binding.
pub const UNIT_NOT_HANDED: &str =
    "the unit is not one the host handed this caller for this binding";
/// The words of a call the binding's auth could not answer.
pub const AUTH_COULD_NOT_ANSWER: &str = "the binding's auth could not answer";

/// One binding as the root holds it: who it serves and the kernel's binding.
#[derive(Clone)]
struct Held {
    member: String,
    binding: AuthBinding,
}

/// THE PROCESS'S OUTBOUND BINDINGS, by id and by (plane instance, need, registration).
#[derive(Default)]
pub struct OutboundBindings {
    by_member: Mutex<HashMap<(InstanceId, NeedId, String), u64>>,
    by_id: Mutex<HashMap<u64, Held>>,
    /// The next plugin-own request unit.
    requests: AtomicU64,
}

impl std::fmt::Debug for OutboundBindings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundBindings").finish_non_exhaustive()
    }
}

impl OutboundBindings {
    /// Hold `binding` as the one `caller`'s dials on `need` to `member` begin with, replacing the
    /// one it held: the id stays the registration's across generations (a ref of an older
    /// generation still verifies for none). Its id.
    pub fn register(
        &self,
        caller: InstanceId,
        need: NeedId,
        member: &str,
        binding: &AuthBinding,
    ) -> u64 {
        let key = (caller, need, member.to_owned());
        let id = *self
            .by_member
            .lock()
            .expect("bindings")
            .entry(key)
            .or_insert_with(|| auth_handle::next_ref_id(auth_handle::RefSpace::Binding));
        self.by_id.lock().expect("bindings").insert(
            id,
            Held {
                member: member.to_owned(),
                binding: binding.clone(),
            },
        );
        id
    }

    /// Hold `route`'s binding (when it has one) for every need the route rides: its own and each
    /// beside it, under the registration it serves.
    pub fn register_route(
        &self,
        caller: InstanceId,
        route: &busbar_kernel::plane_driver::MemberRoute,
    ) {
        let Some(binding) = route.auth.as_ref() else {
            return;
        };
        for need in std::iter::once(route.need).chain(route.rides.iter().map(|(n, _)| *n)) {
            self.register(caller, need, &route.provider, binding);
        }
    }

    fn held(&self, id: u64) -> Option<Held> {
        self.by_id.lock().expect("bindings").get(&id).cloned()
    }
}

impl BindingRefs for OutboundBindings {
    fn binding(
        &self,
        owner: u64,
        caller: InstanceId,
        need: NeedId,
        member: &str,
    ) -> Option<FramerBinding> {
        let id =
            *self
                .by_member
                .lock()
                .expect("bindings")
                .get(&(caller, need, member.to_owned()))?;
        let held = self.held(id)?;
        let points = held.binding.points.bits();
        if points == 0 {
            return None;
        }
        let auth = auth_handle::mint_auth_ref(owner, auth_handle::generation(), id)?;
        Some(FramerBinding {
            auth,
            points,
            line_points: 0,
        })
    }

    /// The unit `unit`'s ref, minted for the framer `owner` (what the host hands the framer with
    /// the unit's request, for it to present on its `auth.call`); `None` for a unit with no live
    /// attempt record.
    fn unit_ref(&self, owner: u64, unit: u64) -> Option<UnitRef> {
        let record = attempt_auth::of(unit)?;
        auth_handle::mint_unit_ref(
            record.secret,
            auth_handle::generation(),
            owner,
            LINE_NONE,
            unit,
        )
    }
}

/// The auth's answer, as the framer is handed it.
fn served(unit: UnitRef, answer: Fields) -> AuthServed {
    match answer {
        Fields::Ready(fields) => AuthServed::Fields {
            unit,
            fields: fields
                .into_iter()
                .map(|f| ServedField {
                    value: Wiped(f.value.expose(&busbar_kernel::seal::lend()).clone()),
                    name: f.name,
                    flags: if f.sensitive { FIELD_SENSITIVE } else { 0 },
                })
                .collect(),
        },
        Fields::Refused => AuthServed::Refused(OUTBOUND_REFUSED),
        Fields::Failed => AuthServed::Failed(AUTH_COULD_NOT_ANSWER),
    }
}

/// Book the auth's `answer` on `unit`'s record: a refusal or a failure is the attempt's auth
/// outcome (never the destination's failure); lines clear a wait.
fn book(unit: u64, answer: &Fields) {
    match answer {
        Fields::Ready(_) => attempt_auth::clear(unit),
        Fields::Refused => attempt_auth::mark(unit, AuthOutcome::Refused),
        Fields::Failed => attempt_auth::mark(unit, AuthOutcome::Failed),
    }
}

/// The wall clock's whole seconds, for a signing style's timestamp.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl OutboundServer for OutboundBindings {
    fn serves(&self, _owner: u64, binding: u64) -> bool {
        binding & OUTBOUND_ID != 0 && self.by_id.lock().expect("bindings").contains_key(&binding)
    }

    fn serve(&self, ask: AuthAsk, later: Option<Answer>) -> Option<AuthServed> {
        let Some(held) = self.held(ask.binding) else {
            return Some(AuthServed::Refused(UNIT_NOT_HANDED));
        };
        // THE UNIT, verified against its own secret for this caller: a unit of another request,
        // another owner or a forged one is refused, and so is a unit whose live attempt rides
        // another registration than the one this binding serves.
        let Some(record) = attempt_auth::of(ask.unit.id) else {
            return Some(AuthServed::Refused(UNIT_NOT_HANDED));
        };
        let verified = auth_handle::verify_unit_ref(
            record.secret,
            auth_handle::generation(),
            ask.owner,
            LINE_NONE,
            &ask.unit,
        );
        if verified.is_err() || record.member != held.member {
            return Some(AuthServed::Refused(UNIT_NOT_HANDED));
        }
        // THE PLANE'S WAIVER: no member auth for this request; the framer adds no line.
        if record.waived {
            return Some(AuthServed::Fields {
                unit: ask.unit,
                fields: Vec::new(),
            });
        }
        let Some(point) = AuthPoint::from_bit(ask.point) else {
            return Some(AuthServed::Refused(UNIT_NOT_HANDED));
        };
        let binding = &held.binding;
        let request = FieldsRequest {
            point,
            conn: ask.conn,
            unit: ask.unit.id,
            body: ask.body,
            method: ask.method,
            authority: String::from_utf8_lossy(&ask.authority).into_owned(),
            path: ask.target,
            query: ask.query,
            timestamp: now_secs(),
            // The head the framer will encode, its own lines included: what a signing style
            // signs is what goes out (THE DESIGN section 6, step 5).
            headers: if binding.style_flags & STYLE_NEEDS_HEADERS != 0 {
                ask.fields
            } else {
                Vec::new()
            },
            caller_credential: record.caller_credential.clone(),
            extensions: record.extensions.clone(),
        };
        let unit = ask.unit;
        if let Some(answer) = binding.auth.fields_now(record.handle, &request) {
            book(unit.id, &answer);
            return Some(served(unit, answer));
        }
        // An auth that must wait (a token refreshing) answers when it is ready; the framer's op
        // pends meanwhile, and only its own stream is parked. Until it answers, the attempt is
        // waiting on its auth, never on the destination.
        let runtime = tokio::runtime::Handle::try_current().ok();
        let (Some(later), Some(runtime)) = (later, runtime) else {
            attempt_auth::mark(unit.id, AuthOutcome::Failed);
            return Some(AuthServed::Failed(AUTH_COULD_NOT_ANSWER));
        };
        attempt_auth::mark(unit.id, AuthOutcome::Waiting);
        let waiting = binding.auth.fields(record.handle, request, 0);
        runtime.spawn(async move {
            let answer = waiting.await;
            book(unit.id, &answer);
            later(served(unit, answer));
        });
        None
    }

    /// A plugin's own request to a member, recorded as a unit's attempt under a fresh request unit:
    /// the framer's call on the member's binding is served from it exactly as a walk's is.
    fn record_request(&self, request: OwnRequest) -> Option<u64> {
        let unit = OWN_REQUEST | (self.requests.fetch_add(1, Ordering::Relaxed) + 1);
        attempt_auth::record(
            unit,
            AttemptAuth {
                member: request.member,
                handle: request.handle,
                extensions: request.extensions,
                caller_credential: request.caller_credential,
                waived: request.waived,
                secret: [0, 0],
                outcome: None,
            },
        );
        attempt_auth::of(unit).map(|_| unit)
    }

    fn forget_request(&self, unit: u64) {
        if unit & OWN_REQUEST != 0 {
            attempt_auth::forget(unit);
        }
    }
}

/// The process's one.
pub fn process() -> &'static Arc<OutboundBindings> {
    static ONE: OnceLock<Arc<OutboundBindings>> = OnceLock::new();
    ONE.get_or_init(|| Arc::new(OutboundBindings::default()))
}

/// Arm `connector` with the process's bindings: every dial naming a registration begins with its
/// binding. The framers' `auth.call` on one is served by the dispatcher they load on, armed as it is
/// built ([`arm_dispatcher`]).
pub fn arm(connector: &busbar_core_connector::Connector) {
    connector.arm_bindings(Arc::clone(process()) as Arc<dyn BindingRefs>);
}

/// Arm `dispatcher` with the process's bindings: its instances' `auth.call` on an outbound
/// binding's ref is served here. Held by that dispatcher alone (no process-wide seam).
pub fn arm_dispatcher(dispatcher: &crate::root::loader::dispatch::Dispatcher) {
    dispatcher.arm_outbound(Arc::clone(process()) as Arc<dyn OutboundServer>);
}

#[cfg(test)]
#[path = "tests/outbound_auth.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/outbound_auth_wire.rs"]
mod wire_tests;
