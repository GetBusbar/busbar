// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native children use the selected immutable route table, checked invocation owner and the
//! parent's actual money admission. No credential or spent ticket is copied to a child.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use busbar_contract::UnitKey;
use busbar_kernel::guest::{Claimant, GuestList, Matched};
use busbar_kernel::host_services::{InvocationContext, KernelServices, Nest, NestReply};
use busbar_kernel::host_units::UnitRecord;
use busbar_kernel::plane_driver::port::{HttpHead, HttpIn, ServeIn, Served};
use busbar_kernel::plane_driver::port_auth::{Credentials, Principal, Subject};
use busbar_kernel::plane_driver::port_billing::{end_of, PortBilling};
use busbar_kernel::plane_driver::port_session::{ClientSink, ToClient};
use busbar_kernel::plane_driver::HeadFields;

use super::{DispatchSnapshot, NEST_INPUT_FULL, NEST_PARENT_GONE, NEST_REPLY_MAX, NEST_UNREAD};

const CONSTRAINTS_UNAVAILABLE: &str = "native child target and spend constraints are not available";
const PARENT_ADMISSION: &str = "native child has no live parent billing admission";

/// Built once before the serving generation is published. The same guest precedence rules
/// choose native, legacy and core claims; matching a core claim never falls through to a plane.
pub(crate) struct NativeNests {
    pub(crate) guests: GuestList,
    pub(crate) destinations: BTreeMap<(String, u32), usize>,
}

impl NativeNests {
    fn selected(&self, method: &str, target: &str) -> Option<(usize, u32)> {
        let path = target.split('?').next().unwrap_or_default();
        let Matched::Line(line) = self.guests.matched(method, path, &[]) else {
            return None;
        };
        let Claimant::Plane(instance) = &line.claimant else {
            return None;
        };
        self.destinations
            .get(&(instance.clone(), line.route.rung))
            .map(|seat| (*seat, line.route.rung))
    }

    /// `None` means this table selected no native destination; the existing legacy dispatcher
    /// may resolve its own claim. Every selected native refusal is terminal, with no fallback.
    pub(crate) async fn dispatch(
        &self,
        snapshot: Arc<DispatchSnapshot>,
        context: &InvocationContext,
        nest: &Nest,
    ) -> Option<NestReply> {
        let (seat, route) = self.selected(&nest.ask.verb, &nest.ask.target)?;
        Some(Self::run(snapshot, context, nest, seat, route).await)
    }

    async fn run(
        snapshot: Arc<DispatchSnapshot>,
        context: &InvocationContext,
        nest: &Nest,
        seat: usize,
        route: u32,
    ) -> NestReply {
        let seat = &snapshot.served.ports[seat];
        let core = context.generation().core();
        let parent_owned = snapshot
            .served
            .ports
            .iter()
            .any(|parent| context.accepts(parent.driver.caller()));
        if context.unit() != nest.parent || !parent_owned || !Arc::ptr_eq(core, seat.driver.core())
        {
            return NestReply::Unserved(NEST_PARENT_GONE);
        }
        let Some(parent) = core.units().get(nest.parent) else {
            return NestReply::Unserved(NEST_PARENT_GONE);
        };
        let Some(key) = parent.principal.as_ref() else {
            return NestReply::Unserved(PARENT_ADMISSION);
        };
        if nest.depth != parent.depth.saturating_add(1)
            || !nest
                .principal
                .as_ref()
                .is_some_and(|claimed| Arc::ptr_eq(key, claimed))
        {
            return NestReply::Unserved(NEST_PARENT_GONE);
        }
        let Some(frame) = snapshot
            .frames
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&nest.parent)
            .cloned()
        else {
            return NestReply::Unserved(NEST_PARENT_GONE);
        };
        // PortUpstream currently has no checked target-binding/spend-cap input. Never turn a
        // configured hook grant into an unconstrained ordinary request or try legacy fallback.
        if nest.constraints.is_some() {
            return NestReply::Unserved(CONSTRAINTS_UNAVAILABLE);
        }
        let Some(billing) = &snapshot.served.billing else {
            return NestReply::Unserved(PARENT_ADMISSION);
        };
        let request = frame.request.clone();
        // This is an independent retained input copy. Reserve from the same admitted
        // request before allocating, and let its Bytes backing own the credit thereafter.
        let body = match request.copy_input(&nest.ask.body) {
            Ok(body) => body.into_bytes(),
            Err(_) => return NestReply::Unserved(NEST_INPUT_FULL),
        };
        let unit = match billing.child(
            UnitKey::new(nest.parent),
            key,
            &seat.instance,
            seat.driver.usage_classes(),
        ) {
            Ok(unit) => unit,
            Err(_) => return NestReply::Unserved(PARENT_ADMISSION),
        };
        let id = unit.ctx.key;
        let reply = Arc::new(Reply {
            state: Mutex::new(ReplyState::default()),
            bound: NEST_REPLY_MAX,
            owner: Some(Child {
                snapshot: Arc::clone(&snapshot),
                core: Arc::clone(core),
                billing: billing.clone(),
                id,
            }),
        });
        core.units().admitted_for(
            id.get(),
            seat.driver.caller(),
            UnitRecord {
                principal: Some(Arc::clone(key)),
                depth: nest.depth,
            },
        );
        core.units()
            .set_child_ancestry(id.get(), nest.ancestry.clone());
        core.units().ticketed(id.get(), None);
        snapshot
            .frames
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.get(), frame);
        let invocation = match seat
            .driver
            .invocation(Arc::clone(context.generation()), id.get())
        {
            Ok(invocation) => invocation,
            Err(why) => return NestReply::Unserved(why),
        };
        let (path, query) = nest
            .ask
            .target
            .split_once('?')
            .unwrap_or((&nest.ask.target, ""));
        // A dropped waiter cannot assert that no work ran on the blocking session. Only an
        // explicit admission refusal below establishes the unspent result.
        reply
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ran = true;
        let result = seat
            .driver
            .serve(ServeIn {
                request,
                admission: None,
                invocation: Some(invocation),
                route,
                http: HttpIn::new(
                    HttpHead::Text {
                        method: nest.ask.verb.clone(),
                        path: path.into(),
                        query: query.into(),
                        headers: Vec::new(),
                    },
                    body,
                    id.get(),
                ),
                creds: Credentials {
                    bearer: None,
                    principal: Principal::Verified(Subject::Key(Arc::clone(key))),
                    operator: false,
                    signed: None,
                },
                audience: seat.audience.as_deref().unwrap_or_default(),
                now_s: busbar_kernel::store::now(),
                unit: Some(unit),
                upstream: seat.upstream.clone(),
                client: Some(Arc::clone(&reply) as Arc<dyn ClientSink>),
                carrier: seat.carrier.clone(),
                intents: Arc::clone(&seat.intents),
                models: Vec::new(),
            })
            .await;
        match result {
            Ok(Served::Refused(items)) => {
                reply
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .ran = false;
                reply.items(items.items);
            }
            Ok(Served::Ran(ran)) => {
                reply.items(ran.client);
            }
            Err(_) => return NestReply::Failed(NEST_UNREAD),
        }
        reply.answer()
    }
}

struct Child {
    snapshot: Arc<DispatchSnapshot>,
    core: Arc<KernelServices>,
    billing: PortBilling,
    id: UnitKey,
}

/// The sink owns the child registration and settlement, including while a detached blocking
/// port task outlives its awaiting future. Dropping the waiter cannot retire active authority.
struct Reply {
    state: Mutex<ReplyState>,
    bound: usize,
    owner: Option<Child>,
}

#[derive(Default)]
struct ReplyState {
    head: Option<(u16, HeadFields)>,
    body: Vec<u8>,
    held: usize,
    overflow: bool,
    ran: bool,
}

impl ClientSink for Reply {
    fn items(&self, items: Vec<ToClient>) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.overflow {
            return false;
        }
        for item in items {
            let size = match &item {
                ToClient::Head { fields, .. } if state.head.is_none() => {
                    fields.iter().try_fold(0usize, |sum, (name, value)| {
                        sum.checked_add(name.len())?.checked_add(value.len())
                    })
                }
                ToClient::Body(bytes) | ToClient::Msg { bytes, .. } => Some(bytes.len()),
                _ => Some(0),
            };
            let Some(held) = size
                .and_then(|n| state.held.checked_add(n))
                .filter(|n| *n <= self.bound)
            else {
                state.overflow = true;
                state.body.clear();
                state.head = None;
                return false;
            };
            state.held = held;
            match item {
                ToClient::Head { status, fields } => {
                    state.head.get_or_insert((status, fields));
                }
                ToClient::Body(bytes) | ToClient::Msg { bytes, .. } => state.body.extend(bytes),
                ToClient::Trailers(_) | ToClient::End => {}
            }
        }
        true
    }
}

impl Reply {
    fn answer(&self) -> NestReply {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.overflow {
            return NestReply::Failed(NEST_UNREAD);
        }
        let Some((status, fields)) = state.head.as_mut() else {
            return NestReply::Failed(NEST_UNREAD);
        };
        NestReply::Answered {
            status: u32::from(*status),
            fields: std::mem::take(fields),
            body: std::mem::take(&mut state.body),
        }
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let status = state.head.as_ref().map_or(502, |(status, _)| *status);
            owner
                .billing
                .settle(owner.id, end_of(u32::from(status), state.ran));
            owner.core.units().ended(owner.id.get());
            owner
                .snapshot
                .frames
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&owner.id.get());
        }
    }
}

#[cfg(test)]
#[path = "tests/native_nests.rs"]
mod tests;
