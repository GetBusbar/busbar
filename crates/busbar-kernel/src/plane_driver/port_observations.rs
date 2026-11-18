// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The production [`UsageObservations`] (IF §12.4): OBS_SCOPE and OBSERVE of a plane's cross-request usage, over the
//! kernel's observation custody (`host_observations.rs`, `plane_driver/money/observations.rs`).
//!
//! Custody is a unit's: a scope is reserved against, attached to and closed on the money of one in-flight billed
//! request, under the operator's [`ObservationPolicy`]. The plane's calls carry the verified principal's identity
//! records and the instance's name, not the request, so the request that bills registers its unit here for as long
//! as it runs ([`ObsCustody::register`], released when the [`Registration`] drops) and a call reaches only a unit
//! registered by the same principal of the same instance. Nothing registered, or no unit that is unambiguously the
//! call's, answers `OBS_REFUSED`: a plane never learns whether another principal's scope exists.
//!
//! Several in-flight units of one principal of one instance are told apart by the scope the call names: the unit the
//! scope is attached to, else the one unit that has none attached. Two candidates and no way to tell them apart are
//! refused (fail closed) rather than guessed.

use std::borrow::Borrow;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, PoisonError};

use busbar_contract::UnitKey;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::plane::OBS_ACCEPTED;
use busbar_plugin_abi::plane::{
    OBS_ATTACH, OBS_CLOSE, OBS_CLOSED, OBS_CREATE, OBS_FINAL, OBS_PENDING, OBS_PROVISIONAL,
    OBS_READY, OBS_REFUSED,
};

use super::port_services::{ObservationIn, UsageObservations};
use super::port_work::subject_of;
use super::usage::scaled;
use super::{ObservationPolicy, ObservationRuntimeError, PlaneMoney};
use crate::host_services::WallMs;
use crate::persistence::observations::Error as StoreError;

/// The most units registered at once, across every instance. Every slot is made with the custody, at boot.
pub(crate) const MAX_UNITS: usize = 4_096;

/// No slot: the end of a principal's chain.
pub(crate) const NIL: u32 = u32::MAX;

/// One billed request's observation context: its money and unit, the operator's policy for the destination it was
/// routed to, and its declared class names (the index of a name is its class id). Every part is shared or a copy
/// type, so a call takes its own handle on the unit under the book's lock and lets the lock go before it awaits.
#[derive(Clone)]
pub struct ActiveUnit {
    pub money: Arc<PlaneMoney>,
    pub unit: UnitKey,
    pub policy: Arc<ObservationPolicy>,
    pub classes: Arc<[String]>,
}

/// A registered unit in its slot, chained to the next unit of the same principal.
pub(crate) struct Held {
    pub(crate) unit: ActiveUnit,
    pub(crate) next: u32,
}

/// A principal's (instance, subject) names as borrowed text, so a lookup needs no owned key.
pub(crate) trait Principal {
    fn names(&self) -> (&str, &str);
}

impl Principal for (Arc<str>, Arc<str>) {
    fn names(&self) -> (&str, &str) {
        (&self.0, &self.1)
    }
}

impl Principal for (&str, &str) {
    fn names(&self) -> (&str, &str) {
        (self.0, self.1)
    }
}

impl<'a> Borrow<dyn Principal + 'a> for (Arc<str>, Arc<str>) {
    fn borrow(&self) -> &(dyn Principal + 'a) {
        self
    }
}

impl PartialEq for dyn Principal + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.names() == other.names()
    }
}

impl Eq for dyn Principal + '_ {}

// Hashed as the owned tuple hashes: instance, then subject (`Arc<str>` hashes as its `str`).
impl Hash for dyn Principal + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.names().hash(state);
    }
}

/// A principal's first slot, by its (instance, subject) names, shared with the caller that registered it.
pub(crate) type ByPrincipal = foldhash::HashMap<(Arc<str>, Arc<str>), u32>;

/// Every slot, the free ones and the map's room are made at boot (`off_path::plane_port_observations`); a
/// registration claims a slot, a drop gives it back, and nothing here allocates, grows or shifts.
pub(crate) struct Book {
    pub(crate) slots: Vec<Option<Held>>,
    /// Slots no registration holds.
    pub(crate) free: Vec<u32>,
    pub(crate) by_principal: ByPrincipal,
}

impl Book {
    /// The units registered now.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    fn held(&self, slot: u32) -> Option<&Held> {
        self.slots.get(slot as usize)?.as_ref()
    }

    /// A principal's units in flight, newest first.
    fn chain(&self, first: u32) -> impl Iterator<Item = &ActiveUnit> {
        let mut at = first;
        std::iter::from_fn(move || {
            let held = self.held(at)?;
            at = held.next;
            Some(&held.unit)
        })
    }

    /// The unit a call of the principal whose chain starts at `first` is for: see the module docs.
    fn pick(&self, first: u32, scope: Option<[u8; 32]>) -> Option<&ActiveUnit> {
        let mut units = self.chain(first);
        let only = units.next()?;
        if units.next().is_none() {
            return Some(only);
        }
        if let Some(scope) = scope {
            if let Some(attached) = self
                .chain(first)
                .find(|c| c.money.observation_scope(c.unit) == Some(scope))
            {
                return Some(attached);
            }
        }
        let mut unattached = self
            .chain(first)
            .filter(|c| c.money.observation_scope(c.unit).is_none());
        match (unattached.next(), unattached.next()) {
            (Some(one), None) => Some(one),
            _ => None,
        }
    }

    /// Take `slot` out of the chain of the principal `key`, and give the slot back. The unit is handed out so the
    /// caller drops it after the lock.
    fn release(&mut self, key: &dyn Principal, slot: u32) -> Option<ActiveUnit> {
        let next = self.held(slot)?.next;
        let first = *self.by_principal.get(key)?;
        if first == slot {
            if next == NIL {
                self.by_principal.remove(key);
            } else if let Some(head) = self.by_principal.get_mut(key) {
                *head = next;
            }
        } else {
            // Bounded by the principal's own units in flight.
            let mut at = first;
            loop {
                let held = self.slots.get_mut(at as usize)?.as_mut()?;
                if held.next == slot {
                    held.next = next;
                    break;
                }
                at = held.next;
            }
        }
        let held = self.slots.get_mut(slot as usize)?.take()?;
        // `free` was made with room for every slot, and a slot is given back once.
        self.free.push(slot);
        Some(held.unit)
    }
}

/// The observation custody of every plane instance in the process. Clones share the registrations. Made at boot
/// (`off_path::plane_port_observations`).
#[derive(Clone)]
pub struct ObsCustody {
    pub(crate) book: Arc<Mutex<Book>>,
    pub(crate) wall_ms: WallMs,
}

/// A registered unit, released when this drops (the request ended: transient exchange custody only, never the
/// durable reservation).
#[must_use = "dropping a registration releases the unit"]
pub struct Registration {
    book: Arc<Mutex<Book>>,
    instance: Arc<str>,
    subject: Arc<str>,
    slot: u32,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let released = self
            .book
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .release(&(&*self.instance, &*self.subject), self.slot);
        drop(released);
    }
}

impl ObsCustody {
    /// Root-only activation, after admission and the verified destination selection: `subject` of plane `instance`
    /// has `unit` in flight. The caller hands the names it already shares; a registration keeps them, never a copy.
    ///
    /// # Errors
    /// The policy names another instance, the money has no observation store or does not serve the unit, or the
    /// process holds [`MAX_UNITS`] registrations.
    pub fn register(
        &self,
        instance: &Arc<str>,
        subject: &Arc<str>,
        unit: ActiveUnit,
    ) -> Result<Registration, &'static str> {
        const REFUSED: &str = "usage observation refused";
        if unit.policy.instance != **instance
            || !unit.money.observations_supported()
            || unit.money.serving(unit.unit).is_none()
        {
            return Err(REFUSED);
        }
        let mut book = self.book.lock().unwrap_or_else(PoisonError::into_inner);
        let book = &mut *book;
        let Some(slot) = book.free.pop() else {
            return Err(REFUSED);
        };
        let key: &dyn Principal = &(&**instance, &**subject);
        let next = match book.by_principal.get_mut(key) {
            Some(first) => std::mem::replace(first, slot),
            None => {
                // The map was made with room for twice every slot, so this insert never grows it.
                book.by_principal
                    .insert((Arc::clone(instance), Arc::clone(subject)), slot);
                NIL
            }
        };
        if let Some(free) = book.slots.get_mut(slot as usize) {
            *free = Some(Held { unit, next });
        }
        Ok(Registration {
            book: Arc::clone(&self.book),
            instance: Arc::clone(instance),
            subject: Arc::clone(subject),
            slot,
        })
    }

    /// The unit a call of `subject` on `instance` is for: see the module docs. The handle is taken under the lock
    /// (shared parts only) so the call holds no lock while it awaits the money.
    fn resolve(
        &self,
        instance: &str,
        identity: &[u8],
        scope: Option<[u8; 32]>,
    ) -> Option<ActiveUnit> {
        let subject = subject_of(identity)?;
        let book = self.book.lock().unwrap_or_else(PoisonError::into_inner);
        let first = *book
            .by_principal
            .get(&(instance, subject) as &dyn Principal)?;
        book.pick(first, scope).cloned()
    }
}

fn class_of(classes: &[String], name: &str) -> Option<u32> {
    classes
        .iter()
        .position(|class| class == name)
        .and_then(|at| u32::try_from(at).ok())
}

fn pending(error: &ObservationRuntimeError) -> bool {
    matches!(
        error,
        ObservationRuntimeError::Store(StoreError::Pending { .. })
    )
}

impl UsageObservations for ObsCustody {
    fn scope<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        principal: &'a [u8],
        op: u32,
        scope: Option<[u8; 32]>,
        require: &'a [&'a str],
    ) -> BoxFut<'a, (u32, Option<[u8; 32]>)> {
        Box::pin(async move {
            let Some(active) = self.resolve(plane.name, principal, scope) else {
                return (OBS_REFUSED, None);
            };
            let mut required = smallvec::SmallVec::<[u32; 8]>::new();
            for name in require {
                let Some(class) = class_of(&active.classes, name) else {
                    return (OBS_REFUSED, None);
                };
                required.push(class);
            }
            let (money, unit, policy) = (&active.money, active.unit, &active.policy);
            let result = async {
                let id = match op {
                    OBS_CREATE => {
                        // Refuse missing policy classes before reserving any money. An already bound scope is
                        // checked against its original tariff below.
                        if money.observation_scope(unit).is_none()
                            && required.iter().any(|class| !policy.classes.contains(class))
                        {
                            return Err(ObservationRuntimeError::Unpriced);
                        }
                        money.issue_observation_scope(unit, policy).await?
                    }
                    OBS_ATTACH | OBS_CLOSE => {
                        let bound = money.observation_scope(unit);
                        let Some(named) = scope.or(if op == OBS_CLOSE { bound } else { None })
                        else {
                            return Err(ObservationRuntimeError::Unauthorized);
                        };
                        match bound {
                            Some(current) if current == named => {}
                            Some(_) => return Err(ObservationRuntimeError::AlreadyBound),
                            None => {
                                money.attach_observation_scope(unit, policy, named).await?;
                            }
                        }
                        named
                    }
                    _ => return Err(ObservationRuntimeError::Unauthorized),
                };
                money.require_observation_classes(unit, &required).await?;
                if op == OBS_CLOSE {
                    money.close_observation_scope(unit).await?;
                }
                Ok::<_, ObservationRuntimeError>(id)
            }
            .await;
            match result {
                Ok(id) if op == OBS_CLOSE => (OBS_CLOSED, Some(id)),
                Ok(id) => (OBS_READY, Some(id)),
                Err(error) if pending(&error) => (OBS_PENDING, None),
                Err(_) => (OBS_REFUSED, None),
            }
        })
    }

    fn observe<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        principal: &'a [u8],
        o: &'a ObservationIn<'a>,
    ) -> BoxFut<'a, (u32, Box<[u8]>)> {
        Box::pin(async move {
            let refused = || (OBS_REFUSED, Box::<[u8]>::default());
            let Some(active) = self.resolve(plane.name, principal, Some(o.scope)) else {
                return refused();
            };
            let Some(observation) = observation_of(&active.classes, o) else {
                return refused();
            };
            let observed_at = (self.wall_ms)() / 1000;
            match active
                .money
                .submit_observation(active.unit, &observation, observed_at)
                .await
            {
                Ok(receipt) => match busbar_contract::json::to_vec(&receipt) {
                    Ok(bytes) => (OBS_ACCEPTED, bytes.into()),
                    // An accepted observation whose receipt cannot be written is still durable: the plane
                    // retries and is told so by the idempotent duplicate receipt.
                    Err(_) => (OBS_PENDING, Box::default()),
                },
                Err(error) if pending(&error) => (OBS_PENDING, Box::default()),
                Err(_) => refused(),
            }
        })
    }
}

/// The wire observation of one OBSERVE: class names resolved to the unit's class ids, counts at the ledger's
/// scale. `None` for anything the shape refuses (an unknown class or state, a count that does not scale, a
/// duplicate class).
fn observation_of(
    classes: &[String],
    o: &ObservationIn<'_>,
) -> Option<busbar_contract::abi::sdk::plane::observation::Observation> {
    use busbar_contract::abi::sdk::plane::observation::Observation;
    let mut observation = Observation::new(o.scope, o.event.to_vec(), o.component.to_vec());
    for (name, amount, scale) in o.counts {
        let class = class_of(classes, name)?;
        let (count, _rounded) = scaled(*amount, *scale)?;
        observation = observation.count(class, count).ok()?;
    }
    if let Some((identity, order)) = o.revision {
        observation = observation.revision(identity.to_vec(), order);
    }
    observation = observation
        .rated_to(o.rated_subject)
        .evidence(o.evidence.to_vec());
    observation = match o.state {
        OBS_FINAL => observation.final_totals(),
        OBS_PROVISIONAL => observation,
        _ => return None,
    };
    observation.validate().ok()?;
    Some(observation)
}

#[cfg(test)]
#[path = "tests/port_observations_tests.rs"]
mod tests;
