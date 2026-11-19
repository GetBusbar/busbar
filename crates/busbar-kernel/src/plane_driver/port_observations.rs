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

/// The most units registered at once, across every instance.
const MAX_UNITS: usize = 4_096;

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

/// A principal's units in flight, each with the id of the registration that holds it. One unit is held in
/// place; more spill to the heap, and the entry goes with the principal's last unit.
pub(crate) type Units = smallvec::SmallVec<[(u64, ActiveUnit); 1]>;

/// By (instance, subject) names, shared with the caller that registered them: the key is a second handle on
/// the caller's names, never a copy.
pub(crate) type ByPrincipal = foldhash::HashMap<(Arc<str>, Arc<str>), Units>;

/// The registrations in flight. Empty at boot: a principal's entry is made with its first unit and removed with
/// its last.
#[derive(Default)]
pub(crate) struct Book {
    pub(crate) by_principal: ByPrincipal,
    pub(crate) len: usize,
    /// The id the next registration takes (it tells two registrations of one unit apart).
    next_id: u64,
}

impl Book {
    /// The unit a call of the principal holding `units` is for: see the module docs.
    fn pick(units: &Units, scope: Option<[u8; 32]>) -> Option<&ActiveUnit> {
        if let [(_, only)] = units.as_slice() {
            return Some(only);
        }
        if let Some(scope) = scope {
            if let Some((_, attached)) = units
                .iter()
                .find(|(_, c)| c.money.observation_scope(c.unit) == Some(scope))
            {
                return Some(attached);
            }
        }
        let mut unattached = units
            .iter()
            .filter(|(_, c)| c.money.observation_scope(c.unit).is_none());
        match (unattached.next(), unattached.next()) {
            (Some((_, one)), None) => Some(one),
            _ => None,
        }
    }
}

/// The observation custody of every plane instance in the process. Clones share the registrations.
#[derive(Clone)]
pub struct ObsCustody {
    book: Arc<Mutex<Book>>,
    wall_ms: WallMs,
}

/// A registered unit, released when this drops (the request ended: transient exchange custody only, never the
/// durable reservation).
#[must_use = "dropping a registration releases the unit"]
pub struct Registration {
    book: Arc<Mutex<Book>>,
    instance: Arc<str>,
    subject: Arc<str>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut book = self.book.lock().unwrap_or_else(PoisonError::into_inner);
        let key: &dyn Principal = &(&*self.instance, &*self.subject);
        let Some(units) = book.by_principal.get_mut(key) else {
            return;
        };
        // A registration holds the one entry for its unit; the order of a principal's units is not
        // observed (a call picks by scope), so the entry is swapped out.
        let Some(at) = units.iter().position(|(held, _)| *held == self.id) else {
            return;
        };
        let (_, unit) = units.swap_remove(at);
        if units.is_empty() {
            book.by_principal.remove(key);
        }
        book.len -= 1;
        drop(book);
        // The unit's shared parts are let go after the lock.
        drop(unit);
    }
}

impl ObsCustody {
    #[must_use]
    pub fn new(wall_ms: WallMs) -> Self {
        Self {
            book: Arc::default(),
            wall_ms,
        }
    }

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
            || unit.money.serving(unit.unit, |_| ()).is_none()
        {
            return Err(REFUSED);
        }
        let mut book = self.book.lock().unwrap_or_else(PoisonError::into_inner);
        let book = &mut *book;
        if book.len >= MAX_UNITS {
            return Err(REFUSED);
        }
        let id = book.next_id;
        book.next_id = id.wrapping_add(1);
        let key: &dyn Principal = &(&**instance, &**subject);
        if let Some(units) = book.by_principal.get_mut(key) {
            units.push((id, unit));
        } else {
            // The principal's first unit in flight: its entry is made now, keyed by the caller's shared names.
            let mut units = Units::new();
            units.push((id, unit));
            book.by_principal
                .insert((Arc::clone(instance), Arc::clone(subject)), units);
        }
        book.len += 1;
        Ok(Registration {
            book: Arc::clone(&self.book),
            instance: Arc::clone(instance),
            subject: Arc::clone(subject),
            id,
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
        let units = book
            .by_principal
            .get(&(instance, subject) as &dyn Principal)?;
        Book::pick(units, scope).cloned()
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
) -> Option<busbar_contract::observation::Observation> {
    use busbar_contract::observation::Observation;
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
