// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Invocation-bound usage observation exchange. The root supplies policy and money
//! custody; the plugin supplies only opaque scope IDs and declared raw counts.
use super::*;
use crate::plane_driver::{ObservationPolicy, PlaneMoney};
use busbar_contract::abi::mechanism::{extensions, ticket::Ticket, KindCode};
use busbar_contract::abi::sdk::plane::observation::{self as wire, Observation, ScopeRequest};
use busbar_contract::UnitKey;

const REFUSED: &str = "usage observation refused";
const MAX_UNITS: usize = 4096;
const MAX_TICKETS: usize = 256;
type Done = Box<dyn FnOnce(Result<Vec<u8>, &'static str>) + Send>;
#[derive(Default)]
pub(super) struct ObservationRuntime {
    units: Mutex<Units>,
}
/// Registered units, grouped by the instance incarnation that registered them, so retiring a
/// ticket across an instance's units reads only that instance's group.
#[derive(Default)]
struct Units {
    by_caller: HashMap<busbar_contract::services::Incarnation, HashMap<u64, Arc<Context>>>,
    len: usize,
}
struct Context {
    money: Arc<PlaneMoney>,
    policy: ObservationPolicy,
    unit: UnitKey,
    exchanges: Mutex<HashMap<Ticket, Exchange>>,
}
struct Exchange {
    intent: Vec<u8>,
    retired: bool,
    result: Option<Result<Vec<u8>, &'static str>>,
}
struct Completion {
    context: Arc<Context>,
    ticket: Ticket,
    done: Option<Done>,
}
fn unresolved(result: &Result<Vec<u8>, &'static str>) -> bool {
    result.as_ref().is_ok_and(|bytes| {
        matches!(
            wire::result(bytes),
            Ok(Some(wire::ObservationResult::PendingReconciliation))
        )
    })
}
fn failed_result(
    error: &crate::plane_driver::ObservationRuntimeError,
) -> Result<Vec<u8>, &'static str> {
    match error {
        crate::plane_driver::ObservationRuntimeError::Store(
            crate::persistence::observations::Error::Pending { .. },
        ) => Ok(extensions::encode(&[(
            wire::RESULT,
            br#"{"error":"pending"}"#,
        )])),
        _ => Err(REFUSED),
    }
}

/// A scope request's answer. Fields in key order: the bytes match the sorted JSON map it replaced.
#[derive(serde::Serialize)]
struct ScopeAnswer {
    closed: bool,
    scope: wire::ScopeId,
}

/// The one `RESULT` extension entry carrying `value` as JSON: what
/// `extensions::encode(&[(wire::RESULT, &serde_json::to_vec(value)?)])` writes, serialized straight
/// into the answer's own buffer instead of through an intermediate copy.
fn json_result<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, &'static str> {
    let key = wire::RESULT.as_bytes();
    let key_len = u16::try_from(key.len()).map_err(|_| REFUSED)?;
    let mut out = Vec::with_capacity(2 + key.len() + 4 + 128);
    out.extend_from_slice(&key_len.to_le_bytes());
    out.extend_from_slice(key);
    let at = out.len();
    out.extend_from_slice(&[0; 4]);
    serde_json::to_writer(&mut out, value).map_err(|_| REFUSED)?;
    let Ok(len) = u32::try_from(out.len() - at - 4) else {
        // `extensions::encode` drops an entry whose value overflows its u32 length.
        out.clear();
        return Ok(out);
    };
    out[at..at + 4].copy_from_slice(&len.to_le_bytes());
    Ok(out)
}

impl Completion {
    fn finish(mut self, result: Result<Vec<u8>, &'static str>) {
        {
            let mut exchanges = self
                .context
                .exchanges
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(exchange) = exchanges.get_mut(&self.ticket) {
                if exchange.retired {
                    exchanges.remove(&self.ticket);
                } else {
                    exchange.result = Some(result.clone());
                }
            }
        }
        if let Some(done) = self.done.take() {
            done(result);
        }
    }
}
impl Drop for Completion {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            {
                let mut exchanges = self
                    .context
                    .exchanges
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(exchange) = exchanges.get_mut(&self.ticket) {
                    if exchange.retired {
                        exchanges.remove(&self.ticket);
                    } else {
                        exchange.result = Some(Err(REFUSED));
                    }
                }
            }
            done(Err(REFUSED));
        }
    }
}

impl KernelServices {
    /// Root-only activation after ordinary admission and verified destination selection.
    /// No capability is advertised merely because a durable backend exists.
    pub fn register_observation_unit(
        &self,
        caller: &Caller,
        unit: UnitKey,
        money: Arc<PlaneMoney>,
        policy: ObservationPolicy,
    ) -> Result<(), &'static str> {
        if caller.kind() != KindCode::Plane
            || policy.instance != caller.namespace().as_ref()
            || !money.observations_supported()
            || money.serving(unit, |_| ()).is_none()
            || self
                .units
                .get(unit.get())
                .is_none_or(|r| r.principal.is_none())
        {
            return Err(REFUSED);
        }
        let mut units = self
            .observations
            .units
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(current) = units
            .by_caller
            .get(caller.incarnation())
            .and_then(|of| of.get(&unit.get()))
        {
            return if current.policy == policy && Arc::ptr_eq(&current.money, &money) {
                Ok(())
            } else {
                Err(REFUSED)
            };
        }
        if units.len >= MAX_UNITS {
            return Err(REFUSED);
        }
        units.len += 1;
        units
            .by_caller
            .entry(caller.incarnation().clone())
            .or_default()
            .insert(
                unit.get(),
                Arc::new(Context {
                    money,
                    policy,
                    unit,
                    exchanges: Mutex::default(),
                }),
            );
        Ok(())
    }

    fn observation_context(&self, caller: &Caller, unit: Option<u64>) -> Option<Arc<Context>> {
        if caller.kind() != KindCode::Plane {
            return None;
        }
        let unit = unit?;
        self.units.get(unit)?.principal.as_ref()?;
        self.observations
            .units
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .by_caller
            .get(caller.incarnation())?
            .get(&unit)
            .cloned()
    }

    pub(super) fn observation_output_allowed(
        &self,
        caller: &Caller,
        ticket: Ticket,
        unit: Option<u64>,
    ) -> bool {
        let Some(context) = self.observation_context(caller, unit) else {
            return true;
        };
        let exchanges = context.exchanges.lock().unwrap_or_else(|e| e.into_inner());
        exchanges
            .get(&ticket)
            .is_none_or(|e| e.result.as_ref().is_some_and(|r| !unresolved(r)))
    }

    pub(super) fn observation_retire(&self, caller: &Caller, ticket: Ticket, unit: Option<u64>) {
        let retire = |context: &Context| {
            let mut exchanges = context.exchanges.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(exchange) = exchanges.get_mut(&ticket) {
                if exchange.result.is_some() {
                    exchanges.remove(&ticket);
                } else {
                    exchange.retired = true;
                }
            }
        };
        match unit {
            Some(unit) => {
                if let Some(context) = self.observation_context(caller, Some(unit)) {
                    retire(&context);
                }
            }
            // Units lock before exchanges, as nowhere takes them the other way round.
            None => {
                let units = self
                    .observations
                    .units
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(of) = units.by_caller.get(caller.incarnation()) {
                    of.values().for_each(|context| retire(context));
                }
            }
        }
    }

    pub(super) fn observation_input(
        &self,
        caller: &Caller,
        ticket: Ticket,
        unit: Option<u64>,
    ) -> Option<Vec<u8>> {
        if ticket.is_none() {
            return None;
        }
        self.pool.as_ref()?;
        let context = self.observation_context(caller, unit)?;
        let mut result = extensions::encode(&[(wire::CAPABILITY, b"1")]);
        if let Some(scope) = context.money.observation_scope(context.unit) {
            result.extend(extensions::encode(&[(wire::SCOPE, &scope)]));
        }
        if let Some(exchange) = context
            .exchanges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&ticket)
        {
            if let Some(answer) = &exchange.result {
                match answer {
                    Ok(bytes) => result.extend_from_slice(bytes),
                    Err(_) => result.extend(extensions::encode(&[(
                        wire::RESULT,
                        br#"{"error":"refused"}"#,
                    )])),
                }
            }
        }
        Some(result)
    }

    fn begin_observation(
        &self,
        caller: &Caller,
        ticket: Ticket,
        unit: Option<u64>,
        intent: Vec<u8>,
        done: Done,
    ) -> Result<Option<Completion>, &'static str> {
        if ticket.is_none() {
            return Err(REFUSED);
        }
        let context = self.observation_context(caller, unit).ok_or(REFUSED)?;
        let mut exchanges = context.exchanges.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(previous) = exchanges.get(&ticket) {
            if previous.intent == intent && !previous.result.as_ref().is_some_and(unresolved) {
                let result = previous.result.clone();
                drop(exchanges);
                // A pending retry has the original callback; completed replay wakes immediately.
                if let Some(result) = result {
                    done(result);
                }
                return Ok(None);
            }
            if previous.result.is_none()
                || (previous.intent != intent && previous.result.as_ref().is_some_and(unresolved))
            {
                return Err(REFUSED);
            }
        } else if exchanges.len() >= MAX_TICKETS {
            return Err(REFUSED);
        }
        exchanges.insert(
            ticket,
            Exchange {
                intent,
                retired: false,
                result: None,
            },
        );
        drop(exchanges);
        Ok(Some(Completion {
            context,
            ticket,
            done: Some(done),
        }))
    }

    pub(super) fn observation_submit(
        &self,
        caller: &Caller,
        ticket: Ticket,
        unit: Option<u64>,
        observation: Observation,
        done: Done,
    ) -> Result<(), &'static str> {
        let pool = self.pool.as_ref().ok_or(REFUSED)?;
        let intent = observation.extension().map_err(|_| REFUSED)?;
        let Some(completion) = self.begin_observation(caller, ticket, unit, intent, done)? else {
            return Ok(());
        };
        let context = completion.context.clone();
        let observed_at = (self.wall_ms)() / 1000;
        pool.run_async(Box::pin(async move {
            let answer = match context
                .money
                .submit_observation(context.unit, &observation, observed_at)
                .await
            {
                Ok(receipt) => json_result(&receipt),
                Err(error) => failed_result(&error),
            };
            completion.finish(answer);
        }));
        Ok(())
    }

    pub(super) fn observation_scope_request(
        &self,
        caller: &Caller,
        ticket: Ticket,
        unit: Option<u64>,
        request: ScopeRequest,
        done: Done,
    ) -> Result<(), &'static str> {
        let pool = self.pool.as_ref().ok_or(REFUSED)?;
        let intent = request.extension().map_err(|_| REFUSED)?;
        let Some(completion) = self.begin_observation(caller, ticket, unit, intent, done)? else {
            return Ok(());
        };
        let context = completion.context.clone();
        pool.run_async(Box::pin(async move {
            let result = async {
                let scope = match request.scope {
                    Some(scope) => {
                        match context.money.observation_scope(context.unit) {
                            Some(current) if current == scope => {}
                            Some(_) => {
                                return Err(
                                    crate::plane_driver::ObservationRuntimeError::AlreadyBound,
                                )
                            }
                            None => {
                                context
                                    .money
                                    .attach_observation_scope(context.unit, &context.policy, scope)
                                    .await?
                            }
                        }
                        scope
                    }
                    None => {
                        // Refuse missing policy classes before reserving any money. An
                        // already bound scope is checked against its original tariff below.
                        if context.money.observation_scope(context.unit).is_none()
                            && request
                                .required_classes
                                .iter()
                                .any(|class| !context.policy.classes.contains(class))
                        {
                            return Err(crate::plane_driver::ObservationRuntimeError::Unpriced);
                        }
                        context
                            .money
                            .issue_observation_scope(context.unit, &context.policy)
                            .await?
                    }
                };
                context
                    .money
                    .require_observation_classes(context.unit, &request.required_classes)
                    .await?;
                if request.close {
                    context.money.close_observation_scope(context.unit).await?;
                }
                Ok::<_, crate::plane_driver::ObservationRuntimeError>(scope)
            }
            .await;
            let answer = match result {
                Ok(scope) => json_result(&ScopeAnswer {
                    closed: request.close,
                    scope,
                }),
                Err(error) => failed_result(&error),
            };
            completion.finish(answer);
        }));
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/host_observations_tests.rs"]
mod tests;
