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
type Invocation = (busbar_contract::services::Incarnation, u64);

#[derive(Default)]
pub(super) struct ObservationRuntime {
    units: Mutex<HashMap<Invocation, Arc<Context>>>,
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
    error: crate::plane_driver::ObservationRuntimeError,
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
            || money.serving(unit).is_none()
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
        let key = (caller.incarnation().clone(), unit.get());
        if let Some(current) = units.get(&key) {
            return if current.policy == policy && Arc::ptr_eq(&current.money, &money) {
                Ok(())
            } else {
                Err(REFUSED)
            };
        }
        if units.len() >= MAX_UNITS {
            return Err(REFUSED);
        }
        units.insert(
            key,
            Arc::new(Context {
                money,
                policy,
                unit,
                exchanges: Mutex::default(),
            }),
        );
        Ok(())
    }

    /// Ending a request releases transient exchange custody only, never durable reservation.
    pub fn unregister_observation_unit(&self, caller: &Caller, unit: UnitKey) {
        self.observations
            .units
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(caller.incarnation().clone(), unit.get()));
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
            .get(&(caller.incarnation().clone(), unit))
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
        let contexts: Vec<_> = match unit {
            Some(unit) => self
                .observation_context(caller, Some(unit))
                .into_iter()
                .collect(),
            None => self
                .observations
                .units
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|((incarnation, _), _)| incarnation == caller.incarnation())
                .map(|(_, context)| context.clone())
                .collect(),
        };
        for context in contexts {
            let mut exchanges = context.exchanges.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(exchange) = exchanges.get_mut(&ticket) {
                if exchange.result.is_some() {
                    exchanges.remove(&ticket);
                } else {
                    exchange.retired = true;
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
        self.pool.get()?;
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
        let pool = self.pool.get().ok_or(REFUSED)?;
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
                Ok(receipt) => serde_json::to_vec(&receipt)
                    .map_err(|_| REFUSED)
                    .map(|bytes| extensions::encode(&[(wire::RESULT, &bytes)])),
                Err(error) => failed_result(error),
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
        let pool = self.pool.get().ok_or(REFUSED)?;
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
                        context
                            .money
                            .issue_observation_scope(context.unit, &context.policy)
                            .await?
                    }
                };
                if request.close {
                    context.money.close_observation_scope(context.unit).await?;
                }
                Ok::<_, crate::plane_driver::ObservationRuntimeError>(scope)
            }
            .await;
            let answer = match result {
                Ok(scope) => serde_json::to_vec(&serde_json::json!({
                    "scope": scope, "closed": request.close,
                }))
                .map_err(|_| REFUSED)
                .map(|bytes| extensions::encode(&[(wire::RESULT, &bytes)])),
                Err(error) => failed_result(error),
            };
            completion.finish(answer);
        }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
    use crate::cost::CostModel;
    use crate::governance::GovState;
    use crate::persistence::host_records::tests::{attach, Backend};
    use crate::persistence::observations::ObservationStore;
    use crate::plane_driver::{Checkpoint, EndPost, FeeRefund, MoneySeam, UnitMoney};
    use busbar_contract::{records::VirtualKey, Count};
    use std::collections::BTreeMap;

    struct Post;
    impl EndPost for Post {
        fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
    }
    struct Pool;
    impl Offload for Pool {
        fn run(&self, job: Box<dyn FnOnce() + Send>) {
            job();
        }
        fn run_async(&self, job: AsyncJob) {
            tokio::spawn(job);
        }
    }
    fn cost(rate: u64) -> Arc<CostModel> {
        let rates = BTreeMap::from([(
            "serving".to_owned(),
            crate::config::RateEntryCfg {
                units: BTreeMap::from([(
                    "work_units".to_owned(),
                    busbar_kernel_ledger::cost::UnitRate::from_whole_micros(rate).unwrap(),
                )]),
                ..Default::default()
            },
        )]);
        let groups = BTreeMap::from([(
            "group".to_owned(),
            GroupCfg {
                enabled: true,
                limits: vec![LimitCfg {
                    metric: LimitMetric::Budget,
                    amount: 1,
                    per: Some(LimitWindow::Total),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                    admission: None,
                    on_exhaustion: None,
                }],
                ..Default::default()
            },
        )]);
        Arc::new(CostModel::resolve_parts(Some(&rates), 0, &groups))
    }
    fn admitted(
        money: &PlaneMoney,
        gov: &GovState,
        cost: Arc<CostModel>,
        key: Arc<VirtualKey>,
        unit: u64,
    ) {
        let grant = Arc::new(gov.try_admit(&cost, &key, "", 100).unwrap());
        money.open_admitted(
            UnitKey::new(unit),
            UnitMoney {
                key,
                cost,
                pool: String::new(),
                lane: "serving".into(),
                classes: Arc::from(vec!["work_units".into()]),
                arrived: 100,
                mode: crate::config::groups::ExhaustionMode::FinishUnit,
                fee: FeeRefund::CallerStatus,
                charge: grant.charge().clone(),
            },
            grant,
        );
    }
    async fn scope_request(
        kernel: &KernelServices,
        caller: &Caller,
        ticket: Ticket,
        unit: u64,
        request: ScopeRequest,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        kernel
            .usage_observation_scope(
                caller,
                ticket,
                Some(unit),
                request,
                Box::new(move |r| {
                    let _ = tx.send(r);
                }),
            )
            .unwrap();
        rx.await.unwrap().unwrap();
    }
    async fn submit(
        kernel: &KernelServices,
        caller: &Caller,
        ticket: Ticket,
        unit: u64,
        observation: Observation,
    ) -> wire::Receipt {
        let (tx, rx) = tokio::sync::oneshot::channel();
        kernel
            .usage_observation_submit(
                caller,
                ticket,
                Some(unit),
                observation,
                Box::new(move |r| {
                    let _ = tx.send(r);
                }),
            )
            .unwrap();
        let bytes = rx.await.unwrap().unwrap();
        serde_json::from_slice(extensions::unique(&bytes, wire::RESULT).unwrap().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn neutral_runtime_custody_reserves_settles_and_reattaches_original_tariff() {
        let core = Arc::new(attach(Arc::new(Backend::default())).await);
        let gov = Arc::new(
            GovState::new_with_core(core.clone(), None, None)
                .await
                .unwrap(),
        );
        let money = Arc::new(PlaneMoney::new(gov.clone(), Arc::new(Post)));
        let key = Arc::new(VirtualKey {
            id: "owner".into(),
            enabled: true,
            group: Some("group".into()),
            ..Default::default()
        });
        let original_cost = cost(1);
        admitted(&money, &gov, original_cost.clone(), key.clone(), 1);
        let kernel = KernelServices::new().with_pool(Arc::new(Pool));
        kernel.units().admitted(
            1,
            crate::host_units::UnitRecord {
                principal: Some(key.clone()),
                depth: 0,
            },
        );
        let caller = Caller::for_test("fixture".into(), KindCode::Plane);
        let ticket = Ticket {
            slot: 1,
            generation: 1,
        };
        let policy = ObservationPolicy {
            instance: "fixture".into(),
            destination: "member".into(),
            serving_subject: "serving".into(),
            accounting_namespace: "account".into(),
            classes: vec![0],
            rated_subjects: vec![],
            reserve_nanos: 10_000_000,
            ordered_revisions: true,
        };
        assert!(kernel
            .usage_observation_input(&caller, ticket, Some(1))
            .is_none());
        kernel
            .register_observation_unit(&caller, UnitKey::new(1), money.clone(), policy.clone())
            .unwrap();
        assert!(wire::supported(
            &kernel
                .usage_observation_input(&caller, ticket, Some(1))
                .unwrap()
        )
        .unwrap());
        let forged = Caller::for_test("fixture".into(), KindCode::Plane);
        assert!(kernel
            .usage_observation_input(&forged, ticket, Some(1))
            .is_none());
        scope_request(&kernel, &caller, ticket, 1, ScopeRequest::create()).await;
        let id = wire::scope(
            &kernel
                .usage_observation_input(&caller, ticket, Some(1))
                .unwrap(),
        )
        .unwrap()
        .unwrap();
        assert!(gov
            .check_observation_admission(&original_cost, &key, "", 100, None)
            .await
            .is_err());
        let observation = Observation::new(id, b"event".to_vec(), b"part".to_vec())
            .count(0, Count::from(20))
            .unwrap()
            .revision(vec![1], 1)
            .final_totals();
        assert!(
            !submit(&kernel, &caller, ticket, 1, observation.clone())
                .await
                .duplicate
        );
        assert!(
            submit(
                &kernel,
                &caller,
                Ticket {
                    slot: 2,
                    generation: 1
                },
                1,
                observation.clone()
            )
            .await
            .duplicate
        );
        let ctx = crate::teller::UnitCtx {
            call: busbar_contract::caps::CallId::UNBOUND,
            key: UnitKey::new(1),
            origin: busbar_contract::caps::OriginKind::Client,
            session: None,
            generation: crate::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        assert_eq!(
            money.checkpoint(
                &ctx,
                &[busbar_contract::abi::plane::UnitCount {
                    class: 0,
                    source: busbar_contract::abi::plane::UNITS_REPORTED,
                    amount: 20,
                }]
            ),
            Checkpoint::Unpriced
        );
        scope_request(&kernel, &caller, ticket, 1, ScopeRequest::close(id)).await;
        assert_eq!(
            wire::result(
                &kernel
                    .usage_observation_input(&caller, ticket, Some(1))
                    .unwrap()
            )
            .unwrap(),
            Some(wire::ObservationResult::ScopeReady {
                scope: id,
                closed: true
            })
        );
        assert!(gov
            .check_observation_admission(&original_cost, &key, "", 100, None)
            .await
            .is_ok());
        let owner = ObservationStore::open(core).unwrap();
        let bound = owner
            .bind_scope(
                id,
                crate::persistence::observations::PrincipalBinding {
                    principal: key.id.clone(),
                    instance: policy.instance.clone(),
                    destination: policy.destination.clone(),
                    accounting_namespace: policy.accounting_namespace.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            owner.dated_total(&bound, 0).await.unwrap().spent_nanos,
            20_000
        );
        admitted(&money, &gov, cost(90), key.clone(), 2);
        kernel.units().admitted(
            2,
            crate::host_units::UnitRecord {
                principal: Some(key),
                depth: 0,
            },
        );
        kernel
            .register_observation_unit(&caller, UnitKey::new(2), money.clone(), policy)
            .unwrap();
        scope_request(&kernel, &caller, ticket, 2, ScopeRequest::attach(id)).await;
        let corrected = Observation::new(id, b"event".to_vec(), b"part".to_vec())
            .count(0, Count::from(12))
            .unwrap()
            .revision(vec![2], 2)
            .final_totals();
        submit(&kernel, &caller, ticket, 2, corrected).await;
        assert_eq!(
            owner.dated_total(&bound, 0).await.unwrap().spent_nanos,
            12_000
        );
        assert_eq!(owner.binding(&bound).await.unwrap().rate_time, 100);
        assert!(money
            .attach_observation_scope(
                UnitKey::new(2),
                &ObservationPolicy {
                    accounting_namespace: "other".into(),
                    ..kernel
                        .observation_context(&caller, Some(2))
                        .unwrap()
                        .policy
                        .clone()
                },
                id
            )
            .await
            .is_err());
    }
}
