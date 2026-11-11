// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Composition of loader custody with the kernel's existing raw usage ledger.
//! Neither the attribution context nor maintenance authority crosses the plugin ABI.

use std::future::Future;
use std::sync::{Arc, LazyLock, RwLock, Weak};

use busbar_contract::{abi::mechanism::lifecycle::slot, UnitKey};
use busbar_kernel::{
    config::{measurement_rates, PluginRateCards},
    host_measurement::{
        MeasurementBinding, MeasurementContext, MeasurementOperation, MeasurementRuntime,
    },
    plane_driver::PlaneMoney,
};

use super::loader::dispatch::measurement::{
    self, Authority, Binding, CapturedBatch, Context, Operation, Refusal,
};

#[derive(Default)]
struct State {
    rates: PluginRateCards,
    runtime: Option<Arc<MeasurementRuntime>>,
    governor: Weak<busbar_kernel::governance::GovState>,
}

#[derive(Default)]
struct RootAuthority(RwLock<State>);
static AUTHORITY: LazyLock<Arc<RootAuthority>> =
    LazyLock::new(|| Arc::new(RootAuthority::default()));
static READY: tokio::sync::Notify = tokio::sync::Notify::const_new();

struct Maintenance;
struct Request {
    money: Weak<PlaneMoney>,
    unit: UnitKey,
    preadmission: MeasurementContext,
}

pub(super) struct RequestScope {
    context: Context,
    _guard: busbar_kernel::plane_driver::MeasurementRequestGuard,
}

impl RequestScope {
    pub(super) fn new(
        money: &Arc<PlaneMoney>,
        unit: UnitKey,
        principal: &busbar_contract::caps::PrincipalId,
        key: Option<&busbar_contract::records::VirtualKey>,
        arrived: super::plane_node::Arrived,
    ) -> Result<Self, Refusal> {
        let seal = busbar_kernel::seal::acquire();
        let era =
            busbar_kernel::rate_apply::RateEpoch::era_at(&*super::kernel::ROOT_CARD, arrived.ms());
        let preadmission = MeasurementContext::request(
            &seal,
            unit.get(),
            key.map_or_else(|| principal.as_str().to_owned(), |key| key.id.clone()),
            key.and_then(|key| key.group.clone()).unwrap_or_default(),
            Vec::new(),
            arrived.secs(),
            era,
        )
        .map_err(refusal)?;
        let guard = money
            .begin_measurement_request(&seal, unit)
            .map_err(refusal)?;
        Ok(Self {
            context: Arc::new(Request {
                money: Arc::downgrade(money),
                unit,
                preadmission,
            }),
            _guard: guard,
        })
    }
}

fn refusal(error: busbar_kernel::host_measurement::Refusal) -> Refusal {
    match error {
        busbar_kernel::host_measurement::Refusal::Unavailable => Refusal::Unavailable,
        busbar_kernel::host_measurement::Refusal::Malformed => Refusal::Malformed,
        busbar_kernel::host_measurement::Refusal::Conflict => Refusal::Conflict,
    }
}

fn coverage(rates: &PluginRateCards, binding: &Binding) -> Result<Vec<String>, String> {
    measurement_rates::validate_plugin_rate_coverage(
        rates,
        binding.caller.kind().word(),
        binding.caller.namespace(),
        binding.classes.iter().map(|class| class.class.as_str()),
    )
}

impl Authority for RootAuthority {
    fn admit(&self, binding: &Binding) -> Result<(), Refusal> {
        let state = self.0.read().unwrap_or_else(|p| p.into_inner());
        for warning in coverage(&state.rates, binding).map_err(|error| {
            tracing::error!(%error, "plugin measurement registration refused");
            Refusal::Malformed
        })? {
            tracing::warn!(%warning);
        }
        Ok(())
    }

    fn reserve(
        &self,
        binding: &Binding,
        context: Option<&Context>,
        operation: u32,
    ) -> Result<Arc<dyn Operation>, Refusal> {
        // Reject foreign host context types even on lifecycle calls. There is no user-to-system
        // fallback and a plugin cannot request the private maintenance marker.
        if context.is_some_and(|context| {
            !context.is::<Maintenance>()
                && !context.is::<Request>()
                && !context.is::<MeasurementContext>()
        }) {
            return Err(Refusal::Malformed);
        }
        if context.is_some_and(|context| context.is::<Maintenance>())
            || matches!(
                operation,
                slot::VALIDATE
                    | slot::OPEN
                    | slot::REFRESH
                    | slot::RETIRE
                    | slot::RELEASE
                    | slot::CLOSE
                    | slot::READY
                    | slot::MIGRATE
            )
        {
            return Ok(Arc::new(Maintenance));
        }
        let seal = busbar_kernel::seal::acquire();
        let context = match context {
            Some(context) if context.is::<Request>() => {
                let request = context
                    .downcast_ref::<Request>()
                    .ok_or(Refusal::Malformed)?;
                let money = request.money.upgrade().ok_or(Refusal::Unavailable)?;
                match money.measurement_request_state(&seal, request.unit) {
                    busbar_kernel::plane_driver::MeasurementRequestState::PendingAdmission => {
                        request.preadmission.clone()
                    }
                    busbar_kernel::plane_driver::MeasurementRequestState::Admitted(context) => {
                        context
                    }
                    busbar_kernel::plane_driver::MeasurementRequestState::Retired => {
                        return Err(Refusal::Unavailable)
                    }
                }
            }
            Some(context) => context
                .downcast_ref::<MeasurementContext>()
                .ok_or(Refusal::Malformed)?
                .clone(),
            None => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| Refusal::Unavailable)?;
                let millis = u64::try_from(now.as_millis()).map_err(|_| Refusal::Unavailable)?;
                let era = busbar_kernel::rate_apply::RateEpoch::era_at(
                    &*super::kernel::ROOT_CARD,
                    millis,
                );
                MeasurementContext::system(&seal, now.as_secs(), era)
            }
        };
        let runtime = self
            .0
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .runtime
            .clone()
            .ok_or(Refusal::Unavailable)?;
        runtime
            .reserve(
                &seal,
                MeasurementBinding {
                    caller: binding.caller.clone(),
                    statement_digest: binding.statement_digest,
                    classes: binding
                        .classes
                        .iter()
                        .map(|class| class.class.clone())
                        .collect(),
                },
                &context,
                operation,
            )
            .map(|operation| Arc::new(RootOperation(operation)) as Arc<dyn Operation>)
            .map_err(refusal)
    }
}

impl Operation for Maintenance {
    fn revision(&self) -> u64 {
        0
    }
    fn is_maintenance(&self) -> bool {
        true
    }
    fn capture(&self, batch: CapturedBatch) -> Result<(), Refusal> {
        if batch.revision == 0 && batch.counts.is_empty() {
            Ok(())
        } else {
            Err(Refusal::Malformed)
        }
    }
    fn released(&self, _: bool) {}
}

struct RootOperation(Arc<MeasurementOperation>);
impl Operation for RootOperation {
    fn revision(&self) -> u64 {
        self.0.revision()
    }
    fn capture(&self, batch: CapturedBatch) -> Result<(), Refusal> {
        let mut counts =
            [(0, busbar_contract::Count::ZERO); busbar_kernel::host_measurement::MAX_CLASSES];
        let used = counts
            .get_mut(..batch.counts.len())
            .ok_or(Refusal::Malformed)?;
        for (output, count) in used.iter_mut().zip(batch.counts) {
            *output = (count.class, count.count().map_err(|_| Refusal::Malformed)?);
        }
        self.0
            .capture(batch.revision, used.iter().copied())
            .map_err(refusal)
    }
    fn released(&self, terminal: bool) {
        self.0.released(terminal);
    }
}

pub(super) fn authority() -> Arc<dyn Authority> {
    AUTHORITY.clone()
}

/// Staged configuration is checked against already bound instances before replacing it.
pub(crate) fn configure(rates: &PluginRateCards) -> Result<(), String> {
    measurement_rates::validate(rates)?;
    let bindings = super::dispatch::dispatcher().measurement_bindings();
    for binding in &bindings {
        for warning in coverage(rates, binding)? {
            tracing::warn!(%warning);
        }
    }
    AUTHORITY.0.write().unwrap_or_else(|p| p.into_inner()).rates = rates.clone();
    Ok(())
}

/// Only the existing confirmed rate publication notification updates live coverage metadata.
pub(super) fn confirmed_rates(rates: &PluginRateCards) {
    AUTHORITY.0.write().unwrap_or_else(|p| p.into_inner()).rates = rates.clone();
}

pub(crate) fn validate_bindings() -> Result<(), String> {
    let bindings = super::dispatch::dispatcher().measurement_bindings();
    let state = AUTHORITY.0.read().unwrap_or_else(|p| p.into_inner());
    measurement_rates::validate_plugin_rate_instances(
        &state.rates,
        bindings.iter().map(|binding| {
            (
                binding.caller.kind().word(),
                binding.caller.namespace().as_ref(),
            )
        }),
    )
}

/// Validate an activation without mutating the confirmed card or its publication state.
pub(super) fn validate_rates(rates: &PluginRateCards) -> Result<(), String> {
    let bindings = super::dispatch::dispatcher().measurement_bindings();
    for binding in &bindings {
        coverage(rates, binding)?;
    }
    if AUTHORITY
        .0
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .runtime
        .is_some()
    {
        measurement_rates::validate_plugin_rate_instances(
            rates,
            bindings.iter().map(|binding| {
                (
                    binding.caller.kind().word(),
                    binding.caller.namespace().as_ref(),
                )
            }),
        )?;
    }
    Ok(())
}

/// Called only after both native recovery sinks have been attached.
pub(super) fn install(app: &busbar_kernel::state::App) -> Result<(), String> {
    let gov = app
        .governance
        .clone()
        .ok_or("measurement custody requires governance")?;
    configure(app.cost.measurement_rates())?;
    let mut state = AUTHORITY.0.write().unwrap_or_else(|p| p.into_inner());
    if state
        .governor
        .upgrade()
        .is_some_and(|old| Arc::ptr_eq(&old, &gov))
    {
        return Ok(());
    }
    if state
        .runtime
        .as_ref()
        .is_some_and(|runtime| runtime.pending() != 0)
    {
        return Err(
            "measurement custody still holds unsettled operations from the previous governor"
                .into(),
        );
    }
    let runtime = MeasurementRuntime::new(
        &busbar_kernel::seal::acquire(),
        gov.clone(),
        busbar_kernel::host_measurement::MAX_OPERATIONS,
    )
    .map_err(|error| format!("measurement custody: {error:?}"))?;
    state.governor = Arc::downgrade(&gov);
    state.runtime = Some(runtime);
    drop(state);
    READY.notify_waiters();
    Ok(())
}

/// Detached periodic work starts only after recovery has installed accounting custody.
/// Its later callbacks are system usage, even if the task was created during startup.
pub(super) async fn background<F: Future>(future: F) -> F::Output {
    loop {
        let ready = READY.notified();
        tokio::pin!(ready);
        ready.as_mut().enable();
        if AUTHORITY
            .0
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .runtime
            .is_some()
        {
            break;
        }
        ready.await;
    }
    measurement::scope(None, future).await
}

/// Config-time secret refresh also runs on host threads. Initial resolution is bootstrap
/// maintenance; refresh after ledger installation is ordinary system usage. Decide on each
/// invocation so a long-lived refresher never retains startup's accounting suppression.
pub(super) fn configuration_refresh<R>(run: impl FnOnce() -> R) -> R {
    let context = AUTHORITY
        .0
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .runtime
        .is_none()
        .then(|| Arc::new(Maintenance) as Context);
    measurement::with_context(context, run)
}

pub(crate) async fn maintenance<F: Future>(future: F) -> F::Output {
    measurement::scope(Some(Arc::new(Maintenance)), future).await
}

pub(super) async fn request<F: Future>(scope: RequestScope, future: F) -> F::Output {
    let RequestScope { context, _guard } = scope;
    measurement::scope(Some(context), future).await
}

#[cfg(test)]
pub(super) fn local_authority(
    gov: Arc<busbar_kernel::governance::GovState>,
    rates: PluginRateCards,
) -> Result<Arc<dyn Authority>, String> {
    measurement_rates::validate(&rates)?;
    let runtime = MeasurementRuntime::new(
        &busbar_kernel::seal::acquire(),
        gov.clone(),
        busbar_kernel::host_measurement::MAX_OPERATIONS,
    )
    .map_err(|error| format!("measurement custody: {error:?}"))?;
    Ok(Arc::new(RootAuthority(RwLock::new(State {
        rates,
        runtime: Some(runtime),
        governor: Arc::downgrade(&gov),
    }))))
}

#[cfg(test)]
#[path = "tests/measurements.rs"]
mod tests;
