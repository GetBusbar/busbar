// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot walk over `Registry::boot_plan` (ABI-MIN3-INTERFACE §11.2 `BootPlan`, §12.10 item 4; W2-BOOT).
//!
//! One generic loop for every kind: each step opens before the next starts (2a the secret instances the store
//! references, 2b the store, 2c the rest kind by kind), so a store's SECRET Need always finds its secret open.
//! Between the last 2b and the first 2c step sits the deployment point (round 29): the id is read or written
//! through the just-opened store, published once to the host (`host_vt::set_deployment`), and every 2a/2b
//! instance is re-checked (DRY_RUN, same spec) so a plugin that binds to the install identity sees `None` in its
//! open and `Some` in the re-check, always before any 2c instance opens. A refusal anywhere refuses the boot. The
//! walk reads only plan indices and phases: no kind, plugin name or per-kind branch (§15.8, 257b).

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::instance::{
    BootPhase, BootPlan, InstanceSpec, OpenError, OpenedPort, Registry,
};

/// What the walk asks of the registry. `index` is the configured instance index the plan names.
pub trait BootSteps: Sync {
    /// The opened instance the walk hands back to the composition root.
    type Opened: Send;
    /// Open instance `index` (§11.2 `open_<kind>`; the bag bound, its settled answer kept for step 5).
    fn open(&self, index: u32) -> BoxFut<'_, Result<Self::Opened, OpenError>>;
    /// The DRY_RUN `check` of instance `index`, with the spec it was opened with (§11.2 `check`).
    fn check(&self, index: u32) -> BoxFut<'_, Result<(), OpenError>>;
    /// Read or write the `busbar.deployment.v1`/`id` row through the opened store (boot_identity.rs keep-once).
    fn deployment<'a>(&'a self, store: &'a Self::Opened) -> BoxFut<'a, Result<[u8; 16], String>>;
    /// Publish the id to every plugin's `Host::deployment` (§10.7). Called once per boot.
    fn publish(&self, id: [u8; 16]) {
        busbar_plugin_abi::host_side::host_vt::set_deployment(id);
    }
}

/// A walked boot: every instance in plan order with its phase and opened value, and the published id.
pub struct Booted<O> {
    pub opened: Vec<(u32, BootPhase, O)>,
    pub deployment: [u8; 16],
}

/// Why the walk refused the boot. Every arm names the instance index; the text is core's words plus the
/// plugin's scrubbed text (`OpenError` carries it already scrubbed, §11.2).
#[derive(Debug)]
pub enum BootRefused {
    /// The plan cannot place the deployment point (phases out of order, not exactly one store, a repeated index).
    Plan(String),
    /// An instance's open refused or failed.
    Open {
        index: u32,
        phase: BootPhase,
        error: Box<OpenError>,
    },
    /// A 2a/2b instance's re-check after the deployment id was published refused.
    Recheck { index: u32, error: Box<OpenError> },
    /// The deployment id could not be read or kept through the store.
    Deployment(String),
}

impl core::fmt::Display for BootRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Plan(text) => write!(f, "boot plan refused: {text}"),
            Self::Open {
                index,
                phase,
                error,
            } => write!(
                f,
                "boot refused: instance {index} ({}) did not open: {}",
                phase_word(*phase),
                OpenText(error)
            ),
            Self::Recheck { index, error } => write!(
                f,
                "boot refused: instance {index} refused its check after the deployment id was set: {}",
                OpenText(error)
            ),
            Self::Deployment(text) => write!(f, "boot refused: deployment id: {text}"),
        }
    }
}

impl std::error::Error for BootRefused {}

fn phase_word(phase: BootPhase) -> &'static str {
    match phase {
        BootPhase::StoreSecrets => "step 2a",
        BootPhase::Store => "step 2b",
        BootPhase::Rest => "step 2c",
    }
}

/// `OpenError` has no `Display` of its own: core's words, the code, then the plugin's scrubbed text.
pub(super) struct OpenText<'a>(pub(super) &'a OpenError);

impl core::fmt::Display for OpenText<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fn coded(
            f: &mut core::fmt::Formatter<'_>,
            word: &str,
            code: u32,
            text: &str,
            error: Option<&busbar_ports::PluginCode>,
        ) -> core::fmt::Result {
            write!(f, "{word} {code}")?;
            if let Some(error) = error {
                write!(f, " ({error})")?;
            }
            write!(f, ": {text}")
        }
        match self.0 {
            OpenError::Refused { refusal, error } => {
                write!(f, "refused: {refusal}")?;
                match error {
                    Some(error) => write!(f, " ({error})"),
                    None => Ok(()),
                }
            }
            OpenError::Config { code, text, error } => {
                coded(f, "config", *code, text, error.as_ref())
            }
            OpenError::Failed { code, text, error } => {
                coded(f, "failed", *code, text, error.as_ref())
            }
            OpenError::Call(call) => write!(f, "call: {call:?}"),
            OpenError::Unknown(text) => write!(f, "unknown: {text}"),
        }
    }
}

/// Walk `plan`: open every step in order, with the deployment point between 2b and 2c (or after 2b when the
/// plan has no 2c step). Stops at the first refusal; what was opened is dropped (closed) with the error.
pub async fn walk<S: BootSteps>(
    plan: &BootPlan,
    steps: &S,
) -> Result<Booted<S::Opened>, BootRefused> {
    bootstrap(plan, steps).await?.finish(steps).await
}

/// Completed S5/S6 owners and the validated remainder. Constructing this value has
/// published and rechecked the deployment identity, but has opened no 2c instance.
/// Root may retain it while reading overlays and constructing complete S7 services.
pub struct Bootstrap<O> {
    opened: Vec<(u32, BootPhase, O)>,
    deployment: [u8; 16],
    rest: Vec<u32>,
}

impl<O: Send> Bootstrap<O> {
    /// Consume the stage exactly once after the caller has prepared serving dependencies.
    pub async fn finish<S: BootSteps<Opened = O>>(
        self,
        steps: &S,
    ) -> Result<Booted<O>, BootRefused> {
        let Self {
            mut opened,
            deployment,
            rest,
        } = self;
        for index in rest {
            let port = steps.open(index).await.map_err(|error| BootRefused::Open {
                index,
                phase: BootPhase::Rest,
                error: Box::new(error),
            })?;
            opened.push((index, BootPhase::Rest, port));
        }
        Ok(Booted { opened, deployment })
    }
}

pub async fn bootstrap<S: BootSteps>(
    plan: &BootPlan,
    steps: &S,
) -> Result<Bootstrap<S::Opened>, BootRefused> {
    in_phase_order(plan)?;
    let mut opened = Vec::new();
    let mut rest = Vec::new();
    for &(index, phase) in &plan.steps {
        if phase == BootPhase::Rest {
            rest.push(index);
            continue;
        }
        let port = steps.open(index).await.map_err(|error| BootRefused::Open {
            index,
            phase,
            error: Box::new(error),
        })?;
        opened.push((index, phase, port));
    }
    let deployment = deployment_point(steps, &opened).await?;
    Ok(Bootstrap {
        opened,
        deployment,
        rest,
    })
}

/// Round 29: read the id through the store, publish it, then re-check every 2a/2b instance in plan order.
/// `opened` holds exactly the 2a/2b steps here (the walk calls it before the first 2c open).
async fn deployment_point<S: BootSteps>(
    steps: &S,
    opened: &[(u32, BootPhase, S::Opened)],
) -> Result<[u8; 16], BootRefused> {
    let store = opened
        .iter()
        .find(|(_, phase, _)| *phase == BootPhase::Store)
        .map(|(_, _, store)| store)
        .ok_or_else(|| BootRefused::Plan("no store step before the deployment point".into()))?;
    let id = steps
        .deployment(store)
        .await
        .map_err(BootRefused::Deployment)?;
    if id == [0; 16] {
        return Err(BootRefused::Deployment(
            "the store answered an all-zero deployment id".into(),
        ));
    }
    steps.publish(id);
    for (index, _, _) in opened {
        steps
            .check(*index)
            .await
            .map_err(|error| BootRefused::Recheck {
                index: *index,
                error: Box::new(error),
            })?;
    }
    Ok(id)
}

/// 2a* then exactly one 2b then 2c*, each index once: the only shape in which the deployment point has a place.
fn in_phase_order(plan: &BootPlan) -> Result<(), BootRefused> {
    let rank = |phase| match phase {
        BootPhase::StoreSecrets => 0u8,
        BootPhase::Store => 1,
        BootPhase::Rest => 2,
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut last = 0u8;
    let mut stores = 0usize;
    for (at, &(index, phase)) in plan.steps.iter().enumerate() {
        if !seen.insert(index) {
            return Err(BootRefused::Plan(format!(
                "instance {index} appears twice (step {at})"
            )));
        }
        if rank(phase) < last {
            return Err(BootRefused::Plan(format!(
                "instance {index} ({}) comes after a later phase (step {at})",
                phase_word(phase)
            )));
        }
        if phase == BootPhase::Rest && stores == 0 {
            return Err(BootRefused::Plan(format!(
                "instance {index} (step 2c) comes before any store (step {at})"
            )));
        }
        stores += usize::from(phase == BootPhase::Store);
        last = rank(phase);
    }
    if stores != 1 {
        return Err(BootRefused::Plan(format!(
            "{stores} store steps; a boot has exactly one"
        )));
    }
    Ok(())
}

/// The kernel's boot identity keeps the id as `dep_` + 32 lowercase hex (`BootIdentity::keep_deployment_id`);
/// the host publishes the 16 bytes. All zero is not an id.
pub fn deployment_bytes(text: &str) -> Result<[u8; 16], String> {
    let malformed = || "the deployment identity is not dep_ followed by 32 hex digits".to_owned();
    let hex_part = text.strip_prefix("dep_").ok_or_else(malformed)?;
    let mut id = [0u8; 16];
    hex::decode_to_slice(hex_part, &mut id).map_err(|_| malformed())?;
    if id == [0; 16] {
        return Err("the deployment identity is all zero".into());
    }
    Ok(id)
}

/// The root's deployment-row read over the opened store; the future owns what it needs (the store's `Arc`).
pub type DeploymentRead =
    dyn Fn(&busbar_ports::store::StoreHandle) -> BoxFut<'static, Result<[u8; 16], String>> + Sync;

/// The MIN-3 registry as the walk's steps: `instances[i]` is configured instance `i` with its kind, exactly the
/// slice `Registry::boot_plan` was given. The kind picks the registry's typed `open_<kind>`; this table is the
/// only place the boot names a kind.
pub struct RegistryBoot<'r, N: Needs> {
    pub registry: &'r Registry,
    pub needs: &'r std::sync::Arc<N>,
    pub store_seal: busbar_plugin_loader::instance::StoreSeal,
    pub instances: &'r [(KindCode, InstanceSpec<'r>)],
    /// Reads or writes the deployment row through the opened store (the root's `BootIdentity` over that store,
    /// then `deployment_bytes`).
    pub deployment: &'r DeploymentRead,
}

fn wrap_open<'a, T: 'a>(
    fut: BoxFut<'a, Result<T, OpenError>>,
    wrap: fn(T) -> OpenedPort,
) -> BoxFut<'a, Result<OpenedPort, OpenError>> {
    Box::pin(async move { fut.await.map(wrap) })
}

impl<N: Needs> RegistryBoot<'_, N> {
    fn spec(&self, index: u32) -> Option<&(KindCode, InstanceSpec<'_>)> {
        usize::try_from(index)
            .ok()
            .and_then(|at| self.instances.get(at))
    }
}

/// The refusal of a plan step that names an instance the boot was not given.
fn unconfigured(index: u32) -> OpenError {
    OpenError::Unknown(format!(
        "the boot plan names instance {index}, which is not configured"
    ))
}

impl<N: Needs> BootSteps for RegistryBoot<'_, N> {
    type Opened = OpenedPort;

    fn open(&self, index: u32) -> BoxFut<'_, Result<OpenedPort, OpenError>> {
        let Some((kind, spec)) = self.spec(index) else {
            return Box::pin(core::future::ready(Err(unconfigured(index))));
        };
        let registry = self.registry;
        match kind {
            KindCode::Store => wrap_open(
                registry.open_store(spec, self.needs, std::sync::Arc::clone(&self.store_seal)),
                OpenedPort::Store,
            ),
            KindCode::Secret => {
                wrap_open(registry.open_secret(spec, self.needs), OpenedPort::Secret)
            }
            KindCode::Auth => wrap_open(registry.open_auth(spec, self.needs), OpenedPort::Auth),
            KindCode::Hook => wrap_open(registry.open_hook(spec, self.needs), OpenedPort::Hook),
            KindCode::Export => {
                wrap_open(registry.open_export(spec, self.needs), OpenedPort::Export)
            }
            KindCode::Plane => wrap_open(registry.open_plane(spec, self.needs), OpenedPort::Plane),
            KindCode::Transport => wrap_open(
                registry.open_transport(spec, self.needs),
                OpenedPort::Transport,
            ),
        }
    }

    fn check(&self, index: u32) -> BoxFut<'_, Result<(), OpenError>> {
        match self.spec(index) {
            Some((_, spec)) => self.registry.check(spec),
            None => Box::pin(core::future::ready(Err(unconfigured(index)))),
        }
    }

    fn deployment<'a>(&'a self, store: &'a OpenedPort) -> BoxFut<'a, Result<[u8; 16], String>> {
        match store {
            OpenedPort::Store(handle) => (self.deployment)(handle),
            _ => Box::pin(core::future::ready(Err(
                "the step-2b instance did not open as a store".to_owned(),
            ))),
        }
    }
}
