// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot's MIN-3 registry (ROOT-BOOT; ABI-MIN3-INTERFACE §11.2, §12.10 item 4, §13).
//!
//! Bootstrap Secret and Store opens use permanently restricted record and directory capabilities.
//! After the deployment identity is established and rechecked, serving opens receive complete shared
//! record and directory owners and the immutable prefix of successfully opened secret instances.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::boot::restricted::{BootstrapDirectory, BootstrapRecords};
use super::boot::walk::{deployment_bytes, BootSteps, DeploymentRead};
use busbar_contract::secret_ref::{SecretRef, Sugars};
use busbar_contract::secure::SecureVec;
use busbar_core_connector::guard::Guard;
use busbar_core_connector::need::judge::Judge;
use busbar_core_connector::need::network::{
    BootstrapConnector, NetworkInputs, ServingConnector, SharedResolver,
};
use busbar_core_connector::need::{ConnectorIo, HostNeeds, NeedLimits};
use busbar_kernel::channels::signals::SignalRegistry;
use busbar_kernel::channels::SessionSignals;
use busbar_kernel::config::{PluginsCfg, RootCfg};
use busbar_kernel::directory::{KernelDirectory, LogEvents};
use busbar_kernel::host_services::{DestJudge, KernelServices};
use busbar_kernel::ingress::replay::StoreReplay;
use busbar_kernel::ingress::signed_ingress::{RouteSecrets, StandardWebhooks};
use busbar_kernel::persistence::boot_identity::BootIdentity;
use busbar_kernel::persistence::startup::Startup;
use busbar_kernel::plane_driver::plane_judge::PlaneJudge;
use busbar_kernel::plane_driver::port::{PortDriver, PortSeat};
use busbar_kernel::plane_driver::port_intents::{
    DurableDecider, DurableWork, KernelIntents, Namespace,
};
use busbar_kernel::plane_driver::port_observations::ObsCustody;
use busbar_kernel::plane_driver::port_serve::TicketGate;
use busbar_kernel::plane_driver::port_services::Services;
use busbar_kernel::plane_driver::port_work::{Binder as WorkBinder, StoreWork};
use busbar_kernel::plane_grants::{
    SealedTickets, TicketAdmitted, TicketDenied, TicketMint, Tickets,
};
use busbar_kernel::plugin_config::{Binder, ConfigBinder};
use busbar_kernel::plugin_records::{PluginRecords, RecordsDenied, StoreRecords};
use busbar_kernel::push::{PushQueue, StorePushQueue};
use busbar_kernel::retry::Policy as RetryPolicyImpl;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller as LoaderCaller};
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::admit::Admitted;
use busbar_plugin_loader::instance::{
    InstanceSpec, OpenError, OpenedPort, PreparedInstance, Registry,
};
use busbar_ports::store::StoreHandle;

use busbar_kernel::teller::Kernel;

use super::plane_seats::{compose as compose_seat, ConnTable, SeatShared, SpawnCustody};
use super::port_mount::Ingress;
use super::secret_custody::{BootCustody, BootSecrets};

/// The complete records owner shared by serving Needs, replay and plane drivers.
pub(crate) type Records = Arc<StoreRecords>;
/// The complete directory owner shared by serving DIRECTORY Needs.
pub(crate) type Directory = Arc<KernelDirectory>;
/// The Need handlers the registry runs every plugin under.
pub(crate) type Needs = HostNeeds<BootCustody, Records, Directory>;
type BootstrapNeeds = HostNeeds<BootCustody, BootstrapRecords, BootstrapDirectory>;
#[path = "min3_hooks.rs"]
pub(crate) mod hooks;
/// The process's MIN-3 registry.
pub(crate) type MinRegistry = Registry;

/// How long a core-internal secret may take to resolve at boot.
pub(crate) const CORE_SECRET_DEADLINE: Duration = Duration::from_secs(30);
/// Core's own secrets, resolved at boot through the secret kind into owned values (IF §11.2: the admin token,
/// the signing key). `None` = the config states no such reference.
#[derive(Default)]
pub(crate) struct CoreSecrets {
    pub(crate) operator_token: Option<SecureVec>,
    pub(crate) signing_key: Option<SecureVec>,
}

/// The serving instances' shared owners, constructed after the Store deployment checks.
struct Shared {
    records: Records,
    push: Arc<dyn PushQueue>,
    signals: Arc<SignalRegistry>,
    /// The observation custody every seat's OBS_SCOPE and OBSERVE run on (units register as requests bill).
    observations: ObsCustody,
    /// Durable WORK for every seat (rows are scoped by instance name).
    work: Arc<StoreWork>,
}

/// The ticket store of a deployment with no usable `auth.signing_key`: nothing is a ticket and nothing mints
/// (fail closed). Every seat holds either this or the sealed store the host key opened.
struct ClosedTickets;

impl Tickets for ClosedTickets {
    fn mint<'a>(
        &'a self,
        _who: &'a LoaderCaller<'_>,
        _m: TicketMint<'a>,
    ) -> BoxFut<'a, Result<(Box<str>, u64), RecordsDenied>> {
        Box::pin(core::future::ready(Err(RecordsDenied::Unavailable)))
    }

    fn is_ticket(&self, _credential: &str) -> bool {
        false
    }

    fn admit<'a>(
        &'a self,
        _plane: &'a LoaderCaller<'_>,
        _audience: &'a str,
        _credential: &'a str,
        _now_s: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>> {
        Box::pin(core::future::ready(Err(TicketDenied::Unavailable)))
    }
}

/// The ticket store every plane seat is built with (IF §12.11): its host key is derived from core's
/// `auth.signing_key`, which the walk resolves (the secret instances are open before any plane, step 2a) before
/// the seat is built. Without a signing key, or when the key cannot be derived, the store is shut.
fn ticket_store<R: PluginRecords + Clone>(
    records: &R,
    signing: Option<&SecureVec>,
) -> Arc<dyn Tickets> {
    let Some(signing) = signing else {
        tracing::info!("no auth.signing_key: plane tickets are not admitted");
        return Arc::new(ClosedTickets);
    };
    let mut key = SecureVec::zeroed(32);
    if busbar_contract::crypto::hkdf_sha256(
        b"busbar.ticket-host.v1",
        &signing[..],
        b"host-key",
        &mut key[..],
    )
    .is_err()
    {
        tracing::warn!("the ticket host key could not be derived: plane tickets are not admitted");
        return Arc::new(ClosedTickets);
    }
    match SealedTickets::new(records.clone(), &key[..], busbar_kernel::store::now) {
        Some(sealed) => Arc::new(sealed),
        None => {
            tracing::warn!("the ticket store refused its host key: plane tickets are not admitted");
            Arc::new(ClosedTickets)
        }
    }
}

/// The services every plane seat's intents run on (IF §12.1, §12.11): what the boot can build. JUDGE is the
/// deployment's one destination judge, or the fail-closed one (every destination internal, BUSBAR-7108) when the
/// process has none. MINT is the ticket store the seat is built with, OBS_SCOPE and OBSERVE the process's observation custody. ENTITLE,
/// SIGN, CONNECT, SIGHT/TRUST and RENDEZVOUS have no production owner at boot yet (no grant resolver, host signing
/// key, caller-connection store, trust book or media carrier is built here), so each answers its fail-closed value.
fn plane_services(
    observations: &ObsCustody,
    tickets: Arc<dyn Tickets>,
    judge: Option<Arc<dyn DestJudge>>,
) -> Services {
    Services {
        judge: Some(judge.map_or_else(PlaneJudge::unavailable, PlaneJudge::new)),
        tickets: Some(tickets),
        observations: Some(Arc::new(observations.clone())),
        ..Services::default()
    }
}

/// Whether a WORK_OPEN target (a path and query) lies on one of the instance's ROUTE_RECOVERY patterns.
fn recovery_matcher(patterns: Vec<Box<str>>) -> Box<dyn Fn(&str) -> bool + Send + Sync> {
    use busbar_contract::abi::transport::route::{path_matches, PATH_PATTERN};
    Box::new(move |target| {
        let path = target.split(['?', '#']).next().unwrap_or_default();
        patterns
            .iter()
            .any(|pattern| path_matches(PATH_PATTERN, pattern, path))
    })
}

impl Shared {
    fn new(
        records: Records,
        push: Arc<dyn PushQueue>,
        store: Arc<busbar_kernel::persistence::facade::CoreStore>,
        binder: Arc<WorkBinder>,
    ) -> Self {
        Self {
            records,
            push,
            signals: SignalRegistry::new(),
            observations: ObsCustody::new(Arc::new(busbar_kernel::store::now_ms)),
            work: Arc::new(StoreWork::new(
                store,
                binder,
                Arc::new(busbar_kernel::store::now_ms),
            )),
        }
    }
}

/// What a boot through the MIN-3 registry leaves running.
pub(crate) struct Booted {
    pub(crate) registry: Arc<MinRegistry>,
    _bootstrap_registry: Arc<MinRegistry>,
    _transports: Vec<transports::ServedTransport>,
    _native_invocations: Vec<busbar_kernel::host_services::NativeInvocationAdmission>,
    _opened: Vec<(
        u32,
        busbar_plugin_loader::instance::BootPhase,
        Option<OpenedPort>,
    )>,
    pub(crate) auth: Arc<super::min3_auth::AuthSet>,
    pub(crate) provisioning: Vec<Arc<super::provisioning_mount::ProvisionMount>>,
    pub(crate) config_version: u64,
    pub(crate) seats: Vec<PortSeat>,
    pub(crate) core: Arc<CoreSecrets>,
    /// The secret kind the boot opened its secret instances into (webhook secrets resolve through it).
    pub(crate) secrets: Arc<BootSecrets>,
    pub(crate) resolver: Arc<busbar_kernel::config::secret::SecretResolver>,
    pub(crate) deployment: [u8; 16],
    /// The records the signed-ingress replay claims are written through.
    records: Records,
    /// Durable WORK of every seat: what the recovery scheduler scans ([`recover_ports`]).
    work: Arc<StoreWork>,
}

impl std::fmt::Debug for Booted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Booted")
            .field("seats", &self.seats)
            .finish_non_exhaustive()
    }
}

impl Booted {
    /// The boot's one summary line: what ran, never a value.
    fn describe(&self) -> String {
        let held = |secret: &Option<SecureVec>| {
            if secret.is_some() {
                "resolved"
            } else {
                "not configured"
            }
        };
        format!(
            "MIN-3 boot: {} planes served through ports, {} shorthands declared, deployment dep_{}, \
             store attached: true; core secrets: admin token {}, signing key {}",
            self.seats.len(),
            self.registry.sugars().len(),
            hex::encode(self.deployment),
            held(&self.core.operator_token),
            held(&self.core.signing_key),
        )
    }
}

/// How long one recovery scan, and one recovery poll, may take (today's scheduler's per-poll deadline).
const RECOVERY_POLL: Duration = Duration::from_secs(30);

/// The request ids of core-originated recovery polls (non-zero, unique for the process life).
static RECOVERY_REQUESTS: AtomicU64 = AtomicU64::new(1);

/// The recovery scheduler runs (`true`) or stopped (`false`): WORK_OPEN answers `R_UNSUPPORTED` while it does not
/// (core cannot recover, IF §12.24 step 1). A boot that took the old path has no MIN-3 instances.
pub(crate) fn set_recovery_ready(booted: &Booted, ready: bool) {
    booted.work.set_recovery_ready(ready);
}

/// One recovery pass over the MIN-3 plane seats (IF §12.24 step 3), on the scheduler's cadence: per seat with a
/// ROUTE_RECOVERY route, the live rows no recovery session holds (`DurableWork::recoverable`); for each whose binding
/// still restores (`restore_for_app` + `standing_over`, today's standing and expiry rules) one poll as the restored
/// principal (`PortSeat::recover`), the row held for the poll's life. Core never infers settlement: a row stays live
/// until the plane settles it. Answers how many polls were attempted.
pub(crate) async fn recover_ports(booted: &Booted, app: Arc<busbar_kernel::state::App>) -> usize {
    if app.governance.is_none() {
        return 0;
    }
    let mut attempted = 0;
    for seat in &booted.seats {
        if seat.driver.routes().recovery.is_empty() {
            continue;
        }
        let who = seat.who.caller();
        let found = tokio::time::timeout(RECOVERY_POLL, booted.work.recoverable(&who)).await;
        let work = match found {
            Ok(Ok(work)) => work,
            Ok(Err(error)) => {
                tracing::warn!(instance = %seat.instance, error, "durable work recovery scan failed");
                continue;
            }
            Err(_) => continue,
        };
        for work in work {
            let now = busbar_kernel::store::now();
            let Some(key) = work.restore_for_app(&app, now) else {
                continue;
            };
            if busbar_kernel::plane_driver::standing_over(Arc::clone(&app))(&key, now).is_none() {
                continue;
            }
            let request_id = RECOVERY_REQUESTS.fetch_add(1, Ordering::Relaxed);
            match tokio::time::timeout(RECOVERY_POLL, seat.recover(&work, &key.id, request_id))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(refused)) => {
                    tracing::warn!(instance = %seat.instance, ?refused, "a durable work poll was not delivered");
                }
                Err(_) => {
                    tracing::warn!(instance = %seat.instance, "a durable work poll ran past its deadline");
                }
            }
            attempted += 1;
            drop(work);
        }
    }
    attempted
}

/// Webhook secrets by reference, through custody (a route's secret resolves like any other reference: by reference,
/// an empty call stack, no source named in an error). A reference that does not resolve verifies nothing.
struct CustodySecrets(Arc<BootSecrets>);

impl RouteSecrets for CustodySecrets {
    fn resolve<'a>(&'a self, reference: &'a SecretRef) -> BoxFut<'a, Option<SecureVec>> {
        Box::pin(async move {
            self.0
                .resolve_ref(Instant::now() + CORE_SECRET_DEADLINE, reference)
                .await
                .ok()
        })
    }
}

/// What the plane routes of class AUTH_SIGNED_INGRESS verify with (IF §12.11, TRANSPORT-SECURITY-POLICY): core's
/// Standard Webhooks verifier over custody and the replay claim in the core store. The IF names no config key for a
/// route's webhook secret and K7's `Min3Config` carries none yet, so no route has one: every signed route answers
/// `R_BAD_CREDENTIAL` until the operator's `routes.<id>` block supplies it (the same answer the unwired route gave).
pub(crate) fn signed_ingress(booted: &Booted) -> Arc<Ingress> {
    Arc::new(Ingress {
        verifier: Arc::new(StandardWebhooks::new(CustodySecrets(Arc::clone(
            &booted.secrets,
        )))),
        replay: Arc::new(StoreReplay::new(booted.records.clone())),
        secrets: Arc::new(|_: &str, _: u32| None),
    })
}

/// The MIN-3 images the plugins directory's scan holds, each with its signed manifest's `alias` (a plane instance is
/// named by it, [`plane_instances`]). The scan verified each one; admission re-verifies the same bytes. An image that
/// is not MIN-3 (a refusal at admit) stays on the old path, which judges it as before.
pub(crate) fn admit_images(plugins: &PluginsCfg) -> Result<Vec<(Admitted, String)>, String> {
    let mut admitted = admit_linked_images(crate::LINKED.images)?;
    admit_dropped_images(plugins, &mut admitted)?;
    Ok(admitted)
}

fn admit_linked_images(
    rows: &[super::linked::LinkedImage],
) -> Result<Vec<(Admitted, String)>, String> {
    rows.iter()
        .map(|row| {
            (row.admit)()
                .map(|image| (image, row.alias.to_owned()))
                .map_err(|refusal| refusal.to_string())
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn admit_dropped_images(
    plugins: &PluginsCfg,
    admitted: &mut Vec<(Admitted, String)>,
) -> Result<(), String> {
    let Some(scanned) = super::boot::dropped_registry() else {
        return Ok(());
    };
    let policy = super::boot::trust_policy(plugins, env!("CARGO_PKG_VERSION"))
        .map_err(|error| format!("plugins.trust is invalid: {error}"))?;
    for row in scanned.loadable() {
        if row.linked() {
            continue;
        }
        match busbar_plugin_loader::admit::admit_bytes(&row.lib_bytes, &row.manifest, &policy) {
            Ok(image) => admitted.push((image, row.manifest.alias.clone())),
            Err(refusal) => tracing::debug!(
                plugin = %row.manifest.name,
                %refusal,
                "not a MIN-3 image: it stays on the old path"
            ),
        }
    }
    Ok(())
}

/// Only Linux loads plugin images.
#[cfg(not(target_os = "linux"))]
fn admit_dropped_images(
    _plugins: &PluginsCfg,
    _admitted: &mut Vec<(Admitted, String)>,
) -> Result<(), String> {
    Ok(())
}

/// One configured instance, owned until the plan borrows it.
pub(crate) struct Configured {
    pub(crate) kind: KindCode,
    pub(crate) identity: String,
    pub(crate) name: String,
    pub(crate) config: Vec<u8>,
    pub(crate) limits: busbar_plugin_abi::host_side::caller::InstanceLimits,
}

/// One admitted MIN-3 plane image: its identity and its signed manifest's `alias` (today's plane name, IF §12.10:
/// `llm`, `mcp`, `a2a`, `streaming`, `decisions`; empty when the manifest states none).
pub(crate) struct PlaneImage {
    identity: String,
    alias: String,
}

/// The plane instances the admitted MIN-3 plane images make (W2-SW-PLANE). The operator serves a plane by serving it
/// (IF §12.23 rule 1: "no config word is added"), so each admitted plane image is one instance. Its name is the
/// image's alias, so an instance keeps today's plane name (ADMIN-API A-1), else its identity. Its config is the
/// document's top-level section of that name, the plane's 1.x bag, which its own `migrate` converts (IF §12.10 item
/// 2), else `{}`. The config grammar has no `planes.<name>` block, so a plane runs at the kind's default limits. Two images answering one name are refused.
fn plane_instances(
    images: &[PlaneImage],
    sections: &std::collections::BTreeMap<&'static str, busbar_contract::yaml::Value>,
) -> Result<Vec<Configured>, String> {
    let mut out: Vec<Configured> = Vec::with_capacity(images.len());
    for image in images {
        let name = if image.alias.is_empty() {
            image.identity.clone()
        } else {
            image.alias.clone()
        };
        if let Some(first) = out.iter().find(|one| one.name == name) {
            return Err(format!(
                "the plane images `{}` and `{}` both answer to the instance name `{name}`; remove one",
                first.identity, image.identity
            ));
        }
        let config = match sections.get(name.as_str()) {
            Some(section) => serde_json::to_vec(section)
                .map_err(|error| format!("{name}: the plane's section is not JSON ({error})"))?,
            None => b"{}".to_vec(),
        };
        out.push(Configured {
            kind: KindCode::Plane,
            identity: image.identity.clone(),
            limits: busbar_plugin_abi::host_side::caller::InstanceLimits::default(),
            name,
            config,
        });
    }
    Ok(out)
}

/// Every configured instance of a kind the MIN-3 path serves, in config order: the secret instances, the store, then
/// the plane instances ([`plane_instances`]). A later switch-over adds its kind here and nowhere else (the walk is
/// generic).
fn configured(cfg: &RootCfg, planes: &[PlaneImage]) -> Result<Vec<Configured>, String> {
    use busbar_kernel::appbuild::{instance_limits, STORE_INSTANCE};
    let seal = busbar_kernel::seal::lend();
    let mut out = Vec::new();
    let grammar = cfg.grammar().map_err(|error| error.0)?;
    for (name, source) in &grammar.secret_instances {
        let config = match cfg.secrets.get(name) {
            Some(secret) => secret
                .settings
                .encode()
                .map_err(|error| format!("secrets.{name}: {error}"))?
                .into_exposed(&seal),
            None => b"{}".to_vec(),
        };
        out.push(Configured {
            kind: KindCode::Secret,
            identity: source.identity.clone(),
            name: name.clone(),
            config,
            limits: instance_limits(cfg, "secrets", name),
        });
    }
    let store = cfg
        .store
        .as_ref()
        .ok_or_else(busbar_kernel::config::store_required)?;
    let config = store
        .settings
        .encode()
        .map_err(|error| format!("store: {error}"))?
        .into_exposed(&seal);
    out.push(Configured {
        kind: KindCode::Store,
        identity: store.module.clone(),
        name: STORE_INSTANCE.to_owned(),
        config,
        limits: instance_limits(cfg, STORE_INSTANCE, STORE_INSTANCE),
    });
    out.extend(plane_instances(
        planes,
        &super::door_steps::raw_sections(cfg),
    )?);
    out.extend(hooks::configured(cfg)?);
    let mut providers = cfg.identity_providers.iter().collect::<Vec<_>>();
    providers.sort_by_key(|(name, _)| *name);
    for (name, provider) in providers {
        if busbar_kernel::config::is_builtin_identity_module(&provider.module) {
            continue;
        }
        out.push(Configured {
            kind: KindCode::Auth,
            identity: provider.module.clone(),
            name: name.clone(),
            config: provider
                .settings
                .encode()
                .map_err(|error| format!("identity-providers.{name}: {error}"))?
                .into_exposed(&seal),
            limits: instance_limits(cfg, "identity-providers", name),
        });
    }
    for (name, def) in &cfg.export_defs {
        out.push(Configured {
            kind: KindCode::Export,
            identity: def.module.clone(),
            name: name.clone(),
            config: def
                .settings
                .encode()
                .map_err(|error| format!("export.{name}: {error}"))?
                .into_exposed(&seal),
            limits: instance_limits(cfg, "export", name),
        });
    }
    Ok(out)
}

/// The boot's configured upstreams (IF §12.1): one table, shared by every plane seat's egress walk and carrier,
/// typed over the config's `upstreams:` section and each entry's parsed binding (`cfg.min3`, W1-K7). The load
/// already typed the same section once (`config::resolve`), so a refusal here means the config changed shape
/// between load and boot; a binding naming an upstream with no entry still refuses the boot.
pub(crate) fn declared_planes(
    registry: &MinRegistry,
    instances: &mut [Configured],
) -> Result<std::collections::BTreeMap<String, busbar_kernel::upstreams::Declared>, String> {
    let mut declarations = std::collections::BTreeMap::new();
    for instance in instances
        .iter_mut()
        .filter(|one| matches!(one.kind, KindCode::Plane))
    {
        let described = registry
            .described(&instance.identity)
            .ok_or_else(|| format!("{}: the plane image has not been admitted", instance.name))?;
        let pointers: Vec<_> = described
            .paths(busbar_plugin_abi::records::tag::D_UPSTREAM_PATH)
            .collect();
        let authored = busbar_contract::json::parse_value(&instance.config)
            .map_err(|e| format!("{}: its authored config is invalid: {e}", instance.name))?;
        let declared = busbar_kernel::upstreams::declared(
            &instance.name,
            &authored,
            &pointers,
            &busbar_kernel::plugin_config::upstream_anchor,
        )
        .map_err(|errors| errors.join("; "))?;
        instance.config = busbar_contract::json::to_vec(&declared.visible_bag).map_err(|e| {
            format!(
                "{}: its visible config cannot be encoded: {e}",
                instance.name
            )
        })?;
        declarations.insert(instance.name.clone(), declared);
    }
    Ok(declarations)
}

/// Reference schemas include implicit instances and are keyed by the exact configured reference target.
fn ref_schemas(cfg: &RootCfg) -> Result<Vec<(Arc<str>, Box<str>)>, String> {
    let grammar = cfg.grammar().map_err(|error| error.0)?;
    Ok(grammar
        .secret_instances
        .iter()
        .map(|(name, source)| {
            (
                Arc::from(name.as_str()),
                Box::from(source.ref_schema.as_str()),
            )
        })
        .collect())
}

/// The registry over the production Need handlers, every image added, the binder told the shorthands and the
/// schemas, custody attached to the binder and the registry's scrub sets, and the kernel's sides installed.
/// `store` carries what the deployment step fills.
struct Built {
    registry: Arc<MinRegistry>,
    sugars: Sugars,
    secrets: Arc<BootSecrets>,
    binder: Arc<dyn ConfigBinder>,
    network: NetworkOwner,
}

/// The stage's one retained native network owner (#298 option B, SECURITY-297-298-r3): the file-era
/// owner for S5/S6 bootstrap Needs, a separate owner for the effective configuration's serving Needs.
/// Every Need of a stage shares its frozen guard, resolver, trust and proxy choice.
enum NetworkOwner {
    Bootstrap(BootstrapConnector),
    Serving(ServingConnector),
}

impl NetworkOwner {
    fn io(&self) -> ConnectorIo {
        match self {
            Self::Bootstrap(owner) => owner.io(),
            Self::Serving(owner) => owner.io(),
        }
    }

    fn judge(&self) -> Judge<SharedResolver> {
        match self {
            Self::Bootstrap(owner) => owner.judge(),
            Self::Serving(owner) => owner.judge(),
        }
    }
}

/// The complete network inputs of one stage, read before any native instance opens: `guard` frozen,
/// the system resolver, `advanced.tls` validated into its trust store, the process proxy choice and
/// `advanced.proxy_resolution`.
fn network_inputs(cfg: &RootCfg, guard: &Guard) -> Result<NetworkInputs, String> {
    Ok(NetworkInputs {
        runtime: tokio::runtime::Handle::try_current()
            .map_err(|_| "native networking is built on the boot runtime".to_owned())?,
        guard: guard.freeze(),
        resolver: Arc::new(busbar_core_connector::guard::SystemResolver),
        trust: super::connector::trust_store_of(&cfg.outbound_tls)
            .map_err(|errors| errors.join("\n"))?,
        proxy: busbar_core_connector::proxy::from_env()?,
        resolution: cfg.proxy_resolution,
        observations: Arc::default(),
    })
}

impl Built {
    fn bootstrap_needs_for(&self, prefix: Arc<BootSecrets>) -> Arc<BootstrapNeeds> {
        Arc::new(HostNeeds::new(
            self.network.io(),
            self.network.judge(),
            BootCustody(prefix),
            BootstrapRecords,
            BootstrapDirectory,
            Arc::clone(&self.binder),
            NeedLimits::default(),
        ))
    }

    fn needs_for(
        &self,
        prefix: Arc<BootSecrets>,
        records: Records,
        directory: Directory,
    ) -> Arc<Needs> {
        Arc::new(HostNeeds::new(
            self.network.io(),
            self.network.judge(),
            BootCustody(prefix),
            records,
            directory,
            Arc::clone(&self.binder),
            NeedLimits::default(),
        ))
    }
}

fn build(
    process: &busbar_plugin_loader::process::ProcessResources,
    guard: Guard,
    cfg: &RootCfg,
    images: busbar_plugin_loader::instance::Images,
) -> Result<Built, String> {
    let sugars = cfg.grammar().map_err(|error| error.0)?.sugars.clone();
    let binder: Arc<dyn ConfigBinder> =
        Arc::new(Binder::new(Arc::new(sugars.clone()), ref_schemas(cfg)?));
    // The process's one secret kind, built over the binder and kept for the life of the process.
    let secrets = BootSecrets::empty(Arc::clone(&binder), Arc::clone(process.slots()));
    let registry = Registry::new(images, Arc::clone(&binder), Arc::clone(process.ids()));

    let network = NetworkOwner::Bootstrap(BootstrapConnector::new(network_inputs(cfg, &guard)?));
    let registry = Arc::new(registry);
    Ok(Built {
        registry,
        sugars,
        secrets,
        binder,
        network,
    })
}

/// S5/S6-only authority. No serving service or worker exists in this step owner.
struct BootstrapSteps<'r> {
    registry: &'r MinRegistry,
    instances: &'r [(KindCode, InstanceSpec<'r>)],
    deployment: &'r DeploymentRead,
    store_seal: busbar_plugin_loader::instance::StoreSeal,
    secrets: Mutex<Arc<BootSecrets>>,
    built: &'r Built,
    at_rest: Option<SecretRef>,
}

impl BootstrapSteps<'_> {
    fn prefix(&self) -> Arc<BootSecrets> {
        Arc::clone(&self.secrets.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl BootSteps for BootstrapSteps<'_> {
    type Opened = Option<OpenedPort>;

    fn open(&self, index: u32) -> BoxFut<'_, Result<Self::Opened, OpenError>> {
        let Some((kind, spec)) = self.instances.get(index as usize) else {
            return Box::pin(async {
                Err(OpenError::Unknown("unconfigured bootstrap step".into()))
            });
        };
        match kind {
            KindCode::Secret => Box::pin(async move {
                let prefix = self.prefix();
                let needs = self.built.bootstrap_needs_for(Arc::clone(&prefix));
                let prepared = self.registry.reserve(spec)?;
                let id = prepared.id();
                let port = self
                    .registry
                    .open_secret_reserved(prepared, &needs, &prefix.refs())
                    .await?;
                let next = prefix
                    .with_opened(
                        spec.name,
                        busbar_kernel::custody::SecretSource {
                            instance: id,
                            port: Arc::clone(&port),
                        },
                    )
                    .map_err(|_| OpenError::Unknown("secret prefix extension refused".into()))?;
                *self.secrets.lock().unwrap_or_else(PoisonError::into_inner) = next;
                Ok(Some(OpenedPort::Secret(port)))
            }),
            KindCode::Store => Box::pin(async move {
                // The secret instances are open (2a): the gate's key is published before the store's open asks.
                let secrets = self.prefix();
                publish_at_rest(self.at_rest.as_ref(), |what, reference| {
                    let secrets = Arc::clone(&secrets);
                    async move {
                        secrets
                            .resolve_ref(Instant::now() + CORE_SECRET_DEADLINE, &reference)
                            .await
                            .map_err(|denied| format!("{what} could not be resolved ({denied:?})"))
                    }
                })
                .await;
                let needs = self.built.bootstrap_needs_for(self.prefix());
                self.registry
                    .open_store(spec, &needs, &secrets.refs(), Arc::clone(&self.store_seal))
                    .await
                    .map(OpenedPort::Store)
                    .map(Some)
            }),
            _ => Box::pin(async {
                Err(OpenError::Unknown(
                    "serving instance requested before S7".into(),
                ))
            }),
        }
    }

    fn check(&self, index: u32) -> BoxFut<'_, Result<(), OpenError>> {
        match self.instances.get(index as usize) {
            Some((_, spec)) => self.registry.check(spec),
            None => {
                Box::pin(async { Err(OpenError::Unknown("unconfigured bootstrap step".into())) })
            }
        }
    }

    fn deployment<'a>(&'a self, store: &'a Self::Opened) -> BoxFut<'a, Result<[u8; 16], String>> {
        match store {
            Some(OpenedPort::Store(port)) => (self.deployment)(port),
            _ => Box::pin(async { Err("bootstrap did not open the Store".into()) }),
        }
    }
}

/// S8 steps hold the completed S5 secret prefix. They cannot extend or replace it.
struct Steps<'r> {
    registry: &'r MinRegistry,
    instances: &'r [(KindCode, InstanceSpec<'r>)],
    services: Option<Arc<KernelServices>>,
    seats: Mutex<Vec<PortSeat>>,
    invocations: Mutex<Vec<busbar_kernel::host_services::NativeInvocationAdmission>>,
    shared: Arc<Shared>,
    directory: Directory,
    /// `auth.signing_key`: the reference the ticket host key is derived from (IF §12.11).
    core: Arc<CoreSecrets>,
    /// The process's secret kind: the open secret instances and the custody that resolves through them.
    secrets: Arc<BootSecrets>,
    built: &'r Built,
    /// K9: what every seat's egress walk and carrier are composed over (the boot's one upstream table).
    seat: SeatShared,
    /// Dormant probes prepared while opening seats, consumed only at publication.
    probes: Mutex<Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>>,
}

impl Steps<'_> {
    fn prefix(&self) -> Arc<BootSecrets> {
        Arc::clone(&self.secrets)
    }

    async fn open_port(
        &self,
        index: u32,
        prepared: PreparedInstance,
    ) -> Result<OpenedPort, OpenError> {
        let prefix = self.prefix();
        let refs = prefix.refs();
        let needs =
            self.built
                .needs_for(prefix, self.shared.records.clone(), self.directory.clone());
        let Some((kind, _spec)) = self.instances.get(index as usize) else {
            return Err(OpenError::Unknown("unconfigured serving step".into()));
        };
        match kind {
            KindCode::Auth => self
                .registry
                .open_auth_reserved(prepared, &needs, &refs)
                .await
                .map(OpenedPort::Auth),
            KindCode::Hook => self
                .registry
                .open_hook_reserved(prepared, &needs, &refs)
                .await
                .map(OpenedPort::Hook),
            KindCode::Export => self
                .registry
                .open_export_reserved(prepared, &needs, &refs)
                .await
                .map(OpenedPort::Export),
            KindCode::Transport => self
                .registry
                .open_transport_reserved(prepared, &needs, &refs)
                .await
                .map(OpenedPort::Transport),
            KindCode::Plane => self
                .registry
                .open_plane_reserved(prepared, &needs, &refs)
                .await
                .map(OpenedPort::Plane),
            _ => Err(OpenError::Unknown("bootstrap kind in serving step".into())),
        }
    }

    #[cfg(test)]
    async fn open_plane(
        &self,
        spec: &InstanceSpec<'_>,
        prepared: PreparedInstance,
        hooks: &hooks::Environment,
        opened_hooks: &std::collections::BTreeMap<String, hooks::Opened>,
    ) -> Result<(), OpenError> {
        let who = Namespace {
            plugin: Arc::from(prepared.identity()),
            name: Arc::from(prepared.name()),
            instance: prepared.id(),
            slot: prepared.slot(),
        };
        let prefix = self.prefix();
        let needs = self.built.needs_for(
            Arc::clone(&prefix),
            self.shared.records.clone(),
            self.directory.clone(),
        );
        let port = self
            .registry
            .open_plane_reserved(prepared, &needs, &prefix.refs())
            .await?;
        self.compose_plane(spec, who, port, hooks, opened_hooks)
    }

    fn compose_plane(
        &self,
        spec: &InstanceSpec<'_>,
        who: Namespace,
        port: Arc<dyn busbar_ports::plane::PlanePort>,
        hooks: &hooks::Environment,
        opened_hooks: &std::collections::BTreeMap<String, hooks::Opened>,
    ) -> Result<(), OpenError> {
        let services = self.services.clone().ok_or_else(|| {
            OpenError::Unknown(
                "the kernel services are not installed: a plane cannot compose".into(),
            )
        })?;
        let seal = busbar_kernel::seal::acquire();
        let caller = busbar_contract::services::Caller::issue(
            &seal,
            Arc::from(spec.name),
            busbar_contract::abi::mechanism::KindCode::Plane,
        );
        let prefix = self.prefix();
        let driver = PortDriver::new(
            port,
            Arc::clone(&services),
            caller.clone(),
            Arc::new(busbar_kernel::refusal::CoreRefusals::new()),
            // The operator's `routes.<id>.auth` choice arrives with the K7 config (slice 9 leaves it unset).
            &|_| None,
        )
        .map_err(|error| OpenError::Unknown(format!("plane route declaration refused: {error}")))?;
        let driver = hooks
            .bind(self.registry, spec.name, driver, opened_hooks)
            .map_err(OpenError::Unknown)?;
        let invocation = services
            .admit_native_invocation(&caller)
            .map_err(|why| OpenError::Unknown(why.into()))?;
        // Tickets: the host key is resolved here (the secret instances are open, step 2a), so the gate and the
        // MINT store are built whole, with the key, before the seat exists.
        let tickets = ticket_store(&self.shared.records, self.core.signing_key.as_ref());
        let driver =
            driver.with_tickets(Arc::new(TicketGate::new(Arc::clone(&tickets), who.clone())));
        let rt = tokio::runtime::Handle::current();
        // K9: the seat's egress walk and carrier over the boot's upstream table, under the instance's core-held
        // `insecure_transport.accept`.
        let seat = SeatShared {
            upstreams: self.seat.upstreams.clone(),
            catalogs: self.seat.catalogs.clone(),
            signals: Arc::clone(&self.seat.signals),
            secrets: Arc::new(SpawnCustody(prefix)),
            kernel: Arc::clone(&self.seat.kernel),
            table: self.seat.table.clone(),
        };
        let wiring = compose_seat(
            &seat,
            spec.name,
            spec.limits.accept,
            &who,
            driver.port(),
            rt.clone(),
        )
        .map_err(|why| OpenError::Unknown(format!("plane `{}`: {why}", spec.name)))?;
        if let Some(probes) = wiring.probes {
            self.probes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(probes);
        }
        // WORK is opened only for a target on this instance's ROUTE_RECOVERY routes.
        let recovers = recovery_matcher(
            driver
                .routes()
                .recovery
                .iter()
                .map(|route| route.pattern.clone())
                .collect(),
        );
        let work: Arc<dyn DurableWork> = Arc::clone(&self.shared.work) as Arc<dyn DurableWork>;
        let judge = self
            .services
            .as_ref()
            .and_then(|s| s.installed_dest_judge());
        let intents = KernelIntents::new(
            Arc::new(self.shared.records.clone()),
            self.shared.push.clone(),
            Arc::clone(&self.shared.signals) as Arc<dyn SessionSignals>,
            who.clone(),
            rt.clone(),
        )
        .with_work(Arc::new(DurableDecider::new(work, recovers, rt)))
        .with_services(plane_services(&self.shared.observations, tickets, judge));
        self.seats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(PortSeat {
                instance: spec.name.to_owned(),
                driver: Arc::new(driver),
                audience: audience_of(spec.config_json),
                intents: Arc::new(intents),
                who,
                upstream: wiring.upstream,
                carrier: Some(wiring.carrier),
            });
        self.invocations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(invocation);
        Ok(())
    }
}

/// The `canonical_uri` of a plane's config block: the audience its line session is bound to.
fn audience_of(config_json: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(config_json)
        .ok()?
        .get("canonical_uri")?
        .as_str()
        .map(str::to_owned)
}

impl Steps<'_> {
    async fn open_reserved(
        &self,
        index: u32,
        prepared: PreparedInstance,
    ) -> Result<Option<OpenedPort>, OpenError> {
        let Some((kind, _)) = self.instances.get(index as usize) else {
            return Err(OpenError::Unknown("unconfigured serving step".into()));
        };
        match kind {
            KindCode::Secret | KindCode::Store => Err(OpenError::Unknown(
                "bootstrap instances cannot reopen in the serving stage".into(),
            )),
            _ => self.open_port(index, prepared).await.map(Some),
        }
    }
}

/// S6 attaches the Store and establishes its deployment identity without constructing serving dependencies.
fn deployment_read(startup: Arc<Mutex<Option<Startup>>>) -> Box<DeploymentRead> {
    Box::new(
        move |handle: &StoreHandle| -> BoxFut<'static, Result<[u8; 16], String>> {
            let backend = handle.backend.clone();
            let startup = Arc::clone(&startup);
            Box::pin(async move {
                let admitted = super::boot::admit_format(backend, true).await?;
                let core = admitted
                    .store()
                    .ok_or("the Store admission has no core store")?;
                let kept = BootIdentity::new(core)?.keep_deployment_id().await?;
                *startup.lock().unwrap_or_else(PoisonError::into_inner) = Some(admitted);
                deployment_bytes(&kept)
            })
        },
    )
}

/// Core's own secrets, through the secret kind (§12.2: by reference, an empty call stack, no source named in an
/// error). A reference naming no open secret instance refuses the boot.
async fn core_secrets_of(cfg: &RootCfg, secrets: &BootSecrets) -> Result<CoreSecrets, String> {
    let deadline = Instant::now() + CORE_SECRET_DEADLINE;
    let resolve = |what: &'static str, reference: &busbar_contract::secret_ref::SecretRef| {
        let reference = reference.clone();
        async move {
            secrets
                .resolve_ref(deadline, &reference)
                .await
                .map_err(|denied| format!("{what} could not be resolved ({denied:?})"))
        }
    };
    let mut out = CoreSecrets::default();
    if let Some(auth) = &cfg.auth {
        if let Some(reference) = auth.operator_token_ref() {
            out.operator_token = Some(resolve("the admin token", reference).await?);
        }
        if let Some(reference) = &auth.signing_key {
            out.signing_key = Some(resolve("the signing key", reference).await?);
        }
    }
    Ok(out)
}

/// THE RECOVERABLE GATE's key on this path (MIGRATE-ON-BOOT §3 step 2 (a)): the walk opens every secret instance
/// (2a) before the store (2b), so `credentials.at_rest` is resolved through them here, parsed exactly as the records
/// step parses it, and published for `root::migrate::admit_for_host` before the store's open asks. `resolve` is the
/// walk's core-secret resolution (by reference, the text naming only `what`).
async fn publish_at_rest<F, Fut>(at_rest: Option<&SecretRef>, resolve: F)
where
    F: Fn(&'static str, SecretRef) -> Fut,
    Fut: std::future::Future<Output = Result<SecureVec, String>>,
{
    let verdict = match at_rest {
        None => Ok(false),
        Some(keys) => at_rest_resolves(keys, resolve).await,
    };
    busbar_kernel::appbuild::publish_bootstrap_at_rest(verdict);
}

/// Whether `keys` resolve and parse as at-rest keys; `Err` the first refusal's text.
async fn at_rest_resolves<F, Fut>(keys: &SecretRef, resolve: F) -> Result<bool, String>
where
    F: Fn(&'static str, SecretRef) -> Fut,
    Fut: std::future::Future<Output = Result<SecureVec, String>>,
{
    let key = resolve("the signing key", keys.clone()).await?;
    busbar_kernel::appbuild::records_keys_from(Some(&*key)).map(|parsed| parsed.at_rest.is_some())
}

/// S6 owners. No serving instance has opened when this value is returned.
pub(crate) struct BootstrapReady {
    built: Built,
    instances: Vec<Configured>,
    bootstrap: super::boot::walk::Bootstrap<Option<OpenedPort>>,
    pub(crate) core: Arc<CoreSecrets>,
    prefix: Arc<BootSecrets>,
    converting: bool,
    normalization_source: Option<(std::path::PathBuf, busbar_contract::secure::SecureString)>,
}

/// S4b's effective registry and its retained bootstrap leases, before serving opens.
pub(crate) struct ServingReady {
    hook_plan: hooks::Plan,
    provider_plan: super::min3_provider_plan::Plan,
    provider_catalogs: busbar_kernel::plane_driver::provider_catalog::ProviderCatalogs,
    implicit_auth: std::collections::BTreeSet<String>,
    staged_catalogs:
        std::collections::BTreeMap<String, super::min3_provider_catalog::StagedCatalog>,
    auth_policy: busbar_kernel::config::min3::Min3Config,
    request_body_cap: usize,
    built: Built,
    instances: Vec<Configured>,
    declared: std::collections::BTreeMap<String, busbar_kernel::upstreams::Declared>,
    leases: super::boot::walk::BootstrapLeases<Option<OpenedPort>>,
    reserved: Vec<(u32, PreparedInstance)>,
    provisioning: Vec<busbar_kernel::directory::ProvisioningInstance>,
    core: Arc<CoreSecrets>,
    public_url: Option<String>,
    prefix: Arc<BootSecrets>,
    converting: bool,
    normalization_source: Option<(std::path::PathBuf, busbar_contract::secure::SecureString)>,
    _bootstrap_registry: Arc<MinRegistry>,
}

impl ServingReady {
    /// Reserve the complete candidate before any export pump receives a producer handle.
    pub(crate) fn export_names(&self) -> impl Iterator<Item = String> + '_ {
        self.instances
            .iter()
            .filter(|instance| instance.kind == KindCode::Export)
            .map(|instance| instance.name.clone())
    }
}

impl BootstrapReady {
    pub(crate) fn converting(&self) -> bool {
        self.converting
    }
    pub(crate) fn resolver(
        &self,
        reactor: tokio::runtime::Handle,
    ) -> Arc<busbar_kernel::config::secret::SecretResolver> {
        self.prefix.resolver(reactor, self.built.sugars.clone())
    }
}

pub(crate) async fn prepare_bootstrap(
    process: &busbar_plugin_loader::process::ProcessResources,
    file_images: super::boot::images::FileImages,
    cfg: &RootCfg,
    guard: Guard,
) -> Result<Option<(BootstrapReady, Startup)>, String> {
    let images = file_images.images;
    let transport_images: Vec<String> = images
        .identities()
        .filter(|identity| {
            images
                .described(identity)
                .is_some_and(|facts| facts.kind == KindCode::Transport)
        })
        .map(str::to_owned)
        .collect();
    let planes: Vec<PlaneImage> = file_images
        .aliases
        .into_iter()
        .filter(|(identity, _)| {
            images
                .described(identity)
                .is_some_and(|facts| facts.kind == KindCode::Plane)
        })
        .map(|(identity, alias)| PlaneImage { identity, alias })
        .collect();
    let built = build(process, guard, cfg, images)?;
    let store_module = cfg
        .store
        .as_ref()
        .map(|store| store.module.as_str())
        .ok_or_else(busbar_kernel::config::store_required)?;
    if built.registry.identity_of(store_module).is_none() {
        return Ok(None);
    }
    let converting = !super::migrate::stamped();
    let normalization_source = super::migrate::normalization_source()?;
    let mut instances = configured(cfg, &planes)?;
    // Transports have no config section: one instance per admitted image (its schema is the registry's).
    if !converting {
        instances.extend(transports::configured(
            cfg,
            &built.registry,
            &transport_images,
        )?);
    }
    let specs = specifications(&instances, cfg.public_url.as_deref(), converting);
    let mut core_modules = busbar_kernel::appbuild::core_secret_modules(cfg);
    core_modules.extend(
        instances
            .iter()
            .filter(|instance| instance.kind == KindCode::Secret)
            .map(|instance| instance.name.clone()),
    );
    core_modules.sort();
    core_modules.dedup();
    let core_refs: Vec<&str> = core_modules.iter().map(String::as_str).collect();
    let startup: Arc<Mutex<Option<Startup>>> = Arc::default();
    let reader = deployment_read(Arc::clone(&startup));
    let bootstrap_steps = BootstrapSteps {
        registry: &built.registry,
        instances: &specs,
        deployment: &*reader,
        store_seal: Arc::new(|| Box::new(busbar_kernel::seal::lend())),
        secrets: Mutex::new(Arc::clone(&built.secrets)),
        built: &built,
        at_rest: cfg.auth.as_ref().and_then(|a| a.signing_key.clone()),
    };
    let plan = built
        .registry
        .boot_plan_with_core(&specs, &built.sugars, &core_refs)
        .map_err(|error| format!("{error:?}"))?;
    let bootstrap = super::boot::walk::bootstrap(&plan, &bootstrap_steps)
        .await
        .map_err(|refused| refused.to_string())?;
    let prefix = bootstrap_steps.prefix();
    drop(bootstrap_steps);
    let startup = startup
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .ok_or("S6 did not retain the admitted Store")?;
    drop(specs);
    let core = Arc::new(core_secrets_of(cfg, &prefix).await?);
    Ok(Some((
        BootstrapReady {
            built,
            instances,
            bootstrap,
            core,
            prefix,
            converting,
            normalization_source,
        },
        startup,
    )))
}

fn specifications<'a>(
    instances: &'a [Configured],
    public_url: Option<&'a str>,
    converting: bool,
) -> Vec<(KindCode, InstanceSpec<'a>)> {
    instances
        .iter()
        .map(|one| {
            (
                one.kind,
                InstanceSpec {
                    purpose: if converting {
                        busbar_plugin_loader::instance::OpenPurpose::ConvertUnstamped
                    } else {
                        busbar_plugin_loader::instance::OpenPurpose::Canonical
                    },
                    identity: &one.identity,
                    name: &one.name,
                    config_json: &one.config,
                    limits: one.limits,
                    public_url,
                    caller_upstreams: &[],
                },
            )
        })
        .collect()
}

pub(crate) fn prepare_serving(
    ready: BootstrapReady,
    process: &busbar_plugin_loader::process::ProcessResources,
    effective_images: super::boot::images::FileImages,
    cfg: &RootCfg,
    catalogs: &busbar_kernel::plane_driver::provider_catalog::ProviderCatalogs,
    guard: Guard,
) -> Result<ServingReady, String> {
    let mut provider_plan = super::min3_provider_plan::capture(&effective_images, cfg, catalogs)?;
    let BootstrapReady {
        built: bootstrap_built,
        instances: before,
        bootstrap,
        core,
        prefix,
        converting,
        normalization_source,
    } = ready;
    let images = effective_images.images;
    let transports: Vec<String> = images
        .identities()
        .filter(|id| {
            images
                .described(id)
                .is_some_and(|facts| facts.kind == KindCode::Transport)
        })
        .map(str::to_owned)
        .collect();
    let planes: Vec<PlaneImage> = effective_images
        .aliases
        .into_iter()
        .filter(|(id, _)| {
            images
                .described(id)
                .is_some_and(|facts| facts.kind == KindCode::Plane)
        })
        .map(|(identity, alias)| PlaneImage { identity, alias })
        .collect();
    let sugars = cfg.grammar().map_err(|error| error.0)?.sugars.clone();
    let binder: Arc<dyn ConfigBinder> =
        Arc::new(Binder::new(Arc::new(sugars.clone()), ref_schemas(cfg)?));
    let prefix = prefix.with_binder(Arc::clone(&binder));
    let registry = Arc::new(Registry::new(
        images,
        Arc::clone(&binder),
        Arc::clone(process.ids()),
    ));
    let mut instances = configured(cfg, &planes)?;
    let authored_auth: std::collections::BTreeSet<_> = instances
        .iter()
        .filter(|instance| instance.kind == KindCode::Auth)
        .map(|instance| instance.name.clone())
        .collect();
    let implicit_auth = provider_plan
        .auth
        .iter()
        .filter(|instance| !authored_auth.contains(&instance.name))
        .map(|instance| instance.name.clone())
        .collect();
    instances.retain(|instance| instance.kind != KindCode::Auth);
    instances.extend(std::mem::take(&mut provider_plan.auth));
    if !converting {
        instances.extend(transports::configured(cfg, &registry, &transports)?);
    }
    let declared = if converting {
        Default::default()
    } else {
        declared_planes(&registry, &mut instances)?
    };
    let mut staged_catalogs = std::collections::BTreeMap::new();
    let registrations = declared
        .iter()
        .map(|(name, split)| {
            busbar_kernel::plane_driver::port_egress::SeatPool::of(name, &split.definitions)
                .map(|pool| (name.clone(), pool))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
    let mut next_destination = registrations
        .values()
        .flat_map(|pool| pool.members.iter().map(|member| member.destination.get()))
        .max()
        .map_or(Ok(0), |last| {
            last.checked_add(1)
                .ok_or("catalog destination IDs exhausted")
        })?;
    let mut next_need = registrations
        .values()
        .flat_map(|pool| pool.members.iter().map(|member| member.need.0))
        .max()
        .map_or(Ok(0), |last| {
            last.checked_add(1).ok_or("catalog Need IDs exhausted")
        })?;
    for (name, catalog) in catalogs {
        let registration = registrations
            .get(name)
            .ok_or_else(|| format!("plane {name}: catalog has no admitted registration owner"))?;
        let definitions = &declared
            .get(name)
            .ok_or("catalog owner lost its definitions")?
            .definitions;
        let mut allocations = super::min3_provider_catalog::Allocations::new();
        for pair in catalog.targets().keys() {
            let destination = busbar_kernel_egress::ports::DestinationId::new(next_destination);
            next_destination = next_destination
                .checked_add(1)
                .ok_or("catalog destination IDs exhausted")?;
            let need = busbar_contract::conn::NeedId(next_need);
            next_need = next_need
                .checked_add(1)
                .ok_or("catalog Need IDs exhausted")?;
            allocations.insert(
                pair.clone(),
                super::min3_provider_catalog::Allocation {
                    destination,
                    need,
                    upstream: format!("catalog-{}", destination.get()).into(),
                },
            );
        }
        let staged = provider_plan.stage(cfg, catalog, &allocations, registration, definitions)?;
        staged_catalogs.insert(name.clone(), staged);
    }
    let mut leases = bootstrap.into_leases();
    for (index, _, _) in &mut leases.opened {
        let old = before
            .get(*index as usize)
            .ok_or("bootstrap lease has no configured owner")?;
        let (next, candidate) = instances
            .iter()
            .enumerate()
            .find(|(_, one)| one.kind == old.kind && one.name == old.name)
            .ok_or("effective configuration removed a bootstrap instance")?;
        if old.identity != candidate.identity
            || old.config != candidate.config
            || old.limits != candidate.limits
        {
            return Err("effective configuration changes an opened bootstrap instance".into());
        }
        *index = u32::try_from(next).map_err(|_| "too many effective instances")?;
    }
    let core_names: Vec<&str> = instances
        .iter()
        .filter(|one| one.kind == KindCode::Secret)
        .map(|one| one.name.as_str())
        .collect();
    let specs = specifications(&instances, cfg.public_url.as_deref(), converting);
    let plan = registry
        .boot_plan_with_core(&specs, &sugars, &core_names)
        .map_err(|error| format!("{error:?}"))?;
    let mut rest = Vec::new();
    for (index, phase) in plan.steps {
        if phase == busbar_plugin_loader::instance::BootPhase::Rest {
            rest.push(index);
        } else if !leases
            .opened
            .iter()
            .any(|(held, held_phase, _)| *held == index && *held_phase == phase)
        {
            return Err("effective configuration introduces a new bootstrap dependency".into());
        }
    }
    let reserved = rest
        .into_iter()
        .map(|index| {
            let (_, spec) = specs
                .get(index as usize)
                .ok_or("serving plan index is not configured")?;
            registry
                .reserve(spec)
                .map(|prepared| (index, prepared))
                .map_err(|error| format!("{error:?}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    drop(specs);
    let auth = reserved
        .iter()
        .filter(|(_, prepared)| prepared.kind() == KindCode::Auth)
        .map(|(_, prepared)| {
            let described = registry
                .described(prepared.identity())
                .ok_or("reserved auth image has no admitted description")?;
            let inbound = cfg.auth.as_ref().is_some_and(|auth| {
                auth.chain
                    .iter()
                    .chain(&auth.admin_auth)
                    .any(|entry| entry.name == prepared.name())
            });
            Ok(super::provisioning::ProvisioningAuth::described(
                prepared.name(),
                prepared.identity(),
                prepared.id(),
                inbound,
                described.facts,
                described.methods,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let provisioning = super::provisioning::specifications(&cfg.min3, &auth)
        .map_err(|refusals| refusals.join("\n"))?;
    let built = Built {
        registry,
        sugars,
        secrets: Arc::clone(&prefix),
        binder,
        network: NetworkOwner::Serving(ServingConnector::new(network_inputs(cfg, &guard)?)),
    };
    let hook_plan = hooks::Plan::capture(cfg, &instances)?;
    Ok(ServingReady {
        hook_plan,
        provider_plan,
        provider_catalogs: catalogs.clone(),
        implicit_auth,
        staged_catalogs,
        auth_policy: cfg.min3.clone(),
        request_body_cap: cfg.limits.request_body_max_bytes,
        built,
        instances,
        declared,
        leases,
        reserved,
        provisioning,
        core,
        prefix,
        public_url: cfg.public_url.clone(),
        converting,
        normalization_source,
        _bootstrap_registry: bootstrap_built.registry,
    })
}

pub(crate) struct ServingEnvironment<'a> {
    app: &'a busbar_kernel::state::App,
}

impl<'a> ServingEnvironment<'a> {
    pub(crate) fn new(app: &'a busbar_kernel::state::App) -> Self {
        Self { app }
    }
}

pub(crate) async fn finish(
    ready: ServingReady,
    reactor: tokio::runtime::Handle,
    startup: Startup,
    services: Option<Arc<KernelServices>>,
    work_binder: Arc<WorkBinder>,
    environment: Option<ServingEnvironment<'_>>,
    export_observers: &super::export_observer::ExportReservation,
) -> Result<
    (
        Startup,
        super::boot::workers::PreparedWorkers,
        super::exports::ports::Exports,
        Arc<Booted>,
    ),
    String,
> {
    let ServingReady {
        hook_plan,
        provider_plan,
        mut provider_catalogs,
        implicit_auth,
        mut staged_catalogs,
        auth_policy,
        request_body_cap,
        built,
        instances,
        declared,
        leases,
        reserved,
        provisioning,
        _bootstrap_registry,
        core: core_secrets,
        public_url,
        prefix,
        converting,
        normalization_source,
    } = ready;
    let hook_environment = environment
        .as_ref()
        .map(|environment| hooks::Environment::new(hook_plan, environment.app))
        .transpose()?;
    let hooks = hook_environment.as_ref();
    if let Some(hooks) = hooks {
        hooks.check_pools(&instances)?;
    }
    let core = startup
        .store()
        .ok_or("S6 did not retain the admitted Store")?;
    let specs = specifications(&instances, public_url.as_deref(), converting);
    let records = Arc::new(StoreRecords::new(Arc::clone(&core)));
    let super::provisioning::PreparedProvisioning {
        directory,
        holds,
        refresh,
    } = super::provisioning::prepare(Arc::clone(&core), Arc::new(LogEvents), provisioning).await?;
    let push = Arc::new(StorePushQueue::new(
        Arc::clone(&core),
        Arc::new(RetryPolicyImpl::default()),
    ));
    let shared = Arc::new(Shared::new(records.clone(), push, core, work_binder));
    let seat = SeatShared {
        upstreams: declared
            .iter()
            .map(|(name, split)| (name.clone(), Arc::new(split.definitions.clone())))
            .collect(),
        catalogs: Default::default(),
        signals: Arc::clone(&shared.signals),
        secrets: Arc::new(SpawnCustody(Arc::clone(&prefix))),
        kernel: Arc::new(Kernel::new()),
        table: ConnTable::installed(),
    };
    let mut steps = Steps {
        registry: &built.registry,
        instances: &specs,
        services,
        seats: Mutex::default(),
        invocations: Mutex::default(),
        shared: Arc::clone(&shared),
        directory: Arc::clone(&directory),
        core: Arc::clone(&core_secrets),
        secrets: prefix,
        built: &built,
        seat,
        probes: Mutex::default(),
    };
    let mut opened = leases.opened;
    let mut opened_auth = Vec::new();
    let mut export_doors = Vec::new();
    let mut opened_hooks = std::collections::BTreeMap::new();
    let mut opened_planes = Vec::new();
    for (index, prepared) in reserved {
        let instance_id = prepared.id();
        let who = Namespace {
            plugin: Arc::from(prepared.identity()),
            name: Arc::from(prepared.name()),
            instance: prepared.id(),
            slot: prepared.slot(),
        };
        let plane = (prepared.kind() == KindCode::Plane).then(|| who.clone());
        let port = if prepared.kind() == KindCode::Auth {
            let prefix = steps.prefix();
            let needs = built.needs_for(
                Arc::clone(&prefix),
                Arc::clone(&records),
                Arc::clone(&directory),
            );
            let opening = built
                .registry
                .open_auth_reserved_with_metadata(prepared, &needs, &prefix.refs())
                .await
                .map_err(|error| format!("serving auth {index}: {error:?}"))?;
            let port = Arc::clone(&opening.port);
            opened_auth.push(super::min3_auth::OpenedAuth {
                who,
                port: opening.port,
                methods: opening.methods,
                limits: opening.limits,
                out_of_process: false,
            });
            Some(OpenedPort::Auth(port))
        } else if prepared.kind() == KindCode::Hook {
            let hook = hooks::open(
                &built,
                prepared,
                steps.prefix(),
                Arc::clone(&records),
                Arc::clone(&directory),
            )
            .await
            .map_err(|error| format!("serving hook {index}: {error:?}"))?;
            let port = Arc::clone(&hook.port);
            opened_hooks.insert(hook.who.name.to_string(), hook);
            Some(OpenedPort::Hook(port))
        } else {
            steps
                .open_reserved(index, prepared)
                .await
                .map_err(|error| format!("serving open {index}: {error:?}"))?
        };
        if let (Some(who), Some(OpenedPort::Plane(port))) = (plane, &port) {
            opened_planes.push((index, who, Arc::clone(port)));
        }
        if let Some(OpenedPort::Export(port)) = &port {
            let instance = instances
                .get(index as usize)
                .ok_or("opened export has no configured owner")?;
            let disk = Arc::new(super::exports::ports::BoundDisk::new(
                instance_id,
                Arc::clone(&built.binder),
                super::linked::disk_lane(),
            ));
            let door = busbar_plugin_loader::export_door::port::PortDoor::prepare(
                &instance.name,
                Arc::clone(port),
                disk,
                &instance.limits,
                export_observers
                    .observer(&instance.name)
                    .ok_or("opened export has no reserved observation owner")?,
            );
            export_doors.push((instance.name.clone(), door));
        }
        opened.push((index, busbar_plugin_loader::instance::BootPhase::Rest, port));
    }
    let walked = super::boot::walk::Booted {
        opened,
        deployment: leases.deployment,
    };
    if converting {
        let mut settled = Vec::new();
        let mut plane_checks = Vec::new();
        for (index, instance) in instances.iter().enumerate() {
            let identity = built
                .registry
                .identity_of(&instance.identity)
                .ok_or("CONFIG: settlement image is no longer admitted")?;
            let described = built
                .registry
                .described(&identity)
                .ok_or("CONFIG: settlement image has no describe")?;
            if instance.kind == KindCode::Plane {
                plane_checks.push((
                    instance.name.clone(),
                    described
                        .paths(busbar_plugin_abi::records::tag::D_UPSTREAM_PATH)
                        .map(str::to_owned)
                        .collect(),
                ));
            }
            let settlement_registry = if matches!(instance.kind, KindCode::Secret | KindCode::Store)
            {
                &_bootstrap_registry
            } else {
                &built.registry
            };
            let answer = settlement_registry
                .take_settled(&instance.name)
                .ok_or_else(|| {
                    format!("CONFIG: instance {index} did not settle its converting CONFIG")
                })?;
            settled.push(settlement::answer(
                u32::try_from(index).map_err(|_| "CONFIG: too many configured instances")?,
                instance,
                &described,
                answer,
            )?);
        }
        // Temporary planes are never composed into seats or published. Keep bootstrap owners
        // while the record/config writers run, then close them before replacing this process.
        drop(opened_planes);
        let mut opened = walked.opened;
        opened.retain(|(index, _, _)| instances[*index as usize].kind != KindCode::Plane);
        let admission = startup;
        let core = admission
            .store()
            .ok_or("CONFIG: conversion has no admitted core store")?;
        let keys = super::migrate_records::Keys::from_core(&core_secrets)?;
        super::migrate::records_with_keys(Arc::clone(&core), keys).await?;
        let written = super::migrate::finish_settled_checked(
            settled,
            Some(Arc::clone(&core)),
            Arc::new(move |text| settlement::candidate(text, &plane_checks)),
        )
        .await?
        .ok_or("CONFIG: conversion lost its pending source plan")?;
        drop(steps);
        drop(specs);
        return Err(super::migrate::restart(
            written,
            (opened, admission, core, built, shared, _bootstrap_registry),
            drop,
            super::migrate::reexec,
        ));
    }
    let mut normalized = Vec::new();
    let mut plane_checks = Vec::new();
    for (index, instance) in instances.iter().enumerate() {
        // Provider bindings synthesize these instances from admitted style metadata. They
        // have no authored identity-provider block to rewrite during normalization.
        if instance.kind == KindCode::Auth && implicit_auth.contains(&instance.name) {
            continue;
        }
        let identity = built
            .registry
            .identity_of(&instance.identity)
            .ok_or("CONFIG: normalization image is no longer admitted")?;
        let described = built
            .registry
            .described(&identity)
            .ok_or("CONFIG: normalization image has no describe")?;
        if instance.kind == KindCode::Plane {
            plane_checks.push((
                instance.name.clone(),
                described
                    .paths(busbar_plugin_abi::records::tag::D_UPSTREAM_PATH)
                    .map(str::to_owned)
                    .collect(),
            ));
        }
        let settlement_registry = if matches!(instance.kind, KindCode::Secret | KindCode::Store) {
            &_bootstrap_registry
        } else {
            &built.registry
        };
        let Some(mut answer) = settlement_registry.take_settled(&instance.name) else {
            continue;
        };
        if instance.kind == KindCode::Transport {
            let before = busbar_contract::json::parse_value(&instance.config)
                .map_err(|_| "CONFIG: invalid transport config")?;
            let after = busbar_contract::json::parse_value(answer.config_json.as_slice())
                .map_err(|_| "CONFIG: invalid transport CONFIG")?;
            if before != after {
                return Err("CONFIG: a transport cannot normalize core-owned config".to_owned());
            }
            continue;
        }
        if let Some(retained) = declared.get(&instance.name) {
            let visible = busbar_contract::json::parse_value(answer.config_json.as_slice())
                .map_err(|_| "CONFIG: invalid plane CONFIG")?;
            let complete = retained
                .reattach(&visible)
                .map_err(|errors| errors.join("; "))?;
            answer.config_json = SecureVec::from(
                busbar_contract::json::to_vec(&complete)
                    .map_err(|_| "CONFIG: cannot encode normalized plane config")?,
            );
        }
        normalized.push(settlement::answer(
            u32::try_from(index).map_err(|_| "CONFIG: too many configured instances")?,
            instance,
            &described,
            answer,
        )?);
    }
    super::migrate::normalize_settled(
        normalization_source,
        normalized,
        Arc::new(move |text| settlement::candidate(text, &plane_checks)),
    )
    .await?;
    let environment = environment.ok_or("serving composition has no candidate authority")?;
    let owners = super::min3_admin_auth::owners(
        environment.app,
        &auth_policy,
        &opened_auth,
        Arc::clone(&records),
    )?;
    let auth = Arc::new(super::min3_auth::AuthSet::new(
        opened_auth,
        &holds,
        owners,
        Duration::from_secs(auth_policy.unknown_key_refresh_s),
    )?);
    use busbar_kernel::retry::{RetryPolicy, RetrySite};
    let retry = RetryPolicyImpl::default();
    let cache = Arc::new(busbar_kernel::custody::CredCache::new(
        auth_policy.outbound,
        move |attempt, error| retry.next(RetrySite::AuthOutbound, attempt, error),
        |key, event| {
            let action = match event {
                busbar_kernel::custody::CredEvent::Backoff => "outbound_credential_backoff",
                busbar_kernel::custody::CredEvent::NoLifetime => "outbound_credential_no_lifetime",
            };
            busbar_kernel::audit_ring::AUDIT.record_by(
                action,
                &format!("auth:{}:upstream:{}", key.auth_instance, key.upstream),
                busbar_kernel::audit_ring::OUTCOME_APPLIED,
                "system",
            );
        },
    ));
    let rows = staged_catalogs
        .values_mut()
        .flat_map(super::min3_provider_catalog::StagedCatalog::take_auth_rows)
        .collect();
    let outbound = super::min3_outbound_auth::prepare(
        &provider_plan.bindings,
        rows,
        &auth,
        &provider_plan.styles,
        cache,
    )?;
    for (name, staged) in staged_catalogs {
        let pools = provider_plan
            .pools
            .get(&name)
            .ok_or("staged catalog has no retained pool policy")?
            .clone();
        let catalog = super::plane_seats::CatalogSeat {
            plan: Arc::new(
                provider_catalogs
                    .remove(&name)
                    .ok_or("staged catalog lost its exact resolved plan")?,
            ),
            sealed: staged.seal(&outbound)?,
            pools,
        };
        steps.seat.catalogs.insert(name, Arc::new(catalog));
    }
    let hooks = hooks.ok_or("native planes have no frozen hook construction inputs")?;
    for (index, who, port) in opened_planes {
        let (_, spec) = specs
            .get(index as usize)
            .ok_or("opened plane has no configured owner")?;
        steps
            .compose_plane(spec, who, port, hooks, &opened_hooks)
            .map_err(|error| format!("serving plane {index}: {error:?}"))?;
    }
    let provisioning = super::provisioning::mounts(
        &auth_policy,
        &auth,
        environment.app,
        environment
            .app
            .config_generation
            .load(std::sync::atomic::Ordering::Acquire),
        request_body_cap,
        crate::root::dispatch::dispatcher().budgets().call,
        Arc::clone(&environment.app.request_id_counter),
    )?;
    let transports = transports::table(transports::opened(&walked.opened, &specs))?;
    let secrets = steps.prefix();
    let core = core_secrets;
    let seats = steps
        .seats
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    let probes = steps
        .probes
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    let invocations = steps
        .invocations
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    let ticking = seats.clone();
    let booted = Arc::new(Booted {
        resolver: secrets.resolver(reactor, built.sugars.clone()),
        registry: built.registry,
        _bootstrap_registry,
        _transports: transports,
        _native_invocations: invocations,
        _opened: walked.opened,
        auth,
        provisioning,
        config_version: environment.app.config_version,
        seats,
        core,
        secrets,
        deployment: walked.deployment,
        work: Arc::clone(&shared.work),
        records,
    });
    // Retain dormant maintenance until root has published the serving routes.
    let mut workers = super::boot::workers::PreparedWorkers::new();
    workers.push(refresh.run());
    for probe in probes {
        workers.push(probe);
    }
    let queue: Arc<dyn PushQueue> = shared.push.clone();
    for seat in ticking {
        let queue = Arc::clone(&queue);
        workers.push(async move { seat.tick_task(queue).await });
    }
    tracing::info!("{}", booted.describe());
    Ok((
        startup,
        workers,
        super::exports::ports::Exports::new(export_doors)?,
        booted,
    ))
}

#[cfg(test)]
#[path = "tests/min3_boot.rs"]
mod tests;

/// The transport arm (W2-SW-TRANSPORT): every admitted MIN-3 transport image opened through
/// `Registry::open_transport` and published for the connector.
#[path = "min3_transports.rs"]
pub(crate) mod transports;

#[path = "min3_settled.rs"]
mod settlement;

#[cfg(test)]
#[path = "tests/fixture_bootstrap.rs"]
pub(crate) mod fixture;
