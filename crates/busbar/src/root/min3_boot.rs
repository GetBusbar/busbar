// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot's MIN-3 registry (ROOT-BOOT; ABI-MIN3-INTERFACE §11.2, §12.10 item 4, §13).
//!
//! The root builds one `Registry<HostNeeds<..>>` over the process's custody (`BootSecrets`), the guard, the config
//! binder and the records and directory handles, admits the MIN-3 images the plugins directory holds, installs the
//! kernel's sides (store seal, auth core, store opener, auth opener) and walks the boot plan (2a, 2b,
//! `set_deployment`, re-check, 2c) before any listener serves. A plugin image that is not MIN-3 is not admitted
//! here: the old path still serves it (the WBS's switch-overs, then the W3 deletions).
//!
//! Records and directory are built before the store (the store opens through the registry), so the Need handlers
//! own late handles the walk fills at the deployment point, after the store opened and before the first 2c
//! instance.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use busbar_contract::secret_ref::{SecretRef, Sugars};
use busbar_contract::secure::SecureVec;
use busbar_core_connector::guard::Guard;
use busbar_core_connector::need::{HostNeeds, NeedLimits};
use busbar_kernel::appbuild::boot_registry::{boot, install_kernel_sides, KernelAuthCore};
use busbar_kernel::appbuild::boot_walk::{
    deployment_bytes, BootSteps, DeploymentRead, RegistryBoot,
};
use busbar_kernel::channels::signals::SignalRegistry;
use busbar_kernel::channels::SessionSignals;
use busbar_kernel::config::{PluginsCfg, RootCfg};
use busbar_kernel::directory::{KernelDirectory, LateDirectory, LogEvents};
use busbar_kernel::host_services::{DestJudge, KernelServices};
use busbar_kernel::ingress::replay::StoreReplay;
use busbar_kernel::ingress::signed_ingress::{RouteSecrets, StandardWebhooks};
use busbar_kernel::issued::IssuedCredentials;
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
use busbar_kernel::plane_driver::port_work::{governed_binder, LateBinder, LateStore, StoreWork};
use busbar_kernel::plane_grants::{
    SealedTickets, TicketAdmitted, TicketDenied, TicketMint, Tickets,
};
use busbar_kernel::plugin_config::{Binder, ConfigBinder};
use busbar_kernel::plugin_records::{LateRecords, RecordsDenied, StoreRecords};
use busbar_kernel::push::{PushQueue, StorePushQueue};
use busbar_kernel::retry::Policy as RetryPolicyImpl;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller as LoaderCaller};
use busbar_plugin_abi::host_side::host_vt::HOST;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::admit::Admitted;
use busbar_plugin_loader::instance::{
    Ceilings, InstanceSpec, OpenError, OpenedPort, Registry, StoreSeal,
};
use busbar_ports::store::StoreHandle;

use busbar_kernel::teller::Kernel;
use busbar_kernel::upstreams::ConfiguredUpstreams;

use super::plane_seats::{compose as compose_seat, ConnTable, SeatShared, SpawnCustody};
use super::port_mount::Ingress;
use super::secret_custody::{self, BootCustody, BootRefs, BootSecrets};

/// The records every Need handler, the replay guard and the plane driver share: filled once the store is open.
pub(crate) type Records = LateRecords<Arc<StoreRecords>>;
/// The directory the DIRECTORY Need reads: filled once the store is open.
pub(crate) type Directory = LateDirectory<KernelDirectory>;
/// The Need handlers the registry runs every plugin under.
pub(crate) type Needs = HostNeeds<BootCustody, Records, Directory>;
/// The process's MIN-3 registry.
pub(crate) type MinRegistry = Registry<Needs>;

/// How long a core-internal secret may take to resolve at boot.
const CORE_SECRET_DEADLINE: Duration = Duration::from_secs(30);
/// `auth.unknown_key_refresh_s` (IF §12.11): at least 5 s, 30 s by default.
const UNKNOWN_KEY_REFRESH: Duration = Duration::from_secs(30);

/// The issued credentials core has minted. The admin surface that issues them on this path has not landed, so
/// every id is unknown: the empty value, through the one code path every unknown id takes (IF §12.8).
struct Unissued;

impl IssuedCredentials for Unissued {
    fn lookup<'a>(
        &'a self,
        _auth_instance: u64,
        _kind: &'a str,
        _id: &'a str,
    ) -> BoxFut<'a, SecureVec> {
        Box::pin(core::future::ready(SecureVec::from(&[0u8; 0][..])))
    }
}

/// Core's own secrets, resolved at boot through the secret kind into owned values (IF §11.2: the admin token,
/// the signing key). `None` = the config states no such reference.
#[derive(Default)]
pub(crate) struct CoreSecrets {
    pub(crate) operator_token: Option<SecureVec>,
    pub(crate) signing_key: Option<SecureVec>,
}

/// The push queue the plane instances' PUSH intents and ticks enqueue into: filled once the store is open (the
/// queue is rows in the core store), `Unavailable` until then. Clones share the one slot.
#[derive(Clone, Default)]
pub(crate) struct LatePush {
    slot: Arc<OnceLock<StorePushQueue>>,
}

impl LatePush {
    /// The queue every clone enqueues into from now on (the first install stays).
    fn install(&self, queue: StorePushQueue) {
        let _ = self.slot.set(queue);
    }
}

impl PushQueue for LatePush {
    fn enqueue<'a>(
        &'a self,
        who: &'a LoaderCaller<'_>,
        ttl_s: u64,
        recs: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        match self.slot.get() {
            Some(queue) => queue.enqueue(who, ttl_s, recs),
            None => Box::pin(core::future::ready(Err(RecordsDenied::Unavailable))),
        }
    }
}

/// What the plane instances' intents, tickets and tick share, built before any instance opens and filled as the
/// boot proceeds: the records and push queue are filled at the deployment point.
struct Shared {
    records: Records,
    push: LatePush,
    signals: Arc<SignalRegistry>,
    next_instance: AtomicU64,
    /// The observation custody every seat's OBS_SCOPE and OBSERVE run on (units register as requests bill).
    observations: ObsCustody,
    /// The core store (filled at the deployment point) and the governance binder (filled when governance
    /// attaches): the two things durable WORK waits for.
    work_store: LateStore,
    work_binder: LateBinder,
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
fn ticket_store(records: &Records, signing: Option<&SecureVec>) -> Arc<dyn Tickets> {
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
    shared: &Shared,
    tickets: Arc<dyn Tickets>,
    judge: Option<Arc<dyn DestJudge>>,
) -> Services {
    Services {
        judge: Some(judge.map_or_else(PlaneJudge::unavailable, PlaneJudge::new)),
        tickets: Some(tickets),
        observations: Some(Arc::new(shared.observations.clone())),
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
    fn new(records: Records, push: LatePush) -> Self {
        let work_store = LateStore::default();
        let work_binder = LateBinder::default();
        Self {
            records,
            push,
            signals: SignalRegistry::new(),
            next_instance: AtomicU64::new(1),
            observations: ObsCustody::new(Arc::new(busbar_kernel::store::now_ms)),
            work: Arc::new(StoreWork::new(
                work_store.clone(),
                work_binder.clone(),
                Arc::new(busbar_kernel::store::now_ms),
            )),
            work_store,
            work_binder,
        }
    }
}

/// What a boot through the MIN-3 registry leaves running.
pub(crate) struct Booted {
    pub(crate) registry: Arc<MinRegistry>,
    pub(crate) seats: Vec<PortSeat>,
    pub(crate) core: CoreSecrets,
    /// The secret kind the boot opened its secret instances into (webhook secrets resolve through it).
    pub(crate) secrets: &'static BootSecrets,
    pub(crate) deployment: [u8; 16],
    /// The format admission the walk attached the store through.
    pub(crate) startup: Mutex<Option<Startup>>,
    /// Durable WORK: the governance binder, filled when governance attaches ([`attach_governance`]).
    work_binder: LateBinder,
    /// The records the signed-ingress replay claims are written through.
    records: Records,
    /// Durable WORK of every seat: what the recovery scheduler scans ([`recover_ports`]).
    work: Arc<StoreWork>,
    /// The seats' probe targets: their probers hold them weakly, so the process holds them here.
    _probes: Vec<Arc<dyn Send + Sync>>,
}

static BOOTED: OnceLock<Booted> = OnceLock::new();

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
        let attached = self
            .startup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        format!(
            "MIN-3 boot: {} planes served through ports, {} shorthands declared, deployment dep_{}, \
             store attached: {attached}; core secrets: admin token {}, signing key {}",
            self.seats.len(),
            self.registry.sugars().len(),
            hex::encode(self.deployment),
            held(&self.core.operator_token),
            held(&self.core.signing_key),
        )
    }
}

/// What the MIN-3 boot left running, once it ran.
pub(crate) fn booted() -> Option<&'static Booted> {
    BOOTED.get()
}

/// The MIN-3 plane instances the boot opened, for `Served.ports`.
pub(crate) fn seats() -> Vec<PortSeat> {
    booted().map(|b| b.seats.clone()).unwrap_or_default()
}

/// Governance is attached (after the app's first build): durable WORK binds a principal's recovery standing through
/// it from now on. Until then every WORK_OPEN answers `R_UNSUPPORTED` (core cannot recover), the IF's fail-closed
/// answer. A boot that took the old path has no MIN-3 instances and nothing to attach.
pub(crate) fn attach_governance(handle: Arc<busbar_kernel::state::AppHandle>) {
    if let Some(booted) = booted() {
        booted.work_binder.install(governed_binder(handle));
    }
}

/// How long one recovery scan, and one recovery poll, may take (today's scheduler's per-poll deadline).
const RECOVERY_POLL: Duration = Duration::from_secs(30);

/// The request ids of core-originated recovery polls (non-zero, unique for the process life).
static RECOVERY_REQUESTS: AtomicU64 = AtomicU64::new(1);

/// The recovery scheduler runs (`true`) or stopped (`false`): WORK_OPEN answers `R_UNSUPPORTED` while it does not
/// (core cannot recover, IF §12.24 step 1). A boot that took the old path has no MIN-3 instances.
pub(crate) fn set_recovery_ready(ready: bool) {
    if let Some(booted) = booted() {
        booted.work.set_recovery_ready(ready);
    }
}

/// One recovery pass over the MIN-3 plane seats (IF §12.24 step 3), on the scheduler's cadence: per seat with a
/// ROUTE_RECOVERY route, the live rows no recovery session holds (`DurableWork::recoverable`); for each whose binding
/// still restores (`restore_for_app` + `standing_over`, today's standing and expiry rules) one poll as the restored
/// principal (`PortSeat::recover`), the row held for the poll's life. Core never infers settlement: a row stays live
/// until the plane settles it. Answers how many polls were attempted.
pub(crate) async fn recover_ports(app: Arc<busbar_kernel::state::App>) -> usize {
    let Some(booted) = booted() else {
        return 0;
    };
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
struct CustodySecrets(&'static BootSecrets);

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
pub(crate) fn signed_ingress() -> Option<Arc<Ingress>> {
    let booted = booted()?;
    Some(Arc::new(Ingress {
        verifier: Arc::new(StandardWebhooks::new(CustodySecrets(booted.secrets))),
        replay: Arc::new(StoreReplay::new(booted.records.clone())),
        secrets: Arc::new(|_: &str, _: u32| None),
    }))
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
struct Configured {
    kind: KindCode,
    identity: String,
    name: String,
    config: Vec<u8>,
    limits: busbar_plugin_abi::host_side::caller::InstanceLimits,
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
    for (name, secret) in &cfg.secrets {
        let config = secret
            .settings
            .encode()
            .map_err(|error| format!("secrets.{name}: {error}"))?
            .into_exposed(&seal);
        out.push(Configured {
            kind: KindCode::Secret,
            identity: name.clone(),
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
    Ok(out)
}

/// The boot's configured upstreams (IF §12.1): one table, shared by every plane seat's egress walk and carrier,
/// typed over the config's `upstreams:` section and each entry's parsed binding (`cfg.min3`, W1-K7). The load
/// already typed the same section once (`config::resolve`), so a refusal here means the config changed shape
/// between load and boot; a binding naming an upstream with no entry still refuses the boot.
fn configured_upstreams(cfg: &RootCfg) -> Result<Arc<ConfiguredUpstreams>, String> {
    upstreams_of(&cfg.min3.upstream_section, cfg)
}

/// The table typed over `section` (upstream name to entry) and the config's bindings; Err = every refusal, joined.
fn upstreams_of(
    section: &serde_json::Map<String, serde_json::Value>,
    cfg: &RootCfg,
) -> Result<Arc<ConfiguredUpstreams>, String> {
    ConfiguredUpstreams::from_config(
        section,
        &cfg.min3.upstreams,
        &busbar_kernel::plugin_config::upstream_anchor,
    )
    .map(Arc::new)
    .map_err(|refused| refused.join("; "))
}

/// The shorthands the admitted secret images declare, as the one `Sugars` the binder and the config parser read.
fn sugars_of(registry: &MinRegistry) -> Result<Sugars, String> {
    use busbar_contract::abi::mechanism::door::{
        REWRITE_ALIAS, REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE, REWRITE_SUGAR_SHOWN,
        SUGAR_ROLE_FILL, SUGAR_ROLE_PATH,
    };
    let decls = registry.sugars();
    let mut owners: Vec<Arc<str>> = Vec::new();
    for decl in decls {
        if !owners.iter().any(|owner| **owner == *decl.identity) {
            owners.push(Arc::clone(&decl.identity));
        }
    }
    let mut sugars = Sugars::default();
    for owner in owners {
        let mut rewrites: Vec<(u32, String, String)> = Vec::new();
        for decl in decls.iter().filter(|decl| *decl.identity == *owner) {
            let word = decl.word.to_string();
            if decl.alias {
                rewrites.push((REWRITE_ALIAS, word.clone(), owner.to_string()));
            }
            rewrites.push((REWRITE_SUGAR, word.clone(), decl.key.to_string()));
            rewrites.push((REWRITE_SUGAR_SHOWN, word.clone(), decl.shown.to_string()));
            rewrites.push((REWRITE_SUGAR_NAMES, word.clone(), decl.names.to_string()));
            let role = match decl.role {
                busbar_plugin_abi::secret::SUGAR_ROLE_FILL => Some(SUGAR_ROLE_FILL),
                busbar_plugin_abi::secret::SUGAR_ROLE_PATH => Some(SUGAR_ROLE_PATH),
                _ => None,
            };
            if let Some(role) = role {
                rewrites.push((REWRITE_SUGAR_ROLE, word, role.to_owned()));
            }
        }
        sugars.declare(&owner, &rewrites)?;
    }
    Ok(sugars)
}

/// Each configured secret instance's reference schema (its image's D_REF_SCHEMA), by configured name.
fn ref_schemas(registry: &MinRegistry, cfg: &RootCfg) -> Vec<(Arc<str>, Box<str>)> {
    cfg.secrets
        .keys()
        .filter_map(|name| {
            let identity = registry.identity_of(name)?;
            let described = registry.described(&identity)?;
            let (_, body) = described
                .items
                .iter()
                .find(|(tag, _)| *tag == busbar_plugin_abi::secret::tag::D_REF_SCHEMA)?;
            let text = core::str::from_utf8(body).ok()?;
            Some((Arc::from(name.as_str()), Box::from(text)))
        })
        .collect()
}

/// The registry over the production Need handlers, every image added, the binder told the shorthands and the
/// schemas, custody attached to the binder and the registry's scrub sets, and the kernel's sides installed.
/// `store` carries what the deployment step fills.
struct Built {
    registry: Arc<MinRegistry>,
    sugars: Sugars,
    secrets: &'static BootSecrets,
    records: Records,
    directory: Directory,
}

fn build(guard: Guard, cfg: &RootCfg, images: Vec<Admitted>) -> Result<Built, String> {
    let binder: Arc<dyn ConfigBinder> = Arc::new(Binder::new(Arc::new(BootRefs)));
    // The process's one secret kind, built over the binder and kept for the life of the process.
    let secrets: &'static BootSecrets = Box::leak(Box::new(BootSecrets::new(Arc::clone(&binder))));
    let records = Records::default();
    let directory = Directory::default();
    let needs = HostNeeds::production(
        guard,
        BootCustody(secrets),
        records.clone(),
        directory.clone(),
        Arc::clone(&binder),
        NeedLimits::default(),
    );
    let slots = Arc::new(busbar_plugin_loader::instance::SlotTable::new());
    busbar_plugin_loader::instance::install_sinks(&slots);
    let mut described =
        busbar_plugin_loader::instance::ImagesBuilder::new(&HOST, slots, Ceilings::DEFAULT);
    for image in images {
        described
            .admit(image)
            .map_err(|refusal| format!("plugin image refused: {refusal}"))?;
    }
    let registry = Registry::new(described.finish(), Arc::new(needs), Arc::clone(&binder));

    let sugars = sugars_of(&registry)?;
    binder.set_sugars(Arc::new(sugars.clone()));
    binder.set_ref_schemas(ref_schemas(&registry, cfg));
    let registry = Arc::new(registry);
    registry.start_watchdog();
    let weak = Arc::downgrade(&registry);
    secrets.attach(Arc::new(move |slot| weak.upgrade()?.scrub_of(slot)));
    let seal: StoreSeal = Box::new(|| Box::new(busbar_kernel::seal::lend()));
    let auth_core = Arc::new(KernelAuthCore::new(
        Unissued,
        StoreReplay::new(records.clone()),
    ));
    install_kernel_sides(Arc::clone(&registry), seal, auth_core, UNKNOWN_KEY_REFRESH);
    Ok(Built {
        registry,
        sugars,
        secrets,
        records,
        directory,
    })
}

/// The walk's steps: the registry's own, except that a secret instance opens through `open_secret_steps` (its
/// port enters the table the store's SECRET Needs read, at once) and a plane through `PortDriver` (which opens
/// the instance and keeps its seat).
struct Steps<'r> {
    inner: RegistryBoot<'r, Needs>,
    services: Option<Arc<KernelServices>>,
    seats: Mutex<Vec<PortSeat>>,
    shared: Arc<Shared>,
    /// `auth.signing_key`: the reference the ticket host key is derived from (IF §12.11).
    signing_key: Option<SecretRef>,
    /// The process's secret kind: the open secret instances and the custody that resolves through them.
    secrets: &'static BootSecrets,
    /// `credentials.at_rest`: what the recoverable gate seals with, resolved before the store opens (2b).
    at_rest: Option<SecretRef>,
    /// K9: what every seat's egress walk and carrier are composed over (the boot's one upstream table).
    seat: SeatShared,
    /// The seats' probe targets, held for their probers.
    probes: Mutex<Vec<Arc<dyn Send + Sync>>>,
}

impl Steps<'_> {
    async fn open_plane(&self, spec: &InstanceSpec<'_>) -> Result<(), OpenError> {
        let services = self.services.clone().ok_or_else(|| {
            OpenError::Unknown("the kernel services are not installed: a plane cannot open".into())
        })?;
        let seal = busbar_kernel::seal::acquire();
        let caller = busbar_contract::services::Caller::issue(
            &seal,
            Arc::from(spec.name),
            busbar_contract::abi::mechanism::KindCode::Plane,
        );
        let driver = PortDriver::open(
            self.inner.registry,
            spec,
            services,
            caller,
            Arc::new(busbar_kernel::refusal::CoreRefusals::new()),
            // The operator's `routes.<id>.auth` choice arrives with the K7 config (slice 9 leaves it unset).
            &|_| None,
        )
        .await?;
        let who = Namespace {
            plugin: Arc::from(spec.identity),
            name: Arc::from(spec.name),
            instance: self.shared.next_instance.fetch_add(1, Ordering::Relaxed),
            slot: 0,
        };
        // Tickets: the host key is resolved here (the secret instances are open, step 2a), so the gate and the
        // MINT store are built whole, with the key, before the seat exists.
        let signing = match &self.signing_key {
            Some(reference) => Some(
                self.secrets
                    .resolve_ref(Instant::now() + CORE_SECRET_DEADLINE, reference)
                    .await
                    .map_err(|denied| {
                        OpenError::Unknown(format!(
                            "the signing key could not be resolved ({denied:?})"
                        ))
                    })?,
            ),
            None => None,
        };
        let tickets = ticket_store(&self.shared.records, signing.as_ref());
        let driver =
            driver.with_tickets(Arc::new(TicketGate::new(Arc::clone(&tickets), who.clone())));
        let rt = tokio::runtime::Handle::current();
        // K9: the seat's egress walk and carrier over the boot's upstream table, under the instance's core-held
        // `insecure_transport.accept`.
        let wiring = compose_seat(
            &self.seat,
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
            Arc::new(self.shared.push.clone()),
            Arc::clone(&self.shared.signals) as Arc<dyn SessionSignals>,
            who.clone(),
            rt.clone(),
        )
        .with_work(Arc::new(DurableDecider::new(work, recovers, rt)))
        .with_services(plane_services(&self.shared, tickets, judge));
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

impl BootSteps for Steps<'_> {
    /// `None` for a plane: its port lives in its seat.
    type Opened = Option<OpenedPort>;

    fn open(&self, index: u32) -> BoxFut<'_, Result<Option<OpenedPort>, OpenError>> {
        let found = usize::try_from(index)
            .ok()
            .and_then(|at| self.inner.instances.get(at));
        let Some((kind, spec)) = found else {
            return Box::pin(core::future::ready(Err(OpenError::Unknown(format!(
                "the boot plan names instance {index}, which is not configured"
            )))));
        };
        match kind {
            KindCode::Secret => Box::pin(async move {
                secret_custody::open_secret_steps(
                    self.secrets,
                    self.inner.registry,
                    &[index],
                    self.inner.instances,
                )
                .await?;
                self.secrets
                    .port(spec.name)
                    .map(|port| Some(OpenedPort::Secret(port)))
                    .ok_or_else(|| {
                        OpenError::Unknown(format!(
                            "secret instance {index} opened but is not in the process table"
                        ))
                    })
            }),
            KindCode::Plane => Box::pin(async move { self.open_plane(spec).await.map(|()| None) }),
            KindCode::Store => Box::pin(async move {
                // The secret instances are open (2a): the gate's key is published before the store's open asks.
                let secrets = self.secrets;
                publish_at_rest(self.at_rest.as_ref(), |what, reference| async move {
                    secrets
                        .resolve_ref(Instant::now() + CORE_SECRET_DEADLINE, &reference)
                        .await
                        .map_err(|denied| format!("{what} could not be resolved ({denied:?})"))
                })
                .await;
                self.inner.open(index).await.map(Some)
            }),
            _ => {
                let opened = self.inner.open(index);
                Box::pin(async move { opened.await.map(Some) })
            }
        }
    }

    fn check(&self, index: u32) -> BoxFut<'_, Result<(), OpenError>> {
        self.inner.check(index)
    }

    fn deployment<'a>(
        &'a self,
        store: &'a Option<OpenedPort>,
    ) -> BoxFut<'a, Result<[u8; 16], String>> {
        match store {
            Some(port) => self.inner.deployment(port),
            None => Box::pin(core::future::ready(Err(
                "the step-2b instance did not open as a store".to_owned(),
            ))),
        }
    }
}

/// The deployment point (IF §11.2 round 29): the store just opened is attached to the kernel's core store, the
/// records and directory handles the Need handlers hold are filled from it, and the deployment id is read or kept
/// through it. The attached format admission is parked in `startup`.
fn deployment_read(
    records: Records,
    directory: Directory,
    startup: Arc<Mutex<Option<Startup>>>,
    push: LatePush,
    work_store: LateStore,
) -> Box<DeploymentRead> {
    Box::new(
        move |handle: &StoreHandle| -> BoxFut<'static, Result<[u8; 16], String>> {
            let backend = handle.backend.clone();
            let records = records.clone();
            let directory = directory.clone();
            let startup = Arc::clone(&startup);
            let push = push.clone();
            let work_store = work_store.clone();
            Box::pin(async move {
                let admitted = super::boot::admit_format(backend, true).await?;
                let core = admitted
                    .store()
                    .ok_or_else(|| "the store format admission left no core store".to_owned())?;
                records.install(Arc::new(StoreRecords::new(Arc::clone(&core))));
                work_store.install(Arc::clone(&core));
                push.install(StorePushQueue::new(
                    Arc::clone(&core),
                    Arc::new(RetryPolicyImpl::default()),
                ));
                let (served, _holds) =
                    KernelDirectory::build(Arc::clone(&core), Arc::new(LogEvents), Vec::new())
                        .await?;
                directory.install(served);
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

/// Boot through the MIN-3 registry, before any listener serves. `Ok(false)`: the configured store is not a MIN-3
/// image, so the old path boots (nothing here ran past admission). `Ok(true)`: every instance opened in plan
/// order, core's own secrets are resolved and the process holds the registry ([`registry`], [`seats`]).
pub(crate) async fn run(
    cfg: &RootCfg,
    plugins: &PluginsCfg,
    guard: Guard,
    services: Option<Arc<KernelServices>>,
) -> Result<bool, String> {
    let images = admit_images(plugins)?;
    if images.is_empty() {
        return Ok(false);
    }
    let transport_images = transports::identities(images.iter().map(|(image, _)| image));
    let planes: Vec<PlaneImage> = images
        .iter()
        .filter(|(image, _)| matches!(image.kind(), KindCode::Plane))
        .map(|(image, alias)| PlaneImage {
            identity: image.identity().to_owned(),
            alias: alias.clone(),
        })
        .collect();
    let built = build(
        guard,
        cfg,
        images.into_iter().map(|(image, _)| image).collect(),
    )?;
    let store_module = cfg
        .store
        .as_ref()
        .map(|store| store.module.as_str())
        .ok_or_else(busbar_kernel::config::store_required)?;
    if built.registry.identity_of(store_module).is_none() {
        return Ok(false);
    }
    let mut instances = configured(cfg, &planes)?;
    // Transports have no config section: one instance per admitted image (its schema is the registry's).
    instances.extend(transports::configured(
        cfg,
        &built.registry,
        &transport_images,
    )?);
    let specs: Vec<(KindCode, InstanceSpec<'_>)> = instances
        .iter()
        .map(|one| {
            (
                one.kind,
                InstanceSpec {
                    identity: &one.identity,
                    name: &one.name,
                    config_json: &one.config,
                    limits: one.limits,
                    public_url: cfg.public_url.as_deref(),
                    caller_upstreams: &[],
                },
            )
        })
        .collect();
    let startup: Arc<Mutex<Option<Startup>>> = Arc::default();
    let push = LatePush::default();
    let shared = Arc::new(Shared::new(built.records.clone(), push.clone()));
    let reader = deployment_read(
        built.records.clone(),
        built.directory.clone(),
        Arc::clone(&startup),
        push,
        shared.work_store.clone(),
    );
    let seat = SeatShared {
        upstreams: configured_upstreams(cfg)?,
        signals: Arc::clone(&shared.signals),
        secrets: Arc::new(SpawnCustody(built.secrets)),
        kernel: Arc::new(Kernel::new()),
        table: ConnTable::installed(),
    };
    let steps = Steps {
        inner: RegistryBoot {
            registry: &*built.registry,
            instances: &specs,
            deployment: &*reader,
        },
        services,
        seats: Mutex::default(),
        shared: Arc::clone(&shared),
        signing_key: cfg.auth.as_ref().and_then(|auth| auth.signing_key.clone()),
        secrets: built.secrets,
        at_rest: cfg.auth.as_ref().and_then(|a| a.signing_key.clone()),
        seat,
        probes: Mutex::default(),
    };
    let core_modules = busbar_kernel::appbuild::core_secret_modules(cfg);
    let core_refs: Vec<&str> = core_modules.iter().map(String::as_str).collect();
    let walked = boot(&*built.registry, &specs, &built.sugars, &core_refs, &steps)
        .await
        .map_err(|refused| refused.to_string())?;
    transports::publish(transports::opened(&walked.opened, &specs))?;
    let core = core_secrets_of(cfg, built.secrets).await?;
    let seats = steps
        .seats
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    let probes = steps
        .probes
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    let ticking = seats.clone();
    // The admin listener serves the planes' ROUTE_ADMIN routes from here on.
    busbar_kernel::plane_driver::port_admin::install(seats.clone());
    let installed = BOOTED.set(Booted {
        registry: built.registry,
        seats,
        core,
        secrets: built.secrets,
        deployment: walked.deployment,
        work_binder: shared.work_binder.clone(),
        work: Arc::clone(&shared.work),
        records: built.records.clone(),
        _probes: probes,
        startup: Mutex::new(
            startup
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        ),
    });
    if installed.is_err() {
        return Err("the MIN-3 boot ran twice in one process".to_owned());
    }
    // The tick timer task of every seat whose plane states a period (§8.6 `tick_s`): its PUSHes queue under the
    // instance's namespace, its EMITs go to their carriers.
    let queue: Arc<dyn PushQueue> = Arc::new(shared.push.clone());
    for seat in &ticking {
        tokio::spawn(seat.clone().tick_task(Arc::clone(&queue)));
    }
    if let Some(held) = booted() {
        tracing::info!("{}", held.describe());
    }
    Ok(true)
}

#[cfg(test)]
#[path = "tests/min3_boot.rs"]
mod tests;

/// The transport arm (W2-SW-TRANSPORT): every admitted MIN-3 transport image opened through
/// `Registry::open_transport` and published for the connector.
#[path = "min3_transports.rs"]
pub(crate) mod transports;
