//! PLUGIN + SECRET PREFLIGHT — the boot-order half of app construction: load and verify the
//! plugin registry, resolve the admin token and the signing key, validate every secret reference
//! against the modules that can serve it, and build the `SecretResolver`. Split from `appbuild`
//! along the call order (preflight runs first; the App builder consumes its outputs), and kept
//! whole because every fn here is one refusal surface: a plugin or secret that cannot resolve is
//! a boot error naming its source, never a warning.

use std::sync::Arc;

use crate::diagnostics::{
    diag_warn, PLUGIN_FIRSTPARTY_FLOOR_UNREADABLE, PLUGIN_FIRSTPARTY_FLOOR_UNWRITABLE,
    PLUGIN_LOADED_UNVERIFIED, PLUGIN_SKIPPED_TRUST_POLICY,
};

#[allow(unused_imports)]
use crate::{
    admin, audit, auth, billing, breaker, catalogue, config, config_validate, core_routes, cost,
    durable, endpoints, export, governance, handlers, hooks, ingress, ir, json, limits, oauth_as,
    observability, operation, plane, plugin_routes, profile, proto, proxy, snapshot, state, store,
    telemetry, tls, transport, trust,
};

/// The FLEET DATA DIR the first-party anti-downgrade floor persists under, or `None` when this
/// deployment has none.
///
/// PB-13 pins that a deployment without a data dir performs NO data-dir probe and creates NO
/// data-dir files, so `None` here means the floor is memory-only and nothing is written or looked
/// for on disk. `BUSBAR_DATA_DIR` is PB-13's own first probe name; there is no `data_dir` config key
/// yet, so it is the only source, and reading an absent environment variable touches no filesystem.
/// When the `data_dir` config key lands this is the one place that has to learn about it.
///
/// `pub`: the composition root's durability branch reads the SAME resolved directory this preflight
/// persists the anti-downgrade floor under, so the boot book's on-disk journal and the floor never
/// disagree about where a node keeps its own files. ONE accessor, no second probe — a caller that
/// resolved the directory a different way is a caller that could open a journal beside a floor that
/// lives somewhere else, and PB-13's "no data dir, no probe, no files" would then be true of one of
/// them and false of the other.
pub fn fleet_data_dir() -> Option<std::path::PathBuf> {
    let raw = std::env::var_os("BUSBAR_DATA_DIR")?;
    let path = std::path::PathBuf::from(raw);
    (!path.as_os_str().is_empty()).then_some(path)
}

/// A linked STORE's entry: `(key, ephemeral, door, canonical)` — the key `store.module` selects it
/// by (and the store catalog and every refusal print), whether what it holds is lost on restart,
/// its store v3 door (the door boot opens it through, on the root's [`RootInstall::store_axis`]),
/// and its CANONICAL name (the manifest name its release tarball carries, which config may name it
/// by too: ARCHITECT C'). No row is a default: the store is the one config names (Q-STORE = (B)).
pub type LinkedStore = (
    &'static str,
    bool,
    busbar_contract::abi::mechanism::door::DoorFn,
    &'static str,
);

/// A linked STORE's entry as a store crate states it with its `MACRO_DOOR` (status rows 159 and
/// 194): `(key, ephemeral, MACRO_DOOR, canonical)`, #1469's [`LinkedStore`] shape. A store crate's
/// `linked::STORE` moves to this shape first; the root's store axis reads either shape through
/// [`StoreRow`], so the same `STORE` compiles before and after #1469.
pub type LinkedStoreDoor = (
    &'static str,
    bool,
    busbar_contract::abi::sdk::door::MacroDoor,
    &'static str,
);

/// ONE STORE-AXIS ROW as the store crate states it (status rows 159 and 194): its `linked::STORE`
/// in either shape, a [`LinkedStore`] or a [`LinkedStoreDoor`], read as the [`LinkedStore`] the
/// root's install carries. The composition root's generated table wraps every `STORE` in it.
#[derive(Debug, Clone, Copy)]
pub struct StoreRow<T>(pub T);

impl StoreRow<LinkedStore> {
    /// The row itself.
    #[must_use]
    pub const fn linked(self) -> LinkedStore {
        self.0
    }
}

impl StoreRow<LinkedStoreDoor> {
    /// The row, its `MACRO_DOOR` read as the door function it names.
    #[must_use]
    pub const fn linked(self) -> LinkedStore {
        let (key, ephemeral, door, canonical) = self.0;
        (key, ephemeral, door.door_fn(), canonical)
    }
}
/// The root's store axis (WIRE-STORE Q8/Q9): every store boot opens is loaded through the root's
/// one dispatcher and opened through the store v3 table.
pub type StoreAxisOf = fn() -> std::sync::Arc<dyn busbar_contract::store_calls::StoreAxis>;
use busbar_contract::plugin_rows::PluginRows;
pub use busbar_kernel_identity::operator::LinkedAuth;
/// THE ROOT'S REGISTRY BUILD (ARCHITECT ruling Q8: the composition root builds the plugin registry;
/// the kernel receives it as the contract's [`PluginRows`] view and names no registry type): the
/// linked rows alone, or the directory scan with the linked rows ahead of it, each step noted so the
/// preflight's log lines keep their order.
pub type RegistryBuild =
    fn(RegistryIn<'_>, &mut dyn FnMut(BuildNote<'_>)) -> Result<Arc<dyn PluginRows>, String>;

/// One row this build LINKS onto the cold-kind axis, as the root's linked tables state it: the root
/// turns each into the registry row its loader admits (answering also to the former names the root
/// legacy table gives its key).
#[derive(Clone, Copy)]
pub enum LinkedRow {
    /// A linked store ([`LinkedStore`]).
    Store(LinkedStore),
    /// A linked auth row ([`LinkedAuth`]).
    Auth(LinkedAuth),
}

/// One plugin that is linked AND dropped in, the linked build serving it: what the boot logs for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyLine {
    /// The plugin's canonical name.
    pub name: String,
    /// The one version both doors carry.
    pub version: String,
    /// The dropped-in tarball's file name.
    pub file: String,
    /// The INFO line, in the loader's words.
    pub line: String,
}

/// One step of the root's registry build, as the preflight logs it.
pub enum BuildNote<'r> {
    /// The persisted first-party floor could not be used (booting with no floor).
    FloorUnreadable(&'r str),
    /// The plugin subsystem is off: the registry is the linked rows.
    Off,
    /// The directory's rows, admitted, with the linked rows ahead of them.
    Scanned {
        /// The rows.
        rows: &'r dyn PluginRows,
        /// The plugins both linked and dropped in.
        copies: &'r [CopyLine],
    },
    /// The first-party floor rose but could not be persisted (it still floors this process).
    FloorUnwritable(&'r std::io::Error),
}

/// THE ROOT'S SECRET ADMISSION (BUSBAR-1.6.0.md §3, stages 3a/3e: the secret plugins are opened in
/// stage 3): the dropped-in secret plugins `registry` admitted, put on the root's secret axis. The
/// kernel calls it from the app build alone, never from the registry build (stage 1), which
/// `--validate` and every dry run share and which must leave the running node's secret plugins as
/// they are (l.456-457).
///
/// # Errors
/// A dropped-in secret plugin that claims a word another plugin answers to, naming both.
pub type SecretAdmit = fn(&Arc<dyn PluginRows>) -> Result<(), String>;

/// What the root's registry build reads: the build's linked rows and, unless only those are
/// wanted, the `plugins:` block (its trust, its directory, whether it is on) and the fleet data dir
/// the first-party floor persists under.
pub struct RegistryIn<'a> {
    /// The rows this build links, registered ahead of the directory's.
    pub linked: Vec<LinkedRow>,
    /// The `plugins:` block, or `None` for the linked rows alone.
    pub plugins: Option<&'a config::PluginsCfg>,
    /// [`fleet_data_dir`].
    pub data_dir: Option<&'a std::path::Path>,
}
/// One `plugins.fetch` entry's outcome, as the root's fetch reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched {
    /// The pinned file was already present and hashed to the pin: no network.
    Cached {
        /// The file inside `plugins.dir`.
        filename: String,
    },
    /// Downloaded, verified against its pin (if any), and written.
    Fetched {
        /// The file inside `plugins.dir`.
        filename: String,
    },
    /// A reload's miss or mismatch: the node keeps serving what it has.
    Warned {
        /// The entry's URL.
        url: String,
        /// Why.
        error: String,
    },
}

/// THE ROOT'S PLUGINS FETCH: every `plugins.fetch` target into `dir`, downloaded by the root
/// through the connector (status row 130 E6: the kernel dials nothing), the operator's extra
/// cloud-metadata denylist (`security.blocked_metadata_hosts`) the download's SSRF pre-check
/// extends; `fatal_on_miss` at boot, a [`Fetched::Warned`] per problem on reload. Errors are every
/// problem at boot.
pub type PluginsFetch = fn(
    &std::path::Path,
    &[config::FetchTarget],
    bool,
    &[String],
) -> Result<Vec<Fetched>, Vec<String>>;

/// WHAT THE COMPOSITION ROOT INSTALLS into the kernel, by name: its linked entries and its registry
/// build — and, as each kind's axis lands, that kind's
/// `<kind>_axis` field (ARCHITECT ruling Q8: the kernel receives contract `<Kind>Axis` seams from
/// the root, never the loader). A field is added by name; nothing is positional. Nothing
/// installed ([`Default`]): no linked rows, and a build and a fetch that refuse, naming the missing
/// root.
#[derive(Clone, Copy, Default)]
pub struct RootInstall {
    /// The build's linked in-process stores.
    pub stores: &'static [LinkedStore],
    /// The root's registry build.
    pub registry_build: Option<RegistryBuild>,
    /// The root's `plugins.fetch`.
    pub plugins_fetch: Option<PluginsFetch>,
    /// The hook axis the root builds over a registry (ARCHITECT ruling 2026-09-29, the opener seam;
    /// the SWITCH-OVER hook axis): every `kind: hook` row, compiled in or dropped in, opened on the
    /// hook kind's ABI over the process's one dispatcher. `None` = no hook opens.
    pub hook_axis: Option<HookAxisBuild>,
    /// The printed name of each hook row this build LINKS, in manifest order (the root's
    /// `linked-name` row per `hooks`-axis row): what the operator surface lists as the compiled-in
    /// hook plugins. The root's data; the kernel and the admin crate spell none of them.
    pub hook_names: &'static [&'static str],
    /// The root's store axis: what boot opens the configured store through.
    pub store_axis: Option<StoreAxisOf>,
    /// The root's secret axis: every secret plugin it admitted, linked or dropped in, over the
    /// process's one dispatcher (`None`: only a cold-lane plugin resolves).
    pub secret_axis: Option<&'static dyn busbar_contract::secret::SecretAxis>,
    /// The root's secret admission ([`SecretAdmit`]): what puts a build's dropped-in secret
    /// plugins on [`Self::secret_axis`]. `None` = no dropped-in secret plugin joins the axis.
    pub secret_admit: Option<SecretAdmit>,
    /// The root's rate holder ([`crate::rate_apply::RateApply`]): what every rate resolution, at
    /// boot and on each apply/reload, is staged with and raised to. `None` = no holder hears an
    /// apply (a build with no root ledger).
    pub rate_apply: Option<&'static dyn crate::rate_apply::RateApply>,
    /// The root's rate dater ([`crate::rate_apply::RateEpoch`]), beside its holder: what a
    /// metering accrual is dated by and the dated history the ledger reads price through. `None` =
    /// every instant dates to the opening entry (`0`) and no era has a history.
    pub rate_epoch: Option<&'static dyn crate::rate_apply::RateEpoch>,
    /// The export axis: every `kind: export` row, opened on the export kind's ABI by the root over
    /// the process's one dispatcher (ARCHITECT ruling 2026-09-29, the opener seam). `None` = no
    /// export module resolves.
    pub export_axis: Option<&'static dyn busbar_contract::export_calls::ExportAxis>,
    /// The root's PLUGIN ADMISSION over its ONE plugin trust builder — the one boot admits plugins
    /// under — carried onto every [`crate::state::App`] so the operator surface judges a plugin
    /// exactly as boot does. `None` = no trust resolves (the admin catalog lists the linked rows
    /// alone; an upload is refused).
    pub admission: Option<&'static dyn crate::admission::PluginAdmission>,
    /// The ONE durable-write primitive ([`crate::durable`]). `None` = no durable write: every write
    /// through the seam answers an error naming the missing root.
    pub durable: Option<&'static dyn crate::durable::DurableFs>,
    /// The root's reading of the `plugins.logs` block (the plugin log sinks are the loader's): a
    /// block it cannot use is refused, on every path the preflight runs. `None` = nothing to check.
    pub plugin_logs: Option<PluginLogsCheck>,
    /// Whether a DROPPED-IN `kind: hook` row of a registry answers a word by the rule the hook axis
    /// opens it by (its signed Statement's names and hook words beside the manifest's). `None` =
    /// only the registry's own words answer.
    pub hook_answers: Option<HookAnswers>,
    /// Whether a linked auth door's Statement declares an INBOUND auth-chain module.
    /// `None` = no linked row is an auth-chain module.
    pub auth_chain_module: Option<AuthChainModule>,
    /// Whether the process's off-crossing latch has tripped (the plugin dispatch is halted).
    /// `None` = it never trips.
    pub dispatch_latched: Option<fn() -> bool>,
    /// The root's auth-axis opener ([`AuthAxisOpener`]): every build's auth rows, opened on the
    /// process's one dispatcher. `None` = no auth row answers anything.
    pub auth_axis: Option<AuthAxisOpener>,
    /// What the root keeps of each resolved configuration beside the generation built from it
    /// ([`crate::appbuild::ConfigProjection`]), taken by every build. `None` = a generation keeps
    /// no projection.
    pub config_projection: Option<crate::appbuild::ConfigProjection>,
}

/// THE ROOT'S `plugins.logs` CHECK ([`RootInstall::plugin_logs`]).
///
/// # Errors
/// The block's refusal.
pub type PluginLogsCheck = fn(&config::PluginsCfg) -> Result<(), String>;

/// THE ROOT'S DROPPED-IN HOOK CLAIM ([`RootInstall::hook_answers`]).
pub type HookAnswers = fn(&dyn PluginRows, &str) -> bool;

/// THE ROOT'S READING of a linked auth door's Statement ([`RootInstall::auth_chain_module`]).
pub type AuthChainModule = fn(busbar_contract::abi::mechanism::door::DoorFn) -> bool;

/// THE ROOT'S HOOK AXIS over one plugin registry (each configuration's registry gets its own).
///
/// # Errors
/// A `kind: hook` row that will not state itself (a 1.5.5 JSON hook plugin is refused, naming the
/// rebuild).
pub type HookAxisBuild =
    fn(
        &std::sync::Arc<dyn PluginRows>,
    ) -> Result<std::sync::Arc<dyn busbar_contract::hook_calls::HookAxis>, String>;

/// A test build has no root: its store double ([`crate::test_support::store_double`]) and ranking
/// double stand in for the root's entries, the in-crate secret double
/// ([`crate::test_support::secrets`]) as the secret axis, and the test axis for the exports.
#[cfg(any(test, feature = "test-support"))]
const STAND_IN: RootInstall = RootInstall {
    stores: &[crate::test_support::store_double::STORE],
    registry_build: Some(crate::test_support::registry_stand_in),
    plugins_fetch: Some(crate::test_support::fetch_stand_in),
    hook_axis: Some(crate::test_support::hook_axis_stand_in),
    // A test build links no hook row of the root's: the operator surface lists none, unless the
    // root's own test binary hands its names in (`test_support::install_root_hook_names`).
    hook_names: &[],
    store_axis: Some(crate::test_support::store_axis_stand_in),
    secret_axis: Some(&crate::test_support::SecretsStandIn),
    secret_admit: None,
    // A test build has no root ledger: no holder hears an apply and no dater dates an accrual,
    // unless a test binary hands its own in (`test_support::rate_holders`).
    rate_apply: None,
    rate_epoch: None,
    export_axis: Some(&crate::test_support::export_axis::STAND_IN),
    admission: Some(&crate::test_support::AdmissionStandIn),
    durable: Some(&crate::test_support::DurableStandIn),
    plugin_logs: None,
    hook_answers: None,
    auth_chain_module: Some(crate::test_support::auth_chain_module_stand_in),
    dispatch_latched: None,
    // The in-process stand-in (no loader): the build's linked auth rows answered in process, a
    // dropped-in auth row refused at its open, the double for every outbound style.
    auth_axis: Some(crate::test_support::outbound_auth::stand_in),
    // A test build has no root to project a configuration for its door planes.
    config_projection: None,
};

/// The composition root's linked store and hook entries (the build's in-process stores and, when
/// compiled in, its ranking hooks) and its registry build, installed once before the first
/// resolution.
static ROOT_ROWS: std::sync::OnceLock<RootInstall> = std::sync::OnceLock::new();

/// THE ROOT'S DOOR onto the cold-kind axis: its linked tables' `stores` and `hooks` entries and the
/// root's registry build (the first install stands). The kernel names none of the plugins it
/// registers, and no store is a default (#2 rule (1), #40; Q-STORE = (B)).
pub fn install_linked_rows(rows: RootInstall) {
    let _ = ROOT_ROWS.set(rows);
}

/// The installed root rows (a test build stands its fixtures in). Admin's store catalog lists
/// `stores`, the stores this build links.
pub fn root_rows() -> RootInstall {
    #[cfg(any(test, feature = "test-support"))]
    let mut rows = match TEST_ROOT.get().copied() {
        Some(rows) => rows,
        None => {
            let _ = ROOT_ROWS.set(STAND_IN);
            ROOT_ROWS.get().copied().unwrap_or_default()
        }
    };
    #[cfg(not(any(test, feature = "test-support")))]
    let rows = ROOT_ROWS.get().copied().unwrap_or_default();
    #[cfg(any(test, feature = "test-support"))]
    {
        if let Some(hook_names) = TEST_ROOT_HOOK_NAMES.get().copied() {
            rows.hook_names = hook_names;
        }
        if let Some(open) = TEST_ROOT_AUTH_AXIS.get().copied() {
            rows.auth_axis = Some(open);
        }
    }
    rows
}

/// A TEST BINARY'S OWN ROOT, over the stand-in: what a test of the composition root's package
/// installs when it drives the kernel in process over the loader it may name (the kernel names none,
/// so its stand-in rows are in-process doubles). Read ahead of the stand-in, whichever read came
/// first; the first install stands.
#[cfg(any(test, feature = "test-support"))]
pub(crate) static TEST_ROOT: std::sync::OnceLock<RootInstall> = std::sync::OnceLock::new();

/// The hook names the composition root's OWN test binary hands in, in the root's words (its
/// generated linked-hook list): a test build's install record reports them in place of the
/// stand-in's none, whichever read came first, so a document that test binary renders names the
/// hooks the shipped binary names ([`crate::test_support::install_root_hook_names`]). The first
/// hand-in stands.
#[cfg(any(test, feature = "test-support"))]
pub(crate) static TEST_ROOT_HOOK_NAMES: std::sync::OnceLock<&'static [&'static str]> =
    std::sync::OnceLock::new();

/// THE ROOT'S DOOR onto the auth axis: its linked table's `auths` entries (the first install
/// stands; the authenticate step holds them) and their names. Every admin auth module — the operator
/// credential's included — resolves through this axis by the key configuration names; the kernel
/// names none of the rows it registers (DECISIONS #2 rule (1), #40; ARCHITECT 2026-09-27 AUTH-ROW).
pub use busbar_kernel_identity::operator::{
    install_linked as install_linked_auth, linked as linked_auth_rows,
    linked_names as linked_auth_names,
};

/// The names of the INBOUND auth-chain modules among `rows`: those whose Statement declares an
/// inbound capability and is not a host-held credentials' verifier (that one serves the `keys`
/// entry). `build.auth_modules` lists what an operator can name in `auth.chain` /
/// `admin_auth`, by alias, as 1.5.5 did; a row that only presents an upstream credential (outbound
/// styles) is not an auth-chain module. Decided from what the plugin declares, never from its name.
#[must_use]
pub fn inbound_auth_names(rows: &[LinkedAuth]) -> Vec<&'static str> {
    let Some(declares) = root_rows().auth_chain_module else {
        return Vec::new();
    };
    rows.iter().filter(|r| declares(r.2)).map(|r| r.0).collect()
}

/// Opens one build's AUTH AXIS over that build's registry, on the process's one dispatcher: the
/// composition root's (it holds the dispatcher), installed once; the kernel names neither the
/// dispatcher nor the rows it opens (ARCHITECT ruling 2026-09-30, AUTH-DOOR Q1).
pub type AuthAxisOpener = fn(Arc<dyn PluginRows>) -> Arc<dyn busbar_contract::auth_calls::AuthAxis>;

/// The auth-axis opener the composition root's OWN test binary hands in
/// ([`crate::test_support::install_root_auth_axis`]): a test build's install record reports it in
/// place of the stand-in's, whichever read came first. The first hand-in stands.
#[cfg(any(test, feature = "test-support"))]
pub(crate) static TEST_ROOT_AUTH_AXIS: std::sync::OnceLock<AuthAxisOpener> =
    std::sync::OnceLock::new();

/// This build's auth axis over `registry`, through the opener on the root's install record
/// ([`RootInstall::auth_axis`]); `None` (no opener installed): no auth row answers anything. A
/// test build has no root: the in-process stand-in answers its linked rows.
pub(crate) fn auth_axis(
    registry: Arc<dyn PluginRows>,
) -> Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>> {
    root_rows().auth_axis.map(|open| open(registry))
}

/// This build's auth axis over its LINKED rows alone (no plugins directory): what `--validate`
/// asks a style's plugin to judge a credential through.
pub(crate) fn linked_auth_axis() -> Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>> {
    auth_axis(linked().ok()?)
}

/// The rows this build LINKS onto the cold-kind axis, ahead of the plugins directory's: the root's
/// stores and the linked auth rows — a test build (no root) stands its fixture entries in. The
/// root's registry build admits each through the admission a dropped-in row takes (DECISIONS #2
/// rule (1)).
pub fn linked_rows() -> Vec<LinkedRow> {
    let RootInstall { stores, .. } = root_rows();
    let auths = busbar_kernel_identity::operator::linked().iter();
    let rows = stores.iter().copied().map(LinkedRow::Store);
    rows.chain(auths.copied().map(LinkedRow::Auth)).collect()
}

/// The hook axis over this build's LINKED rows alone (no plugins directory): where a pool strategy
/// word resolves.
fn linked_hook_axis() -> Option<std::sync::Arc<dyn busbar_contract::hook_calls::HookAxis>> {
    let build = root_rows().hook_axis?;
    build(&linked().ok()?).ok()
}

/// Whether this build links a ranking hook that claims the strategy word `name` (a hook word mark
/// of a linked `kind: hook` row).
pub(crate) fn builtin_ranking_known(name: &str) -> bool {
    linked_hook_answers(name)
}

/// Whether a `kind: hook` row this build LINKS answers `module` on the hook axis (its Statement
/// name, an alias, a former name the root legacy table gives it, or a hook word it claims): the
/// linked half of the claim table boot opens hooks through (ARCHITECT Q-P4-13).
pub(crate) fn linked_hook_answers(module: &str) -> bool {
    linked_hook_axis().is_some_and(|axis| axis.linked(module))
}

/// The built-in ranking strategy `name` names on the hook axis — the linked row that claims the
/// word, opened with `{"policy": "<name>"}` (ARCHITECT 2026-10-02, the hook-ranking opener) and
/// called through the hook seam — with its deadline: the dispatcher's Call class budget (ARCHITECT
/// Q-SO9), never the gate default. Ranking is pure compute and answers on its first poll, so, as in
/// 1.5.5, it cannot time out. `None` when this build links no ranking row claiming the word.
pub(crate) fn builtin_ranking(
    name: &str,
) -> Option<(
    std::sync::Arc<dyn crate::hooks::RoutingPolicy>,
    std::time::Duration,
)> {
    let axis = linked_hook_axis()?;
    if !axis.linked(name) {
        return None;
    }
    let budget = axis.call_budget();
    let calls = axis
        .open(name, name, &serde_json::json!({ "policy": name }), budget)
        .ok()?;
    Some((
        crate::plane_driver::hooks::policy::HookPolicy::policy(calls, name),
        budget,
    ))
}

/// A configured reference to a `kind` plugin, in the words its refusals use: how it `names` the
/// plugin, how a skipped match is `matched`, how a `missing` one is reported, what the plugin
/// `must_be`, its tarball's `label` and the `remedy`. One per referencing kind (steps 4-6).
struct PluginRef<'a> {
    kind: &'a str,
    names: String,
    matched: String,
    missing: String,
    must_be: &'a str,
    label: &'a str,
    remedy: &'a str,
}

/// `r` must resolve to a loadable row of `want.kind`, or the preflight refuses in `want`'s words:
/// another kind, a match the trust policy skipped, or nothing of that name in `dir`.
fn require_plugin(
    registry: &dyn PluginRows,
    dir: &str,
    r: &str,
    want: PluginRef<'_>,
) -> Result<(), String> {
    match registry.resolve(r) {
        Some(p) if p.kind == want.kind => Ok(()),
        Some(p) => Err(format!(
            "{} resolves to plugin '{}' of kind '{}', not {}",
            want.names, p.key, p.kind, want.must_be
        )),
        None => Err(match registry.unresolved_reason(r) {
            Some(s) => format!(
                "{} plugin '{}' ({}) but it was not loaded: {}",
                want.matched, s.name, s.file, s.reason
            ),
            None => format!(
                "{} is installed in '{dir}' (plugins ARE enabled; loadable: [{}]). Two things to \
                 check: is the plugin subsystem enabled? (it is) — and is the signed {}tarball \
                 actually IN the folder? \
                 Add it to plugins.fetch or drop the signed tarball in the directory, or {}.",
                want.missing,
                registry
                    .loadable()
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                want.label,
                want.remedy
            ),
        }),
    }
}

/// A registry holding only the [`linked_rows`] — what a build with the plugins directory off has,
/// built by the root's registry build with no `plugins:` block: no directory is read.
///
/// # Errors
/// No root installed the registry build, or it refuses a linked row.
pub fn linked() -> Result<Arc<dyn PluginRows>, String> {
    let build = root_rows()
        .registry_build
        .ok_or("no composition root installed the plugin registry build")?;
    build(
        RegistryIn {
            linked: linked_rows(),
            plugins: None,
            data_dir: None,
        },
        &mut |_| {},
    )
}

/// Build a complete `App` from a RESOLVED config — the ONE construction path shared by boot
/// (`prior = None`) and the config plane's apply/reload (`prior = Some(current)`). On apply,
/// process-lifetime state is REUSED from the prior snapshot (HTTP client pool, governance key DB,
/// version history, mutation-rate windows) and the health store is rebuilt with every surviving
/// lane's learned state RESTORED BY STABLE IDENTITY — so a lane-set change never
/// misattributes or discards breaker/latency knowledge. Errors are returned (never process-exit):
/// boot maps them to `die`, the apply endpoints to `invalid_request` — an invalid apply changes
/// nothing.
///
/// PLUGIN PRE-FLIGHT — the ONE pipeline shared byte-for-byte by BOOT (`build_app_from_config`),
/// config APPLY/RELOAD, and `busbar --validate`, so the pre-flight gate can never drift from real
/// boot behavior. Fail-closed at every step:
///
/// 1. CONSISTENCY: a `store.module` no linked row answers to, with `plugins.enabled: false` (or the
///    block absent), is an error NAMING THE FLAG — a dropped-in tarball is inert until the switch is on.
/// 2. POLICY: `plugins.trust` resolves (embedded first-party key + third-party publishers + the
///    explicit opt-ins + anti-downgrade floors); a malformed key is an error.
/// 3. SCAN: when enabled, every tarball in `plugins.dir` runs the three-phase pipeline
///    (structural -> trust -> conflict) in the root's registry build ([`RegistryBuild`]). ANY
///    invalid tarball/manifest or ANY name/alias conflict aborts with every problem named; an
///    untrusted plugin is SKIPPED (warn-logged, never `dlopen`ed).
/// 4. RESOLUTION: the configured `store.module` (alias OR canonical name, resolved against the
///    manifest registry — never a filename) must resolve to a loadable `kind: store` plugin.
///
/// Returns the validated registry (empty when plugins are disabled and no plugin is referenced).
/// NO plugin code runs in this function (manifest-only; `dlopen` happens later, at store open).
pub fn plugins_preflight(
    store_cfg: Option<&config::StoreCfg>,
    auth_cfg: Option<&config::AuthCfg>,
    identity_providers: &config::IdentityProviders,
    hooks_cfg: &std::collections::HashMap<String, config::HookCfg>,
    plugins_cfg: &config::PluginsCfg,
    export_cfg: &config::ExportCfg,
) -> Result<Arc<dyn PluginRows>, String> {
    // `plugins.logs` is refused here, on every path (boot, `--validate`, reload, apply), in the
    // root's words (the plugin log sinks are its loader's).
    if let Some(check) = root_rows().plugin_logs {
        check(plugins_cfg)?;
    }
    // The store config names; an absent block names none and resolves nothing here (Q-STORE = (B):
    // `config_validate::validate` refuses it, on every path that reaches this pre-flight).
    let store_ref = store_cfg.map(|g| g.module.clone()).unwrap_or_default();
    // Resolved on the store AXIS: a row this build links opens in-process; any other name is a
    // `kind: store` plugin the plugins directory must supply.
    let store_is_plugin = store_cfg.is_some() && linked()?.resolve(&store_ref).is_none();

    // Every non-builtin `auth.chain` module is a `kind: auth` plugin — the same manifest-only
    // pre-flight the store ref gets, so `--validate` catches a missing/wrong-kind/untrusted auth
    // plugin BEFORE boot. `keys` is engine-handled (never a plugin); `test-groups-module` is the
    // compiled-in test stand-in — ONLY actually registered under
    // `#[cfg(any(test, feature = "test-support"))]` (`AuthMiddleware::new` and
    // `AdminAuthChain::build`, `crates/busbar-kernel/src/auth/mod.rs`), so filtering it out
    // unconditionally here made `--validate`/`config_validate::validate` silently agree a RELEASE
    // config naming it is fine, while real boot still hard-failed (the invariant `--validate`
    // clean => the plugin half of boot succeeds too, documented a few lines below, broke). Gate
    // the exemption the same way the module itself is gated — ONE gate, `stand_ins`, read by the
    // chain predicate here AND the definition predicate below. The definition side once read
    // `cfg!(test)` alone, so a `test-support` build (how a downstream crate's test binary links
    // this one) refused an `identity-providers:` definition its own auth chain accepts (item 292).
    let stand_ins = cfg!(any(test, feature = "test-support"));
    let auth_plugin_refs: Vec<&str> = auth_cfg
        .map(|a| {
            a.chain
                .iter()
                .map(|e| e.module.as_str())
                .filter(|m| is_real_auth_plugin_ref(m, stand_ins))
                .collect()
        })
        .unwrap_or_default();

    // Every `identity-providers:` DEFINITION whose `module:` is not a built-in is likewise a
    // `kind: auth` plugin reference — checked here over the DEFINITION map rather than over the
    // resolved chain, because that is the only layer that sees an UNREFERENCED definition.
    // `resolve_auth` is keyed off `auth.chain:`/`auth.admin_auth:`, and `AuthCfg.methods` only
    // exists at all when an `auth:` block does, so a provider defined through
    // `PUT /identity-providers/{name}` and not yet referenced was validated by NOTHING: the API
    // answered 200 and stored a `module:` that can never authenticate anyone. `export:` has had the
    // equivalent check since 1.5.3 (`resolve_export` refuses an unknown exporter and names the
    // built-ins); it just needed no registry, because the export vocabulary is a const list.
    // Carries (name, module) pairs so the diagnostics can name the offending DEFINITION, not only
    // the module string — two providers can share one typo'd module.
    let idp_plugin_refs: Vec<(&str, &str)> = identity_providers
        .iter()
        .map(|(name, def)| (name.as_str(), def.module.trim()))
        // An EMPTY module is `resolve_auth`'s rule ("must be a non-empty module name"), reported
        // there in its own words; do not shadow it with a less specific "no such plugin".
        .filter(|(_, m)| !m.is_empty() && is_real_identity_provider_plugin_ref(m, stand_ins))
        .collect();
    let idp_refs_human = |refs: &[(&str, &str)]| {
        refs.iter()
            .map(|(n, m)| format!("identity-providers.{n} (module '{m}')"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    // Every hook references a `kind: hook` plugin — the same manifest-only pre-flight the store/auth
    // refs get. Deduped for the messages, but validated as the set of names each hook declares.
    // THE CLAIM TABLE BOOT USES (ARCHITECT Q-P4-13): a hook a LINKED row answers (its Statement
    // name, an alias, a former name, a hook word) opens through the hook axis with no plugins
    // directory, exactly as boot opens it, so it is no plugin reference here; every other hook names
    // a `kind: hook` plugin the directory must supply.
    let hook_plugin_refs: Vec<String> = {
        let mut v: Vec<String> = hooks_cfg
            .values()
            .map(|h| h.plugin.clone())
            .filter(|m| !linked_hook_answers(m))
            .collect();
        v.sort();
        v.dedup();
        v
    };
    let has_hook_plugin = !hook_plugin_refs.is_empty();

    // 1. Consistency: referencing a plugin store while the master switch is off is a NAMED error.
    if store_is_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "store.module: '{store_ref}' requires the plugin subsystem, but plugins.enabled is \
             false (the default). Set plugins.enabled: true and place the signed \
             '{store_ref}' store plugin tarball in the plugins directory ('{}'), or set \
             store.module: memory.",
            plugins_cfg.dir
        ));
    }
    // Same consistency gate for an auth plugin: a configured `kind: auth` module cannot load with
    // the plugin subsystem off — fail-closed, never a silently-open front door.
    if !auth_plugin_refs.is_empty() && !plugins_cfg.enabled {
        return Err(format!(
            "auth.chain names plugin module(s) [{}], which require the plugin subsystem, but \
             plugins.enabled is false (the default). Set plugins.enabled: true and place the \
             signed auth plugin tarball(s) in the plugins directory ('{}').",
            auth_plugin_refs.join(", "),
            plugins_cfg.dir
        ));
    }

    // Same consistency gate for a hook plugin: a configured `kind: hook` module cannot load with
    // the plugin subsystem off — fail-closed, never a silently-absent gate.
    if has_hook_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "the hooks registry names plugin module(s) [{}], which require the plugin subsystem, \
             but plugins.enabled is false (the default). Set plugins.enabled: true and place the \
             signed `kind: hook` plugin tarball(s) in the plugins directory ('{}').",
            hook_plugin_refs.join(", "),
            plugins_cfg.dir
        ));
    }

    // Same consistency gate for an identity-provider DEFINITION: with the plugin subsystem off the
    // registry is empty by construction, so the only modules that can ever back a provider are the
    // built-ins — naming anything else is a config error today, not a latent one. Ordered AFTER the
    // `auth.chain` gate on purpose: a provider that IS on a chain gets that gate's more specific
    // "auth.chain names plugin module(s)" wording, and this one covers the definitions no chain
    // reaches.
    if !idp_plugin_refs.is_empty() && !plugins_cfg.enabled {
        return Err(format!(
            "{} require(s) the plugin subsystem, but plugins.enabled is false (the default). With \
             plugins off, a provider's `module:` must be one of the built-ins: {}. Set \
             plugins.enabled: true and place the signed `kind: auth` plugin tarball(s) in the \
             plugins directory ('{}'), or name a built-in.",
            idp_refs_human(&idp_plugin_refs),
            config::builtin_identity_providers().join(" | "),
            plugins_cfg.dir
        ));
    }

    // 2. Policy resolution (embedded first-party key + configured third-party trust) is the root's
    //    registry build's, which then arms the AUTOMATIC first-party anti-downgrade floor from the
    //    per-name high-water marks — an observed fact, not a config value. Every automatic path
    //    (boot / config reload / config apply / admin plugin reload) runs through this one build,
    //    and a malformed floor is warned about here first.
    plugins_cfg.warn_invalid_floors();
    let data_dir = fleet_data_dir();
    // 3. Disabled: the registry is the linked rows and NOTHING in the directory is even read
    //    (drop-is-inert). Enabled: the three-phase scan over the plugins directory, fail-closed on
    //    invalid/conflict, the linked rows registered ahead of the directory's through the same
    //    admission; then the floor RISES to what the scan proved loadable (only a VERIFIED
    //    first-party verdict counts, and the mark only ever rises). A failure to persist is NOT
    //    fatal: the in-memory marks still floor this process.
    let build = RegistryIn {
        linked: linked_rows(),
        plugins: Some(plugins_cfg),
        data_dir: data_dir.as_deref(),
    };
    let registry_build = root_rows()
        .registry_build
        .ok_or("no composition root installed the plugin registry build")?;
    let registry = registry_build(build, &mut |n| log_build(n, &plugins_cfg.dir))?;
    if !plugins_cfg.enabled {
        return Ok(registry);
    }

    let rows: &dyn PluginRows = registry.as_ref();

    // 4. The configured store must resolve to a loadable store plugin.
    if store_is_plugin {
        require_plugin(
            rows,
            &plugins_cfg.dir,
            &store_ref,
            PluginRef {
                kind: "store",
                names: format!("store.module: '{store_ref}'"),
                matched: format!("store.module: '{store_ref}' matches"),
                missing: format!("no plugin matching store.module: '{store_ref}'"),
                must_be: "a store plugin",
                label: "",
                remedy: "set store.module: memory",
            },
        )?;
    }

    // 5. Every configured auth-chain plugin must resolve to a loadable `kind: auth` plugin. Same
    // manifest-only resolution as the store ref (no `dlopen` here; the real load happens in
    // `AuthMiddleware::new` at App construction). A missing/wrong-kind/untrusted auth plugin fails
    // `--validate` and boot alike — a typo'd or absent front-door module must never pass silently.
    for auth_ref in &auth_plugin_refs {
        require_plugin(
            rows,
            &plugins_cfg.dir,
            auth_ref,
            PluginRef {
                kind: "auth",
                names: format!("auth.chain module '{auth_ref}'"),
                matched: format!("auth.chain module '{auth_ref}' matches"),
                missing: format!("no plugin matching auth.chain module '{auth_ref}'"),
                must_be: "an `auth` plugin",
                label: "`kind: auth` ",
                remedy: "remove it from auth.chain",
            },
        )?;
    }

    // 6. Every hook's `plugin:` ref must resolve to a loadable `kind: hook` plugin. Same manifest-only
    // resolution as store/auth (no `dlopen` here; the real load happens in `resolve_gate_transport` at
    // App construction). A missing/wrong-kind/untrusted hook plugin fails `--validate` and boot alike.
    for hook_ref in &hook_plugin_refs {
        // A dropped-in hook answers by every word the hook axis finds it by (its Statement's names
        // and hook words beside the manifest's), not only by the words the registry indexes.
        if root_rows()
            .hook_answers
            .is_some_and(|answers| answers(rows, hook_ref))
        {
            continue;
        }
        require_plugin(
            rows,
            &plugins_cfg.dir,
            hook_ref,
            PluginRef {
                kind: "hook",
                names: format!("a hook references plugin '{hook_ref}', which"),
                matched: format!("a hook references plugin '{hook_ref}', matching"),
                missing: format!("no plugin matching the hook reference '{hook_ref}'"),
                must_be: "a `hook` plugin",
                label: "`kind: hook` ",
                remedy: "remove the hook",
            },
        )?;
    }

    // 6b. Every `identity-providers:` DEFINITION's non-built-in `module:` must resolve to a loadable
    // `kind: auth` plugin — the definition-side counterpart of the `auth.chain` resolution above,
    // and the check that finally covers a provider NO chain references (the admin API's whole write
    // surface). Manifest-only, like its siblings.
    for (name, module) in &idp_plugin_refs {
        match rows.resolve(module) {
            Some(p) if p.kind == "auth" => {}
            Some(p) => {
                return Err(format!(
                    "identity-providers.{name}.module: '{module}' resolves to plugin '{}' of kind \
                     '{}', not an `auth` plugin. A provider's `module:` must be a built-in or a \
                     `kind: auth` plugin; the modules available right now are: {}.",
                    p.key,
                    p.kind,
                    valid_identity_provider_modules(rows)
                ));
            }
            None => {
                return Err(match rows.unresolved_reason(module) {
                    Some(s) => format!(
                        "identity-providers.{name}.module: '{module}' matches plugin '{}' ({}) but \
                         it was not loaded: {}",
                        s.name, s.file, s.reason
                    ),
                    None => format!(
                        "identity-providers.{name}.module: no `kind: auth` plugin named or aliased \
                         '{module}' is installed in '{}' (plugins ARE enabled), and it is not a \
                         built-in. The modules a provider may name right now are: {}. Check the \
                         spelling against the plugin's manifest name/alias (see --list-plugins), \
                         add the signed tarball to the plugins directory, or name a built-in.",
                        plugins_cfg.dir,
                        valid_identity_provider_modules(rows)
                    ),
                });
            }
        }
    }

    // 7. PLUGIN HTTP ROUTE COLLISION CHECK. Every route the export: block's sinks declare — the
    // built-in `prometheus` exporter's `GET /metrics` and every export-axis sink opened at boot
    // (`crate::export::plugin::open`, which runs before the first app is built) — namespace-confined
    // and collision-checked by the SAME `build_route_table` the live table is built with, so a sink
    // claiming a path another already owns fails LOUD here, naming both: e.g. `plugin "datadog"
    // cannot register GET /metrics — already registered by "prometheus"`. The manifest-only
    // mirror this replaced read routes from a signed-manifest field that was never defined, so it
    // checked the built-in set alone and could not collide.
    crate::plugin_routes::build_route_table(crate::export::route_decls(export_cfg))
        .map_err(|e| format!("plugin route registration conflict: {e}"))?;

    Ok(registry)
}

/// The preflight's log line for each step of the root's registry build, in the build's order.
fn log_build(n: BuildNote<'_>, dir: &str) {
    match n {
        BuildNote::FloorUnreadable(note) => diag_warn!(
            PLUGIN_FIRSTPARTY_FLOOR_UNREADABLE,
            detail = %note,
            "the persisted first-party anti-downgrade floor could not be used"
        ),
        BuildNote::Off => tracing::info!(
            "plugins: disabled (plugins.enabled is false; tarballs in the directory are inert)"
        ),
        BuildNote::Scanned { rows, copies } => {
            let loadable = rows.loadable();
            let skipped = rows.skipped();
            tracing::info!(
                dir = %dir,
                loadable = loadable.len(),
                skipped = skipped.len(),
                "plugins: enabled"
            );
            for copy in copies {
                tracing::info!(
                    plugin = %copy.name,
                    version = %copy.version,
                    file = %copy.file,
                    "{}",
                    copy.line
                );
            }
            for s in &skipped {
                diag_warn!(
                    PLUGIN_SKIPPED_TRUST_POLICY,
                    plugin = %s.name,
                    file = %s.file,
                    reason = %s.reason,
                    "plugin present but NOT loaded (trust policy)"
                );
            }
            for p in &loadable {
                match &p.trust {
                    busbar_contract::plugin_rows::Trust::Trusted {
                        publisher,
                        first_party,
                    } => tracing::info!(
                        plugin = %p.name,
                        alias = %p.alias,
                        kind = %p.kind,
                        version = %p.version,
                        publisher = %publisher,
                        first_party,
                        "plugin validated"
                    ),
                    busbar_contract::plugin_rows::Trust::Allowed { reason } => diag_warn!(
                        PLUGIN_LOADED_UNVERIFIED,
                        plugin = %p.name,
                        alias = %p.alias,
                        kind = %p.kind,
                        reason = %reason,
                        "plugin validated as UNVERIFIED (permitted by an explicit plugins.trust opt-in)"
                    ),
                }
            }
        }
        BuildNote::FloorUnwritable(e) => diag_warn!(
            PLUGIN_FIRSTPARTY_FLOOR_UNWRITABLE,
            error = %e,
            "could not persist the first-party anti-downgrade floor; it still applies to this \
             process but will not survive a restart"
        ),
    }
}

/// Resolve the operator ADMIN credential — the operator-credential entry's `token:` secret ref —
/// with the BLANK-TOKEN guard. Shared by boot and the apply/reload path so the two cannot drift.
///
/// FAIL-CLOSED twice over:
/// * an unresolvable ref refuses boot/apply (a silently-absent token would lock the admin API
///   while the operator believes it is guarded);
/// * a ref that resolves to EMPTY or ALL-WHITESPACE is refused too. The
///   documented boot guard for this had been lost in the move to secret refs, and the consequence
///   is worse than the docs described: the digest is computed over the blank string, so
///   `admin_token_hash` is `Some(sha256(""))` — a REAL credential that an `Authorization: Bearer `
///   with an empty value satisfies. An env var that expanded to nothing would silently hand the
///   whole admin surface to an unauthenticated caller.
pub(crate) fn resolve_admin_token(
    auth: Option<&config::AuthCfg>,
    resolver: &config::secret::SecretResolver,
) -> Result<Option<busbar_contract::redacted::Secret<String>>, String> {
    let Some(r) = auth.and_then(|a| a.admin_token_ref()) else {
        return Ok(None);
    };
    use busbar_kernel_identity::operator::{blank_token, unresolved_token};
    let op = config::operator_provider();
    let token = resolver
        .resolve_string_at_config(r, &busbar_contract::config_time::ConfigScope::config_time())
        .map_err(|e| unresolved_token(op, &e))?;
    if token.trim().is_empty() {
        return Err(blank_token(op));
    }
    Ok(Some(busbar_contract::redacted::Secret::new(token)))
}

/// Parse resolved bytes into a 32-byte ed25519 secret: accept RAW 32 bytes or 64 hex chars. Shared
/// by the signing-key resolver and the `--generate-signing-key` self-check.
pub(crate) fn parse_signing_secret(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        return Ok(out);
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        let s = s.trim();
        if s.len() == 64 {
            if let Ok(v) = hex::decode(s) {
                let mut out = [0u8; 32];
                out.copy_from_slice(&v);
                return Ok(out);
            }
        }
    }
    Err(
        "auth.signing_key must resolve to a 32-byte ed25519 secret key (raw 32 bytes or 64 hex \
         characters)"
            .to_string(),
    )
}

/// Resolve the KEY-SIGNING key. `auth.signing_key` is a reference to an EXISTING secret
/// (env/file/plugin) resolving to the ed25519 secret material (32 raw bytes, or 64 hex chars) busbar
/// mints + verifies virtual-key tokens with. Fleet-shared: every node resolves the SAME secret so
/// they verify each other's tokens.
///
/// 1.5.1 BREAKING CHANGE: busbar NO LONGER auto-generates and persists a signing key at boot (the
/// 1.5.0 behavior wrote `busbar-signing.key` beside the config, which boot-looped a read-only config
/// mount with a misleading Permission-denied). When `auth.signing_key` is absent this returns `None`;
/// `config_validate` fails CLOSED at `--validate`/boot if the deployment actually uses signed-token
/// auth (the `keys` verifier in the chain), and the mint path fails closed with a clear message
/// otherwise. Generate a key with `busbar --generate-signing-key`.
///
/// FAIL-CLOSED: a configured-but-unresolvable / malformed signing key refuses boot.
pub(crate) fn resolve_signing_key(
    auth: Option<&config::AuthCfg>,
    resolver: &config::secret::SecretResolver,
) -> Result<Option<governance::signing::TokenSigner>, String> {
    use governance::signing::{TokenSigner, DEFAULT_KID};

    let Some(sk) = auth.and_then(|a| a.signing_key.as_ref()) else {
        // No configured key: busbar does not generate one (1.5.1). A deployment that verifies
        // busbar-signed keys is REQUIRED to provide it (enforced fail-closed by config_validate);
        // one that never issues signed tokens simply has no signer.
        return Ok(None);
    };
    let bytes = resolver
        .resolve_at_config(
            sk,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map_err(|e| {
            format!(
            "auth.signing_key did not resolve: {e}. auth.signing_key is a reference to an EXISTING \
             secret (env/file/plugin) - it does NOT generate a key. Provide the key first (a \
             32-byte raw or 64-hex-char ed25519 secret: `busbar --generate-signing-key`, or \
             `openssl rand -hex 32`), or OMIT auth.signing_key entirely if this deployment never \
             issues busbar-signed keys."
        )
        })?;
    let secret = parse_signing_secret(&bytes)?;
    Ok(Some(TokenSigner::from_secret_bytes(&secret, DEFAULT_KID)))
}

/// Whether `m` names a REAL `auth.chain` plugin ref that must resolve against the plugin registry
/// (`true`) vs a builtin/test stand-in that's exempt (`false`). `keys` is engine-handled, never a
/// plugin. `test-groups-module` is ONLY actually registered as a chain module under
/// `#[cfg(any(test, feature = "test-support"))]` (`AuthMiddleware::new`,
/// `crates/busbar-kernel/src/auth/mod.rs`) — `is_test_build` MUST be that same gate at the real call
/// site, so this exemption fires exactly where the stand-in exists. Module-
/// level (not inlined into the `.filter(...)` closure) so the exact predicate that determines
/// `--validate`/`config_validate::validate`'s pass/fail is unit-testable independent of which
/// binary flavor happens to be running `cargo test` — see `tests/tests.rs`. A prior version
/// exempted `test-groups-module` UNCONDITIONALLY (no `is_test_build` gate at all), which made
/// `--validate` silently agree a RELEASE config naming it was fine while real boot still hard-
/// failed (`AuthMiddleware::new` has no non-test arm for it) — breaking the documented invariant
/// a few lines below ("a clean `--validate` means the plugin half of boot succeeds too").
pub(crate) fn is_real_auth_plugin_ref(m: &str, is_test_build: bool) -> bool {
    m != config::KEYS_MODULE && !(is_test_build && m == "test-groups-module")
}

/// The DEFINITION-side twin of [`is_real_auth_plugin_ref`]: whether an
/// `identity-providers.<name>.module:` is a REAL `kind: auth` plugin reference that must resolve
/// against the registry, as opposed to a built-in the engine handles inline
/// ([`config::builtin_identity_providers`] — `keys` and the operator credential) or a compiled-in
/// test stand-in. Separate from the chain predicate because the two answer different questions over
/// different vocabularies: `auth.chain:` never carries the operator credential (that plane is
/// `admin_auth:`),
/// so the chain predicate exempts only `keys`, while EVERY built-in is legal as a definition's
/// module. Same `is_test_build` discipline for the same reason: `test-scope-module` /
/// `test-groups-module` are only ever registered under `#[cfg(any(test, feature = "test-support"))]`
/// (`AdminAuthChain::build`, `crates/busbar-kernel/src/auth/mod.rs`), so exempting them
/// unconditionally would make `--validate` silently bless a RELEASE config that real boot still
/// hard-fails, and gating them on `cfg!(test)` alone refused them in a `test-support` build that
/// registers them (item 292).
pub(crate) fn is_real_identity_provider_plugin_ref(m: &str, is_test_build: bool) -> bool {
    !config::is_builtin_identity_module(m)
        && !(is_test_build && matches!(m, "test-groups-module" | "test-scope-module"))
}

/// The human list of every module an `identity-providers.<name>.module:` may legally name RIGHT NOW:
/// the built-ins, plus every loaded `kind: auth` plugin. Named as a SET, never counted — the same
/// "name the whole valid vocabulary" discipline the `export.<n>.streams:` diagnostic follows.
pub(crate) fn valid_identity_provider_modules(registry: &dyn PluginRows) -> String {
    let mut names: Vec<String> = config::builtin_identity_providers()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    names.extend(
        registry
            .loadable()
            .into_iter()
            .filter(|p| p.kind == "auth")
            .map(|p| p.name),
    );
    names.join(" | ")
}

/// Build the [`config::secret::SecretResolver`] the engine resolves every secret reference through:
/// the built-in `env`/`file` modules inline, and any OTHER module name via a loaded `kind: secret`
/// plugin on the secret axis (opened once per resolver, over the one dispatcher). FAIL-CLOSED: a
/// module no door answers is an unresolvable secret, refused in the registry's words. When the plugin subsystem is off the registry is empty and every non-built-in reference
/// is a fail-closed error at resolve time.
pub(crate) fn build_secret_resolver(
    registry: Arc<dyn PluginRows>,
    secret_modules: &std::collections::BTreeMap<String, config::SecretModuleCfg>,
) -> Result<config::secret::SecretResolver, String> {
    // MODULE-LEVEL config delivery for `kind: secret` plugins: resolve each configured
    // `secrets.<module>.settings` ONCE at boot and hand it to the plugin's `open()`, exactly as
    // `store.settings` configures the store plugin. Without this a secret plugin's `open()` always
    // received `{}`, so a Vault-style plugin's address/namespace/token/CA had to be repeated in EVERY
    // SecretRef — multiplying secret exposure and defeating the open-vs-resolve separation the ABI
    // is designed around.
    //
    // The module config is resolved against the BUILT-IN env/file resolvers ONLY (a `builtins_only`
    // resolver). A secret module cannot resolve its OWN `open()` config through a secret plugin —
    // that would be a bootstrap cycle — so `{ token: { env: VAULT_TOKEN } }` resolves but
    // `{ token: { module: some-other-secret-plugin } }` is a fail-closed error.
    let builtins = config::secret::SecretResolver::builtins_only();
    // Key the open-config map by the plugin's CANONICAL name, not by the literal `secrets:` block
    // key: a `SecretRef` may name the plugin by EITHER its canonical name or its alias, and
    // the registry resolves both — but a bare string-equality lookup on the block key would MISS the
    // other spelling and silently open the plugin with `{}` (dropping the operator's configured
    // address/token/CA). Canonicalize the block key through the SAME by_name/by_alias resolution the
    // registry uses, so a `secrets:` entry written under an alias and a `SecretRef` written under the
    // canonical name (or vice versa) line up. The one validator (`config_validate::check`) has
    // already refused a `secrets:` entry that resolves to no `kind: secret` plugin.
    let mut raw_config: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    // Which `secrets:` block key produced each canonical entry, so an ALIAS/CANONICAL collision can
    // be named precisely.
    let mut claimed_by: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (module, mcfg) in secret_modules {
        let canonical = config_validate::secret_module(registry.as_ref(), module)?;
        // TWO SPELLINGS, ONE MODULE: a `secrets:` block written under BOTH a plugin's alias and its
        // canonical name canonicalizes to the same key, and the second insert silently DROPPED the
        // first entry's open() config — one of the two blocks (address, token, CA) just vanished,
        // with the module still loading happily on the survivor. Ambiguous by construction: there is
        // no defensible rule for which one wins. Fail LOUD and name both spellings.
        if let Some(previous) = claimed_by.get(&canonical) {
            return Err(format!(
                "secrets: the module '{canonical}' is configured TWICE — once as '{previous}' and \
                 once as '{module}' (an alias and its canonical name resolve to the same plugin). \
                 One of the two blocks would be silently dropped; keep exactly one."
            ));
        }
        config::secret::resolve_settings(
            &mcfg.settings,
            &registry.secret_slots(module),
            module,
            &builtins,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map_err(|e| format!("secrets.{module} settings: {e}"))?;
        claimed_by.insert(canonical.clone(), module.clone());
        raw_config.insert(canonical, serde_json::Value::Object(mcfg.settings.clone()));
    }
    // A dropped-in plugin that states a door opens through the root's secret axis, once per
    // resolver, over its settings as written: the keys its Statement names as secret references are
    // resolved through the linked plugins and lent to `open`, never substituted into the settings.
    let opened = OpenedSecrets::default();
    Ok(config::secret::SecretResolver::with_scoped_plugin(
        Box::new(
            move |module: &str,
                  settings: &str,
                  scope: Option<&busbar_contract::config_time::ConfigScope>|
                  -> Result<Vec<u8>, String> {
                if let Some(axis) = config::secret::axis().filter(|a| a.answers(module)) {
                    // Keyed by the plugin's CANONICAL name, so an alias and its canonical spelling
                    // open the plugin once.
                    let canonical = registry.resolve(module).map(|p| p.key);
                    let key = canonical.as_deref().unwrap_or(module);
                    return opened.resolve(key, settings, scope, || {
                        let raw = canonical.as_ref().and_then(|name| raw_config.get(name));
                        let linked = config::secret::SecretResolver::builtins_only();
                        axis.open(
                            module,
                            raw.unwrap_or(&serde_json::Value::Null),
                            &|r| match scope {
                                Some(scope) => linked.resolve_at_config(r, scope),
                                None => linked.resolve(r),
                            },
                        )
                    });
                }
                // No door answers it: no such secret plugin, or a 1.5.5 JSON-contract one, which this
                // host does not load (THE DESIGN §11.8). Refused in the registry's own words.
                Err(registry.secret_refusal(module))
            },
        ),
    ))
}

/// THE SECRET PLUGINS A RESOLVER OPENED, one handle per plugin (audit kernel-K1 #6).
///
/// The map's lock is held to find or open a plugin's handle and released before the plugin is asked
/// to `resolve`: one slow or hung secret source (a remote vault) stalls only the resolutions it
/// answers, never another module's, and never a second caller of its own that already holds the
/// handle.
#[derive(Default)]
pub(crate) struct OpenedSecrets(
    std::sync::Mutex<
        std::collections::BTreeMap<String, Arc<dyn busbar_contract::secret::SecretCalls>>,
    >,
);

impl OpenedSecrets {
    /// The handle opened under `key`, opening it with `open` the first time.
    fn calls(
        &self,
        key: &str,
        open: impl FnOnce() -> Result<Arc<dyn busbar_contract::secret::SecretCalls>, String>,
    ) -> Result<Arc<dyn busbar_contract::secret::SecretCalls>, String> {
        let mut opened = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(calls) = opened.get(key) {
            return Ok(Arc::clone(calls));
        }
        let calls = open()?;
        opened.insert(key.to_string(), Arc::clone(&calls));
        Ok(calls)
    }

    /// Resolve `settings` through the plugin opened under `key`, with no lock held while the plugin
    /// answers — at config time when the caller holds the proof `scope` (THE DESIGN §11.11 R4: a
    /// source that reads the disk answers only so).
    pub(crate) fn resolve(
        &self,
        key: &str,
        settings: &str,
        scope: Option<&busbar_contract::config_time::ConfigScope>,
        open: impl FnOnce() -> Result<Arc<dyn busbar_contract::secret::SecretCalls>, String>,
    ) -> Result<Vec<u8>, String> {
        let calls = self.calls(key, open)?;
        match scope {
            Some(scope) => calls.resolve_at_config(settings.as_bytes(), scope),
            None => calls.resolve(settings.as_bytes()),
        }
        .map(|m| m.expose(&crate::seal::lend()).clone())
        .map_err(|r| r.text)
    }
}

/// THE `plugins.fetch` PRE-CHECK, before any dial (status row 130 E6: the root downloads through
/// the connector; the rules are the kernel's deleted downloader's, verbatim): https required for a
/// public host, plaintext http only for a loopback or private one (a local dev registry, the
/// provider base_url rule); never a cloud-metadata host (no per-provider carve-outs; the operator's
/// `blocked` denylist extends the built-in list). `Ok` answers whether the URL is secured.
///
/// # Errors
///
/// The refusal, in 1.5.5's words.
pub fn plugin_fetch_admits(url: &str, blocked: &[String]) -> Result<bool, String> {
    let https = config_validate::scheme_is(url, "https");
    if !https {
        let host_local = config_validate::extract_normalized_host(url)
            .as_deref()
            .map(config_validate::host_is_private_or_loopback)
            .unwrap_or(false);
        if !(config_validate::scheme_is(url, "http") && host_local) {
            return Err(format!(
                "plugins.fetch url must use https for a public host (got '{url}')"
            ));
        }
    }
    if let Some(bad) = config_validate::ssrf_blocked_host(url, &[], false, blocked) {
        return Err(format!(
            "plugins.fetch url '{url}' targets a blocked cloud-metadata host '{bad}'"
        ));
    }
    Ok(https)
}

/// THE `plugins.fetch` VERDICT ON AN ANSWER'S STATUS `code`, in 1.5.5's words: `None` for a
/// success; a redirect is refused and never followed (the pre-check vets only the original url, so
/// a `Location` from the semi-trusted registry could otherwise bounce the fetch to an internal
/// target); any other status is refused with its code and reason (`404 Not Found`).
#[must_use]
pub fn plugin_fetch_status_refusal(url: &str, code: u32) -> Option<String> {
    if (200..300).contains(&code) {
        return None;
    }
    let shown = u16::try_from(code)
        .ok()
        .and_then(|c| http::StatusCode::from_u16(c).ok())
        .map_or_else(|| code.to_string(), |s| s.to_string());
    if (300..400).contains(&code) {
        return Some(format!(
            "GET {url}: HTTP {shown} — refusing to follow a plugins.fetch redirect \
             (redirect-SSRF guard)"
        ));
    }
    Some(format!("GET {url}: HTTP {shown}"))
}

#[cfg(test)]
#[path = "tests/opened_secrets_tests.rs"]
mod opened_secrets_tests;

#[cfg(test)]
#[path = "tests/store_row_tests.rs"]
mod store_row_tests;
