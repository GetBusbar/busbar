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
    durable, endpoints, export, failover, governance, handlers, hooks, ingress, ir, json, limits,
    metrics, net_guard, oauth_as, observability, operation, plane, plugin_routes, profile, proto,
    proxy, state, store, telemetry, tls, transport, trust,
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

/// A linked STORE's entry: `(name, ephemeral, door)` — the name `store.module` selects it by,
/// whether what it holds is lost on restart, and its store v3 door (the door boot opens it through,
/// on the root's [`RootInstall::store_axis`]). No row is a default: the store is the one config
/// names (Q-STORE = (B)).
pub type LinkedStore = (
    &'static str,
    bool,
    busbar_contract::abi::mechanism::door::DoorFn,
);
/// The root's store axis (WIRE-STORE Q8/Q9): every store boot opens is loaded through the root's
/// one dispatcher and opened through the store v3 table.
pub type StoreAxisOf = fn() -> std::sync::Arc<dyn busbar_contract::store_calls::StoreAxis>;
pub use busbar_kernel_identity::operator::LinkedAuth;
use busbar_plugin_loader::{boot, dispatch::PluginLogConfig, LinkedPlugin, PluginRegistry};
/// THE ROOT'S REGISTRY BUILD (ARCHITECT ruling Q8: the composition root builds the plugin registry;
/// the kernel receives it): the linked rows alone, or the directory scan with the linked rows ahead
/// of it, each step noted so the preflight's log lines keep their order.
pub type RegistryBuild =
    fn(RegistryIn<'_>, &mut dyn FnMut(boot::Note<'_>)) -> Result<PluginRegistry, String>;

/// What the root's registry build reads: the build's linked rows and, unless only those are
/// wanted, the `plugins:` block (its trust, its directory, whether it is on) and the fleet data dir
/// the first-party floor persists under.
pub struct RegistryIn<'a> {
    /// The rows this build links, registered ahead of the directory's.
    pub linked: Vec<LinkedPlugin>,
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

/// THE ROOT'S PLUGINS FETCH: every `plugins.fetch` target into `dir`, through the kernel's
/// SSRF-guarded `download` (the root never downloads by any other path); `fatal_on_miss` at boot,
/// a [`Fetched::Warned`] per problem on reload. Errors are every problem at boot.
pub type PluginsFetch = fn(
    &std::path::Path,
    &[config::FetchTarget],
    bool,
    &dyn Fn(&str) -> Result<Vec<u8>, String>,
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
    /// The root's store axis: what boot opens the configured store through.
    pub store_axis: Option<StoreAxisOf>,
    /// The root's secret axis: every secret plugin it admitted, linked or dropped in, over the
    /// process's one dispatcher (`None`: only a cold-lane plugin resolves).
    pub secret_axis: Option<&'static dyn busbar_contract::secret::SecretAxis>,
    /// The export axis: every `kind: export` row, opened on the export kind's ABI by the root over
    /// the process's one dispatcher (ARCHITECT ruling 2026-09-29, the opener seam). `None` = no
    /// export module resolves.
    pub export_axis: Option<&'static dyn busbar_contract::export_calls::ExportAxis>,
}

/// THE ROOT'S HOOK AXIS over one plugin registry (each configuration's registry gets its own).
///
/// # Errors
/// A `kind: hook` row that will not state itself (a 1.5.5 JSON hook plugin is refused, naming the
/// rebuild).
pub type HookAxisBuild =
    fn(
        &std::sync::Arc<PluginRegistry>,
    ) -> Result<std::sync::Arc<dyn busbar_contract::hook_calls::HookAxis>, String>;

/// A test build has no root: its store and ranking fixtures stand in for the root's entries, the
/// shipped secret sources as the secret axis, and the test axis for the exports.
#[cfg(any(test, feature = "test-support"))]
const STAND_IN: RootInstall = RootInstall {
    stores: &[fixture_store::linked::STORE],
    registry_build: Some(crate::test_support::registry_stand_in),
    plugins_fetch: Some(crate::test_support::fetch_stand_in),
    hook_axis: Some(crate::test_support::hook_axis_stand_in),
    store_axis: Some(crate::test_support::store_axis_stand_in),
    secret_axis: Some(&crate::test_support::SecretsStandIn),
    export_axis: Some(&crate::test_support::export_axis::STAND_IN),
};

/// The hook doors a test build links in place of the root's (the stand-in hook axis,
/// [`crate::test_support::hook_axis_stand_in`]): the ranking door, under its feature.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const STAND_IN_HOOK_DOORS: &[busbar_contract::abi::mechanism::door::DoorFn] = &[
    #[cfg(feature = "hooks-ranking")]
    fixture_hook::linked::door,
];

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
    let _ = ROOT_ROWS.set(STAND_IN);
    ROOT_ROWS.get().copied().unwrap_or_default()
}

/// THE ROOT'S DOOR onto the auth axis: its linked table's `auths` entries (the first install
/// stands; the authenticate step holds them) and their names. Every admin auth module — the operator
/// credential's included — resolves through this axis by the key configuration names; the kernel
/// names none of the rows it registers (DECISIONS #2 rule (1), #40; ARCHITECT 2026-09-27 AUTH-ROW).
pub use busbar_kernel_identity::operator::{
    install_linked as install_linked_auth, linked_names as linked_auth_names,
};

/// Opens one build's AUTH AXIS over that build's registry, on the process's one dispatcher: the
/// composition root's (it holds the dispatcher), installed once; the kernel names neither the
/// dispatcher nor the rows it opens (ARCHITECT ruling 2026-09-30, AUTH-DOOR Q1).
pub type AuthAxisOpener = fn(Arc<PluginRegistry>) -> Arc<dyn busbar_contract::auth_calls::AuthAxis>;

static AUTH_AXIS: std::sync::OnceLock<AuthAxisOpener> = std::sync::OnceLock::new();

/// THE ROOT'S DOOR onto the auth axis's opener (the first install stands).
pub fn install_auth_axis(open: AuthAxisOpener) {
    let _ = AUTH_AXIS.set(open);
}

/// This build's auth axis over `registry`; `None` (no opener installed, no stand-in): no auth row
/// answers anything. A test build has no root: the loader's test stand-in opens the build's rows on a
/// dispatcher of its own.
pub(crate) fn auth_axis(
    registry: Arc<PluginRegistry>,
) -> Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>> {
    #[cfg(feature = "test-support")]
    let _ = AUTH_AXIS.set(crate::test_support::outbound_auth::stand_in);
    AUTH_AXIS.get().map(|open| open(registry))
}

/// This build's auth axis over its LINKED rows alone (no plugins directory): what `--validate`
/// asks a style's plugin to judge a credential through.
pub(crate) fn linked_auth_axis() -> Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>> {
    auth_axis(Arc::new(linked().ok()?))
}

/// The rows this build LINKS onto the cold-kind axis, ahead of the plugins directory's: the root's
/// stores and the root's hooks — a test build (no root) stands its
/// fixture entries in. Registered through `PluginRegistry::link`, the admission a dropped-in row
/// takes (DECISIONS #2 rule (1)).
fn linked_rows() -> Vec<LinkedPlugin> {
    let RootInstall { stores, .. } = root_rows();
    let store = |&(name, ephemeral, door): &LinkedStore| LinkedPlugin::store(name, door, ephemeral);
    let rows = stores.iter().map(store);
    let auths = busbar_kernel_identity::operator::linked().iter();
    rows.chain(auths.map(|&(name, door)| LinkedPlugin::auth_door(name, door)))
        .map(answering_former_names)
        .collect()
}

/// `row`, answering also to the former names the root legacy table declares for its alias
/// (`former.<alias>`, from plugins.yaml `former_names:`): a linked plugin answers the names its
/// earlier releases carried exactly as its dropped-in copy's signed manifest does.
pub fn answering_former_names(row: LinkedPlugin) -> LinkedPlugin {
    let former = config::legacy::former_names(&row.manifest.alias);
    row.with_former_names(former)
}

/// The hook axis over this build's LINKED rows alone (no plugins directory): where a pool strategy
/// word resolves.
fn linked_hook_axis() -> Option<std::sync::Arc<dyn busbar_contract::hook_calls::HookAxis>> {
    let build = root_rows().hook_axis?;
    build(&std::sync::Arc::new(linked().ok()?)).ok()
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
        crate::hooks::plugin::HookPolicy::policy(calls, name),
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
    registry: &busbar_plugin_loader::PluginRegistry,
    dir: &str,
    r: &str,
    want: PluginRef<'_>,
) -> Result<(), String> {
    match registry.resolve(r) {
        Some(p) if p.manifest.kind == want.kind => Ok(()),
        Some(p) => Err(format!(
            "{} resolves to plugin '{}' of kind '{}', not {}",
            want.names, p.manifest.name, p.manifest.kind, want.must_be
        )),
        None => Err(match registry.unresolved_reason(r) {
            Some(s) => format!(
                "{} plugin '{}' ({}) but it was not loaded: {}",
                want.matched, s.manifest.name, s.file, s.reason
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
                    .map(|p| p.manifest.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                want.label,
                want.remedy
            ),
        }),
    }
}

/// A registry holding only the [`linked_rows`] — what a build with the plugins directory off has.
/// No directory is read and no root is needed: the kernel's own built-in secret modules resolve in
/// any build.
pub(crate) fn linked() -> Result<PluginRegistry, String> {
    PluginRegistry::empty().link(linked_rows())
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
) -> Result<busbar_plugin_loader::PluginRegistry, String> {
    // `plugins.logs` is refused here, on every path (boot, `--validate`, reload, apply).
    let l = &plugins_cfg.logs;
    PluginLogConfig::from_words(
        l.dir.as_deref(),
        l.level.as_deref(),
        &l.levels,
        l.rotate_mb,
        l.keep,
    )?;
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

    // 4. The configured store must resolve to a loadable store plugin.
    if store_is_plugin {
        require_plugin(
            &registry,
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
            &registry,
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
        if busbar_plugin_loader::hook_door::dropped_answers(&registry, hook_ref) {
            continue;
        }
        require_plugin(
            &registry,
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
        match registry.resolve(module) {
            Some(p) if p.manifest.kind == "auth" => {}
            Some(p) => {
                return Err(format!(
                    "identity-providers.{name}.module: '{module}' resolves to plugin '{}' of kind \
                     '{}', not an `auth` plugin. A provider's `module:` must be a built-in or a \
                     `kind: auth` plugin; the modules available right now are: {}.",
                    p.manifest.name,
                    p.manifest.kind,
                    valid_identity_provider_modules(&registry)
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(module) {
                    Some(s) => format!(
                        "identity-providers.{name}.module: '{module}' matches plugin '{}' ({}) but \
                         it was not loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "identity-providers.{name}.module: no `kind: auth` plugin named or aliased \
                         '{module}' is installed in '{}' (plugins ARE enabled), and it is not a \
                         built-in. The modules a provider may name right now are: {}. Check the \
                         spelling against the plugin's manifest name/alias (see --list-plugins), \
                         add the signed tarball to the plugins directory, or name a built-in.",
                        plugins_cfg.dir,
                        valid_identity_provider_modules(&registry)
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
fn log_build(n: boot::Note<'_>, dir: &str) {
    match n {
        boot::Note::FloorUnreadable(note) => diag_warn!(
            PLUGIN_FIRSTPARTY_FLOOR_UNREADABLE,
            detail = %note,
            "the persisted first-party anti-downgrade floor could not be used"
        ),
        boot::Note::Off => tracing::info!(
            "plugins: disabled (plugins.enabled is false; tarballs in the directory are inert)"
        ),
        boot::Note::Scanned(registry) => {
            tracing::info!(
                dir = %dir,
                loadable = registry.loadable().len(),
                skipped = registry.skipped().len(),
                "plugins: enabled"
            );
            for s in registry.skipped() {
                diag_warn!(
                    PLUGIN_SKIPPED_TRUST_POLICY,
                    plugin = %s.manifest.name,
                    file = %s.file,
                    reason = %s.reason,
                    "plugin present but NOT loaded (trust policy)"
                );
            }
            for p in registry.loadable() {
                match &p.verdict {
                    busbar_plugin_loader::sign::Verdict::Trusted {
                        publisher,
                        first_party,
                    } => tracing::info!(
                        plugin = %p.manifest.name,
                        alias = %p.manifest.alias,
                        kind = %p.manifest.kind,
                        version = %p.manifest.version,
                        publisher = %publisher,
                        first_party,
                        "plugin validated"
                    ),
                    busbar_plugin_loader::sign::Verdict::Allowed { reason, .. } => diag_warn!(
                        PLUGIN_LOADED_UNVERIFIED,
                        plugin = %p.manifest.name,
                        alias = %p.manifest.alias,
                        kind = %p.manifest.kind,
                        reason = %reason,
                        "plugin validated as UNVERIFIED (permitted by an explicit plugins.trust opt-in)"
                    ),
                }
            }
        }
        boot::Note::FloorUnwritable(e) => diag_warn!(
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
) -> Result<Option<busbar_contract::redacted::Redacted<String>>, String> {
    let Some(r) = auth.and_then(|a| a.admin_token_ref()) else {
        return Ok(None);
    };
    use busbar_kernel_identity::operator::{blank_token, unresolved_token};
    let op = config::operator_provider();
    let token = resolver
        .resolve_string(r)
        .map_err(|e| unresolved_token(op, &e))?;
    if token.trim().is_empty() {
        return Err(blank_token(op));
    }
    Ok(Some(busbar_contract::redacted::Redacted::new(token)))
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
    let bytes = resolver.resolve(sk).map_err(|e| {
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

/// Parse resolved bytes into a 32-byte ed25519 PUBLIC key: accept RAW 32 bytes or 64 hex chars. The
/// verifying-key twin of [`parse_signing_secret`] — same wire shapes (a fleet's `operator.pub` is
/// distributed either as raw bytes in a file or as 64 hex chars), a distinct error string so a
/// malformed operator key never reads as a malformed signing key.
pub(crate) fn parse_operator_public_key(bytes: &[u8]) -> Result<[u8; 32], String> {
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
        "auth.operator_pub must resolve to a 32-byte ed25519 PUBLIC key (raw 32 bytes or 64 hex \
         characters)"
            .to_string(),
    )
}

/// Resolve the POLICY-SEALED operator public key. `auth.operator_pub` is a reference to an EXISTING
/// secret (env/file/plugin) resolving to the raw 32-byte ed25519 VERIFYING key the fleet's operator
/// ceremony sealed (`operator.pub`). D38's `amend_rate_history` verifies a back-dated correction's
/// detached signature against it. Fleet-shared: every node resolves the SAME key.
///
/// When `auth.operator_pub` is ABSENT this returns `None` — the operator ceremony has not run, which
/// the composition root seals as [`crate::posture`]'s `OperatorState::Unset`, refusing every
/// irreducible money-governance verb at the ceremony gate exactly as the release without this key
/// does. FAIL-CLOSED: a configured-but-unresolvable / malformed operator key refuses boot, so a
/// fleet that MEANT to seal a key never comes up silently ungated.
pub fn resolve_operator_public_key(
    auth: Option<&config::AuthCfg>,
    resolver: &config::secret::SecretResolver,
) -> Result<Option<[u8; 32]>, String> {
    let Some(op) = auth.and_then(|a| a.operator_pub.as_ref()) else {
        return Ok(None);
    };
    let bytes = resolver.resolve(op).map_err(|e| {
        format!(
            "auth.operator_pub did not resolve: {e}. auth.operator_pub is a reference to an EXISTING \
             secret (env/file/plugin) holding the fleet's sealed operator public key (32 raw bytes \
             or 64 hex chars — the `operator.pub` your operator ceremony produced), or OMIT \
             auth.operator_pub entirely if this fleet has not run the operator ceremony."
        )
    })?;
    Ok(Some(parse_operator_public_key(&bytes)?))
}

/// Validate ONE `secrets:` block key against the plugin registry and return the plugin's CANONICAL
/// name. Fail-closed (an `Err`) when the key names a reserved built-in resolver (`env`/`file`, which
/// take no module-level config), when no loadable plugin is named or aliased by it, or when the
/// resolved plugin is not `kind: secret`. Shared by `build_secret_resolver` (boot) and the
/// `--validate` pre-flight so both apply the identical policy (a mistyped/aliased
/// `secrets:` key must never silently open a plugin with `{}`).
pub(crate) fn validate_secret_module(
    registry: &busbar_plugin_loader::PluginRegistry,
    module: &str,
) -> Result<String, String> {
    if config::secret::is_linked_secret(module) {
        return Err(format!(
            "secrets.{module}: '{module}' is a built-in secret resolver, not a plugin; it takes no \
             module-level configuration. Remove this `secrets:` entry (reference it inline as \
             {{ {module}: … }} where the secret is used)."
        ));
    }
    match registry.resolve(module) {
        Some(p) if p.manifest.kind == "secret" => Ok(p.manifest.name.clone()),
        Some(p) => Err(format!(
            "secrets.{module}: plugin '{}' has kind '{}', not 'secret'; only a kind: secret plugin \
             can back a `secrets:` block entry",
            p.manifest.name, p.manifest.kind
        )),
        None => Err(format!(
            "secrets.{module}: no loadable `kind: secret` plugin is named or aliased '{module}' \
             (check the spelling against the plugin's manifest name/alias, and that the plugin \
             loaded — see --list-plugins)"
        )),
    }
}

/// THE POST-RESOLVE HALF OF `--validate`, in one place.
///
/// `config_validate::validate` is only part of what makes a config valid: the plugin pre-flight
/// (consistency, trust resolution, the three-phase tarball scan, store resolution) and the two
/// secret-reference checks are the rest, and they cannot run until the registry exists. Every caller
/// that asks "is this config valid?" must run ALL of it -- `--validate` assembled the steps by hand
/// and `POST /api/v1/admin/config/validate` ran only the first, so the admin dry-run answered
/// `ok: true` for configs the CLI rejects and an operator could ship one straight into a failed boot.
///
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
    !config::builtin_identity_providers().contains(&m)
        && !(is_test_build && matches!(m, "test-groups-module" | "test-scope-module"))
}

/// The human list of every module an `identity-providers.<name>.module:` may legally name RIGHT NOW:
/// the built-ins, plus every loaded `kind: auth` plugin. Named as a SET, never counted — the same
/// "name the whole valid vocabulary" discipline the `export.<n>.streams:` diagnostic follows.
pub(crate) fn valid_identity_provider_modules(
    registry: &busbar_plugin_loader::PluginRegistry,
) -> String {
    let mut names: Vec<String> = config::builtin_identity_providers()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    names.extend(
        registry
            .loadable()
            .iter()
            .filter(|p| p.manifest.kind == "auth")
            .map(|p| p.manifest.name.clone()),
    );
    names.join(" | ")
}

/// Manifest-only, like the pre-flight it wraps: nothing is `dlopen`ed and no store is opened, so it
/// is safe on the admin read path.
pub fn preflight_plugins_and_secrets(
    deploy: &config::DeployCfg,
    cfg: &config::RootCfg,
) -> Result<busbar_plugin_loader::PluginRegistry, String> {
    let registry = plugins_preflight(
        deploy.store.as_ref(),
        cfg.auth.as_ref(),
        &cfg.identity_providers,
        &cfg.hooks,
        &deploy.plugins,
        &cfg.export,
    )?;
    validate_secret_modules(&registry, &cfg.secrets)?;
    validate_secret_refs(&registry, cfg)?;
    Ok(registry)
}

/// Validate EVERY `secrets:` block entry against the registry (the `--validate` counterpart of the
/// per-entry check `build_secret_resolver` runs at boot). Returns the FIRST offending entry's error.
pub(crate) fn validate_secret_modules(
    registry: &busbar_plugin_loader::PluginRegistry,
    secret_modules: &std::collections::BTreeMap<String, config::SecretModuleCfg>,
) -> Result<(), String> {
    for module in secret_modules.keys() {
        validate_secret_module(registry, module)?;
    }
    Ok(())
}

/// Validate every SECRET REFERENCE's module against the plugin registry — the deferred half of the
/// secret-reference check `config_validate` cannot do (it runs before the registry exists). The
/// built-in `env`/`file` modules always pass; ANY OTHER module name is a `kind: secret` PLUGIN
/// reference (the 1.5.0 "secrets are plugins" feature: `api_key: { module: acme-vault, … }`, TLS
/// cert/key, `auth.signing_key`, the admin token) and must resolve to a LOADED, TRUSTED, `kind:
/// secret` plugin. A genuine typo (no built-in, no plugin) is a hard boot / `--validate` error;
/// an installed vault/aws-sm plugin PASSES. Shared by boot (`build_app_from_config`) and the
/// `--validate` pre-flight so the two cannot drift. Returns the FIRST offending reference's error.
pub(crate) fn validate_secret_refs(
    registry: &busbar_plugin_loader::PluginRegistry,
    cfg: &config::RootCfg,
) -> Result<(), String> {
    for (what, r) in config_validate::secret_refs(cfg) {
        if config::secret::is_linked_secret(&r.module)
            // `none` names no module at all — it declares the ABSENCE of a credential — so there is
            // nothing here for the registry to resolve, and it must never be looked up as though a
            // `kind: secret` plugin called `none` could back it. WHERE it is permitted is
            // `config_validate`'s call, not this one.
            || r.is_none()
        {
            continue; // built-in resolver — already structurally checked in config_validate
        }
        match registry.resolve(&r.module) {
            Some(p) if p.manifest.kind == "secret" => {}
            Some(p) => {
                return Err(format!(
                    "{what} references secret module '{}', but plugin '{}' has kind '{}', not \
                     'secret'; only a `kind: secret` plugin can back a secret reference",
                    r.module, p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(format!(
                    "{what} references secret module '{}', which is not a built-in (`env` | `file`) \
                     and no loadable `kind: secret` plugin is named or aliased '{}'. Fix the \
                     spelling, install/trust the plugin (see --list-plugins), or use a built-in, \
                     e.g.:\n\n    {what}: {{ env: MY_SECRET_VAR }}\n",
                    r.module, r.module
                ));
            }
        }
    }
    Ok(())
}

/// RESOLVE every built-in (`env` / `file`) secret reference, for `--validate` ONLY.
///
/// `config_validate` proves a reference is well-FORMED; it cannot prove the variable is set or the
/// file is readable, because it runs before anything touches the environment. Without this,
/// `--validate` reported a config VALID while boot would warn and then serve a gateway whose every
/// upstream request fails on a missing credential: success reported for something that cannot work.
///
/// DELIBERATELY NOT IN `preflight_plugins_and_secrets`. That pre-flight is SHARED with boot and with
/// the admin apply/reload path, where an unresolvable secret is a WARNING by design, not a refusal
/// (`test_admin_v1_config_settings_unresolvable_store_secret_warns_not_rejects` pins that). A live
/// config change must not be rejected for a secret that may resolve on the next deploy. The operator
/// asking `--validate` is asking a different question, and deserves the strict answer.
///
/// Returns the FIRST unresolvable reference's error, naming the field so it is actionable.
///
/// Walks the references boot RESOLVES, not every reference the config can hold: an
/// `identity-providers:` definition's `token:` is only read through the resolved auth chains, so a
/// defined-but-unreferenced provider whose token env var is unset boots fine and must pass here too
/// (see `boot_resolved_secret_refs`). The exhaustive walk stays in use for the structural and
/// module-existence checks, which cost nothing to run over a reference boot never reads.
pub fn validate_builtin_secrets_resolve(cfg: &config::RootCfg) -> Result<(), String> {
    let builtins = config::secret::SecretResolver::builtins_only();
    for (what, r) in config_validate::boot_resolved_secret_refs(cfg) {
        if !config::secret::is_linked_secret(&r.module) {
            // `none` is a declared ABSENCE, not a source: there is nothing to resolve and nothing
            // that can fail. Every other non-built-in module is plugin-backed — the plugin may not
            // be loadable here, and pre-flight covers it.
            continue;
        }
        if let Err(e) = builtins.resolve(r) {
            return Err(format!("{what}: {e}"));
        }
    }
    Ok(())
}

/// Build the [`config::secret::SecretResolver`] the engine resolves every secret reference through:
/// the built-in `env`/`file` modules inline, and any OTHER module name via a loaded `kind: secret`
/// plugin on the secret axis (opened once per resolver, over the one dispatcher). FAIL-CLOSED: a
/// module no door answers is an unresolvable secret, refused in the registry's words. When the plugin subsystem is off the registry is empty and every non-built-in reference
/// is a fail-closed error at resolve time.
pub(crate) fn build_secret_resolver(
    registry: Arc<busbar_plugin_loader::PluginRegistry>,
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
    // canonical name (or vice versa) line up. A `secrets:` entry that resolves to NOTHING — a typo, or
    // a module that names one of the reserved built-in resolvers (`env`/`file`, which take no
    // module-level open config) — is a hard boot error: silently passing `{}` for a mis-typed module
    // is exactly the failure this closes. The `--validate` path applies the identical policy via the
    // shared `validate_secret_module`/`validate_secret_modules` helpers.
    let mut raw_config: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    // Which `secrets:` block key produced each canonical entry, so an ALIAS/CANONICAL collision can
    // be named precisely.
    let mut claimed_by: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (module, mcfg) in secret_modules {
        // Validate + canonicalize the block key against the registry (shared with --validate). A
        // reserved built-in name, an unknown module, or a non-secret plugin is a hard error here.
        let canonical = validate_secret_module(&registry, module)?;
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
        config::secret::resolve_settings(&mcfg.settings, &builtins)
            .map_err(|e| format!("secrets.{module} settings: {e}"))?;
        claimed_by.insert(canonical.clone(), module.clone());
        raw_config.insert(canonical, serde_json::Value::Object(mcfg.settings.clone()));
    }
    // A dropped-in plugin that states a door opens through the root's secret axis, once per
    // resolver, over its settings as written: the keys its Statement names as secret references are
    // resolved through the linked plugins and lent to `open`, never substituted into the settings.
    let opened: std::sync::Mutex<
        std::collections::BTreeMap<String, Arc<dyn busbar_contract::secret::SecretCalls>>,
    > = Default::default();
    Ok(config::secret::SecretResolver::with_plugin(Box::new(
        move |module: &str, settings: &str| -> Result<Vec<u8>, String> {
            if let Some(axis) = config::secret::axis().filter(|a| a.answers(module)) {
                let mut opened = opened.lock().unwrap_or_else(|e| e.into_inner());
                let calls = match opened.get(module) {
                    Some(c) => c.clone(),
                    None => {
                        let raw = registry
                            .resolve(module)
                            .and_then(|p| raw_config.get(&p.manifest.name));
                        let linked = config::secret::SecretResolver::builtins_only();
                        let c =
                            axis.open(module, raw.unwrap_or(&serde_json::Value::Null), &|r| {
                                linked.resolve(r)
                            })?;
                        opened.insert(module.to_string(), c.clone());
                        c
                    }
                };
                return calls
                    .resolve(settings.as_bytes())
                    .map(|m| m.expose_secret().clone())
                    .map_err(|r| r.text);
            }
            // No door answers it: no such secret plugin, or a 1.5.5 JSON-contract one, which this
            // host does not load (THE DESIGN §11.8). Refused in the registry's own words.
            Err(registry.secret_refusal(module))
        },
    )))
}

/// The `plugins.fetch` download closure the engine hands to the root's fetch ([`PluginsFetch`]).
/// Enforces the SAME cloud-metadata SSRF denylist provider URLs face (fetch is off-box, key-adjacent
/// I/O) and requires https for a public host, then performs the GET. The GET runs on a DEDICATED
/// std::thread with its own current-thread runtime, so it is safe whether the caller sits on a tokio
/// worker (boot) or a `spawn_blocking` thread (reload) — a nested `block_on` on a runtime thread would
/// otherwise panic. The loader owns cache/verify/atomic-write; this owns network + SSRF.
pub fn plugin_fetch_downloader(blocked: &[String]) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    plugin_fetch_downloader_with_cap(blocked, config::DEFAULT_PLUGIN_FETCH_MAX_BYTES)
}

/// Same as [`plugin_fetch_downloader`] with an explicit download-size cap — split out so a test can
/// exercise the over-cap rejection path against a small in-memory server without actually moving
/// hundreds of megabytes through loopback. Production always calls [`plugin_fetch_downloader`], which
/// pins `cap` to [`config::DEFAULT_PLUGIN_FETCH_MAX_BYTES`].
pub(crate) fn plugin_fetch_downloader_with_cap(
    blocked: &[String],
    cap: usize,
) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    let blocked: Vec<String> = blocked.to_vec();
    move |url: &str| -> Result<Vec<u8>, String> {
        // Scheme: https required for a public host; plaintext http only for loopback/private (a local
        // dev registry). Mirrors the provider base_url rule.
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
        // SSRF: never fetch from a cloud-metadata host (no per-provider carve-outs; the operator
        // denylist still extends the built-in list).
        if let Some(bad) = config_validate::ssrf_blocked_host(url, &[], false, &blocked) {
            return Err(format!(
                "plugins.fetch url '{url}' targets a blocked cloud-metadata host '{bad}'"
            ));
        }
        let url = url.to_string();
        std::thread::scope(|s| {
            s.spawn(|| -> Result<Vec<u8>, String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("fetch runtime: {e}"))?;
                rt.block_on(async {
                    // The ENGINE, on a cold one-shot posture (`pooled_webpki` values, one idle slot):
                    // webpki trust, system DNS, boot-env proxy — and redirect non-following is
                    // STRUCTURAL now (hyper follows nothing), where reqwest needed
                    // `Policy::none()`: the SSRF guard above only vets the ORIGINAL url, so a 3xx
                    // `Location` from the semi-trusted plugin registry could otherwise bounce the
                    // fetch to an internal/cloud-metadata target with no re-check — the same
                    // redirect-SSRF vector the OTLP exporter and provider clients already close.
                    // A redirect arrives as a 3xx status and falls into the non-success arm below.
                    let client = crate::proxy::build_egress_client(
                        &crate::proxy::EgressClientSpec::pooled_webpki(1, 4, false, false),
                    );
                    let uri: http::Uri = url
                        .parse()
                        .map_err(|e| format!("GET {url}: not a valid URI: {e}"))?;
                    let request = busbar_kernel::egress::engine::client_request(
                        http::Method::GET,
                        uri,
                        http::HeaderMap::new(),
                        bytes::Bytes::new(),
                    );
                    let resp = client
                        .request(request)
                        .await
                        // 1.5.5-faithful wording, formatted IN-HOUSE so it does not track the
                        // egress client's version-specific error text: the older client rendered
                        // every send failure as `error sending request for url (URL)` — the url,
                        // and no flattened cause chain. Reproduced verbatim here rather than via
                        // `with_cause(&e)`, whose output follows the newer client's spelling.
                        .map_err(|_e| {
                            format!("GET {url}: error sending request for url ({url})")
                        })?;
                    let status = resp.status();
                    if !status.is_success() {
                        if status.is_redirection() {
                            return Err(format!(
                                "GET {url}: HTTP {status} — refusing to follow a plugins.fetch \
                                 redirect (redirect-SSRF guard)"
                            ));
                        }
                        return Err(format!("GET {url}: HTTP {status}"));
                    }
                    // A declared Content-Length over the cap is rejected BEFORE reading a single body
                    // byte — the fast, cheap path for the common case of an honest oversized response.
                    // Not load-bearing on its own (a dishonest/absent header falls through to the
                    // streamed cap below), just an early exit.
                    if let Some(len) = resp
                        .headers()
                        .get(http::header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                    {
                        if len as usize > cap {
                            return Err(format!(
                                "GET {url}: declared Content-Length {len} exceeds the {cap}-byte \
                                 plugins.fetch download cap"
                            ));
                        }
                    }
                    // Stream with a running byte counter (never a whole-body buffer, which would
                    // hold the ENTIRE — possibly multi-gigabyte — body before any cap could apply)
                    // so a mistyped or compromised URL serving an unbounded body is rejected with a
                    // clear error instead of OOMing busbar on boot or `/plugins/reload`.
                    use http_body_util::BodyExt;
                    let (bytes, end) =
                        crate::proxy::read_capped(resp.into_body().into_data_stream(), cap).await;
                    match end {
                        crate::proxy::ReadEnd::Complete => Ok(bytes.to_vec()),
                        crate::proxy::ReadEnd::Truncated => Err(format!(
                            "GET {url}: response exceeded the {cap}-byte plugins.fetch download cap; \
                             refusing to buffer a truncated download"
                        )),
                        crate::proxy::ReadEnd::TransportError => {
                            Err(format!("read body {url}: connection failed mid-download"))
                        }
                    }
                })
            })
            .join()
            .map_err(|_| "plugins.fetch download thread panicked".to_string())?
        })
    }
}
