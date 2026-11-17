// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use crate::diagnostics::{
    diag_warn, PLUGIN_FIRSTPARTY_FLOOR_UNREADABLE, PLUGIN_FIRSTPARTY_FLOOR_UNWRITABLE,
    PLUGIN_LOADED_UNVERIFIED, PLUGIN_SKIPPED_TRUST_POLICY,
};

use crate::{config, config_validate, governance};

pub fn fleet_data_dir() -> Option<std::path::PathBuf> {
    let raw = std::env::var_os("BUSBAR_DATA_DIR")?;
    let path = std::path::PathBuf::from(raw);
    (!path.as_os_str().is_empty()).then_some(path)
}

pub type LinkedStore = (
    &'static str,
    bool,
    busbar_contract::abi::mechanism::door::DoorFn,
    &'static str,
);

type LinkedStoreDoor = (
    &'static str,
    bool,
    busbar_contract::abi::sdk::door::MacroDoor,
    &'static str,
);

/// ONE STORE-AXIS ROW as the store crate states it: its `linked::STORE`
/// in either shape, a [`LinkedStore`] or the door-carrying tuple, read as the [`LinkedStore`] the
/// root's install carries. The composition root's generated table wraps every `STORE` in it.
#[derive(Debug, Clone, Copy)]
pub struct StoreRow<T>(pub T);

impl StoreRow<LinkedStore> {
    #[must_use]
    pub const fn linked(self) -> LinkedStore {
        self.0
    }

    /// The names an earlier release answered to: none on this shape, which carries no door
    /// declarations.
    #[must_use]
    pub const fn former_names(self) -> &'static [&'static str] {
        &[]
    }
}

impl StoreRow<LinkedStoreDoor> {
    #[must_use]
    pub const fn linked(self) -> LinkedStore {
        let (key, ephemeral, door, canonical) = self.0;
        (key, ephemeral, door.door_fn(), canonical)
    }

    /// The names an earlier release answered to: the door's `FORMER_NAMES`.
    #[must_use]
    pub const fn former_names(self) -> &'static [&'static str] {
        let (_, _, door, _) = self.0;
        door.former_names()
    }
}

use busbar_contract::plugin_rows::PluginRows;
pub use busbar_kernel_identity::operator::LinkedAuth;

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

pub enum BuildNote<'r> {
    FloorUnreadable(&'r str),

    Off,

    Scanned {
        rows: &'r dyn PluginRows,

        copies: &'r [CopyLine],
    },

    FloorUnwritable(&'r std::io::Error),
}

/// Pure declaration-owned target syntax, followed by the kernel's independent destination policy.
pub type EndpointLocate =
    fn(&Arc<dyn PluginRows>, &str) -> Result<crate::config_validate::ProviderDestination, String>;

pub struct RegistryIn<'a> {
    pub linked: Vec<LinkedRow>,

    pub plugins: Option<&'a config::PluginsCfg>,

    pub data_dir: Option<&'a std::path::Path>,

    pub inventory_only: bool,
}
/// One `plugins.fetch` entry's outcome, as the root's fetch reports it.
#[derive(Clone, PartialEq, Eq)]
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

pub type PluginsFetch = fn(
    &std::path::Path,
    &[config::FetchTarget],
    bool,
    &[String],
) -> Result<Vec<Fetched>, Vec<String>>;

/// WHAT THE COMPOSITION ROOT INSTALLS into the kernel, by name: its linked entries and its registry
/// build — and, as each kind's axis lands, that kind's
/// `<kind>_axis` field. The kernel receives contract `<Kind>Axis` seams from the root, never
/// the loader. A field is added by name; nothing is positional. Nothing
/// installed ([`Default`]): no linked rows, and a build and a fetch that refuse, naming the missing
/// root.
#[derive(Clone, Copy, Default)]
pub struct RootInstall {
    /// The build's linked in-process stores.
    pub stores: &'static [LinkedStore],
    /// The root's registry build.
    pub registry_build: Option<RegistryBuild>,
    /// Resolve a provider target through an admitted transport's pure LOCATE operation.
    /// No instance is opened and no address is resolved or dialled.
    pub endpoint_locate: Option<EndpointLocate>,
    /// The root's `plugins.fetch`.
    pub plugins_fetch: Option<PluginsFetch>,
    /// The root's secret axis: the native secret images it admitted, linked or dropped in, resolved
    /// through custody (WP3 step 2; `None`: no secret image resolves outside a resolver's own source).
    pub secret_axis: Option<&'static dyn busbar_contract::secret::SecretAxis>,
    /// The root's rate holder ([`crate::rate_apply::RateApply`]): what every rate resolution, at
    /// boot and on each apply/reload, is staged with and raised to. `None` = no holder hears an
    /// apply (a build with no root ledger).
    pub rate_apply: Option<&'static dyn crate::rate_apply::RateApply>,
    /// The root's rate dater ([`crate::rate_apply::RateEpoch`]), beside its holder: what a
    /// metering accrual is dated by and the dated history the ledger reads price through. `None` =
    /// every instant dates to the opening entry (`0`) and no era has a history.
    pub rate_epoch: Option<&'static dyn crate::rate_apply::RateEpoch>,
    /// The export axis: every `kind: export` row, opened on the export kind's ABI by the root over
    /// the process's one dispatcher. `None` = no
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
    /// The admitted native hook images' facts (WP3 hook step): what config validation reads of hooks (the names
    /// and aliases a hook image answers to, which are linked, and the D_WORD words they declare). `None` = no hook
    /// image is admitted.
    pub hook_facts: Option<&'static dyn busbar_contract::hook_calls::HookImageFacts>,
    /// Whether a linked auth door's Statement declares an INBOUND auth-chain module.
    /// `None` = no linked row is an auth-chain module.
    pub auth_chain_module: Option<AuthChainModule>,
    /// Whether the process's off-crossing latch has tripped (the plugin dispatch is halted).
    /// `None` = it never trips.
    pub dispatch_latched: Option<fn() -> bool>,
    /// The root's auth-axis opener ([`AuthAxisOpener`]): every build's auth rows, opened on the
    /// process's one dispatcher. `None` = no auth row answers anything.
    pub auth_axis: Option<AuthAxisOpener>,
    /// The `auth.chain` / `identity-providers` modules this build's auth axis answers in process
    /// with no plugin behind them, which the plugin pre-flight therefore does not require in the
    /// plugins directory. `None` = every module but the engine's built-ins is a plugin reference.
    pub in_process_auth: Option<fn(&str) -> bool>,
    /// What the root keeps of each resolved configuration beside the generation built from it
    /// ([`crate::appbuild::ConfigProjection`]), taken by every build. `None` = a generation keeps
    /// no projection.
    pub config_projection: Option<crate::appbuild::ConfigProjection>,
    /// The grammar of the registry a build admits: the same judgement as [`Self::grammar`], over
    /// the registry admission put on the axis, so the grammar pin (BUSBAR-3170) compares the read's
    /// grammar with what was admitted. `None` (or `Ok(None)` for rows that are not the root's
    /// registry): nothing to pin against.
    pub admitted_grammar: Option<AdmittedGrammar>,
}

/// [`RootInstall::admitted_grammar`].
pub type AdmittedGrammar =
    fn(&dyn PluginRows) -> Result<Option<config::Grammar>, config::GrammarRefusal>;

pub type AuthChainModule = fn(busbar_contract::abi::mechanism::door::DoorFn) -> bool;

static ROOT_ROWS: std::sync::RwLock<Option<RootInstall>> = std::sync::RwLock::new(None);

pub fn install_linked_rows(rows: RootInstall) {
    let mut held = ROOT_ROWS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if held.is_none() {
        *held = Some(rows);
    }
}

/// Set the install record to `rows`, replacing any set before. The composition root never calls
/// this: it installs once through [`install_linked_rows`]. A test binary, which has no root,
/// publishes the rows it stands in through it.
#[doc(hidden)]
pub fn publish_root_rows(rows: RootInstall) {
    *ROOT_ROWS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(rows);
}

pub fn root_rows() -> RootInstall {
    let held = *ROOT_ROWS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    held.unwrap_or_else(unset)
}

fn unset() -> RootInstall {
    RootInstall::default()
}

pub use busbar_kernel_identity::operator::{
    install_linked as install_linked_auth, linked as linked_auth_rows,
    linked_names as linked_auth_names,
};

pub use busbar_kernel_identity::operator::{choose as choose_operator, Judged, OperatorBinding};

/// Bind the operator credential for the process lifetime, at process start (OPERATOR-FROM-
/// ADMITTED-AUTH §3.4), and raise its held `auth.operator` rows: one per inert claimant, and the
/// refusal of an ambiguous or unreadable set of claims.
pub fn install_operator(binding: OperatorBinding) {
    if let OperatorBinding::Bound(judged) = &binding {
        audit_judged(judged);
    }
    busbar_kernel_identity::operator::install_operator(binding);
}

/// Bind a `Deferred` start's operator credential from the startup upgrade's own converted
/// `plugins:` view (§3.4.1), once, and raise its held `auth.operator` rows.
pub fn bind_deferred(judged: Judged) -> Result<(), String> {
    audit_judged(&judged);
    busbar_kernel_identity::operator::bind_deferred(judged)
}

fn audit_judged(judged: &Judged) {
    use crate::audit::auditlog::{record_operator, OperatorAudit};
    for claim in &judged.inert {
        record_operator(OperatorAudit::Inert, &claim.provider, &claim.signer);
    }
    if let Err(refusal) = &judged.words {
        let event = match refusal.contains("do not read") {
            true => OperatorAudit::RefusedUnreadable,
            false => OperatorAudit::RefusedAmbiguous,
        };
        record_operator(event, "operator", refusal);
    }
}

#[must_use]
pub fn inbound_auth_names(rows: &[LinkedAuth]) -> Vec<&'static str> {
    let Some(declares) = root_rows().auth_chain_module else {
        return Vec::new();
    };
    rows.iter().filter(|r| declares(r.2)).map(|r| r.0).collect()
}

pub type AuthAxisOpener = fn(Arc<dyn PluginRows>) -> Arc<dyn busbar_contract::auth_calls::AuthAxis>;

pub(crate) fn auth_axis(
    registry: Arc<dyn PluginRows>,
) -> Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>> {
    root_rows().auth_axis.map(|open| open(registry))
}

pub(crate) fn linked_auth_axis() -> Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>> {
    auth_axis(linked().ok()?)
}

static DECLARED_STYLES: std::sync::OnceLock<Vec<busbar_contract::auth_calls::DeclaredStyle>> =
    std::sync::OnceLock::new();

pub fn install_declared_styles(styles: Vec<busbar_contract::auth_calls::DeclaredStyle>) {
    let _ = DECLARED_STYLES.set(styles);
}

#[must_use]
pub fn declared_styles() -> Vec<busbar_contract::auth_calls::DeclaredStyle> {
    if let Some(styles) = DECLARED_STYLES.get() {
        return styles.clone();
    }
    linked_auth_axis()
        .map(|axis| axis.outbound_styles())
        .unwrap_or_default()
}

#[must_use]
pub fn style_flags(word: &str) -> u32 {
    declared_styles()
        .into_iter()
        .find(|s| s.name == word)
        .map_or(0, |s| s.flags)
}

pub fn linked_rows() -> Vec<LinkedRow> {
    let RootInstall { stores, .. } = root_rows();
    let auths = busbar_kernel_identity::operator::linked().iter();
    let rows = stores.iter().copied().map(LinkedRow::Store);
    rows.chain(auths.copied().map(LinkedRow::Auth)).collect()
}

/// The admitted native hook images' facts (WP3 hook step).
fn hook_facts() -> Option<&'static dyn busbar_contract::hook_calls::HookImageFacts> {
    root_rows().hook_facts
}

/// Whether `name` is a ranking strategy: a D_WORD some admitted native hook image declares.
pub(crate) fn builtin_ranking_known(name: &str) -> bool {
    hook_facts().is_some_and(|facts| facts.declares_word(name))
}

/// Every pool ranking strategy is a D_WORD of an admitted native hook image.
pub(crate) fn validate_pool_strategies(cfg: &config::RootCfg) -> Result<(), String> {
    for (pool_name, pool) in &cfg.pools {
        if let Some(name) = pool.policy.native_name() {
            if !builtin_ranking_known(name) {
                return Err(format!(
                    "pool '{pool_name}': ranking strategy '{name}' has no admitted hook plugin"
                ));
            }
        }
    }
    Ok(())
}

/// Whether `module` names a linked native hook image.
pub(crate) fn linked_hook_answers(module: &str) -> bool {
    hook_facts().is_some_and(|facts| facts.linked(module))
}

/// Operator remedy shared by the store refusals.
const STORE_REMEDY: &str =
    "install a signed plugin of kind store and select it with store.module set to its name";

fn store_needs_plugins_error(store_ref: &str, dir: &str) -> String {
    format!(
        "store.module: '{store_ref}' requires the plugin subsystem, but plugins.enabled is \
         false (the default). Set plugins.enabled: true and place the signed \
         '{store_ref}' store plugin tarball in the plugins directory ('{dir}'). The published \
         binary links no store of its own: store.module selects a plugin of kind store by name."
    )
}

struct PluginRef<'a> {
    kind: &'a str,
    names: String,
    matched: String,
    missing: String,
    must_be: &'a str,
    label: &'a str,
    remedy: &'a str,
}

fn missing_plugin_error(
    dir: &str,
    want: PluginRef<'_>,
    loadable: &[busbar_contract::plugin_rows::Row],
) -> String {
    // On the upgrade boot of an unstamped config, a name no installed plugin answers may predate
    // 1.5.5: the refusal carries the one generic upgrade line (MIGRATE-ON-BOOT §A2).
    busbar_contract::upgrade::unknown_module(format!(
        "{} is installed in '{dir}' (plugins ARE enabled; loadable: [{}]). Two things to \
                 check: is the plugin subsystem enabled? (it is) — and is the signed {}tarball \
                 actually IN the folder? \
                 Add it to plugins.fetch or drop the signed tarball in the directory, or {}.",
        want.missing,
        loadable
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        want.label,
        want.remedy
    ))
}

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
            None => missing_plugin_error(dir, want, &registry.loadable()),
        }),
    }
}

pub fn linked() -> Result<Arc<dyn PluginRows>, String> {
    let build = root_rows()
        .registry_build
        .ok_or("no composition root installed the plugin registry build")?;
    build(
        RegistryIn {
            linked: linked_rows(),
            plugins: None,
            data_dir: None,
            inventory_only: false,
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
    let store_ref = store_cfg.map(|g| g.module.clone()).unwrap_or_default();

    let store_is_plugin = store_cfg.is_some() && linked()?.resolve(&store_ref).is_none();

    let in_process = root_rows().in_process_auth.unwrap_or(|_| false);
    let auth_plugin_refs: Vec<&str> = auth_cfg
        .map(|a| {
            a.chain
                .iter()
                .map(|e| e.module.as_str())
                .filter(|m| is_real_auth_plugin_ref(m, in_process))
                .collect()
        })
        .unwrap_or_default();

    let idp_plugin_refs: Vec<(&str, &str)> = identity_providers
        .iter()
        .map(|(name, def)| (name.as_str(), def.module.trim()))
        .filter(|(_, m)| !m.is_empty() && is_real_identity_provider_plugin_ref(m, in_process))
        .collect();
    let idp_refs_human = |refs: &[(&str, &str)]| {
        refs.iter()
            .map(|(n, m)| format!("identity-providers.{n} (module '{m}')"))
            .collect::<Vec<_>>()
            .join(", ")
    };

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

    if store_is_plugin && !plugins_cfg.enabled {
        return Err(store_needs_plugins_error(&store_ref, &plugins_cfg.dir));
    }

    if !auth_plugin_refs.is_empty() && !plugins_cfg.enabled {
        return Err(format!(
            "auth.chain names plugin module(s) [{}], which require the plugin subsystem, but \
             plugins.enabled is false (the default). Set plugins.enabled: true and place the \
             signed auth plugin tarball(s) in the plugins directory ('{}').",
            auth_plugin_refs.join(", "),
            plugins_cfg.dir
        ));
    }

    if has_hook_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "the hooks registry names plugin module(s) [{}], which require the plugin subsystem, \
             but plugins.enabled is false (the default). Set plugins.enabled: true and place the \
             signed `kind: hook` plugin tarball(s) in the plugins directory ('{}').",
            hook_plugin_refs.join(", "),
            plugins_cfg.dir
        ));
    }

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

    plugins_cfg.warn_invalid_floors();

    let build = RegistryIn {
        linked: linked_rows(),
        plugins: Some(plugins_cfg),
        data_dir: None,
        inventory_only: false,
    };
    let registry_build = root_rows()
        .registry_build
        .ok_or("no composition root installed the plugin registry build")?;
    let registry = registry_build(build, &mut |n| log_build(n, &plugins_cfg.dir))?;
    if !plugins_cfg.enabled {
        return Ok(registry);
    }

    let rows: &dyn PluginRows = registry.as_ref();

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
                remedy: STORE_REMEDY,
            },
        )?;
    }

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

    for hook_ref in &hook_plugin_refs {
        if hook_facts().is_some_and(|facts| facts.answers(hook_ref)) {
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
                    None => busbar_contract::upgrade::unknown_module(format!(
                        "identity-providers.{name}.module: no `kind: auth` plugin named or aliased \
                         '{module}' is installed in '{}' (plugins ARE enabled), and it is not a \
                         built-in. The modules a provider may name right now are: {}. Check the \
                         spelling against the plugin's manifest name/alias (see --list-plugins), \
                         add the signed tarball to the plugins directory, or name a built-in.",
                        plugins_cfg.dir,
                        valid_identity_provider_modules(rows)
                    )),
                });
            }
        }
    }

    crate::plugin_routes::build_route_table(crate::export::route_decls(export_cfg))
        .map_err(|e| format!("plugin route registration conflict: {e}"))?;

    Ok(registry)
}

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
            log_scanned_rows(&rows.loadable(), &rows.skipped(), copies, dir);
        }
        BuildNote::FloorUnwritable(e) => diag_warn!(
            PLUGIN_FIRSTPARTY_FLOOR_UNWRITABLE,
            error = %e,
            "could not persist the first-party anti-downgrade floor; it still applies to this \
             process but will not survive a restart"
        ),
    }
}

fn log_scanned_rows(
    loadable: &[busbar_contract::plugin_rows::Row],
    skipped: &[busbar_contract::plugin_rows::Skipped],
    copies: &[CopyLine],
    dir: &str,
) {
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
    for s in skipped {
        diag_warn!(
            PLUGIN_SKIPPED_TRUST_POLICY,
            plugin = %s.name,
            file = %s.file,
            reason = %s.reason,
            "plugin present but NOT loaded (trust policy)"
        );

        crate::audit::auditlog::record_plugin_refusal(
            crate::audit::auditlog::PluginRefusal::Trust,
            "file",
            &s.file,
            s.code,
        );
    }
    for p in loadable {
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
            busbar_contract::plugin_rows::Trust::Allowed { reason, setting } => {
                diag_warn!(
                    PLUGIN_LOADED_UNVERIFIED,
                    plugin = %p.name,
                    alias = %p.alias,
                    kind = %p.kind,
                    reason = %reason,
                    "plugin validated as UNVERIFIED (permitted by an explicit plugins.trust opt-in)"
                );

                crate::audit::auditlog::record_plugin_refusal(
                    crate::audit::auditlog::PluginRefusal::Unverified,
                    "file",
                    &p.file,
                    setting,
                );
            }
        }
    }
}

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

pub(crate) fn resolve_signing_key(
    auth: Option<&config::AuthCfg>,
    resolver: &config::secret::SecretResolver,
) -> Result<Option<governance::signing::TokenSigner>, String> {
    use governance::signing::{TokenSigner, DEFAULT_KID};

    let Some(sk) = auth.and_then(|a| a.signing_key.as_ref()) else {
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
    let secret = parse_signing_secret(bytes.expose(&crate::seal::lend()))?;
    Ok(Some(TokenSigner::from_secret_bytes(&secret, DEFAULT_KID)))
}

pub(crate) fn is_real_auth_plugin_ref(m: &str, in_process: fn(&str) -> bool) -> bool {
    m != config::KEYS_MODULE && !in_process(m)
}

pub(crate) fn is_real_identity_provider_plugin_ref(m: &str, in_process: fn(&str) -> bool) -> bool {
    !config::is_builtin_identity_module(m) && !in_process(m)
}

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

#[cfg(test)]
fn check_secret_module_claim(
    claimed_by: &std::collections::BTreeMap<String, String>,
    canonical: &str,
    module: &str,
) -> Result<(), String> {
    if let Some(previous) = claimed_by.get(canonical) {
        return Err(format!(
            "secrets: the module '{canonical}' is configured TWICE — once as '{previous}' and \
                 once as '{module}' (an alias and its canonical name resolve to the same plugin). \
                 One of the two blocks would be silently dropped; keep exactly one."
        ));
    }
    Ok(())
}

/// THE SECRET PLUGINS A RESOLVER OPENED, one SOURCE per plugin (audit kernel-K1 #6).
///
/// The map's lock is held only to find or insert a source, never across an open or a resolve: one
/// slow or hung secret source (a remote vault) stalls only the resolutions it answers, never
/// another module's, and never a second caller of its own that already holds the handle. Two first
/// resolutions racing to open one module may both open; the loser's instance is dropped (closed)
/// outside the lock.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct OpenedSecrets(std::sync::Mutex<std::collections::BTreeMap<String, Arc<Source>>>);

/// ONE OPENED SECRET SOURCE: the instance every resolution through it clones (lock-free), swapped
/// whole when a re-lend opens a successor. An instance opened with its own lent references is
/// polled by the host refresher every [`RELEND_EVERY`] ± 10 %: a rotated credential (a
/// workload-identity token file) reaches the plugin's `refresh`, or a successor instance, with no
/// reload; a refusal keeps the running instance (BUSBAR-8028).
#[cfg(test)]
pub(crate) struct Source {
    key: String,
    calls: arc_swap::ArcSwap<Arc<dyn busbar_contract::secret::SecretCalls>>,
    relending: std::sync::Mutex<RelendStreak>,
    report: &'static dyn crate::refresh::Report,
}

/// How often a source's own references are re-read.
pub(crate) const RELEND_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// A re-lend poll's rate limit, per source or auth instance.
#[derive(Default)]
pub(crate) struct RelendStreak {
    failures: u32,
    reported: Option<std::time::Instant>,
}

impl RelendStreak {
    /// Report BUSBAR-8028 for a re-lend `refused` on the instance `label`: the first failure, then
    /// at most once a minute; audited `plugin.credential.rotate` degraded alongside.
    pub(crate) fn failed(
        &mut self,
        report: &dyn crate::refresh::Report,
        label: &str,
        refused: &busbar_contract::secret::RelendRefused,
        now: std::time::Instant,
    ) {
        use busbar_contract::secret::RelendCause;
        self.failures = self.failures.saturating_add(1);
        let due = self.reported.is_none_or(|at| {
            now.saturating_duration_since(at) >= std::time::Duration::from_secs(60)
        });
        if !due || crate::refresh::stopping() {
            return;
        }
        self.reported = Some(now);
        let level = match refused.cause {
            RelendCause::Unresolvable => tracing::Level::WARN,
            RelendCause::Refused | RelendCause::ReopenFailed => tracing::Level::ERROR,
        };
        report.diag(
            &crate::diagnostics::PLUGIN_CREDENTIAL_ROTATION_FAILED,
            level,
            "a plugin instance's own credential changed and could not be applied: the running \
             instance and what it holds are kept, and the change is retried on the next poll",
            &[
                ("instance", label.to_string()),
                ("cause", refused.cause.as_str().to_string()),
                ("error", refused.text.clone()),
                ("failures", self.failures.to_string()),
            ],
        );
        report.audit(
            RELEND_ACTION,
            &format!("plugin:{label}"),
            crate::audit_ring::OUTCOME_DEGRADED,
        );
    }

    /// The rotated credential was applied (`how`: refreshed in place or re-opened).
    pub(crate) fn applied(&mut self, report: &dyn crate::refresh::Report, label: &str, how: &str) {
        report.info(
            "a plugin instance took its rotated credential",
            &[
                ("instance", label.to_string()),
                ("applied", how.to_string()),
                ("failures", self.failures.to_string()),
            ],
        );
        report.audit(
            RELEND_ACTION,
            &format!("plugin:{label}"),
            crate::audit_ring::OUTCOME_APPLIED,
        );
        *self = Self::default();
    }
}

/// The audit action a re-lend writes.
pub(crate) const RELEND_ACTION: &str = "plugin.credential.rotate";

#[cfg(test)]
impl Source {
    fn new(
        key: &str,
        calls: Arc<dyn busbar_contract::secret::SecretCalls>,
        report: &'static dyn crate::refresh::Report,
    ) -> Self {
        Self {
            key: key.to_string(),
            calls: arc_swap::ArcSwap::from_pointee(calls),
            relending: std::sync::Mutex::new(RelendStreak::default()),
            report,
        }
    }

    /// The instance a resolution uses now.
    pub(crate) fn calls(&self) -> Arc<dyn busbar_contract::secret::SecretCalls> {
        Arc::clone(&self.calls.load())
    }

    /// One re-lend poll at `now`: re-read this source's own references and apply a change.
    pub(crate) fn relend_now(&self, now: std::time::Instant) {
        use busbar_contract::secret::SecretRelent;
        let Ok(mut streak) = self.relending.try_lock() else {
            return;
        };
        let current = self.calls();
        let linked = config::secret::SecretResolver::builtins_only();
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let relent = current.relend(&|r| linked.resolve_at_config(r, &scope));
        if crate::refresh::stopping() {
            return;
        }
        let label = format!("secrets.{}", self.key);
        match relent {
            Ok(SecretRelent::Unchanged) => {}
            Ok(SecretRelent::Refreshed) => streak.applied(self.report, &label, "refreshed"),
            Ok(SecretRelent::Reopened(successor)) => {
                self.calls.store(Arc::new(successor));
                streak.applied(self.report, &label, "reopened");
            }
            Err(refused) => streak.failed(self.report, &label, &refused, now),
        }
    }
}

#[cfg(test)]
impl crate::refresh::Refreshable for Source {
    fn refresh(&self, now: std::time::Instant) -> std::time::Instant {
        self.relend_now(now);
        now + crate::retry::spread(RELEND_EVERY, 0.1, crate::retry::unit())
    }
}

#[cfg(test)]
impl OpenedSecrets {
    fn calls(
        &self,
        key: &str,
        open: impl FnOnce() -> Result<Arc<dyn busbar_contract::secret::SecretCalls>, String>,
    ) -> Result<Arc<dyn busbar_contract::secret::SecretCalls>, String> {
        if let Some(source) = self.source(key) {
            return Ok(source.calls());
        }
        let opened = open()?;
        let (calls, lost) = {
            let mut sources = self.0.lock().unwrap_or_else(|e| e.into_inner());
            match sources.get(key) {
                Some(source) => (source.calls(), Some(opened)),
                None => {
                    let source = Arc::new(Source::new(
                        key,
                        Arc::clone(&opened),
                        &crate::refresh::HOST_REPORT,
                    ));
                    if opened.relends() {
                        crate::refresh::keep(
                            Arc::downgrade(&source)
                                as std::sync::Weak<dyn crate::refresh::Refreshable>,
                            std::time::Instant::now()
                                + crate::retry::spread(RELEND_EVERY, 0.1, crate::retry::unit()),
                        );
                    }
                    sources.insert(key.to_string(), source);
                    (opened, None)
                }
            }
        };
        drop(lost);
        Ok(calls)
    }

    /// The source opened for `key`, if one is.
    pub(crate) fn source(&self, key: &str) -> Option<Arc<Source>> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }

    pub(crate) fn resolve(
        &self,
        key: &str,
        settings: &busbar_contract::plugin_settings::Settings,
        scope: Option<&busbar_contract::config_time::ConfigScope>,
        open: impl FnOnce() -> Result<Arc<dyn busbar_contract::secret::SecretCalls>, String>,
    ) -> Result<config::secret::Held, config::secret::SecretRefused> {
        let calls = self
            .calls(key, open)
            .map_err(|text| config::secret::SecretRefused {
                error_kind: busbar_contract::abi::secret::ERROR_KIND_INTERNAL,
                text,
            })?;

        let encoded = settings
            .encode()
            .map_err(|_| config::secret::SecretRefused {
                error_kind: busbar_contract::abi::secret::ERROR_KIND_INVALID,
                text: "source settings could not be encoded".into(),
            })?;
        let seal = crate::seal::lend();
        let encoded = encoded.expose(&seal);
        match scope {
            Some(scope) => calls.resolve_at_config(encoded, scope),
            None => calls.resolve(encoded),
        }
    }
}

pub fn plugin_fetch_admits(url: &str, blocked: &[String]) -> Result<bool, String> {
    let https = config_validate::scheme_is(url, "https");
    if !https {
        let host_local = config_validate::extract_normalized_host(url)
            .as_deref()
            .map(config_validate::host_is_private_or_loopback)
            .unwrap_or(false);
        if !(config_validate::scheme_is(url, http::uri::Scheme::HTTP.as_str()) && host_local) {
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
#[path = "tests/secret_sources_tests.rs"]
mod secret_sources_tests;

#[cfg(test)]
#[path = "tests/store_row_tests.rs"]
mod store_row_tests;

#[cfg(test)]
#[path = "tests/plugin_refusal_tests.rs"]
mod plugin_refusal_tests;

#[cfg(test)]
#[path = "tests/central2_secret_claim_tests.rs"]
mod central2_secret_claim_tests;

#[cfg(test)]
#[path = "tests/central2_boot_log_tests.rs"]
mod central2_boot_log_tests;

#[cfg(test)]
#[path = "tests/central2_missing_plugin_tests.rs"]
mod central2_missing_plugin_tests;

impl std::fmt::Debug for Fetched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cached { filename } => f
                .debug_struct("Cached")
                .field("filename", filename)
                .finish(),
            Self::Fetched { filename } => f
                .debug_struct("Fetched")
                .field("filename", filename)
                .finish(),
            Self::Warned { url: _, error } => f
                .debug_struct("Warned")
                .field("url", &"<redacted>")
                .field("error", error)
                .finish(),
        }
    }
}
