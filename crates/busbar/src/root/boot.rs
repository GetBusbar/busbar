// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use super::linked::{linked_exports, Linked};
use super::loader::{
    boot::*, dispatch::LoadError, dispatch::ManifestFacts, LinkedPlugin, PluginRegistry,
};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::plugin_rows::PluginRows;
use busbar_kernel::config::{FetchTarget, PluginsCfg};
use busbar_kernel::config_validate::deal::{Document, Seat};
use busbar_kernel::preflight::{BuildNote, CopyLine, Fetched, LinkedRow, RegistryIn};

/// A host-owned pairing of the admitted archive and the exact retained library allocation.
/// Weak ownership follows the caller's generation without keeping retired images alive forever.
#[derive(Clone)]
struct NativeImage {
    bytes: std::sync::Weak<Vec<u8>>,
    row: busbar_contract::plugin_rows::Row,
    archive: String,
    release_keys_version: Option<u64>,
    plugins: Arc<PluginsCfg>,
    floor: Option<Arc<busbar_kernel::persistence::plugin_floor::AdmissionProof>>,
}

static NATIVE_IMAGES: std::sync::Mutex<Vec<NativeImage>> = std::sync::Mutex::new(Vec::new());

fn remember_native_images(registry: &PluginRegistry, plugins: &PluginsCfg) {
    let plugins = Arc::new(plugins.clone());
    let fresh: Vec<_> = registry
        .loadable()
        .iter()
        .filter(|image| !image.linked())
        .filter_map(|image| {
            Some(NativeImage {
                bytes: Arc::downgrade(&image.lib_bytes),
                row: PluginRows::resolve(registry, &image.manifest.name)?,
                archive: image.archive_sha256.clone()?,
                release_keys_version: image.release_keys_version(),
                plugins: Arc::clone(&plugins),
                floor: None,
            })
        })
        .collect();
    let mut remembered = NATIVE_IMAGES.lock().unwrap_or_else(|p| p.into_inner());
    remembered.retain(|image| image.bytes.strong_count() != 0);
    remembered.extend(fresh);
}

pub fn install_native_load_guard() -> Result<(), &'static str> {
    super::loader::install_native_load_guard(authorize_native_image)
}

fn authorize_native_image(bytes: &[u8], display: &str) -> Result<(), String> {
    let snapshots = NATIVE_IMAGES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let image = snapshots.into_iter().find_map(|image| {
        let held = image.bytes.upgrade()?;
        (held.as_ptr() == bytes.as_ptr() && held.len() == bytes.len()).then_some((image, held))
    });
    let (image, _held) = image.ok_or_else(|| {
        format!("native plugin '{display}' has no retained admitted archive proof")
    })?;
    if let Some(authority) = PLUGIN_FLOOR.get() {
        super::durability::check_prepared_plugin_floor_candidate(
            image
                .floor
                .as_deref()
                .ok_or("native image lacks completed Store floor admission")?,
            &authority.host,
            &image.row,
            image.release_keys_version,
            &image.plugins.first_party_floors,
            &image.archive,
        )
    } else {
        busbar_kernel::appbuild::validate_bootstrap_archive(
            &image.row.name,
            &image.row.file,
            Some(&image.archive),
            &image.plugins,
        )
    }
}

/// Retained admission owner. Hydration and routing begin only after this has
/// confirmed the logical format and registered this process's writer.
pub async fn admit_store(
    backend: busbar_contract::persistence::axis::OpenedBackend,
) -> Result<busbar_kernel::persistence::startup::Startup, String> {
    admit_format(backend, true).await
}

/// Only the native prepared session may supply a checkpoint-bound recovery backend.
/// A recovery target must already contain the confirmed current-format manifest.
pub async fn admit_prepared_store(
    prepared: &busbar_migrations::RecoveryPending,
) -> Result<busbar_kernel::persistence::startup::Startup, String> {
    if let Some(recovery) = &prepared.recovery {
        if recovery.upgrade != prepared.upgrade_id
            || recovery.target != prepared.backend.info().dataset
            || recovery.activation_receipt_digest == [0; 32]
            || recovery.selector_digest == [0; 32]
        {
            return Err("native cold recovery binding does not match its prepared target".into());
        }
    }
    admit_format(prepared.backend.clone(), prepared.recovery.is_none()).await
}

async fn admit_format(
    backend: busbar_contract::persistence::axis::OpenedBackend,
    initialize_empty: bool,
) -> Result<busbar_kernel::persistence::startup::Startup, String> {
    use busbar_kernel::persistence::{
        facade::Limits,
        startup::{Progress, Startup},
    };
    let mut startup = Startup::new(
        backend,
        Limits {
            pending_operations: 4096,
            conflict_retries: 16,
            scan_items: 4096,
            // Include framing above the existing 16-MiB OAuth logical cell.
            scan_bytes: 32 * 1024 * 1024,
        },
        // The configured adapter may initialize only a proven wholly empty
        // dataset. An existing legacy or incomplete dataset is never relabelled.
        initialize_empty,
    )
    .map_err(|error| format!("Store format admission refused: {error:?}"))?;
    loop {
        match startup
            .advance()
            .await
            .map_err(|error| format!("Store format admission refused: {error:?}"))?
        {
            Progress::Advanced => {}
            Progress::Admitted => return Ok(startup),
            Progress::Pending => {
                // The same Startup owns the original candidate throughout uncertainty.
                // Advancing it reconciles that candidate; it never allocates a replacement.
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Progress::Reconcile => {
                return Err(
                    "Store admission has an unresolved original operation; serving remains closed"
                        .into(),
                );
            }
            Progress::Draining | Progress::Retired => {
                return Err("Store admission entered an invalid boot state".into());
            }
        }
    }
}

struct PluginFloorAuthority {
    owner: busbar_kernel::persistence::plugin_floor::PluginFloor,
    host: String,
    release_keys: std::sync::atomic::AtomicU64,
}

static PLUGIN_FLOOR: std::sync::OnceLock<PluginFloorAuthority> = std::sync::OnceLock::new();

pub async fn bind_plugin_floor(
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
) -> Result<(), String> {
    let owner = busbar_kernel::persistence::plugin_floor::PluginFloor::new(core)?;
    let host = super::durability::host_identity();
    let release_keys = owner.release_keys_floor(&host).await?;
    PLUGIN_FLOOR
        .set(PluginFloorAuthority {
            owner,
            host,
            release_keys: std::sync::atomic::AtomicU64::new(release_keys),
        })
        .map_err(|_| "the plugin floor Store is already bound".to_string())
}

async fn hold_plugin_floor(rows: &dyn PluginRows, plugins: &PluginsCfg) -> Result<(), String> {
    if let Some(authority) = PLUGIN_FLOOR.get() {
        super::durability::hold_plugin_floor(
            &authority.owner,
            &authority.host,
            rows,
            &plugins.first_party_floors,
        )
        .await?;
        let floor = authority.owner.release_keys_floor(&authority.host).await?;
        authority
            .release_keys
            .fetch_max(floor, std::sync::atomic::Ordering::AcqRel);
        // Each native image receives an exact archive-bound admission observation.
        // The synchronous dlopen guard checks this proof; it performs no Store I/O.
        if let Some(registry) = super::loader::rows::registry_of(rows) {
            let mut prepared = Vec::new();
            for image in registry.loadable().iter().filter(|image| !image.linked()) {
                let row = PluginRows::resolve(registry, &image.manifest.name)
                    .ok_or("admitted native image lost its registry row")?;
                let archive = image
                    .archive_sha256
                    .clone()
                    .ok_or("native image lacks archive digest")?;
                let proof = super::durability::prepare_plugin_floor_candidate(
                    &authority.owner,
                    &authority.host,
                    &row,
                    image.release_keys_version(),
                    &plugins.first_party_floors,
                    &archive,
                )
                .await?;
                prepared.push(NativeImage {
                    bytes: Arc::downgrade(&image.lib_bytes),
                    row,
                    archive,
                    release_keys_version: image.release_keys_version(),
                    plugins: Arc::new(plugins.clone()),
                    floor: Some(Arc::new(proof)),
                });
            }
            let mut images = NATIVE_IMAGES.lock().unwrap_or_else(|p| p.into_inner());
            for image in prepared {
                images.retain(|old| !old.bytes.ptr_eq(&image.bytes));
                images.push(image);
            }
        }
    }
    Ok(())
}

pub async fn admit_recovered_plugins(plugins: &PluginsCfg) -> Result<(), String> {
    if let Some(registry) = REGISTRY.get() {
        hold_plugin_floor(registry, plugins).await?;
    }
    Ok(())
}

pub fn registry(
    linked: Vec<LinkedPlugin>,
    plugins: Option<&PluginsCfg>,
    _data_dir: Option<&std::path::Path>,
    note: &mut dyn FnMut(Note<'_>),
) -> Result<PluginRegistry, String> {
    registry_with_floor(linked, plugins, true, note)
}

fn registry_with_floor(
    linked: Vec<LinkedPlugin>,
    plugins: Option<&PluginsCfg>,
    _check_floor: bool,
    note: &mut dyn FnMut(Note<'_>),
) -> Result<PluginRegistry, String> {
    let scan = match plugins {
        None => None,
        Some(p) => Some(Scan {
            policy: trust_policy(p, env!("CARGO_PKG_VERSION"))
                .map_err(|e| format!("plugins.trust is invalid: {e}"))?,

            data_dir: None,
            dir: p.enabled.then_some(std::path::Path::new(&p.dir)),
        }),
    };
    let registry = super::loader::boot::registry(Build { linked, scan }, note)?;
    if let Some(plugins) = plugins {
        remember_native_images(&registry, plugins);
    }

    super::linked::secret_rows().judge_dropped(discovered(&registry, |kind| kind == "secret")?)?;
    Ok(registry)
}

pub fn admit_secrets<'a>(
    rows: &'a Arc<dyn PluginRows>,
    plugins: &'a PluginsCfg,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        hold_plugin_floor(rows.as_ref(), plugins).await?;
        match super::loader::rows::registry_arc(Arc::clone(rows)) {
            Some(registry) => admit_dropped_secrets(&registry),
            None => Ok(()),
        }
    })
}

pub fn admit_dropped_secrets(registry: &PluginRegistry) -> Result<(), String> {
    super::linked::secret_rows().admit_dropped(discovered(registry, |kind| kind == "secret")?)
}

pub fn registry_rows(
    i: RegistryIn<'_>,
    note: &mut dyn FnMut(BuildNote<'_>),
) -> Result<Arc<dyn PluginRows>, String> {
    let mut linked: Vec<_> = i.linked.iter().map(linked_row).collect();
    linked.extend(linked_exports(crate::LINKED.export_doors)?);
    let registry = registry_with_floor(linked, i.plugins, !i.inventory_only, &mut |n| match n {
        Note::FloorUnreadable(detail) => note(BuildNote::FloorUnreadable(detail)),
        Note::Off => note(BuildNote::Off),
        Note::Scanned(scanned) => {
            let copies: Vec<CopyLine> = scanned
                .linked_copies()
                .iter()
                .map(|c| CopyLine {
                    name: c.name.clone(),
                    version: c.version.clone(),
                    file: c.file.clone(),
                    line: c.line(),
                })
                .collect();
            note(BuildNote::Scanned {
                rows: scanned,
                copies: &copies,
            });
        }
        Note::FloorUnwritable(e) => note(BuildNote::FloorUnwritable(e)),
    })?;
    Ok(Arc::new(registry))
}

#[must_use]
pub fn linked_row(row: &LinkedRow) -> LinkedPlugin {
    match *row {
        LinkedRow::Store((key, ephemeral, door, canonical)) => {
            LinkedPlugin::store_named(canonical, key, door, ephemeral)
        }
        LinkedRow::Auth((key, canonical, door)) => {
            LinkedPlugin::auth_door_named(canonical, key, door)
        }
    }
}

#[must_use]
pub fn linked_registry() -> PluginRegistry {
    let mut linked: Vec<_> = busbar_kernel::preflight::linked_rows()
        .iter()
        .map(linked_row)
        .collect();
    linked.extend(
        linked_exports(crate::LINKED.export_doors)
            .expect("the build's linked export declarations must be valid"),
    );
    PluginRegistry::empty()
        .link(linked)
        .expect("the build's linked plugin declarations must not conflict")
}

pub fn trust_policy(
    cfg: &PluginsCfg,
    binary_version: &str,
) -> Result<super::loader::sign::TrustPolicy, String> {
    let mut policy =
        super::loader::sign::TrustPolicy::from_config(super::loader::sign::TrustInput {
            publishers: &cfg.publisher_keys(),
            allow_unsigned: cfg.trust.allow_unsigned,
            allow_third_party: cfg.trust.allow_third_party,
            min_versions: &cfg.min_versions,
            first_party_floors: &cfg.first_party_floors,
            binary_version,
        })?;
    if let Some(authority) = PLUGIN_FLOOR.get() {
        policy.release_keys_floor = authority
            .release_keys
            .load(std::sync::atomic::Ordering::Acquire);
    }
    #[cfg(feature = "test-harness")]
    if let Some(key) =
        harness_first_party_key(std::env::var(HARNESS_FIRST_PARTY_KEY_ENV).ok().as_deref())?
    {
        policy.first_party_key = Some(key);
        policy.first_party_keys = vec![super::loader::sign::FirstPartyKey::unnamed(key)];
    }
    Ok(policy)
}

#[cfg(feature = "test-harness")]
pub const HARNESS_FIRST_PARTY_KEY_ENV: &str = "BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY";

#[cfg(feature = "test-harness")]
pub fn harness_first_party_key(
    raw: Option<&str>,
) -> Result<Option<super::loader::sign::VerifyingKey>, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(hex_key) => super::loader::sign::public_key_from_hex(hex_key)
            .map(Some)
            .map_err(|e| format!("{HARNESS_FIRST_PARTY_KEY_ENV} is not a usable key: {e}")),
    }
}

pub fn plugins_fetch(
    dir: &std::path::Path,
    targets: &[FetchTarget],
    fatal_on_miss: bool,
    blocked: &[String],
) -> Result<Vec<Fetched>, Vec<String>> {
    let download = super::plugin_fetch::downloader(blocked);
    let specs: Vec<super::loader::FetchSpec> = targets
        .iter()
        .map(|t| super::loader::FetchSpec {
            url: t.url.clone(),
            sha256: t.sha256.clone(),
            filename: t.filename.clone(),
        })
        .collect();
    let outcomes = super::loader::fetch_plugins(dir, &specs, fatal_on_miss, &download)?;
    Ok(outcomes
        .into_iter()
        .map(|o| match o {
            super::loader::FetchOutcome::Cached { filename } => Fetched::Cached { filename },
            super::loader::FetchOutcome::Fetched { filename } => Fetched::Fetched { filename },
            super::loader::FetchOutcome::Warned { url, error } => Fetched::Warned { url, error },
        })
        .collect())
}

fn config_path() -> std::path::PathBuf {
    std::path::PathBuf::from(crate::root::cli::resolve_config_path(
        crate::root::cli::config_path_flag().as_deref(),
    ))
}

pub fn plan(path: &std::path::Path) -> Uses {
    document(path)
        .map(|doc| Uses::of(doc.value()))
        .unwrap_or_default()
}

pub fn document(path: &std::path::Path) -> Option<Document> {
    let raw = std::fs::read_to_string(path).ok()?;
    let text = busbar_kernel::config::interpolate_env_with(
        &raw,
        busbar_kernel::config::EnvSubst::Lenient,
        &mut Vec::new(),
    )
    .ok()?;
    Document::parse(text).ok()
}

pub fn validate_dealt<'s>(
    doc: &Document,
    seats: impl IntoIterator<Item = (&'s str, Seat<'s>)>,
    mut validate: impl FnMut(&'s str, &[u8]) -> Result<(), String>,
) -> Result<(), String> {
    for (instance, seat) in seats {
        let Some(section) = doc.deal(seat)? else {
            continue;
        };
        let seal = busbar_kernel::seal::lend();
        validate(instance, section.settings.expose(&seal)).map_err(|reason| {
            format!(
                "config.yaml: invalid YAML: {}",
                doc.refuse(&section, &reason)
            )
        })?;
    }
    Ok(())
}

fn validate_door(door: &DoorPlane, settings: &[u8]) -> Result<(), String> {
    use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_JSON};
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, ValidateIn};
    use busbar_contract::abi::sdk::door::{blank_in, blank_out};
    let mut err = [0_u8; 1024];
    let mut i: ValidateIn = blank_in();
    i.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    i.err_buf = err.as_mut_ptr();
    i.err_cap = err.len();
    let mut f = super::loader::dispatch::Frame::new(i, blank_out::<OutHead>());
    let called = door.call(life::VALIDATE, &mut f);
    if called.outcome == Outcome::Ready {
        return Ok(());
    }
    Err(called.error.map_or_else(
        || format!("{:?}", called.outcome),
        |e| String::from_utf8_lossy(&e).into_owned(),
    ))
}

pub fn discover(registry: &PluginRegistry) -> Result<Vec<Candidate>, String> {
    discovered(registry, |_| true)
}

pub fn listener_candidates(linked: &Linked) -> Result<Vec<Candidate>, String> {
    listener_candidates_from(linked, dropped_registry())
}

fn listener_candidates_from(
    linked: &Linked,
    registry: Option<&PluginRegistry>,
) -> Result<Vec<Candidate>, String> {
    let mut candidates = registry.map(discover).transpose()?.unwrap_or_default();

    candidates.retain(|candidate| !matches!(candidate.kind, KindCode::Plane | KindCode::Export));
    candidates.extend(
        dropped_registry()
            .map(|registry| discovered(registry, |kind| matches!(kind, "plane" | "export")))
            .transpose()?
            .unwrap_or_default(),
    );
    for door in linked.plane_doors.iter().chain(linked.hook_doors) {
        let candidate = Candidate::linked(*door)?;
        if !candidates
            .iter()
            .any(|c| c.kind == candidate.kind && c.name == candidate.name)
        {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

/// A declared inbound need and the physical listener on which it is served.
#[derive(Debug, Clone, PartialEq)]
pub struct ListenerNeed {
    /// The selected instance name; planes use their canonical door name.
    pub instance: String,
    /// The canonical declaring module, retained for boot-dispatch provenance.
    pub module: String,
    /// The declaring kind.
    pub kind: KindCode,
    /// The index in the Statement's needs.
    pub need: u32,
    /// The selected framing scheme.
    pub transport: String,
    /// The declared default authentication style, used only without an operator chain.
    pub auth: String,
    /// The physical bind's setting name.
    pub at: String,
}

/// Physical binds and the declarations assigned to them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ListenerNeeds {
    /// An operator supplied the root data bind or its TLS policy.
    pub root_required: bool,
    /// Root binds followed by additional plugin binds.
    pub binds: Vec<InboundBind>,
    /// Assignments, including needs sharing the root data bind.
    pub needs: Vec<ListenerNeed>,
}

pub fn configured_listener_needs(
    cfg: &busbar_kernel::config::RootCfg,
    sections: &std::collections::BTreeMap<&'static str, serde_yaml::Value>,
) -> Result<ListenerNeeds, String> {
    let mut listeners = listener_projection(
        listener_candidates(&crate::LINKED)?,
        &cfg.hooks,
        &cfg.export_defs,
        sections,
        configured_root_binds(cfg)?,
    )?;
    listeners.root_required = cfg.listen_explicit
        || cfg.listen != busbar_kernel::config::DEFAULT_LISTEN_ADDR
        || cfg.tls.is_some();
    Ok(listeners)
}

pub fn configured_root_binds(
    cfg: &busbar_kernel::config::RootCfg,
) -> Result<Vec<InboundBind>, String> {
    let authoring_seal = busbar_kernel::seal::acquire();
    let doc = serde_json::json!({"tls": serde_json::to_value(cfg.tls.as_ref().map(|tls| tls.authoring(&authoring_seal))).map_err(|e| e.to_string())?,
        "admin_tls": serde_json::to_value(cfg.admin_tls.as_ref().map(|tls| tls.authoring(&authoring_seal))).map_err(|e| e.to_string())?});
    let binds = root_binds(
        &doc,
        &RootListens {
            listen: &cfg.listen,
            admin_listen: &cfg.admin_listen,
        },
    )?;
    for (setting, addr) in [("listen", &cfg.listen), ("admin_listen", &cfg.admin_listen)] {
        if !binds.iter().any(|bind| bind.at == setting) {
            return Err(format!(
                "cannot bind listen address '{addr}': it resolves to no socket address"
            ));
        }
    }
    Ok(binds)
}

pub fn candidate_listener_needs(
    app: &busbar_kernel::state::App,
    sections: &std::collections::BTreeMap<&'static str, serde_yaml::Value>,
    root: Vec<InboundBind>,
) -> Option<Result<ListenerNeeds, String>> {
    let registry = super::loader::rows::registry_of(app.hook_env.registry.as_ref())?;
    Some(
        listener_candidates_from(&crate::LINKED, Some(registry)).and_then(|candidates| {
            listener_projection(
                candidates,
                &app.hook_registry,
                &app.export_defs,
                sections,
                root,
            )
        }),
    )
}

fn listener_projection(
    candidates: Vec<Candidate>,
    hooks: &std::collections::HashMap<String, busbar_kernel::config::HookCfg>,
    exports: &busbar_kernel::config::ExportDefs,
    sections: &std::collections::BTreeMap<&'static str, serde_yaml::Value>,
    root: Vec<InboundBind>,
) -> Result<ListenerNeeds, String> {
    let mut uses = Uses::default();
    uses.roots.extend(sections.keys().map(|s| (*s).to_string()));
    uses.modules.extend(
        hooks
            .iter()
            .map(|(name, hook)| (KindCode::Hook, name.clone(), hook.plugin.clone())),
    );
    uses.modules.extend(
        exports
            .iter()
            .map(|(name, export)| (KindCode::Export, name.clone(), export.module.clone())),
    );
    let selected = select(&uses, &candidates);
    listener_needs_from(
        &candidates,
        &selected,
        root,
        false,
        |candidate, instance| {
            let (settings, base) = match candidate.kind {
                KindCode::Plane => {
                    let settings = sections
                        .get(instance)
                        .map(|source| {
                            serde::Deserialize::deserialize(source.clone())
                                .map_err(|_| format!("{instance}: settings must be an object"))
                        })
                        .transpose()?
                        .unwrap_or_default();
                    (settings, instance.to_owned())
                }
                KindCode::Hook => (
                    hooks
                        .get(instance)
                        .map(|hook| hook.settings.clone())
                        .unwrap_or_default(),
                    format!("hooks.{instance}.settings"),
                ),
                KindCode::Export => (
                    exports
                        .get(instance)
                        .map(|export| export.settings.clone())
                        .unwrap_or_default(),
                    format!("export.{instance}.settings"),
                ),
                _ => return Err(format!("{instance}: unsupported inbound kind")),
            };
            Ok((settings, base))
        },
    )
}

pub fn listener_needs(
    doc: &serde_json::Value,
    candidates: &[Candidate],
    selected: &[Selected],
    root: Vec<InboundBind>,
) -> Result<ListenerNeeds, String> {
    listener_needs_from(
        candidates,
        selected,
        root,
        doc.get("listen").is_some() || doc.get("tls").is_some_and(|v| !v.is_null()),
        |candidate, instance| {
            Ok(listener_settings(doc, candidate.kind, instance)?
                .unwrap_or_else(|| (Default::default(), instance.to_owned())))
        },
    )
}

fn listener_needs_from(
    candidates: &[Candidate],
    selected: &[Selected],
    root: Vec<InboundBind>,
    root_required: bool,
    mut settings: impl FnMut(
        &Candidate,
        &str,
    )
        -> Result<(busbar_contract::plugin_settings::Settings, String), String>,
) -> Result<ListenerNeeds, String> {
    use busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
    let seal = busbar_kernel::seal::acquire();
    let mut binds = root;
    let mut shared = Vec::new();
    for selection in selected {
        let candidate = candidates
            .get(selection.candidate)
            .ok_or_else(|| format!("{}: no such candidate", selection.instance))?;
        if !candidate
            .needs
            .iter()
            .any(|need| need.direction == DIRECTION_INBOUND)
        {
            continue;
        }
        if !matches!(
            candidate.kind,
            KindCode::Plane | KindCode::Hook | KindCode::Export
        ) {
            return Err(format!(
                "{}: {:?} inbound needs have no SERVE consumer",
                selection.instance, candidate.kind
            ));
        }
        let (settings, base) = settings(candidate, &selection.instance)?;
        let claims = busbar_contract::conn::inbound::admit(&seal, &settings, &candidate.needs)
            .map_err(|why| format!("{base}.{why}"))?;
        for claim in claims {
            let declared = &candidate.needs[claim.need as usize];
            let instance = if candidate.kind == KindCode::Plane {
                &candidate.name
            } else {
                &selection.instance
            };
            let at = if let Some(binding) = claim.binding {
                let bind = InboundBind {
                    owner: BindOwner::Need {
                        instance: instance.clone(),
                        kind: candidate.kind,
                        need: claim.need,
                    },
                    transport: declared.transport.clone(),
                    at: format!("{base}.{}", claim.path),
                    listen: binding.listen,
                    tls: binding.tls,
                    max_conns: binding.max_conns,
                };
                let collision = binds.iter().find(|old| {
                    bind.listen.port() != 0
                        && old.listen.port() == bind.listen.port()
                        && (old.listen.ip() == bind.listen.ip()
                            || old.listen.ip().is_unspecified()
                            || bind.listen.ip().is_unspecified())
                });
                if let Some(old) = collision {
                    if old.at == "admin_listen"
                        || old.listen != bind.listen
                        || (old.owner != BindOwner::Root || binding.tls_explicit)
                            && old.tls != bind.tls
                        || (old.owner != BindOwner::Root || binding.max_conns_explicit)
                            && old.max_conns != bind.max_conns
                    {
                        return Err(format!("{}: inbound declaration is incompatible with physical listener {}; configure a different listen address or matching TLS and connection limits", bind.at, old.at));
                    }
                    old.at.clone()
                } else {
                    let at = bind.at.clone();
                    binds.push(bind);
                    at
                }
            } else {
                let inherits = declared.target_from == "listen"
                    || candidate.kind == KindCode::Plane && declared.target_from == "ingress";
                if !inherits {
                    return Err(format!(
                        "{base}.{}: not set; an inbound listener needs `listen`",
                        claim.path
                    ));
                }
                binds
                    .iter()
                    .find(|bind| bind.owner == BindOwner::Root && bind.at == "listen")
                    .ok_or_else(|| {
                        format!(
                            "{}: inbound need {} names an unavailable root listen bind",
                            selection.instance, claim.need
                        )
                    })?
                    .at
                    .clone()
            };
            shared.push(ListenerNeed {
                module: candidate.name.clone(),
                instance: instance.clone(),
                kind: candidate.kind,
                need: claim.need,
                transport: declared.transport.clone(),
                auth: declared.auth.clone(),
                at,
            });
        }
    }
    Ok(ListenerNeeds {
        root_required,
        binds,
        needs: shared,
    })
}

fn discovered(
    registry: &PluginRegistry,
    keep: impl Fn(&str) -> bool,
) -> Result<Vec<Candidate>, String> {
    let mut out = Vec::new();
    for row in registry
        .loadable()
        .iter()
        .filter(|r| keep(&r.manifest.kind))
    {
        out.extend(row.candidate()?);
    }
    Ok(out)
}

pub struct Stages {
    pub candidates: Vec<Candidate>,

    pub selected: Vec<Selected>,

    pub inbound: Vec<InboundBind>,
}

impl Stages {
    pub fn lines(&self) -> Vec<String> {
        self.candidates
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let used: Vec<&str> = self
                    .selected
                    .iter()
                    .filter(|s| s.candidate == i)
                    .map(|s| s.instance.as_str())
                    .collect();
                let abi = ManifestFacts::read(&c.stated).map_or(0, |f| f.kind_abi);
                let status = if used.is_empty() {
                    "not used by this config".to_string()
                } else {
                    format!("selected as {}", used.join(", "))
                };
                format!(
                    "    plugin: {} ({}, ABI {abi}) — {status}",
                    c.name,
                    kind_word(c.kind)
                )
            })
            .chain(
                self.inbound
                    .iter()
                    .filter(|b| b.owner != BindOwner::Root)
                    .map(|b| {
                        let tls = if b.tls.is_some() { "tls" } else { "clear" };
                        format!(
                            "    listens: {} on {} over {} ({tls}, at most {} connections)",
                            b.at, b.listen, b.transport, b.max_conns
                        )
                    }),
            )
            .collect()
    }
}

fn kind_word(k: KindCode) -> String {
    format!("{k:?}").to_ascii_lowercase()
}

pub fn validate(
    path: &std::path::Path,
    registry: &PluginRegistry,
    root: &RootListens<'_>,
    root_required: bool,
) -> Result<Stages, String> {
    let doc = document(path)
        .map(|d| d.value().clone())
        .unwrap_or_default();
    let root_required = root_required
        || doc.get("listen").is_some()
        || doc.get("tls").is_some_and(|v| !v.is_null())
        || root.listen != busbar_kernel::config::DEFAULT_LISTEN_ADDR;
    let binds = root_binds(&doc, root)?;
    for (slot, address) in [("listen", root.listen), ("admin_listen", root.admin_listen)] {
        if !binds.iter().any(|bind| bind.at == slot) {
            return Err(format!(
                "cannot bind listen address '{address}': it resolves to no socket address"
            ));
        }
    }
    let mut stages = stages(&doc, discover(registry)?, binds)?;
    resolve_validation_listeners(
        &mut stages,
        registry,
        &transport_uses_for(path, &[]),
        root_required,
    )?;
    Ok(stages)
}

/// Resolve validation's physical binds from declarations without calling lifecycle OPEN.
fn resolve_validation_listeners(
    stages: &mut Stages,
    registry: &PluginRegistry,
    uses: &Uses,
    root_required: bool,
) -> Result<(), String> {
    use super::loader::dispatch::{
        kinds::transport::{self, TransportFacts},
        Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
    };
    let mut facts = crate::LINKED_TRANSPORT_DOORS
        .iter()
        .map(|(_, door)| transport::linked_facts(*door))
        .collect::<Result<Vec<_>, _>>()?;
    let dispatcher = Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    );
    let bind = Bind {
        instance: Arc::from("configuration-listeners"),
        max_inflight_cap: 1,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::NoNeeds,
    };
    let declared = registry.open_transport_entries(&bind, uses, plugin_logs())?;
    for plugin in &declared.doors {
        facts.push(
            plugin
                .context::<TransportFacts>()
                .cloned()
                .ok_or("listener transport has no validated declaration")?,
        );
    }
    let accepting: Vec<_> = facts
        .iter()
        .filter(|facts| facts.role == busbar_contract::abi::transport::ROLE_FRAMER && facts.accepts)
        .collect();
    let data_required = stages.selected.iter().any(|selection| {
        stages.candidates[selection.candidate]
            .needs
            .iter()
            .any(|need| {
                need.direction == busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND
            })
    });
    if !root_required && !data_required && accepting.is_empty() {
        stages.inbound.retain(|bind| bind.at != "listen");
    } else {
        let claim = busbar_contract::abi::transport::listener_bindings::resolve(
            "listen",
            accepting.iter().flat_map(|facts| &facts.listener_bindings),
        )?;
        if !accepting
            .iter()
            .any(|facts| facts.claims.contains(&claim.as_str()) && !facts.datagram)
        {
            return Err("listen: its declared claim requires an accepting stream framer".into());
        }
        for bind in &mut stages.inbound {
            if bind.owner == BindOwner::Root && bind.at == "listen" {
                bind.transport.clone_from(&claim);
            }
        }
    }
    for bind in stages
        .inbound
        .iter()
        .filter(|bind| bind.at != "admin_listen")
    {
        let count = accepting
            .iter()
            .filter(|facts| facts.claims.contains(&bind.transport.as_str()))
            .count();
        if count != 1 {
            return Err(format!(
                "{}: expected one accepting framer for {}, found {count}",
                bind.at, bind.transport
            ));
        }
    }
    Ok(())
}

/// The addresses the host's own listeners take, as the resolved configuration states them.
#[derive(Debug, Clone, Copy)]
pub struct RootListens<'a> {
    /// The data door (`listen`).
    pub listen: &'a str,
    /// The admin surface (`admin_listen`).
    pub admin_listen: &'a str,
}

pub fn root_binds(
    doc: &serde_json::Value,
    root: &RootListens<'_>,
) -> Result<Vec<InboundBind>, String> {
    [
        ("listen", root.listen, "tls"),
        ("admin_listen", root.admin_listen, "admin_tls"),
    ]
    .into_iter()
    .map(|(setting, addr, tls)| {
        Ok(InboundBind {
            owner: BindOwner::Root,
            transport: String::new(),
            at: setting.to_string(),
            listen: addr
                .parse()
                .ok()
                .or_else(|| std::net::ToSocketAddrs::to_socket_addrs(addr).ok()?.next())
                .ok_or_else(|| {
                    format!("cannot bind listen address '{addr}': it resolves to no socket address")
                })?,
            tls: doc
                .get(tls)
                .filter(|v| !v.is_null())
                .map(serde::Deserialize::deserialize)
                .transpose()
                .map_err(|_| format!("{tls}: invalid TLS configuration"))?,
            max_conns: u64::MAX,
        })
    })
    .collect()
}

pub fn stages(
    doc: &serde_json::Value,
    candidates: Vec<Candidate>,
    root: Vec<InboundBind>,
) -> Result<Stages, String> {
    let uses = Uses::of(doc);
    let selected = select(&uses, &candidates);
    let inbound = listener_needs(doc, &candidates, &selected, root)?.binds;
    for s in &selected {
        let c = &candidates[s.candidate];
        let facts =
            ManifestFacts::read(&c.stated).map_err(|e| format!("plugin '{}': {e}", c.name))?;
        let host = facts.kind.abi_version();
        let refusal =
            if facts.mechanism_version != busbar_contract::abi::mechanism::MECHANISM_VERSION {
                Some(LoadError::ManifestMechanism {
                    stated: facts.mechanism_version,
                    host: busbar_contract::abi::mechanism::MECHANISM_VERSION,
                })
            } else if facts.kind_abi != host {
                Some(LoadError::ManifestKindAbi {
                    stated: facts.kind_abi,
                    host,
                })
            } else {
                None
            };
        if let Some(r) = refusal {
            return Err(format!("plugin '{}' ({}): {r}", c.name, s.instance));
        }
    }
    Ok(Stages {
        candidates,
        selected,
        inbound,
    })
}

pub fn dropped_from_config(
    linked: &Linked,
) -> Option<&'static crate::root::loader::PluginRegistry> {
    let rows = linked_exports(linked.export_doors).unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    });
    let scanned = scan_configured();
    if scanned.is_none() && rows.is_empty() {
        return None;
    }
    let registry = scanned.unwrap_or_else(crate::root::loader::PluginRegistry::empty);
    let registry = registry.link(rows).unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    });

    Some(REGISTRY.get_or_init(|| registry))
}

pub(crate) static REGISTRY: std::sync::OnceLock<crate::root::loader::PluginRegistry> =
    std::sync::OnceLock::new();

static BASE_BOOTSTRAP_PLUGINS: std::sync::OnceLock<PluginsCfg> = std::sync::OnceLock::new();

pub(crate) fn authorize_early_plugin(name: &str) -> Result<(), String> {
    let registry = REGISTRY
        .get()
        .ok_or("the early plugin inventory is not initialized")?;
    let base = BASE_BOOTSTRAP_PLUGINS
        .get()
        .ok_or("the operator's base bootstrap archive pins are not initialized")?;
    busbar_kernel::appbuild::validate_bootstrap_artifacts(
        registry,
        &std::collections::BTreeSet::from([name.to_string()]),
        base,
    )
}

pub fn dropped_registry() -> Option<&'static crate::root::loader::PluginRegistry> {
    REGISTRY.get()
}

fn scan_configured() -> Option<crate::root::loader::PluginRegistry> {
    let path =
        crate::root::cli::resolve_config_path(crate::root::cli::config_path_flag().as_deref());
    let raw = std::fs::read_to_string(path).ok()?;
    let text = busbar_kernel::config::interpolate_env_with(
        &raw,
        busbar_kernel::config::EnvSubst::Lenient,
        &mut Vec::new(),
    )
    .ok()?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    let plugins =
        serde_yaml::from_value::<busbar_kernel::config::PluginsCfg>(doc.get("plugins")?.clone())
            .ok()
            .filter(|p| p.enabled)?;
    let l = &plugins.logs;
    let words = (l.dir.as_deref(), l.level.as_deref(), &l.levels);
    if let Ok(logs) = crate::root::loader::dispatch::PluginLogConfig::from_words(
        words.0,
        words.1,
        words.2,
        l.rotate_mb,
        l.keep,
    ) {
        let _ = LOGS.set(logs);
    }
    plugins.warn_invalid_floors();
    let data_dir = busbar_kernel::preflight::fleet_data_dir();
    let registry =
        crate::root::boot::registry(Vec::new(), Some(&plugins), data_dir.as_deref(), &mut |_| {})
            .ok()?;
    admit_dropped_secrets(&registry).ok()?;
    let _ = BASE_BOOTSTRAP_PLUGINS.set(plugins);
    Some(registry)
}

pub fn discover_planes(linked: &Linked, dropped: Option<&crate::root::loader::PluginRegistry>) {
    let set = match dropped {
        Some(registry) => registry.open_planes(linked.plane_doors),
        None => crate::root::loader::PluginRegistry::empty().open_planes(linked.plane_doors),
    };
    let set = set.unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    });
    let _ = DOOR_CANDIDATES.set(set.doors);
}

#[must_use]
pub fn unbound_sections() -> Vec<&'static str> {
    let bound = door_planes();
    DOOR_CANDIDATES
        .get()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|c| !bound.iter().any(|(instance, _)| *instance == c.name))
        .filter_map(|c| c.verbs.first())
        .filter_map(|section| {
            busbar_kernel::plane_driver::registry::plane_decl_for_config_section(section)
        })
        .filter(|decl| !decl.fallback)
        .map(|decl| decl.config_section)
        .collect()
}

static PROVIDER_URLS: std::sync::RwLock<Vec<String>> = std::sync::RwLock::new(Vec::new());

pub fn note_provider_urls(urls: impl IntoIterator<Item = String>) {
    let next = urls.into_iter().collect();
    let previous = std::mem::replace(
        &mut *PROVIDER_URLS.write().unwrap_or_else(|p| p.into_inner()),
        next,
    );
    drop(previous);
}

fn transport_uses() -> Uses {
    let urls = PROVIDER_URLS
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    transport_uses_for(&config_path(), &urls)
}

pub(crate) fn transport_uses_for(path: &std::path::Path, urls: &[String]) -> Uses {
    let mut uses = plan(path).reaching(urls.iter().map(String::as_str));
    uses.schemes.extend(
        crate::LINKED_TRANSPORT_DOORS
            .iter()
            .filter_map(|(_, door)| Candidate::linked(*door).ok())
            .flat_map(|c| c.schemes),
    );
    uses
}

pub fn check_bootstrap_transports(plugins: &PluginsCfg) -> Result<(), String> {
    let Some(registry) = REGISTRY.get() else {
        return Ok(());
    };
    let uses = transport_uses();
    let mut selected = std::collections::BTreeSet::new();
    for row in registry
        .loadable()
        .iter()
        .filter(|row| row.manifest.kind == "transport")
    {
        if row
            .candidate()?
            .is_some_and(|candidate| candidate.serves(&uses))
        {
            selected.insert(row.manifest.name.clone());
        }
    }
    busbar_kernel::appbuild::validate_bootstrap_artifacts(registry, &selected, plugins)
}

pub(crate) static DOOR_CANDIDATES: std::sync::OnceLock<Vec<crate::root::loader::boot::Candidate>> =
    std::sync::OnceLock::new();

static DOOR_PLANES: std::sync::OnceLock<Vec<(String, DoorPlane)>> = std::sync::OnceLock::new();

pub type DoorPlane = std::sync::Arc<
    crate::root::loader::dispatch::Plugin<crate::root::loader::dispatch::kinds::plane::Plane>,
>;

pub fn load_door_planes<'s>(sections: impl IntoIterator<Item = &'s str>) {
    let doors = DOOR_CANDIDATES.get().map_or(&[][..], Vec::as_slice);
    let uses = Uses {
        roots: sections.into_iter().map(str::to_string).collect(),
        ..Uses::default()
    };
    let used = crate::root::loader::boot::used_planes(&uses, doors);

    let conns: std::sync::Arc<dyn busbar_contract::conn::DeclaredConns> =
        crate::root::connector::the().clone();
    let bound = crate::root::loader::boot::load_planes(
        &used,
        plugin_logs(),
        std::sync::Arc::new(crate::root::loader::dispatch::NoSink),
        crate::root::dispatch::dispatcher().adopter(),
        u32::MAX,
        crate::root::loader::dispatch::ConnTable::Host(crate::root::connector::admit(conns)),
    )
    .unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    })
    .into_iter()
    .map(|(instance, plane)| (instance, std::sync::Arc::new(plane)))
    .collect::<Vec<(String, DoorPlane)>>();

    let path =
        crate::root::cli::resolve_config_path(crate::root::cli::config_path_flag().as_deref());
    if let Some(doc) = document(std::path::Path::new(&path)) {
        let seats = doors.iter().map(|c| {
            (
                c.name.as_str(),
                Seat::of(kind_of(c.kind), &c.verbs, &c.name),
            )
        });
        let refused = validate_dealt(&doc, seats, |instance, settings| {
            bound
                .iter()
                .find(|(name, _)| name == instance)
                .map_or(Ok(()), |(_, door)| validate_door(door, settings))
        });
        if let Err(refusal) = refused {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
    let _ = DOOR_PLANES.set(bound);
}

static LOGS: std::sync::OnceLock<crate::root::loader::dispatch::PluginLogConfig> =
    std::sync::OnceLock::new();

pub(crate) fn plugin_logs() -> &'static crate::root::loader::dispatch::PluginLogConfig {
    LOGS.get_or_init(|| {
        let none = Default::default();
        crate::root::loader::dispatch::PluginLogConfig::from_words(None, None, &none, None, None)
            .expect("the plugins.logs defaults resolve")
    })
}

pub(crate) fn follow_plugin_logs(
    logs: &crate::root::loader::dispatch::PluginLogConfig,
    plugins: &busbar_kernel::config::PluginsCfg,
) {
    let l = &plugins.logs;
    match crate::root::loader::dispatch::PluginLogConfig::from_words(
        l.dir.as_deref(),
        l.level.as_deref(),
        &l.levels,
        l.rotate_mb,
        l.keep,
    ) {
        Ok(next) => logs.reconfigure(&next),
        Err(e) => tracing::warn!(error = %e, "plugins.logs kept its words across a config apply"),
    }
}

pub fn door_planes() -> &'static [(String, DoorPlane)] {
    DOOR_PLANES.get().map_or(&[], Vec::as_slice)
}

pub fn dropped_transports(
    settings: &busbar_contract::transport::TransportSettings,
) -> crate::root::registry::Dropped {
    if let Some(opened) = WIRES.lock().unwrap_or_else(|p| p.into_inner()).clone() {
        return opened;
    }
    let opened = open_dropped_transports(settings).unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    });
    let retained = {
        let mut wires = WIRES.lock().unwrap_or_else(|p| p.into_inner());
        wires.get_or_insert_with(|| opened.clone()).clone()
    };

    drop(opened);
    retained
}

static WIRES: std::sync::Mutex<Option<crate::root::registry::Dropped>> =
    std::sync::Mutex::new(None);

pub(crate) fn open_dropped_transports(
    settings: &busbar_contract::transport::TransportSettings,
) -> Result<crate::root::registry::Dropped, String> {
    let doors = match REGISTRY.get() {
        None => Vec::new(),
        Some(registry) => registry
            .open_transport_entries(&crate::root::doors::bind(), &transport_uses(), plugin_logs())
            .and_then(|entries| {
                entries
                    .doors
                    .into_iter()
                    .map(|plugin| {
                        let facts = plugin
                            .context::<crate::root::loader::dispatch::kinds::transport::TransportFacts>()
                            .cloned()
                            .ok_or_else(|| format!("`{}` states no transport tail", plugin.name()))?;
                        let key = facts.claims.first().copied().unwrap_or_default();
                        let claims = facts.claims;
                        let composes_over = facts.composes_over;
                        let offered = facts.offered;
                        let upgrades = facts.upgrades;
                        let (door, wire) = crate::root::doors::served(plugin, settings)?;
                        Ok(crate::root::registry::DroppedDoor {
                            key,
                            claims,
                            composes_over,
                            offered,
                            upgrades,
                            wire,
                            door,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()
            })?,
    };
    Ok(crate::root::registry::Dropped {
        doors: std::borrow::Cow::Owned(doors),
    })
}

pub(crate) fn publish_dropped_transports(dropped: crate::root::registry::Dropped) {
    publish_transport_inventory(&WIRES, dropped);
}

fn publish_transport_inventory(
    wires: &std::sync::Mutex<Option<crate::root::registry::Dropped>>,
    dropped: crate::root::registry::Dropped,
) {
    let previous = wires
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .replace(dropped);
    drop(previous);
}

#[cfg(test)]
pub async fn compose_book(
    journal: Arc<busbar_kernel::persistence::journal::RuntimeJournal>,
    identity: &busbar_kernel::persistence::boot_identity::BootIdentity,
    node: u64,
    now: u64,
    token: &busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
) -> Result<super::durability::Durability, String> {
    let mut durability = super::durability::build_on_store(
        &super::durability::DurabilityConfig::default(),
        node,
        journal,
        Some(&crate::root::kernel::ROOT_CARD),
        journal_history_budget(),
    )
    .await
    .map_err(|e| format!("the native boot journal could not be opened: {e}"))?;
    bind_boot_keyset(&mut durability, identity, token, now).await?;
    Ok(durability)
}

fn journal_history_budget() -> busbar_kernel::persistence::journal::BufferBudget {
    busbar_kernel::persistence::journal::BufferBudget {
        records: 1_048_576,
        bytes: 512 * 1024 * 1024,
    }
}

pub type NodeLeaseTask = tokio::task::JoinHandle<Result<(), String>>;
pub type WatchedBook = (super::durability::NodeBook, Option<NodeLeaseTask>);

/// Construction retains the actual owners before every asynchronous crossing.
/// A pending native original suspends this same preparation; it never restarts
/// node allocation, global price binding, or application construction.
pub struct BookPreparation {
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
    governance: Arc<busbar_kernel::governance::GovState>,
    identity: Arc<busbar_kernel::persistence::boot_identity::BootIdentity>,
    taken: Option<busbar_kernel::persistence::boot_identity::TakenNode>,
    journal: Option<Arc<busbar_kernel::persistence::journal::RuntimeJournal>>,
    durability: Option<super::durability::Durability>,
    shared: Option<Arc<std::sync::Mutex<super::durability::Durability>>>,
    token: Option<busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>>,
    phase: BookPhase,
    lease_watch: Option<LeaseWatch>,
    node_lease_task: Option<NodeLeaseTask>,
    node_lease: Option<Arc<busbar_kernel::persistence::boot_identity::NodeLease>>,
}
struct LeaseWatch {
    stop: tokio::sync::watch::Receiver<bool>,
    failure: tokio::sync::watch::Sender<bool>,
}
impl Drop for BookPreparation {
    fn drop(&mut self) {
        if let Some(task) = &self.node_lease_task {
            task.abort();
        }
    }
}
#[derive(Debug, Clone, Copy)]
enum BookPhase {
    AllocateNode,
    OpenJournal,
    BindPrices,
    BuildDurability,
    BootPrices,
    BindKeyset,
    RestoreAmendments,
    AttachRecovery,
    Hydrate,
    Ready,
}
/// A terminal refusal owns the interrupted preparation for explicit disposal.
/// Dropping a displayed error is not permission to construct a replacement book.
pub struct BookFailure {
    reason: String,
    _preparation: Option<Box<BookPreparation>>,
}
impl BookFailure {
    pub fn reason(&self) -> &str {
        &self.reason
    }
    fn unstarted(reason: String) -> Self {
        Self {
            reason,
            _preparation: None,
        }
    }
}
impl std::fmt::Display for BookFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::fmt::Debug for BookFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BookFailure")
            .field("reason", &self.reason)
            .field("phase", &self._preparation.as_ref().map(|p| p.phase))
            .finish_non_exhaustive()
    }
}
impl std::error::Error for BookFailure {}
impl BookPreparation {
    fn new(app: &busbar_kernel::state::App) -> Result<Self, String> {
        let governance = app
            .governance
            .clone()
            .ok_or("the boot book requires admitted core persistence")?;
        let core = governance
            .core_store_handle()
            .map_err(|error| error.to_string())?;
        let identity =
            Arc::new(busbar_kernel::persistence::boot_identity::BootIdentity::new(core.clone())?);
        Ok(Self {
            core,
            governance,
            identity,
            taken: None,
            journal: None,
            durability: None,
            shared: None,
            token: Some(super::kernel::new_kernel().durability_token()),
            phase: BookPhase::AllocateNode,
            lease_watch: None,
            node_lease_task: None,
            node_lease: None,
        })
    }
    async fn finish(
        mut self,
        app: &busbar_kernel::state::App,
        store: &str,
    ) -> Result<WatchedBook, BookFailure> {
        let result = if let Some(mut stop) =
            self.lease_watch.as_ref().map(|watch| watch.stop.clone())
        {
            tokio::select! {
                biased;
                _ = stop.wait_for(|stopping| *stopping) => Err("startup stopped during boot book preparation".to_owned()),
                result = super::measurements::maintenance(self.run(app, store)) => result,
            }
        } else {
            super::measurements::maintenance(self.run(app, store)).await
        };
        match result {
            Ok(book) => Ok((book, self.node_lease_task.take())),
            Err(reason) => {
                if let Some(task) = &self.node_lease_task {
                    task.abort();
                }
                Err(BookFailure {
                    reason,
                    _preparation: Some(Box::new(self)),
                })
            }
        }
    }
    async fn run(
        &mut self,
        app: &busbar_kernel::state::App,
        store: &str,
    ) -> Result<super::durability::NodeBook, String> {
        use busbar_kernel::persistence::journal::{BufferBudget, RuntimeJournal};
        let host = super::durability::host_identity();
        self.taken = Some(super::durability::take_node(&self.identity, &host).await?);
        self.node_lease = self.taken.as_mut().unwrap().lease.take().map(Arc::new);
        if self.lease_watch.is_some() && self.node_lease.is_none() {
            return Err("the admitted startup node has no writer lease".into());
        }
        // Recovery may wait for foreign writers' leases. Renew our actual writer
        // before any journal, keyset, price or recovery await can outlast its lease.
        if let (Some(watch), Some(lease)) = (&self.lease_watch, self.node_lease.clone()) {
            self.node_lease_task = Some(tokio::spawn(super::measurements::maintenance(
                crate::refresh_node_lease(lease, watch.stop.clone(), watch.failure.clone()),
            )));
        }
        let node = self.taken.as_ref().expect("retained node result").id;
        self.phase = BookPhase::OpenJournal;
        self.journal = Some(
            RuntimeJournal::open(
                self.core.clone(),
                node,
                BufferBudget {
                    records: 65_536,
                    bytes: 64 * 1024 * 1024,
                },
            )
            .await
            .map_err(|error| format!("native journal admission refused: {error:?}"))?,
        );
        self.phase = BookPhase::BindPrices;
        super::kernel::ROOT_CARD.keep_in_store(self.core.clone(), node)?;
        self.phase = BookPhase::BuildDurability;
        self.durability = Some(
            super::durability::build_on_store(
                &super::durability::DurabilityConfig::default(),
                node,
                self.journal.as_ref().unwrap().clone(),
                None,
                journal_history_budget(),
            )
            .await
            .map_err(|error| format!("the native boot journal could not be opened: {error}"))?,
        );
        self.phase = BookPhase::BootPrices;
        super::kernel::ROOT_CARD.boot_bound_store().await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.phase = BookPhase::BindKeyset;
        bind_boot_keyset(
            self.durability.as_mut().unwrap(),
            &self.identity,
            self.token.as_ref().unwrap(),
            now,
        )
        .await?;
        self.phase = BookPhase::RestoreAmendments;
        let durability = self.durability.as_mut().unwrap();
        durability
            .restore_amendments(&app.amendments, self.token.as_ref().unwrap())
            .await?;
        super::durability::report_operator_breaks(durability).await;
        if let Some(material) = durability
            .record
            .derived_secret(super::keyset::CALLER_REF_MATERIAL)
        {
            self.governance.bind_deployment_caller_ref(material);
        }
        self.shared = Some(Arc::new(std::sync::Mutex::new(
            self.durability.take().unwrap(),
        )));
        let journal = self.journal.as_ref().unwrap().clone();
        let shared = self.shared.as_ref().unwrap();
        self.phase = BookPhase::AttachRecovery;
        self.governance
            .attach_recovery_sink(
                super::durability::usage_recovery_sink(journal.clone())
                    .map_err(|error| error.to_string())?,
            )
            .await
            .map_err(|error| format!("usage recovery: {error}"))?;
        self.governance
            .attach_unit_checkpoint_sink(
                super::durability::unit_checkpoint_sink(shared, journal.clone())
                    .map_err(|error| error.to_string())?,
            )
            .await
            .map_err(|error| format!("unit checkpoint recovery: {error}"))?;
        self.phase = BookPhase::Hydrate;
        self.governance
            .hydrate_budgets_async(&app.cost, now)
            .await
            .map_err(|error| format!("budget hydration: {error}"))?;
        if let Err(error) = self.governance.resume_correction_verdicts(&app.cost).await {
            tracing::warn!(%error,"usage correction remains retained for continuation");
        }
        super::durability::bind_amendments(shared, &app.amendments).await?;
        super::measurements::install(app)?;
        let token = self.token.take().unwrap();
        let verb_store = super::durability::node_verb_store(shared.clone(), token, store);
        self.phase = BookPhase::Ready;
        Ok(super::durability::NodeBook {
            durability: self.shared.take().unwrap(),
            runtime_journal: self.journal.take().unwrap(),
            node_lease: self.node_lease.take(),
            verb_store,
        })
    }
}
async fn bind_boot_keyset(
    durability: &mut super::durability::Durability,
    identity: &busbar_kernel::persistence::boot_identity::BootIdentity,
    token: &busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
    now: u64,
) -> Result<(), String> {
    loop {
        match super::keyset::bind(
            durability,
            identity,
            token,
            busbar_contract::caps::StepName::Meter,
            now,
        )
        .await
        {
            Ok(_) => return Ok(()),
            Err(super::keyset::KeysetError::PendingOriginal { .. }) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}
pub async fn book(
    app: &busbar_kernel::state::App,
    store: &str,
) -> Result<super::durability::NodeBook, BookFailure> {
    BookPreparation::new(app)
        .map_err(BookFailure::unstarted)?
        .finish(app, store)
        .await
        .map(|(book, _)| book)
}

/// Start the existing lease watcher before boot recovery, then transfer that
/// exact task alongside the book into the retained serving candidate.
pub async fn book_with_lease_watch(
    app: &busbar_kernel::state::App,
    store: &str,
    stop: tokio::sync::watch::Receiver<bool>,
    failure: tokio::sync::watch::Sender<bool>,
) -> Result<WatchedBook, BookFailure> {
    let mut preparation = BookPreparation::new(app).map_err(BookFailure::unstarted)?;
    preparation.lease_watch = Some(LeaseWatch { stop, failure });
    preparation.finish(app, store).await
}

#[cfg(test)]
#[path = "tests/boot.rs"]
mod tests;

#[cfg(test)]
include!(concat!(env!("OUT_DIR"), "/context_test_sources.rs"));
#[cfg(test)]
owner_test_sources!(transport_inventory);

#[cfg(all(test, unix, linked_every_plane_door, feature = "test-harness"))]
#[path = "tests/bootstrap_pins.rs"]
mod bootstrap_pin_tests;

/// Select the exact admitted transport claim and run its pre-open, pure LOCATE operation.
/// This path uses an isolated dispatcher with no connection needs and never opens an instance.
pub fn locate_provider_destination(
    rows: &Arc<dyn PluginRows>,
    target: &str,
) -> Result<busbar_kernel::config_validate::ProviderDestination, String> {
    locate_provider_destination_with(rows, target, crate::LINKED_TRANSPORT_DOORS)
}

fn locate_provider_destination_with(
    rows: &Arc<dyn PluginRows>,
    target: &str,
    linked: &[(&str, busbar_contract::abi::mechanism::door::DoorFn)],
) -> Result<busbar_kernel::config_validate::ProviderDestination, String> {
    use crate::root::loader::dispatch::{
        kinds::transport::{Transport, TransportFacts},
        load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    let claim = target
        .split_once("://")
        .map(|(s, _)| s)
        .filter(|s| {
            s.starts_with(|c: char| c.is_ascii_alphabetic())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        })
        .ok_or("endpoint must name an absolute registered transport claim")?
        .to_ascii_lowercase();
    let on = Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    );
    let bind = Bind {
        instance: Arc::from("configuration-locate"),
        max_inflight_cap: 1,
        sink: Arc::new(NoSink),
        dispatcher: on.adopter(),
        conns: ConnTable::NoNeeds,
    };
    let mut selected = Vec::new();
    for (_, door) in linked {
        let facts = crate::root::loader::dispatch::kinds::transport::linked_facts(*door)?;
        if facts.claims.iter().any(|c| *c == claim) {
            let row = LinkedRow::of(*door).map_err(|e| e.to_string())?;
            selected.push(load_linked::<Transport>(&row, bind.clone()).map_err(|e| e.to_string())?);
        }
    }
    let registry = rows
        .as_any()
        .downcast_ref::<PluginRegistry>()
        .ok_or("configuration registry cannot supply transport declarations")?;
    let uses = Uses::default().reaching([target]);
    // Loading/binding checks the signed declaration; it does not call lifecycle OPEN or READY.
    let logs = crate::root::loader::dispatch::PluginLogConfig::from_words(
        None,
        None,
        &std::collections::BTreeMap::new(),
        None,
        None,
    )?;
    selected.extend(
        registry
            .open_transport_entries(&bind, &uses, &logs)?
            .doors
            .into_iter()
            .filter(|p| {
                p.context::<TransportFacts>()
                    .is_some_and(|f| f.claims.iter().any(|c| *c == claim))
            }),
    );
    let plugin = match selected.as_slice() {
        [] => return Err(format!("no admitted transport claims '{claim}'")),
        [plugin] => plugin,
        _ => {
            return Err(format!(
                "multiple admitted transports claim '{claim}': {}",
                selected
                    .iter()
                    .map(|p| p.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    };
    let facts = plugin
        .context::<TransportFacts>()
        .ok_or("transport declaration disappeared")?;
    let located = if facts.role == busbar_contract::abi::transport::ROLE_CARRIER && facts.ported {
        // A network carrier is carried as itself at runtime too: its declared claim names an
        // authority, and the connector never invents connection security for that authority.
        busbar_core_connector::compose::carried_at(&claim, target).map_err(|e| e.to_string())?
    } else {
        crate::root::doors::locate_bound(plugin, target)?
    };
    Ok(busbar_kernel::config_validate::ProviderDestination {
        authority: located.authority,
        secure: located.secure,
        name: located.name,
    })
}

/// Resolve only compiled core schemas or the attested instance's exact historical
/// raw-record framing. An unscoped unknown schema is never guessed into a namespace.
pub fn bootstrap_witness(
    instance: &str,
    schema: &str,
    key: &[u8],
    value: &[u8],
) -> Result<busbar_contract::persistence::Address, &'static str> {
    use busbar_migrations::legacy::archive::{route_record, Binding, Route, Scope};
    let bindings = [Binding {
        schema,
        instance,
        private: false,
        source_scope: Scope::Instance,
    }];
    match route_record(schema, key, value, &bindings)
        .map_err(|_| "unsupported or ambiguous bootstrap witness binding")?
    {
        Route::Record {
            address,
            value: mapped,
        } if mapped == value => Ok(address),
        _ => Err("bootstrap witness requires an explicit supported exact-record binding"),
    }
}
