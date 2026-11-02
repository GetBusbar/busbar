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
        super::durability::check_plugin_floor_candidate(
            authority.calls.as_ref(),
            &authority.host,
            &image.row,
            image.release_keys_version,
            &image.plugins.first_party_floors,
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

struct PluginFloorAuthority {
    calls: Arc<dyn busbar_contract::store_calls::StoreCalls>,
    host: String,
}

static PLUGIN_FLOOR: std::sync::OnceLock<PluginFloorAuthority> = std::sync::OnceLock::new();

pub fn bind_plugin_floor(
    calls: Arc<dyn busbar_contract::store_calls::StoreCalls>,
) -> Result<(), String> {
    PLUGIN_FLOOR
        .set(PluginFloorAuthority {
            calls,
            host: super::durability::host_identity(),
        })
        .map_err(|_| "the plugin floor Store is already bound".to_string())
}

fn check_plugin_floor(rows: &dyn PluginRows, plugins: &PluginsCfg) -> Result<(), String> {
    if let Some(authority) = PLUGIN_FLOOR.get() {
        super::durability::check_plugin_floor(
            authority.calls.as_ref(),
            &authority.host,
            rows,
            &plugins.first_party_floors,
        )?;
    }
    Ok(())
}

fn hold_plugin_floor(rows: &dyn PluginRows, plugins: &PluginsCfg) -> Result<(), String> {
    if let Some(authority) = PLUGIN_FLOOR.get() {
        super::durability::hold_plugin_floor(
            authority.calls.as_ref(),
            &authority.host,
            rows,
            &plugins.first_party_floors,
        )?;
    }
    Ok(())
}

pub fn admit_recovered_plugins(plugins: &PluginsCfg) -> Result<(), String> {
    if let Some(registry) = REGISTRY.get() {
        hold_plugin_floor(registry, plugins)?;
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
    check_floor: bool,
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

    if check_floor {
        if let Some(plugins) = plugins {
            check_plugin_floor(&registry, plugins)?;
        }
    }

    super::linked::secret_rows().judge_dropped(discovered(&registry, |kind| kind == "secret")?)?;
    Ok(registry)
}

pub fn admit_secrets(rows: &Arc<dyn PluginRows>, plugins: &PluginsCfg) -> Result<(), String> {
    hold_plugin_floor(rows.as_ref(), plugins)?;
    match super::loader::rows::registry_arc(Arc::clone(rows)) {
        Some(registry) => admit_dropped_secrets(&registry),
        None => Ok(()),
    }
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
            answering_former_names(LinkedPlugin::store_named(canonical, key, door, ephemeral))
        }
        LinkedRow::Auth((key, canonical, door)) => {
            answering_former_names(LinkedPlugin::auth_door_named(canonical, key, door))
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

#[must_use]
pub fn answering_former_names(row: LinkedPlugin) -> LinkedPlugin {
    let former = busbar_kernel::config::migration_table::former_names(&row.manifest.alias);
    row.with_former_names(former)
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
        policy.release_keys_floor =
            super::durability::release_keys_floor(authority.calls.as_ref(), &authority.host)?;
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
        let Some(section) = doc.deal(seat) else {
            continue;
        };

        let settings = match seat {
            Seat::Verbs(_) => {
                busbar_kernel::config::filled::plane_bound(&[], section.settings.clone())
            }
            Seat::Instance(..) => section.settings.clone(),
        };
        let blob = serde_json::to_vec(&settings).map_err(|e| e.to_string())?;
        validate(instance, &blob).map_err(|reason| {
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
        let former: Vec<_> = candidate
            .aliases
            .iter()
            .chain(std::iter::once(&candidate.name))
            .flat_map(|name| busbar_kernel::config::migration_table::former_names(name))
            .collect();
        let candidate = candidate.answering(former);
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
    /// Root binds followed by additional plugin binds.
    pub binds: Vec<InboundBind>,
    /// Assignments, including needs sharing the root data bind.
    pub needs: Vec<ListenerNeed>,
}

pub fn configured_listener_needs(
    cfg: &busbar_kernel::config::RootCfg,
    sections: &std::collections::BTreeMap<&'static str, serde_yaml::Value>,
) -> Result<ListenerNeeds, String> {
    listener_projection(
        listener_candidates(&crate::LINKED)?,
        &cfg.hooks,
        &cfg.export_defs,
        sections,
        configured_root_binds(cfg)?,
    )
}

pub fn configured_root_binds(
    cfg: &busbar_kernel::config::RootCfg,
) -> Result<Vec<InboundBind>, String> {
    let doc = serde_json::json!({"tls": serde_json::to_value(&cfg.tls).map_err(|e| e.to_string())?,
        "admin_tls": serde_json::to_value(&cfg.admin_tls).map_err(|e| e.to_string())?});
    Ok(root_binds(
        &doc,
        &RootListens {
            listen: &cfg.listen,
            admin_listen: &cfg.admin_listen,
        },
    ))
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
    use serde_json::{Map, Value};
    fn insert_path(map: &mut Map<String, Value>, path: &[&str], value: Value) {
        if let Some((first, rest)) = path.split_first() {
            if rest.is_empty() {
                map.insert((*first).into(), value);
            } else {
                let next = map
                    .entry((*first).to_string())
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Some(next) = next.as_object_mut() {
                    insert_path(next, rest, value);
                }
            }
        }
    }
    fn settings(
        candidate: &Candidate,
        mut block: impl FnMut(&[&str]) -> Result<Option<Value>, String>,
    ) -> Result<Value, String> {
        let mut out = Map::new();
        for need in &candidate.needs {
            if need.direction != busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND {
                continue;
            }
            let path: Vec<_> = need.target_from.split('.').collect();
            if let Some(block) = block(&path)? {
                insert_path(&mut out, &path, block);
            }
        }
        Ok(Value::Object(out))
    }
    fn json_block(source: Option<&Map<String, Value>>, path: &[&str]) -> Option<Value> {
        let (first, rest) = path.split_first()?;
        rest.iter()
            .try_fold(source?.get(*first)?, |value, part| value.get(*part))
            .cloned()
    }
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
    let mut doc = Map::new();
    for selection in &selected {
        let candidate = &candidates[selection.candidate];
        if !candidate
            .needs
            .iter()
            .any(|n| n.direction == busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND)
        {
            continue;
        }
        let (root, settings) = match candidate.kind {
            KindCode::Plane => (
                None,
                settings(candidate, |path| {
                    let block = sections
                        .get(selection.instance.as_str())
                        .and_then(|source| {
                            path.iter().try_fold(source, |value, part| value.get(*part))
                        });
                    block
                        .map(serde_json::to_value)
                        .transpose()
                        .map_err(|e| e.to_string())
                })?,
            ),
            KindCode::Hook => (
                Some("hooks"),
                settings(candidate, |path| {
                    Ok(json_block(
                        hooks.get(&selection.instance).map(|hook| &hook.settings),
                        path,
                    ))
                })?,
            ),
            KindCode::Export => (
                Some("export"),
                settings(candidate, |path| {
                    Ok(json_block(
                        exports
                            .get(&selection.instance)
                            .map(|export| &export.settings),
                        path,
                    ))
                })?,
            ),
            _ => continue,
        };
        if let Some(root) = root {
            insert_path(&mut doc, &[root, &selection.instance, "settings"], settings);
        } else {
            doc.insert(selection.instance.clone(), settings);
        }
    }
    let doc = Value::Object(doc);
    listener_needs(&doc, &candidates, &selected, root)
}

pub fn listener_needs(
    doc: &serde_json::Value,
    candidates: &[Candidate],
    selected: &[Selected],
    root: Vec<InboundBind>,
) -> Result<ListenerNeeds, String> {
    use busbar_contract::abi::host::conn::connector::{DIRECTION_INBOUND, DIRECTION_OUTBOUND};
    let mut binds = root;
    let mut shared = Vec::new();
    for selection in selected {
        let candidate = &candidates[selection.candidate];
        let mut physical = candidate.clone();
        for (index, need) in candidate.needs.iter().enumerate() {
            if need.direction != DIRECTION_INBOUND {
                continue;
            }
            if !matches!(
                candidate.kind,
                KindCode::Plane | KindCode::Hook | KindCode::Export
            ) {
                return Err(format!(
                    "{}: {:?} inbound need {index} has no SERVE consumer",
                    selection.instance, candidate.kind
                ));
            }
            let settings = match candidate.kind {
                KindCode::Plane => doc.get(&selection.instance),
                KindCode::Hook => doc
                    .get("hooks")
                    .and_then(|v| v.get(&selection.instance))
                    .and_then(|v| v.get("settings")),
                KindCode::Export => doc
                    .get("export")
                    .and_then(|v| v.get(&selection.instance))
                    .and_then(|v| v.get("settings")),
                _ => None,
            };
            if need.target_from == "listen" && settings.and_then(|v| v.get("listen")).is_none() {
                let bind = binds
                    .iter()
                    .find(|b| b.owner == BindOwner::Root && b.at == "listen")
                    .ok_or_else(|| {
                        format!(
                            "{}: inbound need {index} names an unavailable root listen bind",
                            selection.instance
                        )
                    })?;
                shared.push(ListenerNeed {
                    module: candidate.name.clone(),
                    instance: if candidate.kind == KindCode::Plane {
                        candidate.name.clone()
                    } else {
                        selection.instance.clone()
                    },
                    kind: candidate.kind,
                    need: u32::try_from(index)
                        .map_err(|_| "inbound need index does not fit u32")?,
                    transport: need.transport.clone(),
                    auth: need.auth.clone(),
                    at: bind.at.clone(),
                });
                physical.needs[index].direction = DIRECTION_OUTBOUND;
            }
        }

        for index in 0..physical.needs.len() {
            if physical.needs[index].direction != DIRECTION_INBOUND {
                continue;
            }
            let mut one = physical.clone();
            for (other, need) in one.needs.iter_mut().enumerate() {
                if other != index {
                    need.direction = DIRECTION_OUTBOUND;
                }
            }
            let mut parsed = inbound(
                doc,
                &[one],
                &[Selected {
                    candidate: 0,
                    instance: selection.instance.clone(),
                }],
                Vec::new(),
            )?;
            let mut bind = parsed.pop().ok_or("inbound declaration produced no bind")?;
            let declared = &candidate.needs[index];
            let settings = match candidate.kind {
                KindCode::Plane => doc.get(&selection.instance),
                KindCode::Hook => doc
                    .get("hooks")
                    .and_then(|v| v.get(&selection.instance))
                    .and_then(|v| v.get("settings")),
                KindCode::Export => doc
                    .get("export")
                    .and_then(|v| v.get(&selection.instance))
                    .and_then(|v| v.get("settings")),
                _ => None,
            };
            let block = settings.and_then(|settings| {
                declared
                    .target_from
                    .split('.')
                    .try_fold(settings, |v, key| v.get(key))
            });
            let collision = binds.iter().find(|old| {
                bind.listen.port() != 0
                    && old.listen.port() == bind.listen.port()
                    && (old.listen.ip() == bind.listen.ip()
                        || old.listen.ip().is_unspecified()
                        || bind.listen.ip().is_unspecified())
            });
            let at = if let Some(old) = collision {
                if old.at == "admin_listen"
                    || old.listen != bind.listen
                    || (old.owner != BindOwner::Root
                        || block.is_some_and(|b| b.get("tls").is_some()))
                        && old.tls != bind.tls
                    || (old.owner != BindOwner::Root
                        || block.is_some_and(|b| b.get("max_conns").is_some()))
                        && old.max_conns != bind.max_conns
                {
                    return Err(format!(
                        "{}: inbound declaration is incompatible with physical listener {}",
                        bind.at, old.at
                    ));
                }
                old.at.clone()
            } else {
                if candidate.kind == KindCode::Plane {
                    if let BindOwner::Need { instance, .. } = &mut bind.owner {
                        *instance = candidate.name.clone();
                    }
                }
                let at = bind.at.clone();
                binds.push(bind);
                at
            };
            shared.push(ListenerNeed {
                module: candidate.name.clone(),
                instance: if candidate.kind == KindCode::Plane {
                    candidate.name.clone()
                } else {
                    selection.instance.clone()
                },
                kind: candidate.kind,
                need: u32::try_from(index).map_err(|_| "inbound need index does not fit u32")?,
                transport: declared.transport.clone(),
                auth: declared.auth.clone(),
                at,
            });
        }
    }
    Ok(ListenerNeeds {
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
) -> Result<Stages, String> {
    let doc = document(path)
        .map(|d| d.value().clone())
        .unwrap_or_default();
    let root = root_binds(&doc, root);
    stages(&doc, discover(registry)?, root)
}

/// The addresses the host's own listeners take, as the resolved configuration states them.
#[derive(Debug, Clone, Copy)]
pub struct RootListens<'a> {
    /// The data door (`listen`).
    pub listen: &'a str,
    /// The admin surface (`admin_listen`).
    pub admin_listen: &'a str,
}

#[must_use]
pub fn root_binds(doc: &serde_json::Value, root: &RootListens<'_>) -> Vec<InboundBind> {
    [
        ("listen", root.listen, "tls"),
        ("admin_listen", root.admin_listen, "admin_tls"),
    ]
    .into_iter()
    .filter_map(|(setting, addr, tls)| {
        Some(InboundBind {
            owner: BindOwner::Root,
            transport: String::new(),
            at: setting.to_string(),
            listen: addr
                .parse()
                .ok()
                .or_else(|| std::net::ToSocketAddrs::to_socket_addrs(addr).ok()?.next())?,
            tls: doc.get(tls).filter(|v| !v.is_null()).cloned(),
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
    let previous = std::mem::replace(&mut *PROVIDER_URLS.write().expect("provider URLs"), next);
    drop(previous);
}

fn transport_uses() -> Uses {
    let urls = PROVIDER_URLS.read().expect("provider URLs").clone();
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
        crate::root::loader::dispatch::ConnTable::Host(conns),
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
    if let Some(opened) = WIRES.lock().expect("transport inventory").clone() {
        return opened;
    }
    let opened = open_dropped_transports(settings).unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    });
    let retained = {
        let mut wires = WIRES.lock().expect("transport inventory");
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
    let previous = wires.lock().expect("transport inventory").replace(dropped);
    drop(previous);
}

pub fn compose_book(
    lane: super::durability::JournalLane,
    data_dir: Option<std::path::PathBuf>,
    node: u64,
    now: u64,
    token: &busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
) -> Result<super::durability::Durability, String> {
    let mut durability = super::durability::build_on_store(
        &super::durability::DurabilityConfig { data_dir },
        node,
        lane,
        Some(&crate::root::kernel::ROOT_CARD),
    )
    .map_err(|e| format!("the boot journal could not be opened: {e}"))?;

    if let Err(lost) =
        durability.journal_quarantines(token, busbar_contract::caps::StepName::Meter, now)
    {
        tracing::error!(
            step = lost.step().as_str(),
            "the journal could not record the quarantine boot recovery made"
        );
    }

    super::keyset::bind(
        &mut durability,
        None,
        token,
        busbar_contract::caps::StepName::Meter,
        now,
    )
    .map_err(|e| e.to_string())?;
    Ok(durability)
}

pub fn book(
    app: &busbar_kernel::state::App,
    store: &str,
) -> Result<super::durability::NodeBook, String> {
    let Some(gov) = app.governance.as_ref() else {
        return Err(
            "the boot book needs the configured store and none resolved; add a store, e.g. \
             `store: {module: memory}`, or run `busbar migrate` (Q-STORE)"
                .to_string(),
        );
    };
    let Some(calls) = gov.store_calls() else {
        return Err(no_record_slots(store));
    };
    let lane = super::durability::JournalLane::start(calls, store)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let data_dir = busbar_kernel::preflight::fleet_data_dir();
    let host = super::durability::host_identity();
    let calls = lane.calls();
    let taken = super::durability::take_node(calls.as_ref(), &host)
        .map_err(|why| format!("this node's identity in the store `{store}`: {why}"))?;

    super::durability::hold_plugin_floor(
        calls.as_ref(),
        &host,
        app.hook_env.registry.as_ref(),
        &app.plugins_cfg.first_party_floors,
    )?;

    if let Some(lease) = taken.lease {
        lane.hold_lease(lease);
    }
    let node = taken.id;
    lane.bind_recovery_identity(&host, node)?;

    super::kernel::ROOT_CARD.keep_in_store(calls.clone(), node);
    let token = super::kernel::new_kernel().durability_token();
    let mut durability = compose_book(lane, data_dir, node, now, &token)?;

    durability.restore_amendments(&app.amendments, &token)?;

    super::durability::report_operator_breaks(&durability);

    if let Some(material) = durability
        .record
        .derived_secret(super::keyset::CALLER_REF_MATERIAL)
    {
        gov.bind_deployment_caller_ref(material);
    } else {
        tracing::debug!(
            node,
            "no deployment keyset is bound: caller references are keyed by this boot's random key \
             unless the node keeps signing material, so they differ per node and per restart"
        );
    }
    let durability = Arc::new(std::sync::Mutex::new(durability));

    gov.attach_recovery_sink(super::durability::usage_recovery_sink(&durability))
        .map_err(|why| {
            format!("usage recovery could not be restored from the Store journal: {why}")
        })?;
    gov.hydrate_budgets(&app.cost, now)
        .map_err(|why| format!("budget hydration after usage recovery failed: {why}"))?;
    if let Err(why) = gov.resume_correction_verdicts(&app.cost) {
        use busbar_kernel::diagnostics::{diag_warn, BUDGET_FLUSH_PARTIAL_FAILURE};
        diag_warn!(BUDGET_FLUSH_PARTIAL_FAILURE, error = %why,
            "usage correction recovery remains retained after boot; background continuation will retry");
    }

    super::durability::bind_amendments(&durability, &app.amendments);

    let verb_store = super::durability::node_verb_store(
        Arc::clone(&durability),
        super::kernel::new_kernel().durability_token(),
        store,
    );
    Ok(super::durability::NodeBook {
        durability,
        verb_store,
    })
}

#[must_use]
pub fn no_record_slots(store: &str) -> String {
    format!(
        "the configured store `{store}` does not offer the record slots ({}) the node's journal is \
         kept in; configure a store that implements store ABI v3",
        super::durability::RECORD_SLOTS
    )
}

#[cfg(test)]
#[path = "tests/boot.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/transport_inventory.rs"]
mod transport_inventory_tests;

#[cfg(all(test, unix, linked_every_plane_door, feature = "test-harness"))]
#[path = "tests/bootstrap_pins.rs"]
mod bootstrap_pin_tests;
