// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::v1::contract::ObservationUsageView;
use busbar_contract::confined_path::{ConfinedPathError, ConfinedRoot};
use busbar_kernel::admission::{Judged, PluginAdmission, Refusal, Stated};

pub(crate) fn admission(app: &App) -> Result<&'static dyn PluginAdmission, String> {
    resolve_admission(&app.plugins_cfg, app.plugin_admission)
}

pub(super) fn resolve_admission(
    cfg: &busbar_kernel::config::PluginsCfg,
    installed: Option<&'static dyn PluginAdmission>,
) -> Result<&'static dyn PluginAdmission, String> {
    cfg.warn_invalid_floors();
    installed
        .ok_or_else(|| "no plugin trust policy is installed (the composition root's)".to_string())
}

fn refused(refusal: Refusal) -> AdminError {
    match refusal {
        Refusal::Validation(m) => AdminError::Validation(m),
        Refusal::Conflict(m) => AdminError::Conflict(m),
    }
}

fn plugin_io_failed(operation: &'static str, error: std::io::Error) -> AdminError {
    diag_error!(
        ADMIN_STORE_OPERATION_FAILED,
        operation,
        error = ?error.kind(),
        os_error = ?error.raw_os_error(),
        "admin plugin persistence failed; the filesystem mutation may already have taken effect"
    );
    AdminError::Internal
}

impl AdminService {
    pub(crate) fn new(app: Arc<App>) -> Self {
        Self {
            app,
            rate_history: None,
        }
    }

    pub(crate) async fn info(&self) -> Result<InfoView, AdminError> {
        let live = busbar_kernel::persistence::boot_identity::live();
        let nodes = match live {
            Some(live) => live
                .nodes()
                .await
                .map_err(|_| AdminError::Internal)?
                .into_iter()
                .map(|n| NodeView {
                    node_id: n.node_id,
                    started_at: n.started_at,
                    last_seen_at: n.last_seen_at,
                    state: n.state.into(),
                    role: n.role.into(),
                })
                .collect(),
            None => Vec::new(),
        };

        let auth_modules = auth_modules_compiled_in();
        let hook_plugins = hook_plugins_compiled_in();

        let view = self.app.engine_tables_view();
        let providers: std::collections::BTreeSet<String> = (0..view.lane_count())
            .filter_map(|i| view.lane_view(i).map(|l| l.provider.to_string()))
            .collect();

        Ok(InfoView {
            version: env!("CARGO_PKG_VERSION"),
            build: BuildInfo {
                auth_modules,
                hook_plugins,
                weighted_floor: true,
            },
            uptime_seconds: PROCESS_START.get().map(|s| s.elapsed().as_secs()),
            started_at: PROCESS_START_EPOCH.get().copied(),
            process_boot_nonce: busbar_kernel::snapshot::process_generation()
                .map(|(nonce, _)| nonce.to_string()),
            topology: TopologyInfo {
                pools: view.pools().len(),
                models: view.model_indices().len(),
                providers: providers.len(),
            },
            config_persistence: self.app.overlay_path.is_some(),
            config_version: self.app.config_version,
            kinds_revision: crate::v1::json::kinds::kinds_revision(&self.app),
            config_generation: self
                .app
                .config_generation
                .load(std::sync::atomic::Ordering::Acquire),
            overlay_ignored: busbar_kernel::appbuild::booted_with_ignore_overlay(),
            deployment_id: live.map(|l| l.deployment_id().to_string()),
            node_id: live.map(|l| l.node_id()),
            nodes,
        })
    }

    pub(crate) async fn list_pools(&self) -> Result<Page<PoolView>, AdminError> {
        let view = self.app.engine_tables_view();
        let mut pool_views: Vec<PoolView> = view
            .pools()
            .iter()
            .map(|(name, _)| PoolView {
                name: name.to_string(),
                members: view
                    .pool_members(name)
                    .iter()
                    .map(|&(idx, weight)| PoolMemberView {
                        model: lane_model(view, idx),
                        weight,
                    })
                    .collect(),
            })
            .collect();
        pool_views.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(pool_views))
    }

    fn pool_detail(&self, name: &str, members: &[(usize, u32)]) -> PoolDetailView {
        let view = self.app.engine_tables_view();
        let now = busbar_kernel::store::now();
        let members = members
            .iter()
            .map(|&(idx, weight)| {
                let snap = self.app.store.snapshot(idx, now);
                PoolMemberStatusView {
                    model: lane_model(view, idx),
                    weight,

                    usable: self.app.store.ready_in(name, idx, now),
                    cooldown_remaining_seconds: self
                        .app
                        .store
                        .cooldown_remaining_in(name, idx, now),
                    available_concurrency: self.app.store.available_permits(idx),
                    inflight: snap.inflight,
                    latency_ms: self.app.store.lane_latency_ms(idx),
                    ok: snap.ok,
                    err: snap.err,
                    dead: snap.dead,
                    trip_count: snap.trips,
                    last_trip_at: (snap.last_trip_at > 0).then_some(snap.last_trip_at),
                }
            })
            .collect();
        PoolDetailView {
            name: name.to_string(),
            members,
        }
    }

    pub(crate) async fn list_pools_detailed(&self) -> Result<Page<PoolDetailView>, AdminError> {
        let view = self.app.engine_tables_view();
        let mut pool_views: Vec<PoolDetailView> = view
            .pools()
            .iter()
            .map(|(name, _)| self.pool_detail(name, &view.pool_members(name)))
            .collect();
        pool_views.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(pool_views))
    }

    pub(crate) async fn list_models(&self) -> Result<Page<ModelView>, AdminError> {
        let view = self.app.engine_tables_view();
        let mut models: Vec<ModelView> = (0..view.lane_count())
            .filter_map(|i| {
                view.lane_view(i).map(|l| ModelView {
                    model: l.model.to_string(),
                    upstream: l.provider.to_string(),
                })
            })
            .collect();
        models.sort_by(|a, b| a.model.cmp(&b.model));
        Ok(Page::single(models))
    }

    pub(crate) async fn list_providers(&self) -> Result<Page<ProviderView>, AdminError> {
        let view = self.app.engine_tables_view();
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for i in 0..view.lane_count() {
            if let Some(l) = view.lane_view(i) {
                *counts.entry(l.provider.to_string()).or_insert(0) += 1;
            }
        }
        let providers = counts
            .into_iter()
            .map(|(provider, model_count)| ProviderView {
                upstream: provider.to_string(),
                model_count,
            })
            .collect();
        Ok(Page::single(providers))
    }

    pub(crate) async fn list_hooks(&self) -> Result<Page<HookView>, AdminError> {
        let mut hooks: Vec<HookView> = self
            .app
            .hook_registry
            .iter()
            .map(|(name, cfg)| self.hook_view(name, cfg))
            .collect();
        hooks.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(hooks))
    }

    pub(crate) async fn get_hook(&self, name: &str) -> Result<HookView, AdminError> {
        self.app
            .hook_registry
            .get(name)
            .map(|cfg| self.hook_view(name, cfg))
            .ok_or_else(|| AdminError::not_found(format!("hook `{name}`")))
    }

    pub(crate) fn list_named_defs(
        &self,
        section: NamedMapSection,
        pending: &std::collections::BTreeMap<
            String,
            busbar_kernel::config::overlay::UnparseableNamedDef,
        >,
    ) -> Result<Page<NamedDefView>, AdminError> {
        let mut defs: Vec<NamedDefView> = match section {
            NamedMapSection::IdentityProviders => self
                .app
                .identity_providers
                .iter()
                .map(|(name, cfg)| identity_provider_view(name, cfg))
                .collect(),
            NamedMapSection::Export => self
                .app
                .export_defs
                .iter()
                .map(|(name, cfg)| export_def_view(name, cfg))
                .collect(),

            NamedMapSection::Plane(_) => plane_named_def_list(section, &self.app),
        };

        for (name, entry) in pending {
            if !defs.iter().any(|d| &d.name == name) {
                defs.push(unparseable_def_view(name, entry));
            }
        }
        defs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(defs))
    }

    pub(crate) fn get_named_def(
        &self,
        section: NamedMapSection,
        name: &str,
        pending: &std::collections::BTreeMap<
            String,
            busbar_kernel::config::overlay::UnparseableNamedDef,
        >,
    ) -> Result<NamedDefView, AdminError> {
        let view = match section {
            NamedMapSection::IdentityProviders => self
                .app
                .identity_providers
                .get(name)
                .map(|cfg| identity_provider_view(name, cfg)),
            NamedMapSection::Export => self
                .app
                .export_defs
                .get(name)
                .map(|cfg| export_def_view(name, cfg)),

            NamedMapSection::Plane(_) => plane_named_def_get(section, &self.app, name),
        };
        if let Some(view) = view {
            return Ok(view);
        }

        pending
            .get(name)
            .map(|entry| unparseable_def_view(name, entry))
            .ok_or_else(|| AdminError::not_found(format!("{} `{name}`", section.singular())))
    }

    /// Every group, name-sorted; the handler cuts the keyset page.
    pub(crate) async fn list_groups(&self) -> Result<Page<GroupView>, AdminError> {
        let mut items: Vec<GroupView> = self
            .app
            .groups_registry
            .iter()
            .map(|(name, cfg)| GroupView::from_cfg(name, cfg))
            .collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(items))
    }

    pub(crate) async fn get_group(&self, name: &str) -> Result<GroupView, AdminError> {
        self.app
            .groups_registry
            .get(name)
            .map(|cfg| GroupView::from_cfg(name, cfg))
            .ok_or_else(|| AdminError::not_found(format!("group `{name}`")))
    }

    pub(crate) async fn get_group_usage(
        &self,
        name: &str,
    ) -> Result<crate::v1::contract::GroupUsageView, AdminError> {
        use crate::v1::contract::{GroupBucketUsageView, GroupUsageView};
        let Some(rt) = self.app.cost.group_named(name) else {
            return Err(AdminError::not_found(format!("group `{name}`")));
        };
        let now = busbar_kernel::store::now();

        let reads = match self.app.governance.clone() {
            Some(gov) => {
                let cost = self.app.cost.clone();
                let wanted: Vec<(String, String)> = rt
                    .buckets
                    .iter()
                    .map(|b| (b.bucket_id.to_string(), b.window.to_string()))
                    .collect();
                let mut reads = Vec::with_capacity(wanted.len());
                for (id, window) in &wanted {
                    reads.push(
                        gov.derived_bucket_usage_priced_async(&cost, id, window, true, now)
                            .await,
                    );
                }
                reads
            }
            None => Vec::new(),
        };
        let mut reads = reads.into_iter();
        let mut buckets = Vec::with_capacity(rt.buckets.len());
        for b in &rt.buckets {
            let usage = match reads.next() {
                Some(read) => read
                    .map_err(|e| {
                        busbar_kernel::diagnostics::diag_error!(
                            busbar_kernel::diagnostics::GROUP_USAGE_READ_FAILED,
                            group = name, bucket = %b.bucket_id, err = %e,
                            "group usage read failed"
                        );
                        AdminError::Internal
                    })?
                    .map_err(|e| usage_refusal("group_usage", &e))?,
                None => Default::default(),
            };
            buckets.push(GroupBucketUsageView {
                window: b.window,
                scope: b.scope.as_ref().map(|s| s.value.clone()),
                requests: usage.requests,
                tokens: usage.tokens,
                spend_cents: usage.spend_cents,
                requests_cap: b.requests_cap,
                tokens_cap: b.tokens_cap,
                budget_cap: b.budget_cap,

                budget_remaining_cents: b
                    .budget_cap
                    .map(|cap| busbar_kernel::cost::budget_remaining(cap, usage.spend_cents)),
            });
        }
        Ok(GroupUsageView {
            group: name.to_string(),
            enabled: rt.enabled,
            buckets,
            as_of: now,
        })
    }

    /// Keep native filesystem and archive work off the reactor while retaining
    /// both the shared scan gate and the caller's config-transaction fence.
    pub(crate) async fn list_plugins_current_async(
        &self,
        ptype: &str,
    ) -> Result<Page<PluginView>, AdminError> {
        plugin_query(ptype)?;
        let gate = match tokio::time::timeout(CATALOG_SCAN_GATE_WAIT, CATALOG_SCAN_GATE.lock())
            .await
        {
            Ok(guard) => guard,
            Err(_elapsed) => {
                diag_warn!(
                    PLUGIN_CATALOG_SCAN_GATE_TIMEOUT,
                    operation = "plugins.list",
                    wait = ?CATALOG_SCAN_GATE_WAIT,
                    "plugin catalog scan could not acquire the shared scan gate within its bound"
                );
                return Err(AdminError::Unavailable(
                    "the plugin directory scan is taking too long; try again shortly".into(),
                ));
            }
        };
        let service = Self::new(self.app.clone());
        let ptype = ptype.to_string();
        match tokio::task::spawn_blocking(move || {
            // Dropping the waiting future cannot release the gate while its
            // native filesystem worker is still scanning.
            let _gate = gate;
            service.list_plugins_current(&ptype)
        })
        .await
        {
            Ok(result) => result,
            Err(join_err) => {
                diag_error!(
                    ADMIN_STORE_TASK_JOIN_FAILED,
                    operation = "plugins.list",
                    error = %join_err,
                    "admin plugin catalog worker failed"
                );
                Err(AdminError::Internal)
            }
        }
    }

    /// Called inside the config transaction: inventory and archive hashes share the mutation fence.
    pub(crate) fn list_plugins_current(&self, ptype: &str) -> Result<Page<PluginView>, AdminError> {
        plugin_query(ptype)?;
        let catalog = self.store_plugin_catalog();
        self.list_plugins_from_catalog(ptype, catalog)
    }

    fn list_plugins_from_catalog(
        &self,
        ptype: &str,
        catalog: Vec<PluginView>,
    ) -> Result<Page<PluginView>, AdminError> {
        let mut plugins: Vec<PluginView> = Vec::new();
        match plugin_query(ptype)? {
            PluginQuery::Auth => {
                let chain = self.app.auth.chain_names();
                for name in auth_modules_compiled_in() {
                    // The operator row is found through the admitted words; it is an installed
                    // plugin row (linked or dropped), never a compiled-in built-in (§3.9).
                    let operator = !busbar_kernel::config::operator_provider().is_empty()
                        && busbar_kernel::config::names_operator(name);
                    let active = if name == busbar_kernel::config::KEYS_MODULE {
                        self.app.auth.keys_in_chain
                    } else if operator {
                        let op = &self.app.admin_modules.operator;
                        self.app.admin_chain.iter().any(|m| op.is(m))
                    } else {
                        chain.iter().any(|c| c == name)
                    };
                    plugins.push(PluginView::basic(
                        name.to_string(),
                        "auth",
                        if operator { "installed" } else { "compiled-in" },
                        Some(active),
                        None,
                    ));
                }

                let compiled = auth_modules_compiled_in();
                for name in &chain {
                    if !compiled.contains(&name.as_str()) {
                        plugins.push(PluginView::basic(
                            name.to_string(),
                            "auth",
                            "plugin",
                            Some(true),
                            None,
                        ));
                    }
                }

                let mut dynamic_auth: Vec<PluginView> =
                    catalog.into_iter().filter(|p| p.r#type == "auth").collect();
                plugins.append(&mut dynamic_auth);
            }
            PluginQuery::Hooks => {
                plugins.push(PluginView::basic(
                    "weighted".to_string(),
                    "hooks",
                    "compiled-in",
                    None,
                    None,
                ));
                for name in hook_plugins_compiled_in() {
                    plugins.push(PluginView::basic(
                        name.to_string(),
                        "hooks",
                        "compiled-in",
                        None,
                        None,
                    ));
                }

                let mut externals: Vec<PluginView> = self
                    .app
                    .hook_registry
                    .iter()
                    .map(|(name, cfg)| {
                        let target = Some(cfg.plugin.clone());
                        PluginView::basic(name.clone(), "hooks", "external", Some(true), target)
                    })
                    .collect();
                externals.sort_by(|a, b| a.name.cmp(&b.name));
                plugins.append(&mut externals);
                plugins.extend(catalog_rows_of_kind(catalog, "hook"));
            }

            PluginQuery::Store => {
                plugins.extend(catalog_rows_of_kind(catalog, "store"));
            }

            PluginQuery::Secret => {
                plugins.extend(
                    self.app
                        .hook_env
                        .registry
                        .linked()
                        .into_iter()
                        .filter(|row| row.kind == "secret")
                        .map(|row| linked_plugin_view(row, "secret")),
                );
                plugins.extend(catalog_rows_of_kind(catalog, "secret"));
            }
            PluginQuery::Catalog(kind) => {
                plugins.extend(
                    self.app
                        .hook_env
                        .registry
                        .linked()
                        .into_iter()
                        .filter(|row| row.kind == kind)
                        .map(|row| linked_plugin_view(row, kind)),
                );
                plugins.extend(catalog_rows_of_kind(catalog, kind));
            }
        }
        if let Ok(admission) = admission(&self.app) {
            let kind = match plugin_query(ptype)? {
                PluginQuery::Catalog(kind) => Some(kind),
                _ => None,
            };
            for stated in admission
                .linked_configuration()
                .into_iter()
                .filter(|row| Some(row.kind.as_str()) == kind)
            {
                if !plugins
                    .iter()
                    .any(|row| row.loader == "compiled-in" && row.name == stated.name)
                {
                    plugins.push(linked_configuration_view(stated));
                }
            }
        }
        for view in &mut plugins {
            if view.configuration.is_none() {
                let row = self.app.hook_env.registry.resolve(&view.name);
                let declaration = admission(&self.app).ok().and_then(|admission| {
                    admission.loaded_configuration(self.app.hook_env.registry.as_ref(), &view.name)
                });
                view.configuration = Some(crate::v1::plugin_configuration::configuration(
                    row.as_ref().map_or(view.r#type, |row| row.kind.as_str()),
                    declaration.as_ref(),
                    if row.as_ref().is_some_and(|row| row.linked) {
                        "linked_statement"
                    } else {
                        "loaded_manifest"
                    },
                    row.is_some() && self.app.plugin_admission.is_some(),
                ));
            }
            if view.loader != "compiled-in" {
                continue;
            }
            if let Some(row) = self
                .app
                .hook_env
                .registry
                .resolve(&view.name)
                .filter(|row| row.linked)
            {
                let projected = linked_plugin_view(row, view.r#type);
                view.has_schema = projected.has_schema;
                view.schema_url = projected.schema_url;
                view.schema_error = projected.schema_error;
                view.version = projected.version;
                view.interface_version = projected.interface_version;
                view.publisher = projected.publisher;
                view.trust = projected.trust;
                view.valid = projected.valid;
            }
        }
        Ok(Page::single(plugins))
    }

    pub(super) fn store_plugin_catalog(&self) -> Vec<PluginView> {
        let mut out = linked_store_rows();
        let Ok(admission) = admission(&self.app) else {
            return out;
        };
        if admission.policy_resolves(&self.app.plugins_cfg).is_err() {
            return out;
        }

        let now = busbar_kernel::store::now();

        prune_catalog_cache(&mut catalog_cache().lock().unwrap(), now);

        static FINGERPRINT_WARNED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        let before = match plugins_dir_fingerprint(
            &self.app.plugins_dir,
            &|file| admission.is_tarball(file),
            admission.max_tarball_bytes(),
        ) {
            Ok(fp) => {
                FINGERPRINT_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
                Some(fp)
            }
            Err(e) => {
                if !FINGERPRINT_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    diag_warn!(
                        PLUGINS_DIR_FINGERPRINT_FAILED,
                        dir = %self.app.plugins_dir.display(),
                        error = %e,
                        "cannot fingerprint plugins dir; bypassing the catalog cache for this read"
                    );
                } else {
                    diag_debug!(
                        PLUGINS_DIR_FINGERPRINT_FAILED,
                        dir = %self.app.plugins_dir.display(),
                        error = %e,
                        "cannot fingerprint plugins dir; still bypassing the catalog cache for this \
                         read (dir not yet readable)"
                    );
                }
                None
            }
        };

        if let Some(before) = before {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            before.hash(&mut hasher);
            (admission as *const dyn PluginAdmission as *const ()).hash(&mut hasher);
            format!("{:?}", self.app.plugins_cfg).hash(&mut hasher);
            let key = hasher.finish();

            if let Some(entry) = catalog_cache().lock().unwrap().get(&self.app.plugins_dir) {
                if entry.key == key {
                    out.extend(entry.rows.iter().cloned());
                    return out;
                }
            }

            let rows = Self::scan_store_plugin_rows(
                &self.app.plugins_dir,
                admission,
                &self.app.plugins_cfg,
            );

            let after = plugins_dir_fingerprint(
                &self.app.plugins_dir,
                &|file| admission.is_tarball(file),
                admission.max_tarball_bytes(),
            );
            if matches!(after, Ok(after) if after == before) {
                let mut cache = catalog_cache().lock().unwrap();
                let misses = cache
                    .get(&self.app.plugins_dir)
                    .map(|e| e.misses)
                    .unwrap_or(0)
                    + 1;
                cache.insert(
                    self.app.plugins_dir.clone(),
                    CatalogCacheEntry {
                        key,
                        rows: rows.clone(),
                        misses,
                        inserted_at: now,
                    },
                );
            }

            out.extend(rows);
            out
        } else {
            out.extend(Self::scan_store_plugin_rows(
                &self.app.plugins_dir,
                admission,
                &self.app.plugins_cfg,
            ));
            out
        }
    }

    fn scan_store_plugin_rows(
        dir: &Path,
        admission: &dyn PluginAdmission,
        cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Vec<PluginView> {
        let mut rows = Vec::new();

        let Ok(inventory) = admission.inventory(dir, cfg) else {
            return rows;
        };
        for row in inventory {
            let bytes = read_archive_bounded(dir, &row.file, admission.max_tarball_bytes()).ok();
            let archive_sha256 = bytes
                .as_ref()
                .map(|bytes| busbar_contract::redacted::sha256_hex(bytes));
            let mut view = plugin_inventory_view(row);
            view.configuration = Some(
                match bytes
                    .as_ref()
                    .and_then(|bytes| admission.inspect(bytes, cfg).ok())
                {
                    Some((manifest, judged))
                        if manifest.name == view.name
                            && manifest.kind == view.r#type
                            && Some(&manifest.version) == view.version.as_ref() =>
                    {
                        crate::v1::plugin_configuration::configuration(
                            &manifest.kind,
                            manifest.configuration.as_ref(),
                            "installed_archive",
                            view.valid == Some(true) && !matches!(judged, Judged::Rejected { .. }),
                        )
                    }
                    _ => crate::v1::plugin_configuration::configuration(
                        view.r#type,
                        None,
                        "unavailable",
                        false,
                    ),
                },
            );
            if view.has_schema {
                if let Some(digest) = archive_sha256.as_deref() {
                    let file = archive_path_segment(
                        view.file.as_deref().expect("inventory row has a file"),
                    );
                    view.schema_url = Some(format!("{}/plugins/{file}/schema?source=installed_archive&expected_archive_sha256={digest}", crate::v1::contract::ADMIN_PREFIX));
                } else {
                    view.schema_url = None;
                    view.has_schema = false;
                    view.schema_error = Some("installed archive schema is unavailable: archive could not be read within the admission cap".into());
                }
            }
            view.archive_sha256 = archive_sha256;
            rows.push(view);
        }
        rows
    }

    /// `POST /api/v1/admin/plugins` — INSTALL a plugin: the caller uploads a SIGNED plugin tarball
    /// (`{cdylib + manifest.json}` as one `.tar.gz`); the engine RE-VERIFIES it server-side against
    /// the running `plugins.*` posture (the client is NEVER trusted — the upload may originate
    /// remotely) and atomically writes the tarball into `plugins.dir`. Full scope, audited. The
    /// change takes effect on the next plugin (re)load (restart / config apply), not as a hot swap.
    ///
    /// Verification order (fail-closed, MANIFEST-ONLY — the uploaded code is NEVER `dlopen`ed by
    /// this endpoint, so pushing a plugin over the API cannot execute it and cannot bypass the
    /// trust model; loading only ever happens through the boot pipeline's same three phases):
    /// 1. Filename sanity — a bare `.tar.gz` filename (no path traversal). Storage only; identity
    ///    comes from the signed manifest.
    /// 2. STRUCTURAL — the tarball unpacks in memory; the manifest parses, is complete and
    ///    well-formed, the sha256 binds the library bytes, the abi_version is supported. `400`.
    /// 3. TRUST — signature vs the embedded first-party key / allowlisted publishers, opt-in flags,
    ///    anti-downgrade floors. An untrusted upload is a `409 conflict` (nothing is written).
    /// 4. CONFLICT — the manifest's name/alias must not collide with a DIFFERENT already-installed
    ///    loadable plugin. `409` naming both.
    /// 5. Atomic publish — write to a temp name in the same directory, then rename into place.
    pub(crate) fn install_store_plugin(
        &self,
        file: &str,
        tarball: &[u8],
    ) -> Result<crate::v1::contract::PluginInstallView, AdminError> {
        let file = validate_plugin_filename(&self.app, file)?;

        let admission = admission(&self.app).map_err(AdminError::Validation)?;
        let admitted = admission
            .admit_upload(&self.app.plugins_dir, &file, tarball, &self.app.plugins_cfg)
            .map_err(refused)?;
        let manifest = &admitted.stated;
        let (trust, publisher) = match &admitted.judged {
            Judged::Trusted { publisher } => ("trusted", Some(publisher.clone())),
            Judged::Allowed => ("unverified", Some(manifest.publisher.clone())),

            Judged::Rejected { reason } => {
                return Err(AdminError::Conflict(format!(
                    "plugin rejected by the trust policy: {reason}"
                )));
            }
        };
        if admitted.linked_serves {
            return Ok(crate::v1::contract::PluginInstallView {
                file,
                name: manifest.name.clone(),
                interface_version: manifest.abi_version,
                trust,
                version: Some(manifest.version.clone()),
                publisher,
                note: "this build links the plugin at this version and the linked build \
                       serves it: nothing was written",
            });
        }
        self.validate_bootstrap_candidate("install", &file, manifest, tarball, admission)?;

        let dir = &self.app.plugins_dir;
        busbar_kernel::durable::create_dir_all(dir)
            .map_err(|e| plugin_io_failed("plugins.install.create_dir", e))?;
        let final_path = confined_plugin_path(dir, &file)?;
        busbar_kernel::durable::write(&final_path, tarball)
            .map_err(|e| plugin_io_failed("plugins.install.publish", e))?;

        Ok(crate::v1::contract::PluginInstallView {
            file,
            name: manifest.name.clone(),
            interface_version: manifest.abi_version,
            trust,
            version: Some(manifest.version.clone()),
            publisher,
            note:
                "installed durably in the plugins directory; the change takes effect on the next \
                   plugin (re)load (restart or config apply), not as a hot swap",
        })
    }

    /// `POST /api/v1/admin/plugins/inspect` — a STATELESS, `read-only`-scope PREVIEW of a
    /// candidate plugin tarball: verify its signature, parse its manifest, and return the SAME
    /// response shape `GET /plugins/{name}/schema` already carries
    /// (`schema`/`schema_error`/`trust`/`source`, plus
    /// `kind`/`restart_required_default` — see [`Self::install_store_plugin`]'s sibling handler for
    /// the shape those two carry), PLUS `name`/`version` so a caller can identify the candidate
    /// before ever committing to `POST /plugins`. Touches NOTHING: no write to `plugins.dir`, no
    /// conflict check against the installed set — an inspect has no interaction with what is
    /// currently loaded (unlike [`Self::install_store_plugin`], steps 4/5 of that pipeline do not
    /// exist here at all). An untrusted/unverified/rejected candidate is reported, not refused — the
    /// whole point is letting an operator see what a not-yet-trusted plugin WOULD need without ever
    /// executing it ("untrusted-render hardening").
    ///
    /// HARDENING (this body is an attacker-controlled,
    /// base64-encoded, COMPRESSED ARCHIVE, reachable by the WEAKEST admin credential in the system,
    /// and the archive must be decompressed and its manifest parsed BEFORE the signature can even be
    /// checked, so the trust check happens strictly after the dangerous part):
    ///   1. a hard cap on the DECODED tarball size, the admission's `max_tarball_bytes`
    ///      — the same ceiling `POST /plugins` (install) and the on-disk catalog scan both already
    ///      enforce, checked here BEFORE anything else, the unpack included;
    ///   2. the admission's unpack itself streams each archive member through a
    ///      cap enforced DURING decompression (`read_entry_bounded`'s `.take(cap + 1)`) — a
    ///      decompression bomb fails fast, never after allocating the bomb — and rejects any
    ///      non-regular-file or path-traversal entry name outright, and errors immediately on a
    ///      second manifest/library member (an entry-count flood cannot accumulate past two real
    ///      entries before the archive is refused);
    ///   3. the embedded `settings_schema` string — the ONE place an attacker-controlled JSON
    ///      document can nest arbitrarily deep on a tiny byte count (every OTHER `Manifest` field is
    ///      a flat scalar, so `unpack`'s own `MAX_MANIFEST_BYTES` size cap is sufficient for the
    ///      manifest itself) — is depth- AND size-bounded via [`schema_json_within_bounds`] BEFORE
    ///      it is ever handed to `serde_json::from_str`, a distinct attack from a pathological
    ///      tarball;
    ///   4. its own dedicated rate bucket (`ratelimit::MutationClass::PluginInspect`), not the
    ///      shared 60/min CRUD bucket and not the unmetered-read bucket — wired in `auth::mod.rs`/
    ///      `ratelimit::classify_mutation` via `contract::PATH_PLUGINS_INSPECT`, exactly like
    ///      `/config/validate`'s existing carve-out.
    pub(crate) fn inspect_plugin(&self, tarball: &[u8]) -> Result<serde_json::Value, AdminError> {
        let admission = admission(&self.app).map_err(AdminError::Validation)?;
        let cap = admission.max_tarball_bytes();
        check_inspect_tarball_size(tarball.len(), cap)?;

        let (manifest, judged) = admission
            .inspect(tarball, &self.app.plugins_cfg)
            .map_err(refused)?;
        Ok(inspect_plugin_view(manifest, judged, |kind| {
            admission.restart_default(kind)
        }))
    }

    /// Static inspection of the exact installed artifact named by a catalog URL. Caller holds
    /// the config transaction throughout read, digest comparison, and admission inspection.
    pub(crate) fn installed_plugin_schema(
        &self,
        file: &str,
        expected: Option<&str>,
    ) -> Result<serde_json::Value, AdminError> {
        let file = validate_plugin_filename(&self.app, file)?;
        let admission = admission(&self.app).map_err(AdminError::Validation)?;
        let bytes = read_guarded_archive(
            &self.app.plugins_dir,
            &file,
            expected,
            admission.max_tarball_bytes(),
        )?;
        check_archive_preimage(expected, &bytes)?;
        let digest = busbar_contract::redacted::sha256_hex(&bytes);
        let (manifest, judged) = admission
            .inspect(&bytes, &self.app.plugins_cfg)
            .map_err(refused)?;
        let configuration = crate::v1::plugin_configuration::configuration(
            &manifest.kind,
            manifest.configuration.as_ref(),
            "installed_archive",
            !matches!(&judged, Judged::Rejected { .. }),
        );
        let mut view =
            inspect_plugin_view(manifest, judged, |kind| admission.restart_default(kind));
        view["configuration"] =
            serde_json::to_value(configuration).expect("configuration metadata serializes");
        view["source"] = serde_json::json!("installed_archive");
        view["file"] = serde_json::json!(file);
        view["archive_sha256"] = serde_json::json!(digest);
        view["schema_state"] = serde_json::json!(if !view["schema_error"].is_null() {
            "invalid"
        } else if view["schema"].is_null() {
            "absent"
        } else {
            "present"
        });
        Ok(view)
    }

    pub(crate) fn remove_store_plugin_if_archive(
        &self,
        file: &str,
        expected: Option<&str>,
    ) -> Result<crate::v1::contract::PluginRemoveView, AdminError> {
        let file = validate_plugin_filename(&self.app, file)?;
        if expected.is_some() {
            let bytes = read_guarded_archive(
                &self.app.plugins_dir,
                &file,
                expected,
                admission(&self.app)
                    .map_err(AdminError::Validation)?
                    .max_tarball_bytes(),
            )?;
            check_archive_preimage(expected, &bytes)?;
        }
        // Confined: never a link, so `is_file` below and the unlink act on the plugins dir entry.
        let lib_path = confined_plugin_path(&self.app.plugins_dir, &file)?;
        if expected.is_none() && !lib_path.is_file() {
            return Err(AdminError::not_found(format!("plugin `{file}`")));
        }
        busbar_kernel::durable::remove(&lib_path)
            .map_err(|e| plugin_io_failed("plugins.remove", e))?;
        Ok(crate::v1::contract::PluginRemoveView {
            file,
            removed: true,
        })
    }

    pub(crate) fn reload_store_plugins(
        &self,
    ) -> Result<crate::v1::contract::PluginReloadView, AdminError> {
        let plugins: Vec<PluginView> = self
            .store_plugin_catalog()
            .into_iter()
            .filter(|p| p.loader == "dynamic-library")
            .collect();
        Ok(crate::v1::contract::PluginReloadView {
            plugins,
            note:
                "hot-reloaded the plugin layer LIVE: a new plugin registry and new kind:hook \
                   transports are serving with no restart, and the prior shared libraries unmap once \
                   in-flight requests drain. A `store` MODULE change still lands on a dedicated store \
                   swap (the token ledger cannot be re-hydrated under load), not this reload.",
        })
    }

    pub(crate) fn resolve_plugin_rollback_if_archive(
        &self,
        file: &str,
        prior_pins: &std::collections::BTreeMap<String, String>,
        expected: Option<&str>,
    ) -> Result<(Stated, std::collections::BTreeMap<String, String>), AdminError> {
        let file = validate_plugin_filename(&self.app, file)?;
        let bytes = read_guarded_archive(
            &self.app.plugins_dir,
            &file,
            expected,
            admission(&self.app)
                .map_err(AdminError::Validation)?
                .max_tarball_bytes(),
        )?;
        check_archive_preimage(expected, &bytes)?;

        let admission = admission(&self.app).map_err(AdminError::Validation)?;
        let manifest = admission
            .rollback_target(&file, &bytes, &self.app.plugins_cfg)
            .map_err(refused)?;
        self.validate_bootstrap_candidate("rollback", &file, &manifest, &bytes, admission)?;

        let mut pins = prior_pins.clone();
        pins.insert(manifest.name.clone(), manifest.version.clone());
        Ok((manifest, pins))
    }

    fn validate_bootstrap_candidate(
        &self,
        operation: &str,
        file: &str,
        manifest: &Stated,
        bytes: &[u8],
        admission: &dyn PluginAdmission,
    ) -> Result<(), AdminError> {
        let Some(config_path) = self.app.config_path.as_deref() else {
            return Ok(());
        };
        let loaded = busbar_kernel::load_config_from_disk_judged(
            config_path,
            self.app.providers_override.as_deref(),
            false,
            busbar_kernel::config::EnvSubst::Strict,
            &*self.app.root_rules,
        )
        .map_err(|error| {
            AdminError::Validation(format!(
                "cannot validate the operator's Store overlay bootstrap policy: {error}"
            ))
        })?;
        let cfg =
            busbar_kernel::config::resolve(&loaded.deploy, &loaded.defs).map_err(|errors| {
                AdminError::Validation(format!(
                    "cannot validate the operator's Store overlay bootstrap policy: {}",
                    errors.join("; ")
                ))
            })?;
        let build = busbar_kernel::preflight::root_rows()
            .registry_build
            .ok_or_else(|| {
                AdminError::Validation(
                    "no root installed the Store overlay bootstrap registry".into(),
                )
            })?;
        let data_dir = busbar_kernel::preflight::fleet_data_dir();
        let rows = build(
            busbar_kernel::preflight::RegistryIn {
                linked: busbar_kernel::preflight::linked_rows(),
                plugins: Some(&loaded.deploy.plugins),
                data_dir: data_dir.as_deref(),

                inventory_only: true,
            },
            &mut |_| {},
        )
        .map_err(|error| {
            AdminError::Validation(format!(
                "cannot validate the operator's Store overlay bootstrap registry: {error}"
            ))
        })?;
        let dependencies = busbar_kernel::appbuild::bootstrap_dependency_names(&cfg, rows.as_ref());
        let selected_early_plugin = matches!(manifest.kind.as_str(), "transport" | "plane")
            && admission
                .bootstrap_probe_selected(
                    bytes,
                    config_path,
                    &cfg.providers
                        .values()
                        .map(|provider| provider.base_url.clone())
                        .collect::<Vec<_>>(),
                )
                .map_err(refused)?;
        if dependencies.contains(&manifest.name)
            || dependencies.contains(&manifest.alias)
            || selected_early_plugin
        {
            let archive_hash = busbar_contract::redacted::sha256_hex(bytes);
            busbar_kernel::appbuild::validate_bootstrap_archive(
                &manifest.name,
                file,
                Some(&archive_hash),
                &loaded.deploy.plugins,
            )
            .map_err(AdminError::Conflict)?;
            let (_, verdict) = admission
                .inspect(bytes, &loaded.deploy.plugins)
                .map_err(refused)?;
            let refused_reason = match verdict {
                Judged::Rejected { reason } => Some(reason),

                _ if operation == "rollback" => rows
                    .skipped()
                    .into_iter()
                    .find(|row| row.file == file && row.name == manifest.name)
                    .map(|row| row.reason),
                _ => None,
            };
            if let Some(reason) = refused_reason {
                return Err(AdminError::Conflict(format!("plugin {operation} would make Store overlay bootstrap dependency '{}' unavailable under the operator's base trust policy: {reason}. Keep an admitted bootstrap version, or deliberately change the base config.yaml Store/trust/floor configuration and reload or restart before this change; an unread Store-owned version pin cannot authorize opening that same Store", manifest.name)));
            }
        }
        Ok(())
    }

    pub(crate) async fn get_config(&self) -> Result<EffectiveConfigView, AdminError> {
        Ok(EffectiveConfigView {
            version: self.app.config_version,
            config_generation: self
                .app
                .config_generation
                .load(std::sync::atomic::Ordering::Acquire),
            auth: self.get_auth().await?,
            pools: self.list_pools().await?.items,
            models: self.list_models().await?.items,
            providers: self.list_providers().await?.items,
            hooks: self.list_hooks().await?.items,
            global_hooks: self.app.global_hooks.clone(),
            reload_to_apply: self.app.planes_awaiting_restart.clone(),
        })
    }

    /// `POST config/validate` (SECRET-SHORTHAND-BOOT §3.12): the body read exactly as apply reads
    /// it, without changing anything. The authority pre-check runs first, with the caller's
    /// authority: where apply would answer forbidden, validate answers `needs full operator` with
    /// the field classes and scans nothing. Then, as ONE unit behind the plugin scan gate on a
    /// blocking worker: the body's phase 1 over the SERVER's `plugins.dir` with the Store's version
    /// pins (no fetch), the typed parse under that grammar, and the checks. `Ok(Err(_))` is the
    /// operator-file-policy refusal apply answers too.
    pub(crate) async fn validate_config(
        &self,
        config: serde_json::Value,
        providers: std::collections::HashMap<String, busbar_kernel::config::ProviderDef>,
        parse: crate::v1::json::BodyParser,
    ) -> Result<Result<ConfigValidateView, AdminError>, AdminError> {
        let overlay = match self.app.overlay_path.as_deref() {
            Some(store) => store
                .read_required_async()
                .await
                .map_err(AdminError::Validation)?,
            None => None,
        };
        let mut candidate = busbar_kernel::config::security_policy::Candidate::of_json(
            &config,
            &super::running_grammar(&self.app),
            overlay.as_ref(),
        )
        .map_err(AdminError::Validation)?;
        let authority = match busbar_kernel::auth::effect::current() {
            Some(context) => Some(context.revalidate(&self.app).await.unwrap_or(
                busbar_kernel::auth::effect::Authority {
                    full_operator: false,
                },
            )),
            None => None,
        };
        if let Some(classes) = busbar_kernel::config::security_policy::needs_full_operator(
            &self.app, &candidate, authority,
        ) {
            return Ok(Ok(ConfigValidateView {
                ok: false,
                errors: vec![format!(
                    "needs full operator: this configuration changes {}; config/apply refuses \
                     it without full-operator authority, so nothing was read from plugins.dir",
                    classes.join(", ")
                )],
            }));
        }
        candidate.plugins.dir = self.app.plugins_dir.to_string_lossy().into_owned();
        let gate = super::scan_gate("config.validate").await?;
        let rules = std::sync::Arc::clone(&self.app.root_rules);
        let reference = std::sync::Arc::clone(&self.app.operator_file_defs);
        match tokio::task::spawn_blocking(move || {
            let _gate = gate;
            validate_config_blocking(
                config,
                providers,
                parse,
                candidate.plugins,
                &rules,
                reference,
            )
        })
        .await
        {
            Ok(view) => view,
            Err(join_err) => {
                diag_error!(
                    ADMIN_STORE_TASK_JOIN_FAILED,
                    operation = "config.validate",
                    error = %join_err,
                    "admin blocking task failed"
                );
                Err(AdminError::Internal)
            }
        }
    }

    pub(crate) async fn get_admin_auth(&self) -> Result<AdminAuthView, AdminError> {
        let modules = self.app.admin_chain.clone();
        let default = modules == busbar_kernel::config::auth::default_admin_auth_names();
        Ok(AdminAuthView {
            configured: !modules.is_empty(),
            modules,
            default,
        })
    }

    pub(crate) async fn get_usage(
        &self,
        window: Option<u64>,
        as_of: Option<busbar_kernel::cost::EntryKey>,
    ) -> Result<UsageView, AdminError> {
        let now = busbar_kernel::store::now();
        let current = busbar_kernel::governance::metering_bucket(now);
        let bucket = match window {
            None => current,
            Some(w) => {
                if w % busbar_kernel::governance::METERING_BUCKET_SECS != 0 {
                    return Err(AdminError::Validation(format!(
                        "window must be a UTC-day bucket start (a multiple of {}); got {w}",
                        busbar_kernel::governance::METERING_BUCKET_SECS
                    )));
                }
                if w > current {
                    return Err(AdminError::Validation("window is in the future".into()));
                }
                w
            }
        };
        let window = UsageWindow {
            start: bucket,
            end: bucket + busbar_kernel::governance::METERING_BUCKET_SECS,
        };

        let history = self.rate_history.clone().or_else(dated_rate_history);

        let snapshot = match as_of {
            None => None,
            Some(key) => Some(validated_snapshot(history.as_deref(), key)?),
        };
        let empty = || UsageView {
            window,
            as_of: now,
            currency: (),

            rate_card_version: None,
            total: UsageBreakdown::default(),
            by_model: Vec::new(),
            by_key: Vec::new(),
            by_key_truncated: false,
            others: None,
            observations: Vec::new(),
        };
        let Some(gov) = self.app.governance.clone() else {
            return Ok(empty());
        };
        let fetched = fetch_usage_day(&gov, bucket).await;
        let cost = self.app.cost.clone();
        let ((rows, names, adjustments), observations) = fetched.map_err(|(operation, error)| {
            diag_error!(ADMIN_STORE_OPERATION_FAILED, operation, error = %error, "admin store operation failed");
            AdminError::Internal
        })?;

        project_usage_rows_with_observations(
            cost,
            history,
            snapshot,
            window,
            now,
            (rows, names, adjustments),
            observations,
        )
    }

    /// `GET /usage` in range mode: every UTC day `spec.from..=spec.to`, priced and grouped. The
    /// caller has already bounded the range. Reads only: nothing is written.
    pub(crate) async fn get_usage_series(
        &self,
        spec: &SeriesSpec,
    ) -> Result<crate::v1::contract::UsageSeries, AdminError> {
        let now = busbar_kernel::store::now();
        let history = self.rate_history.clone().or_else(dated_rate_history);
        let snapshot = match spec.as_of {
            None => None,
            Some(key) => Some(validated_snapshot(history.as_deref(), key)?),
        };
        let mut days = Vec::new();
        if let Some(gov) = self.app.governance.clone() {
            let mut bucket = spec.from;
            while bucket <= spec.to {
                let fetched = fetch_usage_day(&gov, bucket).await.map_err(|(operation, error)| {
                    diag_error!(ADMIN_STORE_OPERATION_FAILED, operation, error = %error, "admin store operation failed");
                    AdminError::Internal
                })?;
                days.push((bucket, fetched));
                bucket += METERING_DAY;
            }
        }
        project_usage_series(self.app.cost.clone(), history, snapshot, now, days, spec)
    }

    pub(crate) async fn get_auth(&self) -> Result<AuthView, AdminError> {
        let chain = self.app.auth.effective_chain_names();
        Ok(AuthView {
            open: self.app.auth.is_open(),
            chain,
            upstream_credentials: match self.app.upstream_creds() {
                busbar_kernel::auth::UpstreamCreds::Own => "own",
                busbar_kernel::auth::UpstreamCreds::Passthrough => "passthrough",
                busbar_kernel::auth::UpstreamCreds::Connection => "connection",
            },
        })
    }

    pub(crate) async fn hook_health(&self, name: &str) -> Result<HookHealthView, AdminError> {
        let cfg = self.app.hook_registry.get(name);
        let loadable = cfg.and_then(|cfg| self.app.hook_env.registry.resolve(&cfg.plugin));
        let skipped = if loadable.is_none() {
            cfg.and_then(|cfg| self.app.hook_env.registry.unresolved_reason(&cfg.plugin))
        } else {
            None
        };
        hook_health_projection(
            name,
            cfg,
            &self.app.global_hooks,
            loadable.as_ref().map(|row| row.kind.as_str()),
            skipped.as_ref().map(|row| row.reason.as_str()),
        )
    }

    fn hook_view(&self, name: &str, cfg: &HookCfg) -> HookView {
        let mut view = project_hook_view(name, cfg, &self.app.global_hooks);
        view.attachments = crate::v1::json::attachments_of(&self.app, name);
        view
    }
}

type ObservationRecord = busbar_kernel::persistence::observations::DatedRecord;

type FetchedUsage<T = i128> = (
    Vec<busbar_kernel::governance::MeteringRow>,
    std::collections::HashMap<String, String>,
    Vec<busbar_kernel::governance::UsageAdjustment<T>>,
);

type UsageFetchError = (&'static str, busbar_kernel::governance::RecordStoreError);

/// Everything one UTC-day bucket contributes to a usage read: metering rows, key names,
/// adjustments, and dated observation records.
async fn fetch_usage_day(
    gov: &busbar_kernel::governance::GovState,
    bucket: u64,
) -> Result<(FetchedUsage<Count>, Vec<ObservationRecord>), UsageFetchError> {
    let rows = gov
        .metering_for_async(bucket)
        .await
        .map_err(|e| ("usage.metering", e))?;
    let names = gov
        .all_keys_async()
        .await
        .map_err(|e| ("usage.keys", e))?
        .into_iter()
        .map(|k| (k.id, k.name))
        .collect();
    let adjustments = gov
        .usage_adjustments_exact_async(bucket)
        .await
        .map_err(|e| ("usage.adjustments", e))?;
    let core = gov
        .core_store_handle()
        .map_err(|e| ("usage.observations", e))?;
    let observations =
        if busbar_kernel::persistence::observations::ObservationStore::supports(&core) {
            let store = busbar_kernel::persistence::observations::ObservationStore::open(core)
                .map_err(|e| {
                    (
                        "usage.observations",
                        busbar_kernel::governance::RecordStoreError(e.to_string()),
                    )
                })?;
            store.dated_records_for_day(bucket).await.map_err(|e| {
                (
                    "usage.observations",
                    busbar_kernel::governance::RecordStoreError(e.to_string()),
                )
            })?
        } else {
            Vec::new()
        };
    Ok(((rows, names, adjustments), observations))
}

#[cfg(test)]
pub(super) fn project_usage_rows(
    cost: Arc<busbar_kernel::cost::CostModel>,
    history: Option<Arc<busbar_kernel::cost::History>>,
    snapshot: Option<busbar_kernel::cost::EntryKey>,
    window: UsageWindow,
    now: u64,
    data: FetchedUsage,
) -> Result<UsageView, AdminError> {
    let (mut rows, names, adjustments) = data;
    fold_adjustments(&mut rows, &adjustments).map_err(|_| AdminError::Internal)?;
    project_usage_rows_exact(
        cost,
        history,
        snapshot,
        window,
        now,
        (rows, names, Vec::new()),
    )
}

#[cfg(test)]
pub(super) fn project_usage_rows_exact(
    cost: Arc<busbar_kernel::cost::CostModel>,
    history: Option<Arc<busbar_kernel::cost::History>>,
    snapshot: Option<busbar_kernel::cost::EntryKey>,
    window: UsageWindow,
    now: u64,
    data: FetchedUsage<Count>,
) -> Result<UsageView, AdminError> {
    project_usage_rows_with_observations(cost, history, snapshot, window, now, data, Vec::new())
}

pub(super) fn project_usage_rows_with_observations(
    cost: Arc<busbar_kernel::cost::CostModel>,
    history: Option<Arc<busbar_kernel::cost::History>>,
    snapshot: Option<busbar_kernel::cost::EntryKey>,
    window: UsageWindow,
    now: u64,
    data: FetchedUsage<Count>,
    records: Vec<ObservationRecord>,
) -> Result<UsageView, AdminError> {
    let (mut rows, names, adjustments) = data;
    let view = history.as_deref().map(|h| match snapshot {
        Some(at) => h.snapshot(at),
        None => h.current(),
    });

    let mut priced_by: Option<busbar_kernel::cost::EntryKey> = None;

    if let Err(why) = super::fold_adjustments_exact(&mut rows, &adjustments) {
        diag_error!(
            ADMIN_STORE_OPERATION_FAILED,
            operation = "usage.adjustments",
            error = %why,
            "admin store operation failed"
        );
        return Err(AdminError::Internal);
    }

    let mut total = UsageRollup::default();
    let mut by_model: std::collections::BTreeMap<(String, String), UsageRollup> =
        std::collections::BTreeMap::new();
    let mut by_key: std::collections::BTreeMap<String, UsageRollup> =
        std::collections::BTreeMap::new();
    for r in &rows {
        let priced_row = price_metering_row(&cost, view.as_ref(), window.start, r, false)?;
        priced_by = priced_by.max(priced_row.card);
        let row = priced_row.rollup;
        for aggregate in [
            &mut total,
            by_model
                .entry((r.model.clone(), r.provider.clone()))
                .or_default(),
            by_key.entry(r.key_id.clone()).or_default(),
        ] {
            aggregate.add(&row)?;
        }
    }
    let mut observations = Vec::new();
    for record in records
        .into_iter()
        .filter(|r| window.start <= r.rate_time && r.rate_time < window.end)
    {
        let (row, raw) = observation_rollup(&record)?;
        let rated_subject = observation_subject(&record.rated_subject);
        for aggregate in [
            &mut total,
            by_model
                .entry((rated_subject.to_string(), record.destination.clone()))
                .or_default(),
            by_key.entry(record.principal.clone()).or_default(),
        ] {
            aggregate.add(&row)?;
        }
        observations.push(ObservationUsageView {
            key_id: record.principal,
            group: record.group,
            instance: record.instance,
            destination: record.destination,
            serving_subject: observation_subject(&record.serving_subject).to_string(),
            rated_subject: rated_subject.to_string(),
            accounting_time: record.rate_time.to_string(),
            counts: raw
                .into_iter()
                .map(|(class, n)| (class, n.to_decimal_string()))
                .collect(),
            spend_micros: if record.spent_nanos % 1_000 == 0 {
                (record.spent_nanos / 1_000).to_string()
            } else {
                format!(
                    "{}.{:03}",
                    record.spent_nanos / 1_000,
                    record.spent_nanos % 1_000
                )
                .trim_end_matches('0')
                .to_string()
            },
        });
    }
    let by_model = by_model
        .into_iter()
        .map(|((model, provider), usage)| {
            Ok(ModelUsageView {
                model,
                upstream: provider,
                usage: usage.project()?,
            })
        })
        .collect::<Result<Vec<_>, AdminError>>()?;
    let mut by_key: Vec<_> = by_key.into_iter().collect();
    const BY_KEY_CAP: usize = 1000;
    by_key.sort_by(|(a_id, a), (b_id, b)| {
        busbar_kernel::cost::Money::of_exact(b.exact)
            .micros()
            .cmp(&busbar_kernel::cost::Money::of_exact(a.exact).micros())
            .then_with(|| a_id.cmp(b_id))
    });
    let by_key_truncated = by_key.len() > BY_KEY_CAP;
    let others = if by_key_truncated {
        let mut others = UsageRollup::default();
        for (_, row) in &by_key[BY_KEY_CAP..] {
            others.add(row)?;
        }
        Some(others.project()?)
    } else {
        None
    };
    by_key.truncate(BY_KEY_CAP);
    let by_key = by_key
        .into_iter()
        .map(|(id, usage)| {
            Ok(KeyUsageView {
                name: names.get(&id).cloned(),
                id,
                usage: usage.project()?,
            })
        })
        .collect::<Result<Vec<_>, AdminError>>()?;
    Ok(UsageView {
        window,
        as_of: now,
        currency: (),
        rate_card_version: priced_by.map(|key| key.hex()),
        total: total.project()?,
        by_model,
        by_key,
        by_key_truncated,
        others,
        observations,
    })
}

/// A `/usage` series dimension. Declaration order is the sort and output order of a row's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum UsageDim {
    Bucket,
    Key,
    Group,
    Model,
    Provider,
    Kind,
    Instance,
}

impl UsageDim {
    pub(crate) fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "bucket" => Self::Bucket,
            "key" => Self::Key,
            "group" => Self::Group,
            "model" => Self::Model,
            "provider" => Self::Provider,
            "kind" => Self::Kind,
            "instance" => Self::Instance,
            _ => return None,
        })
    }
}

/// One range read: UTC-day bucket starts `from..=to`, the dimensions to group by (sorted, unique),
/// the row filters, and an optional rate-card snapshot.
pub(crate) struct SeriesSpec {
    pub(crate) from: u64,
    pub(crate) to: u64,
    pub(crate) group_by: Vec<UsageDim>,
    pub(crate) filters: Vec<(UsageDim, String)>,
    pub(crate) as_of: Option<busbar_kernel::cost::EntryKey>,
}

/// The engine kind of every instance a metering row can name: a plane.
const SERIES_INSTANCE_KIND: &str = "plane";

/// The instance a metering row belongs to, derived at read from its plane-qualified `provider`
/// by the rule `metering_lane` prices with: a non-fallback plane key names its own plane, and
/// every other row belongs to the fallback (pools) plane. The accrual key is not touched.
fn row_instance(provider: &str) -> String {
    use busbar_kernel::plane_driver::registry::{plane_decl_for, plane_decls};
    match plane_decl_for(provider) {
        Some(decl) if !decl.fallback => decl.key.to_string(),
        _ => plane_decls()
            .iter()
            .find(|decl| decl.fallback)
            .map_or("pools", |decl| decl.key)
            .to_string(),
    }
}

#[derive(Clone)]
struct DimValues {
    key: String,
    group: String,
    model: String,
    provider: String,
    instance: String,
}

impl DimValues {
    fn of(key: &str, group: &str, model: &str, provider: &str, instance: String) -> Self {
        Self {
            key: key.to_string(),
            group: group.to_string(),
            model: model.to_string(),
            provider: provider.to_string(),
            instance,
        }
    }

    fn admitted(&self, filters: &[(UsageDim, String)]) -> bool {
        filters.iter().all(|(dim, want)| match dim {
            UsageDim::Bucket => true,
            UsageDim::Key => &self.key == want,
            UsageDim::Group => &self.group == want,
            UsageDim::Model => &self.model == want,
            UsageDim::Provider => &self.provider == want,
            UsageDim::Kind => want == SERIES_INSTANCE_KIND,
            UsageDim::Instance => &self.instance == want,
        })
    }
}

struct SeriesCell {
    bucket: u64,
    dims: DimValues,
    rollup: UsageRollup,
    priced: bool,
}

fn fold_series(
    cells: &mut std::collections::BTreeMap<String, SeriesCell>,
    spec: &SeriesSpec,
    bucket: u64,
    dims: &DimValues,
    row: &UsageRollup,
    priced: bool,
) -> Result<(), AdminError> {
    let sort = spec
        .group_by
        .iter()
        .map(|dim| match dim {
            UsageDim::Bucket => format!("{bucket:020}"),
            UsageDim::Key => dims.key.clone(),
            UsageDim::Group => dims.group.clone(),
            UsageDim::Model => dims.model.clone(),
            UsageDim::Provider => dims.provider.clone(),
            UsageDim::Kind => SERIES_INSTANCE_KIND.to_string(),
            UsageDim::Instance => dims.instance.clone(),
        })
        .collect::<Vec<_>>()
        .join("\u{1f}");
    let cell = cells.entry(sort).or_insert_with(|| SeriesCell {
        bucket,
        dims: dims.clone(),
        rollup: UsageRollup::default(),
        priced: true,
    });
    cell.rollup.add(row)?;
    cell.priced &= priced;
    Ok(())
}

/// One day of usage: its start, its fetched counts and its observations.
type UsageDay = (u64, (FetchedUsage<Count>, Vec<ObservationRecord>));

/// The whole range, priced row by row exactly as the single-day read prices, then summed per
/// requested dimension tuple. An unpriced lane or class makes its cell `priced: false` with a null
/// spend; it never refuses the read.
pub(super) fn project_usage_series(
    cost: Arc<busbar_kernel::cost::CostModel>,
    history: Option<Arc<busbar_kernel::cost::History>>,
    snapshot: Option<busbar_kernel::cost::EntryKey>,
    now: u64,
    days: Vec<UsageDay>,
    spec: &SeriesSpec,
) -> Result<crate::v1::contract::UsageSeries, AdminError> {
    use crate::v1::contract::{SeriesUsage, UsageSeries, UsageSeriesRow};
    let view = history.as_deref().map(|h| match snapshot {
        Some(at) => h.snapshot(at),
        None => h.current(),
    });
    let mut priced_by = None;
    let mut cells = std::collections::BTreeMap::new();
    for (bucket, ((mut rows, _names, adjustments), records)) in days {
        if let Err(why) = super::fold_adjustments_exact(&mut rows, &adjustments) {
            diag_error!(
                ADMIN_STORE_OPERATION_FAILED,
                operation = "usage.adjustments",
                error = %why,
                "admin store operation failed"
            );
            return Err(AdminError::Internal);
        }
        for r in &rows {
            let dims = DimValues::of(
                &r.key_id,
                &r.key_group_at_use,
                &r.model,
                &r.provider,
                row_instance(&r.provider),
            );
            if !dims.admitted(&spec.filters) {
                continue;
            }
            let priced = price_metering_row(&cost, view.as_ref(), bucket, r, true)?;
            priced_by = priced_by.max(priced.card);
            fold_series(
                &mut cells,
                spec,
                bucket,
                &dims,
                &priced.rollup,
                priced.priced,
            )?;
        }
        for record in records
            .into_iter()
            .filter(|r| bucket <= r.rate_time && r.rate_time < bucket + METERING_DAY)
        {
            let (row, _raw) = observation_rollup(&record)?;
            let dims = DimValues::of(
                &record.principal,
                &record.group,
                observation_subject(&record.rated_subject),
                &record.destination,
                record.instance.clone(),
            );
            if dims.admitted(&spec.filters) {
                fold_series(&mut cells, spec, bucket, &dims, &row, true)?;
            }
        }
    }
    let has = |dim| spec.group_by.contains(&dim);
    let items = cells
        .into_iter()
        .map(|(sort, cell)| {
            Ok(UsageSeriesRow {
                bucket_start: has(UsageDim::Bucket).then_some(cell.bucket),
                key: has(UsageDim::Key).then(|| cell.dims.key.clone()),
                group: has(UsageDim::Group).then(|| cell.dims.group.clone()),
                model: has(UsageDim::Model).then(|| cell.dims.model.clone()),
                provider: has(UsageDim::Provider).then(|| cell.dims.provider.clone()),
                kind: has(UsageDim::Kind).then(|| SERIES_INSTANCE_KIND.to_string()),
                instance: has(UsageDim::Instance).then(|| cell.dims.instance.clone()),
                usage: SeriesUsage::of(cell.rollup.project()?, cell.priced),
                sort,
            })
        })
        .collect::<Result<Vec<_>, AdminError>>()?;
    Ok(UsageSeries {
        currency: (),
        as_of: now,
        rate_card_version: priced_by.map(|key: busbar_kernel::cost::EntryKey| key.hex()),
        items,
        next_cursor: None,
    })
}

/// `YYYY-MM-DD` (UTC) to the epoch second of that day's start. Strict: four-digit year, two-digit
/// month and day, a real calendar day.
pub(crate) fn parse_utc_day(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |s: &str| {
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse::<i64>().ok())
            .flatten()
    };
    let (y, m, d) = (num(&text[0..4])?, num(&text[5..7])?, num(&text[8..10])?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if d < 1 || d > month_days {
        return None;
    }
    // Days from civil (Hinnant): the proleptic Gregorian day number relative to 1970-01-01.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days).ok()?.checked_mul(METERING_DAY)
}

const METERING_DAY: u64 = busbar_kernel::governance::METERING_BUCKET_SECS;

/// One metering row, priced: its rollup, the history entry that priced it, and whether every class
/// priced. `lenient` (range reads, V9) turns an unpriced lane or class into `priced == false` with
/// zero spend instead of a refusal.
struct PricedRow {
    rollup: UsageRollup,
    card: Option<busbar_kernel::cost::EntryKey>,
    priced: bool,
}

fn price_metering_row(
    cost: &busbar_kernel::cost::CostModel,
    view: Option<&busbar_kernel::cost::HistoryView<'_>>,
    window_start: u64,
    r: &busbar_kernel::governance::MeteringRow,
    lenient: bool,
) -> Result<PricedRow, AdminError> {
    let lane = row_lane(&r.model, &r.provider);
    let mut row = UsageRollup {
        usage: UsageBreakdown {
            tokens_input: Count::from_micros(r.tokens_input),
            tokens_output: Count::from_micros(r.tokens_output),
            tokens_cache_read: Count::from_micros(r.tokens_cache_read),
            tokens_cache_creation: Count::from_micros(r.tokens_cache_write),
            requests: r.requests,
            ..Default::default()
        },
        ..Default::default()
    };
    let at = row_priced_at_ms(window_start, r.priced_from_ms);
    let resolved = view
        .map(|v| row_card(v, r, at))
        .transpose()
        .map_err(|e| usage_refusal("usage.price", &e))?;
    let mut priced = true;
    let classes: std::collections::BTreeMap<String, Count> = r
        .usage_units
        .iter()
        .map(|(class, n)| (class.clone(), Count::from_micros(*n)))
        .collect();
    let mut price = |usage: &UsageBreakdown,
                     classes: &std::collections::BTreeMap<String, Count>| {
        let metered = metered_row(cost, &lane, usage, classes);
        match match resolved {
            Some((seq, card)) => metered.exact_at_card_seq(seq, card),
            None => metered.exact_at_card(cost.card()),
        } {
            Ok(exact) => Ok(exact),
            Err(
                busbar_kernel::cost::MoneyError::ClassUnpriced { .. }
                | busbar_kernel::cost::MoneyError::LaneUnpriced { .. },
            ) if lenient => {
                priced = false;
                Ok(0)
            }
            Err(e) => Err(usage_refusal("usage.price", &e)),
        }
    };
    row.exact = price(&row.usage, &classes)?;
    for (class, count) in &classes {
        if !busbar_contract::records::RESERVED_UNITS.contains(&class.as_str()) {
            let one = std::collections::BTreeMap::from([(class.clone(), *count)]);
            row.class_exact
                .insert(class.clone(), price(&UsageBreakdown::default(), &one)?);
            row.usage.classes.insert(
                class.clone(),
                ClassUsage {
                    count: *count,
                    cost: 0,
                },
            );
        }
    }
    // Price the disjoint stored classes first. Reserved usage columns are reporting
    // views only; their declared descendants must not be charged again as parent usage.
    let mut raw = classes.clone();
    for (class, count) in [
        (busbar_contract::records::UNIT_INPUT, row.usage.tokens_input),
        (
            busbar_contract::records::UNIT_OUTPUT,
            row.usage.tokens_output,
        ),
        (
            busbar_contract::records::UNIT_CACHE_READ,
            row.usage.tokens_cache_read,
        ),
        (
            busbar_contract::records::UNIT_CACHE_WRITE,
            row.usage.tokens_cache_creation,
        ),
    ] {
        // Named planes carry all raw classes in usage_units; fallback lanes use columns.
        raw.entry(class.to_string()).or_insert(count);
    }
    project_reserved_counts(&lane, &raw, &mut row.usage)?;
    Ok(PricedRow {
        rollup: row,
        card: resolved.map(|(seq, _)| seq),
        priced,
    })
}

fn project_reserved_counts(
    lane: &str,
    raw: &std::collections::BTreeMap<String, Count>,
    usage: &mut UsageBreakdown,
) -> Result<(), AdminError> {
    for (class, count) in [
        (
            busbar_contract::records::UNIT_INPUT,
            &mut usage.tokens_input,
        ),
        (
            busbar_contract::records::UNIT_OUTPUT,
            &mut usage.tokens_output,
        ),
        (
            busbar_contract::records::UNIT_CACHE_READ,
            &mut usage.tokens_cache_read,
        ),
        (
            busbar_contract::records::UNIT_CACHE_WRITE,
            &mut usage.tokens_cache_creation,
        ),
    ] {
        *count = busbar_kernel::governance::class_total(lane, raw, class)
            .map_err(|_| AdminError::Internal)?;
    }
    Ok(())
}

fn observation_subject(lane: &str) -> &str {
    lane.split_once(busbar_kernel::governance::PLANE_LANE_SEP)
        .map_or(lane, |(_, subject)| subject)
}

fn observation_rollup(
    record: &ObservationRecord,
) -> Result<(UsageRollup, std::collections::BTreeMap<String, Count>), AdminError> {
    let mut raw = std::collections::BTreeMap::new();
    let mut row = UsageRollup {
        // The durable settlement is authoritative. Never reprice with a current card or
        // reapply its journal to ordinary metering; both would change a committed charge.
        exact: i128::try_from(record.spent_nanos)
            .ok()
            .and_then(|n| n.checked_mul(1_000_000))
            .ok_or_else(|| rollup_refused("the observation spend left the range"))?,
        ..Default::default()
    };
    for (index, count) in &record.counts {
        let class = record
            .classes
            .get(index)
            .ok_or_else(|| rollup_refused("unknown observation class"))?;
        let rate = record
            .rates_nanos
            .get(index)
            .ok_or_else(|| rollup_refused("unpriced observation class"))?;
        if count.is_negative() || raw.insert(class.clone(), *count).is_some() {
            return Err(rollup_refused("invalid observation class counts"));
        }
        if !busbar_contract::records::RESERVED_UNITS.contains(&class.as_str()) {
            let exact = count
                .micros()
                .checked_mul(i128::from(*rate))
                .ok_or_else(|| rollup_refused("the observation class price left the range"))?;
            row.class_exact.insert(class.clone(), exact);
            row.usage.classes.insert(
                class.clone(),
                ClassUsage {
                    count: *count,
                    cost: 0,
                },
            );
        }
    }
    project_reserved_counts(&record.serving_subject, &raw, &mut row.usage)?;
    Ok((row, raw))
}

/// Read-time totals retain scale-15 prices until each complete wire view is projected.
#[derive(Default)]
struct UsageRollup {
    usage: UsageBreakdown,
    exact: i128,
    class_exact: std::collections::BTreeMap<String, i128>,
}

impl UsageRollup {
    fn add(&mut self, row: &Self) -> Result<(), AdminError> {
        for (into, value) in [
            (&mut self.usage.tokens_input, row.usage.tokens_input),
            (&mut self.usage.tokens_output, row.usage.tokens_output),
            (
                &mut self.usage.tokens_cache_read,
                row.usage.tokens_cache_read,
            ),
            (
                &mut self.usage.tokens_cache_creation,
                row.usage.tokens_cache_creation,
            ),
        ] {
            *into = into
                .checked_add(value)
                .map_err(|_| rollup_refused("the count rollup left the range"))?;
        }
        self.usage.requests = self
            .usage
            .requests
            .checked_add(row.usage.requests)
            .ok_or_else(|| rollup_refused("the request rollup left the range"))?;
        self.exact = self
            .exact
            .checked_add(row.exact)
            .ok_or_else(|| rollup_refused("the exact spend rollup left the range"))?;
        for (class, usage) in &row.usage.classes {
            let into = self.usage.classes.entry(class.clone()).or_default();
            into.count = into
                .count
                .checked_add(usage.count)
                .map_err(|_| rollup_refused("the class count rollup left the range"))?;
        }
        for (class, exact) in &row.class_exact {
            let into = self.class_exact.entry(class.clone()).or_default();
            *into = into
                .checked_add(*exact)
                .ok_or_else(|| rollup_refused("the exact class cost rollup left the range"))?;
        }
        Ok(())
    }

    fn project(mut self) -> Result<UsageBreakdown, AdminError> {
        self.usage.spend_micros = busbar_kernel::cost::Money::of_exact(self.exact)
            .micros_i64()
            .map_err(|e| usage_refusal("usage.price", &e))?;
        for (class, exact) in self.class_exact {
            self.usage.classes.entry(class).or_default().cost =
                busbar_kernel::cost::Money::of_exact(exact)
                    .micros_i64()
                    .map_err(|e| usage_refusal("usage.price", &e))?;
        }
        Ok(self.usage)
    }
}

fn linked_store_rows() -> Vec<PluginView> {
    let stores = busbar_kernel::preflight::root_rows().stores;
    let row = |s: &busbar_kernel::preflight::LinkedStore| {
        PluginView::basic(s.0.to_string(), "store", "compiled-in", None, None)
    };
    stores.iter().map(row).collect()
}

pub(super) fn linked_plugin_view(
    row: busbar_contract::plugin_rows::Row,
    kind: &'static str,
) -> PluginView {
    let (schema_url, schema_error) =
        manifest_schema_url_and_error(&row.name, row.settings_schema.as_deref());
    let mut view = PluginView::basic(row.name, kind, "compiled-in", None, None);
    view.has_schema = schema_url.is_some();
    view.schema_url = schema_url;
    view.schema_error = schema_error;
    view.version = Some(row.version);
    view.interface_version = Some(row.abi_version);
    view.valid = Some(true);
    match row.trust {
        busbar_contract::plugin_rows::Trust::Trusted { publisher, .. } => {
            view.trust = Some("trusted");
            view.publisher = Some(publisher);
        }
        busbar_contract::plugin_rows::Trust::Allowed { .. } => view.trust = Some("unverified"),
    }
    view
}

fn linked_configuration_view(stated: Stated) -> PluginView {
    let kind = match stated.kind.as_str() {
        "plane" => "plane",
        "transport" => "transport",
        _ => "unknown",
    };
    let (schema_url, schema_error) =
        manifest_schema_url_and_error(&stated.name, stated.settings_schema.as_deref());
    let configuration = crate::v1::plugin_configuration::configuration(
        &stated.kind,
        stated.configuration.as_ref(),
        "linked_statement",
        true,
    );
    let mut view = PluginView::basic(stated.name, kind, "compiled-in", None, None);
    view.version = Some(stated.version);
    view.interface_version = Some(stated.abi_version);
    view.publisher = Some(stated.publisher);
    view.trust = Some("trusted");
    view.valid = Some(true);
    view.has_schema = schema_url.is_some();
    view.schema_url = schema_url.map(|url| format!("{url}?source=linked_statement"));
    view.schema_error = schema_error;
    view.configuration = Some(configuration);
    view
}

fn rollup_refused(error: &'static str) -> AdminError {
    diag_error!(
        ADMIN_STORE_OPERATION_FAILED,
        operation = "usage.price",
        error = error,
        "admin store operation failed"
    );
    AdminError::Internal
}

/// The validate unit, behind the plugin scan gate: phase 1 over `plugins` (the body's policy with
/// the server's directory and the Store's pins), the body typed under that grammar, then the same
/// operator-file-policy pre-check and configuration checks apply runs. `Ok(Err(_))` is the
/// operator-file-policy refusal.
fn validate_config_blocking(
    config: serde_json::Value,
    defs: std::collections::HashMap<String, busbar_kernel::config::ProviderDef>,
    parse: crate::v1::json::BodyParser,
    plugins: busbar_kernel::config::PluginsCfg,
    rules: &std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>,
    reference: std::sync::Arc<busbar_kernel::config::OperatorFileDefs>,
) -> Result<Result<ConfigValidateView, AdminError>, AdminError> {
    let grammar = super::phase_one(
        &plugins,
        busbar_kernel::config::grammar::Fetch::None,
        "config.validate",
    )?;
    let deploy = crate::v1::json::typed_body(config, &grammar, parse)?;
    // A dry run never says yes to what apply refuses: the same pre-check, status and text.
    if let Some(refusal) =
        crate::v1::json::config_body_refusal(&deploy, &reference, "config.validate")
    {
        return Ok(Err(refusal));
    }
    let mut root = match busbar_kernel::config::resolve(&deploy, &defs) {
        Ok(root) => root,
        Err(errors) => return Ok(Ok(ConfigValidateView { ok: false, errors })),
    };
    // A body is held to the running generation's disk reference (OPERATOR-FROM-ADMITTED-AUTH §3.6.1).
    root.operator_file_defs = Some(reference);

    let root_rules = |c: &busbar_kernel::config::RootCfg| rules.check(c);
    let checked = busbar_kernel::config_validate::check(
        &root,
        busbar_kernel::config_validate::Check {
            plugins: &plugins,
            unset_env_vars: &[],
            root: &root_rules,
            fetch: None,
            resolve_builtins: false,
            secret_axis: busbar_kernel::config::secret::live_axis(),
        },
    );
    let ok = checked.is_ok();
    let errors = match checked {
        Ok(_) => Vec::new(),
        Err(busbar_kernel::config_validate::Refusal::Config(errors)) => errors,
        Err(
            busbar_kernel::config_validate::Refusal::Root(e)
            | busbar_kernel::config_validate::Refusal::Plugins(e)
            | busbar_kernel::config_validate::Refusal::Unresolved(e),
        ) => vec![e],
    };
    Ok(Ok(ConfigValidateView { ok, errors }))
}

fn read_guarded_archive(
    dir: &Path,
    file: &str,
    expected: Option<&str>,
    cap: u64,
) -> Result<Vec<u8>, AdminError> {
    let missing = || {
        if expected.is_some() {
            AdminError::Conflict("plugin archive preimage changed or is missing".into())
        } else {
            AdminError::not_found(format!("plugin `{file}`"))
        }
    };
    // `file` is admin-API input (a validated bare name); it opens only as a regular file inside
    // the operator-configured plugins dir, never through a link.
    let archive = match ConfinedRoot::new(dir).and_then(|root| root.open(file)) {
        Ok(archive) => archive,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(missing()),
        Err(error) => return Err(plugin_path_refused(file, error)),
    };
    if !archive.metadata().is_ok_and(|meta| meta.is_file()) {
        return Err(missing());
    }
    read_bounded(archive, cap)
        .map_err(|error| AdminError::Validation(format!("cannot read plugin `{file}`: {error}")))
}

/// `file` (admin-API input, already a validated bare name) confined to the operator-configured
/// plugins dir: refused when it resolves through or to a link.
fn confined_plugin_path(dir: &Path, file: &str) -> Result<PathBuf, AdminError> {
    ConfinedRoot::new(dir)
        .and_then(|root| root.resolve(file))
        .map_err(|error| plugin_path_refused(file, error))
}

fn plugin_path_refused(file: &str, error: ConfinedPathError) -> AdminError {
    if error.kind() == std::io::ErrorKind::NotFound {
        return AdminError::not_found(format!("plugin `{file}`"));
    }
    AdminError::Validation(format!(
        "plugin `{file}` must be a regular file inside the plugins directory: {error}"
    ))
}

fn check_archive_preimage(expected: Option<&str>, bytes: &[u8]) -> Result<(), AdminError> {
    if expected.is_some_and(|expected| expected != busbar_contract::redacted::sha256_hex(bytes)) {
        return Err(AdminError::Conflict(
            "plugin archive preimage changed or is missing".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Plugin archive reads on this thread (WASTE-CORE-LIFECYCLE W7 count tests).
    pub(super) static ARCHIVE_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Read `file` from `dir` (an archive name the admission inventory listed there), confined to
/// `dir` and bounded by `cap`.
pub(super) fn read_archive_bounded(dir: &Path, file: &str, cap: u64) -> std::io::Result<Vec<u8>> {
    read_bounded(ConfinedRoot::new(dir)?.open(file)?, cap)
}

/// Read an already-opened (confined) archive handle, bounded by `cap`.
pub(super) fn read_bounded(archive: std::fs::File, cap: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    #[cfg(test)]
    ARCHIVE_READS.with(|reads| reads.set(reads.get() + 1));
    let mut bytes = Vec::new();
    archive
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "plugin archive exceeds the admission size cap",
        ));
    }
    Ok(bytes)
}

fn archive_path_segment(file: &str) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::new();
    for byte in file.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

#[cfg(test)]
mod exact_usage_rollup_tests {
    use super::*;

    #[test]
    fn class_cost_and_overflow_are_projected_only_after_aggregation() {
        let row = UsageRollup {
            usage: UsageBreakdown {
                classes: std::collections::BTreeMap::from([(
                    "seconds".into(),
                    ClassUsage {
                        count: Count::parse("0.5").unwrap(),
                        cost: 0,
                    },
                )]),
                ..Default::default()
            },
            exact: 500_000_000,
            class_exact: std::collections::BTreeMap::from([("seconds".into(), 500_000_000)]),
        };
        let mut total = UsageRollup::default();
        total.add(&row).unwrap();
        total.add(&row).unwrap();
        let view = total.project().unwrap();
        assert_eq!(view.spend_micros, 1);
        assert_eq!(view.classes["seconds"].cost, 1);
        assert_eq!(view.classes["seconds"].count, Count::ONE);
        assert!(UsageRollup {
            exact: i128::MAX,
            ..Default::default()
        }
        .project()
        .is_err());
        let mut overflow = UsageRollup {
            exact: i128::MAX,
            ..Default::default()
        };
        assert!(overflow.add(&row).is_err());
    }
}
