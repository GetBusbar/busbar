// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::admission::{Judged, PluginAdmission, Refusal, Stated};
use busbar_kernel::config::groups::LimitMetric;

pub(crate) fn admission(app: &App) -> Result<&'static dyn PluginAdmission, String> {
    app.plugins_cfg.warn_invalid_floors();
    app.plugin_admission
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

    #[cfg(test)]
    pub(crate) fn with_rate_history(mut self, history: Arc<busbar_kernel::cost::History>) -> Self {
        self.rate_history = Some(history);
        self
    }

    pub(crate) async fn info(&self) -> Result<InfoView, AdminError> {
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
            topology: TopologyInfo {
                pools: view.pools().len(),
                models: view.model_indices().len(),
                providers: providers.len(),
            },
            config_persistence: self.app.overlay_path.is_some(),
            config_version: self.app.config_version,
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

    pub(crate) async fn get_pool(&self, name: &str) -> Result<PoolDetailView, AdminError> {
        let view = self.app.engine_tables_view();

        if !view.pools().iter().any(|(n, _)| *n == name) {
            return Err(AdminError::not_found(format!("pool `{name}`")));
        }
        let members = view.pool_members(name);
        Ok(self.pool_detail(name, &members))
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

    pub(crate) async fn list_named_defs(
        &self,
        section: NamedMapSection,
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

        for (name, entry) in self.unparseable_overlay_entries(section).await? {
            if !defs.iter().any(|d| d.name == name) {
                defs.push(unparseable_def_view(&name, &entry));
            }
        }
        defs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(defs))
    }

    pub(crate) async fn get_named_def(
        &self,
        section: NamedMapSection,
        name: &str,
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

        self.unparseable_overlay_entries(section)
            .await?
            .get(name)
            .map(|entry| unparseable_def_view(name, entry))
            .ok_or_else(|| AdminError::not_found(format!("{} `{name}`", section.singular())))
    }

    async fn unparseable_overlay_entries(
        &self,
        section: NamedMapSection,
    ) -> Result<
        std::collections::BTreeMap<String, busbar_kernel::config::overlay::UnparseableNamedDef>,
        AdminError,
    > {
        let overlay = self.app.overlay_path.clone();

        let dispatch = tracing::dispatcher::get_default(|d| d.clone());
        tokio::task::spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                busbar_kernel::config::overlay::unparseable_named_map_entries(
                    overlay.as_deref(),
                    section,
                )
            })
        })
        .await
        .map_err(|join_err| {
            diag_error!(
                ADMIN_STORE_TASK_JOIN_FAILED,
                operation = "named_defs.overlay",
                error = %join_err,
                "admin blocking task failed"
            );
            AdminError::Internal
        })?
        .map_err(AdminError::Validation)
    }

    pub(crate) async fn list_groups(
        &self,
        start: usize,
        limit: usize,
    ) -> Result<Page<GroupView>, AdminError> {
        let registry = &self.app.groups_registry;
        let total = registry.len();
        let items: Vec<GroupView> = registry
            .iter()
            .skip(start)
            .take(limit)
            .map(|(name, cfg)| GroupView::from_cfg(name, cfg))
            .collect();
        let end = start.saturating_add(items.len());
        let next_cursor = (end < total).then(|| crate::v1::contract::encode_offset_cursor(end));
        Ok(Page { items, next_cursor })
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
                tokio::task::spawn_blocking(move || {
                    wanted
                        .iter()
                        .map(|(id, window)| {
                            gov.derived_bucket_usage_priced(&cost, id, window, true, now)
                        })
                        .collect::<Vec<_>>()
                })
                .await
                .map_err(|e| {
                    busbar_kernel::diagnostics::diag_error!(
                        busbar_kernel::diagnostics::GROUP_USAGE_READ_FAILED,
                        group = name, err = %e,
                        "group usage read failed"
                    );
                    AdminError::Internal
                })?
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
                tokens_input_cap: b.class_cap(LimitMetric::TokensInput),
                tokens_output_cap: b.class_cap(LimitMetric::TokensOutput),
                tokens_cache_read_cap: b.class_cap(LimitMetric::TokensCacheRead),
                tokens_cache_write_cap: b.class_cap(LimitMetric::TokensCacheWrite),
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

    pub(crate) async fn list_plugins(&self, ptype: &str) -> Result<Page<PluginView>, AdminError> {
        let mut plugins: Vec<PluginView> = Vec::new();
        match ptype {
            "auth" => {
                let chain = self.app.auth.chain_names();
                for name in auth_modules_compiled_in() {
                    let active = if name == busbar_kernel::config::KEYS_MODULE {
                        self.app.auth.keys_in_chain
                    } else if name == busbar_kernel::config::operator_provider() {
                        let op = &self.app.admin_modules.operator;
                        self.app.admin_chain.iter().any(|m| op.is(m))
                    } else {
                        chain.iter().any(|c| c == name)
                    };
                    plugins.push(PluginView::basic(
                        name.to_string(),
                        "auth",
                        "compiled-in",
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

                let mut dynamic_auth: Vec<PluginView> = self
                    .store_plugin_catalog_async()
                    .await?
                    .into_iter()
                    .filter(|p| p.r#type == "auth")
                    .collect();
                plugins.append(&mut dynamic_auth);
            }
            "hooks" => {
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
            }

            "store" | "db" => {
                plugins.extend(
                    self.store_plugin_catalog_async()
                        .await?
                        .into_iter()
                        .filter(|p| p.r#type == "store"),
                );
            }

            "secret" => {
                plugins.extend(
                    self.store_plugin_catalog_async()
                        .await?
                        .into_iter()
                        .filter(|p| p.r#type == "secret"),
                );
            }
            other => {
                return Err(AdminError::Validation(format!(
                    "unknown plugin type `{other}`: expected `auth`, `hooks`, `secret`, or `store`"
                )));
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

        catalog_cache().lock().unwrap().retain(|_, e| {
            e.inserted_at <= now && now.saturating_sub(e.inserted_at) < CATALOG_CACHE_TTL_SECS
        });

        static FINGERPRINT_WARNED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        let before = match plugins_dir_fingerprint(&self.app.plugins_dir) {
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

            if matches!(plugins_dir_fingerprint(&self.app.plugins_dir), Ok(after) if after == before)
            {
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
        catalog_scan_test_hook!(dir);
        let mut rows = Vec::new();

        let Ok(inventory) = admission.inventory(dir, cfg) else {
            return rows;
        };
        for row in inventory {
            let trust = if row.status == "ready" {
                if row.signature == "first-party" || row.signature.starts_with("publisher:") {
                    Some("trusted")
                } else {
                    Some("unverified")
                }
            } else if row.stated.is_some() {
                Some("rejected")
            } else {
                None
            };
            let name = row
                .stated
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_else(|| row.file.clone());

            let r#type = match row.stated.as_ref().map(|m| m.kind.as_str()) {
                Some("secret") => "secret",
                Some("auth") => "auth",
                Some("hook") => "hook",
                Some("export") => "export",
                Some("transport") => "transport",
                Some("plane") => "plane",
                _ => "store",
            };

            let (schema_url, schema_error) = match row.stated.as_ref() {
                Some(m) => manifest_schema_url_and_error(&name, m.settings_schema.as_deref()),
                None => (None, None),
            };
            rows.push(PluginView {
                name,
                r#type,
                loader: "dynamic-library",
                active: None,
                target: Some(row.file.clone()),
                file: Some(row.file.clone()),
                has_schema: schema_url.is_some(),
                version: row.stated.as_ref().map(|m| m.version.clone()),
                publisher: row.stated.as_ref().map(|m| m.publisher.clone()),
                interface_version: row.stated.as_ref().map(|m| m.abi_version),
                trust,
                valid: Some(row.status == "ready"),
                error: (row.status != "ready").then(|| row.status.clone()),
                schema_url,
                schema_error,
            });
        }
        rows
    }

    async fn store_plugin_catalog_async(&self) -> Result<Vec<PluginView>, AdminError> {
        let _gate = match tokio::time::timeout(CATALOG_SCAN_GATE_WAIT, CATALOG_SCAN_GATE.lock())
            .await
        {
            Ok(guard) => guard,
            Err(_elapsed) => {
                diag_warn!(
                    PLUGIN_CATALOG_SCAN_GATE_TIMEOUT,
                    operation = "list_plugins.store",
                    wait = ?CATALOG_SCAN_GATE_WAIT,
                    "catalog scan gate could not be acquired within the wait bound; a prior scan \
                     is not returning (e.g. a stale/hung plugins_dir mount). Answering with a \
                     retryable error rather than hanging this request too."
                );
                return Err(AdminError::Unavailable(
                    "the plugin catalog scan is taking too long; try again shortly".to_string(),
                ));
            }
        };
        let app = self.app.clone();
        match tokio::task::spawn_blocking(move || AdminService::new(app).store_plugin_catalog())
            .await
        {
            Ok(rows) => Ok(rows),
            Err(join_err) => {
                diag_warn!(
                    PLUGIN_CATALOG_BLOCKING_TASK_FAILED,
                    operation = "list_plugins.store",
                    error = %join_err,
                    "admin blocking task failed"
                );

                Ok(linked_store_rows())
            }
        }
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
        let final_path = dir.join(&file);
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

    pub(crate) fn remove_store_plugin(
        &self,
        file: &str,
    ) -> Result<crate::v1::contract::PluginRemoveView, AdminError> {
        let file = validate_plugin_filename(&self.app, file)?;
        let lib_path = self.app.plugins_dir.join(&file);
        if !lib_path.is_file() {
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

    pub(crate) fn resolve_plugin_rollback(
        &self,
        file: &str,
        prior_pins: &std::collections::BTreeMap<String, String>,
    ) -> Result<(Stated, std::collections::BTreeMap<String, String>), AdminError> {
        let file = validate_plugin_filename(&self.app, file)?;
        let lib_path = self.app.plugins_dir.join(&file);
        if !lib_path.is_file() {
            return Err(AdminError::not_found(format!("plugin `{file}`")));
        }
        let bytes = std::fs::read(&lib_path)
            .map_err(|e| AdminError::Validation(format!("cannot read plugin `{file}`: {e}")))?;

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
            self.app.providers_path.as_deref(),
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
            auth: self.get_auth().await?,
            pools: self.list_pools().await?.items,
            models: self.list_models().await?.items,
            providers: self.list_providers().await?.items,
            hooks: self.list_hooks().await?.items,
            global_hooks: self.app.global_hooks.clone(),
            reload_to_apply: self.app.planes_awaiting_restart.clone(),
        })
    }

    pub(crate) async fn validate_config(
        &self,
        deploy: DeployCfg,
        defs: std::collections::HashMap<String, ProviderDef>,
    ) -> Result<ConfigValidateView, AdminError> {
        let _gate = match tokio::time::timeout(CATALOG_SCAN_GATE_WAIT, CATALOG_SCAN_GATE.lock())
            .await
        {
            Ok(guard) => guard,
            Err(_elapsed) => {
                diag_warn!(
                    PLUGIN_CATALOG_SCAN_GATE_TIMEOUT,
                    operation = "config.validate",
                    wait = ?CATALOG_SCAN_GATE_WAIT,
                    "plugin scan gate could not be acquired within the wait bound; a prior scan \
                     is not returning (e.g. a stale/hung plugins_dir mount). Answering with a \
                     retryable error rather than hanging this request too."
                );
                return Err(AdminError::Unavailable(
                    "the plugin directory scan is taking too long; try again shortly".to_string(),
                ));
            }
        };
        let plugins_dir = self.app.plugins_dir.to_string_lossy().into_owned();

        let rules = std::sync::Arc::clone(&self.app.root_rules);
        match tokio::task::spawn_blocking(move || {
            validate_config_blocking(deploy, &defs, plugins_dir, &rules)
        })
        .await
        {
            Ok(view) => Ok(view),
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
        Ok(AdminAuthView {
            configured: !modules.is_empty(),
            modules,
        })
    }

    fn validated_snapshot(
        history: Option<&busbar_kernel::cost::History>,
        key: busbar_kernel::cost::EntryKey,
    ) -> Result<busbar_kernel::cost::EntryKey, AdminError> {
        let history = history
            .filter(|history| !history.is_empty())
            .ok_or_else(|| {
                AdminError::Validation(
                    "as_of names a rate-card history snapshot; this node has resolved no \
                 rate-card history to snapshot"
                        .into(),
                )
            })?;
        if history.entry(&key).is_none() {
            return Err(AdminError::Validation(format!(
                "as_of {} does not name a known rate-card history entry; an unknown snapshot \
                 is refused, never interpreted as a list position",
                key.hex()
            )));
        }
        Ok(key)
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
            Some(key) => Some(Self::validated_snapshot(history.as_deref(), key)?),
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
        };
        let Some(gov) = self.app.governance.clone() else {
            return Ok(empty());
        };
        type Fetched = (
            Vec<busbar_kernel::governance::MeteringRow>,
            std::collections::HashMap<String, String>,
            Vec<busbar_kernel::governance::UsageAdjustment>,
        );
        type UsageFetchError = (&'static str, busbar_kernel::governance::RecordStoreError);
        let joined = tokio::task::spawn_blocking(move || -> Result<Fetched, UsageFetchError> {
            let rows = gov
                .metering_for(bucket)
                .map_err(|e| ("usage.metering", e))?;

            let names = gov
                .all_keys()
                .map_err(|e| ("usage.keys", e))?
                .into_iter()
                .map(|k| (k.id, k.name))
                .collect();

            let adjustments = gov
                .usage_adjustments(bucket)
                .map_err(|e| ("usage.adjustments", e))?;
            Ok((rows, names, adjustments))
        })
        .await;
        let cost = self.app.cost.clone();
        let (mut rows, names, adjustments) = match joined {
            Ok(Ok(f)) => f,

            Ok(Err((operation, e))) => {
                diag_error!(ADMIN_STORE_OPERATION_FAILED, operation, error = %e, "admin store operation failed");
                return Err(AdminError::Internal);
            }
            Err(join_err) => {
                diag_error!(
                    USAGE_BLOCKING_TASK_JOIN_FAILED,
                    operation = "usage",
                    error = %join_err,
                    "admin blocking task failed"
                );
                return Err(AdminError::Internal);
            }
        };

        let view = history.as_deref().map(|h| match snapshot {
            Some(at) => h.snapshot(at),
            None => h.current(),
        });

        let mut priced_by: Option<busbar_kernel::cost::EntryKey> = None;

        if let Err(why) = fold_adjustments(&mut rows, &adjustments) {
            diag_error!(
                ADMIN_STORE_OPERATION_FAILED,
                operation = "usage.adjustments",
                error = %why,
                "admin store operation failed"
            );
            return Err(AdminError::Internal);
        }

        let mut total = UsageBreakdown::default();
        let mut by_model: std::collections::BTreeMap<(String, String), UsageBreakdown> =
            std::collections::BTreeMap::new();
        let mut by_key: std::collections::BTreeMap<String, UsageBreakdown> =
            std::collections::BTreeMap::new();
        for r in &rows {
            let lane = row_lane(&r.model, &r.provider);

            let mut row_view = UsageBreakdown {
                tokens_input: r.tokens_input,
                tokens_output: r.tokens_output,
                tokens_cache_read: r.tokens_cache_read,

                tokens_cache_creation: r.tokens_cache_write,
                requests: r.requests,
                spend_micros: 0,
                classes: std::collections::BTreeMap::new(),
            };

            let at = row_priced_at_ms(window.start, r.priced_from_ms);
            let resolved = view
                .as_ref()
                .map(|v| row_card(v, r, at))
                .transpose()
                .map_err(|e| usage_refusal("usage.price", &e))?;

            let classes: &std::collections::BTreeMap<String, u64> = &r.usage_units;
            let row_spend = match resolved {
                Some((card_seq, card)) => {
                    priced_by = priced_by.max(Some(card_seq));
                    derive_spend_micros_row_classes_at_entry(
                        card_seq, card, &cost, &lane, &row_view, classes,
                    )
                }
                None => derive_spend_micros_row_classes(&cost, &lane, &row_view, classes),
            };

            let row_spend = match row_spend {
                Ok(spend) => spend,
                Err(e) => return Err(usage_refusal("usage.price", &e)),
            };

            let none = UsageBreakdown::default();
            let unitemized = std::collections::BTreeMap::new();
            let itemized = if row_carries_classes(&r.provider) {
                classes
            } else {
                &unitemized
            };
            for (class, count) in itemized {
                let one = std::collections::BTreeMap::from([(class.clone(), *count)]);
                let class_cost = match resolved {
                    Some((card_seq, card)) => derive_spend_micros_row_classes_at_entry(
                        card_seq, card, &cost, &lane, &none, &one,
                    ),
                    None => derive_spend_micros_row_classes(&cost, &lane, &none, &one),
                }
                .map_err(|e| usage_refusal("usage.price", &e))?;
                row_view.classes.insert(
                    class.clone(),
                    ClassUsage {
                        count: *count,
                        cost: class_cost,
                    },
                );
            }
            for b in [
                &mut total,
                by_model
                    .entry((r.model.clone(), r.provider.clone()))
                    .or_default(),
                by_key.entry(r.key_id.clone()).or_default(),
            ] {
                b.tokens_input = b.tokens_input.saturating_add(row_view.tokens_input);
                b.tokens_output = b.tokens_output.saturating_add(row_view.tokens_output);
                b.tokens_cache_read = b
                    .tokens_cache_read
                    .saturating_add(row_view.tokens_cache_read);
                b.tokens_cache_creation = b
                    .tokens_cache_creation
                    .saturating_add(row_view.tokens_cache_creation);
                b.requests = b.requests.saturating_add(r.requests);
                if add_classes(&mut b.classes, &row_view.classes).is_none() {
                    diag_error!(
                        ADMIN_STORE_OPERATION_FAILED,
                        operation = "usage.price",
                        error = "a class cost rollup left the representable range",
                        "admin store operation failed"
                    );
                    return Err(AdminError::Internal);
                }

                b.spend_micros = match busbar_kernel::cost::sum_spend(b.spend_micros, row_spend) {
                    Ok(sum) => sum,
                    Err(_) => {
                        diag_error!(
                            ADMIN_STORE_OPERATION_FAILED,
                            operation = "usage.price",
                            error = "the spend rollup left the representable range",
                            "admin store operation failed"
                        );
                        return Err(AdminError::Internal);
                    }
                };
            }
        }
        let by_model = by_model
            .into_iter()
            .map(|((model, provider), usage)| ModelUsageView {
                model,
                upstream: provider,
                usage,
            })
            .collect();
        let mut by_key: Vec<KeyUsageView> = by_key
            .into_iter()
            .map(|(id, usage)| KeyUsageView {
                name: names.get(&id).cloned(),
                id,
                usage,
            })
            .collect();

        const BY_KEY_CAP: usize = 1000;
        by_key.sort_by(|a, b| {
            b.usage
                .spend_micros
                .cmp(&a.usage.spend_micros)
                .then_with(|| a.id.cmp(&b.id))
        });
        let by_key_truncated = by_key.len() > BY_KEY_CAP;

        let others = if by_key_truncated {
            let mut o = UsageBreakdown::default();
            for row in &by_key[BY_KEY_CAP..] {
                o.tokens_input = o.tokens_input.saturating_add(row.usage.tokens_input);
                o.tokens_output = o.tokens_output.saturating_add(row.usage.tokens_output);
                o.tokens_cache_read = o
                    .tokens_cache_read
                    .saturating_add(row.usage.tokens_cache_read);
                o.tokens_cache_creation = o
                    .tokens_cache_creation
                    .saturating_add(row.usage.tokens_cache_creation);
                o.requests = o.requests.saturating_add(row.usage.requests);

                o.spend_micros =
                    busbar_kernel::cost::sum_spend(o.spend_micros, row.usage.spend_micros)
                        .map_err(|_| rollup_refused("the others spend rollup left the range"))?;
                for (class, u) in &row.usage.classes {
                    let e = o.classes.entry(class.clone()).or_default();
                    e.count = e.count.saturating_add(u.count);
                    e.cost = busbar_kernel::cost::sum_spend(e.cost, u.cost)
                        .map_err(|_| rollup_refused("the others class cost left the range"))?;
                }
            }
            Some(o)
        } else {
            None
        };
        by_key.truncate(BY_KEY_CAP);
        Ok(UsageView {
            window,
            as_of: now,
            currency: (),
            rate_card_version: priced_by.map(|key| key.hex()),
            total,
            by_model,
            by_key,
            by_key_truncated,
            others,
        })
    }

    pub(crate) async fn get_auth(&self) -> Result<AuthView, AdminError> {
        let chain = self.app.auth.chain_names();
        Ok(AuthView {
            open: chain.is_empty(),
            chain,
            upstream_credentials: match self.app.upstream_creds() {
                busbar_kernel::auth::UpstreamCreds::Own => "own",
                busbar_kernel::auth::UpstreamCreds::Passthrough => "passthrough",
            },
        })
    }

    pub(crate) async fn hook_health(&self, name: &str) -> Result<HookHealthView, AdminError> {
        let cfg = self
            .app
            .hook_registry
            .get(name)
            .ok_or_else(|| AdminError::not_found(format!("hook `{name}`")))?;
        let view = self.hook_view(name, cfg);
        let (reachable, detail) = probe_transport(cfg, &self.app.hook_env).await;
        Ok(HookHealthView {
            name: name.to_string(),
            transport: view.transport,
            reachable,
            detail,
        })
    }

    fn hook_view(&self, name: &str, cfg: &HookCfg) -> HookView {
        project_hook_view(name, cfg, &self.app.global_hooks)
    }
}

fn linked_store_rows() -> Vec<PluginView> {
    let stores = busbar_kernel::preflight::root_rows().stores;
    let row = |s: &busbar_kernel::preflight::LinkedStore| {
        PluginView::basic(s.0.to_string(), "store", "compiled-in", None, None)
    };
    stores.iter().map(row).collect()
}

fn add_classes(
    into: &mut std::collections::BTreeMap<String, ClassUsage>,
    row: &std::collections::BTreeMap<String, ClassUsage>,
) -> Option<()> {
    for (class, u) in row {
        let e = into.entry(class.clone()).or_default();
        e.count = e.count.saturating_add(u.count);
        e.cost = busbar_kernel::cost::sum_spend(e.cost, u.cost).ok()?;
    }
    Some(())
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

fn validate_config_blocking(
    mut deploy: DeployCfg,
    defs: &std::collections::HashMap<String, ProviderDef>,
    plugins_dir: String,
    rules: &std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>,
) -> ConfigValidateView {
    let root = match busbar_kernel::config::resolve(&deploy, defs) {
        Ok(root) => root,
        Err(errors) => return ConfigValidateView { ok: false, errors },
    };

    deploy.plugins.dir = plugins_dir;

    let root_rules = |c: &busbar_kernel::config::RootCfg| rules.check(c);
    let checked = busbar_kernel::config_validate::check(
        &root,
        busbar_kernel::config_validate::Check {
            plugins: &deploy.plugins,
            unset_env_vars: &[],
            root: &root_rules,
            fetch: None,
            resolve_builtins: false,
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
    ConfigValidateView { ok, errors }
}
