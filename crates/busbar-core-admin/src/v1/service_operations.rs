// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY ADMIN v1 OPERATION — the one `impl AdminService` block, carved out of `service.rs`.
//!
//! The struct, the module-private helpers these methods call, and the view projectors they hand
//! their results to all stay in [`super`]; what lives here is the operation surface itself, which
//! was 1,570 of that file's 2,723 lines and pushed it over the `structure-lint:oversized` cap.
//!
//! A CHILD MODULE OF `service`, NOT A SIBLING — declared through `#[path]` the way the tree's other
//! carved modules are. A child sees its ancestors' private items, so one `use super::*` restores
//! every name these methods already resolved: `AdminService`'s own private fields, the private
//! helpers (`dated_rate_history`, `catalog_cache`, `validate_plugin_filename`, the `App`
//! builders), and the imports the parent module had already pulled in. That relationship is the
//! reason the move needed no rewriting — nothing here changed except the two lines it took to say
//! where the block now lives.

use super::*;
use busbar_kernel::admission::{Judged, PluginAdmission, Refusal, Stated};
use busbar_kernel::config::groups::LimitMetric;

/// THE ROOT'S PLUGIN ADMISSION — the one boot admits plugins under, carried on the snapshot
/// (`App::plugin_admission`) — after warning about any malformed anti-downgrade floor, so every
/// admin moment that judges a plugin (catalog, install, inspect, rollback) reaches boot's verdict
/// and warns exactly as boot does. No policy is built here: the admission judges under the root's
/// one trust builder over `app.plugins_cfg`.
pub(crate) fn admission(app: &App) -> Result<&'static dyn PluginAdmission, String> {
    app.plugins_cfg.warn_invalid_floors();
    app.plugin_admission
        .ok_or_else(|| "no plugin trust policy is installed (the composition root's)".to_string())
}

/// A refusal of the root's admission, in the class the operator surface answers it with.
fn refused(refusal: Refusal) -> AdminError {
    match refusal {
        Refusal::Validation(m) => AdminError::Validation(m),
        Refusal::Conflict(m) => AdminError::Conflict(m),
    }
}

impl AdminService {
    pub(crate) fn new(app: Arc<App>) -> Self {
        Self {
            app,
            rate_history: None,
        }
    }

    /// The same service, resolving usage against `history` instead of the process's.
    ///
    /// The process's history is the kernel's rate dater's, installed once — so a test that needs to
    /// drive the read against a history of its own naming pins it here rather than racing that
    /// install. Every other caller reads the process's by construction.
    #[cfg(test)]
    pub(crate) fn with_rate_history(mut self, history: Arc<busbar_kernel::cost::History>) -> Self {
        self.rate_history = Some(history);
        self
    }

    /// `GET /api/v1/admin/info` — version, the COMPILED-IN plugin sets (compliance-by-compilation proof),
    /// uptime, and pool/model/provider topology. Read scope. Infallible today, but returns `Result`
    /// for a uniform transport contract (every op is `Result<View, AdminError>`).
    pub(crate) async fn info(&self) -> Result<InfoView, AdminError> {
        // The compiled-in plugin sets reflect the ACTUAL binary: the `keys` builtin and the linked
        // auth rows, plus the ranking hooks. `weighted` is the one baked in
        // (non-removable), so it appears as `weighted_floor` below, not in `hook_plugins`.
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

    /// `GET /api/v1/admin/pools` — the pool topology (name + member models/weights). Read scope. Sorted
    /// by name for a stable, diff-friendly listing. Live per-member
    /// status is an additive follow-up.
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

    /// `GET /api/v1/admin/pools/{name}` — the LIVE per-member status of one pool (breaker/concurrency/
    /// latency/tallies), from the same store signals the routing seam ranks on. Read scope.
    /// `not_found` if the pool is unknown.
    pub(crate) async fn get_pool(&self, name: &str) -> Result<PoolDetailView, AdminError> {
        let view = self.app.engine_tables_view();
        // A pool is known iff it appears in the neutral pool label space (distinct from `pool_members`
        // returning empty, which an unknown pool also does).
        if !view.pools().iter().any(|(n, _)| *n == name) {
            return Err(AdminError::not_found(format!("pool `{name}`")));
        }
        let members = view.pool_members(name);
        Ok(self.pool_detail(name, &members))
    }

    /// Project one pool's LIVE member status — the shared core of `GET /pools/{name}` and
    /// `GET /pools?detail=true` (one projection, two readers — the shapes can never diverge). Takes the
    /// NEUTRAL `(lane idx, weight)` projection ([`EngineTablesView::pool_members`]), naming no plane type.
    fn pool_detail(&self, name: &str, members: &[(usize, u32)]) -> PoolDetailView {
        let view = self.app.engine_tables_view();
        let now = busbar_kernel::store::now();
        let members = members
            .iter()
            .map(|&(idx, weight)| {
                // `snapshot` is the same release-exposed live summary `/stats` reads (ok/err/trips/
                // dead/inflight — genuinely lane-GLOBAL counters); `available_permits` +
                // `lane_latency_ms` round it out. `usable`/`cooldown_remaining_seconds` are NOT lane
                // counters, though — routing ranks a member per-POOL (`select_weighted_in`), so this
                // endpoint reports the per-pool breaker cell via `ready_in`/`cooldown_remaining_in`,
                // NOT `snapshot`'s any-cell/max-cell lane aggregates (which would mislabel a member
                // as usable in a pool where its OWN cell is tripped, or vice versa).
                let snap = self.app.store.snapshot(idx, now);
                PoolMemberStatusView {
                    model: lane_model(view, idx),
                    weight,
                    // `ready_in`, NOT `usable_in`: `usable_in` delegates to the MUTATING `usable_for`,
                    // which can transition an expired-Open cell to HalfOpen and CAS-steal the
                    // single-flight recovery probe. `ready_in` is `select_weighted_in`'s own
                    // side-effect-free predicate — exactly what this read-only endpoint must report.
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

    /// `GET /api/v1/admin/pools?detail=true` — the WHOLE topology with live member status in ONE
    /// call (the summary + per-pool detail split forced an M+1 fan-out per dashboard refresh).
    /// Same row shape as `GET /pools/{name}` via the shared projection. Sorted by name.
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

    /// `GET /api/v1/admin/models` — every model lane + its upstream provider. Read scope. Sorted by
    /// model name. No credentials.
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

    /// `GET /api/v1/admin/providers` — distinct upstream providers + the count of model lanes routing
    /// through each. Read scope. Sorted by provider name.
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

    /// `GET /api/v1/admin/hooks` — the hook registry read. Read scope. Each entry
    /// is the DEFINITION (kind/transport/grants/ordering/stage), never a secret. Sorted by name.
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

    /// `GET /api/v1/admin/hooks/{name}` — one hook definition, or `not_found` if the name is unregistered.
    pub(crate) async fn get_hook(&self, name: &str) -> Result<HookView, AdminError> {
        self.app
            .hook_registry
            .get(name)
            .map(|cfg| self.hook_view(name, cfg))
            .ok_or_else(|| AdminError::not_found(format!("hook `{name}`")))
    }

    /// `GET /api/v1/admin/<section>` — the GENERIC named-DEFINITION map read (`identity-providers`,
    /// `export`; `tools`/`agents` later). ONE method for every section, parameterized by
    /// [`NamedMapSection`] — the read half of the same "define once, reference by name" grammar the
    /// config file speaks. Definitions only; never a secret (see [`NamedDefView`]). Sorted by name so
    /// the read is stable regardless of the map's insertion order.
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
            // A plane section reads its registrations through the plane's `named_def_list` seam,
            // so this arm names no plane crate's view or registry type; the empty vec for
            // a plane compiled out is the seam's own `None`.
            NamedMapSection::Plane(_) => plane_named_def_list(section, &self.app),
        };
        // Plus every overlay entry this binary could not parse, explicitly FLAGGED. They are stored
        // but NOT live (dropped at each rebuild), and listing them here is what makes that
        // discoverable to an operator inspecting state rather than boot logs. A name that is live
        // wins — the registry only ever holds names the applier actually dropped.
        for (name, entry) in self.unparseable_overlay_entries(section).await? {
            if !defs.iter().any(|d| d.name == name) {
                defs.push(unparseable_def_view(&name, &entry));
            }
        }
        defs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(defs))
    }

    /// `GET /api/v1/admin/<section>/{name}` — ONE named definition, or `not_found`. The single-entry
    /// twin of [`AdminService::list_named_defs`].
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
            // A plane section reads its one registration through the plane's `named_def_get`
            // seam; `None` for a plane compiled out is the seam's own `None`.
            NamedMapSection::Plane(_) => plane_named_def_get(section, &self.app, name),
        };
        if let Some(view) = view {
            return Ok(view);
        }
        // A stored-but-unparseable overlay entry answers the FLAGGED view rather than a 404: a 404
        // for a name that is sitting in the operator's own overlay is precisely the silent drop
        // this surfaces.
        self.unparseable_overlay_entries(section)
            .await?
            .get(name)
            .map(|entry| unparseable_def_view(name, entry))
            .ok_or_else(|| AdminError::not_found(format!("{} `{name}`", section.singular())))
    }

    /// The overlay entries of `section` this binary could not parse, read OFF THE ASYNC WORKER.
    ///
    /// Finding them reads the operator's overlay FILE and parses all of it — every section, the
    /// group tree a self-service mint grows among them — on a read-scope endpoint the admin limiter
    /// does not meter. Inline, that file read held the runtime worker the data plane shares for as
    /// long as the disk took; on a blocking thread it holds nothing. A blocking task that fails to
    /// join answers what a panic inside the handler always answered, the `500` `internal` envelope.
    async fn unparseable_overlay_entries(
        &self,
        section: NamedMapSection,
    ) -> Result<
        std::collections::BTreeMap<String, busbar_kernel::config::overlay::UnparseableNamedDef>,
        AdminError,
    > {
        let overlay = self.app.overlay_path.clone();
        // The caller's tracing dispatcher rides onto the blocking thread, so the corrupt-overlay
        // warning the read raises still reaches it (the `GET /config/settings` read does the same).
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
        })
    }

    /// `GET /api/v1/admin/groups` — the `groups:` limit tree read. Read scope. Each entry is the
    /// DEFINITION (parent, enabled, limits, `child_default`), never a secret. Sorted by name (the
    /// registry is already a BTreeMap, so iteration is name-ordered).
    ///
    /// Cursor-paginated by the SAME `{items, next_cursor}` envelope every other growable admin
    /// collection uses (keys/audit/config-versions): unlike `/pools`/`/models`/`/hooks` (bounded by
    /// static config, still a `Page::single`), the group tree GROWS at runtime — `plan_mint_group`
    /// auto-provisions a leaf per self-service key mint — so it needs the same bound every other
    /// growable list has. `start`/`limit` are the caller's already-decoded cursor offset and clamped
    /// page size (see the JSON handler, which owns cursor parsing).
    pub(crate) async fn list_groups(
        &self,
        start: usize,
        limit: usize,
    ) -> Result<Page<GroupView>, AdminError> {
        // Skip to the page BEFORE projecting: only the page's groups are built into their wire
        // view, so a page costs its own size rather than the whole tree's.
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

    /// `GET /api/v1/admin/groups/{name}` — one group definition, or `not_found` if the name is unknown.
    pub(crate) async fn get_group(&self, name: &str) -> Result<GroupView, AdminError> {
        self.app
            .groups_registry
            .get(name)
            .map(|cfg| GroupView::from_cfg(name, cfg))
            .ok_or_else(|| AdminError::not_found(format!("group `{name}`")))
    }

    /// `GET /api/v1/admin/groups/{name}/usage` — the group's derived current-window usage per
    /// enforcement bucket vs its caps. Read scope.
    /// `not_found` for an unknown group; governance off = every bucket reads zero (the caps are
    /// still projected — the definition exists even when nothing enforces).
    pub(crate) async fn get_group_usage(
        &self,
        name: &str,
    ) -> Result<crate::v1::contract::GroupUsageView, AdminError> {
        use crate::v1::contract::{GroupBucketUsageView, GroupUsageView};
        let Some(rt) = self.app.cost.group_named(name) else {
            return Err(AdminError::not_found(format!("group `{name}`")));
        };
        let now = busbar_kernel::store::now();
        // THE STORE READS RUN OFF THE ASYNC WORKER, all of the group's buckets in one blocking
        // task (as `get_usage`'s are): a slow store never stalls the worker the admin surface and
        // the data plane share. One read per bucket, in bucket order.
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
                        // Include the flat per-request fee (`true`) — the group `/usage` read must
                        // match ENFORCEMENT (`try_admit` counts the fee for EVERY chain bucket,
                        // groups included). Passing `false` here understated spend and overstated
                        // remaining budget, so operators saw more headroom than the enforcer
                        // actually allows.
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
                    // An unpriced lane or class is NAMED (`unpriced_class`, 409 — Q25b).
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
                // The headroom is the ledger's read-time arithmetic (THE DESIGN, Money), never this crate's.
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

    /// `GET /api/v1/admin/plugins?type=auth|hooks|store|secret` — the plugin catalog for one TYPE.
    /// Read scope. Lists COMPILED-IN plugins (feature-gated, from the binary — the same source as
    /// `info`'s build proof), EXTERNAL plugins (registered over socket/webhook), and DYNAMIC-LIBRARY
    /// plugins from `plugins.dir` (`store`/`secret`, and `auth` rows installed on disk, so every
    /// kind has a real, manifest-backed row to carry `trust`/`schema_url`/`schema_error` on). An
    /// unknown/absent `type` is an `invalid_request` (there is no unified cross-kind list; a caller
    /// must pick one — busbar-ui makes up to FOUR separate `GET /plugins?type=X`
    /// calls to build a full picture).
    pub(crate) async fn list_plugins(&self, ptype: &str) -> Result<Page<PluginView>, AdminError> {
        let mut plugins: Vec<PluginView> = Vec::new();
        match ptype {
            "auth" => {
                // Compiled-in auth modules (feature-gated). Active = wired into its chain: `keys`
                // is engine-handled (a flag, not a boxed module), the operator credential lives on the
                // ADMIN chain, and anything else is a boxed data-plane chain module.
                let chain = self.app.auth.chain_names();
                for name in auth_modules_compiled_in() {
                    let active = if name == busbar_kernel::config::KEYS_MODULE {
                        self.app.auth.keys_in_chain
                    } else if name == busbar_kernel::config::operator_provider() {
                        // By module: a provider of any name backed by the operator credential.
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
                // DYNAMIC auth modules: a `kind: auth` plugin loaded over the signed hybrid ABI and
                // boxed into the data-plane chain. Its runtime name (`module.name()`, what
                // `role_bindings.<module>` keys off) appears in `chain_names()` but is NOT
                // compiled-in — report each such module as a loaded plugin, always `active` (it is
                // in the chain by construction).
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
                // External auth modules (runtime-registered over socket/webhook) — none until the
                // auth-module registration endpoint lands; the catalog shape is ready.

                // DYNAMIC-LIBRARY `kind: auth` plugins installed in `plugins.dir`: they get the
                // same manifest-backed view `store` rows already get —
                // version/publisher/interface_version/trust/schema_url/schema_error —
                // rather than leaving every dynamic auth plugin as a bare name+active `basic` row).
                // This is the SAME directory scan `type=store`/`type=secret` already run (cached,
                // kind-agnostic), filtered down to `kind: auth` rows here. NOTE: an entry here is
                // "installed on disk", not necessarily "currently wired into the live chain" — the
                // `active: true` "plugin" rows above (from `chain_names()`) are the currently-active
                // signal; correlating the two by manifest name is a real follow-on, not solved here.
                let mut dynamic_auth: Vec<PluginView> = self
                    .store_plugin_catalog_async()
                    .await?
                    .into_iter()
                    .filter(|p| p.r#type == "auth")
                    .collect();
                plugins.append(&mut dynamic_auth);
            }
            "hooks" => {
                // The weighted SWRR floor is compiled in unconditionally (the non-removable default
                // hook); activation is the per-pool default, not summarized here.
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
                // External hooks = the configured registry entries (socket/webhook). Configured ⇒
                // active; the transport target is projected (operator config, not a secret).
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
            // `store` (alias `db`) — DYNAMIC-LIBRARY plugins in the plugins directory. Always includes
            // the compiled-in `memory` default; then every loadable library present, each vetted (ABI
            // handshake) and its signed sidecar manifest read + re-evaluated against the running trust
            // posture. The store the operator configured (`store.module`) is `active`.
            //
            // The underlying scan reads every kind in the shared `plugins.dir` in one pass (cached,
            // kind-agnostic); each row is tagged with its OWN manifest kind (`scan_store_plugin_rows`),
            // so filtering to `r#type == "store"` here is what makes `type=store` show only store
            // plugins — a `secret`/`auth` kind tarball dropped in the same directory no longer leaks
            // into this listing (it did before `type=secret`/richer `type=auth` rows existed, since
            // nothing filtered the scan's mixed-kind output by the requested type).
            "store" | "db" => {
                plugins.extend(
                    self.store_plugin_catalog_async()
                        .await?
                        .into_iter()
                        .filter(|p| p.r#type == "store"),
                );
            }
            // DYNAMIC-LIBRARY `kind: secret` plugins: previously the ONLY accepted `type` values
            // were `auth`, `hooks`, `store`, despite secret plugins being in scope throughout this
            // design. Same directory scan as `store`/`auth`, filtered to `kind: secret`. No
            // compiled-in default (unlike `store`'s `memory`) — there is no built-in secret module
            // that needs a catalog row; `env`/`file` are handled inline by the engine, not as plugins.
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

    /// The DYNAMIC plugin catalog (`GET /api/v1/admin/plugins?type=store`): the compiled-in
    /// `memory` default plus every signed plugin tarball in `plugins.dir`, each with its manifest
    /// metadata and a re-evaluated trust verdict. Sorted by filename after the `memory` head.
    ///
    /// MANIFEST-ONLY INSPECTION (security): this endpoint NEVER `dlopen`s ANY plugin. Each tarball
    /// is unpacked in memory, structurally validated, and trust-evaluated against the RUNNING
    /// policy — pure data checks; no plugin code can run from listing the catalog. Pushing/listing
    /// a plugin over the admin API therefore cannot bypass the trust model: loading only ever
    /// happens through the boot pipeline, which re-runs the same three-phase validation.
    ///
    /// CACHED (see `catalog_cache`): `inventory_tarballs` fully re-reads and re-unpacks (gunzip +
    /// untar + structural + trust) EVERY tarball on EVERY call — fine for a one-off boot scan, but
    /// this backs an authenticated GET a caller can hit as often as it likes (reads are
    /// deliberately unmetered by the admin rate limiter — see `admin/rate.rs`'s
    /// `CONFIG_CLASS_RULES` and the mutation-only gate in `auth::classify_for_rate_limit`). A
    /// legitimate admin polling this endpoint, or a misbehaving admin-token holder, would otherwise
    /// pay a full directory re-scan per request with nothing bounding the rate. The cache is keyed
    /// off a cheap directory fingerprint (name+size+mtime per entry, no read/decompress) plus the
    /// trust config, so any real change — install, remove, rollback, or a `plugins:` config edit —
    /// invalidates it on the very next call with no bespoke invalidation hook wired into any of
    /// those mutation paths.
    ///
    /// SYNCHRONOUS, BLOCKING FILESYSTEM I/O — both the fingerprint read(s) and, on a cache miss, the
    /// full tarball scan. Safe to call directly only from a context that is already off the Tokio
    /// reactor: `reload_store_plugins` (always invoked inside a `txn.read_store` closure, which
    /// `config_transaction`'s `apply()` runs via `spawn_blocking`), tests, and `--validate`/boot
    /// paths. The `GET /plugins?type=store` request path goes through
    /// [`Self::store_plugin_catalog_async`] instead — never this method directly.
    ///
    /// RACE: the fingerprint read and the scan are two independent,
    /// non-atomic directory reads, so a concurrent install/remove between them could let a scan and
    /// its "before" fingerprint observe different directory states. To narrow that window this
    /// re-fingerprints the directory AFTER the scan and only memoizes when the two fingerprints
    /// still match — but this is a NARROWING, not a CLOSING, of the race: an ABA sequence (the
    /// directory changes and then changes back to the same fingerprint mid-scan — plausible on
    /// filesystems with coarse mtime granularity) could still memoize a torn read. Self-healing
    /// either way: the cache is a pure performance layer over a deterministic scan, so the worst
    /// case is one extra rescan on the next call, never a wrong answer served indefinitely (the
    /// fingerprint fix below is what actually prevents a wrong answer being served indefinitely).
    pub(super) fn store_plugin_catalog(&self) -> Vec<PluginView> {
        // Every store this build LINKS is always present (the declared default among them), read
        // off the root's linked rows; admin names no store. Which store backend is ACTIVE is a
        // `store.module` config concern (read via `GET /config`), not summarized per-row here,
        // the same posture the compiled-in hook rows take (`active: None`).
        let mut out = linked_store_rows();
        let Ok(admission) = admission(&self.app) else {
            return out;
        };
        if admission.policy_resolves(&self.app.plugins_cfg).is_err() {
            return out;
        }

        let now = busbar_kernel::store::now();
        // Bound the cache with the same TTL+`retain()` idiom
        // `admin/mod.rs`'s `idempotency_cache` uses: prune before every read, not just on write, so
        // an abandoned path's entry cannot sit forever just because nothing keeps writing to it.
        // CLOCK SKEW: `saturating_sub` alone avoids an underflow PANIC if `inserted_at`
        // is somehow in the future (a backward system-clock jump), but silently floors the computed
        // age at 0 — which means the entry looks brand-new and never ages out, quietly defeating the
        // TTL bound for exactly that entry until real time catches back up to `inserted_at`. Treating
        // `inserted_at > now` as ALSO immediately-stale (rather than ageless) closes that: a clock
        // that jumped backward means this entry's true age is UNKNOWN, and unknown age is treated the
        // same as "old" — the safe default for a cache, same posture the fingerprint-freshness check
        // above takes toward any signal it cannot trust.
        catalog_cache().lock().unwrap().retain(|_, e| {
            e.inserted_at <= now && now.saturating_sub(e.inserted_at) < CATALOG_CACHE_TTL_SECS
        });

        // A real I/O error (NOT a missing directory — see the doc
        // comment on `plugins_dir_fingerprint`) means the fingerprint cannot be trusted as a
        // freshness signal at all. Skip the cache entirely (no read, no write) and fall through to
        // the real scan, whose own `discover()` call fails the same way and surfaces the
        // `INVALID: cannot read plugins dir` row — on EVERY call, honestly, until the directory
        // becomes readable again, rather than silently serving whatever was cached before.
        // Warn-once transition latch: this read runs on every catalog GET, so an unlatched warn
        // would spam while the dir stays unreadable. Warn on entry into the failing state; hold
        // subsequent failing reads at debug; clear on the next clean fingerprint so a future outage
        // re-warns.
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
            // Cache key: a cheap directory-content fingerprint PLUS the config that governs how
            // each tarball is trust-evaluated. `inventory_tarballs` is a deterministic function of
            // exactly those two things, so a match here is an EXACT cache hit, not a heuristic
            // staleness window — nothing observable differs from re-running the scan.
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

            // "After" fingerprint: only memoize if the directory still looks like it did before the
            // scan started (see the race caveat in the doc comment above — this narrows, it does
            // not close, the window). A mismatch, or the directory becoming unreadable mid-scan,
            // just means this call doesn't memoize; the data returned below is still the real scan
            // result, correct for THIS call either way.
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

    /// The pure scan half of [`Self::store_plugin_catalog`]: run the admission's manifest-only
    /// `inventory` and project each row to a [`PluginView`]. No cache read, no cache write — split out so both the
    /// cache-miss path above and (indirectly, via the whole-method `spawn_blocking`)
    /// [`Self::store_plugin_catalog_async`] share exactly one implementation of "what a scan is."
    fn scan_store_plugin_rows(
        dir: &Path,
        admission: &dyn PluginAdmission,
        cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Vec<PluginView> {
        // TEST-ONLY injection point: expands to nothing outside
        // `#[cfg(test)]`, so the release path carries zero indirection. See
        // `catalog_scan_test_hooks` above for what it does and why.
        catalog_scan_test_hook!(dir);
        let mut rows = Vec::new();
        // The policy resolved a moment ago (the caller checked); a refusal here lists nothing
        // beyond the linked rows, the same answer an unresolvable policy gets.
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
            // `r#type` reflects the manifest's OWN `kind` (`GET /plugins?type=secret` support,
            // plus real rows for `auth`) — not hardcoded "store".
            // `kind: hook` and a manifest-less (invalid/corrupt) row both fall back to "store",
            // preserving the exact pre-existing behavior for every case this change doesn't newly
            // cover (a broken upload of unknown kind still surfaces somewhere an operator will see
            // it, and `type=hooks` has its own, unrelated listing mechanism below — not this scan).
            let r#type = match row.stated.as_ref().map(|m| m.kind.as_str()) {
                Some("secret") => "secret",
                Some("auth") => "auth",
                _ => "store",
            };
            // `schema_url`/`schema_error`: non-null whenever the manifest
            // declared a `settings_schema` at all, even unparseable (`schema_error` then explains
            // why) — never folded into the same `null` a schema-less plugin gets. Always the
            // admin-prefixed RELATIVE path to `GET /plugins/{name}/schema`, resolved by this
            // plugin's real manifest `name` (what that endpoint resolves against), never the
            // installed tarball's filename.
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

    /// The `GET /plugins?type=store` REQUEST-PATH entry point — the async, reactor-safe wrapper
    /// around [`Self::store_plugin_catalog`]. The synchronous version
    /// performs blocking filesystem I/O on EVERY call, not just a cache miss: the fingerprint
    /// read(s) alone are a `read_dir` + a `metadata()`/`modified()` per entry, and a miss adds the
    /// full `inventory_tarballs` unpack on top — none of it safe to run inline in an `async fn` on a
    /// Tokio worker thread, on an endpoint this codebase deliberately leaves unmetered by the admin
    /// rate limiter (see the doc comment above). Mirrors [`Self::get_usage`]'s `spawn_blocking`
    /// wrapper shape.
    ///
    /// Serialized through [`CATALOG_SCAN_GATE`] (see its doc comment for why, and for the
    /// acknowledged hit-path throughput trade-off): N callers that all miss at the same instant
    /// (e.g. right after boot or a config reload, before any entry exists) single-flight into
    /// exactly one real scan, and every other caller wakes up to find the cache already populated
    /// rather than each independently unpacking every tarball.
    ///
    /// `reload_store_plugins` is UNCHANGED and does not go through here — it already runs inside a
    /// `txn.read_store` closure on `spawn_blocking` (see `admin/v1/json/txn.rs`'s `apply()`), so it
    /// calls the synchronous [`Self::store_plugin_catalog`] directly.
    ///
    /// GATE TIMEOUT: acquiring [`CATALOG_SCAN_GATE`] is bounded by
    /// [`CATALOG_SCAN_GATE_WAIT`] — see that constant's doc comment for why an unbounded wait here
    /// would be a permanent wedge, not a self-healing one, on an endpoint this rate limiter never
    /// meters. A caller that cannot even START the scan within the bound gets a clear
    /// [`AdminError::Unavailable`] rather than a hang.
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
                // Fail soft to the always-true linked rows rather than an admin 500 for what is
                // just a plugin CATALOG read — same posture `store_plugin_catalog` itself takes on
                // an unparseable `plugins_cfg` (the policy not resolving) just above.
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
        // ── 1. filename sanity: a bare tarball filename ──
        let file = validate_plugin_filename(&self.app, file)?;

        // ── 2–4b. THE ROOT'S ADMISSION, nothing written: STRUCTURAL (in-memory unpack + manifest
        // completeness + integrity + abi, `400`); TRUST re-verified against the RUNNING posture
        // server-side (an untrusted upload with no matching opt-in is a terminal `409` — retrying
        // the same bytes cannot fix it; the refusal names the exact flag to set); CONFLICT with the
        // already-installed loadable set (a corrupt installed tarball refuses rather than skipping
        // the check, and a same-name upload under a DIFFERENT filename is refused because boot
        // would reject two files claiming one plugin name, `409`); and THE ONE-VERSION RULE against
        // the plugins this build LINKS (ARCHITECT C'), after trust: the same plugin at the same
        // version is served by the linked row, so the install is an accepted no-op; another
        // version is refused now, in the words boot would refuse it with, never published to brick
        // the next boot.
        let admission = admission(&self.app).map_err(AdminError::Validation)?;
        let admitted = admission
            .admit_upload(&self.app.plugins_dir, &file, tarball, &self.app.plugins_cfg)
            .map_err(refused)?;
        let manifest = &admitted.stated;
        let (trust, publisher) = match &admitted.judged {
            Judged::Trusted { publisher } => ("trusted", Some(publisher.clone())),
            Judged::Allowed => ("unverified", Some(manifest.publisher.clone())),
            // An admission never admits a rejected upload; the mapping stays total.
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

        // ── 5. atomic publish via the crate's ONE durable-write choke point ──
        // Directory provisioning goes through the primitive too: `std::fs::create_dir_all` leaves the
        // new directory's own entry non-durable, so the FIRST plugin installed into a not-yet-existing
        // plugins dir could vanish with the directory on power loss — despite the response promising
        // it was installed durably. The temp-in-same-dir → write → flush → fsync(file) → rename → fsync(dir) dance is the
        // primitive's. Collapsing onto it FIXES the former leaked-`.tmp`-on-pre-rename-error class for
        // free: the old `{ }` block returned early on a create/write/flush/fsync failure WITHOUT
        // removing the temp (only the rename path cleaned up), so a full disk / I/O error orphaned a
        // `.<file>.<stamp>.tmp` to accumulate across retries. The primitive's RAII guard removes the
        // temp on EVERY error path. The pid+seq temp naming supersedes the bespoke pid+now stamp with
        // the same per-call-uniqueness property.
        let dir = &self.app.plugins_dir;
        busbar_kernel::durable::create_dir_all(dir)
            .map_err(|e| AdminError::Validation(format!("cannot create plugins dir: {e}")))?;
        let final_path = dir.join(&file);
        busbar_kernel::durable::write(&final_path, tarball).map_err(|e| {
            AdminError::Validation(format!("cannot publish plugin into plugins dir: {e}"))
        })?;

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
        if tarball.len() as u64 > cap {
            return Err(AdminError::Validation(format!(
                "decoded tarball is {} bytes, exceeding the {cap}-byte cap",
                tarball.len()
            )));
        }

        // Trust is REPORTED, never a refusal to answer — an untrusted/rejected candidate is exactly
        // the case an operator most wants to preview before deciding whether to trust it at all.
        let (manifest, judged) = admission
            .inspect(tarball, &self.app.plugins_cfg)
            .map_err(refused)?;
        let trust = match judged {
            Judged::Trusted { .. } => "trusted",
            Judged::Allowed => "unverified",
            Judged::Rejected { .. } => "rejected",
        };

        let (schema, schema_error) = match manifest.settings_schema.as_deref() {
            None => (None, None),
            Some(s) => match schema_json_within_bounds(s) {
                Err(reason) => (None, Some(reason)),
                Ok(()) => match serde_json::from_str::<serde_json::Value>(s) {
                    Ok(v) => (Some(v), None),
                    Err(e) => (
                        None,
                        Some(format!("manifest settings_schema is not valid JSON: {e}")),
                    ),
                },
            },
        };

        Ok(serde_json::json!({
            "name": manifest.name,
            "version": manifest.version,
            "kind": manifest.kind,
            "schema": schema,
            "schema_error": schema_error,
            "trust": trust,
            "source": "manifest",
            "restart_required_default": admission.restart_default(&manifest.kind),
        }))
    }

    /// `DELETE /api/v1/admin/plugins/{file}` — REMOVE a plugin tarball from the plugins directory.
    /// Full scope. `404 not_found` if the file isn't present. A currently-loaded store keeps
    /// running on its already-loaded handle until the next plugin (re)load — removing the file only
    /// affects the NEXT load (folder = source of truth).
    pub(crate) fn remove_store_plugin(
        &self,
        file: &str,
    ) -> Result<crate::v1::contract::PluginRemoveView, AdminError> {
        let file = validate_plugin_filename(&self.app, file)?;
        let lib_path = self.app.plugins_dir.join(&file);
        if !lib_path.is_file() {
            return Err(AdminError::not_found(format!("plugin `{file}`")));
        }
        // `durable::remove`, not a bare `remove_file`: the INSTALL fsyncs the plugins directory so
        // the new artifact's directory entry survives a power loss, and a removal that skipped it was
        // the asymmetric half -- a crash right after a delete could resurrect the artifact and load
        // it on the next boot.
        busbar_kernel::durable::remove(&lib_path)
            .map_err(|e| AdminError::Validation(format!("cannot remove plugin: {e}")))?;
        Ok(crate::v1::contract::PluginRemoveView {
            file,
            removed: true,
        })
    }

    /// `POST /api/v1/admin/plugins/reload` — re-scan the plugins directory and report the current
    /// dynamic-library inventory (the SAME projection `GET /plugins?type=store` produces, minus the
    /// compiled-in `memory` head). Full scope. Reconciles the reported set to the folder (folder =
    /// source of truth), the exact sibling of `config/reload`. A store change still applies on the
    /// next store (re)load, not as a hot swap.
    pub(crate) fn reload_store_plugins(
        &self,
    ) -> Result<crate::v1::contract::PluginReloadView, AdminError> {
        // Reuse the store catalog projection, dropping the compiled-in `memory` head (reload reports
        // only the on-disk dynamic set it reconciled).
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

    /// The RESOLUTION half of an EXPLICIT plugin ROLLBACK (`POST /api/v1/admin/plugins/rollback`,
    /// 1.5.0). Validate that `file` is a plugin tarball in the plugins dir, unpack + STRUCTURALLY
    /// validate its manifest, and TRUST-verify it against a policy whose first-party floor is LOWERED to
    /// the target's OWN version — so a validly-signed but OLDER artifact (exactly the rollback case)
    /// clears trust here even though it would be an anti-downgrade reject on the automatic path. This is
    /// where "automatic vs explicit" is made concrete: the rollback deliberately relaxes the floor to
    /// the pinned target and only that target; a lower artifact still fails, and a signature/opt-in
    /// failure is still fatal (a rollback can never launder an untrusted artifact). Returns the target
    /// manifest identity (name/version/publisher) + the MERGED pin map (prior overlay pins with this
    /// plugin's name set to the target version) the caller persists and re-derives the policy from.
    ///
    /// `prior_pins` is the current persisted `plugin_versions` overlay section (empty if none).
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
        // The root's admission checks the target's structure and judges its trust with THIS
        // plugin's floor LOWERED to the target's own version — the EXPLICIT relaxation. Anything the
        // target does NOT satisfy (a broken signature, an un-opted-in third party) still fails: a
        // rollback authenticates the OPERATOR, never the ARTIFACT.
        let admission = admission(&self.app).map_err(AdminError::Validation)?;
        let manifest = admission
            .rollback_target(&file, &bytes, &self.app.plugins_cfg)
            .map_err(refused)?;

        // Merge: this plugin's pin becomes the target version; other plugins' prior pins are preserved.
        let mut pins = prior_pins.clone();
        pins.insert(manifest.name.clone(), manifest.version.clone());
        Ok((manifest, pins))
    }

    /// `GET /api/v1/admin/config` — the EFFECTIVE running config, composed from the same redacted reads as
    /// the individual endpoints (auth/pools/models/providers/hooks/global-hooks). Read scope. Carries
    /// no secret. For drift detection + one-shot inspection; the base-vs-overlay source annotation
    /// lands with the overlay substrate.
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

    /// `POST /api/v1/admin/config/validate` — DRY-RUN a proposed config: resolve (`config.yaml` deploy +
    /// `providers.yaml` defs) then run the full boot-time `config_validate`, collecting every error at
    /// once, WITHOUT applying anything. Always succeeds as an operation (`Result::Ok`) — the verdict is
    /// in the view's `ok`/`errors`; a valid request describing an invalid config is `ok: false`, not an
    /// error. Read scope (no mutation). Env interpolation is out of scope (structure + resolution only).
    ///
    /// OFF THE REACTOR, BEHIND THE SCAN GATE. The pre-flight scans the running `plugins.dir` (a
    /// `read_dir` and a read of every tarball in it) and the resolve and validate passes before it
    /// are CPU-bound over a caller-sized document; none of it may run inline on a Tokio worker,
    /// which is shared with the data plane. So the whole dry run goes to `spawn_blocking`, behind
    /// [`CATALOG_SCAN_GATE`] — the gate the catalog's own scan of the same directory already takes —
    /// with the same bounded wait: a read-only token can no longer park a worker per request on a
    /// slow or hung plugins mount, and a hung scan answers the next caller a retryable `503` instead
    /// of queuing it forever. A blocking task that fails to join answers what a panic inside the
    /// handler always answered, the `500` `internal` envelope.
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
        // The running generation's root rules: a dry run judges what an apply would.
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

    /// `GET /api/v1/admin/admin-auth` — the ADMIN-plane auth config (distinct from the ingress chain).
    /// Read scope. Reports the live `admin_auth` chain — the SAME resource `PUT /api/v1/admin/admin-auth`
    /// writes, so a read-after-write is coherent (previously this hard-coded `["admin-token"]` and
    /// never reflected a PUT). Never a secret.
    pub(crate) async fn get_admin_auth(&self) -> Result<AdminAuthView, AdminError> {
        let modules = self.app.admin_chain.clone();
        Ok(AdminAuthView {
            // An empty chain is the open (anonymous, full-authority) dev posture — NOT configured.
            configured: !modules.is_empty(),
            modules,
        })
    }

    /// Validate an `?as_of` rate-card-history snapshot, or REFUSE.
    ///
    /// A seq ABOVE THE HEAD is an error and never a clamp. Clamping would answer a DIFFERENT
    /// question under the name of the one that was asked, which is exactly the failure the
    /// behaviour this replaces was recorded for: the parameter was ignored, the body was the
    /// live-card reprice, and the response reported an `as_of` contradicting the URL — a caller
    /// who guessed the parameter got a confident wrong answer. A refusal is the only answer that
    /// cannot be mistaken for the snapshot.
    ///
    /// A node with NO history refuses for the same reason: there is no snapshot of a history that
    /// does not exist, and serving the live figure under a snapshot's name would be that same
    /// confident wrong answer. A refusal rather than an empty body, because an empty body is a
    /// silent zero wearing a different hat (#42).
    fn validated_snapshot(
        history: Option<&busbar_kernel::cost::History>,
        seq: u64,
    ) -> Result<busbar_kernel::cost::HistorySeq, AdminError> {
        let head = history
            .and_then(busbar_kernel::cost::History::head)
            .ok_or_else(|| {
                AdminError::Validation(
                    "as_of names a rate-card history snapshot; this node has resolved no \
                     rate-card history to snapshot"
                        .into(),
                )
            })?;
        if seq > head.get() {
            return Err(AdminError::Validation(format!(
                "as_of {seq} is above the rate-card history head ({head}); a snapshot that does \
                 not exist is refused, never answered at the head"
            )));
        }
        Ok(busbar_kernel::cost::HistorySeq(seq))
    }

    /// `GET /api/v1/admin/usage` — the fleet METERING read (FinOps surface): the current UTC-day
    /// bucket's raw consumption, aggregated per (model, provider) and per key, each row carrying the
    /// full token SPLIT plus a DERIVED `spend_micros` (raw counts are what's stored, so a consumer
    /// with its own price catalog reconstructs cost from the split instead). The derivation is a
    /// LOOKUP, not a reprice: under DECISION #79 each posting prices against the card in force at
    /// ITS OWN arrival instant, resolved through the deployment's dated rate-card history, so
    /// publishing a card never moves the figure for the window before its `effective_from` and a
    /// signed back-dated correction moves exactly the window it names. `requests` counts DELIVERED
    /// responses (the metering tap), not admissions; budget-enforcement state stays on
    /// `GET /keys/{id}/usage`. Read scope. Empty aggregations when governance is disabled. The
    /// store reads run on a blocking thread; never returns a secret — ids/names only.
    /// `window`: a caller-selected PAST bucket start (validated: bucket-aligned, not in the
    /// future); `None` = the current bucket. The response shape is pinned: always one bucket.
    ///
    /// `as_of`: a caller-selected SNAPSHOT of the dated rate-card history — the reproducibility
    /// primitive. An invoice cut at a snapshot is re-derived by asking for that snapshot again,
    /// because no entry is ever removed and no entry's number ever moves. `None` = the history as
    /// it stands. A seq ABOVE THE HEAD is a REFUSAL, never a clamp
    /// ([`Self::validated_snapshot`]). The `as_of` FIELD on the response is a different thing and
    /// is unchanged: it is the instant the read was taken.
    pub(crate) async fn get_usage(
        &self,
        window: Option<u64>,
        as_of: Option<u64>,
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
        // DECISION #79 — THE DATED RATE-CARD HISTORY, taken ONCE for the whole read so every row of
        // one response is answered at one snapshot. A card appended while this read is in flight
        // must not price half its rows against one history and half against another.
        let history = self.rate_history.clone().or_else(dated_rate_history);
        // The snapshot the caller named, VALIDATED BEFORE ANY BOOK IS READ, so a request for a
        // state that does not exist is refused rather than quietly answered at some other state —
        // including when governance is off and the read would otherwise return early.
        let snapshot = match as_of {
            None => None,
            Some(seq) => Some(Self::validated_snapshot(history.as_deref(), seq)?),
        };
        let empty = || UsageView {
            window,
            as_of: now,
            currency: (),
            // No row was read, so no card priced one.
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
        );
        type UsageFetchError = (&'static str, busbar_kernel::governance::RecordStoreError);
        let joined = tokio::task::spawn_blocking(move || -> Result<Fetched, UsageFetchError> {
            let rows = gov
                .metering_for(bucket)
                .map_err(|e| ("usage.metering", e))?;
            // id → display name, for the by_key rows (a deleted key's history keeps its id).
            let names = gov
                .all_keys()
                .map_err(|e| ("usage.keys", e))?
                .into_iter()
                .map(|k| (k.id, k.name))
                .collect();
            Ok((rows, names))
        })
        .await;
        let cost = self.app.cost.clone();
        let (rows, names) = match joined {
            Ok(Ok(f)) => f,
            // The real store error is logged here — this is the only place it exists, and the wire
            // body deliberately carries none of it so store internals never reach even an
            // authenticated admin. Same `operation`/`error` field vocabulary as `internal_error`
            // (`admin/mod.rs`), so a broken /usage read is greppable alongside every other admin
            // store failure. `operation` distinguishes which of the two reads failed, since each has
            // a different remediation.
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
        // The snapshot this read is answered at: the one the caller named, or the history as it
        // stands when no snapshot was named.
        let view = history.as_deref().map(|h| match snapshot {
            Some(at) => h.snapshot(at),
            None => h.current(),
        });
        // THE COUNT CORRECTIONS (item 404, OWNER RULING Q9): every `adjust` the node amendment
        // journal sealed, read ONCE for the whole response. Each row prices its counts AS CORRECTED
        // (`row_count_corrections`), never a money figure a correction carried — it carries none.
        let corrections = self.app.amendments.corrections();
        // THE VERSION THE RESPONSE WAS PRICED AT (#44, Q93): the highest history seq among the
        // cards that priced its rows. It is RECORDED as each row's card resolves and never read back
        // by the pricing: a row's card is resolved by its own instant (#79). `?as_of=<it>` re-derives
        // every figure below, and a card published after these rows were earned leaves it as it was.
        let mut priced_by: Option<u64> = None;
        // Aggregate in memory — a bucket is bounded by (keys × models) accumulation rows.
        let mut total = UsageBreakdown::default();
        let mut by_model: std::collections::BTreeMap<(String, String), UsageBreakdown> =
            std::collections::BTreeMap::new();
        let mut by_key: std::collections::BTreeMap<String, UsageBreakdown> =
            std::collections::BTreeMap::new();
        // THE CORRECTIONS A ROW OF THIS WINDOW CAN RECEIVE, indexed once by (key, lane). The node's
        // list holds every `adjust` it ever sealed and is never trimmed; only one whose card epoch
        // falls inside this window can land on a row of it, and only on a row of its own key and
        // lane. Handing each row the whole list made the read rows × lifetime corrections; each
        // row is handed its own share instead (one pass over each, not their product).
        let (window_start_ms, window_end_ms) = (
            window.start.saturating_mul(1_000),
            window.end.saturating_mul(1_000),
        );
        let mut corrections_of: std::collections::HashMap<(&str, &str), Vec<&amend::Amendment>> =
            std::collections::HashMap::new();
        for amendment in &corrections {
            let amend::AmendBody::Adjust(adj) = &amendment.body else {
                continue;
            };
            let amend::Subject::PrincipalId(key_id) = &adj.subject else {
                continue;
            };
            if (window_start_ms..window_end_ms).contains(&adj.card_epoch_ms) {
                corrections_of
                    .entry((key_id.as_str(), adj.lane.as_str()))
                    .or_default()
                    .push(amendment);
            }
        }
        // When a correction lands in this window, the eras of every (key, lane), grouped once in
        // row order, so the per-row loop below looks a row's eras up rather than rescanning the
        // bucket for them (one pass, not quadratic in the rows).
        let mut eras_of: std::collections::HashMap<(&str, std::borrow::Cow<'_, str>), Vec<u64>> =
            std::collections::HashMap::new();
        if !corrections_of.is_empty() {
            for r in &rows {
                eras_of
                    .entry((r.key_id.as_str(), row_lane(&r.model, &r.provider)))
                    .or_default()
                    .push(r.priced_from_ms);
            }
        }
        for r in &rows {
            // THE ROW'S LANE: a non-pools plane's row is priced as that plane's (`row_lane`) — its
            // requests at the plane's own fee, as the budget book charges them (#47).
            let lane = row_lane(&r.model, &r.provider);
            // Spend derives PER ROW (the model is known here - the per-model rate applies), then
            // aggregates ADDITIVELY into total/by_model/by_key, so every rollup is exact under a
            // heterogeneous rate card.
            let mut row_view = UsageBreakdown {
                tokens_input: r.tokens_input,
                tokens_output: r.tokens_output,
                tokens_cache_read: r.tokens_cache_read,
                // `r` is a store MeteringRow (internal field: tokens_cache_write); UsageBreakdown
                // is the public admin-API view struct and keeps its own JSON field name unchanged.
                tokens_cache_creation: r.tokens_cache_write,
                requests: r.requests,
                spend_micros: 0,
                classes: std::collections::BTreeMap::new(),
            };
            // The row's counts AS CORRECTED — its token columns and its ledgered classes alike. A
            // correction that leaves a count fractional or below zero REFUSES the read: a figure
            // over counts nobody recorded is not one this read may serve.
            let mut corrected_classes = std::borrow::Cow::Borrowed(&r.usage_units);
            if !corrections_of.is_empty() {
                let eras = eras_of
                    .get(&(r.key_id.as_str(), lane.clone()))
                    .map_or(&[][..], Vec::as_slice);
                let own = corrections_of
                    .get(&(r.key_id.as_str(), &*lane))
                    .map_or(&[][..], Vec::as_slice);
                for (class, delta) in row_count_corrections(
                    own,
                    &r.key_id,
                    &lane,
                    (window.start, window.end),
                    r.priced_from_ms,
                    eras,
                ) {
                    let column = match class.as_str() {
                        busbar_contract::records::UNIT_INPUT => &mut row_view.tokens_input,
                        busbar_contract::records::UNIT_OUTPUT => &mut row_view.tokens_output,
                        busbar_contract::records::UNIT_CACHE_READ => {
                            &mut row_view.tokens_cache_read
                        }
                        busbar_contract::records::UNIT_CACHE_WRITE => {
                            &mut row_view.tokens_cache_creation
                        }
                        _ => corrected_classes.to_mut().entry(class).or_insert(0),
                    };
                    *column = corrected_column(*column, delta).ok_or(AdminError::Internal)?;
                }
            }
            // **THE RESOLUTION**, and the key is the ROW'S OWN FIRST INSTANT (see
            // `row_priced_at_ms`): the row prices against the card it was earned under rather than
            // the newest card ever authored, and a card edit inside the day opened a second row at
            // the edit so the two halves resolve to the two cards. Never
            // `PostingStamp::rate_card_version` — that is reporting provenance (#44), and a
            // version resolves only forward, which is what would put a back-dated correction out
            // of reach.
            //
            // ONE WAY TO FALL BACK: no source installed or no history resolved (a build with no
            // root ledger in it) prices through the derivation this read has always used. A HOLE —
            // a history that IS resolved but has no entry covering this row's instant — is NOT a
            // fallback: it is `MoneyError::NoCardInForce`, a refusal like the other three (#42,
            // item 374). Pricing a hole at the current card would answer for an instant with a
            // card nobody put in force for it; the record has a gap and the read says so.
            //
            // THE PRICING ITSELF IS NOT HERE AND IS NOT THIS CRATE'S: the row is handed to
            // the ledger's `cost::price_in_view`, THE ONE FUNCTION, which resolves the
            // card at the instant below and prices against it. See
            // `derive_spend_micros_row_at_card`.
            let at = row_priced_at_ms(window.start, r.priced_from_ms);
            // THE ROW'S LEDGERED CLASSES (`usage_units`) — every count the budget book holds that the
            // token split does not (a plane's declared classes, a pools open class, a plane's session
            // count) — price on the row's lane beside its tokens, as the budget book prices them.
            let classes: &std::collections::BTreeMap<String, u64> = &corrected_classes;
            let row_spend = match view.as_ref() {
                Some(v) => match v.card_at(at) {
                    Some((card_seq, card)) => {
                        priced_by = priced_by.max(Some(card_seq.get()));
                        derive_spend_micros_row_classes_at_card(
                            v, at, card, &cost, &lane, &row_view, classes,
                        )
                    }
                    None => Err(busbar_kernel::cost::MoneyError::NoCardInForce { at }),
                },
                None => derive_spend_micros_row_classes(&cost, &lane, &row_view, classes),
            };
            // A REFUSED figure fails the read (#42, items 31 and 374): the card is present and
            // silent about this row's model or class, no entry covers the row's instant, or the
            // figure left the range (item 28). The response does not carry a number nobody
            // priced; the refusal is logged with the row it came from.
            // An unpriced lane or class is NAMED (`unpriced_class`, 409 — Q25b).
            let row_spend = match row_spend {
                Ok(spend) => spend,
                Err(e) => return Err(usage_refusal("usage.price", &e)),
            };
            // EACH LEDGERED CLASS, ITS COUNT AND ITS COST: the class alone on the row's lane (no
            // tokens, no requests), priced by the same one function at the same instant, so a
            // class's cost is the share of `row_spend` it is and never a second pricing of its own.
            // A pools-plane row itemizes none: its open classes are already in `row_spend`, and its
            // view keeps 1.5.5's shape (`row_carries_classes`).
            let none = UsageBreakdown::default();
            let unitemized = std::collections::BTreeMap::new();
            let itemized = if row_carries_classes(&r.provider) {
                classes
            } else {
                &unitemized
            };
            for (class, count) in itemized {
                let one = std::collections::BTreeMap::from([(class.clone(), *count)]);
                let class_cost = match view.as_ref() {
                    Some(v) => match v.card_at(at) {
                        Some((_card_seq, card)) => derive_spend_micros_row_classes_at_card(
                            v, at, card, &cost, &lane, &none, &one,
                        ),
                        None => Err(busbar_kernel::cost::MoneyError::NoCardInForce { at }),
                    },
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
                // The ledger's rollup (THE DESIGN, Money), CHECKED like the one function it sums (item 28): a
                // rollup past the range is a refused read, never a figure pinned at the ceiling.
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
        // Bound the response (no memory/latency cliff at fleet scale):
        // keep the TOP spenders (the rows a FinOps consumer actually wants first), ordered
        // spend-desc then id for determinism, and SAY when the cap fired.
        const BY_KEY_CAP: usize = 1000;
        by_key.sort_by(|a, b| {
            b.usage
                .spend_micros
                .cmp(&a.usage.spend_micros)
                .then_with(|| a.id.cmp(&b.id))
        });
        let by_key_truncated = by_key.len() > BY_KEY_CAP;
        // FinOps completeness: the tail beyond the cap is summed into an `others` bucket, so
        // total == sum(by_key) + others and every unit stays attributable.
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
                // The ledger's rollup (THE DESIGN, Money), CHECKED as the total's is: the tail sums to no more
                // than the total, which summed, so a refusal here is a figure nothing served.
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
            rate_card_version: priced_by,
            total,
            by_model,
            by_key,
            by_key_truncated,
            others,
        })
    }

    /// `GET /api/v1/admin/auth` — the ingress auth chain + upstream-credential mode. Read scope. Never a
    /// secret: only module names and the mode. This is READ-ONLY at runtime — the ingress chain is
    /// mutated through the config-plane write path (`PUT/POST /api/v1/admin/config`), not a dedicated PUT.
    /// (The ADMIN-plane chain, by contrast, has `PUT /api/v1/admin/admin-auth`.)
    ///
    /// `open` is the 1.5.5 field: whether the BOXED chain is empty, i.e. whether `chain` above reads
    /// `[]`. It is NOT `AuthMiddleware::is_open`, which is the admission predicate (`keys` closes the
    /// door without installing a boxed module) and which the admin grant reads. Reporting that here
    /// flipped `open` to `false` under `chain: [keys]` on every GET /auth, GET /config and config
    /// reload — a customer-visible change no ruling covers. The grant keeps the strict predicate.
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

    /// `GET /api/v1/admin/hooks/{name}/health` — best-effort transport reachability for one hook. Read
    /// scope. `not_found` if the name is unregistered. NEVER fires the hook: for a socket it does a
    /// short-timeout connect probe (`reachable = Some(_)`); for a webhook (or on non-unix) it reports
    /// `reachable = None` with a note (webhooks are probed on demand at request time, not here).
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

    /// Project a registry `HookCfg` into the wire `HookView` against the LIVE global wiring.
    fn hook_view(&self, name: &str, cfg: &HookCfg) -> HookView {
        project_hook_view(name, cfg, &self.app.global_hooks)
    }
}

/// THE LINKED STORE ROWS of the store catalog: one `compiled-in` row per store this build links, in
/// the root's table order (none a default: a config names its store, Q-STORE = (B)). Read off the
/// kernel's installed root rows, so admin names no store instance.
fn linked_store_rows() -> Vec<PluginView> {
    let stores = busbar_kernel::preflight::root_rows().stores;
    let row = |s: &busbar_kernel::preflight::LinkedStore| {
        PluginView::basic(s.0.to_string(), "store", "compiled-in", None, None)
    };
    stores.iter().map(row).collect()
}

/// Add one row's classes into a rollup's: counts summed saturating like the token columns, costs
/// through the ledger's rollup, CHECKED like `spend_micros` (item 28) — `None` when a cost left the range, so the read refuses
/// rather than serving a figure pinned at the ceiling.
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

/// A usage rollup the ledger refused (it left the range), logged as every usage-read failure is and
/// answered `internal`: the read serves no figure pinned at the ceiling.
fn rollup_refused(error: &'static str) -> AdminError {
    diag_error!(
        ADMIN_STORE_OPERATION_FAILED,
        operation = "usage.price",
        error = error,
        "admin store operation failed"
    );
    AdminError::Internal
}

/// The dry run itself, on a blocking thread (see [`AdminService::validate_config`]): resolve, the
/// boot-time semantic validation, then the plugin and secret pre-flight over the running install's
/// `plugins_dir`.
fn validate_config_blocking(
    mut deploy: DeployCfg,
    defs: &std::collections::HashMap<String, ProviderDef>,
    plugins_dir: String,
    rules: &std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>,
) -> ConfigValidateView {
    // Resolve first (cross-references config.yaml providers against providers.yaml defs); if that
    // fails there is no RootCfg to hand to the semantic validator, so return the resolve errors.
    let root = match busbar_kernel::config::resolve(&deploy, defs) {
        Ok(root) => root,
        Err(errors) => return ConfigValidateView { ok: false, errors },
    };
    // SECURITY (R3-B): the plugin pre-flight SCANS `plugins.dir` — `fs::read_dir` plus a read of
    // every tarball it finds. On THIS endpoint `deploy` is CALLER-SUPPLIED, so honoring its
    // `plugins.dir` turned validation into an arbitrary-path readability + directory-enumeration
    // oracle for any token that can reach it (`plugins.dir: /root/.ssh`). PIN the scanned directory
    // to the RUNNING install's plugins dir: every store/auth/hook/secret REFERENCE is still linted
    // against the plugins that are ACTUALLY installed — the CI dry-run use case.
    deploy.plugins.dir = plugins_dir;
    // THE ONE VALIDATOR (`config_validate::check`), the sequence boot and `--validate` run, with the
    // composition root's rules an apply's build judges: a dry run never answers green for a
    // configuration the apply or the CLI would refuse. Manifest-only: nothing is `dlopen`ed.
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
