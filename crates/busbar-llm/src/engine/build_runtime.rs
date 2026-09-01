// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLANE'S `build_runtime` SEAM (1.6.0 money-path Phase 3-4 C — THE PIVOT).
//!
//! `busbar-core`'s `appbuild` populates the neutral [`LlmBuildInput`] carrier from the resolved config
//! and hands it across the `PlaneDecl::build_runtime` fn-pointer as `&dyn Any` (single-compiled-safe —
//! the carrier holds NO `busbar_core::` type). Here, IN-PLANE, we downcast it and rebuild the concrete
//! [`Lane`]/[`WeightedLane`]/[`MemberMeta`]/[`PoolRuntime`]/[`NativeRuntime`] routing tables, re-running
//! the egress-target/credential/upstream-client/probe-schedule resolution against the widened core
//! down-primitives (`busbar_core::egress_auth`, `busbar_core::state::UpstreamClients`, this plane's own
//! `EgressTarget`/`ProbeSchedule`) — the allowed plane→core edge. Byte-identical to the pre-pivot
//! core-resident lowering (old `appbuild`'s lane/pool build loop).
//!
//! Fallible resolution (`build_egress_targets`, the OAuth token-endpoint SSRF vet) is `expect`ed here:
//! the fn-pointer is infallible and `config_validate` runs the identical checks before every apply
//! (validate == apply), so a failure at this point is a validation-coverage bug, surfaced loudly.

use std::collections::HashMap;
use std::sync::Arc;

use busbar_substrate::plane_host::{
    LlmAuthStyle, LlmBuildInput, LlmHealthMode, LlmOnExhausted, PlaneSlots,
};

use busbar_core::egress_auth::{self, MetadataSsrfPolicy};

use crate::engine::health::ProbeSchedule;
use crate::engine::{
    build_egress_targets, host_from_base, Lane, MemberMeta, NativeRuntime, PoolRuntime, QueuedDepth,
    WeightedLane,
};

/// Map the neutral [`LlmAuthStyle`] back to the core `Option<ProviderAuth>` the sync
/// `egress_auth::resolve` reads (the OAuth styles never route through `resolve` — they mint at boot).
fn provider_auth(style: LlmAuthStyle) -> Option<busbar_core::config::ProviderAuth> {
    match style {
        LlmAuthStyle::Default => None,
        LlmAuthStyle::Bearer => Some(busbar_core::config::ProviderAuth::Bearer),
        LlmAuthStyle::ApiKey => Some(busbar_core::config::ProviderAuth::ApiKey),
        LlmAuthStyle::JwtBearer => Some(busbar_core::config::ProviderAuth::JwtBearer),
        LlmAuthStyle::OAuthClientCredentials => {
            Some(busbar_core::config::ProviderAuth::OAuthClientCredentials)
        }
    }
}

/// Rebuild the runtime `HealthCfg` from the neutral [`busbar_substrate::plane_host::LlmHealthInput`].
fn health_cfg(
    h: &busbar_substrate::plane_host::LlmHealthInput,
) -> busbar_core::config::HealthCfg {
    busbar_core::config::HealthCfg {
        mode: match h.mode {
            LlmHealthMode::None => busbar_core::config::HealthMode::None,
            LlmHealthMode::Dead => busbar_core::config::HealthMode::Dead,
            LlmHealthMode::Active => busbar_core::config::HealthMode::Active,
        },
        interval_secs: h.interval_secs,
        timeout_secs: h.timeout_secs,
    }
}

/// THE `PlaneDecl::build_runtime` FN-POINTER for the LLM plane. Downcast the neutral carrier, lower it
/// to a [`NativeRuntime`], and hand it back type-erased for `plane_slots[runtime_slot_key(<llm key>)]`.
pub(crate) fn build_runtime(
    input: &dyn std::any::Any,
    prior: Option<&dyn PlaneSlots>,
) -> Arc<dyn std::any::Any + Send + Sync> {
    // Under the test/test-support surface, ensure this plugin's six dialect declarations are in the
    // process protocol registry before the lane loop resolves `lane_protocol_name` — the lowering
    // reads `busbar_core::proto::decl_for` (folds `register_test_protocols`), and a `TestApp`/`build_once`
    // build in a binary that has not yet folded them (core's own test binary, or a filtered plane run)
    // would otherwise panic "unknown protocol". Idempotent (dedupes by name); a no-op in production.
    #[cfg(any(test, feature = "test-support"))]
    busbar_substrate::proto::register_test_protocols(crate::DECLS);
    let input = input
        .downcast_ref::<LlmBuildInput>()
        .expect("LlmBuildInput: the LLM plane's build_runtime received a foreign carrier");

    // The PRIOR generation's runtime (for the warm-client + probe-schedule carry-over), read through
    // the neutral slot seam then downcast to THIS plane's own NativeRuntime.
    let prior_rt: Option<&NativeRuntime> = prior.and_then(|p| {
        p.plane_slot(busbar_substrate::plane_host::runtime_slot_key(
            crate::PLANE_DECL.key,
        ))
        .and_then(|slot| slot.downcast_ref::<NativeRuntime>())
    });

    // ── lanes (one per model, in the carrier's deterministic sorted order — `lanes[i]` IS lane `i`) ──
    let mut lanes: Vec<Lane> = Vec::with_capacity(input.lanes.len());
    let mut by_model: HashMap<String, usize> = HashMap::with_capacity(input.lanes.len());
    for (i, li) in input.lanes.iter().enumerate() {
        by_model.insert(li.model.clone(), i);
        let protocol = busbar_core::proto::lane_protocol_name(&li.protocol).unwrap_or_else(|| {
            panic!(
                "lane '{}' names unknown protocol '{}' (validated core-side)",
                li.model, li.protocol
            )
        });
        // SSRF posture: this provider's allow list ∪ the global one, plus the nuclear allow-all and
        // the operator's denylist — the SAME union config_validate builds.
        let allow_overrides: Vec<String> = li
            .allow_metadata_hosts
            .iter()
            .chain(input.allow_metadata_hosts.iter())
            .cloned()
            .collect();
        let ssrf = MetadataSsrfPolicy {
            allow_overrides: &allow_overrides,
            allow_all: input.allow_all_metadata,
            blocked_hosts: &input.blocked_metadata_hosts,
        };
        let api_key = li.api_key_plaintext.clone();
        let credential = match li.auth_style {
            LlmAuthStyle::JwtBearer => {
                egress_auth::jwt_bearer::build(&api_key, li.scope.as_deref(), li.subject.as_deref(), &ssrf)
                    .unwrap_or_else(|e| panic!("provider for '{}' (jwt-bearer auth): {e}", li.model))
            }
            LlmAuthStyle::OAuthClientCredentials => {
                let token_url = li
                    .token_url
                    .as_deref()
                    .expect("oauth-client-credentials lane requires token_url (validated)");
                let scope = li
                    .scope
                    .as_deref()
                    .expect("oauth-client-credentials lane requires scope (validated)");
                egress_auth::oauth_client_credentials::build(&api_key, token_url, scope, &ssrf)
                    .unwrap_or_else(|e| {
                        panic!("provider for '{}' (oauth-client-credentials auth): {e}", li.model)
                    })
            }
            other => egress_auth::resolve(protocol, provider_auth(other)),
        };
        let base_url = li.base_url.clone();
        let egress_targets = build_egress_targets(
            protocol,
            li.path.as_deref(),
            li.path_base.as_deref(),
            li.upstream_model.as_deref().unwrap_or(&li.model),
            &base_url,
        )
        .unwrap_or_else(|e| panic!("provider for '{}': {e}", li.model));
        let signing_host = host_from_base(&base_url);
        let prebuilt_auth = egress_auth::prebuild_auth(&credential, &api_key, &signing_host);
        lanes.push(Lane {
            model: li.model.clone(),
            provider: li.provider.clone(),
            signing_host,
            base_url,
            api_key: busbar_api::Redacted::new(api_key),
            protocol,
            credential,
            max: li.max_concurrent,
            error_map: Arc::new(li.error_map.clone()),
            context_max: li.context_max,
            path: li.path.clone(),
            path_base: li.path_base.clone(),
            health: li.health.as_ref().map(health_cfg),
            attempt_timeout_ms: li.attempt_timeout_ms,
            reasoning: li.reasoning,
            prompt_caching: li.prompt_caching,
            default_max_tokens: li.default_max_tokens,
            upstream_model: li.upstream_model.clone(),
            egress_targets,
            prebuilt_auth,
        });
    }

    // ── pools (weighted lanes) ──
    let mut pools: HashMap<String, Vec<WeightedLane>> = HashMap::with_capacity(input.pools.len());
    for p in &input.pools {
        let mut weighted: Vec<WeightedLane> = Vec::with_capacity(p.members.len());
        for m in &p.members {
            weighted.push(WeightedLane {
                idx: m.lane_idx,
                weight: m.weight,
                reasoning: m.reasoning,
                attempt_timeout_ms: m.attempt_timeout_ms,
            });
        }
        pools.insert(p.name.clone(), weighted);
    }

    // ── per-pool runtime (member metadata + failover/affinity/breaker/upstream-creds). The routing
    //    policy/gates/rewrites are NOT here — they stay resolved-and-read core-side (the pool-hook
    //    facade). ──
    let mut pool_runtime: HashMap<String, PoolRuntime> = HashMap::with_capacity(input.pools.len());
    for p in &input.pools {
        let members: HashMap<usize, MemberMeta> = p
            .members
            .iter()
            .map(|m| {
                (
                    m.lane_idx,
                    MemberMeta {
                        tier: m.tier.clone(),
                        cost_per_mtok: m.cost_per_mtok,
                        tags: m.tags.clone(),
                    },
                )
            })
            .collect();
        pool_runtime.insert(
            p.name.clone(),
            PoolRuntime {
                members,
                failover: p.failover.as_ref().map(|f| busbar_core::config::FailoverCfg {
                    timeout_secs: f.timeout_secs,
                    exclusions: f.exclusions.clone(),
                    max_hops: f.max_hops,
                }),
                upstream_credentials: p.upstream_credentials,
                affinity: p.affinity.as_ref().map(|a| busbar_core::config::AffinityCfg {
                    mode: busbar_core::config::AffinityMode::Session,
                    header_name: a.header_name.clone(),
                }),
                breaker: p.breaker.as_ref().map(busbar_core::store::BreakerCfg::from_llm),
            },
        );
    }

    let any_pool_upstream_creds_override = pool_runtime
        .values()
        .any(|rt| rt.upstream_credentials.is_some());

    // The fallback-pool routing table mirrors the pools map (any pool can be an on_exhausted target).
    let fallback_pools = pools.clone();

    // Per-pool on_exhausted policy table.
    let mut on_exhausted_cfgs: HashMap<String, busbar_core::config::OnExhausted> =
        HashMap::with_capacity(input.pools.len());
    for p in &input.pools {
        let mode = match &p.on_exhausted {
            LlmOnExhausted::Status503 => busbar_core::config::OnExhausted::Status503,
            LlmOnExhausted::FallbackPool(name) => {
                busbar_core::config::OnExhausted::FallbackPool(name.clone())
            }
            LlmOnExhausted::LeastBad => busbar_core::config::OnExhausted::LeastBad,
            LlmOnExhausted::Queue { max_ms } => {
                busbar_core::config::OnExhausted::Queue { max_ms: *max_ms }
            }
        };
        on_exhausted_cfgs.insert(p.name.clone(), mode);
    }

    // The global-default failover config — the fixed fallback for pools that set no `failover:` of
    // their own. Carried on the input (production fills the `DEFAULT_FAILOVER_*` constants; the test
    // fixture may override), so this is byte-identical to the pre-pivot inline lowering.
    let failover_cfg = input.default_failover.as_ref().map(|f| busbar_core::config::FailoverCfg {
        timeout_secs: f.timeout_secs,
        exclusions: f.exclusions.clone(),
        max_hops: f.max_hops,
    });

    // The active-probe schedule: CARRY the prior generation's Arc iff the lane set is identical (the
    // deadlines are lane-indexed, and a genuine lane change should re-establish probing), else fresh.
    let probe_schedule = match prior_rt {
        Some(pr)
            if pr.lanes.len() == lanes.len()
                && pr
                    .lanes
                    .iter()
                    .zip(lanes.iter())
                    .all(|(a, b)| a.model == b.model && a.provider == b.provider) =>
        {
            pr.probe_schedule.clone()
        }
        _ => Arc::new(ProbeSchedule::new(lanes.len())),
    };

    // The sharded upstream client: REUSE the prior warm pool iff the client-affecting settings are
    // unchanged (its kept-alive upstream sockets), else rebuild so a changed setting takes effect.
    let reuse_prior_client = prior_rt.is_some_and(|pr| pr.client_settings == input.client_settings);
    let client = if let (true, Some(pr)) = (reuse_prior_client, prior_rt) {
        pr.client.clone()
    } else {
        crate::engine::install_proxy_tunnel_if_configured()
            .unwrap_or_else(|e| panic!("upstream proxy tunnel: {e}"));
        let shard_count = busbar_core::state::UpstreamClients::shard_count();
        let idle_per_host_per_shard = input
            .client_settings
            .pool_max_idle_per_host
            .div_ceil(shard_count)
            .max(1);
        let cs = input.client_settings;
        let make_one = || {
            busbar_core::proxy::build_egress_client(&crate::engine::EgressClientSpec::llm_lane(
                idle_per_host_per_shard,
                cs.pool_idle_timeout_secs,
                cs.http1_only,
                cs.h2_prior_knowledge,
            ))
        };
        busbar_core::state::UpstreamClients::build(shard_count, make_one)
    };

    Arc::new(NativeRuntime {
        lanes,
        by_model,
        pools,
        pool_runtime,
        fallback_pools,
        on_exhausted_cfgs,
        failover_cfg,
        queued_depth: Arc::new(QueuedDepth::default()),
        probe_schedule,
        upstream_credentials: input.upstream_credentials,
        any_pool_upstream_creds_override,
        client,
        client_settings: input.client_settings,
    })
}

/// THE `PlaneDecl::viewer` FN-POINTER for the LLM plane — project this generation's runtime slot into
/// the neutral [`busbar_substrate::plane_host::EngineTablesView`] the core-resident `/metrics`,
/// `/v1/models` and telemetry-label readers consult (cold/scrape paths only). Downcasts to this plane's
/// own [`NativeRuntime`] (which impls the view) and returns the borrow.
pub(crate) fn viewer(
    slot: &(dyn std::any::Any + Send + Sync),
) -> &dyn busbar_substrate::plane_host::EngineTablesView {
    // Core invokes this ONLY on THIS plane's present runtime slot (an absent slot short-circuits to
    // the core-resident `EMPTY_VIEW` before the pointer is reached), so the downcast never misses.
    slot.downcast_ref::<NativeRuntime>()
        .expect("viewer: the LLM plane's viewer received a foreign runtime slot")
}
