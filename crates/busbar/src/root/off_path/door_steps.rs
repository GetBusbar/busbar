// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door planes' off-path code: what `door_steps` needs built once per configuration
//! generation, per bind or by the credential refresher, never per unit. Each pool table, the
//! kernel-owned sections, the provider routes, the members' sealed routes and bindings, the root's
//! configuration rules, the outbound auths' opening and the upstream credentials' renewal.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use busbar_contract::caps::OpClassId;
use busbar_contract::section::{
    MODEL_PROVIDER_KEY, POOL_MEMBERS_KEY, POOL_MEMBER_MODEL_KEY, POOL_MEMBER_NAME_KEY,
    POOL_MEMBER_TIER_KEY, RESERVED_MODELS_KEY, RESERVED_POOLS_KEY, RESERVED_SECTION_KEYS,
    RESERVED_WORK_KEY,
};
use busbar_contract::yaml::{MappingExt, ValueExt};
use busbar_contract::MeterClassId;
use busbar_kernel::state::App;

use crate::root::door_steps::{
    offline_root_rules, plane_lane, presenting, DoorFacts, DoorPools, EndpointStripped,
    MainLogSink, POOL_BREAKER_KEY,
};

impl DoorPools {
    pub(crate) fn of(
        section: &busbar_contract::yaml::Value,
        declared: &str,
    ) -> Result<Self, String> {
        let Some(map) = section.as_mapping() else {
            return Ok(Self::default());
        };
        let key = |k: &busbar_contract::yaml::Value| k.as_str().map(str::to_owned);

        let models = map
            .get_key(RESERVED_MODELS_KEY)
            .and_then(busbar_contract::yaml::Value::as_mapping);
        let entries: Vec<String> = match models {
            Some(models) => models.keys().filter_map(key).collect(),
            None => map
                .keys()
                .filter_map(key)
                .filter(|k| {
                    k != RESERVED_POOLS_KEY
                        && k != RESERVED_WORK_KEY
                        && !RESERVED_SECTION_KEYS.contains(&k.as_str())
                })
                .collect(),
        };
        let mut pools: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut tiers: BTreeMap<String, Vec<u32>> = BTreeMap::new();
        for (name, pool) in map
            .get_key(RESERVED_POOLS_KEY)
            .and_then(busbar_contract::yaml::Value::as_mapping)
            .into_iter()
            .flatten()
        {
            let Some(name) = key(name) else {
                continue;
            };
            let listed = members(pool).map_err(|e| format!("pool '{name}': {e}"))?;
            pools.insert(
                name.clone(),
                listed.iter().map(|(m, _)| m.clone()).collect(),
            );
            tiers.insert(name, listed.into_iter().map(|(_, t)| t).collect());
        }
        let fallbacks = map
            .get_key(RESERVED_POOLS_KEY)
            .and_then(busbar_contract::yaml::Value::as_mapping)
            .map(|pools| {
                pools
                    .iter()
                    .filter_map(|(name, pool)| {
                        let fallback = pool
                            .get(ON_EXHAUSTED_KEY)?
                            .get(FALLBACK_POOL_KEY)?
                            .as_str()?;
                        Some((key(name)?, fallback.to_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let member_granted = map
            .get_key(RESERVED_POOLS_KEY)
            .and_then(busbar_contract::yaml::Value::as_mapping)
            .map(|pools| {
                pools
                    .iter()
                    .filter(|(_, pool)| {
                        pool.get(busbar_contract::section::POOL_MEMBER_GRANTED_KEY)
                            .and_then(busbar_contract::yaml::Value::as_bool)
                            .unwrap_or(false)
                    })
                    .filter_map(|(name, _)| key(name))
                    .collect()
            })
            .unwrap_or_default();

        let breakers = map
            .get_key(RESERVED_POOLS_KEY)
            .and_then(busbar_contract::yaml::Value::as_mapping)
            .map(|pools| {
                pools
                    .iter()
                    .filter_map(|(name, pool)| {
                        let block = pool.get(POOL_BREAKER_KEY)?.clone();
                        Some((key(name)?, busbar_contract::yaml::from_value(block).ok()?))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let registration_default = busbar_contract::section::default_entry_timeout_ms(declared);
        let timeouts = entries
            .iter()
            .filter_map(|entry| {
                let written = models
                    .unwrap_or(map)
                    .get_key(entry.as_str())
                    .and_then(|e| e.get(busbar_contract::section::ENTRY_TIMEOUT_KEY))
                    .and_then(busbar_contract::yaml::Value::as_str)
                    .and_then(|t| busbar_contract::section::entry_timeout_ms(t).ok());
                let ms = match (written, models) {
                    (Some(ms), _) => ms,
                    (None, None) => registration_default?,
                    (None, Some(_)) => return None,
                };
                Some((entry.clone(), ms))
            })
            .collect();
        let entry_set = Self::entry_set(&entries);
        let member_pools = Self::member_pools(&pools, &member_granted);
        Ok(DoorPools {
            entries,
            pools,
            fallbacks,
            member_granted,
            timeouts,
            tiers,
            breakers,
            entry_set,
            member_pools,
        })
    }

    pub(crate) fn entry_set(entries: &[String]) -> std::collections::BTreeSet<String> {
        entries.iter().cloned().collect()
    }

    pub(crate) fn member_pools(
        pools: &BTreeMap<String, Vec<String>>,
        granted: &std::collections::BTreeSet<String>,
    ) -> BTreeMap<String, String> {
        let mut by_entry = BTreeMap::new();
        for (pool, members) in pools.iter().filter(|(pool, _)| granted.contains(*pool)) {
            for member in members {
                if !by_entry.contains_key(member) {
                    by_entry.insert(member.clone(), pool.clone());
                }
            }
        }
        by_entry
    }
}

pub(crate) const ON_EXHAUSTED_KEY: &str = "on_exhausted";
pub(crate) const FALLBACK_POOL_KEY: &str = "fallback_pool";

pub(crate) fn members(pool: &busbar_contract::yaml::Value) -> Result<Vec<(String, u32)>, String> {
    let Some(list) = pool
        .get(POOL_MEMBERS_KEY)
        .and_then(busbar_contract::yaml::Value::as_sequence)
    else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(list.len());
    for (i, m) in list.iter().enumerate() {
        if let Some(name) = m.as_str() {
            out.push((name.to_owned(), 0));
            continue;
        }
        // A declared plane's member is `{name, tier}`; an llm pool member is `{model, ..}`
        // (`kernel_sections`). A member naming neither refuses the load: skipping it would load a
        // pool whose walk reaches no member.
        let Some(name) = m
            .get(POOL_MEMBER_NAME_KEY)
            .or_else(|| m.get(POOL_MEMBER_MODEL_KEY))
            .and_then(busbar_contract::yaml::Value::as_str)
        else {
            return Err(format!(
                "member {i} names no entry (expected `{POOL_MEMBER_NAME_KEY}` or `{POOL_MEMBER_MODEL_KEY}`)"
            ));
        };
        let Some(written) = m.get(POOL_MEMBER_TIER_KEY) else {
            out.push((name.to_owned(), 0));
            continue;
        };
        let tier = written
            .as_u64()
            .and_then(|t| u32::try_from(t).ok())
            .ok_or_else(|| {
                format!("member '{name}' has tier {written:?}, which is no unsigned integer that fits u32")
            })?;
        out.push((name.to_owned(), tier));
    }
    Ok(out)
}

#[must_use]
pub(crate) fn door_facts(
    plane: busbar_kernel::plane_driver::dispatch::LaneQualifier,
    scope_kinds: &[&str],
    classes: &[&'static str],
    fee_units: &[&str],
    audit_kind: &'static str,
    keeps: Vec<busbar_kernel::plane_driver::ResponseKeep>,
) -> DoorFacts {
    let index: foldhash::HashMap<&str, u32> =
        classes.iter().zip(0u32..).map(|(c, i)| (*c, i)).collect();
    DoorFacts {
        plane,
        scope_kind: scope_kinds.first().map(|k| (*k).to_string()),
        secondary_scopes: BTreeMap::new(),
        classes: classes.iter().map(|c| (*c).to_string()).collect(),
        route_cost: Vec::new(),
        meter_classes: classes.iter().map(|c| MeterClassId::new(c)).collect(),
        fee_units: fee_units
            .iter()
            .filter_map(|f| index.get(f).copied())
            .collect(),
        audit_kind: OpClassId::new(audit_kind),
        keeps,
        translations: (Arc::default(), Arc::default()),
        dialects: Arc::default(),
        bench_below_trip_threshold: None,
        metric_lanes: Vec::new(),
        stream_ceiling_secs: 0,
    }
}

#[must_use]
pub(crate) fn label_bound(
    plane: &str,
    pools: &DoorPools,
    vocabulary: &[String],
) -> crate::root::egress_ports::LabelBound {
    let mut bound = crate::root::egress_ports::LabelBound::new(vocabulary.iter().cloned());
    for label in pools.pools().keys() {
        let mut labels = Vec::new();
        let mut entries = Vec::new();
        let mut at = Some(label.as_str());
        while let Some(pool) = at.filter(|p| !labels.iter().any(|l: &String| l == p)) {
            labels.push(pool.to_string());
            entries.extend(pools.pools().get(pool).into_iter().flatten().cloned());
            at = pools.fallback(pool);
        }
        bound = bound.reaching(label, labels, entries);
    }
    for entry in pools.entries() {
        bound = bound.reaching(&plane_lane(plane, entry), [], [entry.clone()]);
    }
    bound
}

pub(crate) fn compose_egress(
    facts: &DoorFacts,
    pools: &DoorPools,
    caller: busbar_contract::conn::InstanceId,
    conns: Arc<dyn busbar_contract::conn::PollConns>,
    routes: &BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>,
    journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
    clock: busbar_ports::clock::HostClock,
    stream_ceiling_secs: u64,
) -> Result<busbar_kernel::plane_driver::Egress, String> {
    use busbar_kernel_egress::{Member, OnExhausted, Pool};
    let mut members: BTreeMap<String, Member> = BTreeMap::new();
    let mut sealed = foldhash::HashMap::default();
    let mut names = Vec::new();
    for (entry, id) in pools.entries().iter().zip(0u64..) {
        let Some(route) = routes.get(entry) else {
            continue;
        };

        let mut route = route.clone();
        let keep_of = |need: busbar_contract::conn::NeedId| {
            facts
                .keeps
                .get(need.0 as usize)
                .cloned()
                .unwrap_or_default()
        };
        route.keep = keep_of(route.need);
        for (need, keep) in &mut route.rides {
            *keep = keep_of(*need);
        }

        for (need, base_url) in ridden(&route) {
            conns
                .anchor(
                    caller,
                    need,
                    &route.provider,
                    &base_url,
                    route.anchors_for(need),
                )
                .map_err(|e| {
                    format!("member '{entry}': its trust anchors could not be sealed: {e}")
                })?;

            conns
                .seal_reach(
                    caller,
                    need,
                    &route.provider,
                    &base_url,
                    route.anchors_for(need).private_reach,
                )
                .map_err(|e| {
                    format!("member '{entry}': its private reach could not be sealed: {e}")
                })?;
        }
        let destination = busbar_contract::dest::DestinationId::new(id);
        let name = plane_lane(facts.plane.lane_prefix(), entry);

        let mut member = Member::new(destination, name.clone(), 1);
        member.attempt_timeout_ms = pools.timeout_ms(entry);
        members.insert(entry.clone(), member);
        sealed.insert(destination, route);
        names.push((destination, name));
    }
    let mut built: foldhash::HashMap<String, Pool> = foldhash::HashMap::default();
    for (label, entries) in pools.pools() {
        let list = entries
            .iter()
            .enumerate()
            .map(|(index, e)| {
                let mut member = members.get(e).cloned().ok_or_else(|| {
                    format!("pool '{label}' names entry '{e}', which has no sealed route")
                })?;
                member.tier = pools.tier(label, index);
                Ok(member)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut pool = Pool::new(label.clone(), list);
        if let Some(fallback) = pools.fallback(label) {
            let fallback = fallback.to_string();
            pool.on_exhausted = OnExhausted::FallbackPool(fallback);
        }
        built.insert(label.clone(), pool);
    }
    for member in members.values() {
        built.insert(
            member.name.as_str().to_owned(),
            Pool::new(member.name.as_str(), vec![member.clone()]),
        );
    }

    let cell = |pool: Option<&str>| {
        let mut cfg = busbar_kernel::store::pool_breaker_cfg(pool.and_then(|p| pools.breaker(p)));
        if let Some(bench) = facts.bench_below_trip_threshold {
            cfg.bench_below_trip_threshold = bench;
        }
        cfg
    };
    let policy = built.keys().fold(
        crate::root::adapters::BreakerPolicy::new().with_default_cell(cell(None)),
        |policy, pool| policy.with_pool(pool.as_str(), cell(Some(pool.as_str()))),
    );

    let (hard_down_cooldown_secs, max_honored_retry_after_secs) =
        busbar_kernel::config::limits::installed().map_or(
            (
                busbar_kernel::config::limits::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
                busbar_kernel::config::limits::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
            ),
            |l| (l.hard_down_cooldown_secs, l.max_honored_retry_after_secs),
        );
    let unit = busbar_kernel_breaker::BreakerUnit::new()
        .with_limits(hard_down_cooldown_secs, max_honored_retry_after_secs);
    Ok(busbar_kernel::plane_driver::Egress {
        caller,
        conns,
        breaker: busbar_kernel::plane_driver::fixed_breaker(Arc::new(
            crate::root::adapters::BreakerAdapter::new(unit, policy),
        )),
        capacity: Arc::new(crate::root::egress_ports::MemberPermits::new(Vec::new())),
        clock,
        journal,
        telemetry: Arc::new(
            crate::root::egress_ports::WalkTelemetry::new(names).bounded(label_bound(
                facts.plane.lane_prefix(),
                pools,
                &facts.metric_lanes,
            )),
        ),
        pools: built,
        routes: sealed,
        stream_ceiling_secs,
        stated_ceiling_secs: facts.stream_ceiling_secs,
        error_body_max: busbar_kernel::config::limits::installed().map_or(
            busbar_kernel::plane_driver::DEFAULT_ERROR_BODY_MAX,
            |limits| limits.upstream_error_body_max_bytes,
        ),
    })
}

/// WHAT A DOOR PLANE IS SEALED OVER, for ONE configuration generation (spec Part 1 line 569: one
/// validated `{section: value}` object per `open`/`refresh`): the kernel-owned sections it reads
/// ([`kernel_sections`]), the providers its members are reached through ([`provider_routes`]) and
/// the model-serving pools' bounds ([`crate::root::model_egress::ModelPools`]). Projected from each
/// resolved configuration as it is built (the root's install record,
/// `busbar_kernel::preflight::RootInstall::config_projection`), and read back when that generation
/// is swapped in.
#[derive(Debug, Clone)]
pub(crate) struct DoorConfig {
    /// Complete native owner retained with this App, including invocation registrations.
    pub(crate) native_generation: Option<Arc<crate::root::min3_candidate::NativeGeneration>>,
    /// Exact candidate-native dispatchers; request lookup always uses its retained App.
    pub(crate) native_slots: crate::root::min3_physical::NativeSlots,
    /// Effective physical listener settings of this candidate, before publication.
    pub(crate) listeners: Result<crate::root::boot::ListenerNeeds, String>,
    /// The ordered configured data auth positions, resolved against this candidate's opened auths.
    pub(crate) data_chain: Vec<String>,
    /// The kernel-owned sections, and beside them every plane section the configuration carries RAW
    /// (a door plane's other owned sections among them: a config apply hands a plane its owned
    /// sections from here, as boot hands them from the document's sections).
    pub(crate) sections: Result<BTreeMap<&'static str, busbar_contract::yaml::Value>, String>,
    /// The providers, by name.
    pub(crate) providers: BTreeMap<String, ProviderRoute>,
    /// The model-serving pools' bounds.
    pub(crate) model_pools: crate::root::model_egress::ModelPools,
}

#[must_use]
pub(crate) fn door_config(
    cfg: &busbar_kernel::config::RootCfg,
) -> Arc<dyn std::any::Any + Send + Sync> {
    let sections = kernel_sections(cfg).map(|mut sections| {
        for (key, value) in cfg.instance_sections() {
            sections.entry(key).or_insert(value);
        }
        sections
    });
    let config = DoorConfig {
        native_generation: None,
        native_slots: Default::default(),
        listeners: sections
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|sections| crate::root::boot::configured_listener_needs(cfg, sections)),
        data_chain: cfg
            .auth
            .as_ref()
            .map(|auth| auth.chain.iter().map(|entry| entry.name.clone()).collect())
            .unwrap_or_default(),
        sections,
        providers: provider_routes(
            &cfg.providers,
            &busbar_kernel::config_validate::MetadataPosture::global(cfg),
        ),
        model_pools: crate::root::model_egress::ModelPools::of(cfg),
    };
    Arc::new(config)
}

pub(crate) fn listener_needs(
    cfg: &busbar_kernel::config::RootCfg,
) -> Result<crate::root::boot::ListenerNeeds, String> {
    let mut sections = kernel_sections(cfg)?;
    for (key, value) in cfg.instance_sections() {
        sections.entry(key).or_insert(value);
    }
    crate::root::boot::configured_listener_needs(cfg, &sections)
}

pub(crate) fn owned_anchor_refusal(at: &str, written: &str) -> Result<(), String> {
    busbar_core_connector::tls::client::operator_ca_config(written.as_bytes())
        .map(|_| ())
        .map_err(|_| {
            format!(
                "`{at}` is not a usable trust anchor: it must be one or more PEM certificates the \
                 TLS stack takes as a trust anchor"
            )
        })
}

pub(crate) fn owned_anchors_refusal<P: AsRef<str>>(
    paths: &[P],
    sections: &BTreeMap<&'static str, busbar_contract::yaml::Value>,
) -> Result<(), String> {
    for path in paths {
        let Some(at) = busbar_contract::section::owned_path(path.as_ref()) else {
            continue;
        };
        let mut segments = at.split('.');
        let written = segments
            .next()
            .and_then(|section| sections.get(section))
            .and_then(|v| segments.try_fold(v, |v, key| v.get(key)))
            .and_then(busbar_contract::yaml::Value::as_str)
            .filter(|t| !t.is_empty());
        if let Some(written) = written {
            owned_anchor_refusal(at, written)?;
        }
    }
    Ok(())
}

/// THE COMPOSITION ROOT'S RULES OF A CONFIGURATION (`busbar_kernel::appbuild::RootRules`): what
/// the build judges every configuration by before any part of it is built, at boot and at every
/// apply, rebuild or dry run, through the `App` each generation keeps them in. Today, the owned
/// trust anchors the composed door planes name (`owned.<section>.<key>`): each, as a
/// configuration writes it, judged by [`owned_anchor_refusal`], the rule the boot judges it by, so a
/// configuration whose anchor the boot would refuse never goes live through an apply, and the
/// running generation (its declared trust among it) is untouched. They also hold the deployment's
/// one destination guard, which hears each committed configuration's destinations through them.
pub(crate) struct Rules {
    reader: Arc<dyn busbar_kernel::appbuild::RootRules>,
    pub(crate) member_tls_sections: Mutex<Vec<&'static str>>,
    native_listeners: Option<Arc<crate::root::min3_listener_plan::NativeListenerPlan>>,
    native_candidate: Option<Arc<crate::root::min3_candidate::Factory>>,
    /// The owned trust anchors the composed door planes name, held as each plane is composed.
    pub(crate) owned_anchors: Mutex<Vec<&'static str>>,
    /// The declaring sections of the door planes the boot bound but did not open (their section
    /// absent from the boot configuration), held once the boot composed its planes
    /// ([`Rules::hold_unopened`]). A door plane is opened once, at boot, so a configuration that
    /// writes one of these is restart-to-apply ([`Rules::planes_awaiting_restart`]).
    pub(crate) unopened: Mutex<Vec<&'static str>>,
    /// The deployment's one destination guard (`root::connector::dest_judge`), told each committed
    /// configuration's destinations ([`Rules::with_reader`]). `None`: no guard hears a commit.
    pub(crate) guard: Option<Arc<dyn busbar_kernel::host_services::DestJudge>>,
    /// The discovered plane doors the boot's configuration did not use, so the boot never loaded
    /// them (Law 7), held from the boot plan ([`Rules::hold_unloaded`]). A running process cannot
    /// take a first section of one: an apply or reload that writes one is refused
    /// ([`unloaded_plane_refusal`]).
    pub(crate) unloaded: Mutex<Vec<crate::root::loader::boot::Candidate>>,
}

impl std::fmt::Debug for Rules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rules")
            .field("owned_anchors", &self.owned_anchors)
            .field("unopened", &self.unopened)
            .field("guard", &self.guard.is_some())
            .finish()
    }
}

#[cfg(test)]
impl Default for Rules {
    fn default() -> Self {
        Self::with_reader(None, Arc::new(busbar_kernel::appbuild::AcceptAll))
    }
}

impl Rules {
    /// Keep the exact reader and bootstrap owners through every serving candidate read.
    pub(crate) fn with_reader(
        guard: Option<Arc<dyn busbar_kernel::host_services::DestJudge>>,
        reader: Arc<dyn busbar_kernel::appbuild::RootRules>,
    ) -> Self {
        Self {
            reader,
            member_tls_sections: Mutex::new(Vec::new()),
            native_listeners: None,
            native_candidate: None,
            owned_anchors: Mutex::new(Vec::new()),
            unopened: Mutex::new(Vec::new()),
            guard,
            unloaded: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn with_native_listeners(
        &self,
        listeners: Arc<crate::root::min3_listener_plan::NativeListenerPlan>,
    ) -> Self {
        let mut next = self.copy_rules();
        next.native_listeners = Some(listeners);
        next
    }

    pub(crate) fn with_native_candidate(
        &self,
        candidate: Arc<crate::root::min3_candidate::Factory>,
    ) -> Self {
        let mut next = self.copy_rules();
        next.native_candidate = Some(candidate);
        next
    }

    fn copy_rules(&self) -> Self {
        Self {
            reader: Arc::clone(&self.reader),
            member_tls_sections: Mutex::new(
                self.member_tls_sections
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone(),
            ),
            native_listeners: self.native_listeners.clone(),
            native_candidate: self.native_candidate.clone(),
            owned_anchors: Mutex::new(
                self.owned_anchors
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone(),
            ),
            unopened: Mutex::new(
                self.unopened
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone(),
            ),
            guard: self.guard.clone(),
            unloaded: Mutex::new(
                self.unloaded
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone(),
            ),
        }
    }

    /// Rules whose destination guard hears each committed configuration's destinations.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn hearing(guard: Arc<dyn busbar_kernel::host_services::DestJudge>) -> Self {
        Self::with_reader(Some(guard), Arc::new(busbar_kernel::appbuild::AcceptAll))
    }

    pub(crate) fn hold_member_tls_sections(&self, sections: &[&'static str]) {
        let mut held = self
            .member_tls_sections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for section in sections {
            if !held.contains(section) {
                held.push(section);
            }
        }
    }

    pub(crate) fn hold_owned_anchors(&self, paths: &[&'static str]) {
        let mut held = self
            .owned_anchors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for path in paths
            .iter()
            .filter(|p| busbar_contract::section::owned_path(p).is_some())
        {
            if !held.contains(path) {
                held.push(path);
            }
        }
    }

    pub(crate) fn hold_unloaded(&self, candidates: Vec<crate::root::loader::boot::Candidate>) {
        self.unloaded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(candidates);
    }

    pub(crate) fn hold_unopened(&self, sections: impl IntoIterator<Item = &'static str>) {
        let mut held = self
            .unopened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for section in sections {
            if !held.contains(&section) {
                held.push(section);
            }
        }
    }
}

/// The async native producer supplies fresh owners and the actual reserved publication
/// epoch. This seals only the exclusively owned candidate; no live owner is replaced.
pub(crate) fn prepare_native_candidate(
    plan: &crate::root::min3_listener_plan::NativeListenerPlan,
    app: &mut App,
    served: &crate::root::serve::Served,
    owners: &crate::root::min3_physical::SlotOwners,
) -> Result<(), String> {
    check_native_topology(app, plan)?;
    if app.prepared_generation() != Some(owners.epoch) {
        return Err("native candidate has no matching reserved publication epoch".into());
    }
    let native = served
        .native
        .as_ref()
        .ok_or("candidate has no freshly prepared native owners")?;
    if native.config_version != app.config_version
        || !Arc::ptr_eq(&native.auth, &owners.auth)
        || !Arc::ptr_eq(&native.inventories, &owners.inventories)
    {
        return Err("native listener owners belong to another serving candidate".into());
    }
    crate::root::min3_admin_auth::install(app, Arc::clone(&owners.auth), owners.epoch)?;
    let slots = plan.assemble(app, served, owners)?;
    crate::root::serve::install_native_slots(app, slots)
}

fn check_native_topology(
    app: &App,
    plan: &crate::root::min3_listener_plan::NativeListenerPlan,
) -> Result<(), String> {
    let config = app
        .config_projection
        .as_ref()
        .and_then(|value| value.downcast_ref::<DoorConfig>())
        .ok_or("native candidate has no root configuration projection")?;
    let needs = config.listeners.as_ref().map_err(Clone::clone)?;
    if !needs.needs.is_empty() || needs.binds.as_slice() != plan.binds() {
        return Err(
            "native listener topology changed; write the configuration file and restart".into(),
        );
    }
    Ok(())
}

pub(crate) fn writes_plane(section: &str, cfg: &busbar_kernel::config::RootCfg) -> bool {
    cfg.plane_sections.contains(section)
}

#[must_use]
pub(crate) fn unloaded_doors() -> Vec<crate::root::loader::boot::Candidate> {
    let bound = crate::root::boot::door_planes();
    crate::root::boot::DOOR_CANDIDATES
        .get()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|c| c.kind == busbar_contract::abi::mechanism::KindCode::Plane)
        .filter(|c| !bound.iter().any(|(instance, _)| *instance == c.name))
        .cloned()
        .collect()
}

#[must_use]
pub(crate) fn unloaded_plane_refusal(
    unloaded: &[crate::root::loader::boot::Candidate],
    keys: &[&str],
) -> Option<String> {
    let uses = crate::root::loader::boot::Uses {
        roots: keys.iter().map(|k| (*k).to_string()).collect(),
        ..Default::default()
    };
    unloaded.iter().find_map(|c| {
        crate::root::loader::boot::plane_use(&uses, c).map(|section| {
            format!(
                "`{section}:` is the section of the `{plane}` plane, which this process did not \
                 load because its configuration did not use it at start; a first `{section}:` \
                 cannot take effect on a running process, so the change was refused and nothing \
                 was changed: write it in the config file and restart.",
                plane = c.name
            )
        })
    })
}

impl busbar_kernel::appbuild::RootRules for Rules {
    fn prepare_read(
        &self,
        input: &busbar_kernel::config::grammar::PhaseOneIn<'_>,
    ) -> Result<
        busbar_kernel::config::grammar::PreparedConfigRead,
        busbar_kernel::config::GrammarRefusal,
    > {
        self.reader.prepare_read(input)
    }

    fn prepare_candidate<'a>(
        &'a self,
        cfg: &'a busbar_kernel::config::RootCfg,
        plugins: &'a busbar_kernel::config::PluginsCfg,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<Option<busbar_kernel::appbuild::CandidatePreparation>, String>,
    > {
        match &self.native_candidate {
            Some(candidate) => candidate.prepare(cfg),
            None => self.reader.prepare_candidate(cfg, plugins),
        }
    }

    fn grammar(
        &self,
        input: &busbar_kernel::config::grammar::PhaseOneIn<'_>,
    ) -> Result<busbar_kernel::config::Grammar, busbar_kernel::config::GrammarRefusal> {
        self.reader.grammar(input)
    }

    fn secret_resolver<'a>(
        &'a self,
        cfg: &'a busbar_kernel::config::RootCfg,
        plugins: &'a busbar_kernel::config::PluginsCfg,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<Arc<busbar_kernel::config::secret::SecretResolver>, String>,
    > {
        self.reader.secret_resolver(cfg, plugins)
    }

    /// An unstamped boot runs the planned document, not the 1.5.5 bytes on disk (MIGRATE-ON-BOOT
    /// r42 §3 step 2).
    fn held_document(
        &self,
        path: &std::path::Path,
    ) -> Option<busbar_contract::secure::SecureString> {
        self.reader.held_document(path)
    }
    fn claim_ticket_admission(
        &self,
        identity: &busbar_kernel::host_services::VerifiedTicketIdentity,
    ) -> busbar_kernel::host_services::TicketClaimDisposition {
        crate::root::serve::claim_ticket_custody(identity)
    }

    fn check_built(&self, app: &mut App) -> Result<(), String> {
        if let Some(config) = app
            .config_projection
            .as_ref()
            .and_then(|c| c.downcast_ref::<DoorConfig>())
        {
            config.sections.as_ref().map_err(Clone::clone)?;
        }
        if let Some(plan) = &self.native_listeners {
            let generation = crate::root::min3_candidate::generation(app)?;
            if generation.native.config_version != app.config_version
                || !generation.has_prepared_workers()
            {
                return Err(
                    "native candidate has no complete generation with dormant workers".into(),
                );
            }
            check_native_topology(app, plan)?;
            let config = app
                .config_projection
                .as_ref()
                .and_then(|value| value.downcast_ref::<DoorConfig>())
                .ok_or("native candidate has no root configuration projection")?;
            let required: std::collections::BTreeSet<_> =
                plan.binds().iter().map(|bind| bind.at.as_str()).collect();
            if config.native_slots.len() != required.len()
                || plan.binds().iter().any(|bind| {
                    config
                        .native_slots
                        .get(&bind.at)
                        .is_none_or(|slot| slot.slot() != bind.at)
                })
            {
                return Err(
                    "native candidate has no complete freshly prepared listener map".into(),
                );
            }
            return Ok(());
        }
        Ok(())
    }

    fn unloaded_plane_refusal(&self, keys: &[&str]) -> Option<String> {
        unloaded_plane_refusal(
            &self
                .unloaded
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            keys,
        )
    }

    fn planes_awaiting_restart(&self, cfg: &busbar_kernel::config::RootCfg) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = self
            .unopened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .copied()
            .filter(|section| writes_plane(section, cfg))
            .collect();
        out.sort();
        out
    }

    fn check(&self, cfg: &busbar_kernel::config::RootCfg) -> Result<(), String> {
        self.reader.check(cfg)?;
        offline_root_rules(cfg).map_err(|e| e.join("\n"))?;
        let anchors = self
            .owned_anchors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let sections = cfg.instance_sections();
        owned_anchors_refusal(&anchors, &sections)?;
        for section in self
            .member_tls_sections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            if let Some(written) = sections.get(section) {
                member_tls_section_refusal(written)?;
            }
        }
        Ok(())
    }

    fn destinations_applied(&self, destinations: &busbar_kernel::config::Destinations) {
        if let Some(guard) = &self.guard {
            guard.destinations_applied(destinations);
        }
    }
}

/// Project the kernel-owned configuration without passing JSON's arbitrary-precision
/// serialization markers to YAML. A provider number outside YAML's scalar domain is refused.
pub(crate) fn kernel_sections(
    cfg: &busbar_kernel::config::RootCfg,
) -> Result<BTreeMap<&'static str, busbar_contract::yaml::Value>, String> {
    use busbar_contract::yaml::{Pairs, Value};
    fn opt(m: &mut Pairs, key: &str, v: Option<Value>) {
        if let Some(v) = v {
            m.insert_key(Value::from(key), v);
        }
    }
    let mut out = BTreeMap::new();
    let mut providers = Pairs::new();
    for (name, p) in &cfg.providers {
        let mut m = Pairs::new();
        for (key, value) in &p.table {
            m.insert_key(
                Value::from(key.clone()),
                provider_yaml(value, &format!("providers.{name}.{key}"))?,
            );
        }
        opt(&mut m, "path", p.path.clone().map(Value::from));
        opt(&mut m, "path_base", p.path_base.clone().map(Value::from));
        opt(
            &mut m,
            "auth",
            p.auth.as_ref().map(style_word).map(Value::from),
        );
        providers.insert_key(Value::from(name.clone()), Value::Map(m));
    }
    let mut models = Pairs::new();
    for (name, model) in &cfg.models {
        let mut m = Pairs::new();
        m.insert_key(
            Value::from(MODEL_PROVIDER_KEY),
            Value::from(model.provider.clone()),
        );
        opt(
            &mut m,
            "upstream_model",
            model.upstream_model.clone().map(Value::from),
        );
        opt(
            &mut m,
            "default_max_tokens",
            model.default_max_tokens.map(Value::from),
        );
        opt(&mut m, "reasoning", model.reasoning.map(Value::from));
        opt(
            &mut m,
            "prompt_caching",
            model.prompt_caching.map(Value::from),
        );
        models.insert_key(Value::from(name.clone()), Value::Map(m));
    }
    let mut pools = Pairs::new();
    for (name, pool) in &cfg.pools {
        let members = pool
            .members
            .iter()
            .map(|member| {
                let mut m = Pairs::new();
                m.insert_key(
                    Value::from(POOL_MEMBER_MODEL_KEY),
                    Value::from(member.model.clone()),
                );
                opt(&mut m, "reasoning", member.reasoning.map(Value::from));
                opt(
                    &mut m,
                    "context_max",
                    member.context_max.map(|n| Value::from(n as u64)),
                );
                Value::Map(m)
            })
            .collect();
        let mut p = Pairs::new();
        p.insert_key(Value::from(POOL_MEMBERS_KEY), Value::Array(members));
        if let Some(busbar_kernel::config::pools::OnExhaustedCfg::FallbackPool(fallback)) =
            &pool.on_exhausted
        {
            p.insert_key(
                Value::from(ON_EXHAUSTED_KEY),
                section_map([(FALLBACK_POOL_KEY, Value::from(fallback.clone()))]),
            );
        }
        if let Some(header) = pool.affinity.as_ref().and_then(|a| a.header_name.as_ref()) {
            p.insert_key(
                Value::from("affinity"),
                section_map([("header_name", Value::from(header.clone()))]),
            );
        }
        pools.insert_key(Value::from(name.clone()), Value::Map(p));
    }
    let limits = section_map([
        (
            "default_max_tokens",
            Value::from(cfg.limits.default_max_tokens),
        ),
        (
            "request_body_max_bytes",
            Value::from(cfg.limits.request_body_max_bytes as u64),
        ),
        (
            "reasoning_effort_budgets",
            section_map([
                (
                    "minimal",
                    Value::from(cfg.limits.reasoning_effort_budgets.minimal),
                ),
                ("low", Value::from(cfg.limits.reasoning_effort_budgets.low)),
                (
                    "medium",
                    Value::from(cfg.limits.reasoning_effort_budgets.medium),
                ),
                (
                    "high",
                    Value::from(cfg.limits.reasoning_effort_budgets.high),
                ),
            ]),
        ),
    ]);
    if !providers.is_empty() {
        out.insert(
            busbar_contract::plugin::Kind::Transport.root(),
            Value::Map(providers),
        );
    }
    let required = |key: &'static str| {
        busbar_kernel::plane_driver::registry::plane_decls()
            .iter()
            .any(|d| d.required_config_sections.contains(&key))
    };
    if !models.is_empty() || !pools.is_empty() || required(RESERVED_MODELS_KEY) {
        out.insert(RESERVED_MODELS_KEY, Value::Map(models));
        out.insert(RESERVED_POOLS_KEY, Value::Map(pools));
    }
    out.insert("limits", limits);
    Ok(out)
}

pub(crate) fn section_map<const N: usize>(
    entries: [(&str, busbar_contract::yaml::Value); N],
) -> busbar_contract::yaml::Value {
    let map = entries
        .into_iter()
        .map(|(key, value)| (busbar_contract::yaml::Value::from(key), value))
        .collect();
    busbar_contract::yaml::Value::Map(map)
}

pub(crate) fn provider_yaml(
    value: &serde_json::Value,
    path: &str,
) -> Result<busbar_contract::yaml::Value, String> {
    use busbar_contract::yaml::Value as Yaml;
    use serde_json::Value as Json;
    Ok(match value {
        Json::Null => Yaml::Null,
        Json::Bool(value) => Yaml::Bool(*value),
        Json::String(value) => Yaml::Text(value.clone()),
        Json::Number(value) => {
            if let Some(value) = value.as_u64() {
                Yaml::from(value)
            } else if let Some(value) = value.as_i64() {
                Yaml::from(value)
            } else if let Some(integer) = decimal_integer(value.as_str()) {
                integer
            } else {
                // Only a declared decimal may become a YAML float. Require the float's
                // shortest decimal to retain the same decimal value; never round an integer
                // or silently truncate an arbitrary-precision decimal to fit the handoff.
                let text = value.as_str();
                let decimal = text
                    .contains(['.', 'e', 'E'])
                    .then(|| value.as_f64())
                    .flatten();
                let exact = decimal.and_then(|float| {
                    let back = serde_json::Number::from_f64(float)?;
                    (decimal_parts(text)? == decimal_parts(back.as_str())?).then_some(float)
                });
                Yaml::from(exact.ok_or_else(|| {
                    format!(
                        "{path}: number cannot be represented without loss in plane configuration"
                    )
                })?)
            }
        }
        Json::Array(values) => Yaml::Array(
            values
                .iter()
                .enumerate()
                .map(|(i, value)| provider_yaml(value, &format!("{path}[{i}]")))
                .collect::<Result<_, _>>()?,
        ),
        Json::Object(values) => Yaml::Map(
            values
                .iter()
                .map(|(key, value)| {
                    Ok((
                        Yaml::from(key.clone()),
                        provider_yaml(value, &format!("{path}.{key}"))?,
                    ))
                })
                .collect::<Result<_, String>>()?,
        ),
    })
}

// Decimal notation can name an exact integer beyond f64's precision. Construct it
// with bounded checked arithmetic; an exponent never controls an allocation.
pub(crate) fn decimal_integer(text: &str) -> Option<busbar_contract::yaml::Value> {
    let (negative, digits, exponent) = decimal_parts(text)?;
    if !(0..=19).contains(&exponent) || (negative && digits == "0") {
        return None;
    }
    let magnitude = digits
        .parse::<u64>()
        .ok()?
        .checked_mul(10_u64.checked_pow(u32::try_from(exponent).ok()?)?)?;
    if negative {
        i64::try_from(-i128::from(magnitude))
            .ok()
            .map(busbar_contract::yaml::Value::from)
    } else {
        Some(busbar_contract::yaml::Value::from(magnitude))
    }
}

// Normalize decimal notation, not binary floating point: 1.25e2 and 125.0 agree.
// Preserve the sign of zero, and refuse exponents too wide for this bounded handoff.
pub(crate) fn decimal_parts(text: &str) -> Option<(bool, String, i64)> {
    let negative = text.starts_with('-');
    let text = text.strip_prefix('-').unwrap_or(text);
    let (mantissa, exponent) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
    let fraction = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let digits = mantissa.replace('.', "");
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Some((negative, "0".into(), 0));
    }
    let significant = digits.trim_end_matches('0');
    let exponent = exponent
        .parse::<i64>()
        .ok()?
        .checked_sub(i64::try_from(fraction).ok()?)?
        .checked_add(i64::try_from(digits.len() - significant.len()).ok()?)?;
    let significant = significant.to_string();
    Some((negative, significant, exponent))
}

/// ONE `providers:` ENTRY as a door plane's member reaches it (THE DESIGN §6 step 2; #50, #51): the
/// `base_url` it dials, its default `protocol` and `error_map` (the dialect fields its plane is handed
/// at open), its credential reference, the `auth:` style it states (`None` = its plane's dialect
/// default) and the parameters that style is opened with.
#[derive(Clone)]
pub(crate) struct ProviderRoute {
    /// `base_url`, as the operator (or the catalog) spelled it, less any `user:pass@`: 1.5.5 dialled,
    /// sent and signed the host after it (v1.5.5 `crates/busbar/src/proxy/egress.rs:18`; row 74, F25),
    /// so the member's route, its sealed reach, its binding and every dial read that host alone.
    pub(crate) base_url: String,
    /// The basic credential that userinfo spelled, read at configuration time and held by the root:
    /// the member's binding is led by it as 1.5.5 sent it ([`crate::root::userinfo::lead_with`]);
    /// the kernel holds the binding's handle, never these bytes.
    pub(crate) userinfo: Option<crate::root::userinfo::UserinfoBasic>,
    /// The default wire protocol (#51).
    pub(crate) protocol: String,
    /// The `error_map`, catalog-merged; empty = none stated.
    pub(crate) error_map: BTreeMap<String, String>,
    /// `api_key`, a reference; resolved once, at the seal.
    pub(crate) credential: busbar_contract::secret_ref::SecretRef,
    /// `auth:`, the style it overrides its plane's dialect default with.
    pub(crate) style: Option<String>,
    /// The style's parameters (`token_url`, `scope`, `subject`, where stated).
    pub(crate) params: StyleParams,
    /// The metadata posture its credential's own token endpoint is judged under at the seal
    /// (`token_uri`, [`StyleParams::token_uri`]).
    pub(crate) metadata: busbar_kernel::config_validate::MetadataPosture,
}

/// THE PARAMETERS A PROVIDER'S `auth:` STYLE IS OPENED WITH, typed: the three keys a provider states
/// (`token_url`, `scope`, `subject`), each present only where the operator wrote it, and the one its
/// credential states (`token_uri`, a `jwt-bearer` service account's token endpoint), filled at the
/// seal once the credential resolves. The JSON object the auth plugin's `open_outbound` reads is
/// built from them at the call, never carried as a bag.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct StyleParams {
    /// `token_url`, where stated.
    pub(crate) token_url: Option<String>,
    /// `token_uri`, the service-account token endpoint: the target
    /// of the serving plugin's `settings.token_uri` need, subject
    /// to the auth-mint endpoint destination policy.
    pub(crate) token_uri: Option<String>,
    /// `scope`, where stated.
    pub(crate) scope: Option<String>,
    /// `subject`, where stated.
    pub(crate) subject: Option<String>,
}

impl StyleParams {
    #[must_use]
    pub(crate) fn to_json(&self) -> serde_json::Value {
        let mut object = serde_json::Map::new();
        for (key, value) in [
            ("token_url", &self.token_url),
            ("token_uri", &self.token_uri),
            ("scope", &self.scope),
            ("subject", &self.subject),
        ] {
            if let Some(v) = value {
                object.insert(key.to_string(), serde_json::Value::String(v.clone()));
            }
        }
        serde_json::Value::Object(object)
    }
}

pub(crate) fn style_word(auth: &busbar_kernel::config::ProviderAuth) -> &str {
    auth.as_str()
}

#[must_use]
pub(crate) fn declared_styles() -> Vec<busbar_contract::auth_calls::DeclaredStyle> {
    use crate::root::loader::dispatch::kinds::auth::{rendered_facts, stated_facts};
    let linked = crate::LINKED
        .auths
        .iter()
        .filter_map(|(_, _, door)| stated_facts(*door).ok())
        .flat_map(|facts| facts.styles);
    let dropped = crate::root::boot::dropped_registry()
        .map_or(&[][..], |r| r.loadable())
        .iter()
        .filter(|r| r.manifest.kind == "auth")
        .filter_map(|r| r.manifest.stated_rendering().ok().flatten())
        .filter_map(|stated| rendered_facts(&stated).ok())
        .flat_map(|facts| facts.styles);
    busbar_contract::auth_calls::listed_styles(linked.chain(dropped).map(|s| {
        busbar_contract::auth_calls::DeclaredStyle {
            name: s.name,
            flags: s.flags,
        }
    }))
}

pub(crate) struct RouteFacts<'a> {
    pub(crate) provider: &'a busbar_kernel::config::ResolvedProvider,
    pub(crate) protocol: String,
    pub(crate) error_map: BTreeMap<String, String>,
}

impl<'a> RouteFacts<'a> {
    pub(crate) fn of(provider: &'a busbar_kernel::config::ResolvedProvider) -> Self {
        Self {
            provider,
            protocol: provider.dialect().to_string(),
            error_map: provider
                .error_map()
                .map(|(code, class)| (code.to_string(), class.to_string()))
                .collect(),
        }
    }
}

impl std::ops::Deref for RouteFacts<'_> {
    type Target = busbar_kernel::config::ResolvedProvider;
    fn deref(&self) -> &Self::Target {
        self.provider
    }
}

#[must_use]
pub(crate) fn provider_routes(
    providers: &busbar_kernel::config::ResolvedProviders,
    security: &busbar_kernel::config_validate::MetadataPosture,
) -> BTreeMap<String, ProviderRoute> {
    providers
        .iter()
        .map(|(name, p)| (name, RouteFacts::of(p)))
        .map(|(name, facts)| {
            // The route takes the facts' owned words; the provider itself is only borrowed.
            let RouteFacts {
                provider: p,
                protocol,
                error_map,
            } = facts;
            (
                name.clone(),
                ProviderRoute {
                    base_url: busbar_kernel_egress::trust::net::strip_userinfo(&p.base_url)
                        .into_owned(),
                    userinfo: crate::root::userinfo::UserinfoBasic::of(&p.base_url),
                    protocol,
                    error_map,
                    credential: p.api_key.clone(),
                    style: p.auth.as_ref().map(|a| style_word(a).to_string()),
                    params: StyleParams {
                        token_url: p.token_url.clone(),
                        token_uri: None,
                        scope: p.scope.clone(),
                        subject: p.subject.clone(),
                    },
                    metadata: security.for_provider(p),
                },
            )
        })
        .collect()
}

#[must_use]
pub(crate) fn dialect_facts(
    section: &busbar_contract::yaml::Value,
    providers: &BTreeMap<String, ProviderRoute>,
) -> Vec<busbar_contract::plane_calls::DialectFacts> {
    busbar_contract::plane_calls::dialect_facts(section, |name| {
        providers
            .get(name)
            .map(|p| (p.protocol.clone(), p.error_map.clone()))
    })
}

pub(crate) type Serving = (
    Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
    crate::root::loader::dispatch::kinds::auth::OutboundStyle,
);

pub(crate) struct OutboundAuths {
    pub(crate) dispatcher: Arc<crate::root::loader::dispatch::Dispatcher>,
    pub(crate) linked: Vec<busbar_kernel::preflight::LinkedAuth>,
    pub(crate) dropped: Option<&'static crate::root::loader::PluginRegistry>,
    pub(crate) conns: crate::root::loader::dispatch::ConnTable,

    pub(crate) catalogue: busbar_kernel::diagnostics::Catalogue,

    pub(crate) linked_facts: std::sync::OnceLock<Vec<AuthRowFacts>>,

    pub(crate) dropped_facts: std::sync::OnceLock<Vec<AuthRowFacts>>,

    pub(crate) opened: crate::root::loader::open_once::OpenOnce<
        String,
        crate::root::loader::dispatch::auth_outbound::OutboundInstance,
    >,

    #[cfg(test)]
    pub(crate) bound: Mutex<Vec<String>>,
}

pub(crate) struct AuthRowFacts {
    pub(crate) name: String,
    pub(crate) door: AuthRowDoor,
    pub(crate) styles: Vec<crate::root::loader::dispatch::kinds::auth::OutboundStyle>,
    pub(crate) per_binding: bool,
}

/// Where an auth row's door is: the build's linked row, or the plugins directory's loadable row,
/// by index.
#[derive(Clone, Copy)]
pub(crate) enum AuthRowDoor {
    Linked(usize),
    Dropped(usize),
}

/// A list's Debug spelling, written straight from its iterator.
pub(crate) struct DebugEntries<I>(I);

impl<I, T> std::fmt::Debug for DebugEntries<I>
where
    I: Iterator<Item = T> + Clone,
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.clone()).finish()
    }
}

impl std::fmt::Debug for OutboundAuths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundAuths")
            .field(
                "linked",
                &DebugEntries(self.linked.iter().map(|(n, _, _)| *n)),
            )
            .finish_non_exhaustive()
    }
}

impl OutboundAuths {
    #[must_use]
    pub(crate) fn new(
        dispatcher: Arc<crate::root::loader::dispatch::Dispatcher>,
        linked: &[busbar_kernel::preflight::LinkedAuth],
        dropped: Option<&'static crate::root::loader::PluginRegistry>,
        conns: crate::root::loader::dispatch::ConnTable,
        catalogue: busbar_kernel::diagnostics::Catalogue,
    ) -> Self {
        let linked = linked.to_vec();
        Self {
            dispatcher,
            linked,
            dropped,
            conns,
            catalogue,
            linked_facts: std::sync::OnceLock::new(),
            dropped_facts: std::sync::OnceLock::new(),
            opened: crate::root::loader::open_once::OpenOnce::new(),
            #[cfg(test)]
            bound: Mutex::default(),
        }
    }

    pub(crate) fn bind_with(
        &self,
        name: &str,
        conns: crate::root::loader::dispatch::ConnTable,
    ) -> crate::root::loader::dispatch::Bind {
        use crate::root::loader::dispatch::{EnvelopeSink, NoSink};
        let sink: Arc<dyn EnvelopeSink> = crate::root::boot::plugin_logs()
            .sink(
                name,
                busbar_contract::abi::mechanism::KindCode::Auth,
                Arc::new(NoSink),
            )
            .map_or_else(
                |_| Arc::new(NoSink) as Arc<dyn EnvelopeSink>,
                |s| Arc::new(s) as Arc<dyn EnvelopeSink>,
            );
        let sink: Arc<dyn EnvelopeSink> = Arc::new(MainLogSink(sink, self.catalogue));
        crate::root::loader::dispatch::Bind {
            accept: Default::default(),
            instance: Arc::from(name),
            max_inflight_cap: 64,
            sink,
            dispatcher: self.dispatcher.adopter(),
            conns,
        }
    }

    pub(crate) fn load(
        &self,
        name: &str,
        door: AuthRowDoor,
    ) -> Option<
        crate::root::loader::dispatch::Plugin<crate::root::loader::dispatch::kinds::auth::Auth>,
    > {
        self.load_with(name, door, self.conns.clone())
    }

    pub(crate) fn load_with(
        &self,
        name: &str,
        door: AuthRowDoor,
        conns: crate::root::loader::dispatch::ConnTable,
    ) -> Option<
        crate::root::loader::dispatch::Plugin<crate::root::loader::dispatch::kinds::auth::Auth>,
    > {
        use crate::root::loader::dispatch::kinds::auth::Auth;
        use crate::root::loader::dispatch::{load_linked, LinkedRow};
        #[cfg(test)]
        self.bound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(name.to_string());
        match door {
            AuthRowDoor::Linked(i) => {
                let (_, _, door) = self.linked.get(i)?;
                LinkedRow::of(*door)
                    .and_then(|row| load_linked::<Auth>(&row, self.bind_with(name, conns)))
                    .ok()
            }
            AuthRowDoor::Dropped(i) => {
                let row = self.dropped?.loadable().get(i)?;
                crate::root::loader::registry::open_loadable::<Auth>(row, name, || {
                    Ok(self.bind_with(name, conns))
                })
                .ok()
            }
        }
    }

    #[must_use]
    pub(crate) fn style_flags(&self, style: &str) -> Option<u32> {
        self.stating(style)
            .next()
            .and_then(|row| row.styles.iter().find(|s| s.name == style))
            .map(|s| s.flags)
    }

    pub(crate) fn stating<'a>(
        &'a self,
        style: &'a str,
    ) -> impl Iterator<Item = &'a AuthRowFacts> + 'a {
        self.linked_facts()
            .iter()
            .chain(std::iter::once_with(move || self.dropped_facts()).flatten())
            .filter(move |row| row.styles.iter().any(|s| s.name == style))
    }

    pub(crate) fn linked_facts(&self) -> &[AuthRowFacts] {
        use crate::root::loader::dispatch::kinds::auth::stated_facts;
        use crate::root::loader::dispatch::LinkedRow;
        self.linked_facts.get_or_init(|| {
            self.linked
                .iter()
                .enumerate()
                .filter_map(|(i, (name, _, door))| {
                    let styles = stated_facts(*door).ok()?.styles;
                    let per_binding = LinkedRow::of(*door)
                        .ok()
                        .and_then(|row| {
                            busbar_contract::abi::mechanism::rendering::read(&row.statement).ok()
                        })
                        .is_some_and(|r| r.needs.iter().any(|n| !n.target_from.is_empty()));
                    Some(AuthRowFacts {
                        name: (*name).to_string(),
                        door: AuthRowDoor::Linked(i),
                        styles,
                        per_binding,
                    })
                })
                .collect()
        })
    }

    pub(crate) fn dropped_facts(&self) -> &[AuthRowFacts] {
        use crate::root::loader::dispatch::kinds::auth::rendered_facts;
        self.dropped_facts.get_or_init(|| {
            self.dropped
                .map_or(&[][..], |r| r.loadable())
                .iter()
                .enumerate()
                .filter(|(_, r)| r.manifest.kind == "auth")
                .filter_map(|(i, r)| {
                    let stated = r.manifest.stated_rendering().ok().flatten()?;
                    let styles = rendered_facts(&stated).ok()?.styles;
                    let per_binding = busbar_contract::abi::mechanism::rendering::read(&stated)
                        .is_ok_and(|r| r.needs.iter().any(|n| !n.target_from.is_empty()));
                    Some(AuthRowFacts {
                        name: r.manifest.name.clone(),
                        door: AuthRowDoor::Dropped(i),
                        styles,
                        per_binding,
                    })
                })
                .collect()
        })
    }

    pub(crate) fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<Serving>, String> {
        use crate::root::loader::dispatch::auth_outbound::OutboundInstance;

        let endpoint = endpoint_userinfo(settings);
        let (stated, userinfo) = match &endpoint {
            Some((stripped, userinfo)) => (stripped, userinfo.clone()),
            None => (settings, None),
        };
        for row in self.stating(style) {
            let Some(decl) = row.styles.iter().find(|s| s.name == style).cloned() else {
                continue;
            };
            let open_with = if row.per_binding {
                serde_json::to_vec(stated).map_err(|e| e.to_string())?
            } else {
                b"{}".to_vec()
            };

            let key = if row.per_binding {
                let written = serde_json::to_vec(settings).map_err(|e| e.to_string())?;
                let presenting = userinfo
                    .as_ref()
                    .and_then(|u| u.leading(&[]))
                    .and_then(|led| led.first().map(|(_, value)| value.to_vec()))
                    .map(|value| String::from_utf8_lossy(&value).into_owned())
                    .unwrap_or_default();
                format!(
                    "{}\0{}\0{presenting}",
                    row.name,
                    String::from_utf8_lossy(&written)
                )
            } else {
                row.name.clone()
            };
            let instance = match self.opened.get(&key) {
                Some(instance) => instance,
                None => {
                    let loaded = match &userinfo {
                        Some(userinfo) if row.per_binding => self.load_with(
                            &row.name,
                            row.door,
                            presenting(self.conns.clone(), userinfo),
                        ),
                        _ => self.load(&row.name, row.door),
                    };
                    let Some(plugin) = loaded else {
                        continue;
                    };
                    let (instance, installed) = self.opened.get_or_open(&key, || {
                        OutboundInstance::open_with(
                            plugin,
                            Arc::clone(&self.dispatcher),
                            0,
                            &open_with,
                        )
                    })?;

                    if installed {
                        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                            runtime.spawn(crate::root::measurements::credential_upkeep(
                                Arc::clone(&instance).ticks(),
                            ));
                        }
                    }
                    instance
                }
            };
            let auth = instance as Arc<dyn busbar_contract::auth_calls::OutboundAuth>;
            let auth = if endpoint.is_some() {
                Arc::new(EndpointStripped(auth))
                    as Arc<dyn busbar_contract::auth_calls::OutboundAuth>
            } else {
                auth
            };
            return Ok(Some((auth, decl)));
        }
        Ok(None)
    }
}

pub(crate) const TOKEN_ENDPOINT_SETTINGS: [&str; 2] = ["token_url", "token_uri"];

pub(crate) fn endpoint_userinfo(
    settings: &serde_json::Value,
) -> Option<(
    serde_json::Value,
    Option<crate::root::userinfo::UserinfoBasic>,
)> {
    let mut stripped_settings: Option<serde_json::Value> = None;
    let mut userinfo = None;
    for key in TOKEN_ENDPOINT_SETTINGS {
        let Some(written) = settings.get(key).and_then(serde_json::Value::as_str) else {
            continue;
        };
        let std::borrow::Cow::Owned(stripped) =
            busbar_kernel_egress::trust::net::strip_userinfo(written)
        else {
            continue;
        };
        userinfo = userinfo.or_else(|| crate::root::userinfo::UserinfoBasic::of(written));
        stripped_settings.get_or_insert_with(|| settings.clone())[key] =
            serde_json::Value::String(stripped);
    }
    stripped_settings.map(|stripped| (stripped, userinfo))
}

impl OutboundAuths {
    pub(crate) fn check_settings(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Vec<String>, String> {
        use crate::root::loader::dispatch::{auth_outbound::check_settings, ConnTable};
        for row in self.stating(style) {
            let Some(plugin) = self.load_with(&row.name, row.door, ConnTable::Probe) else {
                continue;
            };
            let bytes = serde_json::to_vec(settings).map_err(|e| e.to_string())?;
            return Ok(match check_settings(&plugin, style, &bytes) {
                Ok(()) => Vec::new(),
                Err(why) => why.lines().map(str::to_owned).collect(),
            });
        }
        Err(format!(
            "outbound style '{style}' has no settings-only validator"
        ))
    }

    pub(crate) fn check(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<Vec<String>, String> {
        use crate::root::loader::dispatch::auth_outbound::OutboundInstance;
        use crate::root::loader::dispatch::ConnTable;
        for row in self.stating(style) {
            let Some(plugin) = self.load_with(&row.name, row.door, ConnTable::Probe) else {
                continue;
            };
            let bytes = serde_json::to_vec(settings).map_err(|e| e.to_string())?;
            let instance =
                OutboundInstance::open_with(plugin, Arc::clone(&self.dispatcher), 0, &bytes)?;
            return Ok(
                match instance.open_outbound_raw(style, credential, settings) {
                    Ok(_) => Vec::new(),
                    Err((_, why)) => why
                        .lines()
                        .filter_map(|line| {
                            line.strip_prefix("credential: ")
                                .map(str::to_owned)
                                .or_else(|| line.starts_with("settings: ").then(|| line.to_owned()))
                        })
                        .collect(),
                },
            );
        }
        Ok(Vec::new())
    }
}

pub(crate) fn process_auths() -> Arc<OutboundAuths> {
    static AUTHS: std::sync::OnceLock<Arc<OutboundAuths>> = std::sync::OnceLock::new();
    Arc::clone(AUTHS.get_or_init(|| {
        Arc::new(OutboundAuths::new(
            crate::root::dispatch::dispatcher(),
            crate::LINKED.auths,
            crate::root::boot::dropped_registry(),
            crate::root::loader::dispatch::ConnTable::Host(crate::root::connector::admit(
                Arc::clone(crate::root::connector::the())
                    as Arc<dyn busbar_contract::conn::DeclaredConns>,
            )),
            crate::root::linked::catalogue(),
        ))
    }))
}

pub(crate) struct DoorReach<'a> {
    pub(crate) providers: &'a BTreeMap<String, ProviderRoute>,

    pub(crate) secrets: Arc<dyn busbar_contract::secret::SecretResolve>,

    pub(crate) auths: Arc<OutboundAuths>,

    pub(crate) conns: Arc<dyn busbar_contract::conn::PollConns>,

    pub(crate) stream_ceiling_secs: u64,

    pub(crate) catalog:
        Option<&'a std::collections::HashMap<String, busbar_contract::config::ModelCfg>>,

    pub(crate) models: Option<&'a crate::root::model_egress::ModelServing>,

    pub(crate) upgrades: Vec<&'static str>,
}

impl std::fmt::Debug for DoorReach<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorReach")
            .field("provider_names", &DebugEntries(self.providers.keys()))
            .finish_non_exhaustive()
    }
}

pub(crate) fn member_entry<'s>(
    section: &'s busbar_contract::yaml::Value,
    entry: &str,
) -> Option<&'s busbar_contract::yaml::Value> {
    section.get(RESERVED_MODELS_KEY)?.get(entry)
}

pub(crate) fn entry_text<'s>(
    entry: &'s busbar_contract::yaml::Value,
    key: &str,
) -> Option<&'s str> {
    key.split('.')
        .try_fold(entry, |value, part| value.get(part))
        .and_then(busbar_contract::yaml::Value::as_str)
}

pub(crate) fn origin_of(url: &str) -> &str {
    let after = url.find("://").map_or(0, |at| at + 3);
    url[after..].find('/').map_or(url, |at| &url[..after + at])
}

pub(crate) const PASSTHROUGH: &str = "passthrough";

pub(crate) const PASSTHROUGH_STYLE: &str = "bearer";

pub(crate) const TOKEN_EXCHANGE_STYLE: &str = "oauth-token-exchange";

/// The secret shorthand of the generation a plane section was written in: what its resolver serves
/// (SECRET-SHORTHAND-BOOT §3.4). A resolver bound to no generation reads canonical references only.
fn generation_sources(
    secrets: &dyn busbar_contract::secret::SecretResolve,
) -> busbar_contract::secret_ref::Sugars {
    secrets.sources().cloned().unwrap_or_default()
}

pub(crate) fn token_exchange_binding(
    entry: &str,
    registration: &busbar_contract::yaml::Value,
    reach: &DoorReach<'_>,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<Option<busbar_kernel::plane_driver::ConfiguredAuthBinding>, String> {
    use busbar_contract::section::{
        AUDIENCE_KEY, DEFAULT_SUBJECT_TOKEN_TYPE, SUBJECT_TOKEN_KEY, SUBJECT_TOKEN_TYPE_KEY,
        TOKEN_EXCHANGE_KEY, TOKEN_URL_KEY,
    };
    let Some(block) = registration.get(TOKEN_EXCHANGE_KEY) else {
        return Ok(None);
    };
    // Read under the shorthand of the generation the section was written in (its resolver's).
    let sources = generation_sources(reach.secrets.as_ref());
    let subject: busbar_contract::secret_ref::SecretRef = block
        .get(SUBJECT_TOKEN_KEY)
        .cloned()
        .ok_or_else(|| format!("member '{entry}': its token exchange states no subject token"))
        .and_then(|v| {
            busbar_contract::secret_ref::context::deserialize(
                busbar_contract::yaml::deserializer(v),
                &sources,
            )
            .map_err(|e| format!("member '{entry}': its subject token reference: {e}"))
        })?;
    let credential = reach
        .secrets
        .resolve_at_config(&subject, scope)
        .map_err(|e| {
            format!("member '{entry}': busbar's own subject token for it cannot resolve: {e}")
        })?;
    let mut settings = serde_json::Map::new();
    for (key, value) in [
        ("token_url", entry_text(block, TOKEN_URL_KEY)),
        (
            "subject_token_type",
            Some(entry_text(block, SUBJECT_TOKEN_TYPE_KEY).unwrap_or(DEFAULT_SUBJECT_TOKEN_TYPE)),
        ),
        ("resource", entry_text(registration, AUDIENCE_KEY)),
    ] {
        if let Some(v) = value {
            settings.insert(key.to_string(), serde_json::Value::String(v.to_string()));
        }
    }
    let settings = serde_json::Value::Object(settings);
    let (auth, decl) = reach
        .auths
        .serving(TOKEN_EXCHANGE_STYLE, &settings)?
        .ok_or_else(|| {
            format!(
                "member '{entry}': no linked or dropped-in auth plugin serves the style \
                 '{TOKEN_EXCHANGE_STYLE}' a token-exchange registration is bound under"
            )
        })?;
    let handle = auth
        .open_outbound(
            TOKEN_EXCHANGE_STYLE,
            credential.expose(&busbar_kernel::seal::lend()),
            &settings,
        )
        .map_err(|e| format!("member '{entry}' {e}"))?;
    Ok(Some(busbar_kernel::plane_driver::ConfiguredAuthBinding {
        auth,
        handle,
        style_flags: decl.flags,
        points: busbar_contract::abi::auth::AuthPoints(decl.points),
        passthrough: false,
        per_request: None,
    }))
}

pub(crate) fn upstream_credential_binding(
    member_name: &str,
    registration: &busbar_contract::yaml::Value,
    reach: &DoorReach<'_>,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<Option<busbar_kernel::plane_driver::ConfiguredAuthBinding>, String> {
    Ok(
        upstream_credential(member_name, registration, reach, scope)?.map(|(binding, per)| {
            let first = per.first_due(std::time::Instant::now(), busbar_kernel::retry::unit());
            busbar_kernel::refresh::keep(
                Arc::downgrade(&per) as std::sync::Weak<dyn busbar_kernel::refresh::Refreshable>,
                first,
            );
            binding
        }),
    )
}

pub(crate) fn upstream_credential(
    member_name: &str,
    registration: &busbar_contract::yaml::Value,
    reach: &DoorReach<'_>,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<
    Option<(
        busbar_kernel::plane_driver::ConfiguredAuthBinding,
        Arc<PerHop>,
    )>,
    String,
> {
    use busbar_contract::section::{
        CREDENTIAL_LEASE_TTL_KEY, CREDENTIAL_PLACEMENT_KEY, CREDENTIAL_SECRET_KEY,
        PLACEMENT_BEARER, PLACEMENT_HEADER_KEY, UPSTREAM_CREDENTIAL_KEY,
    };

    const BEARER_STYLE: &str = "bearer";

    const HEADER_STYLE: &str = "api-key";
    let Some(block) = registration.get(UPSTREAM_CREDENTIAL_KEY) else {
        return Ok(None);
    };
    let sources = generation_sources(reach.secrets.as_ref());
    let secret: busbar_contract::secret_ref::SecretRef = block
        .get(CREDENTIAL_SECRET_KEY)
        .cloned()
        .ok_or_else(|| {
            format!(
                "member '{member_name}': its `{UPSTREAM_CREDENTIAL_KEY}` states no \
                 `{CREDENTIAL_SECRET_KEY}`"
            )
        })
        .and_then(|v| {
            busbar_contract::secret_ref::context::deserialize(
                busbar_contract::yaml::deserializer(v),
                &sources,
            )
            .map_err(|_| {
                format!(
                    "member '{member_name}': its \
                     `{UPSTREAM_CREDENTIAL_KEY}.{CREDENTIAL_SECRET_KEY}` is not a secret \
                     reference (the value is not echoed): use {{ env: <VAR> }}, \
                     {{ file: <path> }} or {{ module: <secret-module>, settings: {{…}} }}"
                )
            })
        })?;
    let (style, header) = match block.get(CREDENTIAL_PLACEMENT_KEY) {
        None => (BEARER_STYLE, None),
        Some(p) if p.as_str() == Some(PLACEMENT_BEARER) => (BEARER_STYLE, None),
        Some(p) => match p
            .get(PLACEMENT_HEADER_KEY)
            .and_then(busbar_contract::yaml::Value::as_str)
        {
            Some(header) if !header.is_empty() => (HEADER_STYLE, Some(header.to_string())),
            _ => {
                return Err(format!(
                    "member '{member_name}': its upstream credential's placement is neither \
                     `{PLACEMENT_BEARER}` nor `{{{PLACEMENT_HEADER_KEY}: <name>}}`"
                ));
            }
        },
    };

    let minted = std::time::Instant::now();
    let lease = block
        .get(CREDENTIAL_LEASE_TTL_KEY)
        .and_then(busbar_contract::yaml::Value::as_u64)
        .filter(|ms| *ms > 0)
        .map(std::time::Duration::from_millis)
        .filter(|lease| minted.checked_add(*lease).is_some())
        .ok_or_else(|| {
            format!(
                "member '{member_name}': its \
                 `{UPSTREAM_CREDENTIAL_KEY}.{CREDENTIAL_LEASE_TTL_KEY}` is not a lease in \
                 milliseconds greater than zero"
            )
        })?;
    let settings = placement_settings(header.as_deref());

    let credential = busbar_kernel::config::secret::resolve_text_refusing(
        reach.secrets.as_ref(),
        &secret,
        scope,
    )
    .map_err(|e| {
        format!(
            "member '{member_name}': busbar's own upstream credential for it cannot \
                     resolve: {}",
            e.text
        )
    })?;
    let (auth, decl) = reach.auths.serving(style, &settings)?.ok_or_else(|| {
        format!(
            "member '{member_name}': no linked or dropped-in auth plugin serves the style \
             '{style}' its upstream credential is presented under"
        )
    })?;

    let seal = busbar_kernel::seal::lend();
    let handle = auth
        .open_outbound(style, credential.expose(&seal), &settings)
        .map_err(|e| format!("member '{member_name}' {e}"))?;

    let per = Arc::new(PerHop::new(
        Lent {
            member: member_name.to_string(),
            secret,
            secrets: Arc::clone(&reach.secrets),
            auth: Arc::clone(&auth),
            style,
            header,
            lease,
        },
        busbar_kernel::refresh::fingerprint([credential.expose(&seal).as_slice()]),
        handle,
        minted,
        &busbar_kernel::refresh::HOST_REPORT,
    ));
    drop(credential);
    Ok(Some((
        busbar_kernel::plane_driver::ConfiguredAuthBinding {
            auth,
            handle,
            style_flags: decl.flags,
            points: busbar_contract::abi::auth::AuthPoints(decl.points),
            passthrough: false,
            per_request: Some(
                Arc::clone(&per) as Arc<dyn busbar_contract::auth_calls::PerRequestHandle>
            ),
        },
        per,
    )))
}

pub(crate) fn placement_settings(header: Option<&str>) -> serde_json::Value {
    header.map_or_else(
        || serde_json::json!({}),
        |name| serde_json::json!({ busbar_contract::section::PLACEMENT_HEADER_KEY: name }),
    )
}

/// What a member's credential is presented as now: the outbound handle its value opened, the
/// value's fingerprint (never the value) and when its lease runs out.
pub(crate) struct Held {
    pub(crate) digest: [u8; 32],
    pub(crate) handle: u64,
    pub(crate) expires_at: std::time::Instant,
}

/// How often a held credential is renewed: half its lease, at most every five minutes (so a very
/// long lease still re-checks its source), never more often than the host's retry floor.
pub(crate) fn renew_every(lease: std::time::Duration) -> std::time::Duration {
    (lease / 2)
        .min(std::time::Duration::from_secs(300))
        .max(busbar_kernel::retry::FLOOR)
}

/// The retry backoff for one lease: base 1 s, cap `clamp(lease/8, 1 s, 30 s)`.
pub(crate) fn lease_backoff(lease: std::time::Duration) -> busbar_kernel::retry::Backoff {
    const BASE: std::time::Duration = std::time::Duration::from_secs(1);
    busbar_kernel::retry::Backoff::new(
        BASE,
        (lease / 8).clamp(BASE, std::time::Duration::from_secs(30)),
    )
}

/// WHAT ONE REFRESH ATTEMPT LEADS TO NEXT, for [`next_due`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next {
    /// It renewed or rotated: the next renewal.
    Renew,
    /// A definitive answer (not found, denied) that a re-read must confirm.
    Confirm,
    /// Failure `n` (1-based) of a streak.
    Retry(u32),
}

/// WHEN A MEMBER'S CREDENTIAL IS NEXT REFRESHED, as a pure function of its lease, what the last
/// attempt led to, when what it holds runs out and one uniform draw `unit` in `[0, 1)`:
///
/// - renewal: `renew_every(lease)` ± 10 %;
/// - a definitive answer's confirmation: 1 s;
/// - failure `n`: full-jitter backoff (`lease_backoff`), never past the held value's expiry while
///   one is held — a wait that would reach it is halved toward it, so attempts keep landing before
///   expiry without spinning (the floor is 100 ms);
/// - past expiry (or with nothing held): a steady retry uniform in `[cap/2, cap]`.
pub(crate) fn next_due(
    lease: std::time::Duration,
    next: Next,
    expires_at: Option<std::time::Instant>,
    now: std::time::Instant,
    unit: f64,
) -> std::time::Instant {
    use busbar_kernel::retry::{spread, FLOOR};
    let backoff = lease_backoff(lease);
    let wait = match next {
        Next::Renew => spread(renew_every(lease), 0.1, unit),
        Next::Confirm => backoff.base,
        Next::Retry(failures) => match expires_at.filter(|at| *at > now) {
            None => backoff.steady(unit),
            Some(at) => {
                let left = at - now;
                let wait = backoff.delay(failures, unit);
                if wait < left {
                    wait
                } else {
                    (left / 2).max(FLOOR)
                }
            }
        },
    };
    now + wait
}

/// What a member's credential refresh needs, apart from what it holds.
pub(crate) struct Lent {
    pub(crate) member: String,
    pub(crate) secret: busbar_contract::secret_ref::SecretRef,
    pub(crate) secrets: Arc<dyn busbar_contract::secret::SecretResolve>,
    pub(crate) auth: Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
    pub(crate) style: &'static str,
    pub(crate) header: Option<String>,
    pub(crate) lease: std::time::Duration,
}

/// The refresh's own state, behind its single-flight lock.
#[derive(Default)]
pub(crate) struct Streak {
    /// Failures since the last success.
    pub(crate) failures: u32,
    /// A definitive kind (not found, denied) the next re-read must answer again to drop.
    pub(crate) confirming: Option<u32>,
    /// When this member last reported 8026.
    pub(crate) warned: Option<std::time::Instant>,
    /// Whether this streak's last-attempt-before-expiry report was made.
    pub(crate) warned_final: bool,
    /// The previous `(fingerprint, handle)` pair: a source flapping between two values reuses its
    /// handle instead of opening a new one per flip.
    pub(crate) prior: Option<([u8; 32], u64)>,
    /// Whether the held value was dropped (a confirmed revocation).
    pub(crate) dropped: bool,
    /// When the next attempt is due, as last scheduled.
    pub(crate) due: Option<std::time::Instant>,
}

/// One member's upstream credential, held on its lease and renewed off the request path.
pub(crate) struct PerHop {
    pub(crate) lent: Lent,
    pub(crate) held: arc_swap::ArcSwapOption<Held>,

    pub(crate) refreshing: Mutex<Streak>,

    pub(crate) lapsed: std::sync::atomic::AtomicBool,
    pub(crate) report: &'static dyn busbar_kernel::refresh::Report,
}

/// What one refresh attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Attempt {
    /// Another refresh of this member was in flight; nothing was done.
    Busy,
    /// The value is unchanged; its lease was renewed.
    Renewed,
    /// The value changed and the new one is presented.
    Rotated,
    /// The source answered a definitive kind once; a re-read confirms it.
    Confirming { error_kind: u32 },
    /// The source confirmed a definitive kind: the held credential was dropped.
    Dropped { error_kind: u32 },
    /// The source could not be read (an outage): the held credential is kept until it expires.
    Failed { error_kind: u32 },
    /// The value changed and the auth plugin refused the new one: the old one is kept.
    Refused,
}

pub(crate) const UPSTREAM_REFRESH_ACTION: &str = "upstream_credential.refresh";

pub(crate) fn definitive(error_kind: u32) -> bool {
    use busbar_contract::abi::secret::{ERROR_KIND_DENIED, ERROR_KIND_NOT_FOUND};
    matches!(error_kind, ERROR_KIND_NOT_FOUND | ERROR_KIND_DENIED)
}

pub(crate) fn millis(d: std::time::Duration) -> String {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX).to_string()
}

impl PerHop {
    pub(crate) fn new(
        lent: Lent,
        digest: [u8; 32],
        handle: u64,
        minted: std::time::Instant,
        report: &'static dyn busbar_kernel::refresh::Report,
    ) -> Self {
        let expires_at = minted + lent.lease;
        Self {
            lent,
            held: arc_swap::ArcSwapOption::from_pointee(Held {
                digest,
                handle,
                expires_at,
            }),
            refreshing: Mutex::new(Streak::default()),
            lapsed: std::sync::atomic::AtomicBool::new(false),
            report,
        }
    }

    /// When the refresher first renews a credential just bound at `now`.
    pub(crate) fn first_due(&self, now: std::time::Instant, unit: f64) -> std::time::Instant {
        next_due(self.lent.lease, Next::Renew, None, now, unit)
    }

    pub(crate) fn resource(&self) -> String {
        format!("member:{}", self.lent.member)
    }

    pub(crate) fn fields(&self, extra: Vec<(&'static str, String)>) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("member", self.lent.member.clone()),
            ("reference", self.lent.secret.describe()),
            ("style", self.lent.style.to_string()),
        ];
        if let Some(header) = &self.lent.header {
            fields.push(("header", header.clone()));
        }
        fields.extend(extra);
        fields
    }

    /// Refresh now, on the calling thread: a test's lever (the refresher steps through
    /// `refresh_with`).
    #[cfg(test)]
    pub(crate) fn refresh(&self, scope: &busbar_contract::config_time::ConfigScope) -> Attempt {
        self.refresh_with(
            scope,
            std::time::Instant::now(),
            busbar_kernel::retry::unit(),
        )
        .0
    }

    /// One attempt at `now` with the draw `unit`: what it did and when the next is due.
    pub(crate) fn refresh_with(
        &self,
        scope: &busbar_contract::config_time::ConfigScope,
        now: std::time::Instant,
        unit: f64,
    ) -> (Attempt, std::time::Instant) {
        let mut streak = match self.refreshing.try_lock() {
            Ok(streak) => streak,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return (
                    Attempt::Busy,
                    now + busbar_kernel::retry::FLOOR.max(std::time::Duration::from_secs(1)),
                );
            }
        };
        let resolved = busbar_kernel::config::secret::resolve_text_refusing(
            self.lent.secrets.as_ref(),
            &self.lent.secret,
            scope,
        );
        let stopping = busbar_kernel::refresh::stopping();
        let value = match resolved {
            Ok(value) => value,
            Err(refused) => {
                return self.failed(&mut streak, refused, now, unit, stopping);
            }
        };
        let expires_at = now + self.lent.lease;
        let seal = busbar_kernel::seal::lend();
        let digest = busbar_kernel::refresh::fingerprint([value.expose(&seal).as_slice()]);
        let held = self.held.load_full();
        let same = |d: &[u8; 32]| busbar_contract::redacted::constant_time_eq(d, &digest);
        let reuse = match held.as_deref() {
            Some(held) if same(&held.digest) => Some((held.handle, false)),
            _ => streak
                .prior
                .filter(|(d, _)| same(d))
                .map(|(_, handle)| (handle, held.is_some())),
        };
        let (handle, rotated) = match reuse {
            Some(found) => found,
            None if stopping => return (Attempt::Busy, now + renew_every(self.lent.lease)),
            None => {
                let opened = self.lent.auth.open_outbound(
                    self.lent.style,
                    value.expose(&seal),
                    &placement_settings(self.lent.header.as_deref()),
                );
                drop(value);
                match opened {
                    Ok(handle) => (handle, true),
                    Err(text) => return self.refused(&mut streak, &text, now, unit),
                }
            }
        };
        if let Some(held) = held.as_deref().filter(|_| rotated) {
            streak.prior = Some((held.digest, held.handle));
        }
        self.held.store(Some(Arc::new(Held {
            digest,
            handle,
            expires_at,
        })));
        let was_lapsed = self
            .lapsed
            .swap(false, std::sync::atomic::Ordering::Relaxed);
        if streak.failures > 0 || was_lapsed || streak.dropped {
            self.report.info(
                "busbar's upstream credential for this member refreshed again",
                &self.fields(vec![("failures", streak.failures.to_string())]),
            );
            self.report.audit(
                UPSTREAM_REFRESH_ACTION,
                &self.resource(),
                busbar_kernel::audit_ring::OUTCOME_APPLIED,
            );
        }
        let (prior, due) = (
            streak.prior,
            next_due(self.lent.lease, Next::Renew, None, now, unit),
        );
        *streak = Streak {
            prior,
            due: Some(due),
            ..Streak::default()
        };
        (
            if rotated {
                Attempt::Rotated
            } else {
                Attempt::Renewed
            },
            due,
        )
    }

    pub(crate) fn failed(
        &self,
        streak: &mut Streak,
        refused: busbar_kernel::config::secret::SecretRefused,
        now: std::time::Instant,
        unit: f64,
        stopping: bool,
    ) -> (Attempt, std::time::Instant) {
        let kind = refused.error_kind;
        streak.failures = streak.failures.saturating_add(1);
        let held = self.held.load_full();
        let expires_at = held.as_deref().map(|h| h.expires_at);
        if definitive(kind) && !stopping {
            if streak.confirming == Some(kind) {
                streak.confirming = None;
                if let Some(dropped) = held.as_deref() {
                    streak.prior = Some((dropped.digest, dropped.handle));
                    self.held.store(None);
                    streak.dropped = true;
                    self.lapsed
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    let due = next_due(
                        self.lent.lease,
                        Next::Retry(streak.failures),
                        None,
                        now,
                        unit,
                    );
                    streak.due = Some(due);
                    self.report.diag(
                        &busbar_kernel::diagnostics::UPSTREAM_CREDENTIAL_LAPSED,
                        tracing::Level::ERROR,
                        "the source of busbar's upstream credential for this member confirmed it \
                         is gone or no longer readable (revoked at source): the credential is \
                         dropped and each hop on the member is refused (credential_unavailable) \
                         until a refresh reads it again",
                        &self.fields(vec![
                            ("cause", "revoked-at-source".into()),
                            ("error_kind", kind.to_string()),
                            ("error", refused.text.clone()),
                            ("retry_in_ms", millis(due - now)),
                        ]),
                    );
                    self.report.audit(
                        UPSTREAM_REFRESH_ACTION,
                        &self.resource(),
                        busbar_kernel::audit_ring::OUTCOME_REJECTED,
                    );
                    return (Attempt::Dropped { error_kind: kind }, due);
                }
            } else {
                streak.confirming = Some(kind);
                let due = next_due(self.lent.lease, Next::Confirm, expires_at, now, unit);
                streak.due = Some(due);
                self.warn_failed(
                    streak,
                    ("resolve", kind),
                    &refused.text,
                    expires_at,
                    now,
                    due,
                );
                return (Attempt::Confirming { error_kind: kind }, due);
            }
        } else {
            streak.confirming = None;
        }
        let due = next_due(
            self.lent.lease,
            Next::Retry(streak.failures),
            expires_at,
            now,
            unit,
        );
        streak.due = Some(due);
        if !stopping {
            self.warn_failed(
                streak,
                ("resolve", kind),
                &refused.text,
                expires_at,
                now,
                due,
            );
        }
        (Attempt::Failed { error_kind: kind }, due)
    }

    pub(crate) fn refused(
        &self,
        streak: &mut Streak,
        text: &str,
        now: std::time::Instant,
        unit: f64,
    ) -> (Attempt, std::time::Instant) {
        streak.failures = streak.failures.saturating_add(1);
        streak.confirming = None;
        let expires_at = self.held.load().as_deref().map(|h| h.expires_at);
        let due = next_due(
            self.lent.lease,
            Next::Retry(streak.failures),
            expires_at,
            now,
            unit,
        );
        streak.due = Some(due);
        self.warn_failed(streak, ("reopen", 0), text, expires_at, now, due);
        (Attempt::Refused, due)
    }

    /// BUSBAR-8026, rate limited: the first failure of a streak, then at most one a minute per
    /// member (also after a lapse), and always the last attempt before expiry. Within one minute
    /// only the first member on a SOURCE reports at its level; the others report at debug and are
    /// counted into that source's next report. A `reopen` (the auth plugin refused the rotated
    /// value) is ERROR from the first.
    /// `failure` is the cause (`resolve` or `reopen`) and the error kind.
    pub(crate) fn warn_failed(
        &self,
        streak: &mut Streak,
        failure: (&'static str, u32),
        text: &str,
        expires_at: Option<std::time::Instant>,
        now: std::time::Instant,
        due: std::time::Instant,
    ) {
        let (cause, error_kind) = failure;
        static PER_SOURCE: std::sync::OnceLock<busbar_kernel::refresh::Throttle> =
            std::sync::OnceLock::new();
        const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
        let cap = lease_backoff(self.lent.lease).cap;
        let left = expires_at.map(|at| at.saturating_duration_since(now));
        let lapsed = left.is_none_or(|left| left.is_zero());
        let last_before_expiry =
            !lapsed && expires_at.is_some_and(|at| due >= at.checked_sub(cap).unwrap_or(at));
        let reopen = cause == "reopen";
        let member_due = streak.failures == 1
            || streak
                .warned
                .is_none_or(|at| now.saturating_duration_since(at) >= WINDOW)
            || (last_before_expiry && !streak.warned_final)
            || (reopen && streak.warned.is_none());
        let forced = reopen || (last_before_expiry && !streak.warned_final);
        let level = if reopen || lapsed || left.is_some_and(|left| left < 2 * cap) {
            tracing::Level::ERROR
        } else {
            tracing::Level::WARN
        };
        let others = if member_due {
            PER_SOURCE
                .get_or_init(|| busbar_kernel::refresh::Throttle::new(WINDOW))
                .pass(&self.lent.secret.describe(), now)
        } else {
            None
        };
        let loud = member_due && (forced || others.is_some());
        let message = if reopen {
            "busbar's upstream credential for this member changed at its source and the auth \
             plugin refused the new value: the previous value is presented until its lease ends; \
             fix the value at the source"
        } else if lapsed {
            "busbar's upstream credential for this member still cannot be refreshed: its lease \
             has ended and each hop on the member is refused (credential_unavailable)"
        } else {
            "busbar's upstream credential for this member could not be refreshed: the value it \
             holds is presented until its lease ends, and the refresh is retried"
        };
        let mut extra = vec![
            ("cause", cause.to_string()),
            ("error_kind", error_kind.to_string()),
            ("error", text.to_string()),
            ("failures", streak.failures.to_string()),
            ("retry_in_ms", millis(due.saturating_duration_since(now))),
        ];
        if let Some(left) = left {
            extra.push(("expires_in_ms", millis(left)));
        }
        if let Some(others) = others.filter(|n| *n > 0) {
            extra.push(("others", others.to_string()));
        }
        let fields = self.fields(extra);
        if !loud {
            self.report.diag(
                &busbar_kernel::diagnostics::UPSTREAM_CREDENTIAL_REFRESH_FAILED,
                tracing::Level::DEBUG,
                message,
                &fields,
            );
            return;
        }
        streak.warned = Some(now);
        streak.warned_final |= last_before_expiry;
        self.report.diag(
            &busbar_kernel::diagnostics::UPSTREAM_CREDENTIAL_REFRESH_FAILED,
            level,
            message,
            &fields,
        );
        self.report.audit(
            UPSTREAM_REFRESH_ACTION,
            &self.resource(),
            busbar_kernel::audit_ring::OUTCOME_DEGRADED,
        );
    }

    /// BUSBAR-8027 once per lapse, when `now` is past what is held: reported by the refresher at
    /// the expiry itself, whether or not a hop arrives.
    pub(crate) fn check_lapse(&self, now: std::time::Instant) {
        let Some(held) = self.held.load_full() else {
            return;
        };
        if now < held.expires_at || busbar_kernel::refresh::stopping() {
            return;
        }
        if self.lapsed.swap(true, std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let failures = self
            .refreshing
            .try_lock()
            .map(|s| s.failures)
            .unwrap_or_default();
        self.report.diag(
            &busbar_kernel::diagnostics::UPSTREAM_CREDENTIAL_LAPSED,
            tracing::Level::ERROR,
            "busbar's upstream credential for this member reached the end of its lease with no \
             successful refresh: each hop on the member is refused (credential_unavailable) until \
             a refresh succeeds",
            &self.fields(vec![
                ("cause", "lease-expired".into()),
                ("failures", failures.to_string()),
                ("lease_ms", millis(self.lent.lease)),
            ]),
        );
        self.report.audit(
            UPSTREAM_REFRESH_ACTION,
            &self.resource(),
            busbar_kernel::audit_ring::OUTCOME_REJECTED,
        );
    }
}

impl busbar_kernel::refresh::Refreshable for PerHop {
    fn refresh(&self, now: std::time::Instant) -> std::time::Instant {
        self.check_lapse(now);
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let (_, due) = crate::root::measurements::configuration_refresh(|| {
            self.refresh_with(&scope, now, busbar_kernel::retry::unit())
        });
        let after = std::time::Instant::now();
        self.check_lapse(after);
        match self.held.load().as_deref() {
            Some(held)
                if held.expires_at > after
                    && !self.lapsed.load(std::sync::atomic::Ordering::Relaxed) =>
            {
                due.min(held.expires_at)
            }
            _ => due,
        }
    }

    fn deadline(&self) -> Option<std::time::Instant> {
        self.held.load().as_deref().map(|held| held.expires_at)
    }
}

impl std::fmt::Debug for PerHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let handle = self.held.load().as_ref().map(|held| held.handle);
        f.debug_struct("PerHop")
            .field("member", &self.lent.member)
            .field("secret", &"<redacted; refreshed once per lease>")
            .field("style", &self.lent.style)
            .field("carried_in", &self.lent.header)
            .field("lease", &self.lent.lease)
            .field("handle", &handle)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) fn refresh_credentials() {
    busbar_kernel::refresh::process().refresh_all_now();
}

pub(crate) fn bind_member_fetches(
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    routes: &BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>,
    instance: busbar_contract::conn::InstanceId,
    table: &dyn busbar_contract::conn::DeclaredConns,
    units: &Arc<busbar_kernel::host_units::UnitRecords>,
) {
    let targeted = member_target_needs(served);
    for (member, route) in routes {
        let Some(busbar_kernel::plane_driver::AuthBinding::Configured(binding)) = &route.auth
        else {
            continue;
        };

        for (need, base_url) in ridden(route) {
            if !targeted.iter().any(|(n, _)| *n == need) {
                continue;
            }
            table.bind_auth(
                instance,
                need,
                member,
                busbar_contract::conn::origin_of(&base_url),
                busbar_contract::conn::ConnAuth {
                    auth: Arc::clone(&binding.auth),
                    handle: binding.handle,
                    style_flags: binding.style_flags,
                    points: binding.points,
                    passthrough: binding.passthrough,
                    per_request: binding.per_request.clone(),
                    lender: Some(
                        Arc::clone(units) as Arc<dyn busbar_contract::conn::LendCredential>
                    ),
                },
            );
        }
    }
}

pub(crate) fn member_target_needs(
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
) -> Vec<(busbar_contract::conn::NeedId, &'static str)> {
    served
        .need_targets
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(at, path)| {
            let key = busbar_contract::section::member_target(path)?;
            Some((busbar_contract::conn::NeedId(u32::try_from(at).ok()?), key))
        })
        .collect()
}

pub(crate) fn ridden(
    route: &busbar_kernel::plane_driver::MemberRoute,
) -> Vec<(busbar_contract::conn::NeedId, String)> {
    std::iter::once(route.need)
        .chain(route.rides.iter().map(|(need, _)| *need))
        .filter_map(|need| {
            let ride = route.ride(need.0.checked_add(1)?)?;
            Some((ride.need, ride.base_url.to_string()))
        })
        .collect()
}

pub(crate) fn member_routes(
    section: &busbar_contract::yaml::Value,
    pools: &DoorPools,
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    reach: &DoorReach<'_>,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
    use busbar_kernel::plane_driver::{
        resolve_member_needs, ConfiguredAuthBinding, MemberAuth, MemberRoute,
    };
    struct Resolved<'p> {
        entry: String,
        name: String,
        provider: &'p ProviderRoute,
        style: String,

        params: &'static [u8],
    }
    let mut resolved = Vec::new();
    let mut registered = BTreeMap::new();

    let member_targets = member_target_needs(served);
    let member_target = member_targets.first().copied();

    let member_program = served
        .need_targets
        .iter()
        .position(|path| busbar_contract::section::member_program(path))
        .and_then(|at| u32::try_from(at).ok())
        .map(busbar_contract::conn::NeedId);
    let mut programs = BTreeMap::new();
    for entry in pools.entries() {
        let Some(member) = member_entry(section, entry) else {
            let registration = section.get(entry.as_str());
            if let Some((need, key)) = member_target {
                if let Some((registration, target)) = registration
                    .and_then(|r| entry_text(r, key).filter(|t| !t.is_empty()).map(|t| (r, t)))
                {
                    let anchors =
                        registration_anchors(entry, registration, need, served, &*reach.secrets)?;
                    let base_url = origin_of(target).to_string();

                    let mut rides = Vec::new();
                    let mut spelled = Vec::new();
                    let mut ride_anchors = Vec::new();
                    for (other, key) in member_targets.iter().skip(1) {
                        let Some(at) = entry_text(registration, key).filter(|t| !t.is_empty())
                        else {
                            continue;
                        };
                        rides.push(*other);
                        if origin_of(at) != base_url {
                            spelled.push((*other, origin_of(at).to_string()));
                            // A separately declared destination does not inherit another peer's
                            // certificate pin, client identity or private-network reach.
                            ride_anchors.push((
                                *other,
                                busbar_contract::transport::trust::Anchors::default(),
                            ));
                        }
                    }
                    registered.insert(
                        entry.clone(),
                        (need, base_url, anchors, rides, spelled, ride_anchors),
                    );
                    continue;
                }
            }

            if let Some(need) = member_program {
                if registration
                    .and_then(|r| entry_text(r, busbar_contract::conn::PROGRAM_KEYS[0]))
                    .is_some()
                {
                    programs.insert(entry.clone(), need);
                }
            }
            continue;
        };
        let name = entry_text(member, MODEL_PROVIDER_KEY)
            .ok_or_else(|| format!("member '{entry}' names no provider"))?;
        let provider = reach.providers.get(name).ok_or_else(|| {
            format!("member '{entry}' names provider '{name}', which is not configured")
        })?;
        let dialect: &str = &provider.protocol;
        let default_of = |dialect: &str| {
            let at = served.dialects.iter().position(|d| *d == dialect)?;
            let at = u32::try_from(at).ok()?;
            served
                .dialect_auth
                .iter()
                .find(|(d, _, _)| *d == at)
                .map(|(_, style, params)| ((*style).to_string(), *params))
        };

        let default = default_of(dialect).or_else(|| default_of(&provider.protocol));

        let (style, params) = match (&provider.style, default) {
            (Some(style), _) => (Some(style.clone()), &[][..]),
            (None, Some((style, params))) => (Some(style), params),
            (None, None) => (None, &[][..]),
        };
        let style = style.ok_or_else(|| {
            format!(
                "member '{entry}': provider '{name}' states no `auth:` and its plane declares no \
                 default style for the dialect '{dialect}'"
            )
        })?;
        resolved.push(Resolved {
            entry: entry.clone(),
            name: name.to_string(),
            provider,
            style,
            params,
        });
    }
    let needs: Vec<ReadNeed> = served
        .need_auths
        .iter()
        .zip(served.need_transports.iter().chain(std::iter::repeat(&"")))
        .map(|((direction, auth), transport)| ReadNeed {
            direction: *direction,
            egress_class: 0,
            transport: (*transport).to_string(),
            auth: (*auth).to_string(),
            target_from: String::new(),
            trust_from: String::new(),
            details: ReadBlob {
                fmt: 0,
                flags: 0,
                bytes: Vec::new(),
            },
            timeout_ms: 0,

            keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
            keep_response_headers: Vec::new(),
            deny_response_headers: Vec::new(),
        })
        .collect();
    let members: Vec<MemberAuth<'_>> = resolved
        .iter()
        .map(|r| MemberAuth {
            member: &r.entry,
            auth: &r.style,
        })
        .collect();
    let dialled = resolve_member_needs(&needs, &members).map_err(|e| e.to_string())?;
    let mut routes = BTreeMap::new();

    let section_default = section
        .get(busbar_contract::section::UPSTREAM_CREDENTIALS_KEY)
        .and_then(busbar_contract::yaml::Value::as_str);
    for (entry, (need, base_url, anchors, rides, spelled, ride_anchors)) in registered {
        let mode = section
            .get(entry.as_str())
            .and_then(|r| entry_text(r, busbar_contract::section::UPSTREAM_CREDENTIALS_KEY))
            .or(section_default);
        let auth = if mode == Some("connection") {
            None
        } else if mode == Some(PASSTHROUGH) {
            let (auth, decl) = reach
                .auths
                .serving(PASSTHROUGH_STYLE, &serde_json::json!({}))?
                .ok_or_else(|| {
                    format!(
                        "member '{entry}': no linked or dropped-in auth plugin serves the style \
                         '{PASSTHROUGH_STYLE}' a passthrough registration presents the caller's \
                         credential under"
                    )
                })?;
            let handle = auth
                .open_outbound(PASSTHROUGH_STYLE, &[], &serde_json::json!({}))
                .map_err(|e| format!("member '{entry}' {e}"))?;
            Some(ConfiguredAuthBinding {
                auth,
                handle,
                style_flags: decl.flags,
                points: busbar_contract::abi::auth::AuthPoints(decl.points),
                passthrough: true,
                per_request: None,
            })
        } else {
            match section.get(entry.as_str()) {
                Some(registration) => {
                    match token_exchange_binding(&entry, registration, reach, scope)? {
                        Some(binding) => Some(binding),
                        None => upstream_credential_binding(&entry, registration, reach, scope)?,
                    }
                }
                None => None,
            }
        };
        routes.insert(
            entry.clone(),
            MemberRoute {
                ride_anchors,
                connection_required: mode == Some("connection"),
                rides: rides
                    .into_iter()
                    .map(|n| (n, busbar_kernel::plane_driver::ResponseKeep::default()))
                    .collect(),
                need,
                base_url,
                auth: auth.map(busbar_kernel::plane_driver::AuthBinding::Configured),
                provider: entry,
                keep: busbar_kernel::plane_driver::ResponseKeep::default(),
                anchors,
                spelled,
            },
        );
    }

    for (entry, need) in programs {
        routes.insert(
            entry.clone(),
            MemberRoute {
                ride_anchors: Vec::new(),
                connection_required: false,
                rides: Vec::new(),
                need,
                base_url: entry.clone(),
                auth: None,
                provider: entry,
                keep: busbar_kernel::plane_driver::ResponseKeep::default(),
                anchors: busbar_contract::transport::trust::Anchors::default(),
                spelled: Vec::new(),
            },
        );
    }
    // One resolve per provider for this call (WASTE-AUTH-SECRETS W3): every member of a provider
    // presents the same `r.provider.credential`, so N members resolved it N times. The map holds
    // zeroizing values for this call only and wipes on return, so the next call (a reload)
    // resolves fresh and sees a rotated value. Errors are not memoized: `?` returns as before.
    let mut by_provider: std::collections::HashMap<String, busbar_kernel::config::secret::Held> =
        std::collections::HashMap::new();
    for r in resolved {
        let credential = if r.provider.credential.is_none() {
            busbar_kernel::config::secret::Held::default()
        } else if let Some(held) = by_provider.get(&r.name) {
            held.clone()
        } else {
            let held = reach
                .secrets
                .resolve_at_config(&r.provider.credential, scope)
                .map_err(|e| format!("provider '{}' credential: {e}", r.name))?;
            by_provider.insert(r.name.clone(), held.clone());
            held
        };

        let from_credential = reach.auths.style_flags(&r.style).is_some_and(|flags| {
            flags & busbar_contract::abi::auth::STYLE_ENDPOINT_FROM_CREDENTIAL != 0
        });
        let seal = busbar_kernel::seal::lend();
        let credential = credential.expose(&seal);
        let settings =
            sealed_params(&r.name, &r.style, from_credential, r.provider, credential)?.to_json();
        let (auth, decl) = reach.auths.serving(&r.style, &settings)?.ok_or_else(|| {
            format!(
                "member '{}': no linked or dropped-in auth plugin serves the style '{}'",
                r.entry, r.style
            )
        })?;
        let settings = sealed_settings(r.params, &r.provider.base_url, &settings)
            .map_err(|e| format!("member '{}': {e}", r.entry))?;
        let handle = auth
            .open_outbound(&r.style, credential, &settings)
            .map_err(|e| format!("provider '{}' {e}", r.name))?;

        let bound = dialled
            .get(&r.entry)
            .filter(|b| !b.is_empty())
            .ok_or_else(|| format!("member '{}' dials no need", r.entry))?;
        let need = bound[0];
        let rides = bound[1..]
            .iter()
            .map(|n| (*n, busbar_kernel::plane_driver::ResponseKeep::default()))
            .collect();

        let spelled = bound
            .iter()
            .filter_map(|n| {
                let transport = served.need_transports.get(n.0 as usize)?;
                let url = spelled_for(&r.provider.base_url, transport, &reach.upgrades)?;
                Some((*n, url))
            })
            .collect();
        let connection_required = section
            .get(r.entry.as_str())
            .and_then(|entry| entry_text(entry, busbar_contract::section::UPSTREAM_CREDENTIALS_KEY))
            .or(section_default)
            == Some("connection");
        routes.insert(
            r.entry,
            MemberRoute {
                ride_anchors: Vec::new(),
                connection_required,
                need,
                base_url: r.provider.base_url.clone(),

                auth: Some(busbar_kernel::plane_driver::AuthBinding::Configured(
                    ConfiguredAuthBinding {
                        auth: crate::root::userinfo::lead_with(auth, r.provider.userinfo.clone()),
                        handle,
                        style_flags: decl.flags,
                        points: busbar_contract::abi::auth::AuthPoints(decl.points),
                        passthrough: false,
                        per_request: None,
                    },
                )),
                provider: r.name,
                keep: busbar_kernel::plane_driver::ResponseKeep::default(),
                rides,
                anchors: busbar_contract::transport::trust::Anchors::default(),
                spelled,
            },
        );
    }
    Ok(routes)
}

pub(crate) fn sealed_settings(
    params: &[u8],
    base_url: &str,
    provider: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    if params.is_empty() {
        return Ok(provider.clone());
    }
    let serde_json::Value::Object(mut sealed) = serde_json::from_slice(params)
        .map_err(|e| format!("its dialect's auth parameters are not JSON: {e}"))?
    else {
        return Err("its dialect's auth parameters are not a JSON object".to_string());
    };
    let mut unread: Vec<(String, serde_json::Value)> = Vec::new();
    for (key, value) in &mut sealed {
        let Some(directive) = value.get("host_label_after") else {
            continue;
        };
        let labels: Vec<&str> = directive
            .as_array()
            .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
            .unwrap_or_default();
        let default = value
            .get("default")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("its dialect's auth parameter `{key}` names no default"))?
            .to_string();
        let resolved = match host_label(base_url_host(base_url), &labels) {
            Some(label) => label.to_string(),
            None => {
                if let Some(words) = value.get("unread").filter(|w| w.is_string()) {
                    unread.push((format!("{key}_unread"), words.clone()));
                }
                default
            }
        };
        *value = serde_json::Value::String(resolved);
    }
    sealed.extend(unread);
    if let serde_json::Value::Object(own) = provider {
        for (key, value) in own {
            sealed.insert(key.clone(), value.clone());
        }
    }
    Ok(serde_json::Value::Object(sealed))
}

pub(crate) fn base_url_host(base_url: &str) -> &str {
    busbar_contract::net::url_authority(base_url)
        .host_port
        .split(':')
        .next()
        .unwrap_or("")
}

pub(crate) fn host_label<'h>(host: &'h str, after: &[&str]) -> Option<&'h str> {
    let shaped = |label: &str| {
        let parts: Vec<&str> = label.split('-').collect();
        let Some((last, leading)) = parts.split_last() else {
            return false;
        };
        parts.len() >= 3
            && parts.iter().all(|p| !p.is_empty())
            && last.bytes().all(|b| b.is_ascii_digit())
            && leading
                .iter()
                .all(|p| p.bytes().all(|b| b.is_ascii_alphabetic()))
    };
    let labels: Vec<&str> = host.split('.').collect();
    labels.iter().enumerate().find_map(|(i, label)| {
        if !after.contains(label) {
            return None;
        }
        labels.get(i + 1).copied().filter(|next| shaped(next))
    })
}

pub(crate) fn sealed_params(
    name: &str,
    style: &str,
    from_credential: bool,
    provider: &ProviderRoute,
    credential: &[u8],
) -> Result<StyleParams, String> {
    let mut params = provider.params.clone();
    if !from_credential || credential.is_empty() {
        return Ok(params);
    }
    let Ok(text) = std::str::from_utf8(credential) else {
        return Ok(params);
    };
    let Ok(token_uri) = busbar_kernel::config_validate::service_account_token_uri(text) else {
        return Ok(params);
    };
    busbar_kernel::config_validate::vet_token_uri(&token_uri, &provider.metadata)
        .map_err(|e| format!("provider '{name}' ({style} auth): {e}"))?;
    params.token_uri = Some(token_uri);
    Ok(params)
}

#[must_use]
pub(crate) fn spelled_for(base_url: &str, transport: &str, upgrades: &[&str]) -> Option<String> {
    if !upgrades.contains(&transport) {
        return None;
    }
    if let Some(rest) = base_url.strip_prefix("https://") {
        Some(format!("{transport}s://{rest}"))
    } else {
        base_url
            .strip_prefix("http://")
            .map(|rest| format!("{transport}://{rest}"))
    }
}

pub(crate) fn registration_anchors(
    entry: &str,
    registration: &busbar_contract::yaml::Value,
    need: busbar_contract::conn::NeedId,
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    secrets: &dyn busbar_contract::secret::SecretResolve,
) -> Result<busbar_contract::transport::trust::Anchors, String> {
    let at = format!("`{}.{entry}`", served.section);
    let pin = busbar_kernel::trust::section::parse_entry(&at, registration, &served.trust_keys)?
        .pin
        .filter(|p| p.peer_key)
        .and_then(|p| p.key)
        .map(|written| {
            busbar_contract::transport::trust::canonical_key_pin(&written)
                .map_err(|_| peer_key_pin_refusal(&at, &served.trust_keys))
        })
        .transpose()?;

    let private_reach =
        busbar_kernel::trust::section::private_reach(registration, &served.trust_keys);
    let identity_at = served
        .need_trust
        .get(need.0 as usize)
        .and_then(|path| busbar_contract::section::member_target(path));
    let extra_anchors = if identity_at == Some("tls") {
        registration_ca_anchors(entry, registration)?
    } else {
        Vec::new()
    };

    let identity_at = identity_at.map(|key| if key == "tls" { "client_identity" } else { key });
    let client_identity = match identity_at
        .and_then(|key| Some((key, registration.get(key).filter(|v| !v.is_null())?)))
    {
        None => None,
        Some((key, identity)) => {
            let sources = generation_sources(secrets);
            let reference = |half: &str| {
                identity
                    .get(half)
                    .cloned()
                    .ok_or_else(|| format!("member '{entry}': `{key}.{half}:` is required"))
                    .and_then(|v| {
                        busbar_contract::secret_ref::context::deserialize::<
                            busbar_contract::secret_ref::SecretRef,
                            _,
                        >(busbar_contract::yaml::deserializer(v), &sources)
                        .map_err(|e| format!("member '{entry}': `{key}.{half}:` {e}"))
                    })
            };
            let (cert, private) = (reference("cert")?, reference("key")?);
            let identity = busbar_core_connector::tls::client_identity(secrets, &cert, &private)
                .map_err(|e| format!("member '{entry}': `{key}`: {e}"))?;
            Some(identity)
        }
    };
    Ok(busbar_contract::transport::trust::Anchors {
        extra_anchors,
        key_pin: pin,
        client_identity,
        private_reach,
    })
}

/// Validate only sections whose actual Need explicitly selects the member TLS bundle.
pub(crate) fn member_tls_refusal(
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    section: &busbar_contract::yaml::Value,
) -> Result<(), String> {
    if served
        .need_trust
        .iter()
        .any(|path| busbar_contract::section::member_target(path) == Some("tls"))
    {
        member_tls_section_refusal(section)?;
    }
    Ok(())
}

pub(crate) fn member_tls_section_refusal(
    section: &busbar_contract::yaml::Value,
) -> Result<(), String> {
    if let Some(members) = section.as_mapping() {
        for (name, registration) in members {
            if let Some(entry) = name.as_str() {
                registration_ca_anchors(entry, registration)?;
            }
        }
    }
    Ok(())
}

/// Read the explicitly selected member TLS bundle; its certificate material is public,
pub(crate) fn registration_ca_anchors(
    entry: &str,
    registration: &busbar_contract::yaml::Value,
) -> Result<Vec<Vec<u8>>, String> {
    let Some(tls) = registration.get("tls").filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let invalid = || {
        format!("member '{entry}': `tls` must contain only optional `ca_cert_pem` certificate PEM")
    };
    let map = tls.as_mapping().ok_or_else(invalid)?;
    if map.keys().any(|key| key.as_str() != Some("ca_cert_pem")) {
        return Err(invalid());
    }
    let Some(pem) = tls.get("ca_cert_pem") else {
        return Ok(Vec::new());
    };
    let pem = pem
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(invalid)?;
    busbar_core_connector::tls::client::operator_ca_anchors(pem.as_bytes()).map_err(|_| {
        format!(
            "member '{entry}': `tls.ca_cert_pem` must be a nonempty valid certificate PEM bundle"
        )
    })
}

pub(crate) fn peer_key_pin_refusal(
    at: &str,
    keys: &[busbar_contract::plane::TrustKeyDecl],
) -> String {
    let k = keys
        .iter()
        .find(|k| k.role == busbar_contract::plane::TrustRole::Pin)
        .map_or("pin", |k| k.key);
    format!(
        "{at}: `{k}.key:` is not a key pin. Write `sha256/<base64>`: the standard, padded base64 \
         of the 32-byte SHA-256 digest of the far end's certificate SubjectPublicKeyInfo (the \
         plain `<base64>` of the same digest is also accepted)."
    )
}

impl std::fmt::Debug for ProviderRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderRoute")
            .field("base_url", &"<redacted>")
            .field("userinfo", &self.userinfo)
            .field("protocol", &self.protocol)
            .field("error_map", &self.error_map)
            .field("credential", &self.credential)
            .field("style", &self.style)
            .field("params", &self.params)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl std::fmt::Debug for StyleParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StyleParams")
            .field("token_url", &"<redacted>")
            .field("token_uri", &"<redacted>")
            .field("scope", &self.scope)
            .field("subject", &self.subject)
            .finish()
    }
}

#[cfg(test)]
mod owned_reader_tests {
    use super::Rules;
    use busbar_kernel::{appbuild::RootRules, config};
    use std::sync::Arc;

    struct Reader;
    impl RootRules for Reader {
        fn grammar(
            &self,
            _: &config::grammar::PhaseOneIn<'_>,
        ) -> Result<config::Grammar, config::GrammarRefusal> {
            Err(config::GrammarRefusal("candidate image refused".into()))
        }
        fn check(&self, _: &config::RootCfg) -> Result<(), String> {
            Ok(())
        }
        fn held_document(
            &self,
            _: &std::path::Path,
        ) -> Option<busbar_contract::secure::SecureString> {
            Some("held candidate".into())
        }
        fn secret_resolver<'a>(
            &'a self,
            _: &'a config::RootCfg,
            _: &'a config::PluginsCfg,
        ) -> busbar_plugin_abi::host_side::caller::BoxFut<
            'a,
            Result<Arc<config::secret::SecretResolver>, String>,
        > {
            Box::pin(async { Err("candidate boot projection refused".into()) })
        }
    }

    struct CandidateReader;
    impl RootRules for CandidateReader {
        fn prepare_read(
            &self,
            _: &config::grammar::PhaseOneIn<'_>,
        ) -> Result<config::grammar::PreparedConfigRead, config::GrammarRefusal> {
            Ok(
                config::grammar::PreparedConfigRead::new(config::Grammar::empty())
                    .with_context(Arc::new(73u64)),
            )
        }
        fn prepare_candidate<'a>(
            &'a self,
            _: &'a config::RootCfg,
            _: &'a config::PluginsCfg,
        ) -> busbar_plugin_abi::host_side::caller::BoxFut<
            'a,
            Result<Option<busbar_kernel::appbuild::CandidatePreparation>, String>,
        > {
            Box::pin(async { Err("exact candidate preparation refused".into()) })
        }
        fn check(&self, _: &config::RootCfg) -> Result<(), String> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn serving_rules_preserve_native_read_and_candidate_preparation() {
        let rules = Rules::with_reader(None, Arc::new(CandidateReader));
        let plugins = config::PluginsCfg::default();
        let read = rules
            .prepare_read(&config::grammar::PhaseOneIn::of(&plugins))
            .unwrap();
        assert_eq!(read.context::<u64>(), Some(&73));
        let deploy = busbar_contract::yaml::from_str("{}").unwrap();
        let cfg = config::resolve(&deploy, &Default::default()).unwrap();
        assert_eq!(
            rules.prepare_candidate(&cfg, &plugins).await.err().unwrap(),
            "exact candidate preparation refused"
        );
    }

    #[tokio::test]
    async fn serving_rules_preserve_the_owned_reader_refusals() {
        let rules = Rules::with_reader(None, Arc::new(Reader));
        let plugins = config::PluginsCfg::default();
        assert_eq!(
            rules
                .grammar(&config::grammar::PhaseOneIn::of(&plugins))
                .err()
                .unwrap()
                .0,
            "candidate image refused"
        );
        assert_eq!(
            rules
                .held_document(std::path::Path::new("config.yaml"))
                .unwrap()
                .as_str(),
            "held candidate"
        );
        let deploy = busbar_contract::yaml::from_str("{}").unwrap();
        let cfg = config::resolve(&deploy, &Default::default()).unwrap();
        assert_eq!(
            rules.secret_resolver(&cfg, &plugins).await.err().unwrap(),
            "candidate boot projection refused"
        );
    }
}
