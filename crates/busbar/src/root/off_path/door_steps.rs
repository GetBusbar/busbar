// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The root's configuration projection and rules, built once per configuration generation: the
//! kernel-owned sections, the listener needs, the native candidate's projection
//! ([`DoorConfig`]) and the root's configuration rules ([`Rules`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::section::{
    MODEL_PROVIDER_KEY, POOL_MEMBERS_KEY, POOL_MEMBER_MODEL_KEY, RESERVED_MODELS_KEY,
    RESERVED_POOLS_KEY,
};
use busbar_contract::yaml::MappingExt;
use busbar_kernel::state::App;

pub(crate) const ON_EXHAUSTED_KEY: &str = "on_exhausted";
pub(crate) const FALLBACK_POOL_KEY: &str = "fallback_pool";

/// WHAT ONE CONFIGURATION GENERATION IS SEALED OVER (spec Part 1 line 569: one validated
/// `{section: value}` object per `open`/`refresh`): the kernel-owned sections ([`kernel_sections`])
/// and the native candidate's owners and listener slots. Projected from each resolved
/// configuration as it is built (the root's install record,
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
    /// The kernel-owned sections, and beside them every plane section the configuration carries RAW.
    pub(crate) sections: Result<BTreeMap<&'static str, busbar_contract::yaml::Value>, String>,
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

/// THE COMPOSITION ROOT'S RULES OF A CONFIGURATION (`busbar_kernel::appbuild::RootRules`): what
/// the build judges every configuration by before any part of it is built, at boot and at every
/// apply, rebuild or dry run, through the `App` each generation keeps them in. They hold the
/// owned reader, the native listener plan and candidate factory, and the deployment's one
/// destination guard, which hears each committed configuration's destinations through them.
pub(crate) struct Rules {
    reader: Arc<dyn busbar_kernel::appbuild::RootRules>,
    native_listeners: Option<Arc<crate::root::min3_listener_plan::NativeListenerPlan>>,
    native_candidate: Option<Arc<crate::root::min3_candidate::Factory>>,
    /// The deployment's one destination guard (`root::connector::dest_judge`), told each committed
    /// configuration's destinations ([`Rules::with_reader`]). `None`: no guard hears a commit.
    pub(crate) guard: Option<Arc<dyn busbar_kernel::host_services::DestJudge>>,
}

impl std::fmt::Debug for Rules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rules")
            .field("guard", &self.guard.is_some())
            .finish_non_exhaustive()
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
            native_listeners: None,
            native_candidate: None,
            guard,
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
            native_listeners: self.native_listeners.clone(),
            native_candidate: self.native_candidate.clone(),
            guard: self.guard.clone(),
        }
    }

    /// Rules whose destination guard hears each committed configuration's destinations.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn hearing(guard: Arc<dyn busbar_kernel::host_services::DestJudge>) -> Self {
        Self::with_reader(Some(guard), Arc::new(busbar_kernel::appbuild::AcceptAll))
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

    fn check(&self, cfg: &busbar_kernel::config::RootCfg) -> Result<(), String> {
        self.reader.check(cfg)?;
        offline_root_rules(cfg).map_err(|e| e.join("\n"))
    }

    fn destinations_applied(&self, destinations: &busbar_kernel::config::Destinations) {
        if let Some(guard) = &self.guard {
            guard.destinations_applied(destinations);
        }
    }
}

/// The composition root's rules that read only the resolved config: no I/O, no loaded plugin
/// state. Boot/apply (`Rules::check`) and `--validate` both run exactly this, so they agree.
pub(crate) fn offline_root_rules(cfg: &busbar_kernel::config::RootCfg) -> Result<(), Vec<String>> {
    kernel_sections(cfg).map_err(|e| vec![e])?;
    if let Some(url) = cfg.public_url.as_deref() {
        busbar_core_admin::config::validate_public_url(url, &cfg.blocked_metadata_hosts)?;
    }
    Ok(())
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
            p.auth.as_ref().map(|auth| auth.as_str()).map(Value::from),
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
