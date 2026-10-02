//! THE PLANE'S SHAPING TABLES: what it reads, once per open or refresh, out of the settings the
//! kernel hands it (ARCHITECT ruling Q1, 2026-09-30).
//!
//! `OpenIn::settings` is ONE JSON object `{section: value}` holding the sections the plane's tail
//! names, as the kernel validated them, with secret references stripped: `providers` (declaring),
//! `models`, `pools` and `limits` (consumed). The kernel keeps the credentials, the money and the
//! routing; the plane keeps only the fields that shape the bytes it writes to a far end:
//!
//! | field | from |
//! |---|---|
//! | the far end's dialect, `path`, `path_base`, `error_map` | the provider |
//! | the output-cap spelling and the two capability switches, per wire model | the provider and its `model_capabilities` |
//! | `upstream_model`, `default_max_tokens`, `reasoning`, `prompt_caching` | the model |
//! | `context_max` (one value per model across every pool), a member's own `reasoning` | the pools |
//! | the global `default_max_tokens` and the effort → thinking-budget table | `limits` |
//!
//! Each derivation is the previous release's (its boot build of the same tables), so a request is
//! written the same way whichever build holds the tables. The grammar was already judged by the
//! kernel: a field this reading does not use is not read, and a malformed one it does use is a
//! refusal to open.

use std::collections::{BTreeMap, HashMap};

use busbar_contract::ir::egress_prep::{LaneCaps, MaxOutputKey};
use serde::Deserialize;
use serde_json::Value;

use crate::codec::DECLS;

/// The dialect a provider speaks when it names none.
pub const DEFAULT_PROTOCOL: &str = "anthropic";
/// The global output-token default when `limits` names none.
pub const DEFAULT_MAX_TOKENS: u32 = 4096;
/// The effort → thinking-budget table when `limits` names none (minimal, low, medium, high).
pub const DEFAULT_REASONING_BUDGETS: [u32; 4] = [1024, 4096, 8192, 16384];

/// One configured model as a far end: everything that shapes the request written to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lane {
    /// The model's configured name (the key requests and pool members name it by).
    pub model: String,
    /// Its provider's configured name.
    pub provider: String,
    /// The dialect the far end speaks.
    pub dialect: &'static str,
    /// The provider's fixed path, overriding the dialect's own.
    pub path: Option<String>,
    /// The provider's path base, handed to the dialect's own path builder.
    pub path_base: Option<String>,
    /// The provider's configured tenant (`organization`, `project`), set on every far request.
    pub organization: Option<String>,
    /// See `organization`.
    pub project: Option<String>,
    /// The name the far end knows the model by, when it differs.
    pub upstream_model: Option<String>,
    /// The model's own output-token default.
    pub default_max_tokens: Option<u32>,
    /// The model's context window, one value across every pool.
    pub context_max: Option<usize>,
    /// Whether the model takes reasoning.
    pub reasoning: bool,
    /// Whether the model takes prompt-cache markers.
    pub prompt_caching: bool,
    /// The request-shape capabilities the far end accepts.
    pub caps: LaneCaps,
    /// The provider's error-code map.
    pub error_map: HashMap<String, String>,
}

impl Lane {
    /// The model name written to the far end.
    #[must_use]
    pub fn wire_model(&self) -> &str {
        self.upstream_model.as_deref().unwrap_or(&self.model)
    }

    /// What of the lane shapes a request body, borrowed.
    #[must_use]
    pub fn shape(&self) -> FarShape<'_> {
        FarShape {
            dialect: self.dialect,
            wire_model: self.wire_model(),
            default_max_tokens: self.default_max_tokens,
            prompt_caching: self.prompt_caching,
            caps: self.caps,
            path_base: self.path_base.as_deref(),
        }
    }
}

/// What of a far end shapes a request body: its dialect, the model name it is sent, its output-
/// token default, its prompt-cache switch, its capabilities and its path base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FarShape<'a> {
    /// The far end's dialect.
    pub dialect: &'static str,
    /// The model name written to it.
    pub wire_model: &'a str,
    /// Its output-token default.
    pub default_max_tokens: Option<u32>,
    /// Whether it takes prompt-cache markers.
    pub prompt_caching: bool,
    /// The request-shape capabilities it accepts.
    pub caps: LaneCaps,
    /// Its path base.
    pub path_base: Option<&'a str>,
}

/// One pool member as the pool names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The member's configured name: the model key.
    pub model: String,
    /// The member's own reasoning switch, overriding the model's.
    pub reasoning: Option<bool>,
}

/// THE TABLES, read once per generation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shaping {
    /// Every configured model, by name.
    pub lanes: BTreeMap<String, Lane>,
    /// Every pool's members, in the pool's order, by pool name.
    pub pools: BTreeMap<String, Vec<Member>>,
    /// The global output-token default.
    pub default_max_tokens: u32,
    /// The effort → thinking-budget table.
    pub reasoning_budgets: [u32; 4],
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum MaxOutputKeyCfg {
    MaxTokens,
    MaxCompletionTokens,
}

impl MaxOutputKeyCfg {
    fn key(&self) -> MaxOutputKey {
        match self {
            MaxOutputKeyCfg::MaxTokens => MaxOutputKey::MaxTokens,
            MaxOutputKeyCfg::MaxCompletionTokens => MaxOutputKey::MaxCompletionTokens,
        }
    }
}

#[derive(Deserialize, Default)]
struct ModelCapabilities {
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    max_output_key: Option<MaxOutputKeyCfg>,
    #[serde(default)]
    anthropic_adaptive_thinking: Option<bool>,
    #[serde(default)]
    native_structured_output: Option<bool>,
    #[serde(default)]
    reasoning_none: Option<bool>,
    #[serde(default)]
    thinking_always_on: Option<bool>,
}

#[derive(Deserialize)]
struct ProviderCfg {
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    path_base: Option<String>,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    error_map: HashMap<String, String>,
    #[serde(default)]
    max_output_key: Option<MaxOutputKeyCfg>,
    #[serde(default)]
    anthropic_adaptive_thinking: Option<bool>,
    #[serde(default)]
    native_structured_output: Option<bool>,
    #[serde(default)]
    model_capabilities: Vec<ModelCapabilities>,
}

#[derive(Deserialize)]
struct ModelCfg {
    provider: String,
    #[serde(default)]
    upstream_model: Option<String>,
    #[serde(default)]
    default_max_tokens: Option<u32>,
    #[serde(default)]
    reasoning: Option<bool>,
    #[serde(default)]
    prompt_caching: Option<bool>,
}

#[derive(Deserialize)]
struct Budgets {
    #[serde(default)]
    minimal: Option<u32>,
    #[serde(default)]
    low: Option<u32>,
    #[serde(default)]
    medium: Option<u32>,
    #[serde(default)]
    high: Option<u32>,
}

#[derive(Deserialize)]
struct LimitsCfg {
    #[serde(default)]
    default_max_tokens: Option<u32>,
    #[serde(default)]
    reasoning_effort_budgets: Option<Budgets>,
}

/// A `*` glob over a model name: the only wildcard `model_capabilities` takes.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

/// The capabilities a far end accepts for `wire_model`: the provider's switches, then the first
/// `model_capabilities` rule whose glob matches the wire model.
fn lane_caps(p: &ProviderCfg, wire_model: &str) -> LaneCaps {
    let mut caps = LaneCaps::default();
    if let Some(k) = &p.max_output_key {
        caps.max_output_key = k.key();
    }
    if let Some(b) = p.anthropic_adaptive_thinking {
        caps.anthropic_adaptive_thinking = b;
    }
    if let Some(b) = p.native_structured_output {
        caps.native_structured_output = b;
    }
    if let Some(rule) = p
        .model_capabilities
        .iter()
        .find(|r| r.models.iter().any(|g| glob_match(g, wire_model)))
    {
        if let Some(k) = &rule.max_output_key {
            caps.max_output_key = k.key();
        }
        if let Some(b) = rule.anthropic_adaptive_thinking {
            caps.anthropic_adaptive_thinking = b;
        }
        if let Some(b) = rule.native_structured_output {
            caps.native_structured_output = b;
        }
        if let Some(b) = rule.reasoning_none {
            caps.reasoning_none = b;
        }
        if let Some(b) = rule.thinking_always_on {
            caps.thinking_always_on = b;
        }
    }
    caps
}

/// A pool member, bare (`model-name`) or rich (`{ model, reasoning, context_max, … }`).
fn member(v: &Value) -> Option<(Member, Option<usize>)> {
    match v {
        Value::String(s) => Some((
            Member {
                model: s.clone(),
                reasoning: None,
            },
            None,
        )),
        Value::Object(o) => {
            let model = o.get("model")?.as_str()?.to_string();
            let reasoning = o.get("reasoning").and_then(Value::as_bool);
            let context_max = o
                .get("context_max")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok());
            Some((Member { model, reasoning }, context_max))
        }
        _ => None,
    }
}

fn section<T: for<'de> Deserialize<'de>>(
    settings: &Value,
    name: &str,
) -> Result<Option<T>, String> {
    match settings.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v.clone())
            .map(Some)
            .map_err(|e| format!("the `{name}` settings do not read: {e}")),
    }
}

impl Shaping {
    /// READ THE TABLES from the settings object.
    ///
    /// # Errors
    ///
    /// Why the settings do not describe a generation this plane can serve: a section that does not
    /// read, a model naming no provider, a provider naming a dialect the plane does not speak, a
    /// pool member naming no model, or one model given two context windows.
    pub fn from_settings(settings: &Value) -> Result<Self, String> {
        let providers: BTreeMap<String, ProviderCfg> =
            section(settings, "providers")?.unwrap_or_default();
        let models: BTreeMap<String, ModelCfg> = section(settings, "models")?.unwrap_or_default();
        let limits: Option<LimitsCfg> = section(settings, "limits")?;
        let mut pools: BTreeMap<String, Vec<Member>> = BTreeMap::new();
        let mut context: HashMap<String, Option<usize>> = HashMap::new();
        if let Some(Value::Object(sec)) = settings.get("pools") {
            for (name, pool) in sec {
                // The reserved keys of the section are settings, not pools: a pool has members.
                let Some(Value::Array(ms)) = pool.get("members") else {
                    continue;
                };
                let mut members = Vec::with_capacity(ms.len());
                for m in ms {
                    let (m, context_max) = member(m)
                        .ok_or_else(|| format!("pool '{name}' has a member that does not read"))?;
                    // One model is one far end: its context window is single-valued across every
                    // pool that names it, and two explicit values that disagree are refused.
                    match (context.get(&m.model).copied().flatten(), context_max) {
                        (Some(have), Some(c)) if have != c => {
                            return Err(format!(
                                "model '{}' has conflicting context_max across pools ({have} vs {c}); \
                                 a model maps to one lane and must declare a single context_max",
                                m.model
                            ));
                        }
                        (Some(_), _) => {}
                        (None, c) => {
                            context.insert(m.model.clone(), c);
                        }
                    }
                    members.push(m);
                }
                pools.insert(name.clone(), members);
            }
        }
        let mut lanes = BTreeMap::new();
        for (name, m) in models {
            let p = providers.get(&m.provider).ok_or_else(|| {
                format!(
                    "model '{name}' references unknown provider '{}'",
                    m.provider
                )
            })?;
            let asked = p.protocol.as_deref().unwrap_or(DEFAULT_PROTOCOL);
            let dialect = DECLS
                .iter()
                .find(|d| d.name == asked && d.codec.is_some())
                .map(|d| d.name)
                .ok_or_else(|| {
                    format!("provider '{}' uses unknown protocol '{asked}'", m.provider)
                })?;
            let wire = m.upstream_model.as_deref().unwrap_or(&name);
            let lane = Lane {
                model: name.clone(),
                provider: m.provider.clone(),
                dialect,
                path: p.path.clone(),
                path_base: p.path_base.clone(),
                organization: p.organization.clone(),
                project: p.project.clone(),
                upstream_model: m.upstream_model.clone(),
                default_max_tokens: m.default_max_tokens,
                context_max: context.get(&name).copied().flatten(),
                reasoning: m.reasoning.unwrap_or(false),
                prompt_caching: m.prompt_caching.unwrap_or(false),
                caps: lane_caps(p, wire),
                error_map: p.error_map.clone(),
            };
            lanes.insert(name, lane);
        }
        for (name, members) in &pools {
            if let Some(m) = members.iter().find(|m| !lanes.contains_key(&m.model)) {
                return Err(format!(
                    "pool '{name}' references unknown model '{}'",
                    m.model
                ));
            }
        }
        let budgets = limits
            .as_ref()
            .and_then(|l| l.reasoning_effort_budgets.as_ref());
        let [minimal, low, medium, high] = DEFAULT_REASONING_BUDGETS;
        Ok(Shaping {
            lanes,
            pools,
            default_max_tokens: limits
                .as_ref()
                .and_then(|l| l.default_max_tokens)
                .unwrap_or(DEFAULT_MAX_TOKENS),
            reasoning_budgets: [
                budgets.and_then(|b| b.minimal).unwrap_or(minimal),
                budgets.and_then(|b| b.low).unwrap_or(low),
                budgets.and_then(|b| b.medium).unwrap_or(medium),
                budgets.and_then(|b| b.high).unwrap_or(high),
            ],
        })
    }

    /// The far end a pool member names.
    #[must_use]
    pub fn lane(&self, member: &str) -> Option<&Lane> {
        self.lanes.get(member)
    }

    /// Whether reasoning reaches the far end for `member` of `pool`: the member's own switch when
    /// the pool gives it one, else the model's.
    #[must_use]
    pub fn reasoning(&self, pool: &str, member: &str) -> Option<bool> {
        let lane = self.lane(member)?;
        let own = self
            .pools
            .get(pool)
            .and_then(|ms| ms.iter().find(|m| m.model == member))
            .and_then(|m| m.reasoning);
        Some(own.unwrap_or(lane.reasoning))
    }

    /// The configured provider serving `model`, for the ad-hoc surface's door check.
    #[must_use]
    pub fn provider_of(&self, model: &str) -> Option<&str> {
        self.lanes.get(model).map(|l| l.provider.as_str())
    }
}

impl super::arrive::Catalogue for Shaping {
    fn provider_of(&self, model: &str) -> Option<&str> {
        Shaping::provider_of(self, model)
    }
}
