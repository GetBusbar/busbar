// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::plugin::Kind;
use serde::Deserialize;

/// A PLANE'S TOP-LEVEL CONFIG SECTION, CAPTURED RAW — the neutral carrier `DeployCfg`/`RootCfg` use
/// for a plane's section in a build where the plane that would LOWER it is compiled out.
///
/// A declared-definition section and its paired endpoint block (when the plane has one) deserialize
/// into that plane's own config types — types that do not exist when their plane is compiled out
/// (each gated by its own `plane-<x>` feature). So in that build the field is typed `RawPlaneSection`
/// instead (behind `#[cfg(not(feature = "plane-<x>"))]`), which captures whatever the operator wrote
/// without naming a plane type. A section that carries CONTENT in such a build names a plane that is
/// not present; `resolve` REFUSES it (see the config deletion-gate leg), exactly as the protocol
/// registry refuses a config naming a deleted dialect.
///
/// This type lives OUTSIDE `config/` on purpose: `cargo xtask gate config-schema` fingerprints the
/// `config/` directory, and the `#[cfg(feature = "plane-<x>")]` twin field (declared LAST) is what
/// that fingerprint records — so the `tools:`/`mcp:`/`agents:` schema is unchanged by this capture. A
/// `RawPlaneSection` type declared under `config/` would add a new fingerprinted type and drift the
/// committed snapshot; declared here it never enters the config surface.
///
/// Compiled UNCONDITIONALLY: besides the compiled-out-plane capture, it is the empty-section fallback
/// the neutral `*Section` newtypes take when a plane hook is absent, so it must exist in every feature
/// combination (including both planes on, where it is simply never constructed).
#[derive(Debug, Clone, Default)]
pub(crate) struct RawPlaneSection {
    /// The captured value, or `None` when the section was absent or explicitly null.
    raw: Option<serde_yaml::Value>,
}

impl<'de> serde::Deserialize<'de> for RawPlaneSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_yaml::Value::deserialize(deserializer)?;
        let raw = if value.is_null() { None } else { Some(value) };
        Ok(RawPlaneSection { raw })
    }
}

impl PlaneCfg for RawPlaneSection {
    fn secret_refs(&self) -> Vec<(String, &crate::config::SecretRef)> {
        Vec::new()
    }

    fn contains_def(&self, _name: &str) -> bool {
        false
    }
    fn def_names(&self) -> Vec<&str> {
        Vec::new()
    }
    fn entry_document(&self, _name: &str) -> Option<serde_json::Value> {
        None
    }
    fn insert_def(&mut self, _name: &str, _def: &serde_json::Value) -> Result<(), String> {
        Err("this build was compiled without the plane that owns this section".to_string())
    }
    fn container_gates(&self) -> ContainerGateInputs {
        ContainerGateInputs {
            section_hooks: Vec::new(),
            containers: Vec::new(),
        }
    }
    fn validate_registry(&self) -> Result<(), String> {
        Ok(())
    }
    fn is_present(&self) -> bool {
        RawPlaneSection::is_present(self)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn clone_box(&self) -> Box<dyn PlaneCfg> {
        Box::new(self.clone())
    }
    fn clone_arc_any(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
        std::sync::Arc::new(self.clone())
    }
}

impl PlaneEndpointCfg for RawPlaneSection {
    fn is_present(&self) -> bool {
        RawPlaneSection::is_present(self)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl RawPlaneSection {
    pub(crate) fn is_present(&self) -> bool {
        match &self.raw {
            None | Some(serde_yaml::Value::Null) => false,
            Some(serde_yaml::Value::Mapping(m)) => !m.is_empty(),
            Some(_) => true,
        }
    }
}

fn default_plane_section(config_section: &str) -> Box<dyn PlaneCfg> {
    match crate::plane_driver::registry::plane_decl_for_config_section(config_section)
        .and_then(|d| d.default_section.map(|f| (d, f)))
    {
        Some((d, f)) => f(d),
        None => Box::new(RawPlaneSection::default()),
    }
}

fn deserialize_plane_section<'de, D>(
    config_section: &str,
    deserializer: D,
) -> Result<Box<dyn PlaneCfg>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_yaml::Value::deserialize(deserializer)?;
    let decl = crate::plane_driver::registry::plane_decl_for_config_section(config_section);
    match decl.and_then(|d| d.parse_section.map(|parse| (d, parse))) {
        Some((d, parse)) => {
            validate_plane_section(
                config_section,
                &value,
                d.trust_keys,
                d.caller_credential_refusal,
                &config_sections(),
            )
            .map_err(serde::de::Error::custom)?;
            parse(d, &value).map_err(serde::de::Error::custom)
        }
        None => {
            let raw = if value.is_null() { None } else { Some(value) };
            Ok(Box::new(RawPlaneSection { raw }))
        }
    }
}

fn deserialize_plane_endpoint<'de, D>(
    config_section: &str,
    deserializer: D,
) -> Result<Option<Box<dyn PlaneEndpointCfg>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_yaml::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(None);
    }
    match crate::plane_driver::registry::plane_decl_for_config_section(config_section)
        .and_then(|d| d.parse_endpoint.map(|parse| (d, parse)))
    {
        Some((d, parse)) => parse(d, &value).map(Some).map_err(serde::de::Error::custom),
        None => Ok(Some(Box::new(RawPlaneSection { raw: Some(value) }))),
    }
}

/// THE DECLARED SECTIONS as they land in `DeployCfg`: every declaring section a REGISTERED plane
/// parses (its own `parse_section` hook) and either OWNS the grammar of
/// (`PlaneDeclaration::owned_config_sections` lists its own `config_section`) or writes as one of the
/// frozen named-definition maps ([`NAMED_MAP_SECTIONS`]), keyed by that section and type-erased behind [`PlaneCfg`] — the one map carrier, so `DeployCfg`
/// names no plane section and no plane-local type (#47/#49). Each entry is parsed by its plane's own
/// `parse_section` hook; an absent section has no entry. `busbar-kernel` has no dependency on any
/// plane crate (#40), which is why the plane's typed section is reached only through this seam.
#[derive(Debug, Default)]
pub struct DeclaredSections(pub std::collections::BTreeMap<&'static str, Box<dyn PlaneCfg>>);

impl DeclaredSections {
    pub(crate) fn holds(decl: &crate::plane_driver::registry::PlaneDeclaration) -> bool {
        decl.owned_config_sections.contains(&decl.config_section)
            || (NAMED_MAP_SECTIONS[2..].contains(&decl.config_section)
                && crate::plane_driver::registry::plane_decl_for_config_section(
                    decl.config_section,
                )
                .is_some_and(|d| d.parse_section.is_some()))
    }

    #[must_use]
    pub fn get(&self, section: &str) -> Option<&dyn PlaneCfg> {
        self.0.get(section).map(|b| &**b)
    }

    pub fn get_or_default(&mut self, section: &str) -> Option<&mut dyn PlaneCfg> {
        let key =
            crate::plane_driver::registry::plane_decl_for_config_section(section)?.config_section;
        Some(
            &mut **self
                .0
                .entry(key)
                .or_insert_with(|| default_plane_section(key)),
        )
    }

    pub(crate) fn parse(
        section: &'static str,
        value: serde_yaml::Value,
    ) -> Result<Self, serde_yaml::Error> {
        let cfg = deserialize_plane_section(section, value)?;
        Ok(DeclaredSections([(section, cfg)].into_iter().collect()))
    }
}

/// THE ENDPOINT BLOCK as it lands in `DeployCfg`, type-erased behind [`PlaneEndpointCfg`] — the
/// neutral seam the owning plane's own endpoint-config type deserializes through. Absent/null ⇒
/// `None` (endpoint not configured), byte-identical to the pre-seam typed field's `Default`.
#[derive(Debug, Default)]
pub struct EndpointSection(pub Option<Box<dyn PlaneEndpointCfg>>);

impl EndpointSection {
    pub(crate) const OWNER: &'static str = NAMED_MAP_SECTIONS[2];
}

impl<'de> serde::Deserialize<'de> for EndpointSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_plane_endpoint(Self::OWNER, deserializer).map(EndpointSection)
    }
}

pub fn config_sections() -> Vec<&'static str> {
    config_sections_from(crate::plane_driver::registry::plane_decls())
}

pub fn config_sections_from(
    decls: &[&'static crate::plane_driver::registry::PlaneDecl],
) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for section in decls
        .iter()
        .map(|decl| decl.config_section)
        .chain(busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS)
    {
        if !out.contains(&section) {
            out.push(section);
        }
    }
    out
}

pub fn validate_plane_section(
    section: &str,
    value: &serde_yaml::Value,
    trust_keys: &[busbar_contract::plane::TrustKeyDecl],
    caller_credential_refusal: Option<&str>,
    sections: &[&'static str],
) -> Result<(), String> {
    for (name, entry) in crate::trust::section::registrations(value) {
        validate_plane_entry(section, name, entry, trust_keys, sections)?;
        refuse_registration_forwarding_caller_credential(
            &format!("`{section}.{name}`"),
            entry,
            caller_credential_refusal,
        )?;
    }
    let models = value
        .get(busbar_contract::section::RESERVED_MODELS_KEY)
        .and_then(serde_yaml::Value::as_mapping);
    for (name, entry) in models.into_iter().flatten() {
        if let Some(name) = name.as_str() {
            let models = busbar_contract::section::RESERVED_MODELS_KEY;
            judge_entry_timeout(&format!("`{section}.{models}.{name}`"), entry)?;
        }
    }
    refuse_forwarded_caller_credential(value, caller_credential_refusal)
}

const UPSTREAM_CREDENTIALS: &str = "upstream_credentials";

pub fn refuse_forwarded_caller_credential(
    value: &serde_yaml::Value,
    refusal: Option<&str>,
) -> Result<(), String> {
    let Some(refusal) = refusal else {
        return Ok(());
    };
    let default = value
        .as_mapping()
        .and_then(|m| m.get(UPSTREAM_CREDENTIALS))
        .cloned()
        .map(serde_yaml::from_value::<busbar_contract::config::UpstreamCreds>);
    match default {
        Some(Ok(busbar_contract::config::UpstreamCreds::Passthrough)) => Err(refusal.to_string()),
        _ => Ok(()),
    }
}

pub fn refuse_registration_forwarding_caller_credential(
    at: &str,
    entry: &serde_yaml::Value,
    refusal: Option<&str>,
) -> Result<(), String> {
    match refuse_forwarded_caller_credential(entry, refusal) {
        Ok(()) => Ok(()),
        Err(refusal) => Err(format!(
            "{at}: `upstream_credentials: passthrough` on this registration is refused, as it is \
             as the section default: {refusal}"
        )),
    }
}

pub fn validate_plane_entry(
    section: &str,
    name: &str,
    entry: &serde_yaml::Value,
    trust_keys: &[busbar_contract::plane::TrustKeyDecl],
    sections: &[&'static str],
) -> Result<(), String> {
    let at = format!("`{section}.{name}`");
    crate::trust::section::judge_entry(&at, entry, trust_keys)?;

    if name != busbar_contract::section::RESERVED_MODELS_KEY
        && name != busbar_contract::section::RESERVED_POOLS_KEY
    {
        judge_entry_timeout(&at, entry)?;
    }
    let hooks = entry
        .as_mapping()
        .and_then(|m| m.get(Kind::Hook.root()))
        .and_then(serde_yaml::Value::as_sequence);
    for hook in hooks.into_iter().flatten() {
        if let Some(hook) = hook.as_str() {
            refuse_cross_plane_reference(&at, hook, sections)?;
        }
    }
    Ok(())
}

pub fn judge_entry_timeout(at: &str, entry: &serde_yaml::Value) -> Result<(), String> {
    use busbar_contract::section::{entry_timeout_ms, ENTRY_TIMEOUT_KEY};
    let Some(written) = entry
        .as_mapping()
        .and_then(|m| m.get(ENTRY_TIMEOUT_KEY))
        .filter(|v| !v.is_null())
    else {
        return Ok(());
    };
    let Some(text) = written.as_str() else {
        return Err(format!(
            "{at}: `{ENTRY_TIMEOUT_KEY}:` must be a duration `<n><s|m|h|d>`, e.g. `30s`"
        ));
    };
    entry_timeout_ms(text)
        .map(|_| ())
        .map_err(|reason| format!("{at}: {reason}"))
}

pub fn validate_section_hooks(
    at: &str,
    hooks: &[String],
    sections: &[&'static str],
) -> Result<(), String> {
    for hook in hooks {
        refuse_cross_plane_reference(at, hook, sections)?;
    }
    Ok(())
}

pub fn split_section_for_plane<'de, D, T>(
    deserializer: D,
    plane_key: &'static str,
    validate: impl Fn(&str, &T) -> Result<(), String>,
) -> Result<busbar_contract::section::Section<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    use serde::de::Error as _;
    let d = crate::plane_driver::registry::plane_decl_for(plane_key).ok_or_else(|| {
        D::Error::custom(format!(
            "no plane is registered to own this config section (looked up by key `{plane_key}`) \
             — this build has no plane plugin compiled in or installed, so it cannot resolve \
             config that names a plane-owned section; install a plane plugin or remove the \
             section from the config"
        ))
    })?;
    busbar_contract::section::split_section(
        deserializer,
        d.config_section,
        d.subject_noun,
        validate,
    )
}

#[cfg(test)]
#[path = "tests/plane_sections_tests.rs"]
mod config_tests;

#[cfg(test)]
#[path = "tests/plane_boot_validation_tests.rs"]
mod boot_validation_tests;

pub trait PlaneCfg: std::any::Any + Send + Sync + std::fmt::Debug {
    fn secret_refs(&self) -> Vec<(String, &busbar_contract::secret_ref::SecretRef)>;

    fn undeclared_secret_ref(&self) -> Option<String> {
        None
    }

    fn contains_def(&self, name: &str) -> bool;

    fn def_names(&self) -> Vec<&str>;

    fn entry_document(&self, name: &str) -> Option<serde_json::Value>;

    fn insert_def(&mut self, name: &str, def: &serde_json::Value) -> Result<(), String>;

    fn container_gates(&self) -> ContainerGateInputs;

    fn validate_registry(&self) -> Result<(), String>;

    fn ledger_lanes(&self) -> Vec<String> {
        Vec::new()
    }

    fn model_provider_refs(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    fn known_dialects(&self) -> Option<&'static [&'static str]> {
        None
    }

    fn is_present(&self) -> bool;

    fn as_any(&self) -> &dyn std::any::Any;

    fn clone_box(&self) -> Box<dyn PlaneCfg>;

    fn clone_arc_any(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync>;
}

pub struct ContainerGateInputs {
    pub section_hooks: Vec<String>,

    pub containers: Vec<(String, Vec<String>)>,
}

pub trait PlaneEndpointCfg: std::any::Any + Send + Sync + std::fmt::Debug {
    fn is_present(&self) -> bool;

    fn as_any(&self) -> &dyn std::any::Any;
}

/// WHY a hook reference was refused. Three arms, and each one is a different thing for an operator
/// to do about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookRefError {
    /// The name is empty or whitespace. Nothing to look up, and nothing to diagnose.
    Empty,
    /// The name is prefixed with a config SECTION, so it reaches onto another plane.
    CrossPlane {
        /// The reference exactly as the operator wrote it (trimmed).
        hook: String,
        /// The section it reaches onto.
        section: &'static str,
        /// What is left after the section prefix — the bare name they probably meant.
        rest: String,
    },
    /// The name is dotted but names no section busbar knows. Still not a bare name.
    NotBare {
        /// The reference exactly as the operator wrote it (trimmed).
        hook: String,
    },
}

pub(crate) struct Refusal<'a> {
    pub(crate) at: &'a str,

    pub(crate) err: HookRefError,
}

impl From<Refusal<'_>> for String {
    fn from(r: Refusal<'_>) -> String {
        let at = r.at;
        match r.err {
            HookRefError::Empty => format!("{at}: `hooks:` contains an empty name"),
            HookRefError::CrossPlane {
                hook,
                section,
                rest,
            } => format!(
                "{at}: `hooks:` may only name hooks from the top-level `hooks:` map, by bare name. \
                 `{hook}` reaches onto the `{section}:` plane, and no entry on one plane may \
                 reference an entry on another. Did you mean the hook `{rest}`?"
            ),
            HookRefError::NotBare { hook } => format!(
                "{at}: `hooks:` may only name hooks from the top-level `hooks:` map, by bare name. \
                 `{hook}` is not a bare name."
            ),
        }
    }
}

pub fn judge_hook_ref(hook: &str, sections: &[&'static str]) -> Result<(), HookRefError> {
    let hook = hook.trim();
    if hook.is_empty() {
        return Err(HookRefError::Empty);
    }

    for section in sections {
        if let Some(rest) = hook.strip_prefix(&format!("{section}.")) {
            return Err(HookRefError::CrossPlane {
                hook: hook.to_string(),
                section,
                rest: rest.to_string(),
            });
        }
    }
    if hook.contains('.') {
        return Err(HookRefError::NotBare {
            hook: hook.to_string(),
        });
    }
    Ok(())
}

pub fn refuse_cross_plane_reference(
    at: &str,
    hook: &str,
    sections: &[&'static str],
) -> Result<(), String> {
    judge_hook_ref(hook, sections).map_err(|err| Refusal { at, err }.into())
}

pub const NAMED_MAP_SECTIONS: [&str; 4] =
    [Kind::Auth.root(), Kind::Export.root(), "tools", "agents"];

pub fn attach_list(section: &[String], own: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(section.len() + own.len());
    for h in section.iter().chain(own) {
        if !out.iter().any(|e| e == h) {
            out.push(h.clone());
        }
    }
    out
}
