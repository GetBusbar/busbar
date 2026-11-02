// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::plane::{BillableClass, PlaneDeclaration, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::PlaneRegistration;

use crate::config::plane_sections::{ContainerGateInputs, PlaneCfg};
use crate::plane_driver::registry::{BuildCtx, PlaneDecl, PlaneHooks};

pub struct DoorRow {
    reg: PlaneRegistration,
    dialects: &'static [&'static str],

    provider_dialects: &'static [&'static str],
}

impl std::fmt::Debug for DoorRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorRow")
            .field("key", &self.reg.key)
            .field("section", &self.reg.section)
            .finish_non_exhaustive()
    }
}

fn row(decl: &PlaneDecl) -> Option<&'static DoorRow> {
    decl.door
}

pub fn fold(reg: PlaneRegistration) -> Result<&'static PlaneDecl, String> {
    if reg.key.is_empty() || reg.section.is_empty() {
        return Err(format!(
            "plane door `{}` states no name or no declaring section; a plane is installed by its \
             name and configured by its section",
            reg.key
        ));
    }
    let declaration = declaration_of(&reg);

    let named = busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS.contains(&reg.section);
    let hooks = door_hooks(named, !reg.owns.is_empty(), !reg.admin_routes.is_empty());
    let dialects: &'static [&'static str] = reg.dialects.clone().leak();
    let provider_dialects: &'static [&'static str] = (reg.dialects.iter())
        .zip(&reg.dialect_flags)
        .filter(|(_, f)| *f & busbar_contract::abi::plane::DIALECT_PROVIDER != 0)
        .map(|(d, _)| *d)
        .collect::<Vec<_>>()
        .leak();
    let door: &'static DoorRow = Box::leak(Box::new(DoorRow {
        reg,
        dialects,
        provider_dialects,
    }));
    let mut decl = PlaneDecl::assemble(declaration, hooks);
    decl.door = Some(door);
    Ok(Box::leak(Box::new(decl)))
}

fn declaration_of(reg: &PlaneRegistration) -> PlaneDeclaration {
    PlaneDeclaration {
        key: reg.key,
        fallback: reg.fallback,
        config_section: reg.section,
        scope_kinds: reg.scope_kinds.clone().leak(),
        subject_noun: reg.subject_noun,
        admin_noun: reg.admin_noun,
        audit_kind: reg.audit_kind,
        card_signing_domain: reg.signing.map(|(d, _)| d),
        card_kid_prefix: reg.signing.map(|(_, p)| p),
        owned_config_sections: reg.owns.clone().leak(),
        billable_classes: reg
            .billable_classes
            .iter()
            .map(|&(class, family)| BillableClass { class, family })
            .collect::<Vec<_>>()
            .leak(),
        fee_units: reg.fee_units.clone().leak(),
        metric_families: &[],
        record_kinds: reg.record_kinds.clone().leak(),
        required_config_sections: reg.requires.clone().leak(),
        trust_keys: reg.trust_keys.clone().leak(),
        caller_credential_refusal: reg.caller_credential_refusal,
        served_op_classes: &[],
    }
}

#[must_use]
pub fn is_door(decl: &PlaneDecl) -> bool {
    decl.door.is_some()
}

#[must_use]
pub fn consumed_sections(decl: &PlaneDecl) -> &'static [&'static str] {
    row(decl).map_or(&[], |d| d.reg.consumes.as_slice())
}

#[must_use]
pub fn streaming_content_types(decl: &PlaneDecl) -> &'static [&'static str] {
    row(decl).map_or(&[], |d| d.reg.streaming_content_types.as_slice())
}

#[must_use]
pub fn provider_keys(
    decls: &[&'static PlaneDecl],
) -> Option<&'static busbar_contract::provider_keys::ProviderKeys> {
    (decls.iter())
        .filter_map(|d| d.door)
        .find_map(|d| d.reg.provider_keys.as_ref())
}

#[must_use]
pub fn judge_provider(
    name: &str,
    table: &crate::config::ProviderTable,
) -> Option<Result<(), String>> {
    let dialect = table
        .get(busbar_contract::section::MODEL_PROTOCOL_KEYS[0])
        .and_then(serde_json::Value::as_str)?;
    let door = (crate::plane_driver::registry::plane_decls().iter())
        .filter_map(|d| d.door)
        .find(|d| d.provider_dialects.contains(&dialect))?;
    let blob = serde_json::json!({ "providers": { name: table } });
    Some(
        serde_json::to_vec(&blob)
            .map_err(|e| e.to_string())
            .and_then(|bytes| (door.reg.validate)(&bytes)),
    )
}

/// A DOOR PLANE'S SECTION, as written: the door judged it (`validate`) and is handed it raw; the
/// kernel reads only the words it owns (the registrations' names, their trust keys and `hooks:`
/// lists, and the reserved section words). Also the plane's per-generation runtime slot, which the
/// named-map reads project.
#[derive(Debug, Clone)]
pub struct DoorSection {
    /// The door that declares the section (the row it was parsed through), whose registration names
    /// the section's secret paths and judges it whole.
    door: Option<&'static DoorRow>,
    /// The section's key.
    pub section: &'static str,
    /// The section as written (`Null` when absent).
    pub value: serde_yaml::Value,
    /// The secret references the section holds at its door's declared paths
    /// (`PlaneRegistration::secret_refs`), each with the config path it was read at.
    refs: Vec<(String, busbar_contract::secret_ref::SecretRef)>,
    /// The refusal for the first secret reference the section holds at a position its door did
    /// NOT declare (OWNER RULING, CHIP-REVIEW-v4 change 2), if any.
    undeclared: Option<String>,
}

impl DoorSection {
    #[must_use]
    pub fn as_defs(
        &self,
    ) -> std::collections::BTreeMap<&'static str, Box<dyn crate::config::plane_sections::PlaneCfg>>
    {
        std::collections::BTreeMap::from([(
            self.section,
            Box::new(self.clone()) as Box<dyn crate::config::plane_sections::PlaneCfg>,
        )])
    }

    #[must_use]
    pub fn new(
        door: Option<&'static DoorRow>,
        section: &'static str,
        value: serde_yaml::Value,
    ) -> Self {
        let declaring = door.filter(|d| d.reg.section == section);
        let paths = declaring
            .map(|d| d.reg.secret_refs.as_slice())
            .unwrap_or_default();
        let mut refs = Vec::new();
        for path in paths {
            let Some(rest) = path.strip_prefix("settings.") else {
                continue;
            };
            let segments: Vec<&str> = rest.split('.').collect();
            collect_refs(&value, &segments, section.to_string(), &mut refs);
        }
        let declared: Vec<String> = paths
            .iter()
            .filter_map(|p| p.strip_prefix("settings.").map(str::to_string))
            .collect();
        let undeclared = serde_json::to_value(&value).ok().and_then(|tree| {
            busbar_contract::secret_fields::undeclared_reference(&tree, &declared).map(|at| {
                busbar_contract::secret_fields::undeclared_refusal(
                    &format!("{section}.{at}"),
                    declaring.map_or(section, |d| d.reg.key),
                )
            })
        });
        Self {
            door,
            section,
            value,
            refs,
            undeclared,
        }
    }

    fn registrations(&self) -> impl Iterator<Item = (&str, &serde_yaml::Value)> {
        crate::trust::section::registrations(&self.value)
    }

    fn hooks_of(v: &serde_yaml::Value) -> Vec<String> {
        v.as_mapping()
            .and_then(|m| m.get(busbar_contract::plugin::Kind::Hook.root()))
            .and_then(serde_yaml::Value::as_sequence)
            .map(|s| {
                s.iter()
                    .filter_map(|h| h.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl PlaneCfg for DoorSection {
    fn secret_refs(&self) -> Vec<(String, &busbar_contract::secret_ref::SecretRef)> {
        self.refs.iter().map(|(at, r)| (at.clone(), r)).collect()
    }

    fn undeclared_secret_ref(&self) -> Option<String> {
        self.undeclared.clone()
    }

    fn contains_def(&self, name: &str) -> bool {
        self.registrations().any(|(n, _)| n == name)
    }

    fn def_names(&self) -> Vec<&str> {
        self.registrations().map(|(n, _)| n).collect()
    }

    fn entry_document(&self, name: &str) -> Option<serde_json::Value> {
        self.registrations()
            .find(|(n, _)| *n == name)
            .and_then(|(_, v)| serde_json::to_value(v).ok())
    }

    fn insert_def(&mut self, name: &str, def: &serde_json::Value) -> Result<(), String> {
        let entry: serde_yaml::Value = serde_yaml::to_value(def)
            .map_err(|e| format!("invalid `{}.{name}` definition: {e}", self.section))?;
        if !self.value.is_mapping() {
            self.value = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        }
        if let Some(m) = self.value.as_mapping_mut() {
            m.insert(serde_yaml::Value::String(name.to_string()), entry);
        }

        *self = Self::new(self.door, self.section, std::mem::take(&mut self.value));
        Ok(())
    }

    fn container_gates(&self) -> ContainerGateInputs {
        ContainerGateInputs {
            section_hooks: Self::hooks_of(&self.value),
            containers: self
                .registrations()
                .map(|(n, v)| (n.to_string(), Self::hooks_of(v)))
                .collect(),
        }
    }

    fn validate_registry(&self) -> Result<(), String> {
        if !self.is_present() {
            return Ok(());
        }
        let Some(fold) = self.door.filter(|d| d.reg.section == self.section) else {
            return Ok(());
        };
        (fold.reg.validate)(&dealt(
            self.section,
            settings_of(self.section, &self.value)?,
        )?)
    }

    fn ledger_lanes(&self) -> Vec<String> {
        let Some(decl) = crate::plane_driver::registry::plane_decl_for_config_section(self.section)
            .filter(|d| is_door(d))
        else {
            return Vec::new();
        };
        let priced = (decl.billable_classes.iter()).any(|c| !decl.fee_units.contains(&c.class));
        let Some(kind) = decl.scope_kinds.first().filter(|_| priced) else {
            return Vec::new();
        };
        let sep = crate::governance::PLANE_LANE_SEP;
        self.registrations()
            .filter(|(name, _)| *name != busbar_contract::section::RESERVED_POOLS_KEY)
            .map(|(name, _)| format!("{}{sep}{kind}:{name}", decl.key))
            .collect()
    }

    fn model_provider_refs(&self) -> Vec<(String, String)> {
        use busbar_contract::section::{MODEL_PROVIDER_KEY, RESERVED_MODELS_KEY};
        self.value
            .get(RESERVED_MODELS_KEY)
            .and_then(serde_yaml::Value::as_mapping)
            .into_iter()
            .flat_map(|m| m.iter())
            .filter_map(|(name, entry)| {
                let provider = entry.get(MODEL_PROVIDER_KEY)?.as_str()?;
                Some((
                    format!(
                        "{}.{RESERVED_MODELS_KEY}.{}.{MODEL_PROVIDER_KEY}",
                        self.section,
                        name.as_str()?
                    ),
                    provider.to_string(),
                ))
            })
            .collect()
    }

    fn known_dialects(&self) -> Option<&'static [&'static str]> {
        let connections = busbar_contract::plugin::Kind::Transport.root();
        self.door
            .filter(|d| d.reg.section == self.section)
            .filter(|d| d.reg.consumes.contains(&connections))
            .map(|d| d.dialects)
    }

    fn is_present(&self) -> bool {
        match &self.value {
            serde_yaml::Value::Null => false,
            serde_yaml::Value::Mapping(m) => !m.is_empty(),
            _ => true,
        }
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

fn collect_refs(
    value: &serde_yaml::Value,
    segments: &[&str],
    at: String,
    out: &mut Vec<(String, busbar_contract::secret_ref::SecretRef)>,
) {
    let Some((head, rest)) = segments.split_first() else {
        if value.is_mapping() {
            if let Ok(r) =
                serde_yaml::from_value::<busbar_contract::secret_ref::SecretRef>(value.clone())
            {
                out.push((at, r));
            }
        }
        return;
    };
    if let (Some(items), true) = (value.as_sequence(), *head == "*") {
        for (i, v) in items.iter().enumerate() {
            collect_refs(v, rest, format!("{at}.{i}"), out);
        }
        return;
    }
    let Some(map) = value.as_mapping() else {
        return;
    };
    if *head == "*" {
        for (k, v) in map {
            if let Some(k) = k.as_str() {
                collect_refs(v, rest, format!("{at}.{k}"), out);
            }
        }
    } else if let Some(v) = map.get(*head) {
        collect_refs(v, rest, format!("{at}.{head}"), out);
    }
}

fn dealt(section: &str, settings: Vec<u8>) -> Result<Vec<u8>, String> {
    if settings.is_empty() {
        return Ok(settings);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&settings).map_err(|e| format!("the section is not JSON: {e}"))?;

    let value = crate::config_validate::deal::strip(section, value, &mut Vec::new());
    serde_json::to_vec(&serde_json::json!({ section: value })).map_err(|e| e.to_string())
}

fn settings_of(key: &str, value: &serde_yaml::Value) -> Result<Vec<u8>, String> {
    crate::config::filled::plane_bound_bytes(&[key], value)
}

fn view_of(
    name: &str,
    entry: &serde_yaml::Value,
    keys: &[TrustKeyDecl],
) -> crate::api::NamedDefView {
    let map = entry.as_mapping();
    let field = |key: &str| map.and_then(|m| m.get(key)).filter(|v| !v.is_null());
    let pin = keys.iter().find(|k| k.role == TrustRole::Pin);
    let ttl = keys.iter().find(|k| k.role == TrustRole::ReverifyTtl);
    let pin_obj = pin
        .and_then(|k| field(k.key))
        .and_then(serde_yaml::Value::as_mapping);
    crate::api::NamedDefView {
        name: name.to_string(),
        module: String::new(),
        settings_keys: Vec::new(),
        max_admin_scope: None,
        token_configured: None,
        browser_login_configured: None,
        pin_mechanism: pin.map(|_| {
            pin_obj
                .and_then(|m| m.get("mechanism"))
                .and_then(serde_yaml::Value::as_str)
                .unwrap_or_default()
                .to_string()
        }),
        fingerprint_pinned: pin.map(|_| {
            pin_obj
                .and_then(|m| m.get("fingerprint"))
                .is_some_and(|v| !v.is_null())
        }),
        reverify_ttl: ttl.map(|k| {
            field(k.key)
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_string)
                .or_else(|| k.default.map(str::to_string))
                .unwrap_or_default()
        }),
        unparseable: None,
    }
}

fn wire_formats(decl: &PlaneDecl) -> &'static [&'static str] {
    row(decl).map_or(&[], |d| d.dialects)
}

fn provider_dialects(decl: &PlaneDecl) -> &'static [&'static str] {
    row(decl).map_or(&[], |d| d.provider_dialects)
}

/// A door plane's runtime slot for one generation: its section, and what its `open` faces the world
/// with over that section and the deployment's public base URL.
#[derive(Debug, Clone)]
pub struct DoorSlot {
    /// The section, as written.
    pub section: DoorSection,
    /// Its claims (mounted by their literal prefix) and its audience.
    pub facing: busbar_contract::plane_calls::DoorFacing,
    /// Whether the door's open for this generation answered: `false` when it refused, its refusal
    /// logged and `facing` the empty default. `/healthz` on a deployment with no model lanes reads
    /// it ([`opened`]).
    pub opened: bool,
}

#[must_use]
pub fn opened(slot: &dyn std::any::Any) -> bool {
    slot.downcast_ref::<DoorSlot>().is_none_or(|s| s.opened)
}

fn build(
    decl: &PlaneDecl,
    ctx: &BuildCtx,
) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    let d = row(decl)?;
    let mine = |s: &DoorSection| s.section == d.reg.section && s.is_present();
    let section = match ctx
        .plane_defs
        .get(d.reg.section)
        .and_then(|defs| defs.as_any().downcast_ref::<DoorSection>())
        .filter(|s| mine(s))
    {
        Some(s) => s.clone(),

        None if ctx
            .endpoint_slot
            .as_deref()
            .and_then(|slot| slot.downcast_ref::<DoorOwned>())
            .is_some_and(crate::config::plane_sections::PlaneEndpointCfg::is_present) =>
        {
            DoorSection::new(Some(d), d.reg.section, serde_yaml::Value::Null)
        }
        None => {
            let raw = ctx.endpoint_slot.as_deref()?;
            let (section, value) = raw.downcast_ref::<(&'static str, serde_yaml::Value)>()?;
            let s = DoorSection::new(Some(d), section, value.clone());
            if !mine(&s) {
                return None;
            }
            s
        }
    };

    let section = DoorSection {
        door: Some(d),
        ..section
    };

    let owned = ctx
        .endpoint_slot
        .as_deref()
        .and_then(|slot| slot.downcast_ref::<DoorOwned>())
        .map(DoorOwned::bytes)
        .unwrap_or_default();

    let dialects = busbar_contract::plane_calls::dialect_facts(&section.value, |name| {
        ctx.providers?.get(name).map(|p| {
            (
                p.dialect().to_string(),
                p.error_map()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        })
    });
    let (facing, opened) = match settings_of(section.section, &section.value)
        .and_then(|bytes| (d.reg.facing)(&bytes, &owned, ctx.public_url, &dialects))
    {
        Ok(f) => (f, true),
        Err(refusal) => {
            tracing::error!(plane = d.reg.key, "{refusal}");
            (busbar_contract::plane_calls::DoorFacing::default(), false)
        }
    };
    Some(std::sync::Arc::new(DoorSlot {
        section,
        facing,
        opened,
    }))
}

fn mount_of(target: &str) -> String {
    let literal = target.split("/{").next().unwrap_or(target);
    literal.trim_end_matches('/').to_string()
}

fn claims(slot: &dyn std::any::Any) -> Vec<(String, &'static str)> {
    let Some(s) = slot.downcast_ref::<DoorSlot>() else {
        return Vec::new();
    };
    let mut out: Vec<(String, &'static str)> = Vec::new();
    for (target, dialect) in &s.facing.claims {
        let path = mount_of(target);
        if !path.is_empty() && !out.iter().any(|(p, _)| *p == path) {
            out.push((path, dialect));
        }
    }
    out
}

fn admission(slot: &dyn std::any::Any) -> Option<crate::plane_driver::dispatch::PlaneAdmission> {
    let (audience, resource_metadata) =
        slot.downcast_ref::<DoorSlot>()?.facing.admission.clone()?;
    Some(crate::plane_driver::dispatch::PlaneAdmission {
        audience,
        resource_metadata,
    })
}

pub fn listed<'a>(
    slots: &'a std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,
    key: Option<&busbar_contract::records::VirtualKey>,
) -> Vec<&'a str> {
    let registered = crate::plane_driver::registry::plane_decls();
    let mut doors: Vec<(&'static str, &'a DoorSlot)> = slots
        .iter()
        .filter_map(|(k, s)| s.downcast_ref::<DoorSlot>().map(|slot| (*k, slot)))
        .collect();

    doors.sort_by_key(|(k, _)| {
        registered
            .iter()
            .position(|d| d.key == *k)
            .unwrap_or(usize::MAX)
    });
    let mut out = Vec::new();
    for (_, slot) in doors {
        let Some(door) = slot.section.door else {
            continue;
        };
        let kind = door.reg.scope_kinds.first();
        out.extend(
            slot.facing
                .listed
                .iter()
                .map(String::as_str)
                .filter(|name| match (key, kind) {
                    (Some(key), Some(kind)) => key.scope_allowed(kind, name),
                    _ => true,
                }),
        );
    }
    out
}

fn slot_of(
    decl: &PlaneDecl,
    slots: &dyn crate::plane_driver::slots::PlaneSlots,
) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    slots.plane_slot(row(decl)?.reg.key).cloned()
}

fn named_def_list(
    decl: &PlaneDecl,
    slots: &dyn crate::plane_driver::slots::PlaneSlots,
) -> Vec<crate::api::NamedDefView> {
    let (Some(d), Some(slot)) = (row(decl), slot_of(decl, slots)) else {
        return Vec::new();
    };
    let Some(s) = slot.downcast_ref::<DoorSlot>() else {
        return Vec::new();
    };
    let views = s
        .section
        .registrations()
        .map(|(n, v)| view_of(n, v, &d.reg.trust_keys))
        .collect();
    views
}

fn named_def_get(
    decl: &PlaneDecl,
    slots: &dyn crate::plane_driver::slots::PlaneSlots,
    name: &str,
) -> Option<crate::api::NamedDefView> {
    let d = row(decl)?;
    let slot = slot_of(decl, slots)?;
    let s = slot.downcast_ref::<DoorSlot>()?;
    let view = s
        .section
        .registrations()
        .find(|(n, _)| *n == name)
        .map(|(n, v)| view_of(n, v, &d.reg.trust_keys));
    view
}

fn registry_contains(
    decl: &PlaneDecl,
    slots: &dyn crate::plane_driver::slots::PlaneSlots,
    name: &str,
) -> bool {
    let Some(slot) = slot_of(decl, slots) else {
        return false;
    };
    slot.downcast_ref::<DoorSlot>()
        .is_some_and(|s| s.section.contains_def(name))
}

fn reresolve_gates(decl: &PlaneDecl, next: &mut dyn crate::plane_driver::slots::ContainerGateSink) {
    let Some(d) = row(decl) else {
        return;
    };
    let section = next
        .plane_slot(d.reg.key)
        .and_then(|slot| slot.downcast_ref::<DoorSlot>().map(|s| s.section.clone()));
    let gates = section
        .map(|s| s.container_gates())
        .unwrap_or(ContainerGateInputs {
            section_hooks: Vec::new(),
            containers: Vec::new(),
        });
    let containers: Vec<(&str, &[String])> = gates
        .containers
        .iter()
        .map(|(n, h)| (n.as_str(), h.as_slice()))
        .collect();
    next.reresolve_container_gates(d.reg.key, &containers, &gates.section_hooks);
}

fn config_validate(decl: &PlaneDecl, name: &str, def: &serde_json::Value) -> Result<(), String> {
    let Some(d) = row(decl) else {
        return Ok(());
    };
    let section = d.reg.section;
    let one = serde_json::json!({ name: def });
    let bytes = serde_json::to_vec(&one).map_err(|e| e.to_string())?;
    (d.reg.validate)(&dealt(section, bytes)?).map_err(|e| {
        if e.starts_with(&format!("`{section}.{name}`")) {
            e
        } else {
            format!("invalid `{section}.{name}` definition: {e}")
        }
    })
}

/// A DOOR PLANE'S OWNED SECTION beside its verb (its endpoint block), as written: the door reads it
/// at its `open` (`PlaneOpenIn::owned`) and judges it there, in its own words; the kernel carries it.
#[derive(Debug, Clone)]
pub struct DoorOwned {
    /// The owned section's key.
    pub section: &'static str,
    /// The section as written.
    pub value: serde_yaml::Value,
}

impl DoorOwned {
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        if self.value.is_null() {
            return Vec::new();
        }
        serde_json::to_value(&self.value)
            .ok()
            .map(|v| crate::config::filled::plane_bound(&[self.section], v))
            .and_then(|v| serde_json::to_vec(&serde_json::json!({ self.section: v })).ok())
            .unwrap_or_default()
    }
}

impl crate::config::plane_sections::PlaneEndpointCfg for DoorOwned {
    fn is_present(&self) -> bool {
        match &self.value {
            serde_yaml::Value::Null => false,
            serde_yaml::Value::Mapping(m) => !m.is_empty(),
            _ => true,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn parse_endpoint(
    decl: &PlaneDecl,
    value: &serde_yaml::Value,
) -> Result<Box<dyn crate::config::plane_sections::PlaneEndpointCfg>, String> {
    let section = row(decl)
        .and_then(|d| d.reg.owns.first().copied())
        .unwrap_or("");
    Ok(Box::new(DoorOwned {
        section,
        value: value.clone(),
    }))
}

fn lower_endpoint(
    endpoint: &dyn crate::config::plane_sections::PlaneEndpointCfg,
) -> Result<std::sync::Arc<dyn std::any::Any + Send + Sync>, String> {
    endpoint
        .as_any()
        .downcast_ref::<DoorOwned>()
        .map(|o| std::sync::Arc::new(o.clone()) as std::sync::Arc<dyn std::any::Any + Send + Sync>)
        .ok_or_else(|| "a door plane's endpoint block was not carried as written".to_string())
}

fn parse_section(decl: &PlaneDecl, value: &serde_yaml::Value) -> Result<Box<dyn PlaneCfg>, String> {
    let Some(d) = row(decl) else {
        return Err("a door plane's section was parsed before its door was folded".to_string());
    };
    (d.reg.validate)(&dealt(d.reg.section, settings_of(d.reg.section, value)?)?)?;
    Ok(Box::new(DoorSection::new(
        Some(d),
        d.reg.section,
        value.clone(),
    )))
}

fn default_section(decl: &PlaneDecl) -> Box<dyn PlaneCfg> {
    Box::new(DoorSection::new(
        row(decl),
        row(decl).map_or("", |d| d.reg.section),
        serde_yaml::Value::Null,
    ))
}

fn admin_routes(
    decl: &PlaneDecl,
    _slot: &dyn std::any::Any,
) -> Vec<crate::admin_verbs::AdminRouteSpec> {
    use crate::admin_verbs::{AdminRouteSpec, AdminScope, AdminVerbKind};
    use busbar_contract::abi::mechanism::route::RouteMethod;
    let Some(d) = row(decl) else {
        return Vec::new();
    };
    d.reg
        .admin_routes
        .iter()
        .filter(|r| r.flags & busbar_contract::abi::plane::ROUTE_PUBLIC == 0)
        .filter_map(|r| {
            let method = [
                RouteMethod::Get,
                RouteMethod::Post,
                RouteMethod::Put,
                RouteMethod::Patch,
                RouteMethod::Delete,
            ]
            .into_iter()
            .find(|m| m.as_str().eq_ignore_ascii_case(r.verb))?;
            let scope = if method == RouteMethod::Get {
                AdminScope::ReadOnly
            } else {
                AdminScope::Full
            };
            let kind = if r.audit_verb.is_empty() {
                AdminVerbKind::Read
            } else {
                AdminVerbKind::Audited { verb: r.audit_verb }
            };
            let (verb, target) = (method.as_str(), r.target);
            Some(AdminRouteSpec {
                method,
                path: target.to_string(),
                scope,
                kind,
                handler: std::sync::Arc::new(move |ctx: crate::admin_verbs::AdminReqCtx| {
                    Box::pin(admin_reply(verb, target, ctx)) as crate::admin_verbs::AdminReplyFuture
                }),
            })
        })
        .collect()
}

const OPENAPI_COMPONENTS: &str = "components";

fn openapi_blob(decl: &PlaneDecl) -> serde_json::Map<String, serde_json::Value> {
    match row(decl)
        .and_then(|d| d.reg.admin_openapi)
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
    {
        Some(serde_json::Value::Object(blob)) => blob,
        _ => serde_json::Map::new(),
    }
}

fn openapi(decl: &PlaneDecl) -> serde_json::Value {
    serde_json::Value::Object(
        openapi_blob(decl)
            .into_iter()
            .filter(|(rel, _)| rel != OPENAPI_COMPONENTS)
            .map(|(rel, item)| (format!("{}{rel}", crate::api::ADMIN_PREFIX), item))
            .collect(),
    )
}

#[allow(dead_code)]
pub(crate) fn stated_schemas(
    decl: &PlaneDecl,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    match openapi_blob(decl)
        .remove(OPENAPI_COMPONENTS)
        .and_then(|c| c.get("schemas").cloned())
    {
        Some(serde_json::Value::Object(schemas)) => Some(schemas),
        _ => None,
    }
}

fn filled(target: &str, name: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(name.len());
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    target
        .split('/')
        .map(|seg| {
            if seg.len() > 1 && seg.starts_with('{') && seg.ends_with('}') {
                encoded.as_str()
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

async fn admin_reply(
    verb: &'static str,
    target: &'static str,
    ctx: crate::admin_verbs::AdminReqCtx,
) -> crate::admin_verbs::AdminReply {
    use crate::admin_verbs::{AdminReply, PlaneVerbError};
    let path = filled(target, &ctx.name);

    let req = crate::plane_driver::serve::AdminServe {
        method: verb,
        path: &path,
        query: ctx.query.as_deref(),
        headers: &ctx.headers,
        consumed: ctx.consumed.as_ref(),
        principal: ctx.principal.as_ref(),
    };
    match ctx.serve.served_at(req, ctx.body).await {
        None => AdminReply::Refused(PlaneVerbError::NotFound),
        Some(Err(unserved)) => AdminReply::Rejected(PlaneVerbError::Internal(format!(
            "the plane did not serve `{verb} {path}`: {unserved:?}"
        ))),
        Some(Ok(served)) => {
            let text = String::from_utf8_lossy(&served.body).into_owned();
            let refused = match served.status {
                200..=299 => return AdminReply::Applied(text),
                404 => PlaneVerbError::NotFound,
                400 => match condition_of(&served.fields) {
                    Some(cond) => PlaneVerbError::ValidationOf(text, cond),
                    None => PlaneVerbError::Validation(text),
                },
                status => {
                    return AdminReply::Rejected(PlaneVerbError::Internal(format!(
                        "the plane answered `{verb} {path}` with status {status}"
                    )))
                }
            };
            if served.audit == busbar_contract::abi::plane::AUDIT_NONE {
                AdminReply::Refused(refused)
            } else {
                AdminReply::Rejected(refused)
            }
        }
    }
}

fn condition_of(
    fields: &crate::plane_driver::HeadFields,
) -> Option<crate::admin_verbs::PlaneAdminCond> {
    use crate::admin_verbs::PlaneAdminCond;
    use busbar_contract::plane::{
        ADMIN_CONDITION_FIELD, ADMIN_CONDITION_INVALID_CONFIG, ADMIN_CONDITION_MALFORMED_BODY,
    };
    let (_, value) = fields
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(ADMIN_CONDITION_FIELD.as_bytes()))?;
    match value.as_slice() {
        v if v == ADMIN_CONDITION_MALFORMED_BODY.as_bytes() => Some(PlaneAdminCond::MalformedBody),
        v if v == ADMIN_CONDITION_INVALID_CONFIG.as_bytes() => Some(PlaneAdminCond::InvalidConfig),
        _ => None,
    }
}

fn door_hooks(named: bool, owns: bool, admin: bool) -> PlaneHooks {
    PlaneHooks {
        wire_format_names: wire_formats,
        provider_dialects,
        claims,
        admission,
        build,
        routes: None,
        admin_routes: admin.then_some(admin_routes as _),
        openapi: admin.then_some(openapi as _),
        hydrate: None,
        start: None,
        config_validate: named.then_some(config_validate as _),
        named_def_list: named.then_some(named_def_list as _),
        named_def_get: named.then_some(named_def_get as _),
        registry_contains: named.then_some(registry_contains as _),
        reresolve_gates: Some(reresolve_gates),
        openapi_schemas: crate::plane_driver::registry::stated_schemas_hook().filter(|_| admin),
        on_swap: None,
        parse_section: Some(parse_section),
        parse_endpoint: owns.then_some(parse_endpoint as _),
        lower_endpoint: owns.then_some(lower_endpoint as _),
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: Some(default_section),
        resolve_provider: None,
    }
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
