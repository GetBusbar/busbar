// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver::door`'s off-path code: a door plane's fold (once per process), its section's
//! parse, judgement and projections (once per configuration or generation), its generation build
//! and route claims, and its admin verbs and OpenAPI fragment. The request path reads only what
//! this builds (the folded row and the generation's slot).

use busbar_contract::plane::{BillableClass, PlaneDeclaration, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::PlaneRegistration;
use busbar_contract::yaml::{MappingExt as _, ValueExt as _};

use crate::config::plane_sections::{ContainerGateInputs, PlaneCfg};
use crate::plane_driver::door::{
    admin_openapi, admission, is_door, provider_dialects, row, wire_formats, DoorSlot,
    OPENAPI_COMPONENTS,
};
use crate::plane_driver::registry::{BuildCtx, PlaneDecl, PlaneHooks};

pub struct DoorRow {
    pub(crate) reg: PlaneRegistration,

    pub(crate) provider_dialects: &'static [&'static str],
}

impl std::fmt::Debug for DoorRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorRow")
            .field("key", &self.reg.key)
            .field("section", &self.reg.section)
            .finish_non_exhaustive()
    }
}

pub fn fold(reg: PlaneRegistration) -> Result<&'static PlaneDecl, String> {
    if reg.key.is_empty() || reg.section.is_empty() {
        return Err(format!(
            "plane door `{}` states no name or no declaring section; a plane is installed by its \
             name and configured by its section",
            reg.key
        ));
    }
    let named = busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS.contains(&reg.section);
    let hooks = door_hooks(named, !reg.owns.is_empty(), !reg.admin_routes.is_empty());
    let provider_dialects: &'static [&'static str] = (reg.dialects.iter())
        .zip(&reg.dialect_flags)
        .filter(|(_, f)| *f & busbar_contract::abi::plane::DIALECT_PROVIDER != 0)
        .map(|(d, _)| *d)
        .collect::<Vec<_>>()
        .leak();
    let door: &'static DoorRow = Box::leak(Box::new(DoorRow {
        reg,
        provider_dialects,
    }));
    let mut decl = PlaneDecl::assemble(declaration_of(&door.reg), hooks);
    decl.door = Some(door);
    Ok(Box::leak(Box::new(decl)))
}

pub(crate) fn declaration_of(reg: &'static PlaneRegistration) -> PlaneDeclaration {
    PlaneDeclaration {
        key: reg.key,
        fallback: reg.fallback,
        config_section: reg.section,
        scope_kinds: reg.scope_kinds.as_slice(),
        subject_noun: reg.subject_noun,
        admin_noun: reg.admin_noun,
        audit_kind: reg.audit_kind,
        card_signing_domain: reg.signing.map(|(d, _)| d),
        card_kid_prefix: reg.signing.map(|(_, p)| p),
        owned_config_sections: reg.owns.as_slice(),
        billable_classes: billable_classes_of(reg),
        class_parents: reg.class_parents.as_slice(),
        fee_units: reg.fee_units.as_slice(),
        metric_families: &[],
        record_kinds: reg.record_kinds.as_slice(),
        required_config_sections: reg.requires.as_slice(),
        trust_keys: reg.trust_keys.as_slice(),
        caller_credential_refusal: reg.caller_credential_refusal,
        served_op_classes: &[],
    }
}

pub(crate) fn billable_classes_of(reg: &PlaneRegistration) -> &'static [BillableClass] {
    reg.billable_classes
        .iter()
        .map(|&(class, family)| BillableClass { class, family })
        .collect::<Vec<_>>()
        .leak()
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
    let judged = serde_json::to_vec(&OneEntry("providers", &OneEntry(name, table)))
        .map_err(|e| e.to_string())
        .and_then(|bytes| (door.reg.validate)(&bytes));
    Some(judged)
}

/// A DOOR PLANE'S SECTION, as written: the door judged it (`validate`) and is handed it raw; the
/// kernel reads only the words it owns (the registrations' names, their trust keys and `hooks:`
/// lists, and the reserved section words). Also the plane's per-generation runtime slot, which the
/// named-map reads project.
#[derive(Debug, Clone)]
pub struct DoorSection {
    /// The door that declares the section (the row it was parsed through), whose registration names
    /// the section's secret paths and judges it whole.
    pub(crate) door: Option<&'static DoorRow>,
    /// The section's key.
    pub section: &'static str,
    /// The section as written (`Null` when absent).
    pub value: busbar_contract::yaml::Value,
    /// The secret references the section holds at its door's declared paths
    /// (`PlaneRegistration::secret_refs`), each with the config path it was read at.
    pub(crate) refs: Vec<(String, busbar_contract::secret_ref::SecretRef)>,
    /// The refusal for the first secret reference the section holds at a position its door did
    /// NOT declare, if any.
    pub(crate) undeclared: Option<String>,
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
        value: busbar_contract::yaml::Value,
    ) -> Self {
        let declaring = door.filter(|d| d.reg.section == section);
        let paths = declaring
            .map(|d| d.reg.secret_refs.as_slice())
            .unwrap_or_default();
        let mut refs = Vec::new();
        let mut at = String::with_capacity(64);
        for path in paths {
            let Some(rest) = path.strip_prefix("settings.") else {
                continue;
            };
            at.clear();
            at.push_str(section);
            collect_refs(&value, Some(rest), &mut at, &mut refs);
        }
        let declared: Vec<String> = paths
            .iter()
            .filter_map(|p| p.strip_prefix("settings.").map(str::to_string))
            .collect();
        let undeclared = undeclared_in(
            &value,
            section,
            declaring.map_or(section, |d| d.reg.key),
            &declared,
            &crate::config::secret::admitted_sugars(),
        );
        Self {
            door,
            section,
            value,
            refs,
            undeclared,
        }
    }

    pub(crate) fn registrations(
        &self,
    ) -> impl Iterator<Item = (&str, &busbar_contract::yaml::Value)> {
        crate::trust::section::registrations(&self.value)
    }

    pub(crate) fn ledger_lanes_for(&self, decl: &PlaneDeclaration) -> Vec<String> {
        use busbar_contract::section::{RESERVED_MODELS_KEY, RESERVED_POOLS_KEY};

        if !decl
            .billable_classes
            .iter()
            .any(|c| !decl.fee_units.contains(&c.class))
        {
            return Vec::new();
        }
        let sep = crate::governance::PLANE_LANE_SEP;

        if let Some(models) = self
            .value
            .get(RESERVED_MODELS_KEY)
            .and_then(busbar_contract::yaml::Value::as_mapping)
        {
            return models
                .keys()
                .filter_map(busbar_contract::yaml::Value::as_str)
                .map(|name| format!("{}{sep}{name}", decl.key))
                .collect();
        }
        let Some(kind) = decl.scope_kinds.first() else {
            return Vec::new();
        };
        self.registrations()
            .filter(|(name, _)| ![RESERVED_MODELS_KEY, RESERVED_POOLS_KEY].contains(name))
            .map(|(name, _)| format!("{}{sep}{kind}:{name}", decl.key))
            .collect()
    }

    pub(crate) fn hooks_of(v: &busbar_contract::yaml::Value) -> Vec<String> {
        v.as_mapping()
            .and_then(|m| m.get_key(busbar_contract::plugin::Kind::Hook.root()))
            .and_then(busbar_contract::yaml::Value::as_sequence)
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
        let entry: busbar_contract::yaml::Value = busbar_contract::yaml::to_value(def)
            .map_err(|e| format!("invalid `{}.{name}` definition: {e}", self.section))?;
        if !self.value.is_mapping() {
            self.value = busbar_contract::yaml::Value::Map(busbar_contract::yaml::Pairs::new());
        }
        if let Some(m) = self.value.as_mapping_mut() {
            m.insert_key(busbar_contract::yaml::Value::Text(name.to_string()), entry);
        }

        *self = Self::new(
            self.door,
            self.section,
            std::mem::replace(&mut self.value, busbar_contract::yaml::Value::Null),
        );
        Ok(())
    }

    fn container_gates(&self) -> ContainerGateInputs {
        let containers = self
            .registrations()
            .map(|(n, v)| (n.to_string(), Self::hooks_of(v)))
            .collect();
        ContainerGateInputs {
            section_hooks: Self::hooks_of(&self.value),
            containers,
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
        self.ledger_lanes_for(&decl.declaration)
    }

    fn model_provider_refs(&self) -> Vec<(String, String)> {
        use busbar_contract::section::{MODEL_PROVIDER_KEY, RESERVED_MODELS_KEY};
        self.value
            .get(RESERVED_MODELS_KEY)
            .and_then(busbar_contract::yaml::Value::as_mapping)
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
            .map(|d| d.reg.dialects.as_slice())
    }

    fn is_present(&self) -> bool {
        yaml_present(&self.value)
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

/// The refusal for a secret reference a door section holds outside the paths its plane declared,
/// judged against `sugars` (the shorthand admission published), the same rule every other kind's
/// settings meet (`Settings::undeclared_reference`).
pub(crate) fn undeclared_in(
    value: &busbar_contract::yaml::Value,
    section: &str,
    owner: &str,
    declared: &[String],
    sugars: &busbar_contract::secret_ref::Sugars,
) -> Option<String> {
    let mut tree = serde_json::to_value(value).ok()?;
    if let Err(why) = busbar_contract::plugin_settings::canonicalize(&mut tree, sugars) {
        return Some(format!("{section}: {why}"));
    }
    busbar_contract::secret_fields::undeclared_reference(&tree, declared).map(|at| {
        busbar_contract::secret_fields::undeclared_refusal(&format!("{section}.{at}"), owner)
    })
}

pub(crate) fn collect_refs(
    value: &busbar_contract::yaml::Value,
    path: Option<&str>,
    at: &mut String,
    out: &mut Vec<(String, busbar_contract::secret_ref::SecretRef)>,
) {
    use std::fmt::Write as _;
    let Some(path) = path else {
        if value.is_mapping() {
            // Door section references are judged by the process-lifetime plane machinery: the
            // shorthand admission last published (SECRET-SHORTHAND-BOOT OQ3).
            if let Ok(r) = busbar_contract::secret_ref::context::deserialize::<
                busbar_contract::secret_ref::SecretRef,
                _,
            >(
                busbar_contract::yaml::deserializer(value.clone()),
                &crate::config::secret::admitted_sugars(),
            ) {
                out.push((at.clone(), r));
            }
        }
        return;
    };
    let (head, rest) = match path.split_once('.') {
        Some((head, rest)) => (head, Some(rest)),
        None => (path, None),
    };
    let base = at.len();
    if let (Some(items), true) = (value.as_sequence(), head == "*") {
        for (i, v) in items.iter().enumerate() {
            at.truncate(base);
            let _ = write!(at, ".{i}");
            collect_refs(v, rest, at, out);
        }
        at.truncate(base);
        return;
    }
    let Some(map) = value.as_mapping() else {
        return;
    };
    if head == "*" {
        for (k, v) in map {
            if let Some(k) = k.as_str() {
                at.truncate(base);
                at.push('.');
                at.push_str(k);
                collect_refs(v, rest, at, out);
            }
        }
        at.truncate(base);
    } else if let Some(v) = map.get_key(head) {
        at.push('.');
        at.push_str(head);
        collect_refs(v, rest, at, out);
        at.truncate(base);
    }
}

/// `{ key: value }`, serialized straight from the borrowed parts (no JSON tree is built for it).
pub(crate) struct OneEntry<'a, V: ?Sized>(pub(crate) &'a str, pub(crate) &'a V);

impl<V: serde::Serialize + ?Sized> serde::Serialize for OneEntry<'_, V> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(self.0, self.1)?;
        map.end()
    }
}

/// Write each admitted source shorthand at a door's declared secret path as its canonical
/// `{module, settings}` reference, so a plane is only ever handed canonical references and never
/// needs the host's source declarations to read its own section. `prefix` is where `value` sits in
/// the document: a door's own section (`[section]`), or the keyed blob of sections (`[]`).
pub(crate) fn canonical_sources(
    prefix: &[&str],
    value: &mut serde_json::Value,
    sources: &busbar_contract::secret_ref::Sugars,
) -> Result<(), String> {
    for door in crate::plane_driver::registry::plane_decls()
        .iter()
        .filter_map(|d| d.door)
    {
        let section = match prefix {
            [] => match value.get_mut(door.reg.section) {
                Some(section) => section,
                None => continue,
            },
            [only] if *only == door.reg.section => &mut *value,
            _ => continue,
        };
        for path in &door.reg.secret_refs {
            let Some(rest) = path.strip_prefix("settings.") else {
                continue;
            };
            let segments: Vec<&str> = rest.split('.').collect();
            canonical_at(section, &segments, sources)?;
        }
    }
    Ok(())
}

pub(crate) fn canonical_at(
    value: &mut serde_json::Value,
    segments: &[&str],
    sources: &busbar_contract::secret_ref::Sugars,
) -> Result<(), String> {
    let Some((head, rest)) = segments.split_first() else {
        let declared = value.as_object().is_some_and(|object| {
            object.len() == 1 && object.keys().all(|word| sources.get(word).is_some())
        });
        if declared {
            let reference: busbar_contract::secret_ref::SecretRef =
                busbar_contract::secret_ref::context::deserialize(value.clone(), sources).map_err(
                    |_| "invalid admitted source shorthand (value not echoed)".to_owned(),
                )?;
            *value = serde_json::to_value(reference.authoring(&crate::seal::acquire()))
                .map_err(|_| "cannot encode admitted source reference".to_owned())?;
        }
        return Ok(());
    };
    match value {
        serde_json::Value::Array(items) if *head == "*" => {
            for item in items {
                canonical_at(item, rest, sources)?;
            }
        }
        serde_json::Value::Object(map) if *head == "*" => {
            for item in map.values_mut() {
                canonical_at(item, rest, sources)?;
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(item) = map.get_mut(*head) {
                canonical_at(item, rest, sources)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn dealt(section: &str, settings: Vec<u8>) -> Result<Vec<u8>, String> {
    if settings.is_empty() {
        return Ok(settings);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&settings).map_err(|e| format!("the section is not JSON: {e}"))?;

    let value = crate::config_validate::deal::strip(section, value, &mut Vec::new());
    serde_json::to_vec(&OneEntry(section, &value)).map_err(|e| e.to_string())
}

pub(crate) fn settings_of(
    key: &str,
    value: &busbar_contract::yaml::Value,
) -> Result<Vec<u8>, String> {
    crate::config::filled::plane_bound_bytes(&[key], value)
}

pub(crate) fn view_of(
    name: &str,
    entry: &busbar_contract::yaml::Value,
    keys: &[TrustKeyDecl],
) -> crate::api::NamedDefView {
    let map = entry.as_mapping();
    let field = |key: &str| map.and_then(|m| m.get_key(key)).filter(|v| !v.is_null());
    let pin = keys.iter().find(|k| k.role == TrustRole::Pin);
    let ttl = keys.iter().find(|k| k.role == TrustRole::ReverifyTtl);
    let pin_obj = pin
        .and_then(|k| field(k.key))
        .and_then(busbar_contract::yaml::Value::as_mapping);
    crate::api::NamedDefView {
        name: name.to_string(),
        module: None,
        settings_keys: Vec::new(),
        max_admin_scope: None,
        token_configured: None,
        browser_login_configured: None,
        pin_mechanism: pin.map(|_| {
            pin_obj
                .and_then(|m| m.get_key("mechanism"))
                .and_then(busbar_contract::yaml::Value::as_str)
                .unwrap_or_default()
                .to_string()
        }),
        fingerprint_pinned: pin.map(|_| {
            pin_obj
                .and_then(|m| m.get_key("fingerprint"))
                .is_some_and(|v| !v.is_null())
        }),
        reverify_ttl: ttl.map(|k| {
            field(k.key)
                .and_then(busbar_contract::yaml::Value::as_str)
                .map(str::to_string)
                .or_else(|| k.default.map(str::to_string))
                .unwrap_or_default()
        }),
        unparseable: None,
    }
}

pub(crate) fn build(
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
            DoorSection::new(Some(d), d.reg.section, busbar_contract::yaml::Value::Null)
        }
        None => {
            let raw = ctx.endpoint_slot.as_deref()?;
            let (section, value) =
                raw.downcast_ref::<(&'static str, busbar_contract::yaml::Value)>()?;
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
        .unwrap_or_else(|| Ok(Vec::new()));

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
    let (facing, opened) = match settings_of(section.section, &section.value).and_then(|bytes| {
        owned.and_then(|owned| (d.reg.facing)(&bytes, &owned, ctx.public_url, &dialects))
    }) {
        Ok(f) => (f, true),
        Err(refusal) => {
            tracing::error!(plane = d.reg.key, "{refusal}");

            if let Some(prior) = ctx.prior.and_then(|prior| prior.plane_slot(decl.key)) {
                if prior.downcast_ref::<DoorSlot>().is_some_and(|prior| {
                    prior.opened
                        && prior.section.section == d.reg.section
                        && prior
                            .section
                            .door
                            .is_some_and(|door| door.reg.key == decl.key)
                }) {
                    return Some(std::sync::Arc::clone(prior));
                }
            }
            (busbar_contract::plane_calls::DoorFacing::default(), false)
        }
    };
    Some(std::sync::Arc::new(DoorSlot {
        section,
        facing,
        opened,
    }))
}

pub(crate) fn mount_of(target: &str) -> &str {
    let literal = target.split("/{").next().unwrap_or(target);
    literal.trim_end_matches('/')
}

pub(crate) fn claims(slot: &dyn std::any::Any) -> Vec<(String, &'static str)> {
    let Some(s) = slot.downcast_ref::<DoorSlot>() else {
        return Vec::new();
    };
    let mut out: Vec<(String, &'static str)> = Vec::new();
    for (target, dialect) in &s.facing.claims {
        let path = mount_of(target);
        if !path.is_empty() && !out.iter().any(|(p, _)| p == path) {
            out.push((path.to_string(), dialect));
        }
    }
    out
}

pub(crate) fn slot_of(
    decl: &PlaneDecl,
    slots: &dyn crate::plane_driver::slots::PlaneSlots,
) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    slots.plane_slot(row(decl)?.reg.key).cloned()
}

pub(crate) fn named_def_list(
    decl: &PlaneDecl,
    slots: &dyn crate::plane_driver::slots::PlaneSlots,
) -> Vec<crate::api::NamedDefView> {
    let (Some(d), Some(slot)) = (row(decl), slot_of(decl, slots)) else {
        return Vec::new();
    };
    let Some(s) = slot.downcast_ref::<DoorSlot>() else {
        return Vec::new();
    };
    s.section
        .registrations()
        .map(|(n, v)| view_of(n, v, &d.reg.trust_keys))
        .collect()
}

pub(crate) fn named_def_get(
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

pub(crate) fn registry_contains(
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

pub(crate) fn reresolve_gates(
    decl: &PlaneDecl,
    next: &mut dyn crate::plane_driver::slots::ContainerGateSink,
) {
    let Some(d) = row(decl) else {
        return;
    };
    let gates = next
        .plane_slot(d.reg.key)
        .and_then(|slot| slot.downcast_ref::<DoorSlot>())
        .map_or(
            ContainerGateInputs {
                section_hooks: Vec::new(),
                containers: Vec::new(),
            },
            |s| s.section.container_gates(),
        );
    let containers: Vec<(&str, &[String])> = gates
        .containers
        .iter()
        .map(|(n, h)| (n.as_str(), h.as_slice()))
        .collect();
    next.reresolve_container_gates(d.reg.key, &containers, &gates.section_hooks);
}

/// Whether `e` already names the definition, as `` `<section>.<name>` ``.
pub(crate) fn names_definition(e: &str, section: &str, name: &str) -> bool {
    e.strip_prefix('`')
        .and_then(|r| r.strip_prefix(section))
        .and_then(|r| r.strip_prefix('.'))
        .and_then(|r| r.strip_prefix(name))
        .is_some_and(|r| r.starts_with('`'))
}

pub(crate) fn config_validate(
    decl: &PlaneDecl,
    name: &str,
    def: &serde_json::Value,
) -> Result<(), String> {
    let Some(d) = row(decl) else {
        return Ok(());
    };
    let section = d.reg.section;
    let bytes = serde_json::to_vec(&OneEntry(name, def)).map_err(|e| e.to_string())?;
    (d.reg.validate)(&dealt(section, bytes)?).map_err(|e| {
        if names_definition(&e, section, name) {
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
    pub value: busbar_contract::yaml::Value,
}

impl DoorOwned {
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        if self.value.is_null() {
            return Ok(Vec::new());
        }
        let value = serde_json::to_value(&self.value)
            .map_err(|_| "owned plane configuration is not JSON")?;
        let value = crate::config::filled::plane_bound(&[self.section], value)?;
        serde_json::to_vec(&OneEntry(self.section, &value))
            .map_err(|_| "owned plane configuration cannot be encoded".to_owned())
    }
}

impl crate::config::plane_sections::PlaneEndpointCfg for DoorOwned {
    fn is_present(&self) -> bool {
        yaml_present(&self.value)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub(crate) fn parse_endpoint(
    decl: &PlaneDecl,
    value: &busbar_contract::yaml::Value,
) -> Result<Box<dyn crate::config::plane_sections::PlaneEndpointCfg>, String> {
    let section = row(decl)
        .and_then(|d| d.reg.owns.first().copied())
        .unwrap_or("");
    let owned = DoorOwned {
        section,
        value: value.clone(),
    };
    Ok(Box::new(owned))
}

pub(crate) fn lower_endpoint(
    endpoint: &dyn crate::config::plane_sections::PlaneEndpointCfg,
) -> Result<std::sync::Arc<dyn std::any::Any + Send + Sync>, String> {
    endpoint
        .as_any()
        .downcast_ref::<DoorOwned>()
        .map(|o| std::sync::Arc::new(o.clone()) as std::sync::Arc<dyn std::any::Any + Send + Sync>)
        .ok_or_else(|| "a door plane's endpoint block was not carried as written".to_string())
}

pub(crate) fn parse_section(
    decl: &PlaneDecl,
    value: &busbar_contract::yaml::Value,
) -> Result<Box<dyn PlaneCfg>, String> {
    let Some(d) = row(decl) else {
        return Err("a door plane's section was parsed before its door was folded".to_string());
    };
    (d.reg.validate)(&dealt(d.reg.section, settings_of(d.reg.section, value)?)?)?;
    let section = DoorSection::new(Some(d), d.reg.section, value.clone());
    Ok(Box::new(section))
}

pub(crate) fn default_section(decl: &PlaneDecl) -> Box<dyn PlaneCfg> {
    Box::new(DoorSection::new(
        row(decl),
        row(decl).map_or("", |d| d.reg.section),
        busbar_contract::yaml::Value::Null,
    ))
}

pub(crate) fn admin_routes(
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

pub(crate) fn openapi(decl: &PlaneDecl) -> serde_json::Value {
    match admin_openapi(decl).and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok()) {
        Some(serde_json::Value::Object(blob)) => serde_json::Value::Object(
            blob.into_iter()
                .filter(|(rel, _)| rel != OPENAPI_COMPONENTS)
                .map(|(rel, item)| (format!("{}{rel}", crate::api::ADMIN_PREFIX), item))
                .collect(),
        ),
        _ => serde_json::Value::Object(serde_json::Map::new()),
    }
}

pub(crate) fn filled(target: &str, name: &str) -> String {
    let mut path = String::with_capacity(target.len() + 3 * name.len());
    for (i, seg) in target.split('/').enumerate() {
        if i > 0 {
            path.push('/');
        }
        if seg.len() > 1 && seg.starts_with('{') && seg.ends_with('}') {
            busbar_contract::net::push_percent_encoded(&mut path, name);
        } else {
            path.push_str(seg);
        }
    }
    path
}

pub(crate) async fn admin_reply(
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
        trust_authority: ctx.trust_authority.as_ref(),
    };
    let served = match ctx.serve.served_at(req, ctx.body).await {
        None => return AdminReply::Refused(PlaneVerbError::NotFound),
        Some(Err(unserved)) => {
            let refusal = format!("the plane did not serve `{verb} {path}`: {unserved:?}");
            return AdminReply::Rejected(PlaneVerbError::Internal(refusal));
        }
        Some(Ok(served)) => served,
    };
    let text = match String::from_utf8(served.body) {
        Ok(text) => text,
        Err(bytes) => String::from_utf8_lossy(bytes.as_bytes()).into_owned(),
    };
    if (200..=299).contains(&served.status) {
        return AdminReply::Applied(text);
    }
    let refused = admin_plane_error(served.status, text, &served.fields);
    if matches!(&refused, PlaneVerbError::Internal(_)) {
        return AdminReply::Rejected(refused);
    }
    if served.audit == busbar_contract::abi::plane::AUDIT_NONE {
        AdminReply::Refused(refused)
    } else {
        AdminReply::Rejected(refused)
    }
}

pub(crate) fn admin_plane_error(
    status: u32,
    text: String,
    fields: &crate::plane_driver::HeadFields,
) -> crate::admin_verbs::PlaneVerbError {
    use crate::admin_verbs::PlaneVerbError;
    match status {
        404 => PlaneVerbError::NotFound,
        503 => PlaneVerbError::Unavailable,
        400 => match condition_of(fields) {
            Some(cond) => PlaneVerbError::ValidationOf(text, cond),
            None => PlaneVerbError::Validation(text),
        },
        status => {
            let refusal = format!("the plane answered with status {status}");
            PlaneVerbError::Internal(refusal)
        }
    }
}

pub(crate) fn condition_of(
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

pub(crate) fn door_hooks(named: bool, owns: bool, admin: bool) -> PlaneHooks {
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

pub(crate) fn yaml_present(value: &busbar_contract::yaml::Value) -> bool {
    match value {
        busbar_contract::yaml::Value::Null => false,
        busbar_contract::yaml::Value::Map(m) => !m.is_empty(),
        _ => true,
    }
}
