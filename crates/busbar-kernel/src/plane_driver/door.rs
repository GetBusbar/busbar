// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::plane::{BillableClass, PlaneDeclaration, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::PlaneRegistration;

use crate::config::plane_sections::{ContainerGateInputs, PlaneCfg};
use crate::plane_driver::registry::{BuildCtx, PlaneDecl, PlaneHooks};

pub struct DoorRow {
    reg: PlaneRegistration,

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
        #[expect(
            clippy::disallowed_methods,
            reason = "error: a door with no name or section is refused once, at fold"
        )]
        return Err(format!(
            "plane door `{}` states no name or no declaring section; a plane is installed by its \
             name and configured by its section",
            reg.key
        ));
    }
    let named = busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS.contains(&reg.section);
    let hooks = door_hooks(named, !reg.owns.is_empty(), !reg.admin_routes.is_empty());
    #[expect(
        clippy::disallowed_methods,
        reason = "boot: a door's provider dialects are filtered once, at fold, and leaked for the process"
    )]
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

fn declaration_of(reg: &'static PlaneRegistration) -> PlaneDeclaration {
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

fn billable_classes_of(reg: &PlaneRegistration) -> &'static [BillableClass] {
    #[expect(
        clippy::disallowed_methods,
        reason = "boot: a door's billable classes are lowered once, at fold, and leaked for the process"
    )]
    let classes = reg
        .billable_classes
        .iter()
        .map(|&(class, family)| BillableClass { class, family })
        .collect::<Vec<_>>()
        .leak();
    classes
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
    #[expect(
        clippy::disallowed_types,
        reason = "config: a provider's protocol is read from its parsed config table"
    )]
    let dialect = table
        .get(busbar_contract::section::MODEL_PROTOCOL_KEYS[0])
        .and_then(serde_json::Value::as_str)?;
    let door = (crate::plane_driver::registry::plane_decls().iter())
        .filter_map(|d| d.door)
        .find(|d| d.provider_dialects.contains(&dialect))?;
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a provider entry is encoded once, for its door's validate"
    )]
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
    door: Option<&'static DoorRow>,
    /// The section's key.
    pub section: &'static str,
    /// The section as written (`Null` when absent).
    pub value: serde_yaml::Value,
    /// The secret references the section holds at its door's declared paths
    /// (`PlaneRegistration::secret_refs`), each with the config path it was read at.
    refs: Vec<(String, busbar_contract::secret_ref::SecretRef)>,
    /// The refusal for the first secret reference the section holds at a position its door did
    /// NOT declare, if any.
    undeclared: Option<String>,
}

impl DoorSection {
    #[must_use]
    pub fn as_defs(
        &self,
    ) -> std::collections::BTreeMap<&'static str, Box<dyn crate::config::plane_sections::PlaneCfg>>
    {
        // busbar:expect(bp::into_alloc, reason = "config: the section's one-entry definitions map is built per generation")
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
        // busbar:expect(bp::fresh_buffer, reason = "config: the section's secret references are read once per parse and kept on it")
        let mut refs = Vec::new();
        // busbar:expect(bp::fresh_buffer, reason = "config: one path buffer serves every secret-reference walk of the parse")
        let mut at = String::with_capacity(64);
        for path in paths {
            let Some(rest) = path.strip_prefix("settings.") else {
                continue;
            };
            at.clear();
            at.push_str(section);
            collect_refs(&value, Some(rest), &mut at, &mut refs);
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the declared secret paths are lowered once per parse for the contract's check"
        )]
        let declared: Vec<String> = paths
            .iter()
            .filter_map(|p| p.strip_prefix("settings.").map(str::to_string))
            .collect();
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the section is judged for undeclared secret references once per parse"
        )]
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

    fn ledger_lanes_for(&self, decl: &PlaneDeclaration) -> Vec<String> {
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
            .and_then(serde_yaml::Value::as_mapping)
        {
            #[expect(
                clippy::disallowed_methods,
                reason = "config: a section's ledger lane names are composed once per generation"
            )]
            let lanes = models
                .keys()
                .filter_map(serde_yaml::Value::as_str)
                .map(|name| format!("{}{sep}{name}", decl.key))
                .collect();
            return lanes;
        }
        let Some(kind) = decl.scope_kinds.first() else {
            return Vec::new();
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a section's ledger lane names are composed once per generation"
        )]
        let lanes = self
            .registrations()
            .filter(|(name, _)| ![RESERVED_MODELS_KEY, RESERVED_POOLS_KEY].contains(name))
            .map(|(name, _)| format!("{}{sep}{kind}:{name}", decl.key))
            .collect();
        lanes
    }

    fn hooks_of(v: &serde_yaml::Value) -> Vec<String> {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a container's `hooks:` list is read once per generation"
        )]
        let hooks = v
            .as_mapping()
            .and_then(|m| m.get(busbar_contract::plugin::Kind::Hook.root()))
            .and_then(serde_yaml::Value::as_sequence)
            .map(|s| {
                s.iter()
                    .filter_map(|h| h.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        hooks
    }
}

impl PlaneCfg for DoorSection {
    fn secret_refs(&self) -> Vec<(String, &busbar_contract::secret_ref::SecretRef)> {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the section's secret references are listed for the generation's secret resolve"
        )]
        let refs = self.refs.iter().map(|(at, r)| (at.clone(), r)).collect();
        refs
    }

    fn undeclared_secret_ref(&self) -> Option<String> {
        // busbar:expect(bp::clone_alloc, reason = "config: the undeclared-reference refusal is handed to the config load")
        self.undeclared.clone()
    }

    fn contains_def(&self, name: &str) -> bool {
        self.registrations().any(|(n, _)| n == name)
    }

    fn def_names(&self) -> Vec<&str> {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the section's definition names are listed for the config load"
        )]
        let names = self.registrations().map(|(n, _)| n).collect();
        names
    }

    fn entry_document(&self, name: &str) -> Option<serde_json::Value> {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: one definition is projected for the admin named-map read"
        )]
        let document = self
            .registrations()
            .find(|(n, _)| *n == name)
            .and_then(|(_, v)| serde_json::to_value(v).ok());
        document
    }

    fn insert_def(&mut self, name: &str, def: &serde_json::Value) -> Result<(), String> {
        #[expect(
            clippy::disallowed_methods,
            reason = "error: an unrepresentable definition is refused once, at the admin write"
        )]
        let entry: serde_yaml::Value = serde_yaml::to_value(def)
            .map_err(|e| format!("invalid `{}.{name}` definition: {e}", self.section))?;
        if !self.value.is_mapping() {
            self.value = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        }
        if let Some(m) = self.value.as_mapping_mut() {
            #[expect(
                clippy::disallowed_methods,
                reason = "config: the admin write stores the definition under its own name"
            )]
            m.insert(serde_yaml::Value::String(name.to_string()), entry);
        }

        *self = Self::new(self.door, self.section, std::mem::take(&mut self.value));
        Ok(())
    }

    fn container_gates(&self) -> ContainerGateInputs {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the section's container gates are read once per generation"
        )]
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
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the section's model provider references are listed once per config load"
        )]
        let refs = self
            .value
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
            .collect();
        refs
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

fn collect_refs(
    value: &serde_yaml::Value,
    path: Option<&str>,
    at: &mut String,
    out: &mut Vec<(String, busbar_contract::secret_ref::SecretRef)>,
) {
    use std::fmt::Write as _;
    let Some(path) = path else {
        if value.is_mapping() {
            if let Ok(r) = busbar_contract::secret_ref::context::deserialize::<
                busbar_contract::secret_ref::SecretRef,
                _,
            >(value, &crate::config::secret::sugars())
            {
                // busbar:expect(bp::clone_alloc, reason = "config: each found secret reference keeps the path it was read at")
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
    } else if let Some(v) = map.get(head) {
        at.push('.');
        at.push_str(head);
        collect_refs(v, rest, at, out);
        at.truncate(base);
    }
}

/// `{ key: value }`, serialized straight from the borrowed parts (no JSON tree is built for it).
struct OneEntry<'a, V: ?Sized>(&'a str, &'a V);

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

fn canonical_at(
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

fn dealt(section: &str, settings: Vec<u8>) -> Result<Vec<u8>, String> {
    if settings.is_empty() {
        return Ok(settings);
    }
    #[expect(
        clippy::disallowed_types,
        clippy::disallowed_methods,
        reason = "config: the section is parsed once per judgement for the reserved-word strip"
    )]
    let value: serde_json::Value =
        serde_json::from_slice(&settings).map_err(|e| format!("the section is not JSON: {e}"))?;

    let value = crate::config_validate::deal::strip(section, value, &mut Vec::new());
    #[expect(
        clippy::disallowed_methods,
        reason = "config: the stripped section is encoded once per judgement for the door's validate"
    )]
    let dealt = serde_json::to_vec(&OneEntry(section, &value)).map_err(|e| e.to_string());
    dealt
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
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a named definition is projected for the admin read"
    )]
    let view = crate::api::NamedDefView {
        name: name.to_string(),
        module: None,
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
    };
    view
}

fn wire_formats(decl: &PlaneDecl) -> &'static [&'static str] {
    row(decl).map_or(&[], |d| d.reg.dialects.as_slice())
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
    /// Whether this serving slot's facing answered. A refused candidate retains its prior
    /// successful slot; without one, this is `false` and `facing` is the empty default.
    /// `/healthz` on a deployment with no model lanes reads it ([`opened`]).
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
        .unwrap_or_else(|| Ok(Vec::new()));

    #[expect(
        clippy::disallowed_methods,
        reason = "boot: the providers' dialect facts are lowered once per generation build"
    )]
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

fn mount_of(target: &str) -> &str {
    let literal = target.split("/{").next().unwrap_or(target);
    literal.trim_end_matches('/')
}

fn claims(slot: &dyn std::any::Any) -> Vec<(String, &'static str)> {
    let Some(s) = slot.downcast_ref::<DoorSlot>() else {
        return Vec::new();
    };
    // busbar:expect(bp::fresh_buffer, reason = "boot: a door's claimed mounts are listed once per generation's route table")
    let mut out: Vec<(String, &'static str)> = Vec::new();
    for (target, dialect) in &s.facing.claims {
        let path = mount_of(target);
        if !path.is_empty() && !out.iter().any(|(p, _)| p == path) {
            #[expect(
                clippy::disallowed_methods,
                reason = "boot: each distinct claimed mount is owned by the generation's route table"
            )]
            out.push((path.to_string(), dialect));
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

#[cfg(test)]
pub fn listed<'a>(
    slots: &'a std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,
    key: Option<&'a busbar_contract::records::VirtualKey>,
) -> Vec<&'a str> {
    listed_matching(slots, key, None).collect()
}

/// The names `plane`'s door slots list that `key` may see, in plane registration order.
pub fn listed_for_plane<'a>(
    slots: &'a std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,
    key: Option<&'a busbar_contract::records::VirtualKey>,
    plane: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    listed_matching(slots, key, Some(plane))
}

fn listed_matching<'a>(
    slots: &'a std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,
    key: Option<&'a busbar_contract::records::VirtualKey>,
    plane: Option<&'a str>,
) -> impl Iterator<Item = &'a str> + 'a {
    let registered = crate::plane_driver::registry::plane_decls();
    let door_slot = |(k, s): (
        &'a &'static str,
        &'a std::sync::Arc<dyn std::any::Any + Send + Sync>,
    )| { s.downcast_ref::<DoorSlot>().map(|slot| (*k, slot)) };
    // Registered doors in registration order, then any door slot no registered plane names (in key
    // order): the order the listing has always had.
    let in_order = registered
        .iter()
        .filter_map(move |d| slots.get_key_value(d.key))
        .filter_map(door_slot);
    let unregistered = slots
        .iter()
        .filter(move |(k, _)| !registered.iter().any(|d| d.key == **k))
        .filter_map(door_slot);
    in_order
        .chain(unregistered)
        .filter_map(move |(_, slot)| {
            let door = slot.section.door?;
            if plane.is_some_and(|plane| door.reg.key != plane) {
                return None;
            }
            let kind = door.reg.scope_kinds.first();
            Some(
                slot.facing
                    .listed
                    .iter()
                    .map(String::as_str)
                    .filter(move |name| match (key, kind) {
                        (Some(key), Some(kind)) => key.scope_allowed(kind, name),
                        _ => true,
                    }),
            )
        })
        .flatten()
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
    #[expect(
        clippy::disallowed_methods,
        reason = "config: the section's named definitions are projected for the admin list"
    )]
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
    #[expect(
        clippy::disallowed_methods,
        reason = "config: the container gates are re-resolved once per generation swap"
    )]
    let containers: Vec<(&str, &[String])> = gates
        .containers
        .iter()
        .map(|(n, h)| (n.as_str(), h.as_slice()))
        .collect();
    next.reresolve_container_gates(d.reg.key, &containers, &gates.section_hooks);
}

/// Whether `e` already names the definition, as `` `<section>.<name>` ``.
fn names_definition(e: &str, section: &str, name: &str) -> bool {
    e.strip_prefix('`')
        .and_then(|r| r.strip_prefix(section))
        .and_then(|r| r.strip_prefix('.'))
        .and_then(|r| r.strip_prefix(name))
        .is_some_and(|r| r.starts_with('`'))
}

fn config_validate(decl: &PlaneDecl, name: &str, def: &serde_json::Value) -> Result<(), String> {
    let Some(d) = row(decl) else {
        return Ok(());
    };
    let section = d.reg.section;
    #[expect(
        clippy::disallowed_methods,
        reason = "config: an admin-written definition is encoded once, for its door's validate"
    )]
    let bytes = serde_json::to_vec(&OneEntry(name, def)).map_err(|e| e.to_string())?;
    #[expect(
        clippy::disallowed_methods,
        reason = "error: a refused definition is named once, in the admin write's refusal"
    )]
    let judged = (d.reg.validate)(&dealt(section, bytes)?).map_err(|e| {
        if names_definition(&e, section, name) {
            e
        } else {
            format!("invalid `{section}.{name}` definition: {e}")
        }
    });
    judged
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
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        if self.value.is_null() {
            return Ok(Vec::new());
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the owned section is lowered once per generation build for the bound fill"
        )]
        let value = serde_json::to_value(&self.value)
            .map_err(|_| "owned plane configuration is not JSON")?;
        let value = crate::config::filled::plane_bound(&[self.section], value)?;
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the owned section is encoded once per generation build for the door's open"
        )]
        let bytes = serde_json::to_vec(&OneEntry(self.section, &value))
            .map_err(|_| "owned plane configuration cannot be encoded".to_owned());
        bytes
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

fn parse_endpoint(
    decl: &PlaneDecl,
    value: &serde_yaml::Value,
) -> Result<Box<dyn crate::config::plane_sections::PlaneEndpointCfg>, String> {
    let section = row(decl)
        .and_then(|d| d.reg.owns.first().copied())
        .unwrap_or("");
    // busbar:expect(bp::clone_alloc, reason = "config: the endpoint block is carried as written into the parsed config")
    let owned = DoorOwned {
        section,
        value: value.clone(),
    };
    Ok(Box::new(owned))
}

fn lower_endpoint(
    endpoint: &dyn crate::config::plane_sections::PlaneEndpointCfg,
) -> Result<std::sync::Arc<dyn std::any::Any + Send + Sync>, String> {
    #[expect(
        clippy::disallowed_methods,
        reason = "error: an endpoint block not carried as written is refused once, at lowering"
    )]
    let lowered = endpoint
        .as_any()
        .downcast_ref::<DoorOwned>()
        .map(|o| std::sync::Arc::new(o.clone()) as std::sync::Arc<dyn std::any::Any + Send + Sync>)
        .ok_or_else(|| "a door plane's endpoint block was not carried as written".to_string());
    lowered
}

fn parse_section(decl: &PlaneDecl, value: &serde_yaml::Value) -> Result<Box<dyn PlaneCfg>, String> {
    let Some(d) = row(decl) else {
        #[expect(
            clippy::disallowed_methods,
            reason = "error: a section parsed before its door folded is refused once"
        )]
        return Err("a door plane's section was parsed before its door was folded".to_string());
    };
    (d.reg.validate)(&dealt(d.reg.section, settings_of(d.reg.section, value)?)?)?;
    // busbar:expect(bp::clone_alloc, reason = "config: the section is carried as written into the parsed config")
    let section = DoorSection::new(Some(d), d.reg.section, value.clone());
    Ok(Box::new(section))
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
    #[expect(
        clippy::disallowed_methods,
        reason = "boot: a door's admin routes are mounted once per generation"
    )]
    let routes = d
        .reg
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
        .collect();
    routes
}

pub(crate) const OPENAPI_COMPONENTS: &str = "components";

/// The door's stated admin OpenAPI blob, as the plane registered it.
pub(crate) fn admin_openapi(decl: &PlaneDecl) -> Option<&'static [u8]> {
    row(decl).and_then(|d| d.reg.admin_openapi)
}

fn openapi(decl: &PlaneDecl) -> serde_json::Value {
    #[expect(
        clippy::disallowed_types,
        clippy::disallowed_methods,
        reason = "config: the door's admin OpenAPI paths are composed per OpenAPI document build"
    )]
    let paths = match admin_openapi(decl)
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
    {
        Some(serde_json::Value::Object(blob)) => serde_json::Value::Object(
            blob.into_iter()
                .filter(|(rel, _)| rel != OPENAPI_COMPONENTS)
                .map(|(rel, item)| (format!("{}{rel}", crate::api::ADMIN_PREFIX), item))
                .collect(),
        ),
        _ => serde_json::Value::Object(serde_json::Map::new()),
    };
    paths
}

fn push_encoded(out: &mut String, name: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
}

fn filled(target: &str, name: &str) -> String {
    // busbar:expect(bp::fresh_buffer, reason = "config: an admin verb's plane path is filled once per admin call")
    let mut path = String::with_capacity(target.len() + 3 * name.len());
    for (i, seg) in target.split('/').enumerate() {
        if i > 0 {
            path.push('/');
        }
        if seg.len() > 1 && seg.starts_with('{') && seg.ends_with('}') {
            push_encoded(&mut path, name);
        } else {
            path.push_str(seg);
        }
    }
    path
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
    let served = match ctx.serve.served_at(req, ctx.body).await {
        None => return AdminReply::Refused(PlaneVerbError::NotFound),
        Some(Err(unserved)) => {
            #[expect(
                clippy::disallowed_methods,
                reason = "error: an admin verb the plane did not serve is refused once, in words"
            )]
            let refusal = format!("the plane did not serve `{verb} {path}`: {unserved:?}");
            return AdminReply::Rejected(PlaneVerbError::Internal(refusal));
        }
        Some(Ok(served)) => served,
    };
    let text = match String::from_utf8(served.body) {
        Ok(text) => text,
        Err(bytes) => {
            #[expect(
                clippy::disallowed_methods,
                reason = "error: a plane's non-UTF-8 admin reply is replaced lossily, once"
            )]
            let lossy = String::from_utf8_lossy(bytes.as_bytes()).into_owned();
            lossy
        }
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

fn admin_plane_error(
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
            #[expect(
                clippy::disallowed_methods,
                reason = "error: a plane's unexpected admin status is refused once, in words"
            )]
            let refusal = format!("the plane answered with status {status}");
            PlaneVerbError::Internal(refusal)
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

fn yaml_present(value: &serde_yaml::Value) -> bool {
    match value {
        serde_yaml::Value::Null => false,
        serde_yaml::Value::Mapping(m) => !m.is_empty(),
        _ => true,
    }
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
