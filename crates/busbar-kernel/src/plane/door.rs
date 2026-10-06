// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PLANES' REGISTRY FOLD (ARCHITECT RULING 2026-10-03, Q-DEL-A2A-DECL; `BUSBAR-1.6.0.md`
//! #49, OWNER-LOCKED: "the config SECTION name for a plane comes from that plane's Statement
//! `sections.owns`"; R2-C: duplicate declarations are derived, not declared).
//!
//! A plane served through its memory-ABI door states everything its registry row holds: its
//! declaring section, and in its plane tail its scope kinds, nouns, signing, billable classes, fee
//! units, record kinds, trust keys and passthrough refusal. The loader reads those facts off a door,
//! linked or dropped alike, as a [`PlaneRegistration`]; [`fold`] turns one into the kernel's
//! [`PlaneDecl`], so the composition root installs it beside the linked rows BEFORE the config
//! prepass, and the prepass lifts the plane's section from the registry like any other. No root row
//! and no plane literal: every word here is the door's.
//!
//! What the row DOES:
//! * its section parses through the door's own `validate` and is carried as written
//!   ([`DoorSection`]), so a section the door refuses fails `--validate` and boot in the door's words;
//! * when the section is one of the 1.5.3 named-definition maps (the kernel's frozen
//!   `NAMED_MAP_SECTIONS`: a registration per key beside the reserved section words), the admin
//!   named-map CRUD (`/<section>/{name}`) is generated from the row: the reads
//!   ([`PlaneDecl::named_def_list`], `named_def_get`, `registry_contains`) project each registration
//!   onto the shared view (its trust keys read by the kernel, which owns them), and a write is
//!   judged by the door's `validate` over a one-entry section, in the 1.5.3 named-map wording;
//! * the per-registration hook attach is re-resolved from the section's `hooks:` lists.
//!
//! * its runtime slot holds what the door faces the world with for the generation (the snapshot a
//!   probe instance of the door publishes over the section and the public base URL): the kernel mounts the
//!   door's claims by their literal prefix and binds its audience from it, so a credential at the
//!   door is judged for that resource and a refusal there is the resource's RFC 6750 challenge.
//!
//! What it does NOT do: build an engine runtime or serve a route. The door's routes are mounted by
//! the serve row, and the door serves them.
//!
//! THE HOOK TABLE. A registry row's hooks are plain `fn` pointers, which carry no state, so each
//! folded door gets the hooks of its own table index ([`MAX_DOOR_PLANES`] of them, each a
//! monomorphised copy that reads its door by index). A process folding more doors than that is
//! refused at boot, naming the cap.

use std::sync::{Mutex, OnceLock};

use busbar_contract::plane::{BillableClass, PlaneDeclaration, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::PlaneRegistration;

use crate::plane::config::{ContainerGateInputs, PlaneCfg};
use crate::plane::registry::{BuildCtx, PlaneDecl, PlaneHooks};

/// The most door planes one process folds into its registry.
pub const MAX_DOOR_PLANES: usize = 16;

/// One folded door: its registration and the row built from it.
struct Folded {
    reg: PlaneRegistration,
    dialects: &'static [&'static str],
    decl: PlaneDecl,
}

/// The folded doors, by hook-table index.
static DOORS: [OnceLock<Folded>; MAX_DOOR_PLANES] = [const { OnceLock::new() }; MAX_DOOR_PLANES];

/// The next free hook-table index; held while a fold claims one.
static NEXT: Mutex<usize> = Mutex::new(0);

/// FOLD a door plane's registration into a registry row. Folding the same key twice answers the row
/// the first fold built (a test binary folds per test; the composition root folds once).
///
/// # Errors
///
/// A registration that names no key or no section (a plane is installed by its name and configured
/// by its section), or a process past [`MAX_DOOR_PLANES`].
pub fn fold(reg: PlaneRegistration) -> Result<&'static PlaneDecl, String> {
    if reg.key.is_empty() || reg.section.is_empty() {
        return Err(format!(
            "plane door `{}` states no name or no declaring section; a plane is installed by its \
             name and configured by its section",
            reg.key
        ));
    }
    let mut next = NEXT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(f) = DOORS[..*next]
        .iter()
        .filter_map(OnceLock::get)
        .find(|f| f.reg.key == reg.key)
    {
        return Ok(&f.decl);
    }
    let index = *next;
    if index >= MAX_DOOR_PLANES {
        return Err(format!(
            "plane door `{}`: this process already folds {MAX_DOOR_PLANES} door planes, the most one \
             process folds",
            reg.key
        ));
    }
    let declaration = declaration_of(&reg);
    // The named-map surface is the 1.5.3 named-definition maps' (the frozen section list), so a
    // door plane whose verb is one of them answers its CRUD and any other answers none.
    let named = busbar_kernel::plane::config::NAMED_MAP_SECTIONS.contains(&reg.section);
    let decl = PlaneDecl::assemble(
        declaration,
        HOOK_TABLE[index].clone_hooks(named, !reg.owns.is_empty(), !reg.admin_routes.is_empty()),
    );
    let dialects: &'static [&'static str] = reg.dialects.clone().leak();
    let folded = DOORS[index].get_or_init(|| Folded {
        reg,
        dialects,
        decl,
    });
    *next = index + 1;
    Ok(&folded.decl)
}

/// The registration's contract declaration, every word the door's.
fn declaration_of(reg: &PlaneRegistration) -> PlaneDeclaration {
    PlaneDeclaration {
        key: reg.key,
        fallback: false,
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
        required_config_sections: &[],
        trust_keys: reg.trust_keys.clone().leak(),
        caller_credential_refusal: reg.caller_credential_refusal,
        served_op_classes: &[],
    }
}

/// The folded door at `index`.
fn door(index: usize) -> Option<&'static Folded> {
    DOORS.get(index).and_then(OnceLock::get)
}

// ── THE SECTION ───────────────────────────────────────────────────────────────────────────────

/// A DOOR PLANE'S SECTION, as written: the door judged it (`validate`) and is handed it raw; the
/// kernel reads only the words it owns (the registrations' names, their trust keys and `hooks:`
/// lists, and the reserved section words). Also the plane's per-generation runtime slot, which the
/// named-map reads project.
#[derive(Debug, Clone)]
pub struct DoorSection {
    /// The section's key.
    pub section: &'static str,
    /// The section as written (`Null` when absent).
    pub value: serde_yaml::Value,
    /// The secret references the section holds at its door's declared paths
    /// (`PlaneRegistration::secret_refs`), each with the config path it was read at.
    refs: Vec<(String, busbar_contract::secret_ref::SecretRef)>,
}

impl DoorSection {
    /// The section `section` as written, with the secret references it holds at its door's
    /// declared paths (`settings.<segment>…`, `*` every key of the map there) read out, so
    /// `--validate` and boot resolve each one as they resolve every other reference.
    #[must_use]
    pub fn new(section: &'static str, value: serde_yaml::Value) -> Self {
        let paths = DOORS
            .iter()
            .filter_map(OnceLock::get)
            .find(|f| f.reg.section == section)
            .map(|f| f.reg.secret_refs.as_slice())
            .unwrap_or_default();
        let mut refs = Vec::new();
        for path in paths {
            let Some(rest) = path.strip_prefix("settings.") else {
                continue;
            };
            let segments: Vec<&str> = rest.split('.').collect();
            collect_refs(&value, &segments, section.to_string(), &mut refs);
        }
        Self {
            section,
            value,
            refs,
        }
    }

    fn registrations(&self) -> impl Iterator<Item = (&str, &serde_yaml::Value)> {
        crate::trust::section::registrations(&self.value)
    }

    /// A hook list under `hooks:` in `v`, as written (non-strings skipped: the door refused them).
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
        // The references at the door's declared paths, so `--validate` and boot resolve each one.
        self.refs.iter().map(|(at, r)| (at.clone(), r)).collect()
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
        // The written entry's references are the section's too.
        *self = Self::new(self.section, std::mem::take(&mut self.value));
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

    /// THE WHOLE EFFECTIVE SECTION, judged by its door: the file's entries and every entry the
    /// management surface wrote, in one `validate` — the rules no single entry can see (one
    /// registration's published name colliding with another's) run here, at `resolve`, which boot,
    /// `--validate` and every config-apply rebuild pass through. An absent section is nothing to judge.
    fn validate_registry(&self) -> Result<(), String> {
        if !self.is_present() {
            return Ok(());
        }
        let Some(fold) = DOORS
            .iter()
            .filter_map(OnceLock::get)
            .find(|f| f.reg.section == self.section)
        else {
            return Ok(());
        };
        (fold.reg.validate)(&dealt(self.section, settings_of(&self.value)?)?)
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

/// Every secret reference under `value` at `segments` (a `*` segment is every key of the map there),
/// each with its config path. A value at the path that is not a reference (a plain scalar beside
/// references in one map) is not one: the door's own `validate` judged the section's shape.
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

/// The section as the door's `validate` reads it: JSON, in the order it was written.
/// THE BLOB A DOOR'S `validate` IS HANDED, in the one shape stage 3g deals it
/// (`config_validate::deal`, `Seat::Verbs`): `{<section>: <section as written>}` for the section the
/// door declares. Every kernel-side judge (a section's parse, an admin write's one-entry section,
/// the effective registry at `resolve`) hands the door that shape, so a door reads one blob shape
/// whoever asks. An absent section stays the empty blob (nothing written).
fn dealt(section: &str, settings: Vec<u8>) -> Result<Vec<u8>, String> {
    if settings.is_empty() {
        return Ok(settings);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&settings).map_err(|e| format!("the section is not JSON: {e}"))?;
    serde_json::to_vec(&serde_json::json!({ section: value })).map_err(|e| e.to_string())
}

fn settings_of(value: &serde_yaml::Value) -> Result<Vec<u8>, String> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    serde_json::to_vec(value).map_err(|e| format!("the section is not representable as JSON: {e}"))
}

/// One registration projected onto the shared named-definition view: its name, and the trust keys
/// the kernel owns (the pin's mechanism and whether a fingerprint is approved, the re-verification
/// cadence as written or its declared default); `None` for a key the plane does not declare.
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

// ── THE HOOKS, ONE COPY PER TABLE INDEX ─────────────────────────────────────────────────────────

fn wire_formats<const I: usize>() -> &'static [&'static str] {
    door(I).map_or(&[], |d| d.dialects)
}

/// A door plane's runtime slot for one generation: its section, and what its `open` faces the world
/// with over that section and the deployment's public base URL.
#[derive(Debug, Clone)]
pub struct DoorSlot {
    /// The section, as written.
    pub section: DoorSection,
    /// Its claims (mounted by their literal prefix) and its audience.
    pub facing: busbar_contract::plane_calls::DoorFacing,
}

fn build<const I: usize>(
    ctx: &BuildCtx,
) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    let d = door(I)?;
    let mine = |s: &DoorSection| s.section == d.reg.section && s.is_present();
    let section = match [ctx.agent_defs, ctx.tool_defs]
        .into_iter()
        .filter_map(|defs| defs.downcast_ref::<DoorSection>())
        .find(|s| mine(s))
    {
        Some(s) => s.clone(),
        // ITS ENDPOINT BLOCK ALONE CONFIGURES IT (LAW 7): an owned block carried as written, with no
        // registration in the section, builds the slot over the section as absent and that block.
        None if ctx
            .endpoint_slot
            .as_deref()
            .and_then(|slot| slot.downcast_ref::<DoorOwned>())
            .is_some_and(crate::plane::config::PlaneEndpointCfg::is_present) =>
        {
            DoorSection::new(d.reg.section, serde_yaml::Value::Null)
        }
        None => {
            let raw = ctx.endpoint_slot.as_deref()?;
            let (section, value) = raw.downcast_ref::<(&'static str, serde_yaml::Value)>()?;
            let s = DoorSection::new(section, value.clone());
            if !mine(&s) {
                return None;
            }
            s
        }
    };
    // A door that will not face the world with this section claims nothing this generation (its
    // section already passed its `validate`); the refusal is logged, naming it.
    // Its owned sections, as its endpoint block was carried (`DoorOwned`): handed beside its section.
    let owned = ctx
        .endpoint_slot
        .as_deref()
        .and_then(|slot| slot.downcast_ref::<DoorOwned>())
        .map(DoorOwned::bytes)
        .unwrap_or_default();
    let facing = match settings_of(&section.value)
        .and_then(|bytes| (d.reg.facing)(&bytes, &owned, ctx.public_url))
    {
        Ok(f) => f,
        Err(refusal) => {
            tracing::error!(plane = d.reg.key, "{refusal}");
            busbar_contract::plane_calls::DoorFacing::default()
        }
    };
    Some(std::sync::Arc::new(DoorSlot { section, facing }))
}

/// The path a claim mounts at: the target up to its first `{name}` segment (a pattern answers under
/// its literal prefix), without a trailing slash.
fn mount_of(target: &str) -> String {
    let literal = target.split("/{").next().unwrap_or(target);
    literal.trim_end_matches('/').to_string()
}

fn claims<const I: usize>(slot: &dyn std::any::Any) -> Vec<(String, &'static str)> {
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

fn admission<const I: usize>(slot: &dyn std::any::Any) -> Option<super::PlaneAdmission> {
    let (audience, resource_metadata) =
        slot.downcast_ref::<DoorSlot>()?.facing.admission.clone()?;
    Some(super::PlaneAdmission {
        audience,
        resource_metadata,
    })
}

/// The generation's slot of the door at `I`, off the neutral slot seam.
fn slot_of<const I: usize>(
    slots: &dyn crate::plane_host::PlaneSlots,
) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    slots.plane_slot(door(I)?.reg.key).cloned()
}

fn named_def_list<const I: usize>(
    slots: &dyn crate::plane_host::PlaneSlots,
) -> Vec<crate::api::NamedDefView> {
    let (Some(d), Some(slot)) = (door(I), slot_of::<I>(slots)) else {
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

fn named_def_get<const I: usize>(
    slots: &dyn crate::plane_host::PlaneSlots,
    name: &str,
) -> Option<crate::api::NamedDefView> {
    let d = door(I)?;
    let slot = slot_of::<I>(slots)?;
    let s = slot.downcast_ref::<DoorSlot>()?;
    let view = s
        .section
        .registrations()
        .find(|(n, _)| *n == name)
        .map(|(n, v)| view_of(n, v, &d.reg.trust_keys));
    view
}

fn registry_contains<const I: usize>(
    slots: &dyn crate::plane_host::PlaneSlots,
    name: &str,
) -> bool {
    let Some(slot) = slot_of::<I>(slots) else {
        return false;
    };
    slot.downcast_ref::<DoorSlot>()
        .is_some_and(|s| s.section.contains_def(name))
}

fn reresolve_gates<const I: usize>(next: &mut dyn crate::plane_host::ContainerGateSink) {
    let Some(d) = door(I) else {
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

/// An admin write of one registration, judged by the door over a one-entry section. The door's
/// value rule speaks for itself (it names its registration, `` `<section>.<name>`: ``); any other
/// refusal is a shape refusal and reads as the 1.5.3 named-map sentence the in-core sections speak
/// (`invalid `<section>.<name>` definition: …`).
fn config_validate<const I: usize>(name: &str, def: &serde_json::Value) -> Result<(), String> {
    let Some(d) = door(I) else {
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
    /// The owned sections as `PlaneOpenIn::owned` carries them: one JSON object keyed by section
    /// name; empty when the section is absent or not representable.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        if self.value.is_null() {
            return Vec::new();
        }
        serde_json::to_value(&self.value)
            .ok()
            .and_then(|v| serde_json::to_vec(&serde_json::json!({ self.section: v })).ok())
            .unwrap_or_default()
    }
}

impl crate::plane::config::PlaneEndpointCfg for DoorOwned {
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

fn parse_endpoint<const I: usize>(
    value: &serde_yaml::Value,
) -> Result<Box<dyn crate::plane::config::PlaneEndpointCfg>, String> {
    let section = door(I)
        .and_then(|d| d.reg.owns.first().copied())
        .unwrap_or("");
    Ok(Box::new(DoorOwned {
        section,
        value: value.clone(),
    }))
}

fn lower_endpoint<const I: usize>(
    endpoint: &dyn crate::plane::config::PlaneEndpointCfg,
) -> Result<std::sync::Arc<dyn std::any::Any + Send + Sync>, String> {
    endpoint
        .as_any()
        .downcast_ref::<DoorOwned>()
        .map(|o| std::sync::Arc::new(o.clone()) as std::sync::Arc<dyn std::any::Any + Send + Sync>)
        .ok_or_else(|| "a door plane's endpoint block was not carried as written".to_string())
}

fn parse_section<const I: usize>(value: &serde_yaml::Value) -> Result<Box<dyn PlaneCfg>, String> {
    let Some(d) = door(I) else {
        return Err("a door plane's section was parsed before its door was folded".to_string());
    };
    (d.reg.validate)(&dealt(d.reg.section, settings_of(value)?)?)?;
    Ok(Box::new(DoorSection::new(d.reg.section, value.clone())))
}

fn default_section<const I: usize>() -> Box<dyn PlaneCfg> {
    Box::new(DoorSection::new(
        door(I).map_or("", |d| d.reg.section),
        serde_yaml::Value::Null,
    ))
}

// ── THE ADMIN ROUTES ITS STATEMENT STATES ───────────────────────────────────────────────────────

/// The door's stated admin routes as the admin router mounts them (ARCHITECT Q-L3B-VERBS): each
/// non-public route at its stated verb and target, a read at `read-only` and anything else at
/// `full`, audited under its stated word; every one served by the instance's own `serve` op
/// (`plane_driver::serve::served_at`), its answer framed in the admin taxonomy.
fn admin_routes<const I: usize>(
    _slot: &dyn std::any::Any,
) -> Vec<crate::admin_verbs::AdminRouteSpec> {
    use crate::admin_verbs::{AdminRouteSpec, AdminScope, AdminVerbKind};
    use busbar_contract::abi::mechanism::route::RouteMethod;
    let Some(d) = door(I) else {
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

/// The key of the door's admin OpenAPI blob that is no path: the component schemas its paths'
/// `$ref`s name, stated as data because a door links no schema generator (ARCHITECT Q2).
const OPENAPI_COMPONENTS: &str = "components";

/// The door's stated admin OpenAPI blob as an object (empty when it states none).
fn openapi_blob<const I: usize>() -> serde_json::Map<String, serde_json::Value> {
    match door(I)
        .and_then(|d| d.reg.admin_openapi)
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
    {
        Some(serde_json::Value::Object(blob)) => blob,
        _ => serde_json::Map::new(),
    }
}

/// The door's stated admin OpenAPI fragment, its paths keyed under the admin mount (its
/// `components` key is no path; [`stated_schemas`] reads it).
fn openapi<const I: usize>() -> serde_json::Value {
    serde_json::Value::Object(
        openapi_blob::<I>()
            .into_iter()
            .filter(|(rel, _)| rel != OPENAPI_COMPONENTS)
            .map(|(rel, item)| (format!("{}{rel}", crate::api::ADMIN_PREFIX), item))
            .collect(),
    )
}

/// The door's stated `components.schemas`: the bodies its paths' `$ref`s name (the paths already
/// carry those `$ref`s, as [`openapi`] keyed them). The admin document's generator inserts them
/// ([`crate::plane::registry::stated_schemas_hook`]); a build that generates no document reads none.
#[allow(dead_code)] // read only by the document generator's hook, which a non-generating build omits
pub(crate) fn stated_schemas<const I: usize>() -> Option<serde_json::Map<String, serde_json::Value>>
{
    match openapi_blob::<I>()
        .remove(OPENAPI_COMPONENTS)
        .and_then(|c| c.get("schemas").cloned())
    {
        Some(serde_json::Value::Object(schemas)) => Some(schemas),
        _ => None,
    }
}

/// `target` with its `{name}` segment filled by `name`.
fn filled(target: &str, name: &str) -> String {
    target
        .split('/')
        .map(|seg| {
            if seg.len() > 1 && seg.starts_with('{') && seg.ends_with('}') {
                name
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// ONE STATED ADMIN ROUTE, SERVED: by the published instance's `serve` op; its answer as the admin
/// shim frames it: a success's body verbatim, a `404` the taxonomy's not-found, a `400` a
/// validation refusal in the plane's words (condition-tagged when its reply names the condition,
/// [`busbar_contract::plane::ADMIN_CONDITION_FIELD`]), anything else internal. A refusal is audited
/// as rejected when the plane's answer asks for an audit row, and is not audited when it asks for
/// none (a refusal before anything was judged). No published instance answers is the not-found.
async fn admin_reply(
    verb: &'static str,
    target: &'static str,
    ctx: crate::admin_verbs::AdminReqCtx,
) -> crate::admin_verbs::AdminReply {
    use crate::admin_verbs::{AdminReply, PlaneVerbError};
    let path = filled(target, &ctx.name);
    match crate::plane_driver::serve::served_at(verb, &path, &ctx.headers, ctx.body).await {
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

/// The admin taxonomy condition a served reply's head fields name, if they name one.
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

/// One table index's hooks, as data a `const` table can hold.
struct HookRow {
    wire_format_names: fn() -> &'static [&'static str],
    claims: fn(&dyn std::any::Any) -> Vec<(String, &'static str)>,
    admission: fn(&dyn std::any::Any) -> Option<super::PlaneAdmission>,
    build: fn(&BuildCtx) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    config_validate: fn(&str, &serde_json::Value) -> Result<(), String>,
    named_def_list: fn(&dyn crate::plane_host::PlaneSlots) -> Vec<crate::api::NamedDefView>,
    named_def_get: fn(&dyn crate::plane_host::PlaneSlots, &str) -> Option<crate::api::NamedDefView>,
    registry_contains: fn(&dyn crate::plane_host::PlaneSlots, &str) -> bool,
    reresolve_gates: fn(&mut dyn crate::plane_host::ContainerGateSink),
    parse_section: fn(&serde_yaml::Value) -> Result<Box<dyn PlaneCfg>, String>,
    default_section: fn() -> Box<dyn PlaneCfg>,
    admin_routes: fn(&dyn std::any::Any) -> Vec<crate::admin_verbs::AdminRouteSpec>,
    openapi: fn() -> serde_json::Value,
    openapi_schemas: Option<crate::plane::registry::OpenapiSchemasHook>,
    #[allow(clippy::type_complexity)]
    parse_endpoint:
        fn(&serde_yaml::Value) -> Result<Box<dyn crate::plane::config::PlaneEndpointCfg>, String>,
    #[allow(clippy::type_complexity)]
    lower_endpoint: fn(
        &dyn crate::plane::config::PlaneEndpointCfg,
    ) -> Result<std::sync::Arc<dyn std::any::Any + Send + Sync>, String>,
}

impl HookRow {
    const fn of<const I: usize>() -> HookRow {
        HookRow {
            wire_format_names: wire_formats::<I>,
            claims: claims::<I>,
            admission: admission::<I>,
            build: build::<I>,
            config_validate: config_validate::<I>,
            named_def_list: named_def_list::<I>,
            named_def_get: named_def_get::<I>,
            registry_contains: registry_contains::<I>,
            reresolve_gates: reresolve_gates::<I>,
            parse_section: parse_section::<I>,
            default_section: default_section::<I>,
            parse_endpoint: parse_endpoint::<I>,
            lower_endpoint: lower_endpoint::<I>,
            admin_routes: admin_routes::<I>,
            openapi: openapi::<I>,
            openapi_schemas: crate::plane::registry::stated_schemas_hook::<I>(),
        }
    }

    /// The registry row's hooks: this index's, and nothing a door plane does not do; the named-map
    /// surface only when `named`.
    fn clone_hooks(&self, named: bool, owns: bool, admin: bool) -> PlaneHooks {
        PlaneHooks {
            wire_format_names: self.wire_format_names,
            claims: self.claims,
            admission: self.admission,
            build: self.build,
            routes: None,
            admin_routes: admin.then_some(self.admin_routes),
            openapi: admin.then_some(self.openapi),
            hydrate: None,
            start: None,
            config_validate: named.then_some(self.config_validate),
            named_def_list: named.then_some(self.named_def_list),
            named_def_get: named.then_some(self.named_def_get),
            registry_contains: named.then_some(self.registry_contains),
            reresolve_gates: Some(self.reresolve_gates),
            openapi_schemas: self.openapi_schemas.filter(|_| admin),
            on_swap: None,
            parse_section: Some(self.parse_section),
            parse_endpoint: owns.then_some(self.parse_endpoint),
            lower_endpoint: owns.then_some(self.lower_endpoint),
            build_runtime: None,
            viewer: None,
            retain_verify_gates: None,
            default_section: Some(self.default_section),
            resolve_provider: None,
        }
    }
}

/// Every table index's hooks.
static HOOK_TABLE: [HookRow; MAX_DOOR_PLANES] = [
    HookRow::of::<0>(),
    HookRow::of::<1>(),
    HookRow::of::<2>(),
    HookRow::of::<3>(),
    HookRow::of::<4>(),
    HookRow::of::<5>(),
    HookRow::of::<6>(),
    HookRow::of::<7>(),
    HookRow::of::<8>(),
    HookRow::of::<9>(),
    HookRow::of::<10>(),
    HookRow::of::<11>(),
    HookRow::of::<12>(),
    HookRow::of::<13>(),
    HookRow::of::<14>(),
    HookRow::of::<15>(),
];

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
