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
//! What it does NOT do: claim a path, bind an audience or build an engine runtime. The door's routes
//! are mounted by the serve row, and the door serves them.
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
    decl: &'static PlaneDecl,
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
        return Ok(f.decl);
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
    let decl: &'static PlaneDecl = Box::leak(Box::new(PlaneDecl::assemble(
        declaration,
        HOOK_TABLE[index].clone_hooks(named),
    )));
    let dialects: &'static [&'static str] = reg.dialects.clone().leak();
    let _ = DOORS[index].set(Folded {
        reg,
        dialects,
        decl,
    });
    *next = index + 1;
    Ok(decl)
}

/// The registration's contract declaration, every word the door's.
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
        owned_config_sections: &[],
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
}

impl DoorSection {
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
        // A door resolves its own settings' references through the secret service it is handed; the
        // kernel holds no typed reference of a door's section.
        Vec::new()
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
        Ok(())
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

/// The section as the door's `validate` reads it: JSON, in the order it was written.
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

fn build<const I: usize>(
    ctx: &BuildCtx,
) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    let d = door(I)?;
    let mine = |s: &DoorSection| s.section == d.reg.section && s.is_present();
    if let Some(s) = ctx
        .agent_defs
        .downcast_ref::<DoorSection>()
        .filter(|s| mine(s))
    {
        return Some(std::sync::Arc::new(s.clone()));
    }
    let raw = ctx.endpoint_slot.as_deref()?;
    let (section, value) = raw.downcast_ref::<(&'static str, serde_yaml::Value)>()?;
    let s = DoorSection {
        section,
        value: value.clone(),
    };
    mine(&s).then(|| std::sync::Arc::new(s) as std::sync::Arc<dyn std::any::Any + Send + Sync>)
}

/// The generation's section of the door at `I`, off the neutral slot seam.
fn slot_section<const I: usize>(
    slots: &dyn crate::plane_host::PlaneSlots,
) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    slots.plane_slot(door(I)?.reg.key).cloned()
}

fn named_def_list<const I: usize>(
    slots: &dyn crate::plane_host::PlaneSlots,
) -> Vec<crate::api::NamedDefView> {
    let (Some(d), Some(slot)) = (door(I), slot_section::<I>(slots)) else {
        return Vec::new();
    };
    slot.downcast_ref::<DoorSection>()
        .map(|s| {
            s.registrations()
                .map(|(n, v)| view_of(n, v, &d.reg.trust_keys))
                .collect()
        })
        .unwrap_or_default()
}

fn named_def_get<const I: usize>(
    slots: &dyn crate::plane_host::PlaneSlots,
    name: &str,
) -> Option<crate::api::NamedDefView> {
    let d = door(I)?;
    let slot = slot_section::<I>(slots)?;
    let s = slot.downcast_ref::<DoorSection>()?;
    let view = s
        .registrations()
        .find(|(n, _)| *n == name)
        .map(|(n, v)| view_of(n, v, &d.reg.trust_keys));
    view
}

fn registry_contains<const I: usize>(
    slots: &dyn crate::plane_host::PlaneSlots,
    name: &str,
) -> bool {
    let Some(slot) = slot_section::<I>(slots) else {
        return false;
    };
    slot.downcast_ref::<DoorSection>()
        .is_some_and(|s| s.contains_def(name))
}

fn reresolve_gates<const I: usize>(next: &mut dyn crate::plane_host::ContainerGateSink) {
    let Some(d) = door(I) else {
        return;
    };
    let section = next
        .plane_slot(d.reg.key)
        .and_then(|slot| slot.downcast_ref::<DoorSection>().cloned());
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
    (d.reg.validate)(&bytes).map_err(|e| {
        if e.starts_with(&format!("`{section}.{name}`")) {
            e
        } else {
            format!("invalid `{section}.{name}` definition: {e}")
        }
    })
}

fn parse_section<const I: usize>(value: &serde_yaml::Value) -> Result<Box<dyn PlaneCfg>, String> {
    let Some(d) = door(I) else {
        return Err("a door plane's section was parsed before its door was folded".to_string());
    };
    (d.reg.validate)(&settings_of(value)?)?;
    Ok(Box::new(DoorSection {
        section: d.reg.section,
        value: value.clone(),
    }))
}

fn default_section<const I: usize>() -> Box<dyn PlaneCfg> {
    Box::new(DoorSection {
        section: door(I).map_or("", |d| d.reg.section),
        value: serde_yaml::Value::Null,
    })
}

/// One table index's hooks, as data a `const` table can hold.
struct HookRow {
    wire_format_names: fn() -> &'static [&'static str],
    build: fn(&BuildCtx) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    config_validate: fn(&str, &serde_json::Value) -> Result<(), String>,
    named_def_list: fn(&dyn crate::plane_host::PlaneSlots) -> Vec<crate::api::NamedDefView>,
    named_def_get: fn(&dyn crate::plane_host::PlaneSlots, &str) -> Option<crate::api::NamedDefView>,
    registry_contains: fn(&dyn crate::plane_host::PlaneSlots, &str) -> bool,
    reresolve_gates: fn(&mut dyn crate::plane_host::ContainerGateSink),
    parse_section: fn(&serde_yaml::Value) -> Result<Box<dyn PlaneCfg>, String>,
    default_section: fn() -> Box<dyn PlaneCfg>,
}

impl HookRow {
    const fn of<const I: usize>() -> HookRow {
        HookRow {
            wire_format_names: wire_formats::<I>,
            build: build::<I>,
            config_validate: config_validate::<I>,
            named_def_list: named_def_list::<I>,
            named_def_get: named_def_get::<I>,
            registry_contains: registry_contains::<I>,
            reresolve_gates: reresolve_gates::<I>,
            parse_section: parse_section::<I>,
            default_section: default_section::<I>,
        }
    }

    /// The registry row's hooks: this index's, and nothing a door plane does not do; the named-map
    /// surface only when `named`.
    fn clone_hooks(&self, named: bool) -> PlaneHooks {
        PlaneHooks {
            wire_format_names: self.wire_format_names,
            claims: |_| Vec::new(),
            admission: |_| None,
            build: self.build,
            routes: None,
            admin_routes: None,
            openapi: None,
            hydrate: None,
            start: None,
            config_validate: named.then_some(self.config_validate),
            named_def_list: named.then_some(self.named_def_list),
            named_def_get: named.then_some(self.named_def_get),
            registry_contains: named.then_some(self.registry_contains),
            reresolve_gates: Some(self.reresolve_gates),
            openapi_schemas: None,
            on_swap: None,
            parse_section: Some(self.parse_section),
            parse_endpoint: None,
            lower_endpoint: None,
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
