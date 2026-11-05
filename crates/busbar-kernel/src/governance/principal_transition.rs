// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold, explicit principal continuity. No identity inference, aliases, or historical rewrites.
//!
//! This facility requires deployment-wide sender AND backend quiescence. A process restart or
//! readback cannot establish that fact. Each apply process consumes a fresh attestation; after
//! any uncertain write, a new attestation is required before a later process may resume.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use busbar_contract::abi::sdk::store::conditional::{
    Decision, Expected, Mutation, Predicate, Request, VERSION,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::records::{RecordStore, UsageLedger, VirtualKey};
use busbar_contract::store_calls::StoreCalls;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{
    overlay::{OverlayDoc, OverlayStore},
    GroupCfg,
};
use crate::host_record_bootstrap::StoreWitness;
use crate::host_records::{RecordRows, StoreRows};

pub const SCHEMA: RecordSchemaId = RecordSchemaId::new("busbar.principal-transition.v1");
const HEAD: &[u8] = b"head";
const MAX_PLAN_BYTES: usize = 256 * 1024;
/// Opaque, plugin-authored metadata on its existing settings-schema document.
pub const FORMAT_ANNOTATION: &str = "x-busbar-principal-format";
pub const DOMAIN_ANNOTATION: &str = "x-busbar-principal-domain-fields";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub provider: String,
    pub plugin: String,
    pub format: String,
    pub domain_sha256: String,
    pub product_sha256: String,
    pub settings_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub old_principal: String,
    pub new_principal: String,
    pub provider: String,
    /// Evidence must establish ONE historical issuer for this actor, not just today's config.
    pub historical_provenance_sha256: String,
    pub old_product_sha256: String,
}

/// A historical deletion is excluded from subject-level holds ONLY with explicit operator proof
/// of a successful rotation, bound to both exact retained rows. No live-successor inference.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationDisposition {
    pub retired_key_id: String,
    pub successor_key_id: String,
    pub retired_key_sha256: String,
    pub successor_key_sha256: String,
    pub evidence_sha256: String,
}

/// Explicit provenance for a retained SELF principal outside the changed identity domains.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnaffectedPrincipal {
    pub principal: String,
    pub provider: String,
    pub requirement_sha256: String,
    pub keys_sha256: String,
    pub group_sha256: String,
    pub provenance_sha256: String,
}

/// Derived from an exact completed predecessor, and checked again before its conditional replace.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreviousReceipt {
    pub head_sha256: String,
    pub requirements: Vec<Requirement>,
    pub holds: BTreeSet<String>,
    /// Current held principal output and its proved provider; historical hold strings stay above.
    pub held_principals: BTreeMap<String, String>,
    pub retired_keys: BTreeMap<String, String>,
    pub historical_groups: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleDisposition {
    pub provider: String,
    pub old_role: String,
    /// None retires an unprovable or historically unasserted grant. Equal names affirm continuity.
    pub new_role: Option<String>,
    pub historical_provenance_sha256: String,
    pub old_product_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Specification {
    pub version: u32,
    pub id: String,
    pub bindings: Vec<Binding>,
    /// Exact effective policy inventory; never infer historical role ownership from current names.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub role_bindings_before: crate::config::RoleBindings,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub role_dispositions: Vec<RoleDisposition>,
    #[serde(default)]
    pub rotations: Vec<RotationDisposition>,
    #[serde(default)]
    pub unaffected: Vec<UnaffectedPrincipal>,
    pub complete_legacy_inventory_sha256: String,
    pub requirements: Vec<Requirement>,
    pub store_config_sha256: String,
    pub effective_config_sha256: String,
    pub witness: StoreWitness,
    pub cutover: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Carry {
    pub source: String,
    pub destination: String,
    pub window: u64,
    pub period: String,
    pub raw: UsageLedger,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub specification: Specification,
    #[serde(default)]
    pub previous: Option<PreviousReceipt>,
    /// Every key, including tombstones, proves that the affected-reference inventory is complete.
    pub keys_before: Vec<VirtualKey>,
    pub denylist_before: Vec<String>,
    pub groups_before: BTreeMap<String, GroupCfg>,
    pub overlay_before: Option<OverlayDoc>,
    pub carry: Vec<Carry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdAttestation {
    pub version: u32,
    pub epoch: String,
    pub plan_sha256: String,
    pub sender_quiesced: bool,
    pub backend_quiesced: bool,
    pub recovery_and_corrections_settled: bool,
    pub actor: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u32,
    plan_sha256: String,
    length: usize,
    fresh: bool,
    complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous: Option<String>,
    #[serde(skip)]
    retired_keys: BTreeMap<String, String>,
    #[serde(skip)]
    historical_groups: BTreeMap<String, String>,
    #[serde(skip)]
    depth: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization: Option<AuthorizationRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollover: Option<AuthorizationRef>,
    #[serde(skip)]
    extra_carry: Vec<Carry>,
    #[serde(skip)]
    store_config_sha256: String,
    #[serde(skip)]
    requirements: Vec<Requirement>,
    #[serde(skip)]
    holds: BTreeSet<String>,
    #[serde(skip)]
    held_principals: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationRef {
    digest: String,
    length: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rollover {
    baseline_sha256: String,
    clock: u64,
    carry: Vec<Carry>,
}

/// Explicit proof that a new artifact/settings vector preserves every existing principal output.
/// A changed issuer that changes principal identities cannot truthfully use this operation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reauthorization {
    pub version: u32,
    pub baseline_sha256: String,
    pub previous_requirements_sha256: String,
    pub requirements: Vec<Requirement>,
    pub identity_outputs_unchanged: bool,
    pub continuity_evidence_sha256: String,
    pub witness: StoreWitness,
    /// The attestation's plan_sha256 names baseline_sha256; epoch is consumed exactly once.
    pub attestation: ColdAttestation,
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    // preserve_order is feature-unified in assembled products. Sort recursively, including
    // nested values, rather than relying on the default serde_json map implementation.
    let mut value = serde_json::to_value(value).map_err(|e| e.to_string())?;
    value.sort_all_objects();
    serde_json::to_vec(&value).map_err(|e| e.to_string())
}

pub fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(canonical_bytes(value)?)))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainField {
    pointer: String,
    required: bool,
}

fn domain_fingerprint(
    schema: &serde_json::Value,
    settings: &serde_json::Value,
    secret_paths: &[String],
) -> Result<String, String> {
    let declaration = schema
        .get(DOMAIN_ANNOTATION)
        .ok_or("principal format requires declared non-secret identity domain fields")?;
    let fields: Vec<DomainField> = serde_json::from_value(declaration.clone())
        .map_err(|_| "invalid principal domain field declaration")?;
    if fields.is_empty() || fields.len() > 32 {
        return Err("principal domain declaration requires 1..32 fields".into());
    }
    let mut seen = BTreeSet::new();
    let mut values = Vec::with_capacity(fields.len());
    for field in &fields {
        if !field.pointer.starts_with('/')
            || field.pointer.len() > 256
            || field.pointer.chars().any(char::is_control)
            || !seen.insert(&field.pointer)
        {
            return Err("invalid or duplicate principal domain JSON pointer".into());
        }
        let mut segments = Vec::new();
        for token in field.pointer[1..].split('/') {
            let mut decoded = String::new();
            let mut chars = token.chars();
            while let Some(ch) = chars.next() {
                decoded.push(if ch == '~' {
                    match chars.next() {
                        Some('0') => '~',
                        Some('1') => '/',
                        _ => return Err("invalid principal domain JSON pointer escape".into()),
                    }
                } else {
                    ch
                });
            }
            segments.push(decoded);
        }
        // Statement secret paths use dot-separated components and '*' wildcards. Either
        // ancestor direction overlaps: hashing a parent object also hashes its secret slot.
        if secret_paths.iter().any(|path| {
            path.split('.')
                .zip(&segments)
                .all(|(secret, selected)| secret == "*" || secret == selected)
        }) {
            return Err(
                "principal domain fields must not overlap declared secret/reference slots".into(),
            );
        }
        let value = settings
            .pointer(&field.pointer)
            .unwrap_or(&serde_json::Value::Null);
        if field.required && value.is_null() {
            return Err("required principal domain field is absent or null".into());
        }
        // Admission rejects undeclared SecretRefs; also reject them locally so this helper
        // never fingerprints an unresolved reference if called before that validation.
        if busbar_contract::secret_fields::undeclared_reference(value, &[]).is_some() {
            return Err(
                "principal domain fields must contain non-secret configuration values".into(),
            );
        }
        values.push(value.clone());
    }
    digest(&(fields, values))
}

/// Principal continuity's single canonical Store binding; unrelated bootstrap hashes are unchanged.
pub fn store_fingerprint<T: Serialize>(store: &T) -> Result<String, String> {
    digest(store)
}

fn previous_receipt(head: &Head, bytes: &[u8]) -> PreviousReceipt {
    PreviousReceipt {
        head_sha256: hex::encode(Sha256::digest(bytes)),
        requirements: head.requirements.clone(),
        holds: head.holds.clone(),
        held_principals: head.held_principals.clone(),
        retired_keys: head.retired_keys.clone(),
        historical_groups: head.historical_groups.clone(),
    }
}

fn body_prefix(digest: &str) -> Vec<u8> {
    format!("body:{digest}:").into_bytes()
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn identity(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(char::is_control)
        && !value.starts_with(crate::cost::GROUP_BUCKET_PREFIX)
        && !value.starts_with("vk_")
        && value.len() + super::SELF_KEY_GROUP_PREFIX.len()
            <= super::group_provision::MAX_GROUP_NAME_LEN
}

fn group(principal: &str) -> String {
    format!("{}{principal}", super::SELF_KEY_GROUP_PREFIX)
}

fn validate_spec(spec: &Specification) -> Result<(), String> {
    if spec.version != 1
        || spec.id.is_empty()
        || spec.id.len() > 128
        || spec.id.chars().any(char::is_control)
        || (spec.bindings.is_empty() && spec.role_dispositions.is_empty())
        || spec.bindings.len() > 256
        || spec.role_dispositions.len() > 256
        || spec.unaffected.len() > 256
        || !hash(&spec.complete_legacy_inventory_sha256)
        || !hash(&spec.store_config_sha256)
        || !hash(&spec.effective_config_sha256)
        || spec.requirements.is_empty()
        || spec.cutover == 0
    {
        return Err(
            "invalid principal transition specification or missing inventory provenance".into(),
        );
    }
    let mut sources = BTreeSet::new();
    let mut destinations = BTreeSet::new();
    for b in &spec.bindings {
        if !identity(&b.old_principal)
            || !identity(&b.new_principal)
            || !hash(&b.historical_provenance_sha256)
            || !hash(&b.old_product_sha256)
            || !sources.insert(&b.old_principal)
            || !destinations.insert(&b.new_principal)
            || !spec
                .requirements
                .iter()
                .any(|r| r.provider == b.provider && !r.format.is_empty())
        {
            return Err("ambiguous, duplicate, oversized or unproven principal mapping".into());
        }
    }
    if !sources.is_disjoint(&destinations) {
        return Err("overlapping principal mapping is not supported".into());
    }
    let mut providers = BTreeSet::new();
    for r in &spec.requirements {
        if r.provider.is_empty()
            || r.plugin.is_empty()
            || r.format.len() > 256
            || (!r.format.is_empty() && !hash(&r.domain_sha256))
            || (!r.format.is_empty() && !hash(&r.product_sha256))
            || !hash(&r.settings_sha256)
            || !providers.insert(&r.provider)
        {
            return Err("invalid or duplicate principal format requirement".into());
        }
    }
    role_bindings_after(spec)?;
    let witness = &spec.witness;
    if witness.schema.is_empty()
        || witness.schema == SCHEMA.as_str()
        || hex::decode(&witness.key_hex).is_err()
        || hex::decode(&witness.value_hex).map_or(true, |bytes| bytes.is_empty())
    {
        return Err("invalid external Store namespace witness".into());
    }
    Ok(())
}

/// Validate exact, operator-proven role dispositions and preserve every grant field.
/// Role names are opaque: the historical plugin evidence, not a present-day name lookup,
/// establishes whether a rename, unchanged assertion, or retirement is authorized.
pub fn role_bindings_after(spec: &Specification) -> Result<crate::config::RoleBindings, String> {
    let mut after = spec.role_bindings_before.clone();
    let mut sources = BTreeSet::new();
    let mut destinations = BTreeSet::new();
    for disposition in &spec.role_dispositions {
        let source = (disposition.provider.clone(), disposition.old_role.clone());
        if disposition.old_role.is_empty()
            || disposition.old_role.chars().any(char::is_control)
            || !hash(&disposition.historical_provenance_sha256)
            || !hash(&disposition.old_product_sha256)
            || !sources.insert(source)
            || !spec
                .requirements
                .iter()
                .any(|r| r.provider == disposition.provider && !r.format.is_empty())
        {
            return Err("duplicate, unproven or untracked role disposition".into());
        }
        let before = spec
            .role_bindings_before
            .get(&disposition.provider)
            .ok_or("role disposition provider is absent from exact policy inventory")?;
        let grant = before
            .get(&disposition.old_role)
            .ok_or("role disposition source is absent from exact policy inventory")?;
        if let Some(new) = &disposition.new_role {
            if new.is_empty()
                || new.chars().any(char::is_control)
                || !destinations.insert((disposition.provider.clone(), new.clone()))
                || (new != &disposition.old_role && before.contains_key(new))
            {
                return Err("invalid or colliding role disposition destination".into());
            }
        }
        let roles = after
            .get_mut(&disposition.provider)
            .expect("checked provider");
        roles.remove(&disposition.old_role);
        if let Some(new) = &disposition.new_role {
            roles.insert(new.clone(), grant.clone());
        }
    }
    // Format declarations do not promise unchanged role output. Every configured role of a
    // tracked provider needs explicit evidence, including an assertion that its spelling stays.
    for requirement in spec.requirements.iter().filter(|r| !r.format.is_empty()) {
        if let Some(roles) = spec.role_bindings_before.get(&requirement.provider) {
            if roles
                .keys()
                .any(|role| !sources.contains(&(requirement.provider.clone(), role.clone())))
            {
                return Err(
                    "tracked provider role policy lacks an explicit historical disposition".into(),
                );
            }
        }
    }
    Ok(after)
}

fn compare_witness(calls: &dyn StoreCalls, spec: &Specification) -> Result<(), String> {
    let key = hex::decode(&spec.witness.key_hex).map_err(|_| "invalid witness key")?;
    let expected = hex::decode(&spec.witness.value_hex).map_err(|_| "invalid witness value")?;
    let actual = futures::executor::block_on(calls.record_get(&spec.witness.schema, &key))
        .map_err(|e| e.to_string())?;
    if actual.as_ref().map(|v| v.as_slice()) != Some(expected.as_slice()) {
        return Err("Store namespace witness changed".into());
    }
    Ok(())
}

/// Enumerate only actual enforcement cells from the resolved cost model; shared ancestors stay put.
pub fn addresses(
    spec: &Specification,
    groups: &BTreeMap<String, GroupCfg>,
    now: u64,
) -> Result<Vec<(String, String, u64, String)>, String> {
    let cost = crate::cost::CostModel::resolve_parts(None, 0, groups);
    let mut cells = BTreeMap::new();
    for b in &spec.bindings {
        let old = group(&b.old_principal);
        let new = group(&b.new_principal);
        if groups.contains_key(&new) {
            return Err("destination personal group already exists".into());
        }
        if groups
            .values()
            .any(|g| g.parent.as_deref() == Some(old.as_str()))
        {
            return Err(
                "personal group has child references; explicit policy disposition required".into(),
            );
        }
        let mut plain = vec![(b.old_principal.clone(), b.new_principal.clone(), "total")];
        if let Some(g) = cost.group_named(&old) {
            plain.extend(g.buckets.iter().map(|cell| {
                (
                    cell.bucket_id.clone(),
                    crate::cost::group_bucket_id(&new, cell.window, cell.scope.as_ref()),
                    cell.window,
                )
            }));
        }
        for (source, destination, period) in plain {
            let window = super::budget_window(period, now);
            for (source, destination) in [
                (source.clone(), destination.clone()),
                (super::era_bucket(&source), super::era_bucket(&destination)),
            ] {
                if let Some(previous) =
                    cells.insert((source, window), (destination.clone(), period.to_string()))
                {
                    if previous != (destination, period.to_string()) {
                        return Err("ambiguous enforcement bucket mapping".into());
                    }
                }
            }
        }
    }
    let sources: BTreeSet<_> = cells.keys().map(|(s, w)| (s.clone(), *w)).collect();
    let mut destinations = BTreeSet::new();
    let mut result = Vec::new();
    for ((source, window), (destination, period)) in cells {
        if sources.contains(&(destination.clone(), window))
            || !destinations.insert((destination.clone(), window))
        {
            return Err("colliding enforcement bucket destination".into());
        }
        result.push((source, destination, window, period));
    }
    Ok(result)
}

fn target_key(plan: &Plan, key: &VirtualKey) -> Result<VirtualKey, String> {
    let mut after = key.clone();
    for b in &plan.specification.bindings {
        if key.group.as_deref() == Some(group(&b.new_principal).as_str())
            || key.idp_subject.as_deref() == Some(&b.new_principal)
            || key.id == b.new_principal
        {
            return Err("destination principal already has key state".into());
        }
        let bound = key.idp_subject.as_deref() == Some(&b.old_principal);
        if bound && key.idp_provider.as_deref() != Some(&b.provider) {
            return Err("historical provider differs from exact principal mapping".into());
        }
        if key.deleted_at.is_some() {
            continue;
        }
        if key.group.as_deref() == Some(group(&b.old_principal).as_str()) {
            after.group = Some(group(&b.new_principal));
        }
        if bound {
            after.idp_subject = Some(b.new_principal.clone());
        }
    }
    Ok(after)
}

fn holds(plan: &Plan) -> BTreeSet<String> {
    let prior = plan.previous.as_ref().map(|p| &p.holds);
    let mut held = prior.cloned().unwrap_or_default();
    held.extend(
        plan.specification
            .bindings
            .iter()
            .filter(|b| {
                prior.is_some_and(|held| held.contains(&b.old_principal))
                    || plan.denylist_before.contains(&b.old_principal)
                    || plan.keys_before.iter().any(|k| {
                        (k.idp_subject.as_deref() == Some(&b.old_principal)
                            || k.group.as_deref() == Some(group(&b.old_principal).as_str()))
                            && !plan
                                .specification
                                .rotations
                                .iter()
                                .any(|rotation| rotation.retired_key_id == k.id)
                            && (!k.enabled
                                || k.deleted_at.is_some()
                                || plan.denylist_before.contains(&k.id))
                    })
            })
            .map(|b| b.new_principal.clone()),
    );
    held
}

fn held_principals(plan: &Plan) -> BTreeMap<String, String> {
    let mut active = plan
        .previous
        .as_ref()
        .map(|p| p.held_principals.clone())
        .unwrap_or_default();
    let held = holds(plan);
    for binding in &plan.specification.bindings {
        active.remove(&binding.old_principal);
        if held.contains(&binding.new_principal) {
            active.insert(binding.new_principal.clone(), binding.provider.clone());
        }
    }
    active
}

fn binding_covers_key(binding: &Binding, key: &VirtualKey) -> bool {
    key.idp_provider.as_deref() == Some(binding.provider.as_str())
        && (key.idp_subject.as_deref() == Some(binding.old_principal.as_str())
            || (key.idp_subject.is_none()
                && key.group.as_deref() == Some(group(&binding.old_principal).as_str())))
}

fn carried_denials(plan: &Plan) -> BTreeSet<String> {
    plan.specification
        .bindings
        .iter()
        .filter(|b| plan.denylist_before.contains(&b.old_principal))
        .map(|b| b.new_principal.clone())
        .collect()
}

pub fn after_overlay(plan: &Plan) -> Result<OverlayDoc, String> {
    let mut after = plan.overlay_before.clone().unwrap_or_default();
    for b in &plan.specification.bindings {
        if let Some(original) = plan.groups_before.get(&group(&b.old_principal)) {
            let name = group(&b.new_principal);
            if after.groups.contains_key(&name) || after.deleted_groups.contains(&name) {
                return Err("destination group has retained overlay state".into());
            }
            after.groups.insert(name, original.clone());
        }
    }
    if !plan.specification.role_dispositions.is_empty() {
        let roles = role_bindings_after(&plan.specification)?;
        let patch = crate::config::document_patch::DocumentPatch::from_value(
            serde_json::json!({"set": {"/auth/role_bindings": roles}}),
        )
        .map_err(|e| e.to_string())?;
        // Ordered composition also handles a preceding whole-auth edit without losing it.
        after.document_patch = Some(match after.document_patch.take() {
            Some(previous) if previous.paths().next().is_none() => patch,
            Some(previous) => {
                let mut value = serde_json::to_value(previous).map_err(|e| e.to_string())?;
                let mut stages = value
                    .get_mut("$stages")
                    .and_then(serde_json::Value::as_array_mut)
                    .map(std::mem::take)
                    .unwrap_or_else(|| vec![value]);
                stages.push(serde_json::to_value(patch).map_err(|e| e.to_string())?);
                serde_json::from_value(serde_json::json!({"$stages": stages}))
                    .map_err(|e| e.to_string())?
            }
            None => patch,
        });
    }
    after.version = crate::config::overlay::OVERLAY_VERSION;
    Ok(after)
}

pub fn prepare(
    specification: Specification,
    store: &dyn RecordStore,
    calls: Arc<dyn StoreCalls>,
    groups: BTreeMap<String, GroupCfg>,
    overlay: Option<OverlayDoc>,
) -> Result<Plan, String> {
    validate_spec(&specification)?;
    compare_witness(calls.as_ref(), &specification)?;
    let previous = read_head(&StoreRows(calls.clone()))?
        .map(|(head, bytes)| {
            if !head.complete || head.depth >= 64 || head.store_config_sha256 != specification.store_config_sha256 {
                return Err("predecessor must be complete, within the 64-generation bound and on the same Store".to_string());
            }
            Ok(previous_receipt(&head, &bytes))
        }).transpose()?;
    let mut keys_before = store.list_keys().map_err(|e| e.to_string())?;
    keys_before.sort_by(|a, b| a.id.cmp(&b.id));
    let mut denylist_before = store.list_denylist().map_err(|e| e.to_string())?;
    denylist_before.sort();
    let mut carry = Vec::new();
    for (source, destination, window, period) in
        addresses(&specification, &groups, specification.cutover)?
    {
        if store
            .get_usage(&destination, window)
            .map_err(|e| e.to_string())?
            != UsageLedger::default()
        {
            return Err("destination usage is occupied; merging is forbidden".into());
        }
        let raw = store
            .get_usage(&source, window)
            .map_err(|e| e.to_string())?;
        carry.push(Carry {
            source,
            destination,
            window,
            period,
            raw,
        });
    }
    let plan = Plan {
        specification,
        previous,
        keys_before,
        denylist_before,
        groups_before: groups,
        overlay_before: overlay,
        carry,
    };
    validate_plan(&plan)?;
    Ok(plan)
}

pub fn validate_plan(plan: &Plan) -> Result<(), String> {
    validate_spec(&plan.specification)?;
    // The existing overlay wire must preserve every policy field. Do not normalize an opaque
    // scope into a different kind merely because the current config grammar cannot encode it.
    let roundtrip: BTreeMap<String, GroupCfg> = serde_json::from_value(
        serde_json::to_value(&plan.groups_before).map_err(|_| "group serialization failed")?,
    )
    .map_err(|_| "group policy cannot round-trip through existing overlay grammar")?;
    if roundtrip != plan.groups_before {
        return Err("group policy is not lossless in existing overlay grammar".into());
    }
    let expected = addresses(
        &plan.specification,
        &plan.groups_before,
        plan.specification.cutover,
    )?;
    let actual: Vec<_> = plan
        .carry
        .iter()
        .map(|c| {
            (
                c.source.clone(),
                c.destination.clone(),
                c.window,
                c.period.clone(),
            )
        })
        .collect();
    if expected != actual {
        return Err("plan does not cover exact enforcement cells".into());
    }
    if let Some(previous) = &plan.previous {
        if !hash(&previous.head_sha256)
            || tracked(&previous.requirements).any(|old| {
                !tracked(&plan.specification.requirements)
                    .any(|new| old.provider == new.provider && old.plugin == new.plugin)
            })
        {
            return Err("successor must preserve every tracked provider lineage".into());
        }
    }
    let stable = |requirement: &Requirement| {
        plan.previous.as_ref().is_some_and(|previous| {
            previous.requirements.iter().any(|old| {
                same_identity_domains(std::slice::from_ref(old), std::slice::from_ref(requirement))
            })
        })
    };
    let changed: BTreeSet<_> = plan
        .specification
        .requirements
        .iter()
        .filter(|requirement| {
            !requirement.format.is_empty()
                && (!stable(requirement)
                    || plan
                        .specification
                        .bindings
                        .iter()
                        .any(|b| b.provider == requirement.provider))
        })
        .map(|requirement| requirement.provider.as_str())
        .collect();
    if let Some(previous) = &plan.previous {
        for (principal, provider) in &previous.held_principals {
            let requirement = plan
                .specification
                .requirements
                .iter()
                .find(|r| r.provider == *provider && !r.format.is_empty())
                .ok_or("held predecessor principal lost its tracked provider")?;
            let binding = plan
                .specification
                .bindings
                .iter()
                .find(|b| b.old_principal == *principal);
            if !previous.holds.contains(principal)
                || binding.is_some_and(|b| b.provider != *provider)
                || (!stable(requirement) && binding.is_none())
            {
                return Err(
                    "changed identity domain omits or reassigns a known held predecessor principal"
                        .into(),
                );
            }
        }
        if plan
            .specification
            .bindings
            .iter()
            .any(|b| previous.held_principals.contains_key(&b.new_principal))
        {
            return Err(
                "destination already has active held identity provenance; merging is forbidden"
                    .into(),
            );
        }
    }
    let mapped_groups: BTreeSet<_> = plan
        .specification
        .bindings
        .iter()
        .map(|binding| group(&binding.old_principal))
        .collect();
    let mut unaffected_groups = BTreeSet::new();
    let mut unaffected_keys = BTreeSet::new();
    for disposition in &plan.specification.unaffected {
        let name = group(&disposition.principal);
        let requirement = plan
            .specification
            .requirements
            .iter()
            .find(|r| r.provider == disposition.provider)
            .ok_or("unaffected principal has no exact admitted provider provenance")?;
        let keys: Vec<_> = plan
            .keys_before
            .iter()
            .filter(|k| {
                k.group.as_deref() == Some(name.as_str())
                    || k.idp_subject.as_deref() == Some(disposition.principal.as_str())
            })
            .collect();
        if !identity(&disposition.principal)
            || !hash(&disposition.provenance_sha256)
            || (!requirement.format.is_empty() && !stable(requirement))
            || changed.contains(requirement.provider.as_str())
            || !unaffected_groups.insert(name.clone())
            || mapped_groups.contains(&name)
            || plan
                .specification
                .bindings
                .iter()
                .any(|b| b.new_principal == disposition.principal)
            || keys.is_empty()
            || keys.iter().any(|k| {
                k.idp_provider.as_deref() != Some(disposition.provider.as_str())
                    || k.idp_subject
                        .as_deref()
                        .is_some_and(|subject| subject != disposition.principal)
            })
            || digest(requirement)? != disposition.requirement_sha256
            || digest(&keys)? != disposition.keys_sha256
            || digest(&plan.groups_before.get(&name))? != disposition.group_sha256
        {
            return Err("unaffected principal requires exact unrelated provider, key/group preimages and historical provenance".into());
        }
        unaffected_keys.extend(keys.iter().map(|k| k.id.as_str()));
    }
    // An immutable predecessor proves only the exact retired records and old policy it retained.
    // A new/changed row in an old personal group is not historical just because its name matches.
    for key in &plan.keys_before {
        let historical = key.deleted_at.is_some()
            && plan
                .previous
                .as_ref()
                .and_then(|p| p.retired_keys.get(&key.id))
                .is_some_and(|expected| digest(key).as_ref() == Ok(expected));
        if !historical
            && key
                .idp_provider
                .as_deref()
                .is_some_and(|provider| changed.contains(provider))
        {
            let covered = plan
                .specification
                .bindings
                .iter()
                .any(|binding| binding_covers_key(binding, key));
            if !covered {
                return Err("retained changed-provider identity is omitted from the explicit transition inventory".into());
            }
        }
        if key.group.as_deref().is_some_and(|name| {
            name.starts_with(super::SELF_KEY_GROUP_PREFIX)
                && !mapped_groups.contains(name)
                && !unaffected_keys.contains(key.id.as_str())
                && !historical
        }) {
            return Err(
                "retained personal key group is omitted from the explicit transition inventory"
                    .into(),
            );
        }
    }
    for (name, policy) in &plan.groups_before {
        if name.starts_with(super::SELF_KEY_GROUP_PREFIX)
            && !mapped_groups.contains(name)
            && !unaffected_groups.contains(name)
            && !plan
                .previous
                .as_ref()
                .and_then(|p| p.historical_groups.get(name))
                .is_some_and(|expected| digest(policy).as_ref() == Ok(expected))
        {
            return Err(
                "retained personal group is omitted from the explicit transition inventory".into(),
            );
        }
    }
    let mut retired = BTreeSet::new();
    for rotation in &plan.specification.rotations {
        let old = plan
            .keys_before
            .iter()
            .find(|key| key.id == rotation.retired_key_id)
            .ok_or("rotation retirement row missing")?;
        let new = plan
            .keys_before
            .iter()
            .find(|key| key.id == rotation.successor_key_id)
            .ok_or("rotation successor row missing")?;
        let generation = |key: &VirtualKey| {
            super::binding_generation(&key.generation_hash)
                .and_then(|generation| generation.parse::<u64>().ok())
        };
        if !retired.insert(&old.id)
            || old.deleted_at.is_none()
            || old.enabled
            || !new.enabled
            || new.deleted_at.is_some()
            || old.binding_mode.as_deref() != Some(super::SELF_KEY_BINDING_MODE)
            || new.binding_mode.as_deref() != Some(super::SELF_KEY_BINDING_MODE)
            || old.idp_subject.is_none()
            || old.idp_subject != new.idp_subject
            || old.idp_provider.is_none()
            || old.idp_provider != new.idp_provider
            || old.group != new.group
            || plan.denylist_before.contains(&old.id)
            || plan.denylist_before.contains(&new.id)
            || !matches!((generation(old),generation(new)),(Some(old),Some(new)) if new > old)
            || digest(old)? != rotation.retired_key_sha256
            || digest(new)? != rotation.successor_key_sha256
            || !hash(&rotation.evidence_sha256)
        {
            return Err(
                "rotation disposition does not prove exact retired and live successor rows".into(),
            );
        }
    }
    for binding in &plan.specification.bindings {
        let belongs = |key: &&VirtualKey| {
            key.idp_subject.as_deref() == Some(binding.old_principal.as_str())
                || key.group.as_deref() == Some(group(&binding.old_principal).as_str())
        };
        let history: Vec<_> = plan.keys_before.iter().filter(belongs).collect();
        if history
            .iter()
            .any(|key| key.deleted_at.is_some() && !retired.contains(&key.id))
            && history.iter().any(|key| {
                key.enabled && key.deleted_at.is_none() && !plan.denylist_before.contains(&key.id)
            })
        {
            return Err("tombstoned SELF history with a live successor needs explicit rotation versus revocation disposition before migration".into());
        }
    }
    let mut ids = BTreeSet::new();
    for k in &plan.keys_before {
        if !ids.insert(&k.id) {
            return Err("duplicate key in transition inventory".into());
        }
        target_key(plan, k)?;
    }
    after_overlay(plan)?;
    let mut groups = plan.groups_before.clone();
    for binding in &plan.specification.bindings {
        if let Some(original) = plan.groups_before.get(&group(&binding.old_principal)) {
            groups.insert(group(&binding.new_principal), original.clone());
        }
    }
    let mut errors = Vec::new();
    crate::config::groups::validate_groups(&groups, &|_| true, &mut errors);
    if !errors.is_empty() {
        return Err(
            "migrated group graph has invalid policy or colliding enforcement buckets".into(),
        );
    }
    Ok(())
}

fn chunk_key(prefix: &[u8], index: usize) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(&(index as u64).to_be_bytes());
    key
}

fn chunks(prefix: &[u8], bytes: &[u8]) -> Result<Vec<Mutation>, String> {
    if bytes.is_empty() || bytes.len() > MAX_PLAN_BYTES {
        return Err("principal transition document exceeds its bounded journal capacity".into());
    }
    Ok(bytes
        .chunks(busbar_contract::MAX_RECORD_BYTES)
        .enumerate()
        .map(|(index, value)| Mutation::Put {
            schema: SCHEMA.as_str().into(),
            key: chunk_key(prefix, index),
            value: value.to_vec(),
        })
        .collect())
}

fn read_body(rows: &dyn RecordRows, prefix: &[u8], length: usize) -> Result<Vec<u8>, String> {
    if length == 0 || length > MAX_PLAN_BYTES {
        return Err("invalid principal journal length".into());
    }
    let mut body = Vec::with_capacity(length);
    for index in 0..length.div_ceil(busbar_contract::MAX_RECORD_BYTES) {
        let chunk = rows
            .record_get(SCHEMA, &chunk_key(prefix, index))
            .map_err(|e| e.to_string())?
            .ok_or("incomplete principal transition journal")?;
        if chunk.as_slice().len() != (length - body.len()).min(busbar_contract::MAX_RECORD_BYTES) {
            return Err("invalid principal transition journal chunk".into());
        }
        body.extend_from_slice(chunk.as_slice());
    }
    Ok(body)
}

fn read_head(rows: &dyn RecordRows) -> Result<Option<(Head, Vec<u8>)>, String> {
    let Some(bytes) = rows.record_get(SCHEMA, HEAD).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let head = read_generation(rows, bytes.as_slice(), 0)?;
    Ok(Some((head, bytes.as_slice().to_vec())))
}

fn read_generation(rows: &dyn RecordRows, bytes: &[u8], depth: usize) -> Result<Head, String> {
    if depth >= 64 {
        return Err("principal receipt ancestry exceeds 64 generations".into());
    }
    let mut head: Head =
        serde_json::from_slice(bytes).map_err(|_| "invalid principal transition fence")?;
    let previous = if let Some(reference) = &head.previous {
        if !hash(reference) {
            return Err("invalid principal predecessor reference".into());
        }
        let bytes = rows
            .record_get(SCHEMA, format!("ancestor:{reference}").as_bytes())
            .map_err(|e| e.to_string())?
            .ok_or("missing immutable principal predecessor")?;
        if hex::encode(Sha256::digest(bytes.as_slice())) != *reference {
            return Err("principal predecessor digest mismatch".into());
        }
        let prior = read_generation(rows, bytes.as_slice(), depth + 1)?;
        if !prior.complete {
            return Err("principal predecessor is not complete".into());
        }
        head.depth = prior.depth + 1;
        head.retired_keys = prior.retired_keys.clone();
        head.historical_groups = prior.historical_groups.clone();
        Some(previous_receipt(&prior, bytes.as_slice()))
    } else {
        head.depth = 1;
        None
    };
    if head.version != 1
        || !hash(&head.plan_sha256)
        || head.length == 0
        || head.length > MAX_PLAN_BYTES
    {
        return Err("invalid principal transition fence".into());
    }
    let body = read_body(rows, &body_prefix(&head.plan_sha256), head.length)?;
    if head.fresh {
        let receipt: FreshNamespace = serde_json::from_slice(&body)
            .map_err(|_| "invalid durable namespace creation evidence")?;
        if !head.complete
            || head.rollover.is_some()
            || previous.is_some()
            || digest(&receipt)? != head.plan_sha256
        {
            return Err("principal baseline differs from creation evidence".into());
        }
        head.store_config_sha256 = receipt.store_config_sha256;
        head.requirements = receipt.requirements;
    } else {
        let plan: Plan = serde_json::from_slice(&body)
            .map_err(|_| "invalid durable principal transition plan")?;
        if digest(&plan)? != head.plan_sha256 || plan.previous != previous {
            return Err(
                "principal transition receipt differs from immutable plan/predecessor".into(),
            );
        }
        for key in &plan.keys_before {
            // Only an explicit completed mapping establishes this row as historical identity
            // evidence. An unrelated unaffected tombstone was never transitioned.
            if key.deleted_at.is_some()
                && plan
                    .specification
                    .bindings
                    .iter()
                    .any(|binding| binding_covers_key(binding, key))
            {
                head.retired_keys.insert(key.id.clone(), digest(key)?);
            }
        }
        for binding in &plan.specification.bindings {
            if let Some(policy) = plan.groups_before.get(&group(&binding.old_principal)) {
                head.historical_groups
                    .insert(group(&binding.old_principal), digest(policy)?);
            }
        }
        if let Some(reference) = &head.rollover {
            if !hash(&reference.digest) {
                return Err("invalid rollover journal reference".into());
            }
            let body = read_body(
                rows,
                format!("rollover:{}:", reference.digest).as_bytes(),
                reference.length,
            )?;
            let rollover: Rollover =
                serde_json::from_slice(&body).map_err(|_| "invalid rollover journal")?;
            if digest(&rollover)? != reference.digest
                || rollover.baseline_sha256 != head.plan_sha256
                || rollover.clock < plan.specification.cutover
            {
                return Err("rollover journal differs from immutable transition plan".into());
            }
            let mut seen = BTreeSet::new();
            for carry in &rollover.carry {
                let possible = addresses(&plan.specification, &plan.groups_before, carry.window)?;
                if !possible.contains(&(
                    carry.source.clone(),
                    carry.destination.clone(),
                    carry.window,
                    carry.period.clone(),
                )) || !seen.insert((carry.source.clone(), carry.window))
                {
                    return Err("invalid rollover enforcement address".into());
                }
            }
            head.extra_carry = rollover.carry;
        }
        head.holds = holds(&plan);
        head.held_principals = held_principals(&plan);
        head.store_config_sha256 = plan.specification.store_config_sha256;
        head.requirements = plan.specification.requirements;
    }
    if let Some(reference) = &head.authorization {
        if !head.complete || !hash(&reference.digest) {
            return Err("invalid principal reauthorization reference".into());
        }
        let body = read_body(
            rows,
            format!("authorization:{}:", reference.digest).as_bytes(),
            reference.length,
        )?;
        let authorization: Reauthorization =
            serde_json::from_slice(&body).map_err(|_| "invalid principal reauthorization")?;
        if digest(&authorization)? != reference.digest
            || authorization.baseline_sha256 != head.plan_sha256
            || !authorization.identity_outputs_unchanged
            || !same_formats(&head.requirements, &authorization.requirements)
        {
            return Err("principal reauthorization differs from immutable baseline".into());
        }
        head.requirements = authorization.requirements;
    }
    Ok(head)
}

/// Early anchor-store fence, including safe mode, before effective config is recovered.
pub fn pending_guard(calls: Arc<dyn StoreCalls>) -> Result<(), String> {
    if read_head(&StoreRows(calls))?.is_some_and(|(head, _)| !head.complete) {
        return Err("principal transition is pending; normal serving is fenced".into());
    }
    Ok(())
}

/// Called on every boot and replacement App before governance or any request writer is started.
/// Absence is safe only when no active auth artifact declares a changed principal format.
pub fn guard(
    calls: Arc<dyn StoreCalls>,
    store_sha256: &str,
    required: &[Requirement],
) -> Result<BTreeSet<String>, String> {
    let rows = StoreRows(calls);
    let Some((head, _)) = read_head(&rows)? else {
        return if required.iter().all(|r| r.format.is_empty()) {
            Ok(BTreeSet::new())
        } else {
            Err("principal format requires an explicit fresh-namespace baseline or completed cold transition".into())
        };
    };
    if !head.complete {
        return Err("principal transition is pending; normal serving is fenced".into());
    }
    if head.store_config_sha256 != store_sha256 {
        return Err("principal transition Store binding changed".into());
    }
    // Persisted marked entries identify the tracked lineage even if the current config removes
    // their marker or alias. Unrelated unmarked providers use ordinary auth revalidation.
    if !same_identity_domains(&head.requirements, required) {
        return Err(
            "active auth product/config lacks matching principal continuity receipt".into(),
        );
    }
    Ok(head.holds)
}

fn operation(plan_sha256: &str, phase: &str) -> OpId {
    let digest = Sha256::digest(format!("principal-transition:{plan_sha256}:{phase}"));
    OpId(digest[..16].try_into().expect("SHA256 has sixteen bytes"))
}

fn transaction(rows: &dyn RecordRows, request: Request) -> Result<(), String> {
    request.encode_held().map_err(|e| e.to_string())?;
    match rows.record_transaction(&request).map_err(|_| "transition transaction outcome uncertain; keep senders stopped and settle backend commands before a new attested resume")? {
        Decision::Applied => Ok(()),
        Decision::ConditionConflict => Err("principal transition conditional state changed".into()),
    }
}

fn same_key(actual: &VirtualKey, expected: &VirtualKey) -> bool {
    let mut actual = actual.clone();
    // The Store owns monotonically allocated revisions. No authority field is normalized.
    if actual.revision < expected.revision {
        return false;
    }
    actual.revision = expected.revision;
    actual == *expected
}

fn inspect(
    plan: &Plan,
    store: &dyn RecordStore,
    overlay: &OverlayStore,
    now: u64,
    allow_after: bool,
) -> Result<(), String> {
    validate_plan(plan)?;
    if now < plan.specification.cutover {
        return Err("cutover clock moved backwards".into());
    }
    let keys = store.list_keys().map_err(|e| e.to_string())?;
    if keys.len() != plan.keys_before.len() {
        return Err("key inventory changed".into());
    }
    for expected in &plan.keys_before {
        let actual = keys
            .iter()
            .find(|k| k.id == expected.id)
            .ok_or("key inventory changed")?;
        if actual != expected && !(allow_after && same_key(actual, &target_key(plan, expected)?)) {
            return Err("key preimage changed".into());
        }
    }
    let mut denied = store.list_denylist().map_err(|e| e.to_string())?;
    denied.sort();
    let mut allowed_denials: BTreeSet<_> = plan.denylist_before.iter().cloned().collect();
    if allow_after {
        allowed_denials.extend(carried_denials(plan));
    }
    if plan.denylist_before.iter().any(|id| !denied.contains(id))
        || denied.iter().any(|id| !allowed_denials.contains(id))
    {
        return Err("revocation inventory changed".into());
    }
    for c in &plan.carry {
        if store
            .get_usage(&c.source, c.window)
            .map_err(|e| e.to_string())?
            != c.raw
        {
            return Err("source usage preimage changed".into());
        }
        let actual = store
            .get_usage(&c.destination, c.window)
            .map_err(|e| e.to_string())?;
        if actual != UsageLedger::default() && !(allow_after && actual == c.raw) {
            return Err("destination usage preimage changed".into());
        }
    }
    let actual = overlay.read_required()?;
    if digest(&actual)? != digest(&plan.overlay_before)?
        && !(allow_after && digest(&actual)? == digest(&Some(after_overlay(plan)?))?)
    {
        return Err("overlay preimage changed".into());
    }
    Ok(())
}

pub fn check(
    plan: &Plan,
    store: &dyn RecordStore,
    calls: Arc<dyn StoreCalls>,
    overlay: &OverlayStore,
    now: u64,
    effective_config_sha256: &str,
) -> Result<(), String> {
    if effective_config_sha256 != plan.specification.effective_config_sha256 {
        return Err("effective configuration changed".into());
    }
    compare_witness(calls.as_ref(), &plan.specification)?;
    let rows = StoreRows(calls);
    let existing = read_head(&rows)?;
    let plan_digest = digest(plan)?;
    let resuming = existing
        .as_ref()
        .is_some_and(|(head, _)| head.plan_sha256 == plan_digest);
    if !resuming {
        let actual_previous = existing
            .as_ref()
            .map(|(head, bytes)| previous_receipt(head, bytes));
        if plan.previous != actual_previous
            || existing.as_ref().is_some_and(|(head, _)| {
                !head.complete
                    || head.depth >= 64
                    || head.store_config_sha256 != plan.specification.store_config_sha256
            })
        {
            return Err(
                "another principal transition owns the Store fence or predecessor changed".into(),
            );
        }
        if plan
            .carry
            .iter()
            .any(|carry| super::budget_window(&carry.period, now) != carry.window)
        {
            return Err("initial plan crossed an enforcement window; prepare a current plan before starting".into());
        }
    }
    if let Some((head, _)) = &existing {
        if resuming {
            inspect_extra(store, &head.extra_carry, false)?;
        }
    }
    inspect(plan, store, overlay, now, resuming)
}

fn inspect_extra(store: &dyn RecordStore, carry: &[Carry], complete: bool) -> Result<(), String> {
    for cell in carry {
        if store
            .get_usage(&cell.source, cell.window)
            .map_err(|e| e.to_string())?
            != cell.raw
        {
            return Err("rollover source usage preimage changed".into());
        }
        let actual = store
            .get_usage(&cell.destination, cell.window)
            .map_err(|e| e.to_string())?;
        if actual != cell.raw && (complete || actual != UsageLedger::default()) {
            return Err("rollover destination usage preimage changed".into());
        }
    }
    Ok(())
}

/// Apply only in a cold process. No callers, recovery tasks, corrections or flushers may exist.
pub fn apply(
    plan: &Plan,
    attestation: &ColdAttestation,
    store: &dyn RecordStore,
    calls: Arc<dyn StoreCalls>,
    overlay: &OverlayStore,
    now: u64,
    effective_config_sha256: &str,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    check(
        plan,
        store,
        calls.clone(),
        overlay,
        now,
        effective_config_sha256,
    )?;
    let plan_sha256 = digest(plan)?;
    let epoch = hex::decode(&attestation.epoch).map_err(|_| "invalid quiescence epoch")?;
    if attestation.version != 1
        || epoch.len() != 16
        || epoch.iter().all(|b| *b == 0)
        || attestation.plan_sha256 != plan_sha256
        || !attestation.sender_quiesced
        || !attestation.backend_quiesced
        || !attestation.recovery_and_corrections_settled
        || attestation.actor.trim().is_empty()
        || attestation.reason.trim().is_empty()
    {
        return Err("explicit fresh sender/backend quiescence attestation required".into());
    }
    let rows = StoreRows(calls.clone());
    if !rows.supports_record_transaction() {
        return Err("principal transition requires conditional records".into());
    }
    let previous = read_head(&rows)?;
    let resuming = previous
        .as_ref()
        .is_some_and(|(h, _)| h.plan_sha256 == plan_sha256);
    if resuming && previous.as_ref().is_some_and(|(h, _)| h.complete) {
        return verify(plan, store, calls, overlay, now);
    }
    let mut extra = if resuming {
        previous
            .as_ref()
            .map_or_else(Vec::new, |(head, _)| head.extra_carry.clone())
    } else {
        Vec::new()
    };
    for (source, destination, window, period) in
        addresses(&plan.specification, &plan.groups_before, now)?
    {
        if plan
            .carry
            .iter()
            .chain(extra.iter())
            .any(|carry| carry.source == source && carry.window == window)
        {
            continue;
        }
        if store
            .get_usage(&destination, window)
            .map_err(|e| e.to_string())?
            != UsageLedger::default()
        {
            return Err("rollover destination is occupied; implicit merging is forbidden".into());
        }
        let raw = store
            .get_usage(&source, window)
            .map_err(|e| e.to_string())?;
        extra.push(Carry {
            source,
            destination,
            window,
            period,
            raw,
        });
    }
    let plan_bytes = canonical_bytes(plan)?;
    let mut mutations = chunks(&body_prefix(&plan_sha256), &plan_bytes)?;
    if !resuming {
        if let Some((_, bytes)) = &previous {
            mutations.push(Mutation::Put {
                schema: SCHEMA.as_str().into(),
                key: format!("ancestor:{}", hex::encode(Sha256::digest(bytes))).into_bytes(),
                value: bytes.clone(),
            });
        }
    }
    let rollover = if extra.is_empty() {
        None
    } else {
        let rollover = Rollover {
            baseline_sha256: plan_sha256.clone(),
            clock: now,
            carry: extra.clone(),
        };
        let digest = digest(&rollover)?;
        let body = serde_json::to_vec(&rollover).map_err(|e| e.to_string())?;
        mutations.extend(chunks(format!("rollover:{digest}:").as_bytes(), &body)?);
        Some(AuthorizationRef {
            digest,
            length: body.len(),
        })
    };
    let head = Head {
        version: 1,
        plan_sha256: plan_sha256.clone(),
        length: plan_bytes.len(),
        fresh: false,
        previous: plan.previous.as_ref().map(|p| p.head_sha256.clone()),
        retired_keys: Default::default(),
        historical_groups: Default::default(),
        depth: 0,
        store_config_sha256: plan.specification.store_config_sha256.clone(),
        requirements: plan.specification.requirements.clone(),
        holds: holds(plan),
        held_principals: held_principals(plan),
        complete: false,
        authorization: None,
        rollover,
        extra_carry: extra.clone(),
    };
    let pending = serde_json::to_vec(&head).map_err(|e| e.to_string())?;
    let mut epoch_key = b"quiescence:".to_vec();
    epoch_key.extend_from_slice(&epoch);
    if rows
        .record_get(SCHEMA, &epoch_key)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err(
            "quiescence attestation already consumed; obtain a new backend-settled attestation"
                .into(),
        );
    }
    // New invocation, new epoch. Replaying a consumed attestation never establishes quiescence.
    let mut predicates = vec![
        Predicate {
            schema: SCHEMA.as_str().into(),
            key: epoch_key.clone(),
            expected: Expected::Absent,
        },
        Predicate {
            schema: SCHEMA.as_str().into(),
            key: HEAD.to_vec(),
            expected: previous
                .as_ref()
                .map_or(Expected::Absent, |(_, b)| Expected::Bytes(b.clone())),
        },
    ];
    predicates.push(Predicate {
        schema: plan.specification.witness.schema.clone(),
        key: hex::decode(&plan.specification.witness.key_hex).map_err(|_| "invalid witness")?,
        expected: Expected::Bytes(
            hex::decode(&plan.specification.witness.value_hex).map_err(|_| "invalid witness")?,
        ),
    });
    transaction(
        &rows,
        Request {
            version: VERSION,
            op_id: operation(&plan_sha256, &format!("begin:{}", attestation.epoch)),
            predicates,
            mutations: {
                mutations.push(Mutation::Put {
                    schema: SCHEMA.as_str().into(),
                    key: HEAD.to_vec(),
                    value: pending.clone(),
                });
                // A compact consumed marker plus bounded immutable attestation chunks.
                mutations.push(Mutation::Put {
                    schema: SCHEMA.as_str().into(),
                    key: epoch_key.clone(),
                    value: digest(attestation)?.into_bytes(),
                });
                epoch_key.extend_from_slice(b":body:");
                mutations.extend(chunks(
                    &epoch_key,
                    &serde_json::to_vec(attestation).map_err(|e| e.to_string())?,
                )?);
                mutations
            },
        },
    )?;
    // Existing vk revocations retain their IDs; an explicitly mapped direct-principal denial is
    // also carried forward. No denial is removed and no credential is recreated.
    for principal in carried_denials(plan) {
        if !store
            .list_denylist()
            .map_err(|e| e.to_string())?
            .contains(&principal)
        {
            store
                .add_denylist(&principal, "explicit cold principal transition denial")
                .map_err(|_| {
                    "denylist write uncertain; fence retained; settle backend before resume"
                })?;
        }
    }
    // All mutations are absolute. Unknown replies leave the durable pending fence in place.
    for c in plan.carry.iter().chain(extra.iter()) {
        let current = store
            .get_usage(&c.destination, c.window)
            .map_err(|e| e.to_string())?;
        if current != c.raw {
            store.put_usage(&c.destination,c.window,&c.raw).map_err(|_|"usage write uncertain; fence retained; settle backend and obtain a new quiescence attestation")?;
        }
    }
    for before in &plan.keys_before {
        let after = target_key(plan, before)?;
        if after == *before {
            continue;
        }
        let current = store
            .get_key(&before.id)
            .map_err(|e| e.to_string())?
            .ok_or("key disappeared")?;
        if !same_key(&current, &after) {
            store.put_key(&after).map_err(|_|"key write uncertain; fence retained; settle backend and obtain a new quiescence attestation")?;
        }
    }
    let after = after_overlay(plan)?;
    if digest(&overlay.read_required()?)? != digest(&Some(&after))? {
        crate::config::overlay::write(overlay,&after).map_err(|_|"overlay write uncertain; fence retained; settle backend and obtain a new quiescence attestation")?;
    }
    let elapsed = started.elapsed();
    let completion_clock = now
        .checked_add(elapsed.as_secs())
        .and_then(|clock| clock.checked_add(u64::from(elapsed.subsec_nanos() != 0)))
        .ok_or("cutover clock overflow; transition remains fenced")?;
    verify_poststate(plan, store, overlay, completion_clock, &extra)?;
    let complete = Head {
        complete: true,
        ..head
    };
    transaction(
        &rows,
        Request {
            version: VERSION,
            op_id: operation(&plan_sha256, &format!("complete:{}", digest(&complete)?)),
            predicates: vec![Predicate {
                schema: SCHEMA.as_str().into(),
                key: HEAD.to_vec(),
                expected: Expected::Bytes(pending),
            }],
            mutations: vec![Mutation::Put {
                schema: SCHEMA.as_str().into(),
                key: HEAD.to_vec(),
                value: serde_json::to_vec(&complete).map_err(|e| e.to_string())?,
            }],
        },
    )
}

fn verify_poststate(
    plan: &Plan,
    store: &dyn RecordStore,
    overlay: &OverlayStore,
    now: u64,
    extra: &[Carry],
) -> Result<(), String> {
    inspect(plan, store, overlay, now, true)?;
    inspect_extra(store, extra, true)?;
    for (source, _, window, _) in addresses(&plan.specification, &plan.groups_before, now)? {
        if !plan
            .carry
            .iter()
            .chain(extra.iter())
            .any(|carry| carry.source == source && carry.window == window)
        {
            return Err("completion crossed an enforcement window; resume SAME plan with a new settled attestation to reconcile current windows".into());
        }
    }
    let denied = store.list_denylist().map_err(|e| e.to_string())?;
    if carried_denials(plan).iter().any(|id| !denied.contains(id)) {
        return Err("incomplete principal denial transition".into());
    }
    for c in &plan.carry {
        if store
            .get_usage(&c.destination, c.window)
            .map_err(|e| e.to_string())?
            != c.raw
        {
            return Err("incomplete usage carry".into());
        }
    }
    for before in &plan.keys_before {
        let current = store
            .get_key(&before.id)
            .map_err(|e| e.to_string())?
            .ok_or("missing migrated key")?;
        if !same_key(&current, &target_key(plan, before)?) {
            return Err("incomplete key transition".into());
        }
    }
    if digest(&overlay.read_required()?)? != digest(&Some(after_overlay(plan)?))? {
        return Err("incomplete group transition".into());
    }
    Ok(())
}

pub fn verify(
    plan: &Plan,
    store: &dyn RecordStore,
    calls: Arc<dyn StoreCalls>,
    overlay: &OverlayStore,
    now: u64,
) -> Result<(), String> {
    compare_witness(calls.as_ref(), &plan.specification)?;
    let rows = StoreRows(calls);
    let (head, _) = read_head(&rows)?.ok_or("missing transition receipt")?;
    if !head.complete || head.plan_sha256 != digest(plan)? {
        return Err("transition has no matching completed receipt".into());
    }
    verify_poststate(plan, store, overlay, now, &head.extra_carry)
}

/// Read a generic annotation from the admitted auth schema, never provider protocol fields.
/// Linked auth code is bound to the complete running executable; dropped code to its archive.
pub fn requirements(
    cfg: &crate::config::RootCfg,
    registry: &dyn busbar_contract::plugin_rows::PluginRows,
) -> Result<Vec<Requirement>, String> {
    let mut requirements = Vec::new();
    for (provider, definition) in &cfg.identity_providers {
        let Some(row) = registry.resolve(&definition.module) else {
            continue;
        };
        if row.kind != "auth" {
            continue;
        }
        let schema: serde_json::Value = match row.settings_schema.as_deref() {
            Some(text) => {
                serde_json::from_str(text).map_err(|_| "invalid admitted auth settings schema")?
            }
            None => serde_json::Value::Null,
        };
        let format = match schema.get(FORMAT_ANNOTATION) {
            None => String::new(),
            Some(serde_json::Value::String(value))
                if !value.is_empty()
                    && value.len() <= 256
                    && !value.chars().any(char::is_control) =>
            {
                value.clone()
            }
            Some(_) => return Err("invalid opaque auth principal format annotation".into()),
        };
        let domain_sha256 = if format.is_empty() {
            if schema.get(DOMAIN_ANNOTATION).is_some() {
                return Err("principal domain declaration requires a principal format".into());
            }
            String::new()
        } else {
            let mut secret_paths = registry.secret_slots(&definition.module);
            secret_paths.extend(registry.reference_slots(&definition.module));
            domain_fingerprint(
                &schema,
                &serde_json::Value::Object(definition.settings.clone()),
                &secret_paths,
            )?
        };
        let product_sha256 = if format.is_empty() {
            String::new()
        } else {
            match registry.archive_sha256(&definition.module) {
                Some(hash) => hash,
                None if row.linked => executable_sha256()?,
                None => {
                    return Err("auth principal provenance has no admitted artifact digest".into())
                }
            }
        };
        requirements.push(Requirement {
            provider: provider.clone(),
            plugin: row.name.clone(),
            format,
            domain_sha256,
            product_sha256,
            settings_sha256: digest(definition)?,
        });
    }
    requirements.sort();
    Ok(requirements)
}

fn executable_sha256() -> Result<String, String> {
    static DIGEST: std::sync::OnceLock<Result<String, String>> = std::sync::OnceLock::new();
    DIGEST
        .get_or_init(|| {
            use std::io::Read;
            let path = std::env::current_exe().map_err(|e| e.to_string())?;
            let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
            let mut digest = Sha256::new();
            let mut bytes = [0u8; 65536];
            loop {
                let n = file.read(&mut bytes).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                digest.update(&bytes[..n]);
            }
            Ok(hex::encode(digest.finalize()))
        })
        .clone()
}

fn tracked(requirements: &[Requirement]) -> impl Iterator<Item = &Requirement> {
    // Every migration binding must name a marked requirement. This classification comes from
    // the immutable receipt, not just today's annotation; dropping a marker never drops a hold.
    requirements.iter().filter(|r| !r.format.is_empty())
}

fn same_formats(before: &[Requirement], after: &[Requirement]) -> bool {
    tracked(before)
        .map(|r| (&r.provider, &r.plugin, &r.format))
        .eq(tracked(after).map(|r| (&r.provider, &r.plugin, &r.format)))
}

fn same_identity_domains(before: &[Requirement], after: &[Requirement]) -> bool {
    tracked(before)
        .map(|r| (&r.provider, &r.plugin, &r.format, &r.domain_sha256))
        .eq(tracked(after).map(|r| (&r.provider, &r.plugin, &r.format, &r.domain_sha256)))
}

/// Safe operator diagnostics; never exposes key inventories, denial holds or provider settings.
pub fn receipt_head_digest(calls: Arc<dyn StoreCalls>) -> Result<Option<String>, String> {
    Ok(read_head(&StoreRows(calls))?.map(|(_, bytes)| hex::encode(Sha256::digest(bytes))))
}

pub fn receipt_binding(calls: Arc<dyn StoreCalls>) -> Result<Option<(String, String)>, String> {
    read_head(&StoreRows(calls))?
        .map(|(head, _)| Ok((head.plan_sha256, digest(&head.requirements)?)))
        .transpose()
}

pub fn reauthorize(
    receipt: &Reauthorization,
    calls: Arc<dyn StoreCalls>,
    store_sha256: &str,
    required: &[Requirement],
) -> Result<(), String> {
    let rows = StoreRows(calls);
    let (mut head, before) =
        read_head(&rows)?.ok_or("reauthorization requires an existing baseline")?;
    let attestation = &receipt.attestation;
    let epoch = hex::decode(&attestation.epoch).map_err(|_| "invalid cold attestation epoch")?;
    if !head.complete
        || receipt.version != 1
        || receipt.baseline_sha256 != head.plan_sha256
        || head.store_config_sha256 != store_sha256
        || !receipt.identity_outputs_unchanged
        || !hash(&receipt.continuity_evidence_sha256)
        || receipt.requirements != required
        || !same_formats(&head.requirements, required)
        || attestation.version != 1
        || epoch.len() != 16
        || epoch.iter().all(|b| *b == 0)
        || attestation.plan_sha256 != head.plan_sha256
        || !attestation.sender_quiesced
        || !attestation.backend_quiesced
        || !attestation.recovery_and_corrections_settled
        || attestation.actor.trim().is_empty()
        || attestation.reason.trim().is_empty()
        || receipt.witness.schema.is_empty()
        || receipt.witness.schema == SCHEMA.as_str()
    {
        return Err("explicit unchanged-identity provenance and cold complete-baseline attestation required".into());
    }
    let receipt_digest = digest(receipt)?;
    if head
        .authorization
        .as_ref()
        .is_some_and(|reference| reference.digest == receipt_digest)
    {
        return Ok(());
    }
    if receipt.previous_requirements_sha256 != digest(&head.requirements)? {
        return Err("principal reauthorization before requirements changed".into());
    }
    let witness_key = hex::decode(&receipt.witness.key_hex).map_err(|_| "invalid witness key")?;
    let witness_value =
        hex::decode(&receipt.witness.value_hex).map_err(|_| "invalid witness value")?;
    if witness_value.is_empty() {
        return Err("empty namespace witness".into());
    }
    let mut epoch_key = b"quiescence:".to_vec();
    epoch_key.extend_from_slice(&epoch);
    if rows
        .record_get(SCHEMA, &epoch_key)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("cold reauthorization attestation already consumed".into());
    }
    let body = serde_json::to_vec(receipt).map_err(|e| e.to_string())?;
    let mut mutations = chunks(format!("authorization:{receipt_digest}:").as_bytes(), &body)?;
    head.authorization = Some(AuthorizationRef {
        digest: receipt_digest.clone(),
        length: body.len(),
    });
    mutations.push(Mutation::Put {
        schema: SCHEMA.as_str().into(),
        key: HEAD.to_vec(),
        value: serde_json::to_vec(&head).map_err(|e| e.to_string())?,
    });
    mutations.push(Mutation::Put {
        schema: SCHEMA.as_str().into(),
        key: epoch_key.clone(),
        value: receipt_digest.as_bytes().to_vec(),
    });
    transaction(
        &rows,
        Request {
            version: VERSION,
            op_id: operation(&receipt_digest, "reauthorize"),
            predicates: vec![
                Predicate {
                    schema: SCHEMA.as_str().into(),
                    key: HEAD.to_vec(),
                    expected: Expected::Bytes(before),
                },
                Predicate {
                    schema: SCHEMA.as_str().into(),
                    key: epoch_key,
                    expected: Expected::Absent,
                },
                Predicate {
                    schema: receipt.witness.schema.clone(),
                    key: witness_key,
                    expected: Expected::Bytes(witness_value),
                },
            ],
            mutations,
        },
    )
}

/// Explicit creation proof is supplied by the namespace owner. An empty key scan is never proof.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshNamespace {
    pub version: u32,
    pub store_config_sha256: String,
    pub requirements: Vec<Requirement>,
    pub witness: Option<StoreWitness>,
    #[serde(default)]
    pub ephemeral_instance: bool,
    #[serde(default)]
    pub exclusive_instance: bool,
    pub creation_evidence_sha256: String,
    pub newly_created_namespace: bool,
    pub sender_quiesced: bool,
    pub backend_quiesced: bool,
    pub actor: String,
    pub reason: String,
}

pub fn initialize_fresh(
    receipt: &FreshNamespace,
    calls: Arc<dyn StoreCalls>,
    store_sha256: &str,
    required: &[Requirement],
) -> Result<(), String> {
    initialize_namespace(receipt, calls, store_sha256, required, false)
}

/// Explicit startup-only creation attestation; the caller continues serving on these SAME calls.
/// Ephemerality is necessary but never establishes namespace freshness by itself.
pub fn initialize_ephemeral_fresh(
    receipt: &FreshNamespace,
    calls: Arc<dyn StoreCalls>,
    store_sha256: &str,
    required: &[Requirement],
    effective_ephemeral: bool,
) -> Result<(), String> {
    if !effective_ephemeral || !receipt.ephemeral_instance || !receipt.exclusive_instance {
        return Err("explicit new exclusive ephemeral-instance attestation and actual ephemeral Store required".into());
    }
    initialize_namespace(receipt, calls, store_sha256, required, true)
}

/// Explicit operator-selected record initialization on the SAME newly created ephemeral Store.
/// No receipt is returned for retained state or a durable Store. The newly committed principal
/// baseline is the exact public witness consumed by the existing cold record bootstrap path.
pub fn initialize_ephemeral_with_record_bootstrap(
    receipt: &FreshNamespace,
    calls: Arc<dyn StoreCalls>,
    store_sha256: &str,
    required: &[Requirement],
    effective_ephemeral: bool,
    instance: &str,
    record_store_sha256: &str,
) -> Result<crate::host_record_bootstrap::ColdRecordReceipt, String> {
    if instance.is_empty()
        || instance.len() > usize::from(u16::MAX)
        || instance.chars().any(char::is_control)
        || !hash(record_store_sha256)
        || receipt.actor.len() > 256
        || receipt.reason.len() > 4096
    {
        return Err("invalid fresh record bootstrap binding".into());
    }
    initialize_ephemeral_fresh(
        receipt,
        calls.clone(),
        store_sha256,
        required,
        effective_ephemeral,
    )?;
    let (head, bytes) = read_head(&StoreRows(calls))?
        .ok_or("fresh principal baseline disappeared before record bootstrap")?;
    if !head.fresh || !head.complete || head.plan_sha256 != digest(receipt)? {
        return Err("fresh principal baseline changed before record bootstrap".into());
    }
    let mut epoch = [0u8; 16];
    getrandom::fill(&mut epoch).map_err(|_| "fresh record bootstrap entropy unavailable")?;
    Ok(crate::host_record_bootstrap::ColdRecordReceipt {
        version: 1,
        epoch: hex::encode(epoch),
        instance: instance.into(),
        namespace_hex: hex::encode(crate::host_records::record_key(instance, &[])),
        store_config_sha256: record_store_sha256.into(),
        store_witness: StoreWitness {
            schema: SCHEMA.as_str().into(),
            key_hex: hex::encode(HEAD),
            value_hex: hex::encode(bytes),
        },
        sender_quiesced: receipt.sender_quiesced,
        backend_quiesced: receipt.backend_quiesced,
        actor: receipt.actor.clone(),
        reason: receipt.reason.clone(),
    })
}

fn initialize_namespace(
    receipt: &FreshNamespace,
    calls: Arc<dyn StoreCalls>,
    store_sha256: &str,
    required: &[Requirement],
    ephemeral: bool,
) -> Result<(), String> {
    if receipt.version != 1
        || !receipt.newly_created_namespace
        || !receipt.sender_quiesced
        || !receipt.backend_quiesced
        || !hash(&receipt.creation_evidence_sha256)
        || receipt.store_config_sha256 != store_sha256
        || receipt.requirements != required
        || receipt.actor.trim().is_empty()
        || receipt.reason.trim().is_empty()
        || receipt.ephemeral_instance != ephemeral
        || (!ephemeral && receipt.witness.is_none())
    {
        return Err("explicit new namespace creation/witness receipt required".into());
    }
    let mut predicates = Vec::new();
    if let Some(witness) = &receipt.witness {
        let key = hex::decode(&witness.key_hex).map_err(|_| "invalid namespace witness key")?;
        let value =
            hex::decode(&witness.value_hex).map_err(|_| "invalid namespace witness value")?;
        if witness.schema.is_empty() || witness.schema == SCHEMA.as_str() || value.is_empty() {
            return Err("invalid namespace witness".into());
        }
        predicates.push(Predicate {
            schema: witness.schema.clone(),
            key,
            expected: Expected::Bytes(value),
        });
    }
    let receipt_sha256 = digest(receipt)?;
    let body = serde_json::to_vec(receipt).map_err(|e| e.to_string())?;
    let mut mutations = chunks(&body_prefix(&receipt_sha256), &body)?;
    let head = Head {
        version: 1,
        plan_sha256: receipt_sha256.clone(),
        length: body.len(),
        fresh: true,
        previous: None,
        retired_keys: Default::default(),
        historical_groups: Default::default(),
        depth: 0,
        store_config_sha256: store_sha256.into(),
        requirements: required.to_vec(),
        holds: Default::default(),
        held_principals: Default::default(),
        complete: true,
        authorization: None,
        rollover: None,
        extra_carry: Vec::new(),
    };
    let rows = StoreRows(calls);
    if !rows.supports_record_transaction() {
        return Err("fresh namespace baseline requires conditional records".into());
    }
    if read_head(&rows)?.is_some() {
        return Err("namespace already has a principal baseline or pending transition".into());
    }
    transaction(
        &rows,
        Request {
            version: VERSION,
            op_id: operation(&receipt_sha256, "fresh"),
            predicates: {
                predicates.push(Predicate {
                    schema: SCHEMA.as_str().into(),
                    key: HEAD.to_vec(),
                    expected: Expected::Absent,
                });
                predicates
            },
            mutations: {
                mutations.push(Mutation::Put {
                    schema: SCHEMA.as_str().into(),
                    key: HEAD.to_vec(),
                    value: serde_json::to_vec(&head).map_err(|e| e.to_string())?,
                });
                mutations
            },
        },
    )
}

#[cfg(test)]
#[path = "tests/principal_transition_tests.rs"]
mod tests;
