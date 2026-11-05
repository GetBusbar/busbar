// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit principal maintenance over the already opened bootstrap Store.

use std::io::Read;
use std::path::{Path, PathBuf};

use busbar_contract::store_calls::OpenedStore;
use busbar_kernel::config::{self, overlay::OverlayDoc};
use busbar_kernel::governance::principal_transition as transition;
use serde::de::DeserializeOwned;

pub const INPUT_FLAG: &str = "--principal-transition";
pub const ACTION_FLAG: &str = "--transition-action";
pub const ATTESTATION_FLAG: &str = "--transition-attestation";
const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Inspect,
    Prepare,
    Check,
    Apply,
    Verify,
    InitializeFresh,
    InitializeFreshAndServe,
    Reauthorize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    input: PathBuf,
    action: Action,
    attestation: Option<PathBuf>,
}

impl Command {
    /// Only this action consumes a fresh ephemeral-instance receipt and resumes ordinary boot.
    pub fn continues_serving(&self) -> bool {
        self.action == Action::InitializeFreshAndServe
    }

    pub fn validate_overlay_mode(
        &self,
        locked: bool,
        retained_overlay: bool,
    ) -> Result<(), &'static str> {
        if locked
            && (retained_overlay
                || !matches!(
                    self.action,
                    Action::Inspect
                        | Action::InitializeFresh
                        | Action::InitializeFreshAndServe
                        | Action::Reauthorize
                ))
        {
            return Err("principal transition requires normal boot to recover its exact Store overlay; reconcile locked configuration before preparing a plan");
        }
        Ok(())
    }
}

/// Parse maintenance's entire argument list, refusing accidental combinations with serving flags.
pub fn command(args: impl Iterator<Item = String>) -> Result<Option<Command>, &'static str> {
    let args: Vec<_> = args.collect();
    let mut input = None;
    let mut action = None;
    let mut attestation = None;
    let mut other = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let (flag, assigned) = arg
            .split_once('=')
            .map_or((arg.as_str(), None), |(k, v)| (k, Some(v)));
        if matches!(flag, INPUT_FLAG | ACTION_FLAG | ATTESTATION_FLAG) {
            let value = assigned.or_else(|| iter.next().map(String::as_str));
            let value = value
                .filter(|value| {
                    !value.is_empty()
                        && (!value.starts_with('-') || (flag == INPUT_FLAG && *value == "-"))
                })
                .ok_or("principal transition flags require explicit values")?;
            let slot = match flag {
                INPUT_FLAG => &mut input,
                ACTION_FLAG => &mut action,
                _ => &mut attestation,
            };
            if slot.replace(value.to_owned()).is_some() {
                return Err("duplicate principal transition flag");
            }
        } else if matches!(flag, "--config" | "-c" | "--providers") {
            if flag == "-c" && assigned.is_some() {
                return Err("use -c <path> or --config=<path>");
            }
            assigned
                .or_else(|| iter.next().map(String::as_str))
                .filter(|value| !value.is_empty() && !value.starts_with('-'))
                .ok_or("configuration path flags require explicit values")?;
        } else {
            other = true;
        }
    }
    if input.is_none() && action.is_none() && attestation.is_none() {
        return Ok(None);
    }
    if other {
        return Err(
            "principal transition accepts only --config and --providers alongside its flags",
        );
    }
    let input = input.ok_or("--transition-action requires --principal-transition")?;
    let action = match action.as_deref() {
        Some("inspect") => Action::Inspect,
        Some("prepare") => Action::Prepare,
        Some("check") => Action::Check,
        Some("apply") => Action::Apply,
        Some("verify") => Action::Verify,
        Some("initialize-fresh") => Action::InitializeFresh,
        Some("initialize-fresh-and-serve") => Action::InitializeFreshAndServe,
        Some("reauthorize") => Action::Reauthorize,
        _ => {
            return Err(
                "--transition-action must be inspect, prepare, check, apply, verify, initialize-fresh, initialize-fresh-and-serve or reauthorize",
            )
        }
    };
    if action == Action::Inspect && input != "-" {
        return Err("inspect requires --principal-transition - (no input document)");
    }
    if (action == Action::Apply) != attestation.is_some() {
        return Err("--transition-attestation is required only for apply");
    }
    Ok(Some(Command {
        input: input.into(),
        action,
        attestation: attestation.map(PathBuf::from),
    }))
}

fn bounded_bytes(path: &Path) -> Result<Vec<u8>, String> {
    // Refuse ordinary device/FIFO inputs before opening them can block. Recheck the opened
    // descriptor below, and cap the actual read even if a regular file grows concurrently.
    let metadata = std::fs::metadata(path).map_err(|_| "cannot inspect transition/config input")?;
    if !metadata.is_file() {
        return Err("transition/config input must be a regular file".into());
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err("transition/config input exceeds 8 MiB".into());
    }
    let file = std::fs::File::open(path).map_err(|_| "cannot open transition/config input")?;
    if !file
        .metadata()
        .map_err(|_| "cannot inspect transition/config input")?
        .is_file()
    {
        return Err("transition/config input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read transition/config input")?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("transition/config input exceeds 8 MiB".into());
    }
    Ok(bytes)
}

fn input<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&bounded_bytes(path)?)
        .map_err(|_| "invalid principal transition JSON input".into())
}

/// Hash exactly the interpolated sources consumed by the loader, rather than reinterpreting
/// RootCfg's non-serializable fields or recording secret-bearing configuration in the plan.
pub fn source_fingerprint(
    config_path: &Path,
    providers_path: &Path,
    expected: Option<config::document_patch::SourceFingerprints>,
) -> Result<String, String> {
    let interpolated = |path: &Path| -> Result<String, String> {
        let text = String::from_utf8(bounded_bytes(path)?)
            .map_err(|_| "configuration input is not UTF-8")?;
        config::interpolate_env(&text).map_err(|_| "configuration interpolation failed".into())
    };
    let config = interpolated(config_path)?;
    let providers = interpolated(providers_path)?;
    if expected
        != Some(config::document_patch::SourceFingerprints::from_sources(
            &config, &providers,
        ))
    {
        return Err("configuration sources changed after loading".into());
    }
    transition::digest(&("principal-transition-config-sources-v1", config, providers))
}

fn effective_fingerprint(source: &str, overlay: Option<&OverlayDoc>) -> Result<String, String> {
    let mut settings = overlay.cloned().unwrap_or_default();
    // Exact group and tombstone preimages are bound separately by the plan. Normalizing the
    // schema version also makes creation of the migration's first overlay resume-stable.
    settings.groups.clear();
    settings.deleted_groups.clear();
    settings.version = config::overlay::OVERLAY_VERSION;
    transition::digest(&("principal-transition-effective-v1", source, settings))
}

fn check_references(bindings: &[transition::Binding], cfg: &config::RootCfg) -> Result<(), String> {
    let names: std::collections::BTreeSet<_> = bindings
        .iter()
        .flat_map(|binding| {
            [&binding.old_principal, &binding.new_principal].map(|principal| {
                format!(
                    "{}{principal}",
                    busbar_kernel::governance::SELF_KEY_GROUP_PREFIX
                )
            })
        })
        .collect();
    let role_reference = cfg.auth.as_ref().is_some_and(|auth| {
        auth.role_bindings
            .values()
            .flat_map(|roles| roles.values())
            .any(|role| {
                role.group
                    .as_ref()
                    .is_some_and(|group| names.contains(group))
            })
    });
    let hook_reference = cfg
        .hooks
        .values()
        .any(|hook| hook.groups.iter().any(|group| names.contains(group)));
    if role_reference || hook_reference {
        return Err("personal group has static role or hook references requiring explicit policy disposition".into());
    }
    Ok(())
}

fn check_groups(plan: &transition::Plan, cfg: &config::RootCfg) -> Result<(), String> {
    if cfg.groups == plan.groups_before {
        return Ok(());
    }
    let mut after = plan.groups_before.clone();
    for binding in &plan.specification.bindings {
        if let Some(group) = plan.groups_before.get(&format!(
            "{}{}",
            busbar_kernel::governance::SELF_KEY_GROUP_PREFIX,
            binding.old_principal
        )) {
            after.insert(
                format!(
                    "{}{}",
                    busbar_kernel::governance::SELF_KEY_GROUP_PREFIX,
                    binding.new_principal
                ),
                group.clone(),
            );
        }
    }
    if cfg.groups != after {
        return Err("effective group configuration changed".into());
    }
    Ok(())
}

/// All context is from the real boot reconstruction. No Store is reopened or selected by a plan.
pub fn execute(
    command: &Command,
    cfg: &config::RootCfg,
    plugins: &config::PluginsCfg,
    anchor: &OpenedStore,
    anchor_settings: &serde_json::Value,
    source_sha256: &str,
    overlay: Option<&OverlayDoc>,
) -> Result<serde_json::Value, String> {
    let effective_store = serde_json::to_value(&cfg.store)
        .map_err(|_| "cannot fingerprint effective Store configuration")?;
    if &effective_store != anchor_settings {
        return Err(
            "principal transition refuses an effective Store different from the bootstrap anchor"
                .into(),
        );
    }
    let store_sha256 = transition::store_fingerprint(&cfg.store)?;
    let effective_sha256 = effective_fingerprint(source_sha256, overlay)?;
    let registry = busbar_kernel::preflight::plugins_preflight(
        cfg.store.as_ref(),
        cfg.auth.as_ref(),
        &cfg.identity_providers,
        &cfg.hooks,
        plugins,
        &cfg.export,
    )
    .map_err(|_| "principal transition plugin admission failed")?;
    let required = transition::requirements(cfg, registry.as_ref())
        .map_err(|_| "cannot bind admitted principal formats")?;
    let calls = anchor
        .calls
        .clone()
        .ok_or("principal transition requires typed Store calls")?;
    // Per-open metadata takes precedence over the admitted Statement fallback. A plugin's
    // configured spelling never determines whether its state is ephemeral.
    let effective_ephemeral = calls.ephemeral().or_else(|| {
        cfg.store.as_ref().and_then(|store| {
            registry
                .resolve(&store.module)
                .filter(|row| row.kind == "store")
                .map(|row| row.ephemeral)
        })
    });
    if command.action == Action::Inspect {
        let binding = transition::receipt_binding(calls.clone())?;
        let mut keys = anchor
            .records
            .list_keys()
            .map_err(|_| "cannot inspect retained key preimages")?;
        keys.sort_by(|left, right| left.id.cmp(&right.id));
        let group_preimages = cfg
            .groups
            .iter()
            .map(|(name, group)| {
                let principal = name.strip_prefix(busbar_kernel::governance::SELF_KEY_GROUP_PREFIX);
                let retained: Vec<_> = keys
                    .iter()
                    .filter(|key| {
                        principal.is_some_and(|principal| {
                            key.group.as_deref() == Some(name.as_str())
                                || key.idp_subject.as_deref() == Some(principal)
                        })
                    })
                    .collect();
                let provider = retained
                    .first()
                    .and_then(|key| key.idp_provider.as_deref())
                    .filter(|provider| {
                        retained
                            .iter()
                            .all(|key| key.idp_provider.as_deref() == Some(*provider))
                    });
                let requirement =
                    provider.and_then(|provider| required.iter().find(|r| r.provider == provider));
                Ok(serde_json::json!({
                    "group": name, "sha256": transition::digest(&Some(group))?,
                    "keys_sha256": transition::digest(&retained)?,
                    "provider": provider,
                    "requirement_sha256": requirement.map(transition::digest).transpose()?,
                }))
            })
            .collect::<Result<Vec<serde_json::Value>, String>>()?;
        let key_preimages = keys
            .iter()
            .map(|key| Ok(serde_json::json!({"key_id":key.id,"sha256":transition::digest(key)?})))
            .collect::<Result<Vec<serde_json::Value>, String>>()?;
        return Ok(serde_json::json!({
            "retained_key_preimages": key_preimages,
            "retained_group_preimages": group_preimages,
            "absent_group_sha256": transition::digest(&Option::<config::GroupCfg>::None)?,
            "principal_receipt_head_sha256": transition::receipt_head_digest(calls.clone())?,
            "principal_receipt_baseline_sha256": binding.as_ref().map(|(baseline,_)| baseline),
            "principal_receipt_requirements_sha256": binding.as_ref().map(|(_,requirements)| requirements),
            "principal_format_required": required.iter().any(|requirement| !requirement.format.is_empty()),
            "principal_format_ready": transition::guard(calls.clone(), &store_sha256, &required).is_ok(),
            "store_config_sha256": store_sha256,
            "store_ephemeral": effective_ephemeral,
            "effective_config_sha256": effective_sha256,
            "requirements": required,
            "groups_sha256": transition::digest(&cfg.groups)?,
            "overlay_sha256": transition::digest(&overlay)?,
        }));
    }
    if matches!(
        command.action,
        Action::InitializeFresh | Action::InitializeFreshAndServe
    ) {
        let receipt: transition::FreshNamespace = input(&command.input)?;
        let action = if command.continues_serving() {
            let ephemeral = effective_ephemeral
                .ok_or("principal initialization requires admitted Store durability metadata")?;
            transition::initialize_ephemeral_fresh(
                &receipt,
                calls,
                &store_sha256,
                &required,
                ephemeral,
            )?;
            "initialize-fresh-and-serve"
        } else {
            transition::initialize_fresh(&receipt, calls, &store_sha256, &required)?;
            "initialize-fresh"
        };
        return Ok(serde_json::json!({"ok": true, "action": action}));
    }
    let overlay_store = config::overlay::OverlayStore::new(calls.clone())
        .map_err(|_| "principal transition requires a durable Store overlay")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time precedes the Unix epoch")?
        .as_secs();

    if command.action == Action::Reauthorize {
        let receipt: transition::Reauthorization = input(&command.input)?;
        transition::reauthorize(&receipt, calls, &store_sha256, &required)?;
        return Ok(serde_json::json!({"ok": true, "action": "reauthorize"}));
    }
    let check_binding = |spec: &transition::Specification| -> Result<(), String> {
        if spec.store_config_sha256 != store_sha256 || spec.requirements != required {
            return Err(
                "transition Store or admitted auth artifact/settings binding changed".into(),
            );
        }
        if spec.effective_config_sha256 != effective_sha256 {
            return Err("effective configuration changed".into());
        }
        Ok(())
    };
    if command.action == Action::Prepare {
        let spec: transition::Specification = input(&command.input)?;
        check_binding(&spec)?;
        check_references(&spec.bindings, cfg)?;
        let plan = transition::prepare(
            spec,
            anchor.records.as_ref(),
            calls,
            cfg.groups.clone(),
            overlay.cloned(),
        )?;
        return serde_json::to_value(plan)
            .map_err(|_| "cannot encode principal transition plan".into());
    }
    let plan: transition::Plan = input(&command.input)?;
    check_binding(&plan.specification)?;
    check_references(&plan.specification.bindings, cfg)?;
    check_groups(&plan, cfg)?;
    let action = match command.action {
        Action::Check => {
            transition::check(
                &plan,
                anchor.records.as_ref(),
                calls,
                &overlay_store,
                now,
                &effective_sha256,
            )?;
            "check"
        }
        Action::Apply => {
            let attestation = input(
                command
                    .attestation
                    .as_deref()
                    .ok_or("missing cold attestation")?,
            )?;
            transition::apply(
                &plan,
                &attestation,
                anchor.records.as_ref(),
                calls,
                &overlay_store,
                now,
                &effective_sha256,
            )?;
            "apply"
        }
        Action::Verify => {
            transition::verify(&plan, anchor.records.as_ref(), calls, &overlay_store, now)?;
            "verify"
        }
        Action::Inspect
        | Action::Prepare
        | Action::InitializeFresh
        | Action::InitializeFreshAndServe
        | Action::Reauthorize => {
            unreachable!("handled above")
        }
    };
    Ok(serde_json::json!({"ok": true, "action": action, "plan_sha256": transition::digest(&plan)?}))
}

#[cfg(test)]
#[path = "tests/principal_transition.rs"]
mod tests;
