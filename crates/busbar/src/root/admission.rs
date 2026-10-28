// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN ADMISSION AND THE DURABLE WRITE, THE ROOT'S (`BUSBAR-1.6.0.md` THE DESIGN l.322: the
//! kernel never names the loader). The operator surface's plugin verbs — the catalog's inventory,
//! an upload, an inspect, a rollback — judge a tarball through the loader's structure, signature
//! and conflict machinery under THE ROOT'S ONE TRUST BUILDER ([`crate::root::boot::trust_policy`],
//! the one boot admits plugins under), and the kernel reaches them as its own
//! [`PluginAdmission`] seam ([`ADMISSION`], installed by `root::linked::register_stores`). Every
//! judgement is MANIFEST-ONLY: nothing here loads a plugin.
//!
//! [`DURABLE`] is the loader's one durable-write primitive (`root::loader::durable`) as the kernel's
//! [`DurableFs`] seam: the overlay, the `plugins.fetch` directory and the admin plugin verbs write
//! through it.

use std::path::Path;

use busbar_kernel::admission::{Admitted, Inventoried, Judged, PluginAdmission, Refusal, Stated};
use busbar_kernel::config::PluginsCfg;
use busbar_kernel::durable::{DurableFs, DurableOpts};

use crate::root::loader::sign::{
    evaluate, validate_structure, Manifest, TrustPolicy, Verdict, HOST_IDENTITY,
};

/// The process's plugin admission (`RootInstall::admission`).
pub static ADMISSION: RootAdmission = RootAdmission;

/// The process's durable write (`RootInstall::durable`).
pub static DURABLE: RootDurable = RootDurable;

/// What a manifest states, in the kernel's words.
fn stated(m: &Manifest) -> Stated {
    Stated {
        name: m.name.clone(),
        alias: m.alias.clone(),
        kind: m.kind.clone(),
        version: m.version.clone(),
        publisher: m.publisher.clone(),
        abi_version: m.abi_version,
        settings_schema: m.settings_schema.clone(),
    }
}

/// `cfg`'s trust under the root's one builder; `binary_version` is carried for diagnostics only.
fn policy(cfg: &PluginsCfg, binary_version: &str) -> Result<TrustPolicy, String> {
    crate::root::boot::trust_policy(cfg, binary_version)
}

/// [`policy`] for an INSTALL or UPDATE (an upload, and the preview of one): a first-party plugin's
/// release seal is also judged for EXPIRY, as TUF judges metadata when it fetches. Boot judges an
/// installed plugin without it, so time passing never stops one from loading
/// (`docs/design/release-trust.md`).
fn install_policy(cfg: &PluginsCfg, binary_version: &str) -> Result<TrustPolicy, String> {
    policy(cfg, binary_version).map(|p| TrustPolicy {
        release_enforce_expiry: true,
        ..p
    })
}

/// `tarball` unpacked in memory and its manifest checked for completeness, integrity and a
/// supported ABI; `what` names the tarball in a refusal (empty: the upload's own words).
fn unpack_checked(
    tarball: &[u8],
    what: &str,
) -> Result<crate::root::loader::tarball::UnpackedPlugin, Refusal> {
    let unpacked = crate::root::loader::tarball::unpack(tarball)
        .map_err(|e| Refusal::Validation(format!("invalid plugin tarball{what}: {e}")))?;
    validate_structure(
        &unpacked.manifest,
        &unpacked.lib_bytes,
        &crate::root::loader::supported_abi,
        HOST_IDENTITY,
    )
    .map_err(|e| Refusal::Validation(format!("invalid plugin manifest{what}: {e}")))?;
    Ok(unpacked)
}

/// THE ROOT'S PLUGIN ADMISSION.
#[derive(Debug)]
pub struct RootAdmission;

impl PluginAdmission for RootAdmission {
    fn is_tarball(&self, file: &str) -> bool {
        crate::root::loader::tarball::is_plugin_tarball(file)
    }

    fn max_tarball_bytes(&self) -> u64 {
        crate::root::loader::tarball::MAX_TARBALL_FILE_BYTES
    }

    fn restart_default(&self, kind: &str) -> bool {
        crate::root::loader::sign::kind_restart_default(kind)
    }

    fn policy_resolves(&self, cfg: &PluginsCfg) -> Result<(), String> {
        policy(cfg, env!("CARGO_PKG_VERSION")).map(|_| ())
    }

    fn inventory(&self, dir: &Path, cfg: &PluginsCfg) -> Result<Vec<Inventoried>, String> {
        let policy = policy(cfg, env!("CARGO_PKG_VERSION"))?;
        Ok(crate::root::loader::inventory_tarballs(dir, &policy)
            .into_iter()
            .map(|row| Inventoried {
                stated: row.manifest.as_ref().map(stated),
                file: row.file,
                signature: row.signature,
                status: row.status,
            })
            .collect())
    }

    /// The upload pipeline's steps 2-4b (`POST /plugins`): STRUCTURAL (the tarball unpacks in
    /// memory; the manifest is complete, its sha256 binds the library, its ABI is supported) ->
    /// TRUST re-verified against the RUNNING posture (an untrusted upload is a conflict) -> CONFLICT
    /// with a DIFFERENT installed loadable plugin by any identifier -> THE ONE-VERSION RULE against
    /// the rows this build links, after trust.
    fn admit_upload(
        &self,
        dir: &Path,
        file: &str,
        tarball: &[u8],
        cfg: &PluginsCfg,
    ) -> Result<Admitted, Refusal> {
        let policy = install_policy(cfg, env!("CARGO_PKG_VERSION")).map_err(Refusal::Validation)?;
        let unpacked = unpack_checked(tarball, "")?;
        let manifest = &unpacked.manifest;
        let judged = match evaluate(&unpacked.lib_bytes, manifest, &policy) {
            Ok(Verdict::Trusted { publisher, .. }) => Judged::Trusted { publisher },
            Ok(Verdict::Allowed { .. }) => Judged::Allowed,
            // An untrusted upload with no matching opt-in is a terminal state conflict (retrying
            // the same bytes cannot fix it); the evaluator's reason names the flag to set.
            Err(rejected) => {
                return Err(Refusal::Conflict(format!(
                    "plugin rejected by the trust policy: {}",
                    rejected.reason
                )));
            }
        };
        // A corrupt tarball already in the directory makes the scan refuse: the conflict status of
        // the upload cannot be determined, so it is refused rather than published unchecked.
        // The INSTALLED set is judged as boot will judge it (expiry not enforced): an installed
        // plugin whose seal has since expired still loads at boot, so it still claims its names here.
        let installed_policy = TrustPolicy {
            release_enforce_expiry: false,
            ..policy.clone()
        };
        let installed =
            crate::root::loader::scan_and_validate(dir, &installed_policy).map_err(|errors| {
                Refusal::Conflict(format!(
                "cannot validate the installed plugin set before publishing (fix or remove the \
                 offending tarball first): {}",
                errors.join("; ")
            ))
            })?;
        for existing in installed.loadable() {
            if existing.file == file {
                continue; // overwriting the same tarball file is a legitimate upgrade
            }
            // Every identifier either claims (name, alias, former names) against the other's. A
            // same-name upload under a different file would brick the next boot (phase 3 refuses
            // two files claiming one plugin), so it is refused here.
            if manifest
                .identities()
                .any(|word| existing.manifest.answers_to(word))
            {
                return Err(Refusal::Conflict(format!(
                    "plugin name/alias conflict: uploaded '{}' (alias '{}', file {}) collides with \
                     installed '{}' (alias '{}', file {}); a same-name upgrade must reuse the \
                     existing filename, not add a second file (boot would reject two files claiming \
                     the same plugin name)",
                    manifest.name,
                    manifest.alias,
                    file,
                    existing.manifest.name,
                    existing.manifest.alias,
                    existing.file
                )));
            }
        }
        let linked: Vec<_> = busbar_kernel::preflight::linked_rows()
            .iter()
            .map(crate::root::boot::linked_row)
            .collect();
        let linked_serves = crate::root::loader::PluginRegistry::empty()
            .link(linked)
            .and_then(|rows| rows.linked_copy(manifest, file))
            .map_err(Refusal::Conflict)?
            .is_some();
        Ok(Admitted {
            stated: stated(manifest),
            judged,
            linked_serves,
        })
    }

    fn inspect(&self, tarball: &[u8], cfg: &PluginsCfg) -> Result<(Stated, Judged), Refusal> {
        let policy = install_policy(cfg, env!("CARGO_PKG_VERSION")).map_err(Refusal::Validation)?;
        let unpacked = unpack_checked(tarball, "")?;
        // Trust is REPORTED, never a refusal to answer: an untrusted candidate is the case an
        // operator most wants to preview.
        let judged = match evaluate(&unpacked.lib_bytes, &unpacked.manifest, &policy) {
            Ok(Verdict::Trusted { publisher, .. }) => Judged::Trusted { publisher },
            Ok(Verdict::Allowed { .. }) => Judged::Allowed,
            Err(rejected) => Judged::Rejected {
                reason: rejected.reason,
            },
        };
        Ok((stated(&unpacked.manifest), judged))
    }

    /// The EXPLICIT rollback's trust: the policy with this plugin's floor LOWERED to the target's
    /// own version, so a validly-signed OLDER artifact clears it; a signature or opt-in failure is
    /// still fatal (a rollback authenticates the operator, never the artifact).
    fn rollback_target(
        &self,
        file: &str,
        bytes: &[u8],
        cfg: &PluginsCfg,
    ) -> Result<Stated, Refusal> {
        let what = format!(" `{file}`");
        let unpacked = unpack_checked(bytes, &what)?;
        let manifest = &unpacked.manifest;
        let mut policy = policy(cfg, &manifest.version).map_err(Refusal::Validation)?;
        policy
            .min_versions
            .insert(manifest.name.clone(), manifest.version.clone());
        match evaluate(&unpacked.lib_bytes, manifest, &policy) {
            Ok(Verdict::Trusted { .. } | Verdict::Allowed { .. }) => Ok(stated(manifest)),
            Err(rejected) => Err(Refusal::Conflict(format!(
                "rollback target `{file}` is not loadable under the trust policy even with the \
                 floor lowered to its own version {}: {}. A rollback lowers the anti-downgrade \
                 floor for an explicit operator action; it cannot load an untrusted artifact.",
                manifest.version, rejected.reason
            ))),
        }
    }
}

/// THE ROOT'S DURABLE WRITE: the loader's one primitive.
#[derive(Debug)]
pub struct RootDurable;

impl DurableFs for RootDurable {
    fn write_with(&self, path: &Path, bytes: &[u8], opts: DurableOpts) -> std::io::Result<()> {
        crate::root::loader::durable::write_with(
            path,
            bytes,
            crate::root::loader::durable::DurableOpts {
                mode: opts.mode,
                exclusive: opts.exclusive,
            },
        )
    }

    fn remove(&self, path: &Path) -> std::io::Result<()> {
        crate::root::loader::durable::remove(path)
    }

    fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        crate::root::loader::durable::create_dir_all(path)
    }
}

/// THE `plugins.logs` CHECK (`RootInstall::plugin_logs`): the block in the loader's words.
///
/// # Errors
///
/// A level, directory or rotation the plugin log sinks cannot use.
pub fn plugin_logs(cfg: &PluginsCfg) -> Result<(), String> {
    let l = &cfg.logs;
    crate::root::loader::dispatch::PluginLogConfig::from_words(
        l.dir.as_deref(),
        l.level.as_deref(),
        &l.levels,
        l.rotate_mb,
        l.keep,
    )
    .map(|_| ())
}

/// Whether a DROPPED-IN `kind: hook` row of `rows` answers `module` by the rule the hook axis opens
/// it by (`RootInstall::hook_answers`); rows this root did not build carry none.
pub fn hook_answers(rows: &dyn busbar_contract::plugin_rows::PluginRows, module: &str) -> bool {
    crate::root::loader::rows::registry_of(rows)
        .is_some_and(|registry| crate::root::loader::hook_door::dropped_answers(registry, module))
}

/// Whether a linked auth door's Statement declares an INBOUND auth-chain module
/// (`RootInstall::auth_chain_module`).
pub fn auth_chain_module(door: busbar_contract::abi::mechanism::door::DoorFn) -> bool {
    crate::root::loader::dispatch::kinds::auth::declares_chain_module(door)
}

/// Whether the process's off-crossing latch has tripped (`RootInstall::dispatch_latched`).
pub fn dispatch_latched() -> bool {
    crate::root::loader::dispatch::handle::latched()
}
