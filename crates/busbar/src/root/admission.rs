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
//! [`DurableFs`] seam: the `plugins.fetch` directory and the admin plugin verbs write
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

/// The audited action relaxes only its target's two independent floor gates. Trust and all
/// other names retain the running posture.
fn rollback_policy(mut policy: TrustPolicy, manifest: &Manifest) -> TrustPolicy {
    policy
        .min_versions
        .insert(manifest.name.clone(), manifest.version.clone());
    policy
        .first_party_floors
        .insert(manifest.name.clone(), manifest.version.clone());
    policy
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
    fn bootstrap_probe_selected(
        &self,
        tarball: &[u8],
        config_path: &std::path::Path,
        provider_urls: &[String],
    ) -> Result<bool, Refusal> {
        let unpacked = unpack_checked(tarball, " bootstrap candidate")?;
        if !matches!(unpacked.manifest.kind.as_str(), "transport" | "plane") {
            return Ok(false);
        }
        let Some(stated) = unpacked
            .manifest
            .stated_rendering()
            .map_err(Refusal::Validation)?
        else {
            return Ok(false);
        };
        let candidate = super::loader::boot::Candidate::from_manifest(
            stated,
            &unpacked.manifest,
            super::loader::boot::Origin::Dropped {
                file: "bootstrap candidate".into(),
                bytes: std::sync::Arc::new(unpacked.lib_bytes),
            },
        )
        .map_err(Refusal::Validation)?;
        Ok(unpacked.manifest.kind == "plane"
            || candidate.serves(&super::boot::transport_uses_for(config_path, provider_urls)))
    }

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
        let policy = policy(cfg, env!("CARGO_PKG_VERSION")).map_err(Refusal::Validation)?;
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
        let installed = crate::root::loader::scan_and_validate(dir, &policy).map_err(|errors| {
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
        let policy = policy(cfg, env!("CARGO_PKG_VERSION")).map_err(Refusal::Validation)?;
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
        let policy = rollback_policy(
            policy(cfg, &manifest.version).map_err(Refusal::Validation)?,
            manifest,
        );
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

#[cfg(test)]
mod rollback_tests {
    use super::*;
    use crate::root::loader::sign::{sign, SigningKey, FIRST_PARTY_PUBLISHER};

    #[test]
    fn first_party_rollback_relaxes_its_prior_pin_and_preserves_other_floors_and_trust() {
        let key = SigningKey::from_bytes(&[0x31; 32]);
        let lib = b"signed rollback fixture, never loaded";
        let make = |name: &str| {
            sign(
                &key,
                Manifest {
                    name: name.into(),
                    alias: name.into(),
                    kind: "hook".into(),
                    version: "1.4.0".into(),
                    publisher: FIRST_PARTY_PUBLISHER.into(),
                    abi_version: *crate::root::loader::supported_abi("hook")
                        .iter()
                        .max()
                        .unwrap(),
                    ..Default::default()
                },
                lib,
            )
        };
        let target = make("busbar-hook-rollback-fixture");
        let other = make("busbar-hook-other-fixture");
        let mut running = TrustPolicy {
            first_party_key: Some(key.verifying_key()),
            ..Default::default()
        };
        for name in [&target.name, &other.name] {
            running.min_versions.insert(name.clone(), "2.0.0".into());
            running
                .first_party_floors
                .insert(name.clone(), "2.0.0".into());
            running
                .first_party_high_water
                .insert(name.clone(), "3.0.0".into());
        }
        assert!(
            evaluate(lib, &target, &running).is_err(),
            "the ordinary path keeps the prior pin"
        );
        let tarball = crate::root::loader::tarball::package(&target, "lib.so", lib).unwrap();
        let checked = unpack_checked(&tarball, " `old.tar.gz`").unwrap();
        let rollback = rollback_policy(running, &checked.manifest);
        assert!(matches!(
            evaluate(&checked.lib_bytes, &checked.manifest, &rollback),
            Ok(Verdict::Trusted {
                first_party: true,
                ..
            })
        ));
        assert!(
            evaluate(lib, &other, &rollback).is_err(),
            "another name's floor is preserved"
        );
        let mut wrong_key = rollback;
        wrong_key.first_party_key = Some(SigningKey::from_bytes(&[0x32; 32]).verifying_key());
        assert!(
            evaluate(lib, &target, &wrong_key).is_err(),
            "floor relaxation never relaxes signature trust"
        );
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

#[cfg(test)]
mod store_overlay_management {
    use busbar_kernel::config::overlay::{persist_root, resolve_backend_with_env, RootSettings};
    use busbar_kernel::config::{ConfigMgmtCfg, OverlayBackend, OverlayCfg};
    use busbar_kernel::test_support::TestOverlayStore;
    #[test]
    fn legacy_overlay_file_is_untouched_and_store_remains_writable() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "busbar-overlay-input-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = dir.join("overlay.json");
        let original = b"operator-owned legacy input";
        std::fs::write(&legacy, original).unwrap();
        let cfg = ConfigMgmtCfg {
            locked: false,
            overlay: Some(OverlayCfg::Backend(OverlayBackend {
                file: Some(legacy.to_string_lossy().into_owned()),
            })),
        };
        assert!(
            resolve_backend_with_env(&cfg, &dir.join("config.yaml"), None, true)
                .unwrap()
                .enabled
        );
        let store = TestOverlayStore::new();
        persist_root(Some(&store.backend()), &RootSettings::default()).unwrap();
        assert!(store.read_bytes().is_some());
        assert_eq!(std::fs::read(&legacy).unwrap(), original);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
