// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::Path;

use busbar_kernel::admission::{Admitted, Inventoried, Judged, PluginAdmission, Refusal, Stated};
use busbar_kernel::config::PluginsCfg;
use busbar_kernel::durable::{DurableFs, DurableOpts};

use crate::root::loader::sign::{
    evaluate, validate_structure, Manifest, TrustPolicy, Verdict, HOST_IDENTITY,
};

pub static ADMISSION: RootAdmission = RootAdmission;

pub static DURABLE: RootDurable = RootDurable;

fn configuration_declaration(
    m: &Manifest,
    statement: &busbar_contract::abi::mechanism::rendering::Read,
) -> busbar_kernel::admission::ConfigurationDeclaration {
    let mut declaration =
        busbar_kernel::admission::ConfigurationDeclaration::from_statement(statement);
    declaration.valid &= busbar_contract::abi::mechanism::KindCode::from_raw(statement.kind)
        .is_some_and(|kind| crate::root::loader::boot::kind_of(kind).to_string() == m.kind)
        && statement.name == m.name
        && statement.version == m.version
        && statement.kind_abi == m.abi_version
        && statement.mechanism_version == busbar_contract::abi::mechanism::MECHANISM_VERSION;
    declaration
}

pub(super) fn linked_configuration_from_statement(bytes: &[u8]) -> Result<Stated, String> {
    use busbar_contract::abi::mechanism::{door::REWRITE_ALIAS, rendering, KindCode};
    let statement =
        rendering::read(bytes).map_err(|e| format!("invalid linked Statement: {e:?}"))?;
    let kind = KindCode::from_raw(statement.kind).ok_or("unknown linked Statement kind")?;
    let schema = super::loader::settings_schema::statement_schema(&statement.settings_schema)?;
    Ok(Stated {
        name: statement.name.clone(),
        alias: statement
            .rewrites
            .iter()
            .find(|(class, _, _)| *class == REWRITE_ALIAS)
            .map_or_else(|| statement.name.clone(), |(_, from, _)| from.clone()),
        kind: super::loader::boot::kind_of(kind).to_string(),
        version: statement.version.clone(),
        publisher: super::loader::sign::FIRST_PARTY_PUBLISHER.to_string(),
        abi_version: statement.kind_abi,
        settings_schema: schema,
        configuration: Some(
            busbar_kernel::admission::ConfigurationDeclaration::from_statement(&statement),
        ),
    })
}

fn stated(m: &Manifest) -> Result<Stated, String> {
    Ok(Stated {
        name: m.name.clone(),
        alias: m.alias.clone(),
        kind: m.kind.clone(),
        version: m.version.clone(),
        publisher: m.publisher.clone(),
        abi_version: m.abi_version,
        settings_schema: m.settings_schema_text()?,
        configuration: m
            .stated()?
            .as_ref()
            .map(|statement| configuration_declaration(m, statement)),
    })
}

fn policy(cfg: &PluginsCfg, binary_version: &str) -> Result<TrustPolicy, String> {
    crate::root::boot::trust_policy(cfg, binary_version)
}

fn install_policy(cfg: &PluginsCfg, binary_version: &str) -> Result<TrustPolicy, String> {
    policy(cfg, binary_version).map(|policy| TrustPolicy {
        release_enforce_expiry: true,
        ..policy
    })
}

fn rollback_policy(mut policy: TrustPolicy, manifest: &Manifest) -> TrustPolicy {
    policy
        .min_versions
        .insert(manifest.name.clone(), manifest.version.clone());
    policy
        .first_party_floors
        .insert(manifest.name.clone(), manifest.version.clone());
    policy
}

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
    fn linked_configuration(&self) -> Vec<Stated> {
        super::settings_public::linked_configuration()
    }

    fn loaded_configuration(
        &self,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        name: &str,
    ) -> Option<busbar_kernel::admission::ConfigurationDeclaration> {
        let row = crate::root::loader::rows::registry_of(registry)?.resolve(name)?;
        row.configuration_statement()
            .map(|statement| configuration_declaration(&row.manifest, statement))
    }

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
                // Invalid Statement schemas already carry the inventory's INVALID status.
                stated: row.manifest.as_ref().and_then(|m| stated(m).ok()),
                file: row.file,
                signature: row.signature,
                status: row.status,
            })
            .collect())
    }

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

            Err(rejected) => {
                return Err(Refusal::Conflict(format!(
                    "plugin rejected by the trust policy: {}",
                    rejected.reason
                )));
            }
        };

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
                continue;
            }

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
            stated: stated(manifest).map_err(Refusal::Validation)?,
            judged,
            linked_serves,
        })
    }

    fn inspect(&self, tarball: &[u8], cfg: &PluginsCfg) -> Result<(Stated, Judged), Refusal> {
        let policy = install_policy(cfg, env!("CARGO_PKG_VERSION")).map_err(Refusal::Validation)?;
        let unpacked = unpack_checked(tarball, "")?;

        let judged = match evaluate(&unpacked.lib_bytes, &unpacked.manifest, &policy) {
            Ok(Verdict::Trusted { publisher, .. }) => Judged::Trusted { publisher },
            Ok(Verdict::Allowed { .. }) => Judged::Allowed,
            Err(rejected) => Judged::Rejected {
                reason: rejected.reason,
            },
        };
        Ok((
            stated(&unpacked.manifest).map_err(Refusal::Validation)?,
            judged,
        ))
    }

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
            Ok(Verdict::Trusted { .. } | Verdict::Allowed { .. }) => {
                stated(manifest).map_err(Refusal::Validation)
            }
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
            release_keys_floor: 17,
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
        assert_eq!(
            rollback.release_keys_floor, 17,
            "a plugin rollback never relaxes keys metadata rollback protection"
        );
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

    fn inspect_document(
        &self,
        path: &Path,
        original: &[u8],
        converted: &[u8],
    ) -> std::io::Result<busbar_kernel::durable::DocumentInspection> {
        use crate::root::loader::durable::DocumentInspection as Native;
        use busbar_kernel::durable::DocumentInspection as Host;
        Ok(
            match crate::root::loader::durable::inspect_document(path, original, converted)? {
                Native::Original {
                    metadata,
                    read_only,
                } => Host::Original {
                    metadata,
                    read_only,
                },
                Native::Converted => Host::Converted,
                Native::Missing => Host::Missing,
                Native::Changed => Host::Changed,
            },
        )
    }

    fn replace_document(
        &self,
        path: &Path,
        original: &[u8],
        converted: &[u8],
        metadata: &[u8],
    ) -> std::io::Result<busbar_kernel::durable::DocumentReplace> {
        document_replace(crate::root::loader::durable::replace_document(
            path, original, converted, metadata,
        ))
    }

    fn recover_document(
        &self,
        path: &Path,
        converted: &[u8],
        metadata: &[u8],
    ) -> std::io::Result<busbar_kernel::durable::DocumentReplace> {
        document_replace(crate::root::loader::durable::recover_document(
            path, converted, metadata,
        ))
    }
}

fn document_replace(
    result: std::io::Result<crate::root::loader::durable::DocumentReplace>,
) -> std::io::Result<busbar_kernel::durable::DocumentReplace> {
    use crate::root::loader::durable::DocumentReplace as Native;
    use busbar_kernel::durable::DocumentReplace as Host;
    Ok(match result? {
        Native::Published => Host::Published,
        Native::AlreadyConverted => Host::AlreadyConverted,
        Native::ReadOnly => Host::ReadOnly,
        Native::Missing => Host::Missing,
        Native::Changed => Host::Changed,
    })
}

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

pub fn hook_answers(rows: &dyn busbar_contract::plugin_rows::PluginRows, module: &str) -> bool {
    crate::root::loader::rows::registry_of(rows)
        .is_some_and(|registry| crate::root::loader::hook_door::dropped_answers(registry, module))
}

pub fn auth_chain_module(door: busbar_contract::abi::mechanism::door::DoorFn) -> bool {
    crate::root::loader::dispatch::kinds::auth::declares_chain_module(door)
}

pub fn dispatch_latched() -> bool {
    crate::root::loader::dispatch::handle::latched()
}

#[cfg(test)]
mod store_overlay_management {
    use busbar_kernel::config::overlay::{persist_root_async, resolve_backend, RootSettings};
    use busbar_kernel::config::ConfigMgmtCfg;
    #[tokio::test]
    async fn mutable_management_persists_to_the_configured_store() {
        let cfg = ConfigMgmtCfg { locked: false };
        assert!(resolve_backend(&cfg).enabled);
        let store = busbar_kernel::config::overlay::OverlayStore::from_core(
            crate::root::real_store::core().await,
        )
        .expect("the actual configured Store supports conditional overlay persistence");
        persist_root_async(Some(&store), &RootSettings::default())
            .await
            .unwrap();
        assert!(store.read_bytes_async().await.unwrap().is_some());
    }
}
