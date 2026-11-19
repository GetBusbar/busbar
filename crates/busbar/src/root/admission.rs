// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::Path;

use busbar_kernel::admission::{Admitted, Inventoried, Judged, PluginAdmission, Refusal, Stated};
use busbar_kernel::config::PluginsCfg;
use busbar_kernel::durable::{DurableFs, DurableOpts};

use crate::root::loader::sign::{
    evaluate, evaluate_with_verification, validate_structure, Manifest, TrustPolicy, Verdict,
    HOST_IDENTITY,
};

pub(crate) static ADMISSION: RootAdmission = RootAdmission;

pub(crate) static DURABLE: RootDurable = RootDurable;

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

fn stated(m: &Manifest) -> Result<Stated, String> {
    Ok(Stated {
        name: m.name.clone(),
        alias: m.alias.clone(),
        kind: m.kind.clone(),
        version: m.version.clone(),
        signature_present: !m.signature.is_empty(),
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
    /// No linked row states a door Statement: every linked plugin is a MIN-3 image.
    fn linked_configuration(&self) -> Vec<Stated> {
        Vec::new()
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
        _config_path: &std::path::Path,
        _provider_urls: &[String],
    ) -> Result<bool, Refusal> {
        // The bootstrap selection read a dropped-in transport or plane door's Statement. Every
        // plugin is a MIN-3 image now: no dropped-in door is selected for the bootstrap, and the
        // archive still has to unpack and verify.
        unpack_checked(tarball, " bootstrap candidate")?;
        Ok(false)
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
        let (verdict, verification) =
            evaluate_with_verification(&unpacked.lib_bytes, manifest, &policy).map_err(
                |rejected| {
                    Refusal::Conflict(format!(
                        "plugin rejected by the trust policy: {}",
                        rejected.reason
                    ))
                },
            )?;
        let judged = match verdict {
            Verdict::Trusted { publisher, .. } => Judged::Trusted { publisher },
            Verdict::Allowed { .. } => Judged::Allowed,
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
            verification,
            linked_serves,
        })
    }

    fn inspect(&self, tarball: &[u8], cfg: &PluginsCfg) -> Result<(Stated, Judged), Refusal> {
        self.inspect_with_verification(tarball, cfg)
            .map(|(stated, judged, _)| (stated, judged))
    }

    fn inspect_with_verification(
        &self,
        tarball: &[u8],
        cfg: &PluginsCfg,
    ) -> Result<(Stated, Judged, busbar_contract::plugin_rows::Verification), Refusal> {
        let policy = install_policy(cfg, env!("CARGO_PKG_VERSION")).map_err(Refusal::Validation)?;
        inspect_with_policy(tarball, &policy)
    }

    fn inspect_installed_with_verification(
        &self,
        tarball: &[u8],
        cfg: &PluginsCfg,
    ) -> Result<(Stated, Judged, busbar_contract::plugin_rows::Verification), Refusal> {
        let policy = policy(cfg, env!("CARGO_PKG_VERSION")).map_err(Refusal::Validation)?;
        inspect_with_policy(tarball, &policy)
    }

    fn inspect_audited(
        &self,
        tarball: &[u8],
        cfg: &PluginsCfg,
        installed: bool,
        principal: &str,
    ) -> busbar_kernel::admission::Inspection {
        let policy = if installed {
            policy(cfg, env!("CARGO_PKG_VERSION"))
        } else {
            install_policy(cfg, env!("CARGO_PKG_VERSION"))
        };
        match policy {
            Ok(policy) => inspect_by(tarball, &policy, principal),
            Err(text) => (Err(Refusal::Validation(text)), None),
        }
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

fn inspect_with_policy(
    tarball: &[u8],
    policy: &TrustPolicy,
) -> Result<(Stated, Judged, busbar_contract::plugin_rows::Verification), Refusal> {
    inspect_by(tarball, policy, "anonymous").0
}

/// One inspection for `principal` (DES-443 r3): the manifest view, with a Trusted native image's D_SCHEMA read by
/// the loader's describe-only inspection, and the audit facts of that load (None when nothing was loaded).
fn inspect_by(
    tarball: &[u8],
    policy: &TrustPolicy,
    principal: &str,
) -> busbar_kernel::admission::Inspection {
    let unpacked = match unpack_checked(tarball, "") {
        Ok(unpacked) => unpacked,
        Err(refusal) => return (Err(refusal), None),
    };
    let (judged, verification) =
        match evaluate_with_verification(&unpacked.lib_bytes, &unpacked.manifest, policy) {
            Ok((Verdict::Trusted { publisher, .. }, verification)) => {
                (Judged::Trusted { publisher }, verification)
            }
            Ok((Verdict::Allowed { .. }, verification)) => (Judged::Allowed, verification),
            Err(rejected) => (
                Judged::Rejected {
                    reason: rejected.reason,
                },
                Default::default(),
            ),
        };
    let mut stated = match stated(&unpacked.manifest) {
        Ok(stated) => stated,
        Err(text) => return (Err(Refusal::Validation(text)), None),
    };
    // IF r29 l.2764: a native image's authoritative schema is the D_SCHEMA its describe answers, held to core's
    // D_SCHEMA validator. A Trusted native candidate is described without being admitted for life (#443), so the
    // inspected schema is its own and a refused describe is the inspect's refusal (#442).
    let native = match crate::root::loader::pack_native::is_native(&unpacked.lib_bytes) {
        Ok(native) => native,
        Err(text) => return (Err(Refusal::Validation(text)), None),
    };
    if !(loads_on_inspect(&judged) && native) {
        return (Ok((stated, judged, verification)), None);
    }
    let (schema, load) = native_schema(&unpacked.lib_bytes, &unpacked.manifest, policy, principal);
    match schema {
        Ok(schema) => {
            stated.settings_schema = schema;
            (Ok((stated, judged, verification)), load)
        }
        Err(refusal) => (Err(refusal), load),
    }
}

/// The process's plugin resources for an inspection's describe: the ones `main` installed, else (a test build
/// with no booted process) one made on first use.
static PROCESS: std::sync::OnceLock<
    std::sync::Arc<busbar_plugin_loader::process::ProcessResources>,
> = std::sync::OnceLock::new();

/// Install the process's plugin resources for inspection (called once by `main`).
pub(crate) fn install_process(
    process: &std::sync::Arc<busbar_plugin_loader::process::ProcessResources>,
) {
    let _ = PROCESS.set(std::sync::Arc::clone(process));
}

fn process(
) -> Result<&'static std::sync::Arc<busbar_plugin_loader::process::ProcessResources>, String> {
    if let Some(process) = PROCESS.get() {
        return Ok(process);
    }
    // The process installs its plugin sinks once (a02080fd43): with nothing installed, the start
    // stage's one set (`boot::images::process`), never a second.
    let made = super::boot::images::process()?;
    Ok(PROCESS.get_or_init(|| made))
}

/// `lib`'s D_SCHEMA text (None when it declares none), from the loader's describe-only inspection under `policy`
/// (DES-443 r3): cached, described from a resident image, or opened once, described, closed and probed. A busy
/// slot, a passed deadline or the cap is a 503 the caller may retry.
#[cfg(target_os = "linux")]
fn native_schema(
    lib: &[u8],
    manifest: &Manifest,
    policy: &TrustPolicy,
    principal: &str,
) -> (
    Result<Option<String>, Refusal>,
    Option<busbar_kernel::admission::InspectOutcome>,
) {
    use busbar_plugin_loader::inspect::{self, Unanswered};
    metrics::gauge!(busbar_kernel::snapshot::PLUGIN_INSPECT_SLOT_HELD_SECONDS)
        .set(inspect::slot_held_seconds() as f64);
    let process = match process() {
        Ok(process) => process,
        Err(text) => return (Err(Refusal::Validation(text)), None),
    };
    let (plugin, principal) = (manifest.name.clone(), principal.to_owned());
    let late = Box::new(move |outcome: inspect::InspectOutcome| {
        metrics::gauge!(busbar_kernel::snapshot::PLUGIN_INSPECT_SLOT_HELD_SECONDS).set(0.0);
        audit_late(&plugin, &principal, &kernel_outcome(&outcome));
    });
    let (answer, outcome) = inspect::describe(
        lib,
        manifest,
        policy,
        &busbar_plugin_abi::host_side::host_vt::HOST,
        process.slots(),
        late,
    );
    if outcome.reason.as_deref() == Some("inspect-cap") {
        metrics::counter!(busbar_kernel::snapshot::PLUGIN_INSPECT_CAP_REFUSALS_TOTAL).increment(1);
    }
    metrics::gauge!(busbar_kernel::snapshot::PLUGIN_INSPECT_SLOT_HELD_SECONDS)
        .set(inspect::slot_held_seconds() as f64);
    let answer = match answer {
        Ok(described) => Ok(described.schema.map(String::from)),
        Err(Unanswered::Refused(refusal)) => Err(Refusal::Validation(refusal.to_string())),
        Err(Unanswered::Unavailable {
            text,
            retry_after_s,
        }) => Err(Refusal::Unavailable {
            text,
            retry_after_s,
        }),
    };
    (answer, Some(kernel_outcome(&outcome)))
}

/// Native images are inspected only where the loader's sealed-memfd staging runs.
#[cfg(not(target_os = "linux"))]
fn native_schema(
    _lib: &[u8],
    _manifest: &Manifest,
    _policy: &TrustPolicy,
    _principal: &str,
) -> (
    Result<Option<String>, Refusal>,
    Option<busbar_kernel::admission::InspectOutcome>,
) {
    (
        Err(Refusal::Validation(
            "a native plugin is inspected only on Linux, where its image can be staged".into(),
        )),
        None,
    )
}

#[cfg(target_os = "linux")]
fn kernel_outcome(
    outcome: &busbar_plugin_loader::inspect::InspectOutcome,
) -> busbar_kernel::admission::InspectOutcome {
    busbar_kernel::admission::InspectOutcome {
        sha256: hex::encode(outcome.sha256),
        opened: outcome.opened,
        outcome: outcome.outcome.word(),
        reason: outcome.reason.clone(),
    }
}

/// The audit row of an inspection that finished after its request answered 503 (DES-443 r3 §5): the same fields as
/// the request's row, the principal captured at dispatch, outcome `late`.
#[cfg(target_os = "linux")]
fn audit_late(plugin: &str, principal: &str, outcome: &busbar_kernel::admission::InspectOutcome) {
    let mut message = format!(
        "verdict=trusted opened={} sha256={}",
        outcome.opened, outcome.sha256
    );
    if let Some(reason) = &outcome.reason {
        message.push_str(" reason=");
        message.push_str(reason);
    }
    busbar_kernel::audit_ring::AUDIT.record_row(busbar_kernel::audit::auditlog::AuditRowInput {
        action: "plugin.inspect".into(),
        resource: format!("plugin:{plugin}"),
        outcome: outcome.outcome.into(),
        principal: principal.into(),
        kind: Some("plugin".into()),
        message,
        ..Default::default()
    });
}

/// Which verdicts an inspection may load (dlopen and describe) to read a native image's D_SCHEMA: Trusted only
/// (DES-443 H1). An operator opt-in (`allow_untrusted`: Allowed) is shown from its manifest and never executed.
fn loads_on_inspect(judged: &Judged) -> bool {
    matches!(judged, Judged::Trusted { .. })
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
                    abi_version: crate::root::loader::supported_abi("hook").unwrap(),
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
            crate::root::loader::durable::DurableOpts { mode: opts.mode },
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
/// DES-443 H1: inspect loads only a Trusted candidate. An operator opt-in (Allowed) or a refused one is shown from
/// its manifest alone and never loaded, so a read-only preview never executes an untrusted image.
#[cfg(test)]
mod inspect_tests {
    use super::*;

    fn bomb_tarball() -> (Vec<u8>, String) {
        let path = crate::root::test_plugins::native_schema_bomb_path().unwrap_or_else(|| {
            crate::root::test_plugins::missing(
                "native_schema_bomb",
                crate::root::test_plugins::BUILD_LOADER_EXAMPLES,
            )
        });
        let manifest = crate::root::test_plugins::native_manifest("store", &path, "acme");
        let name = manifest.name.clone();
        let lib = std::fs::read(&path).expect("the bomb image reads");
        let tarball = crate::root::loader::tarball::package(&manifest, "lib.so", &lib)
            .expect("the unsigned bomb packs");
        (tarball, name)
    }

    #[test]
    fn only_a_trusted_verdict_loads_on_inspect() {
        assert!(loads_on_inspect(&Judged::Trusted {
            publisher: "acme".into()
        }));
        assert!(!loads_on_inspect(&Judged::Allowed));
        assert!(!loads_on_inspect(&Judged::Rejected {
            reason: "unsigned".into()
        }));
    }

    #[test]
    fn an_allowed_candidate_is_shown_from_its_manifest_and_never_loaded() {
        let (tarball, _) = bomb_tarball();
        let policy = TrustPolicy {
            allow_untrusted: true,
            ..TrustPolicy::default()
        };
        let (stated, judged, _) = inspect_with_policy(&tarball, &policy)
            .expect("an allowed image inspects from its manifest; its D_SCHEMA is never read");
        assert!(matches!(judged, Judged::Allowed), "{judged:?}");
        assert!(stated.settings_schema.is_none());
    }

    /// #443 (DES-443 r3, A-F3): inspecting a Trusted native image that is never installed leaves no resident
    /// mapping: it is described, closed on a worker and unloaded (or pinned), never admitted for life.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_inspected_image_is_not_left_resident() {
        use crate::root::loader::sign::{sign, PublisherKey, PublisherTrust, SigningKey};
        let path = crate::root::test_plugins::native_schema_bomb_path().unwrap_or_else(|| {
            crate::root::test_plugins::missing(
                "native_schema_bomb",
                crate::root::test_plugins::BUILD_LOADER_EXAMPLES,
            )
        });
        let lib = std::fs::read(&path).expect("the bomb image reads");
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let manifest = crate::root::test_plugins::native_manifest("store", &path, "acme");
        let name = manifest.name.clone();
        let manifest = sign(&key, manifest, &lib);
        let tarball = crate::root::loader::tarball::package(&manifest, "lib.so", &lib)
            .expect("the signed bomb packs");
        let mut policy = TrustPolicy::default();
        policy.publishers.insert(
            "acme".into(),
            PublisherTrust {
                plugins: [name].into_iter().collect(),
                keys: vec![PublisherKey {
                    key: key.verifying_key(),
                    revoked: false,
                }],
            },
        );
        let refused = inspect_with_policy(&tarball, &policy);
        assert!(
            refused.is_err(),
            "the Trusted bomb is described and refused"
        );
        let sha256 = busbar_contract::crypto::sha256(&lib);
        assert!(
            !crate::root::loader::admit::is_resident(&sha256),
            "an inspected image that is never installed is not left resident"
        );
    }

    #[test]
    fn a_rejected_candidate_is_shown_from_its_manifest_and_never_loaded() {
        let (tarball, _) = bomb_tarball();
        let (stated, judged, _) = inspect_with_policy(&tarball, &TrustPolicy::default())
            .expect("a rejected image inspects from its manifest");
        assert!(matches!(judged, Judged::Rejected { .. }), "{judged:?}");
        assert!(stated.settings_schema.is_none());
    }
}
