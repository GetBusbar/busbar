// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::config::{migrated_store_module, HookCfg, HookKind, PromptAccess, UserAccess};

#[path = "bootstrap_rollback.rs"]
mod bootstrap_rollback;
#[path = "usage_adjustment_range.rs"]
mod usage_adjustment_range;

pub(crate) fn hook(kind: HookKind, global: bool) -> HookCfg {
    HookCfg {
        kind,
        plugin: "test-hook".to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new(),
        at: None,
        on_empty: None,
        global,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

use busbar_kernel::admission::{Admitted, Inventoried, Judged, PluginAdmission, Refusal, Stated};

fn tmp_plugins_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);

    static PROC_TOKEN: std::sync::OnceLock<u128> = std::sync::OnceLock::new();
    let token = PROC_TOKEN.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    });
    let d = std::env::temp_dir().join(format!(
        "busbar-plugin-admin-{}-{token:x}-{n}-{tag}",
        std::process::id(),
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

const FAKE_HEAD: &[u8] = b"busbar-admin-test-plugin\n";

pub(crate) struct DirAdmission;

pub(crate) static DIR_ADMISSION: DirAdmission = DirAdmission;

const FAKE_MAX_TARBALL_BYTES: u64 = 64 * 1024;

fn fake_tarball(name: &str, alias: &str, version: &str, trust: &str) -> Vec<u8> {
    fake_tarball_with(name, alias, version, trust, None)
}

fn fake_tarball_with(
    name: &str,
    alias: &str,
    version: &str,
    trust: &str,
    settings_schema: Option<String>,
) -> Vec<u8> {
    let mut out = FAKE_HEAD.to_vec();
    out.extend_from_slice(
        serde_json::json!({
            "name": name,
            "alias": alias,
            "kind": "store",
            "version": version,
            "publisher": "acme",
            "abi_version": 3,
            "settings_schema": settings_schema,
            "trust": trust,
        })
        .to_string()
        .as_bytes(),
    );
    out
}

impl DirAdmission {
    fn rollback_only(bytes: &[u8]) -> bool {
        bytes
            .strip_prefix(FAKE_HEAD)
            .and_then(|json| serde_json::from_slice::<serde_json::Value>(json).ok())
            .is_some_and(|value| value["trust"].as_str() == Some("rollback-only"))
    }

    fn read(bytes: &[u8]) -> Result<(Stated, Judged), String> {
        let json = bytes
            .strip_prefix(FAKE_HEAD)
            .ok_or_else(|| "not a test plugin tarball".to_string())?;
        let v: serde_json::Value =
            serde_json::from_slice(json).map_err(|e| format!("manifest: {e}"))?;
        let word = |k: &str| v[k].as_str().unwrap_or_default().to_string();
        let stated = Stated {
            name: word("name"),
            alias: word("alias"),
            kind: word("kind"),
            version: word("version"),
            publisher: word("publisher"),
            abi_version: v["abi_version"].as_u64().unwrap_or_default() as u32,
            settings_schema: v["settings_schema"].as_str().map(str::to_string),
        };
        let judged = match v["trust"].as_str() {
            Some("trusted") => Judged::Trusted {
                publisher: stated.publisher.clone(),
            },
            Some("allowed") => Judged::Allowed,
            Some("rollback-only") => Judged::Rejected {
                reason: "operator bootstrap floor rejects this test target".into(),
            },
            _ => Judged::Rejected {
                reason: "unsigned plugin (set plugins.trust.allow_unsigned)".to_string(),
            },
        };
        Ok((stated, judged))
    }
}

impl PluginAdmission for DirAdmission {
    fn is_tarball(&self, file: &str) -> bool {
        file.ends_with(".tar.gz") || file.ends_with(".tgz")
    }

    fn max_tarball_bytes(&self) -> u64 {
        FAKE_MAX_TARBALL_BYTES
    }

    fn restart_default(&self, kind: &str) -> bool {
        kind != "hook"
    }

    fn policy_resolves(&self, _cfg: &busbar_kernel::config::PluginsCfg) -> Result<(), String> {
        Ok(())
    }

    fn inventory(
        &self,
        dir: &std::path::Path,
        _cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Result<Vec<Inventoried>, String> {
        let entries = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Ok(vec![Inventoried {
                    file: dir.display().to_string(),
                    stated: None,
                    signature: "-".to_string(),
                    status: format!("INVALID: cannot read plugins dir: {e}"),
                }])
            }
        };
        let mut files: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|f| self.is_tarball(f))
            .collect();
        files.sort();
        Ok(files
            .into_iter()
            .map(|file| {
                let read = std::fs::read(dir.join(&file))
                    .map_err(|e| e.to_string())
                    .and_then(|bytes| Self::read(&bytes));
                match read {
                    Ok((stated, Judged::Trusted { publisher })) => Inventoried {
                        file,
                        stated: Some(stated),
                        signature: format!("publisher:{publisher}"),
                        status: "ready".to_string(),
                    },
                    Ok((stated, Judged::Allowed)) => Inventoried {
                        file,
                        stated: Some(stated),
                        signature: "unsigned (allowed)".to_string(),
                        status: "ready".to_string(),
                    },
                    Ok((stated, Judged::Rejected { reason })) => Inventoried {
                        file,
                        stated: Some(stated),
                        signature: "unsigned".to_string(),
                        status: format!("SKIPPED: {reason}"),
                    },
                    Err(e) => Inventoried {
                        file,
                        stated: None,
                        signature: "-".to_string(),
                        status: format!("INVALID: {e}"),
                    },
                }
            })
            .collect())
    }

    fn admit_upload(
        &self,
        _dir: &std::path::Path,
        _file: &str,
        tarball: &[u8],
        cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Result<Admitted, Refusal> {
        let (stated, mut judged) = Self::read(tarball)
            .map_err(|e| Refusal::Validation(format!("invalid plugin tarball: {e}")))?;
        if Self::rollback_only(tarball)
            && cfg.min_versions.get(&stated.name) == Some(&stated.version)
        {
            judged = Judged::Trusted {
                publisher: stated.publisher.clone(),
            };
        }
        if let Judged::Rejected { reason } = judged {
            return Err(Refusal::Conflict(format!(
                "plugin rejected by the trust policy: {reason}"
            )));
        }
        Ok(Admitted {
            stated,
            judged,
            linked_serves: false,
        })
    }

    fn inspect(
        &self,
        tarball: &[u8],
        cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Result<(Stated, Judged), Refusal> {
        let (stated, mut judged) = Self::read(tarball)
            .map_err(|e| Refusal::Validation(format!("invalid plugin tarball: {e}")))?;
        if Self::rollback_only(tarball)
            && cfg.min_versions.get(&stated.name) == Some(&stated.version)
        {
            judged = Judged::Trusted {
                publisher: stated.publisher.clone(),
            };
        }
        Ok((stated, judged))
    }

    fn rollback_target(
        &self,
        file: &str,
        bytes: &[u8],
        _cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Result<Stated, Refusal> {
        match Self::read(bytes) {
            Ok((stated, Judged::Trusted { .. } | Judged::Allowed)) => Ok(stated),
            Ok((stated, _)) if Self::rollback_only(bytes) => Ok(stated),
            Ok((stated, Judged::Rejected { reason })) => Err(Refusal::Conflict(format!(
                "rollback target `{file}` is not loadable under the trust policy even with the \
                 floor lowered to its own version {}: {reason}",
                stated.version
            ))),
            Err(e) => Err(Refusal::Validation(format!(
                "invalid plugin tarball `{file}`: {e}"
            ))),
        }
    }
}

fn app_with(
    dir: std::path::PathBuf,
    cfg: busbar_kernel::config::PluginsCfg,
) -> std::sync::Arc<busbar_kernel::state::App> {
    crate::new_test_app()
        .plugins_dir(dir)
        .plugins_cfg(cfg)
        .plugin_admission(&DIR_ADMISSION)
        .build()
}

fn svc_with(dir: std::path::PathBuf, cfg: busbar_kernel::config::PluginsCfg) -> AdminService {
    AdminService::new(app_with(dir, cfg))
}

fn strict_posture() -> busbar_kernel::config::PluginsCfg {
    busbar_kernel::config::PluginsCfg::default()
}

fn unsigned_ok_posture() -> busbar_kernel::config::PluginsCfg {
    let mut cfg = busbar_kernel::config::PluginsCfg::default();
    cfg.trust.allow_unsigned = true;
    cfg
}

#[test]
fn inspect_rejects_oversized_tarball_before_unpacking() {
    let cap = 64 * 1024;
    let huge = vec![0u8; cap + 1];
    let err = check_inspect_tarball_size(huge.len(), cap as u64).unwrap_err();
    assert!(
        matches!(&err, AdminError::Validation(msg) if msg.contains("byte cap")),
        "got {err:?}"
    );
}

#[test]
fn inspect_reports_the_admissions_verdict_in_the_catalog_vocabulary() {
    for (judged, word) in [
        (
            Judged::Trusted {
                publisher: "acme".into(),
            },
            "trusted",
        ),
        (Judged::Allowed, "unverified"),
        (
            Judged::Rejected {
                reason: "unsigned plugin".into(),
            },
            "rejected",
        ),
    ] {
        let manifest = Stated {
            name: "acme-store-v".into(),
            alias: "v".into(),
            kind: "store".into(),
            version: "1.0.0".into(),
            publisher: "acme".into(),
            abi_version: 3,
            settings_schema: None,
        };
        let view = inspect_plugin_view(manifest, judged, |_| true);
        assert_eq!(view["trust"], word, "{word}");
        assert_eq!(view["name"], "acme-store-v");
        assert_eq!(view["kind"], "store");
        assert_eq!(view["restart_required_default"], true);
    }
}

#[test]
fn install_answers_the_admissions_refusals_in_their_classes() {
    let dir = tmp_plugins_dir("refusal-classes");
    let svc = svc_with(dir.clone(), strict_posture());
    assert!(matches!(
        svc.install_store_plugin("x.tar.gz", b"garbage, not a tarball"),
        Err(AdminError::Validation(msg)) if msg.starts_with("invalid plugin tarball")
    ));
    assert!(matches!(
        svc.install_store_plugin("x.tar.gz", &fake_tarball("acme-store-x", "x", "1.0.0", "rejected")),
        Err(AdminError::Conflict(msg)) if msg.starts_with("plugin rejected by the trust policy")
    ));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

#[test]
fn install_catalog_remove_roundtrip() {
    let dir = tmp_plugins_dir("roundtrip");
    let svc = svc_with(dir.clone(), unsigned_ok_posture());
    let tarball = fake_tarball("acme-store-junk", "junkstore", "1.0.0", "allowed");

    let view = svc
        .install_store_plugin("junk.tar.gz", &tarball)
        .expect("an unsigned tarball installs under allow_unsigned");
    assert_eq!(view.trust, "unverified");
    assert_eq!(view.name, "acme-store-junk");
    assert!(dir.join("junk.tar.gz").exists(), "tarball published");

    let cat = svc.store_plugin_catalog();
    assert_eq!(cat[0].name, migrated_store_module());
    let dyn_row = cat
        .iter()
        .find(|p| p.loader == "dynamic-library")
        .expect("dynamic plugin in catalog");
    assert_eq!(dyn_row.valid, Some(true));
    assert_eq!(dyn_row.name, "acme-store-junk");
    assert_eq!(dyn_row.target.as_deref(), Some("junk.tar.gz"));
    assert_eq!(dyn_row.trust, Some("unverified"));

    let reload = svc.reload_store_plugins().unwrap();
    assert!(reload.plugins.iter().all(|p| p.loader == "dynamic-library"));
    assert_eq!(reload.plugins.len(), 1);

    svc.remove_store_plugin("junk.tar.gz").expect("remove");
    assert!(!dir.join("junk.tar.gz").exists());
    assert!(matches!(
        svc.remove_store_plugin("junk.tar.gz"),
        Err(AdminError::NotFound { .. })
    ));
}

#[test]
fn install_filesystem_failures_are_internal_errors() {
    let dir = tmp_plugins_dir("install-io-errors");
    let blocked_dir = dir.join("not-a-directory");
    std::fs::write(&blocked_dir, b"keep this file").unwrap();
    let publish_dir = dir.join("publish");
    std::fs::create_dir(&publish_dir).unwrap();
    std::fs::create_dir(publish_dir.join("plugin.tar.gz")).unwrap();
    let tarball = fake_tarball("acme-store-io", "io", "1.0.0", "allowed");

    for plugins_dir in [&blocked_dir, &publish_dir] {
        let svc = svc_with(plugins_dir.clone(), unsigned_ok_posture());
        let invalid = svc
            .install_store_plugin("plugin.tar.gz", b"not a tarball")
            .unwrap_err();
        assert_eq!(invalid.http_status(), 400);
        assert_eq!(invalid.code(), "invalid_request");

        let err = svc
            .install_store_plugin("plugin.tar.gz", &tarball)
            .unwrap_err();
        assert!(matches!(err, AdminError::Internal), "{err:?}");
        assert_eq!(err.http_status(), 500);
        assert_eq!(err.code(), "internal");
        assert_eq!(err.message(), AdminError::Internal.message());
    }
    assert_eq!(std::fs::read(&blocked_dir).unwrap(), b"keep this file");
    assert!(publish_dir.join("plugin.tar.gz").is_dir());
    assert_eq!(std::fs::read_dir(&publish_dir).unwrap().count(), 1);

    let svc = svc_with(dir.clone(), unsigned_ok_posture());
    svc.install_store_plugin("ok.tar.gz", &tarball).unwrap();
    assert_eq!(std::fs::read(dir.join("ok.tar.gz")).unwrap(), tarball);
    assert!(svc.remove_store_plugin("ok.tar.gz").unwrap().removed);
    let missing = svc.remove_store_plugin("ok.tar.gz").unwrap_err();
    assert_eq!(missing.http_status(), 404);
    assert_eq!(missing.code(), "not_found");
}

#[cfg(unix)]
#[test]
fn remove_filesystem_failure_is_internal_error() {
    use std::os::unix::fs::PermissionsExt;

    struct RestorePermissions(std::path::PathBuf, std::fs::Permissions);
    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, self.1.clone());
        }
    }

    let dir = tmp_plugins_dir("remove-io-error");
    let file = dir.join("plugin.tar.gz");
    let probe = dir.join("unlink-probe");
    std::fs::write(&file, b"keep this plugin").unwrap();
    std::fs::write(&probe, b"probe").unwrap();
    let svc = svc_with(dir.clone(), unsigned_ok_posture());
    let _restore = RestorePermissions(dir.clone(), std::fs::metadata(&dir).unwrap().permissions());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    match std::fs::remove_file(&probe) {
        Ok(()) => {
            eprintln!(
                "remove failure regression not exercised: runner bypasses directory mode bits"
            );
            return;
        }
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
    }
    assert!(file.is_file(), "the existing-file guard must pass");
    let err = svc.remove_store_plugin("plugin.tar.gz").unwrap_err();
    assert!(matches!(err, AdminError::Internal), "{err:?}");
    assert_eq!(err.http_status(), 500);
    assert_eq!(err.code(), "internal");
    assert_eq!(err.message(), AdminError::Internal.message());
    assert_eq!(std::fs::read(file).unwrap(), b"keep this plugin");
}

#[test]
fn catalog_preserves_manifest_kinds_and_filters_store_queries() {
    let mut inventory = Vec::new();
    for kind in [
        "store",
        "auth",
        "secret",
        "hook",
        "export",
        "transport",
        "plane",
        "unknown",
    ] {
        inventory.push(Inventoried {
            file: format!("{kind}.tar.gz"),
            stated: Some(Stated {
                name: kind.into(),
                alias: kind.into(),
                kind: kind.into(),
                version: "1.0.0".into(),
                publisher: "acme".into(),
                abi_version: 3,
                settings_schema: None,
            }),
            signature: "unsigned (allowed)".into(),
            status: "ready".into(),
        });
    }
    inventory.push(Inventoried {
        file: "corrupt.tar.gz".into(),
        stated: None,
        signature: "-".into(),
        status: "INVALID: invalid manifest".into(),
    });
    let catalog: Vec<_> = inventory.into_iter().map(plugin_inventory_view).collect();
    for kind in [
        "store",
        "auth",
        "secret",
        "hook",
        "export",
        "transport",
        "plane",
        "unknown",
        "corrupt",
    ] {
        let file = format!("{kind}.tar.gz");
        let row = catalog
            .iter()
            .find(|p| p.file.as_deref() == Some(file.as_str()))
            .unwrap();
        let expected = if matches!(kind, "unknown" | "corrupt") {
            "store"
        } else {
            kind
        };
        assert_eq!(row.r#type, expected, "{file}");
    }
    for query in ["store", "db"] {
        assert!(matches!(plugin_query(query), Ok(PluginQuery::Store)));
        let mut files: Vec<_> = catalog_rows_of_kind(catalog.clone(), "store")
            .filter_map(|row| row.file)
            .collect();
        files.sort();
        assert_eq!(files, ["corrupt.tar.gz", "store.tar.gz", "unknown.tar.gz"]);
    }
    for query in ["export", "transport", "plane"] {
        assert!(
            matches!(plugin_query(query), Err(AdminError::Validation(_))),
            "the catalog correction adds no new query type"
        );
    }
}

#[test]
fn catalog_projects_each_inventory_row_into_the_catalog_vocabulary() {
    let mut inventory = Vec::new();
    for (file, name, signature, status) in [
        ("a.tar.gz", "acme-store-a", "publisher:acme", "ready"),
        ("b.tar.gz", "acme-store-b", "unsigned (allowed)", "ready"),
        (
            "c.tar.gz",
            "acme-store-c",
            "unsigned",
            "SKIPPED: unsigned plugin",
        ),
    ] {
        inventory.push(Inventoried {
            file: file.into(),
            stated: Some(Stated {
                name: name.into(),
                alias: name.into(),
                kind: "store".into(),
                version: "2.1.0".into(),
                publisher: "acme".into(),
                abi_version: 3,
                settings_schema: None,
            }),
            signature: signature.into(),
            status: status.into(),
        });
    }
    inventory.push(Inventoried {
        file: "d.tar.gz".into(),
        stated: None,
        signature: "-".into(),
        status: "INVALID: not a tarball".into(),
    });
    let cat: Vec<_> = inventory.into_iter().map(plugin_inventory_view).collect();
    let row = |file: &str| {
        cat.iter()
            .find(|p| p.target.as_deref() == Some(file))
            .unwrap_or_else(|| panic!("{file} is listed: {cat:?}"))
    };
    assert_eq!(row("a.tar.gz").trust, Some("trusted"));
    assert_eq!(row("a.tar.gz").publisher.as_deref(), Some("acme"));
    assert_eq!(row("a.tar.gz").version.as_deref(), Some("2.1.0"));
    assert_eq!(row("b.tar.gz").trust, Some("unverified"));
    assert_eq!(row("c.tar.gz").trust, Some("rejected"));
    assert_eq!(row("c.tar.gz").valid, Some(false));
    assert!(row("c.tar.gz")
        .error
        .as_deref()
        .is_some_and(|e| e.contains("SKIPPED")));
    assert_eq!(row("d.tar.gz").trust, None);
    assert_eq!(
        row("d.tar.gz").name,
        "d.tar.gz",
        "no manifest: named by its file"
    );
}

#[test]
fn catalog_repeat_gets_reuse_the_cached_scan() {
    let dir = tmp_plugins_dir("cache-reuse");
    let svc = svc_with(dir.clone(), unsigned_ok_posture());
    let tarball = fake_tarball("acme-store-cache", "cachestore", "1.0.0", "allowed");
    svc.install_store_plugin("cache.tar.gz", &tarball)
        .expect("install");

    for _ in 0..5 {
        let cat = svc.store_plugin_catalog();
        assert!(cat.iter().any(|p| p.name == "acme-store-cache"));
    }
    let misses_after_repeats = catalog_cache().lock().unwrap()[&dir].misses;
    assert_eq!(
        misses_after_repeats, 1,
        "5 repeat GETs over an unchanged directory must cost exactly 1 real scan"
    );

    let tarball2 = fake_tarball("acme-store-cache-2", "cachestore2", "1.0.0", "allowed");
    svc.install_store_plugin("cache2.tar.gz", &tarball2)
        .expect("install");

    let cat = svc.store_plugin_catalog();
    assert!(
        cat.iter().any(|p| p.name == "acme-store-cache-2"),
        "the newly installed plugin is visible on the very next GET"
    );
    let misses_after_change = catalog_cache().lock().unwrap()[&dir].misses;
    assert_eq!(
        misses_after_change, 2,
        "a real directory change must invalidate the cache and cost exactly 1 more scan"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn list_plugins_store_scan_does_not_park_the_reactor() {
    let dir = tmp_plugins_dir("no-park");
    for i in 0..2000 {
        let tarball = fake_tarball(
            &format!("acme-store-{i}"),
            &format!("s{i}"),
            "1.0.0",
            "trusted",
        );
        std::fs::write(dir.join(format!("p{i}.tar.gz")), &tarball).unwrap();
    }
    let svc = svc_with(dir.clone(), strict_posture());

    let _delay_guard =
        catalog_scan_test_hooks::set_delay(dir, std::time::Duration::from_millis(400));

    let scanner =
        tokio::spawn(async move { svc.list_plugins("store").await.expect("catalog read ok") });
    let start = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let elapsed = start.elapsed();
    let page = scanner.await.unwrap();
    assert!(
        elapsed < std::time::Duration::from_millis(300),
        "a 50ms sleep took {elapsed:?} — the catalog scan parked the reactor"
    );
    assert!(
        page.items.len() > 2000,
        "the scan actually ran and produced rows: got {}",
        page.items.len()
    );
}

#[tokio::test]
async fn store_plugin_catalog_async_survives_a_spawn_blocking_panic() {
    let dir = tmp_plugins_dir("panic-fallback");
    let svc = svc_with(dir.clone(), unsigned_ok_posture());

    let _panic_guard = catalog_scan_test_hooks::set_panic(dir);

    let page = svc
        .list_plugins("store")
        .await
        .expect("a panicking scan must fall back gracefully, never propagate as an error");
    assert_eq!(
        page.items.len(),
        1,
        "the panic fallback must be exactly the one compiled-in `memory` row: {:?}",
        page.items
    );
    assert_eq!(page.items[0].name, migrated_store_module());
    assert_eq!(page.items[0].loader, "compiled-in");
}

#[tokio::test(start_paused = true)]
async fn store_plugin_catalog_async_times_out_when_gate_is_held() {
    let dir = tmp_plugins_dir("gate-timeout");
    let svc = svc_with(dir, unsigned_ok_posture());

    let _held = CATALOG_SCAN_GATE.lock().await;

    let call = tokio::spawn(async move { svc.list_plugins("store").await });
    tokio::time::advance(CATALOG_SCAN_GATE_WAIT + std::time::Duration::from_millis(1)).await;
    let result = call.await.expect("caller task must not panic");
    assert!(
        matches!(result, Err(AdminError::Unavailable(_))),
        "a caller that cannot acquire the gate within the wait bound must get a clear, \
             retryable error instead of hanging: {result:?}"
    );
}

#[tokio::test]
async fn list_plugins_store_single_flights_concurrent_misses() {
    let dir = tmp_plugins_dir("single-flight");
    let tarball = fake_tarball("acme-store-sf", "sfstore", "1.0.0", "allowed");
    std::fs::write(dir.join("sf.tar.gz"), &tarball).unwrap();

    let app = app_with(dir.clone(), unsigned_ok_posture());

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            AdminService::new(app)
                .list_plugins("store")
                .await
                .expect("catalog read ok")
        }));
    }
    for t in tasks {
        let page = t.await.unwrap();
        assert!(
            page.items.iter().any(|p| p.name == "acme-store-sf"),
            "every one of the 10 concurrent callers must see the real (not truncated) catalog"
        );
    }

    let misses = catalog_cache().lock().unwrap()[&dir].misses;
    assert_eq!(
            misses, 1,
            "10 concurrent cache-miss callers must single-flight into exactly 1 real scan, got {misses}"
        );
}

#[test]
fn catalog_cache_ttl_prunes_stale_entries() {
    let now = CATALOG_CACHE_TTL_SECS + 10;
    let dir = std::path::PathBuf::from("cached");
    let mut cache = HashMap::from([(
        dir.clone(),
        CatalogCacheEntry {
            key: 0,
            rows: Vec::new(),
            misses: 1,
            inserted_at: now,
        },
    )]);
    assert!(
        cache.contains_key(&dir),
        "the input contains a cached entry"
    );
    cache.get_mut(&dir).expect("entry present").inserted_at =
        now.saturating_sub(CATALOG_CACHE_TTL_SECS + 1);
    prune_catalog_cache(&mut cache, now);
    assert!(
        !cache.contains_key(&dir),
        "an entry older than CATALOG_CACHE_TTL_SECS must be pruned on the next cache access"
    );
}

#[test]
fn catalog_cache_future_inserted_at_is_treated_as_stale() {
    let now = CATALOG_CACHE_TTL_SECS + 10;
    let dir = std::path::PathBuf::from("cached");
    let mut cache = HashMap::from([(
        dir.clone(),
        CatalogCacheEntry {
            key: 0,
            rows: Vec::new(),
            misses: 1,
            inserted_at: now,
        },
    )]);
    assert!(
        cache.contains_key(&dir),
        "the input contains a cached entry"
    );
    cache.get_mut(&dir).expect("entry present").inserted_at = now + CATALOG_CACHE_TTL_SECS + 1;
    prune_catalog_cache(&mut cache, now);
    assert!(!cache.contains_key(&dir), "an entry whose inserted_at is in the future (backward clock jump) must be treated as stale, not ageless");
}

#[cfg(unix)]
#[test]
fn catalog_unreadable_dir_does_not_serve_stale_cache() {
    let dir = tmp_plugins_dir("unreadable");
    let svc = svc_with(dir.clone(), unsigned_ok_posture());

    let cat = svc.store_plugin_catalog();
    assert!(
        cat.iter().all(|p| p.loader != "dynamic-library"),
        "an empty, readable plugins dir has no dynamic-library rows"
    );
    assert!(
        catalog_cache().lock().unwrap().contains_key(&dir),
        "an empty dir's (empty) scan is cached, exactly like a missing dir would be"
    );

    struct RemoveFileOnDrop<'a>(&'a std::path::Path);
    impl Drop for RemoveFileOnDrop<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }

    std::fs::remove_dir(&dir).unwrap();
    std::fs::write(&dir, b"not a directory").unwrap();
    let _remove = RemoveFileOnDrop(&dir);

    assert!(
        std::fs::read_dir(&dir).is_err(),
        "a regular file at the plugins-dir path must fail read_dir for every user"
    );

    let cat_after = svc.store_plugin_catalog();

    let cat_again = svc.store_plugin_catalog();

    let row = cat_after
        .iter()
        .find(|p| p.loader == "dynamic-library")
        .expect("an unreadable dir must surface a row, never silently serve the stale empty cache");
    assert_eq!(row.valid, Some(false));
    assert!(
            row.error.as_deref().is_some_and(|e| e.starts_with("INVALID:")),
            "must be the real INVALID row surfaced by inventory_tarballs/discover, not stale data: {row:?}"
        );

    let row_again = cat_again
        .iter()
        .find(|p| p.loader == "dynamic-library")
        .expect("a second read while still unreadable surfaces the row again, every time");
    assert_eq!(row_again.error, row.error);
}

#[test]
fn rollback_reads_the_target_and_merges_pins() {
    let dir = tmp_plugins_dir("rollback-merge");
    let svc = svc_with(dir.clone(), strict_posture());
    let empty = std::collections::BTreeMap::new();

    assert!(matches!(
        svc.resolve_plugin_rollback("nope.tar.gz", &empty),
        Err(AdminError::NotFound { .. })
    ));

    std::fs::write(
        dir.join("old.tar.gz"),
        fake_tarball("acme-store-x", "x", "1.4.0", "trusted"),
    )
    .unwrap();
    let prior =
        std::collections::BTreeMap::from([("other-plugin".to_string(), "3.0.0".to_string())]);
    let (manifest, pins) = svc
        .resolve_plugin_rollback("old.tar.gz", &prior)
        .expect("rollback resolves the trusted target");
    assert_eq!(manifest.name, "acme-store-x");
    assert_eq!(manifest.version, "1.4.0");
    assert_eq!(
        pins.get("acme-store-x").map(String::as_str),
        Some("1.4.0"),
        "this plugin is pinned to the target version"
    );
    assert_eq!(
        pins.get("other-plugin").map(String::as_str),
        Some("3.0.0"),
        "a prior pin for another plugin is preserved"
    );

    std::fs::write(
        dir.join("unsigned.tar.gz"),
        fake_tarball("acme-store-x", "x", "1.4.0", "rejected"),
    )
    .unwrap();
    let err = svc
        .resolve_plugin_rollback("unsigned.tar.gz", &empty)
        .unwrap_err();
    assert!(
        matches!(err, AdminError::Conflict(_)),
        "an untrusted rollback target is refused (a rollback never launders trust), got {err:?}"
    );
}

use busbar_kernel::config::groups::{LimitMetric, LimitWindow};
use busbar_kernel::config::{GroupCfg, LimitCfg};

use busbar_kernel::governance::{GovState, VirtualKey};

use busbar_kernel_testkit::test_support::store_double::MemoryStore;

fn usage_group_cfg() -> GroupCfg {
    let limit = |metric, amount, per, pool: Option<&str>| LimitCfg {
        metric,
        amount,
        per: Some(per),
        scope: pool.map(busbar_contract::records::ScopeRef::pool),
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    };
    GroupCfg {
        limits: vec![
            limit(LimitMetric::Requests, 5, LimitWindow::Day, None),
            limit(LimitMetric::Budget, 1_000, LimitWindow::Month, None),
            limit(
                LimitMetric::Budget,
                500,
                LimitWindow::Month,
                Some("frontier"),
            ),
        ],
        ..Default::default()
    }
}

fn usage_cost(
    groups: &std::collections::BTreeMap<String, GroupCfg>,
) -> busbar_kernel::cost::CostModel {
    let card = std::collections::BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 10.0,
            output_utok: 10.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    busbar_kernel::cost::CostModel::resolve_parts(Some(&card), 0, groups)
}

fn usage_key(group: &str) -> VirtualKey {
    VirtualKey {
        id: "vk_usage_probe".to_string(),
        generation_hash: "h:vk_usage_probe".to_string(),
        name: "usage-probe".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: Some(group.to_string()),
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

fn input_toks(n: u64) -> std::collections::BTreeMap<String, u64> {
    let mut m = std::collections::BTreeMap::new();
    if n != 0 {
        m.insert(busbar_contract::records::UNIT_INPUT.to_string(), n);
    }
    m
}

#[tokio::test]
async fn get_group_usage_splits_window_pool_buckets_and_derives_remaining() {
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).unwrap());
    let app = crate::new_test_app()
        .group("acme", usage_group_cfg())
        .cost(usage_cost(&groups))
        .governance(gov.clone())
        .build();

    let k = usage_key("acme");
    let now = busbar_kernel::store::now();
    gov.try_admit(&app.cost, &k, "frontier", now)
        .expect("frontier request admits");
    gov.record_usage(&app.cost, &k, "frontier", "m", &input_toks(100_000), now);
    gov.try_admit(&app.cost, &k, "value", now)
        .expect("value request admits");
    gov.record_usage(&app.cost, &k, "value", "m", &input_toks(50_000), now);

    let svc = AdminService::new(app);
    let view = svc.get_group_usage("acme").await.expect("usage read");
    assert_eq!(view.group, "acme");
    assert!(view.enabled);
    assert!(view.as_of >= now, "as_of is the read instant");
    assert_eq!(
        view.buckets.len(),
        3,
        "three (window, pool?) buckets: {:?}",
        view.buckets
    );
    let find = |window: &str, pool: Option<&str>| {
        view.buckets
            .iter()
            .find(|b| b.window == window && b.scope.as_deref() == pool)
            .unwrap_or_else(|| panic!("bucket ({window}, {pool:?}) missing: {:?}", view.buckets))
    };

    let day = find("day", None);
    assert_eq!(day.requests, 2);
    assert_eq!(day.tokens, 150_000);
    assert_eq!(day.requests_cap, Some(5));
    assert_eq!(day.budget_cap, None);
    assert_eq!(day.budget_remaining_cents, None);

    let month = find("month", None);
    assert_eq!(month.requests, 2);
    assert_eq!(month.tokens, 150_000);
    assert_eq!(month.spend_cents, 150, "150k tokens at 1c/1k tokens");
    assert_eq!(month.budget_cap, Some(1_000));
    assert_eq!(month.budget_remaining_cents, Some(850));

    let frontier = find("month", Some("frontier"));
    assert_eq!(frontier.requests, 1);
    assert_eq!(frontier.tokens, 100_000);
    assert_eq!(frontier.spend_cents, 100);
    assert_eq!(frontier.budget_cap, Some(500));
    assert_eq!(frontier.budget_remaining_cents, Some(400));
}

#[tokio::test]
async fn get_group_usage_unknown_group_not_found() {
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    let app = crate::new_test_app()
        .group("acme", usage_group_cfg())
        .cost(usage_cost(&groups))
        .build();
    let svc = AdminService::new(app);
    let err = svc.get_group_usage("ghost").await.unwrap_err();
    assert!(
        matches!(&err, AdminError::NotFound { what: m, .. } if m.contains("ghost")),
        "unknown group is not_found: {err:?}"
    );
}

struct WaitsForTheRuntime {
    inner: MemoryStore,
    started: Arc<tokio::sync::Notify>,
    word: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    waited: std::sync::atomic::AtomicBool,
    heard: Arc<std::sync::atomic::AtomicBool>,
}

impl busbar_contract::records::RecordStore for WaitsForTheRuntime {
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_contract::records::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_contract::records::RecordStoreResult<busbar_contract::records::UsageLedger> {
        use std::sync::atomic::Ordering::SeqCst;
        if !self.waited.swap(true, SeqCst) {
            self.started.notify_one();
            let word = self
                .word
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if word.recv_timeout(std::time::Duration::from_secs(5)).is_ok() {
                self.heard.store(true, SeqCst);
            }
        }
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_contract::records::MeteringDelta,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn get_group_usage_reads_the_store_off_the_async_worker() {
    let started = Arc::new(tokio::sync::Notify::new());
    let (tell, word) = std::sync::mpsc::channel();
    let heard = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let store = Arc::new(WaitsForTheRuntime {
        inner: MemoryStore::new(),
        started: Arc::clone(&started),
        word: std::sync::Mutex::new(word),
        waited: std::sync::atomic::AtomicBool::new(false),
        heard: Arc::clone(&heard),
    });
    let sibling = tokio::spawn(async move {
        started.notified().await;
        let _ = tell.send(());
    });
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    let gov = Arc::new(GovState::new(store, None).unwrap());
    let app = crate::new_test_app()
        .group("acme", usage_group_cfg())
        .cost(usage_cost(&groups))
        .governance(gov)
        .build();
    let view = AdminService::new(app)
        .get_group_usage("acme")
        .await
        .expect("usage read");
    assert_eq!(view.buckets.len(), 3, "{:?}", view.buckets);
    sibling.await.expect("the sibling task runs");
    assert!(
        heard.load(std::sync::atomic::Ordering::SeqCst),
        "the group usage read held the async worker: no other task ran while the store read was \
         in progress"
    );
}

#[test]
fn admin_usage_breakdown_json_is_byte_identical_flat_token_aliases() {
    use crate::v1::contract::UsageBreakdown;
    let b = UsageBreakdown {
        tokens_input: 100,
        tokens_output: 40,
        tokens_cache_read: 7,
        tokens_cache_creation: 3,
        requests: 5,
        spend_micros: 12_345,
        classes: Default::default(),
    };
    let json = serde_json::to_string(&b).unwrap();
    assert_eq!(
        json,
        r#"{"tokens_input":100,"tokens_output":40,"tokens_cache_read":7,"tokens_cache_creation":3,"requests":5,"spend_micros":12345}"#,
        "the admin usage JSON must keep the flat token aliases, byte-identical to pre-M1b"
    );
}

#[tokio::test]
async fn get_group_usage_governance_off_zero_usage_caps_projected() {
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    let app = crate::new_test_app()
        .group("acme", usage_group_cfg())
        .cost(usage_cost(&groups))
        .build();
    let svc = AdminService::new(app);
    let view = svc.get_group_usage("acme").await.expect("usage read");
    assert_eq!(
        view.buckets.len(),
        3,
        "caps still projected: {:?}",
        view.buckets
    );
    for b in &view.buckets {
        assert_eq!(b.requests, 0, "governance off = zero usage ({b:?})");
        assert_eq!(b.tokens, 0);
        assert_eq!(b.spend_cents, 0);
        assert_eq!(
            b.budget_remaining_cents, b.budget_cap,
            "nothing spent ⇒ the whole cap remains ({b:?})"
        );
    }

    assert!(view.buckets.iter().any(|b| b.requests_cap == Some(5)));
    assert!(view
        .buckets
        .iter()
        .any(|b| b.budget_cap == Some(500) && b.scope.as_deref() == Some("frontier")));
}

/// A `Store` decorator whose `list_metering` always fails, everything else delegating to a
/// real `MemoryStore` — proves `get_usage`'s store-failure arm without needing a real broken
/// backend.
#[derive(Default)]
struct FailingMeteringStore {
    inner: MemoryStore,
}
impl busbar_contract::records::RecordStore for FailingMeteringStore {
    fn put_key(&self, key: &VirtualKey) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> busbar_contract::records::RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> busbar_contract::records::RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_contract::records::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_contract::records::MeteringDelta,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        _bucket: u64,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::MeteringRow>>
    {
        Err(busbar_contract::records::RecordStoreError(
            "simulated metering store outage".to_string(),
        ))
    }
}

#[test]
fn usage_read_store_failure_logs_the_real_error() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let cap = busbar_kernel_testkit::test_support::warn_capture::WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let gov =
                Arc::new(GovState::new(Arc::new(FailingMeteringStore::default()), None).unwrap());
            let app = crate::new_test_app().governance(gov).build();
            let svc = AdminService::new(app);
            let err = svc.get_usage(None, None).await.unwrap_err();
            assert!(
                matches!(err, AdminError::Internal),
                "wire contract is unchanged: still AdminError::Internal, {err:?}"
            );
        });
    });
    assert!(
        cap.contains("usage.metering") && cap.contains("simulated metering store outage"),
        "the real store error and which read failed must be logged: {:?}",
        cap.messages()
    );
}

#[test]
fn plugins_dir_fingerprint_treats_a_missing_dir_as_ok_empty() {
    let missing = tmp_plugins_dir("fingerprint-missing");
    std::fs::remove_dir_all(&missing).unwrap();
    assert!(
        !missing.exists(),
        "precondition: the directory must genuinely not exist"
    );
    let fp = plugins_dir_fingerprint(&missing).expect("a missing dir must not I/O-error");

    let empty = tmp_plugins_dir("fingerprint-really-empty");
    std::fs::create_dir_all(&empty).unwrap();
    let empty_fp =
        plugins_dir_fingerprint(&empty).expect("a real empty dir must not I/O-error either");
    assert_eq!(
        fp, empty_fp,
        "a missing dir's fingerprint must equal a real empty dir's fingerprint, not some \
             other Ok value"
    );

    std::fs::write(empty.join("something"), b"x").unwrap();
    let nonempty_fp = plugins_dir_fingerprint(&empty).expect("a populated dir must not error");
    assert_ne!(
        fp, nonempty_fp,
        "a populated dir's fingerprint must differ from the empty one"
    );
}

#[test]
fn validate_plugin_filename_rejects_each_escape_form_independently() {
    assert!(
        validate_plugin_filename_with("../evil.tar.gz", |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_err(),
        "..  alone must reject"
    );
    assert!(
        validate_plugin_filename_with("sub/evil.tar.gz", |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_err(),
        "/ alone must reject"
    );
    assert!(
        validate_plugin_filename_with("sub\\evil.tar.gz", |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_err(),
        "\\ alone must reject"
    );
    assert!(
        validate_plugin_filename_with("plain.tar.gz", |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_ok(),
        "a bare filename with none of the three must be accepted"
    );
}

#[test]
fn validate_plugin_filename_length_boundary_is_exact() {
    let suffix = ".tar.gz";
    let at_cap = "a".repeat(MAX_PLUGIN_FILENAME_LEN - suffix.len()) + suffix;
    assert_eq!(at_cap.len(), MAX_PLUGIN_FILENAME_LEN);
    assert!(
        validate_plugin_filename_with(&at_cap, |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_ok(),
        "exactly MAX_PLUGIN_FILENAME_LEN chars must be accepted"
    );
    let over_cap = format!("a{at_cap}");
    assert!(
        validate_plugin_filename_with(&over_cap, |file| file.ends_with(".tar.gz")
            || file.ends_with(".tgz"))
        .is_err(),
        "MAX_PLUGIN_FILENAME_LEN + 1 chars must be rejected"
    );
}

#[test]
fn max_settings_bytes_is_exactly_64_kibibytes() {
    assert_eq!(MAX_SETTINGS_BYTES, 65_536);
    assert_eq!(MAX_SETTINGS_BYTES, 64 * 1024);
}

#[test]
fn max_inspect_schema_json_bytes_is_exactly_256_kibibytes() {
    assert_eq!(MAX_INSPECT_SCHEMA_JSON_BYTES, 262_144);
    assert_eq!(MAX_INSPECT_SCHEMA_JSON_BYTES, 256 * 1024);
}

#[tokio::test]
async fn probe_transport_distinguishes_wrong_kind_from_unresolved() {
    let env = busbar_kernel_testkit::test_support::test_hook_env_with_wrong_kind_plugin(
        "test-hook",
        "test-wrong-kind",
    );
    let hook_cfg = hook(HookKind::Tap, false);

    let mut wired = hook_cfg.clone();
    wired.plugin = "test-hook".to_string();
    let (reachable, detail) = probe_transport(&wired, &env).await;
    assert_eq!(reachable, Some(true));
    assert_eq!(detail, None);

    let mut wrong_kind = hook_cfg.clone();
    wrong_kind.plugin = "test-wrong-kind".to_string();
    let (reachable, detail) = probe_transport(&wrong_kind, &env).await;
    assert_eq!(reachable, Some(false));
    assert!(
        detail
            .as_deref()
            .is_some_and(|d| d.contains("test-wrong-kind")
                && d.contains("secret")
                && d.contains("hook")),
        "wrong-kind resolution must name both the resolved kind and the expected kind: {detail:?}"
    );

    let mut missing = hook_cfg.clone();
    missing.plugin = "totally-unregistered-plugin-name".to_string();
    let (reachable, detail) = probe_transport(&missing, &env).await;
    assert_eq!(reachable, Some(false));
    assert!(
        detail
            .as_deref()
            .is_some_and(|d| d.contains("is not installed")),
        "unresolved plugin must say so distinctly: {detail:?}"
    );
}

#[test]
fn build_with_registry_rejects_more_than_one_default_but_allows_exactly_one() {
    let mut one_default = hook(HookKind::Tap, false);
    one_default.default = true;
    let mut registry = HashMap::new();
    registry.insert("a".to_string(), one_default.clone());
    assert!(
        validate_hook_registry(&registry, &[]).is_ok(),
        "exactly one default: true hook must be accepted"
    );

    let mut second_default = hook(HookKind::Tap, false);
    second_default.default = true;
    registry.insert("b".to_string(), second_default);
    assert!(
        validate_hook_registry(&registry, &[]).is_err(),
        "more than one default: true hook must be rejected"
    );
}

#[test]
fn build_with_registry_rejects_a_dangling_global_hook_reference() {
    let mut registry = HashMap::new();
    registry.insert("logger".to_string(), hook(HookKind::Tap, true));

    assert!(
        validate_hook_registry(&registry, &["logger".to_string()]).is_ok(),
        "a global_hooks entry that IS in the registry must be accepted"
    );

    assert!(
        validate_hook_registry(&registry, &["ghost".to_string()]).is_err(),
        "a global_hooks entry naming an unregistered hook must be rejected"
    );
}

#[test]
fn hook_snapshot_builders_recompute_the_content_gate() {
    let env =
        busbar_kernel_testkit::test_support::test_hook_env(&["test-hook"], Default::default());
    let app = crate::new_test_app().hook_env(env).build();
    assert!(
        !app.any_content_hook,
        "a fixture with no hooks grants no content"
    );

    let mut granted = hook(HookKind::Tap, true);
    granted.prompt = PromptAccess::Ro;
    let registered = build_with_hook(&app, "screener", granted.clone()).expect("registers");
    assert!(
        registered.any_content_hook,
        "registering a `prompt: ro` hook must open the gate"
    );

    let deleted = build_without_hook(&registered, "screener").expect("deletes");
    assert!(
        !deleted.any_content_hook,
        "deleting the last granted hook must close the gate"
    );

    let mut registry = HashMap::new();
    registry.insert("screener".to_string(), granted);
    let rolled_back =
        build_with_registry(&app, registry, vec!["screener".to_string()]).expect("rolls back");
    assert!(
        rolled_back.any_content_hook,
        "a rolled-back snapshot's gate must match the registry it installed"
    );
}

#[test]
fn hook_derived_fields_follow_the_registry() {
    let env =
        busbar_kernel_testkit::test_support::test_hook_env(&["test-hook"], Default::default());

    fn assert_hook_derived(app: &busbar_kernel::state::App, ctx: &str) {
        assert_eq!(
            app.any_content_hook,
            busbar_kernel::hooks::any_content_hook(&app.hook_registry),
            "{ctx}: `any_content_hook` disagrees with the registry the snapshot installed"
        );
        assert_eq!(
            app.requested_signals,
            busbar_kernel::hooks::requested_signals(&app.hook_registry),
            "{ctx}: `requested_signals` disagrees with the registry the snapshot installed — a \
             hook's `signals:` declaration did not take effect on the snapshot that installed it"
        );
    }

    let app = crate::new_test_app().hook_env(env).build();
    assert_hook_derived(&app, "boot fixture");

    let mut declaring = hook(HookKind::Tap, true);
    declaring.prompt = PromptAccess::Ro;
    declaring.signals = vec![busbar_contract::signal::Signal::CandidateBreakerState];

    let registered = build_with_hook(&app, "declarer", declaring.clone()).expect("registers");
    assert_hook_derived(&registered, "after build_with_hook (POST/PUT /hooks)");
    assert!(
        registered
            .requested_signals
            .wants(busbar_contract::signal::Signal::CandidateBreakerState),
        "registering a hook that declares `candidate.breaker_state` must open the compute gate for \
         the very next request"
    );

    let deleted = build_without_hook(&registered, "declarer").expect("deletes");
    assert_hook_derived(&deleted, "after build_without_hook (DELETE /hooks/{name})");
    assert!(
        deleted.requested_signals.is_empty(),
        "deleting the last declaring hook must close the compute gate again"
    );

    let mut registry = HashMap::new();
    registry.insert("declarer".to_string(), declaring);
    let rolled_back =
        build_with_registry(&app, registry, vec!["declarer".to_string()]).expect("rolls back");
    assert_hook_derived(&rolled_back, "after build_with_registry (config rollback)");
}

#[tokio::test]
async fn validate_config_pins_the_scan_to_the_running_plugins_dir() {
    let running_dir = tmp_plugins_dir("validate-running");
    let svc = svc_with(running_dir, unsigned_ok_posture());

    let evil_dir = tmp_plugins_dir("validate-evil");
    std::fs::write(evil_dir.join("probe.tar.gz"), b"not a real tarball at all").unwrap();

    let yaml = format!(
        r#"
listen: "0.0.0.0:8080"
providers:
  upstream:
    api_key: {{ env: UPSTREAM_API_KEY }}
models:
  claude:
    provider: upstream
pools:
  main:
    members:
      - model: claude
store:
  module: memory
plugins:
  enabled: true
  dir: '{}'
"#,
        // Single-quoted YAML scalar: a Windows path's backslashes are literal here, whereas a
        // double-quoted scalar would read `\U`/`\v`/... as invalid escapes and fail to parse.
        evil_dir.display()
    );
    let deploy: busbar_kernel::config::DeployCfg =
        serde_yaml::from_str(&yaml).expect("test DeployCfg yaml must parse");
    let def: busbar_kernel::config::ProviderDef = serde_yaml::from_str(&format!(
        "protocol: {}\nbase_url: https://upstream.example\nerror_map:\n  \"400\": client_error\n",
        crate::linked_protocol()
    ))
    .unwrap();
    let defs = std::collections::HashMap::from([("upstream".to_string(), def)]);

    let view = svc
        .validate_config(deploy, defs)
        .await
        .expect("validate returns a view");
    assert!(
        view.ok,
        "the caller's plugins.dir (holding a garbage tarball) must NOT be scanned — the scan is \
         pinned to the running install dir; got errors: {:?}",
        view.errors
    );
}

#[tokio::test]
async fn validate_config_waits_on_the_plugin_scan_gate_and_runs_off_the_reactor() {
    let svc = svc_with(tmp_plugins_dir("validate-gated"), unsigned_ok_posture());
    let deploy: busbar_kernel::config::DeployCfg = serde_yaml::from_str(
        r#"
listen: "0.0.0.0:8080"
providers:
  upstream:
    api_key: { env: UPSTREAM_API_KEY }
models:
  claude:
    provider: upstream
pools:
  main:
    members:
      - model: claude
store:
  module: memory
"#,
    )
    .expect("test DeployCfg yaml must parse");
    let def: busbar_kernel::config::ProviderDef = serde_yaml::from_str(&format!(
        "protocol: {}\nbase_url: https://upstream.example\nerror_map:\n  \"400\": client_error\n",
        crate::linked_protocol()
    ))
    .unwrap();
    let defs = std::collections::HashMap::from([("upstream".to_string(), def)]);

    let held = CATALOG_SCAN_GATE.lock().await;
    let call = tokio::spawn(async move { svc.validate_config(deploy, defs).await });
    for _ in 0..256 {
        tokio::task::yield_now().await;
    }
    assert!(
        !call.is_finished(),
        "validate_config finished while the plugin scan gate was held: its scan ran inline on \
         the async worker instead of behind the gate on a blocking thread"
    );
    drop(held);
    let view = call
        .await
        .expect("the caller task must not panic")
        .expect("validate returns a view");
    assert!(view.ok, "the verdict is unchanged: {:?}", view.errors);
}

#[cfg(test)]
mod dated_rate_card_history {
    use super::*;
    use busbar_kernel::cost::{Author, CardEntryDraft, History, RateCard, TierRates};
    use busbar_kernel::governance::GovState;
    use busbar_kernel_testkit::test_support::store_double::MemoryStore;

    const LANE: &str = "m-priced-chat";
    const PROVIDER: &str = "priced-chat";
    const KEY: &str = "vk_payg";

    const TOKENS: u64 = 1_000;
    const DAY: u64 = busbar_kernel::governance::METERING_BUCKET_SECS;

    pub(super) fn card(micro_per_token: f64) -> RateCard {
        RateCard::from_config(
            Some([(
                LANE,
                TierRates {
                    input: Some((micro_per_token * 1000.0).round() as u64),
                    ..Default::default()
                },
            )]),
            0,
        )
    }

    fn newest_cost() -> busbar_kernel::cost::CostModel {
        let rates = std::collections::BTreeMap::from([(
            LANE.to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: 1.0,
                output_utok: 0.0,
                cache_read_utok: 0.0,
                cache_write_utok: 0.0,
                ..Default::default()
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(
            Some(&rates),
            0,
            &std::collections::BTreeMap::new(),
        )
    }

    pub(super) fn source(history: History) -> &'static Arc<History> {
        Box::leak(Box::new(Arc::new(history)))
    }

    pub(super) fn metering_rows(
        rows: &[(u64, u64)],
    ) -> Vec<(u64, busbar_kernel::governance::MeteringRow)> {
        priced_metering_rows(rows.iter().map(|(bucket, era)| (*bucket, *era, "")))
    }

    pub(super) fn priced_metering_rows<'a>(
        rows: impl IntoIterator<Item = (u64, u64, &'a str)>,
    ) -> Vec<(u64, busbar_kernel::governance::MeteringRow)> {
        rows.into_iter()
            .map(|(bucket, priced_from_ms, pricing_version)| {
                (
                    bucket,
                    busbar_kernel::governance::MeteringRow {
                        usage_units: Default::default(),
                        key_id: KEY.to_string(),
                        model: LANE.to_string(),
                        provider: PROVIDER.to_string(),
                        tokens_input: TOKENS,
                        tokens_output: 0,
                        tokens_cache_read: 0,
                        tokens_cache_write: 0,
                        requests: 1,
                        billable_requests: 1,
                        key_group_at_use: String::new(),
                        pricing_version: pricing_version.to_string(),
                        priced_from_ms,
                    },
                )
            })
            .collect()
    }

    async fn read_stored(gov: Arc<GovState>, src: &'static Arc<History>, bucket: u64) -> UsageView {
        let app = crate::new_test_app()
            .governance(gov)
            .cost(newest_cost())
            .build();
        AdminService::new(app)
            .with_rate_history(Arc::clone(src))
            .get_usage(Some(bucket), None)
            .await
            .expect("usage read")
    }

    async fn read(
        rows: Vec<(u64, busbar_kernel::governance::MeteringRow)>,
        src: &'static Arc<History>,
        bucket: u64,
    ) -> UsageView {
        read_as_of(rows, src, bucket, None)
            .await
            .expect("usage read")
    }

    pub(super) async fn read_as_of(
        rows: Vec<(u64, busbar_kernel::governance::MeteringRow)>,
        src: &'static Arc<History>,
        bucket: u64,
        as_of: Option<busbar_kernel::cost::EntryKey>,
    ) -> Result<UsageView, AdminError> {
        let snapshot = as_of
            .map(|key| validated_snapshot(Some(src.as_ref()), key))
            .transpose()?;
        let rows = rows
            .into_iter()
            .filter(|(window, _)| *window == bucket)
            .map(|(_, row)| row)
            .collect();
        super::super::operations::project_usage_rows(
            Arc::new(newest_cost()),
            Some(Arc::clone(src)),
            snapshot,
            UsageWindow {
                start: bucket,
                end: bucket + DAY,
            },
            busbar_kernel::store::now(),
            (rows, HashMap::new(), Vec::new()),
        )
    }

    pub(super) async fn read_no_source_as_of(
        rows: Vec<(u64, busbar_kernel::governance::MeteringRow)>,
        bucket: u64,
        as_of: Option<busbar_kernel::cost::EntryKey>,
    ) -> Result<UsageView, AdminError> {
        let snapshot = as_of.map(|key| validated_snapshot(None, key)).transpose()?;
        let rows = rows
            .into_iter()
            .filter(|(window, _)| *window == bucket)
            .map(|(_, row)| row)
            .collect();
        super::super::operations::project_usage_rows(
            Arc::new(newest_cost()),
            None,
            snapshot,
            UsageWindow {
                start: bucket,
                end: bucket + DAY,
            },
            busbar_kernel::store::now(),
            (rows, HashMap::new(), Vec::new()),
        )
    }

    #[tokio::test]
    async fn an_adjust_of_a_units_counts_moves_the_served_usage_figure() {
        use busbar_kernel::governance::{AdjustRefused, Adjustment};
        const ADJUSTED_KEY: &str = "vk_adjust_404";

        let (day, _, _) = windows();
        let served_at = day + 5;
        let store = Arc::new(MemoryStore::new());
        let key = VirtualKey {
            id: ADJUSTED_KEY.to_string(),
            generation_hash: format!("h:{ADJUSTED_KEY}"),
            name: "adjusted".to_string(),
            enabled: true,
            revision: 1,
            ..Default::default()
        };
        busbar_contract::records::RecordStore::put_key(store.as_ref(), &key).expect("key persists");
        busbar_contract::records::RecordStore::add_metering(
            store.as_ref(),
            &busbar_contract::records::MeteringDelta {
                key_id: ADJUSTED_KEY.to_string(),
                bucket: day,
                model: LANE.to_string(),
                provider: PROVIDER.to_string(),
                tokens_input: TOKENS,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: 1,
                billable_requests: 1,
                key_group_at_use: String::new(),
                pricing_version: String::new(),
                priced_from_ms: 0,
                usage_units: Default::default(),
            },
        )
        .expect("the memory store accepts a metering delta");
        let cost = newest_cost();
        let gov = Arc::new(GovState::new(store.clone(), None).expect("governance builds"));

        let units = std::collections::BTreeMap::from([(
            busbar_contract::records::UNIT_INPUT.to_string(),
            TOKENS,
        )]);
        gov.record_usage(&cost, &key, "", LANE, &units, served_at);
        let src = source(History::opening(card(2.5), 0));

        let before = read_stored(gov.clone(), src, day).await.total;
        assert_eq!((before.tokens_input, before.spend_micros), (1_000, 2_500));

        let era = busbar_kernel::rate_apply::effective_from_at(busbar_kernel::store::now_ms());
        let adjust = |key_id: &'static str, by: i64| {
            let delta = std::collections::BTreeMap::from([(
                busbar_contract::records::UNIT_INPUT.to_string(),
                by,
            )]);
            gov.adjust_usage(
                &cost,
                &Adjustment {
                    key_id,
                    pool: "",
                    model: LANE,
                    entry_era: era,
                    entry_id: None,
                    card_epoch_ms: served_at * 1_000,
                    delta: &delta,
                    now: busbar_kernel::store::now(),
                },
            )
            .expect("the store reads")
        };
        assert!(
            matches!(
                adjust(ADJUSTED_KEY, -1_001),
                Err(AdjustRefused::Exceeds { .. })
            ),
            "an adjustment past the metered count is refused"
        );
        assert_eq!(
            read_stored(gov.clone(), src, day).await.total.spend_micros,
            2_500,
            "a refused adjustment moves nothing"
        );
        assert_eq!(adjust(ADJUSTED_KEY, -200), Ok(()));
        let after = read_stored(gov.clone(), src, day).await.total;
        assert_eq!(
            (after.tokens_input, after.spend_micros),
            (800, 2_000),
            "the served figure prices the adjusted counts: 800 x 2.5"
        );

        let restarted = Arc::new(GovState::new(store, None).expect("governance builds"));
        let again = read_stored(restarted, src, day).await.total;
        assert_eq!(
            (again.tokens_input, again.spend_micros),
            (800, 2_000),
            "the adjustment row is durable: a restart serves the same figure"
        );
    }

    pub(super) fn windows() -> (u64, u64, u64) {
        let today = busbar_kernel::governance::metering_bucket(busbar_kernel::store::now());
        (today - 3 * DAY, today - 2 * DAY, today - DAY)
    }

    fn payg_then_monthly_then_prepaid(monthly: u64, prepaid: u64) -> History {
        let mut history = History::opening(card(10.0), 0);
        history.append(CardEntryDraft {
            effective_from: monthly * 1_000,
            effective_until: None,
            card: card(5.0),
            appended_at: monthly * 1_000,
            author: Author::Config { policy_epoch: 1 },
        });
        history.append(CardEntryDraft {
            effective_from: prepaid * 1_000,
            effective_until: None,
            card: card(1.0),
            appended_at: prepaid * 1_000,
            author: Author::Config { policy_epoch: 2 },
        });
        history
    }

    #[tokio::test]
    async fn each_window_prices_at_the_card_in_force_when_it_was_earned() {
        let (payg, monthly, prepaid) = windows();
        let src = source(payg_then_monthly_then_prepaid(monthly, prepaid));

        let gov = metering_rows(&[
            (payg, 0),
            (monthly, monthly * 1_000),
            (prepaid, prepaid * 1_000),
        ]);

        assert_eq!(
            read(gov.clone(), src, payg).await.total.spend_micros,
            10_000,
            "the PAYG window keeps the card it was earned under (10 x 1_000 tokens)"
        );
        assert_eq!(
            read(gov.clone(), src, monthly).await.total.spend_micros,
            5_000,
            "the month-to-month window prices at 5"
        );
        assert_eq!(
            read(gov, src, prepaid).await.total.spend_micros,
            1_000,
            "the prepaid window prices at 1"
        );
    }

    #[tokio::test]
    async fn old_served_counts_keep_their_config_era_across_a_later_bucket_and_activation() {
        let (old, activated, later) = windows();
        let mut history = History::opening(card(20.0), 0);
        history.append(CardEntryDraft {
            effective_from: old * 1_000,
            effective_until: None,
            card: card(10.0),
            appended_at: old * 1_000,
            author: Author::Config { policy_epoch: 1 },
        });
        let old_seq = history.head_key().expect("the appended entry has a key");
        history.append(CardEntryDraft {
            effective_from: activated * 1_000,
            effective_until: None,
            card: card(1.0),
            appended_at: activated * 1_000,
            author: Author::Config { policy_epoch: 2 },
        });
        let src = source(history);
        let old_rows = metering_rows(&[(later, old * 1_000)]);
        let old_read = read(old_rows.clone(), src, later).await;
        assert_eq!(old_read.total.spend_micros, 10_000);
        assert_eq!(old_read.rate_card_version, Some(old_seq.hex()));
        assert_eq!(
            read_as_of(old_rows, src, later, Some(old_seq))
                .await
                .unwrap()
                .total
                .spend_micros,
            10_000,
        );
        let both = metering_rows(&[(later, old * 1_000), (later, activated * 1_000)]);
        let both_read = read(both, src, later).await;
        assert_eq!(both_read.total.tokens_input, TOKENS * 2);
        assert_eq!(both_read.total.spend_micros, 11_000);
    }

    #[tokio::test]
    async fn amendments_reach_old_served_eras_without_enabling_later_config_repricing() {
        let (old, activated, corrected_day) = windows();
        let mut history = History::opening(card(20.0), 0);
        history.append(CardEntryDraft {
            effective_from: old * 1_000,
            effective_until: None,
            card: card(10.0),
            appended_at: old * 1_000,
            author: Author::Config { policy_epoch: 1 },
        });
        let old_seq = history.head_key().expect("the appended entry has a key");
        history.append(CardEntryDraft {
            effective_from: activated * 1_000,
            effective_until: None,
            card: card(1.0),
            appended_at: activated * 1_000,
            author: Author::Config { policy_epoch: 2 },
        });
        let activated_seq = history.head_key().expect("the appended entry has a key");
        history.append(CardEntryDraft {
            effective_from: corrected_day * 1_000,
            effective_until: Some((corrected_day + DAY) * 1_000),
            card: card(5.0),
            appended_at: busbar_kernel::store::now_ms(),
            author: Author::Amend {
                reason_hash: [7; 32],
            },
        });
        let amended_seq = history.head_key().expect("the appended entry has a key");
        let src = source(history);
        let rows = metering_rows(&[(activated, old * 1_000), (corrected_day, old * 1_000)]);
        let before = read_as_of(rows.clone(), src, corrected_day, Some(activated_seq))
            .await
            .unwrap();
        assert_eq!(before.total.spend_micros, 10_000);
        assert_eq!(before.rate_card_version, Some(old_seq.hex()));
        let corrected = read(rows.clone(), src, corrected_day).await;
        assert_eq!(corrected.total.spend_micros, 5_000);
        assert_eq!(corrected.rate_card_version, Some(amended_seq.hex()));
        assert_eq!(read(rows, src, activated).await.total.spend_micros, 10_000);
    }

    #[tokio::test]
    async fn exact_opening_provenance_survives_a_later_config_and_legacy_names_keep_their_reading()
    {
        use busbar_kernel::cost::EntryId;
        const UNKNOWN_ENTRY_ID: &str = "ffffffffffffffffffffffff";
        const LEGACY_NAMED_VERSION: &str = "historical-card";
        let (_old, activated, later) = windows();
        let mut history = History::opening(card(10.0), 0);
        let opening_version = history.entries()[0].id().metering_version();
        history.append(CardEntryDraft {
            effective_from: activated * 1_000,
            effective_until: None,
            card: card(1.0),
            appended_at: activated * 1_000,
            author: Author::Config { policy_epoch: 1 },
        });
        let activated_seq = history.head_key().expect("the appended entry has a key");
        let activated_version = history.entries()[1].id().metering_version();
        let src = source(history);
        let known = priced_metering_rows([(later, 0, opening_version.as_str())]);
        let view = read(known, src, later).await;
        assert_eq!(view.total.spend_micros, 10_000);
        assert_eq!(view.rate_card_version, Some(src.entries()[0].key().hex()));
        for legacy in ["", LEGACY_NAMED_VERSION] {
            let rows = priced_metering_rows([(later, 0, legacy)]);
            let view = read(rows, src, later).await;
            assert_eq!(view.total.spend_micros, 1_000);
            assert_eq!(view.rate_card_version, Some(activated_seq.hex()));
        }
        let malformed = EntryId::METERING_VERSION_PREFIX;
        let unknown = EntryId::parse_hex(UNKNOWN_ENTRY_ID)
            .unwrap()
            .metering_version();
        for (era, version) in [
            (0, malformed),
            (0, unknown.as_str()),
            (activated * 1_000, opening_version.as_str()),
        ] {
            let rows = priced_metering_rows([(later, era, version)]);
            assert!(matches!(
                read_as_of(rows, src, later, None).await,
                Err(AdminError::Internal)
            ));
        }
        let new_rows =
            priced_metering_rows([(later, activated * 1_000, activated_version.as_str())]);
        assert!(
            matches!(
                read_as_of(new_rows, src, later, Some(src.entries()[0].key())).await,
                Err(AdminError::Internal)
            ),
            "a snapshot cannot price counts whose exact source entry it does not contain"
        );
    }

    #[tokio::test]
    async fn the_usage_response_names_the_rate_card_version_that_priced_it() {
        let (payg, monthly, prepaid) = windows();
        let src = source(payg_then_monthly_then_prepaid(monthly, prepaid));
        let gov = metering_rows(&[
            (payg, 0),
            (monthly, monthly * 1_000),
            (prepaid, prepaid * 1_000),
        ]);
        for (bucket, index) in [(payg, 0), (monthly, 1), (prepaid, 2)] {
            let seq = src.entries()[index].key();
            let live = read(gov.clone(), src, bucket).await;
            assert_eq!(
                live.rate_card_version,
                Some(seq.hex()),
                "the window at {bucket} is priced by history entry {seq}"
            );
            let pinned = read_as_of(gov.clone(), src, bucket, Some(seq))
                .await
                .expect("the named version is a snapshot this history holds");
            assert_eq!(
                pinned.total.spend_micros, live.total.spend_micros,
                "`?as_of=<rate_card_version>` re-derives the figure the version was served beside"
            );
            assert_eq!(pinned.rate_card_version, Some(seq.hex()));
            let wire = serde_json::to_value(&live).expect("a usage view serializes");
            assert_eq!(wire["rate_card_version"], serde_json::json!(seq.hex()));
        }
        let none = read_no_source_as_of(gov, payg, None)
            .await
            .expect("a node with no dated history still reads");
        assert_eq!(none.rate_card_version, None);
        let wire = serde_json::to_value(&none).expect("a usage view serializes");
        assert!(
            wire["rate_card_version"].is_null(),
            "no history: the version is null, never a zero"
        );
    }

    #[tokio::test]
    async fn a_hole_in_the_dated_history_refuses_rather_than_pricing_at_the_current_card() {
        let (payg, monthly, _prepaid) = windows();
        let mut history = History::new();
        history.append(CardEntryDraft {
            effective_from: monthly * 1_000,
            effective_until: None,
            card: card(5.0),
            appended_at: monthly * 1_000,
            author: Author::Config { policy_epoch: 0 },
        });
        let src = source(history);
        let gov = metering_rows(&[(payg, 0), (monthly, monthly * 1_000)]);

        assert_eq!(
            read(gov.clone(), src, monthly).await.total.spend_micros,
            5_000,
            "the covered window prices at the entry in force (5 x 1_000 tokens)"
        );
        assert!(
            matches!(
                read_as_of(gov, src, payg, None).await,
                Err(AdminError::Internal)
            ),
            "a row no history entry covers must REFUSE the read, never price at the current card"
        );
    }

    #[tokio::test]
    async fn publishing_a_card_leaves_the_window_before_it_byte_identical() {
        let (payg, _, _) = windows();
        let gov = metering_rows(&[(payg, 0)]);

        let before = source(History::opening(card(10.0), 0));

        let mut published = History::opening(card(10.0), 0);
        let now_ms = busbar_kernel::store::now().saturating_mul(1_000);
        published.append(CardEntryDraft {
            effective_from: now_ms,
            effective_until: None,
            card: card(1.0),
            appended_at: now_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        let after = source(published);

        let bytes = |mut v: serde_json::Value| {
            v["as_of"] = serde_json::json!(0);
            serde_json::to_string(&v).expect("a usage view serializes")
        };
        let a =
            bytes(serde_json::to_value(read(gov.clone(), before, payg).await).expect("serializes"));
        let b = bytes(serde_json::to_value(read(gov, after, payg).await).expect("serializes"));
        assert_eq!(
            a, b,
            "a forward-dated publish must not touch the window before its effective_from"
        );
        assert!(
            a.contains("\"spend_micros\":10000"),
            "and the window is still priced at the card it was earned under: {a}"
        );
    }

    #[tokio::test]
    async fn a_back_dated_correction_reprices_its_window_and_nothing_outside_it() {
        let (payg, monthly, prepaid) = windows();

        let gov = metering_rows(&[(payg, 0), (monthly, 0), (prepaid, 0)]);

        let before = source(History::opening(card(10.0), 0));
        for w in [payg, monthly, prepaid] {
            assert_eq!(
                read(gov.clone(), before, w).await.total.spend_micros,
                10_000,
                "a single-entry history prices every window at the opening card"
            );
        }

        let mut corrected = History::opening(card(10.0), 0);
        corrected.append(CardEntryDraft {
            effective_from: monthly * 1_000,
            effective_until: Some(prepaid * 1_000),
            card: card(5.0),
            appended_at: busbar_kernel::store::now().saturating_mul(1_000),
            author: Author::Amend {
                reason_hash: [7u8; 32],
            },
        });
        let after = source(corrected);

        assert_eq!(
            read(gov.clone(), after, payg).await.total.spend_micros,
            10_000,
            "OUTSIDE, before effective_from: unmoved"
        );
        assert_eq!(
            read(gov.clone(), after, monthly).await.total.spend_micros,
            5_000,
            "INSIDE [effective_from, effective_until): repriced"
        );
        assert_eq!(
            read(gov, after, prepaid).await.total.spend_micros,
            10_000,
            "OUTSIDE, at and after effective_until: unmoved"
        );
    }

    #[tokio::test]
    async fn a_card_edit_inside_a_day_splits_the_day_and_each_half_keeps_its_own_card() {
        let (_, _, today) = windows();
        let noon = (today + DAY / 2) * 1_000;
        let mut history = History::opening(card(10.0), 0);
        history.append(CardEntryDraft {
            effective_from: noon,
            effective_until: None,
            card: card(1.0),
            appended_at: noon,
            author: Author::Config { policy_epoch: 1 },
        });
        let src = source(history);

        let gov = metering_rows(&[(today, 0), (today, noon)]);

        let view = read(gov, src, today).await;
        assert_eq!(
            view.total.spend_micros, 11_000,
            "the day is 10 x 1_000 earned before noon plus 1 x 1_000 earned after it — not \
             20_000 (all morning) and not 2_000 (all afternoon)"
        );
        assert_eq!(
            view.total.tokens_input, 2_000,
            "and the quantities still roll up whole: splitting the price never splits the counts"
        );
        assert_eq!(
            view.by_model.len(),
            1,
            "the split is a PRICING fact, not an attribution one: one model, one provider, one row \
             in the report"
        );
    }

    #[tokio::test]
    async fn with_no_history_source_the_read_is_the_previous_release_to_the_byte() {
        let gov =
            Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).expect("governance builds"));
        let now = busbar_kernel::store::now();
        let usage = busbar_contract::billing::TokenUsage {
            input: 11,
            output: 7,
            ..Default::default()
        };
        for _ in 0..3 {
            gov.record_metering(KEY, LANE, PROVIDER, Some(&usage), now);
        }
        gov.flush_metering();

        let rates = std::collections::BTreeMap::from([(
            LANE.to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: 10_000_000.0,
                output_utok: 20_000_000.0,
                cache_read_utok: 0.0,
                cache_write_utok: 0.0,
                ..Default::default()
            },
        )]);
        let app = crate::new_test_app()
            .governance(gov)
            .cost(busbar_kernel::cost::CostModel::resolve_parts(
                Some(&rates),
                3,
                &std::collections::BTreeMap::new(),
            ))
            .build();
        let view = AdminService::new(app)
            .get_usage(None, None)
            .await
            .expect("usage read");
        assert_eq!(
            view.total.spend_micros, 750_090_000,
            "with no history installed the read is the published 1.5.5 figure"
        );
    }
}

#[cfg(test)]
mod usage_as_of {
    use super::dated_rate_card_history::{
        card, metering_rows, priced_metering_rows, read_as_of, source, windows,
    };
    use busbar_kernel::cost::{Author, CardEntryDraft, History};

    #[tokio::test]
    async fn an_older_snapshot_is_re_derivable_and_the_publish_moves_neither() {
        let (payg, _, _) = windows();
        let gov = metering_rows(&[(payg, 0)]);
        let mut history = History::opening(card(10.0), 0);
        let now_ms = busbar_kernel::store::now().saturating_mul(1_000);
        history.append(CardEntryDraft {
            effective_from: now_ms,
            effective_until: None,
            card: card(1.0),
            appended_at: now_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        let src = source(history);

        assert_eq!(
            read_as_of(gov.clone(), src, payg, Some(src.entries()[0].key()))
                .await
                .expect("the opening key exists")
                .total
                .spend_micros,
            10_000,
            "at the opening snapshot the window prices at the opening card"
        );
        assert_eq!(
            read_as_of(gov, src, payg, Some(src.entries()[1].key()))
                .await
                .expect("the head key exists")
                .total
                .spend_micros,
            10_000,
            "and at the head too — the publish is dated after the window it did not touch"
        );
    }

    #[tokio::test]
    async fn a_snapshot_before_a_correction_still_answers_the_old_figure() {
        let (payg, _, _) = windows();
        let gov = metering_rows(&[(payg, 0)]);
        let mut history = History::opening(card(10.0), 0);
        history.append(CardEntryDraft {
            effective_from: payg.saturating_mul(1_000),
            effective_until: Some(payg.saturating_add(86_400).saturating_mul(1_000)),
            card: card(5.0),
            appended_at: busbar_kernel::store::now().saturating_mul(1_000),
            author: Author::Amend {
                reason_hash: [7u8; 32],
            },
        });
        let src = source(history);

        assert_eq!(
            read_as_of(gov.clone(), src, payg, Some(src.entries()[0].key()))
                .await
                .expect("the opening key exists")
                .total
                .spend_micros,
            10_000,
            "the snapshot taken before the correction re-derives the figure it was cut at"
        );
        assert_eq!(
            read_as_of(gov.clone(), src, payg, Some(src.entries()[1].key()))
                .await
                .expect("the head key exists")
                .total
                .spend_micros,
            5_000,
            "the snapshot that can see the correction reports the corrected figure"
        );
        assert_eq!(
            read_as_of(gov, src, payg, None)
                .await
                .expect("no snapshot named")
                .total
                .spend_micros,
            5_000,
            "and naming no snapshot is the history as it stands, which is the head"
        );
    }

    #[test]
    fn an_unknown_snapshot_key_is_refused_on_either_side_of_known_entries() {
        use busbar_kernel::cost::EntryKey;
        let mut history = History::new();
        for at in [100, 300] {
            history.insert(
                EntryKey::new(at, [1; 8], 0),
                CardEntryDraft {
                    effective_from: at,
                    effective_until: None,
                    card: card(10.0),
                    appended_at: at,
                    author: Author::Config { policy_epoch: at },
                },
            );
        }
        let src = history;
        for at in [50, 200, 400] {
            let unknown = EntryKey::new(at, [1; 8], 0);
            let err = validated_snapshot(Some(&src), unknown)
                .expect_err("a snapshot key that does not exist is a refusal");
            let crate::v1::contract::AdminError::Validation(msg) = &err else {
                panic!("expected a client-safe validation refusal, got {err:?}");
            };
            assert!(
                msg.contains(&unknown.hex()) && msg.contains("known rate-card history entry"),
                "the refusal must name the unknown key without interpreting its position: {msg}"
            );
        }
    }

    #[test]
    fn a_snapshot_of_a_history_that_does_not_exist_is_refused() {
        let err = validated_snapshot(None, busbar_kernel::cost::EntryKey::new(0, [0; 8], 0))
            .expect_err("there is no snapshot of a history that does not exist");
        let crate::v1::contract::AdminError::Validation(msg) = &err else {
            panic!("expected a client-safe validation refusal, got {err:?}");
        };
        assert!(
            msg.contains("no rate-card history"),
            "the refusal must say WHY there is nothing to snapshot: {msg}"
        );
    }

    #[tokio::test]
    async fn a_saved_keyed_read_replays_after_an_earlier_peer_entry_arrives() {
        use busbar_kernel::cost::EntryKey;
        let (payg, _, _) = windows();
        let wall = payg * 1_000;
        let draft = |at, rate| CardEntryDraft {
            effective_from: at,
            effective_until: None,
            card: card(rate),
            appended_at: at,
            author: Author::Config { policy_epoch: at },
        };
        let opening = EntryKey::new(100, [1; 8], 0);
        let saved = EntryKey::new(300, [1; 8], 1);
        let late_peer = EntryKey::new(200, [2; 8], 0);
        let mut history = History::new();
        let mut first = draft(0, 20.0);
        first.author = Author::Opening;
        history.insert(opening, first);
        history.insert(saved, draft(300, 10.0));
        let version = saved.id().metering_version();
        for gov in [
            metering_rows(&[(payg, 0)]),
            priced_metering_rows([(payg, 300, version.as_str())]),
        ] {
            let before = read_as_of(gov.clone(), source(history.clone()), payg, Some(saved))
                .await
                .expect("the saved key is present before peer delivery");
            assert_eq!(before.total.spend_micros, 10_000);
            assert_eq!(before.rate_card_version, Some(saved.hex()));
            assert!(wall > 300, "all three entries cover the row instant");

            let mut after_history = history.clone();
            after_history.insert(late_peer, draft(200, 2.0));
            let after_source = source(after_history);
            let current = read_as_of(gov.clone(), after_source, payg, None)
                .await
                .unwrap();
            assert_eq!(current.total.spend_micros, 10_000);
            let after = read_as_of(gov, after_source, payg, Some(saved))
                .await
                .expect("late delivery cannot invalidate the saved boundary");
            assert_eq!(after.total.spend_micros, before.total.spend_micros);
            assert_eq!(after.rate_card_version, before.rate_card_version);
            assert_eq!(after.total.tokens_input, before.total.tokens_input);
        }
    }
}

#[cfg(test)]
mod one_recorded_usage_every_surface {
    use super::*;
    use busbar_kernel::cost::{
        self as ledger_cost, Author, CardEntryDraft, History, LedgerEntry, RateCard, TierRates,
    };

    const LANE: &str = "m-priced-chat";
    const PROVIDER: &str = "priced-chat";
    const KEY: &str = "vk_auditor";

    const TOKENS: u64 = 1_000;
    const DAY: u64 = busbar_kernel::governance::METERING_BUCKET_SECS;

    const RATE_EARNED: f64 = 27.0;

    const RATE_CURRENT: f64 = 12.0;

    fn card(micro_per_token: f64) -> RateCard {
        RateCard::from_config(
            Some([(
                LANE,
                TierRates {
                    input: Some((micro_per_token * 1000.0).round() as u64),
                    ..Default::default()
                },
            )]),
            0,
        )
    }

    fn current_cost() -> busbar_kernel::cost::CostModel {
        let rates = std::collections::BTreeMap::from([(
            LANE.to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: RATE_CURRENT,
                output_utok: 0.0,
                cache_read_utok: 0.0,
                cache_write_utok: 0.0,
                ..Default::default()
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(
            Some(&rates),
            0,
            &std::collections::BTreeMap::new(),
        )
    }

    fn history(edit_ms: u64) -> History {
        let mut history = History::opening(card(RATE_EARNED), 0);
        history.append(CardEntryDraft {
            effective_from: edit_ms,
            effective_until: None,
            card: card(RATE_CURRENT),
            appended_at: edit_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        history
    }

    fn metering(bucket: u64, edit_ms: u64) -> Arc<busbar_kernel::governance::GovState> {
        let store = Arc::new(busbar_kernel_testkit::test_support::store_double::MemoryStore::new());
        for priced_from_ms in [0, edit_ms] {
            busbar_contract::records::RecordStore::add_metering(
                store.as_ref(),
                &busbar_contract::records::MeteringDelta {
                    usage_units: Default::default(),
                    key_id: KEY.to_string(),
                    bucket,
                    model: LANE.to_string(),
                    provider: PROVIDER.to_string(),
                    tokens_input: TOKENS,
                    tokens_output: 0,
                    tokens_cache_read: 0,
                    tokens_cache_write: 0,
                    requests: 1,
                    billable_requests: 1,
                    key_group_at_use: String::new(),
                    pricing_version: String::new(),
                    priced_from_ms,
                },
            )
            .expect("the memory store accepts a metering delta");
        }
        Arc::new(busbar_kernel::governance::GovState::new(store, None).expect("governance builds"))
    }

    fn enforcement(now: u64) -> Arc<busbar_kernel::governance::GovState> {
        let store = Arc::new(busbar_kernel_testkit::test_support::store_double::MemoryStore::new());
        busbar_contract::records::RecordStore::put_key(store.as_ref(), &enforcement_key())
            .expect("the memory store accepts the key needed for hydration");
        let ledger = busbar_contract::records::UsageLedger {
            requests: 2,
            billable_requests: 2,
            models: vec![busbar_contract::records::ModelTokens {
                model: LANE.to_string(),
                usage_units: std::collections::BTreeMap::from([(
                    busbar_contract::records::UNIT_INPUT.to_string(),
                    TOKENS * 2,
                )]),
            }],
        };
        for window in [
            busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_TOTAL, now),
            busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, now),
        ] {
            busbar_contract::records::RecordStore::put_usage(store.as_ref(), KEY, window, &ledger)
                .expect("the memory store accepts a usage ledger");
        }
        Arc::new(busbar_kernel::governance::GovState::new(store, None).expect("governance builds"))
    }

    fn enforcement_key() -> busbar_contract::records::VirtualKey {
        busbar_contract::records::VirtualKey {
            id: KEY.to_string(),
            enabled: true,
            ..Default::default()
        }
    }

    fn one_function_slice(bucket: u64, edit_ms: u64) -> Vec<LedgerEntry> {
        [bucket.saturating_mul(1_000), edit_ms]
            .into_iter()
            .map(|arrived_ms| {
                LedgerEntry::new(LANE, arrived_ms)
                    .with_whole(busbar_contract::records::UNIT_INPUT, TOKENS)
            })
            .collect()
    }

    const MICROS_PER_CENT: i64 = 10_000;

    fn row(label: &str, figure: impl std::fmt::Display) {
        eprintln!("  {label:<56} {figure:>18}");
    }

    #[tokio::test]
    async fn one_recorded_usage_is_one_number_on_every_surface() {
        let now = busbar_kernel::store::now();
        let bucket = busbar_kernel::governance::metering_bucket(now) - DAY;

        let edit_ms = bucket.saturating_add(DAY / 2).saturating_mul(1_000);

        let hist = history(edit_ms);
        let cost = current_cost();

        let one = ledger_cost::price_ledger(&one_function_slice(bucket, edit_ms), &hist)
            .expect("both postings are priced by the card in force at their own instant");
        let one_micros = i64::try_from(one.micros()).expect("the figure fits");

        let admin = {
            let app = crate::new_test_app()
                .governance(metering(bucket, edit_ms))
                .cost(current_cost())
                .build();
            AdminService::new(app)
                .with_rate_history(Arc::new(history(edit_ms)))
                .get_usage(Some(bucket), None)
                .await
                .expect("usage read")
                .total
                .spend_micros
        };

        let gov = enforcement(now);
        gov.hydrate_budgets(&cost, now)
            .expect("the key ledger hydrates");

        let group_cents = gov
            .derived_bucket_usage(&cost, KEY, busbar_kernel::governance::WINDOW_DAY, true, now)
            .expect("the group bucket reads")
            .spend_cents;

        let key_cents = gov
            .derived_bucket_usage(
                &cost,
                KEY,
                busbar_kernel::governance::WINDOW_TOTAL,
                true,
                now,
            )
            .expect("the key bucket reads")
            .spend_cents;

        let scrape_cents = gov
            .viewed_bucket_usage(
                &cost,
                KEY,
                busbar_kernel::governance::WINDOW_TOTAL,
                true,
                now,
            )
            .expect("the metrics bucket reads")
            .spend_cents;

        let hook_micros = gov
            .budget_state(&cost, &enforcement_key(), now)
            .into_iter()
            .find(|bucket| bucket.bucket_id == KEY)
            .expect("the key budget state is present")
            .spend_micros_at_current_rate;

        eprintln!("\n── ONE RECORDED USAGE: 2 x {TOKENS} input tokens on `{LANE}`, one posting");
        eprintln!("   under a {RATE_EARNED} card and one under a {RATE_CURRENT} card ────────────");
        row(
            "THE ONE FUNCTION   price(ledger, history)  [micro]",
            one_micros,
        );
        row("GET /admin/usage                           [micro]", admin);
        row(
            "GET /groups/{g}/usage                      [cents]",
            group_cents,
        );
        row(
            "GET /keys/{id}/usage                       [cents]",
            key_cents,
        );
        row(
            "the metrics money view                    [cents]",
            scrape_cents,
        );
        row(
            "the hook seam    budget_state              [micro]",
            hook_micros,
        );
        eprintln!("   ─── the same five, in ONE unit (micro-units) ───");
        row("THE ONE FUNCTION", one_micros);
        row("GET /admin/usage", admin);
        row("GET /groups/{g}/usage", group_cents * MICROS_PER_CENT);
        row("GET /keys/{id}/usage", key_cents * MICROS_PER_CENT);
        row("the metrics money view", scrape_cents * MICROS_PER_CENT);
        row("the hook seam", hook_micros);

        assert_eq!(
            i128::from(admin),
            one.micros(),
            "the dated admin read and the one function are the same function"
        );
        assert_eq!(
            one_micros,
            39_000,
            "one posting at the {RATE_EARNED} card it was earned under ({}) plus one at the \
             {RATE_CURRENT} card in force now ({}) — #79 `BUSBAR-1.6.0.md:423`",
            (RATE_EARNED as i64) * (TOKENS as i64),
            (RATE_CURRENT as i64) * (TOKENS as i64),
        );

        let flat_micros = (RATE_CURRENT as i64) * (TOKENS as i64) * 2;
        assert_eq!(
            hook_micros, flat_micros,
            "the enforcement fold prices both postings at the card in force NOW"
        );
        assert_eq!(flat_micros, 24_000);
        for (surface, cents) in [
            ("GET /groups/{g}/usage", group_cents),
            ("GET /keys/{id}/usage", key_cents),
            ("the metrics money view", scrape_cents),
        ] {
            assert_eq!(
                cents, 2,
                "{surface} reads the enforcement book, which carries no instant, and then \
                 projects to WHOLE MINOR UNITS — so {flat_micros} micro-units is served as 2 \
                 cents and the remaining 4000 is dropped by the projection on top of the 15000 \
                 dropped by pricing flat. PARKED."
            );
        }

        let served = group_cents * MICROS_PER_CENT;
        assert_eq!(
            one_micros - served,
            19_000,
            "the dated book says {one_micros}; the enforcement surfaces say {served}"
        );
    }
}

mod plane_fees_on_admin_usage {
    use super::*;
    use busbar_contract::records::RecordStore as _;
    use busbar_kernel::cost::PlaneFees;
    use busbar_kernel::governance::PLANE_LANE_SEP;
    use busbar_kernel::plane_driver::registry::{PlaneDecl, PlaneDeclaration};
    use busbar_kernel_testkit::test_support::planes::TestRegistryIsolation;

    const KEY: &str = "vk_plane_fees";

    const POOLS_MODEL: &str = "m";
    const POOLS_PROVIDER: &str = "priced-chat";

    const FEE_PLANE: &str = "tp";

    const FREE_PLANE: &str = "np";

    const POOLS_PLANE: &str = "pools-test";

    const MICROS_PER_MINOR: i64 = 10_000;

    macro_rules! decl {
        ($key:expr, $fallback:expr, $section:expr) => {
            PlaneDecl {
                declaration: PlaneDeclaration {
                    key: $key,
                    fallback: $fallback,
                    config_section: $section,
                    scope_kinds: &[],
                    subject_noun: $key,
                    admin_noun: $key,
                    audit_kind: $key,
                    card_signing_domain: None,
                    card_kid_prefix: None,
                    owned_config_sections: &[],
                    billable_classes: &[],
                    fee_units: &[],
                    metric_families: &[],
                    record_kinds: &[],
                    required_config_sections: &[],
                    trust_keys: &[],
                    served_op_classes: &[],
                    caller_credential_refusal: None,
                },
                wire_format_names: |_| &[],
                provider_dialects: |_| &[],
                claims: |_| Vec::new(),
                admission: |_| None,
                build: |_, _| None,
                routes: None,
                admin_routes: None,
                openapi: None,
                hydrate: None,
                start: None,
                config_validate: None,
                named_def_list: None,
                named_def_get: None,
                registry_contains: None,
                reresolve_gates: None,
                openapi_schemas: None,
                on_swap: None,
                parse_section: None,
                parse_endpoint: None,
                lower_endpoint: None,
                build_runtime: None,
                viewer: None,
                retain_verify_gates: None,
                default_section: None,
                resolve_provider: None,
                door: None,
            }
        };
    }
    static POOLS: PlaneDecl = decl!(POOLS_PLANE, true, "pools");
    static FEE: PlaneDecl = decl!(FEE_PLANE, false, "tools");
    static FREE: PlaneDecl = decl!(FREE_PLANE, false, "streams");

    fn cost() -> busbar_kernel::cost::CostModel {
        let fees = busbar_kernel::config::PlaneFeesMap::from([(
            FEE_PLANE.to_string(),
            PlaneFees {
                per_request: 3,
                per_session: 0,
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(None, 5, &std::collections::BTreeMap::new())
            .with_plane_fees(&fees)
    }

    fn key() -> VirtualKey {
        VirtualKey {
            id: KEY.to_string(),
            generation_hash: format!("h:{KEY}"),
            name: "plane-fees".to_string(),
            enabled: true,
            revision: 1,
            ..Default::default()
        }
    }

    fn gov() -> Arc<GovState> {
        let store = Arc::new(MemoryStore::new());
        store.put_key(&key()).unwrap();
        Arc::new(GovState::new(store, None).unwrap())
    }

    async fn serve(pool_calls: usize, plane: &str, calls: usize) -> (i64, i64) {
        let gov = gov();
        let cost = cost();
        let app = crate::new_test_app()
            .governance(Arc::clone(&gov))
            .cost(self::cost())
            .build();
        let _planes = TestRegistryIsolation::seeded(&[&POOLS, &FEE, &FREE]);
        let now = busbar_kernel::store::now();
        let key = key();
        for _ in 0..pool_calls {
            assert!(gov.try_admit(&cost, &key, "", now).is_ok(), "a pools call");
            gov.record_metering(KEY, POOLS_MODEL, POOLS_PROVIDER, None, now);
        }
        for _ in 0..calls {
            let pool = format!("{plane}{PLANE_LANE_SEP}srv.read");
            assert!(
                gov.try_admit(&cost, &key, &pool, now).is_ok(),
                "a plane call"
            );
            gov.record_metering(KEY, "srv.read", plane, None, now);
        }
        gov.flush_metering();
        let book = gov
            .usage_for(&cost, KEY, now)
            .unwrap()
            .expect("the key's usage")
            .spend_cents;
        let view = AdminService::new(app)
            .get_usage(None, None)
            .await
            .expect("usage read");
        (book, view.total.spend_micros)
    }

    #[tokio::test]
    async fn a_planes_rows_price_at_its_own_fee_and_admin_usage_agrees_with_the_budget_book() {
        let (book, admin) = serve(2, FEE_PLANE, 3).await;
        assert_eq!(book, 19, "the budget book: 2 pools × 5 + 3 tools × 3");
        assert_eq!(
            admin,
            19 * MICROS_PER_MINOR,
            "/admin/usage prices the tools rows at tools.fees.per_request, not the flat fee \
             (before: 25), and agrees with the budget book"
        );
        assert_eq!(admin, book * MICROS_PER_MINOR);
    }

    #[tokio::test]
    async fn a_plane_without_fees_reads_zero_fee_on_admin_usage() {
        let (book, admin) = serve(0, FREE_PLANE, 4).await;
        assert_eq!(book, 0, "the budget book: a fee-less plane bills no fee");
        assert_eq!(
            admin, 0,
            "/admin/usage: 4 calls on a fee-less plane (before: 20)"
        );
    }

    #[test]
    fn the_dated_read_prices_a_planes_row_at_its_own_fee() {
        use crate::v1::contract::UsageBreakdown;
        let cost = cost();
        let history = busbar_kernel::cost::History::opening(cost.card().clone(), 0);
        let view = history.current();
        let (_, card) = view.card_at(0).expect("the opening card");
        let price = |lane: &str, requests: u64| {
            let b = UsageBreakdown {
                requests,
                ..Default::default()
            };
            crate::v1::service::derive_spend_micros_row_at_card(&view, 0, card, &cost, lane, &b)
                .expect("priced")
        };
        let tools = format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read");
        let free = format!("{FREE_PLANE}{PLANE_LANE_SEP}srv.read");
        assert_eq!(price(&tools, 3), 9 * MICROS_PER_MINOR, "3 × tools fee 3");
        assert_eq!(
            price(POOLS_MODEL, 2),
            10 * MICROS_PER_MINOR,
            "2 × flat fee 5"
        );
        assert_eq!(price(&free, 4), 0, "a fee-less plane bills no fee");
        assert_eq!(
            crate::v1::service::derive_spend_micros_row(
                &cost,
                &tools,
                &UsageBreakdown {
                    requests: 3,
                    ..Default::default()
                }
            )
            .expect("priced"),
            9 * MICROS_PER_MINOR,
            "the no-history fallback agrees"
        );
    }

    #[tokio::test]
    async fn a_pools_row_keeps_the_flat_fee() {
        let (book, admin) = serve(2, POOLS_PLANE, 0).await;
        assert_eq!((book, admin), (10, 10 * MICROS_PER_MINOR));
        let _planes = TestRegistryIsolation::seeded(&[&POOLS, &FEE, &FREE]);
        assert_eq!(
            crate::v1::service::row_lane(POOLS_MODEL, POOLS_PLANE),
            POOLS_MODEL,
            "the fallback plane's key is a pools row"
        );
        assert_eq!(
            crate::v1::service::row_lane(POOLS_MODEL, POOLS_PROVIDER),
            POOLS_MODEL
        );
        assert_eq!(
            crate::v1::service::row_lane("srv.read", FEE_PLANE),
            format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read")
        );
    }

    fn carded_cost(
        per_call_micros: u64,
        per_request: i64,
        per_session: i64,
    ) -> busbar_kernel::cost::CostModel {
        let entry = |units: &[(&str, u64)]| -> busbar_kernel::config::RateEntryCfg {
            let units: serde_json::Map<String, serde_json::Value> = units
                .iter()
                .map(|(c, r)| (c.to_string(), serde_json::json!(r)))
                .collect();
            serde_json::from_value(serde_json::json!({ "units": units })).expect("a rate entry")
        };
        let mut pools = entry(&[("search_units", 3)]);
        pools.input_utok = 1.0;
        pools.output_utok = 2.0;
        let card = std::collections::BTreeMap::from([
            (POOLS_MODEL.to_string(), pools),
            (PLANE_LANE_SEP.to_string(), Default::default()),
            (format!("{FEE_PLANE}{PLANE_LANE_SEP}"), Default::default()),
            (
                format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read"),
                entry(&[("tool_calls", per_call_micros)]),
            ),
        ]);
        let fees = busbar_kernel::config::PlaneFeesMap::from([(
            FEE_PLANE.to_string(),
            PlaneFees {
                per_request,
                per_session,
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(
            Some(&card),
            5,
            &std::collections::BTreeMap::new(),
        )
        .with_plane_fees(&fees)
    }

    enum Call {
        Tokens { input: u64, output: u64 },

        Rerank { search_units: u64 },

        Session,

        Tool,
    }

    async fn serve_calls(
        cost: fn() -> busbar_kernel::cost::CostModel,
        calls: &[Call],
    ) -> (i64, i64) {
        let (book, view) = serve_calls_view(cost, calls).await;
        (book, view.total.spend_micros)
    }

    async fn serve_calls_view(
        cost: fn() -> busbar_kernel::cost::CostModel,
        calls: &[Call],
    ) -> (i64, crate::v1::contract::UsageView) {
        use busbar_kernel::cost::{plane_fee_lane, PER_SESSION};
        let gov = gov();
        let app = crate::new_test_app()
            .governance(Arc::clone(&gov))
            .cost(cost())
            .build();
        let cost = cost();
        let _planes = TestRegistryIsolation::seeded(&[&POOLS, &FEE, &FREE]);
        let now = busbar_kernel::store::now();
        let key = key();
        let units = |pairs: &[(&str, u64)]| -> std::collections::BTreeMap<String, u64> {
            pairs.iter().map(|(c, n)| (c.to_string(), *n)).collect()
        };
        let tool_lane = format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read");
        for call in calls {
            match call {
                Call::Tokens { input, output } => {
                    assert!(gov.try_admit(&cost, &key, "", now).is_ok());
                    let t = busbar_contract::billing::TokenUsage {
                        input: *input,
                        output: *output,
                        ..Default::default()
                    };
                    gov.record_usage(
                        &cost,
                        &key,
                        "",
                        POOLS_MODEL,
                        &units(&[("input", *input), ("output", *output)]),
                        now,
                    );
                    gov.record_metering(KEY, POOLS_MODEL, POOLS_PROVIDER, Some(&t), now);
                }
                Call::Rerank { search_units } => {
                    assert!(gov.try_admit(&cost, &key, "", now).is_ok());
                    gov.record_usage(
                        &cost,
                        &key,
                        "",
                        POOLS_MODEL,
                        &units(&[("search_units", *search_units)]),
                        now,
                    );
                    gov.record_metering(KEY, POOLS_MODEL, POOLS_PROVIDER, None, now);
                }
                Call::Session => {
                    gov.record_usage(
                        &cost,
                        &key,
                        "sessions",
                        &plane_fee_lane(FEE_PLANE),
                        &units(&[(PER_SESSION, 1)]),
                        now,
                    );
                }
                Call::Tool => {
                    assert!(gov.try_admit(&cost, &key, &tool_lane, now).is_ok());
                    gov.record_metering(KEY, "srv.read", FEE_PLANE, None, now);
                    gov.record_usage(
                        &cost,
                        &key,
                        "srv.read",
                        &tool_lane,
                        &units(&[("tool_calls", 1)]),
                        now,
                    );
                }
            }
        }
        gov.flush_metering();
        let book = gov
            .usage_for(&cost, KEY, now)
            .unwrap()
            .expect("the key's usage")
            .spend_cents;
        let view = AdminService::new(app)
            .get_usage(None, None)
            .await
            .expect("usage read");
        (book, view)
    }

    #[tokio::test]
    async fn two_sessions_price_their_session_fee_on_admin_usage() {
        let (book, admin) = serve_calls(
            || carded_cost(70_000, 0, 40),
            &[Call::Session, Call::Session],
        )
        .await;
        assert_eq!(book, 80, "the budget book: 2 sessions × 40");
        assert_eq!(
            admin,
            80 * MICROS_PER_MINOR,
            "/admin/usage agrees (before: 0)"
        );
    }

    #[tokio::test]
    async fn a_planes_ledgered_class_prices_on_admin_usage() {
        let calls = [Call::Tool, Call::Tool, Call::Tool];
        let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 0), &calls).await;
        assert_eq!(book, 30, "the budget book: 3 × fee 3 + 3 × tool_calls 7");
        assert_eq!(
            admin,
            30 * MICROS_PER_MINOR,
            "/admin/usage agrees (before: 9)"
        );
    }

    #[tokio::test]
    async fn a_planes_class_rides_its_usage_row_with_its_count_and_its_cost() {
        use crate::v1::contract::ClassUsage;
        let calls = [Call::Tool, Call::Tool, Call::Tool];
        let (_, view) = serve_calls_view(|| carded_cost(70_000, 3, 0), &calls).await;
        let want = std::collections::BTreeMap::from([(
            "tool_calls".to_string(),
            ClassUsage {
                count: 3,
                cost: 21 * MICROS_PER_MINOR,
            },
        )]);
        let row = view
            .by_model
            .iter()
            .find(|r| r.upstream == FEE_PLANE)
            .expect("the plane's row");
        assert_eq!(row.usage.classes, want, "the row carries its class");
        assert_eq!(view.total.classes, want, "the total sums it");
        assert_eq!(
            view.total.spend_micros,
            30 * MICROS_PER_MINOR,
            "the class's cost is part of spend_micros, not added to it"
        );
        let wire = serde_json::to_value(row).expect("the row serializes");
        assert_eq!(
            wire["classes"]["tool_calls"],
            serde_json::json!({"count": 3, "cost": 21 * MICROS_PER_MINOR}),
            "the wire shape: classes keyed by class name, each {{count, cost}}"
        );
    }

    #[tokio::test]
    async fn a_token_only_row_carries_no_classes_key_as_on_1_5_5() {
        let t = Call::Tokens {
            input: 1_000_000,
            output: 500_000,
        };
        let (_, view) = serve_calls_view(|| carded_cost(70_000, 3, 0), &[t]).await;
        let row = view.by_model.first().expect("the pools row");
        assert!(row.usage.classes.is_empty());
        let wire = serde_json::to_value(row).expect("the row serializes");
        assert!(
            wire.get("classes").is_none(),
            "a token-only row is 1.5.5's shape: {wire}"
        );
        let total = serde_json::to_value(&view.total).expect("the total serializes");
        assert!(total.get("classes").is_none());
    }

    #[tokio::test]
    async fn a_pools_open_class_prices_on_admin_usage() {
        let calls = [
            Call::Rerank {
                search_units: 1_000_000,
            },
            Call::Rerank {
                search_units: 1_000_000,
            },
        ];
        let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 0), &calls).await;
        assert_eq!(book, 610, "the budget book: 2 × 5 + 6,000,000 micro-units");
        assert_eq!(
            admin,
            610 * MICROS_PER_MINOR,
            "/admin/usage agrees (before: 10)"
        );
    }

    #[tokio::test]
    async fn a_pools_open_class_is_priced_but_never_itemized_on_the_usage_read() {
        let calls = [
            Call::Rerank {
                search_units: 1_000_000,
            },
            Call::Rerank {
                search_units: 1_000_000,
            },
        ];
        let (_, view) = serve_calls_view(|| carded_cost(70_000, 3, 0), &calls).await;
        assert_eq!(view.total.spend_micros, 610 * MICROS_PER_MINOR);
        assert_eq!(
            view.by_model
                .iter()
                .map(|r| r.usage.spend_micros)
                .sum::<i64>(),
            610 * MICROS_PER_MINOR,
            "the model rows still price the open class"
        );
        let mut wires = vec![(
            "total".to_string(),
            serde_json::to_value(&view.total).expect("the total serializes"),
        )];
        for r in &view.by_model {
            wires.push((
                format!("model row {}/{}", r.model, r.upstream),
                serde_json::to_value(r).expect("the row serializes"),
            ));
        }
        for r in &view.by_key {
            wires.push((
                format!("key row {}", r.id),
                serde_json::to_value(r).expect("the key row serializes"),
            ));
        }
        assert!(
            wires.len() >= 3,
            "a total, a model row and a key row: {wires:?}"
        );
        for (what, wire) in wires {
            assert!(
                wire.get("classes").is_none(),
                "a pools {what} keeps 1.5.5's usage shape: {wire}"
            );
        }
    }

    #[tokio::test]
    async fn pools_only_token_traffic_is_unchanged() {
        let t = || Call::Tokens {
            input: 1_000_000,
            output: 500_000,
        };
        let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 0), &[t(), t()]).await;
        assert_eq!(book, 410);
        assert_eq!(admin, 410 * MICROS_PER_MINOR);
    }

    #[tokio::test]
    async fn an_old_served_entry_prices_both_the_row_and_its_itemized_classes() {
        use busbar_kernel::cost::{Author, CardEntryDraft, History};
        const TOOL_SUBJECT: &str = "srv.read";
        const TOOL_CLASS: &str = "tool_calls";
        const CALLS: u64 = 3;
        const OLD_CALL_MICROS: u64 = 70_000;
        const NEW_CALL_MICROS: u64 = 10_000;
        const OLD_REQUEST_MINOR: i64 = 3;
        const NEW_REQUEST_MINOR: i64 = 1;
        let bucket = busbar_kernel::governance::metering_bucket(busbar_kernel::store::now());
        let day = busbar_kernel::governance::METERING_BUCKET_SECS;
        let old_era = (bucket - day) * 1_000;
        let activated = (bucket - day / 2) * 1_000;
        let old_cost = carded_cost(OLD_CALL_MICROS, OLD_REQUEST_MINOR, 0);
        let new_cost = carded_cost(NEW_CALL_MICROS, NEW_REQUEST_MINOR, 0);
        let mut history = History::opening(new_cost.card().clone(), 0);
        history.append(CardEntryDraft {
            effective_from: old_era,
            effective_until: None,
            card: old_cost.card().clone(),
            appended_at: old_era,
            author: Author::Config { policy_epoch: 1 },
        });
        let old_seq = history.head_key().expect("the appended entry has a key");
        let old_version = history.entries()[1].id().metering_version();
        history.append(CardEntryDraft {
            effective_from: activated,
            effective_until: None,
            card: new_cost.card().clone(),
            appended_at: activated,
            author: Author::Config { policy_epoch: 2 },
        });
        let store = Arc::new(MemoryStore::new());
        store
            .add_metering(&busbar_contract::records::MeteringDelta {
                key_id: KEY.to_string(),
                bucket,
                model: TOOL_SUBJECT.to_string(),
                provider: FEE_PLANE.to_string(),
                tokens_input: 0,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: CALLS,
                billable_requests: CALLS,
                key_group_at_use: String::new(),
                pricing_version: old_version,
                priced_from_ms: old_era,
                usage_units: std::collections::BTreeMap::from([(TOOL_CLASS.to_string(), CALLS)]),
            })
            .unwrap();
        let gov = Arc::new(GovState::new(store, None).unwrap());
        let app = crate::new_test_app().governance(gov).cost(new_cost).build();
        let _planes = TestRegistryIsolation::seeded(&[&POOLS, &FEE, &FREE]);
        let view = AdminService::new(app)
            .with_rate_history(Arc::new(history))
            .get_usage(Some(bucket), None)
            .await
            .unwrap();
        let call_count = i64::try_from(CALLS).unwrap();
        let class_cost = call_count * i64::try_from(OLD_CALL_MICROS).unwrap();
        let request_cost = call_count * OLD_REQUEST_MINOR * MICROS_PER_MINOR;
        assert_eq!(view.total.spend_micros, class_cost + request_cost);
        assert_eq!(view.total.classes[TOOL_CLASS].cost, class_cost);
        assert_eq!(view.by_model[0].usage.classes[TOOL_CLASS].cost, class_cost);
        assert_eq!(view.rate_card_version, Some(old_seq.hex()));
    }

    #[test]
    fn the_dated_read_prices_a_rows_classes_as_the_fallback_does() {
        use crate::v1::contract::UsageBreakdown;
        use busbar_kernel::cost::PER_SESSION;
        let cost = carded_cost(70_000, 3, 40);
        let history = busbar_kernel::cost::History::opening(cost.card().clone(), 0);
        let view = history.current();
        let (_, card) = view.card_at(0).expect("the opening card");
        let classes = |pairs: &[(&str, u64)]| -> std::collections::BTreeMap<String, u64> {
            pairs.iter().map(|(c, n)| (c.to_string(), *n)).collect()
        };
        let fee_row = format!("{FEE_PLANE}{PLANE_LANE_SEP}");
        let tool_row = format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read");
        for (lane, requests, units, minor) in [
            (fee_row.as_str(), 0, classes(&[(PER_SESSION, 2)]), 80),
            (tool_row.as_str(), 3, classes(&[("tool_calls", 3)]), 30),
            (POOLS_MODEL, 1, classes(&[("search_units", 1_000_000)]), 305),
        ] {
            let b = UsageBreakdown {
                requests,
                ..Default::default()
            };
            let dated = crate::v1::service::derive_spend_micros_row_classes_at_card(
                &view, 0, card, &cost, lane, &b, &units,
            )
            .expect("priced");
            let fallback =
                crate::v1::service::derive_spend_micros_row_classes(&cost, lane, &b, &units)
                    .expect("priced");
            assert_eq!(
                (dated, fallback),
                (minor * MICROS_PER_MINOR, minor * MICROS_PER_MINOR)
            );
        }
    }

    #[tokio::test]
    async fn mixed_traffic_agrees_with_the_budget_book() {
        let calls = [
            Call::Tokens {
                input: 1_000_000,
                output: 500_000,
            },
            Call::Rerank {
                search_units: 1_000_000,
            },
            Call::Session,
            Call::Tool,
            Call::Tool,
        ];
        let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 40), &calls).await;
        assert_eq!(book, 200 + 5 + 300 + 5 + 40 + 2 * (3 + 7));
        assert_eq!(admin, book * MICROS_PER_MINOR);
    }
}

#[test]
fn the_store_catalog_heads_with_the_linked_store_rows() {
    let svc = svc_with(tmp_plugins_dir("linked-head"), unsigned_ok_posture());
    busbar_kernel_testkit::test_support::root::ensure();
    let stores = busbar_kernel::preflight::root_rows().stores;
    let linked: Vec<&str> = stores.iter().map(|s| s.0).collect();
    assert!(!linked.is_empty(), "the build links a store row");
    let cat = svc.store_plugin_catalog();
    let head: Vec<(&str, &str, &str, Option<bool>)> = cat[..linked.len()]
        .iter()
        .map(|p| (p.name.as_str(), p.r#type, p.loader, p.active))
        .collect();
    let want: Vec<_> = linked
        .iter()
        .map(|n| (*n, "store", "compiled-in", None))
        .collect();
    assert_eq!(head, want);
}

#[test]
fn every_admin_trust_resolution_warns_about_a_malformed_floor() {
    use busbar_kernel::diagnostics::CONFIG_ANTIDOWNGRADE_FLOOR_INVALID;
    use tracing_subscriber::layer::SubscriberExt as _;
    let mut cfg = busbar_kernel::config::PluginsCfg::default();
    cfg.min_versions.insert("p".into(), "v2".into());
    let app = crate::new_test_app().plugins_cfg(cfg).build();
    let cap = busbar_kernel_testkit::test_support::warn_capture::WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        super::operations::admission(&app).expect("an admission is installed");
    });
    assert!(
        cap.contains(&CONFIG_ANTIDOWNGRADE_FLOOR_INVALID.banner().to_string()),
        "{:?}",
        cap.messages()
    );
}

struct RefusingAdmission;

impl busbar_kernel::admission::PluginAdmission for RefusingAdmission {
    fn is_tarball(&self, file: &str) -> bool {
        file.ends_with(".tar.gz")
    }
    fn max_tarball_bytes(&self) -> u64 {
        1024
    }
    fn restart_default(&self, _kind: &str) -> bool {
        true
    }
    fn policy_resolves(&self, _cfg: &busbar_kernel::config::PluginsCfg) -> Result<(), String> {
        Err("the root's refusal".into())
    }
    fn inventory(
        &self,
        _dir: &std::path::Path,
        _cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Result<Vec<busbar_kernel::admission::Inventoried>, String> {
        Err("the root's refusal".into())
    }
    fn admit_upload(
        &self,
        _dir: &std::path::Path,
        _file: &str,
        _tarball: &[u8],
        _cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Result<busbar_kernel::admission::Admitted, busbar_kernel::admission::Refusal> {
        Err(busbar_kernel::admission::Refusal::Validation(
            "the root's refusal".into(),
        ))
    }
    fn inspect(
        &self,
        _tarball: &[u8],
        _cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Result<
        (
            busbar_kernel::admission::Stated,
            busbar_kernel::admission::Judged,
        ),
        busbar_kernel::admission::Refusal,
    > {
        Err(busbar_kernel::admission::Refusal::Validation(
            "the root's refusal".into(),
        ))
    }
    fn rollback_target(
        &self,
        _file: &str,
        _bytes: &[u8],
        _cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Result<busbar_kernel::admission::Stated, busbar_kernel::admission::Refusal> {
        Err(busbar_kernel::admission::Refusal::Validation(
            "the root's refusal".into(),
        ))
    }
}

#[test]
fn every_admin_trust_moment_resolves_through_the_snapshots_builder() {
    static REFUSING: RefusingAdmission = RefusingAdmission;
    let dir = tmp_plugins_dir("refusing-admission");
    std::fs::write(dir.join("p.tar.gz"), b"bytes").unwrap();
    let app = crate::new_test_app()
        .plugins_dir(dir)
        .plugin_admission(&REFUSING)
        .build();
    let admission = super::operations::admission(&app).expect("the snapshot's admission");
    assert_eq!(
        admission.policy_resolves(&app.plugins_cfg).err().as_deref(),
        Some("the root's refusal")
    );
    let svc = AdminService::new(app.clone());
    assert!(matches!(
        svc.inspect_plugin(b"bytes"),
        Err(AdminError::Validation(msg)) if msg == "the root's refusal"
    ));
    assert!(matches!(
        svc.install_store_plugin("p2.tar.gz", b"bytes"),
        Err(AdminError::Validation(msg)) if msg == "the root's refusal"
    ));
    assert!(matches!(
        svc.resolve_plugin_rollback("p.tar.gz", &std::collections::BTreeMap::new()),
        Err(AdminError::Validation(msg)) if msg == "the root's refusal"
    ));
    assert!(
        svc.store_plugin_catalog()
            .iter()
            .all(|p| p.loader == "compiled-in"),
        "an unresolvable policy lists the linked rows alone"
    );
    let mut none = (*app).clone();
    none.plugin_admission = None;
    assert!(super::operations::admission(&none).is_err());

    assert!(validate_plugin_filename(&none, "plain.tar.gz").is_err());
}

#[test]
fn an_admin_view_shows_only_declared_public_setting_values() {
    let public = |module: &str| -> std::collections::BTreeSet<String> {
        match module {
            "stub" => ["url".to_string()].into_iter().collect(),
            _ => std::collections::BTreeSet::new(),
        }
    };
    let mut v = serde_json::json!({
        "store": { "module": "stub", "settings": {
            "url": "https://ledger.internal", "password": "hunter2", "undeclared": "u-value"
        } },
        "other": { "module": "plain", "settings": { "url": "https://plain.internal" } }
    });
    super::redact_settings_bags_with(&mut v, &public);
    let text = v.to_string();
    for hidden in ["hunter2", "u-value", "https://plain.internal"] {
        assert!(!text.contains(hidden), "`{hidden}` shown: {text}");
    }
    assert_eq!(
        v["store"]["settings_public"],
        serde_json::json!({ "url": "https://ledger.internal" })
    );
    assert_eq!(
        v["store"]["settings_keys"],
        serde_json::json!(["password", "undeclared", "url"])
    );
    assert!(v["other"].get("settings_public").is_none(), "{text}");
    assert_eq!(v["other"]["settings_keys"], serde_json::json!(["url"]));
}
