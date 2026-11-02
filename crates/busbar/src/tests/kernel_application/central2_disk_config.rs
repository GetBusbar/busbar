// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use busbar_kernel::appbuild::load_config_from_disk_judged as load_config_from_disk;
use std::time::{Duration, Instant};
fn frozen_str(key: &str) -> String {
    let doc: serde_yaml::Value = serde_yaml::from_str(include_str!(
        "../../../../busbar-kernel/src/tests/fixtures/frozen_customer_text.yaml"
    ))
    .expect("the existing customer fixture parses");
    doc.get(key)
        .and_then(serde_yaml::Value::as_str)
        .expect("existing frozen customer word")
        .to_string()
}
const BOOT_LEGACY_14X_CONFIG: &str = r#"
listen: "0.0.0.0:8080"
governance:
  enabled: true
  db_path: "/var/lib/busbar/governance.db"
  admin_token: '${PATH}'
providers:
  upstream-a:
    api_key_env: UPSTREAM_A_KEY
models:
  claude: { provider: upstream-a }
pools:
  fast:
    members:
      - { target: claude, weight: 1 }
"#;
const BOOT_MINIMAL_CONFIG: &str = "providers: {}\nmodels: {}\n";
fn boot_config_dir(
    tag: &str,
    config_yaml: &str,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-boot-legacy-{}-{tag}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");
    let providers_path = dir.join("providers.yaml");
    std::fs::write(&providers_path, "{}\n").unwrap();
    std::fs::write(&config_path, config_yaml).unwrap();
    (dir, config_path, providers_path)
}
#[test]
fn load_config_from_disk_refuses_a_real_legacy_config_file_loudly() {
    const CHILD: &str = "BUSBAR_CENTRAL2_DISK_CHILD";
    const WITNESS: &str = "actual root disk config assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let (dir, config_path, providers_path) = boot_config_dir("refuse", BOOT_LEGACY_14X_CONFIG);

    let result = load_config_from_disk(
        &config_path,
        Some(&providers_path),
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &crate::root::door_steps::Rules::default(),
    );

    let err = match result {
        Ok(_) => panic!(
            "a REAL 1.x config file on disk must be REFUSED at the real boot entry point \
             (load_config_from_disk), not silently loaded under 1.5.0 semantics"
        ),
        Err(e) => e,
    };
    assert!(
        err.contains("busbar --migrate-config"),
        "the boot-time refusal must name the migrator: {err}"
    );
    assert!(
        err.contains("1.x"),
        "the boot-time refusal must name the version family: {err}"
    );

    std::fs::remove_dir_all(&dir).ok();
    println!("{WITNESS}");
}
#[test]
fn migrate_config_then_load_config_from_disk_boots_the_real_migrated_file() {
    const CHILD: &str = "BUSBAR_CENTRAL2_DISK_CHILD";
    const WITNESS: &str = "actual root disk config assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let (dir, legacy_config_path, providers_path) =
        boot_config_dir("migrate", BOOT_LEGACY_14X_CONFIG);

    let raw = std::fs::read_to_string(&legacy_config_path).unwrap();
    let migrated =
        busbar_kernel::config::migrate::migrate_config(&raw).expect("legacy config migrates");

    let migrated_path = dir.join("migrated-config.yaml");
    std::fs::write(&migrated_path, &migrated.yaml).unwrap();

    let loaded = load_config_from_disk(
        &migrated_path,
        Some(&providers_path),
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &crate::root::door_steps::Rules::default(),
    )
    .unwrap_or_else(|e| {
        panic!("the migrated config must boot cleanly through the real boot path: {e}")
    });

    assert_eq!(loaded.deploy.listen, "0.0.0.0:8080");
    assert_eq!(
        loaded.deploy.store.as_ref().map(|s| s.module.as_str()),
        Some(frozen_str("legacy_backend_1_4").as_str()),
        "the migrated store module must survive the real disk-load pipeline"
    );

    std::fs::remove_dir_all(&dir).ok();
    println!("{WITNESS}");
}
#[test]
fn boot_default_config_defers_store_overlay_recovery_until_the_anchor_opens() {
    const CHILD: &str = "BUSBAR_CENTRAL2_DISK_CHILD";
    const WITNESS: &str = "actual root disk config assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let (dir, config_path, _providers_path) = boot_config_dir("durable", BOOT_MINIMAL_CONFIG);

    std::env::remove_var("BUSBAR_CONFIG_OVERLAY");
    let loaded = load_config_from_disk(
        &config_path,
        None,
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &crate::root::door_steps::Rules::default(),
    )
    .expect("a mutable default config must boot");
    assert!(!loaded.config_locked, "default config is mutable");
    assert!(loaded.overlay_path.is_none());
    assert!(loaded.overlay_doc.is_none());
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        2,
        "only operator input files exist"
    );
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}
#[test]
fn boot_mutable_with_overlay_disabled_refuses_to_boot() {
    const CHILD: &str = "BUSBAR_CENTRAL2_DISK_CHILD";
    const WITNESS: &str = "actual root disk config assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let cfg = "providers: {}\nmodels: {}\nconfig:\n  locked: false\n  overlay: false\n";
    let (dir, config_path, _p) = boot_config_dir("no-backend", cfg);
    let Err(err) = load_config_from_disk(
        &config_path,
        None,
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &crate::root::door_steps::Rules::default(),
    ) else {
        panic!("mutable + overlay disabled must refuse to boot");
    };

    assert!(
        err.contains("mutable config requires") && err.contains("Store-backed overlay"),
        "the boot refusal must be the specific mutable-without-backend message: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}
#[test]
fn boot_locked_config_has_no_overlay() {
    const CHILD: &str = "BUSBAR_CENTRAL2_DISK_CHILD";
    const WITNESS: &str = "actual root disk config assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let cfg = "providers: {}\nmodels: {}\nconfig:\n  locked: true\n";
    let (dir, config_path, _p) = boot_config_dir("locked", cfg);
    let loaded = load_config_from_disk(
        &config_path,
        None,
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &crate::root::door_steps::Rules::default(),
    )
    .expect("a locked config boots");
    assert!(loaded.config_locked);
    assert!(loaded.overlay_path.is_none(), "locked ⇒ no overlay backend");
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}
#[test]
fn boot_providers_file_pointer_is_honored_and_override_wins() {
    const CHILD: &str = "BUSBAR_CENTRAL2_DISK_CHILD";
    const WITNESS: &str = "actual root disk config assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-providers-file-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");

    let catalog = dir.join("catalog.yaml");
    std::fs::write(&catalog, "{}\n").unwrap();
    std::fs::write(
        &config_path,
        "providers: {}\nmodels: {}\nproviders_file: catalog.yaml\n",
    )
    .unwrap();

    let loaded = load_config_from_disk(
        &config_path,
        None,
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &crate::root::door_steps::Rules::default(),
    )
    .expect("providers_file pointer resolves");
    assert_eq!(
        loaded.providers_path, catalog,
        "the providers_file pointer must be honored"
    );

    let other = dir.join("other-catalog.yaml");
    std::fs::write(&other, "{}\n").unwrap();
    let loaded2 = load_config_from_disk(
        &config_path,
        Some(&other),
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &crate::root::door_steps::Rules::default(),
    )
    .expect("override resolves");
    assert_eq!(
        loaded2.providers_path, other,
        "the override wins over providers_file"
    );

    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}
