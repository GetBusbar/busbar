// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.5.5 jwt-bearer key-file credential migrates automatically (LIFECYCLE-A-PLAN §WP2,
//! owner ruling 2026-11-17). A 1.5.5 provider whose `api_key` resolves to a FILENAME (not inline
//! JSON) is converted by the owning auth plugin's own self-migration to an explicit
//! `{file: <path>}` reference. The first boot writes it back and re-executes, and the restarted
//! boot reads the key through the built-in file secret. The ledger is the deleted
//! `migrate_door_tests` file cases: a symlink is followed, the path is kept verbatim (spaces
//! included); a directory or a device is refused at the first boot's write-back (core's leak
//! guard, LEGACY-KEYFILE-MARKER r2 A-M2), and an over-bound file by busbar_secret_file on the
//! restarted boot.

#![cfg(unix)]
#![cfg(all(linked_section_pools, linked_every_auth))]

mod common;

use std::path::{Path, PathBuf};

/// A service account in the shape the jwt-bearer style accepts (auth-oauth's own test key shape).
const SERVICE_ACCOUNT: &str = r#"{"type":"service_account","client_email":"sa@p.iam","token_uri":"https://127.0.0.1:9/token","private_key":"-----BEGIN PRIVATE KEY-----\nAAEC\nAw==\n-----END PRIVATE KEY-----\n"}"#;

/// busbar_secret_file's bound (`secret-file/src/lib.rs` HARD_MAX_BYTES = 16 MiB - 64).
const SECRET_FILE_MAX: u64 = (16 << 20) - 64;

fn workdir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "busbar-jwt-key-file-{}-{tag}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Boot a 1.5.5 document whose jwt-bearer provider's `api_key` is `{env: SA_PATH}` with `SA_PATH`
/// holding `key_path`, through the first boot's write-back and automatic restart.
fn boot_1_5_5(dir: &Path, key_path: &Path) -> common::chat_spend::Gateway {
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    let signing = common::chat_spend::signing_key(dir);
    let mut doc = busbar_contract::yaml::from_str(
        "store: { module: memory }\n\
         providers:\n  mock:\n    api_key: { env: SA_PATH }\n    auth: jwt-bearer\n\
         models:\n  test-model:\n    provider: mock\n",
    )
    .unwrap();
    common::chat_spend::serve(&mut doc, data, admin, &signing);
    let config = dir.join("config.yaml");
    std::fs::write(&config, busbar_contract::yaml::to_string(&doc).unwrap()).unwrap();
    let providers = dir.join("providers.yaml");
    std::fs::write(&providers, common::chat_spend::providers_yaml(9)).unwrap();
    let path = key_path.to_str().expect("a UTF-8 test path").to_owned();
    common::chat_spend::Gateway::spawn(dir, &config, &providers, data, admin, &[("SA_PATH", &path)])
}

/// The migrated config.yaml names `key_path` verbatim as a file reference and no longer the
/// historical environment reference.
fn assert_converted(dir: &Path, key_path: &Path) {
    let migrated = std::fs::read_to_string(dir.join("config.yaml")).unwrap();
    let path = key_path.to_str().unwrap();
    assert!(
        migrated.contains("file:") && migrated.contains(path),
        "the credential became a file reference to {path:?}:\n{migrated}"
    );
    assert!(
        !migrated.contains("SA_PATH"),
        "the historical filename reference is gone:\n{migrated}"
    );
}

#[test]
fn a_symlinked_1_5_5_key_file_converts_and_serves_after_the_restart() {
    let dir = workdir("symlink");
    let key = dir.join("sa.json");
    std::fs::write(&key, SERVICE_ACCOUNT).unwrap();
    let link = dir.join("sa-link.json");
    std::os::unix::fs::symlink(&key, &link).unwrap();
    let mut gateway = boot_1_5_5(&dir, &link);
    gateway
        .ready()
        .unwrap_or_else(|log| panic!("the converted key file serves; log:\n{log}"));
    // The symlink path itself is kept, never the resolved target.
    assert_converted(&dir, &link);
    drop(gateway);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_1_5_5_key_file_name_with_spaces_is_kept_verbatim_and_serves() {
    let dir = workdir("spaces");
    let key = dir.join(" sa key.json ");
    std::fs::write(&key, SERVICE_ACCOUNT).unwrap();
    let mut gateway = boot_1_5_5(&dir, &key);
    gateway
        .ready()
        .unwrap_or_else(|log| panic!("the verbatim path serves; log:\n{log}"));
    assert_converted(&dir, &key);
    drop(gateway);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An over-bound regular file passes the write-back (it is an existing regular file), converts and is
/// then refused by the restarted boot with busbar_secret_file's reason (A-M2); no key text is echoed.
fn assert_refused_after_restart(tag: &str, key_path: &Path, reason: &str) {
    let dir = workdir(tag);
    let mut gateway = boot_1_5_5(&dir, key_path);
    let log = gateway
        .ready()
        .expect_err("the restarted boot refuses the unreadable key file");
    assert!(
        log.contains(reason),
        "secret-file's reason {reason:?}; log:\n{log}"
    );
    assert!(
        !log.contains("BEGIN PRIVATE KEY"),
        "no key text is echoed; log:\n{log}"
    );
    drop(gateway);
    let _ = std::fs::remove_dir_all(&dir);
}

/// LEGACY-KEYFILE-MARKER r2 condition A-M2: a source that names no existing regular file (a
/// directory, a device) is refused at the first boot's write-back by core's leak guard, before
/// anything is written; config.yaml keeps its 1.5.5 text and no key text is echoed.
fn assert_refused_at_write_back(tag: &str, key_path: &Path) {
    let dir = workdir(tag);
    let mut gateway = boot_1_5_5(&dir, key_path);
    let log = gateway
        .ready()
        .expect_err("the first boot refuses a credential that is not an existing key file");
    assert!(
        log.contains("was not converted to an existing key file"),
        "the leak guard's refusal; log:\n{log}"
    );
    assert!(
        !log.contains("BEGIN PRIVATE KEY"),
        "no key text is echoed; log:\n{log}"
    );
    let kept = std::fs::read_to_string(dir.join("config.yaml")).unwrap();
    assert!(
        kept.contains("SA_PATH") && !kept.contains("file:"),
        "nothing was written back:\n{kept}"
    );
    drop(gateway);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_1_5_5_key_file_that_is_a_directory_is_refused_at_the_write_back() {
    let holder = workdir("directory-holder");
    let directory = holder.join("keys");
    std::fs::create_dir_all(&directory).unwrap();
    assert_refused_at_write_back("directory", &directory);
    let _ = std::fs::remove_dir_all(&holder);
}

#[test]
fn a_1_5_5_key_file_that_is_a_device_is_refused_at_the_write_back() {
    assert_refused_at_write_back("device", Path::new("/dev/zero"));
}

#[test]
fn a_1_5_5_key_file_over_the_secret_file_bound_is_refused_after_the_restart() {
    let holder = workdir("oversize-holder");
    let big = holder.join("big.json");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(SECRET_FILE_MAX + 1)
        .unwrap();
    assert_refused_after_restart("oversize", &big, "is larger than");
    let _ = std::fs::remove_dir_all(&holder);
}
