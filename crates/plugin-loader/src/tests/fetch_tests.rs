// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn tmpdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let mut rnd = [0u8; 8];
    let _ = getrandom::fill(&mut rnd);
    p.push(format!(
        "busbar-fetch-test-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn spec(url: &str, sha: Option<&str>, file: &str) -> FetchSpec {
    FetchSpec {
        url: url.into(),
        sha256: sha.map(str::to_string),
        filename: file.into(),
    }
}

#[test]
fn cached_by_pin_skips_network() {
    let dir = tmpdir();
    let body = sealed_tarball(crate::release_trust::now() + 86_400);
    std::fs::write(dir.join("plugin.tar.gz"), &body).unwrap();
    let pin = sha256_hex(&body);

    let never = |_: &str| -> Result<Vec<u8>, String> { panic!("network must not be touched") };
    let out = fetch_plugins(
        &dir,
        &[spec("https://x/plugin.tar.gz", Some(&pin), "plugin.tar.gz")],
        true,
        &never,
    )
    .unwrap();
    assert_eq!(
        out,
        vec![FetchOutcome::Cached {
            filename: "plugin.tar.gz".into()
        }]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hash_mismatch_never_writes() {
    let dir = tmpdir();
    let pin = sha256_hex(b"expected");
    let dl = |_: &str| Ok(b"WRONG-BYTES".to_vec());
    let err = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", Some(&pin), "p.tar.gz")],
        true,
        &dl,
    )
    .unwrap_err();
    assert!(err[0].contains("mismatch"), "{err:?}");
    assert!(
        !dir.join("p.tar.gz").exists(),
        "no file must be written on mismatch"
    );

    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(leftovers.is_empty(), "dir must be unchanged: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn boot_miss_fatal_reload_miss_warns() {
    let dir = tmpdir();
    let dead = |_: &str| -> Result<Vec<u8>, String> { Err("connection refused".into()) };
    let s = [spec(
        "https://unreachable/p.tar.gz",
        Some("deadbeef"),
        "p.tar.gz",
    )];

    assert!(
        fetch_plugins(&dir, &s, true, &dead).is_err(),
        "boot miss must be fatal"
    );

    let out = fetch_plugins(&dir, &s, false, &dead).unwrap();
    assert!(
        matches!(out.as_slice(), [FetchOutcome::Warned { .. }]),
        "reload miss must warn: {out:?}"
    );
    assert!(!dir.join("p.tar.gz").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn traversal_filename_is_refused_at_both_sites() {
    let dir = tmpdir();
    let body = sealed_tarball(crate::release_trust::now() + 86_400);
    let pin = sha256_hex(&body);

    let dl = |_: &str| Ok(body.to_vec());

    for evil in [
        "../../evil",
        "../evil.tar.gz",
        "sub/evil.tar.gz",
        "/etc/evil",
        ".",
        "",
    ] {
        let err = fetch_plugins(
            &dir,
            &[spec("https://x/p.tar.gz", Some(&pin), evil)],
            true,
            &dl,
        )
        .unwrap_err();
        assert!(
            err[0].contains("unsafe target filename"),
            "filename {evil:?} must be refused as unsafe, got {err:?}"
        );
    }

    assert!(!dir.parent().unwrap().join("evil").exists());
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(leftovers.is_empty(), "dir must be untouched: {leftovers:?}");

    let out = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", Some(&pin), "good.tar.gz")],
        true,
        &dl,
    )
    .unwrap();
    assert_eq!(
        out,
        vec![FetchOutcome::Fetched {
            filename: "good.tar.gz".into()
        }]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verified_download_is_written() {
    let dir = tmpdir();
    let body = sealed_tarball(crate::release_trust::now() + 86_400);
    let pin = sha256_hex(&body);
    let dl = |_: &str| Ok(body.to_vec());
    let out = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", Some(&pin), "p.tar.gz")],
        true,
        &dl,
    )
    .unwrap();
    assert_eq!(
        out,
        vec![FetchOutcome::Fetched {
            filename: "p.tar.gz".into()
        }]
    );
    assert_eq!(std::fs::read(dir.join("p.tar.gz")).unwrap(), body);
    let _ = std::fs::remove_dir_all(&dir);
}

fn sealed_tarball(expires: u64) -> Vec<u8> {
    use crate::release_trust::tests::{
        entry, keys_doc, seal_keys, seal_targets, targets_doc, TestSigner,
    };
    let (root, signer) = (TestSigner::p256(), TestSigner::p256());
    let lib = b"lib";
    let m = crate::sign::Manifest {
        name: "busbar-store-x".into(),
        alias: "x".into(),
        kind: "store".into(),
        version: "1.6.0".into(),
        publisher: "busbar".into(),
        abi_version: 1,
        sha256: sha256_hex(lib),
        ..Default::default()
    };
    let listed = sha256_hex(&crate::sign::canonical_manifest_bytes(&m));
    let mut keys = keys_doc(&[&signer]);
    keys.expires = expires;
    let mut targets = targets_doc(vec![entry(
        &m.name,
        &m.version,
        crate::release_trust::PLUGIN_TARGET,
        &listed,
    )]);
    targets.expires = expires;
    let m = crate::sign::Manifest {
        signature: crate::release_trust::wire::write_seal(
            &seal_keys(&keys, &[&root]),
            &seal_targets(&targets, &[&signer]),
        )
        .unwrap(),
        ..m
    };
    crate::tarball::package(&m, "lib.so", lib).unwrap()
}

#[test]
fn a_fetched_tarball_whose_seal_has_expired_is_refused_and_not_written() {
    let dir = tmpdir();
    let body = sealed_tarball(1_600_000_000);
    let dl = |_: &str| Ok(body.clone());
    let err = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", None, "p.tar.gz")],
        true,
        &dl,
    )
    .unwrap_err();
    assert!(err[0].contains("keys-expired"), "{err:?}");
    assert!(
        !dir.join("p.tar.gz").exists(),
        "an expired download is never written"
    );
    let fresh = sealed_tarball(crate::release_trust::now() + 86_400);
    let dl = |_: &str| Ok(fresh.clone());
    fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", None, "p.tar.gz")],
        true,
        &dl,
    )
    .expect("a fresh seal is written");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_installed_tarball_whose_seal_has_since_expired_is_kept() {
    let dir = tmpdir();
    let body = sealed_tarball(1_600_000_000);
    std::fs::write(dir.join("p.tar.gz"), &body).unwrap();
    let pin = sha256_hex(&body);
    let never = |_: &str| -> Result<Vec<u8>, String> { panic!("network must not be touched") };
    let out = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", Some(&pin), "p.tar.gz")],
        true,
        &never,
    )
    .unwrap();
    assert_eq!(
        out,
        vec![FetchOutcome::Cached {
            filename: "p.tar.gz".into()
        }]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unpinned_refetch_of_the_installed_bytes_is_not_judged_for_expiry() {
    let dir = tmpdir();
    let body = sealed_tarball(1_600_000_000);
    std::fs::write(dir.join("p.tar.gz"), &body).unwrap();
    let dl = |_: &str| Ok(body.clone());
    let out = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", None, "p.tar.gz")],
        true,
        &dl,
    )
    .expect("the same bytes as the installed copy: the boot succeeds");
    assert_eq!(
        out,
        vec![FetchOutcome::Fetched {
            filename: "p.tar.gz".into()
        }]
    );
    assert_eq!(std::fs::read(dir.join("p.tar.gz")).unwrap(), body);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unpinned_fetch_of_changed_bytes_with_an_expired_seal_is_refused() {
    let dir = tmpdir();
    let installed = sealed_tarball(1_600_000_000);
    std::fs::write(dir.join("p.tar.gz"), &installed).unwrap();
    let changed = sealed_tarball(1_600_000_001);
    assert_ne!(installed, changed);
    let dl = |_: &str| Ok(changed.clone());
    let err = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", None, "p.tar.gz")],
        true,
        &dl,
    )
    .unwrap_err();
    assert!(
        err[0].contains("(keys-expired)") && err[0].contains("installed copy is kept"),
        "{err:?}"
    );
    assert_eq!(std::fs::read(dir.join("p.tar.gz")).unwrap(), installed);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_successful_downloads_never_replace_an_installed_archive() {
    let installed = sealed_tarball(crate::release_trust::now() + 86_400);
    let truncated = installed[..installed.len() / 2].to_vec();
    for body in [
        b"<html>upstream error served as HTTP 200</html>".to_vec(),
        truncated,
    ] {
        assert!(
            crate::tarball::unpack(&body).is_err(),
            "the RED body is not an archive"
        );
        for fatal in [true, false] {
            let dir = tmpdir();
            let target = dir.join("p.tar.gz");
            std::fs::write(&target, &installed).unwrap();
            let download = |_: &str| Ok(body.clone());
            let answer = fetch_plugins(
                &dir,
                &[spec("https://x/p.tar.gz", None, "p.tar.gz")],
                fatal,
                &download,
            );
            if fatal {
                let errors = answer.expect_err("an invalid successful download refuses boot");
                assert!(errors[0].contains("plugin archive refused"), "{errors:?}");
            } else {
                let outcomes = answer.expect("reload warns and keeps the installed archive");
                assert!(
                    matches!(outcomes.as_slice(), [FetchOutcome::Warned { error, .. }]
                    if error.contains("plugin archive refused")),
                    "{outcomes:?}"
                );
            }
            assert_eq!(
                std::fs::read(&target).unwrap(),
                installed,
                "the installed artifact is byte-identical"
            );
            assert_eq!(
                std::fs::read_dir(&dir).unwrap().count(),
                1,
                "no replacement temp file remains"
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[test]
fn invalid_first_download_is_refused_even_when_its_checksum_matches() {
    let body = b"<html>not a plugin archive</html>";
    let pin = sha256_hex(body);
    for pin in [None, Some(pin.as_str())] {
        let dir = tmpdir();
        let download = |_: &str| Ok(body.to_vec());
        let errors = fetch_plugins(
            &dir,
            &[spec("https://x/p.tar.gz", pin, "p.tar.gz")],
            true,
            &download,
        )
        .expect_err("integrity alone cannot make an unreadable archive installable");
        assert!(errors[0].contains("plugin archive refused"), "{errors:?}");
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "the first install writes nothing"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn a_checksum_mismatch_keeps_the_installed_archive_before_archive_validation() {
    let dir = tmpdir();
    let installed = sealed_tarball(crate::release_trust::now() + 86_400);
    let target = dir.join("p.tar.gz");
    std::fs::write(&target, &installed).unwrap();
    let pin = sha256_hex(b"the expected replacement");
    let download = |_: &str| Ok(b"not an archive and not the pinned download".to_vec());
    let errors = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", Some(&pin), "p.tar.gz")],
        true,
        &download,
    )
    .unwrap_err();
    assert!(errors[0].contains("sha256 mismatch"), "{errors:?}");
    assert!(
        !errors[0].contains("plugin archive refused"),
        "the checksum gate stays first"
    );
    assert_eq!(std::fs::read(&target).unwrap(), installed);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_valid_changed_archive_replaces_the_installed_archive() {
    let dir = tmpdir();
    let installed = sealed_tarball(1_600_000_000);
    let replacement = sealed_tarball(crate::release_trust::now() + 86_400);
    assert_ne!(installed, replacement);
    let target = dir.join("p.tar.gz");
    std::fs::write(&target, &installed).unwrap();
    let download = |_: &str| Ok(replacement.clone());
    let outcomes = fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", None, "p.tar.gz")],
        false,
        &download,
    )
    .expect("a readable fresh archive can still replace an installed artifact");
    assert_eq!(
        outcomes,
        vec![FetchOutcome::Fetched {
            filename: "p.tar.gz".into()
        }]
    );
    assert_eq!(std::fs::read(&target).unwrap(), replacement);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_fetched_third_party_archive_still_requires_the_publishers_trust() {
    use crate::sign::{evaluate, sign, RejectKind, SigningKey, TrustPolicy, Verdict};
    let dir = tmpdir();
    let mut fixture = crate::tarball::unpack(&sealed_tarball(1_600_000_000)).unwrap();
    fixture.manifest.publisher = "acme".into();
    let key = SigningKey::from_bytes(&[7; 32]);
    let manifest = sign(&key, fixture.manifest, &fixture.lib_bytes);
    let body = crate::tarball::package(&manifest, &fixture.lib_name, &fixture.lib_bytes).unwrap();
    let download = |_: &str| Ok(body.clone());
    fetch_plugins(
        &dir,
        &[spec("https://x/p.tar.gz", None, "p.tar.gz")],
        true,
        &download,
    )
    .expect("fetch validates archive shape without changing the third-party admission policy");
    let installed = crate::tarball::unpack(&std::fs::read(dir.join("p.tar.gz")).unwrap()).unwrap();
    let mut policy = TrustPolicy::default();
    assert_eq!(
        evaluate(&installed.lib_bytes, &installed.manifest, &policy)
            .unwrap_err()
            .kind,
        RejectKind::UnknownPublisher
    );
    policy.publishers.insert("acme".into(), key.verifying_key());
    assert!(matches!(
        evaluate(&installed.lib_bytes, &installed.manifest, &policy).unwrap(),
        Verdict::Trusted {
            first_party: false,
            ..
        }
    ));
    std::fs::remove_dir_all(dir).unwrap();
}
