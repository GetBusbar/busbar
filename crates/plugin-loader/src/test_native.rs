// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST SIGNER AND ADMISSION FOR MIN-3 IMAGES: a fixed test key that only [`test_trust`] trusts, the manifest
//! a pack would sign for an image, and the dropped-in image admitted through the loader's own `admit`, with no
//! `unsafe`. Moved out of `test_host.rs` (which re-exports these names until it is deleted).
#![forbid(unsafe_code)]

/// The publisher every test-signed MIN-3 manifest names; only [`test_trust`] trusts it.
pub const TEST_PUBLISHER: &str = "busbar-test";

/// The test signing key (a fixed seed: never a release key, trusted by nothing but [`test_trust`]).
#[must_use]
pub fn test_key() -> crate::sign::SigningKey {
    crate::sign::SigningKey::from_bytes(&[0x5a; 32])
}

/// A `plugins.trust` that trusts [`TEST_PUBLISHER`]'s [`test_key`] only for `expected_scope`
/// (no opt-in flag). The scope must come from the fixture's expectation, not the manifest under test.
#[must_use]
pub fn test_trust(expected_scope: &str) -> crate::admit::TrustConfig {
    let mut trust = crate::sign::TrustPolicy::default();
    trust.publishers.insert(
        TEST_PUBLISHER.to_string(),
        crate::sign::PublisherTrust {
            plugins: [expected_scope.to_string()].into_iter().collect(),
            keys: vec![crate::sign::PublisherKey {
                key: test_key().verifying_key(),
                revoked: false,
            }],
        },
    );
    trust
}

/// The manifest a pack would sign for `bytes`: name, version, kind and ABI read from the image's own stamp,
/// `former_names` as the header states them, signed by [`test_key`] under [`TEST_PUBLISHER`].
///
/// # Errors
/// The image's stamp scan refusal (no stamp, more than one, or a malformed one).
pub fn test_manifest(
    bytes: &[u8],
    former_names: &[&str],
) -> Result<crate::admit::SignedManifest, crate::refusal::Refusal> {
    let stamp = crate::scan::stamp(bytes).map_err(crate::scan::StampScanErr::refusal)?;
    let kind = busbar_plugin_abi::types::KindCode::from_raw(stamp.kind)
        .map_or("", crate::admit::kind_word);
    let name = crate::scan::text(&stamp.name).to_string();
    let manifest = crate::sign::Manifest {
        alias: name.clone(),
        name,
        kind: kind.to_string(),
        version: crate::scan::text(&stamp.version).to_string(),
        publisher: TEST_PUBLISHER.to_string(),
        abi_version: stamp.kind_abi,
        former_names: former_names.iter().map(|n| (*n).to_string()).collect(),
        ..crate::sign::Manifest::default()
    };
    Ok(test_sign(manifest, bytes))
}

/// `manifest` re-signed by [`test_key`] over `bytes` (its `sha256` set to theirs).
#[must_use]
pub fn test_sign(
    manifest: crate::admit::SignedManifest,
    bytes: &[u8],
) -> crate::admit::SignedManifest {
    crate::sign::sign(&test_key(), manifest, bytes)
}

/// A dropped-in MIN-3 image: `bytes` written to a private file, opened read-only, unlinked, and admitted from
/// that descriptor through the loader's `admit` under [`test_trust`] for the explicit expected plugin
/// scope (every step production runs).
///
/// # Errors
/// The loader's refusal.
///
/// # Panics
/// When the scratch file cannot be written or opened.
#[cfg(unix)]
pub fn admit_bytes(
    bytes: &[u8],
    manifest: &crate::admit::SignedManifest,
    expected_scope: &str,
) -> Result<crate::admit::Admitted, crate::refusal::Refusal> {
    use std::io::Write as _;
    let path = std::env::temp_dir().join(format!(
        "busbar-test-admit-{}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("create the scratch image {}: {e}", path.display()));
    file.write_all(bytes)
        .unwrap_or_else(|e| panic!("write the scratch image {}: {e}", path.display()));
    drop(file);
    let file = std::fs::File::open(&path)
        .unwrap_or_else(|e| panic!("open the scratch image {}: {e}", path.display()));
    let _ = std::fs::remove_file(&path);
    crate::admit::admit(
        std::os::fd::OwnedFd::from(file),
        manifest,
        &test_trust(expected_scope),
    )
}
