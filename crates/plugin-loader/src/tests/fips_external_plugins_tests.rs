// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FIPS admission (CRYPTO-SEAM §9 "no external", IF §5.2 round 13): a binary whose crypto backend
//! states `EXTERNAL_PLUGINS = false` loads a dropped-in plugin only on busbar's own verified
//! release signature. Each case drives the real directory scan (`scan_and_validate`: phase 1
//! structure, phase 2 trust) over a packed tarball of the neutral secret witness's real cdylib,
//! under the loosest posture an operator can configure, and the admitted one goes on through the
//! real `dlopen` admission (`prepare_dropped_bytes`). [`FipsBackend`] substitutes only the
//! backend's answer: a test binary links one backend.

use super::*;
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::load::{prepare_dropped_bytes, prepare_linked};
use crate::dispatch::{rendering_of, LinkedRow};
use crate::neutral_secret::{door, NAME};
use crate::sign::{sha256_hex, sign, FipsBackend, SigningKey};

/// The embedded first-party release key of these scans.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[0x46; 32])
}

/// A third-party publisher the operator allowlists under `plugins.trust.publishers`.
fn allowlisted() -> SigningKey {
    SigningKey::from_bytes(&[0x47; 32])
}

/// The neutral secret witness's dropped-in image.
fn image() -> Vec<u8> {
    std::fs::read(crate::neutral_secret::cdylib()).expect("read the neutral secret cdylib")
}

/// The witness's manifest, stating its door's own Statement, as `publisher` packs it.
fn stated(publisher: &str) -> Manifest {
    let mut m = crate::both_ways::statement(
        "secret",
        NAME,
        NAME,
        busbar_contract::abi::secret::ABI_VERSION,
    );
    m.publisher = publisher.into();
    m.statement = Some(hex::encode(
        rendering_of(door).expect("the witness renders its Statement"),
    ));
    m
}

/// Every opt-in on and a third party allowlisted: what `plugins.trust` can open, it has opened.
fn wide_open() -> TrustPolicy {
    TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        binary_version: "1.6.0".into(),
        publishers: std::iter::once((
            "acme-allowlisted".to_string(),
            crate::sign::PublisherTrust {
                plugins: [NAME.to_string()].into_iter().collect(),
                keys: vec![crate::sign::PublisherKey {
                    key: allowlisted().verifying_key(),
                    revoked: false,
                }],
            },
        ))
        .collect(),
        allow_untrusted: true,
        ..TrustPolicy::default()
    }
}

/// Scan a plugins directory holding `m` over `lib` alone.
fn scan(tag: &str, m: &Manifest, lib: &[u8], policy: &TrustPolicy) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!(
        "busbar-fips-external-{}-{tag}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    std::fs::create_dir_all(&dir).expect("create the plugins dir");
    let bytes = tarball::package(m, "libplugin.so", lib).expect("package the witness");
    std::fs::write(dir.join(format!("{tag}.tar.gz")), bytes).expect("write the tarball");
    let registry = scan_and_validate(&dir, policy).expect("a refused plugin is skipped, not fatal");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

/// The drop-ins a FIPS build refuses, each of which this policy would otherwise load.
fn not_busbar_s_release(lib: &[u8]) -> Vec<(&'static str, Manifest)> {
    let unsigned = Manifest {
        sha256: sha256_hex(lib),
        ..stated("acme")
    };
    vec![
        ("unsigned", unsigned),
        (
            "unlisted-third-party",
            sign(
                &SigningKey::from_bytes(&[0x48; 32]),
                stated("acme-unlisted"),
                lib,
            ),
        ),
        (
            "allowlisted-third-party",
            sign(&allowlisted(), stated("acme-allowlisted"), lib),
        ),
        (
            "claims-busbar-without-its-key",
            sign(&SigningKey::from_bytes(&[0x49; 32]), stated("busbar"), lib),
        ),
    ]
}

#[test]
fn a_software_backend_keeps_the_trust_policy_s_answer() {
    let lib = image();
    for (case, m) in not_busbar_s_release(&lib) {
        let registry = scan(case, &m, &lib, &wide_open());
        assert!(
            if case == "claims-busbar-without-its-key" {
                registry.resolve(NAME).is_none() && !registry.skipped().is_empty()
            } else {
                registry.resolve(NAME).is_some() && registry.skipped().is_empty()
            },
            "{case}: a backend that admits external plugins leaves plugins.trust the whole \
             answer: {:?}",
            registry
                .skipped()
                .iter()
                .map(|s| &s.reason)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn a_fips_backend_refuses_every_drop_in_that_is_not_busbar_s_own_release() {
    let lib = image();
    for (case, m) in not_busbar_s_release(&lib) {
        let registry = {
            let _fips = FipsBackend::link();
            scan(case, &m, &lib, &wide_open())
        };
        assert!(
            registry.loadable().is_empty() && registry.resolve(NAME).is_none(),
            "{case}: a FIPS backend loads no plugin but busbar's own release, whatever \
             allow_untrusted, allow_untrusted and publishers say"
        );
        let skipped = registry.skipped();
        assert_eq!(skipped.len(), 1, "{case}: the refusal is a skip");
        assert_eq!(
            skipped[0].kind.code(),
            "external_crypto",
            "{case}: refused as the backend's refusal: {}",
            skipped[0].reason
        );
        let rows = busbar_contract::plugin_rows::PluginRows::skipped(&registry);
        assert_eq!(
            rows[0].code, "external_crypto",
            "{case}: the code the boot logger seals on the audit chain"
        );
        let refused = registry.secret_refusal(NAME);
        assert!(
            refused.contains("was not loaded"),
            "{case}: a reference to it fails loud: {refused}"
        );
    }
}

#[test]
fn a_fips_backend_admits_and_opens_busbar_s_own_signed_release() {
    let lib = image();
    let m = sign(&release(), stated("busbar"), &lib);
    let registry = {
        let _fips = FipsBackend::link();
        scan("first-party", &m, &lib, &wide_open())
    };
    assert!(
        registry.skipped().is_empty(),
        "{:?}",
        registry
            .skipped()
            .iter()
            .map(|s| &s.reason)
            .collect::<Vec<_>>()
    );
    let row = registry
        .resolve(NAME)
        .expect("busbar's own release is admitted");
    assert!(
        matches!(
            row.verdict,
            Verdict::Trusted {
                first_party: true,
                ..
            }
        ),
        "admitted on the release key, not an opt-in"
    );
    let stated = row
        .manifest
        .stated_rendering()
        .expect("the manifest's Statement is hex")
        .expect("the manifest states a Statement");
    let _fips = FipsBackend::link();
    if let Err(e) = prepare_dropped_bytes::<Secret>(&row.lib_bytes, NAME, &stated) {
        panic!("busbar's own release is opened and admitted at its door: {e}");
    }
}

#[test]
fn a_fips_backend_leaves_a_compiled_in_plugin_alone() {
    let _fips = FipsBackend::link();
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            crate::both_ways::statement(
                "secret",
                NAME,
                NAME,
                busbar_contract::abi::secret::ABI_VERSION,
            ),
            door,
        )])
        .expect("the witness links");
    let row = linked.resolve(NAME).expect("the linked row");
    assert!(row.linked() && row.first_party());
    let row = LinkedRow::of(door).expect("the witness door renders");
    if let Err(e) = prepare_linked::<Secret>(&row) {
        panic!("a compiled-in plugin is built in the same build and admitted: {e}");
    }
}
