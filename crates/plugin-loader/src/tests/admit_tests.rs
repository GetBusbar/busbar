// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admission (IF §11.1): steps 3 to 7 on a compiled-in header, steps 1 to 8 on dropped-in bytes, the step-6
//! crypto gate over the facade's answers alone, and the refusal each step gives.

use super::*;
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Endpoints, Open};
use busbar_plugin_abi::stamp::{emit, Spec};
use busbar_plugin_abi::types::Str;

busbar_plugin_abi::kind! {
    /// A secret-shaped kind for the admit tests.
    pub trait Source: kind = 2, abi = 3 {
        views {}
        pods {}
        tags { VALUE = 0x0100; }
        consts { REQUIRED: u64 = 0b1; }
        async fn resolve(&self, h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail> {
            let _ = (h, reference);
            Err(busbar_plugin_abi::fail::Fail::unsupported())
        }
    }
}

/// The plugin type behind every compiled-in fixture here.
pub struct Fx;
impl Source for Fx {}
impl Open for Fx {
    async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
        Ok(Fx)
    }
    fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        Ok(())
    }
}

// `PLUGIN`: what `plugin!` writes for a kind declared here, stamped with this test kind's own FP, which is not the
// engine's `secret::FP`: a mismatched SDK build.
busbar_plugin_abi::plugin!(@kind [secret] Fx);

const NAME: &str = "busbar-admit-fixture";

const fn spec(out_of_process: bool, crypto: &'static str) -> Spec<'static> {
    Spec {
        kind: KindCode::Secret,
        kind_abi: busbar_plugin_abi::versions::SECRET,
        kind_minor: busbar_plugin_abi::versions::SECRET_MINOR,
        layout: busbar_plugin_abi::secret::FP,
        out_of_process,
        engine_min: None,
        engine_max: None,
        name: NAME,
        version: "1.6.0",
        build_id: None,
        crypto,
    }
}

static STAMP: busbar_ffi::StampBytes = emit(&spec(false, "host"));
static STAMP_OOP: busbar_ffi::StampBytes = emit(&spec(true, "host"));
static TABLE: busbar_ffi::Table<secret::Shim<Fx>, { secret::ENTRIES }> = secret::table::<Fx>();
/// A compiled-in secret image stamped with the engine's own secret FP and CORE_FP.
static REGISTERED: busbar_ffi::LinkedPlugin = busbar_ffi::plugin::<
    secret::Shim<Fx>,
    secret::Marker,
    { secret::ENTRIES },
>(&TABLE, &STAMP, Str::EMPTY);
/// The same image stamped `out_of_process`.
static OUT_OF_PROCESS: busbar_ffi::LinkedPlugin = busbar_ffi::plugin::<
    secret::Shim<Fx>,
    secret::Marker,
    { secret::ENTRIES },
>(&TABLE, &STAMP_OOP, Str::EMPTY);

const STUB: CryptoFacts = CryptoFacts {
    external_plugins: false,
    backend: "stub",
    plugin_host: false,
};

#[test]
fn a_compiled_in_image_is_admitted_on_its_static() {
    let admitted = admit_linked(&REGISTERED).expect("the engine's own fingerprints admit");
    assert_eq!(admitted.identity(), NAME);
    assert_eq!(admitted.kind(), KindCode::Secret);
    assert!(matches!(&*admitted.image, Image::Linked));
    assert_eq!(admitted.sha256(), None);
    assert_eq!(admitted.stamp.layout, busbar_plugin_abi::secret::FP);
    assert_eq!(admitted.stamp.core_layout, CORE_CONTRACT.wire);
    let agreed = admitted.agreed();
    assert_eq!(agreed.kind, KindCode::Secret);
    assert_eq!(
        (agreed.core_second, agreed.kind_second),
        (CORE_CONTRACT.speaks.second, secret_contract().speaks.second)
    );
    assert_eq!(admitted.plugin().kind(), Some(KindCode::Secret));
    // Step 6 never looks past "host" for a Rust plugin: a backend that loads no external plugin admits it.
    assert!(admit_linked_with(&REGISTERED, &STUB).is_ok());
}

#[test]
fn a_mismatched_sdk_build_is_refused_layout() {
    let refusal =
        admit_linked(&PLUGIN).expect_err("this test kind's FP is not the engine's secret FP");
    assert_eq!(refusal.code, RefusalCode::Layout);
    assert_eq!(refusal.field, "layout");
    assert!(
        refusal.want.ends_with("unreleased or altered contract"),
        "{}",
        refusal.want
    );
    assert_eq!(refusal.plugin.as_deref(), Some(env!("CARGO_PKG_NAME")));
    assert!(refusal.to_string().contains("a mismatched SDK build"));
}

#[test]
fn an_out_of_process_image_never_loads_in_process() {
    let refusal = admit_linked(&OUT_OF_PROCESS).expect_err("no plugin host in this build");
    assert_eq!(refusal.code, RefusalCode::OutOfProcessUnavailable);
    assert_eq!(refusal.plugin.as_deref(), Some(NAME));
}

#[test]
fn the_crypto_gate_is_the_facade_and_nothing_else() {
    assert_eq!(
        CryptoFacts::FACADE,
        CryptoFacts {
            external_plugins: busbar_contract::crypto::EXTERNAL_PLUGINS,
            backend: busbar_contract::crypto::BACKEND,
            plugin_host: false,
        }
    );
    let host = CryptoFacts {
        plugin_host: true,
        ..STUB
    };
    let external = CryptoFacts {
        external_plugins: true,
        ..STUB
    };
    // "host": always, in process.
    assert!(crypto_gate("host", false, &STUB).is_ok());
    // "external": exactly the facade's EXTERNAL_PLUGINS.
    assert!(crypto_gate("external", false, &external).is_ok());
    let r = crypto_gate("external", false, &STUB).expect_err("EXTERNAL_PLUGINS = false");
    assert_eq!(
        (r.code, r.field, r.have.as_str(), r.want.as_str()),
        (RefusalCode::Crypto, "crypto", "external", "stub")
    );
    // A backend name: only out of process, with a plugin host, naming exactly BACKEND.
    assert!(crypto_gate("stub", true, &host).is_ok());
    for (crypto, oop, facts) in [
        ("stub", false, &host),
        ("stub", true, &STUB),
        ("other", true, &host),
    ] {
        let r = crypto_gate(crypto, oop, facts).expect_err("refused");
        assert_eq!((r.code, r.have.as_str()), (RefusalCode::Crypto, crypto));
    }
    // An out-of-process image with host crypto still needs the plugin host.
    assert_eq!(
        crypto_gate("host", true, &STUB).map_err(|r| r.code),
        Err(RefusalCode::OutOfProcessUnavailable)
    );
    assert!(crypto_gate("host", true, &host).is_ok());
}

#[cfg(unix)]
mod dropped {
    use super::*;
    use crate::test_host::{admit_bytes, test_sign, TEST_PUBLISHER};

    fn manifest(name: &str, version: &str, bytes: &[u8]) -> SignedManifest {
        test_sign(
            crate::sign::Manifest {
                name: name.to_string(),
                alias: name.to_string(),
                kind: "secret".to_string(),
                version: version.to_string(),
                publisher: TEST_PUBLISHER.to_string(),
                abi_version: busbar_plugin_abi::versions::SECRET,
                ..crate::sign::Manifest::default()
            },
            bytes,
        )
    }

    /// The registered stamp inside bytes that are not a loadable image.
    fn stamped() -> Vec<u8> {
        let mut bytes = b"\x7fELF not really".to_vec();
        bytes.extend_from_slice(&STAMP.0);
        bytes
    }

    #[test]
    fn bytes_with_no_stamp_are_refused_stamp_missing_after_integrity_and_signature() {
        let bytes = b"a 1.5.x library".to_vec();
        let refusal = admit_bytes(
            &bytes,
            &manifest("busbar-old", "1.5.5", &bytes),
            "busbar-old",
        )
        .expect_err("no stamp");
        assert_eq!(refusal.code, RefusalCode::StampMissing);
        assert_eq!(
            refusal.plugin.as_deref(),
            Some("busbar-old"),
            "the manifest name passed valid_name"
        );
    }

    #[test]
    fn other_bytes_than_the_manifest_names_are_refused_integrity() {
        let bytes = stamped();
        let mut other = bytes.clone();
        other[0] ^= 1;
        let refusal =
            admit_bytes(&other, &manifest(NAME, "1.6.0", &bytes), NAME).expect_err("tampered");
        assert_eq!(
            (refusal.code, refusal.field),
            (RefusalCode::Integrity, "sha256")
        );
    }

    #[test]
    fn a_manifest_no_trusted_key_signed_is_refused_signature() {
        let bytes = stamped();
        let mut m = manifest(NAME, "1.6.0", &bytes);
        m = crate::sign::sign(&crate::sign::SigningKey::from_bytes(&[0x11; 32]), m, &bytes);
        let refusal = admit_bytes(&bytes, &m, NAME).expect_err("not the test key");
        assert_eq!(
            (refusal.code, refusal.field),
            (RefusalCode::Signature, "signature")
        );
    }

    #[test]
    fn a_manifest_that_states_another_version_is_refused_manifest_mismatch() {
        let bytes = stamped();
        let refusal = admit_bytes(&bytes, &manifest(NAME, "9.9.9", &bytes), NAME)
            .expect_err("version differs");
        assert_eq!(refusal.code, RefusalCode::ManifestMismatch);
        assert_eq!(refusal.field, "manifest.version");
        assert_eq!(
            (refusal.have.as_str(), refusal.want.as_str()),
            ("9.9.9", "1.6.0")
        );
    }

    #[test]
    fn a_verified_stamp_in_bytes_the_dynamic_loader_cannot_load_is_refused_at_dlopen() {
        let bytes = stamped();
        let refusal =
            admit_bytes(&bytes, &manifest(NAME, "1.6.0", &bytes), NAME).expect_err("not loadable");
        assert_eq!(
            (refusal.code, refusal.field),
            (RefusalCode::Target, "dlopen")
        );
        assert_eq!(refusal.plugin.as_deref(), Some(NAME));
        assert!(
            !refusal.have.contains('\n'),
            "the loader's reason is one line"
        );
    }

    #[test]
    fn a_descriptor_that_is_not_a_regular_file_is_refused_integrity() {
        let dir = std::fs::File::open(std::env::temp_dir()).expect("open the temp dir");
        let bytes = stamped();
        let refusal = admit(
            std::os::fd::OwnedFd::from(dir),
            &manifest(NAME, "1.6.0", &bytes),
            &crate::test_host::test_trust(NAME),
        )
        .expect_err("a directory");
        assert_eq!(
            (refusal.code, refusal.field),
            (RefusalCode::Integrity, "file")
        );
        assert_eq!(refusal.have, "not a regular file");
    }
}

/// DES-NATIVE-FIRST-PARTY r3 §2.1-§2.2 and §5 L1, L2: an admitted image carries this admission's signer and its
/// proof, from `evaluate_with_verification` over these bytes, on both the fresh load and the resident hit.
#[cfg(target_os = "linux")]
mod signer {
    use super::*;
    use crate::sign::{AllowReason, Manifest, TrustPolicy, Verdict, FIRST_PARTY_PUBLISHER};

    /// The native secret fixture, its manifest completed from its own stamp and header.
    fn fixture(publisher: &str) -> (Vec<u8>, Manifest) {
        let bytes = crate::test_host::cdylib_bytes("native_pack_fixture");
        let manifest = crate::pack_native::complete(
            &bytes,
            Manifest {
                name: "native-pack-fixture".into(),
                alias: "native".into(),
                kind: "secret".into(),
                publisher: publisher.into(),
                ..Manifest::default()
            },
            None,
        )
        .expect("the native fixture packs");
        (bytes, manifest)
    }

    /// The fixture sealed as busbar ships it, and the policy whose release roots verify that seal.
    fn first_party() -> (Vec<u8>, Manifest, TrustPolicy) {
        let (bytes, manifest) = fixture(FIRST_PARTY_PUBLISHER);
        let (sealed, roots) = crate::both_ways::sealed_first_party(manifest, &bytes);
        let policy = TrustPolicy {
            first_party_keys: roots,
            release_clock: Some(crate::release_trust::tests::NOW),
            binary_version: sealed.version.clone(),
            ..TrustPolicy::default()
        };
        (bytes, sealed, policy)
    }

    /// L1: release-sealed, an allowlisted third party, `allow_untrusted`, and compiled in.
    #[test]
    fn an_admission_carries_its_signer_and_the_proof_behind_it() {
        let (bytes, sealed, policy) = first_party();
        let admitted = admit_bytes(&bytes, &sealed, &policy).expect("the sealed fixture admits");
        assert!(admitted.first_party() && admitted.trusted());
        match admitted.signer() {
            Signer::Dropped {
                verdict:
                    Verdict::Trusted {
                        first_party: true, ..
                    },
                proof,
            } => assert!(
                !proof.signers.is_empty(),
                "the proof names the signer: {proof:?}"
            ),
            other => panic!("a release-sealed image is first party: {other:?}"),
        }

        let (bytes, manifest) = fixture(crate::test_host::TEST_PUBLISHER);
        let signed = crate::test_host::test_sign(manifest, &bytes);
        let admitted = admit_bytes(
            &bytes,
            &signed,
            &crate::test_host::test_trust("native-pack-fixture"),
        )
        .expect("the allowlisted third party admits");
        assert!(admitted.trusted() && !admitted.first_party());
        match admitted.signer() {
            Signer::Dropped {
                verdict:
                    Verdict::Trusted {
                        first_party: false, ..
                    },
                proof,
            } => assert!(
                !proof.signers.is_empty(),
                "the publisher key is named: {proof:?}"
            ),
            other => panic!("an allowlisted publisher is trusted, not first party: {other:?}"),
        }

        let (bytes, unsigned) = fixture("someone-else");
        let admitted = admit_bytes(
            &bytes,
            &unsigned,
            &TrustPolicy {
                allow_untrusted: true,
                ..TrustPolicy::default()
            },
        )
        .expect("allow_untrusted admits the unsigned fixture");
        assert!(!admitted.trusted() && !admitted.first_party());
        assert!(
            matches!(
                admitted.signer(),
                Signer::Dropped {
                    verdict: Verdict::Allowed {
                        allow: AllowReason::Untrusted,
                        ..
                    },
                    ..
                }
            ),
            "{:?}",
            admitted.signer()
        );

        let linked = admit_linked(&REGISTERED).expect("the engine's own fingerprints admit");
        assert_eq!(linked.signer(), &Signer::Linked);
        assert!(linked.first_party() && linked.trusted());
    }

    /// L2: the same bytes admitted twice. The seal is never corrupted: the second policy drops the publisher
    /// (the design's fallback form, since a known publisher with an invalid proof is a hard refusal) and opts in
    /// to `allow_untrusted`. The second admission is a resident hit and carries its own signer, never the first's.
    #[test]
    fn the_resident_cache_never_replays_a_signer() {
        let (bytes, manifest) = fixture(crate::test_host::TEST_PUBLISHER);
        let signed = crate::test_host::test_sign(manifest, &bytes);
        let first = admit_bytes(
            &bytes,
            &signed,
            &crate::test_host::test_trust("native-pack-fixture"),
        )
        .expect("the allowlisted publisher admits");
        assert!(first.trusted());
        let second = admit_bytes(
            &bytes,
            &signed,
            &TrustPolicy {
                allow_untrusted: true,
                ..TrustPolicy::default()
            },
        )
        .expect("allow_untrusted admits the same bytes once the publisher is dropped");
        assert!(
            Arc::ptr_eq(&first.image, &second.image),
            "the second admission is a resident hit"
        );
        assert!(
            !second.trusted() && !second.first_party(),
            "{:?}",
            second.signer()
        );
    }
}

// ---- agreement at load: the outcomes of DESIGN-interface-revision C.4, on a real stamp ----

/// What this engine speaks of the secret kind.
fn secret_contract() -> busbar_plugin_abi::versions::Contract {
    contract_of(KindCode::Secret, busbar_plugin_abi::secret::FP)
}

/// The stamp of the compiled-in fixture as admitted: the engine's own versions and fingerprints.
fn own_stamp() -> Stamp {
    admit_linked(&REGISTERED)
        .expect("the engine's own fingerprints admit")
        .stamp
}

fn refused(change: impl FnOnce(&mut Stamp)) -> Refusal {
    let mut stamp = own_stamp();
    change(&mut stamp);
    agreed(&stamp, &CryptoFacts::FACADE).expect_err("the changed stamp does not agree")
}

#[test]
fn the_engines_own_versions_agree_and_are_remembered() {
    let agreed = agreed(&own_stamp(), &CryptoFacts::FACADE).expect("agrees");
    assert_eq!(agreed.kind, KindCode::Secret);
    assert!(agreed.knows(secret_contract().speaks.second));
    assert!(!agreed.knows(secret_contract().speaks.second + 1));
    assert!(!agreed.knows_core(CORE_CONTRACT.speaks.second + 1));
}

#[test]
fn a_kind_second_number_above_the_engines_is_refused_naming_both() {
    let speaks = secret_contract().speaks;
    let refusal = refused(|s| s.kind_minor += 1);
    assert_eq!(refusal.code, RefusalCode::KindAbi);
    assert_eq!(refusal.field, "kind_abi");
    assert_eq!(
        refusal.have,
        format!("built for secret {}.{}", speaks.first, speaks.second + 1)
    );
    assert_eq!(
        refusal.want,
        format!(
            "this engine speaks secret {speaks}: upgrade the engine or use the plugin's build for secret {speaks}"
        )
    );
    assert_eq!(refusal.plugin.as_deref(), Some(NAME));
}

#[test]
fn a_core_second_number_above_the_engines_is_refused_naming_both() {
    let speaks = CORE_CONTRACT.speaks;
    let refusal = refused(|s| s.core_minor += 1);
    assert_eq!(refusal.code, RefusalCode::Mechanism);
    assert_eq!(refusal.field, "core_abi");
    assert_eq!(
        refusal.have,
        format!("built for core {}.{}", speaks.first, speaks.second + 1)
    );
    assert!(refusal.want.starts_with(&format!(
        "this engine speaks core {speaks}: upgrade the engine"
    )));
}

#[test]
fn another_kind_first_number_is_refused_naming_both() {
    let speaks = secret_contract().speaks;
    for other in [speaks.first - 1, speaks.first + 1] {
        let refusal = refused(|s| s.kind_abi = other);
        assert_eq!(refusal.code, RefusalCode::KindAbi);
        assert_eq!(
            refusal.have,
            format!("built for secret {other}.{}", speaks.second)
        );
        assert_eq!(
            refusal.want,
            format!(
                "this engine speaks secret {speaks}: use the plugin's build for secret {}",
                speaks.first
            )
        );
    }
}

#[test]
fn another_core_first_number_is_refused_before_the_kind_is_read() {
    let refusal = refused(|s| {
        s.core_abi += 1;
        // A kind disagreement too: the core's is the one reported.
        s.kind_abi += 1;
    });
    assert_eq!(refusal.code, RefusalCode::Mechanism);
    assert!(refusal.have.starts_with("built for core "));
}

#[test]
fn an_altered_fingerprint_is_refused_for_the_kind_and_for_the_core() {
    let refusal = refused(|s| s.layout ^= 1);
    assert_eq!(
        (refusal.code, refusal.field),
        (RefusalCode::Layout, "layout")
    );
    assert!(refusal.have.starts_with("secret "));
    assert!(refusal.want.ends_with("unreleased or altered contract"));
    let refusal = refused(|s| s.core_layout ^= 1);
    assert_eq!(
        (refusal.code, refusal.field),
        (RefusalCode::Layout, "core_layout")
    );
    assert!(refusal.have.starts_with("core "));
}

/// The dev form of a stamp: this build's own stamp names the unreleased version at the label (no
/// contract has a released line in dev). A dev engine loads it; an engine built for release does not.
#[test]
fn an_engine_built_for_release_refuses_this_dev_stamp() {
    use busbar_plugin_abi::versions::{Build, Disagree};
    let stamp = own_stamp();
    let claims = claims(&stamp, KindCode::Secret);
    assert!(crate::agree::agree(Build::Dev, &claims, &CORE_CONTRACT, &secret_contract()).is_ok());
    let no = crate::agree::agree(Build::Release, &claims, &CORE_CONTRACT, &secret_contract())
        .expect_err("a release engine has no released line for an unreleased version");
    assert!(no.is_core, "the core is judged first");
    assert_eq!(
        no.why,
        Disagree::Unreleased {
            version: CORE_CONTRACT.speaks
        }
    );
    assert_eq!(no.refusal().code, RefusalCode::Mechanism);
    assert!(no.want_text().contains("loads released builds only"));
}

#[test]
fn a_stated_engine_range_that_excludes_this_engine_is_refused_and_the_default_is_any() {
    let own = own_stamp();
    assert_eq!(
        (own.engine_min, own.engine_max),
        (
            busbar_plugin_abi::versions::ENGINE_ANY_MIN,
            busbar_plugin_abi::versions::ENGINE_ANY_MAX
        ),
        "a plugin that states no range is stamped with every engine"
    );
    let refusal = refused(|s| {
        s.engine_min = busbar_plugin_abi::versions::ENGINE_ANY_MAX;
    });
    assert_eq!(refusal.code, RefusalCode::EngineRange);
}
