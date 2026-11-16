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
    pub trait Source: kind = 2, abi = 2 {
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
        kind_abi: 2,
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
static VT: busbar_ffi::Built<secret::Shim<Fx>, secret::Vt> = secret::vt::<Fx>();
/// A compiled-in secret image stamped with the engine's own secret FP and CORE_FP.
static REGISTERED: busbar_ffi::LinkedPlugin =
    busbar_ffi::plugin::<secret::Shim<Fx>, secret::Marker>(&VT, &STAMP, Str::EMPTY);
/// The same image stamped `out_of_process`.
static OUT_OF_PROCESS: busbar_ffi::LinkedPlugin =
    busbar_ffi::plugin::<secret::Shim<Fx>, secret::Marker>(&VT, &STAMP_OOP, Str::EMPTY);

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
    assert_eq!(admitted.stamp.mechanism_layout, CORE_FP);
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
    assert_eq!(
        refusal.want,
        format!("{:#018x}", busbar_plugin_abi::secret::FP)
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
                abi_version: 2,
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
        let refusal =
            admit_bytes(&bytes, &manifest("busbar-old", "1.5.5", &bytes)).expect_err("no stamp");
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
        let refusal = admit_bytes(&other, &manifest(NAME, "1.6.0", &bytes)).expect_err("tampered");
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
        let refusal = admit_bytes(&bytes, &m).expect_err("not the test key");
        assert_eq!(
            (refusal.code, refusal.field),
            (RefusalCode::Signature, "signature")
        );
    }

    #[test]
    fn a_manifest_that_states_another_version_is_refused_manifest_mismatch() {
        let bytes = stamped();
        let refusal =
            admit_bytes(&bytes, &manifest(NAME, "9.9.9", &bytes)).expect_err("version differs");
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
            admit_bytes(&bytes, &manifest(NAME, "1.6.0", &bytes)).expect_err("not loadable");
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
            &crate::test_host::test_trust(),
        )
        .expect_err("a directory");
        assert_eq!(
            (refusal.code, refusal.field),
            (RefusalCode::Integrity, "file")
        );
        assert_eq!(refusal.have, "not a regular file");
    }
}
