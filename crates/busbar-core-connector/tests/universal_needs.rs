// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIVERSAL-NEEDS WITNESS (THE DESIGN: connections — "any plugin of any kind reaches the
//! network only through a need"). A SECRET-kind fixture (`examples/need_dialler.rs`) that declares
//! one outbound need is loaded DROPPED IN through the real admission, scan and open, and asked for its
//! secret: it dials through the connection table, writes `ping` and returns what came back.
//!
//! TODAY'S TRUTH, asserted explicitly: the secret kind's open hands an instance no connection table
//! yet, so the instance holds none and the dial answers [`TODAY`] — the named refusal for an
//! instance handed no table, decided per instance. The fixture
//! has no other way to the network: its closure is held to that by the `dep-wall` gate.
//!
//! FLIPS TO GREEN (dial succeeds, bytes round-trip over a loopback echo) once the open/refresh
//! host tables hand the instance its table: the dial reaches the connector, `TODAY` becomes
//! success, the test starts a loopback echo as the target, and the assertion below becomes "the
//! secret is the echoed `ping`".

use std::sync::OnceLock;

use busbar_contract::conn::ConnError;
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};

/// What the dial answers today. The one edit that flips this witness once instances are handed their table.
const TODAY: ConnError = ConnError::Unarmed;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where the fixture dials: a loopback address nothing answers on, until the witness starts an echo.
const TARGET: &str = "127.0.0.1:1";

fn release() -> SigningKey {
    SigningKey::from_bytes(&[23u8; 32])
}

/// The fixture's cdylib, as `cargo test` built it (under `examples/`). A missing artifact is a
/// failure, never a skip: this test IS the witness.
fn fixture() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("need_dialler");
    let found = [
        profile.join("examples").join(&file),
        profile.join("examples").join("deps").join(&file),
    ]
    .into_iter()
    .find(|p| p.exists())
    .unwrap_or_else(|| panic!("the need_dialler fixture ({file}) is not built"));
    std::fs::read(found).expect("read the fixture")
}

/// The fixture, loaded dropped in: signed first-party into a fresh `plugins/` directory, scanned
/// under a policy holding the release key, and opened as a secret module by name.
fn dropped_in() -> &'static dyn busbar_contract::secret::SecretModule {
    static MODULE: OnceLock<Box<dyn busbar_contract::secret::SecretModule>> = OnceLock::new();
    MODULE
        .get_or_init(|| {
            let lib = fixture();
            let dir = std::env::temp_dir().join(format!("universal-needs-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create the plugins dir");
            let manifest = Manifest {
                name: "need-dialler".into(),
                alias: "need-dialler".into(),
                kind: "secret".into(),
                version: VERSION.into(),
                publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
                abi_version: busbar_contract::abi::cold::SECRET_ABI_VERSION,
                sha256: String::new(),
                signature: String::new(),
                description: String::new(),
                homepage: String::new(),
                license: String::new(),
                needs: Default::default(),
                settings_schema: None,
                schema_derived: false,
                host: None,
                declares: Default::default(),
            };
            let signed = sign(&release(), manifest, &lib);
            let tarball = busbar_plugin_loader::tarball::package(&signed, "libneed.so", &lib)
                .expect("package");
            std::fs::write(dir.join("need-dialler.tar.gz"), tarball).expect("write the tarball");
            let policy = TrustPolicy {
                first_party_key: Some(release().verifying_key()),
                binary_version: VERSION.into(),
                first_party_floors: Default::default(),
                first_party_high_water: Default::default(),
                publishers: Default::default(),
                allow_unsigned: false,
                allow_third_party: false,
                min_versions: Default::default(),
            };
            let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy)
                .unwrap_or_else(|e| panic!("the signed fixture scans: {e:?}"));
            let module = registry
                .open_secret("need-dialler", "{}")
                .expect("the dropped-in door opens the fixture");
            let _ = std::fs::remove_dir_all(&dir);
            module
        })
        .as_ref()
}

/// THE WITNESS: a plugin of a kind that is not a transport reaches the network only through the
/// connection table — and today, handed none, its dial is refused by name and reaches nothing.
#[test]
fn a_secret_plugin_reaches_the_network_only_through_a_need() {
    let mut settings = serde_json::Map::new();
    settings.insert("target".into(), serde_json::Value::String(TARGET.into()));
    let err = match dropped_in().resolve(&settings) {
        Ok(bytes) => panic!("the dial succeeded ({bytes:?}) — flip TODAY"),
        Err(e) => e,
    };
    assert_eq!(err.message, TODAY.to_string(), "the host's named refusal");
}
