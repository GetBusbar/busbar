// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO CONSTRUCTOR RUNS FOR A REFUSED ARCHIVE (LEDGER S-R1 store, S-R2 plane; restored from the deleted root
//! tests `bootstrap_archive_pins_refuse_before_native_constructors` and
//! `early_plane_archive_pins_refuse_before_native_constructors`).
//!
//! The fixture is the deleted tests' inline C image: one `__attribute__((constructor))` that writes a marker
//! file, now carrying a real native stamp (format 3, the kind's current ABI) so the loader admits it as far as
//! a native image goes. It exports no `busbar_plugin` door, so even the matching archive is refused, but only
//! after `dlopen` ran its constructor: that is the positive control proving the marker is reachable.
//!
//! Each refused archive is refused by exactly one defect, through the loader's own pipeline in boot order:
//! the directory scan (`scan_and_validate`: trust and the `plugins.min_versions` floor), then `admit` (the
//! same trust and floor evaluated again over the bytes, the stamp, the manifest), then the native load guard
//! the engine installs (the exact archive SHA-256 pin of the retained archive), and only then `dlopen`.
//! An archive the scan skips is still handed to `admit` directly: the refusal must not depend on the caller
//! honouring the scan.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Once};

use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::refusal::RefusalCode;
use busbar_plugin_loader::sign::{
    sha256_hex, sign, Manifest, PublisherKey, PublisherTrust, RejectKind, SigningKey, TrustPolicy,
};

const PUBLISHER: &str = "constructor-publisher";

/// What the engine's guard holds for one admitted image: the digest of the archive the scan retained it
/// from, and the operator's `plugins.fetch` pin for that archive.
struct Proof {
    archive: String,
    pin: Option<String>,
}

/// By the image's SHA-256 (the guard sees only the bytes about to be opened).
static PROOFS: Mutex<BTreeMap<String, Proof>> = Mutex::new(BTreeMap::new());
static GUARD: Once = Once::new();

/// The engine's rule (busbar-kernel `appbuild::validate_bootstrap_archive`, called from the root's
/// `authorize_native_image`): an image opens only as the bytes of a retained admitted archive whose exact
/// SHA-256 the operator pinned.
fn pin_guard(bytes: &[u8], display: &str) -> Result<(), String> {
    let proofs = PROOFS.lock().unwrap_or_else(|p| p.into_inner());
    let proof = proofs.get(&sha256_hex(bytes)).ok_or_else(|| {
        format!("native plugin '{display}' has no retained admitted archive proof")
    })?;
    if proof.pin.as_deref() != Some(proof.archive.as_str()) {
        return Err(format!(
            "native plugin '{display}' requires its exact archive SHA-256 in plugins.fetch before it \
             can load; the pin is missing or does not match the retained admitted archive"
        ));
    }
    Ok(())
}

fn install_guard() {
    GUARD.call_once(|| {
        busbar_plugin_loader::install_native_load_guard(pin_guard)
            .expect("this test binary installs the one native load guard");
    });
}

fn scratch(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-ctor-gate-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("clear a stale scratch directory of a dead process");
    }
    std::fs::create_dir_all(&dir).expect("create the scratch directory");
    dir
}

/// The deleted tests' constructor fixture, emitting `stamp` and writing `marker` when it is loaded.
fn constructor_image(dir: &Path, tag: &str, stamp: &[u8], marker: &Path) -> Vec<u8> {
    let marker = marker.to_str().expect("the marker path is UTF-8");
    assert!(
        !marker.contains(['"', '\\', '\n']),
        "the marker path is a plain C string literal: {marker}"
    );
    let bytes: Vec<String> = stamp.iter().map(|b| format!("0x{b:02x}")).collect();
    let source = dir.join(format!("{tag}.c"));
    let image = dir.join(format!("{tag}.so"));
    std::fs::write(
        &source,
        format!(
            r#"#include <stdio.h>
const unsigned char busbar_constructor_stamp[{len}] __attribute__((used, aligned(8))) = {{ {bytes} }};
__attribute__((constructor)) static void mark_loaded(void) {{
    FILE *out = fopen("{marker}", "wb");
    if (out) {{ fputs("loaded", out); fclose(out); }}
}}
"#,
            len = stamp.len(),
            bytes = bytes.join(", "),
        ),
    )
    .expect("write the fixture source");
    let mut compiler = std::process::Command::new("cc");
    #[cfg(target_os = "macos")]
    compiler.arg("-dynamiclib");
    #[cfg(not(target_os = "macos"))]
    compiler.args(["-shared", "-fPIC"]);
    let compiled = compiler
        .arg(&source)
        .arg("-o")
        .arg(&image)
        .output()
        .expect("run the C compiler");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    std::fs::read(&image).expect("read the compiled fixture")
}

struct Fixture {
    kind: KindCode,
    word: &'static str,
    name: &'static str,
    kind_abi: u32,
    kind_minor: u32,
    layout: u64,
}

const STORE: Fixture = Fixture {
    kind: KindCode::Store,
    word: "store",
    name: "constructor-store-bootstrap",
    kind_abi: busbar_plugin_abi::versions::STORE,
    kind_minor: busbar_plugin_abi::versions::STORE_MINOR,
    layout: busbar_plugin_abi::store::FP,
};

const PLANE: Fixture = Fixture {
    kind: KindCode::Plane,
    word: "plane",
    name: "constructor-plane-bootstrap",
    kind_abi: busbar_plugin_abi::versions::PLANE,
    kind_minor: busbar_plugin_abi::versions::PLANE_MINOR,
    layout: busbar_plugin_abi::plane::FP,
};

/// One signed archive of the fixture at `version`.
struct Archive {
    lib: Vec<u8>,
    bytes: Vec<u8>,
}

impl Fixture {
    fn stamp(&self, version: &str) -> [u8; 272] {
        busbar_plugin_abi::stamp::emit(&busbar_plugin_abi::stamp::Spec {
            kind: self.kind,
            kind_abi: self.kind_abi,
            kind_minor: self.kind_minor,
            layout: self.layout,
            out_of_process: false,
            engine_min: None,
            engine_max: None,
            name: self.name,
            version,
            build_id: None,
            crypto: "host",
        })
        .0
    }

    fn archive(&self, key: &SigningKey, version: &str, lib: &[u8]) -> Archive {
        let alias = format!("{}-alias", self.word);
        let manifest = sign(
            key,
            Manifest {
                name: self.name.into(),
                alias: alias.clone(),
                former_names: vec![alias],
                kind: self.word.into(),
                version: version.into(),
                publisher: PUBLISHER.into(),
                abi_version: busbar_plugin_loader::supported_abi(self.word)
                    .expect("the engine loads this kind"),
                ..Default::default()
            },
            lib,
        );
        assert_eq!(manifest.abi_version, self.kind_abi, "one ABI source");
        Archive {
            lib: lib.to_vec(),
            bytes: busbar_plugin_loader::tarball::package(&manifest, "lib.so", lib)
                .expect("package the fixture"),
        }
    }

    fn policy(&self, trusted: &SigningKey, floor: &str) -> TrustPolicy {
        let mut policy = TrustPolicy::default();
        policy.publishers.insert(
            PUBLISHER.into(),
            PublisherTrust {
                plugins: [self.name.to_string()].into_iter().collect(),
                keys: vec![PublisherKey {
                    key: trusted.verifying_key(),
                    revoked: false,
                }],
            },
        );
        policy.min_versions.insert(self.name.into(), floor.into());
        policy
    }
}

/// What one boot attempt over `archive` did: whether the scan admitted it (else why it skipped it), and what
/// `admit` answered (it never succeeds: the fixture exports no door).
struct Attempt {
    scanned: Result<(), RejectKind>,
    refusal: busbar_plugin_loader::refusal::Refusal,
}

fn attempt(
    fixture: &Fixture,
    archive: &Archive,
    policy: &TrustPolicy,
    pin: Option<&str>,
) -> Attempt {
    use std::io::Write as _;
    let dir = scratch(&format!("{}-plugins", fixture.word));
    std::fs::write(dir.join(format!("{}.tar.gz", fixture.word)), &archive.bytes)
        .expect("drop the archive in");
    let registry = busbar_plugin_loader::scan_and_validate(&dir, policy)
        .unwrap_or_else(|errors| panic!("the fixture archive is structurally valid: {errors:?}"));
    let scanned = match registry.resolve(fixture.name) {
        Some(row) => {
            assert_eq!(
                row.archive_sha256.as_deref(),
                Some(sha256_hex(&archive.bytes).as_str()),
                "the scan retains the digest of the archive it read"
            );
            assert_eq!(*row.lib_bytes, archive.lib);
            Ok(())
        }
        None => Err(registry
            .unresolved_reason(fixture.name)
            .expect("an archive the scan does not admit is recorded as skipped")
            .kind),
    };
    PROOFS.lock().unwrap_or_else(|p| p.into_inner()).insert(
        sha256_hex(&archive.lib),
        Proof {
            archive: sha256_hex(&archive.bytes),
            pin: pin.map(str::to_owned),
        },
    );
    let unpacked =
        busbar_plugin_loader::tarball::unpack(&archive.bytes).expect("the archive unpacks");
    let staged = dir.join("image");
    let mut file = std::fs::File::create_new(&staged).expect("create the scratch image");
    file.write_all(&unpacked.lib_bytes)
        .expect("write the scratch image");
    drop(file);
    let fd = std::fs::File::open(&staged).expect("open the scratch image");
    std::fs::remove_dir_all(&dir).expect("remove the plugins directory");
    let refusal = busbar_plugin_loader::admit::admit(fd.into(), &unpacked.manifest, policy)
        .expect_err("the fixture exports no door, so admission never succeeds");
    Attempt { scanned, refusal }
}

/// S-R1 / S-R2: swapped, unpinned, below-floor and untrusted archives never reach `dlopen`; the matching one does.
fn refused_before_any_constructor(fixture: &Fixture) {
    install_guard();
    let dir = scratch(fixture.word);
    let marker = dir.join("constructor.marker");
    let older_lib = constructor_image(&dir, "older", &fixture.stamp("1.0.0"), &marker);
    let newer_lib = constructor_image(&dir, "newer", &fixture.stamp("1.1.0"), &marker);
    let key = SigningKey::from_bytes(&[0x35; 32]);
    let stranger = SigningKey::from_bytes(&[0x36; 32]);
    let older = fixture.archive(&key, "1.0.0", &older_lib);
    let newer = fixture.archive(&key, "1.1.0", &newer_lib);
    let untrusted = fixture.archive(&stranger, "1.0.0", &older_lib);
    let older_hash = sha256_hex(&older.bytes);
    let newer_hash = sha256_hex(&newer.bytes);
    let at_floor = fixture.policy(&key, "1.0.0");
    let above = fixture.policy(&key, "1.1.0");

    for (tag, archive, policy, pin) in [
        ("swapped", &older, &at_floor, Some(newer_hash.as_str())),
        ("unpinned", &older, &at_floor, None),
        ("below-floor", &older, &above, Some(older_hash.as_str())),
        (
            "untrusted",
            &untrusted,
            &at_floor,
            Some(older_hash.as_str()),
        ),
    ] {
        let attempt = attempt(fixture, archive, policy, pin);
        let refusal = &attempt.refusal;
        match tag {
            "swapped" | "unpinned" => {
                assert!(attempt.scanned.is_ok(), "{tag}: trusted and at its floor");
                assert_eq!(
                    (refusal.code, refusal.field),
                    (RefusalCode::Integrity, "stage"),
                    "{tag}: {refusal}"
                );
                assert!(
                    refusal.have.contains("exact archive SHA-256"),
                    "{tag}: {refusal}"
                );
            }
            "below-floor" => {
                assert_eq!(attempt.scanned, Err(RejectKind::AntiDowngrade), "{tag}");
                assert_eq!(refusal.code, RefusalCode::Signature, "{tag}: {refusal}");
            }
            _ => {
                assert!(attempt.scanned.is_err(), "{tag}: an unknown key is skipped");
                assert_ne!(attempt.scanned, Err(RejectKind::AntiDowngrade), "{tag}");
                assert_eq!(refusal.code, RefusalCode::Signature, "{tag}: {refusal}");
            }
        }
        assert!(
            !marker.exists(),
            "{tag}: the {} image's constructor ran for a refused archive ({refusal})",
            fixture.word
        );
    }

    let matching = attempt(fixture, &older, &at_floor, Some(older_hash.as_str()));
    assert!(matching.scanned.is_ok());
    assert_eq!(
        (matching.refusal.code, matching.refusal.field),
        (RefusalCode::DoorStampMismatch, "busbar_plugin"),
        "the matching archive is opened and refused only for its missing door: {}",
        matching.refusal
    );
    assert!(
        marker.exists(),
        "the matching archive reaches dlopen, so its constructor runs: the marker is reachable"
    );
    std::fs::remove_dir_all(dir).expect("remove the scratch directory");
}

#[test]
fn a_swapped_unpinned_below_floor_or_untrusted_store_archive_is_refused_before_any_constructor() {
    refused_before_any_constructor(&STORE);
}

#[test]
fn a_swapped_unpinned_below_floor_or_untrusted_plane_archive_is_refused_before_any_constructor() {
    refused_before_any_constructor(&PLANE);
}
