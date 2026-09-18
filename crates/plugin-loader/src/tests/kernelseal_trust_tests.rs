// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KERNELSEAL / DROP-IN TRUST BOUNDARY — the ABI-review forgery finding, locked shut and PROVEN.
//!
//! The finding (owner ruling 2026-09-18): a forged / self-attested plugin "seal" must NEVER be
//! trusted on the channel-1 (hot) plugin boundary. The locked seam is Option A (matches 1.5.5):
//!
//!   1. A plugin's trust is decided ONCE at LOAD — before it is admitted to the hot path — by
//!      [`busbar_plugin_sign::evaluate`], which runs inside [`super::super::examine`] during
//!      [`scan_and_validate`], BEFORE any `dlopen`. Once admitted, the live handle is trusted for the
//!      session: the per-crossing hot dispatch re-runs NO signature check (proven below).
//!   2. To load, a seal must chain to a TRUST ANCHOR: EITHER busbar's own embedded release key
//!      (`TrustPolicy::first_party_key`, publisher `busbar`), OR an OPERATOR-CONFIGURED ALLOWLIST of
//!      trusted publisher identities/keys (`TrustPolicy::publishers`, surfaced to operators as
//!      `plugins.trust.publishers`). A seal that chains to NEITHER is refused at load. Critically, a
//!      self-attested seal cannot grant itself trust: it loads ONLY if the operator explicitly
//!      allowlisted that identity. The DEFAULT posture (no opt-ins) REJECTS unknown/self-signed.
//!   3. Mid-session swap defense: every reload/re-resolve path re-runs the full load-time
//!      verification against the same anchors (a reload is a fresh [`scan_and_validate`], which
//!      re-reads and re-`evaluate`s every tarball from disk); a changed, non-allowlisted lib is
//!      refused. The running code is the `dlopen`'d in-memory image the verified BYTES were staged
//!      to, so a disk swap cannot alter running code — this guards the reload window.
//!
//! These tests exercise the REAL drop-in scan path a boot / config-reload / admin-reload runs
//! (`scan_and_validate` -> `examine` -> `evaluate`), classifying each artifact as loadable (admitted
//! to the hot path) or skipped (refused, never `dlopen`ed). The `dropped_in_*` cases additionally
//! use the REAL `busbar_store_example_plugin` cdylib and drive a put/get crossing over the C ABI to
//! prove "does not reach the hot path" for a refused plugin and "trusted once" for an admitted one.

use busbar_plugin_sign::{sign, Manifest, RejectKind, SigningKey, TrustPolicy, Verdict};

use crate::{scan_and_validate, tarball};

// ---- fixtures (mirror crates/plugin-loader/src/tests/registry_tests.rs) -----------------------

/// A deterministic ed25519 key from a one-byte seed — the release key, the operator-allowlisted
/// publisher key, and the ATTACKER key are all distinct seeds so "wrong key" is unambiguous.
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A well-formed `kind: store` manifest at the current store payload schema. `sha256`/`signature`
/// are filled by [`sign`]; leaving them blank models an UNSIGNED artifact.
fn manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: "1.5.0".into(),
        publisher: publisher.into(),
        abi_version: busbar_plugin::cold::ABI_VERSION,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    }
}

/// The DEFAULT operator posture: busbar's embedded release key is the only anchor, the third-party
/// allowlist is EMPTY, and neither opt-in (`allow_unsigned` / `allow_third_party`) is set. This is
/// the fail-closed default a fresh deployment runs with.
fn default_policy(release: &SigningKey) -> TrustPolicy {
    TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.5.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    }
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-kernelseal-{}-{tag}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_tarball(dir: &std::path::Path, file: &str, m: &Manifest, lib: &[u8]) {
    let bytes = tarball::package(m, "lib.so", lib).unwrap();
    std::fs::write(dir.join(file), bytes).unwrap();
}

/// A structurally-valid but UNSIGNED artifact. `sha256` is the INTEGRITY digest (always required —
/// an artifact with a blank/wrong `sha256` is a STRUCTURAL reject, not a trust one), so we compute it
/// correctly by signing, then STRIP the signature so the TRUST phase judges the artifact unsigned.
/// This models a real drop-in file that is well-formed but was never signed by any anchor. `lib` MUST
/// be the same bytes later handed to [`write_tarball`] so the integrity digest matches.
fn unsigned(name: &str, alias: &str, publisher: &str, lib: &[u8]) -> Manifest {
    let mut m = sign(&key(200), manifest(name, alias, publisher), lib);
    m.signature = String::new();
    m
}

// ---- 1. DEFAULT-REJECT: a rogue drop-in does NOT load ----------------------------------------

/// OWNER ACCEPTANCE BAR: "you can't just drop in a rogue plugin and it loads." An UNSIGNED artifact
/// (valid manifest, correct ABI, but NO signature) placed in the drop-in directory is REFUSED under
/// the default policy: the scan succeeds, the plugin is NOT loadable (never `dlopen`ed, never reaches
/// the hot path), it is in the skip list with a clear fail-closed diagnostic, and REFERENCING it
/// fails loud. Dropping the file in is NOT consent.
#[test]
fn rogue_dropin_unsigned_plugin_is_refused_by_default() {
    let release = key(1);
    let dir = tmpdir("unsigned");
    // Well-formed (valid integrity digest) but NO signature -> UNSIGNED.
    let lib = b"a perfectly valid cdylib, just not signed";
    let m = unsigned("rogue-store", "rogue", "busbar", lib);
    write_tarball(&dir, "rogue.tar.gz", &m, lib);

    let reg = scan_and_validate(&dir, &default_policy(&release)).expect("scan itself succeeds");
    assert!(
        reg.loadable().is_empty(),
        "an unsigned drop-in must NOT be admitted to the hot path: {reg:?}"
    );
    assert_eq!(reg.skipped().len(), 1, "it is refused into the skip list");
    assert!(
        reg.resolve("rogue").is_none() && reg.resolve("rogue-store").is_none(),
        "a refused plugin never resolves, so nothing can open it"
    );
    let skip = &reg.skipped()[0];
    assert_eq!(
        skip.kind,
        RejectKind::Unsigned,
        "refused specifically as unsigned, not mislabeled"
    );
    assert!(
        skip.reason.contains("unsigned") && skip.reason.contains("allow_unsigned"),
        "fails closed with an actionable diagnostic: {}",
        skip.reason
    );
    // Referencing it (as a store module would) fails loud with the trust reason attached.
    let err = reg.open_store("rogue", "{}").map(|_| ()).unwrap_err();
    assert!(err.contains("was not loaded"), "open is refused: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A drop-in that IS signed, but by a self-generated publisher identity NOT in the operator
/// allowlist, is refused by default — a self-attested third-party seal cannot admit itself. The
/// diagnostic names the allowlist as the remedy.
#[test]
fn rogue_dropin_unknown_publisher_is_refused_by_default() {
    let release = key(1);
    let rogue = key(9);
    let dir = tmpdir("unknown-pub");
    let m = sign(
        &rogue,
        manifest("rogue-corp-store", "rogue", "rogue-corp"),
        b"lib",
    );
    write_tarball(&dir, "rogue.tar.gz", &m, b"lib");

    let reg = scan_and_validate(&dir, &default_policy(&release)).expect("scan succeeds");
    assert!(
        reg.loadable().is_empty(),
        "unknown publisher is not admitted"
    );
    assert_eq!(reg.skipped().len(), 1);
    let skip = &reg.skipped()[0];
    assert_eq!(skip.kind, RejectKind::UnknownPublisher);
    assert!(
        skip.reason.contains("allowlist") && skip.reason.contains("rogue-corp"),
        "names the offending identity and the allowlist remedy: {}",
        skip.reason
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE FORGERY CASE, stated directly: a seal that CLAIMS the first-party publisher `busbar` but is
/// signed with an ATTACKER key (not the embedded release key) cannot grant itself trust. Under the
/// default policy (whose only first-party anchor is the real release key) it is refused — a
/// self-attested first-party claim is worth nothing without the real anchor's signature.
#[test]
fn a_self_attested_first_party_seal_cannot_grant_itself_trust() {
    let release = key(1);
    let attacker = key(9);
    let dir = tmpdir("forged-firstparty");
    // Signed with the ATTACKER key, but publisher claims to be busbar's own first party.
    let m = sign(
        &attacker,
        manifest("busbar-store-forged", "forged", "busbar"),
        b"lib",
    );
    write_tarball(&dir, "forged.tar.gz", &m, b"lib");

    let reg = scan_and_validate(&dir, &default_policy(&release)).expect("scan succeeds");
    assert!(
        reg.loadable().is_empty(),
        "a forged first-party seal must NEVER be admitted"
    );
    assert_eq!(reg.skipped().len(), 1);
    assert!(
        matches!(
            reg.skipped()[0].kind,
            RejectKind::Tampered | RejectKind::Unsigned
        ),
        "the forged first-party signature fails verification: {:?}",
        reg.skipped()[0].kind
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- 2. THE TWO TRUST ANCHORS: official key and operator allowlist ----------------------------

/// ANCHOR (a): a plugin signed by busbar's own embedded release key loads with ZERO operator config
/// — trusted, first-party.
#[test]
fn an_official_first_party_signed_plugin_loads() {
    let release = key(1);
    let dir = tmpdir("official");
    let m = sign(
        &release,
        manifest("busbar-store-official", "official", "busbar"),
        b"lib",
    );
    write_tarball(&dir, "official.tar.gz", &m, b"lib");

    let reg = scan_and_validate(&dir, &default_policy(&release)).expect("scan succeeds");
    assert_eq!(reg.loadable().len(), 1, "official first-party plugin loads");
    assert!(reg.skipped().is_empty());
    assert!(matches!(
        reg.loadable()[0].verdict,
        Verdict::Trusted {
            first_party: true,
            ..
        }
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// ANCHOR (b) + OWNER ACCEPTANCE BAR part 2: the SAME rogue file that is refused by default becomes
/// loadable once — AND ONLY once — the operator adds ITS identity to the allowlist. Default-reject
/// stays the posture throughout; only the operator's explicit, identity-scoped allowlisting flips
/// this one artifact to loadable. Proven with one set of bytes across three policies: default policy
/// -> refused (skipped); allowlist a DIFFERENT identity -> STILL refused (adding some other publisher
/// is not consent); allowlist THIS identity -> loads (trusted third-party).
#[test]
fn the_same_rogue_file_loads_only_after_the_operator_allowlists_its_identity() {
    let release = key(1);
    let vendor = key(7);
    let someone_else = key(8);
    let dir = tmpdir("allowlist");
    // ONE artifact, signed by `vendor` under publisher name `acme`.
    let m = sign(
        &vendor,
        manifest("acme-store", "acme-kv", "acme"),
        b"identical bytes",
    );
    write_tarball(&dir, "acme.tar.gz", &m, b"identical bytes");

    // (i) default: refused.
    let reg = scan_and_validate(&dir, &default_policy(&release)).expect("scan");
    assert!(
        reg.loadable().is_empty() && reg.skipped().len() == 1,
        "refused by default: {reg:?}"
    );

    // (ii) allowlisting a DIFFERENT identity does NOT admit this one.
    let mut other = default_policy(&release);
    other
        .publishers
        .insert("not-acme".into(), someone_else.verifying_key());
    let reg = scan_and_validate(&dir, &other).expect("scan");
    assert!(
        reg.loadable().is_empty() && reg.skipped().len() == 1,
        "an unrelated allowlist entry is not consent for THIS identity: {reg:?}"
    );

    // (iii) allowlist THIS identity (name + key) -> the identical bytes now load.
    let mut allow = default_policy(&release);
    allow
        .publishers
        .insert("acme".into(), vendor.verifying_key());
    let reg = scan_and_validate(&dir, &allow).expect("scan");
    assert_eq!(reg.loadable().len(), 1, "allowlisted identity loads");
    assert!(reg.skipped().is_empty());
    assert!(
        matches!(
            reg.loadable()[0].verdict,
            Verdict::Trusted {
                first_party: false,
                ..
            }
        ),
        "trusted as an allowlisted third party"
    );
    assert!(reg.resolve("acme-kv").is_some(), "now resolvable by alias");

    // (iv) allowlisting the NAME but with the WRONG key still fails — the key is the anchor, not the
    // self-declared name.
    let mut wrong_key = default_policy(&release);
    wrong_key
        .publishers
        .insert("acme".into(), someone_else.verifying_key());
    let reg = scan_and_validate(&dir, &wrong_key).expect("scan");
    assert!(
        reg.loadable().is_empty(),
        "an allowlisted name signed by the wrong key does not verify"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- 3. MID-SESSION SWAP DEFENSE: reload re-verifies against the same anchors ------------------

/// Reload re-runs the FULL load-time verification. An allowlisted plugin loads; then the on-disk
/// tarball at the SAME path is SWAPPED for an untrusted lib (unsigned, and a differently-signed
/// unknown-publisher build). A reload (a fresh `scan_and_validate`) REFUSES the changed,
/// non-allowlisted bytes — the prior admission does not carry over. A legitimate re-sign by the SAME
/// allowlisted identity still loads, so operator upgrades are unaffected (behavior stays identical).
#[test]
fn a_reload_that_swaps_in_an_untrusted_lib_is_refused_but_a_legit_resign_still_loads() {
    let release = key(1);
    let vendor = key(7);
    let attacker = key(9);
    let dir = tmpdir("reload-swap");
    let mut allow = default_policy(&release);
    allow
        .publishers
        .insert("acme".into(), vendor.verifying_key());

    // Load #1: the allowlisted vendor artifact is admitted.
    let good = sign(
        &vendor,
        manifest("acme-store", "acme-kv", "acme"),
        b"v1 bytes",
    );
    write_tarball(&dir, "acme.tar.gz", &good, b"v1 bytes");
    let reg = scan_and_validate(&dir, &allow).expect("scan");
    assert_eq!(reg.loadable().len(), 1, "the genuine artifact loads");

    // SWAP A: same path, now UNSIGNED bytes. Reload refuses.
    let unsigned_swap = unsigned("acme-store", "acme-kv", "acme", b"swapped unsigned bytes");
    write_tarball(
        &dir,
        "acme.tar.gz",
        &unsigned_swap,
        b"swapped unsigned bytes",
    );
    let reg = scan_and_validate(&dir, &allow).expect("scan");
    assert!(
        reg.loadable().is_empty() && reg.skipped().len() == 1,
        "a swapped-in unsigned lib is refused on reload: {reg:?}"
    );

    // SWAP B: same path, signed by an ATTACKER key under an unknown publisher. Reload refuses.
    let forged = sign(
        &attacker,
        manifest("acme-store", "acme-kv", "evil-corp"),
        b"evil bytes",
    );
    write_tarball(&dir, "acme.tar.gz", &forged, b"evil bytes");
    let reg = scan_and_validate(&dir, &allow).expect("scan");
    assert!(
        reg.loadable().is_empty() && reg.skipped().len() == 1,
        "a swapped-in unknown-publisher lib is refused on reload: {reg:?}"
    );

    // LEGIT UPGRADE: a genuine re-sign by the allowlisted vendor (new bytes, new version) still
    // loads on reload — the swap defense must not break real operator upgrades.
    let mut up = manifest("acme-store", "acme-kv", "acme");
    up.version = "1.6.0".into();
    let up = sign(&vendor, up, b"v2 bytes");
    write_tarball(&dir, "acme.tar.gz", &up, b"v2 bytes");
    let reg = scan_and_validate(&dir, &allow).expect("scan");
    assert_eq!(
        reg.loadable().len(),
        1,
        "a legit re-signed upgrade from the allowlisted identity still loads"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- 4. REAL CDYLIB: refused-never-dlopened, and trusted-once on the hot path ------------------

/// Locate the REAL `busbar_store_example_plugin` cdylib the workspace builds. Returns `None` (and the
/// caller skips) when it is not built, EXCEPT under CI where a missing cdylib is a hard failure — the
/// end-to-end hot-path proofs must not silently vanish.
fn store_example_cdylib() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = crate::plugin_library_filename("busbar_store_example_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "busbar_store_example_plugin cdylib is not built under CI: the KernelSeal trust-boundary \
             end-to-end proofs (rogue-refused, trusted-once-on-hot-path) require it. `cargo test \
             --workspace` must build it first."
        );
    }
    candidate
}

/// END TO END, REAL CODE: a valid cdylib with the correct ABI, packaged with NO signature, dropped
/// into the plugins directory, is REFUSED by default — it does not load and, decisively, is never
/// `dlopen`ed, so it never reaches the hot path. We prove "never reached the hot path" by asserting
/// `open_store` returns an error instead of a live handle.
#[test]
fn a_real_rogue_cdylib_dropped_in_is_refused_by_default_and_never_reaches_the_hot_path() {
    let Some(lib_path) = store_example_cdylib() else {
        eprintln!("skipping: busbar_store_example_plugin cdylib not built");
        return;
    };
    let lib = std::fs::read(&lib_path).expect("read the real cdylib");
    let release = key(1);
    let dir = tmpdir("real-rogue");
    // A REAL cdylib, correct kind/ABI, well-formed integrity digest, but UNSIGNED and NOT
    // allowlisted.
    let m = unsigned("busbar-store-example", "example-kv", "nobody", &lib);
    write_tarball(&dir, "example.tar.gz", &m, &lib);

    let reg = scan_and_validate(&dir, &default_policy(&release)).expect("scan succeeds");
    assert!(
        reg.loadable().is_empty(),
        "a real but untrusted cdylib is NOT admitted"
    );
    assert_eq!(reg.skipped().len(), 1, "it is refused, fail-closed");
    // Decisive: opening it does not hand back a live handle — the image is never dlopened.
    assert!(
        reg.open_store("example-kv", "{}").is_err(),
        "a refused real cdylib is never dlopened / never serves"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// END TO END, REAL CODE: the same real cdylib LOADS once its identity is allowlisted, serves put/get
/// crossings over the hot C ABI, and — the "trusted once" property — KEEPS serving after the on-disk
/// tarball is DELETED. That proves the per-crossing hot lane re-runs NO trust check and never
/// re-reads disk: trust is established exactly once at load, and the live handle is the in-memory
/// `dlopen`'d image.
#[test]
fn a_real_cdylib_loads_once_allowlisted_and_stays_trusted_on_the_hot_path() {
    use busbar_api::VirtualKey;

    let Some(lib_path) = store_example_cdylib() else {
        eprintln!("skipping: busbar_store_example_plugin cdylib not built");
        return;
    };
    let lib = std::fs::read(&lib_path).expect("read the real cdylib");
    let release = key(1);
    let vendor = key(7);
    let dir = tmpdir("real-trusted");
    let m = sign(
        &vendor,
        manifest("busbar-store-example", "example-kv", "acme"),
        &lib,
    );
    write_tarball(&dir, "example.tar.gz", &m, &lib);

    // Operator allowlists the vendor identity -> the real cdylib is admitted.
    let mut allow = default_policy(&release);
    allow
        .publishers
        .insert("acme".into(), vendor.verifying_key());
    let reg = scan_and_validate(&dir, &allow).expect("scan succeeds");
    assert_eq!(reg.loadable().len(), 1, "allowlisted real cdylib loads");

    // Open a live store handle (this is the single dlopen of the verified in-memory bytes) and drive
    // a put/get crossing over the hot C ABI.
    let store = reg
        .open_store("example-kv", "{}")
        .expect("the allowlisted plugin opens a live store");
    let vk = VirtualKey {
        id: "vk_seal".into(),
        ..Default::default()
    };
    store.put_key(&vk).expect("put over the hot C ABI");
    assert_eq!(
        store.get_key("vk_seal").expect("get").map(|k| k.id),
        Some("vk_seal".to_string()),
        "the crossing round-trips"
    );

    // TRUSTED ONCE: delete the on-disk tarball, then keep crossing. The live handle is the in-memory
    // image; the hot lane neither re-reads disk nor re-verifies a seal per crossing.
    std::fs::remove_dir_all(&dir).expect("remove the on-disk plugin dir");
    for i in 0..64 {
        let vk = VirtualKey {
            id: format!("vk_{i}"),
            ..Default::default()
        };
        store
            .put_key(&vk)
            .expect("put still works with no disk file present");
        assert_eq!(
            store
                .get_key(&format!("vk_{i}"))
                .expect("get")
                .map(|k| k.id),
            Some(format!("vk_{i}")),
            "crossing #{i} still serves after the disk file is gone (trusted once)"
        );
    }
}
