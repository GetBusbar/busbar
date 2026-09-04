// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/registry.rs`.

use super::*;
use busbar_plugin_sign::{sign, SigningKey};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// After the auth ABI v1→2 bump the loader floor MUST still admit v1 — a pre-built v1
/// auth plugin (verify-only, e.g. `auth-static-plugin`) keeps loading. The supported range is the
/// inclusive `[1, 2]`.
#[test]
fn supported_abi_auth_floor_admits_v1() {
    let range = supported_abi("auth");
    assert_eq!(range, &[1, busbar_plugin::cold::AUTH_ABI_VERSION]);
    let (floor, max) = (range[0], range[1]);
    assert_eq!(floor, 1, "v1 auth plugins must still load");
    assert_eq!(max, 2, "v2 is the current auth payload schema");
    assert!(floor <= 1 && 1 <= max, "abi_version 1 is in range");
    assert!(floor <= 2 && 2 <= max, "abi_version 2 is in range");
}

/// THE STORE FLOOR IS 2 AND MUST STAY THERE. Every published first-party store plugin
/// (sqlite/postgres/mysql/valkey) carries `abi_version: 2`, the 1.5.x wire. The 2→3 and 3→4 bumps
/// changed what a plugin is COMPILED against, not a byte the engine exchanges with a built artifact:
/// every variant the 1.5.x engine sent still exists unchanged, and the eight neutral plane-record
/// verbs added since are ones a v2 plugin answers with `STATUS_UNSUPPORTED`, which `DynStore`
/// already treats as inert. So the range is `[2, ABI_VERSION]` = `[2, 4]`; v1 (whose AWS-only
/// credential variants no longer exist) is the only store schema this binary cannot speak.
#[test]
fn supported_abi_store_floor_admits_v2() {
    let range = supported_abi("store");
    assert_eq!(range, &[STORE_ABI_FLOOR, busbar_plugin::cold::ABI_VERSION]);
    assert_eq!(
        busbar_plugin::cold::ABI_VERSION,
        4,
        "store payload schema is v4"
    );
    let (floor, max) = (range[0], range[1]);
    assert_eq!(
        floor, 2,
        "the floor MUST be 2 — every published 1.5.x store plugin declares abi_version 2"
    );
    assert!(!(floor <= 1 && 1 <= max), "abi_version 1 is NOT in range");
    assert!(floor <= 2 && 2 <= max, "abi_version 2 is in range");
    assert!(floor <= 3 && 3 <= max, "abi_version 3 is in range");
    assert!(floor <= 4 && 4 <= max, "abi_version 4 is in range");
}

/// PARITY WITH 1.5.5: a signed, otherwise-valid store artifact whose manifest declares
/// `abi_version: 2` (what every published store plugin ships) LOADS — it enters the registry and
/// resolves by name and alias, exactly as it did under the 1.5.5 binary. Refusing it here was the
/// bug that made 1.6.0 reject the entire published store catalogue at boot.
#[test]
fn a_v2_store_artifact_is_accepted_at_load() {
    let release = key(1);
    let dir = tmpdir("v2-accepted");
    let mut m = manifest("busbar-store-legacy", "legacy", "busbar");
    m.abi_version = 2; // the 1.5.x store wire every published plugin was built against
    let m = sign(&release, m, b"legacy lib");
    write_tarball(&dir, "legacy.tar.gz", &m, b"legacy lib");

    let reg = scan_and_validate(&dir, &policy(&release))
        .unwrap_or_else(|e| panic!("a v2 store artifact must load: {e:?}"));
    assert_eq!(reg.loadable().len(), 1);
    assert!(reg.skipped().is_empty(), "nothing skipped: {reg:?}");
    let p = reg
        .resolve("legacy")
        .expect("resolves by alias, like any current-schema store");
    assert_eq!(p.manifest.name, "busbar-store-legacy");
    assert_eq!(p.manifest.abi_version, 2);
    assert!(
        reg.resolve("busbar-store-legacy").is_some(),
        "resolves by name"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE RANGE EDGES, both ways. The store range is `v2..=v4`: a v2 manifest is accepted (above),
/// while v1 (below the floor) and v5 (above what this binary speaks) are each a HARD structural
/// INVALID that names the file, the kind, the offending version AND the range — so an operator
/// reading the line knows exactly what this binary will take. The signatures are valid on purpose:
/// both rejections are the ABI range, not trust.
#[test]
fn store_abi_below_or_above_the_range_is_refused_naming_v2_to_v4() {
    let release = key(1);
    for (tag, version) in [("v1", 1u32), ("v5", 5u32)] {
        let dir = tmpdir(&format!("range-{tag}"));
        let mut m = manifest("busbar-store-edge", "edge", "busbar");
        m.abi_version = version;
        let m = sign(&release, m, b"edge lib");
        write_tarball(&dir, "edge.tar.gz", &m, b"edge lib");

        let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
        assert_eq!(
            errs.len(),
            1,
            "{tag}: one artifact, one hard rejection: {errs:?}"
        );
        assert!(
            errs[0].contains("edge.tar.gz"),
            "{tag}: names the file: {}",
            errs[0]
        );
        assert!(
            errs[0].contains(&format!("abi_version {version} is not supported")),
            "{tag}: rejected by the ABI range, not trust: {}",
            errs[0]
        );
        assert!(
            errs[0].contains("'store'"),
            "{tag}: names the kind: {}",
            errs[0]
        );
        assert!(
            errs[0].contains("supported range v2..=v4"),
            "{tag}: names the range this binary speaks: {}",
            errs[0]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

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

fn policy(first_party: &SigningKey) -> TrustPolicy {
    TrustPolicy {
        first_party_key: Some(first_party.verifying_key()),
        binary_version: "1.5.0".into(),
        first_party_floors: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    // `pid + tag` is already unique across today's 13 call sites (each passes a distinct
    // literal tag), but a clock read is not a monotonic ticket — two threads on two cores can
    // observe the same `SystemTime::now()` value, and routinely do on a coarse-clock platform.
    // `crate::stage::next_seq()` is the in-tree fix for exactly this shape (already applied to
    // `stage.rs`'s own staging-file naming); reuse it here instead of a second, weaker idiom.
    let d = std::env::temp_dir().join(format!(
        "busbar-registry-{}-{tag}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_tarball(dir: &Path, file: &str, m: &Manifest, lib: &[u8]) {
    let bytes = tarball::package(m, "lib.so", lib).unwrap();
    std::fs::write(dir.join(file), bytes).unwrap();
}

/// The full happy path: two signed first-party plugins scan into a registry addressable by
/// name AND alias, with identity from the MANIFEST (the filenames are deliberately wrong).
#[test]
fn scan_registers_by_name_and_alias_from_manifest_not_filename() {
    let release = key(1);
    let dir = tmpdir("happy");
    let valkey = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"valkey lib",
    );
    let pg = sign(
        &release,
        manifest("busbar-store-postgres", "postgres", "busbar"),
        b"pg lib",
    );
    // Filenames lie on purpose - identity must come from the signed manifest.
    write_tarball(&dir, "totally-not-valkey.tar.gz", &valkey, b"valkey lib");
    write_tarball(&dir, "misc.tgz", &pg, b"pg lib");

    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    assert_eq!(reg.loadable().len(), 2);
    assert!(reg.resolve("valkey").is_some(), "alias resolves");
    assert!(
        reg.resolve("busbar-store-valkey-plugin").is_some(),
        "name resolves"
    );
    assert!(reg.resolve("postgres").is_some());
    assert_eq!(
        reg.resolve("valkey").unwrap().manifest.name,
        "busbar-store-valkey-plugin"
    );
    assert!(reg.resolve("no-such").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED: one invalid tarball in the dir fails the WHOLE scan with a named reason -
/// never a partial registry.
#[test]
fn one_invalid_tarball_fails_the_whole_scan() {
    let release = key(1);
    let dir = tmpdir("invalid");
    let good = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"lib",
    );
    write_tarball(&dir, "good.tar.gz", &good, b"lib");
    std::fs::write(dir.join("junk.tar.gz"), b"this is not a tarball").unwrap();

    let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
    assert_eq!(errs.len(), 1);
    assert!(
        errs[0].contains("junk.tar.gz"),
        "names the file: {}",
        errs[0]
    );
    assert!(errs[0].contains("invalid plugin"), "got {}", errs[0]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A file over `tarball::MAX_TARBALL_FILE_BYTES` is rejected by its SIZE, before `fs::read`
/// ever runs - not by a later gzip/tar decode failure. We prove this by making the oversize
/// file a SPARSE all-zeros file (cheap to create, costs no real disk or memory): `fs::read`
/// would happily succeed on it (it is valid, if enormous, input), so if the rejection reason
/// names the byte cap rather than some gzip/tar decode error, the size check - not the
/// decoder - is what caught it, and it caught it before the whole file was read into memory.
#[test]
fn oversize_tarball_file_is_rejected_by_size_before_being_read() {
    let release = key(1);
    let dir = tmpdir("oversize");
    let path = dir.join("huge.tar.gz");
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(tarball::MAX_TARBALL_FILE_BYTES + 1).unwrap();
    drop(f);

    let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
    assert_eq!(errs.len(), 1);
    assert!(
        errs[0].contains("huge.tar.gz"),
        "names the file: {}",
        errs[0]
    );
    assert!(
        errs[0].contains("exceeding") && errs[0].contains("byte cap"),
        "rejected by size, not by decode: {}",
        errs[0]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A structurally-broken manifest (bad kind) fails the scan even though it is validly signed.
#[test]
fn signed_but_malformed_manifest_is_invalid() {
    let release = key(1);
    let dir = tmpdir("malformed");
    let mut m = manifest("busbar-store-x", "x", "busbar");
    m.kind = "widget".into();
    let m = sign(&release, m, b"lib");
    write_tarball(&dir, "x.tar.gz", &m, b"lib");
    let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
    assert!(errs[0].contains("kind"), "got {}", errs[0]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Phase 2: an untrusted (third-party, no opt-in) plugin is SKIPPED - the scan succeeds, the
/// plugin is not loadable, and referencing it fails with the skip reason.
#[test]
fn untrusted_is_skipped_not_fatal_but_reference_fails_loud() {
    let release = key(1);
    let acme = key(2);
    let dir = tmpdir("untrusted");
    let third = sign(
        &acme,
        manifest("acme-store-dynamo", "dynamo", "acme"),
        b"lib3",
    );
    write_tarball(&dir, "dynamo.tar.gz", &third, b"lib3");

    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan succeeds");
    assert!(reg.loadable().is_empty());
    assert_eq!(reg.skipped().len(), 1);
    assert!(
        reg.resolve("dynamo").is_none(),
        "a skipped plugin never resolves"
    );
    let err = reg.open_store("dynamo", "{}").map(|_| ()).unwrap_err();
    assert!(err.contains("was not loaded"), "got {err}");
    assert!(err.contains("allowlist"), "carries the trust reason: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Phase 3: two loadable plugins claiming the same ALIAS is a hard error naming both - the
/// "can't use valkey and a third-party valkey" case (third-party allowed via opt-in).
#[test]
fn alias_conflict_is_a_hard_error_naming_both() {
    let release = key(1);
    let acme = key(2);
    let dir = tmpdir("conflict");
    let first = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"lib1",
    );
    let third = sign(
        &acme,
        manifest("acme-store-valkey", "valkey", "acme"),
        b"lib2",
    );
    write_tarball(&dir, "first.tar.gz", &first, b"lib1");
    write_tarball(&dir, "third.tar.gz", &third, b"lib2");

    let mut pol = policy(&release);
    pol.allow_third_party = true; // both become loadable -> the conflict must fire
    let errs = scan_and_validate(&dir, &pol).unwrap_err();
    assert_eq!(errs.len(), 1, "got {errs:?}");
    assert!(errs[0].contains("alias conflict"), "got {}", errs[0]);
    assert!(
        errs[0].contains("busbar-store-valkey-plugin"),
        "names first: {}",
        errs[0]
    );
    assert!(
        errs[0].contains("acme-store-valkey"),
        "names second: {}",
        errs[0]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Phase 3: duplicate NAME, and an alias colliding with another plugin's NAME, both hard-error.
#[test]
fn name_and_alias_vs_name_conflicts_are_hard_errors() {
    let release = key(1);
    let dir = tmpdir("nameconflict");
    let a = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"a",
    );
    let b = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey2", "busbar"),
        b"b",
    );
    write_tarball(&dir, "a.tar.gz", &a, b"a");
    write_tarball(&dir, "b.tar.gz", &b, b"b");
    let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("name conflict")),
        "got {errs:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);

    // Alias colliding with another plugin's canonical name.
    let dir = tmpdir("aliasvsname");
    let a = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"a",
    );
    let b = sign(
        &release,
        manifest("acme-store-x", "busbar-store-valkey-plugin", "busbar"),
        b"b",
    );
    write_tarball(&dir, "a.tar.gz", &a, b"a");
    write_tarball(&dir, "b.tar.gz", &b, b"b");
    let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("alias/name conflict")),
        "got {errs:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A missing plugins dir is an EMPTY registry (drop-is-inert), not an error.
#[test]
fn missing_dir_is_empty_registry() {
    let reg = scan_and_validate(Path::new("/no/such/busbar/plugins/dir"), &policy(&key(1)))
        .expect("missing dir is fine");
    assert!(reg.loadable().is_empty() && reg.skipped().is_empty());
}

/// Kind gating: a non-store plugin resolves but cannot back the governance store.
#[test]
fn open_store_refuses_non_store_kind() {
    let release = key(1);
    let dir = tmpdir("kind");
    let mut m = manifest("busbar-hook-ranker", "ranker", "busbar");
    m.kind = "hook".into();
    // Stamp the hook-supported ABI version so the scan admits it and the KIND gate (not the
    // ABI gate) is what rejects.
    m.abi_version = busbar_plugin::cold::hook::HOOK_ABI_VERSION;
    let m = sign(&release, m, b"hook lib");
    write_tarball(&dir, "hook.tar.gz", &m, b"hook lib");
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    let err = reg.open_store("ranker", "{}").map(|_| ()).unwrap_err();
    assert!(err.contains("kind 'hook'"), "got {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Kind gating for SECRETS: a `kind: secret` plugin passes the SAME scan/trust pipeline
/// as a store plugin (a plugin is a plugin), and the kind gate is symmetric - a store plugin
/// cannot resolve config secrets, and a secret plugin cannot back the store. FAIL-CLOSED both
/// ways.
#[test]
fn open_secret_refuses_non_secret_kind_and_vice_versa() {
    let release = key(1);
    let dir = tmpdir("secretkind");
    // A trusted secret plugin (abi_version stamped to the secret ABI so the scan admits it).
    let mut m = manifest("busbar-secret-vault", "vault", "busbar");
    m.kind = "secret".into();
    m.abi_version = busbar_plugin::cold::SECRET_ABI_VERSION;
    let m = sign(&release, m, b"secret lib");
    write_tarball(&dir, "vault.tar.gz", &m, b"secret lib");
    // And a trusted store plugin beside it.
    let st = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"store lib",
    );
    write_tarball(&dir, "valkey.tar.gz", &st, b"store lib");
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan admits both kinds");
    assert_eq!(reg.loadable().len(), 2, "one secret + one store validated");
    // The kind gates: a store referenced as a secret module fails naming the kind...
    let err = reg.open_secret("valkey", "{}").map(|_| ()).unwrap_err();
    assert!(err.contains("kind 'store'"), "got {err}");
    // ...and a secret plugin cannot back the store.
    let err = reg.open_store("vault", "{}").map(|_| ()).unwrap_err();
    assert!(err.contains("kind 'secret'"), "got {err}");
    // An unknown secret module name is fail-closed with the loadable set named.
    let err = reg.open_secret("nope", "{}").map(|_| ()).unwrap_err();
    assert!(err.contains("no plugin named or aliased"), "got {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Kind gating: a non-auth plugin resolves but cannot serve as an auth module. Mirrors
/// `open_store_refuses_non_store_kind`: a store-kind manifest passes phase 1/2/3 (its default
/// `kind`/`abi_version` from `manifest()` are already store-admissible) and is then handed to
/// `open_auth`, which must reject on the KIND gate before ever attempting to load it.
#[test]
fn open_auth_refuses_non_auth_kind() {
    let release = key(1);
    let dir = tmpdir("authkind");
    let m = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"store lib",
    );
    write_tarball(&dir, "valkey.tar.gz", &m, b"store lib");
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    let err = reg.open_auth("valkey", "{}").map(|_| ()).unwrap_err();
    assert!(err.contains("kind 'store'"), "got {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Kind gating: a non-hook plugin resolves but cannot serve as a routing hook. Mirrors
/// `open_store_refuses_non_store_kind`: a store-kind manifest passes phase 1/2/3 and is then
/// handed to `open_hook`, which must reject on the KIND gate before ever attempting to load it
/// (the dummy projectors below are never invoked - the kind check short-circuits first).
#[test]
fn open_hook_refuses_non_hook_kind() {
    let release = key(1);
    let dir = tmpdir("hookkind");
    let m = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"store lib",
    );
    write_tarball(&dir, "valkey.tar.gz", &m, b"store lib");
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    let projectors = std::sync::Arc::new(crate::hook::HookProjectors {
        decide: Box::new(|_req, _cands, _ctx| serde_json::Value::Null),
        transform: Box::new(|_req| serde_json::Value::Null),
        normalize: Box::new(|_v, _cands| unreachable!("kind gate must short-circuit first")),
        transform_outcome: Box::new(|_v| unreachable!("kind gate must short-circuit first")),
        status: Box::new(|_v| None),
        describe_schema: Box::new(|_v| None),
    });
    let err = reg
        .open_hook("valkey", "{}", "valkey", projectors)
        .map(|_| ())
        .unwrap_err();
    assert!(err.contains("kind 'store'"), "got {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The inventory is MANIFEST-ONLY and covers every row class: ready, skipped (unknown
/// publisher), and invalid - with the exact reason.
#[test]
fn inventory_reports_every_row_class_without_loading() {
    let release = key(1);
    let acme = key(2);
    let dir = tmpdir("inventory");
    let good = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"g",
    );
    let third = sign(&acme, manifest("acme-store-dynamo", "dynamo", "acme"), b"t");
    write_tarball(&dir, "good.tar.gz", &good, b"g");
    write_tarball(&dir, "third.tar.gz", &third, b"t");
    std::fs::write(dir.join("junk.tar.gz"), b"garbage").unwrap();

    let rows = inventory(&dir, &policy(&release));
    assert_eq!(rows.len(), 3);
    let by_file = |f: &str| rows.iter().find(|r| r.file == f).unwrap();
    assert_eq!(by_file("good.tar.gz").signature, "first-party");
    assert_eq!(by_file("good.tar.gz").status, "ready");
    assert_eq!(by_file("third.tar.gz").signature, "unknown-publisher");
    assert!(by_file("third.tar.gz").status.starts_with("SKIPPED:"));
    assert_eq!(by_file("junk.tar.gz").signature, "INVALID");
    assert!(by_file("junk.tar.gz").status.starts_with("INVALID:"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Locate the REAL `busbar-store-sqlite-plugin` cdylib built from a SIBLING checkout of
/// `GetBusbar/store-sqlite` (mirrors the loader tests' `store_fixture_plugin_path` in
/// `crate::tests` exactly — see that function's doc comment for the full sibling-checkout
/// rationale). Used here purely to prove the tarball PIPELINE's mechanics (sign, package, scan,
/// resolve-by-alias, open), never sqlite-specific behavior (which is that repo's own job).
fn store_fixture_cdylib() -> Option<PathBuf> {
    let candidate = {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")); // .../busbarAI/crates/plugin-loader
        let sibling_root = manifest_dir.join("../../../store-sqlite"); // sibling of busbarAI
        let name = crate::plugin_library_filename("busbar_store_sqlite_plugin");
        let candidate = sibling_root.join("target/release").join(&name);
        candidate.exists().then_some(candidate)
    };
    if candidate.is_none()
        && std::env::var_os("CI").is_some()
        && std::env::var_os("DEV_GATE").is_some()
    {
        panic!(
            "the store-sqlite-plugin cdylib is not built from the ../store-sqlite sibling \
                 checkout under dev-gate.yml: refusing to silently skip the end-to-end tarball \
                 pipeline coverage"
        );
    }
    candidate
}

/// END-TO-END, REAL CODE: package the real store-sqlite-plugin cdylib into a SIGNED tarball, run
/// the full three-phase pipeline, resolve by ALIAS, and open a live `dyn Store` through the
/// memfd (Linux) / private-temp loader - exercising put/get over the C ABI. This is the exact
/// seam the engine sees: verified bytes in, `Box<dyn Store>` out, indistinguishable from a
/// compiled-in backend.
#[test]
fn end_to_end_open_store_from_signed_tarball() {
    let Some(path) = store_fixture_cdylib() else {
        eprintln!(
            "skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p \
                 busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)"
        );
        return;
    };
    let lib = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");
    let acme = key(3);
    let dir = tmpdir("e2e");
    let m = sign(&acme, manifest("acme-store-sqlite", "sqlite", "acme"), &lib);
    let bytes = tarball::package(&m, "libbusbar_store_sqlite_plugin.so", &lib).unwrap();
    std::fs::write(dir.join("sqlite.tar.gz"), bytes).unwrap();

    let mut pol = policy(&key(1));
    pol.publishers
        .insert("acme".to_string(), acme.verifying_key());
    let reg = scan_and_validate(&dir, &pol).expect("scan");
    let store = reg
        .open_store("sqlite", r#"{"db_path": ":memory:"}"#)
        .expect("open the real store through the full pipeline");
    let key = busbar_api::VirtualKey {
        id: "vk_pipeline".into(),
        generation_hash: "h".into(),
        name: "pipeline".into(),
        allowed_scopes: Some(vec![busbar_api::ScopeRef::pool("p")]),
        enabled: true,
        created_at: 1,
        group: Some("growth".into()),
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    };
    store.put_key(&key).expect("put over the ABI");
    let got = store.get_key("vk_pipeline").unwrap().unwrap();
    assert_eq!(got.group.as_deref(), Some("growth"));
    assert_eq!(
        got.allowed_scopes,
        Some(vec![busbar_api::ScopeRef::pool("p")])
    );
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// First-party anti-downgrade in the pipeline is PER-NAME (floors-only — no automatic
/// binary-version floor, since first-party plugins version on independent 1.0.x/2.x lines):
/// a below-pin first-party plugin is REJECTED with the anti-downgrade reason (inventory shows
/// it; scan skips it), while the same artifact without a pin loads.
#[test]
fn first_party_downgrade_is_rejected_in_pipeline() {
    let release = key(1);
    let dir = tmpdir("downgrade");
    let mut m = manifest("busbar-store-valkey-plugin", "valkey", "busbar");
    m.version = "1.0.0".into();
    let m = sign(&release, m, b"old lib");
    write_tarball(&dir, "old.tar.gz", &m, b"old lib");

    // Unpinned: its 1.0.0 line is its own business — it loads.
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    assert!(
        reg.resolve("valkey").is_some(),
        "an unpinned first-party plugin loads regardless of the binary version"
    );

    // Pinned above its version: rejected with the anti-downgrade reason, end to end.
    let mut pinned = policy(&release);
    pinned.first_party_floors.insert(
        "busbar-store-valkey-plugin".to_string(),
        "1.0.1".to_string(),
    );
    let reg = scan_and_validate(&dir, &pinned).expect("scan");
    assert!(reg.resolve("valkey").is_none());
    assert!(reg.skipped()[0].reason.contains("anti-downgrade"));
    let rows = inventory(&dir, &pinned);
    assert!(
        rows[0].status.starts_with("REJECTED:"),
        "got {}",
        rows[0].status
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A malformed `min_versions` floor SKIPS just the one floored plugin — the boot is NOT killed —
/// and the graduated escalation ladder ("a rejection here is a SKIP, unless referenced")
/// surfaces it: `skipped()` names the reason, and `--list-plugins`/the admin catalog show a
/// `REJECTED:` row. All four asserted in one test because the graduated escalation IS the design.
#[test]
fn a_malformed_floor_skips_the_plugin_and_keeps_the_boot_alive() {
    let release = key(1);
    let dir = tmpdir("malformed-floor");
    let m = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"lib",
    );
    write_tarball(&dir, "valkey.tar.gz", &m, b"lib");

    let mut pol = policy(&release);
    pol.min_versions.insert(
        "busbar-store-valkey-plugin".to_string(),
        "v9.9.9".to_string(),
    );

    let reg = scan_and_validate(&dir, &pol).expect("scan must succeed — the boot is not killed");
    assert!(
        reg.resolve("valkey").is_none(),
        "the malformed-floor plugin must not be loadable"
    );
    assert!(
        reg.skipped()[0].reason.contains("v9.9.9"),
        "the skip reason must name the malformed floor: {}",
        reg.skipped()[0].reason
    );
    let rows = inventory(&dir, &pol);
    assert!(
        rows[0].status.starts_with("REJECTED:"),
        "--list-plugins / the admin catalog must show the rejection: {}",
        rows[0].status
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The escalation's top rung — a REFERENCED plugin (e.g. `store.module`) with a malformed floor
/// fails the boot LOUDLY, with the reason attached, via `unresolved_reason` (the same string
/// `main.rs`'s hard boot error interpolates for a referenced module).
#[test]
fn a_referenced_plugin_with_a_malformed_floor_fails_the_boot_loudly() {
    let release = key(1);
    let dir = tmpdir("malformed-floor-referenced");
    let m = sign(
        &release,
        manifest("busbar-store-valkey-plugin", "valkey", "busbar"),
        b"lib",
    );
    write_tarball(&dir, "valkey.tar.gz", &m, b"lib");

    let mut pol = policy(&release);
    pol.min_versions.insert(
        "busbar-store-valkey-plugin".to_string(),
        "v9.9.9".to_string(),
    );

    let reg = scan_and_validate(&dir, &pol).expect("scan");
    let reason = reg
        .unresolved_reason("valkey")
        .expect("a malformed-floor plugin must be reportable as unresolved")
        .reason
        .clone();
    assert!(
        reason.contains("v9.9.9"),
        "the reason `main.rs` interpolates into its hard boot error must name the floor: {reason}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// REGRESSION GUARD: the `--list-plugins` signature label is derived from the STRUCTURED
/// reject verdict (`SkippedPlugin.kind`), NOT a substring of the plugin-controlled reason. A
/// third-party plugin whose author crafts `publisher: "anti-downgrade-bypass"` (so the rejection
/// reason text contains "anti-downgrade") must still be labeled `unknown-publisher`, never
/// mislabeled `trusted (below floor)`. Load decisions never used this text; the fix is the label.
#[test]
fn crafted_publisher_cannot_forge_signature_label() {
    let release = key(1);
    let attacker = key(9);
    let dir = tmpdir("label-forge");
    // Validly signed by the attacker, but the publisher is NOT allowlisted → unknown-publisher.
    // The crafted publisher name is chosen so the reason string contains "anti-downgrade".
    let m = sign(
        &attacker,
        manifest("acme-store-x", "acme", "anti-downgrade-bypass"),
        b"lib",
    );
    write_tarball(&dir, "acme.tar.gz", &m, b"lib");

    // Default posture (no allow_third_party) → skipped as unknown-publisher.
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    assert!(reg.resolve("acme").is_none());
    assert_eq!(
        reg.skipped()[0].kind,
        busbar_plugin_sign::RejectKind::UnknownPublisher
    );

    let rows = inventory(&dir, &policy(&release));
    assert_eq!(
        rows[0].signature, "unknown-publisher",
        "the crafted publisher must NOT forge a 'trusted (below floor)' label; got {}",
        rows[0].signature
    );
    assert!(
        rows[0].status.starts_with("SKIPPED:"),
        "an unknown-publisher reject is a SKIP, not a REJECTED row: {}",
        rows[0].status
    );

    // And the SAME untrusted artifact but with a configured `min_versions`
    // floor on its name must NEVER be labeled `trusted (below floor)`. The floor is trust-relative:
    // `AntiDowngrade` is reserved for artifacts that proved trust. An untrusted+floored artifact is
    // categorized as `UntrustedFloored` and labeled `untrusted (below floor)` — a hard SKIP, never
    // a "trusted" surface. (Regression: the floor check fired BEFORE trust resolution and returned
    // `AntiDowngrade` for this case, mislabeling it "trusted (below floor)".)
    let mut floored = policy(&release);
    floored
        .min_versions
        .insert("acme-store-x".to_string(), "2.0.0".to_string());
    let reg = scan_and_validate(&dir, &floored).expect("scan");
    assert!(reg.resolve("acme").is_none());
    assert_eq!(
        reg.skipped()[0].kind,
        busbar_plugin_sign::RejectKind::UntrustedFloored,
        "a floored untrusted artifact must resolve to UntrustedFloored, not AntiDowngrade"
    );
    let rows = inventory(&dir, &floored);
    assert_eq!(
        rows[0].signature, "untrusted (below floor)",
        "a floored untrusted artifact must NOT be mislabeled 'trusted (below floor)'; got {}",
        rows[0].signature
    );
    assert!(
        rows[0].status.starts_with("SKIPPED:"),
        "a floored untrusted reject is a SKIP, not REJECTED: {}",
        rows[0].status
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The auth range's MAX reads `busbar_plugin::cold::AUTH_ABI_VERSION` (matching `"secret"`/`"hook"`
/// on the max axis). Post-1.5.2 the FLOOR is pinned at 1 (v1 plugins still load — see
/// `supported_abi_auth_floor_admits_v1`), so the range is `[1, AUTH_ABI_VERSION]`, not
/// `[AUTH_ABI_VERSION, AUTH_ABI_VERSION]`.
#[test]
fn auth_supported_abi_reads_the_shared_const() {
    assert_eq!(
        supported_abi("auth"),
        &[1, busbar_plugin::cold::AUTH_ABI_VERSION]
    );
}

/// The export range reads the shared `EXPORT_ABI_VERSION` const on both endpoints, so a bump
/// propagates automatically instead of drifting from the SDK's declared version. `kind: export`
/// is a recognized kind with a non-empty supported range.
#[test]
fn export_supported_abi_reads_the_shared_const() {
    assert_eq!(
        supported_abi("export"),
        &[
            busbar_plugin::cold::export::EXPORT_ABI_VERSION,
            busbar_plugin::cold::export::EXPORT_ABI_VERSION,
        ]
    );
    assert!(!supported_abi("export").is_empty());
}
