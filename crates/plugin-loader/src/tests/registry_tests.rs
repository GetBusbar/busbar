// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/registry.rs`.

use super::*;
use crate::sign::{sign, SigningKey};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// ONE VERSION PER KIND (THE DESIGN §11.2, §11.8; A.9): each kind's window is exactly
/// `abi::<kind>::ABI_VERSION` — no ranges, no JSON-lane versions, no 1.5.5 floors (ruling
/// C21/ABI-o1) — at the shipped numbers.
///
/// RED before the P2 switch-over: store, secret and auth answered their JSON-lane versions (4, 1, 3),
/// plane the range `[1, ABI_MINOR]` and transport `[TRANSPORT_DECL_MINOR, ABI_MINOR]`.
#[test]
fn supported_abi_is_one_version_per_kind() {
    use busbar_contract::abi;
    let shipped: &[(&str, u32, u32)] = &[
        ("store", abi::store::ABI_VERSION, 3),
        ("secret", abi::secret::ABI_VERSION, 2),
        ("auth", abi::auth::ABI_VERSION, 3),
        ("hook", abi::hook::ABI_VERSION, 2),
        ("export", abi::export::ABI_VERSION, 3),
        ("plane", abi::plane::ABI_VERSION, 1),
        ("transport", abi::transport::ABI_VERSION, 1),
    ];
    for &(kind, version, number) in shipped {
        assert_eq!(supported_abi(kind), &[version], "{kind}");
        assert_eq!(version, number, "{kind} ships at {number}");
    }
    assert!(supported_abi("nonsense").is_empty());
}

/// C21 (ABI-o1, THE DESIGN §11.8): a signed, otherwise-valid artifact stating its kind's 1.5.5
/// payload version — what every published 1.5.5 JSON-contract plugin ships (store 2, auth 2, hook 1,
/// export 2) — is a HARD structural refusal at boot that names the file, the kind, the version and
/// the rebuild against the 1.6.0 SDK. The signatures are valid on purpose: the refusal is the
/// version, not trust.
#[test]
fn a_1_5_5_json_contract_plugin_is_refused_at_boot_naming_the_rebuild() {
    let release = key(1);
    for (kind, v155) in [("store", 2u32), ("auth", 2), ("hook", 1), ("export", 2)] {
        let dir = tmpdir(&format!("v155-{kind}"));
        let mut m = manifest(&format!("busbar-{kind}-published"), "published", "busbar");
        m.kind = kind.into();
        m.abi_version = v155;
        let m = sign(&release, m, b"published lib");
        write_tarball(&dir, "published.tar.gz", &m, b"published lib");

        let errs = scan_and_validate(&dir, &policy(&release))
            .expect_err("a 1.5.5 JSON-contract plugin must not load");
        assert_eq!(errs.len(), 1, "{kind}: one artifact, one refusal: {errs:?}");
        let e = &errs[0];
        assert!(
            e.contains("published.tar.gz"),
            "{kind}: names the file: {e}"
        );
        assert!(
            e.contains(&format!("'{kind}'")),
            "{kind}: names the kind: {e}"
        );
        assert!(
            e.contains(&format!("abi_version {v155} is not supported")),
            "{kind}: refused by the version, not trust: {e}"
        );
        assert!(
            e.contains("rebuild the plugin against the 1.6.0 SDK"),
            "{kind}: names the rebuild: {e}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A store artifact built for a NEWER schema than the host speaks is refused the same way.
#[test]
fn a_store_newer_than_the_host_is_refused() {
    let release = key(1);
    let dir = tmpdir("newer");
    let mut m = manifest("busbar-store-edge", "edge", "busbar");
    m.abi_version = busbar_contract::abi::store::ABI_VERSION + 1;
    let m = sign(&release, m, b"edge lib");
    write_tarball(&dir, "edge.tar.gz", &m, b"edge lib");

    let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
    assert_eq!(errs.len(), 1, "one artifact, one refusal: {errs:?}");
    assert!(
        errs[0].contains("edge.tar.gz"),
        "names the file: {}",
        errs[0]
    );
    assert!(
        errs[0].contains("rebuild the plugin against the 1.6.0 SDK"),
        "names the rebuild: {}",
        errs[0]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: "1.5.0".into(),
        publisher: publisher.into(),
        abi_version: busbar_contract::abi::store::ABI_VERSION,
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
        statement: None,
        former_names: Vec::new(),
    }
}

fn policy(first_party: &SigningKey) -> TrustPolicy {
    TrustPolicy {
        first_party_key: Some(first_party.verifying_key()),
        binary_version: "1.5.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
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
    let gamma = sign(
        &release,
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
        b"gamma lib",
    );
    let pg = sign(
        &release,
        manifest("busbar-store-alpha", "alpha", "busbar"),
        b"pg lib",
    );
    // Filenames lie on purpose - identity must come from the signed manifest.
    write_tarball(&dir, "totally-not-gamma.tar.gz", &gamma, b"gamma lib");
    write_tarball(&dir, "misc.tgz", &pg, b"pg lib");

    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    assert_eq!(reg.loadable().len(), 2);
    assert!(reg.resolve("gamma").is_some(), "alias resolves");
    assert!(
        reg.resolve("busbar-store-gamma-plugin").is_some(),
        "name resolves"
    );
    assert!(reg.resolve("alpha").is_some());
    assert_eq!(
        reg.resolve("gamma").unwrap().manifest.name,
        "busbar-store-gamma-plugin"
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
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
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
    let err = reg.store_door("dynamo").map(|_| ()).unwrap_err();
    assert!(err.contains("was not loaded"), "got {err}");
    assert!(err.contains("allowlist"), "carries the trust reason: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Phase 3: two loadable plugins claiming the same ALIAS is a hard error naming both - the
/// "can't use gamma and a third-party gamma" case (third-party allowed via opt-in).
#[test]
fn alias_conflict_is_a_hard_error_naming_both() {
    let release = key(1);
    let acme = key(2);
    let dir = tmpdir("conflict");
    let first = sign(
        &release,
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
        b"lib1",
    );
    let third = sign(
        &acme,
        manifest("acme-store-gamma", "gamma", "acme"),
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
        errs[0].contains("busbar-store-gamma-plugin"),
        "names first: {}",
        errs[0]
    );
    assert!(
        errs[0].contains("acme-store-gamma"),
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
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
        b"a",
    );
    let b = sign(
        &release,
        manifest("busbar-store-gamma-plugin", "valkey2", "busbar"),
        b"b",
    );
    write_tarball(&dir, "a.tar.gz", &a, b"a");
    write_tarball(&dir, "b.tar.gz", &b, b"b");
    let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("name conflict")),
        "got {errs:?}"
    );
    // The refusal reads byte for byte as 1.5.5's (the golden text is fixture data).
    let golden = include_str!("../../tests/fixtures/conflict_messages.txt")
        .lines()
        .find(|l| l.starts_with("plugin name conflict: "))
        .expect("the fixture carries the name-conflict line");
    let mut want = golden.to_string();
    for fill in ["busbar-store-gamma-plugin", "a.tar.gz", "b.tar.gz"] {
        want = want.replacen("{}", fill, 1);
    }
    assert!(errs.contains(&want), "want {want:?}, got {errs:?}");
    let _ = std::fs::remove_dir_all(&dir);

    // Alias colliding with another plugin's canonical name.
    let dir = tmpdir("aliasvsname");
    let a = sign(
        &release,
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
        b"a",
    );
    let b = sign(
        &release,
        manifest("acme-store-x", "busbar-store-gamma-plugin", "busbar"),
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
    m.abi_version = busbar_contract::abi::hook::ABI_VERSION;
    let m = sign(&release, m, b"hook lib");
    write_tarball(&dir, "hook.tar.gz", &m, b"hook lib");
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    let err = reg.store_door("ranker").map(|_| ()).unwrap_err();
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
    m.abi_version = busbar_contract::abi::secret::ABI_VERSION;
    let m = sign(&release, m, b"secret lib");
    write_tarball(&dir, "vault.tar.gz", &m, b"secret lib");
    // And a trusted store plugin beside it.
    let st = sign(
        &release,
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
        b"store lib",
    );
    write_tarball(&dir, "gamma.tar.gz", &st, b"store lib");
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan admits both kinds");
    assert_eq!(reg.loadable().len(), 2, "one secret + one store validated");
    // The kind gates: a store referenced as a secret module fails naming the kind...
    let err = reg.secret_refusal("gamma");
    assert!(err.contains("kind 'store'"), "got {err}");
    // ...and a secret plugin cannot back the store.
    let err = reg.store_door("vault").map(|_| ()).unwrap_err();
    assert!(err.contains("kind 'secret'"), "got {err}");
    // An unknown secret module name is fail-closed with the loadable set named.
    let err = reg.secret_refusal("nope");
    assert!(err.contains("no plugin named or aliased"), "got {err}");
    // A secret plugin that states no door (a 1.5.5 JSON-contract plugin) is refused naming the
    // rebuild: no JSON secret lane remains (THE DESIGN §11.8).
    let err = reg.secret_refusal("vault");
    assert!(
        err.contains(crate::registry::JSON_SECRET_REFUSED),
        "got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Kind gating: a non-auth plugin resolves but cannot serve as an auth module. Mirrors
/// `open_store_refuses_non_store_kind`: a store-kind manifest passes phase 1/2/3 (its default
/// `kind`/`abi_version` from `manifest()` are already store-admissible) and is then resolved as an
/// auth row, which must reject on the KIND gate before ever attempting to load it.
#[test]
fn open_auth_refuses_non_auth_kind() {
    let release = key(1);
    let dir = tmpdir("authkind");
    let m = sign(
        &release,
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
        b"store lib",
    );
    write_tarball(&dir, "gamma.tar.gz", &m, b"store lib");
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    let err = reg
        .resolve_kind("gamma", "auth", "serve as an auth module")
        .map(|_| ())
        .unwrap_err();
    assert!(err.contains("kind 'store'"), "got {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE AUTH REFUSAL, in the one kind-neutral mechanism ([`PluginRegistry::kind_refusal`]): a name
/// no auth row resolves to keeps the loader's resolution words (the ones the cold lane's
/// resolution gave), and a name that resolves to an auth row the auth axis still does not answer
/// (a row stating no auth door) is refused naming the rebuild. No 1.5.5 golden covers the second
/// case (1.5.5 loaded every resolved auth row), so its text is pinned here, byte for byte.
#[test]
fn the_auth_refusal_keeps_the_resolution_words_and_names_the_rebuild() {
    let release = key(1);
    let dir = tmpdir("authrefusal");
    let mut m = manifest("busbar-auth-idp-plugin", "idp", "busbar");
    m.kind = "auth".into();
    m.abi_version = busbar_contract::abi::auth::ABI_VERSION;
    let m = sign(&release, m, b"auth lib");
    write_tarball(&dir, "idp.tar.gz", &m, b"auth lib");
    let st = sign(
        &release,
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
        b"store lib",
    );
    write_tarball(&dir, "gamma.tar.gz", &st, b"store lib");
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan admits both kinds");
    let refusal = |name: &str| reg.kind_refusal("auth", "serve as an auth module", name);
    assert_eq!(
        refusal("gamma"),
        "plugin 'busbar-store-gamma-plugin' has kind 'store', not 'auth' - it cannot serve as an \
         auth module"
    );
    assert!(
        refusal("nope").starts_with("no plugin named or aliased 'nope' is available"),
        "got {}",
        refusal("nope")
    );
    assert_eq!(
        refusal("idp"),
        "plugin 'busbar-auth-idp-plugin': it speaks the 1.5.5 JSON auth contract, which this host \
         does not load — rebuild the plugin against the 1.6.0 SDK"
    );
    // The secret kind's words through the same mechanism are the ones it always gave.
    assert_eq!(
        reg.kind_refusal("secret", "resolve config secrets", "idp"),
        "plugin 'busbar-auth-idp-plugin' has kind 'auth', not 'secret' - it cannot resolve config \
         secrets"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Kind gating: a non-hook plugin resolves but cannot serve as a hook. Mirrors
/// `open_store_refuses_non_store_kind`: a store-kind manifest passes phase 1/2/3, and the hook axis
/// over the registry holds no row for it, so opening it as a hook is refused naming the module,
/// before anything is loaded.
#[test]
fn the_hook_axis_refuses_a_non_hook_kind() {
    use busbar_contract::hook_calls::HookAxis;
    let release = key(1);
    let dir = tmpdir("hookkind");
    let m = sign(
        &release,
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
        b"store lib",
    );
    write_tarball(&dir, "gamma.tar.gz", &m, b"store lib");
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    assert!(reg.resolve("gamma").is_some(), "the store row resolves");
    let dispatcher = std::sync::Arc::new(crate::dispatch::Dispatcher::new(
        crate::dispatch::DispatchConfig::default(),
    ));
    let rows = crate::hook_door::HookRows::new(&[], Some(&reg), dispatcher).expect("the axis");
    let err = rows
        .open(
            "gamma",
            "gamma",
            &serde_json::json!({}),
            std::time::Duration::from_secs(1),
        )
        .map(|_| ())
        .unwrap_err();
    assert!(
        err.contains("no `kind: hook` plugin answers to 'gamma'"),
        "got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The inventory marks the rows a conflict is ABOUT, and only those. The conflict message spells
/// plugin-author-controlled identifiers into prose, so a row is joined to it by the tarball the
/// conflict names — not by finding the row's own quoted identifier somewhere inside the sentence,
/// which a third plugin can arrange to be true of a conflict it has nothing to do with.
#[test]
fn a_conflict_marks_only_the_rows_it_names() {
    let release = key(1);
    let dir = tmpdir("conflictjoin");
    let a = sign(&release, manifest("dup", "alias-a", "busbar"), b"a");
    let b = sign(&release, manifest("dup", "alias-b", "busbar"), b"b");
    // A bystander that claims no identifier either conflicting plugin claims, so it is `ready`.
    let c = sign(&release, manifest("innocent", "vk", "busbar"), b"c");
    write_tarball(&dir, "a.tar.gz", &a, b"a");
    // The message spells the tarball's own name, and a tarball's name is whoever shipped it to
    // choose — so the prose can be made to contain any quoted identifier at all.
    write_tarball(&dir, "spells-'vk'-in-its-name.tar.gz", &b, b"b");
    write_tarball(&dir, "c.tar.gz", &c, b"c");

    let rows = inventory(&dir, &policy(&release));
    let by_file = |f: &str| rows.iter().find(|r| r.file == f).unwrap();
    assert!(
        by_file("a.tar.gz").status.starts_with("CONFLICT:"),
        "got {}",
        by_file("a.tar.gz").status
    );
    assert!(
        by_file("spells-'vk'-in-its-name.tar.gz")
            .status
            .starts_with("CONFLICT:"),
        "got {}",
        by_file("spells-'vk'-in-its-name.tar.gz").status
    );
    assert_eq!(
        by_file("c.tar.gz").status,
        "ready",
        "a bystander the message merely spells is not in conflict"
    );
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
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
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

/// First-party anti-downgrade in the pipeline is PER-NAME (floors-only — no automatic
/// binary-version floor, since first-party plugins version on independent 1.0.x/2.x lines):
/// a below-pin first-party plugin is REJECTED with the anti-downgrade reason (inventory shows
/// it; scan skips it), while the same artifact without a pin loads.
#[test]
fn first_party_downgrade_is_rejected_in_pipeline() {
    let release = key(1);
    let dir = tmpdir("downgrade");
    let mut m = manifest("busbar-store-gamma-plugin", "gamma", "busbar");
    m.version = "1.0.0".into();
    let m = sign(&release, m, b"old lib");
    write_tarball(&dir, "old.tar.gz", &m, b"old lib");

    // Unpinned: its 1.0.0 line is its own business — it loads.
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    assert!(
        reg.resolve("gamma").is_some(),
        "an unpinned first-party plugin loads regardless of the binary version"
    );

    // Pinned above its version: rejected with the anti-downgrade reason, end to end.
    let mut pinned = policy(&release);
    pinned
        .first_party_floors
        .insert("busbar-store-gamma-plugin".to_string(), "1.0.1".to_string());
    let reg = scan_and_validate(&dir, &pinned).expect("scan");
    assert!(reg.resolve("gamma").is_none());
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
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
        b"lib",
    );
    write_tarball(&dir, "gamma.tar.gz", &m, b"lib");

    let mut pol = policy(&release);
    pol.min_versions.insert(
        "busbar-store-gamma-plugin".to_string(),
        "v9.9.9".to_string(),
    );

    let reg = scan_and_validate(&dir, &pol).expect("scan must succeed — the boot is not killed");
    assert!(
        reg.resolve("gamma").is_none(),
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
        manifest("busbar-store-gamma-plugin", "gamma", "busbar"),
        b"lib",
    );
    write_tarball(&dir, "gamma.tar.gz", &m, b"lib");

    let mut pol = policy(&release);
    pol.min_versions.insert(
        "busbar-store-gamma-plugin".to_string(),
        "v9.9.9".to_string(),
    );

    let reg = scan_and_validate(&dir, &pol).expect("scan");
    let reason = reg
        .unresolved_reason("gamma")
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
        crate::sign::RejectKind::UnknownPublisher
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
        crate::sign::RejectKind::UntrustedFloored,
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

// ── The FIRST-PARTY replay, end to end over the real scan ──────────────────────────────────────

/// `docs/plugins.md` security-model item 3, proven through the actual pipeline: a deployment loads
/// 1.2.0 of a first-party plugin, the high-water mark records it, and the GENUINE busbar-signed
/// 1.0.0 an attacker with write access to `plugins.dir` swaps in is then REFUSED — even though its
/// signature verifies against the embedded release key. Before the mark existed this scan admitted
/// the replay silently, with a `first-party` catalog label and no warning.
#[test]
fn a_first_party_replay_is_refused_after_the_mark_records_the_newer_load() {
    let release = key(1);
    let dir = tmpdir("replay");

    // 1. The deployment loads 1.2.0.
    let mut current = manifest("busbar-store-gamma-plugin", "gamma", "busbar");
    current.version = "1.2.0".into();
    let current = sign(&release, current, b"1.2.0 lib");
    write_tarball(&dir, "store.tar.gz", &current, b"1.2.0 lib");

    let mut marks = crate::HighWaterMarks::load(None).0;
    let mut pol = policy(&release);
    pol.first_party_high_water = marks.marks();
    let reg = scan_and_validate(&dir, &pol).expect("the current release loads");
    assert_eq!(reg.loadable().len(), 1);

    // 2. The mark records what was actually loaded.
    assert!(marks.record_registry(&reg), "the mark rises on a load");
    assert_eq!(
        marks.marks().get("busbar-store-gamma-plugin").unwrap(),
        "1.2.0"
    );

    // 3. The attacker swaps in the GENUINE, busbar-signed 1.0.0 with a known fixed defect.
    let mut old = manifest("busbar-store-gamma-plugin", "gamma", "busbar");
    old.version = "1.0.0".into();
    let old = sign(&release, old, b"1.0.0 lib");
    write_tarball(&dir, "store.tar.gz", &old, b"1.0.0 lib");

    // 4. It is REFUSED as a downgrade — skipped, never loaded, with the floor named.
    let mut pol = policy(&release);
    pol.first_party_high_water = marks.marks();
    let reg = scan_and_validate(&dir, &pol).expect("a refusal is a skip, not a scan failure");
    assert!(
        reg.loadable().is_empty(),
        "the replayed artifact must not be loadable"
    );
    let skipped = reg.skipped();
    assert_eq!(skipped.len(), 1);
    assert!(
        skipped[0].reason.contains("1.2.0"),
        "the refusal names the floor: {}",
        skipped[0].reason
    );
    assert!(
        skipped[0].reason.contains("rollback"),
        "the refusal names the override: {}",
        skipped[0].reason
    );

    // 5. The mark does NOT fall to the refused artifact's version.
    assert!(!marks.record_registry(&reg));
    assert_eq!(
        marks.marks().get("busbar-store-gamma-plugin").unwrap(),
        "1.2.0"
    );

    // 6. The documented override: an explicit, audited rollback pin admits that exact version.
    pol.first_party_floors
        .insert("busbar-store-gamma-plugin".into(), "1.0.0".into());
    let reg = scan_and_validate(&dir, &pol).expect("scan");
    assert_eq!(
        reg.loadable().len(),
        1,
        "an explicit rollback pin admits the older artifact"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// TOCTOU-close: `read_file_capped` bounds the STREAM at `cap`, not `metadata().len()`. `examine`
/// used to size-check via `fs::metadata` then `fs::read` the file unbounded, so a file swapped for a
/// larger one AFTER the stat was read in full — the cap was bypassable. This proves the read itself is
/// bounded: a file one byte over the cap is a hard reject, `cap` bytes exactly reads, and a small file
/// reads back byte-for-byte. Exercised with a tiny cap so the test never allocates the real ceiling.
#[test]
fn read_file_capped_bounds_the_stream_not_the_stale_metadata() {
    let dir = tmpdir("capread");

    // Over the cap: 20 bytes against an 8-byte cap → refused (never a silent unbounded read).
    let big = dir.join("big.bin");
    std::fs::write(&big, vec![0u8; 20]).unwrap();
    let err = read_file_capped(&big, 8).expect_err("a file over the cap must be refused");
    assert!(err.contains("cap"), "the refusal names the cap: {err}");

    // Exactly at the cap boundary is allowed (cap bytes read; cap + 1 is the reject threshold).
    let exact = dir.join("exact.bin");
    std::fs::write(&exact, vec![7u8; 8]).unwrap();
    assert_eq!(read_file_capped(&exact, 8).unwrap(), vec![7u8; 8]);

    // A within-cap file reads back byte-for-byte.
    let small = dir.join("small.bin");
    std::fs::write(&small, b"hello").unwrap();
    assert_eq!(read_file_capped(&small, 8).unwrap(), b"hello");

    let _ = std::fs::remove_dir_all(&dir);
}

// ── FORMER NAMES (ARCHITECT ruling: 1.5.5 configs load UNCHANGED) ─────────────────────────────

/// A door a registry row carries but these tests never open.
extern "C" fn unopened_door() -> *const busbar_contract::abi::mechanism::door::Door {
    std::ptr::null()
}

/// The 1.6.0 manifest of a renamed plugin: `name` aliased `alias`, of `kind`, answering `former`.
fn renamed(kind: &str, name: &str, alias: &str, former: &[&str]) -> Manifest {
    let mut m = manifest(name, alias, "busbar");
    m.kind = kind.into();
    m.abi_version = supported_abi(kind)[0];
    m.former_names = former.iter().map(|s| s.to_string()).collect();
    m
}

/// The registry over `m` DROPPED IN (signed first-party into a fresh plugins dir and scanned).
fn dropped_in(tag: &str, m: Manifest) -> PluginRegistry {
    let release = key(1);
    let dir = tmpdir(tag);
    let lib = format!("{tag} lib");
    write_tarball(
        &dir,
        "plugin.tar.gz",
        &sign(&release, m, lib.as_bytes()),
        lib.as_bytes(),
    );
    let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
    let _ = std::fs::remove_dir_all(&dir);
    reg
}

/// The registry over `m` LINKED (the build's own row, no artifact).
fn linked_in(m: Manifest) -> PluginRegistry {
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(m, unopened_door)])
        .expect("the linked door admits the row")
}

/// THE RULING'S CASE: a 1.5.5-shaped config names a hook and a store by the manifest names their
/// 1.5.5-era releases carried (`busbar-webrequest`; a store's `busbar-store-<name>-plugin`, here a
/// neutral one — the fleet's real names are swept from plugins.yaml by
/// [`every_former_name_plugins_yaml_declares_resolves_both_ways`]); each resolves to the 1.6.0 plugin
/// of the kind the reference needs, DROPPED IN and LINKED alike — the resolution preflight's `require_plugin`, the
/// store door and the auth and export axes all read. RED ARM, in the same test: the same plugins
/// without their former names leave both references unresolved, which is the boot refusal 52 oracle
/// cells hit ("no plugin matching the hook reference 'busbar-webrequest'").
#[test]
fn a_1_5_5_name_resolves_to_the_1_6_0_plugin_dropped_in_and_linked() {
    let cases = [
        (
            "hook",
            "busbar-hook-webrequest",
            "webrequest",
            "busbar-webrequest",
        ),
        (
            "store",
            "busbar-store-alpha",
            "alpha",
            "busbar-store-alpha-plugin",
        ),
    ];
    for (kind, name, alias, old) in cases {
        let with = || renamed(kind, name, alias, &[old]);
        for (way, reg) in [
            ("dropped in", dropped_in(&format!("former-{alias}"), with())),
            ("linked", linked_in(with())),
        ] {
            let p = reg
                .resolve(old)
                .unwrap_or_else(|| panic!("{way}: '{old}' resolves"));
            assert_eq!(p.manifest.name, name, "{way}");
            assert!(reg.answers(old, kind), "{way}: '{old}' answers as a {kind}");
            assert!(reg.resolve(alias).is_some() && reg.resolve(name).is_some());
        }
        // RED ARM: no former name, no resolution.
        let without = || renamed(kind, name, alias, &[]);
        for (way, reg) in [
            (
                "dropped in",
                dropped_in(&format!("bare-{alias}"), without()),
            ),
            ("linked", linked_in(without())),
        ] {
            assert!(
                reg.resolve(old).is_none(),
                "{way}: '{old}' must not resolve"
            );
        }
    }
    // The store door opens through the same resolution (the store axis's lookup by config name).
    let reg = linked_in(renamed(
        "store",
        "busbar-store-alpha",
        "alpha",
        &["busbar-store-alpha-plugin"],
    ));
    let refusal = reg
        .store_door("busbar-store-alpha-plugin")
        .expect_err("a door row of a store is not the store kind's linked row");
    assert!(
        refusal.contains("busbar-store-alpha") && !refusal.contains("no plugin named"),
        "the former name resolved to the plugin: {refusal}"
    );
}

/// PHASE 3: two dropped-in plugins claiming ONE former name, or a former name that is another
/// plugin's name or alias, are a hard error naming both plugins and the contested name.
#[test]
fn two_plugins_claiming_one_former_name_are_refused() {
    let release = key(1);
    let mut pol = policy(&release);
    pol.allow_third_party = true;
    let acme = key(2);
    for (second, contested) in [
        (
            renamed("hook", "acme-hook-x", "x", &["busbar-webrequest"]),
            "busbar-webrequest",
        ),
        (
            renamed("hook", "busbar-webrequest", "y", &[]),
            "busbar-webrequest",
        ),
        (
            renamed("hook", "acme-hook-z", "busbar-webrequest", &[]),
            "busbar-webrequest",
        ),
        (
            renamed("hook", "acme-hook-w", "w", &["webrequest"]),
            "webrequest",
        ),
    ] {
        let dir = tmpdir("former-conflict");
        let first = sign(
            &release,
            renamed(
                "hook",
                "busbar-hook-webrequest",
                "webrequest",
                &["busbar-webrequest"],
            ),
            b"lib1",
        );
        let mut second = second;
        second.publisher = "acme".into();
        let other = second.name.clone();
        write_tarball(&dir, "first.tar.gz", &first, b"lib1");
        write_tarball(
            &dir,
            "second.tar.gz",
            &sign(&acme, second, b"lib2"),
            b"lib2",
        );
        let errs = scan_and_validate(&dir, &pol).unwrap_err();
        let all = errs.join("\n");
        assert!(
            all.contains(&format!("'{contested}'"))
                && all.contains("busbar-hook-webrequest")
                && all.contains(&other),
            "{all}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// THE ONE-OWNER RULE ACROSS THE DOORS (ARCHITECT Q-P4-12, BUSBAR-1.6.0.md:106): a linked row and
/// any DIFFERENT plugin claiming one name, alias or former name refuse the boot, naming both and the
/// word; neither door outranks the other. The SAME plugin linked and dropped in is not a claim
/// conflict (the one-version-per-kind rule governs it).
#[test]
fn a_linked_and_another_plugin_claiming_one_name_are_refused() {
    let webrequest = || {
        renamed(
            "hook",
            "busbar-hook-webrequest",
            "webrequest",
            &["busbar-webrequest"],
        )
    };
    // RED: the 1.5.5 tarball (manifest name `busbar-webrequest`) dropped in beside a linked 1.6.0
    // webrequest that answers that name.
    let old = renamed("hook", "busbar-webrequest", "webrequest-1-5-5", &[]);
    let refused = dropped_in("cross-old", old)
        .link(vec![LinkedPlugin::door(webrequest(), unopened_door)])
        .expect_err("a linked row and a dropped-in plugin claiming one name are refused");
    assert!(
        refused.contains("'busbar-webrequest'")
            && refused.contains("busbar-hook-webrequest")
            && refused.contains("claim conflict"),
        "{refused}"
    );
    // RED: two linked rows claiming one alias.
    let refused = PluginRegistry::empty()
        .link(vec![
            LinkedPlugin::door(webrequest(), unopened_door),
            LinkedPlugin::door(
                renamed("hook", "acme-hook-x", "busbar-webrequest", &[]),
                unopened_door,
            ),
        ])
        .expect_err("two linked rows claiming one word are refused");
    assert!(
        refused.contains("'busbar-webrequest'") && refused.contains("acme-hook-x"),
        "{refused}"
    );
    // GREEN: the linked row and its own dropped-in copy; the linked row answers.
    let reg = dropped_in("cross-same", stating(webrequest(), None))
        .link(vec![LinkedPlugin::door(webrequest(), versioned_door)])
        .expect("the same plugin linked and dropped in is not a conflict");
    assert!(reg.resolve("busbar-webrequest").expect("resolves").linked());
    // RED (Q-P4-12): a different dropped-in plugin spelling the linked row's ALIAS, or its NAME.
    for (tag, other) in [
        (
            "cross-alias",
            renamed("hook", "acme-hook-y", "webrequest", &[]),
        ),
        (
            "cross-name",
            renamed("hook", "acme-hook-z", "busbar-hook-webrequest", &[]),
        ),
    ] {
        let refused = dropped_in(tag, other)
            .link(vec![LinkedPlugin::door(webrequest(), unopened_door)])
            .expect_err("no door outranks the other");
        assert!(
            refused.contains("claim conflict") && refused.contains("busbar-hook-webrequest"),
            "{tag}: {refused}"
        );
    }
}

/// A linked door whose Statement states a version: the store both-ways fixture's.
#[allow(non_upper_case_globals)]
const versioned_door: busbar_contract::abi::mechanism::door::DoorFn =
    crate::both_ways::store_fixture::door;

/// The version [`versioned_door`]'s Statement states.
fn door_version() -> String {
    let stated = crate::dispatch::rendering_of(versioned_door).expect("the door states itself");
    busbar_contract::abi::mechanism::rendering::read(&stated)
        .expect("reads")
        .version
}

/// `rendering` with its Statement's version restated as `version` (the rendering's head is the
/// magic, four `u32`s, then the name and the version, each a `u32` length and its bytes).
fn restated(rendering: &[u8], version: &str) -> Vec<u8> {
    let head = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 16;
    let len = |at: usize| u32::from_le_bytes(rendering[at..at + 4].try_into().unwrap()) as usize;
    let at = head + 4 + len(head);
    let mut out = rendering[..at].to_vec();
    out.extend_from_slice(&(version.len() as u32).to_le_bytes());
    out.extend_from_slice(version.as_bytes());
    out.extend_from_slice(&rendering[at + 4 + len(at)..]);
    out
}

/// `m` stating [`versioned_door`]'s Statement in its manifest, its version restated as `version`
/// (`None`: the door's own).
fn stating(m: Manifest, version: Option<&str>) -> Manifest {
    let stated = crate::dispatch::rendering_of(versioned_door).expect("the door states itself");
    let stated = version.map_or(stated.clone(), |v| restated(&stated, v));
    Manifest {
        statement: Some(hex::encode(stated)),
        ..m
    }
}

/// `webrequest`'s 1.6.0 manifest at `version`.
fn webrequest_at(version: &str) -> Manifest {
    let mut m = renamed(
        "hook",
        "busbar-hook-webrequest",
        "webrequest",
        &["busbar-webrequest"],
    );
    m.version = version.into();
    m
}

/// THE ONE-VERSION RULE, SAME VERSION (ARCHITECT C'): one plugin linked and dropped in at ONE
/// version — the version each door's Statement states — is ONE plugin, admitted once: the linked
/// row serves every name, the dropped-in copy is no row of its own, and it is recorded for boot's
/// one INFO line naming both doors and the version. The manifests' own `version`s differ on
/// purpose: they are never compared. RED before: the copy stayed a second loadable row.
#[test]
fn one_plugin_by_both_doors_at_one_version_is_admitted_once() {
    let version = door_version();
    let reg = dropped_in("copy-same", stating(webrequest_at("9.9.9"), None))
        .link(vec![LinkedPlugin::door(
            webrequest_at("1.5.0"),
            versioned_door,
        )])
        .expect("one plugin at one version is admitted");
    assert!(reg.loadable().is_empty(), "the copy is no row of its own");
    for word in ["busbar-hook-webrequest", "webrequest", "busbar-webrequest"] {
        assert!(
            reg.resolve(word).expect("resolves").linked(),
            "{word}: the linked row serves"
        );
    }
    assert_eq!(
        reg.linked_copies(),
        &[LinkedCopy {
            name: "busbar-hook-webrequest".into(),
            version: version.clone(),
            file: "plugin.tar.gz".into(),
        }]
    );
    assert_eq!(
        reg.linked_copies()[0].line(),
        format!(
            "plugin 'busbar-hook-webrequest' v{version} is linked and also dropped in \
             (plugin.tar.gz); the linked build serves it"
        )
    );
}

/// THE ONE-VERSION RULE, TWO VERSIONS: the same plugin linked and dropped in, its Statements stating
/// two versions, refuses the boot, naming the plugin, both doors and both versions. RED before: the
/// pair was skipped and the linked row silently won.
#[test]
fn one_plugin_by_both_doors_at_two_versions_refuses_the_boot() {
    let refused = dropped_in("copy-other", stating(webrequest_at("1.5.0"), Some("1.6.1")))
        .link(vec![LinkedPlugin::door(
            webrequest_at("1.5.0"),
            versioned_door,
        )])
        .expect_err("two versions of one plugin");
    assert_eq!(
        refused,
        format!(
            "plugin 'busbar-hook-webrequest' arrives by both doors at two versions: linked v{}, \
             dropped in v1.6.1 (plugin.tar.gz) - one version per plugin: remove one",
            door_version()
        )
    );
}

/// TRUST BEFORE IDENTITY: an UNSIGNED copy of a linked plugin at another version is SKIPPED by the
/// trust phase before the one-version rule ever compares it — the boot is not refused for a
/// tarball that was never admitted, and the skip names it.
#[test]
fn an_untrusted_copy_is_skipped_before_its_version_is_compared() {
    let release = key(1);
    let dir = tmpdir("copy-unsigned");
    let mut m = stating(webrequest_at("1.5.0"), Some("1.6.1"));
    m.sha256 = crate::sign::sha256_hex(b"unsigned lib");
    write_tarball(&dir, "plugin.tar.gz", &m, b"unsigned lib");
    let reg = scan_and_validate(&dir, &policy(&release))
        .expect("scan")
        .link(vec![LinkedPlugin::door(
            webrequest_at("1.5.0"),
            versioned_door,
        )])
        .expect("an untrusted tarball is skipped, not compared");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(reg.skipped().len(), 1, "the unsigned copy is skipped");
    assert!(reg.linked_copies().is_empty() && reg.loadable().is_empty());
}

/// THE VERSION COMPARED IS THE STATEMENT'S, AND ONLY THE STATEMENT'S (ARCHITECT C', 2026-10-07): a
/// plugin that reaches the one-version compare stating no version in a Statement is REFUSED, naming
/// it — a dropped-in copy whose manifest states no Statement (its manifest `version` is never read
/// in its place, even when it equals the linked plugin's), one stating an empty version, and a
/// linked row whose door states none. The build's store under its canonical name and a copy
/// stating the store door's own Statement are one plugin at one version.
#[test]
fn the_one_version_rule_compares_statement_versions_only() {
    let door = crate::both_ways::store_fixture::door;
    let linked = || {
        vec![LinkedPlugin::store_named(
            "busbar-store-mem",
            "mem",
            door,
            true,
        )]
    };
    let m = || {
        let mut m = manifest("busbar-store-mem", "mem", "busbar");
        m.version = door_version();
        m
    };
    let reg = dropped_in("copy-stated", stating(m(), None))
        .link(linked())
        .expect("one plugin at the version both doors state");
    assert_eq!(reg.linked_copies()[0].version, door_version());
    let refusal = "plugin 'busbar-store-mem' states no version in its Statement: the one-version \
                   rule cannot compare it";
    for (tag, copy) in [
        ("copy-unstated", m()),
        ("copy-empty", stating(m(), Some(""))),
    ] {
        let refused = dropped_in(tag, copy)
            .link(linked())
            .expect_err("a copy stating no version cannot be compared");
        assert_eq!(refused, refusal, "{tag}");
    }
    let refused = dropped_in("copy-unopened", stating(m(), None))
        .link(vec![LinkedPlugin::door_of_kind(
            "store",
            "busbar-store-mem",
            unopened_door,
        )])
        .expect_err("a linked row whose door states nothing cannot be compared");
    assert_eq!(refused, refusal);
}

/// THE LINKED BUILT-IN UNDER ITS CANONICAL NAME (ARCHITECT C'): a store or auth row the root names
/// canonically answers to that name AND to its key, and every surface that printed the key before
/// still prints it ([`LoadablePlugin::key`]): the claim conflict, a row of the wrong kind
/// (`resolve_kind`'s words, which `appbuild` and the axes print), a store with no door. A
/// dropped-in row prints its manifest name.
#[test]
fn a_linked_built_in_answers_its_canonical_name_and_prints_its_key() {
    let door = crate::both_ways::store_fixture::door;
    let reg = PluginRegistry::empty()
        .link(vec![
            LinkedPlugin::store_named("busbar-store-mem", "mem", door, true),
            LinkedPlugin::auth_door_named("busbar-auth-tok", "tok", unopened_door),
        ])
        .expect("the rows register");
    for (word, key) in [
        ("busbar-store-mem", "mem"),
        ("mem", "mem"),
        ("busbar-auth-tok", "tok"),
        ("tok", "tok"),
    ] {
        let p = reg.resolve(word).expect("resolves");
        assert_eq!(p.key(), key, "{word}");
    }
    assert!(reg.store_door("busbar-store-mem").is_ok() && reg.store_door("mem").is_ok());
    // A row of another kind: the key, as before (`store.module` naming the auth row).
    assert_eq!(
        reg.store_door("busbar-auth-tok").err().as_deref(),
        Some("plugin 'tok' has kind 'auth', not 'store' - it cannot back the governance store")
    );
    assert_eq!(
        reg.secret_refusal("tok"),
        "plugin 'tok' has kind 'auth', not 'secret' - it cannot resolve config secrets"
    );
    // The claim conflict: a different dropped-in plugin spelling the store's key.
    let refused = dropped_in("key-claim", manifest("busbar-store-other", "mem", "busbar"))
        .link(vec![LinkedPlugin::store_named(
            "busbar-store-mem",
            "mem",
            door,
            true,
        )])
        .expect_err("two plugins claim `mem`");
    assert_eq!(
        refused,
        "plugin claim conflict: 'mem' is claimed by both (linked) (mem) and plugin.tar.gz \
         (busbar-store-other) - a name, alias or former name must resolve to one plugin; remove one"
    );
    // A row the root does not name canonically prints its name, as before.
    let plain = PluginRegistry::empty()
        .link(vec![LinkedPlugin::store("plain", door, true)])
        .expect("registers");
    assert_eq!(plain.resolve("plain").expect("resolves").key(), "plain");
}

/// The fleet's plugins.yaml entries, as `(repo, kind, alias, former_names)`: the four fields this
/// sweep reads, off the registry's own flat shape (`  - repo:` opens an entry).
fn fleet_entries(yaml: &str) -> Vec<(String, String, String, Vec<String>)> {
    let mut out: Vec<(String, String, String, Vec<String>)> = Vec::new();
    for line in yaml.lines() {
        if let Some(repo) = line.strip_prefix("  - repo: ") {
            out.push((repo.trim().into(), String::new(), String::new(), Vec::new()));
            continue;
        }
        let Some(e) = out.last_mut() else { continue };
        let Some(field) = line.strip_prefix("    ") else {
            continue;
        };
        if let Some(v) = field.strip_prefix("kind: ") {
            e.1 = v.trim().into();
        } else if let Some(v) = field.strip_prefix("alias: ") {
            e.2 = v.trim().into();
        } else if let Some(v) = field.strip_prefix("former_names: ") {
            e.3 = v
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
                .map(|w| w.trim().to_string())
                .filter(|w| !w.is_empty())
                .collect();
        }
    }
    out
}

/// EVERY former name the committed plugins.yaml declares (the measured 1.5.5 manifest names of the
/// renamed fleet plugins) resolves to its 1.6.0 plugin, of its kind, dropped in and linked: the
/// ruling's case over the real data a 1.5.5 config names (`busbar-webrequest` under hooks, a store's
/// `busbar-store-<name>-plugin` under `store.module`). A kind the linked door does not serve is
/// checked dropped in only.
#[test]
fn every_former_name_plugins_yaml_declares_resolves_both_ways() {
    let entries = fleet_entries(include_str!("../../../../plugins.yaml"));
    let renamed_entries: Vec<_> = entries.iter().filter(|e| !e.3.is_empty()).collect();
    assert!(renamed_entries.len() >= 9, "{renamed_entries:?}");
    for (repo, kind, alias, former) in renamed_entries {
        let former: Vec<&str> = former.iter().map(String::as_str).collect();
        let m = || renamed(kind, repo, alias, &former);
        let mut ways = vec![("dropped in", dropped_in(&format!("sweep-{alias}"), m()))];
        if LINKED_KINDS.contains(&kind.as_str()) {
            ways.push(("linked", linked_in(m())));
        }
        for (way, reg) in ways {
            for old in &former {
                let p = reg
                    .resolve(old)
                    .unwrap_or_else(|| panic!("{way}: {repo}'s former name '{old}' resolves"));
                assert_eq!(&p.manifest.name, repo, "{way}");
                assert!(reg.answers(old, kind), "{way}: '{old}' answers as a {kind}");
            }
        }
    }
}
