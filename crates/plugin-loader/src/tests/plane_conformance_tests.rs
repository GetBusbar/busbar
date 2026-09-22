// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DROP-IN CONFORMANCE for `kind: plane` — the plane analogue of the store example's over-the-ABI
//! round trips (`DECISIONS #2/#11/#26 S4`: a plugin is a plugin, both-ways for EVERY kind incl. plane).
//!
//! `busbar-plane-example` is a `["cdylib", "rlib"]` crate, so these tests hold BOTH forms of the SAME
//! plane at once: the COMPILED-IN reference (`busbar_plane_example::PLANE_DECL`, linked via the rlib)
//! and the DROPPED-IN artifact (the `cdylib` on disk, loaded through [`crate::load_plane`] over the
//! HOT-tier ABI). The first test proves the two decls are byte-identical at the vocabulary / carrier /
//! preamble surface — "loads identically compiled-in vs dropped-in". The second drives the dropped-in
//! plane end to end (build → hydrate → start → dispatch) to prove it is a LIVE plane, not just a decl.

use busbar_plugin::hot::pod::StatusClass;
use busbar_plugin::hot::{EmitHandle, InboundHandle, IngressCarrier, PlaneHostVtable, WorkItem};
use busbar_plugin_example_plane::PLANE_DECL as COMPILED_IN;
use crate::sign::{sha256_hex, sign, Manifest, SigningKey, TrustPolicy};

/// Locate the REAL `busbar-plane-example` cdylib built into this workspace's target dir (uplifted or
/// under `deps`, newest wins). Mirrors `store_example_plugin_path()` in `lib_tests.rs`.
fn plane_example_cdylib() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = crate::plugin_library_filename("busbar_plugin_example_plane");
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
            "the plane example plugin cdylib is not built under CI: `cargo test --workspace` must \
             build busbar_plane_example (checked both the uplifted target dir and target/deps). \
             Refusing to silently skip the ONLY both-ways proof for kind:plane."
        );
    }
    candidate
}

/// Read one borrowed vocabulary range from the COMPILED-IN decl into an owned string (the same shape
/// `wire_up_plane` materialises the dropped-in side to, so the two are directly comparable).
fn vocab(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    // SAFETY: the const's vocabulary points at this crate's own `'static` byte strings.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).unwrap().to_string()
}

/// The dropped-in decl the loader reads is byte-identical to the compiled-in `PLANE_DECL` at the
/// vocabulary / carrier surface — a plane loads the SAME whether compiled in or dropped in.
#[test]
fn example_plane_loads_identically_compiled_in_and_dropped_in() {
    let Some(lib) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let dropped = crate::load_plane(&lib).expect("load the example plane over the HOT-tier ABI");

    assert_eq!(
        dropped.name(),
        vocab(COMPILED_IN.name_ptr, COMPILED_IN.name_len)
    );
    assert_eq!(
        dropped.section_key(),
        vocab(COMPILED_IN.section_key_ptr, COMPILED_IN.section_key_len)
    );
    assert_eq!(
        dropped.scope(),
        vocab(COMPILED_IN.scope_ptr, COMPILED_IN.scope_len)
    );
    assert_eq!(
        dropped.label(),
        vocab(COMPILED_IN.label_ptr, COMPILED_IN.label_len)
    );
    assert_eq!(dropped.provided_carriers(), COMPILED_IN.provided_carriers);
    // The wired carrier the example declares.
    assert!(dropped.provides(IngressCarrier::RequestResponse));
    assert!(!dropped.provides(IngressCarrier::DuplexSession));
    // Non-empty vocabulary — a decl that lost its name/section-key at the crossing would fail here.
    assert_eq!(dropped.name(), "example");
    assert_eq!(dropped.section_key(), "example");
}

/// The dropped-in plane is a LIVE plane: config_validate → build → hydrate → start → dispatch all
/// cross the ABI and return `Ok`, driven with an EMPTY host vtable (the example calls back into none
/// of its slots, so `PlaneHostVtable::EMPTY` is a sound host for the round trip).
#[test]
fn dropped_in_example_plane_builds_hydrates_starts_and_dispatches() {
    let Some(lib) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let plane = crate::load_plane(&lib).expect("load the example plane");

    // config_validate produces a parsed handle; free it.
    let (cv_status, parsed) = plane.config_validate(b"{}");
    assert_eq!(cv_status, StatusClass::Ok);
    if let Some(p) = parsed {
        if let Some(free) = p.free {
            free(p.ptr);
        }
    }

    // build with an EMPTY host vtable + null host ctx (the example never calls a host slot).
    let host = PlaneHostVtable::EMPTY;
    let host_ptr: *const PlaneHostVtable = &host;
    // SAFETY: `host_ptr` is a live EMPTY vtable that outlives this call; the example plane does not
    // dereference `host_ctx`.
    let (build_status, handle) =
        unsafe { plane.build(host_ptr, busbar_plugin::hot::host::HostCtx::NULL, b"{}", &[]) };
    assert_eq!(build_status, StatusClass::Ok);
    let handle = handle.expect("build yields an opaque plane handle on Ok");
    assert!(!handle.ptr.is_null());

    // hydrate + start + dispatch drive the built state across the seam.
    // SAFETY: `handle.ptr` is the live state `build` just produced.
    assert_eq!(unsafe { plane.hydrate(handle.ptr) }, StatusClass::Ok);
    assert_eq!(unsafe { plane.start(handle.ptr) }, StatusClass::Ok);

    let inbound_bytes = b"ping";
    let work = WorkItem::new(
        InboundHandle::finite_buffer(inbound_bytes),
        EmitHandle::absent(),
    );
    // SAFETY: as above; `inbound_bytes` outlives the dispatch call.
    assert_eq!(
        unsafe { plane.dispatch(handle.ptr, &work) },
        StatusClass::Ok
    );

    // Free the plane's state through its own `free` fn (the config-swap path core would take).
    if let Some(free) = handle.free {
        free(handle.ptr);
    }
}

/// A plane that declares a vocabulary length far larger than its real buffer must be REFUSED at load,
/// never sliced: `read_vocab` reads each `*_len` verbatim from the (third-party) decl, so an
/// unbounded `from_raw_parts` would over-read past the real allocation — an OOB read in the HOST's
/// address space. Exercises `read_vocab` directly with the hostile short-buffer/huge-length shape.
#[test]
fn oversize_plane_vocab_length_is_refused_not_over_read() {
    use busbar_plugin::hot::PlaneDecl;
    use busbar_plugin::AbiPreamble;

    // A one-byte real buffer paired with a length past the cap — the hostile shape a lying decl uses.
    let small = b"x";
    let decl = PlaneDecl {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<PlaneDecl>() as u32,
        version: busbar_plugin::ABI_MINOR,
        name_ptr: small.as_ptr(),
        name_len: super::MAX_PLANE_VOCAB_LEN + 1,
        section_key_ptr: core::ptr::null(),
        section_key_len: 0,
        scope_ptr: core::ptr::null(),
        scope_len: 0,
        label_ptr: core::ptr::null(),
        label_len: 0,
        provided_carriers: 0,
        _reserved: 0,
        config_validate: None,
        build: None,
        hydrate: None,
        start: None,
        admin_routes: None,
        openapi: None,
        dispatch: None,
    };
    let honoured = busbar_plugin::honoured_size(decl.size, core::mem::size_of::<PlaneDecl>());
    let decl_ptr: *const PlaneDecl = &decl;
    let err = super::read_vocab(decl_ptr, honoured, super::Vocab::Name, "hostile")
        .expect_err("an oversize vocabulary length must be refused, never sliced");
    assert!(
        err.contains("exceeding") && err.contains(&super::MAX_PLANE_VOCAB_LEN.to_string()),
        "expected a cap-refusal naming the limit, got: {err}"
    );

    // A within-cap vocabulary still reads back correctly — the fix is a cap, not a blanket refusal.
    let ok = PlaneDecl {
        name_len: small.len(),
        ..decl
    };
    let ok_ptr: *const PlaneDecl = &ok;
    let name = super::read_vocab(ok_ptr, honoured, super::Vocab::Name, "ok")
        .expect("a within-cap vocabulary reads back");
    assert_eq!(name, "x");
}

// ── SIGNED DROP-IN over the FULL registry pipeline (DECISIONS #26 S4, #55/#70/#75 posture A) ─────
//
// The tests above drive `crate::load_plane` on a bare path — the operator-placed, inherently-trusted
// case. These prove the OTHER half of #11's both-ways contract for `kind: plane`: a plane cdylib
// packaged into a SIGNED tarball rides the EXACT same three-phase discovery/trust/conflict pipeline
// as the five cold kinds (`scan_and_validate` → `PluginRegistry::open_plane`), and posture A holds —
// signed first-party loads by default; unsigned/third-party is REFUSED unless an admin opts in.

/// A `kind: plane` manifest for the example plane, with `abi_version` on the airlock-minor axis
/// `supported_abi("plane")` gates against (`[1, ABI_MINOR]`). `sha256`/`signature` are filled by the
/// caller (via `sign`, or by hand for the unsigned case).
fn plane_manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "plane".into(),
        version: "1.6.0".into(),
        publisher: publisher.into(),
        abi_version: busbar_plugin::ABI_MINOR,
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

/// The DEFAULT posture-A policy: a first-party release key is held; NO unsigned/third-party opt-in.
fn first_party_only_policy(release: &SigningKey) -> TrustPolicy {
    TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    }
}

fn plane_tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-plane-trust-{}-{tag}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_plane_tarball(dir: &std::path::Path, file: &str, m: &Manifest, lib: &[u8]) {
    let bytes = crate::tarball::package(m, "libbusbar_plugin_example_plane.so", lib).unwrap();
    std::fs::write(dir.join(file), bytes).unwrap();
}

/// Drive an opened `DynPlane` end to end (config_validate → build → hydrate → start → dispatch),
/// asserting every hop returns `Ok` — proves the handle the registry produced is a LIVE plane, not
/// merely a decl that resolved. Mirrors `dropped_in_example_plane_builds_hydrates_starts_and_dispatches`.
fn drive_opened_plane(plane: &crate::DynPlane) {
    let (cv_status, parsed) = plane.config_validate(b"{}");
    assert_eq!(cv_status, StatusClass::Ok);
    if let Some(p) = parsed {
        if let Some(free) = p.free {
            free(p.ptr);
        }
    }
    let host = PlaneHostVtable::EMPTY;
    let host_ptr: *const PlaneHostVtable = &host;
    // SAFETY: EMPTY vtable outlives the call; the example plane derefs no host slot / host_ctx.
    let (build_status, handle) =
        unsafe { plane.build(host_ptr, busbar_plugin::hot::host::HostCtx::NULL, b"{}", &[]) };
    assert_eq!(build_status, StatusClass::Ok);
    let handle = handle.expect("build yields an opaque plane handle on Ok");
    // SAFETY: `handle.ptr` is the live state `build` just produced.
    assert_eq!(unsafe { plane.hydrate(handle.ptr) }, StatusClass::Ok);
    assert_eq!(unsafe { plane.start(handle.ptr) }, StatusClass::Ok);
    let inbound = b"ping";
    let work = WorkItem::new(InboundHandle::finite_buffer(inbound), EmitHandle::absent());
    // SAFETY: as above; `inbound` outlives the dispatch.
    assert_eq!(
        unsafe { plane.dispatch(handle.ptr, &work) },
        StatusClass::Ok
    );
    if let Some(free) = handle.free {
        free(handle.ptr);
    }
}

/// THE GREEN PROOF for W1.d: package the REAL example-plane cdylib into a SIGNED FIRST-PARTY tarball,
/// run the full three-phase pipeline, resolve by ALIAS, and `open_plane` a LIVE `DynPlane` — the exact
/// seam the composition root sees, indistinguishable from a compiled-in plane. The plane analogue of
/// `end_to_end_open_store_from_signed_tarball`.
#[test]
fn end_to_end_open_plane_from_signed_first_party_tarball() {
    let Some(path) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).expect("read the example-plane cdylib");
    let release = SigningKey::from_bytes(&[1u8; 32]);
    let dir = plane_tmpdir("e2e-first-party");
    let m = sign(
        &release,
        plane_manifest("busbar-plane-example", "example-plane", "busbar"),
        &lib,
    );
    // Filename deliberately unrelated — identity comes from the signed manifest, never the file.
    write_plane_tarball(&dir, "totally-not-a-plane.tar.gz", &m, &lib);

    let reg = crate::registry::scan_and_validate(&dir, &first_party_only_policy(&release))
        .expect("a signed first-party plane must scan cleanly");
    assert_eq!(reg.loadable().len(), 1, "the signed plane is loadable");
    assert!(reg.skipped().is_empty(), "nothing skipped: {reg:?}");

    // Resolves by BOTH alias and canonical name, from the manifest.
    let plane = reg
        .open_plane("example-plane")
        .expect("open the signed plane over the HOT-tier ABI through the registry");
    assert_eq!(plane.name(), "example");
    assert_eq!(plane.section_key(), "example");
    assert!(plane.provides(IngressCarrier::RequestResponse));
    drive_opened_plane(&plane);

    // The canonical name resolves to the same loadable plane too.
    assert!(reg.open_plane("busbar-plane-example").is_ok());

    let _ = std::fs::remove_dir_all(&dir);
}

/// POSTURE A, unsigned lever: an UNSIGNED plane (valid sha256, empty signature) is REFUSED by default
/// — skipped, never `dlopen`ed, and `open_plane` fails loud with the trust reason — but the SAME
/// artifact loads and drives once an admin sets `allow_unsigned` (DECISIONS #55/#70/#75).
#[test]
fn unsigned_plane_refused_by_default_accepted_under_allow_unsigned() {
    let Some(path) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).expect("read the example-plane cdylib");
    let release = SigningKey::from_bytes(&[1u8; 32]);
    let dir = plane_tmpdir("unsigned");
    let mut m = plane_manifest("busbar-plane-example", "example-plane", "busbar");
    m.sha256 = sha256_hex(&lib); // structurally valid…
    m.signature = String::new(); // …but UNSIGNED.
    write_plane_tarball(&dir, "unsigned.tar.gz", &m, &lib);

    // Default posture: refused (skipped); referencing it fails loud with the opt-in named.
    let reg = crate::registry::scan_and_validate(&dir, &first_party_only_policy(&release))
        .expect("an unsigned artifact is a SKIP, not a scan failure");
    assert!(reg.loadable().is_empty(), "unsigned must not be loadable");
    assert_eq!(reg.skipped().len(), 1);
    let err = reg.open_plane("example-plane").map(|_| ()).unwrap_err();
    assert!(err.contains("was not loaded"), "got {err}");
    assert!(err.contains("allow_unsigned"), "names the opt-in: {err}");

    // Admin opt-in: allow_unsigned makes the exact same artifact loadable and drivable.
    let mut pol = first_party_only_policy(&release);
    pol.allow_unsigned = true;
    let reg = crate::registry::scan_and_validate(&dir, &pol).expect("scan");
    assert_eq!(reg.loadable().len(), 1, "allow_unsigned admits it");
    let plane = reg
        .open_plane("example-plane")
        .expect("the unsigned plane loads once explicitly permitted");
    drive_opened_plane(&plane);

    let _ = std::fs::remove_dir_all(&dir);
}

/// POSTURE A, third-party lever: a plane VALIDLY signed by a NON-first-party publisher is REFUSED by
/// default (unknown publisher, not allowlisted) — skipped, `open_plane` fails loud — but loads and
/// drives once an admin sets `allow_third_party` (DECISIONS #55/#70/#75).
#[test]
fn third_party_plane_refused_by_default_accepted_under_allow_third_party() {
    let Some(path) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).expect("read the example-plane cdylib");
    let release = SigningKey::from_bytes(&[1u8; 32]);
    let acme = SigningKey::from_bytes(&[2u8; 32]); // a NON-first-party publisher key
    let dir = plane_tmpdir("third-party");
    let m = sign(
        &acme,
        plane_manifest("acme-plane-widget", "widget", "acme"),
        &lib,
    );
    write_plane_tarball(&dir, "acme.tar.gz", &m, &lib);

    // Default posture: refused as an unknown publisher; the opt-in is named.
    let reg = crate::registry::scan_and_validate(&dir, &first_party_only_policy(&release))
        .expect("a third-party artifact is a SKIP, not a scan failure");
    assert!(
        reg.loadable().is_empty(),
        "third-party must not be loadable"
    );
    let err = reg.open_plane("widget").map(|_| ()).unwrap_err();
    assert!(err.contains("was not loaded"), "got {err}");
    assert!(err.contains("allow_third_party"), "names the opt-in: {err}");

    // Admin opt-in: allow_third_party admits it; it loads and drives.
    let mut pol = first_party_only_policy(&release);
    pol.allow_third_party = true;
    let reg = crate::registry::scan_and_validate(&dir, &pol).expect("scan");
    assert_eq!(reg.loadable().len(), 1, "allow_third_party admits it");
    let plane = reg
        .open_plane("widget")
        .expect("the third-party plane loads once explicitly permitted");
    drive_opened_plane(&plane);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kind gating over the pipeline: a signed NON-plane artifact resolves but cannot serve as a plane —
/// `open_plane` rejects on the KIND gate before ever attempting the HOT-ABI load. Mirrors
/// `open_store_refuses_non_store_kind`.
#[test]
fn open_plane_refuses_non_plane_kind() {
    let release = SigningKey::from_bytes(&[1u8; 32]);
    let dir = plane_tmpdir("kind-gate");
    let mut m = plane_manifest("busbar-store-valkey-plugin", "valkey", "busbar");
    m.kind = "store".into();
    m.abi_version = busbar_plugin::cold::ABI_VERSION; // store-admissible so the KIND gate is what fires
    let m = sign(&release, m, b"store lib");
    write_plane_tarball(&dir, "store.tar.gz", &m, b"store lib");

    let reg =
        crate::registry::scan_and_validate(&dir, &first_party_only_policy(&release)).expect("scan");
    let err = reg.open_plane("valkey").map(|_| ()).unwrap_err();
    assert!(
        err.contains("kind 'store'") && err.contains("not 'plane'"),
        "the kind gate must fire before any load: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `supported_abi("plane")` gates a plane's manifest `abi_version` against the airlock-minor axis.
#[test]
fn plane_supported_abi_covers_the_airlock_minor() {
    let range = crate::registry::supported_abi("plane");
    assert_eq!(range, &[1, busbar_plugin::ABI_MINOR]);
    // The five cold kinds still resolve; an unknown kind is still empty.
    assert!(!crate::registry::supported_abi("store").is_empty());
    assert!(crate::registry::supported_abi("nonsense").is_empty());
}
