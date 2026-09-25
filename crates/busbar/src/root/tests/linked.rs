// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE PLANE, BOTH DOORS, ONE ROW** — #2 rule (1) on the plane axis, at the composition root.
//!
//! `busbar-plugin-example-plane` is a `["cdylib", "rlib"]` crate, so this binary holds the SAME plane
//! two ways at once: LINKED (its `PLANE_DECL`, through the rlib, in [`Linked::hot_planes`]) and
//! DROPPED IN (its cdylib, packaged into a signed tarball in a temp `plugins/` directory and found by
//! [`dropped_planes`], the scan boot runs over the configured `plugins.dir`). Each arm is folded by
//! [`plane_rows`] — the rows [`register_planes`] installs — and then by the kernel's own boot fold
//! (`merged_boot_plane_decls`: ordering, same-key skip, claim guard). The arms must agree byte for
//! byte on every row: the contract declaration, every hook, the claims and admission a row answers,
//! and the order.
//!
//! This is the loader's `plane_conformance_tests` (which compares the two DECLS) carried one layer
//! up, to the thing a deployment actually gets from a plane: its registry row.
//!
//! ## Red-before-green, PERMANENTLY
//!
//! [`the_boot_that_does_not_hand_the_dropped_in_planes_over_diverges`] is the RED arm and it stays:
//! it replays the boot before this change — `register_planes(&LINKED)`, the dropped-in plane never
//! handed to the axis — and shows the two builds disagreeing. If the two doors ever stop meeting in
//! one function, the equality tests below go red for the same reason that arm is unequal.

use super::*;
use busbar_kernel::plane::registry::{merged_boot_plane_decls, BuildCtx};
use busbar_plugin_example_plane::PLANE_DECL as LINKED_DECL;
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};

/// The linked example plane, as the build table carries it.
static LINKED_HOT: [&HotPlaneDecl; 1] = [&LINKED_DECL];

/// A table with the given plane rows and HOT-lane planes and nothing on any other axis.
fn linked(planes: &'static [PlaneDecl], hot_planes: &'static [&'static HotPlaneDecl]) -> Linked {
    Linked {
        planes,
        hot_planes,
        protocols: &[],
        path_ingress: &[],
        body_ingress: &[],
        protocol_seams: &[],
        diagnostics: &[],
        ws_arrivals: &[],
        on_host: &[],
        compose: &[],
        stdio_serve: &[],
    }
}

/// A Rust-hook plane row keyed `key` (declaring section `key`), leaked for the table.
fn native(key: &'static str) -> &'static [PlaneDecl] {
    let declaration = PlaneDeclaration {
        key,
        fallback: false,
        config_section: key,
        scope_kinds: &[],
        subject_noun: key,
        admin_noun: key,
        audit_kind: key,
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
    };
    let hooks = PlaneHooks {
        wire_format_names: || &[busbar_kernel::plane::WIRE_HTTP_JSON],
        ..HOT_PLANE_HOOKS
    };
    Box::leak(Box::new([PlaneDecl::assemble(declaration, hooks)]))
}

/// EVERYTHING a registry row answers, as one line: the contract declaration, the wire formats, what
/// its claims / admission / build hooks answer, and which optional hooks it carries.
fn render(row: &PlaneDecl) -> String {
    let ctx = BuildCtx {
        endpoint_slot: None,
        agent_defs: &(),
        public_url: None,
        prior: None,
    };
    let optional = [
        row.routes.is_some(),
        row.admin_routes.is_some(),
        row.openapi.is_some(),
        row.hydrate.is_some(),
        row.start.is_some(),
        row.config_validate.is_some(),
        row.named_def_list.is_some(),
        row.named_def_get.is_some(),
        row.registry_contains.is_some(),
        row.reresolve_gates.is_some(),
        row.openapi_schemas.is_some(),
        row.on_swap.is_some(),
        row.parse_section.is_some(),
        row.parse_endpoint.is_some(),
        row.lower_endpoint.is_some(),
        row.build_runtime.is_some(),
        row.viewer.is_some(),
        row.retain_verify_gates.is_some(),
        row.default_section.is_some(),
        row.resolve_provider.is_some(),
    ];
    format!(
        "{:?} wire={:?} claims={:?} admission={:?} build={} hooks={optional:?}",
        row.declaration,
        (row.wire_format_names)(),
        (row.claims)(&()),
        (row.admission)(&()),
        (row.build)(&ctx).is_some(),
    )
}

/// The installed rows after the kernel's boot fold, rendered in fold order.
fn folded(rows: Vec<&'static PlaneDecl>) -> Vec<String> {
    merged_boot_plane_decls(&rows, &[])
        .into_iter()
        .map(render)
        .collect()
}

/// The example plane's cdylib in this target dir (uplifted or under `deps`, newest wins). Under CI a
/// missing artifact is a failure, never a skip: this is the plane axis's both-doors proof.
fn cdylib() -> Option<std::path::PathBuf> {
    let found = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_plugin_example_plane");
        [profile.join(&name), profile.join("deps").join(&name)]
            .into_iter()
            .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
            .max()
            .map(|(_, p)| p)
    })();
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the example plane cdylib is not built under CI; the both-doors proof must not skip"
    );
    found
}

/// A fresh `plugins/` directory holding the example plane's cdylib as a SIGNED first-party tarball,
/// and the default trust posture that admits it (the release key held, no opt-ins).
fn plugins_dir(tag: &str, lib: &[u8]) -> (std::path::PathBuf, TrustPolicy) {
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-dropped-plane-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let release = SigningKey::from_bytes(&[7u8; 32]);
    let manifest = Manifest {
        name: "busbar-plugin-example-plane".into(),
        alias: "example-plane".into(),
        kind: "plane".into(),
        version: "1.6.0".into(),
        publisher: "busbar".into(),
        abi_version: 1,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    let signed = sign(&release, manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libplane.so", lib).unwrap();
    std::fs::write(dir.join("example-plane.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    (dir, policy)
}

/// The example plane dropped into a fresh `plugins/` directory and found by the boot scan.
fn dropped(tag: &str) -> Option<Vec<DynPlane>> {
    let lib = std::fs::read(cdylib()?).expect("read the example plane cdylib");
    let (dir, policy) = plugins_dir(tag, &lib);
    let planes = dropped_planes(&dir, &policy).expect("the signed plane loads");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(planes.len(), 1, "the scan finds the one dropped-in plane");
    Some(planes)
}

/// THE EXIT TEST. Linked or dropped in, the example plane installs the same row — same declaration,
/// same hooks, same claims — in the same slot, behind a Rust-hook plane that was linked ahead of it.
#[test]
fn a_linked_and_a_dropped_in_plane_install_byte_identical_rows() {
    let Some(dropped) = dropped("equal") else {
        eprintln!("skip: example plane cdylib not built");
        return;
    };
    let ahead = native("neutral");
    let linked_arm = folded(plane_rows(&linked(ahead, &LINKED_HOT), Vec::new()).unwrap());
    let dropped_arm = folded(plane_rows(&linked(ahead, &[]), dropped).unwrap());
    assert_eq!(
        linked_arm, dropped_arm,
        "the two doors installed different rows"
    );

    // Not vacuous: the plane's row is there, after the linked row, and says what the plane declares.
    let plane = busbar_plugin_loader::link_plane(&LINKED_DECL, "reference").unwrap();
    assert_eq!(linked_arm.len(), 2, "{linked_arm:#?}");
    assert!(
        linked_arm[0].contains("key: \"neutral\""),
        "{linked_arm:#?}"
    );
    for fact in [
        format!("key: {:?}", plane.name()),
        format!("config_section: {:?}", plane.section_key()),
        format!("scope_kinds: [{:?}]", plane.scope()),
    ] {
        assert!(
            linked_arm[1].contains(&fact),
            "{fact} not in {}",
            linked_arm[1]
        );
    }
}

/// THE SAME REFUSAL, BOTH DOORS: a plane whose key a linked plane already holds is skipped by the
/// boot fold, whichever door it came in by — the linked holder keeps the slot either way.
#[test]
fn a_plane_whose_key_is_taken_is_skipped_the_same_way_by_either_door() {
    let Some(dropped) = dropped("taken") else {
        eprintln!("skip: example plane cdylib not built");
        return;
    };
    let key = busbar_plugin_loader::link_plane(&LINKED_DECL, "reference")
        .unwrap()
        .name()
        .to_string();
    let holder = native(Box::leak(key.into_boxed_str()));
    let linked_arm = folded(plane_rows(&linked(holder, &LINKED_HOT), Vec::new()).unwrap());
    let dropped_arm = folded(plane_rows(&linked(holder, &[]), dropped).unwrap());
    assert_eq!(linked_arm, dropped_arm);
    assert_eq!(
        linked_arm,
        folded(holder.iter().collect()),
        "the holder keeps the slot"
    );
}

/// THE SAME ADMISSION, BOTH DOORS: a plane declaration that names no plane is refused before it is
/// installed, and the refusal is the one function's — the linked door gives it too.
#[test]
fn a_plane_that_names_nothing_is_refused_at_the_linked_door_too() {
    let nameless: &'static HotPlaneDecl = Box::leak(Box::new(HotPlaneDecl {
        abi: LINKED_DECL.abi,
        size: LINKED_DECL.size,
        version: LINKED_DECL.version,
        name_ptr: LINKED_DECL.name_ptr,
        name_len: 0,
        section_key_ptr: LINKED_DECL.section_key_ptr,
        section_key_len: LINKED_DECL.section_key_len,
        scope_ptr: LINKED_DECL.scope_ptr,
        scope_len: LINKED_DECL.scope_len,
        label_ptr: LINKED_DECL.label_ptr,
        label_len: LINKED_DECL.label_len,
        provided_carriers: LINKED_DECL.provided_carriers,
        _reserved: 0,
        config_validate: LINKED_DECL.config_validate,
        build: LINKED_DECL.build,
        hydrate: LINKED_DECL.hydrate,
        start: LINKED_DECL.start,
        admin_routes: LINKED_DECL.admin_routes,
        openapi: LINKED_DECL.openapi,
        dispatch: LINKED_DECL.dispatch,
    }));
    let table: &'static [&'static HotPlaneDecl] = Box::leak(Box::new([nameless]));
    let refusal = plane_rows(&linked(&[], table), Vec::new())
        .map(|_| ())
        .unwrap_err();
    assert!(refusal.contains("declares no name"), "{refusal}");
}

/// THE TRUST GATE HOLDS ON THIS DOOR: the same plane, unsigned, under the default posture is skipped
/// by the scan and never loaded — no plane reaches the axis.
#[test]
fn an_untrusted_dropped_in_plane_reaches_no_row() {
    let Some(path) = cdylib() else {
        eprintln!("skip: example plane cdylib not built");
        return;
    };
    let lib = std::fs::read(path).unwrap();
    let (dir, mut policy) = plugins_dir("untrusted", &lib);
    policy.first_party_key = Some(SigningKey::from_bytes(&[9u8; 32]).verifying_key());
    let planes = dropped_planes(&dir, &policy).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(planes.is_empty(), "an untrusted plane was loaded");
}

/// **THE RED ARM — the boot before the dropped-in door met the axis, kept as the witness.** K1's
/// `register_planes(&LINKED)` installed the linked tables only; a plane dropped into `plugins/` was
/// loadable and never handed over. Replayed here, the two builds install different planes.
#[test]
fn the_boot_that_does_not_hand_the_dropped_in_planes_over_diverges() {
    let Some(dropped) = dropped("red") else {
        eprintln!("skip: example plane cdylib not built");
        return;
    };
    let linked_arm = folded(plane_rows(&linked(&[], &LINKED_HOT), Vec::new()).unwrap());
    drop(dropped);
    let bypassed_arm = folded(plane_rows(&linked(&[], &[]), Vec::new()).unwrap());
    assert_ne!(
        linked_arm, bypassed_arm,
        "a boot that drops the dropped-in planes must install a different axis"
    );
}
