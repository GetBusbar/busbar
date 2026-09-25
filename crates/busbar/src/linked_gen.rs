// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE LINKED-TABLE GENERATOR, shared VERBATIM between `build.rs` (which `include!`s this file and
// writes `$OUT_DIR/linked.rs` with it) and tests/composition_root_names_no_linked_plugin.rs (which
// includes it to read the same tables and to assert what it decides). Plain and dependency-free,
// because a build script has no dependencies to lean on.
//
// The composition root names no plugin. Which plugins a build links is DATA in `Cargo.toml`:
//
//   [package.metadata.busbar.linked]        <cargo feature> = "<plugin crate>"   (registration order)
//   [package.metadata.busbar.linked-axes]   <cargo feature> = "<axis> <axis> …"  (what it registers)
//   [package.metadata.busbar.linked-entry]  "<plugin crate>" = "<entry module>"  (when the entry is
//                                            not `<crate>::linked`: its kernel-typed half lives in
//                                            the root)
//   [package.metadata.busbar.root-units]    <cargo feature> = "<root module>"    (`ROOT_UNIT` of
//                                            `crate::root::<module>`, in order)
//
// and this turns the rows whose feature is ENABLED into `extern crate <crate> as _;` lines, one table
// per registration axis over each entry module's item for that axis (the `LINKED` value), the cfgs
// of the root-bound seams some enabled entry drives, and the `ROOT_UNITS` table. It is the same shape
// as the test-seam table `busbar-core-admin`'s build script emits (`metadata_list` + `linked_table`
// there); a build script may not read another crate's source (kind-isolation `build-script-reach`),
// so the two are written in each crate rather than shared by a path that climbs out of one of them.

/// A registration axis: its manifest name, the `LINKED` field it fills, and the entry item a crate
/// that registers on it exports. The plane axis is the one exception, built below (two items, joined),
/// and its HOT lane (`hot-plane`: the entry's `#[repr(C)]` `PLANE_DECL`, referenced) beside it.
pub(crate) const AXES: &[(&str, &str, &str)] = &[
    ("protocols", "protocols", "PROTOCOLS"),
    ("path-ingress", "path_ingress", "PATH_INGRESS"),
    ("body-ingress", "body_ingress", "BODY_INGRESS"),
    ("protocol-seams", "protocol_seams", "install_protocol_seams"),
    ("diagnostics", "diagnostics", "DIAGNOSTICS"),
    ("ws-arrivals", "ws_arrivals", "install_ws_arrivals"),
    ("on-host", "on_host", "on_host"),
    ("compose", "compose", "compose"),
    ("stdio-serve", "stdio_serve", "stdio_serve"),
    ("exports", "exports", "EXPORT"),
    // The unified kernel loop (#28): the key a plane is flipped onto its one-shot or session runner
    // under — its declaration's key, so these two rows ride on `plane` (refused without it).
    (
        "gauntlet-one-shot",
        "gauntlet_one_shot",
        "PLANE_DECLARATION.key",
    ),
    (
        "gauntlet-session",
        "gauntlet_session",
        "PLANE_DECLARATION.key",
    ),
];

/// The root-bound seams: an axis a crate DRIVES rather than fills, emitted as a cfg the root binds
/// the seam under (the kernel compiles some of them only when a plane that drives them is linked).
pub(crate) const SEAMS: &[(&str, &str)] = &[
    ("egress", "linked_egress"),
    ("plane-sections", "linked_plane_sections"),
    ("admin-envelope", "linked_admin_envelope"),
];

/// The `key = "value"` rows of the `[table]` header of a Cargo manifest, in file order. Deliberately
/// not a TOML parser: one row per line, both sides optionally double-quoted. An absent or empty
/// table is a build failure, never an empty list — an empty list would silently register nothing.
pub(crate) fn metadata_map(manifest: &str, table: &str) -> Vec<(String, String)> {
    let header = format!("[{table}]");
    let mut in_table = false;
    let mut rows = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == header;
            continue;
        }
        if !in_table {
            continue;
        }
        if let Some((key, value)) = code.split_once('=') {
            rows.push((
                key.trim().trim_matches('"').to_string(),
                value.trim().trim_matches('"').to_string(),
            ));
        }
    }
    assert!(
        !rows.is_empty(),
        "Cargo.toml: `{header}` is missing or empty"
    );
    rows
}

/// The feature names the manifest's `[features]` table declares.
pub(crate) fn declared_features(manifest: &str) -> Vec<String> {
    let mut in_table = false;
    let mut out = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == "[features]";
            continue;
        }
        if in_table {
            if let Some((key, _)) = code.split_once('=') {
                out.push(key.trim().to_string());
            }
        }
    }
    out
}

/// `busbar-foo` → `busbar_foo`.
pub(crate) fn ident(krate: &str) -> String {
    krate.replace('-', "_")
}

/// Every cfg name this generator can emit, for the build script's `rustc-check-cfg` line.
pub(crate) fn seam_cfgs() -> Vec<&'static str> {
    SEAMS.iter().map(|(_, cfg)| *cfg).collect()
}

/// THE GENERATED SOURCE, and the seam cfgs to set, for the rows whose feature `enabled` answers
/// true. Every table keeps manifest order. A feature the manifest does not declare, a linked feature
/// with no axes row, an axis nobody knows and an axes/entry row for nothing linked are all refused:
/// each would drop a registration out of every build silently.
pub(crate) fn linked_source(
    manifest: &str,
    enabled: &dyn Fn(&str) -> bool,
) -> (String, Vec<&'static str>) {
    let features = declared_features(manifest);
    let plugins = metadata_map(manifest, "package.metadata.busbar.linked");
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let entries = metadata_map(manifest, "package.metadata.busbar.linked-entry");
    let units = metadata_map(manifest, "package.metadata.busbar.root-units");
    for (feature, _) in plugins.iter().chain(&units) {
        assert!(
            features.contains(feature),
            "Cargo.toml: linked feature `{feature}` is not declared under [features]"
        );
    }
    for (feature, _) in &axes {
        assert!(
            plugins.iter().any(|(f, _)| f == feature),
            "Cargo.toml: `{feature}` has a linked-axes row but no linked row"
        );
    }
    for (krate, _) in &entries {
        assert!(
            plugins.iter().any(|(_, k)| k == krate),
            "Cargo.toml: `{krate}` has a linked-entry row but no linked row"
        );
    }
    let axes_of = |feature: &str, krate: &str| -> Vec<String> {
        let row = axes.iter().find(|(f, _)| f == feature).unwrap_or_else(|| {
            panic!("Cargo.toml: linked feature `{feature}` ({krate}) has no linked-axes row")
        });
        let list: Vec<String> = row.1.split_whitespace().map(str::to_string).collect();
        for axis in &list {
            assert!(
                axis == "plane"
                    || axis == "hot-plane"
                    || AXES.iter().any(|(a, _, _)| a == axis)
                    || SEAMS.iter().any(|(a, _)| a == axis),
                "Cargo.toml: `{krate}` names an unknown linked axis `{axis}`"
            );
        }
        let gauntlet = list.iter().filter(|a| a.starts_with("gauntlet-")).count();
        assert!(
            gauntlet == 0 || (gauntlet == 1 && list.iter().any(|a| a == "plane")),
            "Cargo.toml: `{krate}` rides the kernel loop on one gauntlet axis, beside `plane`"
        );
        list
    };

    let on: Vec<&(String, String)> = plugins.iter().filter(|(f, _)| enabled(f)).collect();
    let mut out =
        String::from("// @generated by build.rs from Cargo.toml metadata (src/linked_gen.rs).\n");
    for (_, krate) in &on {
        out.push_str(&format!("extern crate {} as _;\n", ident(krate)));
    }
    // (entry module, axes) per enabled crate, in manifest order.
    let linked: Vec<(String, Vec<String>)> = on
        .iter()
        .map(|(feature, krate)| {
            let entry = entries
                .iter()
                .find(|(k, _)| k == krate)
                .map(|(_, path)| path.clone())
                .unwrap_or_else(|| format!("{}::linked", ident(krate)));
            (entry, axes_of(feature, krate))
        })
        .collect();
    let on_axis = |axis: &str| -> Vec<&String> {
        linked
            .iter()
            .filter(|(_, a)| a.iter().any(|x| x == axis))
            .map(|(e, _)| e)
            .collect()
    };

    let planes = on_axis("plane");
    out.push_str(&format!(
        "/// The plane axis: each entry's contract declaration joined kernel-side to its hooks.\n\
         static LINKED_PLANES: [busbar_kernel::plane::registry::PlaneDecl; {}] = [\n",
        planes.len()
    ));
    for e in &planes {
        out.push_str(&format!(
            "    busbar_kernel::plane::registry::PlaneDecl::assemble({e}::PLANE_DECLARATION, \
             {e}::PLANE_HOOKS),\n"
        ));
    }
    out.push_str("];\n");
    out.push_str(
        "/// Every linked plugin's entry items, one table per registration axis, in manifest order.\n\
         static LINKED: crate::root::linked::Linked = crate::root::linked::Linked {\n    \
         planes: &LINKED_PLANES,\n",
    );
    out.push_str("    hot_planes: &[");
    for e in on_axis("hot-plane") {
        out.push_str(&format!("&{e}::PLANE_DECL, "));
    }
    out.push_str("],\n");
    for (axis, field, item) in AXES {
        out.push_str(&format!("    {field}: &["));
        for e in on_axis(axis) {
            out.push_str(&format!("{e}::{item}, "));
        }
        out.push_str("],\n");
    }
    out.push_str("};\n");
    // Test builds only: each gauntlet row's declaration key beside the key its plane's gauntlet asks
    // the host-selection seam for (`<crate>::PLANE_KEY`), so the flip is proven to land where the
    // plane looks.
    out.push_str(
        "/// Each kernel-loop row's (declaration key, key its gauntlet asks its runner under).\n\
         #[cfg(test)]\n\
         static LINKED_GAUNTLET_ASKS: &[(&str, &str)] = &[\n",
    );
    for ((entry, list), (_, krate)) in linked.iter().zip(&on) {
        if list.iter().any(|a| a.starts_with("gauntlet-")) {
            out.push_str(&format!(
                "    ({entry}::PLANE_DECLARATION.key, {}::PLANE_KEY),\n",
                ident(krate)
            ));
        }
    }
    out.push_str("];\n");

    out.push_str(
        "/// Every enabled root unit, in manifest order.\n\
         static ROOT_UNITS: &[&crate::root::linked::RootUnit] = &[\n",
    );
    for (_, module) in units.iter().filter(|(f, _)| enabled(f)) {
        out.push_str(&format!("    &crate::root::{module}::ROOT_UNIT,\n"));
    }
    out.push_str("];\n");

    let cfgs = SEAMS
        .iter()
        .filter(|(axis, _)| !on_axis(axis).is_empty())
        .map(|(_, cfg)| *cfg)
        .collect();
    (out, cfgs)
}
