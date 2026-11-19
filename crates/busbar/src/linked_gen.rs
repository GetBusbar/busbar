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
//   [package.metadata.busbar.linked]        <cargo feature> = "<plugin crate>"   (registration order;
//                                            a row whose crate is a NON-OPTIONAL dependency is linked
//                                            in every build and its key only names the row)
//   [package.metadata.busbar.linked-axes]   <row key> = "<axis> <axis> …"        (what it registers)
//   [package.metadata.busbar.linked-entry]  "<plugin crate>" or <row key> = "<entry module>" (when
//                                            the entry is not `<crate>::linked`: its kernel-typed
//                                            half lives in the root, or one crate carries several
//                                            rows)
//   [package.metadata.busbar.root-units]    <cargo feature> = "<root module>"    (`ROOT_UNIT` of
//                                            `crate::root::<module>`, in order; the row keyed
//                                            `node` is the node's own unit, in every build)
//   [package.metadata.busbar.linked-name]   <row key> = "<registry key>"         (the key an `auths`
//                                            row answers on the auth axis, and every surface prints;
//                                            for a `hooks` row, the name the admin surface prints)
//   [package.metadata.busbar.linked-canonical] <row key> = "<manifest name>"     (an `auths` row's
//                                            CANONICAL name, when it is not its key: the manifest
//                                            name its signed tarball states, plugins.yaml
//                                            `manifest_name`; config may name the row by either)
//   [package.metadata.busbar.carriers]      <carrier> = "<row key>"              (which linked MIN-3
//                                            image carries each outbound carrier: `http`, `grpc`,
//                                            `websocket`, `rtc`; see [`carrier_rows`])
//   [package.metadata.busbar.installed-carriers] <carrier> = "<image identity>"  (a carrier supplied
//                                            by a separately installed transport image, when it is
//                                            installed; see [`installed_carrier_rows`])
//
// and this turns the rows whose feature is ENABLED into `extern crate <crate> as _;` lines, one table
// per registration axis over each entry module's item for that axis (the `LINKED` value), the cfgs
// of the root-bound seams some enabled entry drives, and the `ROOT_UNITS` table. The composition root
// is the one crate that generates a linked table: no cleanliness crate has a build script that names
// a plugin, and their tests link the kernel's kind-neutral doubles instead.

pub const NODE_UNIT: &str = "node";

pub const AXES: &[(&str, &str, &str)] = &[
    ("protocols", "protocols", "PROTOCOLS"),
    ("protocol-seams", "protocol_seams", "install_protocol_seams"),
    ("diagnostics", "diagnostics", "DIAGNOSTICS"),
    ("on-host", "on_host", "on_host"),
    ("compose", "compose", "compose"),
];

const CLAIMS_AXIS: &str = "claims";

const MIN3_AXIS: &str = "min3-images";

/// The axes of the old plugin interface (each linked a crate's memory-ABI `door`), retired with it: a
/// row still on one is a manifest that predates the cut, refused rather than silently dropped. Every
/// plugin links as a MIN-3 image on `min3-images`.
pub const RETIRED_AXES: &[&str] = &[
    "stores",
    "transport",
    "transport-door",
    "plane-door",
    "export-doors",
    "auths",
];

/// The manifest table that assigns the outbound carriers.
pub const CARRIERS_TABLE: &str = "package.metadata.busbar.carriers";

/// Each key of [`CARRIERS_TABLE`] and the carrier constant it names (`busbar_plugin_abi::plane`). The child-process
/// carrier is core's own and has no key.
pub const CARRIER_KEYS: &[(&str, &str)] = &[
    ("http", "CARRIER_HTTP"),
    ("grpc", "CARRIER_GRPC"),
    ("websocket", "CARRIER_WEBSOCKET"),
    ("rtc", "CARRIER_RTC"),
];

/// THE CARRIER TABLE: `(key, carrier constant, row key)` for each row of [`CARRIERS_TABLE`], in manifest order. The
/// build's assignment of the one image that carries each outbound carrier, stated in packaging (as
/// `operator-auth` states the operator credential's row) so the root's source names no transport. Refused: an
/// unknown key, a key stated twice, a value that is not a `linked` row on the `min3-images` axis (only an admitted
/// image has a header to admit), and one row under two keys (one image frames one carrier). No table: no carrier
/// is assigned.
///
/// A value names the row by its key or by its package (`rtc = "busbar-transport-webrtc"`); the package spelling is
/// the one a build that excludes the plugin finds and drops with the plugin's other rows (the FIPS repository's
/// `ci/exclude-plugins.sh` deletes a row naming `busbar-<package>`). The returned row is always the key.
pub fn carrier_rows(manifest: &str) -> Vec<(String, &'static str, String)> {
    let plugins = metadata_map(manifest, "package.metadata.busbar.linked");
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let mut out: Vec<(String, &'static str, String)> = Vec::new();
    for (key, named) in metadata_map(manifest, CARRIERS_TABLE) {
        let row = plugins
            .iter()
            .find(|(feature, krate)| *feature == named || *krate == named)
            .map_or(named, |(feature, _)| feature.clone());
        let constant = CARRIER_KEYS
            .iter()
            .find(|(word, _)| *word == key)
            .map(|(_, constant)| *constant)
            .unwrap_or_else(|| {
                panic!(
                    "Cargo.toml: `[{CARRIERS_TABLE}]` names an unknown carrier `{key}` (the carriers are \
                     `http`, `grpc`, `websocket`, `rtc`)"
                )
            });
        assert!(
            !out.iter().any(|(k, _, _)| *k == key),
            "Cargo.toml: `[{CARRIERS_TABLE}]` states the carrier `{key}` twice"
        );
        let on_min3 = plugins.iter().any(|(feature, _)| *feature == row)
            && axes.iter().any(|(feature, list)| {
                *feature == row && list.split_whitespace().any(|axis| axis == MIN3_AXIS)
            });
        assert!(
            on_min3,
            "Cargo.toml: carrier `{key}` names `{row}`, which is not a linked row on the `{MIN3_AXIS}` axis"
        );
        if let Some((other, _, _)) = out.iter().find(|(_, _, r)| *r == row) {
            panic!(
                "Cargo.toml: `{row}` is named for two carriers, `{other}` and `{key}`: one image frames one carrier"
            );
        }
        out.push((key, constant, row));
    }
    out
}

/// The manifest table that assigns an outbound carrier to a SEPARATELY INSTALLED transport image (owner ruling:
/// former built-ins such as the websocket transport are separate plugins this distribution does not link).
pub const INSTALLED_CARRIERS_TABLE: &str = "package.metadata.busbar.installed-carriers";

/// THE INSTALLED CARRIER TABLE: `(key, carrier constant, image identity)` for each row of
/// [`INSTALLED_CARRIERS_TABLE`], in manifest order. The value is the identity (the stamp name, its package name)
/// of a transport image the deployment installs beside the binary, never a linked row: the carrier is supplied
/// exactly when an admitted image of that identity is installed, and has no supplier otherwise. Refused: an
/// unknown key, a key stated twice, an empty identity, a value that names a linked row (a linked image is
/// assigned in [`CARRIERS_TABLE`]), a carrier [`CARRIERS_TABLE`] also assigns, and one identity under two keys
/// (one image frames one carrier).
pub fn installed_carrier_rows(manifest: &str) -> Vec<(String, &'static str, String)> {
    let plugins = metadata_map(manifest, "package.metadata.busbar.linked");
    let linked = carrier_rows(manifest);
    let mut out: Vec<(String, &'static str, String)> = Vec::new();
    for (key, identity) in metadata_map(manifest, INSTALLED_CARRIERS_TABLE) {
        let constant = CARRIER_KEYS
            .iter()
            .find(|(word, _)| *word == key)
            .map(|(_, constant)| *constant)
            .unwrap_or_else(|| {
                panic!(
                    "Cargo.toml: `[{INSTALLED_CARRIERS_TABLE}]` names an unknown carrier `{key}` (the carriers \
                     are `http`, `grpc`, `websocket`, `rtc`)"
                )
            });
        assert!(
            !out.iter().any(|(k, _, _)| *k == key),
            "Cargo.toml: `[{INSTALLED_CARRIERS_TABLE}]` states the carrier `{key}` twice"
        );
        assert!(
            !identity.is_empty(),
            "Cargo.toml: `[{INSTALLED_CARRIERS_TABLE}]` carrier `{key}` names no image"
        );
        assert!(
            !plugins
                .iter()
                .any(|(feature, krate)| *feature == identity || *krate == identity),
            "Cargo.toml: installed carrier `{key}` names `{identity}`, a linked row: assign it in `[{CARRIERS_TABLE}]`"
        );
        assert!(
            !linked.iter().any(|(k, _, _)| *k == key),
            "Cargo.toml: carrier `{key}` is assigned in both `[{CARRIERS_TABLE}]` and `[{INSTALLED_CARRIERS_TABLE}]`"
        );
        if let Some((other, _, _)) = out.iter().find(|(_, _, named)| *named == identity) {
            panic!(
                "Cargo.toml: `{identity}` is named for two carriers, `{other}` and `{key}`: one image frames one carrier"
            );
        }
        out.push((key, constant, identity));
    }
    out
}

pub fn metadata_value(manifest: &str, table: &str, key: &str) -> Option<String> {
    let header = format!("[{table}]");
    let mut in_table = false;
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == header;
            continue;
        }
        if let (true, Some((k, v))) = (in_table, code.split_once('=')) {
            if k.trim().trim_matches('"') == key {
                return Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

pub const SEAMS: &[(&str, &str)] = &[("egress", "linked_egress")];

include!("manifest_rows.rs");

pub fn declared_features(manifest: &str) -> Vec<String> {
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

pub fn required_deps(manifest: &str) -> Vec<String> {
    let mut in_table = false;
    let mut out = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == "[dependencies]";
            continue;
        }
        if let (true, Some((krate, spec))) = (in_table, code.split_once('=')) {
            if !spec.replace(' ', "").contains("optional=true") {
                out.push(krate.trim().to_string());
            }
        }
    }
    out
}

pub fn ident(krate: &str) -> String {
    krate.replace('-', "_")
}

/// The axes whose `linked_axis_<axis>` cfg a build declares (the composition root's sources gate
/// on them) and sets when an enabled row names the axis.
pub const CFG_AXES: &[&str] = &[MIN3_AXIS, "protocols"];

/// THE BUILD'S CFGS: every manifest-driven cfg build.rs declares, each with whether this feature
/// set sets it. build.rs declares every name and sets the ones that are on, from this one table, so
/// a test can hold that every declared name is set by some feature set: a cfg that no build ever
/// sets gates code that runs nowhere. A seam's cfg is declared only when some row drives the seam.
pub fn build_cfgs(manifest: &str, enabled: &dyn Fn(&str) -> bool) -> Vec<(String, bool)> {
    let features = declared_features(manifest);
    let required = required_deps(manifest);
    let plugins = metadata_map(manifest, "package.metadata.busbar.linked");
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let always = |key: &str| {
        !features.iter().any(|f| f == key)
            && plugins
                .iter()
                .any(|(k, krate)| k == key && required.contains(krate))
    };
    let named = |axis: &str| -> Vec<&String> {
        axes.iter()
            .filter(|(_, list)| list.split_whitespace().any(|a| a == axis))
            .map(|(row, _)| row)
            .collect()
    };
    let mut out = vec![(
        "distribution_root".to_string(),
        metadata_value(manifest, "package.metadata.busbar.core", "dir").is_some(),
    )];
    for (axis, cfg) in SEAMS {
        let rows = named(axis);
        if !rows.is_empty() {
            let on = rows.iter().any(|row| enabled(row) || always(row));
            out.push((cfg.to_string(), on));
        }
    }
    for axis in CFG_AXES {
        let on = named(axis).iter().any(|row| enabled(row));
        out.push((format!("linked_axis_{}", axis.replace('-', "_")), on));
    }
    for (feature, section) in metadata_map(manifest, "package.metadata.busbar.linked-section") {
        let cfg = format!("linked_section_{}", section.replace('-', "_"));
        out.push((cfg, enabled(&feature)));
    }
    out.push((
        "linked_operator_auth".to_string(),
        metadata_value(manifest, "package.metadata.busbar.operator-auth", "row")
            .is_some_and(|row| enabled(&row)),
    ));
    out
}

pub fn linked_source(
    manifest: &str,
    enabled: &dyn Fn(&str) -> bool,
) -> (String, Vec<&'static str>) {
    let features = declared_features(manifest);
    let required = required_deps(manifest);
    let plugins = metadata_map(manifest, "package.metadata.busbar.linked");
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let entries = metadata_map(manifest, "package.metadata.busbar.linked-entry");
    let units = metadata_map(manifest, "package.metadata.busbar.root-units");

    let always = |key: &str, krate: &str| {
        !features.iter().any(|f| f == key) && required.iter().any(|d| d == krate)
    };
    for (feature, krate) in &plugins {
        assert!(
            features.contains(feature) || always(feature, krate),
            "Cargo.toml: linked feature `{feature}` is not declared under [features] and \
             `{krate}` is not a required dependency"
        );
    }
    for (feature, _) in &units {
        assert!(
            features.contains(feature) || feature == NODE_UNIT,
            "Cargo.toml: linked feature `{feature}` is not declared under [features]"
        );
    }
    for (feature, _) in &axes {
        assert!(
            plugins.iter().any(|(f, _)| f == feature),
            "Cargo.toml: `{feature}` has a linked-axes row but no linked row"
        );
    }
    for (key, _) in &entries {
        assert!(
            plugins.iter().any(|(f, k)| k == key || f == key),
            "Cargo.toml: `{key}` has a linked-entry row but no linked row"
        );
    }
    let axes_of = |feature: &str, krate: &str| -> Vec<String> {
        let row = axes.iter().find(|(f, _)| f == feature).unwrap_or_else(|| {
            panic!("Cargo.toml: linked feature `{feature}` ({krate}) has no linked-axes row")
        });
        let list: Vec<String> = row.1.split_whitespace().map(str::to_string).collect();
        for axis in &list {
            assert!(
                !RETIRED_AXES.contains(&axis.as_str()),
                "linked row `{feature}` ({krate}) is on the retired `{axis}` axis: the old plugin \
                 interface is gone; link it as a MIN-3 image on `{MIN3_AXIS}`"
            );
            assert!(
                axis == "plane"
                    || axis == CLAIMS_AXIS
                    || axis == MIN3_AXIS
                    || AXES.iter().any(|(a, _, _)| a == axis)
                    || SEAMS.iter().any(|(a, _)| a == axis),
                "Cargo.toml: `{krate}` names an unknown linked axis `{axis}`"
            );
        }
        assert!(
            !list.iter().any(|a| a == CLAIMS_AXIS) || list.iter().any(|a| a == "plane"),
            "Cargo.toml: `{krate}` declares claims only beside `plane`"
        );
        list
    };

    let on: Vec<&(String, String)> = plugins
        .iter()
        .filter(|(f, k)| enabled(f) || always(f, k))
        .collect();
    let mut out =
        String::from("// @generated by build.rs from Cargo.toml metadata (src/linked_gen.rs).\n");
    let mut externs: Vec<String> = Vec::new();
    for (_, krate) in &on {
        let line = format!("extern crate {} as _;\n", ident(krate));
        if !externs.contains(&line) {
            out.push_str(&line);
            externs.push(line);
        }
    }

    let linked: Vec<(String, Vec<String>)> = on
        .iter()
        .map(|(feature, krate)| {
            let entry = entries
                .iter()
                .find(|(k, _)| k == feature)
                .or_else(|| entries.iter().find(|(k, _)| k == krate))
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

    out.push_str(
        "/// Every linked plugin's entry items, one table per registration axis, in manifest order.\n\
         static LINKED: crate::root::linked::Linked = crate::root::linked::Linked {\n",
    );
    out.push_str("    images: &[\n");
    for ((_, axes), (feature, krate)) in linked.iter().zip(&on) {
        if !axes.iter().any(|axis| axis == MIN3_AXIS) {
            continue;
        }
        let entry = entries
            .iter()
            .find(|(key, _)| key == feature)
            .or_else(|| entries.iter().find(|(key, _)| key == krate))
            .map(|(_, path)| path.clone())
            .unwrap_or_else(|| ident(krate));
        let alias = metadata_value(manifest, "package.metadata.busbar.linked-name", feature)
            .unwrap_or_default();
        out.push_str(&format!(
            "        crate::root::linked::LinkedImage {{ alias: {alias:?}, admit: || \
             ::busbar_plugin_loader::admit::admit_linked(&{entry}::PLUGIN) }},\n"
        ));
    }
    out.push_str("    ],\n");
    out.push_str("    claims: &[");
    for e in on_axis(CLAIMS_AXIS) {
        out.push_str(&format!(
            "crate::root::linked::LinkedClaims {{ plane: || ::std::sync::Arc::new({e}::PLANE), \
             claims: {e}::CLAIMS }}, "
        ));
    }
    out.push_str("],\n");
    for (axis, field, item) in AXES {
        if matches!(*field, "protocols") {
            continue;
        }

        out.push_str(&format!("    {field}: &["));
        for (e, axes) in &linked {
            if axes.iter().any(|x| x == axis) {
                out.push_str(&format!("{e}::{item}, "));
            }
        }
        out.push_str("],\n");
    }
    out.push_str("};\n");

    // THE CARRIER TABLE: (carrier, the row's own header) for each assigned row this build links. A row whose
    // feature is off assigns nothing in this build: its carrier has no supplier.
    out.push_str(
        "/// The outbound carriers this build assigns (`[package.metadata.busbar.carriers]`): each carrier and the\n\
         /// admission of its linked image's header.\n\
         static LINKED_CARRIERS: &[crate::root::min3_framers::LinkedCarrier] = &[\n",
    );
    for (_, constant, row) in carrier_rows(manifest) {
        let Some((feature, krate)) = on.iter().find(|(feature, _)| *feature == row) else {
            continue;
        };
        let entry = entries
            .iter()
            .find(|(key, _)| key == feature)
            .or_else(|| entries.iter().find(|(key, _)| key == krate))
            .map(|(_, path)| path.clone())
            .unwrap_or_else(|| ident(krate));
        out.push_str(&format!(
            "    crate::root::min3_framers::LinkedCarrier {{ carrier: ::busbar_plugin_abi::plane::{constant}, \
             admit: || ::busbar_plugin_loader::admit::admit_linked(&{entry}::PLUGIN) }},\n"
        ));
    }
    out.push_str("];\n");

    // THE INSTALLED CARRIER TABLE: (carrier, the identity of the separately installed image that carries it). In
    // every build: whether the carrier has a supplier is the deployment's (the image installed or not).
    out.push_str(
        "/// The outbound carriers this build assigns to separately installed images\n\
         /// (`[package.metadata.busbar.installed-carriers]`): each carrier and its image's identity.\n\
         static INSTALLED_CARRIERS: &[crate::root::min3_framers::InstalledCarrier] = &[\n",
    );
    for (_, constant, identity) in installed_carrier_rows(manifest) {
        out.push_str(&format!(
            "    crate::root::min3_framers::InstalledCarrier {{ carrier: ::busbar_plugin_abi::plane::{constant}, \
             identity: {identity:?} }},\n"
        ));
    }
    out.push_str("];\n");

    out.push_str(
        "/// Every enabled root unit, in manifest order.\n\
         static ROOT_UNITS: &[&crate::root::linked::RootUnit] = &[\n",
    );
    for (_, module) in units.iter().filter(|(f, _)| f == NODE_UNIT || enabled(f)) {
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
