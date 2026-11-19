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

const TRANSPORT_AXIS: &str = "transport";

pub const DOOR_AXIS: &str = "transport-door";

pub const PLANE_DOOR_AXIS: &str = "plane-door";

pub const EXPORT_DOOR_AXIS: &str = "export-doors";

const CLAIMS_AXIS: &str = "claims";

const AUTH_AXIS: &str = "auths";

const MIN3_AXIS: &str = "min3-images";

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
pub fn carrier_rows(manifest: &str) -> Vec<(String, &'static str, String)> {
    let plugins = metadata_map(manifest, "package.metadata.busbar.linked");
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let mut out: Vec<(String, &'static str, String)> = Vec::new();
    for (key, row) in metadata_map(manifest, CARRIERS_TABLE) {
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
pub const CFG_AXES: &[&str] = &[
    MIN3_AXIS,
    PLANE_DOOR_AXIS,
    DOOR_AXIS,
    EXPORT_DOOR_AXIS,
    AUTH_AXIS,
    "protocols",
];

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
        "linked_every_plane_door".to_string(),
        named(PLANE_DOOR_AXIS).iter().all(|row| enabled(row)),
    ));
    out.push((
        "linked_every_auth".to_string(),
        named(AUTH_AXIS).iter().all(|row| enabled(row)),
    ));
    out.push((
        "linked_operator_auth".to_string(),
        metadata_value(manifest, "package.metadata.busbar.operator-auth", "row")
            .is_some_and(|row| enabled(&row)),
    ));
    out.push((
        "linked_driver_proofs".to_string(),
        metadata_map(manifest, "package.metadata.busbar.driver-proofs")
            .iter()
            .any(|(feature, _)| enabled(feature)),
    ));
    out.push((
        "linked_every_transport".to_string(),
        named(TRANSPORT_AXIS)
            .iter()
            .filter(|row| plugins.iter().any(|(k, _)| k == **row))
            .all(|row| enabled(row) || always(row)),
    ));
    out.push((
        "linked_transport_rows".to_string(),
        named(TRANSPORT_AXIS).iter().any(|row| enabled(row)),
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
                axis == "plane"
                    || axis == TRANSPORT_AXIS
                    || axis == DOOR_AXIS
                    || axis == PLANE_DOOR_AXIS
                    || axis == AUTH_AXIS
                    || axis == EXPORT_DOOR_AXIS
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

    let doors: Vec<String> = linked
        .iter()
        .map(|(entry, _)| format!("{entry}::door"))
        .collect();
    let on_axis = |axis: &str| -> Vec<&String> {
        linked
            .iter()
            .filter(|(_, a)| a.iter().any(|x| x == axis))
            .map(|(e, _)| e)
            .collect()
    };

    let doors_on = |axis: &str| -> Vec<&String> {
        linked
            .iter()
            .zip(&doors)
            .filter(|((_, a), _)| a.iter().any(|x| x == axis))
            .map(|(_, d)| d)
            .collect()
    };

    let former_names_of = |feature: &str| -> String {
        metadata_value(
            manifest,
            "package.metadata.busbar.linked-former-names",
            feature,
        )
        .map_or_else(
            || String::from("&[]"),
            |door| format!("{door}.former_names()"),
        )
    };
    // WP3: stores are MIN-3 images only; the door `stores` axis is retired. A row still on it is a manifest
    // that predates the re-pin, refused here rather than silently dropped.
    if let Some((entry, _)) = linked.iter().find(|(_, axes)| axes.iter().any(|a| a == "stores")) {
        panic!(
            "linked row `{entry}` is on the retired `stores` axis: link a store on `{MIN3_AXIS}` (a MIN-3 image)"
        );
    }
    out.push_str(
        "/// The export axis on the memory ABI: each linked export sink's statement and door.\n\
         static LINKED_EXPORT_DOORS: ::std::sync::LazyLock<::std::vec::Vec<crate::root::linked::LinkedDoorExport>> =\n    \
         ::std::sync::LazyLock::new(|| ::std::vec![",
    );
    for (((_, axes), door), (_, krate)) in linked.iter().zip(&doors).zip(&on) {
        if !axes.iter().any(|a| a == EXPORT_DOOR_AXIS) {
            continue;
        }
        let c = ident(krate);
        let former = format!("{c}::MACRO_DOOR.former_names()");
        out.push_str(&format!(
            "crate::root::linked::LinkedDoorExport {{ name: {c}::NAME, alias: {c}::ALIAS, \
             declares: {c}::DECLARES, door: {door}, former_names: {former} }}, "
        ));
    }
    out.push_str("]);\n");

    out.push_str(
        "/// The former names each linked store, auth, secret and plane door declares, one row each.\n\
         static LINKED_FORMER: ::std::sync::LazyLock<::std::vec::Vec<crate::root::linked::LinkedFormer>> =\n    \
         ::std::sync::LazyLock::new(|| ::std::vec![",
    );
    for (((_, axes), door), (feature, _)) in linked.iter().zip(&doors).zip(&on) {
        let row = |axis: &str, key: &str, door: &str, former: &str| {
            format!(
                "crate::root::linked::LinkedFormer {{ axis: {axis:?}, key: {key}, door: {door}, \
                 former_names: {former} }}, "
            )
        };
        let declared = metadata_value(
            manifest,
            "package.metadata.busbar.linked-former-names",
            feature,
        )
        .is_some();
        if !declared {
            continue;
        }
        let former = former_names_of(feature);
        if axes.iter().any(|a| a == AUTH_AXIS) {
            let name = metadata_value(manifest, "package.metadata.busbar.linked-name", feature)
                .unwrap_or_default();
            out.push_str(&row("auth", &format!("{name:?}"), door, &former));
        }
        if axes.iter().any(|a| a == PLANE_DOOR_AXIS) {
            out.push_str(&row("plane", "\"\"", door, &former));
        }
    }
    out.push_str("]);\n");

    out.push_str(
        "/// Every linked plugin's entry items, one table per registration axis, in manifest order.\n\
         static LINKED: crate::root::linked::Linked = crate::root::linked::Linked {\n",
    );
    out.push_str("    plane_doors: &[");
    for door in doors_on(PLANE_DOOR_AXIS) {
        out.push_str(&format!("{door}, "));
    }
    out.push_str("],\n");

    out.push_str("    plane_door_declares: &[");
    for ((feature, krate), door) in on.iter().zip(&doors) {
        let is_door = axes
            .iter()
            .any(|(f, a)| f == feature && a.split_whitespace().any(|x| x == PLANE_DOOR_AXIS));
        if !is_door {
            continue;
        }
        if let Some(path) =
            metadata_value(manifest, "package.metadata.busbar.linked-declares", feature)
        {
            out.push_str(&format!("({krate:?}, {door}, {path}), "));
        }
    }
    out.push_str("],\n");
    out.push_str("    transports: &[");
    for ((e, axes), door) in linked
        .iter()
        .zip(&doors)
        .filter(|((_, a), _)| a.iter().any(|x| x == TRANSPORT_AXIS))
    {
        assert!(
            axes.iter().any(|x| x == DOOR_AXIS),
            "Cargo.toml: `{e}` is on the `{TRANSPORT_AXIS}` axis but not the `{DOOR_AXIS}` axis; a \
             transport is linked only as its memory-ABI door"
        );

        out.push_str(&format!("crate::root::linked::linked_transport!({door}), "));
    }
    out.push_str("],\n");
    out.push_str("    auths: &[");
    for (((entry, list), _), (feature, krate)) in linked.iter().zip(&doors).zip(&on) {
        if list.iter().any(|a| a == AUTH_AXIS) {
            let name = metadata_value(manifest, "package.metadata.busbar.linked-name", feature)
                .unwrap_or_else(|| {
                    panic!(
                        "Cargo.toml: `{feature}` ({krate}) is on the `{AUTH_AXIS}` axis but has no \
                         `[package.metadata.busbar.linked-name]` row naming its registry key"
                    )
                });
            let canonical = metadata_value(
                manifest,
                "package.metadata.busbar.linked-canonical",
                feature,
            )
            .unwrap_or_else(|| name.clone());

            let door = format!("{entry}::door");
            out.push_str(&format!("({name:?}, {canonical:?}, {door}), "));
        }
    }
    out.push_str("],\n");

    out.push_str("    export_doors: &LINKED_EXPORT_DOORS,\n");
    out.push_str("    former: &LINKED_FORMER,\n");
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
        for ((e, axes), door) in linked.iter().zip(&doors) {
            if !axes.iter().any(|x| x == axis) {
                continue;
            }
            if *item == "door" {
                out.push_str(&format!("{door}, "));
            } else {
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

    out.push_str(
        "/// Every linked memory-ABI transport door, by the key its Statement states, read on first use.\n\
         static LINKED_TRANSPORT_DOORS_READ: ::std::sync::LazyLock<::std::vec::Vec<(&'static str, busbar_contract::abi::mechanism::door::DoorFn)>> =\n    \
         ::std::sync::LazyLock::new(|| {\n        \
         let doors: &[busbar_contract::abi::mechanism::door::DoorFn] = &[",
    );
    // Every transport row is a door row (asserted above), so every transport door enters the table.
    for (_, door) in linked
        .iter()
        .zip(&doors)
        .filter(|((_, a), _)| a.iter().any(|x| x == TRANSPORT_AXIS))
    {
        out.push_str(&format!("{door}, "));
    }
    out.push_str(
        "];\n        \
         doors\n            \
         .iter()\n            \
         .map(|door| (crate::root::doors::row_facts(*door).key, *door))\n            \
         .collect()\n    \
         });\n\
         /// Every linked memory-ABI transport door, by key, for the root's one Connector (a slice\n\
         /// wherever one is asked for).\n\
         pub(crate) static LINKED_TRANSPORT_DOORS: &::std::sync::LazyLock<::std::vec::Vec<(&'static str, busbar_contract::abi::mechanism::door::DoorFn)>> =\n    \
         &LINKED_TRANSPORT_DOORS_READ;\n",
    );
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
