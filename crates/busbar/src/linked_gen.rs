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
//
// and this turns the rows whose feature is ENABLED into `extern crate <crate> as _;` lines, one table
// per registration axis over each entry module's item for that axis (the `LINKED` value), the cfgs
// of the root-bound seams some enabled entry drives, and the `ROOT_UNITS` table. The composition root
// is the one crate that generates a linked table: no cleanliness crate has a build script that names
// a plugin, and their tests link the kernel's kind-neutral doubles instead.

/// THE NODE'S OWN ROOT-UNIT ROW (ARCHITECT Q1): keyed to the node itself rather than to a plane
/// feature, because the node compiles in every build and every door plane — compiled in or dropped
/// in — is driven and posted on it. Its configuration and book steps (the card repricer, the book
/// binding) therefore run in every build.
pub(crate) const NODE_UNIT: &str = "node";

/// A registration axis: its manifest name, the `LINKED` field it fills, and the entry item a crate
/// that registers on it exports. The plane axis is the one exception, built below (two items,
/// joined); a plane's door is its own axis ([`PLANE_DOOR_AXIS`]).
pub(crate) const AXES: &[(&str, &str, &str)] = &[
    ("protocols", "protocols", "PROTOCOLS"),
    ("body-ingress", "body_ingress", "BODY_INGRESS"),
    ("protocol-seams", "protocol_seams", "install_protocol_seams"),
    ("diagnostics", "diagnostics", "DIAGNOSTICS"),
    ("on-host", "on_host", "on_host"),
    ("compose", "compose", "compose"),
    ("cli-help", "cli_help", "CLI_HELP"),
    ("stores", "stores", "STORE"),
    // The hook axis: each linked `kind: hook` row's door (`plugin_door!`), the same door its
    // dropped-in build exports.
    ("hooks", "hook_doors", "door"),
    // The node axis: a plane whose units a composition root's node drives is handed that node.
    ("node", "node", "install_node"),
];

/// The transport axis (#3, #30): each row's entry exports its memory-ABI `door` (every transport row
/// is also a [`DOOR_AXIS`] row), and nothing else is read off it: the row's key, the layers it
/// composes over and whether it carries a session are its door's Statement's
/// (`crate::root::linked::linked_transport!`); the root builds each through
/// `crate::root::doors::build` and folds them bottom-up.
const TRANSPORT_AXIS: &str = "transport";

/// Beside `transport`: the row's entry exports its memory-ABI `door` instead of a `build`, and the
/// root builds it (`crate::root::doors::build`) — admitted through the one dispatcher and served over
/// the host's sockets by the connector.
pub(crate) const DOOR_AXIS: &str = "transport-door";

/// Beside `transport-door`: the row's memory-ABI `door` is ALSO opened by the root's one Connector
/// as a framer entry, so a plugin's need over this scheme is served on the connector (an export
/// sink's outbound `http`, `BUSBAR-1.6.0.md` Part 2 #50) while the wire the registry folds is
/// unchanged.
pub(crate) const CONNECTOR_DOOR_AXIS: &str = "connector-door";

/// The plane door axis (#2, THE DESIGN §11.4): the row's entry exports its plane kind's memory-ABI
/// `door`, and the root hands it to the loader beside every dropped-in plane door
/// (`crate::root::boot::discover_planes`), so a compiled-in plane is bound through the same table
/// as a dropped-in one. It needs no `plane` beside it: the door states the plane.
pub(crate) const PLANE_DOOR_AXIS: &str = "plane-door";
/// The export axis on the export kind's MEMORY ABI: each row's crate states its plugin `NAME`,
/// `ALIAS` and manifest `DECLARES`, and its entry module exports its `door` (`plugin_door!`), the
/// same door its `cdylib` exports — admitted through the one registration as a door row.
pub(crate) const EXPORT_DOOR_AXIS: &str = "export-doors";

/// The claims axis: each row's entry exports the pure plane the boot seal registers (`PLANE`) and
/// the claims it declares (`CLAIMS`); rides on `plane`.
const CLAIMS_AXIS: &str = "claims";

/// The secret axis (THE DESIGN, "Plugins": env and file secrets are ordinary plugins, linked in the default
/// build): each row's entry exports its memory-ABI `door`.
const SECRET_AXIS: &str = "secret-doors";

/// The auth axis (#2 rule (1), #40): each row's entry (its crate root, unless a `linked-entry` row
/// names another module) exports, at `door::door`, the
/// memory-ABI door every `kind: auth` plugin exports (the same door its dropped-in build exports as
/// `busbar_plugin_door`: THE DESIGN, compiled-in = dropped-in), registered under the key its
/// `linked-name` row states and the canonical name its `linked-canonical` row states (the key, when
/// it has none).
const AUTH_AXIS: &str = "auths";

/// THE LINKED HOOK NAMES (`$OUT_DIR/linked_hook_names.rs`, included by `main.rs`): each enabled `hooks`-axis row's `linked-name`, in manifest order — what the
/// root carries on its install record (`busbar_kernel::preflight::RootInstall::hook_names`) as the
/// admin surface's compiled-in hook plugins, so that crate spells none.
pub(crate) fn linked_hook_names_source(manifest: &str, enabled: &dyn Fn(&str) -> bool) -> String {
    let plugins = metadata_map(manifest, "package.metadata.busbar.linked");
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    // The hook axis's manifest name, read off its one spelling: the `AXES` row that fills
    // `hook_doors`.
    let hook_axis = AXES
        .iter()
        .find(|(_, field, _)| *field == "hook_doors")
        .map(|(axis, _, _)| *axis)
        .expect("the AXES table carries the hook axis");
    let mut out = String::from(
        "// @generated by build.rs from Cargo.toml metadata (src/linked_gen.rs).\n\
         /// The name of each hook row this build links, as the admin surface prints it.\n\
         #[allow(dead_code)]\n\
         pub(crate) const LINKED_HOOK_NAMES: &[&str] = &[",
    );
    for (feature, krate) in &plugins {
        let on_hooks = axes
            .iter()
            .any(|(f, list)| f == feature && list.split_whitespace().any(|a| a == hook_axis));
        if !on_hooks || !enabled(feature) {
            continue;
        }
        let name = metadata_value(manifest, "package.metadata.busbar.linked-name", feature)
            .unwrap_or_else(|| {
                panic!(
                    "Cargo.toml: `{feature}` ({krate}) is on the `{hook_axis}` axis but has no \
                     `[package.metadata.busbar.linked-name]` row naming what the admin surface prints"
                )
            });
        out.push_str(&format!("{name:?}, "));
    }
    out.push_str("];\n");
    out
}

/// The `value` of `key` under the `[table]` header, when the table and the row exist. The optional
/// twin of [`metadata_map`], for the one table only some rows need.
fn metadata_value(manifest: &str, table: &str, key: &str) -> Option<String> {
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

/// The root-bound seams: an axis a crate DRIVES rather than fills, emitted as a cfg the root binds
/// the seam under (the kernel compiles some of them only when a plane that drives them is linked).
pub(crate) const SEAMS: &[(&str, &str)] = &[
    ("egress", "linked_egress"),
];

/// The `key = "value"` rows of the `[table]` header of a Cargo manifest, in file order. Deliberately
/// not a TOML parser: one row per line, both sides optionally double-quoted. An absent table is no
/// rows (core alone links nothing); a table stated with no row is a build failure.
pub(crate) fn metadata_map(manifest: &str, table: &str) -> Vec<(String, String)> {
    let header = format!("[{table}]");
    let (mut in_table, mut present) = (false, false);
    let mut rows = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == header;
            present |= in_table;
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
    // Core alone states no table: it links nothing. A table stated with no row is a mistake.
    assert!(
        !present || !rows.is_empty(),
        "Cargo.toml: `{header}` is empty"
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

/// The crates the manifest's `[dependencies]` table declares WITHOUT `optional = true` — the edges no
/// feature can drop, so a linked row naming one is linked in every build.
pub(crate) fn required_deps(manifest: &str) -> Vec<String> {
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
    let required = required_deps(manifest);
    let plugins = metadata_map(manifest, "package.metadata.busbar.linked");
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let entries = metadata_map(manifest, "package.metadata.busbar.linked-entry");
    let units = metadata_map(manifest, "package.metadata.busbar.root-units");
    // A row is linked when its feature is on — or always, when its crate is an edge no feature can
    // drop. Anything else would be a row no build ever links, dropped silently.
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
                    || axis == CONNECTOR_DOOR_AXIS
                    || axis == PLANE_DOOR_AXIS
                    || axis == AUTH_AXIS
                    || axis == SECRET_AXIS
                    || axis == EXPORT_DOOR_AXIS
                    || axis == CLAIMS_AXIS
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
    // (entry module, axes) per enabled crate, in manifest order.
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
    // The door each enabled crate reads, parallel to `linked`.
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
    // The door each row on `axis` reads.
    let doors_on = |axis: &str| -> Vec<&String> {
        linked
            .iter()
            .zip(&doors)
            .filter(|((_, a), _)| a.iter().any(|x| x == axis))
            .map(|(_, d)| d)
            .collect()
    };
    // THE STORE AND EXPORT AXES, built when the boot first reads them.
    out.push_str(
        "/// The store axis: each linked store's `(key, ephemeral, door, canonical)`.\n\
         static LINKED_STORES: ::std::sync::LazyLock<::std::vec::Vec<busbar_kernel::preflight::LinkedStore>> =\n    \
         ::std::sync::LazyLock::new(|| ::std::vec![",
    );
    for (entry, axes) in &linked {
        if !axes.iter().any(|a| a == "stores") {
            continue;
        }
        // A store crate's `STORE` in either shape (`busbar_kernel::preflight::StoreRow`): its
        // door function, or its `MACRO_DOOR` (status rows 159 and 194).
        out.push_str(&format!(
            "busbar_kernel::preflight::StoreRow({entry}::STORE).linked(), "
        ));
    }
    out.push_str("]);\n");
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
        out.push_str(&format!(
            "crate::root::linked::LinkedDoorExport {{ name: {c}::NAME, alias: {c}::ALIAS, \
             declares: {c}::DECLARES, door: {door} }}, "
        ));
    }
    out.push_str("]);\n");

    let planes = on_axis("plane");
    out.push_str(&format!(
        "/// The plane axis: each entry's contract declaration joined kernel-side to its hooks.\n\
         static LINKED_PLANES: [busbar_kernel::plane_driver::registry::PlaneDecl; {}] = [\n",
        planes.len()
    ));
    for e in &planes {
        out.push_str(&format!(
            "    busbar_kernel::plane_driver::registry::PlaneDecl::assemble({e}::PLANE_DECLARATION, \
             {e}::PLANE_HOOKS),\n"
        ));
    }
    out.push_str("];\n");
    out.push_str(
        "/// Every linked plugin's entry items, one table per registration axis, in manifest order.\n\
         static LINKED: crate::root::linked::Linked = crate::root::linked::Linked {\n    \
         planes: &LINKED_PLANES,\n",
    );
    out.push_str("    plane_doors: &[");
    for door in doors_on(PLANE_DOOR_AXIS) {
        out.push_str(&format!("{door}, "));
    }
    out.push_str("],\n");
    // THE SECRET AXIS: each linked secret plugin's memory-ABI door, loaded through the one loader
    // (`crate::root::linked::secret_rows`).
    out.push_str("    secrets: &[");
    for door in doors_on(SECRET_AXIS) {
        out.push_str(&format!("{door}, "));
    }
    out.push_str("],\n");
    // EACH LINKED SECRET DOOR'S DECLARED METADATA: `(door, declares)`, the JSON its
    // `[package.metadata.busbar.linked-declares]` row names (the crate's `declares.json`), read as a
    // dropped-in copy's signed `declares` is (its disk need, THE DESIGN §11.11 R4). A secret door
    // with no such row declares none.
    out.push_str("    secret_declares: &[");
    for (((_, list), door), (feature, _)) in linked.iter().zip(&doors).zip(&on) {
        if !list.iter().any(|a| a == SECRET_AXIS) {
            continue;
        }
        if let Some(path) =
            metadata_value(manifest, "package.metadata.busbar.linked-declares", feature)
        {
            out.push_str(&format!("({door}, {path}), "));
        }
    }
    out.push_str("],\n");
    // Each door row's place among the plane rows (how many `plane` rows precede it in manifest
    // order): a door plane's registry row folds in at its row's place, so the layering order is the
    // manifest's whichever axis a plane registers on.
    out.push_str("    plane_door_slots: &[");
    let mut planes_before = 0usize;
    for (_, axes) in &linked {
        if axes.iter().any(|a| a == PLANE_DOOR_AXIS) {
            out.push_str(&format!("{planes_before}, "));
        }
        if axes.iter().any(|a| a == "plane") {
            planes_before += 1;
        }
    }
    out.push_str("],\n");
    // EACH LINKED PLANE DOOR'S DECLARED METADATA: `(crate, door, declares)`, `Some` the JSON its
    // `[package.metadata.busbar.linked-declares]` row names (the crate's `declares.json`), read as
    // every default-linked plugin's `declares` section is, beside the door it belongs to (so the
    // root finds a bound door plane's declaration by its Statement). A door row with no such row is
    // `None`: the root reads the document its door's own Statement states (`EXT_DECLARES`).
    out.push_str("    plane_door_declares: &[");
    for ((feature, krate), door) in on.iter().zip(&doors) {
        let is_door = axes
            .iter()
            .any(|(f, a)| f == feature && a.split_whitespace().any(|x| x == PLANE_DOOR_AXIS));
        if !is_door {
            continue;
        }
        match metadata_value(manifest, "package.metadata.busbar.linked-declares", feature) {
            Some(path) => out.push_str(&format!("({krate:?}, {door}, Some({path})), ")),
            None => out.push_str(&format!("({krate:?}, {door}, None), ")),
        }
    }
    out.push_str("],\n");
    out.push_str("    transports: &[");
    for ((e, axes), door) in linked
        .iter()
        .zip(&doors)
        .filter(|((_, a), _)| a.iter().any(|x| x == TRANSPORT_AXIS))
    {
        // A TRANSPORT LOADS ONLY THROUGH ITS DOOR (step 36): there is no transport trait for a row
        // to build itself as, so a transport row without the door axis is a manifest this root
        // cannot link.
        assert!(
            axes.iter().any(|x| x == DOOR_AXIS),
            "Cargo.toml: `{e}` is on the `{TRANSPORT_AXIS}` axis but not the `{DOOR_AXIS}` axis; a \
             transport is linked only as its memory-ABI door"
        );
        // THE ROW IS ITS BARE `door` (BUSBAR-1.6.0.md l.3560-3561; coordinator ruling (b), row
        // 159): its key, layers and session are read off the door's Statement, never off a constant
        // of the entry's.
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
            // An auth row's door is its entry's `door` module's (`<entry>::door::door`).
            let door = format!("{entry}::door::door");
            out.push_str(&format!("({name:?}, {canonical:?}, {door}), "));
        }
    }
    out.push_str("],\n");
    // The operator credential's provider word: the `linked-name` of the row the manifest's
    // `operator-auth` table names, whether or not this build links it (its 1.5.5 refusals spell it).
    let operator = metadata_value(manifest, "package.metadata.busbar.operator-auth", "row")
        .and_then(|row| metadata_value(manifest, "package.metadata.busbar.linked-name", &row))
        .unwrap_or_default();
    out.push_str(&format!("    operator_auth: {operator:?},\n"));
    out.push_str("    export_doors: &LINKED_EXPORT_DOORS,\n");
    out.push_str("    stores: &LINKED_STORES,\n");
    out.push_str("    claims: &[");
    for e in on_axis(CLAIMS_AXIS) {
        out.push_str(&format!(
            "crate::root::linked::LinkedClaims {{ plane: || ::std::sync::Arc::new({e}::PLANE), \
             claims: {e}::CLAIMS }}, "
        ));
    }
    out.push_str("],\n");
    for (axis, field, item) in AXES {
        // The store axis is `LINKED_STORES`, above.
        if *field == "stores" {
            continue;
        }
        out.push_str(&format!("    {field}: &["));
        for ((e, axes), door) in linked.iter().zip(&doors) {
            if !axes.iter().any(|x| x == axis) {
                continue;
            }
            if *item == "door" {
                // The hook axis: the row's door.
                out.push_str(&format!("{door}, "));
            } else {
                out.push_str(&format!("{e}::{item}, "));
            }
        }
        out.push_str("],\n");
    }
    out.push_str("};\n");
    // THE CONNECTOR'S VIEW of the same door rows: each memory-ABI transport door's key and its
    // `door`, which the root's one Connector opens as a framer entry (`crate::root::connector`). The
    // key is the door's Statement's, read on first use by the reader every row's is
    // (`crate::root::doors::row_facts`), never a constant of the entry's (BUSBAR-1.6.0.md
    // l.3560-3561); the table keeps its name and slice shape, which code outside this crate's
    // source (a pinned plane's root tests) hands the connector.
    out.push_str(
        "/// Every linked memory-ABI transport door, by the key its Statement states, read on first use.\n\
         static LINKED_TRANSPORT_DOORS_READ: ::std::sync::LazyLock<::std::vec::Vec<(&'static str, busbar_contract::abi::mechanism::door::DoorFn)>> =\n    \
         ::std::sync::LazyLock::new(|| {\n        \
         let doors: &[busbar_contract::abi::mechanism::door::DoorFn] = &[",
    );
    for ((_, axes), door) in linked
        .iter()
        .zip(&doors)
        .filter(|((_, a), _)| a.iter().any(|x| x == TRANSPORT_AXIS))
    {
        if axes
            .iter()
            .any(|x| x == DOOR_AXIS || x == CONNECTOR_DOOR_AXIS)
        {
            out.push_str(&format!("{door}, "));
        }
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
         #[allow(dead_code)]\n\
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

/// `$OUT_DIR/test_linked.rs` from `[package.metadata.busbar.test-linked] planes`, each row a plane
/// crate served through its memory-ABI door: `extern crate` per listed crate, and `static
/// TEST_LINKED_DOORS`, each row's `(<crate>, <module>::door)` in list order, `<module>` the
/// `[package.metadata.busbar.linked-entry]` module in that crate (the plane door row's own entry),
/// else `<crate>::plane_door`.
pub(crate) fn test_linked_source(manifest: &str) -> String {
    let doors: Vec<String> = test_linked_list(manifest, "planes")
        .iter()
        .map(|c| c.replace('-', "_"))
        .collect();
    let mut out = String::from("// @generated by build.rs from Cargo.toml metadata.\n");
    for id in &doors {
        out.push_str(&format!("extern crate {id} as _;\n"));
    }
    out.push_str(
        "static TEST_LINKED_DOORS: &[(&str, ::busbar_contract::abi::mechanism::door::DoorFn)] = &[\n",
    );
    // A door row's module is the one its plane-door row names in `linked-entry`, so the roster
    // never spells a module the crate has moved.
    let entries = metadata_map(manifest, "package.metadata.busbar.linked-entry");
    for id in &doors {
        let module = entries
            .iter()
            .map(|(_, module)| module)
            .find(|module| *module == id || module.starts_with(&format!("{id}::")))
            .cloned()
            .unwrap_or_else(|| format!("{id}::plane_door"));
        out.push_str(&format!("    ({id:?}, {module}::door),\n"));
    }
    // Each door whose linked row also fills the protocol axis (`linked-axes` names `protocols`
    // beside `plane-door`): its `PROTOCOLS`, registered by the installer as the root's
    // `register_protocols` installs them in production, so a test binary's registry is the
    // shipped binary's.
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    out.push_str(
        "];\nstatic TEST_LINKED_PROTOCOLS: &[&[&::busbar_contract::protocol::ProtocolDecl]] = &[\n",
    );
    for id in &doors {
        let row = entries
            .iter()
            .find(|(_, module)| *module == id || module.starts_with(&format!("{id}::")));
        if let Some((key, module)) = row {
            let fills = axes
                .iter()
                .any(|(f, list)| f == key && list.split_whitespace().any(|a| a == "protocols"));
            if fills {
                out.push_str(&format!("    {module}::PROTOCOLS,\n"));
            }
        }
    }
    out.push_str("];\n");
    out
}

/// The `key = [...]` string array under `[package.metadata.busbar.test-linked]`. Deliberately not a
/// TOML parser: the array may span lines, entries are double-quoted crate names. An absent key is no
/// entries; a key stated with none is a build failure.
pub(crate) fn test_linked_list(manifest: &str, key: &str) -> Vec<String> {
    let header = "[package.metadata.busbar.test-linked]";
    let (mut in_table, mut collecting, mut body) = (false, false, String::new());
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if !collecting && code.starts_with('[') {
            in_table = code == header;
            continue;
        }
        if collecting {
            body.push_str(code);
        } else if in_table {
            if let Some((k, v)) = code.split_once('=') {
                if k.trim() == key {
                    collecting = true;
                    body.push_str(v.trim());
                }
            }
        }
        if collecting && body.contains(']') {
            break;
        }
    }
    if !collecting {
        // Core alone states no test-linked row: it links nothing.
        return Vec::new();
    }
    let list: Vec<String> = body
        .trim()
        .trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    assert!(
        !list.is_empty(),
        "Cargo.toml: `{key}` under `{header}` is empty"
    );
    list
}
