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

/// The transport axis (#3, #30): each row's entry exports its transport's `KEY`, the `COMPOSES_OVER`
/// it declares and `build(lower, &TransportSettings)`; the root folds the rows bottom-up.
const TRANSPORT_AXIS: &str = "transport";

/// Beside `transport`: the row's entry exports its memory-ABI `door` instead of a `build`, and the
/// root builds it (`crate::root::doors::build`) — admitted through the one dispatcher and served over
/// the host's sockets by the connector.
pub(crate) const DOOR_AXIS: &str = "transport-door";

/// Beside `transport`, for a wire whose row keeps its own `build`: the row's entry ALSO exports its
/// memory-ABI `door`, which the root's one Connector opens as a framer entry, so a plugin's need over
/// this scheme is served on the connector (an export sink's outbound `http`, `BUSBAR-1.6.0.md` Part 2
/// #50) while the wire the registry folds is unchanged.
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

/// The auth axis (#2 rule (1), #40): each row's entry (its crate root) exports, at `door::door`, the
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
pub(crate) const SEAMS: &[(&str, &str)] = &[("egress", "linked_egress")];

/// THE SWAPS TABLE (BUSBAR-1.6.0.md Part 3 section 12, "The switch"): `<row feature> = "<switch>"`,
/// a linked row its fold's development-only switch swaps out. While the switch is on, the row is
/// not linked (no claims, no routes, no section of its own), so the plane's folded door is its one
/// claimant: the switch swaps the row, it never adds a second one.
pub(crate) const LINKED_SWAPS: &str = "package.metadata.busbar.linked-swaps";

/// Whether `feature`'s row is linked: its feature is `on`, and no switch that swaps it is.
pub(crate) fn swapped_in(
    swaps: &[(String, String)],
    on: &dyn Fn(&str) -> bool,
    feature: &str,
) -> bool {
    on(feature)
        && !swaps
            .iter()
            .any(|(row, switch)| row == feature && on(switch))
}

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
         static LINKED_PLANES: [busbar_kernel::plane_driver::row::PlaneDecl; {}] = [\n",
        planes.len()
    ));
    for e in &planes {
        out.push_str(&format!(
            "    busbar_kernel::plane_driver::row::PlaneDecl::assemble({e}::PLANE_DECLARATION, \
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
    for e in on_axis(PLANE_DOOR_AXIS) {
        out.push_str(&format!("{e}::door, "));
    }
    out.push_str("],\n");
    // THE SECRET AXIS: each linked secret plugin's memory-ABI door, loaded through the one loader
    // (`crate::root::linked::secret_rows`).
    out.push_str("    secrets: &[");
    for e in on_axis(SECRET_AXIS) {
        out.push_str(&format!("{e}::door, "));
    }
    out.push_str("],\n");
    // EACH LINKED SECRET DOOR'S DECLARED METADATA: `(door, declares)`, the JSON its
    // `[package.metadata.busbar.linked-declares]` row names (the crate's `declares.json`), read as a
    // dropped-in copy's signed `declares` is (its disk need, THE DESIGN §11.11 R4). A secret door
    // with no such row declares none.
    out.push_str("    secret_declares: &[");
    for ((entry, list), (feature, _)) in linked.iter().zip(&on) {
        if !list.iter().any(|a| a == SECRET_AXIS) {
            continue;
        }
        if let Some(path) =
            metadata_value(manifest, "package.metadata.busbar.linked-declares", feature)
        {
            out.push_str(&format!("({entry}::door, {path}), "));
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
    // EACH LINKED PLANE DOOR'S DECLARED METADATA: `(crate, door, declares)`, the JSON its
    // `[package.metadata.busbar.linked-declares]` row names (the crate's `declares.json`), read as
    // every default-linked plugin's `declares` section is, beside the door it belongs to (so the
    // root finds a bound door plane's declaration by its Statement). A door row with no such row
    // declares none.
    out.push_str("    plane_door_declares: &[");
    for ((feature, krate), (entry, _)) in on.iter().zip(&linked) {
        let is_door = axes
            .iter()
            .any(|(f, a)| f == feature && a.split_whitespace().any(|x| x == PLANE_DOOR_AXIS));
        if !is_door {
            continue;
        }
        if let Some(path) =
            metadata_value(manifest, "package.metadata.busbar.linked-declares", feature)
        {
            out.push_str(&format!("({krate:?}, {entry}::door, {path}), "));
        }
    }
    out.push_str("],\n");
    out.push_str("    transports: &[");
    let mut door_builds = String::new();
    for (n, (e, axes)) in linked
        .iter()
        .filter(|(_, a)| a.iter().any(|x| x == TRANSPORT_AXIS))
        .enumerate()
    {
        // A TRANSPORT LOADS ONLY THROUGH ITS DOOR (step 36): there is no transport trait for a row
        // to build itself as, so a transport row without the door axis is a manifest this root
        // cannot link.
        assert!(
            axes.iter().any(|x| x == DOOR_AXIS),
            "Cargo.toml: `{e}` is on the `{TRANSPORT_AXIS}` axis but not the `{DOOR_AXIS}` axis; a \
             transport is linked only as its memory-ABI door"
        );
        door_builds.push_str(&format!(
            "fn __door_build_{n}(\n    \
             settings: &busbar_contract::transport::TransportSettings,\n\
             ) -> std::sync::Arc<busbar_core_connector::wire::HostWire> {{\n    \
             crate::root::doors::build({e}::KEY, {e}::door, settings)\n}}\n\
             fn __door_claims_{n}() -> Vec<&'static str> {{\n    \
             crate::root::doors::claims_of({e}::door)\n}}\n\
             fn __door_upgrades_{n}() -> Vec<&'static str> {{\n    \
             crate::root::doors::upgrades_of({e}::door)\n}}\n\
             fn __door_lines_{n}() -> Vec<&'static str> {{\n    \
             crate::root::doors::lines_of({e}::door)\n}}\n\
             fn __door_offered_{n}() -> busbar_contract::abi::auth::AuthPoints {{\n    \
             crate::root::doors::offered_of({e}::door)\n}}\n"
        ));
        let (build, claims, upgrades, lines, offered) = (
            format!("__door_build_{n}"),
            format!("__door_claims_{n}"),
            format!("__door_upgrades_{n}"),
            format!("__door_lines_{n}"),
            format!("__door_offered_{n}"),
        );
        out.push_str(&format!(
            "crate::root::linked::LinkedTransport {{ key: {e}::KEY, composes_over: \
             {e}::COMPOSES_OVER, build: {build}, claims: {claims}, upgrades: {upgrades}, \
             lines: {lines}, \
             offered: {offered} }}, "
        ));
    }
    out.push_str("],\n");
    out.push_str("    auths: &[");
    for ((entry, list), (feature, krate)) in linked.iter().zip(&on) {
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
            out.push_str(&format!("({name:?}, {canonical:?}, {entry}::door::door), "));
        }
    }
    out.push_str("],\n");
    // The operator credential's provider word: the `linked-name` of the row the manifest's
    // `operator-auth` table names, whether or not this build links it (its 1.5.5 refusals spell it).
    let operator = metadata_value(manifest, "package.metadata.busbar.operator-auth", "row")
        .and_then(|row| metadata_value(manifest, "package.metadata.busbar.linked-name", &row))
        .unwrap_or_default();
    out.push_str(&format!("    operator_auth: {operator:?},\n"));
    out.push_str("    export_doors: &[");
    for ((entry, list), (_, krate)) in linked.iter().zip(&on) {
        if list.iter().any(|a| a == EXPORT_DOOR_AXIS) {
            let c = ident(krate);
            out.push_str(&format!(
                "crate::root::linked::LinkedDoorExport {{ name: {c}::NAME, alias: {c}::ALIAS, \
                 declares: {c}::DECLARES, door: {entry}::door }}, "
            ));
        }
    }
    out.push_str("],\n");
    out.push_str("    claims: &[");
    for e in on_axis(CLAIMS_AXIS) {
        out.push_str(&format!(
            "crate::root::linked::LinkedClaims {{ plane: || ::std::sync::Arc::new({e}::PLANE), \
             claims: {e}::CLAIMS }}, "
        ));
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
    out.push_str(&door_builds);
    // THE CONNECTOR'S VIEW of the same door rows: each memory-ABI transport door's key and its
    // `door`, which the root's one Connector opens as a framer entry (`crate::root::connector`).
    out.push_str(
        "/// Every linked memory-ABI transport door, by key, for the root's one Connector.\n\
         #[allow(dead_code)]\n\
         pub(crate) static LINKED_TRANSPORT_DOORS: &[(&str, busbar_contract::abi::mechanism::door::DoorFn)] = &[",
    );
    for (e, axes) in linked
        .iter()
        .filter(|(_, a)| a.iter().any(|x| x == TRANSPORT_AXIS))
    {
        if axes
            .iter()
            .any(|x| x == DOOR_AXIS || x == CONNECTOR_DOOR_AXIS)
        {
            out.push_str(&format!("({e}::KEY, {e}::door), "));
        }
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
