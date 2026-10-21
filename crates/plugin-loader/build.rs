// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE BOTH-WAYS FIXTURE TABLES (test builds include them; nothing else reads them). Which in-tree
// plugin proves each kind both ways is DATA in `Cargo.toml`:
//
//   [package.metadata.busbar.both-ways]   <kind>[-<proof>] = "<fixture crate>"
//
// This turns the rows into `$OUT_DIR/both_ways.rs`, which `src/tests/both_ways.rs` includes, so the
// conformance tests reach each fixture by KIND and no test source names a plugin instance. Every
// fixture is on its kind's memory ABI; what differs per kind is only where its LINKED door sits.
//
// A row is keyed by its kind, or `<kind>-<proof>` for a second proof of one kind: the kind is the key
// up to its first `-`. Its value names a plugin repo's LOGIC crate or that crate's `-plugin` twin
// (the thin cdylib packing it); each is read as the pair, derived here once:
//
// * the LOGIC crate is the name without `-plugin`. It is the only crate of a row the test binary
//   ever links: a `-plugin` crate's rlib exports `busbar_plugin_door` (`export_door!`), and two doors
//   in one fat-LTO unit make "symbol multiply defined". No emitted path names a `-plugin` crate, for
//   any row (checked below, and by `src/tests/door_symbol_tests.rs` over the generated table);
// * the CDYLIB crate is the `-plugin` twin, `<logic>_plugin`: the dropped-in door, built because the
//   twin is a dev-dependency. The `store` row is its own cdylib (the store crate builds one).
//
// Generated:
//
// * `BOTH_WAYS_ROWS`: `(row, logic crate, cdylib crate)` of every row;
// * `KIND_FIXTURES`: `(kind, cdylib crate)` of each row of a kind whose linked door is a module of
//   its logic crate (`CRATE_DOOR_KINDS`);
// * `DOOR_FIXTURES`: `(row, cdylib crate, linked door)` of each row of a kind whose linked door is
//   its logic crate's `door::door` (`DOOR_KINDS`);
// * the per-row alias `<row>_fixture`, the logic crate itself, and for a row naming its twin in a
//   `CRATE_DOOR_KINDS` kind, the logic crate's `linked` module as `<kind>_linked`.
//
// The `store` row (`STORE_KINDS`) is also written to `$OUT_DIR/store_fixture.rs` (its crate alias and
// cdylib stem) and `$OUT_DIR/store_door.rs` (the store door example's one `export_door!` line), for
// the targets that cannot include `both_ways.rs`. The loader tests the axis, and a plugin tests
// itself (DECISIONS #2). Reads only this crate's own manifest, and refuses any line of the table it
// cannot read exactly.

use std::env;
use std::path::PathBuf;

/// The kinds whose fixture's linked door is a module of its logic crate (a plane's `#[repr(C)]` decl,
/// a transport's `linked` module, the secret source's `door`), reached through the crate alias.
const CRATE_DOOR_KINDS: &[&str] = &["plane", "transport", "secret"];

/// The kinds whose fixture's linked door is its logic crate's `door::door` (THE DESIGN,
/// compiled-in = dropped-in: the same door its dropped-in build exports).
const DOOR_KINDS: &[&str] = &["auth"];

/// The kinds whose fixture is reached only by its crate and its door example (`store_door.rs`): the
/// store kind's door is the crate's own `door`.
const STORE_KINDS: &[&str] = &["store"];

/// The suffix of a plugin repo's cdylib twin.
const TWIN: &str = "-plugin";

/// One `key = "value"` line of the table, read exactly: a key and a value of lowercase ASCII
/// letters, digits and `-`, the value double-quoted, nothing after it but a comment. `None` for a
/// blank line or a whole-line comment; anything else is a build failure, never a row half-read.
fn row(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let word = |w: &str| {
        !w.is_empty()
            && w.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let parsed = line.split_once('=').and_then(|(key, rest)| {
        let key = key.trim();
        let rest = rest.trim().strip_prefix('"')?;
        let (value, tail) = rest.split_once('"')?;
        let tail = tail.trim();
        (word(key) && word(value) && (tail.is_empty() || tail.starts_with('#')))
            .then_some((key, value))
    });
    Some(parsed.unwrap_or_else(|| {
        panic!(
            "Cargo.toml: [package.metadata.busbar.both-ways] line `{line}` is not \
             `<kind>[-<proof>] = \"<crate>\"`"
        )
    }))
}

/// The kind whose rows (`export`, `export-<proof>`) are sinks on the export kind's memory ABI: each
/// row names the sink's LOGIC crate (the linked `door`; no door symbol in its rlib), and its
/// dropped-in `cdylib` is that crate's `-plugin` twin from the same repo, both read from
/// `BOTH_WAYS_ROWS`. No linked-door table row: the export tests reach the door by the crate.
const EXPORT_KIND: &str = "export";

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    let manifest = std::fs::read_to_string("Cargo.toml").expect("read Cargo.toml");
    let mut out = String::from(
        "// @generated by build.rs from Cargo.toml `[package.metadata.busbar.both-ways]`.\n",
    );
    let mut crates = String::new();
    let mut rows = String::from(
        "/// `(row, logic crate, cdylib crate)` of every both-ways row: the logic crate is the one the \
         test binary links, the cdylib the dropped-in door.\n\
         #[allow(dead_code)]\n\
         pub(crate) static BOTH_WAYS_ROWS: &[(&str, &str, &str)] = &[\n",
    );
    let mut modules = String::from(
        "/// `(kind, cdylib crate)` of each both-ways fixture whose linked door is a module of its \
         logic crate.\n\
         #[allow(dead_code)]\n\
         pub(crate) static KIND_FIXTURES: &[(&str, &str)] = &[\n",
    );
    // THE STORE FIXTURE, BY KIND, for the targets that cannot include `both_ways.rs` (an integration
    // test, the store v3 door example): `store_fixture.rs` aliases the `store` row's crate and names
    // its cdylib stem; `store_door.rs` is the example's one `export_door!` line. No test or fixture
    // source names the store instance (instance-noun-neutrality, ARCHITECT Q-GG4(c)).
    let mut store_fixture = String::new();
    let mut store_door = String::new();
    let mut doors = String::from(
        "/// `(row, cdylib crate, linked door)` of each both-ways fixture whose linked door is its \
         logic crate's `door::door`.\n\
         pub(crate) static DOOR_FIXTURES: &[(&str, &str, busbar_contract::abi::mechanism::door::DoorFn)] = &[\n",
    );
    let mut twins: Vec<String> = Vec::new();
    let mut in_table = false;
    for line in manifest.lines() {
        let code = line.trim();
        if code.starts_with('[') {
            in_table = code.split('#').next().unwrap_or("").trim()
                == "[package.metadata.busbar.both-ways]";
            continue;
        }
        if !in_table {
            continue;
        }
        let Some((key, krate)) = row(code) else {
            continue;
        };
        let kind = key.split('-').next().unwrap_or(key);
        let named_twin = krate.ends_with(TWIN);
        let logic = krate.strip_suffix(TWIN).unwrap_or(krate).replace('-', "_");
        let store = STORE_KINDS.contains(&kind);
        let cdylib = if store {
            logic.clone()
        } else {
            format!("{logic}_plugin")
        };
        twins.push(format!("{logic}_plugin"));
        rows.push_str(&format!("    (\"{key}\", \"{logic}\", \"{cdylib}\"),\n"));
        if CRATE_DOOR_KINDS.contains(&kind) {
            modules.push_str(&format!("    (\"{kind}\", \"{cdylib}\"),\n"));
            if named_twin {
                // The row named the twin: its logic crate's `linked` module is the linked door.
                crates.push_str(&format!(
                    "#[allow(unused_imports)]\npub(crate) use ::{logic}::linked as {}_linked;\n",
                    kind.replace('-', "_")
                ));
            }
        } else if DOOR_KINDS.contains(&kind) {
            doors.push_str(&format!(
                "    (\"{key}\", \"{cdylib}\", ::{logic}::door::door),\n"
            ));
        } else if store {
            store_fixture = format!(
                "// @generated by build.rs from the `store` both-ways row.\n\
                 /// The `store` both-ways fixture crate, reached by kind.\n\
                 #[allow(unused_imports)]\n\
                 pub use ::{logic} as store_fixture;\n\
                 /// The file stem of its dropped-in `cdylib`.\n\
                 #[allow(dead_code)]\n\
                 pub const STORE_FIXTURE_CDYLIB: &str = \"{cdylib}\";\n"
            );
            store_door = format!(
                "// @generated by build.rs from the `store` both-ways row.\n\
                 busbar_contract::export_door!(::{logic}::door);\n"
            );
        } else if kind == EXPORT_KIND {
            // Its logic crate alias and its `BOTH_WAYS_ROWS` row are all it needs.
        } else {
            panic!(
                "Cargo.toml: both-ways row `{key}` ({krate}) is of kind `{kind}`, which has no \
                 linked door here: add the kind to CRATE_DOOR_KINDS, DOOR_KINDS, STORE_KINDS \
                 or EXPORT_KIND"
            );
        }
        crates.push_str(&format!(
            "// The `{key}` both-ways fixture's logic crate.\n\
             #[allow(unused_imports)]\n\
             pub(crate) use ::{logic} as {}_fixture;\n",
            key.replace('-', "_")
        ));
    }
    rows.push_str("];\n");
    out.push_str(&rows);
    modules.push_str("];\n");
    out.push_str(&modules);
    doors.push_str("];\n");
    out.push_str(&doors);
    out.push_str(&crates);
    // THE GUARD, for every row: nothing generated names a `-plugin` crate, so none is linked.
    for twin in &twins {
        for text in [&out, &store_fixture, &store_door] {
            assert!(
                !text.contains(&format!("::{twin}")),
                "build.rs would link the `-plugin` crate {twin}: its rlib exports \
                 busbar_plugin_door"
            );
        }
    }
    let dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(dir.join("both_ways.rs"), out).expect("write both_ways.rs");
    assert!(
        !store_fixture.is_empty(),
        "[package.metadata.busbar.both-ways] has no `store` row: the store fixture has no source"
    );
    std::fs::write(dir.join("store_fixture.rs"), store_fixture).expect("write store_fixture.rs");
    std::fs::write(dir.join("store_door.rs"), store_door).expect("write store_door.rs");
}
