use super::*;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits in the workspace")
        .to_path_buf()
}

/// The contract's own index sees the empty declarations plugins spread (a name whose every struct
/// carries one), and none of a name it shares with a struct that has none.
#[test]
fn the_contract_index_names_the_zero_bearing_structs() {
    let idx = index(&root().join(CONTRACT_SRC)).unwrap();
    let names = idx.zero_names();
    for n in [
        "Statement",
        "KindTailHead",
        "TransportTail",
        "AuthTail",
        "StyleDecl",
        "PlaneTail",
        "StoreTail",
        "FramePiece",
        "ConnFacts",
        "Need",
        "Claim",
        "AbiStr",
        "Blob",
    ] {
        assert!(names.contains(&n), "{n} states no ZERO the gate can see");
    }
    // A shared name is judged by the literal's fields: the store SDK's `Tail` has no ZERO, so a
    // literal only it fits is never a finding, while one only the export tail fits is.
    let sdk_tail: BTreeSet<String> = ["ephemeral", "durable_plane", "fork_refusal"]
        .map(String::from)
        .into();
    assert!(!idx.judged("Tail", &sdk_tail));
    let export_tail: BTreeSet<String> = ["head", "streams", "streams_len", "routes", "routes_len"]
        .map(String::from)
        .into();
    assert!(idx.judged("Tail", &export_tail));
}

/// THE IN-TREE PLUGINS build every ZERO-bearing contract struct with a base: each fixture plugin
/// (`crates/*/tests/fixtures/*.rs`) and the in-tree plane crate's module tree.
#[test]
fn the_in_tree_plugins_spread_every_zero_bearing_literal() {
    let root = root();
    let idx = index(&root.join(CONTRACT_SRC)).unwrap();
    let mut entries = vec![root.join("crates/busbar-plane-llm/src/lib.rs")];
    let mut crates: Vec<PathBuf> = std::fs::read_dir(root.join("crates"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    crates.sort();
    for c in crates {
        let Ok(rd) = std::fs::read_dir(c.join("tests/fixtures")) else {
            continue;
        };
        let mut fx: Vec<PathBuf> = rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "rs"))
            .collect();
        fx.sort();
        entries.extend(fx);
    }
    assert!(entries.len() > 1, "no fixture plugin found");
    let mut found = Vec::new();
    for e in &entries {
        found.extend(scan_tree(&idx, e, &root).unwrap());
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// The scan is RED on a planted base-less literal of a ZERO-bearing struct and GREEN on its spread.
#[test]
fn a_planted_full_literal_is_red_and_its_spread_green() {
    let idx = index(&root().join(CONTRACT_SRC)).unwrap();
    let red = scan_text(
        &idx,
        "plant.rs",
        "const S: StyleDecl = StyleDecl { name: AbiStr::ZERO, flags: 0, points: 1 };",
    )
    .unwrap();
    assert_eq!(red.len(), 1, "{red:?}");
    let green = scan_text(
        &idx,
        "plant.rs",
        "const S: StyleDecl = StyleDecl { points: 1, ..StyleDecl::ZERO };",
    )
    .unwrap();
    assert!(green.is_empty(), "{green:?}");
    // Every field carries a value: a base would be `clippy::needless_update`, so it is not judged.
    let valued = scan_text(
        &idx,
        "plant.rs",
        "const S: StyleDecl = StyleDecl { name: NAME, flags: 2, points: 1 };",
    )
    .unwrap();
    assert!(valued.is_empty(), "{valued:?}");
}
