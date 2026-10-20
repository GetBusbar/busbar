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
    // `ConnFacts` is a shared name too: the ABI struct states a `ZERO`, the transport stack's
    // Rust-side facts (derive `Default`, no ZERO) do not. The abi literal's fields pick the ABI one.
    let abi_facts: BTreeSet<String> = ["size", "offered_name", "agreed_protocol", "claim"]
        .map(String::from)
        .into();
    assert!(idx.judged("ConnFacts", &abi_facts));
    let stack_facts: BTreeSet<String> = ["sni", "alpn", "peer_cert"].map(String::from).into();
    assert!(!idx.judged("ConnFacts", &stack_facts));
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

/// Every builder a plugin may spread as a base exists, and its own body spreads `ZERO`, a parameter
/// it forwards, or another listed builder: the allow-list cannot outlive what it names.
#[test]
fn every_listed_builder_spreads_zero_itself() {
    let idx = index(&root().join(CONTRACT_SRC)).unwrap();
    for h in ZERO_HELPERS {
        assert_eq!(
            idx.helpers().get(*h),
            Some(&true),
            "`{h}` is not a contract builder whose body spreads ZERO"
        );
    }
}

/// A literal's type is resolved as far as the file says: a same-named type the plugin defines, or
/// one a `use` brings from elsewhere, is not the contract's.
#[test]
fn a_same_named_type_that_is_not_the_contracts_is_not_judged() {
    let idx = index(&root().join(CONTRACT_SRC)).unwrap();
    let lit = "fn f() -> ConnFacts { ConnFacts { size: 0, claim: X } }";
    let local = format!("struct ConnFacts {{ size: u32, claim: u8 }}\n{lit}");
    assert!(scan_text(&idx, "p.rs", &local).unwrap().is_empty());
    let other = format!("use crate::stack::ConnFacts;\n{lit}");
    assert!(scan_text(&idx, "p.rs", &other).unwrap().is_empty());
    let pathed = "fn f() { let _ = stack::ConnFacts { size: 0, claim: X }; }";
    assert!(scan_text(&idx, "p.rs", pathed).unwrap().is_empty());
    let ours = format!("use busbar_contract::abi::transport::ConnFacts;\n{lit}");
    assert_eq!(scan_text(&idx, "p.rs", &ours).unwrap().len(), 1);
}

/// A base is judged: `ZERO`, `default()` and a listed builder pass; any other base is a finding.
#[test]
fn a_base_that_is_not_zero_or_a_builder_is_red() {
    let idx = index(&root().join(CONTRACT_SRC)).unwrap();
    for ok in [
        "const S: Statement = Statement { size: 8, ..Statement::ZERO };",
        "const S: Statement = Statement { size: 8, ..statement(N, V, 4) };",
        "const S: Statement = Statement { size: 8, ..with_tail(statement(N, V, 4), &T) };",
    ] {
        assert!(scan_text(&idx, "p.rs", ok).unwrap().is_empty(), "{ok}");
    }
    let red = scan_text(
        &idx,
        "p.rs",
        "const S: Statement = Statement { size: 8, ..mine() };",
    )
    .unwrap();
    assert_eq!(red.len(), 1, "{red:?}");
}

/// The struct `name` in a contract file: its field names, and whether that file gives it a `ZERO`.
fn in_file(rel: &str, name: &str) -> (BTreeSet<String>, bool) {
    let p = root().join(CONTRACT_SRC).join(rel);
    let text = std::fs::read_to_string(&p).unwrap();
    let file = syn::parse_file(&text).unwrap();
    let mut fields = None;
    let mut zero = false;
    for item in &file.items {
        match item {
            syn::Item::Struct(s) if s.ident == name => {
                if let syn::Fields::Named(f) = &s.fields {
                    fields = Some(
                        f.named
                            .iter()
                            .filter_map(|f| f.ident.as_ref().map(ToString::to_string))
                            .collect(),
                    );
                }
            }
            syn::Item::Impl(i) if self_name(&i.self_ty).as_deref() == Some(name) => {
                zero |= i
                    .items
                    .iter()
                    .any(|it| matches!(it, syn::ImplItem::Const(c) if c.ident == "ZERO"));
            }
            _ => {}
        }
    }
    (
        fields.unwrap_or_else(|| panic!("{rel} defines no struct `{name}`")),
        zero,
    )
}

/// Each fixed exemption names a struct its file still defines, and that struct states no `ZERO`
/// (an exemption that gained one, or lost its struct, is stale).
#[test]
fn every_exemption_names_a_struct_with_no_zero() {
    for (rel, name, reason) in EXEMPT {
        assert!(!reason.is_empty());
        let (_, zero) = in_file(rel, name);
        assert!(!zero, "{rel} `{name}` states a ZERO but is listed exempt");
    }
}

/// The observe envelope is exempt for its generic `R` alone: it carries no field the host trusts
/// as a grant (no auth, scope, points, flags, kind, class, role or size).
#[test]
fn the_observe_envelope_carries_no_grant_field() {
    let (fields, _) = in_file("abi/mechanism/observe.rs", "Envelope");
    let want: BTreeSet<String> = ["result", "metrics", "diagnostics"]
        .map(String::from)
        .into();
    assert_eq!(
        fields, want,
        "the envelope's fields moved: re-judge its exemption"
    );
    for f in &fields {
        for word in [
            "auth", "scope", "point", "flag", "kind", "class", "role", "size",
        ] {
            assert!(!f.contains(word), "`{f}` reads as a grant field");
        }
    }
}
