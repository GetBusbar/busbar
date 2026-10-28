//! THE C HEADER GENERATOR, DRIVEN OVER SYNTHETIC SOURCES AND OVER THE REAL TREE.
//!
//! BUSBAR-1.6.0.md §11.5 (line 1322) and #84 (line 2237): a third party builds a plugin from the
//! generated C header alone. These tests pin what the generator maps, how it names and orders what
//! it maps, and that it FAILS, naming the item, on what it cannot map.

mod render;

use render::{first_difference, render_sources, Src};

fn render(files: &[(&str, &str)], golden: &str) -> Result<String, String> {
    let srcs: Vec<Src<'_>> = files
        .iter()
        .map(|(k, t)| Src {
            kind: k,
            rel: "planted.rs",
            text: t,
        })
        .collect();
    render_sources(&srcs, golden)
}

#[test]
fn scalars_pointers_arrays_and_constants_map_to_c() {
    let h = render(
        &[(
            "store",
            r#"
            pub const ABI_VERSION: u32 = 3;
            pub const BIG: u64 = 1 << 40;
            pub const NAME: &str = "store";
            pub const DOOR: &[u8] = b"door\0";
            pub const LEN: usize = 16 * 1024;
            #[repr(C)]
            pub struct Pair {
                pub a: u32,
                pub p: *const u8,
                pub m: *mut u64,
                pub pp: *const *const u8,
                pub arr: [u8; 4],
                pub f: f64,
                pub b: bool,
                pub n: usize,
                pub default: u8,
                pub v: *mut std::os::raw::c_void,
            }
            "#,
        )],
        "",
    )
    .expect("renders");
    for want in [
        "#define BB_STORE_ABI_VERSION UINT32_C(3)",
        "#define BB_STORE_BIG UINT64_C(0x10000000000)",
        "#define BB_STORE_NAME \"store\"",
        "#define BB_STORE_DOOR \"door\"",
        "#define BB_STORE_LEN ((size_t)16384)",
        "struct bb_store_Pair {",
        "    uint32_t a;",
        "    const uint8_t *p;",
        "    uint64_t *m;",
        "    const uint8_t *const *pp;",
        "    uint8_t arr[4];",
        "    double f;",
        "    bool b;",
        "    size_t n;",
        "    uint8_t default_;",
        "    void *v;",
    ] {
        assert!(h.contains(want), "missing `{want}` in:\n{h}");
    }
}

/// A struct stated through `abi_struct!` renders exactly as the same struct written plainly, docs
/// and order included; `abi_op!`/`abi_answers!` invocations are glue and render nothing.
#[test]
fn an_abi_struct_declaration_renders_as_the_plain_struct() {
    let plain = r#"
        pub const BEFORE: u32 = 1;
        /// The pair.
        #[repr(C)]
        pub struct Pair {
            /// The count.
            pub a: u32,
            pub p: *const u8,
        }
        pub const AFTER: u32 = 2;
        #[repr(C)]
        pub struct Holder { pub pair: Pair }
        "#;
    let declared = r#"
        pub const BEFORE: u32 = 1;
        abi_struct! {
            /// The pair.
            #[repr(C)]
            pub struct Pair {
                /// The count.
                pub a: u32,
                pub p: *const u8,
            }
        }
        pub const AFTER: u32 = 2;
        abi_struct! {
            #[repr(C)]
            pub struct Holder { pub pair: Pair }
        }
        abi_op! {
            pub fn check_pair(out: &Pair) as "pair", PAIR_RULES { code(a, 0, 1); }
        }
        abi_answers! { cx: (); }
        "#;
    let want = render(&[("store", plain)], "").expect("the plain source renders");
    let got = render(&[("store", declared)], "").expect("the declared source renders");
    assert_eq!(got, want);
}

#[test]
fn enums_newtypes_and_function_pointers_map_and_order_by_dependency() {
    let h = render(
        &[(
            "store",
            r#"
            #[repr(u8)]
            pub enum Kind { A = 1, B, C = 7 }
            #[repr(transparent)]
            pub struct Code(pub u8);
            pub type Cb = extern "C" fn(x: *mut Outer, c: Code) -> Code;
            #[repr(C)]
            pub struct Outer { pub inner: Inner, pub cb: Option<Cb> }
            #[repr(C)]
            pub struct Inner { pub k: Kind }
            "#,
        )],
        "",
    )
    .expect("renders");
    for want in [
        "typedef uint8_t bb_store_Kind;",
        "#define BB_STORE_Kind_A ((bb_store_Kind)1)",
        "#define BB_STORE_Kind_B ((bb_store_Kind)2)",
        "#define BB_STORE_Kind_C ((bb_store_Kind)7)",
        "typedef uint8_t bb_store_Code;",
        "typedef bb_store_Code (*bb_store_Cb)(bb_store_Outer *, bb_store_Code);",
        "    bb_store_Cb cb;",
        "    bb_store_Inner inner;",
    ] {
        assert!(h.contains(want), "missing `{want}` in:\n{h}");
    }
    let inner = h.find("struct bb_store_Inner {").expect("inner defined");
    let outer = h.find("struct bb_store_Outer {").expect("outer defined");
    assert!(inner < outer, "a struct held by value is defined first");
}

#[test]
fn the_kind_prefix_keeps_one_rust_name_in_two_kinds_apart() {
    let h = render(
        &[
            (
                "auth",
                "#[repr(C)]\npub struct Span { pub off: u32 }\npub const MAX: u32 = 1;\n",
            ),
            (
                "hook",
                "#[repr(C)]\npub struct Span { pub len: u32 }\n#[repr(C)]\npub struct Holder { pub s: crate::abi::auth::Span, pub t: Span }\npub const MAX: u32 = 2;\n",
            ),
        ],
        "",
    )
    .expect("renders");
    assert!(h.contains("struct bb_auth_Span {"), "{h}");
    assert!(h.contains("struct bb_hook_Span {"), "{h}");
    assert!(
        h.contains("    bb_auth_Span s;"),
        "a kind path resolves: {h}"
    );
    assert!(
        h.contains("    bb_hook_Span t;"),
        "a bare name is the own kind's: {h}"
    );
    assert!(h.contains("#define BB_AUTH_MAX UINT32_C(1)"), "{h}");
    assert!(h.contains("#define BB_HOOK_MAX UINT32_C(2)"), "{h}");
}

#[test]
fn a_construct_with_no_c_mapping_fails_naming_the_item() {
    let e = render(
        &[(
            "store",
            "#[repr(C)]\npub struct Bad { pub ok: u32, pub s: String, pub r: &'static str }\n",
        )],
        "",
    )
    .expect_err("an unmappable field must fail");
    assert!(e.contains("`Bad`"), "names the struct: {e}");
    assert!(e.contains("field `s`"), "names the field: {e}");
    assert!(e.contains("String"), "names the type: {e}");
    assert!(e.contains("field `r`"), "names the second field too: {e}");

    let e = render(
        &[(
            "store",
            "#[repr(C)]\npub struct Holder { pub v: Vec<u8> }\n",
        )],
        "",
    )
    .expect_err("a generic type must fail");
    assert!(e.contains("Vec"), "{e}");

    let e = render(&[("store", "#[repr(u8)]\npub enum Data { A(u32) }\n")], "")
        .expect_err("an enum with data must fail");
    assert!(e.contains("`Data`"), "{e}");

    let e = render(&[("nonsense", "")], "").expect_err("an unknown kind must fail");
    assert!(e.contains("nonsense"), "{e}");

    let e = render(&[("store", "item macro_wanted! {}\n")], "")
        .expect_err("source that does not parse must fail");
    assert!(e.contains("does not parse"), "{e}");
}

#[test]
fn a_type_without_a_c_layout_marker_is_rust_only() {
    let h = render(
        &[(
            "store",
            "pub struct RustOnly { pub s: String }\npub enum Fault { A, B }\n#[repr(C)]\npub struct Real { pub a: u8 }\n",
        )],
        "",
    )
    .expect("renders");
    assert!(!h.contains("RustOnly"), "{h}");
    assert!(!h.contains("Fault"), "{h}");
    assert!(h.contains("struct bb_store_Real {"), "{h}");
}

#[test]
fn the_golden_pins_size_alignment_and_offsets_and_must_agree_with_the_struct() {
    let src = [(
        "store",
        "#[repr(C)]\npub struct Inner { pub k: u32, pub w: u64 }\n",
    )];
    let golden = "StoreInner.k=0\nStoreInner.w=8\nStoreInner.__size=16\nStoreInner.__align=8\n";
    let h = render(&src, golden).expect("renders");
    for want in [
        "BB_ASSERT(sizeof(bb_store_Inner) == 16, ",
        "BB_ASSERT(BB_ALIGNOF(bb_store_Inner) == 8, ",
        "BB_ASSERT(offsetof(bb_store_Inner, k) == 0, ",
        "BB_ASSERT(offsetof(bb_store_Inner, w) == 8, ",
        "1 of 1 structures are pinned",
    ] {
        assert!(h.contains(want), "missing `{want}` in:\n{h}");
    }
    let skewed = format!("{golden}StoreInner.ghost=4\n");
    let e = render(&src, &skewed).expect_err("a golden field the struct lacks must fail");
    assert!(e.contains("ghost"), "{e}");
    assert!(e.contains("Inner"), "{e}");
}

#[test]
fn the_store_ops_table_and_its_slots_come_from_the_slot_macro() {
    let h = render(
        &[
            (
                "mech",
                "use std::os::raw::c_void;\npub const LIFECYCLE_SLOTS: u32 = 9;\n#[repr(C)]\npub struct OpsHead { pub size: u32 }\npub type Op = extern \"C\" fn(i: *mut c_void) -> u8;\n",
            ),
            (
                "store",
                "store_slots! {\n  0 PUT_KEY put_key BlobIn, OutHead, Off, Call, HostCap, \"put; with a semicolon\";\n  1 GET_KEY get_key IdIn, OutHead, Off, Call, Fixed, \"get\";\n}\nkind_slots! { PUT_KEY => BlobIn, OutHead; }\n",
            ),
        ],
        "",
    )
    .expect("renders");
    for want in [
        "struct bb_store_Ops {",
        "    bb_mech_OpsHead head;",
        "    bb_mech_Op put_key;",
        "    bb_mech_Op get_key;",
        "#define BB_STORE_SLOT_PUT_KEY UINT32_C(9)",
        "#define BB_STORE_SLOT_GET_KEY UINT32_C(10)",
    ] {
        assert!(h.contains(want), "missing `{want}` in:\n{h}");
    }
}

#[test]
fn an_inline_module_constant_carries_the_module_name_and_resolves_the_mechanism() {
    let h = render(
        &[
            ("mech", "pub const LIFECYCLE_SLOTS: u32 = 9;\n"),
            (
                "secret",
                "pub mod slot {\n    pub const RESOLVE: u32 = LIFECYCLE_SLOTS;\n}\npub const SLOTS: u32 = LIFECYCLE_SLOTS + 1;\n",
            ),
        ],
        "",
    )
    .expect("renders");
    assert!(
        h.contains("#define BB_SECRET_SLOT_RESOLVE UINT32_C(9)"),
        "{h}"
    );
    assert!(h.contains("#define BB_SECRET_SLOTS UINT32_C(10)"), "{h}");
}

#[test]
fn rendering_is_deterministic_and_the_first_difference_names_its_line() {
    let src = [(
        "store",
        "pub const A: u32 = 1;\n#[repr(C)]\npub struct S { pub a: u8 }\n",
    )];
    let a = render(&src, "").expect("renders");
    let b = render(&src, "").expect("renders");
    assert_eq!(a, b);
    assert_eq!(first_difference(&a, &b), None);
    let edited = a.replacen("UINT32_C(1)", "UINT32_C(2)", 1);
    let d = first_difference(&edited, &a).expect("differs");
    assert!(d.starts_with("line "), "{d}");
    assert!(
        d.contains("UINT32_C(2)") && d.contains("UINT32_C(1)"),
        "{d}"
    );
    let short = first_difference("a\nb\n", "a\nb\nc\n").expect("differs");
    assert!(
        short.contains("line 3") && short.contains("<end of file>"),
        "{short}"
    );
}

#[test]
fn the_committed_header_is_what_the_sources_render() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    };
    let mut texts: Vec<(String, String, String)> = Vec::new();
    for (kind, _, path, folder) in render::SOURCES {
        let rel_root = format!("{}/{path}", render::ABI);
        if *folder {
            let mut rels: Vec<String> = Vec::new();
            let mut stack = vec![rel_root.clone()];
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(root.join(&dir)).expect("an ABI folder") {
                    let name = entry.expect("a dir entry").file_name();
                    let rel = format!("{dir}/{}", name.to_string_lossy());
                    let abs = root.join(&rel);
                    if abs.is_dir() {
                        if name != "tests" {
                            stack.push(rel);
                        }
                    } else if rel.ends_with(".rs") {
                        rels.push(rel);
                    }
                }
            }
            rels.sort();
            for rel in rels {
                let text = read(&rel);
                texts.push(((*kind).to_string(), rel, text));
            }
        } else {
            texts.push(((*kind).to_string(), rel_root.clone(), read(&rel_root)));
        }
    }
    let srcs: Vec<Src<'_>> = texts
        .iter()
        .map(|(k, r, t)| Src {
            kind: k,
            rel: r,
            text: t,
        })
        .collect();
    let rendered = render::render_sources_pinned(&srcs, &read(render::GOLDEN))
        .unwrap_or_else(|e| panic!("the ABI sources do not render: {e}"));
    if std::env::var_os("BUSBAR_ABI_HEADER_WRITE").is_some() {
        std::fs::write(root.join(render::HEADER), &rendered).expect("write the header");
        return;
    }
    if let Some(d) = first_difference(&read(render::HEADER), &rendered) {
        panic!(
            "{} drifted at {d}; run `{}`",
            render::HEADER,
            render::REGENERATE
        );
    }
}

/// Audit contract-include #1: a struct the golden records by its module path
/// (`tkind::route::RouteMatch`) or under its alias (`MechStr` for `AbiStr`) is pinned like any
/// other, and the real tree's render fails, naming it, on a struct the golden does not record.
#[test]
fn every_struct_is_pinned_by_its_module_path_or_alias_and_an_unpinned_one_fails() {
    use render::render_sources_pinned;
    let render_pinned = |files: &[(&str, &str)], golden: &str| {
        let srcs: Vec<Src<'_>> = files
            .iter()
            .map(|(k, t)| Src {
                kind: k,
                rel: "planted.rs",
                text: t,
            })
            .collect();
        render_sources_pinned(&srcs, golden)
    };
    let routed = [(
        "transport",
        "#[repr(C)]\npub struct Routed { pub a: u32 }\n",
    )];
    let h = render_pinned(
        &routed,
        "tkind::route::Routed.a=0\ntkind::route::Routed.__size=4\ntkind::route::Routed.__align=4\n",
    )
    .expect("a struct recorded by its module path is pinned");
    for want in [
        "BB_ASSERT(sizeof(bb_transport_Routed) == 4, ",
        "BB_ASSERT(offsetof(bb_transport_Routed, a) == 0, ",
        "1 of 1 structures are pinned",
    ] {
        assert!(h.contains(want), "missing `{want}` in:\n{h}");
    }
    let aliased = [(
        "mech",
        "#[repr(C)]\npub struct AbiStr { pub ptr: *const u8, pub len: usize }\n",
    )];
    let h = render_pinned(
        &aliased,
        "MechStr.ptr=0\nMechStr.len=8\nMechStr.__size=16\nMechStr.__align=8\n",
    )
    .expect("the golden's alias pins its struct");
    assert!(
        h.contains("BB_ASSERT(sizeof(bb_mech_AbiStr) == 16, "),
        "missing the alias's pin in:\n{h}"
    );
    let e = render_pinned(&routed, "").expect_err("an unpinned struct must fail");
    assert!(e.contains("bb_transport_Routed"), "{e}");
    assert!(e.contains("is not pinned"), "{e}");
    assert!(
        render(&routed, "").is_ok(),
        "a synthetic fragment may pin only what it tests"
    );
}
