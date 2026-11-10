// SPDX-License-Identifier: Apache-2.0
//! Admission-owned source checks complement the compiler's capability boundaries.
//! No implementation constructors or broad re-exports may escape a plugin crate.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Item, Meta, Token, UseTree, Visibility};

fn cfg_value(meta: &Meta) -> Option<bool> {
    match meta {
        Meta::Path(p) if p.is_ident("test") => Some(false),
        Meta::NameValue(n) if n.path.is_ident("feature") => match &n.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) if matches!(s.value().as_str(), "test-seal" | "test-support") => Some(false),
            _ => None,
        },
        Meta::List(l) => {
            let nested = Punctuated::<Meta, Token![,]>::parse_terminated
                .parse2(l.tokens.clone())
                .ok()?;
            let values: Vec<_> = nested.iter().map(cfg_value).collect();
            if l.path.is_ident("not") && values.len() == 1 {
                values[0].map(|v| !v)
            } else if l.path.is_ident("all") {
                if values.contains(&Some(false)) {
                    Some(false)
                } else if values.iter().all(|v| *v == Some(true)) {
                    Some(true)
                } else {
                    None
                }
            } else if l.path.is_ident("any") {
                if values.contains(&Some(true)) {
                    Some(true)
                } else if values.iter().all(|v| *v == Some(false)) {
                    Some(false)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

fn shipping(attrs: &[Attribute]) -> bool {
    !attrs
        .iter()
        .filter(|a| a.path().is_ident("cfg"))
        .any(|a| a.parse_args::<Meta>().ok().as_ref().and_then(cfg_value) == Some(false))
}

const EXPORTS: &[&str] = &[
    "door",
    "MACRO_DOOR",
    "DECLARES",
    "NAME",
    "ALIAS",
    "WORD",
    "KEY",
    "COMPOSES_OVER",
    "SESSION",
    "STORE",
    "HOOK",
    "linked",
];

fn public(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

fn export_tree(tree: &UseTree, errors: &mut Vec<String>) {
    match tree {
        UseTree::Path(p) => export_tree(&p.tree, errors),
        UseTree::Group(g) => g.items.iter().for_each(|t| export_tree(t, errors)),
        UseTree::Name(n) if EXPORTS.contains(&n.ident.to_string().as_str()) => (),
        UseTree::Rename(r)
            if r.ident == r.rename && EXPORTS.contains(&r.ident.to_string().as_str()) => {}
        _ => errors.push("unapproved public re-export (including wildcard/alias)".into()),
    }
}

fn surface(items: &[Item], errors: &mut Vec<String>) {
    for item in items {
        match item {
            Item::Mod(m) if shipping(&m.attrs) && public(&m.vis) => {
                if !matches!(
                    m.ident.to_string().as_str(),
                    "linked" | "compiled_in" | "door"
                ) {
                    errors.push(format!("public implementation module {}", m.ident));
                } else if let Some((_, items)) = &m.content {
                    surface(items, errors);
                } else {
                    errors.push(format!(
                        "public out-of-line implementation module {}",
                        m.ident
                    ));
                }
            }
            Item::Use(u) if shipping(&u.attrs) && public(&u.vis) => export_tree(&u.tree, errors),
            Item::Const(c) if shipping(&c.attrs) && public(&c.vis) => {
                if !EXPORTS.contains(&c.ident.to_string().as_str()) {
                    errors.push(format!("unapproved public constant {}", c.ident));
                }
            }
            Item::Fn(f) if shipping(&f.attrs) && public(&f.vis) => {
                errors.push(format!("public implementation function {}", f.sig.ident))
            }
            Item::Struct(s) if shipping(&s.attrs) && public(&s.vis) => {
                errors.push(format!("public implementation struct {}", s.ident))
            }
            Item::Enum(e) if shipping(&e.attrs) && public(&e.vis) => {
                errors.push(format!("public implementation enum {}", e.ident))
            }
            Item::Trait(t) if shipping(&t.attrs) && public(&t.vis) => {
                errors.push(format!("public implementation trait {}", t.ident))
            }
            Item::Type(t) if shipping(&t.attrs) && public(&t.vis) => {
                errors.push(format!("public implementation alias {}", t.ident))
            }
            Item::Static(s) if shipping(&s.attrs) && public(&s.vis) => {
                errors.push(format!("public implementation static {}", s.ident))
            }
            Item::ExternCrate(e) if shipping(&e.attrs) && public(&e.vis) => {
                errors.push("public extern crate".into())
            }
            Item::Macro(m) if shipping(&m.attrs) => {
                let name = m.mac.path.segments.last().unwrap().ident.to_string();
                if m.attrs.iter().any(|a| a.path().is_ident("macro_export")) {
                    errors.push("public implementation macro".into());
                }
                if name == "statement_extensions"
                    && m.mac
                        .tokens
                        .clone()
                        .into_iter()
                        .any(|t| matches!(t, proc_macro2::TokenTree::Ident(i) if i == "pub"))
                {
                    errors.push("public extension implementation data".into());
                }
                // Only the reviewed SDK door macros may manufacture root exports.
                if !matches!(
                    name.as_str(),
                    "include"
                        | "plugin_door"
                        | "export_door"
                        | "auth_door"
                        | "secret_door"
                        | "hook_door"
                        | "store_door"
                        | "exporter_door"
                        | "plane_door"
                        | "transport_door"
                        | "macro_rules"
                        | "auth_verify_door"
                        | "auth_outbound_door"
                        | "statement_extensions"
                        | "hyper_io"
                ) {
                    errors.push(format!("unapproved root macro expansion {name}"));
                }
            }
            _ => (),
        }
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Mod(x) => &x.attrs,
        Item::Fn(x) => &x.attrs,
        Item::Impl(x) => &x.attrs,
        Item::Use(x) => &x.attrs,
        Item::Struct(x) => &x.attrs,
        Item::Enum(x) => &x.attrs,
        Item::Const(x) => &x.attrs,
        Item::Static(x) => &x.attrs,
        Item::Type(x) => &x.attrs,
        Item::Trait(x) => &x.attrs,
        Item::Macro(x) => &x.attrs,
        Item::ExternCrate(x) => &x.attrs,
        _ => &[],
    }
}

#[derive(Default)]
struct Imports {
    errors: Vec<String>,
    includes: Vec<syn::Macro>,
}

impl<'ast> Visit<'ast> for Imports {
    fn visit_item(&mut self, item: &'ast Item) {
        if shipping(item_attrs(item)) {
            visit::visit_item(self, item);
        }
    }
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        let word = ident.to_string();
        if matches!(
            word.as_str(),
            "CallerBinding" | "test_caller_binding" | "KernelSeal" | "RawHost" | "HostLoan"
        ) || word == "busbar_kernel"
            || word.starts_with("busbar_kernel_")
            || matches!(
                word.as_str(),
                "busbar_plugin_loader"
                    | "busbar_migrations"
                    | "busbar_core_connector"
                    | "busbar_core_admin"
                    | "busbar_core_oauth2"
            )
        {
            self.errors
                .push(format!("production host-authority import/reference {word}"));
        }
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac.path.is_ident("include") {
            self.includes.push(mac.clone());
        }
        // SDK macros own their reviewed expansion; ordinary syntax paths are still visited.
        visit::visit_macro(self, mac);
    }
}

fn child_file(file: &Path, root: bool, module: &syn::ItemMod) -> Result<PathBuf, String> {
    for attr in &module.attrs {
        if attr.path().is_ident("path") {
            if let Meta::NameValue(n) = &attr.meta {
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) = &n.value
                {
                    return Ok(file.parent().unwrap().join(s.value()));
                }
            }
        }
    }
    let parent = file.parent().unwrap();
    let base = if root
        || matches!(
            file.file_name().and_then(|n| n.to_str()),
            Some("lib.rs" | "mod.rs" | "main.rs")
        ) {
        parent.to_path_buf()
    } else {
        parent.join(file.file_stem().unwrap())
    };
    let direct = base.join(format!("{}.rs", module.ident));
    if direct.is_file() {
        Ok(direct)
    } else {
        Ok(base.join(module.ident.to_string()).join("mod.rs"))
    }
}

fn source_tree(
    path: &Path,
    root: bool,
    generated_root: Option<&Path>,
    seen: &mut BTreeSet<PathBuf>,
    errors: &mut Vec<String>,
    policy_names: Option<&BTreeSet<String>>,
) {
    let path = path
        .canonicalize()
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let generated_root = generated_root
        .map(Path::to_path_buf)
        .or_else(|| generated_directory(&path));
    if !seen.insert(path.clone()) {
        return;
    }
    let parsed = syn::parse_file(&std::fs::read_to_string(&path).expect("source readable"))
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    if let Some(names) = policy_names {
        let mut check = Selectors {
            names: names.clone(),
            ..Default::default()
        };
        check.visit_file(&parsed);
        errors.extend(
            check
                .errors
                .into_iter()
                .map(|e| format!("{}: implementation selector {e}", path.display())),
        );
    }
    if root && policy_names.is_none() {
        surface(&parsed.items, errors);
    }
    let mut imports = Imports::default();
    imports.visit_file(&parsed);
    if policy_names.is_none() {
        errors.extend(
            imports
                .errors
                .into_iter()
                .map(|e| format!("{}: {e}", path.display())),
        );
    }
    for include in imports.includes {
        let child = if let Ok(literal) = syn::parse2::<syn::LitStr>(include.tokens.clone()) {
            path.parent().unwrap().join(literal.value())
        } else {
            let mapping: std::collections::BTreeMap<String, PathBuf> =
                std::env::var_os("BUSBAR_ARCHITECTURE_GENERATED")
                    .map(|file| {
                        serde_json::from_slice(
                            &std::fs::read(file).expect("generated inventory readable"),
                        )
                        .expect("generated inventory")
                    })
                    .unwrap_or_default();
            let key = format!("{}|{}", path.display(), include.tokens);
            if let Some(generated) = mapping.get(&key) {
                generated.clone()
            } else if let Some(generated) =
                generated_include(&path, &include, generated_root.as_deref())
            {
                generated
            } else {
                errors.push(format!("unresolved generated Rust include: {key}"));
                continue;
            }
        };
        source_tree(
            &child,
            root,
            generated_root.as_deref(),
            seen,
            errors,
            policy_names,
        );
    }
    child_modules(
        &parsed.items,
        &path,
        root,
        generated_root.as_deref(),
        seen,
        errors,
        policy_names,
    );
}

fn generated_directory(source: &Path) -> Option<PathBuf> {
    let env = std::env::var_os("BUSBAR_ARCHITECTURE_GENERATED_DIRS")?;
    let directories: std::collections::BTreeMap<PathBuf, PathBuf> =
        serde_json::from_slice(&std::fs::read(env).expect("generated directories readable"))
            .expect("generated directories");
    directories
        .iter()
        .filter(|(root, _)| source.starts_with(root))
        .max_by_key(|(root, _)| root.components().count())
        .map(|(_, output)| output.clone())
}

fn generated_include(
    source: &Path,
    include: &syn::Macro,
    inherited: Option<&Path>,
) -> Option<PathBuf> {
    let directory = inherited
        .map(Path::to_path_buf)
        .or_else(|| generated_directory(source))?;
    let concat = syn::parse2::<syn::ExprMacro>(include.tokens.clone()).ok()?;
    if !concat.mac.path.is_ident("concat") {
        return None;
    }
    let args = Punctuated::<syn::Expr, Token![,]>::parse_terminated
        .parse2(concat.mac.tokens)
        .ok()?;
    if args.len() != 2 {
        return None;
    }
    let syn::Expr::Macro(environment) = &args[0] else {
        return None;
    };
    // Match compiler syntax as an identifier, not a runtime implementation name.
    let env_macro: syn::Ident = syn::parse_quote!(env);
    if !environment
        .mac
        .path
        .get_ident()
        .is_some_and(|name| *name == env_macro)
        || syn::parse2::<syn::LitStr>(environment.mac.tokens.clone())
            .ok()?
            .value()
            != "OUT_DIR"
    {
        return None;
    }
    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Str(suffix),
        ..
    }) = &args[1]
    else {
        return None;
    };
    let suffix = suffix.value();
    if !suffix.starts_with('/') || suffix.contains("..") {
        return None;
    }
    Some(directory.join(&suffix[1..]))
}

fn child_modules(
    items: &[Item],
    file: &Path,
    root: bool,
    generated_root: Option<&Path>,
    seen: &mut BTreeSet<PathBuf>,
    errors: &mut Vec<String>,
    policy_names: Option<&BTreeSet<String>>,
) {
    for item in items {
        if let Item::Mod(module) = item {
            if policy_names.is_none() && !shipping(&module.attrs) {
                continue;
            }
            if let Some((_, nested)) = &module.content {
                let parent = file.parent().unwrap();
                let base = if root
                    || matches!(
                        file.file_name().and_then(|n| n.to_str()),
                        Some("lib.rs" | "mod.rs" | "main.rs")
                    ) {
                    parent.to_path_buf()
                } else {
                    parent.join(file.file_stem().unwrap())
                };
                child_modules(
                    nested,
                    &base.join(module.ident.to_string()).join("mod.rs"),
                    false,
                    generated_root,
                    seen,
                    errors,
                    policy_names,
                );
            } else {
                source_tree(
                    &child_file(file, root, module).expect("module path"),
                    false,
                    generated_root,
                    seen,
                    errors,
                    policy_names,
                );
            }
        }
    }
}

#[test]
fn public_surface_rejects_constructors_aliases_and_cfg_escape() {
    for code in [
        "pub struct Runtime;",
        "pub mod runtime {}",
        "pub use private::*;",
        "pub use private::Runtime as door;",
        "#[cfg(any(test, feature = \"ordinary\"))] pub fn new() {}",
        "pub static RUNTIME: u8 = 0;",
        "pub enum Runtime { New }",
        "#[cfg(not(test))] pub fn new() {}",
        "#[macro_export] macro_rules! leak { () => {} }",
        "unapproved_root_macro!{}",
    ] {
        let mut errors = Vec::new();
        surface(&syn::parse_file(code).unwrap().items, &mut errors);
        assert!(!errors.is_empty(), "accepted {code}");
    }
    let allowed = "mod runtime; pub use runtime::{door, MACRO_DOOR}; #[cfg(test)] pub struct Fixture; pub mod compiled_in { pub mod door { pub use crate::{door, MACRO_DOOR}; } }";
    let mut errors = Vec::new();
    surface(&syn::parse_file(allowed).unwrap().items, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn private_import_alias_and_test_cfg_are_distinguished() {
    for code in [
        "use busbar_contract::services::CallerBinding as Anything;",
        "type Any = busbar_kernel::SomeType;",
    ] {
        let mut imports = Imports::default();
        imports.visit_file(&syn::parse_file(code).unwrap());
        assert!(!imports.errors.is_empty(), "accepted {code}");
    }
    let mut imports = Imports::default();
    imports.visit_file(&syn::parse_file("#[cfg(test)] mod tests { use busbar_kernel::SomeType; } use busbar_contract::abi::sdk::kind::AuthKind;").unwrap());
    assert!(imports.errors.is_empty(), "{:?}", imports.errors);
}

#[derive(Default)]
struct Selectors {
    names: BTreeSet<String>,
    errors: Vec<String>,
    seen: BTreeSet<(usize, usize)>,
}

// This checks direct spellings, not alias resolution or arbitrary macro expansion.
// Recursing through tokens keeps imports, cfg branches, macro bodies and doc
// attributes visible even when they are not active for the current Cargo target.
fn concrete_package_references(
    input: proc_macro2::TokenStream,
    packages: &BTreeSet<String>,
) -> BTreeSet<String> {
    fn word(value: &str, packages: &BTreeSet<String>, found: &mut BTreeSet<String>) {
        let value = value.strip_prefix("r#").unwrap_or(value);
        let canonical = value.replace('_', "-");
        if packages.contains(&canonical) {
            found.insert(canonical);
        } else if let Some(library) = canonical.strip_prefix("lib") {
            if packages.contains(library) {
                found.insert(library.to_owned());
            }
        }
    }
    fn tokens(
        input: proc_macro2::TokenStream,
        packages: &BTreeSet<String>,
        found: &mut BTreeSet<String>,
    ) {
        for token in input {
            match token {
                proc_macro2::TokenTree::Group(group) => tokens(group.stream(), packages, found),
                proc_macro2::TokenTree::Ident(ident) => word(&ident.to_string(), packages, found),
                proc_macro2::TokenTree::Literal(literal) => {
                    let value = match syn::parse_str::<syn::Lit>(&literal.to_string()) {
                        Ok(syn::Lit::Str(value)) => Some(value.value()),
                        Ok(syn::Lit::ByteStr(value)) => {
                            Some(String::from_utf8_lossy(&value.value()).into_owned())
                        }
                        _ => None,
                    };
                    if let Some(value) = value {
                        for part in value
                            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
                        {
                            word(part, packages, found);
                        }
                    }
                }
                _ => (),
            }
        }
    }
    let mut found = BTreeSet::new();
    tokens(input, packages, &mut found);
    found
}

#[test]
fn direct_owner_references_cannot_hide_in_cfg_macros_or_literals() {
    let packages = BTreeSet::from(["busbar-store-fixture-owner".to_owned()]);
    for code in [
        "use busbar_store_fixture_owner::door as renamed;",
        "use r#busbar_store_fixture_owner::door;",
        "#[cfg(test)] fn f() { busbar_store_fixture_owner::door(); }",
        "macro_rules! f { () => { busbar_store_fixture_owner::door() } }",
        r#"#[cfg(feature = "busbar-store-fixture-owner")] fn f() {}"#,
        r#"fn f() { load("/plugins/libbusbar_store_fixture_owner.so"); }"#,
        r#"fn f() { load(b"busbar-store-fixture-owner"); }"#,
        "/// The busbar-store-fixture-owner package.\nfn f() {}",
    ] {
        assert_eq!(
            concrete_package_references(code.parse().unwrap(), &packages),
            packages,
            "unchecked owner reference: {code}"
        );
    }
    let generic = r#"fn f() { metric("busbar_store_fixture_owner_requests_total");
        describe("http", "env", "busbar-store-fixture-owner-extra"); }"#;
    assert!(concrete_package_references(generic.parse().unwrap(), &packages).is_empty());
}

impl<'ast> Visit<'ast> for Selectors {
    // Selection predicates also occur outside `if`: iterator filters, match guards,
    // assigned booleans, and `while` conditions all execute policy.
    fn visit_expr_binary(&mut self, expr: &'ast syn::ExprBinary) {
        if matches!(expr.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
            self.inspect(expr);
        }
        visit::visit_expr_binary(self, expr);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac.path.is_ident("matches") {
            self.inspect(&mac.tokens);
        }
        visit::visit_macro(self, mac);
    }

    fn visit_expr_if(&mut self, expr: &'ast syn::ExprIf) {
        self.inspect(&expr.cond);
        visit::visit_expr_if(self, expr);
    }
    fn visit_expr_match(&mut self, expr: &'ast syn::ExprMatch) {
        for arm in &expr.arms {
            self.inspect(&arm.pat);
        }
        visit::visit_expr_match(self, expr);
    }
}

impl Selectors {
    fn inspect(&mut self, syntax: &impl quote::ToTokens) {
        fn tokens(
            input: proc_macro2::TokenStream,
            names: &BTreeSet<String>,
            found: &mut Vec<String>,
            seen: &mut BTreeSet<(usize, usize)>,
        ) {
            for token in input {
                match token {
                    proc_macro2::TokenTree::Group(g) => tokens(g.stream(), names, found, seen),
                    proc_macro2::TokenTree::Literal(l) => {
                        if let Ok(s) = syn::parse_str::<syn::LitStr>(&l.to_string()) {
                            let start = l.span().start();
                            if names.contains(&s.value()) && seen.insert((start.line, start.column))
                            {
                                found.push(s.value());
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
        tokens(
            syntax.to_token_stream(),
            &self.names,
            &mut self.errors,
            &mut self.seen,
        );
    }
}

#[test]
fn implementation_selection_is_rejected_but_diagnostics_are_not_selectors() {
    let mut check = Selectors {
        names: ["sqlite".into()].into(),
        ..Default::default()
    };
    check.visit_file(&syn::parse_file("fn policy(name: &str) { if name == \"sqlite\" {} match name { \"sqlite\" => (), _ => () }; }").unwrap());
    assert_eq!(check.errors.len(), 2);
    check.errors.clear();
    check.visit_file(&syn::parse_file("fn diagnostic() { println!(\"sqlite\"); }").unwrap());
    assert!(check.errors.is_empty());
}

#[test]
fn selector_checks_cannot_be_disabled_by_test_or_platform_attributes() {
    for code in [
        "#[cfg(test)] fn f(n: &str) { if n == \"fixture-owner\" {} }",
        "#[cfg(windows)] fn f(n: &str) { match n { \"fixture-owner\" => (), _ => () } }",
        "#[cfg(feature = \"test-support\")] fn f(n: &str) { if n == \"fixture-owner\" {} }",
    ] {
        let mut check = Selectors {
            names: ["fixture-owner".into()].into(),
            ..Default::default()
        };
        check.visit_file(&syn::parse_file(code).unwrap());
        assert_eq!(check.errors, ["fixture-owner"], "unchecked code: {code}");
    }
}

#[test]
fn selectors_reject_standalone_predicates_and_overlapping_protocol_names() {
    for code in [
        r#"fn f(name: &str) -> bool { name == "http" }"#,
        r#"fn f(name: &str) -> bool { name != "env" }"#,
        r#"fn f(name: &str) -> bool { matches!(name, "ws" | "http") }"#,
        r#"fn f(names: &[&str]) { let _ = names.iter().find(|name| **name == "http"); }"#,
        r#"#[cfg(test)] fn f(name: &str) { let selected = name == "http"; }"#,
        r#"#[cfg(windows)] fn f(name: &str) -> bool { matches!(name, "env") }"#,
        r#"fn f(name: &str) { match name { candidate if candidate == "ws" => (), _ => () } }"#,
        r#"fn f(name: &str) { while name == "http" {} }"#,
    ] {
        let mut check = Selectors {
            names: ["http".into(), "ws".into(), "env".into()].into(),
            ..Default::default()
        };
        check.visit_file(&syn::parse_file(code).unwrap());
        assert!(!check.errors.is_empty(), "unchecked predicate: {code}");
    }
    let mut check = Selectors {
        names: ["http".into(), "ws".into(), "env".into()].into(),
        ..Default::default()
    };
    check.visit_file(
        &syn::parse_file(
            r#"fn f(name: &str) { if name == "http" { match name { "ws" => (), _ => () } } }"#,
        )
        .unwrap(),
    );
    assert_eq!(
        check.errors,
        ["http", "ws"],
        "overlapping visitor paths report each source literal once"
    );
}

#[test]
fn core_policy_checks_follow_included_rust() {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("core-included-policy-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let root = directory.join("root.rs");
    let included = directory.join("included.rs");
    std::fs::write(&root, "include!(\"included.rs\");").unwrap();
    std::fs::write(&included, "fn f(n: &str) { if n == \"fixture-owner\" {} }").unwrap();
    let mut errors = Vec::new();
    source_tree(
        &root,
        false,
        None,
        &mut BTreeSet::new(),
        &mut errors,
        Some(&["fixture-owner".into()].into()),
    );
    std::fs::remove_dir_all(&directory).unwrap();
    assert_eq!(
        errors.len(),
        1,
        "included source was not judged: {errors:?}"
    );
    assert!(errors[0].contains("implementation selector fixture-owner"));
}

#[test]
fn core_policy_does_not_select_implementations() {
    let Some(inventory) = std::env::var_os("BUSBAR_ARCHITECTURE_POLICY_SOURCES") else {
        return;
    };
    let rows: std::collections::BTreeMap<String, Vec<String>> = serde_json::from_slice(
        &std::fs::read(inventory).expect("policy source inventory readable"),
    )
    .expect("policy inventory");
    let names: BTreeSet<String> = rows["names"].iter().cloned().collect();
    assert!(!rows["paths"].is_empty());
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    let packages = rows["plugin_packages"].iter().cloned().collect();
    assert!(!rows["raw_paths"].is_empty(), "no handwritten core sources");
    for path in &rows["raw_paths"] {
        let source = std::fs::read_to_string(path).expect("handwritten core source readable");
        let tokens = source.parse().unwrap_or_else(|e| panic!("{path}: {e}"));
        errors.extend(
            concrete_package_references(tokens, &packages)
                .into_iter()
                .map(|package| format!("{path}: direct concrete package reference {package}")),
        );
    }
    // Visit actual Cargo target roots first: custom binary/test names have the
    // same sibling-module resolution as lib.rs, not foo/bar.rs resolution.
    let roots: BTreeSet<String> = rows["roots"].iter().cloned().collect();
    for path in roots.iter().chain(rows["paths"].iter()) {
        source_tree(
            Path::new(path),
            roots.contains(path),
            None,
            &mut seen,
            &mut errors,
            Some(&names),
        );
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn candidate_plugin_surfaces_follow_the_trusted_inventory() {
    let Some(inventory) = std::env::var_os("BUSBAR_ARCHITECTURE_SOURCES") else {
        return;
    };
    // The trusted checker writes this list, not the candidate repository. CI requires this
    // env var; the local parser regression tests can run without checking the fleet.
    let paths: Vec<PathBuf> =
        serde_json::from_slice(&std::fs::read(inventory).expect("inventory readable"))
            .expect("source inventory");
    assert!(!paths.is_empty(), "no source candidates");
    let mut errors = Vec::new();
    for path in paths {
        source_tree(&path, true, None, &mut BTreeSet::new(), &mut errors, None);
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn policy_follows_custom_crate_root_and_nonshipping_modules() {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("custom-root-policy-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let root = directory.join("custom-binary.rs");
    std::fs::write(&root, "#[cfg(test)] mod sibling;").unwrap();
    std::fs::write(
        directory.join("sibling.rs"),
        "fn f(n: &str) { if n == \"fixture-owner\" {} }",
    )
    .unwrap();
    let mut errors = Vec::new();
    source_tree(
        &root,
        true,
        None,
        &mut BTreeSet::new(),
        &mut errors,
        Some(&["fixture-owner".into()].into()),
    );
    std::fs::remove_dir_all(&directory).unwrap();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("implementation selector fixture-owner"));
}

#[test]
fn included_source_uses_the_compiling_crates_generated_directory() {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("included-output-policy-{}", std::process::id()));
    let outside = directory.join("shared");
    let output = directory.join("out");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&output).unwrap();
    let root = directory.join("root.rs");
    std::fs::write(&root, "include!(\"shared/part.rs\");").unwrap();
    std::fs::write(
        outside.join("part.rs"),
        "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));",
    )
    .unwrap();
    std::fs::write(
        output.join("generated.rs"),
        "fn f(n: &str) { if n == \"fixture-owner\" {} }",
    )
    .unwrap();
    let mut errors = Vec::new();
    source_tree(
        &root,
        true,
        Some(&output),
        &mut BTreeSet::new(),
        &mut errors,
        Some(&["fixture-owner".into()].into()),
    );
    std::fs::remove_dir_all(&directory).unwrap();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("implementation selector fixture-owner"));
}
