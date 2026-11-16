// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §15 rule 13 (FU5 (b), MIN3-BLOCKER-RULINGS B25): a dlopened library leaves the loader only by one of
//! IF §11.1's two exits, so no other unload site exists (I13).
//!
//! (a) admitted: the library moves into the image table (`instance.rs`) and is never unloaded;
//! (b) refused before admission: `stage::dlclose_on_worker(lib)`, called only from stage.rs
//!     `load_via_staged_file` (the post-dlopen `verify_pinned` failure) and from admit.rs (the step-9 refusals).
//!
//! A source scan of every production file under `crates/` (syn, no types; test code is not scanned). Findings:
//! 1. libloading's `Library` named (a path or an import) outside stage.rs and the image table;
//! 2. a `Library` constructed (`Library::new`, `open`, `this`, `from_raw`, ...) outside stage.rs
//!    `dlopen_on_worker` and the `RTLD_NOLOAD` probe `name_still_loaded`;
//! 3. a `dlclose_on_worker` call outside the two exits, or a definition of it other than stage.rs's one;
//! 4. a raw unload anywhere: a `dlclose`/`FreeLibrary` path or foreign fn, `Library::close`, or `.close()`
//!    on a `Library` binding;
//! 5. an explicit drop of a `Library` binding (`drop`, `mem::drop`, `ManuallyDrop::{drop, take, into_inner}`)
//!    outside `dlclose_on_worker`, and any `ManuallyDrop::{drop, take, into_inner}` in the image table;
//! 6. a struct or enum field holding a `Library` not wrapped in `ManuallyDrop` (its owner's drop would unload
//!    it: exit (a) holds it as `ManuallyDrop<Library>`);
//! 7. an `impl Drop for Image` or `for LoadedImage` (no `Drop` of `Image` unloads it).
//!
//! A `Library` binding is a fn parameter or `let` whose type names `Library`, or a `let` initialised from
//! `dlopen_on_worker`, `load_library_from_bytes`, `load_via_memfd`, `load_via_staged_file` or a `Library`
//! constructor (through `?`, a method chain, a `match` scrutinee or an `unsafe` block; a tuple pattern binds
//! its first element, the `(Library, Staged)` shape). The scan sees names, not types: an implicit end-of-scope
//! drop is the residual it cannot see, which C-ADMIT-UNLOAD covers at run time.

use std::collections::HashSet;
use std::path::Path;

use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Block, Expr, FnArg, GenericArgument, ImplItem, Item, Pat, PathArguments, Signature, Stmt, Type,
    UseTree,
};

use super::core_src::core_files;
use super::{impl_item_attrs, is_test, item_attrs, Outcome};

/// The file holding `dlopen_on_worker`, `dlclose_on_worker` and the staged loads.
pub(crate) const STAGE: &str = "crates/plugin-loader/src/stage.rs";
/// The loader's process-wide image table (IF §10.4 `Image`: `instance.rs`), exit (a).
pub(crate) const IMAGE_TABLE: &str = "crates/plugin-loader/src/instance.rs";
/// Admit, whose step-9 refusals take exit (b).
pub(crate) const ADMIT: &str = "crates/plugin-loader/src/admit.rs";
/// The unload of exit (b).
const EXIT_B: &str = "dlclose_on_worker";
/// Calls whose value is a freshly opened `Library` (alone or first in a tuple).
const OPENERS: [&str; 4] = [
    "dlopen_on_worker",
    "load_library_from_bytes",
    "load_via_memfd",
    "load_via_staged_file",
];
/// The two stage.rs functions that may construct a `Library`.
const CONSTRUCTORS: [&str; 2] = ["dlopen_on_worker", "name_still_loaded"];
/// Raw unload calls and foreign declarations.
const RAW_UNLOADS: [&str; 2] = ["dlclose", "FreeLibrary"];

pub(crate) fn rule_13(root: &Path) -> Outcome {
    Ok(unload_findings(&core_files(root)?))
}

/// Rule 13 over `(repo-relative path, source)` pairs of core's production files.
pub(crate) fn unload_findings(files: &[(String, String)]) -> Vec<String> {
    let mut findings = Vec::new();
    let mut definitions = 0;
    for (path, source) in files {
        let file = match syn::parse_file(source) {
            Ok(file) => file,
            // Fail closed where a `Library` can live: libloading is the loader's alone (cargo-deny).
            Err(error) if path.starts_with("crates/plugin-loader/") => {
                findings.push(format!(
                    "{path}: syn could not parse the file ({error}), so rule 13 cannot vouch for it (IF §15 rule 13)"
                ));
                continue;
            }
            Err(_) => continue,
        };
        if is_test(&file.attrs) {
            continue;
        }
        let mut uses = Uses::default();
        uses.visit_file(&file);
        let mut probe = Probe {
            path,
            aliases: uses.0.into_iter().map(|(alias, _)| alias).collect(),
            test_depth: 0,
            fns: Vec::new(),
            bound: Vec::new(),
            definitions: 0,
            notes: Vec::new(),
        };
        probe.visit_file(&file);
        definitions += probe.definitions;
        for (line, note) in probe.notes {
            findings.push(format!("{path}:{line}: {note} (IF §15 rule 13)"));
        }
    }
    if definitions != 1 {
        findings.push(format!(
            "`{EXIT_B}` is defined {definitions} times in {STAGE}; exit (b) is exactly one function (IF §15 rule 13, §11.1)"
        ));
    }
    findings
}

/// Every `use` of libloading's `Library`, as (local name, line).
#[derive(Default)]
struct Uses(Vec<(String, usize)>);

impl<'ast> Visit<'ast> for Uses {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        library_imports(&item.tree, false, &mut self.0);
    }
}

fn library_imports(tree: &UseTree, under: bool, out: &mut Vec<(String, usize)>) {
    match tree {
        UseTree::Path(path) => {
            library_imports(&path.tree, under || path.ident == "libloading", out);
        }
        UseTree::Name(name) if under && name.ident == "Library" => {
            out.push(("Library".to_string(), name.ident.span().start().line));
        }
        UseTree::Rename(rename) if under && rename.ident == "Library" => {
            out.push((rename.rename.to_string(), rename.ident.span().start().line));
        }
        UseTree::Group(group) => {
            for item in &group.items {
                library_imports(item, under, out);
            }
        }
        _ => {}
    }
}

struct Probe<'a> {
    path: &'a str,
    /// Local names of libloading's `Library` imported in this file.
    aliases: HashSet<String>,
    test_depth: usize,
    /// Enclosing named functions, innermost last.
    fns: Vec<String>,
    /// The `Library` bindings of each enclosing function.
    bound: Vec<HashSet<String>>,
    /// `dlclose_on_worker` definitions in stage.rs.
    definitions: usize,
    notes: Vec<(usize, String)>,
}

impl Probe<'_> {
    fn note(&mut self, line: usize, note: String) {
        if self.test_depth == 0 {
            self.notes.push((line, note));
        }
    }

    fn guarded(&mut self, test: bool, walk: impl FnOnce(&mut Self)) {
        let test = usize::from(test);
        self.test_depth += test;
        walk(self);
        self.test_depth -= test;
    }

    fn in_fn(&self, names: &[&str]) -> bool {
        self.fns
            .last()
            .is_some_and(|name| names.contains(&name.as_str()))
    }

    /// Stage.rs and the image table are the only files that hold `Library` values by name.
    fn may_name(&self) -> bool {
        self.path == STAGE || self.path == IMAGE_TABLE
    }

    /// Exit (b)'s two callers: stage.rs `load_via_staged_file` and admit.rs.
    fn exit_b(&self) -> bool {
        self.path == ADMIT || (self.path == STAGE && self.in_fn(&["load_via_staged_file"]))
    }

    /// The index of the segment naming libloading's `Library`, if `path` names it.
    fn library_at(&self, path: &syn::Path) -> Option<usize> {
        let first = path.segments.first()?;
        if first.ident == "libloading" {
            path.segments.iter().position(|s| s.ident == "Library")
        } else if self.aliases.contains(&first.ident.to_string()) {
            Some(0)
        } else {
            None
        }
    }

    fn names_library(&self, ty: &Type) -> bool {
        let mut names = TypeNames {
            probe: self,
            hit: false,
        };
        names.visit_type(ty);
        names.hit
    }

    /// A `Library` owned outside `ManuallyDrop` (a reference or a pointer owns nothing).
    fn bare_library(&self, ty: &Type) -> bool {
        match ty {
            Type::Path(ty) => {
                let path = &ty.path;
                if path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "ManuallyDrop")
                {
                    return false;
                }
                if self.library_at(path).is_some() {
                    return true;
                }
                path.segments
                    .iter()
                    .any(|segment| match &segment.arguments {
                        PathArguments::AngleBracketed(args) => args.args.iter().any(
                            |arg| matches!(arg, GenericArgument::Type(ty) if self.bare_library(ty)),
                        ),
                        _ => false,
                    })
            }
            Type::Tuple(ty) => ty.elems.iter().any(|ty| self.bare_library(ty)),
            Type::Array(ty) => self.bare_library(&ty.elem),
            Type::Slice(ty) => self.bare_library(&ty.elem),
            Type::Paren(ty) => self.bare_library(&ty.elem),
            Type::Group(ty) => self.bare_library(&ty.elem),
            _ => false,
        }
    }

    /// `expr` evaluates to a freshly opened `Library` (or a tuple led by one).
    fn yields_library(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Try(e) => self.yields_library(&e.expr),
            Expr::MethodCall(e) => self.yields_library(&e.receiver),
            Expr::Match(e) => self.yields_library(&e.expr),
            Expr::Paren(e) => self.yields_library(&e.expr),
            Expr::Unsafe(e) => tail(&e.block).is_some_and(|e| self.yields_library(e)),
            Expr::Block(e) => tail(&e.block).is_some_and(|e| self.yields_library(e)),
            Expr::Call(call) => match &*call.func {
                Expr::Path(func) => {
                    let path = &func.path;
                    path.segments
                        .last()
                        .is_some_and(|s| OPENERS.contains(&s.ident.to_string().as_str()))
                        || self
                            .library_at(path)
                            .is_some_and(|at| at + 1 < path.segments.len())
                }
                _ => false,
            },
            _ => false,
        }
    }

    /// `expr` (through `&`, `&mut` and parentheses) is a `Library` binding of the enclosing function.
    fn is_bound(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Reference(e) => self.is_bound(&e.expr),
            Expr::Paren(e) => self.is_bound(&e.expr),
            Expr::Path(e) => e.path.get_ident().is_some_and(|ident| {
                self.bound
                    .last()
                    .is_some_and(|bound| bound.contains(&ident.to_string()))
            }),
            _ => false,
        }
    }

    fn function(&mut self, sig: &Signature, walk: impl FnOnce(&mut Self)) {
        let name = sig.ident.to_string();
        if name == EXIT_B && self.test_depth == 0 {
            if self.path == STAGE {
                self.definitions += 1;
            } else {
                self.note(
                    sig.ident.span().start().line,
                    format!(
                        "`{EXIT_B}` defined outside {STAGE}: exit (b) is stage.rs's one function"
                    ),
                );
            }
        }
        let mut bound = HashSet::new();
        for input in &sig.inputs {
            if let FnArg::Typed(arg) = input {
                if self.names_library(&arg.ty) {
                    bind(&arg.pat, &mut bound);
                }
            }
        }
        self.fns.push(name);
        self.bound.push(bound);
        walk(self);
        self.bound.pop();
        self.fns.pop();
    }
}

fn tail(block: &Block) -> Option<&Expr> {
    match block.stmts.last() {
        Some(Stmt::Expr(expr, None)) => Some(expr),
        _ => None,
    }
}

/// The names a pattern binds to a `Library`: an identifier, or a tuple's first element.
fn bind(pat: &Pat, out: &mut HashSet<String>) {
    match pat {
        Pat::Ident(pat) => {
            out.insert(pat.ident.to_string());
        }
        Pat::Type(pat) => bind(&pat.pat, out),
        Pat::Reference(pat) => bind(&pat.pat, out),
        Pat::Tuple(pat) => {
            if let Some(first) = pat.elems.first() {
                bind(first, out);
            }
        }
        _ => {}
    }
}

/// Whether a type names libloading's `Library` anywhere inside it.
struct TypeNames<'p, 'a> {
    probe: &'p Probe<'a>,
    hit: bool,
}

impl<'ast> Visit<'ast> for TypeNames<'_, '_> {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.hit |= self.probe.library_at(path).is_some();
        visit::visit_path(self, path);
    }
}

impl<'ast> Visit<'ast> for Probe<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        self.guarded(is_test(item_attrs(item)), |probe| {
            visit::visit_item(probe, item);
        });
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        self.guarded(is_test(impl_item_attrs(item)), |probe| {
            visit::visit_impl_item(probe, item);
        });
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.function(&item.sig, |probe| visit::visit_item_fn(probe, item));
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.function(&item.sig, |probe| visit::visit_impl_item_fn(probe, item));
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if !self.may_name() {
            let mut imports = Vec::new();
            library_imports(&item.tree, false, &mut imports);
            for (_, line) in imports {
                self.note(
                    line,
                    format!("imports libloading's `Library` outside {STAGE} and the image table"),
                );
            }
        }
        visit::visit_item_use(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if let Some(at) = self.library_at(path) {
            let line = path.segments[at].ident.span().start().line;
            let after = path
                .segments
                .iter()
                .nth(at + 1)
                .map(|s| s.ident.to_string());
            match after.as_deref() {
                Some("close") => self.note(
                    line,
                    "`Library::close` unloads a library outside the two exits".to_string(),
                ),
                Some(_) if !(self.path == STAGE && self.in_fn(&CONSTRUCTORS)) => self.note(
                    line,
                    format!(
                        "constructs a libloading `Library` outside {STAGE} `dlopen_on_worker` and \
                         `name_still_loaded`"
                    ),
                ),
                _ => {}
            }
            if !self.may_name() {
                self.note(
                    line,
                    format!("names libloading's `Library` outside {STAGE} and the image table"),
                );
            }
        }
        if let Some(last) = path.segments.last() {
            let name = last.ident.to_string();
            let line = last.ident.span().start().line;
            if RAW_UNLOADS.contains(&name.as_str()) {
                self.note(
                    line,
                    format!("`{name}` unloads a library outside the two exits"),
                );
            } else if name == EXIT_B && !self.exit_b() {
                self.note(
                    line,
                    format!(
                        "calls `{EXIT_B}` outside the two exits (stage.rs `load_via_staged_file`, \
                         admit.rs step 9)"
                    ),
                );
            }
        }
        visit::visit_path(self, path);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        let typed = matches!(&local.pat, Pat::Type(pat) if self.names_library(&pat.ty));
        let opened = local
            .init
            .as_ref()
            .is_some_and(|init| self.yields_library(&init.expr));
        if typed || opened {
            if let Some(bound) = self.bound.last_mut() {
                bind(&local.pat, bound);
            }
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(func) = &*call.func {
            let segments: Vec<String> = func
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            let last = segments.last().map_or("", String::as_str);
            let parent = segments
                .len()
                .checked_sub(2)
                .map(|at| segments[at].as_str());
            let line = func
                .path
                .segments
                .last()
                .map_or(0, |s| s.ident.span().start().line);
            let library = call.args.first().is_some_and(|arg| self.is_bound(arg));
            if parent == Some("ManuallyDrop") && matches!(last, "drop" | "take" | "into_inner") {
                if library || self.path == IMAGE_TABLE {
                    self.note(
                        line,
                        format!(
                            "`ManuallyDrop::{last}` releases a resident library; exit (a) never unloads"
                        ),
                    );
                }
            } else if last == "drop"
                && matches!(parent, None | Some("mem"))
                && library
                && !(self.path == STAGE && self.in_fn(&[EXIT_B]))
            {
                self.note(
                    line,
                    format!("drops a libloading `Library` outside `{EXIT_B}`"),
                );
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "close" && self.is_bound(&call.receiver) {
            self.note(
                call.method.span().start().line,
                "`.close()` unloads a library outside the two exits".to_string(),
            );
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_foreign_item_fn(&mut self, item: &'ast syn::ForeignItemFn) {
        let name = item.sig.ident.to_string();
        if RAW_UNLOADS.contains(&name.as_str()) {
            self.note(
                item.sig.ident.span().start().line,
                format!("declares `{name}`: a raw unload outside the two exits"),
            );
        }
        visit::visit_foreign_item_fn(self, item);
    }

    fn visit_field(&mut self, field: &'ast syn::Field) {
        if self.bare_library(&field.ty) {
            self.note(
                field.ty.span().start().line,
                "holds a libloading `Library` outside `ManuallyDrop`: its owner's drop would unload \
                 it (exit (a) holds `ManuallyDrop<Library>`)"
                    .to_string(),
            );
        }
        visit::visit_field(self, field);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let drop_impl = item
            .trait_
            .as_ref()
            .is_some_and(|(_, path, _)| path.segments.last().is_some_and(|s| s.ident == "Drop"));
        if let (true, Type::Path(ty)) = (drop_impl, &*item.self_ty) {
            if let Some(last) = ty
                .path
                .segments
                .last()
                .filter(|last| last.ident == "Image" || last.ident == "LoadedImage")
            {
                self.note(
                    last.ident.span().start().line,
                    format!(
                        "`impl Drop for {}`: no Drop of an image unloads it (exit (a))",
                        last.ident
                    ),
                );
            }
        }
        visit::visit_item_impl(self, item);
    }
}

#[cfg(test)]
mod tests {
    use super::{unload_findings, ADMIT, IMAGE_TABLE, STAGE};

    const STAGE_OK: &str = r#"
use libloading::Library;
pub(crate) fn dlopen_on_worker(path: &OsStr) -> Result<Library, String> {
    on_plugin_thread(|| unsafe { Library::new(path) }).map_err(|e| e.to_string())
}
pub(crate) fn dlclose_on_worker(lib: Library) {
    let _ = on_plugin_thread(move || drop(lib));
}
fn load_via_staged_file(bytes: &[u8]) -> Result<(Library, Staged), String> {
    let lib = match dlopen_on_worker(p) { Ok(lib) => lib, Err(e) => return Err(e) };
    if changed(bytes) {
        crate::stage::dlclose_on_worker(lib);
        return Err(String::new());
    }
    let pin = File::open(p);
    drop(pin);
    Ok((lib, Staged::TempFile))
}
fn name_still_loaded(name: &str) -> bool {
    on_plugin_thread(|| {
        let found = unsafe { libloading::os::unix::Library::open(Some(name), 0) };
        found.is_ok()
    })
    .unwrap_or(true)
}
#[cfg(test)]
mod tests {
    fn t(lib: Library) { drop(lib); crate::stage::dlclose_on_worker(lib); unsafe { libc::dlclose(h) }; }
}
"#;

    const ADMIT_OK: &str = r#"
pub fn admit(fd: OwnedFd) -> Result<Admitted, Refusal> {
    let (lib, staged) = crate::stage::load_library_from_bytes(&bytes, "x").map_err(Refusal::load)?;
    let Some(plugin) = symbol(&lib) else {
        crate::stage::dlclose_on_worker(lib);
        return Err(Refusal::NoSymbol);
    };
    Ok(crate::instance::resident(lib, staged, plugin))
}
"#;

    const TABLE_OK: &str = r#"
use std::mem::ManuallyDrop;
use libloading::Library;
pub(crate) struct Resident { lib: ManuallyDrop<Library>, staged: Staged }
pub(crate) fn resident(lib: Library, staged: Staged, plugin: P) -> Admitted {
    table().insert(Resident { lib: ManuallyDrop::new(lib), staged });
    todo()
}
"#;

    const REGISTRY_OK: &str = r#"
impl Registry {
    pub fn add(&mut self, admitted: Admitted) -> Result<(), Refusal> {
        if self.taken(&admitted) { return Err(Refusal::NameConflict); }
        drop(admitted);
        Ok(())
    }
}
"#;

    fn tree(planted: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut files = vec![
            (STAGE.to_string(), STAGE_OK.to_string()),
            (ADMIT.to_string(), ADMIT_OK.to_string()),
            (IMAGE_TABLE.to_string(), TABLE_OK.to_string()),
            (
                "crates/plugin-loader/src/registry.rs".to_string(),
                REGISTRY_OK.to_string(),
            ),
        ];
        for (path, source) in planted {
            match files.iter_mut().find(|(p, _)| p == path) {
                Some(file) => file.1.push_str(source),
                None => files.push(((*path).to_string(), (*source).to_string())),
            }
        }
        files
    }

    /// The findings of a tree with `planted` added, which must all name `file` and say `what`.
    fn found(planted: &[(&str, &str)], file: &str, what: &str) -> Vec<String> {
        let findings = unload_findings(&tree(planted));
        assert!(!findings.is_empty(), "the planted site was not found");
        for finding in &findings {
            assert!(
                finding.starts_with(&format!("{file}:")) && finding.contains(what),
                "unexpected finding {finding:?} (want {file}: {what})"
            );
        }
        findings
    }

    #[test]
    fn the_two_exits_alone_are_clean() {
        assert_eq!(unload_findings(&tree(&[])), Vec::<String>::new());
    }

    /// Exit (b) taken after admission: a refusal in `Registry::add` that unloads the admitted image.
    #[test]
    fn an_extra_dlclose_on_worker_call_is_found() {
        let planted = "fn refuse(lib: X) { crate::stage::dlclose_on_worker(lib); }\n";
        let findings = found(
            &[("crates/plugin-loader/src/registry.rs", planted)],
            "crates/plugin-loader/src/registry.rs",
            "dlclose_on_worker",
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        // A second exit-(b) call inside stage.rs, but outside load_via_staged_file.
        let planted = "fn other(lib: Library) { dlclose_on_worker(lib); }\n";
        found(&[(STAGE, planted)], STAGE, "dlclose_on_worker");
        // A second definition.
        let planted = "pub fn dlclose_on_worker(lib: u8) {}\n";
        found(
            &[("crates/busbar/src/x.rs", planted)],
            "crates/busbar/src/x.rs",
            "defined",
        );
    }

    #[test]
    fn a_drop_of_a_library_outside_dlclose_on_worker_is_found() {
        let planted =
            "fn quiet(p: &OsStr) { let lib = dlopen_on_worker(p).unwrap(); drop(lib); }\n";
        found(&[(STAGE, planted)], STAGE, "drop");
        let planted = "fn quiet(lib: Library) { std::mem::drop(lib); }\n";
        found(&[(STAGE, planted)], STAGE, "drop");
        let planted = "fn quiet(r: &mut Resident) { unsafe { ManuallyDrop::drop(&mut r.lib) }; }\n";
        found(&[(IMAGE_TABLE, planted)], IMAGE_TABLE, "ManuallyDrop");
        // Dropping something that is not a Library is not a finding.
        let planted = "fn fine(p: &OsStr) { let pin = File::open(p); drop(pin); }\n";
        assert_eq!(
            unload_findings(&tree(&[(STAGE, planted)])),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_raw_unload_is_found_anywhere() {
        let planted = "fn raw(h: *mut c_void) { unsafe { libc::dlclose(h) }; }\n";
        found(
            &[("crates/busbar-ffi/src/lib.rs", planted)],
            "crates/busbar-ffi/src/lib.rs",
            "dlclose",
        );
        let planted = "extern \"C\" { fn dlclose(h: *mut c_void) -> i32; }\n";
        found(
            &[("crates/busbar/src/a.rs", planted)],
            "crates/busbar/src/a.rs",
            "dlclose",
        );
        let planted = "fn shut(lib: Library) { let _ = lib.close(); }\n";
        found(&[(STAGE, planted)], STAGE, "close");
    }

    #[test]
    fn a_library_named_outside_stage_and_the_image_table_is_found() {
        let planted = "use libloading::Library;\nfn hold(lib: Library) {}\n";
        found(
            &[("crates/plugin-loader/src/registry.rs", planted)],
            "crates/plugin-loader/src/registry.rs",
            "Library",
        );
        let planted = "fn hold(lib: libloading::os::unix::Library) {}\n";
        found(
            &[("crates/plugin-loader/src/adapters/store.rs", planted)],
            "crates/plugin-loader/src/adapters/store.rs",
            "Library",
        );
        // libloading's other items are not a Library value.
        let planted = "fn no_door(e: &libloading::Error) {}\n";
        assert_eq!(
            unload_findings(&tree(&[("crates/plugin-loader/src/cold.rs", planted)])),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_library_constructed_outside_the_two_stage_openers_is_found() {
        let planted = "fn sneak(p: &OsStr) { let _ = unsafe { Library::new(p) }; }\n";
        found(&[(STAGE, planted)], STAGE, "constructs");
    }

    #[test]
    fn a_library_field_its_owner_drop_would_unload_is_found() {
        let planted = "pub(crate) struct Loose { lib: Option<Library> }\n";
        found(&[(IMAGE_TABLE, planted)], IMAGE_TABLE, "ManuallyDrop");
        let planted = "pub(crate) enum Held { One(Library) }\n";
        found(&[(STAGE, planted)], STAGE, "ManuallyDrop");
    }

    #[test]
    fn a_drop_impl_for_an_image_is_found() {
        let planted = "impl Drop for Image { fn drop(&mut self) {} }\n";
        found(
            &[("crates/busbar-plugin-abi/src/host_side/driver.rs", planted)],
            "crates/busbar-plugin-abi/src/host_side/driver.rs",
            "Drop",
        );
        let planted = "impl core::ops::Drop for LoadedImage { fn drop(&mut self) {} }\n";
        found(&[(IMAGE_TABLE, planted)], IMAGE_TABLE, "Drop");
    }

    #[test]
    fn test_code_is_not_scanned() {
        let planted = "#[cfg(test)]\nmod t { fn x(lib: Library) { crate::stage::dlclose_on_worker(lib); drop(lib); } }\n#[test]\nfn y() { unsafe { libc::dlclose(h) }; }\n";
        assert_eq!(
            unload_findings(&tree(&[("crates/plugin-loader/src/registry.rs", planted)])),
            Vec::<String>::new()
        );
    }
}
