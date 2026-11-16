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

use std::path::Path;

use super::core_src::core_files;
use super::Outcome;

/// The file holding `dlopen_on_worker`, `dlclose_on_worker` and the staged loads.
pub(crate) const STAGE: &str = "crates/plugin-loader/src/stage.rs";
/// The loader's process-wide image table (IF §10.4 `Image`: `instance.rs`), exit (a).
pub(crate) const IMAGE_TABLE: &str = "crates/plugin-loader/src/instance.rs";
/// Admit, whose step-9 refusals take exit (b).
pub(crate) const ADMIT: &str = "crates/plugin-loader/src/admit.rs";

pub(crate) fn rule_13(root: &Path) -> Outcome {
    Ok(unload_findings(&core_files(root)?))
}

/// Rule 13 over `(repo-relative path, source)` pairs of core's production files.
pub(crate) fn unload_findings(files: &[(String, String)]) -> Vec<String> {
    let _ = files;
    todo!("W2-FU5B: rule 13")
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
pub fn add(&mut self, admitted: Admitted) -> Result<(), Refusal> {
    if self.taken(&admitted) { return Err(Refusal::NameConflict); }
    drop(admitted);
    Ok(())
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
