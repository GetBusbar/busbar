//! `cargo xtask gate one-memory-abi` — PLUGINS SPEAK THE MEMORY ABI ONLY (M0 ABI-SPEC).
//!
//! > "Plugins speak Memory ABI ONLY." — OWNER, 2026-09-27
//!
//! One door per plugin, one call shape, no COLD/JSON lane. What this gate measures, over the
//! production code of every workspace member AND every pinned plugin crate the root manifest
//! resolves (the logic crate and its cdylib twin, read at the pinned commit: [`pinned_sources`]):
//!
//! * **`exported-symbol`** — every `#[no_mangle]` / `#[unsafe(no_mangle)]` / `#[export_name]`
//!   item whose symbol is not `busbar_plugin_door`. A plugin exports exactly one symbol.
//! * **`cold-lane`** — every reference to the COLD/JSON lane outside its own home
//!   (`abi/cold/`): `abi::cold`, `busbar_call`, `ColdEntry`.
//! * **`spawn-blocking`** — `spawn_blocking` in the loader or in a dispatcher file: waiting never
//!   blocks, so the one loading path and the one dispatcher own no blocking thread.
//! * **`c-unwind`** — every `extern "C-unwind"`: unwinding across a foreign cdylib is undefined
//!   behaviour, so a slot is `extern "C"` and a panic that escapes it aborts.
//!
//! REPORT-ONLY, armed at today's count as the drain-only ledger `qa/one-memory-abi.toml` (see
//! [`super::one_abi`]). M6 (cold delete) and M3 (the kind tables) drain it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;
use crate::scan::ScopeLine;

pub const ROW_EXPORTED: &str = "one-memory-abi:exported-symbol";
pub const ROW_COLD: &str = "one-memory-abi:cold-lane";
pub const ROW_SPAWN_BLOCKING: &str = "one-memory-abi:spawn-blocking";
pub const ROW_C_UNWIND: &str = "one-memory-abi:c-unwind";

/// The one symbol a plugin exports.
pub const DOOR_SYMBOL: &str = "busbar_plugin_door";
/// THE KERNEL'S SEAL SYMBOL (#65, ARCHITECT ruling 2026-10-14): the contract declares it and the
/// kernel defines it, so the kernel seal reaches the kernel and nothing else
/// (`crates/busbar-kernel/src/seal.rs`). It is no plugin's export — the kernel is in no plugin's
/// closure — and it is excused at exactly its one home: the same name defined anywhere else (a
/// plugin catching the seal) is a finding like any other export.
pub const KERNEL_ROOT_SYMBOL: &str = "__busbar_kernel_root";
/// The one file that may define [`KERNEL_ROOT_SYMBOL`].
pub const KERNEL_ROOT_HOME: &str = "crates/busbar-kernel/src/seal.rs";
/// The cold lane's own home; references inside it are the lane itself, deleted whole in M6.
// qa-names: crates/busbar-contract/src/abi/cold/ -- xtask/src/gates/one_memory_abi.rs -- the cold lane is deleted (row 84, #961); its home stays the one place the cold needles are excused, so a lane that grows back elsewhere is a finding, and this declaration reds the day the path exists again
const COLD_HOME: &str = "crates/busbar-contract/src/abi/cold/";
/// The cold lane's names.
const COLD_NEEDLES: &[&str] = &["abi::cold", "busbar_call", "ColdEntry"];

pub const SPEC: Spec = Spec {
    gate: "one-memory-abi",
    ledger: "qa/one-memory-abi.toml",
    rules: &[
        (
            ROW_EXPORTED,
            "the only exported symbol is busbar_plugin_door",
        ),
        (
            ROW_COLD,
            "no reference to the COLD/JSON lane outside abi/cold/",
        ),
        (
            ROW_SPAWN_BLOCKING,
            "no spawn_blocking in the loader or a dispatcher",
        ),
        (
            ROW_C_UNWIND,
            "no extern \"C-unwind\": slots are extern \"C\"",
        ),
    ],
    header: "# one-memory-abi: DRAIN-ONLY ledger (M0 ABI-SPEC, REPORT-ONLY).\n\
             # Plugins speak the memory ABI only: one exported symbol, no COLD/JSON lane, no\n\
             # blocking thread in the loader or dispatcher, extern \"C\" slots. Each row is one\n\
             # the tree carries today. Strike a row in the commit that drains it; never add one.\n\
             # Regenerate with `cargo xtask gate one-memory-abi --write`.\n",
};

/// The symbol an export attribute on line `idx` gives the item it applies to: its
/// `export_name`, else the next `fn`/`static` name within a few lines.
fn exported_symbol(lines: &[ScopeLine], idx: usize) -> String {
    let raw = &lines[idx].raw;
    if let Some(p) = raw.find("export_name") {
        if let Some(q) = raw[p..].find('"') {
            let rest = &raw[p + q + 1..];
            return rest.split('"').next().unwrap_or("?").to_string();
        }
    }
    for sl in lines.iter().skip(idx).take(8) {
        let words: Vec<&str> = sl
            .counted
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
            .filter(|w| !w.is_empty())
            .collect();
        for w in words.windows(2) {
            if w[0] == "fn" || w[0] == "static" {
                return w[1].to_string();
            }
        }
    }
    "?".to_string()
}

fn is_export_attr(counted: &str) -> bool {
    let t = counted.trim_start();
    t.starts_with("#[no_mangle]")
        || t.starts_with("#[unsafe(no_mangle)]")
        || t.starts_with("#[export_name")
        || t.starts_with("#[unsafe(export_name")
}

fn is_dispatcher(rel: &str) -> bool {
    rel.starts_with("crates/plugin-loader/") || rel.contains("/dispatch")
}

/// The rules over one production file.
fn scan_file(rel: &str, text: &str, findings: &mut Vec<Finding>) {
    let all = crate::scan::test_scope(text);
    for (idx, sl) in all.iter().enumerate() {
        if sl.gated || sl.is_comment {
            continue;
        }
        if is_export_attr(&sl.counted) {
            let sym = exported_symbol(&all, idx);
            let kernel_root = sym == KERNEL_ROOT_SYMBOL && rel == KERNEL_ROOT_HOME;
            if sym != DOOR_SYMBOL && !kernel_root {
                findings.push(Finding::new(ROW_EXPORTED, rel, sym, sl.no));
            }
        }
        if !rel.starts_with(COLD_HOME) {
            for n in COLD_NEEDLES {
                if sl.counted.contains(n) {
                    findings.push(Finding::new(ROW_COLD, rel, *n, sl.no));
                }
            }
        }
        if is_dispatcher(rel) && one_abi::has_word(&sl.counted, "spawn_blocking") {
            findings.push(Finding::new(
                ROW_SPAWN_BLOCKING,
                rel,
                "spawn_blocking",
                sl.no,
            ));
        }
        if sl.raw.contains("\"C-unwind\"") && sl.counted.contains("extern") {
            findings.push(Finding::new(
                ROW_C_UNWIND,
                rel,
                "extern \"C-unwind\"",
                sl.no,
            ));
        }
    }
}

/// THE FLOOR UNDER THE PINNED PLUGINS' FILES (Law 8). 205 production files on the day the pinned
/// plugins joined this scan (30 pinned crates); a reading under this floor has lost most of them.
/// Each pinned crate must also yield at least one file of its own.
pub const PINNED_FILES_FLOOR: usize = 100;

/// THE PINNED PLUGIN CRATES' PRODUCTION FILES, `(path, text)` at `crates/<package>/…` (Law 8; the
/// ARCHITECT P5 ruling 2026-10-14 that the gates keep reading extracted plugin code). Every `git+`
/// package `cargo metadata` resolves over the root manifest (every feature on) that is a plugin crate
/// ([`one_abi::is_plugin_crate`]) and no workspace member: the logic crate AND its `-plugin` cdylib
/// twin, since a cdylib is where an export is written. THE TREE WINS: a crate this tree lays at
/// `crates/<package>` (on disk, or the pinned planes' base layer) is read from it; every other one is
/// read at its pinned commit through the audit ledger's pinned mount ([`crate::audit_pinned`]), with
/// any planted file of the overlay laid over it. A pin that cannot be read is an error, never a skip.
fn pinned_sources(cx: &Ctx, members: &[one_abi::Member]) -> Result<Vec<(String, String)>, String> {
    let meta = all_features_metadata(cx)?;
    let meta: &serde_json::Value = &meta;
    let have: std::collections::BTreeSet<&str> = members.iter().map(|m| m.name.as_str()).collect();
    let store = crate::audit_pinned::PinStore::new(
        crate::audit_pinned::default_cargo_home(),
        cx.root().join("target").join("ledger-pins"),
    );
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut out: Vec<(String, String)> = Vec::new();
    for p in meta["packages"].as_array().into_iter().flatten() {
        let (Some(name), Some(source)) = (p["name"].as_str(), p["source"].as_str()) else {
            continue;
        };
        if !source.starts_with("git+")
            || !one_abi::is_plugin_crate(name)
            || have.contains(name)
            || !seen.insert(name.to_string())
        {
            continue;
        }
        let dir = format!("crates/{name}");
        let src = format!("{dir}/src/");
        let mut files: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        if cx.is_dir(&dir) {
            for f in one_abi::rs_files(cx, &dir)? {
                files.insert(f.rel_str(), f.text);
            }
        } else {
            let pin = crate::audit_pinned::Pin::from_source(name, source).ok_or_else(|| {
                format!("pinned plugin {name}: its source `{source}` names no commit")
            })?;
            files = pinned_production_files(cx, &store, &pin, &dir)?
                .as_ref()
                .clone();
            // A plant into the pinned crate is the top layer, as it is over a crate on disk.
            let planted: Vec<String> = cx
                .overlay()
                .map(|ov| {
                    ov.paths()
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .filter(|p| p.starts_with(&src) && p.ends_with(".rs"))
                        .collect()
                })
                .unwrap_or_default();
            for rel in planted {
                match cx.read(&rel) {
                    Ok(text) => {
                        files.insert(rel, text);
                    }
                    Err(_) => {
                        files.remove(&rel);
                    }
                }
            }
        }
        if files.is_empty() {
            return Err(format!(
                "pinned plugin {name} read as no production file under {src}: a pinned crate the \
                 scan cannot see is a crate it answers for as clean"
            ));
        }
        out.extend(files);
    }
    Ok(out)
}

/// `cargo metadata --all-features` over the root manifest, READ ONCE PER CHECKOUT AND PROCESS.
///
/// Cargo reads the manifests ON DISK, never the overlay, so its answer cannot change while one
/// gate process runs; only a planted answer (the overlay's `cargo-metadata:Cargo.toml` command)
/// can, and that one is read as planted every time. Every self-test case used to pay a whole
/// `cargo metadata` of its own (one-memory-abi 12 258 of 9 000 work units, ModernCI 2026-10-21).
fn all_features_metadata(cx: &Ctx) -> Result<std::sync::Arc<serde_json::Value>, String> {
    use std::sync::{Arc, Mutex, OnceLock, PoisonError};
    let parse = |out: &str| {
        serde_json::from_str::<serde_json::Value>(out)
            .map(Arc::new)
            .map_err(|e| format!("`cargo metadata` output did not parse: {e}"))
    };
    if let Some(planted) = cx.overlay_command("cargo-metadata:Cargo.toml") {
        return parse(&planted);
    }
    type Memo = Mutex<BTreeMap<PathBuf, Result<Arc<serde_json::Value>, String>>>;
    static MEMO: OnceLock<Memo> = OnceLock::new();
    let memo = MEMO.get_or_init(Default::default);
    if let Some(hit) = memo
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(cx.root())
    {
        return hit.clone();
    }
    let answer = cx
        .cargo_metadata_all_features("Cargo.toml")
        .and_then(|out| parse(&out));
    memo.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(cx.root().to_path_buf(), answer.clone());
    answer
}

/// A pinned crate's PRODUCTION files at its pinned commit (`{dir}/{rel}` -> text), READ ONCE PER
/// PIN AND PROCESS: a commit's blobs never change, so the answer is a pure function of the pin and
/// the stores it is read from. Each run used to mount every pin afresh (a new [`PinStore`] per run)
/// and spawn one `git cat-file` per file, a few hundred processes per self-test case. Any planted
/// file is laid over this by the caller, on every run.
///
/// [`PinStore`]: crate::audit_pinned::PinStore
fn pinned_production_files(
    cx: &Ctx,
    store: &crate::audit_pinned::PinStore,
    pin: &crate::audit_pinned::Pin,
    dir: &str,
) -> Result<std::sync::Arc<BTreeMap<String, String>>, String> {
    use std::sync::{Arc, Mutex, OnceLock, PoisonError};
    type Key = (PathBuf, PathBuf, crate::audit_pinned::Pin, String);
    type Memo = Mutex<BTreeMap<Key, Result<Arc<BTreeMap<String, String>>, String>>>;
    static MEMO: OnceLock<Memo> = OnceLock::new();
    let key: Key = (
        crate::audit_pinned::default_cargo_home(),
        cx.root().to_path_buf(),
        pin.clone(),
        dir.to_string(),
    );
    let memo = MEMO.get_or_init(Default::default);
    if let Some(hit) = memo
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key)
    {
        return hit.clone();
    }
    let answer = read_production_files(store, pin, dir).map(Arc::new);
    memo.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key, answer.clone());
    answer
}

/// [`pinned_production_files`]'s reading, taken fresh.
fn read_production_files(
    store: &crate::audit_pinned::PinStore,
    pin: &crate::audit_pinned::Pin,
    dir: &str,
) -> Result<BTreeMap<String, String>, String> {
    let mount = store.mount(pin)?;
    let mut files = BTreeMap::new();
    for (rel, oid) in &mount.files {
        let production = rel.starts_with("src/")
            && rel.ends_with(".rs")
            && !rel.contains("/tests/")
            && !rel.contains("/benches/");
        if production {
            let text = crate::gitp::git(&mount.db, &["cat-file", "blob", oid])
                .map_err(|e| format!("pinned plugin {} @ {}: {rel}: {e}", pin.package, pin.sha))?;
            files.insert(format!("{dir}/{rel}"), text);
        }
    }
    Ok(files)
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let members = match one_abi::members(cx) {
        Ok(m) => m,
        Err(e) => return (findings, vec![e]),
    };
    let mut files = 0usize;
    for m in members.iter().filter(|m| m.dir.starts_with("crates/")) {
        let list = match one_abi::rs_files(cx, &m.dir) {
            Ok(l) => l,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        files += list.len();
        for f in &list {
            scan_file(&f.rel_str(), &f.text, &mut findings);
        }
    }
    if files < 500 {
        errors.push(format!(
            "the workspace read as {files} production file(s); the scan has gone blind"
        ));
    }
    match pinned_sources(cx, &members) {
        Ok(pinned) => {
            if pinned.len() < PINNED_FILES_FLOOR {
                errors.push(format!(
                    "the pinned plugin crates read as {} production file(s), under the floor of \
                     {PINNED_FILES_FLOOR}; the scan of the pinned plugins has gone blind",
                    pinned.len()
                ));
            }
            for (rel, text) in &pinned {
                scan_file(rel, text, &mut findings);
            }
        }
        Err(e) => errors.push(format!(
            "the pinned plugin crates could not be read, so no pinned plugin is held to these \
             rules: {e}"
        )),
    }
    (findings, errors)
}

pub struct OneMemoryAbiGate;

impl Gate for OneMemoryAbiGate {
    fn name(&self) -> &'static str {
        SPEC.gate
    }

    fn owed(&self) -> Vec<String> {
        SPEC.owed()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let (findings, errors) = scan(cx);
        one_abi::verdict(cx, &SPEC, findings, errors)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let file = "crates/busbar-kernel/src/planted_one_abi.rs";
        let loader = "crates/plugin-loader/src/planted_one_abi.rs";
        let plant = |rel: &str, body: &str| {
            let mut ov = Overlay::new();
            ov.set(rel, body.to_string());
            ov
        };
        let door_only = {
            let mut ov = Overlay::new();
            ov.set(
                file,
                "#[no_mangle]\npub extern \"C\" fn busbar_plugin_door() {}\n",
            );
            ov
        };
        let mut report = one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![
                (
                    ROW_EXPORTED,
                    "a second exported symbol is RED, naming it",
                    plant(
                        file,
                        "#[unsafe(no_mangle)]\npub extern \"C\" fn busbar_planted_call() {}\n",
                    ),
                    vec![file, "busbar_planted_call"],
                ),
                (
                    ROW_EXPORTED,
                    "the kernel's seal symbol defined anywhere but its one home is RED",
                    plant(
                        loader,
                        "#[no_mangle]\npub fn __busbar_kernel_root(seal: Seal) -> Box<dyn Any> {}\n",
                    ),
                    vec![loader, KERNEL_ROOT_SYMBOL],
                ),
                (
                    ROW_COLD,
                    "a cold-lane reference outside abi/cold/ is RED",
                    plant(file, "use busbar_contract::abi::cold::Planted;\n"),
                    vec![file, "abi::cold"],
                ),
                (
                    ROW_SPAWN_BLOCKING,
                    "spawn_blocking in the loader is RED",
                    plant(
                        loader,
                        "pub fn planted() { tokio::task::spawn_blocking(|| ()); }\n",
                    ),
                    vec![loader, "spawn_blocking"],
                ),
                (
                    ROW_C_UNWIND,
                    "an extern \"C-unwind\" slot is RED",
                    plant(file, "pub extern \"C-unwind\" fn planted_slot() {}\n"),
                    vec![file, "C-unwind"],
                ),
            ],
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "exporting busbar_plugin_door is the one export that is not a finding",
            &[ROW_EXPORTED],
            door_only,
        ));
        // A COUNTED ROW holds its key to its count: two cold references against `count = 1` are
        // RED, against `count = 2` green.
        let counted = |max: usize| {
            let mut ov = plant(
                file,
                "use busbar_contract::abi::cold::A;\nuse busbar_contract::abi::cold::B;\n",
            );
            let mut ledger = cx.read(SPEC.ledger).unwrap_or_default();
            ledger.push_str(&format!(
                "\n[[finding]]\nrule = \"{ROW_COLD}\"\nfile = \"{file}\"\nitem = \"abi::cold\"\ncount = {max}\n"
            ));
            ov.set(SPEC.ledger, ledger);
            ov
        };
        report.push(crate::gates::prove_rows_red(
            cx,
            self,
            "a counted row's key over its count is RED",
            &[ROW_COLD],
            counted(1),
            &[file, "over its counted row"],
        ));
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "a counted row's key at its count is green",
            &[ROW_COLD],
            counted(2),
        ));
        // A PINNED PLUGIN IS A PLUGIN (Law 8; ARCHITECT P5 ruling 2026-10-14): a plugin that left
        // this tree for its own repo is still linked, so a second export or an unwinding slot
        // written in its source is read and RED, at the path its crate is mounted at.
        match one_abi::pinned_plugin_members(cx) {
            Ok(pinned) if !pinned.is_empty() => {
                let rel = format!("{}/src/planted_pinned_export.rs", pinned[0].dir);
                let mut ov = Overlay::new();
                ov.set(
                    &rel,
                    "#[no_mangle]\npub extern \"C\" fn busbar_planted_pinned() {}\n\
                     pub extern \"C-unwind\" fn planted_pinned_slot() {}\n",
                );
                report.push(crate::gates::prove_rows_red(
                    cx,
                    self,
                    "a pinned plugin's second export and its extern \"C-unwind\" slot are RED",
                    &[ROW_EXPORTED, ROW_C_UNWIND],
                    ov,
                    &[rel.as_str(), "busbar_planted_pinned", "C-unwind"],
                ));
            }
            other => report.note_infra_failure(format!(
                "no pinned plugin crate resolved, so the plant into a pinned plugin is unproven: {}",
                other.err().unwrap_or_else(|| "cargo metadata names none".to_string())
            )),
        }
        report
    }
}
