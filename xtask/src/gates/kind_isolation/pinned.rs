//! THE PINNED CHECKOUTS ARE THE KIND'S CRATES (ARCHITECT ruling W4B-Q1, 2026-10-03; RUN.md:119
//! "read pinned_exemplars, never skip").
//!
//! Every plugin lives in its own repo (BUSBAR-1.6.0.md §9), and busbar pulls the ones it links at
//! one pinned rev each: `busbar-transport-tcp = { git = "…", rev = "…" }` in the root manifest. A
//! kind whose crates have left this tree is not a dead kind and not a pending one: its crates are
//! those pinned checkouts, and `cargo metadata` resolves each to a `git+` package whose source sits
//! on disk. This module reads them back into the census, so a kind whose crates are ALL extracted
//! (the secret sources and export sinks already; the transports once stdio leaves) is read
//! from its pins, and a kind partly extracted is read from the tree and its pins together — the
//! census does not change meaning the day the last crate of a kind moves out.
//!
//! HOW: each such package's crate directory is laid over the tree at `crates/<package>` as an
//! [`Overlay`] BENEATH whatever the caller already overlays, so every rule of the gate — the edge
//! graph, the closure, the vocabulary, the faces, the build inputs, the one registration, the
//! census and its dead-kind rule — reads a pinned crate exactly as it read the crate when it lived
//! here, and a self-test plants into the pinned crate at the same path (a plant is the TOP layer, so
//! it wins over the pinned bytes). Nothing is skipped and nothing fails closed: an empty kind with a
//! pinned checkout is a live kind, and the last wire leaving the tree leaves `:wires` reading the
//! pinned wires, registered by the root's `[package.metadata.busbar.linked]` rows.
//!
//! WHICH PACKAGES: a `git+` package of `cargo metadata` over the root manifest whose name resolves
//! to one of the seven PLUGIN kinds ([`PLUGIN_KINDS`]) and is not the `-plugin` cdylib twin (a
//! plugin repo is a logic crate plus the thin cdylib that packages it, §9; the logic crate is the
//! kind's member, and the twin's four-segment name is the plugin repo's own business). A package is
//! mounted only where nothing of this tree sits: no crate on disk carries its name, and
//! `crates/<package>` is not a directory on disk.
//!
//! The mount is memoised per process (one `cargo metadata`, one read of each checkout), keyed by
//! the tree's root and any planted `cargo metadata` answer — a plant that drops a pin is a tree
//! without that pin.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use crate::ctx::{Ctx, Overlay};

/// The seven plugin kinds (DECISIONS #3), in the kind table's own spelling. Only a crate of one of
/// these lives in a plugin repo; the infra families (kernel, contract, plugin-tooling, cleanliness)
/// and the root never leave this tree.
pub(super) const PLUGIN_KINDS: &[&str] = &[
    "store",
    "secret",
    "auth",
    "hooks",
    "export",
    "plane",
    "transport",
];

/// The suffix of a plugin repo's cdylib twin (`busbar-transport-tcp-plugin`).
const CDYLIB_SUFFIX: &str = "-plugin";

/// The planted `cargo metadata` answer's overlay key ([`Ctx::cargo_metadata`]).
const METADATA_KEY: &str = "cargo-metadata:Cargo.toml";

/// One pinned package: its name, the directory its manifest governs in the checkout, and the
/// `git+` source `cargo metadata` resolved it from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Pinned {
    pub name: String,
    pub dir: PathBuf,
    pub source: String,
}

type Resolved = Arc<Result<Vec<Pinned>, String>>;

static RESOLVE_MEMO: OnceLock<Mutex<BTreeMap<String, Resolved>>> = OnceLock::new();
static MOUNT_MEMO: OnceLock<Mutex<BTreeMap<String, Arc<Overlay>>>> = OnceLock::new();

/// The memo key: the tree's root and the planted `cargo metadata` answer, when there is one.
fn key(cx: &Ctx) -> String {
    format!(
        "{}\u{0}{}",
        cx.root().display(),
        cx.overlay_command(METADATA_KEY).unwrap_or_default()
    )
}

/// Every `git+` package of `cargo metadata` over the root manifest that names a plugin kind and is
/// not a cdylib twin, sorted by name. `Err` when `cargo metadata` does not answer.
pub(super) fn pinned_packages(cx: &Ctx) -> Resolved {
    let key = key(cx);
    let memo = RESOLVE_MEMO.get_or_init(Default::default);
    if let Some(hit) = memo
        .lock()
        .expect("the pinned memo mutex is never poisoned")
        .get(&key)
    {
        return Arc::clone(hit);
    }
    let resolved = Arc::new(resolve(cx));
    memo.lock()
        .expect("the pinned memo mutex is never poisoned")
        .insert(key, Arc::clone(&resolved));
    resolved
}

fn resolve(cx: &Ctx) -> Result<Vec<Pinned>, String> {
    let meta = cx.cargo_metadata("Cargo.toml")?;
    let meta: serde_json::Value =
        serde_json::from_str(&meta).map_err(|e| format!("cargo metadata is not JSON: {e}"))?;
    let mut out: Vec<Pinned> = Vec::new();
    for p in meta["packages"].as_array().into_iter().flatten() {
        let source = p["source"].as_str().unwrap_or("");
        if !source.starts_with("git+") {
            continue;
        }
        let Some(name) = p["name"].as_str() else {
            continue;
        };
        if name.ends_with(CDYLIB_SUFFIX) || out.iter().any(|q| q.name == name) {
            continue;
        }
        let (kind, _, ambiguous) = super::resolve_kind(name);
        if !ambiguous.is_empty() || !kind.is_some_and(|k| PLUGIN_KINDS.contains(&k)) {
            continue;
        }
        let Some(dir) = p["manifest_path"]
            .as_str()
            .and_then(|m| Path::new(m).parent())
        else {
            continue;
        };
        out.push(Pinned {
            name: name.to_string(),
            dir: dir.to_path_buf(),
            source: source.to_string(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// WHERE A PINNED REPO'S `-plugin` TWIN IS LAID: outside `crates/`, so no rule that walks the
/// crates reads it as source of the logic crate. Only [`twin_files`] reads it, for the two facts the
/// twin carries (the exported door and the battery). A self-test plants a twin here.
pub(super) const TWIN_ROOT: &str = ".pinned-twin";

/// The overlay directory of `name`'s twin.
pub(super) fn twin_dir(name: &str) -> String {
    format!("{TWIN_ROOT}/{name}")
}

/// The checkout directory of `p`'s `-plugin` twin: the sibling directory `<logic dir>-plugin`
/// whose manifest names the package `<name>-plugin` (a plugin repo's layout, §9). `None` when the
/// repo carries no such twin.
fn twin_of(p: &Pinned) -> Option<PathBuf> {
    let leaf = p.dir.file_name()?.to_str()?;
    let twin = p.dir.with_file_name(format!("{leaf}{CDYLIB_SUFFIX}"));
    let manifest = std::fs::read_to_string(twin.join("Cargo.toml")).ok()?;
    (super::package_name(&manifest)? == format!("{}{CDYLIB_SUFFIX}", p.name)).then_some(twin)
}

/// Every laid twin file, as `(the logic crate's mount dir, the path inside the twin, text)`, read
/// through `cx` so a plant's twin is the one judged.
pub(super) fn twin_files(cx: &Ctx) -> Vec<(String, String, String)> {
    let Ok(files) = cx.walk(&crate::ctx::WalkSpec::new([TWIN_ROOT]).allow_empty()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for f in files {
        let rel = f.rel_str();
        let Some(rest) = rel.strip_prefix(&format!("{TWIN_ROOT}/")) else {
            continue;
        };
        let Some((name, sub)) = rest.split_once('/') else {
            continue;
        };
        out.push((mount_dir(name), sub.to_string(), f.text.clone()));
    }
    out
}

/// Where a pinned package is read, in the tree's own spelling.
pub(super) fn mount_dir(name: &str) -> String {
    format!("crates/{name}")
}

/// The package names of the crates ON DISK under `crates/` — never the overlay, which the mount
/// sits beneath and a plant is free to edit.
fn disk_crate_names(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(rd) = std::fs::read_dir(root.join("crates")) else {
        return out;
    };
    for e in rd.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path().join("Cargo.toml")) else {
            continue;
        };
        if let Some(name) = super::package_name(&text) {
            out.insert(name);
        }
    }
    out
}

/// Every text file of a checkout's crate directory, relative to it. Build output and dot-directories
/// are not the crate's source.
fn crate_files(dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let path = e.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') || name == "target" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let (Ok(text), Ok(rel)) = (std::fs::read_to_string(&path), path.strip_prefix(dir))
            else {
                continue;
            };
            out.push((rel.to_string_lossy().replace('\\', "/"), text));
        }
    }
    out.sort();
    out
}

/// THE MOUNT: every pinned package of a plugin kind no crate on disk is, laid at its
/// [`mount_dir`]. Empty when `cargo metadata` does not answer (the census then reads the tree alone,
/// and a kind with no crate in it is the dead kind it would be).
fn mount(cx: &Ctx) -> Arc<Overlay> {
    let key = key(cx);
    let memo = MOUNT_MEMO.get_or_init(Default::default);
    if let Some(hit) = memo
        .lock()
        .expect("the mount memo mutex is never poisoned")
        .get(&key)
    {
        return Arc::clone(hit);
    }
    let mut ov = Overlay::new();
    if let Ok(pinned) = pinned_packages(cx).as_ref() {
        let on_disk = disk_crate_names(cx.root());
        for p in pinned {
            let at = mount_dir(&p.name);
            if on_disk.contains(&p.name) || cx.root().join(&at).exists() {
                continue;
            }
            for (rel, text) in crate_files(&p.dir) {
                ov.set(format!("{at}/{rel}"), text);
            }
            if let Some(twin) = twin_of(p) {
                for (rel, text) in crate_files(&twin) {
                    ov.set(format!("{}/{rel}", twin_dir(&p.name)), text);
                }
            }
        }
    }
    let ov = Arc::new(ov);
    memo.lock()
        .expect("the mount memo mutex is never poisoned")
        .insert(key, Arc::clone(&ov));
    ov
}

/// The pinned source of the crate the census reads at `dir` under `name`, when it is a mounted
/// pinned checkout: a plugin-kind crate at exactly [`mount_dir`]`(name)`, NOT on disk (only the
/// mount lays it there), whose name `cargo metadata` resolves to a pinned `git+` package. A crate a
/// self-test plants at a fresh directory is on no pin and stays a crate of the tree for every arm.
pub(super) fn mounted_source(
    cx: &Ctx,
    name: &str,
    dir: &str,
    kind: Option<&str>,
) -> Option<String> {
    if !kind.is_some_and(|k| PLUGIN_KINDS.contains(&k))
        || dir != mount_dir(name)
        || cx.abs(dir).exists()
    {
        return None;
    }
    let resolved = pinned_packages(cx);
    let pinned = resolved.as_ref().as_ref().ok()?;
    pinned
        .iter()
        .find(|p| p.name == name)
        .map(|p| p.source.clone())
}

/// THE TREE THE GATE READS: `cx` with every pinned crate of [`mount`] laid beneath its overlay.
pub(super) fn with_pinned(cx: &Ctx) -> Ctx {
    let base = mount(cx);
    if base.is_empty() {
        return cx.clone();
    }
    let layered = match cx.overlay() {
        Some(top) => base.layered(top),
        None => (*base).clone(),
    };
    cx.with_overlay(layered)
}
