// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A PLUGIN BUILT OUTSIDE BUSBAR, FROM THE C HEADER ALONE, THROUGH THE ONE DROPPED-IN DOOR** —
//! the conformance that `plugin-ci.yml`'s C path (`plugin_lang: c`) runs for a plugin repo with no
//! Rust in it (BUSBAR-1.6.0.md decision #84: "a third party builds a plugin from this header
//! alone"; its witness is the plugin repo GetBusbar/busbar-secret-c). The plugin repo is tested BY
//! ITSELF: its CI builds its C sources against `busbar_plugin.h` at the busbar commit it pins, then
//! runs THIS target, at that same commit, over what it built.
//!
//! Inputs (the plugin's CI sets them; a missing one is a failure, never a skip):
//!   BUSBAR_DROPPED_LIB      the shared library the plugin's build produced (what a release packs)
//!   BUSBAR_DROPPED_SOURCES  the directory of the plugin's `.c` sources (the RED arm rebuilds them)
//!   BUSBAR_DROPPED_SCRIPT   the plugin's `conformance.json`: the inputs the kind's script drives
//!
//! What it proves:
//!   * every source includes `busbar_plugin.h` and nothing else (the witness is honest);
//!   * the library's Statement, read as `busbar-plugin-pack` reads it ([`rendering_of_library`]),
//!     states this busbar's mechanism and the kind's current ABI;
//!   * [`load_dropped`] admits it, and the KIND'S SCRIPT answers as the kind's contract requires,
//!     every answer judged by the one dispatcher's kind checks (only `kind: secret` has a script
//!     here today; another kind is a failure naming that, not a pass).
//!   * RED ARM, KEPT: the same sources built with `-DBUSBAR_PLUGIN_KIND_ABI=<host ± 1>` are refused
//!     at pack time and at load (`KindAbi`, naming the rebuild); a manifest stating another kind ABI,
//!     or another kind, is refused before `dlopen`.
//!
//! Both tests are `#[ignore]`d: busbar's own suite has no plugin to point them at. plugin-ci.yml
//! runs them with `--ignored` and requires them to RUN.

#![cfg(unix)]

use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use busbar_contract::abi::export;
use busbar_contract::abi::mechanism::call::{
    Blob, InHead, OutHead, Outcome, BLOB_JSON, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC;
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut};
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, out_head, rendering_of_library, Bind, Called, DispatchConfig,
    Dispatcher, Frame, InFrame, Kind, LoadError, ManifestFacts, NoSink, OutFrame, Plugin,
};

/// The generated header the plugin builds from (the RED arm rebuilds against it).
const INCLUDE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../busbar-contract/include");

fn input_path(var: &str) -> PathBuf {
    let v = std::env::var_os(var).unwrap_or_else(|| {
        panic!("{var} is not set: plugin-ci.yml's C path sets it to what the plugin built")
    });
    let p = PathBuf::from(v);
    assert!(p.exists(), "{var}={} does not exist", p.display());
    p
}

fn lib() -> PathBuf {
    input_path("BUSBAR_DROPPED_LIB")
}

/// The plugin's `.c` sources, sorted.
fn sources() -> Vec<PathBuf> {
    let dir = input_path("BUSBAR_DROPPED_SOURCES");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "c"))
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no .c source in {}", dir.display());
    out
}

/// The plugin's conformance inputs.
fn script_inputs() -> serde_json::Value {
    let p = input_path("BUSBAR_DROPPED_SCRIPT");
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: not JSON: {e}", p.display()))
}

/// The sources again, into a library with `defines` (`-D`). The system C compiler is REQUIRED.
fn rebuild(name: &str, defines: &[String]) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("dropped-conformance")
        .join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the build dir");
    let out = dir.join(format!(
        "{}{name}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let cc = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let run = Command::new(&cc)
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-shared",
            "-fPIC",
        ])
        .arg("-I")
        .arg(INCLUDE)
        .args(defines.iter().map(|d| format!("-D{d}")))
        .arg("-o")
        .arg(&out)
        .args(sources())
        .output()
        .unwrap_or_else(|e| panic!("the system C compiler {cc:?} did not run: {e}"));
    assert!(
        run.status.success(),
        "{cc:?} refused the plugin's sources:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    out
}

fn bind() -> (Bind, Arc<Dispatcher>) {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: Arc::from("dropped"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    };
    (bind, dispatcher)
}

fn load<K: Kind>(path: &Path, stated: &[u8]) -> Result<(Plugin<K>, Arc<Dispatcher>), LoadError> {
    let (b, d) = bind();
    load_dropped::<K>(path, stated, b).map(|p| (p, d))
}

/// The library's Statement as the pack tool signs it into the manifest.
fn stated(path: &Path) -> Vec<u8> {
    rendering_of_library(path)
        .expect("the library's Statement renders")
        .expect("the library exports busbar_plugin_door")
}

/// The host's current ABI for `kind`.
fn host_abi(kind: KindCode) -> u32 {
    match kind {
        KindCode::Secret => secret::ABI_VERSION,
        other => panic!("no dropped-in conformance script for kind {other:?} yet"),
    }
}

/// An `in` of `T`, every field zero but its head.
fn input<T: InFrame>() -> T {
    // SAFETY: every kind's `in` is plain integers, raw pointers and nested plain structs, for which
    // the all-zero pattern is valid; `T` leads with an `InHead`, written below.
    let mut v: T = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: InFrame` leads with an `InHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}

/// An `out` of `T`, every field zero but its head.
fn output<T: OutFrame>() -> T {
    // SAFETY: as `input`, with an `OutHead` first.
    let mut v: T = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: OutFrame` leads with an `OutHead`.
    unsafe {
        std::ptr::addr_of_mut!(v)
            .cast::<OutHead>()
            .write(out_head())
    };
    v
}

fn blob(bytes: &[u8], fmt: u32) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags: 0,
    }
}

/// One transcript line: the step, the outcome, the error text.
fn line(step: &str, c: &Called) -> String {
    let error = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{step}: {:?} error={error:?}", c.outcome)
}

fn text<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("conformance.json: `{key}` must be a string"))
}

// ---- the secret kind's script ----

fn validate<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    let mut err = [0_u8; 512];
    let mut f: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    f.input.settings = blob(settings, BLOB_JSON);
    f.input.err_buf = err.as_mut_ptr();
    f.input.err_cap = err.len();
    p.call(life::VALIDATE, &mut f)
}

fn open<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    let mut err = [0_u8; 512];
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    f.input.settings = blob(settings, BLOB_JSON);
    f.input.generation = 1;
    f.input.err_buf = err.as_mut_ptr();
    f.input.err_cap = err.len();
    p.call(life::OPEN, &mut f)
}

fn refresh<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    let mut f: Frame<RefreshIn, OutHead> = Frame::new(input(), output());
    f.input.settings = blob(settings, BLOB_JSON);
    f.input.generation = 2;
    p.call(life::REFRESH, &mut f)
}

fn release<K: Kind>(p: &Plugin<K>, lease: u64) -> Called {
    let mut f: Frame<ReleaseIn, OutHead> = Frame::new(input(), output());
    f.input.lease = lease;
    p.call(life::RELEASE, &mut f)
}

/// `resolve`: the call, its `error_kind`, and the material it leased (copied before release).
fn resolve(p: &Plugin<Secret>, settings: &[u8]) -> (Called, u32, Vec<u8>, u32) {
    let mut f: Frame<ResolveIn, ResolveOut> = Frame::new(input(), output());
    f.input.settings = blob(settings, BLOB_JSON);
    let c = p.call(secret::slot::RESOLVE, &mut f);
    let material = if c.outcome == Outcome::Ready && !f.out.secret.ptr.is_null() {
        // SAFETY: a READY resolve's blob is the plugin's, live until `release` of its lease, which
        // has not run; the dispatcher's `check_resolve` judged its pointer/length pairing.
        unsafe { std::slice::from_raw_parts(f.out.secret.ptr, f.out.secret.len) }.to_vec()
    } else {
        Vec::new()
    };
    (c, f.out.error_kind, material, f.out.secret.flags)
}

/// THE SECRET KIND'S SCRIPT over the plugin's own inputs:
///   `settings`        settings the plugin opens over
///   `bad_settings`    settings it must refuse (validate, open and refresh FAIL)
///   `known`           `{ "resolve": <resolve settings>, "material": <what it resolves to> }`
///   `unknown`         resolve settings naming a secret it does not hold (FAILED, NOT_FOUND)
///   `malformed`       resolve settings that are not a reference (FAILED, INVALID)
fn secret_script(lib: &Path, stated: &[u8], inputs: &serde_json::Value) {
    let s = &inputs["secret"];
    assert!(
        s.is_object(),
        "conformance.json has no `secret` script inputs"
    );
    let settings = text(s, "settings").as_bytes();
    let bad: Vec<&str> = s["bad_settings"]
        .as_array()
        .expect("conformance.json: `bad_settings` must be an array")
        .iter()
        .map(|v| v.as_str().expect("`bad_settings` entries are strings"))
        .collect();
    assert!(!bad.is_empty(), "conformance.json: `bad_settings` is empty");
    let known = text(&s["known"], "resolve").as_bytes();
    let material = text(&s["known"], "material").as_bytes();
    assert!(
        !material.is_empty(),
        "the known secret's material is not empty"
    );

    let (p, _d) = load::<Secret>(lib, stated).expect("the dropped-in secret plugin loads");
    assert_eq!(p.kind(), KindCode::Secret);

    for b in &bad {
        let v = validate(&p, b.as_bytes());
        assert_eq!(v.outcome, Outcome::Failed, "{}", line("validate, bad", &v));
        assert!(
            v.error.as_deref().is_some_and(|e| !e.is_empty()),
            "a refusal names why: {}",
            line("validate, bad", &v)
        );
    }
    let v = validate(&p, settings);
    assert_eq!(v.outcome, Outcome::Ready, "{}", line("validate", &v));
    let o = open(&p, bad[0].as_bytes());
    assert_eq!(o.outcome, Outcome::Failed, "{}", line("open, bad", &o));
    assert!(!p.is_open(), "a refused open leaves no instance");
    let o = open(&p, settings);
    assert_eq!(o.outcome, Outcome::Ready, "{}", line("open", &o));
    assert!(p.is_open());

    // A known name: READY, its material under a lease, flagged secret.
    let (c, kind, got, flags) = resolve(&p, known);
    assert_eq!(c.outcome, Outcome::Ready, "{}", line("resolve, known", &c));
    assert_eq!(kind, secret::ERROR_KIND_UNSET);
    assert_eq!(got, material, "the known secret's material");
    assert_ne!(c.lease, 0, "READY material is leased");
    assert_ne!(
        flags & BLOB_SECRET,
        0,
        "secret material is flagged BLOB_SECRET"
    );
    let lease = c.lease;
    // A second resolve while the first is outstanding: its own lease.
    let (c2, _, got2, _) = resolve(&p, known);
    assert_eq!(
        c2.outcome,
        Outcome::Ready,
        "{}",
        line("resolve, again", &c2)
    );
    assert_eq!(got2, material);
    assert_ne!(c2.lease, lease, "each READY material has its own lease");

    let (c, kind, got, _) = resolve(&p, text(s, "unknown").as_bytes());
    assert_eq!(
        c.outcome,
        Outcome::Failed,
        "{}",
        line("resolve, unknown", &c)
    );
    assert_eq!(
        kind,
        secret::ERROR_KIND_NOT_FOUND,
        "an unknown name is NOT_FOUND"
    );
    assert!(
        got.is_empty() && c.lease == 0,
        "a FAILED resolve carries nothing"
    );
    let (c, kind, _, _) = resolve(&p, text(s, "malformed").as_bytes());
    assert_eq!(
        c.outcome,
        Outcome::Failed,
        "{}",
        line("resolve, malformed", &c)
    );
    assert_eq!(
        kind,
        secret::ERROR_KIND_INVALID,
        "a malformed reference is INVALID"
    );

    let r = release(&p, lease);
    assert_eq!(r.outcome, Outcome::Ready, "{}", line("release", &r));
    let r = release(&p, lease);
    assert_eq!(r.outcome, Outcome::Refused, "{}", line("release again", &r));
    let r = release(&p, c2.lease);
    assert_eq!(r.outcome, Outcome::Ready, "{}", line("release, second", &r));

    let mut tk: Frame<TickIn, TickOut> = Frame::new(input(), output());
    let t = p.call(life::TICK, &mut tk);
    assert_eq!(t.outcome, Outcome::Ready, "{}", line("tick", &t));
    let r = refresh(&p, bad[0].as_bytes());
    assert_eq!(r.outcome, Outcome::Failed, "{}", line("refresh, bad", &r));
    let r = refresh(&p, settings);
    assert_eq!(r.outcome, Outcome::Ready, "{}", line("refresh", &r));
    // The refused refresh kept the instance as it was: the known name still resolves.
    let (c, _, got, _) = resolve(&p, known);
    assert_eq!(
        c.outcome,
        Outcome::Ready,
        "{}",
        line("resolve after refresh", &c)
    );
    assert_eq!(got, material);
    let r = release(&p, c.lease);
    assert_eq!(
        r.outcome,
        Outcome::Ready,
        "{}",
        line("release after refresh", &r)
    );

    let mut cl: Frame<InHead, OutHead> = Frame::new(input(), output());
    let c = p.call(life::CLOSE, &mut cl);
    assert_eq!(c.outcome, Outcome::Ready, "{}", line("close", &c));
    let (c, _, got, _) = resolve(&p, known);
    assert_ne!(
        c.outcome,
        Outcome::Ready,
        "a closed instance serves nothing: {}",
        line("resolve after close", &c)
    );
    assert!(got.is_empty());
}

/// **THE PROOF.** The plugin, built from the header alone, is admitted by the one dropped-in path
/// and answers its kind's script as the kind's contract requires.
#[test]
#[ignore = "plugin-ci.yml's C path runs it with --ignored over the plugin it built"]
fn a_plugin_built_from_the_c_header_alone_passes_its_kinds_script() {
    for src in sources() {
        let text = std::fs::read_to_string(&src).expect("the plugin's source");
        let includes: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("#include"))
            .collect();
        assert_eq!(
            includes,
            ["#include \"busbar_plugin.h\""],
            "{} includes something besides the header",
            src.display()
        );
    }
    let lib = lib();
    let stated = stated(&lib);
    let facts = ManifestFacts::read(&stated).expect("a Statement rendering");
    assert_eq!(facts.mechanism_version, MECHANISM_VERSION);
    assert_eq!(
        facts.kind_abi,
        host_abi(facts.kind),
        "the plugin states its kind's current ABI"
    );
    match facts.kind {
        KindCode::Secret => secret_script(&lib, &stated, &script_inputs()),
        other => panic!("no dropped-in conformance script for kind {other:?} yet"),
    }
}

/// THE RED ARM, KEPT: the same sources built against another kind ABI version — newer and older —
/// are refused at pack time and at load, naming the rebuild; a manifest stating another version or
/// another kind is refused before the library is opened. The conforming build loads beside them.
#[test]
#[ignore = "plugin-ci.yml's C path runs it with --ignored over the plugin it built"]
fn a_plugin_built_against_another_kind_abi_is_refused() {
    let lib = lib();
    let stated = stated(&lib);
    let facts = ManifestFacts::read(&stated).expect("a Statement rendering");
    let host = host_abi(facts.kind);
    match facts.kind {
        KindCode::Secret => {
            load::<Secret>(&lib, &stated).expect("the conforming build loads");
        }
        other => panic!("no dropped-in conformance script for kind {other:?} yet"),
    }

    for (name, door) in [("red_newer", host + 1), ("red_older", host - 1)] {
        let red = rebuild(name, &[format!("BUSBAR_PLUGIN_KIND_ABI={door}u")]);
        let want = LoadError::KindAbi {
            kind: facts.kind,
            door,
            host,
        };
        assert_eq!(
            rendering_of_library(&red).err(),
            Some(want.clone()),
            "the pack tool refuses the ABI {door} build (does the source honour BUSBAR_PLUGIN_KIND_ABI?)"
        );
        let Err(refused) = load::<Secret>(&red, &stated) else {
            panic!("the loader refuses a door at another kind ABI");
        };
        assert_eq!(refused, want);
        assert!(refused.to_string().contains("rebuild"), "{refused}");
    }

    // A manifest stating another version: refused before `dlopen`.
    let at = RENDERING_MAGIC.len() + 8;
    let mut newer = stated.clone();
    newer[at..at + 4].copy_from_slice(&(host + 1).to_le_bytes());
    assert_eq!(
        load::<Secret>(&lib, &newer).err(),
        Some(LoadError::ManifestKindAbi {
            stated: host + 1,
            host,
        })
    );
    // Asked for as another kind (a manifest stating export): refused.
    let mut as_export = stated.clone();
    let kind_at = RENDERING_MAGIC.len() + 4;
    as_export[kind_at..kind_at + 4].copy_from_slice(&(KindCode::Export as u32).to_le_bytes());
    as_export[at..at + 4].copy_from_slice(&export::ABI_VERSION.to_le_bytes());
    assert!(
        load::<Export>(&lib, &as_export).is_err(),
        "a secret door is not an export door"
    );
}
