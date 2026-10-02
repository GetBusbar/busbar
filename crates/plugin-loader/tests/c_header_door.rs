// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **#84's ZERO-DEPENDENCY PROOF** (TODO ABI-b3; `BUSBAR-1.6.0.md` decision #84, THE DESIGN §11.5):
//! a plugin built from the generated C header ALONE loads and serves.
//!
//! `tests/fixtures/c_export_door.c` is an export plugin written in C. It includes
//! `busbar_plugin.h` and nothing else — no Rust, no busbar crate, no libc header. This test compiles
//! it with the system C compiler (`$CC`, else `cc`) into a shared library, signs nothing and links
//! nothing: it takes the library's Statement rendering as the pack tool does
//! ([`rendering_of_library`]) and opens it through the loader's one dropped-in path
//! ([`load_dropped`]), the same door validation every Rust plugin crosses. Then it drives every op
//! of the export table through the one dispatcher, whose kind checks (`abi/export/validate.rs`)
//! judge each answer, exactly as they judge a Rust export door.
//!
//! RED ARM, KEPT: [`a_c_plugin_built_against_another_export_abi_is_refused`] builds the SAME source
//! with another kind ABI version (newer and older): the pack-time rendering and the load both refuse
//! it, naming the rebuild, and a manifest stating another version is refused before `dlopen`. The
//! conforming build of that source loads beside it, so the version is the only difference.

#![cfg(unix)]

use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::export::{
    self, slot, CheckIn, CheckOut, DeliverIn, ExportStream, ScrapeIn, ScrapeOut, ServeIn, ServeOut,
    StatusOut,
};
use busbar_contract::abi::mechanism::call::{
    Blob, InHead, OutHead, Outcome, BLOB_JSON, BLOB_JSONL, BLOB_OCTETS, METRIC_ADD,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC;
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, out_head, rendering_of_library, Bind, Called, Diagnostic,
    DispatchConfig, Dispatcher, Dropped, EnvelopeSink, Frame, InFrame, LoadError, ManifestFacts,
    Metric, OutFrame, Plugin,
};

/// The generated header, the one artifact a third party builds from.
const INCLUDE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../busbar-contract/include");

/// The C plugin's source.
const SOURCE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/c_export_door.c"
);

/// What the C plugin's `scrape` renders after the script's one two-line delivery.
const EXPOSITION: &str = "# TYPE c_export_lines_total counter\nc_export_lines_total 2\n";

/// Compile the C plugin into `<target tmp>/c-header-door/<name>-<pid>/`, with `defines` (`-D`),
/// and answer the shared library. The system C compiler is REQUIRED: a missing or failing compiler
/// is a failure, never a skip.
fn build(name: &str, defines: &[&str]) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("c-header-door")
        .join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the build dir");
    let lib = dir.join(format!(
        "{}{name}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let cc = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let mut cmd = Command::new(&cc);
    cmd.args([
        "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
    ])
    .arg("-I")
    .arg(INCLUDE)
    .args(defines.iter().map(|d| format!("-D{d}")))
    .arg("-o")
    .arg(&lib)
    .arg(SOURCE);
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("the system C compiler {cc:?} did not run: {e}"));
    assert!(
        out.status.success(),
        "{cc:?} refused the C plugin built from busbar_plugin.h alone:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    lib
}

/// Everything the host was handed on the #85 envelope, and every entry it dropped.
#[derive(Default)]
struct Seen {
    metrics: Mutex<Vec<(u32, u8, f64)>>,
    dropped: Mutex<Vec<Dropped>>,
}

impl EnvelopeSink for Seen {
    fn metric(&self, m: Metric<'_>) {
        self.metrics
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((m.family, m.kind, m.value));
    }
    fn diag(&self, _: Diagnostic<'_>) {}
    fn dropped(&self, why: Dropped) {
        self.dropped
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(why);
    }
}

/// `path` DROPPED IN against `stated` (what its signed manifest would carry), bound to a fresh
/// dispatcher and `sink`.
fn load(
    path: &Path,
    stated: &[u8],
    sink: Arc<Seen>,
) -> Result<(Plugin<Export>, Arc<Dispatcher>), LoadError> {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: Arc::from("c-export"),
        max_inflight_cap: 64,
        sink,
        dispatcher: dispatcher.adopter(),
        conns: None,
    };
    load_dropped::<Export>(path, stated, bind).map(|p| (p, dispatcher))
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

/// `bytes` as a blob of `fmt`, lent for one call.
fn blob(bytes: &[u8], fmt: u32) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags: 0,
    }
}

/// One transcript line: the step, then what the host was handed.
fn line(step: &str, c: &Called) -> String {
    let error = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{step}: {:?} error={error:?}", c.outcome)
}

fn validate(p: &Plugin<Export>, settings: &[u8]) -> Called {
    let mut f: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    f.input.settings = blob(settings, BLOB_JSON);
    p.call(life::VALIDATE, &mut f)
}

fn open(p: &Plugin<Export>, settings: &[u8]) -> Called {
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    f.input.settings = blob(settings, BLOB_JSON);
    f.input.generation = 1;
    p.call(life::OPEN, &mut f)
}

fn refresh(p: &Plugin<Export>, settings: &[u8]) -> Called {
    let mut f: Frame<RefreshIn, OutHead> = Frame::new(input(), output());
    f.input.settings = blob(settings, BLOB_JSON);
    f.input.generation = 2;
    p.call(life::REFRESH, &mut f)
}

fn deliver(p: &Plugin<Export>, stream: ExportStream, batch: &[u8], fmt: u32) -> Called {
    let mut f: Frame<DeliverIn, OutHead> = Frame::new(input(), output());
    f.input.stream = stream as u8;
    f.input.op_id = [7; 16];
    f.input.batch = blob(batch, fmt);
    p.call(slot::DELIVER, &mut f)
}

fn release(p: &Plugin<Export>, lease: u64) -> Called {
    let mut f: Frame<ReleaseIn, OutHead> = Frame::new(input(), output());
    f.input.lease = lease;
    p.call(life::RELEASE, &mut f)
}

/// **THE PROOF.** The C plugin, built from the header alone, is admitted by the one dropped-in
/// path and answers every op of the export table as the kind's contract requires; the dispatcher's
/// kind checks judge each answer and fault none.
#[test]
fn a_plugin_built_from_the_c_header_alone_loads_and_serves_through_the_one_door() {
    // The witness is honest only if the source names nothing but the header.
    let source = std::fs::read_to_string(SOURCE).expect("the C plugin's source");
    let includes: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("#include"))
        .collect();
    assert_eq!(
        includes,
        ["#include \"busbar_plugin.h\""],
        "the C plugin includes only the header"
    );

    let lib = build("c_export_door", &[]);
    // What the pack tool signs into the manifest: the library's own Statement, rendered.
    let stated = rendering_of_library(&lib)
        .expect("the C door renders its Statement")
        .expect("the C library exports busbar_plugin_door");
    assert_eq!(
        ManifestFacts::read(&stated).expect("a Statement rendering"),
        ManifestFacts {
            mechanism_version: MECHANISM_VERSION,
            kind: KindCode::Export,
            kind_abi: export::ABI_VERSION,
        }
    );

    let seen = Arc::new(Seen::default());
    let (p, _dispatcher) = load(&lib, &stated, seen.clone()).expect("the C plugin loads");

    let mut t = vec![
        line("validate, bad settings", &validate(&p, b"[]")),
        line("validate", &validate(&p, b"{}")),
        line("open, bad settings", &open(&p, b"[]")),
        line("open", &open(&p, br#"{"sink": "c"}"#)),
        line(
            "deliver",
            &deliver(
                &p,
                ExportStream::Logs,
                b"{\"n\":1}\n{\"n\":2}\n",
                BLOB_JSONL,
            ),
        ),
        line(
            "deliver, undeclared stream",
            &deliver(&p, ExportStream::Metrics, b"{}\n", BLOB_JSONL),
        ),
        line(
            "deliver, not JSON lines",
            &deliver(&p, ExportStream::Logs, b"\x00\x01", BLOB_OCTETS),
        ),
    ];

    // `scrape`: too small a buffer is the short-buffer FAILED and earns ONE re-call.
    let mut small = [0_u8; 4];
    let mut s: Frame<ScrapeIn, ScrapeOut> = Frame::new(input(), output());
    s.input.buf = small.as_mut_ptr();
    s.input.cap = small.len();
    let short = p.call(slot::SCRAPE, &mut s);
    t.push(line("scrape, short", &short));
    assert_eq!(
        s.out.needed,
        EXPOSITION.len(),
        "the short answer states what it needs"
    );
    let token = short.recall.expect("a short scrape earns the one re-call");
    let mut big = vec![0_u8; 256];
    let mut s: Frame<ScrapeIn, ScrapeOut> = Frame::new(input(), output());
    s.input.buf = big.as_mut_ptr();
    s.input.cap = big.len();
    t.push(line("scrape", &p.recall(token, slot::SCRAPE, &mut s)));
    assert_eq!(&big[..s.out.written], EXPOSITION.as_bytes());

    // `status`: the 1.5.5 status blob, under a lease the host hands back.
    let mut st: Frame<InHead, StatusOut> = Frame::new(input(), output());
    let status = p.call(slot::STATUS, &mut st);
    t.push(line("status", &status));
    assert_ne!(status.lease, 0, "a status blob is leased");
    // SAFETY: a READY status blob is the plugin's, live until `release` of its lease, not yet run.
    let body = unsafe { std::slice::from_raw_parts(st.out.status.ptr, st.out.status.len) };
    assert_eq!(body, br#"{"lines":2}"#);
    assert_eq!(st.out.status.fmt, BLOB_JSON);
    t.push(line("release", &release(&p, status.lease)));
    t.push(line("release again", &release(&p, status.lease)));

    let mut c: Frame<CheckIn, CheckOut> = Frame::new(input(), output());
    c.input.phase = export::CHECK_PHASE_INSTANCES;
    let check = p.call(slot::CHECK, &mut c);
    assert_eq!(check.lease, 0, "no findings, no lease");
    t.push(line("check", &check));
    let mut sv: Frame<ServeIn, ServeOut> = Frame::new(input(), output());
    t.push(line("serve", &p.call(slot::SERVE, &mut sv)));
    let mut tk: Frame<TickIn, TickOut> = Frame::new(input(), output());
    t.push(line("tick", &p.call(life::TICK, &mut tk)));
    t.push(line("refresh, bad settings", &refresh(&p, b"1")));
    t.push(line("refresh", &refresh(&p, b"{}")));
    let mut cl: Frame<InHead, OutHead> = Frame::new(input(), output());
    t.push(line("close", &p.call(life::CLOSE, &mut cl)));
    t.push(line(
        "deliver after close",
        &deliver(&p, ExportStream::Logs, b"{}\n", BLOB_JSONL),
    ));

    let reason = "settings must be one JSON object";
    let want = [
        format!("validate, bad settings: Failed error={reason:?}"),
        "validate: Ready error=\"\"".to_string(),
        format!("open, bad settings: Failed error={reason:?}"),
        "open: Ready error=\"\"".to_string(),
        "deliver: Ready error=\"\"".to_string(),
        "deliver, undeclared stream: Refused error=\"stream not declared\"".to_string(),
        "deliver, not JSON lines: Failed error=\"batch is not JSON lines\"".to_string(),
        "scrape, short: Failed error=\"\"".to_string(),
        "scrape: Ready error=\"\"".to_string(),
        "status: Ready error=\"\"".to_string(),
        "release: Ready error=\"\"".to_string(),
        "release again: Refused error=\"no such lease\"".to_string(),
        "check: Ready error=\"\"".to_string(),
        "serve: Refused error=\"no routes are declared\"".to_string(),
        "tick: Ready error=\"\"".to_string(),
        format!("refresh, bad settings: Failed error={reason:?}"),
        "refresh: Ready error=\"\"".to_string(),
        "close: Ready error=\"\"".to_string(),
        "deliver after close: Fault error=\"\"".to_string(),
    ];
    for (i, (got, want)) in t.iter().zip(&want).enumerate() {
        assert_eq!(got, want, "the C plugin diverges at step {i}");
    }
    assert_eq!(t.len(), want.len());

    // The delivery's count reached the host on the #85 envelope, against the Statement's family,
    // and the host dropped nothing the plugin reported.
    assert_eq!(
        *seen.metrics.lock().unwrap_or_else(|e| e.into_inner()),
        [(0, METRIC_ADD, 2.0)]
    );
    assert!(seen
        .dropped
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_empty());
}

/// THE RED ARM, KEPT: the same C source built against another export ABI version — newer, and
/// older — is refused at pack time and at load, naming the rebuild; a manifest stating another
/// version is refused before the library is opened. The conforming build loads beside them.
#[test]
fn a_c_plugin_built_against_another_export_abi_is_refused() {
    let host = export::ABI_VERSION;
    let conforming = build("c_export_door_red_control", &[]);
    let stated = rendering_of_library(&conforming)
        .expect("the conforming C door renders")
        .expect("a door");
    load(&conforming, &stated, Arc::default()).expect("the conforming build loads");

    for (name, door) in [
        ("c_export_door_newer", host + 1),
        ("c_export_door_older", host - 1),
    ] {
        let lib = build(name, &[&format!("BB_C_DOOR_KIND_ABI={door}u")]);
        let want = LoadError::KindAbi {
            kind: KindCode::Export,
            door,
            host,
        };
        assert_eq!(
            rendering_of_library(&lib).err(),
            Some(want.clone()),
            "the pack tool refuses the ABI {door} door"
        );
        let refused = load(&lib, &stated, Arc::default())
            .err()
            .expect("the loader refuses a door at another export ABI");
        assert_eq!(refused, want);
        assert!(refused.to_string().contains("rebuild"), "{refused}");
    }

    // A manifest stating another version: refused before `dlopen`.
    let at = RENDERING_MAGIC.len() + 8;
    let mut newer = stated.clone();
    newer[at..at + 4].copy_from_slice(&(host + 1).to_le_bytes());
    assert_eq!(
        load(&conforming, &newer, Arc::default()).err(),
        Some(LoadError::ManifestKindAbi {
            stated: host + 1,
            host,
        })
    );
}
