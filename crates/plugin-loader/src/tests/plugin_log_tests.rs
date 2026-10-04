// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **PLUGIN LOGGING, BOTH WAYS.** One plugin LINKED (the `log_witness_plugin` fixture, compiled
//! into this build) and DROPPED (the same source behind the one-line `export_door!` cdylib, the
//! `log_witness_door` example), driven by ONE script through the SAME dispatcher into the SAME
//! per-plugin log file sink, and the two files compared BYTE FOR BYTE.
//!
//! The script logs through `tracing` and `log`, from the plugin's own code and from the libraries
//! inside it (`h2` through `tracing`, `tungstenite` through `log`), floods past the bound, and
//! writes outside any capture. A compiled-in plugin shares the host's `tracing` and `log`; a
//! dropped-in one carries its own copies of both. The door macro's call capture is what makes the
//! two write the same file.
//!
//! RED ARMS, kept: what a plugin writes to standard error, or logs from a thread of its own, is
//! outside every capture and is shown NOT to reach its log file in either build; two plugin images
//! on one thread keep their own records, even when one calls the other inside its call.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::log_witness_plugin as witness;
use busbar_contract::abi::mechanism::call::{Blob, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut, OpsHead, TickIn, TickOut};
use busbar_contract::abi::mechanism::KindCode;

use crate::dispatch::{
    in_head, load_dropped, load_linked, now_ns, out_head, rendering_of, Adopter, Bind,
    EnvelopeSink, Frame, Kind, LinkedRow, LogLevel, NoSink, Plugin, PluginLogConfig,
    MAX_LOG_RECORDS, NO_BLOB,
};

/// The witness's kind, as the dispatcher sees it: a lifecycle-only table.
struct WitnessKind;
impl Kind for WitnessKind {
    const CODE: KindCode = witness::KIND;
    type Ops = OpsHead;
    const TIMEOUT: busbar_contract::abi::mechanism::call::Outcome =
        busbar_contract::abi::mechanism::call::Outcome::Failed;
}

/// The instance name both builds log under: the same name, so the same file name and line tags.
const INSTANCE: &str = "log-witness";

/// A fixed time, so the two files can be compared byte for byte.
fn fixed_clock() -> u64 {
    1_790_000_000
}

/// A fresh directory of this test's own.
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "busbar-plugin-log-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

fn config(dir: &Path, level: LogLevel) -> PluginLogConfig {
    PluginLogConfig {
        dir: dir.to_path_buf(),
        level,
        levels: Default::default(),
        rotate_bytes: None,
        keep: 5,
        named_dir: true,
    }
}

fn bind(sink: Arc<dyn EnvelopeSink>) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 4,
        sink,
        dispatcher: Adopter::unwatched(),
        conns: None,
    }
}

/// The sink `dir` gives the witness instance, on the fixed clock.
fn sink(dir: &Path, level: LogLevel) -> Arc<dyn EnvelopeSink> {
    Arc::new(
        config(dir, level)
            .sink(INSTANCE, witness::KIND, Arc::new(NoSink))
            .expect("the sink opens")
            .with_clock(fixed_clock),
    )
}

fn linked(sink: Arc<dyn EnvelopeSink>) -> Plugin<WitnessKind> {
    let row = LinkedRow::of(witness::a::door).expect("the witness states its Statement");
    load_linked::<WitnessKind>(&row, bind(sink)).expect("the linked witness loads")
}

fn linked_b(sink: Arc<dyn EnvelopeSink>) -> Plugin<WitnessKind> {
    let row = LinkedRow::of(witness::b::door).expect("the witness B states its Statement");
    load_linked::<WitnessKind>(&row, bind(sink)).expect("the linked witness B loads")
}

/// The dropped-in witness: the `log_witness_door` example cdylib `cargo test` built beside this
/// binary. Under CI a missing artifact is a failure, never a skip.
fn dropped_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let examples = exe.parent()?.parent()?.join("examples");
    let path = examples.join(format!(
        "{}log_witness_door{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let found = path.exists().then_some(path);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the log_witness_door example cdylib is not built under CI; a both-ways proof must not skip \
         ({} holds {:?})",
        examples.display(),
        std::fs::read_dir(&examples)
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name()).collect::<Vec<_>>())
            .unwrap_or_default()
    );
    found
}

fn dropped(sink: Arc<dyn EnvelopeSink>) -> Option<Plugin<WitnessKind>> {
    // The signed manifest's rendering: the linked rlib's door, the same crate the cdylib is.
    let stated = rendering_of(witness::a::door).expect("the witness renders its Statement");
    Some(
        load_dropped::<WitnessKind>(&dropped_path()?, &stated, bind(sink))
            .expect("the dropped witness loads"),
    )
}

fn open(p: &Plugin<WitnessKind>) {
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: NO_BLOB,
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    assert!(
        p.call(slot::OPEN, &mut f).outcome == busbar_contract::abi::mechanism::call::Outcome::Ready
    );
}

/// One `tick` in `mode`.
fn tick(p: &Plugin<WitnessKind>, mode: &'static [u8]) {
    let mut head = in_head();
    head.extensions = Blob {
        ptr: mode.as_ptr(),
        len: mode.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let mut f = Frame::new(
        TickIn {
            head,
            now_ns: now_ns(),
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    );
    assert!(
        p.call(slot::TICK, &mut f).outcome == busbar_contract::abi::mechanism::call::Outcome::Ready
    );
}

/// The script both builds run, each on a thread of its own (a fresh capture slot each).
fn run(p: Plugin<WitnessKind>) {
    std::thread::spawn(move || {
        open(&p);
        tick(&p, witness::LOG);
        tick(&p, witness::FLOOD);
        tick(&p, witness::OUTSIDE);
        tick(&p, witness::LOG);
    })
    .join()
    .expect("the script runs");
}

fn read(dir: &Path) -> String {
    let path = config(dir, LogLevel::Trace).path_for(INSTANCE);
    std::fs::read_to_string(path).unwrap_or_default()
}

/// **THE PROOF.** The linked and the dropped-in witness, the same script, the same sink: the two
/// plugin log files are byte-identical, and they hold what the plugin and its libraries logged.
#[test]
fn a_linked_and_a_dropped_plugin_write_byte_identical_log_files() {
    let (ld, dd) = (scratch("linked"), scratch("dropped"));
    run(linked(sink(&ld, LogLevel::Trace)));
    let Some(p) = dropped(sink(&dd, LogLevel::Trace)) else {
        return;
    };
    run(p);
    let (l, d) = (read(&ld), read(&dd));
    for want in [
        " INFO  log-witness export log_witness: tracing from the plugin who=\"a\" calls=1",
        " DEBUG log-witness export log_witness: tracing at debug from the plugin",
        " WARN  log-witness export log_witness: log from the plugin, a",
        " TRACE log-witness export log_witness: log at trace from the plugin",
        " DEBUG log-witness export h2::client: binding client connection",
        " TRACE log-witness export tungstenite::protocol: Sending frame:",
    ] {
        assert!(l.contains(want), "the linked file lacks {want:?}:\n{l}");
    }
    let flood_dropped = witness::FLOOD_RECORDS - MAX_LOG_RECORDS;
    assert!(
        l.contains(&format!(
            " WARN  log-witness export busbar: {flood_dropped} log records of one reply were dropped over the bound"
        )),
        "the flood's drop is one counted line:\n{l}"
    );
    assert!(
        l.starts_with("2026-09-21T"),
        "the fixed clock stamps every line:\n{l}"
    );
    assert_eq!(
        l, d,
        "the linked and the dropped-in plugin log files differ"
    );
    let _ = (std::fs::remove_dir_all(&ld), std::fs::remove_dir_all(&dd));
}

/// **RED ARM, KEPT.** A plugin writing straight to standard error, or logging from a thread of its
/// own, is outside every capture: neither reaches its log file, in either build. The lines are not
/// caught; they are lost to the plugin's file, which is the rule's other half (a plugin writes no
/// log of its own).
#[test]
fn a_write_outside_the_capture_never_reaches_the_plugin_log() {
    for (tag, load) in [("outside-linked", true), ("outside-dropped", false)] {
        let dir = scratch(tag);
        let s = sink(&dir, LogLevel::Trace);
        let p = if load { Some(linked(s)) } else { dropped(s) };
        let Some(p) = p else { continue };
        std::thread::spawn(move || {
            open(&p);
            tick(&p, witness::OUTSIDE);
        })
        .join()
        .expect("the script runs");
        let text = read(&dir);
        assert!(!text.contains("standard error"), "{tag}: {text}");
        assert!(!text.contains("thread of its own"), "{tag}: {text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// **RED ARM, KEPT: THE CAPTURE IS PER PLUGIN IMAGE.** Plugin A logs, calls plugin B's `tick` on the
/// same thread from inside its own call (B logs), and logs again. A's file holds both of A's lines
/// and none of B's. One capture shared by both images would hand A's first line to B's reply,
/// which A's call discards, and A's file would lose it.
#[test]
fn two_plugin_images_on_one_thread_keep_their_own_records() {
    let (da, db) = (scratch("image-a"), scratch("image-b"));
    let a = linked(sink(&da, LogLevel::Trace));
    let b = linked_b(sink(&db, LogLevel::Trace));
    std::thread::spawn(move || {
        open(&a);
        open(&b);
        tick(&a, witness::NEST);
        tick(&b, witness::LOG);
    })
    .join()
    .expect("the script runs");
    let (ta, tb) = (read(&da), read(&db));
    assert!(ta.contains("a, before the nested call"), "{ta}");
    assert!(ta.contains("a, after the nested call"), "{ta}");
    assert!(
        !ta.contains("b, inside"),
        "A's file holds B's record:\n{ta}"
    );
    assert_eq!(
        tb.matches("b, inside").count(),
        1,
        "B's file holds exactly its own call's record:\n{tb}"
    );
    assert!(
        !tb.contains("nested call"),
        "B's file holds A's records:\n{tb}"
    );
    let _ = (std::fs::remove_dir_all(&da), std::fs::remove_dir_all(&db));
}

/// The instance's configured level filters its file: at `warn`, only warnings and errors.
#[test]
fn the_instance_level_filters_its_file() {
    let dir = scratch("level");
    let p = linked(sink(&dir, LogLevel::Warn));
    std::thread::spawn(move || {
        open(&p);
        tick(&p, witness::LOG);
    })
    .join()
    .expect("the script runs");
    let text = read(&dir);
    assert!(text.contains(" WARN  "), "{text}");
    for below in [" INFO  ", " DEBUG ", " TRACE "] {
        assert!(
            !text.contains(below),
            "a line under warn was written:\n{text}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The file rotates by the host's rule: past the size it is renamed `<file>.1`, and a new file
/// begins. A line break inside a record stays inside its one line.
#[test]
fn the_file_rotates_and_keeps_one_record_per_line() {
    use crate::dispatch::Diagnostic;
    use busbar_contract::abi::mechanism::call::{DIAG_LOG, SEVERITY_INFO};
    let dir = scratch("rotate");
    let mut cfg = config(&dir, LogLevel::Info);
    cfg.rotate_bytes = Some(120);
    let s = cfg
        .sink("a/b c", witness::KIND, Arc::new(NoSink))
        .expect("the sink opens")
        .with_clock(fixed_clock);
    assert_eq!(s.path(), dir.join("a_b_c.log"));
    for i in 0..4 {
        s.diag(Diagnostic {
            id: DIAG_LOG,
            name: &[],
            severity: SEVERITY_INFO,
            text: format!("record {i}\nsecond half").as_bytes(),
        });
    }
    let live = std::fs::read_to_string(dir.join("a_b_c.log")).expect("the live file");
    let archive = std::fs::read_to_string(dir.join("a_b_c.log.1")).expect("the archive");
    assert!(archive.contains("record 0\\nsecond half"), "{archive}");
    assert!(live.contains("record 3\\nsecond half"), "{live}");
    assert!(
        live.lines().all(|l| l.contains(" INFO  a/b c export ")),
        "{live}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The directory is the host's to make: a sink opened on a directory that does not exist yet
/// creates it (and its missing parents) and the file, and opening again reuses both.
#[test]
fn opening_a_sink_creates_a_missing_directory() {
    let root = scratch("create");
    let dir = root.join("not").join("yet");
    assert!(!dir.exists());
    let cfg = config(&dir, LogLevel::Info);
    let s = cfg
        .sink(INSTANCE, witness::KIND, Arc::new(NoSink))
        .expect("a missing directory is created, not refused");
    assert!(dir.is_dir(), "the directory was created");
    assert!(s.path().is_file(), "the file was opened");
    cfg.sink(INSTANCE, witness::KIND, Arc::new(NoSink))
        .expect("an existing directory is reused");
    let _ = std::fs::remove_dir_all(&root);
}

/// **RED ARM, KEPT.** A directory that cannot be used (a FILE where it should be) refuses the
/// open, naming the key and the directory, `plugins.logs.dir <dir>: <error>`.
#[test]
fn an_unusable_directory_refuses_the_open_naming_its_key() {
    let root = scratch("unusable");
    let dir = root.join("taken");
    std::fs::write(&dir, b"a file, not a directory").expect("a file where the directory goes");
    let err = config(&dir, LogLevel::Info)
        .sink(INSTANCE, witness::KIND, Arc::new(NoSink))
        .expect_err("a file where the directory should be is refused");
    let head = format!("plugins.logs.dir {}: ", dir.display());
    assert!(err.starts_with(&head), "{err}");
    let _ = std::fs::remove_dir_all(&root);
}

/// `plugins.logs` resolves, and a level word that names no level is refused, naming its key.
#[test]
fn the_config_resolves_and_refuses_a_bad_level() {
    let mut levels = std::collections::BTreeMap::new();
    levels.insert("noisy".to_string(), "trace".to_string());
    let cfg =
        PluginLogConfig::from_words(None, Some("warn"), &levels, Some(2), None).expect("resolves");
    assert_eq!(cfg.level_for("noisy"), LogLevel::Trace);
    assert_eq!(cfg.level_for("other"), LogLevel::Warn);
    assert_eq!(cfg.rotate_bytes, Some(2 * 1024 * 1024));
    assert_eq!(cfg.dir, PathBuf::from("logs/plugins"));
    levels.insert("typo".to_string(), "loud".to_string());
    let err = PluginLogConfig::from_words(None, None, &levels, None, None).unwrap_err();
    assert!(err.contains("plugins.logs.levels['typo']"), "{err}");
}
