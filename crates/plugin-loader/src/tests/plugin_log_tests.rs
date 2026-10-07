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
    EnvelopeSink, Frame, Kind, LinkedRow, LogLevel, NoSink, Plugin, PluginLogConfig, PluginLogSink,
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
        ..PluginLogConfig::from_words(None, None, &Default::default(), None, None)
            .expect("the defaults resolve")
    }
}

fn bind(sink: Arc<dyn EnvelopeSink>) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 4,
        sink,
        dispatcher: Adopter::unwatched(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    }
}

/// The sink `dir` gives the witness instance, on the fixed clock.
fn sink(dir: &Path, level: LogLevel) -> Arc<PluginLogSink> {
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

/// What the witness instance's file holds once `sink`'s writer has written every line handed over.
fn read(dir: &Path, sink: &PluginLogSink) -> String {
    sink.flush();
    let path = config(dir, LogLevel::Trace).path_for(INSTANCE);
    std::fs::read_to_string(path).unwrap_or_default()
}

/// **THE PROOF.** The linked and the dropped-in witness, the same script, the same sink: the two
/// plugin log files are byte-identical, and they hold what the plugin and its libraries logged.
#[test]
fn a_linked_and_a_dropped_plugin_write_byte_identical_log_files() {
    let (ld, dd) = (scratch("linked"), scratch("dropped"));
    let (ls, ds) = (sink(&ld, LogLevel::Trace), sink(&dd, LogLevel::Trace));
    run(linked(ls.clone()));
    let Some(p) = dropped(ds.clone()) else {
        return;
    };
    run(p);
    let (l, d) = (read(&ld, &ls), read(&dd, &ds));
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
        let p = if load {
            Some(linked(s.clone()))
        } else {
            dropped(s.clone())
        };
        let Some(p) = p else { continue };
        std::thread::spawn(move || {
            open(&p);
            tick(&p, witness::OUTSIDE);
        })
        .join()
        .expect("the script runs");
        let text = read(&dir, &s);
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
    let (sa, sb) = (sink(&da, LogLevel::Trace), sink(&db, LogLevel::Trace));
    let a = linked(sa.clone());
    let b = linked_b(sb.clone());
    std::thread::spawn(move || {
        open(&a);
        open(&b);
        tick(&a, witness::NEST);
        tick(&b, witness::LOG);
    })
    .join()
    .expect("the script runs");
    let (ta, tb) = (read(&da, &sa), read(&db, &sb));
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
    let s = sink(&dir, LogLevel::Warn);
    let p = linked(s.clone());
    std::thread::spawn(move || {
        open(&p);
        tick(&p, witness::LOG);
    })
    .join()
    .expect("the script runs");
    let text = read(&dir, &s);
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
    s.flush();
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

/// A config under `dir` whose file is opened at its first line (the default directory's rule), so
/// the first line is what meets a stalled file.
#[cfg(unix)]
fn deferred(dir: &Path, level: LogLevel) -> PluginLogConfig {
    PluginLogConfig {
        named_dir: false,
        ..config(dir, level)
    }
}

/// A FIFO where the instance's file goes: opening it to write waits until a reader opens it, as a
/// disk that does not answer would.
#[cfg(unix)]
fn stall(path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("a path without NUL");
    // SAFETY: `c` is a live NUL-terminated path.
    let made = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(made, 0, "mkfifo {}", path.display());
}

/// Open the stalled file to read, which lets its writer through, and hand over each line it reads.
#[cfg(unix)]
fn release(path: PathBuf) -> std::sync::mpsc::Receiver<String> {
    use std::io::BufRead as _;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let f = std::fs::File::open(path).expect("the stalled file opens to read");
        for line in std::io::BufReader::new(f).lines() {
            let Ok(line) = line else { return };
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    rx
}

/// **RED ARM: A STALLED LOG FILE NEVER STALLS THE PLUGIN CALL** (§11.2: no blocking on the hot path;
/// §11.11 R4: the bounded disk lane is not plugin logging's). The instance's file is a FIFO nobody
/// reads, so opening it waits; the plugin call that logs still answers, and its lines reach the
/// file, in the one line format, once the file is read.
#[cfg(unix)]
#[test]
fn a_stalled_log_file_never_stalls_the_plugin_call() {
    let dir = scratch("stalled");
    let cfg = deferred(&dir, LogLevel::Trace);
    let path = cfg.path_for(INSTANCE);
    stall(&path);
    let s: Arc<dyn EnvelopeSink> = Arc::new(
        cfg.sink(INSTANCE, witness::KIND, Arc::new(NoSink))
            .expect("the sink opens")
            .with_clock(fixed_clock),
    );
    let p = linked(s);
    let (called, answered) = std::sync::mpsc::channel();
    let caller = std::thread::spawn(move || {
        open(&p);
        tick(&p, witness::LOG);
        let _ = called.send(());
        p
    });
    let returned = answered
        .recv_timeout(std::time::Duration::from_secs(10))
        .is_ok();
    // Let the file through either way, so a call that did wait finishes before the verdict.
    let lines = release(path);
    let p = caller.join().expect("the script runs");
    let want = " INFO  log-witness export log_witness: tracing from the plugin who=\"a\" calls=1";
    let mut read = Vec::new();
    while let Ok(line) = lines.recv_timeout(std::time::Duration::from_secs(30)) {
        let found = line.contains(want);
        read.push(line);
        if found {
            break;
        }
    }
    drop(p);
    assert!(
        returned,
        "the plugin call waited on its stalled log file (no answer in 10 s)"
    );
    assert!(
        read.iter()
            .any(|l| l.starts_with("2026-09-21T") && l.contains(want)),
        "the line reached the file once it was read: {read:#?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **RED ARM: A FULL QUEUE COUNTS, IT NEVER WAITS.** With the file stalled, more lines than the
/// writer's queue holds are handed to the sink: every hand-over returns, and once the file is read
/// each line is either written or counted in ONE line saying how many were dropped.
#[cfg(unix)]
#[test]
fn a_full_log_queue_counts_its_lines_and_never_waits() {
    use crate::dispatch::log_file::LOG_QUEUE_LINES;
    use crate::dispatch::Diagnostic;
    use busbar_contract::abi::mechanism::call::{DIAG_LOG, SEVERITY_INFO};
    let dir = scratch("full");
    let cfg = deferred(&dir, LogLevel::Info);
    let path = cfg.path_for(INSTANCE);
    stall(&path);
    let s = cfg
        .sink(INSTANCE, witness::KIND, Arc::new(NoSink))
        .expect("the sink opens")
        .with_clock(fixed_clock);
    let sent = LOG_QUEUE_LINES + 100;
    let (handed, over) = std::sync::mpsc::channel();
    let feeder = std::thread::spawn(move || {
        for i in 0..sent {
            s.diag(Diagnostic {
                id: DIAG_LOG,
                name: &[],
                severity: SEVERITY_INFO,
                text: format!("record {i}").as_bytes(),
            });
        }
        let _ = handed.send(());
        s
    });
    let returned = over
        .recv_timeout(std::time::Duration::from_secs(10))
        .is_ok();
    let lines = release(path);
    // The sink goes: its writer writes what it holds, reports what it lost, and closes the file.
    drop(feeder.join().expect("the feeder runs"));
    let mut read = Vec::new();
    while let Ok(line) = lines.recv_timeout(std::time::Duration::from_secs(30)) {
        read.push(line);
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        returned,
        "a stalled log file made the sink wait (no return in 10 s)"
    );
    let written = read
        .iter()
        .filter(|l| l.contains(" INFO  log-witness export record "))
        .count();
    let tallies: Vec<&String> = read
        .iter()
        .filter(|l| l.contains(" WARN  log-witness export busbar: "))
        .collect();
    assert_eq!(
        tallies.len(),
        1,
        "one line counts the lost lines: {tallies:#?}"
    );
    let lost: usize = tallies[0]
        .split("busbar: ")
        .nth(1)
        .and_then(|t| t.strip_suffix(" log lines were dropped: the log writer was behind"))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("the count line names a number: {}", tallies[0]));
    assert_eq!(written + lost, sent, "every line is written or counted");
    assert!(
        lost + LOG_QUEUE_LINES + 1 >= sent,
        "the queue held at most {LOG_QUEUE_LINES} lines and the writer one: {lost} lost"
    );
}

/// One `info` record of `text`, handed to `s`.
fn info(s: &PluginLogSink, text: &[u8]) {
    s.diag(crate::dispatch::Diagnostic {
        id: busbar_contract::abi::mechanism::call::DIAG_LOG,
        name: &[],
        severity: busbar_contract::abi::mechanism::call::SEVERITY_INFO,
        text,
    });
}

/// **RED ARM: ONE FILE, ONE STATE.** Two live sinks of one instance (an auth row is bound anew
/// under one label) write one file: it rotates by the size of everything in it, once, and no line
/// lands in an archive through a descriptor a rotation left behind. Oldest archive first, the files
/// hold one unbroken run of lines; none passes the size by more than a line; `keep` archives stay.
#[test]
fn two_sinks_of_one_file_rotate_it_once_and_never_write_an_archive() {
    let dir = scratch("one-file");
    let mut cfg = config(&dir, LogLevel::Info);
    cfg.rotate_bytes = Some(300);
    cfg.keep = 3;
    let open = || {
        cfg.sink("shared", witness::KIND, Arc::new(NoSink))
            .expect("the sink opens")
            .with_clock(fixed_clock)
    };
    let (a, b) = (open(), open());
    for i in 0..40 {
        let s = if i % 2 == 0 { &a } else { &b };
        info(s, format!("seq {i:04}").as_bytes());
        s.flush();
    }
    let live = dir.join("shared.log");
    let archive = |i: u32| PathBuf::from(format!("{}.{i}", live.display()));
    let files: Vec<String> = [archive(3), archive(2), archive(1), live.clone()]
        .iter()
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .collect();
    let beyond = archive(4).exists();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!beyond, "more than keep archives");
    let seqs: Vec<u32> = files
        .iter()
        .flat_map(|f| f.lines())
        .filter_map(|l| l.split("seq ").nth(1)?.parse().ok())
        .collect();
    assert!(
        seqs.windows(2).all(|w| w[1] == w[0] + 1) && seqs.last() == Some(&39),
        "the files hold one run of lines, oldest archive first: {seqs:?}\n{files:#?}"
    );
    let line = files[3].lines().next().map_or(0, |l| l.len() as u64 + 1);
    for f in &files {
        assert!(
            f.len() as u64 <= 300 + line,
            "a file passed the size by more than a line:\n{f}"
        );
    }
}

/// **RED ARM: A FAILED ROTATION IS REPORTED ONCE AND BACKS OFF.** Where the archive goes stands a
/// directory that is not empty, so every rotation of the file fails: the file says so once, keeps
/// every line, and the directory is left as it was.
#[test]
fn a_failed_rotation_is_reported_once_and_keeps_every_line() {
    let dir = scratch("rotate-fails");
    let mut cfg = config(&dir, LogLevel::Info);
    cfg.rotate_bytes = Some(200);
    cfg.keep = 1;
    let s = cfg
        .sink("stuck", witness::KIND, Arc::new(NoSink))
        .expect("the sink opens")
        .with_clock(fixed_clock);
    let blocker = dir.join("stuck.log.1").join("held");
    std::fs::create_dir_all(&blocker).expect("a directory where the archive goes");
    for i in 0..30 {
        info(&s, format!("line {i:02}").as_bytes());
    }
    s.flush();
    let text = std::fs::read_to_string(dir.join("stuck.log")).unwrap_or_default();
    let kept = blocker.is_dir();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(kept, "the directory in the archive's place was touched");
    assert_eq!(
        text.matches("could not be rotated").count(),
        1,
        "a failed rotation is one line, once:\n{text}"
    );
    assert_eq!(
        text.lines()
            .filter(|l| l.contains(" INFO  stuck export line "))
            .count(),
        30,
        "{text}"
    );
}

/// **RED ARM: A PATH IS ROTATED AS ITSELF.** A directory whose name is not UTF-8 rotates its own
/// file: no lossy copy of its name is renamed in its place.
#[cfg(target_os = "linux")]
#[test]
fn a_file_under_a_name_that_is_not_utf8_rotates() {
    use std::os::unix::ffi::OsStrExt as _;
    let root = scratch("not-utf8");
    let dir = root.join(std::ffi::OsStr::from_bytes(b"logs-\xff"));
    let mut cfg = config(&dir, LogLevel::Info);
    cfg.rotate_bytes = Some(120);
    let s = cfg
        .sink("raw", witness::KIND, Arc::new(NoSink))
        .expect("the sink opens")
        .with_clock(fixed_clock);
    for i in 0..8 {
        info(&s, format!("line {i}").as_bytes());
    }
    s.flush();
    let mut archive = dir.join("raw.log").into_os_string();
    archive.push(".1");
    let rotated = Path::new(&archive).is_file();
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        rotated,
        "the file under a non-UTF-8 directory was never rotated"
    );
}

/// **RED ARM: EVERY CONTROL CHARACTER IS ESCAPED.** ESC, NUL, DEL and a tab reach the file as
/// `\u{..}`, and a line break and a carriage return as `\n` and `\r`, as before: nothing raw.
#[test]
fn every_control_character_in_a_record_is_written_escaped() {
    let dir = scratch("escape");
    let s = sink(&dir, LogLevel::Trace);
    info(&s, b"red \x1b[31m nul \0 del \x7f tab \t line\nbreak\r");
    let text = read(&dir, &s);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        text.ends_with(
            " INFO  log-witness export red \\u{1b}[31m nul \\u{0} del \\u{7f} tab \\u{9} line\\nbreak\\r\n"
        ),
        "{text:?}"
    );
    assert_eq!(
        text.bytes().filter(|b| b.is_ascii_control()).count(),
        1,
        "only the line's own end is a control byte: {text:?}"
    );
}

/// **RED ARM: A CONFIG APPLY REACHES A LIVE SINK** (THE DESIGN §11.2). A sink opened under `warn`
/// in one directory drops an `info` line; reconfigured to `info` in another, it writes the next one
/// there (the directory created as at bind) and nothing to the first.
#[test]
fn a_reconfigured_level_and_directory_reach_a_live_sink() {
    let (first, second) = (scratch("reconf-a"), scratch("reconf-b").join("made"));
    let cfg = config(&first, LogLevel::Warn);
    let s = cfg
        .clone()
        .sink(INSTANCE, witness::KIND, Arc::new(NoSink))
        .expect("the sink opens")
        .with_clock(fixed_clock);
    info(&s, b"before");
    cfg.reconfigure(&config(&second, LogLevel::Info));
    info(&s, b"after");
    s.flush();
    let read = |d: &Path| std::fs::read_to_string(d.join("log-witness.log")).unwrap_or_default();
    let (a, b) = (read(&first), read(&second));
    assert_eq!(cfg.level_for(INSTANCE), LogLevel::Info);
    let _ = std::fs::remove_dir_all(&first);
    let _ = std::fs::remove_dir_all(second.parent().unwrap_or(&second));
    assert!(a.is_empty(), "the first directory got a line: {a}");
    assert!(
        b.ends_with(" INFO  log-witness export after\n") && !b.contains("before"),
        "{b}"
    );
}
