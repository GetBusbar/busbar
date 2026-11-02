// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

struct WitnessKind;
impl Kind for WitnessKind {
    const CODE: KindCode = witness::KIND;
    type Ops = OpsHead;
    const TIMEOUT: busbar_contract::abi::mechanism::call::Outcome =
        busbar_contract::abi::mechanism::call::Outcome::Failed;
}

const INSTANCE: &str = "log-witness";

fn fixed_clock() -> u64 {
    1_790_000_000
}

pub(crate) fn scratch(tag: &str) -> PathBuf {
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

pub(crate) fn config(dir: &Path, level: LogLevel) -> PluginLogConfig {
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

fn dropped_path() -> PathBuf {
    crate::both_ways::example_cdylib("log_witness_door")
}

fn dropped(sink: Arc<dyn EnvelopeSink>) -> Plugin<WitnessKind> {
    let stated = rendering_of(witness::a::door).expect("the witness renders its Statement");
    load_dropped::<WitnessKind>(&dropped_path(), &stated, bind(sink))
        .expect("the dropped witness loads")
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

fn tick(p: &Plugin<WitnessKind>, mode: &[u8]) {
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

fn read(dir: &Path, sink: &PluginLogSink) -> String {
    sink.flush();
    let path = config(dir, LogLevel::Trace).path_for(INSTANCE, witness::KIND);
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn a_linked_and_a_dropped_plugin_write_byte_identical_log_files() {
    let (ld, dd) = (scratch("linked"), scratch("dropped"));
    let (ls, ds) = (sink(&ld, LogLevel::Trace), sink(&dd, LogLevel::Trace));
    run(linked(ls.clone()));
    run(dropped(ds.clone()));
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

#[test]
fn a_write_outside_the_capture_never_reaches_the_plugin_log() {
    for (tag, load) in [("outside-linked", true), ("outside-dropped", false)] {
        let dir = scratch(tag);
        let s = sink(&dir, LogLevel::Trace);
        let p = if load {
            linked(s.clone())
        } else {
            dropped(s.clone())
        };
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

#[test]
fn a_store_and_an_auth_provider_of_one_name_log_to_two_files() {
    use crate::dispatch::Diagnostic;
    use busbar_contract::abi::mechanism::call::{DIAG_LOG, SEVERITY_INFO};
    let dir = scratch("two-kinds");
    let cfg = config(&dir, LogLevel::Info);
    let store = cfg
        .sink("memory", KindCode::Store, Arc::new(NoSink))
        .expect("the store's sink opens");
    let auth = cfg
        .sink("memory", KindCode::Auth, Arc::new(NoSink))
        .expect("the auth provider's sink opens");
    assert_ne!(
        store.path(),
        auth.path(),
        "a store and an auth provider named alike share one log file"
    );
    let line = |sink: &PluginLogSink, text: &str| {
        sink.diag(Diagnostic {
            id: DIAG_LOG,
            name: &[],
            severity: SEVERITY_INFO,
            text: text.as_bytes(),
        });
        sink.flush();
    };
    line(&store, "the store's record");
    line(&auth, "the auth provider's record");
    let store_text = std::fs::read_to_string(store.path()).expect("the store's file");
    let auth_text = std::fs::read_to_string(auth.path()).expect("the auth provider's file");
    assert!(store_text.contains("the store's record"), "{store_text}");
    assert!(
        !store_text.contains("the auth provider's record"),
        "{store_text}"
    );
    assert!(
        auth_text.contains("the auth provider's record"),
        "{auth_text}"
    );
    assert!(!auth_text.contains("the store's record"), "{auth_text}");
}

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
    assert_eq!(s.path(), dir.join("export.a_b_c.log"));
    for i in 0..4 {
        s.diag(Diagnostic {
            id: DIAG_LOG,
            name: &[],
            severity: SEVERITY_INFO,
            text: format!("record {i}\nsecond half").as_bytes(),
        });
    }
    s.flush();
    let live = std::fs::read_to_string(dir.join("export.a_b_c.log")).expect("the live file");
    let archive = std::fs::read_to_string(dir.join("export.a_b_c.log.1")).expect("the archive");
    assert!(archive.contains("record 0\\nsecond half"), "{archive}");
    assert!(live.contains("record 3\\nsecond half"), "{live}");
    assert!(
        live.lines().all(|l| l.contains(" INFO  a/b c export ")),
        "{live}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

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

#[cfg(unix)]
fn deferred(dir: &Path, level: LogLevel) -> PluginLogConfig {
    PluginLogConfig {
        named_dir: false,
        ..config(dir, level)
    }
}

#[cfg(unix)]
fn stall(path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("a path without NUL");
    // SAFETY: `c` is a live NUL-terminated path.
    let made = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(made, 0, "mkfifo {}", path.display());
}

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

#[cfg(unix)]
#[test]
fn a_stalled_log_file_never_stalls_the_plugin_call() {
    let dir = scratch("stalled");
    let cfg = deferred(&dir, LogLevel::Trace);
    let path = cfg.path_for(INSTANCE, witness::KIND);
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

#[cfg(unix)]
#[test]
fn a_full_log_queue_counts_its_lines_and_never_waits() {
    use crate::dispatch::log_file::LOG_QUEUE_LINES;
    use crate::dispatch::Diagnostic;
    use busbar_contract::abi::mechanism::call::{DIAG_LOG, SEVERITY_INFO};
    let dir = scratch("full");
    let cfg = deferred(&dir, LogLevel::Info);
    let path = cfg.path_for(INSTANCE, witness::KIND);
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

fn info(s: &PluginLogSink, text: &[u8]) {
    s.diag(crate::dispatch::Diagnostic {
        id: busbar_contract::abi::mechanism::call::DIAG_LOG,
        name: &[],
        severity: busbar_contract::abi::mechanism::call::SEVERITY_INFO,
        text,
    });
}

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
    let live = dir.join("export.shared.log");
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
    let blocker = dir.join("export.stuck.log.1").join("held");
    std::fs::create_dir_all(&blocker).expect("a directory where the archive goes");
    for i in 0..30 {
        info(&s, format!("line {i:02}").as_bytes());
    }
    s.flush();
    let text = std::fs::read_to_string(dir.join("export.stuck.log")).unwrap_or_default();
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

#[test]
fn a_successful_live_rename_resets_the_byte_retry_even_when_retention_fails() {
    let dir = scratch("rotate-partial-recovery");
    let mut cfg = config(&dir, LogLevel::Info);
    cfg.rotate_bytes = Some(200);
    cfg.keep = 2;
    let s = cfg
        .sink("partial", witness::KIND, Arc::new(NoSink))
        .expect("the sink opens")
        .with_clock(fixed_clock);
    let live = dir.join("export.partial.log");
    let first = dir.join("export.partial.log.1");
    let second = dir.join("export.partial.log.2");
    std::fs::create_dir_all(first.join("held")).expect("block live rename");
    std::fs::create_dir_all(second.join("held")).expect("block retention");
    info(&s, format!("initial {}", "x".repeat(1024)).as_bytes());
    s.flush();
    info(&s, format!("failed {}", "x".repeat(1024)).as_bytes());
    s.flush();
    let failed = std::fs::read_to_string(&live).expect("failed rotation keeps live file");
    assert!(failed.contains("could not be rotated"));
    std::fs::remove_dir_all(&first).expect("allow the live rename alone");
    info(
        &s,
        format!("partial-success {}", "x".repeat(1024)).as_bytes(),
    );
    s.flush();
    let archived = std::fs::read_to_string(&first).expect("live file renamed despite retention");
    assert!(archived.contains("initial") && archived.contains("failed"));
    std::fs::remove_dir_all(&second).expect("allow all subsequent rotation steps");
    info(&s, b"next-file");
    s.flush();
    let archived = std::fs::read_to_string(&first).expect("the new file reaches its own limit");
    let current = std::fs::read_to_string(&live).expect("a third file is open");
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(archived.contains("partial-success"), "{archived}");
    assert!(!current.contains("partial-success"), "{current}");
    assert!(current.contains("next-file"), "{current}");
}

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
    let mut archive = dir.join("export.raw.log").into_os_string();
    archive.push(".1");
    let rotated = Path::new(&archive).is_file();
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        rotated,
        "the file under a non-UTF-8 directory was never rotated"
    );
}

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
    let read =
        |d: &Path| std::fs::read_to_string(d.join("export.log-witness.log")).unwrap_or_default();
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

pub(crate) type HostLine = (String, tracing::Level, String, String);

pub(crate) struct HostLog(std::sync::Mutex<Vec<HostLine>>);

impl HostLog {
    pub(crate) fn installed() -> &'static HostLog {
        static LOG: std::sync::OnceLock<&'static HostLog> = std::sync::OnceLock::new();
        LOG.get_or_init(|| {
            let log: &'static HostLog = Box::leak(Box::new(HostLog(Default::default())));
            tracing::subscriber::set_global_default(Shared(log))
                .expect("no other global subscriber in this test binary");
            log
        })
    }

    pub(crate) fn lines(&self) -> Vec<HostLine> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

struct Shared(&'static HostLog);

#[derive(Default)]
struct Fields {
    plugin: String,
    message: String,
}

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "plugin" => self.plugin = format!("{value:?}"),
            "message" => self.message = format!("{value:?}"),
            _ => {}
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "plugin" => self.plugin = value.to_string(),
            "message" => self.message = value.to_string(),
            _ => {}
        }
    }
}

impl tracing::Subscriber for Shared {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let meta = event.metadata();
        self.0 .0.lock().unwrap_or_else(|p| p.into_inner()).push((
            meta.target().to_string(),
            *meta.level(),
            fields.plugin,
            fields.message,
        ));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn a_dropped_in_plugins_warning_is_also_a_line_of_busbars_own_log() {
    const MIRRORED: &str = "mirror-witness";
    let host = HostLog::installed();
    let dir = scratch("mirror");
    let label = dir.file_name().unwrap().to_string_lossy().into_owned();
    let command = format!("log:{label}");
    let expected_message = format!("log from the plugin, {label}");
    let s = Arc::new(
        config(&dir, LogLevel::Trace)
            .sink(MIRRORED, witness::KIND, Arc::new(NoSink))
            .expect("the sink opens")
            .with_clock(fixed_clock),
    );
    let p = dropped(s.clone());
    std::thread::spawn(move || {
        open(&p);
        tick(&p, command.as_bytes());
    })
    .join()
    .expect("the script runs");
    s.flush();
    let file =
        std::fs::read_to_string(config(&dir, LogLevel::Trace).path_for(MIRRORED, witness::KIND))
            .unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        file.contains(&format!(
            " WARN  mirror-witness export log_witness: {expected_message}"
        )),
        "the plugin's own file keeps the line:\n{file}"
    );
    let ours: Vec<HostLine> = host
        .lines()
        .into_iter()
        .filter(|(target, _, _, _)| target == super::MIRROR_TARGET)
        .collect();
    assert!(
        ours.iter()
            .any(|(_, level, plugin, message)| *level == tracing::Level::WARN
                && message == &expected_message
                && plugin.is_empty()),
        "busbar's own log carries the plugin's WARN line as 1.5.5 wrote it: {ours:?}"
    );
    assert!(
        !ours
            .iter()
            .any(|(_, _, _, message)| message.contains("tracing at debug from the plugin")),
        "only WARN and ERROR lines are copied to busbar's log: {ours:?}"
    );
}

#[test]
fn the_busbar_log_copy_carries_no_diag_field() {
    assert_eq!(
        super::without_diag_field("x must be https (got 'h'); disabling it diag=BUSBAR-7070"),
        "x must be https (got 'h'); disabling it"
    );
    assert_eq!(
        super::without_diag_field("a diag=BUSBAR-7070 detail=\"high\""),
        "a detail=\"high\""
    );
    assert_eq!(super::without_diag_field("no field here"), "no field here");
}
