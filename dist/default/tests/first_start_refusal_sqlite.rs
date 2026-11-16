// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FIRST-START-TAKEOVER T12-T12d, against the real binary on a real, empty SQLite Store: a process
//! that owns an unpublished first start and leaves on purpose (a boot refusal, a one-shot
//! principal command) hands it over on the way out, so the next start takes over at once; a
//! process that waits on another owner says so on its real stderr; and a waiter signalled before
//! its listener exits 143 through the one exit path, retiring nothing. Every log assertion reads
//! the process's own stderr, written to a file and polled in-process.

#![cfg(all(unix, feature = "test-harness"))]

mod common;

use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use busbar_contract::json;
use busbar_kernel::diagnostics::{
    BOOT_FATAL_ERROR, FIRST_START_EXIT_RETIRED, FIRST_START_EXIT_RETIRE_FAILED,
    FIRST_START_TAKEOVER,
};
use busbar_kernel::persistence::first_start::Abandoned;

/// The harness boot deadline (T12, T12a, T12c).
const BOOT: Duration = Duration::from_secs(30);
/// `root::exit::EXIT_RETIRE_BUDGET` (5 s) plus the helper join margin (1 s).
const EXIT_BOUND: Duration = Duration::from_secs(6);
/// `busbar_kernel::persistence::startup::stall_window` for a record with no plane done.
const WINDOW: Duration = busbar_kernel::persistence::startup::FIRST_START_STALL;
const WAIT_LINE: &str = "waiting on first start of this dataset by writer ";
/// An export instance naming a module no build links: refused by `config::resolve`, which runs
/// after Store admission, so the refusing process owns the first start when it exits.
const TYPO: &str = "export:\n  typo:\n    module: no-such-exporter\n";

fn diag(diagnostic: &busbar_kernel::diagnostics::Diagnostic) -> String {
    format!("diag={}", diagnostic.banner())
}

/// The stderr text with ANSI styling removed, as an operator's terminal shows it.
fn plain(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

struct Fixture {
    dir: PathBuf,
    data: u16,
    admin: u16,
    governed: bool,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

impl Fixture {
    /// An empty SQLite namespace, staged as boot stages it. `governed` adds a token-verifying
    /// identity provider, which the principal-creation fixture requires.
    fn new(tag: &str, governed: bool) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "busbar-first-start-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("plugins")).unwrap();
        if governed {
            common::credentials::install_auth_plugin(
                &dir.join("plugins"),
                "e2e-idp-module",
                "e2e-idp",
                true,
            );
        }
        common::fresh_namespace::stage(&dir);
        std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
        let fixture = Self {
            dir,
            data: common::boot::free_port(),
            admin: common::boot::free_port(),
            governed,
        };
        fixture.configure("");
        fixture
    }

    fn configure(&self, extra: &str) {
        let auth = if self.governed {
            format!(
                "identity-providers:\n  idp:\n    module: e2e-idp-module\n    settings:\n{}auth:\n  \
                 chain: [idp]\n  signing_key: {{ env: BUSBAR_SIGNING_KEY }}\n",
                common::credentials::issuer_settings_yaml(
                    &format!("http://127.0.0.1:{}/mcp", self.data),
                    6
                )
            )
        } else {
            "auth:\n  chain: []\n".to_owned()
        };
        std::fs::write(
            self.dir.join("config.yaml"),
            format!(
                "listen: \"127.0.0.1:{data}\"\nadmin_listen: \"127.0.0.1:{admin}\"\n\
                 admin_require_mtls: false\nplugins: {plugins}\nstore: {store}\n{auth}\
                 providers: {{}}\nmodels: {{}}\n{extra}",
                data = self.data,
                admin = self.admin,
                plugins = common::plugins::trusted_config_document(&self.dir.join("plugins")),
                store = common::fresh_namespace::selection(&self.dir)
                    .expect("the staged Store selection"),
            ),
        )
        .unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(common::boot::exe());
        command
            .env("BUSBAR_CONFIG", self.dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", self.dir.join("providers.yaml"))
            .env("RUST_LOG", "info")
            .env(
                "BUSBAR_SIGNING_KEY",
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .env(
                common::credentials::HARNESS_FIRST_PARTY_KEY_ENV,
                common::credentials::harness_release_key_hex(),
            )
            .stdin(Stdio::null());
        command
    }

    /// Spawn the binary with stdout and stderr redirected to files named after `name`.
    fn spawn(&self, name: &str, args: &[&str]) -> Boot {
        let stdout = self.dir.join(format!("{name}.stdout"));
        let stderr = self.dir.join(format!("{name}.stderr"));
        let child = self
            .command()
            .args(args)
            .stdout(std::fs::File::create(&stdout).unwrap())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .expect("spawn busbar");
        Boot {
            child: common::boot::Reap(child),
            stdout,
            stderr,
            spawned: Instant::now(),
            data: self.data,
        }
    }
}

struct Boot {
    child: common::boot::Reap,
    stdout: PathBuf,
    stderr: PathBuf,
    spawned: Instant,
    data: u16,
}

impl Boot {
    fn stderr(&self) -> String {
        plain(&std::fs::read_to_string(&self.stderr).unwrap_or_default())
    }

    fn stdout(&self) -> String {
        std::fs::read_to_string(&self.stdout).unwrap_or_default()
    }

    fn evidence(&mut self) -> String {
        let status = self.child.try_wait().ok().flatten();
        format!(
            "status {status:?}\nstdout:\n{}\nstderr:\n{}",
            self.stdout(),
            self.stderr()
        )
    }

    /// Poll every 50 ms until `done` holds; fail with the process's output on `deadline`.
    fn until(&mut self, deadline: Instant, what: &str, mut done: impl FnMut(&mut Self) -> bool) {
        loop {
            if done(self) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: not within the bound;\n{}",
                self.evidence()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn exits_within(&mut self, bound: Duration) -> ExitStatus {
        let deadline = Instant::now() + bound;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "the process did not exit within {bound:?};\n{}",
                self.evidence()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Ready means healthz answers 200 on the data listener; failing early if the process exits.
    fn ready_within(&mut self, deadline: Instant) -> Instant {
        let data = self.data;
        self.until(deadline, "healthz 200", |boot| {
            if let Ok(Some(status)) = boot.child.try_wait() {
                panic!(
                    "the process exited ({status}) before it was ready;\n{}",
                    boot.evidence()
                );
            }
            common::boot::healthz_answers(data)
        });
        Instant::now()
    }

    /// The writer id the first-start wait line names, once the line is on stderr.
    fn waiting_on(&mut self, deadline: Instant) -> String {
        self.until(deadline, "the first-start wait line", |boot| {
            if let Ok(Some(status)) = boot.child.try_wait() {
                panic!(
                    "the waiter exited ({status}) before it logged why it waits;\n{}",
                    boot.evidence()
                );
            }
            boot.stderr().contains(WAIT_LINE)
        });
        let stderr = self.stderr();
        let line = stderr
            .lines()
            .find(|line| line.contains(WAIT_LINE))
            .expect("the wait line");
        assert!(line.contains("takeover in"), "{line}");
        let id: String = line[line.find(WAIT_LINE).unwrap() + WAIT_LINE.len()..]
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        assert_eq!(id.len(), 32, "a writer id is 32 hex digits: {line}");
        id
    }

    fn refuses_connections(&self) -> bool {
        std::net::TcpStream::connect(("127.0.0.1", self.data)).is_err()
    }
}

/// The line `die()` prints, then the hand-over the exit path logs after it.
fn assert_refused_then_handed_over(stderr: &str) {
    let fatal = format!("[error] {}: config errors", BOOT_FATAL_ERROR.banner());
    let refused = stderr
        .find(&fatal)
        .unwrap_or_else(|| panic!("the boot refusal is on stderr:\n{stderr}"));
    let retired = stderr
        .find(&diag(&FIRST_START_EXIT_RETIRED))
        .unwrap_or_else(|| panic!("the exit hand-over is on stderr:\n{stderr}"));
    assert!(
        refused < retired,
        "the refusal precedes the hand-over:\n{stderr}"
    );
    assert!(
        stderr.contains("first start handed over on exit"),
        "{stderr}"
    );
}

fn assert_handed_over(stderr: &str) {
    assert_eq!(
        stderr.matches(&diag(&FIRST_START_EXIT_RETIRED)).count(),
        1,
        "one exit hand-over:\n{stderr}"
    );
    assert!(
        stderr.contains("first start handed over on exit"),
        "{stderr}"
    );
    assert!(
        !stderr.contains(&diag(&FIRST_START_EXIT_RETIRE_FAILED)),
        "{stderr}"
    );
}

/// The next ordinary process takes over at once: ready within the boot deadline, never waiting.
fn next_start_is_immediate(fixture: &Fixture) {
    let mut boot = fixture.spawn("next", &[]);
    let deadline = boot.spawned + BOOT;
    boot.ready_within(deadline);
    let stderr = boot.stderr();
    assert!(!stderr.contains(WAIT_LINE), "no wait:\n{stderr}");
    assert!(
        !stderr.contains(&diag(&FIRST_START_TAKEOVER)),
        "no takeover:\n{stderr}"
    );
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the in-process owner's runtime")
}

/// Drop an in-process owner without a hand-over (a crash): its Store closes in the runtime it
/// opened in; the door axis outlives it.
fn crash(runtime: &tokio::runtime::Runtime, owner: common::fresh_namespace::Owner) {
    let axis = runtime.block_on(async move {
        let common::fresh_namespace::Owner { axis, .. } = owner;
        axis
    });
    drop(axis);
}

fn hex(id: [u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// T12: a refused boot during an unpublished first start hands it over, and the fixed retry
/// starts at once.
#[test]
fn t12_a_refused_first_start_hands_over_and_the_fixed_retry_starts_at_once() {
    let fixture = Fixture::new("t12", false);
    fixture.configure(TYPO);
    let mut refused = fixture.spawn("refused", &[]);
    let status = refused.exits_within(Duration::from_secs(60));
    assert_eq!(status.code(), Some(1), "{}", refused.evidence());
    assert_refused_then_handed_over(&refused.stderr());

    fixture.configure("");
    next_start_is_immediate(&fixture);
}

/// T12a: `initialize-fresh` returns from `main` without serving; the tail exit hands its first
/// start over, after printing exactly its JSON report on stdout.
#[test]
fn t12a_a_one_shot_fresh_initialization_hands_over_on_return() {
    let fixture = Fixture::new("t12a", true);
    common::fresh_namespace::initialize(&fixture.dir, &fixture.command())
        .expect("the new namespace initializes");
    let evidence = fixture.dir.join("principal-setup");
    let observed = |suffix: &str| -> Vec<u8> {
        let mut found: Vec<PathBuf> = std::fs::read_dir(&evidence)
            .expect("the principal CLI observations")
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(&format!("-initialize-fresh.{suffix}")))
            })
            .collect();
        assert_eq!(found.len(), 1, "one initialize-fresh run: {found:?}");
        std::fs::read(found.pop().unwrap()).unwrap()
    };
    let stdout = observed("stdout");
    let report = json::parse_value(&stdout).expect("stdout is exactly the transition report JSON");
    assert_eq!(report["action"], "initialize-fresh");
    assert!(
        !String::from_utf8_lossy(&stdout).contains("diag="),
        "no log line on stdout"
    );
    assert_handed_over(&plain(&String::from_utf8_lossy(&observed("stderr"))));

    next_start_is_immediate(&fixture);
}

/// T12b: `inspect` on an empty namespace owns the first start it registers, and hands it over
/// when it returns.
#[test]
fn t12b_a_one_shot_inspect_on_an_empty_namespace_hands_over_on_return() {
    let fixture = Fixture::new("t12b", false);
    let mut inspect = fixture.spawn(
        "inspect",
        &[
            "--principal-transition",
            "-",
            "--transition-action",
            "inspect",
        ],
    );
    let status = inspect.exits_within(Duration::from_secs(60));
    assert!(status.success(), "{}", inspect.evidence());
    let _ = json::parse_value(inspect.stdout().as_bytes()).unwrap_or_else(|e| {
        panic!(
            "stdout is exactly the inspect report JSON ({e});\n{}",
            inspect.evidence()
        )
    });
    assert_handed_over(&inspect.stderr());

    next_start_is_immediate(&fixture);
}

/// T12c's hold point: this process owns the unpublished, unfrozen first start and holds no Store
/// transaction; boot 2, the real binary, waits on it and says so.
fn waiting_on_this_process(
    tag: &str,
) -> (
    Fixture,
    tokio::runtime::Runtime,
    common::fresh_namespace::Owner,
    Boot,
    String,
) {
    let fixture = Fixture::new(tag, false);
    let runtime = runtime();
    let owner = runtime.block_on(common::fresh_namespace::admit_in_process(&fixture.dir));
    let first_start = owner
        .store
        .first_start()
        .expect("this process owns the namespace's unpublished first start");
    let id = hex(first_start.owner());
    drop(first_start);
    let mut waiter = fixture.spawn("waiter", &[]);
    let deadline = waiter.spawned + BOOT;
    let named = waiter.waiting_on(deadline);
    assert_eq!(named, id, "the wait line names this process's writer");
    assert!(
        waiter.refuses_connections(),
        "no listener is bound while it waits;\n{}",
        waiter.evidence()
    );
    (fixture, runtime, owner, waiter, id)
}

/// T12c release: the owner hands over; the waiter takes over at once, with no takeover banner.
#[test]
fn t12c_a_waiter_says_why_it_waits_and_starts_once_the_owner_hands_over() {
    let (_fixture, runtime, owner, mut waiter, _) = waiting_on_this_process("t12c-release");
    let first_start = owner.store.first_start().expect("still the owner");
    assert_eq!(
        runtime.block_on(first_start.abandon()),
        Ok(Abandoned::Retired)
    );
    let released = Instant::now();
    waiter.ready_within(released + BOOT);
    let stderr = waiter.stderr();
    assert!(
        !stderr.contains(&diag(&FIRST_START_TAKEOVER)),
        "a hand-over is not a takeover:\n{stderr}"
    );
    drop(first_start);
    crash(&runtime, owner);
}

/// T12c takeover: the owner dies without a hand-over; the waiter takes over one window after its
/// first inspect, and says whom it retired.
#[test]
fn t12c_a_waiter_takes_over_a_dead_owner_after_the_window() {
    let (_fixture, runtime, owner, mut waiter, id) = waiting_on_this_process("t12c-takeover");
    crash(&runtime, owner);
    let ready = waiter.ready_within(waiter.spawned + WINDOW + BOOT);
    assert!(
        ready.duration_since(waiter.spawned) >= WINDOW,
        "no takeover before the window: ready after {:?};\n{}",
        ready.duration_since(waiter.spawned),
        waiter.evidence()
    );
    let stderr = waiter.stderr();
    let takeover = stderr
        .lines()
        .find(|line| line.contains(&diag(&FIRST_START_TAKEOVER)))
        .unwrap_or_else(|| panic!("the takeover is audited:\n{stderr}"));
    assert!(
        takeover.contains(&format!("previous={id}")),
        "the takeover names the writer it retired: {takeover}"
    );
}

/// T12d: SIGTERM before the listener exits 143 through the one exit path; a waiter never armed,
/// so it retires nothing and the owner's first start stays as it was.
#[test]
fn t12d_a_signalled_waiter_exits_143_and_retires_nothing() {
    let (fixture, runtime, owner, mut waiter, id) = waiting_on_this_process("t12d");
    assert!(Command::new("kill")
        .args(["-TERM", &waiter.child.id().to_string()])
        .status()
        .unwrap()
        .success());
    let status = waiter.exits_within(EXIT_BOUND);
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            (status.code(), status.signal()),
            (Some(143), None),
            "{}",
            waiter.evidence()
        );
    }
    let stderr = waiter.stderr();
    assert!(
        !stderr.contains(&diag(&FIRST_START_EXIT_RETIRED))
            && !stderr.contains(&diag(&FIRST_START_EXIT_RETIRE_FAILED)),
        "a waiter owns nothing to hand over:\n{stderr}"
    );

    // The owner's first start is untouched: a third process waits on the same writer.
    let mut third = fixture.spawn("third", &[]);
    let deadline = third.spawned + BOOT;
    assert_eq!(third.waiting_on(deadline), id);
    drop(third);

    // And this process's writer row still admits it: its own hand-over applies now.
    let first_start = owner.store.first_start().expect("still the owner");
    assert_eq!(
        runtime.block_on(first_start.abandon()),
        Ok(Abandoned::Retired)
    );
    drop(first_start);
    crash(&runtime, owner);
}

#[test]
fn plain_strips_terminal_styling() {
    assert_eq!(
        plain("\u{1b}[2m2026\u{1b}[0m \u{1b}[3mdiag\u{1b}[0m\u{1b}[2m=\u{1b}[0mBUSBAR-0001"),
        "2026 diag=BUSBAR-0001"
    );
}
