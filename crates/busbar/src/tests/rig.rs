// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared distribution test rig (CORE-ARCHITECTURE-DIET W0.4).

/// Re-run the calling test alone in a child process and return its verdict.
///
/// The parent (no `$child` in the environment) re-executes this test binary with `--exact` on
/// the current test thread's name and `$child=1`, kills the child if the parent unwinds, fails
/// when the child fails, times out, or never prints `$witness`, and returns from the calling
/// test. The child (the variable set) falls through and runs the test body.
///
/// `isolated!(CHILD, WITNESS)` is an actual-root case (90 s); `isolated!(CHILD, WITNESS,
/// witness = "usage")` is an actual-root witness named "usage" (60 s).
macro_rules! isolated {
    ($child:expr, $witness:expr) => {
        if std::env::var_os($child).is_none() {
            crate::distribution::rig::run_isolated(
                $child,
                $witness,
                crate::distribution::rig::Isolation {
                    thread: "the test runner names its exact test thread",
                    spawn: "start the isolated actual-root case",
                    timeout: std::time::Duration::from_secs(90),
                    failed: "the actual-root child failed",
                    timed_out: "the actual-root child timed out",
                },
            );
            return;
        }
    };
    ($child:expr, $witness:expr, witness = $noun:literal) => {
        if std::env::var_os($child).is_none() {
            crate::distribution::rig::run_isolated(
                $child,
                $witness,
                crate::distribution::rig::Isolation {
                    thread: "the test runner names its test thread",
                    spawn: "start the isolated actual-root test",
                    timeout: std::time::Duration::from_secs(60),
                    failed: concat!("the actual-root ", $noun, " witness failed"),
                    timed_out: concat!("the actual-root ", $noun, " witness timed out"),
                },
            );
            return;
        }
    };
}

/// The messages and deadline of one isolated re-run.
pub(super) struct Isolation {
    pub(super) thread: &'static str,
    pub(super) spawn: &'static str,
    pub(super) timeout: std::time::Duration,
    pub(super) failed: &'static str,
    pub(super) timed_out: &'static str,
}

/// The parent side of `isolated!`: run this exact test in a child and judge it.
pub(super) fn run_isolated(child_var: &str, witness: &str, isolation: Isolation) {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let name = std::thread::current()
        .name()
        .expect(isolation.thread)
        .to_string();
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env(child_var, "1")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect(isolation.spawn),
    );
    let until = std::time::Instant::now() + isolation.timeout;
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            use std::io::Read;
            let mut output = String::new();
            child
                .0
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut output)
                .unwrap();
            assert!(status.success(), "{}: {status}: {output}", isolation.failed);
            assert!(
                output.contains(witness),
                "the exact child did not complete its assertions: {output}"
            );
            return;
        }
        assert!(std::time::Instant::now() < until, "{}", isolation.timed_out);
        std::thread::park_timeout(std::time::Duration::from_millis(5));
    }
}
