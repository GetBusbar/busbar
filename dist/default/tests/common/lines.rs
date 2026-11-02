// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct LineChild {
    pub child: super::boot::Reap,
    pub stdin: Option<std::process::ChildStdin>,
    pub stdout: mpsc::Receiver<String>,
    pub stderr: mpsc::Receiver<String>,
}

pub fn spawn(mut cmd: Command) -> LineChild {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = super::boot::Reap(cmd.spawn().expect("spawn the line-served child"));
    let stdin = child.stdin.take();
    let (out_tx, out_rx) = mpsc::channel();
    let stdout = child.stdout.take().expect("stdout piped");
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = out_tx.send(line);
        }
    });
    let (err_tx, err_rx) = mpsc::channel();
    let stderr = child.stderr.take().expect("stderr piped");
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = err_tx.send(line);
        }
    });
    LineChild {
        child,
        stdin,
        stdout: out_rx,
        stderr: err_rx,
    }
}

impl LineChild {
    pub fn send(&mut self, value: &serde_json::Value) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        let mut bytes = serde_json::to_vec(value).expect("the line serializes");
        bytes.push(b'\n');
        stdin.write_all(&bytes).expect("write a line");
        stdin.flush().expect("flush a line");
    }

    pub fn recv(&self) -> serde_json::Value {
        let line = self
            .stdout
            .recv_timeout(Duration::from_secs(120))
            .expect("the child must answer within the bound");
        serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!("every stdout line must be one JSON message ({e}): {line:?}")
        })
    }

    pub fn try_recv(&self, bound: Duration) -> Result<serde_json::Value, String> {
        let line = self
            .stdout
            .recv_timeout(bound)
            .map_err(|_| format!("the child did not answer within {bound:?}"))?;
        serde_json::from_str(&line)
            .map_err(|e| format!("every stdout line must be one JSON message ({e}): {line:?}"))
    }

    pub fn eof_and_wait(mut self, bound: Duration) -> i32 {
        drop(self.stdin.take());
        wait_bounded(&mut self.child, bound)
    }

    pub fn stderr_so_far(&self) -> String {
        let mut all = String::new();
        while let Ok(line) = self.stderr.recv_timeout(Duration::from_millis(300)) {
            all.push_str(&line);
            all.push('\n');
        }
        all
    }
}

pub fn wait_bounded(child: &mut Child, bound: Duration) -> i32 {
    try_wait_bounded(child, bound).unwrap_or_else(|e| panic!("{e}"))
}

pub fn try_wait_bounded(child: &mut Child, bound: Duration) -> Result<i32, String> {
    let deadline = Instant::now() + bound;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("cannot wait on the child: {e}"))?
        {
            return Ok(status.code().unwrap_or(-1));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("the child did not exit within {bound:?}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
#[test]
fn line_child_is_stopped_and_reaped_when_the_caller_unwinds() {
    let pid = std::cell::Cell::new(0);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut command = Command::new("sh");
        command.args(["-c", "exec sleep 60"]);
        let child = spawn(command);
        pid.set(child.child.id());
        panic!("induced caller failure while the line child is live");
    }));
    assert!(unwind.is_err());
    assert_ne!(pid.get(), 0, "the real child was spawned");
    let still_exists = Command::new("kill")
        .args(["-0", &pid.get().to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("probe whether the owned child still exists")
        .success();
    assert!(
        !still_exists,
        "the line child survived or remained a zombie"
    );
}
