// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINE-SERVED CHILD the black-box suites drive: the real binary spawned as somebody's child
//! process, its stdin written line by line and its stdout read line by line, every stdout line
//! required to be ONE JSON message (the line carrier writes nothing else), and EOF on stdin its
//! shutdown. Moved here from the suite that first wrote it.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The child, its pipes, and a line-reader thread per output stream.
pub struct LineChild {
    pub child: Child,
    pub stdin: Option<std::process::ChildStdin>,
    pub stdout: mpsc::Receiver<String>,
    pub stderr: mpsc::Receiver<String>,
}

/// Spawn `cmd` with all three pipes, a reader thread on each output.
pub fn spawn(mut cmd: Command) -> LineChild {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn the line-served child");
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
    /// Write `value` as one line.
    pub fn send(&mut self, value: &serde_json::Value) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        let mut bytes = serde_json::to_vec(value).expect("the line serializes");
        bytes.push(b'\n');
        stdin.write_all(&bytes).expect("write a line");
        stdin.flush().expect("flush a line");
    }

    /// The next stdout line, which MUST be one JSON message. A hang detector, not a latency
    /// assertion: a debug child on a saturated host can take most of a minute to answer.
    pub fn recv(&self) -> serde_json::Value {
        let line = self
            .stdout
            .recv_timeout(Duration::from_secs(120))
            .expect("the child must answer within the bound");
        serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!("every stdout line must be one JSON message ({e}): {line:?}")
        })
    }

    /// [`LineChild::recv`] within `bound`, its failure a sentence rather than a panic.
    pub fn try_recv(&self, bound: Duration) -> Result<serde_json::Value, String> {
        let line = self
            .stdout
            .recv_timeout(bound)
            .map_err(|_| format!("the child did not answer within {bound:?}"))?;
        serde_json::from_str(&line)
            .map_err(|e| format!("every stdout line must be one JSON message ({e}): {line:?}"))
    }

    /// EOF on stdin, then the exit code — bounded, so a child that ignores EOF fails the caller.
    pub fn eof_and_wait(mut self, bound: Duration) -> i32 {
        drop(self.stdin.take());
        wait_bounded(&mut self.child, bound)
    }

    /// Everything stderr has said so far, drained with a short grace per line.
    pub fn stderr_so_far(&self) -> String {
        let mut all = String::new();
        while let Ok(line) = self.stderr.recv_timeout(Duration::from_millis(300)) {
            all.push_str(&line);
            all.push('\n');
        }
        all
    }
}

/// The child's exit code within `bound`; a child still running then is killed and the caller fails.
pub fn wait_bounded(child: &mut Child, bound: Duration) -> i32 {
    try_wait_bounded(child, bound).unwrap_or_else(|e| panic!("{e}"))
}

/// [`wait_bounded`], its failure a sentence rather than a panic.
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
