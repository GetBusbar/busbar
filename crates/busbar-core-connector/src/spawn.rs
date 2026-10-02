// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SPAWN CARRIER: a program destination (`abi::transport::DEST_PROGRAM`, "a program the carrier
//! runs") dialled as a child process whose standard input and output are the connection's byte
//! stream, for the stdio framer above it. The connector owns the carrier (THE DESIGN, §5 and §8), so
//! the child is spawned here, under 1.5.5's carrier rules exactly:
//!
//! * an ABSOLUTE path only (`/...`): a bare name would be resolved through a search path the
//!   deployment did not write down ([`Refusal::NotAbsolute`]);
//! * no shell: the program and its arguments go to the OS as a vector, never a command string;
//! * the environment CLEARED, then set to exactly what the destination declared, so a child
//!   inherits nothing the deployment did not write down;
//! * the child's standard error is the host's own (inherited), as 1.5.5's was: its diagnostics are
//!   the operator's, never swallowed and never read as frames;
//! * the child is KILLED when its connection is dropped.
//!
//! The pipes' readiness is the spawning worker's reactor's, like every host socket ([`crate::io`]):
//! a spawn off a worker is refused ([`Refusal::NotOnAWorker`]) rather than handed a reactor thread
//! to hide behind, and no read or write blocks.

use std::io;
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead as _, AsyncWrite as _, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// Why a program destination was not spawned.
#[derive(Debug)]
pub enum Refusal {
    /// The program is not an absolute path.
    NotAbsolute,
    /// The spawn ran off a worker, with no reactor to register the pipes on.
    NotOnAWorker,
    /// The OS refused the spawn (no such program, not executable, out of processes).
    Spawn(io::Error),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAbsolute => f.write_str("refused: a program destination is an absolute path"),
            Self::NotOnAWorker => f.write_str(crate::io::NOT_ON_A_WORKER),
            Self::Spawn(e) => write!(f, "refused: the program did not start: {e}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// A spawned child as a byte stream: its standard output read, its standard input written. The
/// child is killed when this is dropped.
#[derive(Debug)]
pub struct Spawned {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
}

/// Spawn `program` with exactly `args`, under exactly `env`, on the calling worker's reactor.
///
/// # Errors
///
/// [`Refusal::NotAbsolute`] before anything runs; [`Refusal::NotOnAWorker`] off a worker;
/// [`Refusal::Spawn`] when the OS refuses.
pub fn spawn(program: &str, args: &[&str], env: &[(&str, &str)]) -> Result<Spawned, Refusal> {
    if !program.starts_with('/') {
        return Err(Refusal::NotAbsolute);
    }
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(Refusal::NotOnAWorker);
    }
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(Refusal::Spawn)?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(Refusal::Spawn(io::Error::other(
            "the child's pipes were not opened",
        )));
    };
    Ok(Spawned {
        child,
        stdin: Some(stdin),
        stdout,
    })
}

impl Spawned {
    /// The child's process id, while it runs.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }
}

impl futures::io::AsyncRead for Spawned {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut read = ReadBuf::new(buf);
        std::task::ready!(Pin::new(&mut self.stdout).poll_read(cx, &mut read))?;
        Poll::Ready(Ok(read.filled().len()))
    }
}

impl futures::io::AsyncWrite for Spawned {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.stdin.as_mut() {
            Some(w) => Pin::new(w).poll_write(cx, buf),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.stdin.as_mut() {
            Some(w) => Pin::new(w).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    /// The write half's end: the child's standard input is closed, so it reads its end of input.
    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stdin = None;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[path = "tests/spawn_tests.rs"]
mod tests;
