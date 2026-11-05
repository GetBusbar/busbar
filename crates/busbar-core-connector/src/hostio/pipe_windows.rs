// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Inherited, synchronous child handles with native overlapped host ends. Unlike Tokio's
//! Windows `ChildStdin`/`ChildStdout`, these do not consume blocking-pool threads while idle.

use std::fs::OpenOptions;
use std::io;
use std::process::Stdio;

use futures::FutureExt;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

/// The two child handles and the host's independently closeable write/read ends.
pub(super) fn pipe_ends() -> io::Result<(Stdio, NamedPipeServer, NamedPipeServer, Stdio)> {
    let (host_writes, child_reads) = pipe(false)?;
    let (host_reads, child_writes) = pipe(true)?;
    Ok((child_reads, host_writes, host_reads, child_writes))
}

fn pipe(host_reads: bool) -> io::Result<(NamedPipeServer, Stdio)> {
    // An unguessable capability name and FIRST_PIPE_INSTANCE prevent another process from
    // pre-creating our pipe. Only local clients are admitted, and the child gets the already
    // connected handle rather than the name. No pipe name or handle escapes into its env.
    let mut nonce = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| io::Error::other("could not generate a child pipe name"))?;
    let name = format!(
        r"\\.\pipe\busbar-child-{}",
        nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .access_inbound(host_reads)
        .access_outbound(!host_reads)
        .create(&name)?;
    let child = OpenOptions::new()
        .read(!host_reads)
        .write(host_reads)
        .open(&name)?;
    // Opening the client above synchronously established the connection. ConnectNamedPipe
    // now reports ERROR_PIPE_CONNECTED; Tokio/Mio uses that to arm overlapped reads/writes.
    // Never block a worker if that invariant is broken.
    server
        .connect()
        .now_or_never()
        .ok_or_else(|| io::Error::other("the local child pipe did not connect immediately"))??;
    Ok((server, child.into()))
}
