// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BINARY A BOOT CLOCK TIMES — the shipped `busbar` under test, already exec'd once.
//!
//! A boot deadline measures how long BUSBAR takes to come up: parse its config, seal its
//! composition, bind its listeners. It does not measure how long the operating system takes to
//! page in and admit a freshly linked binary on its first exec (on macOS the first exec of a new
//! ~170MB debug image was measured at 8.4s on its own, then 0.03s on every later exec), and on a
//! loaded machine that one-time cost alone pushed a 30s boot deadline over while busbar itself had
//! not yet started. So the path every boot-deadline test spawns comes from [`exe`], which runs
//! `busbar --version` to completion once per test process before handing the path out: the
//! first-exec cost is paid before any clock starts, and the deadline keeps its value.

use std::process::Command;
use std::sync::OnceLock;

/// The path of the shipped binary under test, exec'd once (`--version`) before it is returned, so
/// a boot deadline started after this call times busbar's boot and not the binary's first exec.
pub fn exe() -> &'static str {
    static WARM: OnceLock<()> = OnceLock::new();
    let path = env!("CARGO_BIN_EXE_busbar");
    WARM.get_or_init(|| {
        let out = Command::new(path)
            .arg("--version")
            .output()
            .expect("exec the busbar binary under test");
        assert!(
            out.status.success(),
            "`busbar --version` failed before any boot clock started: {:?}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    });
    path
}

/// A LOOPBACK PORT THIS PROCESS OWNS FROM THE MOMENT IT IS CHOSEN, for the child busbar to listen on.
///
/// A port picked by binding `:0` and DROPPING the socket is not owned by anyone until the child
/// binds it, and the child is a process spawn and a boot away. In that window any socket on the
/// machine may take the number: an outbound connection's ephemeral source port, a TIME_WAIT left by
/// one, any listener bound to `:0` next — the test's own loopback upstream among them (the kernel
/// handed a just-dropped number straight back to it). The child then refuses to boot (BUSBAR-9007,
/// `cannot bind ... Address already in use`) with nothing of the test's wrong.
/// Busbar cannot be told to bind `:0` and report the port back (its listen line logs the CONFIGURED
/// address, 1.5.5's line, and each data worker binds the address itself), and it takes no inherited
/// listener. So the port is never released instead: the socket that chose it stays BOUND, never
/// listening, for this process's lifetime, with `SO_REUSEADDR` and `SO_REUSEPORT` — the options every
/// root listener binds with (`busbar_core_connector::socket::listen`). The child's listeners bind
/// beside it; nothing else can: an ephemeral bind or an outbound connection is never handed a port
/// a socket is bound to. Never listening, it takes no connection and a connect before the child
/// listens is refused as it was.
///
/// That holds on Linux, where every test run that gates this tree runs. On other unixes a bound,
/// non-listening socket swallows a SYN instead of refusing it (a poll that connects before the child
/// listens would hang for the OS connect timeout), so there the socket is dropped as before.
///
/// Each number is also claimed by an exclusive lock on a per-port file shared by every test process
/// on the machine, held until this process exits, and a claimed number is skipped: where the socket
/// is not kept, that claim is what stops two busbars from being handed one number (the data door's
/// `SO_REUSEPORT` would let both listen and split the connections between them).
pub fn free_port() -> u16 {
    static HELD: std::sync::Mutex<Vec<(std::fs::File, Option<socket2::Socket>)>> =
        std::sync::Mutex::new(Vec::new());
    for _ in 0..512 {
        let (socket, port) = held_ephemeral_port();
        if let Some(lock) = try_reserve(port) {
            let socket = cfg!(target_os = "linux").then_some(socket);
            HELD.lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((lock, socket));
            return port;
        }
    }
    panic!("no loopback port could be reserved in 512 tries");
}

/// A loopback socket bound to an ephemeral port as a root listener binds (`SO_REUSEADDR` and
/// `SO_REUSEPORT`), never listening, and the port the kernel chose for it.
fn held_ephemeral_port() -> (socket2::Socket, u16) {
    use socket2::{Domain, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).expect("a TCP socket");
    socket.set_reuse_address(true).expect("SO_REUSEADDR");
    socket.set_reuse_port(true).expect("SO_REUSEPORT");
    socket
        .bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .expect("bind an ephemeral loopback port");
    let port = socket
        .local_addr()
        .ok()
        .and_then(|a| a.as_socket())
        .expect("the bound address")
        .port();
    (socket, port)
}

/// The exclusive, cross-process claim on `port`, or `None` when another holder has it.
pub fn try_reserve(port: u16) -> Option<std::fs::File> {
    let dir = std::env::temp_dir().join("busbar-test-ports");
    std::fs::create_dir_all(&dir).expect("the port-claim directory");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(format!("{port}.lock")))
        .expect("the port-claim file");
    file.try_lock().ok().map(|()| file)
}
