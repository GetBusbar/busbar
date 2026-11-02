// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

pub fn exe() -> &'static str {
    static WARM: OnceLock<String> = OnceLock::new();
    WARM.get_or_init(|| {
        let path = option_env!("CARGO_BIN_EXE_busbar")
            .map(str::to_owned)
            .unwrap_or_else(|| {
                let test = std::env::current_exe().expect("current test executable");
                let profile = test
                    .parent()
                    .and_then(Path::parent)
                    .expect("the test executable's profile directory");
                let binary = profile.join(format!("busbar{}", std::env::consts::EXE_SUFFIX));
                assert!(
                    binary.is_file(),
                    "build the actual product binary: {}",
                    binary.display()
                );
                binary
                    .to_str()
                    .expect("the product binary path is UTF-8")
                    .to_owned()
            });
        let out = Command::new(&path)
            .arg("--version")
            .output()
            .expect("exec the busbar binary under test");
        assert!(
            out.status.success(),
            "`busbar --version` failed before any boot clock started: {:?}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        path
    })
}

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

fn held_ephemeral_port() -> (socket2::Socket, u16) {
    use socket2::{Domain, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).expect("a stream socket");
    socket.set_reuse_address(true).expect("SO_REUSEADDR");
    #[cfg(unix)]
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

pub struct Reap(pub std::process::Child);

impl std::ops::Deref for Reap {
    type Target = std::process::Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Reap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn log_shows_data_and_admin_listening(log: &str) -> bool {
    log.matches("busbar listening").count() >= 2
}

pub fn healthz_answers(port: u16) -> bool {
    use std::io::{Read, Write};
    let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    if s.write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf.lines().next().and_then(|l| l.split_whitespace().nth(1)) == Some("200")
}

pub struct DumpOnPanic<'a>(pub &'a Path);

impl Drop for DumpOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "--- the node's log ({}):\n{}",
                self.0.display(),
                std::fs::read_to_string(self.0).unwrap_or_default()
            );
        }
    }
}
