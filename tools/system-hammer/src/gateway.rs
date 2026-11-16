// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Booting the real busbar binary under test, and the small blocking HTTP client the setup steps
//! (key minting, MCP/A2A connect, health) use.
//!
//! The shape is the upgrade harness's `Gateway::boot` (tests/upgrade): a work directory holding
//! `config.yaml`, `providers.yaml` and `signing.key`, the binary spawned with `BUSBAR_CONFIG` /
//! `BUSBAR_PROVIDERS` and an admin token in the environment, `/healthz` polled until it answers.
//! When that harness lands on dev, this module is the one to replace with it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Loopback ports for the gateway's listeners, held bound until it is about to bind them: all
/// reserved at once, so they are distinct, and no other `bind(0)` on the host is handed one
/// while they are held. Whatever takes a port after [`Ports::release`] is caught by
/// [`Gateway::boot`], which only accepts a `/healthz` answer from a listener its child owns.
pub struct Ports {
    held: Vec<TcpListener>,
    pub ports: Vec<u16>,
}

impl Ports {
    pub fn reserve(n: usize) -> Result<Ports, String> {
        let mut held = Vec::with_capacity(n);
        let mut ports = Vec::with_capacity(n);
        for _ in 0..n {
            let l = TcpListener::bind("127.0.0.1:0")
                .map_err(|e| format!("reserve a loopback port: {e}"))?;
            let a = l
                .local_addr()
                .map_err(|e| format!("reserve a loopback port: {e}"))?;
            ports.push(a.port());
            held.push(l);
        }
        Ok(Ports { held, ports })
    }

    /// Let the ports go, right before the gateway binds them.
    pub fn release(self) {
        drop(self.held);
    }
}

/// The binary's version line, e.g. `(1, 6, 0)`.
pub fn version(bin: &Path) -> Option<(u32, u32, u32)> {
    let out = Command::new(bin).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let first = text.lines().next()?;
    let v = first.split_whitespace().nth(1)?;
    let mut it = v.split(['.', '-']).map(|p| p.parse::<u32>().unwrap_or(0));
    Some((it.next()?, it.next().unwrap_or(0), it.next().unwrap_or(0)))
}

/// `--version` output in full (1.6.0 prints its build-provenance stamp on the second line).
pub fn version_text(bin: &Path) -> String {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// A fresh node signing key (`--generate-signing-key`, 64 hex characters).
pub fn signing_key(bin: &Path) -> Result<String, String> {
    let out = Command::new(bin)
        .arg("--generate-signing-key")
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("--generate-signing-key: {e}"))?;
    let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if key.len() != 64 {
        return Err(format!("--generate-signing-key printed {key:?}"));
    }
    Ok(key)
}

pub struct BootSpec<'a> {
    pub bin: &'a Path,
    pub work: PathBuf,
    pub config: String,
    pub providers: String,
    pub env: Vec<(String, String)>,
    pub listen: SocketAddr,
    pub admin: SocketAddr,
}

/// A running gateway.
pub struct Gateway {
    child: Child,
    pub pid: u32,
    pub listen: SocketAddr,
    pub admin: SocketAddr,
    pub work: PathBuf,
    /// Spawn to the first healthy `/healthz`.
    pub boot: Duration,
}

impl Gateway {
    pub fn boot(spec: BootSpec<'_>) -> Result<Gateway, String> {
        std::fs::create_dir_all(&spec.work).map_err(|e| e.to_string())?;
        std::fs::write(spec.work.join("config.yaml"), &spec.config).map_err(|e| e.to_string())?;
        std::fs::write(spec.work.join("providers.yaml"), &spec.providers)
            .map_err(|e| e.to_string())?;
        let log = std::fs::File::create(spec.work.join("busbar.log")).map_err(|e| e.to_string())?;
        let mut cmd = Command::new(spec.bin);
        cmd.current_dir(&spec.work)
            .env("BUSBAR_CONFIG", spec.work.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", spec.work.join("providers.yaml"))
            .env(
                "RUST_LOG",
                std::env::var("HAMMER_RUST_LOG").unwrap_or("warn".into()),
            )
            .stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log);
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        let started = Instant::now();
        let child = cmd
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", spec.bin.display()))?;
        let mut gw = Gateway {
            pid: child.id(),
            child,
            listen: spec.listen,
            admin: spec.admin,
            work: spec.work,
            boot: Duration::ZERO,
        };
        let deadline = started + Duration::from_secs(60);
        loop {
            if let Ok(Some(status)) = gw.child.try_wait() {
                return Err(format!(
                    "busbar exited during boot ({status}):\n{}",
                    gw.log_tail(40)
                ));
            }
            if let Ok(r) = call(gw.listen, "GET", "/healthz", &[], b"") {
                if r.status == 200 {
                    // Only the child's own listener counts: if another process holds the port
                    // (it was taken, or the child failed to bind it), every case would load
                    // that process instead.
                    let owned = crate::procstat::listens_on(gw.pid, gw.listen.port());
                    if owned == Ok(true) {
                        gw.boot = started.elapsed();
                        return Ok(gw);
                    }
                    gw.stop();
                    return Err(match owned {
                        Ok(_) => format!(
                            "{} answers /healthz, but busbar (pid {}) does not listen on it: \
                             the port is held by another process",
                            gw.listen, gw.pid
                        ),
                        Err(e) => format!("who listens on {}: {e}", gw.listen),
                    });
                }
            }
            if Instant::now() > deadline {
                let tail = gw.log_tail(40);
                gw.stop();
                return Err(format!("busbar not healthy after 60 s:\n{tail}"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn log_tail(&self, lines: usize) -> String {
        let text = std::fs::read_to_string(self.work.join("busbar.log")).unwrap_or_default();
        let all: Vec<&str> = text.lines().collect();
        all[all.len().saturating_sub(lines)..].join("\n")
    }

    /// SIGTERM, then SIGKILL after 10 s.
    pub fn stop(&mut self) {
        if !self.alive() {
            return;
        }
        if let Some(pid) = i32::try_from(self.pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if !self.alive() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A response of the setup client.
#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// One blocking HTTP/1.1 exchange on a fresh connection (setup only; never on the load path).
pub fn call(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Resp, String> {
    let mut s =
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\ncontent-length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    s.write_all(body).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<Resp, String> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no response head")?;
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("bad status line")?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let rest = &raw[end + 4..];
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        dechunk(rest)?
    } else {
        rest.to_vec()
    };
    Ok(Resp { status, body })
}

fn dechunk(mut b: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let nl = b
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("chunked body ended without terminator")?;
        let line = String::from_utf8_lossy(&b[..nl]);
        let hex = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16).map_err(|_| format!("bad chunk size {hex:?}"))?;
        b = &b[nl + 2..];
        if size == 0 {
            return Ok(out);
        }
        // `b.len() - size < 2` instead of `size + 2` so a huge declared size cannot overflow.
        if b.len() < size || b.len() - size < 2 || &b[size..size + 2] != b"\r\n" {
            return Err(format!("short chunk: want {size}, have {}", b.len()));
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Another process answering 200 on the port the gateway was told to bind (the port was
    /// stolen, or the child failed to bind it) is not the gateway being healthy: boot must not
    /// hand back a gateway whose load would land on someone else.
    #[test]
    fn boot_refuses_a_healthz_answer_from_a_process_that_is_not_the_child() {
        use std::os::unix::fs::PermissionsExt as _;
        let foreign = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = foreign.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in foreign.incoming() {
                let Ok(mut s) = s else { continue };
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                );
            }
        });
        let work = std::env::temp_dir().join(format!("hammer-boot-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        // A "gateway" that binds nothing and just stays up.
        let bin = work.join("not-busbar");
        std::fs::write(&bin, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let booted = Gateway::boot(BootSpec {
            bin: &bin,
            work: work.join("gw"),
            config: String::new(),
            providers: String::new(),
            env: Vec::new(),
            listen,
            admin: listen,
        });
        let refused = booted.is_err();
        drop(booted);
        let _ = std::fs::remove_dir_all(&work);
        assert!(
            refused,
            "boot took another process's /healthz answer as its child's"
        );
    }

    #[test]
    fn parses_chunked_and_plain_responses() {
        let r = parse_response(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").unwrap();
        assert_eq!(r.status, 201);
        assert_eq!(r.body, b"abcde");
        let r = parse_response(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").unwrap();
        assert_eq!(r.text(), "ok");
    }

    #[test]
    fn malformed_chunked_bodies_are_errors() {
        let h = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        for body in [&b"zz\r\nabc\r\n0\r\n\r\n"[..], b"5\r\nab", b"3\r\nabc\r\n"] {
            assert!(
                parse_response(&[&h[..], body].concat()).is_err(),
                "{body:?}"
            );
        }
    }

    #[test]
    fn reserved_ports_report_errors_and_are_distinct_and_never_zero() {
        let p: Result<Ports, String> = Ports::reserve(4);
        let p = p.expect("loopback ports");
        let mut seen = p.ports.clone();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 4);
        assert!(p.ports.iter().all(|&port| port != 0));
    }
}
