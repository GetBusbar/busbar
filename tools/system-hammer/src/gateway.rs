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

/// A free loopback port (bound and released; the gateway binds it right after).
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(0)
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
                    gw.boot = started.elapsed();
                    return Ok(gw);
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
        // SAFETY: signalling our own child.
        unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGTERM) };
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
    #[allow(dead_code)] // kept for setup steps that save a header
    pub headers: Vec<(String, String)>,
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
        dechunk(rest)
    } else {
        rest.to_vec()
    };
    Ok(Resp {
        status,
        headers,
        body,
    })
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = b.windows(2).position(|w| w == b"\r\n") {
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&b[..nl])
                .split(';')
                .next()
                .unwrap_or("0")
                .trim(),
            16,
        )
        .unwrap_or(0);
        b = &b[nl + 2..];
        if size == 0 || b.len() < size {
            break;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[(size + 2).min(b.len())..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chunked_and_plain_responses() {
        let r = parse_response(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").unwrap();
        assert_eq!(r.status, 201);
        assert_eq!(r.body, b"abcde");
        let r = parse_response(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").unwrap();
        assert_eq!(r.text(), "ok");
    }
}
