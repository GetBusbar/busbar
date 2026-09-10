// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BROWSER SIDEBAND SERVES A SESSION — driven against the SHIPPED BINARY over a real socket.
//!
//! The subject is a SESSION: an upgrade, a first server event, a client event, a terminal, a close.
//! Every one of those is a byte a browser sees, and each of the three doors between a configured
//! plane and a served byte sits on a different side of a seam an in-process fixture would stand in
//! for. A harness driving the composition in-process answers "does the composition hold together";
//! it cannot answer "did the shipped door put a byte on the wire", which is the question that was
//! open. The measurement behind these two cells is `VT7-design-served-session.md`; what is repeated
//! here is only what a reader needs to know why each assertion is where it is.
//!
//! THE THREE DOORS. (1) A deployment that declares nothing here mounts nothing here, so every one of
//! these URLs is a path that does not exist — which is what `admission_runs_before_route_lookup`
//! stands behind, and the one ordering 1.5.5 pins for every plane. (A deployment that DOES declare the
//! section and gives it no `public_url` no longer reaches this cell's shape at all: it refuses to boot,
//! because a declared region with no audience is a door with no lock.) (2) With one, the plane claims its region and the verifier demands a token carrying that
//! RFC 8707 audience. Nothing in a shipped build could mint one, so this file used to sign the
//! claim by hand against the deployment's own key to get past a door that was hiding the next one;
//! the mint verb now takes the `resource` indicator and the rig asks for the credential the way an
//! operator does. (3) The socket upgrades, and what it does after that is
//! `sideband_serves_a_session`.
//!
//! GATED ON `plane-voice` as a whole file: a build with the streams plane compiled out has no
//! realtime surface to serve or to refuse, and the deletion gate builds exactly that binary.
#![cfg(feature = "plane-voice")]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The RFC6455 §1.3 sample key, and the `Sec-WebSocket-Accept` a 101 must carry for it. FIXED, not
/// random: the handshake is then a pure function of the request, so the accept header is a recorded
/// byte rather than a nonce this test would have to recompute to check.
const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const WS_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// The call the sideband is opened for. Fixed, never a clock or a uuid: the `{call_id}` capture is
/// part of the URL under test and a moving one would make the request unreproducible.
const CALL_ID: &str = "c-vt7-0001";

/// The admin token the rig mints keys with. Only ever presented on the admin listener.
const ADMIN_TOKEN: &str = "vt7-streams-admin-token";

/// The group every minted key is bound to — a real group, because a key naming none is refused.
const GROUP: &str = "vt7";

// ── the rig ──────────────────────────────────────────────────────────────────────────────────────

/// A free loopback port, asked of the OS. A hard-coded port is a red that is not a defect the first
/// time this machine happens to have something on it.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-streams-served-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A booted busbar with a `streams:` section, killed and cleaned up on drop.
struct Node {
    dir: PathBuf,
    child: Child,
    data: u16,
    admin: u16,
    /// `Some(origin)` when this node was booted with a `public_url` (and therefore mounts the plane).
    public_url: Option<String>,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Node {
    /// Boot a node whose config carries a `streams:` section the grammar accepts, with or without the
    /// top-level `public_url` the plane's dispatch slot is built from.
    fn spawn(tag: &str, with_public_url: bool, with_streams: bool) -> Node {
        let dir = fixture_dir(tag);
        let (data, admin) = (free_port(), free_port());
        let bin = env!("CARGO_BIN_EXE_busbar");

        let key = Command::new(bin)
            .arg("--generate-signing-key")
            .output()
            .expect("generate a signing key");
        let hex_key = String::from_utf8_lossy(&key.stdout).trim().to_string();
        assert_eq!(
            hex_key.len(),
            64,
            "--generate-signing-key must print 64 hex characters on stdout, got {hex_key:?}"
        );
        std::fs::write(dir.join("signing.key"), &hex_key).unwrap();
        std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();

        let public_url = with_public_url.then(|| format!("http://127.0.0.1:{data}"));
        let public_line = match &public_url {
            Some(u) => format!("public_url: \"{u}\"\n"),
            None => String::new(),
        };
        // The section is what DECLARES this plane, and a declaration with no receiving origin to bind
        // an audience from refuses the boot. So the two are written independently: a node that
        // declares and is addressable serves, and a node that declares nothing mounts nothing — which
        // is the shape the ordering cell needs and the only other one that boots.
        let streams_block = if with_streams {
            "streams:\n  session:\n    voice: marin\n"
        } else {
            ""
        };
        std::fs::write(
            dir.join("config.yaml"),
            format!(
                r#"listen: "127.0.0.1:{data}"
admin_listen: "127.0.0.1:{admin}"
admin_require_mtls: false
{public_line}identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain:
    - keys
  signing_key: {{ file: "{key_file}" }}
  admin_auth: [admin-tokens]
groups:
  {GROUP}:
    limits:
      - {{ budget: 1000000, per: day }}
providers: {{}}
models: {{}}
pools: {{}}
{streams_block}"#,
                key_file = dir.join("signing.key").display(),
            ),
        )
        .unwrap();

        let log = std::fs::File::create(dir.join("out.log")).unwrap();
        let child = Command::new(bin)
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn busbar");

        Node {
            dir,
            child,
            data,
            admin,
            public_url,
        }
    }

    /// Spawn a node and WAIT FOR IT TO ANSWER — the ordinary case, and the one that panics if the
    /// process ends instead.
    fn boot(tag: &str, with_public_url: bool, with_streams: bool) -> Node {
        let mut node = Node::spawn(tag, with_public_url, with_streams);
        // READY means ANSWERING on the data listener. `/healthz` reports 503 on a node with no
        // models — which this node deliberately has none of — so readiness is "the listener produced
        // a status line", not "the status line was 200".
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(status) = node.child.try_wait().expect("try_wait") {
                panic!(
                    "busbar exited ({status}) instead of listening; log:\n{}",
                    node.log()
                );
            }
            if http(node.data, "GET", "/healthz", None, None).status != 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "busbar did not answer on 127.0.0.1:{}; log:\n{}",
                node.data,
                node.log()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        node
    }

    /// Spawn the ONE declared shape that must never reach a listener — a section written here with no
    /// receiving origin — and wait for the process to END. Returns the node so the caller reads the
    /// log the refusal was written to. Panics if it is still running at the deadline, because a node
    /// that serves this shape is the defect, not a slow start.
    fn refused(tag: &str) -> Node {
        let mut node = Node::spawn(tag, false, true);
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            match node.child.try_wait().expect("try_wait") {
                Some(status) => {
                    assert!(
                        !status.success(),
                        "the process ended with success on a config it must refuse; log:\n{}",
                        node.log()
                    );
                    return node;
                }
                None => assert!(
                    Instant::now() < deadline,
                    "the process is still running on a config it must refuse; log:\n{}",
                    node.log()
                ),
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("out.log")).unwrap_or_default()
    }

    /// Mint a virtual key through the admin API. `pools: None` is the store's WILDCARD (every scope
    /// kind granted, so the plane's own `session` scope is held); `Some(&[])` is the EMPTY set — a
    /// key that carries a scope list with this plane's scope not in it.
    fn mint(&self, name: &str, pools: Option<&[&str]>) -> String {
        let body = match pools {
            None => format!(r#"{{"name":"{name}","group":"{GROUP}"}}"#),
            Some(list) => format!(
                r#"{{"name":"{name}","group":"{GROUP}","allowed_pools":[{}]}}"#,
                list.iter()
                    .map(|p| format!("\"{p}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        };
        let r = http(
            self.admin,
            "POST",
            "/api/v1/admin/keys",
            Some(ADMIN_TOKEN),
            Some(&body),
        );
        assert_eq!(
            r.status, 201,
            "minting `{name}` failed: {} {}",
            r.status, r.body
        );
        let v: serde_json::Value = serde_json::from_str(&r.body).expect("a key response");
        v["token"]
            .as_str()
            .expect("a minted key carries its token once")
            .to_string()
    }

    /// THE RFC 8707 RESOURCE this deployment's streams plane claims: its own origin plus the base
    /// the plane answers on. Derived from the node's `public_url` because that is what the plane
    /// derives it from; a rig that typed a literal here would pass while the two drifted apart.
    fn audience(&self) -> String {
        format!(
            "{}/v1/realtime",
            self.public_url
                .as_ref()
                .expect("an audience is derived from the public_url a mounted plane was given")
        )
    }

    /// MINT A KEY BOUND TO A RESOURCE, through the SHIPPED ADMIN SURFACE — the RFC 8707 `resource`
    /// indicator on the one mint verb, and the whole of what an operator does to get a credential
    /// for a plane door.
    ///
    /// This rig used to reach behind the admin API and sign the `aud` claim itself against the
    /// deployment's own key, because the only constructor of that claim in the tree was test-only
    /// and the mint endpoint had no field for it. A rig that mints its own credentials proves the
    /// verifier accepts a token it likes the shape of; it cannot prove an OPERATOR can obtain one.
    /// The hand mint is deleted and what is driven here is the door an operator actually has.
    ///
    /// Returns the whole answer, not just the token: the refusal cell reads the same one.
    fn mint_for(&self, name: &str, resource: &str) -> Answer {
        http(
            self.admin,
            "POST",
            "/api/v1/admin/keys",
            Some(ADMIN_TOKEN),
            Some(&format!(
                r#"{{"name":"{name}","group":"{GROUP}","resource":"{resource}"}}"#
            )),
        )
    }
}

// ── raw HTTP, hand-rolled ────────────────────────────────────────────────────────────────────────
//
// Hand-rolled for the same reason `ledger_identity.rs` hand-rolls its own: the test is about the
// bytes a shipped process produced, and a client that retries, redirects or re-encodes on the way is
// a client that can hide the thing being asserted.

struct Answer {
    status: u16,
    body: String,
}

fn http(port: u16, method: &str, path: &str, bearer: Option<&str>, body: Option<&str>) -> Answer {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return Answer {
            status: 0,
            body: String::new(),
        };
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(120)));
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if let Some(t) = bearer {
        head.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    if let Some(b) = body {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    head.push_str("\r\n");
    if let Some(b) = body {
        head.push_str(b);
    }
    if s.write_all(head.as_bytes()).is_err() {
        return Answer {
            status: 0,
            body: String::new(),
        };
    }
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    Answer {
        status,
        body: body.to_string(),
    }
}

// ── the WebSocket client, hand-rolled ────────────────────────────────────────────────────────────

/// An open (or refused) sideband socket: the status line + headers, and the live stream when a 101
/// came back.
struct Socket {
    status: u16,
    head: String,
    stream: Option<TcpStream>,
    /// Bytes read past the header terminator while reading the handshake — the first frames, when a
    /// fast server wrote them in the same segment.
    carry: Vec<u8>,
}

fn upgrade(port: u16, path: &str, bearer: Option<&str>) -> Socket {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
    let mut head = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: {WS_KEY}\r\nSec-WebSocket-Version: 13\r\n"
    );
    if let Some(t) = bearer {
        head.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).expect("write handshake");

    let mut raw: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    // Read exactly to the header terminator, one byte at a time: anything more would consume the
    // first frame's bytes into a buffer the frame reader below never sees.
    while !raw.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => raw.push(byte[0]),
        }
        if raw.len() > 64 * 1024 {
            break;
        }
    }
    let head = String::from_utf8_lossy(&raw).to_string();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let stream = (status == 101).then_some(s);
    Socket {
        status,
        head,
        stream,
        carry: Vec::new(),
    }
}

impl Socket {
    /// Write one masked text frame — the client half of RFC6455 §5.3, which a client MUST mask.
    fn send_text(&mut self, text: &str) {
        let s = self.stream.as_mut().expect("an open socket");
        let payload = text.as_bytes();
        let mut frame = vec![0x81u8];
        // A deterministic mask, not a random one: masking is not a security property on loopback and
        // a fixed key keeps the request bytes reproducible.
        let mask = [0x37u8, 0xfa, 0x21, 0x3d];
        let n = payload.len();
        if n < 126 {
            frame.push(0x80 | n as u8);
        } else {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        s.write_all(&frame).expect("write frame");
    }

    /// Read whatever frames arrive within `budget`, returning the TEXT payloads in order. A read
    /// timeout is not a failure here: "nothing arrived" is exactly the observation the red half of
    /// this file is about, so it must be reportable rather than a panic.
    fn read_text(&mut self, budget: Duration) -> Vec<String> {
        let s = self.stream.as_mut().expect("an open socket");
        let _ = s.set_read_timeout(Some(budget));
        let mut buf = std::mem::take(&mut self.carry);
        let deadline = Instant::now() + budget;
        let mut out = Vec::new();
        loop {
            out.extend(drain_frames(&mut buf));
            if !out.is_empty() || Instant::now() >= deadline {
                break;
            }
            let mut chunk = [0u8; 8192];
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        self.carry = buf;
        out
    }

    /// The client's close frame, and the answer to it.
    fn close(&mut self) {
        if let Some(s) = self.stream.as_mut() {
            // A masked, empty close frame (opcode 8).
            let _ = s.write_all(&[0x88, 0x80, 0x37, 0xfa, 0x21, 0x3d]);
            let _ = s.shutdown(std::net::Shutdown::Write);
        }
    }
}

/// Parse whole SERVER frames out of `buf` (server frames are never masked), consuming what it reads
/// and leaving a partial frame behind for the next read.
fn drain_frames(buf: &mut Vec<u8>) -> Vec<String> {
    let mut out = Vec::new();
    let mut cut = 0usize;
    loop {
        let rest = &buf[cut..];
        if rest.len() < 2 {
            break;
        }
        let opcode = rest[0] & 0x0f;
        let masked = rest[1] & 0x80 != 0;
        let mut len = (rest[1] & 0x7f) as usize;
        let mut at = 2;
        if len == 126 {
            if rest.len() < 4 {
                break;
            }
            len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
            at = 4;
        } else if len == 127 {
            if rest.len() < 10 {
                break;
            }
            len = u64::from_be_bytes(rest[2..10].try_into().unwrap()) as usize;
            at = 10;
        }
        if masked {
            at += 4;
        }
        if rest.len() < at + len {
            break;
        }
        // TEXT (1) **and BINARY (2)**. The GA Realtime wire is JSON in TEXT frames, and this node
        // writes every outbound frame as BINARY — the neutral duplex acceptor's one send site frames
        // `Vec<u8>` as `Message::Binary`, so a browser's `WebSocket` hands the page a `Blob` where
        // the dialect says it should hand it a string. That is a real fidelity gap and it is
        // recorded as one; it is NOT this file's subject, and a reader that refused the frame would
        // report "the session served nothing" for a session that served everything. So both opcodes
        // are read, and the gap is named in the commit rather than hidden behind a red.
        if opcode == 1 || opcode == 2 {
            out.push(String::from_utf8_lossy(&rest[at..at + len]).to_string());
        }
        cut += at + len;
    }
    buf.drain(..cut);
    out
}

/// The `type` of a GA Realtime event, or the whole frame when it does not carry one.
fn event_type(frame: &str) -> String {
    serde_json::from_str::<serde_json::Value>(frame)
        .ok()
        .and_then(|v| v["type"].as_str().map(str::to_string))
        .unwrap_or_else(|| format!("<not a typed GA event: {frame}>"))
}

// ── the cells ────────────────────────────────────────────────────────────────────────────────────

/// THE SIDEBAND SERVES A SESSION: upgrade, a first `session.created`, a `response.create`, a
/// terminal, a close.
///
/// This is the whole claim of the streams plane reduced to the one leg that dials nobody — the
/// browser sideband, whose media is peer-to-peer and whose socket carries only the OpenAI Realtime
/// GA control vocabulary. There is no upstream to relay a first frame from and no provider composed,
/// so every byte the client sees is one this node authored: if the plane serves nothing of its own,
/// this socket is silent, and a silent socket is what "11,609 lines that do not serve a byte" means
/// in bytes rather than in prose.
#[test]
fn sideband_serves_a_session() {
    let node = Node::boot("serves", true, true);
    // THE MINTED KEY, not a hand-signed one: `resource` names the audience the plane declares, and
    // what opens the door below is the token the shipped admin verb handed back.
    let minted = node.mint_for("vt7-session", &node.audience());
    assert_eq!(
        minted.status, 201,
        "the admin mint must issue a key bound to a resource this deployment serves; got {} {}\nlog:\n{}",
        minted.status,
        minted.body,
        node.log()
    );
    let token = serde_json::from_str::<serde_json::Value>(&minted.body).expect("a key response")
        ["token"]
        .as_str()
        .expect("a minted key carries its token once")
        .to_string();

    let mut sock = upgrade(
        node.data,
        &format!("/v1/realtime/sideband/{CALL_ID}"),
        Some(&token),
    );
    assert_eq!(
        sock.status,
        101,
        "the sideband mount must complete the upgrade for a key holding this plane's session scope \
         on a token bound to this plane's audience; got:\n{}\nlog:\n{}",
        sock.head,
        node.log()
    );
    assert!(
        sock.head.contains(WS_ACCEPT),
        "a 101 must carry the RFC6455 accept for the fixed client key; got:\n{}",
        sock.head
    );

    // (1) THE FIRST SERVER EVENT. GA opens with `session.created` carrying the resolved session
    // object, and a client that never receives one has no session to update or respond in.
    let first = sock.read_text(Duration::from_secs(10));
    assert!(
        !first.is_empty(),
        "the upgraded sideband socket sent NOTHING: an admitted session that puts no byte on the \
         wire is a socket, not a session. log:\n{}",
        node.log()
    );
    assert_eq!(
        event_type(&first[0]),
        "session.created",
        "the first server event on a GA Realtime socket is `session.created`; got {:?}",
        first
    );

    // (2) A CLIENT EVENT REACHES A TERMINAL. `response.create` is the one client event that must be
    // answered: with no provider composed there is no response to generate, and the GA terminal for
    // that is an `error` event. Silence is the one answer a client cannot act on.
    sock.send_text(r#"{"type":"response.create"}"#);
    let answered = sock.read_text(Duration::from_secs(10));
    assert!(
        !answered.is_empty(),
        "`response.create` was answered with silence; a client that asked for a response and was \
         told nothing waits forever. log:\n{}",
        node.log()
    );
    let terminal = event_type(&answered[0]);
    assert!(
        terminal == "error" || terminal == "response.done",
        "`response.create` must reach a TERMINAL — an `error` on a node with no provider composed, \
         or `response.done` — got {terminal:?} in {answered:?}"
    );

    // (3) THE CLOSE. The client closes and the node lets the session end rather than holding it.
    sock.close();
}

/// ADMISSION RUNS BEFORE ROUTE LOOKUP — the ONE ordering 1.5.5 pins for every plane, on a
/// deployment where the streams plane mounts nothing at all.
///
/// This node declares NO section here and no `public_url`, so `PLANE_DECL.build` yields no dispatch
/// slot and the router mounts neither the WS arrivals nor the one-shot passes. Every
/// realtime URL is therefore a path that does not exist — and the answer a caller gets to a path
/// that does not exist is the ordering under test: an AUTHENTICATED caller is told 404, and an
/// ANONYMOUS one is told 401 and nothing else. A build that answers 404 to the anonymous caller has
/// moved the router ahead of the gate and published the shape of its surface to strangers.
///
/// Green on both sides of this line by construction: a deployment that declares nothing here mounts
/// exactly what it mounted before, and the ordering it is told back is the same one.
#[test]
fn admission_runs_before_route_lookup() {
    let node = Node::boot("order", false, false);
    let scopeless = node.mint("vt7-scopeless", Some(&[]));

    for path in [
        "/v1/realtime",
        &format!("/v1/realtime/sideband/{CALL_ID}"),
        "/v1/realtime/client_secrets",
    ] {
        let anon = upgrade(node.data, path, None);
        assert_eq!(
            anon.status, 401,
            "an ANONYMOUS caller on {path} must be told 401 and nothing about the surface; got:\n{}",
            anon.head
        );
        let authed = upgrade(node.data, path, Some(&scopeless));
        assert_eq!(
            authed.status, 404,
            "an AUTHENTICATED caller on {path} — a path this deployment mounts nothing at — must be \
             told 404, which is admission answering BEFORE the route lookup; got:\n{}",
            authed.head
        );
    }
}

/// A DECLARATION WITH NO RECEIVING ORIGIN REFUSES THE BOOT — the third answer, against the shipped
/// binary, and the one this file could not previously ask for because it was not an answer.
///
/// Written here and given no `public_url`, this deployment used to boot and answer 404 on every URL it
/// had just been configured to serve: the section reached no build, no slot was made, the router
/// mounted nothing, and nothing said so. It now ends before a listener is bound, and the log carries
/// BOTH halves of why — the field an operator has to fix, named where the operator can act on it, and
/// the rule the composition refused under, which is that a claimed region with no RFC 8707 audience
/// would admit a token minted for any other resource.
#[test]
fn a_declaration_with_no_receiving_origin_refuses_the_boot() {
    let log = Node::refused("refused").log();
    assert!(
        log.contains("public_url"),
        "the refusal must NAME the field an operator has to fix; log:\n{log}"
    );
    assert!(
        log.contains("bound no admission"),
        "and it must name the rule it refused under, not just fail; log:\n{log}"
    );
    assert!(
        !log.contains("listening"),
        "and it must end BEFORE a listener is bound, not after; log:\n{log}"
    );
}

/// A MINT FOR AN AUDIENCE NO PLANE DECLARES IS REFUSED — the other half of the door, and the reason
/// the mintable set is read off the plane decls rather than taken from the caller's word.
///
/// A token bound to a resource this deployment does not serve has exactly one property: nothing
/// accepts it. Issuing it would send an operator who mistyped their own canonical URI away with a
/// credential that looks like every other one, to find out hours later from a `401` on the plane
/// that the mint had known all along. The refusal is a `400` at the mint, and it names the field.
#[test]
fn a_mint_for_an_audience_no_plane_declares_is_refused() {
    let node = Node::boot("undeclared", true, true);

    // A near miss on purpose: this node's plane DOES declare an audience, and this is that audience
    // with one segment changed. An RFC 8707 resource indicator is an opaque identifier compared for
    // equality, never a namespace — a mint that admitted a prefix or a sibling would be the same
    // confused-deputy hole the audience exists to close, moved from the door to the issuer.
    let refused = node.mint_for(
        "vt7-undeclared",
        &format!("{}/v1/realtime-staging", node.public_url.as_ref().unwrap()),
    );
    assert_eq!(
        refused.status,
        400,
        "a resource no mounted plane declares must be refused at the mint; got {} {}\nlog:\n{}",
        refused.status,
        refused.body,
        node.log()
    );
    let body: serde_json::Value = serde_json::from_str(&refused.body).expect("an error envelope");
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("invalid_request"),
        "the refusal rides the mint endpoint's declared 400 family; got {}",
        refused.body
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some(
            "`resource` is not an audience this deployment serves; a key may only be bound to a \
             resource a mounted plane declares"
        ),
        "the refusal must name the field an operator has to fix; got {}",
        refused.body
    );

    // AND THE 1.5.5 BODY IS UNTOUCHED: a mint that names no resource is the mint that has always
    // been here, and it still mints. The field is additive on the wire in both directions.
    let plain = node.mint("vt7-plain", None);
    assert!(
        plain.starts_with("bbk_"),
        "a mint body with no `resource` must be the 1.5.5 mint, unchanged; got {plain:?}"
    );
}
