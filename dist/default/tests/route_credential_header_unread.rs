// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLANE ROUTE NO OPENED AUTH INSTANCE CAN JUDGE IS NOT MOUNTED, AND THE BOOT GOES ON (engine owner's ruling on
//! IF §12.11 "Route credential header": migrate, never refuse). The default configuration names no auth instance that
//! reads plane-streaming's `/twilio/{call_id}` credential header (`x-twilio-signature`), so the default binary boots,
//! logs one line naming the route and the header, and answers a request to that route with the very bytes it answers
//! a request to no route at all: nothing tells an unauthenticated caller the route exists, and nothing reaches the
//! plane.

#![cfg(unix)]

#[path = "common/boot.rs"]
mod boot;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

const LINE: &str =
    "route 'streaming/5' is not served: no configured auth instance reads 'x-twilio-signature'";

struct Node {
    process: boot::Reap,
    dir: PathBuf,
    data: u16,
}

impl Node {
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("out.log")).unwrap_or_default()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The default configuration on loopback: listeners, the memory store, no auth instance.
fn boot_default() -> Node {
    let dir = std::env::temp_dir().join(format!("busbar-route-cred-unread-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the test's work directory");
    let (data, admin) = (boot::free_port(), boot::free_port());
    std::fs::write(dir.join("providers.yaml"), "{}\n").expect("providers.yaml");
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"config_version: 1
listen: "127.0.0.1:{data}"
listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test listener" }}
admin_listen: "127.0.0.1:{admin}"
admin_listen_insecure_transport: {{ accept: [plaintext], reason: "loopback test admin listener" }}
store: {{ module: memory }}
auth:
  chain: []
"#
        ),
    )
    .expect("config.yaml");
    let log = std::fs::File::create(dir.join("out.log")).expect("the boot log");
    let process = boot::Reap(
        Command::new(boot::exe())
            .current_dir(&dir)
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .stdout(log.try_clone().expect("the boot log"))
            .stderr(log)
            .spawn()
            .expect("boot the default binary"),
    );
    let mut node = Node { process, dir, data };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = node.process.try_wait().expect("try_wait") {
            panic!(
                "the default binary exited before serving ({status:?}); log:\n{}",
                node.log()
            );
        }
        assert!(
            Instant::now() < deadline,
            "/healthz never answered on the data listener; log:\n{}",
            node.log()
        );
        if boot::healthz_answers(node.data) {
            return node;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// One GET with `headers`: the raw response bytes.
fn get(port: u16, path: &str, headers: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to busbar");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    let head =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).expect("write the head");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    String::from_utf8_lossy(&raw).into_owned()
}

/// The status line and body of a response, without the headers that differ per response (date).
fn status_and_body(raw: &str) -> (String, String) {
    let status = raw.lines().next().unwrap_or_default().to_owned();
    let body = raw
        .split_once("\r\n\r\n")
        .map_or_else(String::new, |(_, body)| body.to_owned());
    (status, body)
}

#[test]
fn the_default_configuration_boots_with_the_unread_route_unmounted_and_says_so() {
    let node = boot_default();
    let log = node.log();
    assert_eq!(
        log.matches(LINE).count(),
        1,
        "one line names the route and its header; log:\n{log}"
    );
    let twilio = get(
        node.data,
        "/twilio/CA123",
        "Connection: Upgrade\r\nUpgrade: websocket\r\nX-Twilio-Signature: c2lnbmF0dXJl\r\n",
    );
    let nowhere = get(node.data, "/no/such/route", "");
    let (twilio, nowhere) = (status_and_body(&twilio), status_and_body(&nowhere));
    assert!(twilio.0.contains(" 401 "), "{twilio:?}");
    assert_eq!(
        twilio, nowhere,
        "the unmounted route answers exactly as no route does"
    );
}
