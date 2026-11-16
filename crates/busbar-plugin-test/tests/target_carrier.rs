// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST TARGET'S SHARED CODE AND CARRIER (SDK-SAFE-TEST-HOST §10.2-10.3, §11.9 T1a): the
//! adapter, not HTTP itself. A route answers through hyper on HTTP/1.1 and h2c, on each image,
//! crossing that image's own plugin thread; a head past 64 KiB is refused by hyper's limit; a
//! client gone mid-stream is reported to the route as gone; a non-loopback upstream and a
//! hostname `--listen` are refused; the ready file, stdout and the verdict carry no token; and an
//! unserved answer makes `finish` fail and `main` exit non-zero.

#[path = "fixtures/transport_door.rs"]
mod transport_door;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use busbar_contract::abi::transport::{slot, WriteIn};
use busbar_plugin_test::target::carrier::{
    dial_h1, dial_h2, Dial, Gone, Pieces, Reply, Request, Routes, HEAD_MAX,
};
use busbar_plugin_test::target::{
    self, Caller, Images, PluginThread, Refused, Target, Unserved, SUBJECT,
};
use busbar_plugin_test::{Called, Host, Loans, Transport};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use sonic_rs::JsonValueTrait;

/// The driver's bearer: it flows in, and must never come out.
const TOKEN: &str = "tkn-7f3c9a1e-never-written-anywhere";

/// Each image's host, on the contract's dev-only test caller binding.
fn host() -> Host {
    Host::new(busbar_contract::services::test_caller_binding())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
}

/// Status, `x-verb` and body of an answer.
async fn read(answer: hyper::Response<Incoming>) -> (u16, String, String) {
    let status = answer.status().as_u16();
    let verb = answer
        .headers()
        .get("x-verb")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = answer
        .into_body()
        .collect()
        .await
        .expect("the whole answer body")
        .to_bytes();
    (status, verb, String::from_utf8_lossy(&body).into_owned())
}

/// One HTTP/1.1 exchange through hyper's client.
async fn h1(
    addr: SocketAddr,
    verb: &str,
    path: &str,
    body: &'static [u8],
) -> (u16, String, String) {
    let mut send = dial_h1::<Full<Bytes>>(addr).await.expect("an h1 dial");
    send.ready().await.expect("an h1 connection");
    let request = hyper::Request::builder()
        .method(verb)
        .uri(path)
        .header("host", addr.to_string())
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Full::new(Bytes::from_static(body)))
        .expect("a request");
    read(send.send_request(request).await.expect("an h1 answer")).await
}

/// One h2c (prior knowledge) exchange through hyper's client.
async fn h2(
    addr: SocketAddr,
    verb: &str,
    path: &str,
    body: &'static [u8],
) -> (u16, String, String) {
    let mut send = dial_h2::<Full<Bytes>>(addr).await.expect("an h2c dial");
    send.ready().await.expect("an h2c connection");
    let request = hyper::Request::builder()
        .method(verb)
        .uri(format!("http://{addr}{path}"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Full::new(Bytes::from_static(body)))
        .expect("a request");
    read(send.send_request(request).await.expect("an h2c answer")).await
}

/// `POST /write`: crosses WRITE on the image's own plugin thread with the request body, and
/// answers what the plugin took, on which HTTP version, for which caller.
type Plugins = Arc<[(&'static str, PluginThread<Transport>)]>;

fn write_route(plugins: Plugins) -> impl Fn(Request) -> Reply + Send + Sync + 'static {
    move |req: Request| {
        let image = req.image();
        let (_, plugin) = plugins
            .iter()
            .find(|(name, _)| *name == image)
            .expect("a plugin thread per image");
        let bytes = req.body().to_vec();
        let wrote = plugin
            .run(move |t| {
                let mut i = Loans::<WriteIn>::new();
                i.bytes(&bytes).len(999).conn(7);
                match t.call::<{ slot::WRITE }>(i) {
                    Called::Ready(a) => Some(a.get(|o| o.len)),
                    Called::Pending(p) => {
                        p.leak_loans();
                        None
                    }
                }
            })
            .flatten();
        let who = req.caller().map_or("nobody", |c| c.name());
        let granted = req.caller().is_some_and(|c| c.grants(req.path()));
        Reply::ok(format!(
            "{image} took {wrote:?} on {:?} for {who}, granted {granted}",
            req.version()
        ))
        .header("x-verb", req.verb().as_str())
    }
}

#[test]
fn a_route_answers_through_hyper_on_h1_and_h2c_on_each_image() {
    let plugins: Vec<(&'static str, PluginThread<Transport>)> = Images::Both
        .names()
        .iter()
        .map(|&image| {
            let img = target::image::<Transport>(image, "transport_fixture", transport_door::door);
            let opened = PluginThread::open(host, img, "carrier-fixture", b"{}")
                .unwrap_or_else(|e| panic!("{image}: {e:?}"));
            (image, opened)
        })
        .collect();
    let served =
        Target::new(Routes::new().route("POST", "/write", write_route(Arc::from(plugins))))
            .caller(
                Caller::new("conformance")
                    .token(TOKEN.as_bytes())
                    .entries(&["/write"]),
            )
            .seed(3)
            .serve()
            .expect("the target serves");
    let rt = runtime();
    for image in ["linked", "cdylib"] {
        let addr = served.addr(image);
        assert!(addr.ip().is_loopback(), "{image}: {addr}");
        assert_eq!(
            served.admin_addr(image),
            None,
            "{image}: routes have no admin listener"
        );
        assert_eq!(
            rt.block_on(h1(addr, "POST", "/write", b"hello")),
            (
                200,
                "POST".to_owned(),
                format!("{image} took Some(5) on HTTP/1.1 for conformance, granted true")
            ),
            "{image} over HTTP/1.1"
        );
        assert_eq!(
            rt.block_on(h2(addr, "POST", "/write", b"hello")),
            (
                200,
                "POST".to_owned(),
                format!("{image} took Some(5) on HTTP/2.0 for conformance, granted true")
            ),
            "{image} over h2c"
        );
    }
    assert_eq!(served.report().unserved(), Vec::<String>::new());
    let report = served.finish().expect("everything asked was served");
    assert!(report.unserved().is_empty());
}

#[test]
fn a_head_over_64_kib_is_refused_by_hyper() {
    let served = Target::new(Routes::new().route("GET", "/", |_: Request| Reply::ok("never")))
        .images(Images::Linked)
        .serve()
        .expect("the target serves");
    let mut head = b"GET / HTTP/1.1\r\nhost: t\r\nx-big: ".to_vec();
    head.resize(HEAD_MAX, b'a');
    // HEAD_MAX bytes and the head has not ended: it is at least one byte over the limit.
    let mut s = TcpStream::connect(served.addr("linked")).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("a timeout");
    s.write_all(&head).expect("write the head");
    let mut answer = Vec::new();
    drop(s.read_to_end(&mut answer));
    let text = String::from_utf8_lossy(&answer);
    assert!(
        text.starts_with("HTTP/1.1 431"),
        "a head over {HEAD_MAX} bytes is refused 431 by hyper, got {text:?}"
    );
    served.finish().expect("hyper's refusal reaches no route");
}

#[test]
fn a_client_gone_mid_stream_is_reported_to_the_route_as_gone() {
    let (heard, hear) = mpsc::channel::<Result<usize, String>>();
    let served = Target::new(Routes::new().route("GET", "/stream", move |_: Request| {
        let (reply, pieces): (Reply, Pieces) = Reply::stream(200);
        let heard = heard.clone();
        std::thread::spawn(move || {
            for n in 0..3000usize {
                if pieces.send(format!("piece-{n}\n")) == Err(Gone) {
                    drop(heard.send(Ok(n)));
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            drop(heard.send(Err("the client never went".to_owned())));
        });
        reply
    }))
    .images(Images::Linked)
    .serve()
    .expect("the target serves");
    let mut s = TcpStream::connect(served.addr("linked")).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("a timeout");
    s.write_all(b"GET /stream HTTP/1.1\r\nhost: t\r\n\r\n")
        .expect("write");
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    while !seen.windows(7).any(|w| w == b"piece-0") {
        let n = s.read(&mut buf).expect("the first piece");
        assert!(n > 0, "the stream ended before its first piece: {seen:?}");
        seen.extend_from_slice(&buf[..n]);
    }
    drop(s);
    let after = hear
        .recv_timeout(Duration::from_secs(60))
        .expect("the route's sender ends");
    assert!(
        after.is_ok(),
        "the route is told the client went: {after:?}"
    );
    served.finish().expect("a client going is not a gap");
}

#[test]
fn a_non_loopback_upstream_and_a_hostname_listen_are_refused() {
    let far = Target::new(Routes::new())
        .upstream("far", "\x310.1.2.3:80".parse().expect("an address"))
        .serve()
        .err();
    assert!(
        matches!(&far, Some(Refused::NotLoopback(why)) if why.contains("\x310.1.2.3")),
        "{far:?}"
    );
    let named = Target::new(Routes::new()).listen("localhost").serve().err();
    assert!(
        matches!(&named, Some(Refused::NotLoopback(why)) if why.contains("localhost")),
        "{named:?}"
    );
    // A v4-mapped and a v6 loopback are loopback once canonical.
    let near = Target::new(Routes::new())
        .upstream(
            "mapped",
            "[::ffff:127.0.0.1]:9".parse().expect("an address"),
        )
        .upstream("six", "[::1]:9".parse().expect("an address"))
        .images(Images::Linked)
        .serve()
        .expect("loopback upstreams are taken");
    near.finish().expect("nothing was asked");
    let dialled = runtime().block_on(dial_h1::<Full<Bytes>>(
        "192.0.2.7:80".parse().expect("an address"),
    ));
    assert!(
        matches!(dialled, Err(Dial::NotLoopback(_))),
        "the client dials loopback only"
    );
}

#[test]
fn an_unserved_answer_an_unmatched_and_an_ambiguous_request_fail_finish() {
    let served = Target::new(
        Routes::new()
            .route("GET", "/gap", |_: Request| {
                Reply::unserved("a gap the route names")
            })
            .route("GET", "/both/*", |_: Request| Reply::status(204, ""))
            .route("GET", "/both/x", |_: Request| Reply::status(204, "")),
    )
    .images(Images::Linked)
    .serve()
    .expect("the target serves");
    let addr = served.addr("linked");
    let rt = runtime();
    for (path, what) in [
        ("/gap", "a gap the route names"),
        ("/nowhere", "unmatched GET /nowhere"),
        ("/both/x", "ambiguous GET /both/x"),
    ] {
        let (status, _, body) = rt.block_on(h1(addr, "GET", path, b""));
        assert_eq!(status, 501, "{path}");
        assert_eq!(
            body,
            format!("not served by the host target: {what}"),
            "{path}"
        );
    }
    assert_eq!(
        rt.block_on(h1(addr, "GET", "/both/y", b"")).0,
        204,
        "one subtree match"
    );
    assert_eq!(served.report().unserved().len(), 3);
    let Err(Unserved(unserved)) = served.finish() else {
        panic!("three unserved requests must fail the run");
    };
    assert_eq!(
        unserved,
        [
            "linked: a gap the route names",
            "linked: unmatched GET /nowhere",
            "linked: ambiguous GET /both/x",
        ]
    );
}

#[test]
#[should_panic(expected = "dropped unfinished")]
fn a_served_target_dropped_unfinished_with_a_gap_panics() {
    let served = Target::new(Routes::new())
        .images(Images::Linked)
        .serve()
        .expect("the target serves");
    let addr = served.addr("linked");
    assert_eq!(runtime().block_on(h1(addr, "GET", "/", b"")).0, 501);
    drop(served);
}

/// The facade's `[[bin]]` fixture `name`: cargo builds it beside this test and nextest archives it.
fn example(name: &str) -> PathBuf {
    PathBuf::from(match name {
        "carrier_target" => env!("CARGO_BIN_EXE_carrier_target"),
        other => panic!("no fixture binary {other}"),
    })
}

/// A fresh scratch directory for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-target-carrier-{}-{name}",
        std::process::id()
    ));
    drop(std::fs::remove_dir_all(&dir));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

#[test]
fn main_refuses_a_hostname_listen_and_writes_the_error() {
    let dir = scratch("hostname");
    let ready = dir.join("ready.json");
    let out = Command::new(example("carrier_target"))
        .arg("--listen")
        .arg("localhost:0")
        .arg("--ready-file")
        .arg(&ready)
        .stdin(Stdio::null())
        .output()
        .expect("run the carrier target");
    assert_eq!(out.status.code(), Some(2), "refused at start: {out:?}");
    let text = std::fs::read_to_string(&ready).expect("the ready file names the error");
    assert!(
        text.contains("\"error\"") && text.contains("localhost"),
        "{text}"
    );
    drop(std::fs::remove_dir_all(&dir));
}

#[cfg(unix)]
#[test]
fn main_writes_a_tokenless_ready_file_and_exits_non_zero_on_an_unserved_answer() {
    use std::os::unix::fs::OpenOptionsExt;

    let dir = scratch("main");
    let callers = dir.join("callers.json");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&callers)
        .and_then(|mut f| {
            f.write_all(
                format!(r#"[{{"name": "conformance", "token": "{TOKEN}", "entries": ["*"]}}]"#)
                    .as_bytes(),
            )
        })
        .expect("write the callers file 0600");
    let ready = dir.join("ready.json");
    let verdicts = dir.join("conformance");
    std::fs::create_dir_all(&verdicts).expect("the verdict directory");
    let mut child = Command::new(example("carrier_target"))
        .arg("--ready-file")
        .arg(&ready)
        .arg("--callers")
        .arg(&callers)
        .args(["--seed", "7"])
        .env("CONFORMANCE_OUT", &verdicts)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the carrier target");
    let mut waited = 0;
    while !ready.is_file() {
        if let Some(status) = child.try_wait().expect("poll the target") {
            panic!("the target ended before it was ready: {status}");
        }
        assert!(waited < 3000, "the target was not ready within 60 s");
        std::thread::sleep(Duration::from_millis(20));
        waited += 1;
    }
    let text = std::fs::read_to_string(&ready).expect("the ready file");
    assert!(
        !text.contains(TOKEN),
        "the ready file carries no token: {text}"
    );
    let doc: sonic_rs::Value = sonic_rs::from_str(&text).expect("the ready file is JSON");
    assert_eq!(doc.get("seed").and_then(|v| v.as_u64()), Some(7), "{text}");
    let addr = |image: &str| -> SocketAddr {
        doc.get("images")
            .and_then(|v| v.get(image))
            .and_then(|v| v.get("addr"))
            .and_then(|v| v.as_str())
            .and_then(|a| a.parse().ok())
            .unwrap_or_else(|| panic!("{image}'s address in {text}"))
    };
    let rt = runtime();
    assert_eq!(
        rt.block_on(h1(addr("linked"), "GET", "/hello", b"")),
        (
            200,
            String::new(),
            "hello from linked to conformance".to_owned()
        )
    );
    assert_eq!(
        rt.block_on(h2(addr("cdylib"), "GET", "/unserved", b"")).0,
        501
    );
    drop(child.stdin.take());
    let out = child
        .wait_with_output()
        .expect("the target ends when stdin closes");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unserved answer fails the run: {stderr}"
    );
    assert!(stdout.starts_with("BUSBAR_TARGET {"), "{stdout}");
    assert!(
        !stdout.contains(TOKEN) && !stderr.contains(TOKEN),
        "no token on stdout or stderr"
    );
    assert!(
        stderr.contains("cdylib: the fixture's unserved route"),
        "{stderr}"
    );
    let verdict = std::fs::read_to_string(verdicts.join("host-target.json")).expect("the verdict");
    assert!(!verdict.contains(TOKEN), "{verdict}");
    let verdict: sonic_rs::Value = sonic_rs::from_str(&verdict).expect("the verdict is JSON");
    assert_eq!(
        verdict.get("subject").and_then(|v| v.as_str()),
        Some(SUBJECT)
    );
    assert_eq!(
        sonic_rs::to_string(verdict.get("unserved").expect("an unserved list")).expect("JSON"),
        r#"["cdylib: the fixture's unserved route"]"#
    );
    drop(std::fs::remove_dir_all(&dir));
}
