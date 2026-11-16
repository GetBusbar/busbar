// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FETCH against a loopback HTTP server in this process: what goes on the wire (and what never
//! does), that a redirect is an answer, the caps, the judge asked once per new connection, and the
//! one deadline.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::host_side::needs::FetchNeed;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

const BUDGET: Duration = Duration::from_secs(5);

/// What the server saw: one entry per request, head and body as received.
type Seen = Arc<Mutex<Vec<String>>>;

async fn read_request(s: &mut TcpStream) -> String {
    let mut got = Vec::new();
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        let n = s.read(&mut chunk).await.unwrap();
        assert_ne!(n, 0, "the client hung up mid-request");
        got.extend_from_slice(&chunk[..n]);
        if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&got[..head_end]).to_ascii_lowercase();
    let want = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length: "))
        .map_or(0, |v| v.trim().parse::<usize>().unwrap());
    while got.len() < head_end + want {
        let n = s.read(&mut chunk).await.unwrap();
        assert_ne!(n, 0, "the client hung up mid-body");
        got.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// A server answering every connection's one request with `answer`.
async fn serve(answer: Vec<u8>) -> (SocketAddr, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Seen::default();
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let answer = answer.clone();
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let request = read_request(&mut s).await;
                log.lock().unwrap().push(request);
                let _ = s.write_all(&answer).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (addr, seen)
}

fn response(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for h in headers {
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// A judge that admits one address, remembers what it was asked, and can refuse.
struct Fixed {
    addrs: Vec<SocketAddr>,
    deny: bool,
    asked: Mutex<Vec<(String, u16)>>,
}

impl Fixed {
    fn new(addr: SocketAddr) -> Self {
        Fixed {
            addrs: vec![addr],
            deny: false,
            asked: Mutex::default(),
        }
    }
}

impl Admission for Fixed {
    fn dial<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFut<'a, Result<Vec<SocketAddr>, NeedErr>> {
        Box::pin(async move {
            self.asked.lock().unwrap().push((host.to_owned(), port));
            if self.deny {
                Err(NeedErr::Denied)
            } else {
                Ok(self.addrs.clone())
            }
        })
    }
}

#[derive(Default)]
struct Got {
    status: u16,
    body: Vec<u8>,
    headers: Vec<(String, Vec<u8>)>,
}

impl Reply for Got {
    fn status(&mut self, status: u16) {
        self.status = status;
    }
    fn body(&mut self, bytes: &[u8]) -> Result<(), NeedErr> {
        self.body.extend_from_slice(bytes);
        Ok(())
    }
    fn header(&mut self, name: &str, value: &[u8]) -> Result<(), NeedErr> {
        self.headers.push((name.to_owned(), value.to_vec()));
        Ok(())
    }
}

fn req<'a>(method: &'a str, url: &'a str, body: &'a [u8]) -> FetchReq<'a> {
    FetchReq {
        need: FetchNeed {
            method,
            url,
            headers: Records::new(&[]),
            body,
            max_body: 1 << 20,
            trust: 0,
            cert: None,
            egress: 0,
        },
        class: 0,
        waive: false,
        trust: None,
        cert: None,
        max_body: 1 << 20,
        max_headers: 1 << 16,
        timeout: BUDGET,
    }
}

async fn run(r: FetchReq<'_>, judge: &Fixed, got: &mut Got) -> Result<(), NeedErr> {
    fetch(&ConnectorIo::new(), r, judge, got).await
}

#[tokio::test]
async fn a_get_answers_status_body_and_headers_and_adds_no_credential() {
    let (addr, seen) = serve(response("200 OK", &["x-reply: yes"], b"hello")).await;
    let judge = Fixed::new(addr);
    let url = format!("http://127.0.0.1:{}/a/b?x=1", addr.port());
    let mut got = Got::default();
    run(req("GET", &url, b""), &judge, &mut got).await.unwrap();
    assert_eq!(got.status, 200);
    assert_eq!(got.body, b"hello");
    assert!(got
        .headers
        .iter()
        .any(|(n, v)| n == "x-reply" && v == b"yes"));
    let sent = seen.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let head = sent[0].to_ascii_lowercase();
    assert!(head.starts_with("get /a/b?x=1 http/1.1\r\n"), "{head}");
    assert!(head.contains(&format!("host: 127.0.0.1:{}\r\n", addr.port())));
    for ambient in ["authorization", "cookie", "proxy-authorization"] {
        assert!(!head.contains(ambient), "{ambient} was added: {head}");
    }
    assert_eq!(
        *judge.asked.lock().unwrap(),
        vec![("127.0.0.1".to_owned(), addr.port())],
        "the judge is asked once, for the host and port the URL names"
    );
}

#[tokio::test]
async fn a_post_carries_its_method_and_body() {
    let (addr, seen) = serve(response("201 Created", &[], b"")).await;
    let judge = Fixed::new(addr);
    let url = format!("http://127.0.0.1:{}/items", addr.port());
    let mut got = Got::default();
    run(req("POST", &url, b"abcd"), &judge, &mut got)
        .await
        .unwrap();
    assert_eq!(got.status, 201);
    let sent = seen.lock().unwrap().clone();
    let head = sent[0].to_ascii_lowercase();
    assert!(head.starts_with("post /items http/1.1\r\n"), "{head}");
    assert!(head.contains("content-length: 4\r\n"), "{head}");
    assert!(sent[0].ends_with("abcd"));
}

#[tokio::test]
async fn a_redirect_is_the_answer_and_is_not_followed() {
    let (addr, seen) = serve(response(
        "302 Found",
        &["location: http://127.0.0.1:1/elsewhere"],
        b"",
    ))
    .await;
    let judge = Fixed::new(addr);
    let url = format!("http://127.0.0.1:{}/start", addr.port());
    let mut got = Got::default();
    run(req("GET", &url, b""), &judge, &mut got).await.unwrap();
    assert_eq!(got.status, 302);
    assert!(got
        .headers
        .iter()
        .any(|(n, v)| n == "location" && v == b"http://127.0.0.1:1/elsewhere"));
    assert_eq!(seen.lock().unwrap().len(), 1, "one request, no second hop");
    assert_eq!(judge.asked.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_refused_dial_sends_nothing_and_connects_nowhere() {
    let (addr, seen) = serve(response("200 OK", &[], b"")).await;
    let mut judge = Fixed::new(addr);
    judge.deny = true;
    let url = format!("http://127.0.0.1:{}/", addr.port());
    let mut got = Got::default();
    let out = run(req("GET", &url, b""), &judge, &mut got).await;
    assert_eq!(out, Err(NeedErr::Denied));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_url_that_carries_credentials_or_a_foreign_scheme_is_invalid_before_any_dial() {
    let (addr, _seen) = serve(response("200 OK", &[], b"")).await;
    let judge = Fixed::new(addr);
    for url in [
        format!("http://user:pw@127.0.0.1:{}/", addr.port()),
        format!("http://user@127.0.0.1:{}/", addr.port()),
        format!("ftp://127.0.0.1:{}/", addr.port()),
        "not a url".to_owned(),
    ] {
        let mut got = Got::default();
        let out = run(req("GET", &url, b""), &judge, &mut got).await;
        assert_eq!(out, Err(NeedErr::Invalid), "{url}");
    }
    assert!(judge.asked.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_body_over_the_cap_is_a_limit_whether_or_not_its_length_is_declared() {
    let body = vec![b'x'; 100];
    let declared = response("200 OK", &[], &body);
    let mut chunked =
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n64\r\n"
            .to_vec();
    chunked.extend_from_slice(&body);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    for answer in [declared, chunked] {
        let (addr, _seen) = serve(answer).await;
        let judge = Fixed::new(addr);
        let url = format!("http://127.0.0.1:{}/", addr.port());
        let mut r = req("GET", &url, b"");
        r.max_body = 10;
        let mut got = Got::default();
        assert_eq!(run(r, &judge, &mut got).await, Err(NeedErr::Limit));
        assert!(got.body.len() <= 10, "no more than the cap was handed out");
    }
}

#[tokio::test]
async fn response_headers_over_the_cap_are_a_limit() {
    let big = format!("x-big: {}", "y".repeat(2000));
    let (addr, _seen) = serve(response("200 OK", &[big.as_str()], b"")).await;
    let judge = Fixed::new(addr);
    let url = format!("http://127.0.0.1:{}/", addr.port());
    let mut r = req("GET", &url, b"");
    r.max_headers = 100;
    let mut got = Got::default();
    assert_eq!(run(r, &judge, &mut got).await, Err(NeedErr::Limit));
}

#[tokio::test]
async fn an_exchange_that_outlasts_its_deadline_is_a_timeout() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _held = l.accept().await.unwrap();
        tokio::time::sleep(BUDGET).await;
    });
    let judge = Fixed::new(addr);
    let url = format!("http://127.0.0.1:{}/", addr.port());
    let mut r = req("GET", &url, b"");
    r.timeout = Duration::from_millis(100);
    let mut got = Got::default();
    assert_eq!(run(r, &judge, &mut got).await, Err(NeedErr::Timeout));
}
