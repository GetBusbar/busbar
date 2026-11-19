// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LOOPBACK STAND-INS FOR THE FAR SIDE OF A DIAL (tests only): a scripted HTTP/1.1 provider and a
//! CONNECT proxy, each on its own thread over real sockets, each recording what it saw.
//!
//! Every outbound proof against real sockets uses these two: trying the next provider (a closed
//! port, a provider that never answers, each status, a break after the first piece), the redial
//! of a kept connection the provider closed, a sealed credential seen once in its place, and the
//! proxy (the tunnel, the refusal, the password in the CONNECT only, no second CONNECT on a kept
//! connection). Standard library only, so the linked-image tests can use them unchanged.
//!
//! Declared by `conns.rs` beside `test_support`, under the same
//! `#[cfg(any(test, feature = "test-support"))]`.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// What the provider does with one request, in the order requests arrive (across connections).
/// The last behaviour repeats.
#[derive(Clone, Debug)]
pub enum Behaviour {
    /// Answer with this status, these extra head lines (each `name: value`), and this body, with
    /// a stated length; the connection stays open for the next request.
    Answer {
        /// The status.
        status: u16,
        /// Extra head lines.
        lines: Vec<String>,
        /// The body.
        body: Vec<u8>,
    },
    /// The same, then close the connection without saying so (the keep-alive race: the engine
    /// keeps a connection the provider has closed).
    AnswerThenClose {
        /// The status.
        status: u16,
        /// The body.
        body: Vec<u8>,
    },
    /// Read the request and never answer.
    Silent,
    /// Close the connection as soon as the request's head arrived, answering nothing.
    CloseOnRequest,
    /// Answer a chunked 200, send this first piece, then cut the connection.
    BreakAfterFirstPiece(Vec<u8>),
}

/// What a stand-in saw.
#[derive(Clone, Debug, Default)]
pub struct Seen {
    /// Connections accepted.
    pub connections: usize,
    /// Each request as it arrived: its head (through the blank line) and its body.
    pub requests: Vec<Vec<u8>>,
    /// Connections the far side (the engine) closed or reset before a request was complete.
    pub cut: usize,
}

impl Seen {
    /// How many times `needle` appears in everything received.
    #[must_use]
    pub fn count(&self, needle: &[u8]) -> usize {
        self.requests
            .iter()
            .map(|request| {
                request
                    .windows(needle.len())
                    .filter(|window| *window == needle)
                    .count()
            })
            .sum()
    }
}

/// A scripted HTTP/1.1 provider on loopback.
pub struct Provider {
    addr: SocketAddr,
    seen: Arc<Mutex<Seen>>,
}

fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4)
}

fn stated_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0)
}

/// One whole request off `stream` (`carry` holds bytes read past the last one). `None` = the far
/// side closed first.
fn read_request(stream: &mut TcpStream, carry: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(end) = head_end(carry) {
            let whole = end + stated_length(&carry[..end]);
            if carry.len() >= whole {
                let rest = carry.split_off(whole);
                return Some(std::mem::replace(carry, rest));
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => carry.extend_from_slice(&chunk[..n]),
        }
    }
}

fn answer(stream: &mut TcpStream, status: u16, lines: &[String], body: &[u8]) {
    let mut head = format!("HTTP/1.1 {status} X\r\ncontent-length: {}\r\n", body.len());
    for line in lines {
        head.push_str(line);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

impl Provider {
    /// Start a provider that follows `script`.
    ///
    /// # Panics
    /// When loopback cannot be bound, or `script` is empty.
    #[must_use]
    pub fn start(script: Vec<Behaviour>) -> Self {
        assert!(!script.is_empty(), "a provider needs a behaviour");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local address");
        let seen = Arc::new(Mutex::new(Seen::default()));
        let script = Arc::new(script);
        let served = Arc::new(Mutex::new(0_usize));
        let (all_seen, all_script) = (Arc::clone(&seen), script);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                all_seen.lock().expect("seen").connections += 1;
                let (seen, script, served) = (
                    Arc::clone(&all_seen),
                    Arc::clone(&all_script),
                    Arc::clone(&served),
                );
                thread::spawn(move || {
                    let mut carry = Vec::new();
                    loop {
                        let Some(request) = read_request(&mut stream, &mut carry) else {
                            if !carry.is_empty() {
                                seen.lock().expect("seen").cut += 1;
                            }
                            return;
                        };
                        seen.lock().expect("seen").requests.push(request);
                        let turn = {
                            let mut served = served.lock().expect("served");
                            *served += 1;
                            (*served - 1).min(script.len() - 1)
                        };
                        match &script[turn] {
                            Behaviour::Answer {
                                status,
                                lines,
                                body,
                            } => answer(&mut stream, *status, lines, body),
                            Behaviour::AnswerThenClose { status, body } => {
                                answer(&mut stream, *status, &[], body);
                                let _ = stream.shutdown(Shutdown::Both);
                                return;
                            }
                            Behaviour::Silent => {
                                // Held open until the far side gives up.
                                let mut sink = [0_u8; 64];
                                while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
                                return;
                            }
                            Behaviour::CloseOnRequest => {
                                let _ = stream.shutdown(Shutdown::Both);
                                return;
                            }
                            Behaviour::BreakAfterFirstPiece(piece) => {
                                let head = "HTTP/1.1 200 X\r\ntransfer-encoding: chunked\r\n\r\n";
                                let _ = stream.write_all(head.as_bytes());
                                let _ =
                                    stream.write_all(format!("{:x}\r\n", piece.len()).as_bytes());
                                let _ = stream.write_all(piece);
                                let _ = stream.write_all(b"\r\n");
                                let _ = stream.flush();
                                // Long enough for the piece to be read before the cut.
                                thread::sleep(Duration::from_millis(50));
                                let _ = stream.shutdown(Shutdown::Both);
                                return;
                            }
                        }
                    }
                });
            }
        });
        Self { addr, seen }
    }

    /// Where it listens.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>`.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// What it has seen so far.
    #[must_use]
    pub fn seen(&self) -> Seen {
        self.seen.lock().expect("seen").clone()
    }

    /// A loopback port nothing listens on (bound, read, released): a provider whose port is
    /// closed.
    ///
    /// # Panics
    /// When loopback cannot be bound.
    #[must_use]
    pub fn closed_port() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.local_addr().expect("local address")
    }
}

/// A CONNECT proxy on loopback.
pub struct Proxy {
    addr: SocketAddr,
    seen: Arc<Mutex<Seen>>,
}

fn relay(mut from: TcpStream, mut to: TcpStream) {
    let mut chunk = [0_u8; 16 * 1024];
    while let Ok(n) = from.read(&mut chunk) {
        if n == 0 || to.write_all(&chunk[..n]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

impl Proxy {
    /// Start a proxy. `refuse_with` = answer every CONNECT with this status and open no tunnel.
    /// `seen().requests` holds each CONNECT head as it arrived (the request line, the `Host`
    /// line, the `Proxy-Authorization` line where sent).
    ///
    /// # Panics
    /// When loopback cannot be bound.
    #[must_use]
    pub fn start(refuse_with: Option<u16>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local address");
        let seen = Arc::new(Mutex::new(Seen::default()));
        let all_seen = Arc::clone(&seen);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                all_seen.lock().expect("seen").connections += 1;
                let seen = Arc::clone(&all_seen);
                thread::spawn(move || {
                    let mut carry = Vec::new();
                    let Some(head) = read_request(&mut stream, &mut carry) else {
                        seen.lock().expect("seen").cut += 1;
                        return;
                    };
                    let target = String::from_utf8_lossy(&head)
                        .split_whitespace()
                        .nth(1)
                        .map(str::to_owned);
                    seen.lock().expect("seen").requests.push(head);
                    if let Some(status) = refuse_with {
                        let _ = stream.write_all(format!("HTTP/1.1 {status} X\r\n\r\n").as_bytes());
                        return;
                    }
                    let Some(upstream) = target.and_then(|at| TcpStream::connect(at).ok()) else {
                        let _ = stream.write_all(b"HTTP/1.1 502 X\r\n\r\n");
                        return;
                    };
                    let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                    let (Ok(down), Ok(mut up)) = (stream.try_clone(), upstream.try_clone()) else {
                        return;
                    };
                    // Bytes the client sent with its CONNECT belong to the tunnel.
                    let _ = up.write_all(&carry);
                    thread::spawn(move || relay(upstream, down));
                    relay(stream, up);
                });
            }
        });
        Self { addr, seen }
    }

    /// Where it listens.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://[user:password@]127.0.0.1:<port>`, as a proxy variable states it.
    #[must_use]
    pub fn url(&self, userinfo: Option<&str>) -> String {
        match userinfo {
            Some(userinfo) => format!("http://{userinfo}@{}", self.addr),
            None => format!("http://{}", self.addr),
        }
    }

    /// What it has seen so far.
    #[must_use]
    pub fn seen(&self) -> Seen {
        self.seen.lock().expect("seen").clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(stream: &mut TcpStream, request: &[u8]) -> Vec<u8> {
        stream.write_all(request).unwrap();
        let mut got = Vec::new();
        let mut chunk = [0_u8; 1024];
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        while head_end(&got).is_none_or(|end| got.len() < end + stated_length(&got[..end])) {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
            }
        }
        got
    }

    #[test]
    fn the_provider_follows_its_script_and_records_what_it_saw() {
        let provider = Provider::start(vec![
            Behaviour::Answer {
                status: 429,
                lines: vec!["retry-after: 3".to_owned()],
                body: b"slow".to_vec(),
            },
            Behaviour::Answer {
                status: 200,
                lines: Vec::new(),
                body: b"ok".to_vec(),
            },
        ]);
        let mut stream = TcpStream::connect(provider.addr()).unwrap();
        let first = exchange(&mut stream, b"GET /a HTTP/1.1\r\nx-api-key: k1\r\n\r\n");
        assert!(first.starts_with(b"HTTP/1.1 429 "));
        let second = exchange(
            &mut stream,
            b"POST /b HTTP/1.1\r\ncontent-length: 2\r\n\r\n{}",
        );
        assert!(second.ends_with(b"ok"));
        let seen = provider.seen();
        assert_eq!((seen.connections, seen.requests.len()), (1, 2));
        assert_eq!(seen.count(b"k1"), 1);
        assert!(seen.requests[1].ends_with(b"{}"));
    }

    #[test]
    fn the_proxy_tunnels_to_the_target_it_was_asked_for_and_records_the_connect() {
        let provider = Provider::start(vec![Behaviour::Answer {
            status: 200,
            lines: Vec::new(),
            body: b"through".to_vec(),
        }]);
        let proxy = Proxy::start(None);
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        let connect = format!(
            "CONNECT {0} HTTP/1.1\r\nHost: {0}\r\nProxy-Authorization: Basic dTpw\r\n\r\n",
            provider.addr()
        );
        let opened = exchange(&mut stream, connect.as_bytes());
        assert!(opened.starts_with(b"HTTP/1.1 200 "));
        let answered = exchange(&mut stream, b"GET / HTTP/1.1\r\n\r\n");
        assert!(answered.ends_with(b"through"));
        assert_eq!(proxy.seen().count(b"Proxy-Authorization: Basic dTpw"), 1);
        assert_eq!(
            provider.seen().count(b"Proxy-Authorization"),
            0,
            "the password is the proxy's, never the provider's"
        );
    }

    #[test]
    fn a_refusing_proxy_opens_no_tunnel() {
        let proxy = Proxy::start(Some(403));
        let mut stream = TcpStream::connect(proxy.addr()).unwrap();
        let refused = exchange(&mut stream, b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n");
        assert!(refused.starts_with(b"HTTP/1.1 403 "));
    }
}
