//! A FAR END the rig owns: a loopback HTTP/1.1 server that records every request it is sent, byte
//! for byte, and answers each with the next scripted reply.
//!
//! The jev rig judges what busbar RELAYS, and a relay can only be judged from both ends: what the
//! caller sent against what the far end received, and what the far end answered against what the
//! caller got. This is the far end. It speaks just enough HTTP/1.1 to take one request per
//! connection (`Content-Length` or `chunked`) and close; it interprets nothing it receives.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One request, as it arrived.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    /// `(name, value)` in arrival order, names as sent.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    /// Every value of one header, by case-insensitive name.
    pub fn header(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

#[derive(Default)]
struct Shared {
    seen: Vec<Seen>,
    replies: VecDeque<(u16, Vec<u8>)>,
}

/// The running far end. Dropping it stops the accept loop.
pub struct FarEnd {
    pub port: u16,
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
}

impl FarEnd {
    pub fn start() -> Result<FarEnd, String> {
        let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("far end: {e}"))?;
        let port = l.local_addr().map_err(|e| e.to_string())?.port();
        l.set_nonblocking(true).map_err(|e| e.to_string())?;
        let shared = Arc::new(Mutex::new(Shared::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (s, st) = (shared.clone(), stop.clone());
        std::thread::spawn(move || {
            while !st.load(Ordering::Relaxed) {
                match l.accept() {
                    Ok((conn, _)) => serve(conn, &s),
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Ok(FarEnd { port, shared, stop })
    }

    /// Queue the reply the next request gets.
    pub fn reply(&self, status: u16, body: &[u8]) {
        if let Ok(mut s) = self.shared.lock() {
            s.replies.push_back((status, body.to_vec()));
        }
    }

    /// Every request received so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.shared
            .lock()
            .map(|s| s.seen.clone())
            .unwrap_or_default()
    }
}

impl Drop for FarEnd {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn serve(conn: TcpStream, shared: &Arc<Mutex<Shared>>) {
    let _ = conn.set_nonblocking(false);
    let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(mut out) = conn.try_clone() else {
        return;
    };
    let mut r = BufReader::new(conn);
    let mut line = String::new();
    if r.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).unwrap_or(0) == 0 {
            break;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let get = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    let mut body = Vec::new();
    if get("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        loop {
            let mut size = String::new();
            if r.read_line(&mut size).unwrap_or(0) == 0 {
                break;
            }
            let n = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
                .unwrap_or(0);
            let mut chunk = vec![0u8; n + 2];
            if r.read_exact(&mut chunk).is_err() {
                break;
            }
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    } else if let Some(n) = get("content-length").and_then(|v| v.parse::<usize>().ok()) {
        body.resize(n, 0);
        if r.read_exact(&mut body).is_err() {
            body.clear();
        }
    }
    let (status, reply) = {
        let Ok(mut s) = shared.lock() else {
            return;
        };
        s.seen.push(Seen {
            method,
            path,
            headers,
            body,
        });
        s.replies
            .pop_front()
            .unwrap_or((500, b"{\"error\":\"no reply was scripted\"}".to_vec()))
    };
    let head = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        reply.len()
    );
    let _ = out.write_all(head.as_bytes());
    let _ = out.write_all(&reply);
    let _ = out.flush();
}
