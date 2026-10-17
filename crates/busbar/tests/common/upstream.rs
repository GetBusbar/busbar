// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A FAR END ON LOOPBACK: an HTTP/1.1 server that reads one request per connection and answers it,
//! and on it a SCRIPTED JSON-RPC 2.0 RESPONDER whose methods are DATA — each method name the case
//! states answers a stated `result`, or echoes a value from the request into a stated result shape.
//! The responder knows JSON-RPC framing (an `id`, a `method`, a `result`/`error`) and nothing of any
//! plane's methods; every method it serves, and every answer, is the caller's. Each method name is
//! counted as received, and a method's answer can be replaced between steps. The HTTP primitives
//! moved here from the suite that first wrote them.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

/// Read one HTTP/1.1 request off `conn`: the head and a `content-length` body. `None` on a
/// connection that closed or sent something that is not a request.
pub fn read_request(conn: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    conn.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = conn.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = conn.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((head, body))
}

/// Answer `conn` with `status` and the JSON `body`, closing the connection.
pub fn respond(conn: &mut TcpStream, status: u16, body: &Value) {
    let raw = body.to_string();
    let _ = write!(
        conn,
        "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{raw}",
        raw.len()
    );
    let _ = conn.flush();
}

/// How one method answers.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// This `result`, as stated.
    Result(Value),
    /// The value at `from` in the request, rendered through `format` (its `{}` replaced; the value
    /// itself when absent) and written at `into` (a pointer under `/result`) of `base` (the result's
    /// shape; an empty object when absent).
    Echo {
        from: String,
        into: String,
        base: Value,
        format: Option<String>,
    },
}

/// What the responder serves right now, and every method name it has received, counted.
#[derive(Debug, Default)]
pub struct Script {
    pub methods: BTreeMap<String, Answer>,
    pub received: BTreeMap<String, usize>,
}

/// A scripted JSON-RPC responder on a loopback port.
pub struct Responder {
    pub port: u16,
    pub script: Arc<Mutex<Script>>,
}

impl Responder {
    /// Start serving `methods` on a fresh loopback port, one thread per connection.
    pub fn start(methods: BTreeMap<String, Answer>) -> Responder {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the responder");
        let port = listener.local_addr().expect("its address").port();
        let script = Arc::new(Mutex::new(Script {
            methods,
            received: BTreeMap::new(),
        }));
        let state = Arc::clone(&script);
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let state = Arc::clone(&state);
                std::thread::spawn(move || serve_one(conn, &state));
            }
        });
        Responder { port, script }
    }

    /// Replace `method`'s answer.
    pub fn set(&self, method: &str, answer: Answer) {
        self.script
            .lock()
            .expect("the script")
            .methods
            .insert(method.to_string(), answer);
    }

    /// Every method name received so far, counted.
    pub fn received(&self) -> BTreeMap<String, usize> {
        self.script.lock().expect("the script").received.clone()
    }
}

/// `answer` for the request `req`.
fn render(answer: &Answer, req: &Value) -> Value {
    match answer {
        Answer::Result(result) => result.clone(),
        Answer::Echo {
            from,
            into,
            base,
            format,
        } => {
            let picked = req.pointer(from).cloned().unwrap_or(Value::Null);
            let value = match format {
                Some(f) => {
                    let text = picked
                        .as_str()
                        .map_or_else(|| picked.to_string(), str::to_string);
                    Value::String(f.replacen("{}", &text, 1))
                }
                None => picked,
            };
            let mut whole =
                json!({ "result": if base.is_null() { json!({}) } else { base.clone() } });
            if let Some(slot) = whole.pointer_mut(into) {
                *slot = value;
            }
            whole["result"].clone()
        }
    }
}

fn serve_one(mut conn: TcpStream, state: &Mutex<Script>) {
    let Some((head, body)) = read_request(&mut conn) else {
        return;
    };
    if !head.starts_with("POST ") {
        return respond(&mut conn, 404, &json!({ "error": "only POST is served" }));
    }
    let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let answer = {
        let mut s = state.lock().expect("the script");
        *s.received.entry(method.clone()).or_default() += 1;
        match s.methods.get(&method) {
            Some(answer) => json!({ "jsonrpc": "2.0", "id": id, "result": render(answer, &req) }),
            None => json!({ "jsonrpc": "2.0", "id": id, "error": {
                "code": -32601, "message": format!("method {method:?} is not scripted"),
            } }),
        }
    };
    respond(&mut conn, 200, &answer);
}
