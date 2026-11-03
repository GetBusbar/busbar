// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

pub fn read_request(conn: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    conn.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    read_request_io(conn)
}

fn read_request_io(conn: &mut impl std::io::Read) -> Option<(String, Vec<u8>)> {
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

pub fn respond(conn: &mut impl std::io::Write, status: u16, body: &Value) {
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
    /// A complete HTTP JSON answer, without a JSON-RPC envelope.
    Http { status: u16, body: Value },
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

pub struct Responder {
    pub port: u16,
    pub script: Arc<Mutex<Script>>,
    pub ca_pem: Option<String>,
    pub spki: Option<String>,
}

impl Responder {
    pub fn start(methods: BTreeMap<String, Answer>) -> Responder {
        Self::start_with(methods, None)
    }

    pub fn start_tls(methods: BTreeMap<String, Answer>) -> Responder {
        use rcgen::PublicKeyData as _;
        busbar_core_connector::tls::install_crypto_provider();
        let ca_key = rcgen::KeyPair::generate().expect("the responder CA key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("CA parameters");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("the responder CA");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let leaf_key = rcgen::KeyPair::generate().expect("the responder leaf key");
        let params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
            .expect("the responder's IP SAN");
        let leaf = params
            .signed_by(&leaf_key, &issuer)
            .expect("the responder leaf");
        let spki = busbar_contract::transport::trust::key_pin(&leaf_key.subject_public_key_info());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
                    .expect("the responder leaf key DER"),
            )
            .expect("the actual responder TLS configuration");
        Self::start_with(methods, Some((Arc::new(config), ca.pem(), spki)))
    }

    fn start_with(
        methods: BTreeMap<String, Answer>,
        tls: Option<(Arc<rustls::ServerConfig>, String, String)>,
    ) -> Responder {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the responder");
        let port = listener.local_addr().expect("its address").port();
        let script = Arc::new(Mutex::new(Script {
            methods,
            received: BTreeMap::new(),
        }));
        let (config, ca_pem, spki) = match tls {
            Some((config, ca, pin)) => (Some(config), Some(ca), Some(pin)),
            None => (None, None, None),
        };
        let state = Arc::clone(&script);
        std::thread::spawn(move || {
            for mut conn in listener.incoming().flatten() {
                let state = Arc::clone(&state);
                let config = config.clone();
                std::thread::spawn(move || {
                    if let Some(config) = config {
                        if conn
                            .set_read_timeout(Some(Duration::from_secs(20)))
                            .is_err()
                            || conn
                                .set_write_timeout(Some(Duration::from_secs(20)))
                                .is_err()
                        {
                            return;
                        }
                        let Ok(mut session) = rustls::ServerConnection::new(config) else {
                            return;
                        };
                        if session.complete_io(&mut conn).is_err() {
                            return;
                        }
                        let mut socket = rustls::StreamOwned::new(session, conn);
                        serve_request(&mut socket, &state);
                    } else {
                        serve_one(conn, &state);
                    }
                });
            }
        });
        Responder {
            port,
            script,
            ca_pem,
            spki,
        }
    }

    pub fn url(&self) -> String {
        format!(
            "{}://127.0.0.1:{}",
            if self.ca_pem.is_some() {
                "https"
            } else {
                "http"
            },
            self.port
        )
    }

    pub fn set(&self, method: &str, answer: Answer) {
        self.script
            .lock()
            .expect("the script")
            .methods
            .insert(method.to_string(), answer);
    }

    pub fn received(&self) -> BTreeMap<String, usize> {
        self.script.lock().expect("the script").received.clone()
    }
}

fn render(answer: &Answer, req: &Value) -> Value {
    match answer {
        Answer::Http { body, .. } => body.clone(),
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
    if conn
        .set_read_timeout(Some(Duration::from_secs(20)))
        .is_err()
    {
        return;
    }
    serve_request(&mut conn, state);
}

fn serve_request(conn: &mut (impl std::io::Read + std::io::Write), state: &Mutex<Script>) {
    let Some((head, body)) = read_request_io(conn) else {
        return;
    };
    if !head.starts_with("POST ") {
        return respond(conn, 404, &json!({ "error": "only POST is served" }));
    }
    let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let (status, answer) = {
        let mut s = state.lock().expect("the script");
        *s.received.entry(method.clone()).or_default() += 1;
        let scripted = s.methods.get(&method).or_else(|| {
            s.methods
                .get("")
                .filter(|a| matches!(a, Answer::Http { .. }))
        });
        match scripted {
            Some(Answer::Http { status, body }) => (*status, body.clone()),
            Some(answer) => (
                200,
                json!({ "jsonrpc": "2.0", "id": id, "result": render(answer, &req) }),
            ),
            None => (
                200,
                json!({ "jsonrpc": "2.0", "id": id, "error": {
                "code": -32601, "message": format!("method {method:?} is not scripted"),
            } }),
            ),
        }
    };
    respond(conn, status, &answer);
}
