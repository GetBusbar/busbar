// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST STAND-IN FOR THE HOST'S CONNECTION TABLE, FRAMED HTTPS: [`HttpsConns`] serves a plugin's
//! declared outbound needs over the `http` transport (the scheme the http framer claims), to
//! `https` targets, as the connector's framed `exchange()` does, so a plugin that
//! fetches over the host (an IdP's JWKS, a token endpoint) can be opened on a
//! [`Dispatcher`](crate::dispatch::Dispatcher) in a build that cannot link the process's connector
//! (a kernel test). A test double: it never ships (`test-support`).
//!
//! As the connector does, it refuses a need whose `target_from` or `trust_from` resolved to nothing,
//! dials only the target a need's config names when it names one, and secures every connection with
//! TLS trusting exactly the operator CA the need's `trust_from` named (a test has no public roots
//! to reach). Unlike the connector it makes the request whole at `open`, on the caller's thread,
//! over HTTP/1.1 with `Connection: close`, and answers every read at once (no PENDING): a loopback
//! test issuer answers in microseconds.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;

/// The bound on one request when the need states none.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// One declared need, as the table carries it.
struct Declared {
    /// The target its config names (`target_from`), if any.
    target: Option<String>,
    /// TLS trusting the operator CA its `trust_from` named; `None` = no CA (nothing to trust).
    tls: Option<Arc<rustls::ClientConfig>>,
}

/// One answered request, read back piece by piece.
struct Reply {
    step: u8,
    status: u32,
    body: Vec<u8>,
    at: usize,
}

/// THE TEST CONNECTION TABLE (framed https).
#[derive(Default)]
pub struct HttpsConns {
    slab: ConnSlab<Mutex<Reply>>,
    needs: Mutex<HashMap<(InstanceId, NeedId), Result<Declared, ConnError>>>,
    sent: Mutex<Vec<(u32, String)>>,
}

impl std::fmt::Debug for HttpsConns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsConns").finish_non_exhaustive()
    }
}

impl HttpsConns {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every request made, `(need, target)`, in order.
    #[must_use]
    pub fn sent(&self) -> Vec<(u32, String)> {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// TLS trusting exactly the certificates in `pem`.
fn trusting(pem: &str) -> Result<Arc<rustls::ClientConfig>, ConnError> {
    let mut roots = rustls::RootCertStore::empty();
    let mut found = false;
    for der in pem_certificates(pem) {
        roots
            .add(rustls_pki_types::CertificateDer::from(der))
            .map_err(|_| ConnError::Refused)?;
        found = true;
    }
    if !found {
        return Err(ConnError::Refused);
    }
    Ok(Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| ConnError::Refused)?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ))
}

/// The DER of each `CERTIFICATE` block in `pem`.
fn pem_certificates(pem: &str) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    let mut out = Vec::new();
    let mut body = None::<String>;
    for line in pem.lines().map(str::trim) {
        match (line, body.as_mut()) {
            ("-----BEGIN CERTIFICATE-----", _) => body = Some(String::new()),
            ("-----END CERTIFICATE-----", Some(b)) => {
                if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b.as_bytes()) {
                    out.push(der);
                }
                body = None;
            }
            (l, Some(b)) => b.push_str(l),
            _ => {}
        }
    }
    out
}

/// `https://host[:port]/...` as `(host, port)`.
fn authority(url: &str) -> Option<(String, u16)> {
    let rest = url.strip_prefix("https://")?;
    let auth = rest.split(['/', '?', '#']).next()?;
    let (host, port) = if let Some(v6) = auth.strip_prefix('[') {
        let (h, tail) = v6.split_once(']')?;
        match tail.strip_prefix(':') {
            Some(p) => (h, p.parse().ok()?),
            None => (h, 443),
        }
    } else {
        match auth.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok()?),
            None => (auth, 443),
        }
    };
    Some((host.to_ascii_lowercase(), port))
}

/// The request made whole over TLS, and the far end's status and body.
fn exchange(
    tls: Arc<rustls::ClientConfig>,
    (host, port): (String, u16),
    desc: &OpenDesc<'_>,
) -> Result<(u32, Vec<u8>), ConnError> {
    let timeout = match desc.timeout_ms {
        0 => DEFAULT_TIMEOUT,
        ms => Duration::from_millis(ms),
    };
    let tcp = TcpStream::connect((host.as_str(), port)).map_err(|_| ConnError::Refused)?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|_| ConnError::Fault)?;
    let name =
        rustls_pki_types::ServerName::try_from(host.clone()).map_err(|_| ConnError::Refused)?;
    let conn = rustls::ClientConnection::new(tls, name).map_err(|_| ConnError::Refused)?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    let method = if desc.method.is_empty() {
        &b"GET"[..]
    } else {
        desc.method
    };
    let target = if desc.head_target.is_empty() {
        &b"/"[..]
    } else {
        desc.head_target
    };
    let mut head = Vec::new();
    head.extend_from_slice(method);
    head.push(b' ');
    head.extend_from_slice(target);
    head.extend_from_slice(format!(" HTTP/1.1\r\nhost: {host}:{port}\r\n").as_bytes());
    for (n, v) in desc.fields {
        head.extend_from_slice(n.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(v);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(
        format!(
            "content-length: {}\r\nconnection: close\r\n\r\n",
            desc.body.len()
        )
        .as_bytes(),
    );
    head.extend_from_slice(desc.body);
    s.write_all(&head).map_err(|_| ConnError::Refused)?;
    s.flush().map_err(|_| ConnError::Refused)?;
    let mut raw = Vec::new();
    match s.read_to_end(&mut raw) {
        Ok(_) => {}
        // A far end that closes without a close_notify still sent its whole answer.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(_) if !raw.is_empty() => {}
        Err(_) => return Err(ConnError::Closed),
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(ConnError::Closed)?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(ConnError::Closed)?;
    Ok((status, raw[split + 4..].to_vec()))
}

fn piece(kind: PieceKind, len: usize) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end: true,
        status: None,
        status_code: None,
        status_namespace: None,
        retry_after_secs: None,
        reason: None,
    }
}

impl Conns for HttpsConns {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need).inspect_err(|e| {
            eprintln!("https_conns: need {} is not declared: {e}", need.0);
        })?;
        let (declared_target, tls) = {
            let needs = self.needs.lock().unwrap_or_else(PoisonError::into_inner);
            match needs.get(&(caller, need)) {
                Some(Ok(d)) => (d.target.clone(), d.tls.clone()),
                Some(Err(e)) => {
                    eprintln!("https_conns: need {} was refused at declaration", need.0);
                    return Err(*e);
                }
                None => return Err(ConnError::UndeclaredNeed),
            }
        };
        let target = match (desc.target, declared_target.as_deref()) {
            ("", Some(d)) => d.to_owned(),
            (named, _) => named.to_owned(),
        };
        let Some(at) = authority(&target) else {
            eprintln!(
                "https_conns: need {} -> {target}: not an https target",
                need.0
            );
            return Err(ConnError::Refused);
        };
        // A need whose config names its target dials that target and no other.
        if let Some(d) = declared_target {
            if authority(&d).as_ref() != Some(&at) {
                return Err(ConnError::Refused);
            }
        }
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((need.0, target.clone()));
        let tls = tls.ok_or(ConnError::Refused)?;
        let (status, body) = exchange(tls, at, desc).inspect_err(|e| {
            // A test double: say why on the test's stderr (shown when the test fails).
            eprintln!("https_conns: need {} -> {target}: {e}", need.0);
        })?;
        self.slab.insert(
            caller,
            need,
            Mutex::new(Reply {
                step: 0,
                status,
                body,
                at: 0,
            }),
        )
    }

    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        // The request was made whole at `open`.
        Err(ConnError::Closed)
    }

    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        _: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let (_, r) = self.slab.get(caller, conn)?;
        let mut r = r.lock().unwrap_or_else(PoisonError::into_inner);
        if r.step == 0 {
            r.step = 1;
            return Ok(Piece {
                status_code: Some(r.status),
                ..piece(PieceKind::Fields, 0)
            });
        }
        if r.at < r.body.len() {
            let n = (r.body.len() - r.at).min(buf.len());
            let at = r.at;
            buf[..n].copy_from_slice(&r.body[at..at + n]);
            r.at += n;
            return Ok(piece(PieceKind::Body, n));
        }
        Ok(piece(PieceKind::Completion, 0))
    }

    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Ok(0)
    }

    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.slab.get(caller, conn)?;
        Ok(ConnFacts::default())
    }

    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.slab.remove(caller, conn).map(|_| ())
    }
}

impl DeclaredConns for HttpsConns {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        let unresolved = (!spec.target_from.is_empty() && target.is_none())
            || (!spec.trust_from.is_empty() && trust.is_none());
        let answer = if spec.transport != "http" || unresolved {
            Err(ConnError::Refused)
        } else {
            match trust.map(trusting).transpose() {
                Ok(tls) => Ok(Declared {
                    target: target.map(str::to_owned),
                    tls,
                }),
                Err(e) => Err(e),
            }
        };
        let result = answer.as_ref().map(|_| ()).map_err(|e| *e);
        if result.is_ok() {
            self.slab.declare(owner, need);
        }
        self.needs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((owner, need), answer);
        result
    }

    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.needs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(owner, need))
            .map(|a| a.as_ref().map(|_| ()).map_err(|e| *e))
    }

    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        true
    }

    fn serves_scheme(&self, transport: &str) -> bool {
        transport == "http"
    }
}
