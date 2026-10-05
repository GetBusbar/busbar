// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STAND-IN FOR THE HOST'S CONNECTION TABLE, FRAMED (tests, and the published conformance
//! suite): [`HttpsConns`] serves a plugin's declared outbound needs over the `http` transport (the
//! scheme the http framer claims), to `https` targets, as the connector's framed `exchange()`
//! does, so a plugin that fetches over the host (an IdP's JWKS) can be opened on a
//! [`Dispatcher`](crate::dispatch::Dispatcher) in a build that cannot link the process's connector
//! (a kernel test, a plugin repo's conformance run). It never ships (`test-support`,
//! `conformance`), and it names no TLS library (TLS stays in the connector).
//!
//! Its far ends are IN PROCESS: each is a URL the test (or the published conformance suite, from a
//! plugin's `far_ends`) registers ([`HttpsConns::serve`]) with the certificate it presents and its
//! answer. As the connector does, the table refuses a need whose
//! `target_from` or `trust_from` resolved to nothing, dials only the target a need's config names
//! when it names one, and reaches a far end only over a need that trusts the certificate that far
//! end presents (the operator CA its `trust_from` named; a test has no public roots): a need trusting
//! another certificate, or a URL nothing serves, is refused as the connector refuses an unverified
//! or unreachable peer. Every read answers at once (no PENDING).

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;

/// One declared need, as the table carries it.
struct Declared {
    /// The target its config names (`target_from`), if any.
    target: Option<String>,
    /// The operator CA its `trust_from` named; `None` = none (the public roots, which no test far
    /// end chains to).
    trust: Option<String>,
}

/// One far end: the certificate it presents (`None`: one chaining to the public roots) and its
/// answer.
#[derive(Clone)]
struct FarEnd {
    cert_pem: Option<String>,
    status: u32,
    body: Vec<u8>,
}

/// One answered request, read back piece by piece.
struct Reply {
    step: u8,
    status: u32,
    body: Vec<u8>,
    at: usize,
}

/// THE TEST CONNECTION TABLE.
#[derive(Default)]
pub struct HttpsConns {
    slab: ConnSlab<Mutex<Reply>>,
    needs: Mutex<HashMap<(InstanceId, NeedId), Result<Declared, ConnError>>>,
    far: Mutex<HashMap<String, FarEnd>>,
    sent: Mutex<Vec<(u32, String)>>,
}

impl std::fmt::Debug for HttpsConns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsConns").finish_non_exhaustive()
    }
}

impl HttpsConns {
    /// A table with no far end.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve `url` (exact, query included) under the certificate `cert_pem` (`None`: one chaining
    /// to the public roots, which every need trusts), answering `status` and `body`.
    pub fn serve(&self, url: &str, cert_pem: Option<&str>, status: u32, body: &str) {
        self.far
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                url.to_owned(),
                FarEnd {
                    cert_pem: cert_pem.map(str::to_owned),
                    status,
                    body: body.as_bytes().to_vec(),
                },
            );
    }

    /// Serve a test issuer's JWKS at its URL, under its certificate.
    #[cfg(any(test, feature = "test-support"))]
    pub fn serve_issuer(&self, issuer: &crate::test_issuer::Issuer) {
        self.serve(
            issuer.jwks_url(),
            Some(issuer.cert_pem()),
            200,
            issuer.jwks(),
        );
    }

    /// Every request made, `(need, target)`, in order (refused ones included).
    #[must_use]
    pub fn sent(&self) -> Vec<(u32, String)> {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
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

/// The URL a request reaches: the target's scheme and authority, then the request's own path and
/// query (the head target).
fn reached(target: &str, desc: &OpenDesc<'_>) -> String {
    let origin_end = target
        .strip_prefix("https://")
        .and_then(|r| r.find(['/', '?', '#']).map(|i| i + "https://".len()))
        .unwrap_or(target.len());
    let path = String::from_utf8_lossy(desc.head_target);
    if path.is_empty() {
        target.to_owned()
    } else {
        format!("{}{path}", &target[..origin_end])
    }
}

/// A PEM's content: every character but whitespace.
fn pem_content(pem: &str) -> String {
    pem.chars().filter(|c| !c.is_whitespace()).collect()
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
        self.slab.check_need(caller, need)?;
        let (declared_target, trust) = {
            let needs = self.needs.lock().unwrap_or_else(PoisonError::into_inner);
            match needs.get(&(caller, need)) {
                Some(Ok(d)) => (d.target.clone(), d.trust.clone()),
                Some(Err(e)) => return Err(*e),
                None => return Err(ConnError::UndeclaredNeed),
            }
        };
        let target = match (desc.target, declared_target.as_deref()) {
            ("", Some(d)) => d.to_owned(),
            (named, _) => named.to_owned(),
        };
        let url = reached(&target, desc);
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((need.0, url.clone()));
        let at = authority(&target).ok_or(ConnError::Refused)?;
        // A need whose config names its target dials that target and no other.
        if let Some(d) = declared_target {
            if authority(&d).as_ref() != Some(&at) {
                return Err(ConnError::Refused);
            }
        }
        let far = self
            .far
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&url)
            .cloned()
            .ok_or(ConnError::Refused)?;
        // The peer is reached only over a need trusting the certificate it presents (the PEM's
        // content, as a TLS stack reads it: line breaks and surrounding space are not content).
        if let Some(cert) = &far.cert_pem {
            if trust.as_deref().map(pem_content) != Some(pem_content(cert)) {
                return Err(ConnError::Refused);
            }
        }
        self.slab.insert(
            caller,
            need,
            Mutex::new(Reply {
                step: 0,
                status: far.status,
                body: far.body,
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
            Ok(Declared {
                target: target.map(str::to_owned),
                trust: trust.map(str::to_owned),
            })
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
