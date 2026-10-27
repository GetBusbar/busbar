// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STAND-IN FOR THE HOST'S CONNECTION TABLE, FRAMED (tests, and the published conformance
//! suite): [`HttpsConns`] serves a plugin's declared outbound needs over the framed transport its
//! facts name ([`FramedFacts`], data the conformance case supplies), to targets of its secured
//! scheme, as the connector's framed `exchange()` does, so a plugin that fetches over the host (an IdP's JWKS) can be opened on a
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

use crate::stand_in::FramedFacts;

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
pub struct HttpsConns {
    /// The transport it stands in for: the claim it serves, its secured scheme, its default port.
    facts: FramedFacts,
    slab: ConnSlab<Mutex<Reply>>,
    needs: Mutex<HashMap<(InstanceId, NeedId), Result<Declared, ConnError>>>,
    far: Mutex<HashMap<String, FarEnd>>,
    sent: Mutex<Vec<(u32, String)>>,
    /// Schemes a deployment's other transports serve that this table frames no far end for
    /// ([`HttpsConns::unreached`]).
    unreached: Vec<String>,
    /// The needs declared over an unreached scheme, and the scheme each names.
    unreached_needs: Mutex<HashMap<(InstanceId, NeedId), String>>,
    /// Per unreached scheme, the opens attempted on a need over it ([`HttpsConns::unreached_opens`]).
    unreached_tried: Mutex<HashMap<String, u64>>,
}

impl std::fmt::Debug for HttpsConns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsConns").finish_non_exhaustive()
    }
}

impl Default for HttpsConns {
    fn default() -> Self {
        Self::framing(FramedFacts::stand_in())
    }
}

impl HttpsConns {
    /// A table with no far end, standing in for the framed transport `stand_in.json` names.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A table with no far end, standing in for the framed transport `facts` names.
    #[must_use]
    pub fn framing(facts: FramedFacts) -> Self {
        Self {
            facts,
            slab: ConnSlab::default(),
            needs: Mutex::default(),
            far: Mutex::default(),
            sent: Mutex::default(),
            unreached: Vec::new(),
            unreached_needs: Mutex::default(),
            unreached_tried: Mutex::default(),
        }
    }

    /// Per unreached scheme, how many opens were attempted on a need over it, sorted by scheme;
    /// a scheme no open tried is absent. The suite asserts this is empty after a fold: an
    /// unreached scheme is a claim that the fold never touches it.
    #[must_use]
    pub fn unreached_opens(&self) -> Vec<(String, u64)> {
        let mut tried: Vec<(String, u64)> = self
            .unreached_tried
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(s, n)| (s.clone(), *n))
            .collect();
        tried.sort();
        tried
    }

    /// The same table, also answering the boot's scheme match for `schemes`: transports the
    /// deployment it stands in for loads beside the framed one, which this table frames no far end
    /// for. A need over one passes the load (as it does where that transport is loaded) and is
    /// refused at declare, so every open on it is refused as an unreachable peer is: the scheme is
    /// served, its far end is not here.
    #[must_use]
    pub fn unreached<I: IntoIterator<Item = String>>(mut self, schemes: I) -> Self {
        self.unreached
            .extend(schemes.into_iter().filter(|s| !s.is_empty()));
        self
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

/// The fewest characters an unreached scheme's `why` may have: a reason, not a word.
pub const UNREACHED_WHY_MIN: usize = 40;

/// JUDGE `inputs.unreached_schemes` (row 114: no silent skip): each entry is
/// `{ "scheme", "why", "covered_by": ["<path>::<test fn>", ...] }`, and is refused, naming what is
/// wrong, unless its `why` is a reason of at least [`UNREACHED_WHY_MIN`] characters; it cites at
/// least one cell, each a `#[test] fn` in a file at `<path>` under `root` (the plugin's own repo)
/// that exercises the scheme; the scheme is not `framed` (the table's own, which it reaches); and a
/// need the door declares (`need_transports`) names it. The schemes, in order.
///
/// # Errors
/// The first entry refused, and why.
pub fn judge_unreached(
    value: &serde_json::Value,
    framed: &str,
    need_transports: &[String],
    root: &std::path::Path,
) -> Result<Vec<String>, String> {
    let Some(entries) = value.as_array() else {
        return Err("unreached_schemes is a list of objects".to_string());
    };
    let mut schemes = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let at = format!("unreached_schemes[{i}]");
        let Some(obj) = e.as_object() else {
            return Err(format!(
                "{at} must be an object {{\"scheme\", \"why\", \"covered_by\"}}"
            ));
        };
        let scheme = obj
            .get("scheme")
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("{at}.scheme names no scheme"))?;
        let why = obj
            .get("why")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim();
        if why.chars().count() < UNREACHED_WHY_MIN {
            return Err(format!(
                "{at}.why for `{scheme}` is not a reason (at least {UNREACHED_WHY_MIN} characters)"
            ));
        }
        if scheme == framed {
            return Err(format!(
                "{at}: `{scheme}` is the framed table's own scheme, which the suite reaches"
            ));
        }
        if !need_transports.iter().any(|t| t == scheme) {
            return Err(format!(
                "{at}: `{scheme}` is named by no declared need, so nothing is unreached"
            ));
        }
        let cells: Vec<&str> = obj
            .get("covered_by")
            .and_then(serde_json::Value::as_array)
            .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
            .unwrap_or_default();
        if cells.is_empty() {
            return Err(format!(
                "{at}.covered_by for `{scheme}` cites no cell that exercises it"
            ));
        }
        for cell in cells {
            covered(root, cell).map_err(|why| format!("{at}.covered_by `{cell}`: {why}"))?;
        }
        schemes.push(scheme.to_string());
    }
    Ok(schemes)
}

/// `<path>::<fn>` resolves to a `#[test]` function in the file at `path` under `root`.
fn covered(root: &std::path::Path, cell: &str) -> Result<(), String> {
    let (path, name) = cell
        .rsplit_once("::")
        .ok_or_else(|| "is not `<path>::<test fn>`".to_string())?;
    let text = std::fs::read_to_string(root.join(path))
        .map_err(|e| format!("{path} does not read: {e}"))?;
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let decl = format!("fn {name}(");
    let at = lines
        .iter()
        .position(|l| l.starts_with(&decl) || l.contains(&format!(" {decl}")))
        .ok_or_else(|| format!("no fn {name} in {path}"))?;
    // The attributes and doc lines straight above the fn carry `#[test]`.
    let tested = lines[..at]
        .iter()
        .rev()
        .take_while(|l| l.starts_with("#[") || l.starts_with("///"))
        .any(|l| *l == "#[test]");
    if tested {
        Ok(())
    } else {
        Err(format!("fn {name} in {path} is not a #[test]"))
    }
}

/// `<secure scheme>://host[:port]/...` as `(host, port)`, the port `facts.default_port` where the
/// URL names none; `None` for a URL of any other scheme (the double reaches secured targets only).
fn authority(url: &str, facts: &FramedFacts) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    if facts.secure_scheme.is_empty() || !scheme.eq_ignore_ascii_case(&facts.secure_scheme) {
        return None;
    }
    let auth = rest.split(['/', '?', '#']).next()?;
    let (host, port) = if let Some(v6) = auth.strip_prefix('[') {
        let (h, tail) = v6.split_once(']')?;
        match tail.strip_prefix(':') {
            Some(p) => (h, p.parse().ok()?),
            None => (h, facts.default_port),
        }
    } else {
        match auth.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok()?),
            None => (auth, facts.default_port),
        }
    };
    Some((host.to_ascii_lowercase(), port))
}

/// The URL a request reaches: the target's scheme and authority, then the request's own path and
/// query (the head target).
fn reached(target: &str, desc: &OpenDesc<'_>) -> String {
    let origin_end = target
        .split_once("://")
        .and_then(|(scheme, r)| {
            r.find(['/', '?', '#'])
                .map(|i| i + scheme.len() + "://".len())
        })
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
        fault: None,
        reason: None,
        declared_len: None,
    }
}

impl Conns for HttpsConns {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        let unreached = self
            .unreached_needs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(caller, need))
            .cloned();
        if let Some(scheme) = unreached {
            *self
                .unreached_tried
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(scheme)
                .or_insert(0) += 1;
            return Err(ConnError::Refused);
        }
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
        let at = authority(&target, &self.facts).ok_or(ConnError::Refused)?;
        // A need whose config names its target dials that target and no other.
        if let Some(d) = declared_target {
            if authority(&d, &self.facts).as_ref() != Some(&at) {
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

    /// Every connection the double opens reached a target of its SECURED scheme (it serves no
    /// other), so it reports one secured: a certificate stands in for the far end's, as the host's
    /// `FACTS` reads security off a presented certificate. A credential that must go out secured
    /// (`Cred::secure_required`) is then sent as it is to a real `https` far end.
    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.slab.get(caller, conn)?;
        Ok(ConnFacts {
            peer_cert: Some(busbar_contract::transport::CertFacts {
                subject: "CN=conformance far end".to_string(),
                issuer: "CN=conformance far end".to_string(),
                fingerprint: "conformance-far-end".to_string(),
            }),
            ..ConnFacts::default()
        })
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
        if self.unreached.contains(&spec.transport) {
            self.unreached_needs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert((owner, need), spec.transport.clone());
        }
        // As the connector declares (busbar-core-connector `declare`): a member-target need
        // (`settings.*.<key>`) is pinned by no one target, each member's route being sealed at its
        // own, and dials what the plane names per open; a member-scoped or OWNED trust path is
        // optional, absent leaving the public roots alone. Any other path that resolved to nothing
        // refuses the need.
        let per_member = |path: &str| busbar_contract::section::member_target(path).is_some();
        let optional_trust = busbar_contract::section::owned_path(&spec.trust_from).is_some();
        let unresolved =
            (!spec.target_from.is_empty() && !per_member(&spec.target_from) && target.is_none())
                || (!spec.trust_from.is_empty()
                    && !per_member(&spec.trust_from)
                    && !optional_trust
                    && trust.is_none());
        let answer =
            if spec.transport.is_empty() || spec.transport != self.facts.transport || unresolved {
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
        !transport.is_empty()
            && (transport == self.facts.transport || self.unreached.iter().any(|s| s == transport))
    }
}
