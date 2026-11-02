// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

struct Declared {
    target: Option<String>,

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

struct Reply {
    step: u8,
    status: u32,
    body: Vec<u8>,
    at: usize,
}

pub struct HttpsConns {
    facts: FramedFacts,
    slab: ConnSlab<Mutex<Reply>>,
    needs: Mutex<HashMap<(InstanceId, NeedId), Result<Declared, ConnError>>>,
    far: Mutex<HashMap<String, FarEnd>>,
    sent: Mutex<Vec<(u32, String)>>,

    unreached: Vec<String>,

    unreached_needs: Mutex<HashMap<(InstanceId, NeedId), String>>,

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
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

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

    #[must_use]
    pub fn unreached<I: IntoIterator<Item = String>>(mut self, schemes: I) -> Self {
        self.unreached
            .extend(schemes.into_iter().filter(|s| !s.is_empty()));
        self
    }

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

    pub fn serve_issuer(&self, issuer: &crate::test_issuer::Issuer) {
        self.serve(
            issuer.jwks_url(),
            Some(issuer.cert_pem()),
            200,
            issuer.jwks(),
        );
    }

    #[must_use]
    pub fn sent(&self) -> Vec<(u32, String)> {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

pub const UNREACHED_WHY_MIN: usize = 40;

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
    fn open_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        _dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.open_with_security(caller, need, desc, require_secure)
    }

    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        let unreached = self.unreached.contains(&spec.transport);
        if unreached {
            self.unreached_needs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert((owner, need), spec.transport.clone());
        }

        let per_member = |path: &str| busbar_contract::section::member_target(path).is_some();
        let optional_trust = busbar_contract::section::owned_path(&spec.trust_from).is_some();
        let unresolved =
            (!spec.target_from.is_empty() && !per_member(&spec.target_from) && target.is_none())
                || (!spec.trust_from.is_empty()
                    && !per_member(&spec.trust_from)
                    && !optional_trust
                    && trust.is_none());

        let served = spec.transport == self.facts.transport || unreached;
        let answer = if spec.transport.is_empty() || !served || unresolved {
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
