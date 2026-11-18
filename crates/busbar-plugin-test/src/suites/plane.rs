// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane suite body (IF §14). It plays core for a plane plugin: it admits the image, opens one instance,
//! checks the describe surface and the two renders, then drives each [`PlaneCase`] through the port exactly as
//! the kernel's session task does (request, the core's FROM_CORE answers, `upstream`, scripted FROM_UPSTREAM
//! pieces, `end`) and compares the final client status.
//!
//! The core side it plays: LOOKUP (the case's `lookups` plus whatever the plane STOREd), STORE, DELETE, ENTITLE
//! (a grant scripted with `FakeNeeds::grant` is granted), JUDGE (always DEST_ALLOWED), ATTEMPT RETRY (the walk calls `upstream` again, at most [`MAX_ATTEMPTS`] times) and the exchanges
//! the plane opens (`UpNew`), each answered from `upstream[n]`. An intent this driver does not serve (MINT, SIGN,
//! CONNECT, RENDEZVOUS, TRUST, COMMIT, OBSERVE, WORK, CHANNEL, ...) fails the case loudly rather than being
//! answered wrongly: those arms are the dedicated `tests/c_*.rs` cases.

use std::collections::BTreeMap;

use busbar_plugin_abi::fail::refused::{
    R_AUTH_REQUIRED, R_BAD_CREDENTIAL, R_DENIED, R_EXPIRED, R_NOT_FOUND, R_NOT_TRUSTED, R_POLICY,
    R_RATE_LIMITED, R_UNSUPPORTED,
};
use busbar_plugin_abi::plane as p;
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::records::Reply;
use busbar_plugin_abi::types::KindCode;
use busbar_ports::codec::plane::{
    encode_catalog, encode_entitle_answers, encode_judged, encode_lookup_hits, encode_refusal,
    encode_upstream_head,
};
use busbar_ports::plane::{PlaneIn, PlaneOut, PlanePort, PlaneSession, TargetIn};
use busbar_ports::PortError;

use super::harness::Harness;
use super::PlaneCase;
use crate::fake_needs::FakeNeeds;

/// ATTEMPT(RETRY) walks at most this many attempts per case.
const MAX_ATTEMPTS: u32 = 4;
/// Intents beyond this many core round trips in one case mean the plane and the driver loop forever.
const MAX_ROUNDS: usize = 64;
/// The configured instance name the suite opens.
const NAME: &str = "suite-plane";

/// What one answer (a request, an upstream, a piece or an end) told core to do, owned.
#[derive(Default)]
struct Told {
    status: Option<u16>,
    forward: bool,
    lookups: Vec<(u32, u32, Vec<u8>)>,
    stores: Vec<(Vec<u8>, Vec<u8>)>,
    deletes: Vec<(u32, Vec<u8>)>,
    entitles: Vec<(u32, String)>,
    judges: Vec<(u32, String)>,
    /// The exchange numbers the plane opened with UP_NEW in this answer.
    exchanges: Vec<u32>,
    retry: bool,
    finished: bool,
    unserved: Vec<&'static str>,
}

impl Told {
    fn take(&mut self, out: PlaneOut<'_>) {
        match out {
            PlaneOut::Respond { status } => self.status = Some(status),
            PlaneOut::Forward { .. } => self.forward = true,
            PlaneOut::Lookup { flags, limit, key } => {
                self.lookups.push((flags, limit, key.to_vec()))
            }
            PlaneOut::Store { key, value, .. } => self.stores.push((key.to_vec(), value.to_vec())),
            PlaneOut::Delete { flags, key } => self.deletes.push((flags, key.to_vec())),
            PlaneOut::Entitle { check, grant } => self.entitles.push((check, grant.to_owned())),
            PlaneOut::Judge { check, dest, .. } => self.judges.push((check, dest.to_owned())),
            PlaneOut::UpNew { exchange, .. } => self.exchanges.push(exchange),
            PlaneOut::Attempt { verdict, .. } => {
                if verdict == p::ATT_RETRY {
                    self.retry = true;
                }
            }
            PlaneOut::Finish => self.finished = true,
            PlaneOut::Mint { .. } => self.unserved.push("MINT"),
            PlaneOut::Sign { .. } => self.unserved.push("SIGN"),
            PlaneOut::Connect { .. } => self.unserved.push("CONNECT"),
            PlaneOut::Rendezvous { .. } => self.unserved.push("RENDEZVOUS"),
            PlaneOut::Trust { .. } | PlaneOut::TrustVerify { .. } | PlaneOut::Sight { .. } => {
                self.unserved.push("TRUST")
            }
            PlaneOut::Commit { .. } => self.unserved.push("COMMIT"),
            PlaneOut::ObsScope { .. } | PlaneOut::Observe { .. } => self.unserved.push("OBSERVE"),
            PlaneOut::Work { .. } => self.unserved.push("WORK"),
            PlaneOut::Channel { .. } | PlaneOut::ChReady { .. } => self.unserved.push("CHANNEL"),
            // Everything else is output (headers, bodies, messages, usage, audit, facts, wants, upstream
            // request pieces, ...): the suite compares the status only.
            _ => {}
        }
    }

    fn absorb(&mut self, next: Told) {
        self.status = next.status.or(self.status);
        self.forward |= next.forward;
        self.lookups.extend(next.lookups);
        self.stores.extend(next.stores);
        self.deletes.extend(next.deletes);
        self.entitles.extend(next.entitles);
        self.judges.extend(next.judges);
        self.exchanges.extend(next.exchanges);
        self.retry |= next.retry;
        self.finished |= next.finished;
        self.unserved.extend(next.unserved);
    }

    fn wants_core(&self) -> bool {
        !(self.lookups.is_empty() && self.entitles.is_empty() && self.judges.is_empty())
    }
}

/// The core's records for the plane's namespace.
struct Core {
    records: BTreeMap<Vec<u8>, Vec<u8>>,
    grants: Vec<String>,
}

fn must<T>(what: &str, result: Result<T, PortError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("plane suite: {what} failed: {}", describe(&error)),
    }
}

fn describe(error: &PortError) -> String {
    match error {
        PortError::Refused { code, text, .. } => format!("REFUSED {code}: {text}"),
        PortError::Failed { code, text, .. } => format!("FAILED {code}: {text}"),
        PortError::Call(error) => format!("call error: {error:?}"),
    }
}

/// The status core renders a refusal with (§12.15), by generic code.
fn refusal_status(code: u32) -> u16 {
    match code {
        R_AUTH_REQUIRED | R_BAD_CREDENTIAL | R_EXPIRED => 401,
        R_DENIED | R_POLICY | R_NOT_TRUSTED => 403,
        R_NOT_FOUND => 404,
        R_RATE_LIMITED => 429,
        R_UNSUPPORTED => 501,
        _ => 400,
    }
}

fn same_req<'a>(req: &PlaneIn<'a>) -> PlaneIn<'a> {
    PlaneIn {
        route: req.route,
        flags: req.flags,
        auth: req.auth,
        method: req.method,
        path: req.path,
        query: req.query,
        headers: req.headers,
        identity: req.identity,
        request_id: req.request_id,
        carrier: req.carrier,
        work: req.work,
        ticket_record: req.ticket_record,
    }
}

/// `render` must answer Respond first and End last, and nothing else may precede Respond.
fn render_status(port: &dyn PlanePort, req: &PlaneIn<'_>, what: u32, arg: &[u8]) -> Option<u16> {
    let mut status = None;
    let mut order = Vec::new();
    let result = port.render(req, what, arg, &mut |out| match out {
        PlaneOut::Respond { status: s } => {
            status = Some(s);
            order.push("respond");
        }
        PlaneOut::End => order.push("end"),
        _ => order.push("other"),
    });
    match result {
        Ok(()) => {}
        Err(PortError::Refused { code, .. }) if code == R_UNSUPPORTED => return None,
        Err(error) => panic!("plane suite: render({what}) failed: {}", describe(&error)),
    }
    assert_eq!(
        order.first().copied(),
        Some("respond"),
        "plane suite: render({what}) must start with RESPOND, got {order:?}"
    );
    assert_eq!(
        order.last().copied(),
        Some("end"),
        "plane suite: render({what}) must finish with END, got {order:?}"
    );
    status
}

/// Answer the core intents `told` holds with one FROM_CORE piece (lookups, entitlements, judgements, in the §8.6
/// order), applying its STOREs and DELETEs to `core` first. Returns what that piece's answer told.
fn answer_core(
    port: &dyn PlanePort,
    session: &mut PlaneSession,
    core: &mut Core,
    told: &mut Told,
) -> Told {
    for (key, value) in told.stores.drain(..) {
        core.records.insert(key, value);
    }
    for (flags, key) in told.deletes.drain(..) {
        if flags & p::LK_PREFIX != 0 {
            core.records.retain(|have, _| !have.starts_with(&key));
        } else {
            core.records.remove(&key);
        }
    }
    let mut flags = 0u32;
    let mut reply = Reply::new();
    if !told.lookups.is_empty() {
        flags |= p::P_LOOKUP;
        let mut hits: Vec<(u32, Vec<u8>, Vec<u8>)> = Vec::new();
        for (index, (lookup_flags, limit, key)) in told.lookups.iter().enumerate() {
            assert!(
                lookup_flags & (p::LK_CALLER | p::LK_CHAIN) == 0,
                "plane suite: LOOKUP with LK_CALLER or LK_CHAIN is not served by the generic driver"
            );
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            if lookup_flags & p::LK_PREFIX != 0 {
                let cap = if *limit == 0 {
                    usize::MAX
                } else {
                    *limit as usize
                };
                for (have, value) in core.records.iter().filter(|(k, _)| k.starts_with(key)) {
                    if hits.iter().filter(|(i, _, _)| *i == index).count() < cap {
                        hits.push((index, have.clone(), value.clone()));
                    }
                }
            } else if let Some(value) = core.records.get(key) {
                hits.push((index, key.clone(), value.clone()));
            }
        }
        let borrowed: Vec<(u32, &[u8], &[u8])> = hits
            .iter()
            .map(|(i, k, v)| (*i, k.as_slice(), v.as_slice()))
            .collect();
        encode_lookup_hits(&mut reply, &borrowed).expect("plane suite: lookup hits fit a reply");
    }
    if !told.entitles.is_empty() {
        flags |= p::P_ENTITLE;
        let answers: Vec<(u32, bool)> = told
            .entitles
            .iter()
            .map(|(check, grant)| (*check, core.grants.iter().any(|have| have == grant)))
            .collect();
        encode_entitle_answers(&mut reply, &answers)
            .expect("plane suite: entitle answers fit a reply");
    }
    if !told.judges.is_empty() {
        flags |= p::P_JUDGED;
        let answers: Vec<(u32, u32)> = told
            .judges
            .iter()
            .map(|(check, dest)| {
                let _ = dest;
                (*check, p::DEST_ALLOWED)
            })
            .collect();
        encode_judged(&mut reply, &answers).expect("plane suite: judged answers fit a reply");
    }
    told.lookups.clear();
    told.entitles.clear();
    told.judges.clear();
    let mut next = Told::default();
    must(
        "piece(FROM_CORE)",
        port.piece(
            session,
            p::FROM_CORE,
            0,
            flags,
            reply.as_bytes(),
            &mut |out| next.take(out),
        ),
    );
    next
}

/// Serve core's intents until the plane asks for nothing more.
fn settle(
    port: &dyn PlanePort,
    session: &mut PlaneSession,
    core: &mut Core,
    told: &mut Told,
    case: usize,
) {
    for _ in 0..MAX_ROUNDS {
        // STOREs and DELETEs with nothing else pending need no answer.
        if !told.wants_core() {
            for (key, value) in told.stores.drain(..) {
                core.records.insert(key, value);
            }
            for (flags, key) in told.deletes.drain(..) {
                if flags & p::LK_PREFIX != 0 {
                    core.records.retain(|have, _| !have.starts_with(&key));
                } else {
                    core.records.remove(&key);
                }
            }
            return;
        }
        let next = answer_core(port, session, core, told);
        told.absorb(next);
    }
    panic!(
        "plane suite: case {case}: the plane kept asking core for more after {MAX_ROUNDS} rounds"
    );
}

/// Send exchange `exchange`'s scripted upstream pieces: a 200 head, each piece as body, then the end.
fn feed_upstream(
    port: &dyn PlanePort,
    session: &mut PlaneSession,
    core: &mut Core,
    told: &mut Told,
    exchange: u32,
    script: &[&[u8]],
    case: usize,
) {
    let mut head = Reply::new();
    encode_upstream_head(&mut head, 200, &[], None, None)
        .expect("plane suite: the upstream head fits a reply");
    let mut step = |session: &mut PlaneSession, told: &mut Told, flags: u32, bytes: &[u8]| {
        let mut next = Told::default();
        must(
            "piece(FROM_UPSTREAM)",
            port.piece(
                session,
                p::FROM_UPSTREAM,
                exchange,
                flags,
                bytes,
                &mut |out| next.take(out),
            ),
        );
        told.absorb(next);
    };
    step(session, told, p::P_HEAD, head.as_bytes());
    settle(port, session, core, told, case);
    for piece in script {
        step(session, told, p::P_BODY, piece);
        settle(port, session, core, told, case);
    }
    step(session, told, p::P_END, &[]);
    settle(port, session, core, told, case);
}

/// One case end to end; returns the client-visible status.
fn drive(
    port: &dyn PlanePort,
    case: &PlaneCase<'_>,
    index: usize,
    core: &mut Core,
    dialect: &str,
) -> u16 {
    core.records.clear();
    for (key, value) in case.lookups {
        core.records.insert(key.to_vec(), value.to_vec());
    }
    let mut told = Told::default();
    let opened = port.request(&case.req, case.body, &mut |out| told.take(out));
    let mut session = match opened {
        Ok(session) => session,
        Err(PortError::Refused { code, text, .. }) | Err(PortError::Failed { code, text, .. }) => {
            // No session exists: core renders the refusal through the plane (§12.15, RENDER_REFUSAL).
            let status = refusal_status(code.min(0xff));
            let mut arg = Reply::new();
            encode_refusal(&mut arg, status, code.min(0xff), &text)
                .expect("plane suite: a refusal fits a reply");
            return render_status(port, &case.req, p::RENDER_REFUSAL, arg.as_bytes())
                .unwrap_or(status);
        }
        Err(PortError::Call(error)) => {
            panic!("plane suite: case {index}: request faulted: {error:?}")
        }
    };
    settle(port, &mut session, core, &mut told, index);
    let mut attempt = 0u32;
    // Exchange 0 is the one `upstream` answers; later ones arrive as UP_NEW.
    let mut pending: Vec<u32> = Vec::new();
    while told.forward && attempt < MAX_ATTEMPTS && told.status.is_none() {
        told.forward = false;
        told.retry = false;
        let target = TargetIn {
            attempt,
            flags: 0,
            dialect,
            model: "",
            base_path: "",
            upstream: "",
            provider: "",
            params: &[],
            admission: &[],
        };
        let mut up = Told::default();
        must(
            "upstream",
            port.upstream(&mut session, &target, &mut |out| up.take(out)),
        );
        told.absorb(up);
        settle(port, &mut session, core, &mut told, index);
        pending.clear();
        pending.push(0);
        let mut next_exchange = 0usize;
        while let Some(&exchange) = pending.get(next_exchange) {
            next_exchange += 1;
            let script: &[&[u8]] = case
                .upstream
                .get(exchange as usize)
                .map_or(&[], |script| *script);
            told.exchanges.clear();
            feed_upstream(port, &mut session, core, &mut told, exchange, script, index);
            pending.append(&mut told.exchanges);
        }
        if told.retry {
            attempt += 1;
            told.forward = true;
            told.status = None;
        }
    }
    let mut last = Told::default();
    must("end", port.end(session, &mut |out| last.take(out)));
    told.absorb(last);
    assert!(
        told.unserved.is_empty(),
        "plane suite: case {index}: the plane asked core for {:?}, which the generic driver does not serve; \
         cover it with a dedicated case",
        told.unserved
    );
    match told.status {
        Some(status) => status,
        None => {
            panic!("plane suite: case {index}: the plane never answered the client (no RESPOND)")
        }
    }
}

pub(super) fn run(
    plugin: &'static Plugin,
    config: &[u8],
    needs: FakeNeeds,
    cases: &[PlaneCase<'_>],
) {
    let kernel = needs.kernel();
    let mut core = Core {
        records: BTreeMap::new(),
        grants: kernel
            .grants
            .iter()
            .map(|(_, grant)| grant.clone())
            .collect(),
    };
    let harness = match Harness::admit(plugin, needs) {
        Ok(harness) => harness,
        Err(refusal) => panic!("plane suite: the image was refused at admission: {refusal:?}"),
    };
    assert!(
        matches!(harness.kind(), KindCode::Plane),
        "plane suite: the image is not a plane plugin"
    );

    // Config: the operator form must open; a config no plane can read must be refused, never faulted.
    if let Err(error) = harness.check(NAME, config) {
        panic!("plane suite: check refused the operator config: {error:?}");
    }
    let port = match harness.open_plane(NAME, config) {
        Ok(port) => port,
        Err(error) => panic!("plane suite: open refused the operator config: {error:?}"),
    };
    assert!(
        harness
            .check("suite-plane-garbage", b"\xff\xfe not a config")
            .is_err(),
        "plane suite: a config that is not valid text must be refused"
    );

    // Describe surface.
    let routes = port.routes();
    assert!(
        !routes.is_empty(),
        "plane suite: the plane declares no route"
    );
    for route in routes {
        assert!(
            route.pattern.starts_with('/'),
            "plane suite: route {} pattern {:?} must start with '/'",
            route.route,
            route.pattern
        );
    }
    let mut classes: Vec<&str> = port.usage_classes().iter().map(|u| &*u.class).collect();
    classes.sort();
    let declared = classes.len();
    classes.dedup();
    assert_eq!(
        classes.len(),
        declared,
        "plane suite: a usage class is declared twice"
    );
    let dialect: String = port
        .dialects()
        .first()
        .map(|d| d.to_string())
        .unwrap_or_default();

    // Renders (§8.8): a refusal renders RESPOND ... END with the status core gave it; a catalog renders 200.
    if let Some(first) = cases.first() {
        let req = same_req(&first.req);
        let mut arg = Reply::new();
        encode_refusal(&mut arg, 403, R_DENIED, "denied by the suite")
            .expect("plane suite: a refusal fits a reply");
        if let Some(status) = render_status(&*port, &req, p::RENDER_REFUSAL, arg.as_bytes()) {
            assert!(
                (400..=599).contains(&status),
                "plane suite: a rendered refusal answered {status}, not an error status"
            );
        }
        if routes.iter().any(|r| r.flags & p::ROUTE_CATALOG != 0) {
            let mut models = Reply::new();
            encode_catalog(&mut models, &["suite-model"])
                .expect("plane suite: a catalog fits a reply");
            if let Some(status) = render_status(&*port, &req, p::RENDER_CATALOG, models.as_bytes())
            {
                assert_eq!(
                    status, 200,
                    "plane suite: the rendered catalog must answer 200"
                );
            }
        }
    }

    // The cases.
    for (index, case) in cases.iter().enumerate() {
        let status = drive(&*port, case, index, &mut core, &dialect);
        assert_eq!(
            status, case.expect_status,
            "plane suite: case {index} ({} {}): client status",
            case.req.method, case.req.path
        );
    }

    // The cases must leave the instance live: it still opens and renders after them.
    if let Err(error) = harness.check(NAME, config) {
        panic!("plane suite: the instance no longer checks after the cases: {error:?}");
    }
    harness.assert_needs_declared("plane");
}
