// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane port (IF §11.3). A `PlaneSession` is the kind's `SessionHandle` (§10.4): `Send`, `!Sync`, methods on
//! `&mut`, drop without `end` = `cancel`. W0-ABI stub: frozen signatures, `todo!()` bodies; L8 fills it.

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::records::Records;
use busbar_plugin_abi::types::Pair;

use crate::{CallCx, FactRef, PortError};

pub type PlaneSession = busbar_plugin_abi::kinds::plane::plane::SessionHandle;

/// Borrowed output, decoded from the call's OutBuf; valid until the sink returns.
pub enum PlaneOut<'o> {
    Respond {
        status: u16,
    },
    Header(&'o str, &'o [u8]),
    Body(&'o [u8]),
    Msg {
        flags: u32,
        bytes: &'o [u8],
    },
    End,
    /// Round 8: TRAILERS. The `Header` items that follow it, up to `End`, are client trailer fields; K8's serving
    /// task passes them to the client `TransportSession` as one `emit(E_TRAILERS, PAIR*)` before E_END (HTTP/2
    /// trailers-only when no body preceded it; HTTP/1.1 chunked trailers only when the client sent `TE: trailers`,
    /// else dropped and counted `plane_trailers_dropped_total`).
    Trailers,
    Forward {
        stream: bool,
    },
    Want(u32, FactRef<'o>),
    UpCarrier {
        carrier: u32,
        outbound: u32,
    },
    UpMethod(&'o str),
    UpPath(&'o str),
    UpScope(&'o str),
    UpBody(&'o [u8]),
    UpMsg {
        flags: u32,
        bytes: &'o [u8],
    },
    UpEnd,
    UpCut,
    /// Starts exchange n (≥ 1); the UpMethod/UpPath/UpScope/Header/UpBody/UpEnd that follow belong to it.
    UpNew {
        exchange: u32,
        carrier: u32,
        outbound: u32,
    },
    ExMsg {
        exchange: u32,
        flags: u32,
        stream: u64,
        bytes: &'o [u8],
    },
    Fact(u32, FactRef<'o>),
    Conversation(&'o [u8]),
    Usage {
        class: &'o str,
        amount: u64,
        scale: u32,
        source: u32,
    },
    /// EXPECT (request answer, or round 18 a deferred-FORWARD `piece(FROM_CORE)` answer).
    Expect {
        class: &'o str,
        amount: u64,
        scale: u32,
    },
    /// ATTEMPT: the outcome of the current attempt (or DECLINE from `upstream`). reason is operator-only.
    Attempt {
        verdict: u32,
        class: u32,
        retry_after_s: u64,
        reason: &'o str,
    },
    /// AUDIT: one row for the kernel audit chain, under the request's verified principal.
    Audit {
        verdict: u32,
        action: &'o str,
        resource: &'o str,
    },
    /// OBS_SCOPE: scope is the 32-byte id for ATTACH/CLOSE; require = the OBS_REQUIRE class texts (nested TEXT).
    ObsScope {
        check: u32,
        op: u32,
        scope: Option<[u8; 32]>,
        require: Records<'o>,
    },
    /// OBSERVE: counts = the OBS_COUNT records (UsageRec + class), validated by the adapter.
    Observe {
        check: u32,
        state: u32,
        rated_subject: u32,
        revision_order: u64,
        scope: [u8; 32],
        event: &'o [u8],
        component: &'o [u8],
        revision: Option<&'o [u8]>,
        counts: Records<'o>,
        evidence: Option<&'o [u8]>,
    },
    Lookup {
        flags: u32,
        limit: u32,
        key: &'o [u8],
    },
    Store {
        flags: u32,
        ttl_s: u64,
        key: &'o [u8],
        value: &'o [u8],
    },
    Delete {
        flags: u32,
        key: &'o [u8],
    },
    Entitle {
        check: u32,
        grant: &'o str,
    },
    /// Round 16: JUDGE (§8.6). `dest` is the tail as UTF-8 (invalid UTF-8 is FAULT BadRecords, as every text
    /// tail). The adapter only decodes; K8's session task checks class ≤ 4 and flags ⊆ JUDGE_RESOLVE |
    /// JUDGE_REFUSE_PRIVATE (else FAULT BadRecords, quarantine + audit), then hands it to `PlaneJudge::judge` (§12.1).
    Judge {
        check: u32,
        class: u32,
        flags: u32,
        dest: &'o str,
    },
    Rendezvous {
        exchange: u32,
        flags: u32,
        description: &'o str,
    },
    /// MINT (§12.11 `TicketMint`): `flags` = MINT_ONCE?, `prefix` = MT_PREFIX, `record` = MT_RECORD.
    Mint {
        check: u32,
        flags: u32,
        ttl_s: u64,
        scope: Option<&'o str>,
        audience: Option<&'o str>,
        prefix: Option<&'o str>,
        record: Option<&'o [u8]>,
    },
    Sign {
        check: u32,
        flags: u32,
        payload: &'o [u8],
    },
    Connect {
        check: u32,
        op: u32,
        upstream: &'o str,
        return_to: Option<&'o str>,
    },
    /// Raw nested records (H_METHOD, PUSH_URL, PAIR*, BODY); core's push queue copies and owns them.
    Push {
        ttl_s: u64,
        recs: Records<'o>,
    },
    WakeAt(u64),
    Detach {
        ttl_s: u64,
        flags: u32,
        key: &'o [u8],
    },
    Signal {
        flags: u32,
        key: &'o [u8],
    },
    Finish,
    /// The nested REC_PRED*/REC_PUT*/REC_DEL* records, validated by the adapter; core runs PluginRecords::commit.
    Commit {
        check: u32,
        ops: Records<'o>,
    },
    Sight {
        party: &'o str,
        catalog: Option<[u8; 32]>,
        items: Records<'o>, /* TR_ITEM pairs */
    },
    Trust {
        check: u32,
        op: u32,
        party: &'o str,
        item: Option<(&'o str, Option<[u8; 32]>)>,
    },
    /// Round 7: TRUST with op = TRUST_VERIFY (decoded separately; `Trust` never carries TRUST_VERIFY).
    TrustVerify {
        check: u32,
        party: &'o str,
        payload: &'o [u8],
        signatures: &'o [u8],
    },
    /// head = H_METHOD/H_PATH/PAIR* for CARRIER_HTTP channels, empty otherwise.
    Channel {
        exchange: u32,
        carrier: u32,
        flags: u32,
        framing: u32,
        key: &'o str,
        head: Records<'o>,
    },
    ChReady {
        exchange: u32,
        tail: &'o [u8],
    },
    /// The `demux` answer. Round 18: `tail` = the DX_BROADCAST key or the DX_OUTSTANDING fallback, empty otherwise;
    /// the adapter FAULTs every combination §8.6 DemuxRec forbids.
    Demux {
        slot: u64,
        flags: u32,
        tail: &'o [u8],
    },
    /// Round 10: EMIT (§12.23). K8 hands it to `LineCarriers::emit` with the instance's Caller.
    Emit {
        carrier: u64,
        bytes: &'o [u8],
    },
    /// Round 10: WORK (§12.24). OPEN carries `target` (WK_TARGET); FIND and SETTLE carry `reference` (WK_REF).
    Work {
        check: u32,
        op: u32,
        target: Option<&'o str>,
        reference: Option<&'o str>,
    },
}

/// Round 10: `carrier` (0 unless a ROUTE_LINE line) and `work` ("" unless RQ_RECOVERY), §8.6 PlaneReq.
pub struct PlaneIn<'a> {
    pub route: u32,
    pub flags: u32,
    pub auth: u32,
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a [Pair<'a>],
    pub identity: &'a [u8],
    pub request_id: u64,
    pub carrier: u64,
    pub work: &'a str,
    /** round 15 */
    pub ticket_record: &'a [u8],
}

pub struct TargetIn<'a> {
    pub attempt: u32,
    pub flags: u32,
    pub dialect: &'a str,
    pub model: &'a str,
    pub base_path: &'a str,
    pub upstream: &'a str,
    pub provider: &'a str,
    pub params: &'a [Pair<'a>],
}

/// One TRUST answer core encodes for P_TRUST (§12.14). `named` = TRUST_VERIFY's SIGNED_ALGORITHM/SIGNED_CRITICAL
/// text (round 7), "" otherwise; `items` is empty except for TRUST_STATE.
pub struct TrustAnswer<'a> {
    pub check: u32,
    pub verdict: u32,
    pub items: &'a [TrustItem<'a>],
    pub named: &'a str,
}

pub struct TrustItem<'a> {
    pub name: &'a str,
    pub verdict: u32,
    pub approved: Option<[u8; 32]>,
    pub sighted: Option<[u8; 32]>,
}

/// Round 23: `cred_header` = the route's D_ROUTE_CRED_HEADER, lowercase (§8.6, §12.11 "Route credential header").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteInfo {
    pub route: u32,
    pub methods: u32,
    pub flags: u32,
    pub auth: u32,
    pub pattern: Box<str>,
    pub cred_header: Option<Box<str>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UsageClass {
    pub class: Box<str>,
    pub unit: u32,
    pub expected_units: Option<f64>,
}

/// One answer core encodes for P_OBSERVED (§8.8 `encode_observed`), in intent order.
pub enum ObservedAnswer<'a> {
    Scope {
        check: u32,
        status: u32,
        scope: Option<[u8; 32]>,
    },
    Receipt {
        check: u32,
        status: u32,
        receipt: &'a [u8],
    },
}

/// Round 10: one answer core encodes for P_WORK (§8.8 `encode_work_answers`), in intent order. `reference` is
/// "" when refused; `target` is "" except for FIND.
pub struct WorkAnswer<'a> {
    pub check: u32,
    pub status: u32,
    pub state: u32,
    pub reference: &'a str,
    pub target: &'a str,
}

pub trait PlanePort: Send + Sync + 'static {
    fn routes(&self) -> &[RouteInfo];
    fn dialects(&self) -> &[Box<str>];
    fn usage_classes(&self) -> &[UsageClass];
    fn facts(&self) -> u64;
    /// D_TICK_S, if declared.
    fn tick_s(&self) -> Option<u64>;
    /// D_ADMIN_OPENAPI: the OpenAPI fragment of the plane's ROUTE_ADMIN routes (round 8), for the admin document.
    fn admin_openapi(&self) -> Option<&str>;
    /// Charges this plane's image for a once rule core found one of its answers to break (IF §8.6: handled
    /// exactly as an adapter FAULT): the instance is quarantined and `plugin_fault` audited.
    fn charge(&self, reason: busbar_plugin_abi::fail::FaultReason);
    /// Ok(session) even when the plane answered locally; core then calls `end`. A REFUSED/FAILED answer (no
    /// token, §10.4) is Err(PortError::Refused/Failed) and no session exists; core renders the refusal.
    fn request(
        &self,
        req: &PlaneIn<'_>,
        body: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError>;
    fn upstream(
        &self,
        s: &mut PlaneSession,
        t: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError>;
    /// Round 18: the adapter accepts Forward/Want/Expect in a FROM_CORE answer only and FAULTs them beside an intent
    /// or in a FROM_CLIENT/FROM_UPSTREAM answer; K8's session task, which alone knows whether this session already
    /// forwarded or began its response, applies the once rule (a second or late Forward is handled exactly as an
    /// adapter FAULT: the session ends, the image is charged, §8.6 deferred FORWARD).
    fn piece(
        &self,
        s: &mut PlaneSession,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError>;
    fn rewrite(
        &self,
        s: &mut PlaneSession,
        conversation: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError>;
    /// Consumes the session (no cancel afterwards).
    fn end(&self, s: PlaneSession, sink: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError>;
    /// what = RENDER_REFUSAL (arg = plane::encode_refusal) or RENDER_CATALOG (arg = plane::encode_catalog), §8.8.
    /// Round 9: the sink sees Respond, Header*, Body?, then optionally Trailers + Header*, then End; any other
    /// item is FAULT BadRecords. K8 hands Trailers exactly as in a session (`emit(E_TRAILERS)`, trailers-only on
    /// HTTP/2 when no Body preceded it).
    fn render(
        &self,
        req: &PlaneIn<'_>,
        what: u32,
        arg: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError>;
    fn probe(
        &self,
        t: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError>;
    /// Sessionless: the attachment slot of one framed inbound channel message (§12.19).
    fn demux(
        &self,
        key: &str,
        message: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError>;
    fn admin<'a>(
        &'a self,
        cx: CallCx,
        op: u32,
        arg: &'a [u8],
    ) -> BoxFut<'a, Result<Vec<u8>, PortError>>;
}
