// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;

use busbar_contract::caps::{Pass, ReasonCode, Route};
use busbar_contract::kept::Text;
use busbar_contract::plane::codes::RefusalCode;

use super::HeadFields;

/// A caller piece and opaque ownership that follows its allocation across a crossing.
/// A successful crossing retires the consumed allocation before any record/output waits or the
/// next read. A crossing that still borrows it after the session ends retains its custody.
#[derive(Default)]
pub struct SessionInput {
    /// The piece's allocation. Declared first so it is dropped before its custody owner.
    pub bytes: Vec<u8>,
    /// Optional allocation custody; the kernel neither inspects nor clones it.
    pub custody: Option<std::sync::Arc<dyn Send + Sync>>,
}

/// The operator's name of a member: the part of its lane key after the plane's separator.
pub(super) fn operator_name(key: &[u8]) -> &[u8] {
    let sep = crate::governance::PLANE_LANE_SEP as u8;
    key.iter()
        .position(|b| *b == sep)
        .map_or(key, |at| &key[at + 1..])
}

/// One piece of the far end's reply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FarPiece {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// On the reply's first piece: the exact status number and its class. On a trailers piece
    /// (`fields`): the status the transport read off the trailers, where it read one.
    pub status: Option<(u32, u32)>,
    /// No piece follows.
    pub last: bool,
    /// On the reply's first piece: the far end's response head fields the plane's need keeps, in
    /// the far end's order, names lower-case (no other response field crosses).
    pub head: Vec<(Vec<u8>, Vec<u8>)>,
    /// The bytes are the far end's fields after its body (trailers): pushed with `PIECE_FIELDS`,
    /// and the plane decides what they mean.
    pub fields: bool,
    /// The walk's own status table (the breaker's `Disposition` of this piece's status) says this
    /// attempt fails over: the pump moves to the next member WITHOUT pushing the piece to the
    /// plane, while no byte has reached the caller.
    pub fail_over: bool,
    /// On the reply's first piece: the far end relays this answer as the unit's (a terminal's
    /// dispatch: a spill, the least-bad bypass, a queued slot), so it is never failed over: a
    /// retry verdict renders it, as 1.5.5 relayed a degraded dispatch's answer.
    pub relayed: bool,
    /// On the reply's last piece: the answer ended without completing (its connection failed, or
    /// the send's deadline passed, after its head). Pushed with `PIECE_CUT`.
    pub cut: bool,
}

/// What the walk answers for an attempt: the member to try, or the pool's exhaustion terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
    /// The member the walk picked and admitted through its breaker, and the pool it picked it
    /// from (a member shapes its request per pool).
    Member {
        /// The member's configured name: the pool member's own shared name.
        name: Text,
        /// The pool's configured name: the pools' own shared name for it.
        pool: Text,
        /// Whether the member relays the caller's own credential to the far end (its upstream
        /// credentials are passthrough); the plane is told on every piece from this attempt on.
        passthrough: bool,
        /// The provider the member is served by (the metering row's provider): the route's own
        /// shared name.
        provider: Text,
    },
    /// No member is left: the walk's exhaustion terminal, the status the caller is told and its
    /// Retry-After seconds (the floor the walk applies), when it names one.
    Exhausted {
        /// The status number.
        status: u32,
        /// The Retry-After seconds.
        retry_after: Option<u32>,
        /// The terminal's words (`busbar_kernel_egress::wire::Shed::detail`), the previous
        /// release's sentence for that shed.
        detail: &'static str,
    },
    /// The walk refuses for a hook's restriction: a fallback pool no member of which satisfies a
    /// required restrict the hooks decided (the previous release failed closed there rather than
    /// spill to an ineligible far end). The caller is answered as by the hook, with these words.
    Vetoed {
        /// The status number.
        status: u32,
        /// The words (the walk's own, fixed).
        text: &'static str,
    },
    /// The walk refuses the unit for `0` before any member was dialled: the member's credential,
    /// re-resolved for this attempt, is unavailable (`ReasonCode::CredentialUnavailable`). The
    /// plane renders the refusal in its own words.
    Refused(ReasonCode),
}

/// One attempt's request, as the plane bound it for the far end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundRequest {
    /// The member the walk picked: the pick's own shared name.
    pub member: Text,
    /// The pool the walk picked it from: the pick's own shared name.
    pub pool: Text,
    /// The attempt's number, from `1`.
    pub attempt_no: u32,
    /// The verb.
    pub verb: Vec<u8>,
    /// The target.
    pub target: Vec<u8>,
    /// The dialect's head fields (the kernel adds the auth fields when it sends).
    pub fields: HeadFields,
    /// The body.
    pub body: Vec<u8>,
    /// The need the request rides, as the plane named it (`OnPieceOut::need`: its declared index
    /// plus one); `0` = the member's own.
    pub need: u32,
    /// The plane marked the request's message text (`PIECE_OUT_TEXT` on a far-bound answer): a far
    /// end whose wire tells text from binary is written it as text.
    pub text: bool,
    /// The scope the exchange states for its credential call (`UpExchange::scope`); it is never a
    /// head field. A scope field the plane wrote in its own head is read first, as it always was.
    pub scope: Option<Vec<u8>>,
    /// The exchange waives its member's credential (`OUTBOUND_NONE`): no member credential is sent.
    /// The default, `false`, sends the member's credential.
    pub no_member_auth: bool,
}

/// THE ROUTE THE KERNEL RESOLVED FOR A UNIT, as its in-session hooks are scoped: the pool label its
/// walk runs under (empty for a direct route, as 1.5.5 labelled it) and the container its entry's
/// hooks are filed under (a pool route's label, or the direct route's entry).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutedScope {
    /// The pool label (routed-order planes: the global and this pool's hooks).
    pub pool: String,
    /// The container (gate-first planes: the hooks attached to this entry).
    pub container: String,
}

/// THE FAR END: the kernel's egress walk and the connector stand behind it in production (member
/// pick, breaker, allow-list, pin, auth fields, the send); a test double in tests.
pub trait FarEnd: Sync {
    fn send_selected<'a>(
        &'a self,
        token: &'a Pass<Route>,
        request: OutboundRequest,
        handoff: &'a mut super::port_egress::SelectedHandoff,
    ) -> impl Future<Output = bool> + Send + 'a {
        let _ = (token, request, handoff);
        async { false }
    }
    fn member<'a>(
        &'a self,
        token: &'a Pass<Route>,
        attempt_no: u32,
    ) -> impl Future<Output = Pick> + Send + 'a;

    fn send<'a>(
        &'a self,
        token: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a;

    fn next<'a>(
        &'a self,
        token: &'a Pass<Route>,
    ) -> impl Future<Output = Option<FarPiece>> + Send + 'a;

    /// Start a fresh, admitted exchange on the member whose previous response completed.
    /// Implementations must recheck admission and credentials, never reuse a dispatch record.
    fn followup<'a>(
        &'a self,
        token: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a {
        let _ = (token, request);
        async { false }
    }

    fn remaining(&self, token: &Pass<Route>) -> Option<usize> {
        let _ = token;
        None
    }

    fn failure(&self, token: &Pass<Route>) -> Option<&'static str> {
        let _ = token;
        None
    }

    fn scope(&self, token: &Pass<Route>) -> Option<RoutedScope> {
        let _ = token;
        None
    }

    fn candidates(&self, token: &Pass<Route>) -> Option<super::hooks::Candidates> {
        let _ = token;
        None
    }

    /// The exact pricing lane behind an index in `candidates`, never its display model name.
    fn candidate_lane(&self, token: &Pass<Route>, index: usize) -> Option<String> {
        let _ = (token, index);
        None
    }

    fn constrain(&self, token: &Pass<Route>, constraint: super::hooks::Constraint) {
        let _ = (token, constraint);
    }

    fn attempt_span(&self, token: &Pass<Route>) -> tracing::Span {
        let _ = token;
        super::timing::attempt_span()
    }

    fn judged(&self, token: &Pass<Route>, fault: u8) {
        let _ = (token, fault);
    }

    fn taken(&self, token: &Pass<Route>) {
        let _ = token;
    }

    fn judged_stating(&self, token: &Pass<Route>, fault: u8, reason: Option<&str>) {
        let _ = reason;
        self.judged(token, fault);
    }

    /// [`FarEnd::judged_stating`] for a plane verdict that states how long the member asked to be left alone
    /// (an ATTEMPT's `retry_after_s`, IF §12.3: FC_RATE_LIMIT/FC_OVERLOADED feed the walk's exhaustion wait). A far
    /// end that keeps no wait (the default) judges as `judged_stating` does.
    fn judged_waiting(&self, token: &Pass<Route>, fault: u8, retry_after_s: Option<u64>) {
        let _ = retry_after_s;
        self.judged_stating(token, fault, None);
    }

    fn member_wait(&self, token: &Pass<Route>, member: &str) -> Option<u32> {
        let _ = (token, member);
        None
    }

    fn unsent(&self, token: &Pass<Route>) -> Option<RefusalCode> {
        let _ = token;
        None
    }

    /// Whether the walk's LAST attempted member failed on its own credential (its auth fields
    /// answered nothing, or its open or first read failed on the credential): an exhausted walk
    /// then ends `CredentialUnavailable`, never a retryable overload.
    fn credential_refused(&self, token: &Pass<Route>) -> bool {
        let _ = token;
        false
    }

    fn stated(&self, token: &Pass<Route>, labels: busbar_kernel_egress::ports::StatedLabels) {
        let _ = (token, labels);
    }

    fn deadline_ns(&self, now_ns: u64) -> u64 {
        let _ = now_ns;
        0
    }

    fn write<'a>(
        &'a self,
        token: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a;
}

pub trait CallerEnd: Sync {
    /// A terminal caller transport failure, including an expired accepted-stream deadline.
    fn stopped(&self) -> impl Future<Output = ReasonCode> + Send {
        std::future::pending()
    }

    fn head(&self, status: u32, fields: HeadFields);

    /// Head of a WHOLE answer: exactly `len` body bytes follow in this call's writes and nothing
    /// after. Transports that state framing (HTTP) override; every other caller is unchanged.
    fn head_whole(&self, status: u32, fields: HeadFields, len: usize) {
        let _ = len;
        self.head(status, fields);
    }

    fn write<'a>(&'a self, bytes: &'a [u8]) -> impl Future<Output = bool> + Send + 'a;

    fn write_text<'a>(&'a self, bytes: &'a [u8]) -> impl Future<Output = bool> + Send + 'a {
        self.write(bytes)
    }

    fn write_piece<'a>(
        &'a self,
        bytes: &'a [u8],
        text: bool,
        message_end: bool,
    ) -> impl Future<Output = bool> + Send + 'a {
        let _ = message_end;
        async move {
            if bytes.is_empty() {
                true
            } else if text {
                self.write_text(bytes).await
            } else {
                self.write(bytes).await
            }
        }
    }

    fn final_status(&self, status: u32, message: &[u8], details: &[u8]) {
        let _ = (status, message, details);
    }
}
