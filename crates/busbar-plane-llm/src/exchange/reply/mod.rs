//! The far end's answer, sans I/O: what the caller reads for the status, head fields and body the
//! far end answered an attempt with, the units the far end reported, and what the answer means for
//! the walk.
//!
//! [`Reply`] is one attempt's answer as a state machine over the far end's pieces. It is opened on
//! the far end's status and head, and fed the far end's body piece by piece; each [`Piece`] it
//! answers carries the caller's head (on the first piece that carries anything for the caller),
//! the caller's bytes, the far end's CUMULATIVE reported units, a [`Verdict`] and, when the answer
//! failed, the [`Fault`] the far end's standing records. Three shapes, the previous release's:
//!
//! * a far-end ERROR (any status outside 2xx) is read whole and judged ([`failure`]);
//! * a far-end success taken WHOLE (across dialects without a stream, or asked to stream from a far
//!   end that answered one body) is read whole and translated ([`whole`]);
//! * any other success is RELAYED as it arrives ([`relay`]).
//!
//! It is pure: no clock (the wall-clock seconds and the elapsed milliseconds arrive in [`At`]), no
//! I/O, and no decision that is the kernel's — the breaker, the failover, the money, the timing and
//! the credentials are the kernel's; the plane reports and the kernel acts.

use std::borrow::Cow;
use std::collections::BTreeMap;

use busbar_contract::billing::TokenUsage;
use busbar_contract::codec::{OperationHandler, UsageTapFault};
use busbar_contract::protocol::HeadFields;
use busbar_contract::upstream::{Disposition, StatusClass};

use super::arrive::Arrived;
use super::attempt::StreamIntent;
use super::invoke;
use super::refuse::Rendered;
use super::shaping::Lane;
use crate::codec::DECLS;

pub mod failure;
pub mod relay;
pub mod whole;
pub mod wire;

/// What of the exchange an attempt's answer is written for; handed in with every piece, so the
/// reply holds only its own state.
#[derive(Clone, Copy, Debug)]
pub struct ReplyCtx<'a> {
    /// The caller's arrival.
    pub arrived: &'a Arrived,
    /// The far end the attempt reached.
    pub lane: &'a Lane,
    /// The caller's stream intent.
    pub intent: StreamIntent,
    /// The far end was reached with the caller's own credential (the kernel's fact): its 401 and
    /// 403 are the caller's own, relayed unjudged.
    pub passthrough: bool,
    /// The TRANSLATION CAP the plane enforces, the one its settings carry
    /// ([`super::shaping::Shaping::translate_cap`]): a whole answer past it is refused, a
    /// same-dialect copy kept for usage keeps its tail within it, and a writer bounds what it
    /// accumulates there.
    pub translate_cap: usize,
}

/// The time-like inputs of a piece.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct At {
    /// Wall-clock seconds, for a translated answer's creation stamp.
    pub now_s: u64,
    /// Milliseconds from the attempt's start, for a dialect whose answer reports its latency.
    pub elapsed_ms: Option<u64>,
}

/// The caller's head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    /// The status.
    pub status: u16,
    /// The head fields, in order.
    pub fields: Vec<(String, Vec<u8>)>,
}

/// What the answer means for the walk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verdict {
    /// Not known yet.
    #[default]
    None,
    /// A success.
    Ok,
    /// A failure another member may not share: the walk may go on, and if it ends here the caller
    /// reads this piece's answer.
    Retry,
    /// A failure no other member would change, or one after the caller's head: the caller reads
    /// this piece's answer.
    Hard,
}

/// What the far end's standing records for a failed answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A far-end error, judged: its disposition and, unless it was the caller's own credential,
    /// its class.
    Judged {
        /// The disposition.
        disposition: Disposition,
        /// The class.
        class: Option<StatusClass>,
    },
    /// A success answer that failed after its head: a transient fault under this reason.
    Transient(&'static str),
}

/// The far end's cumulative reported units, by meter class.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Units {
    /// Uncached input tokens.
    pub tokens_in: u64,
    /// Output tokens.
    pub tokens_out: u64,
    /// Input tokens read from the far end's cache.
    pub cache_read: u64,
    /// Input tokens written to the far end's cache.
    pub cache_write: u64,
    /// Every open class the answer counted beside its tokens, verbatim.
    pub open: BTreeMap<String, u64>,
    /// The token counts are a FLOOR over the bytes relayed so far, not the far end's report.
    pub floor: bool,
    /// The token counts are stated even at zero: they replace a floor the answer stated before.
    pub stated: bool,
}

impl Units {
    /// The units of a token usage: its four token tiers, and every open class it counted (a turn's
    /// billed searches) beside the open classes the answer's billing named.
    #[must_use]
    pub fn of(usage: Option<&TokenUsage>, mut open: BTreeMap<String, u64>) -> Self {
        let u = usage.cloned().unwrap_or_default();
        for (class, n) in u.open_units.into_iter().filter(|(_, n)| *n != 0) {
            open.entry(class).or_insert(n);
        }
        Units {
            tokens_in: u.input,
            tokens_out: u.output,
            cache_read: u.cache_read.unwrap_or(0),
            cache_write: u.cache_creation.unwrap_or(0),
            open,
            floor: false,
            stated: false,
        }
    }
}

/// One piece of the caller's answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Piece<'a> {
    /// The caller's head, on the first piece that carries anything for the caller.
    pub head: Option<Head>,
    /// The caller's bytes (the far end's own, borrowed, when relayed untouched).
    pub bytes: Cow<'a, [u8]>,
    /// The far end's cumulative reported units.
    pub units: Units,
    /// What the answer means for the walk.
    pub verdict: Verdict,
    /// What the far end's standing records, when the answer failed.
    pub fault: Option<Fault>,
    /// The caller's answer is complete.
    pub done: bool,
    /// The wire paths of a delivered TRANSLATE answer that did not cross to the caller's dialect
    /// (design F3 "Drops"), already warned: the door reports one `egress.control_unrepresentable`
    /// audit row per path (`<path> from <dialect>`), 1.5.5's row. Empty on a relay of the caller's
    /// own dialect and on every end that delivers nothing.
    pub dropped: Vec<String>,
    /// Why the usage tap could not read a same-dialect whole body, on the end that read it: the
    /// door carries it out beside its units, and the kernel counts it (row 155).
    pub tap_fault: Option<UsageTapFault>,
}

enum State {
    Error {
        status: u16,
        head: Vec<(Vec<u8>, Vec<u8>)>,
        body: Vec<u8>,
    },
    Whole {
        status: u16,
        body: Vec<u8>,
        /// The far end's head, kept for a same-dialect answer to relay (empty across dialects).
        head: Vec<(Vec<u8>, Vec<u8>)>,
    },
    Relay {
        relay: Box<relay::Relay>,
        head: Option<Head>,
        units: Units,
    },
    Done,
}

/// ONE ATTEMPT'S ANSWER.
pub struct Reply {
    state: State,
    /// The relayed answer ended a usable success the caller was reading (its first byte reached
    /// the caller and its stream ended clean): a caller that leaves while its last window is still
    /// being written bills the units it stated, as one that left mid-relay does (L1#5). A whole
    /// answer handed to the caller (a delivery, or a failed generation that keeps its usage) sets
    /// it too: its body may span several windows, and its units bill however many the caller read.
    ended_partial: bool,
    /// A streamed answer over the invoke envelope, re-framed into its carried dialect's events
    /// before it is read ([`invoke::Transcoder`]).
    invoke: Option<invoke::Transcoder>,
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let shape = match &self.state {
            State::Error { .. } => "error",
            State::Whole { .. } => "whole",
            State::Relay { .. } => "relay",
            State::Done => "done",
        };
        f.debug_struct("Reply").field("shape", &shape).finish()
    }
}

fn handler(ctx: &ReplyCtx<'_>) -> Option<&'static dyn OperationHandler> {
    DECLS
        .iter()
        .find(|d| d.name == ctx.arrived.dialect)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(ctx.arrived.operation))
}

fn json_array(ctx: &ReplyCtx<'_>) -> bool {
    ctx.arrived
        .path_model
        .as_ref()
        .is_some_and(|p| p.json_array)
}

/// A WHOLE answer, rendered here in full (a translated answer, a judged failure, a refusal): its head
/// states its length, so the caller is sent it under that length, as the previous release sent a
/// buffered answer; a relayed answer states none and is sent as it is relayed.
fn answered<'a>(r: Rendered, units: Units, verdict: Verdict, fault: Option<Fault>) -> Piece<'a> {
    let mut fields = r.fields;
    if !fields
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("content-length"))
    {
        fields.push((
            "content-length".to_string(),
            r.body.len().to_string().into_bytes(),
        ));
    }
    Piece {
        head: Some(Head {
            status: r.status,
            fields,
        }),
        bytes: Cow::Owned(r.body),
        units,
        verdict,
        fault,
        done: true,
        dropped: Vec::new(),
        tap_fault: None,
    }
}

/// The transient reason a far end's reported generation failure is recorded under.
const FAILED_GENERATION: &str = "upstream-generation-failed";

fn pending<'a>() -> Piece<'a> {
    Piece::default()
}

impl Reply {
    /// OPEN the answer on the far end's `status` and head.
    #[must_use]
    pub fn new(
        host: &dyn busbar_contract::codec::CodecHost,
        ctx: &ReplyCtx<'_>,
        status: u16,
        head: HeadFields<'_>,
    ) -> Self {
        if !(200..300).contains(&status) {
            return Reply {
                ended_partial: false,
                state: State::Error {
                    status,
                    head: head.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect(),
                    body: Vec::new(),
                },
                invoke: None,
            };
        }
        let far_ct = wire::head_value(head, "content-type");
        // A STREAM OVER THE INVOKE ENVELOPE is read as its carried dialect's stream: its frames are
        // re-framed into that dialect's events before any byte is read.
        let invoke_stream = ctx.lane.invoke
            && far_ct
                .and_then(wire::head_text)
                .is_some_and(|ct| ct.starts_with(invoke::EVENTSTREAM));
        let far_ct = if invoke_stream {
            Some(busbar_contract::protocol::TEXT_EVENT_STREAM.as_bytes())
        } else {
            far_ct
        };
        let far_is_stream = far_ct
            .and_then(wire::head_text)
            .is_some_and(wire::is_stream_content_type);
        let ingress = ctx.arrived.dialect;
        let egress = ctx.lane.dialect;
        let Some(op) = handler(ctx) else {
            return Reply {
                ended_partial: false,
                state: State::Whole {
                    status,
                    body: Vec::new(),
                    head: Vec::new(),
                },
                invoke: None,
            };
        };
        // Only a translated answer is taken whole, and a translated answer relays no far head; a
        // same-dialect answer takes the relay path below, which carries the far head.
        if relay::takes_whole(ingress, egress, far_is_stream) {
            return Reply {
                ended_partial: false,
                state: State::Whole {
                    status,
                    body: Vec::new(),
                    head: Vec::new(),
                },
                invoke: None,
            };
        }
        let mut fields = Vec::new();
        match relay::content_type(ingress, egress, far_is_stream, json_array(ctx)) {
            relay::ContentType::Json => fields.push((
                "content-type".to_string(),
                busbar_contract::protocol::APPLICATION_JSON
                    .as_bytes()
                    .to_vec(),
            )),
            relay::ContentType::Ingress(ct) => {
                fields.push(("content-type".to_string(), ct.as_bytes().to_vec()));
            }
            relay::ContentType::Far => {
                if let Some(ct) = far_ct {
                    fields.push(("content-type".to_string(), ct.to_vec()));
                }
            }
        }
        fields.extend(failure::request_id_field(host, ingress, head));
        if ingress == egress {
            wire::relay_far_head(ingress, &mut fields, head);
        }
        let relay = relay::Relay::new(relay::RelayCtx {
            ingress,
            egress,
            far_is_stream,
            json_array: json_array(ctx),
            client_include_usage: ctx.intent.client_include_usage,
            request: ctx.arrived.parsed.as_ref(),
            handler: op,
            meter: true,
            translate_cap: ctx.translate_cap,
        });
        Reply {
            ended_partial: false,
            state: State::Relay {
                relay: Box::new(relay),
                head: Some(Head { status, fields }),
                units: Units::default(),
            },
            invoke: invoke_stream.then(invoke::Transcoder::new),
        }
    }

    /// FEED one far-end piece; `last` says no piece follows.
    pub fn feed<'a>(
        &mut self,
        host: &dyn busbar_contract::codec::CodecHost,
        ctx: &ReplyCtx<'_>,
        bytes: &'a [u8],
        last: bool,
        at: At,
    ) -> Piece<'a> {
        let Some(transcoder) = self.invoke.as_mut() else {
            return self.read(host, ctx, bytes, last, at);
        };
        let framed = transcoder.feed(bytes);
        let p = self.read(host, ctx, &framed, last, at);
        Piece {
            head: p.head,
            bytes: Cow::Owned(p.bytes.into_owned()),
            units: p.units,
            verdict: p.verdict,
            fault: p.fault,
            done: p.done,
            dropped: p.dropped,
            tap_fault: p.tap_fault,
        }
    }

    /// READ one piece in the answer's own framing.
    fn read<'a>(
        &mut self,
        host: &dyn busbar_contract::codec::CodecHost,
        ctx: &ReplyCtx<'_>,
        bytes: &'a [u8],
        last: bool,
        at: At,
    ) -> Piece<'a> {
        match &mut self.state {
            State::Done => pending(),
            State::Error { body, .. } => {
                body.extend_from_slice(bytes);
                if last {
                    self.judge(host, ctx)
                } else {
                    pending()
                }
            }
            State::Whole { status, body, head } => {
                body.extend_from_slice(bytes);
                if body.len() > ctx.translate_cap {
                    self.state = State::Done;
                    let w = whole::over_cap(host, ctx.arrived.dialect);
                    return answered(w.answer, Units::default(), Verdict::Hard, None);
                }
                if !last {
                    return pending();
                }
                let (status, body, head) = (*status, std::mem::take(body), std::mem::take(head));
                self.state = State::Done;
                let far_head: Vec<(&[u8], &[u8])> = head
                    .iter()
                    .map(|(n, v)| (n.as_slice(), v.as_slice()))
                    .collect();
                let piece = whole_piece(host, ctx, status, &body, &far_head, at);
                // A WHOLE ANSWER THAT REACHES THE CALLER BILLS WHAT IT REPORTED, whether or not
                // the caller stays for its last window. 1.5.5 billed a buffered translated answer
                // before it wrote a byte of it (v1.5.5 `proxy/engine/mod.rs`
                // `translate_response_cross_protocol`: `record_resp_usage` runs before the
                // response is built), so a caller that leaves while a body larger than one
                // window is still being written bills its units: the delivered answer and the
                // failed generation that keeps its usage. An end that delivers nothing bills
                // nothing.
                self.ended_partial = piece.verdict == Verdict::Ok
                    || piece.fault == Some(Fault::Transient(FAILED_GENERATION));
                piece
            }
            State::Relay { relay, head, units } => {
                let (fed, _) = relay.feed(host, bytes);
                let mut out: Cow<'a, [u8]> = match fed {
                    relay::Fed::Bytes(b) => b,
                    relay::Fed::Nothing => Cow::Borrowed(&[]),
                };
                let head = head.take();
                if !last {
                    // What a stream's readers have read so far. A same-dialect whole body states
                    // nothing while it relays: a caller that leaves mid-body bills no tokens, as
                    // 1.5.5 billed none (v1.5.5 proxy/response_body.rs:620-625: a partially
                    // buffered same-protocol body is not billed on a mid-buffer drop), and the
                    // kernel adds no floor (#77(2), ARCHITECT ruling 2026-10-15; item 367's
                    // relayed floor, Q33 (a), was told, never signed).
                    if let Some(u) = relay.streamed_usage() {
                        *units = Units::of(Some(&u), BTreeMap::new());
                    }
                    return Piece {
                        verdict: if head.is_some() {
                            Verdict::Ok
                        } else {
                            Verdict::None
                        },
                        head,
                        bytes: out,
                        units: units.clone(),
                        fault: None,
                        done: false,
                        dropped: Vec::new(),
                        tap_fault: None,
                    };
                }
                let partial = relay.partial();
                let failed_generation = relay.failed_generation(ctx.lane.dialect);
                let end = relay.end(host);
                if !end.bytes.is_empty() {
                    out.to_mut().extend_from_slice(&end.bytes);
                }
                let fault = end.stream_fault.map(Fault::Transient).or(end
                    .generation_failed
                    .then_some(Fault::Transient(FAILED_GENERATION)));
                // The end's report replaces a floor stated while relaying, even when it is zero.
                // A stream the far end itself ended as FAILED (its in-band terminal error)
                // delivered no completed generation and bills no tokens, as 1.5.5 billed none
                // (v1.5.5 proxy/response_body.rs:550-575, `if !billing_failed`): its buffered twin
                // (a `failed` status) reports none either (row-159 L3#4). A FAILED GENERATION is
                // not one of those: 1.5.5's reader raised no error for it and billed what it
                // reported, and owner ruling Q31 charges it too ([`Relay::failed_generation`]). A
                // TRANSLATION THAT ABORTED after the first byte is a mid-stream cut, not a refund:
                // it bills what the far end reported before it (#62, OWNER-LOCKED 2026-09-20;
                // ruled for this case 2026-10-17), as a caller that leaves after it does.
                let translate_aborted = end.stream_fault == Some("stream-translate-abort");
                let units =
                    if end.stream_fault.is_some() && !failed_generation && !translate_aborted {
                        Units::default()
                    } else {
                        Units {
                            stated: units.floor,
                            ..Units::of(end.usage.as_ref(), end.open_units)
                        }
                    };
                self.ended_partial = partial && fault.is_none();
                self.state = State::Done;
                Piece {
                    head,
                    bytes: out,
                    units,
                    verdict: if fault.is_some() {
                        Verdict::Hard
                    } else {
                        Verdict::Ok
                    },
                    fault,
                    done: true,
                    dropped: end.dropped,
                    tap_fault: end.tap_fault,
                }
            }
        }
    }

    /// The caller had a usable part of a success answer when it left (see [`relay::Relay::partial`]):
    /// its cancel bills the units the answer stated so far.
    #[must_use]
    pub fn partial(&self) -> bool {
        match &self.state {
            State::Relay { relay, .. } => relay.partial(),
            State::Done => self.ended_partial,
            _ => false,
        }
    }

    /// CUT the answer: the far end's transfer failed (`transport`) or the kernel's ceiling for it
    /// expired, before its last piece.
    pub fn cut(
        &mut self,
        host: &dyn busbar_contract::codec::CodecHost,
        ctx: &ReplyCtx<'_>,
        transport: bool,
    ) -> Piece<'static> {
        match std::mem::replace(&mut self.state, State::Done) {
            State::Done => pending(),
            state @ State::Error { .. } => {
                self.state = state;
                self.judge(host, ctx)
            }
            State::Whole { .. } => {
                let w = whole::cut(host, ctx.arrived.dialect);
                answered(
                    w.answer,
                    Units::default(),
                    Verdict::Hard,
                    Some(Fault::Transient("transport")),
                )
            }
            State::Relay {
                mut relay, head, ..
            } => {
                let cut = relay.cut(host, transport);
                self.ended_partial = cut.partial;
                Piece {
                    head,
                    bytes: Cow::Owned(cut.bytes.unwrap_or_default()),
                    units: Units::of(cut.usage.as_ref(), BTreeMap::new()),
                    verdict: Verdict::Hard,
                    fault: Some(Fault::Transient(cut.reason)),
                    done: true,
                    dropped: Vec::new(),
                    tap_fault: None,
                }
            }
        }
    }

    fn judge<'a>(
        &mut self,
        host: &dyn busbar_contract::codec::CodecHost,
        ctx: &ReplyCtx<'_>,
    ) -> Piece<'a> {
        let State::Error { status, head, body } = std::mem::replace(&mut self.state, State::Done)
        else {
            return pending();
        };
        let pairs: Vec<(&[u8], &[u8])> = head
            .iter()
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
            .collect();
        // A refusal over the invoke envelope is read in its carried dialect's error envelope.
        let body = if ctx.lane.invoke {
            invoke::error_body(&pairs, &body)
        } else {
            body
        };
        let far = failure::FarError {
            status,
            head: &pairs,
            body: &body,
        };
        let j = failure::judge(
            host,
            ctx.arrived.dialect,
            ctx.lane.dialect,
            ctx.arrived.operation,
            &ctx.lane.error_map,
            ctx.passthrough,
            &far,
        );
        let verdict = match j.disposition {
            Disposition::ClientFault => Verdict::Hard,
            Disposition::HardDown
                if j.signal.as_ref().map(|s| s.class) == Some(StatusClass::Auth) =>
            {
                Verdict::Hard
            }
            Disposition::HardDown | Disposition::TransientUpstream | Disposition::ContextLength => {
                Verdict::Retry
            }
        };
        answered(
            j.answer,
            Units::default(),
            verdict,
            Some(Fault::Judged {
                disposition: j.disposition,
                class: j.signal.map(|s| s.class),
            }),
        )
    }
}

fn whole_piece<'a>(
    host: &dyn busbar_contract::codec::CodecHost,
    ctx: &ReplyCtx<'_>,
    status: u16,
    body: &[u8],
    far_head: HeadFields<'_>,
    at: At,
) -> Piece<'a> {
    let mut w = whole::translate(
        host,
        &whole::WholeCtx {
            ingress: ctx.arrived.dialect,
            egress: ctx.lane.dialect,
            operation: ctx.arrived.operation,
            model: &ctx.lane.model,
            wants_stream: ctx.intent.wants_stream,
            json_array: json_array(ctx),
            request: ctx.arrived.parsed.as_ref(),
            now_s: at.now_s,
            elapsed_ms: at.elapsed_ms,
            translate_cap: ctx.translate_cap,
        },
        status,
        body,
    );
    // A same-dialect answer relays the far end's head (its head is empty across dialects).
    wire::relay_far_head(ctx.arrived.dialect, &mut w.answer.fields, far_head);
    let units = Units::of(
        wire::token_usage_of(&w.usage).as_ref(),
        wire::open_units_of(&w.usage),
    );
    let dropped = match w.end {
        whole::WholeEnd::Delivered => std::mem::take(&mut w.dropped),
        _ => Vec::new(),
    };
    let (verdict, fault) = match w.end {
        whole::WholeEnd::Delivered => (Verdict::Ok, None),
        whole::WholeEnd::FailedGeneration => {
            (Verdict::Hard, Some(Fault::Transient(FAILED_GENERATION)))
        }
        whole::WholeEnd::NotTranslatable => {
            (Verdict::Hard, Some(Fault::Transient("untranslatable-2xx")))
        }
        whole::WholeEnd::Cut => (Verdict::Hard, Some(Fault::Transient("transport"))),
        whole::WholeEnd::IngressUnsupported | whole::WholeEnd::OverCap => (Verdict::Hard, None),
    };
    Piece {
        dropped,
        ..answered(w.answer, units, verdict, fault)
    }
}
