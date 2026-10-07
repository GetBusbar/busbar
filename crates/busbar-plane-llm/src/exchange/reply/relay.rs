//! A far end's success answer relayed as it arrives: a stream (server-sent events or a binary event
//! stream), or a same-dialect whole body relayed verbatim. Each far-end piece becomes the caller's
//! bytes as soon as it completes a frame; the far end's usage is read as the bytes go by.
//!
//! The previous release's streamed-answer steps, in their order: the translator the pair of
//! dialects names reframes (and, within one dialect, re-emits byte-exact while it reads usage),
//! the JSON-array framer wraps the frames for a caller that asked for an array, a same-dialect
//! whole body relays untouched while a bounded tail-anchored copy is kept for its usage and its
//! stop reason is located incrementally, the end emits the caller's terminator and reads the
//! usage, and a cut ends the caller's stream on an in-band error in its own framing.

use std::borrow::Cow;
use std::collections::BTreeMap;

use busbar_contract::billing::{Billing, TokenUsage};
use busbar_contract::codec::OperationHandler;
use busbar_contract::protocol::{ArrayStreamFramer, ProtocolDecl, StreamTranslator};
use serde_json::Value;

use super::wire;
use crate::codec::usage_tail::StopKeyScanner;
use crate::codec::DECLS;

fn decl(name: &str) -> Option<&'static ProtocolDecl> {
    DECLS.iter().copied().find(|d| d.name == name)
}

/// Where a relayed answer's content type comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    /// `application/json`: a stream reframed into a JSON array.
    Json,
    /// The caller's own content type for a streamed answer: a stream reframed across dialects.
    Ingress(&'static str),
    /// The far end's content type, as it arrived (or none when it sent none).
    Far,
}

/// Whether the far end's success answer is taken whole rather than relayed: a non-stream answer
/// that crosses dialects. Within one dialect the answer is relayed as the far end sent it, a
/// stream-asked, body-answered reply included (DIALECT FIDELITY, owner 2026-10-02).
#[must_use]
pub fn takes_whole(ingress: &str, egress: &str, far_is_stream: bool) -> bool {
    !far_is_stream && ingress != egress
}

/// The content type a relayed answer wears.
#[must_use]
pub fn content_type(
    ingress: &str,
    egress: &str,
    far_is_stream: bool,
    json_array: bool,
) -> ContentType {
    if json_array && far_is_stream {
        return ContentType::Json;
    }
    match (ingress != egress && far_is_stream)
        .then(|| wire::ingress_stream_content_type(ingress))
        .flatten()
    {
        Some(ct) => ContentType::Ingress(ct),
        None => ContentType::Far,
    }
}

/// What one far-end piece became.
#[derive(Debug, PartialEq, Eq)]
pub enum Fed<'a> {
    /// The caller reads these bytes (the far end's own, borrowed, when relayed untouched).
    Bytes(Cow<'a, [u8]>),
    /// No complete frame yet.
    Nothing,
}

/// How a relayed answer ended cleanly.
#[derive(Debug, PartialEq)]
pub struct End {
    /// The caller's terminator and any deferred frames.
    pub bytes: Vec<u8>,
    /// The far end's stream failed after the caller had bytes (its reader saw a terminal error, or
    /// the reframing gave up): the reason the far end's standing records, once.
    pub stream_fault: Option<&'static str>,
    /// A same-dialect whole body whose own stop reason says the generation failed.
    pub generation_failed: bool,
    /// The answer ended in an error rather than a completion.
    pub failed: bool,
    /// The token usage (only when metering).
    pub usage: Option<TokenUsage>,
    /// Every open class the body counted beside its tokens (only when metering).
    pub open_units: BTreeMap<String, u64>,
    /// The far-end wire paths a translated stream dropped (design F3 "Drops"), each warned once:
    /// the host records one audit row per path.
    pub dropped: Vec<String>,
    /// The translator gave up ([`Relay::translate_aborted`]): nothing of the answer bills, so
    /// `usage` and `open_units` are empty and the end states its counts as zero.
    pub withheld: bool,
}

/// How a relayed answer was cut: by the far end's transport, or by the stream's ceiling.
#[derive(Debug, PartialEq)]
pub struct Cut {
    /// The caller's in-band error, for a stream cut after its first byte; `None` ends the caller's
    /// body without one.
    pub bytes: Option<Vec<u8>>,
    /// The reason the far end's standing records.
    pub reason: &'static str,
    /// The caller had bytes: the answer is partial rather than failed.
    pub partial: bool,
    /// The usage the answer had incurred up to the cut.
    pub usage: Option<TokenUsage>,
    /// The translator gave up before the cut ([`Relay::translate_aborted`]): nothing of the answer
    /// bills, so `usage` is `None` and the cut states its counts as zero.
    pub withheld: bool,
}

/// THE RELAY of one far-end success answer.
pub struct Relay {
    ingress: &'static str,
    ingress_eventstream: bool,
    far_is_stream: bool,
    handler: &'static dyn OperationHandler,
    meter: bool,
    translate: Option<Box<dyn StreamTranslator>>,
    json_array: Option<Box<dyn ArrayStreamFramer>>,
    nonstream_buf: Vec<u8>,
    nonstream_buf_truncated: bool,
    stop_scan: Option<StopKeyScanner>,
    upstream_bytes: usize,
    upstream_failed: bool,
    first_byte: bool,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("ingress", &self.ingress)
            .field("far_is_stream", &self.far_is_stream)
            .field("translates", &self.translate.is_some())
            .field("first_byte", &self.first_byte)
            .finish_non_exhaustive()
    }
}

/// What a relay is opened with.
#[derive(Clone, Copy)]
pub struct RelayCtx<'a> {
    /// The caller's dialect.
    pub ingress: &'a str,
    /// The far end's dialect.
    pub egress: &'a str,
    /// The far end answered a stream.
    pub far_is_stream: bool,
    /// The caller asked for its stream as a JSON array.
    pub json_array: bool,
    /// The caller asked for usage in the stream itself.
    pub client_include_usage: bool,
    /// The caller's request, when it was JSON (a dialect whose stream mirrors request members
    /// reads them).
    pub request: Option<&'a Value>,
    /// The caller's operation, as the caller's dialect serves it.
    pub handler: &'static dyn OperationHandler,
    /// Read the usage: keep the bounded copy of a same-dialect whole body and read the usage at
    /// the end. Off, the bytes relay and nothing is read for usage.
    pub meter: bool,
}

/// A relay's translator and JSON-array framer, before the relay is opened over them.
pub type Parts = (
    Option<Box<dyn StreamTranslator>>,
    Option<Box<dyn ArrayStreamFramer>>,
);

/// The translator the pair of dialects names for a far end's answer (a stream reframed across
/// dialects, or re-emitted byte-exact within one),
/// told the caller's usage opt-in and request; and the JSON-array framer for a caller that asked
/// for its stream as an array.
#[must_use]
pub fn parts(ctx: &RelayCtx<'_>) -> Parts {
    parts_on(ctx, std::time::Instant::now)
}

/// [`parts`], the stream timed on `clock` (a Bedrock caller's `metrics.latencyMs`): a proof that
/// relays one stream twice and compares the bytes hands both relays one clock.
#[must_use]
pub fn parts_on(ctx: &RelayCtx<'_>, clock: fn() -> std::time::Instant) -> Parts {
    let translate = crate::codec::proto_stream::new_stream_translator_on(
        ctx.ingress,
        ctx.egress,
        ctx.far_is_stream,
        clock,
    )
    .map(|mut t| {
        t.set_client_include_usage(ctx.client_include_usage);
        if let Some(body) = ctx.request {
            t.set_request_echo(body);
        }
        t
    });
    let json_array = (ctx.json_array && ctx.far_is_stream)
        .then(|| {
            decl(ctx.ingress)
                .and_then(|d| d.dialect())
                .and_then(|dc| dc.make_array_stream_framer())
        })
        .flatten();
    (translate, json_array)
}

impl Relay {
    /// OPEN the relay.
    #[must_use]
    pub fn new(ctx: RelayCtx<'_>) -> Self {
        Self::new_on(ctx, std::time::Instant::now)
    }

    /// OPEN the relay, its stream timed on `clock` ([`parts_on`]).
    #[must_use]
    pub fn new_on(ctx: RelayCtx<'_>, clock: fn() -> std::time::Instant) -> Self {
        let (translate, json_array) = parts_on(&ctx, clock);
        Self::from_parts(
            ctx.ingress,
            ctx.far_is_stream,
            ctx.handler,
            ctx.meter,
            translate,
            json_array,
        )
    }

    /// OPEN the relay over a translator and a framer already made (see [`parts`]).
    #[must_use]
    pub fn from_parts(
        ingress: &str,
        far_is_stream: bool,
        handler: &'static dyn OperationHandler,
        meter: bool,
        translate: Option<Box<dyn StreamTranslator>>,
        json_array: Option<Box<dyn ArrayStreamFramer>>,
    ) -> Self {
        let ingress_decl = decl(ingress);
        let stop_scan = (!far_is_stream && translate.is_none())
            .then(|| {
                crate::codec::proto_codec::with_reader(ingress, |r| r.stop_reason_key())
                    .flatten()
                    .and_then(StopKeyScanner::new)
            })
            .flatten();
        Relay {
            ingress: ingress_decl
                .map(|d| d.name)
                .or_else(|| DECLS.iter().find(|d| d.residual_default).map(|d| d.name))
                .unwrap_or_default(),
            ingress_eventstream: ingress_decl.is_some_and(|d| d.ingress_is_eventstream),
            far_is_stream,
            handler,
            meter,
            translate,
            json_array,
            nonstream_buf: Vec::new(),
            nonstream_buf_truncated: false,
            stop_scan,
            upstream_bytes: 0,
            upstream_failed: false,
            first_byte: false,
        }
    }

    /// The caller's dialect, as the relay frames its errors (the residual dialect for one the
    /// plane does not hold).
    #[must_use]
    pub fn ingress(&self) -> &'static str {
        self.ingress
    }

    /// The far end answered a stream.
    #[must_use]
    pub fn far_is_stream(&self) -> bool {
        self.far_is_stream
    }

    /// A far-end byte has arrived.
    #[must_use]
    pub fn had_first(&self) -> bool {
        self.first_byte
    }

    /// FEED one far-end piece. The second value is `true` on the one piece that first pushed the
    /// retained copy of a same-dialect whole body over the cap (its head is dropped from then on).
    pub fn feed<'a>(&mut self, chunk: &'a [u8]) -> (Fed<'a>, bool) {
        self.first_byte = true;
        self.upstream_bytes = self.upstream_bytes.saturating_add(chunk.len());
        if let Some(t) = self.translate.as_mut() {
            let out = t.feed(chunk);
            if let Some(framer) = self.json_array.as_mut() {
                let framed = framer.feed(&out);
                return (bytes_or_nothing(framed), false);
            }
            return (bytes_or_nothing(out), false);
        }
        if let Some(scan) = self.stop_scan.as_mut() {
            scan.feed(chunk);
        }
        let mut truncated_now = false;
        if !self.far_is_stream && self.handler.taps_usage() && self.meter {
            let cap = crate::codec::wire_shim::max_translated_body_bytes();
            self.nonstream_buf.extend_from_slice(chunk);
            if self.nonstream_buf.len() > cap {
                let excess = self.nonstream_buf.len() - cap;
                self.nonstream_buf.drain(..excess);
                if !self.nonstream_buf_truncated {
                    self.nonstream_buf_truncated = true;
                    truncated_now = true;
                }
            }
        }
        if let Some(framer) = self.json_array.as_mut() {
            let framed = framer.feed(chunk);
            return (bytes_or_nothing(framed), truncated_now);
        }
        (Fed::Bytes(Cow::Borrowed(chunk)), truncated_now)
    }

    /// END the relay cleanly: the far end's body is complete.
    pub fn end(&mut self) -> End {
        let translate_aborted = self.translate.as_ref().is_some_and(|t| t.aborted());
        let stream_terminal_error = self
            .translate
            .as_ref()
            .and_then(|t| t.terminal_error())
            .is_some();
        let stream_fault =
            (self.far_is_stream && self.first_byte)
                .then_some(())
                .and(if stream_terminal_error {
                    Some("stream-terminal-error")
                } else if translate_aborted {
                    Some("stream-translate-abort")
                } else {
                    None
                });
        let tail = self
            .translate
            .as_mut()
            .map(|t| t.finish())
            .unwrap_or_default();
        let bytes = if let Some(framer) = self.json_array.as_mut() {
            let mut wrapped = if translate_aborted {
                Vec::new()
            } else {
                framer.feed(&tail)
            };
            wrapped.extend_from_slice(&framer.finish_for_translate(translate_aborted));
            wrapped
        } else {
            tail
        };
        let generation_failed = self
            .stop_scan
            .as_ref()
            .and_then(|scan| scan.token())
            .and_then(|token| {
                crate::codec::proto_codec::with_reader(self.ingress, |r| {
                    r.stop_reason_of_token(token)
                })
                .flatten()
            })
            == Some(crate::codec::ir::IrStopReason::Error);
        let mut open_billing: Option<Billing> = None;
        let usage = if !self.meter || translate_aborted {
            None
        } else if let Some(t) = self.translate.as_ref() {
            open_billing = t.open_billing();
            if t.terminal_error() == Some(busbar_contract::protocol::SIGNAL_IR_PARSE) {
                fault_unreadable(self.ingress, self.upstream_bytes);
                Some(wire::estimate_usage_from_truncated_tail(
                    self.upstream_bytes,
                ))
            } else {
                t.usage()
            }
        } else if !self.far_is_stream && !self.nonstream_buf.is_empty() {
            let buf = std::mem::take(&mut self.nonstream_buf);
            if self.nonstream_buf_truncated {
                Some(wire::unrecovered_usage(self.ingress, &buf))
            } else {
                self.handler.extract_usage(self.ingress, &buf).or_else(|| {
                    match self.handler.read_response(&buf) {
                        Ok(read) => {
                            open_billing = read.billing();
                            None
                        }
                        // A JSON body that stops short of its end is one the far end CUT (its
                        // transfer failed before its last byte): it bills only the usage the far
                        // end reported in the bytes in hand, never the floor (OWNER RULING Q31,
                        // oracle cell `route.failover|fo|primary-cut-body`).
                        Err(_) if cut_short(&buf) => wire::reported_usage(self.ingress, &buf),
                        Err(_) => {
                            fault_unreadable(self.ingress, buf.len());
                            Some(wire::unrecovered_usage(self.ingress, &buf))
                        }
                    }
                })
            }
        } else {
            None
        };
        let failed = self
            .translate
            .as_ref()
            .and_then(|t| t.terminal_error())
            .is_some()
            || translate_aborted
            || generation_failed;
        End {
            bytes,
            stream_fault,
            generation_failed,
            failed,
            usage,
            open_units: wire::open_units_of(&open_billing),
            dropped: self
                .translate
                .as_ref()
                .map(|t| t.dropped())
                .unwrap_or_default(),
            withheld: translate_aborted,
        }
    }

    /// CUT the relay: the far end's transport failed (`transport`), or the stream's ceiling
    /// expired.
    pub fn cut(&mut self, transport: bool) -> Cut {
        let had_first = self.first_byte;
        let withheld = self.translate_aborted();
        if had_first && self.far_is_stream {
            let usage = self.streamed_usage();
            let bytes = match self.json_array.as_mut() {
                Some(framer) => framer.finish_with_server_error(wire::MID_STREAM_GENERIC_DETAIL),
                None => wire::mid_stream_error_bytes(
                    self.ingress,
                    self.ingress_eventstream,
                    wire::MID_STREAM_GENERIC_DETAIL,
                    self.translate.as_deref_mut(),
                ),
            };
            return Cut {
                bytes: Some(bytes),
                reason: "mid-stream",
                partial: true,
                usage,
                withheld,
            };
        }
        self.upstream_failed = had_first && transport;
        Cut {
            bytes: None,
            reason: if had_first {
                "mid-body-transport"
            } else {
                "pre-first-byte-transport"
            },
            partial: had_first,
            usage: self.incurred_usage(),
            withheld,
        }
    }

    /// THE TRANSLATOR GAVE UP on the far end's stream: busbar failed to produce the caller's answer,
    /// which is not a cut, so nothing of it bills, however the answer then ends (at the far end's
    /// end, on a cut, or by a caller who leaves). 1.5.5's rule: its stream end billed nothing for an
    /// aborted translate (v1.5.5 `crates/busbar/src/proxy/response_body.rs:563-575`,
    /// `billing_failed`) and neither did its drop arm (`:641-647`); ARCHITECT RULING U11 Q2
    /// 2026-10-06.
    #[must_use]
    pub fn translate_aborted(&self) -> bool {
        self.translate.as_ref().is_some_and(|t| t.aborted())
    }

    /// THE CALLER HAD A USABLE PART: a byte of the answer was relayed and nothing failed it (no
    /// reader's terminal error, no translate abort), so a caller that leaves now leaves a partial
    /// answer whose incurred units bill (v1.5.5 `FirstByteBody`'s drop arm).
    #[must_use]
    pub fn partial(&self) -> bool {
        self.first_byte
            && !self
                .translate
                .as_ref()
                .is_some_and(|t| t.aborted() || t.terminal_error().is_some())
    }

    /// The usage a stream's readers have read so far (cheap: nothing is scanned); `None` for a
    /// relay that reads its usage only at the end, and once the translator gave up (nothing of the
    /// answer bills: [`Self::translate_aborted`]).
    #[must_use]
    pub fn streamed_usage(&self) -> Option<TokenUsage> {
        self.translate
            .as_ref()
            .filter(|t| !t.aborted())
            .and_then(|t| t.usage())
    }

    /// THE FLOOR A NON-STREAM SAME-DIALECT ANSWER HAS INCURRED SO FAR, as it relays: it was
    /// generated whole before its first byte, so a caller that leaves mid-relay bills the floor
    /// over the bytes relayed, never 0 (item 367, Q33 (a), told; #62 applied to buffered relays).
    /// `None` for a stream, a translated answer, or one that meters nothing.
    #[must_use]
    pub fn relayed_floor(&self) -> Option<TokenUsage> {
        (self.translate.is_none()
            && !self.far_is_stream
            && self.meter
            && self.handler.taps_usage()
            && self.upstream_bytes > 0)
            .then(|| wire::estimate_usage_from_truncated_tail(self.upstream_bytes))
    }

    /// The usage an answer that ended early had incurred: what a stream's readers accumulated;
    /// for a same-dialect whole body, the usage the bytes in hand report, else the floor over them
    /// (a failed far-end transfer bills only what the far end reported, never the floor).
    #[must_use]
    pub fn incurred_usage(&self) -> Option<TokenUsage> {
        match self.translate.as_ref() {
            Some(_) => self.streamed_usage(),
            None if self.far_is_stream || self.nonstream_buf.is_empty() => None,
            None if self.upstream_failed => wire::reported_usage(self.ingress, &self.nonstream_buf),
            None => Some(wire::unrecovered_usage(self.ingress, &self.nonstream_buf)),
        }
    }
}

/// A JSON body that ends before its value does: the far end's transfer stopped short.
fn cut_short(buf: &[u8]) -> bool {
    serde_json::from_slice::<serde::de::IgnoredAny>(buf).is_err_and(|e| e.is_eof())
}

fn bytes_or_nothing<'a>(out: Vec<u8>) -> Fed<'a> {
    if out.is_empty() {
        Fed::Nothing
    } else {
        Fed::Bytes(Cow::Owned(out))
    }
}

/// The fault an unreadable usage raises: it is billed (the floor), and it is still a fault.
fn fault_unreadable(protocol: &str, delivered: usize) {
    busbar_contract::diag_warn!(
        busbar_contract::diagnostic::USAGE_TAP_DECODE_FAILED,
        protocol,
        delivered,
        "usage is present but unreadable on a delivered response; billing the floor estimate, \
         never 0"
    );
}
