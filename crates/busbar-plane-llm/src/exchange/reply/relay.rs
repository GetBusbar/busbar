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
use busbar_contract::codec::{OperationHandler, UsageTapFault};
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
    /// Why the usage tap could not read a same-dialect whole body (only when metering): returned
    /// as data for the kernel to count, never reported from here (row 155).
    pub tap_fault: Option<UsageTapFault>,
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
}

/// THE RELAY of one far-end success answer.
pub struct Relay {
    ingress: &'static str,
    ingress_eventstream: bool,
    far_is_stream: bool,
    handler: &'static dyn OperationHandler,
    meter: bool,
    translate_cap: usize,
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
    /// The TRANSLATION CAP the plane enforces, the one its settings carry: the bound on the
    /// same-dialect copy kept for usage, and on what the translator's writer accumulates.
    pub translate_cap: usize,
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
/// A stream the translator times (a Bedrock caller's `metrics.latencyMs`) is timed on the host's
/// one clock, the codec host each `feed` is handed, never on a clock of the plane's own.
#[must_use]
pub fn parts(ctx: &RelayCtx<'_>) -> Parts {
    let translate = crate::codec::proto_stream::new_stream_translator_on(
        ctx.ingress,
        ctx.egress,
        ctx.far_is_stream,
        ctx.translate_cap,
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
        let (translate, json_array) = parts(&ctx);
        Self::from_parts(
            ctx.ingress,
            ctx.far_is_stream,
            ctx.handler,
            ctx.meter,
            ctx.translate_cap,
            translate,
            json_array,
        )
    }

    /// OPEN the relay over a translator and a framer already made (see [`parts`]), its same-dialect
    /// usage copy bounded at the plane's `translate_cap`.
    #[must_use]
    pub fn from_parts(
        ingress: &str,
        far_is_stream: bool,
        handler: &'static dyn OperationHandler,
        meter: bool,
        translate_cap: usize,
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
            translate_cap,
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
    pub fn feed<'a>(
        &mut self,
        host: &dyn busbar_contract::codec::CodecHost,
        chunk: &'a [u8],
    ) -> (Fed<'a>, bool) {
        self.first_byte = true;
        self.upstream_bytes = self.upstream_bytes.saturating_add(chunk.len());
        if let Some(t) = self.translate.as_mut() {
            let out = t.feed(host, chunk);
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
            let cap = self.translate_cap;
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
    pub fn end(&mut self, host: &dyn busbar_contract::codec::CodecHost) -> End {
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
            .map(|t| t.finish(host))
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
        let mut tap_fault = None;
        let usage = if !self.meter {
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
                // A body past the usage tap's cap bills no tokens, as 1.5.5 billed none: it kept
                // only the body's first `cap` bytes, whose reading found no usage, and warned that
                // the request was undercounted (v1.5.5 proxy/response_body.rs:230-262).
                None
            } else {
                let tapped = self.handler.extract_usage(host, self.ingress, &buf);
                tap_fault = tapped.as_ref().err().copied();
                tapped.ok().flatten().or_else(|| {
                    match self.handler.read_response(host, &buf) {
                        Ok(read) => {
                            open_billing = read.billing();
                            None
                        }
                        // A JSON body that stops short of its end is one the far end CUT (its
                        // transfer failed before its last byte): it bills only the usage the far
                        // end reported in the bytes in hand, never the floor (OWNER RULING Q31,
                        // oracle cell `route.failover|fo|primary-cut-body`).
                        Err(_) if cut_short(&buf) => wire::reported_usage(self.ingress, &buf),
                        // A body whose dialect reads it as a failure the FAR END REPORTED (a
                        // Responses `status: "failed"`) bills no tokens, as 1.5.5 billed none: its
                        // usage tap read nothing from a body its reader refused (v1.5.5
                        // handlers/chat.rs:60-98, `read_response` failed -> 0 tokens), and its
                        // streamed twin bills none either (row-159 L3#4). ARCHITECT ruling
                        // 2026-10-15; owner answer Q37 is unsigned and does not override 1.5.5.
                        Err(_) if far_reported_failure(host, self.ingress, &buf) => None,
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
            tap_fault,
        }
    }

    /// CUT the relay: the far end's transport failed (`transport`), or the stream's ceiling
    /// expired.
    pub fn cut(&mut self, host: &dyn busbar_contract::codec::CodecHost, transport: bool) -> Cut {
        let had_first = self.first_byte;
        if had_first && self.far_is_stream {
            let usage = self.translate.as_ref().and_then(|t| t.usage());
            let bytes = match self.json_array.as_mut() {
                Some(framer) => framer.finish_with_server_error(wire::MID_STREAM_GENERIC_DETAIL),
                None => wire::mid_stream_error_bytes(
                    host,
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
        }
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

    /// THE STREAM'S TERMINAL ERROR IS ITS FAR END'S FAILED GENERATION: the far dialect's own stop
    /// token that reads as a failed generation (a Gemini `MALFORMED_FUNCTION_CALL`, a Cohere
    /// `ERROR`), which its reader surfaces as an error beside the usage it reports (owner ruling
    /// Q31). 1.5.5's readers raised no error for those stops, so 1.5.5 billed the usage the stream
    /// reported (v1.5.5 `proxy/response_body.rs:550-575`: only a reader-emitted terminal error
    /// skipped the token fee) — and Q31 keeps that charge. Every other terminal error is one 1.5.5
    /// raised too, and bills no tokens. `far` is the far end's dialect.
    #[must_use]
    pub fn failed_generation(&self, far: &str) -> bool {
        self.translate
            .as_ref()
            .and_then(|t| t.terminal_error())
            .is_some_and(|signal| {
                crate::codec::proto_codec::with_reader(far, |r| r.stop_reason_of_token(signal))
                    .flatten()
                    == Some(crate::codec::ir::IrStopReason::Error)
            })
    }

    /// The usage a stream's readers have read so far (cheap: nothing is scanned); `None` for a
    /// relay that reads its usage only at the end.
    #[must_use]
    pub fn streamed_usage(&self) -> Option<TokenUsage> {
        self.translate.as_ref().and_then(|t| t.usage())
    }

    /// The usage an answer that ended early had incurred: what a stream's readers accumulated;
    /// for a same-dialect whole body the FAR END cut, only the usage the bytes in hand report
    /// (OWNER RULING Q31, never a floor). A same-dialect whole body that ended early any other way
    /// (its caller left mid-body) incurred none: 1.5.5 billed no tokens on a mid-buffer drop
    /// (v1.5.5 proxy/response_body.rs:620-625), and no floor is added for it (#77(2); ARCHITECT
    /// ruling 2026-10-15 retired item 367's relayed floor, Q33 (a), which was told, never signed).
    #[must_use]
    pub fn incurred_usage(&self) -> Option<TokenUsage> {
        match self.translate.as_ref() {
            Some(t) => t.usage(),
            None if self.upstream_failed
                && !self.far_is_stream
                && !self.nonstream_buf.is_empty()
                && !self.nonstream_buf_truncated =>
            {
                wire::reported_usage(self.ingress, &self.nonstream_buf)
            }
            None => None,
        }
    }
}

/// THE FAR END REPORTED THE FAILURE ITSELF: the whole body reads, in its dialect's own reader, as a
/// failure the far end stated (a Responses `status: "failed"`), not as a body the reader could not
/// read (`ir_parse`: bad JSON, a shape it does not know, or a usage count it refuses, #42).
fn far_reported_failure(
    host: &dyn busbar_contract::codec::CodecHost,
    protocol: &str,
    buf: &[u8],
) -> bool {
    let Ok(v) = crate::codec::json::parse::<Value>(buf) else {
        return false;
    };
    crate::codec::proto_codec::protocol_for(protocol).is_some_and(|p| {
        p.reader().read_response(host, &v).is_err_and(|e| {
            e.provider_signal.as_deref() != Some(busbar_contract::protocol::SIGNAL_IR_PARSE)
        })
    })
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
