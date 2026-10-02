//! A far end's success answer taken whole: a non-stream answer from a far end of another dialect,
//! or one a caller asked to stream from a far end that answered one body. The whole body is read
//! by the far end's dialect and written by the caller's, and the caller reads exactly one of four
//! ends.
//!
//! The previous release's decision tree, in its order: an opaque body (speech audio) bridges at
//! the byte level; a JSON body is translated (and, for a caller that asked to stream, written as
//! the caller's own stream frames); a translated chat answer whose far end reported the generation
//! failed is an error that still carries the usage the far end reported; the caller's dialect
//! serving no such operation is a 404; and anything the caller's dialect cannot be written from is
//! a 500, never the far end's native bytes.

use busbar_contract::billing::Billing;
use busbar_contract::codec::{OperationHandler, TranslatedResponse};
use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::{
    ProtocolDecl, APPLICATION_JSON, KIND_API_ERROR, KIND_NOT_FOUND, TEXT_EVENT_STREAM,
};
use serde_json::Value;

use super::super::attempt::DETAIL_ENDPOINT_UNSUPPORTED_OPERATION;
use super::super::refuse::{render, Rendered};
use super::failure::request_id_field;
use super::wire;
use super::wire::head_field;
use crate::codec::drops;
use crate::codec::translate::{TranslateCodec as _, TranslateRespInput};
use crate::codec::DECLS;

fn decl(name: &str) -> Option<&'static ProtocolDecl> {
    DECLS.iter().copied().find(|d| d.name == name)
}

fn handler(dialect: &str, operation: OpVerb) -> Option<&'static dyn OperationHandler> {
    decl(dialect)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(operation))
}

/// How a whole answer ended for the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WholeEnd {
    /// The caller reads the answer, in its own dialect.
    Delivered,
    /// The far end reported the generation failed: the caller reads a 502, and the usage the far
    /// end reported stands.
    FailedGeneration,
    /// The caller's dialect serves no such operation: a 404, nothing delivered.
    IngressUnsupported,
    /// The caller's dialect cannot be written from the answer: a 500, nothing delivered.
    NotTranslatable,
    /// The body is over the translation cap: our limit, not the far end's fault; a 500, nothing
    /// delivered.
    OverCap,
    /// The far end's body stopped short of its end: a failed transfer; a 502, nothing delivered.
    Cut,
}

/// A whole answer, as the caller reads it.
#[derive(Clone, Debug, PartialEq)]
pub struct Whole {
    /// How it ended.
    pub end: WholeEnd,
    /// What the far end reported it used: set on a delivery and on a failed generation.
    pub usage: Option<Billing>,
    /// What the caller reads.
    pub answer: Rendered,
    /// Why the far end's dialect refused the body, when it did (for the operator's log).
    pub refused: Option<Refusal>,
}

/// The far end's dialect refusing a whole body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The body was opaque (bridged at the byte level) rather than JSON.
    pub opaque: bool,
    /// The codec's own account.
    pub detail: String,
}

/// What of the exchange a whole answer is written for.
#[derive(Clone, Copy, Debug)]
pub struct WholeCtx<'a> {
    /// The caller's dialect.
    pub ingress: &'a str,
    /// The far end's dialect.
    pub egress: &'a str,
    /// The operation.
    pub operation: OpVerb,
    /// The model's configured name (a translated answer that names none reports it).
    pub model: &'a str,
    /// The caller asked for a stream.
    pub wants_stream: bool,
    /// The caller's stream is a JSON array rather than server-sent events.
    pub json_array: bool,
    /// The caller's request, when it was JSON (a dialect whose answer mirrors request members
    /// reads them here).
    pub request: Option<&'a Value>,
    /// Wall-clock seconds, for a translated answer's creation stamp.
    pub now_s: u64,
    /// Milliseconds from the attempt's start, for a dialect whose answer reports its latency.
    pub elapsed_ms: Option<u64>,
}

/// The caller's error for an answer that could not be relayed.
fn internal(ingress: &str, status: u16) -> Rendered {
    render(
        ingress,
        status,
        KIND_API_ERROR,
        wire::GENERIC_RESPONSE_ERROR_DETAIL,
        0,
    )
}

/// A delivered answer: the far end's status, the content type, the caller's request id.
fn delivered(ctx: &WholeCtx<'_>, status: u16, content_type: &[u8], body: Vec<u8>) -> Rendered {
    let mut fields = vec![("content-type".to_string(), content_type.to_vec())];
    fields.extend(request_id_field(ctx.ingress, &[]));
    Rendered {
        status,
        fields,
        body,
    }
}

fn whole(end: WholeEnd, usage: Option<Billing>, answer: Rendered) -> Whole {
    Whole {
        end,
        usage,
        answer,
        refused: None,
    }
}

/// The body over the translation cap: our limit, not the far end's fault, and nothing delivered.
#[must_use]
pub fn over_cap(ingress: &str) -> Whole {
    whole(WholeEnd::OverCap, None, internal(ingress, 500))
}

/// The far end's body stopped short of its end: a failed transfer, nothing delivered.
#[must_use]
pub fn cut(ingress: &str) -> Whole {
    whole(WholeEnd::Cut, None, internal(ingress, 502))
}

/// TRANSLATE A WHOLE ANSWER: the far end's 2xx `status` and its whole body.
#[must_use]
pub fn translate(ctx: &WholeCtx<'_>, status: u16, bytes: &[u8]) -> Whole {
    let egress_op = handler(ctx.egress, ctx.operation);
    let ingress_serves = handler(ctx.ingress, ctx.operation).is_some();
    let body_json = crate::codec::json::parse::<Value>(bytes);
    let mut refused = None;
    if body_json.is_err() {
        match opaque(ctx, status, egress_op, ingress_serves, bytes) {
            Ok(Some(w)) => return w,
            Ok(None) => {}
            Err(detail) => {
                refused = Some(Refusal {
                    opaque: true,
                    detail,
                })
            }
        }
    }
    if let (Ok(rv), Some(eh)) = (&body_json, egress_op) {
        if decl(ctx.ingress).is_some_and(|d| d.codec.is_some()) {
            match json(ctx, status, eh, ingress_serves, rv) {
                Ok(Some(w)) => return w,
                Ok(None) => {}
                Err(detail) => {
                    refused = Some(Refusal {
                        opaque: false,
                        detail,
                    })
                }
            }
        }
    }
    Whole {
        refused,
        ..whole(WholeEnd::NotTranslatable, None, internal(ctx.ingress, 500))
    }
}

/// An opaque body bridged at the byte level; `None` falls through to the JSON path, `Err` is the
/// far end's dialect refusing the body.
fn opaque(
    ctx: &WholeCtx<'_>,
    status: u16,
    egress_op: Option<&'static dyn OperationHandler>,
    ingress_serves: bool,
    bytes: &[u8],
) -> Result<Option<Whole>, String> {
    let Some(eh) = egress_op else {
        return Ok(None);
    };
    let (usage, answered) = eh
        .translate_response(
            TranslateRespInput::Opaque(bytes),
            ingress_serves,
            ctx.ingress,
            ctx.model,
            ctx.now_s,
            false,
            None,
            ctx.request,
        )
        .map_err(|e| format!("{e:?}"))?;
    let TranslatedResponse::Typed(wire) = answered else {
        return Ok(None);
    };
    Ok(Some(whole(
        WholeEnd::Delivered,
        usage,
        delivered(
            ctx,
            status,
            wire.content_type.as_bytes(),
            wire.bytes.as_slice().to_vec(),
        ),
    )))
}

/// A JSON body translated; `None` when no body could be written, `Err` the far end's dialect
/// refusing the body.
fn json(
    ctx: &WholeCtx<'_>,
    status: u16,
    eh: &dyn OperationHandler,
    ingress_serves: bool,
    rv: &Value,
) -> Result<Option<Whole>, String> {
    let read = || {
        let answered = eh.translate_response(
            TranslateRespInput::Json(rv),
            ingress_serves,
            ctx.ingress,
            ctx.model,
            ctx.now_s,
            ctx.wants_stream && !ctx.json_array,
            ctx.elapsed_ms,
            ctx.request,
        );
        if answered.is_ok() {
            crate::codec::dialect::drop_untranslatable_response_metadata(ctx.egress, rv);
            crate::codec::proto_codec::with_reader(ctx.egress, |r| {
                drops::note_unmodelled_blocks(
                    r.response_blocks(),
                    rv,
                    drops::UNMODELLED_ANSWER_BLOCK,
                )
            });
        }
        answered
    };
    // A translate attempt's drops go through the one drop path; a same-dialect answer drops
    // nothing.
    let answered = if ctx.ingress == ctx.egress {
        read()
    } else {
        let seam = drops::Seam {
            direction: drops::Direction::Response,
            ingress: ctx.ingress,
            egress: ctx.egress,
        };
        drops::scope(seam, read).0
    };
    let (usage, answered) = answered.map_err(|e| format!("{e:?}"))?;
    let delivers = matches!(
        answered,
        TranslatedResponse::StreamFrames(_)
            | TranslatedResponse::Typed(_)
            | TranslatedResponse::Json(_)
    );
    if delivers && ctx.operation == OpVerb::CHAT && wire::generation_failed(ctx.egress, rv) {
        return Ok(Some(whole(
            WholeEnd::FailedGeneration,
            usage,
            internal(ctx.ingress, 502),
        )));
    }
    Ok(Some(match answered {
        TranslatedResponse::StreamFrames(frames) => {
            let ct = wire::ingress_stream_content_type(ctx.ingress).unwrap_or(TEXT_EVENT_STREAM);
            whole(
                WholeEnd::Delivered,
                usage,
                delivered(ctx, status, ct.as_bytes(), frames),
            )
        }
        TranslatedResponse::IngressUnsupported => whole(
            WholeEnd::IngressUnsupported,
            None,
            render(
                ctx.ingress,
                404,
                KIND_NOT_FOUND,
                DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
                0,
            ),
        ),
        TranslatedResponse::Typed(wire) => whole(
            WholeEnd::Delivered,
            usage,
            delivered(
                ctx,
                status,
                wire.content_type.as_bytes(),
                wire.bytes.as_slice().to_vec(),
            ),
        ),
        TranslatedResponse::Json(mut translated) => {
            if let Some(dialect) = decl(ctx.ingress).and_then(|d| d.dialect()) {
                dialect.inject_response_metrics(&mut translated, ctx.elapsed_ms);
            }
            let answer = if ctx.json_array && ctx.wants_stream {
                let arr = Value::Array(vec![translated]);
                let body = crate::codec::json::to_vec(&arr)
                    .unwrap_or_else(|_| arr.to_string().into_bytes());
                Rendered {
                    status,
                    fields: head_field("content-type", APPLICATION_JSON.as_bytes())
                        .into_iter()
                        .collect(),
                    body,
                }
            } else {
                let body = crate::codec::json::to_vec(&translated)
                    .unwrap_or_else(|_| translated.to_string().into_bytes());
                delivered(ctx, status, APPLICATION_JSON.as_bytes(), body)
            };
            whole(WholeEnd::Delivered, usage, answer)
        }
        TranslatedResponse::Untranslatable => return Ok(None),
    }))
}
