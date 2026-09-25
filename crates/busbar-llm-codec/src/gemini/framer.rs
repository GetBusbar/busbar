//! The Gemini JSON-array stream framer (`:streamGenerateContent` without `?alt=sse`).

use super::*;

/// Re-frame a Gemini SSE response stream as the JSON-ARRAY streaming format a native
/// `:streamGenerateContent` request WITHOUT `?alt=sse` expects: a leading `[`, the per-chunk
/// `GenerateContentResponse` JSON objects separated by `,`, and a trailing `]`. (The SSE variant —
/// `?alt=sse` — emits `data:`-framed chunks instead; busbar always requests `?alt=sse` UPSTREAM, so
/// the bytes reaching this framer are Gemini SSE frames either way, whether the egress is gemini
/// same-protocol passthrough or a cross-protocol `StreamTranslate` whose ingress writer is gemini.)
///
/// This framer is the JSON-array sibling of [`StreamTranslate`]'s SSE path: it consumes the SSE
/// bytes (already in the gemini ingress wire shape), strips the `data:` framing, and re-emits the
/// payloads as one streaming JSON array. The output is ALWAYS a syntactically valid JSON array
/// (`finish` emits `]`, or `[]` when no chunk was seen) so a client that buffers and `JSON.parse`s
/// the whole body still succeeds.
pub struct GeminiJsonArrayFramer {
    buf: Vec<u8>,
    /// How far into `buf` the SSE terminator scan has already advanced (keeps `feed` linear; mirrors
    /// `StreamTranslate::scanned`).
    scanned: usize,
    /// Whether the opening `[` (and, for every object after the first, the separating `,`) has been
    /// emitted yet.
    started: bool,
    /// Set once `finish` has emitted the closing `]`, so a second `finish` is a no-op.
    finished: bool,
    /// Abandon the stream if the reassembly buffer grows past the cap with no complete frame.
    aborted: bool,
}

impl Default for GeminiJsonArrayFramer {
    fn default() -> Self {
        Self::new()
    }
}

impl GeminiJsonArrayFramer {
    // `pub(crate)` so the framer's tests in `mod.rs` (which exercise the buffer-overflow abort path)
    // can size a payload off the cap; it stays an internal cap, not part of the wire surface.
    pub const MAX_BUF: usize = busbar_substrate_values::eventstream::MAX_FRAME_BYTES;

    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            scanned: 0,
            started: false,
            finished: false,
            aborted: false,
        }
    }

    /// Feed a chunk of GEMINI SSE bytes; return JSON-array bytes for whatever complete SSE frames are
    /// now available (empty if only a partial frame is buffered, or if the buffered frames carried no
    /// data payload yet). Each emitted object is preceded by `[` (first) or `,` (subsequent).
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.aborted || self.finished {
            return Vec::new();
        }
        self.buf.extend_from_slice(chunk);
        let mut out: Vec<u8> = Vec::new();
        // FRONT cursor (mirrors `StreamTranslate::feed`): advance `consumed` per complete frame and
        // reclaim the prefix in ONE shift after the loop, instead of `drain(..end)` per frame (which
        // shifted the whole tail once per frame → O(n^2) on a buffer of many small frames). The search
        // floor is `consumed` — never below it, or the just-consumed terminator is re-found (infinite
        // loop); the 3-byte straddle backup and the `scanned` skip apply only above that floor.
        let mut consumed = 0usize;
        loop {
            let search_from = self
                .scanned
                .saturating_sub(3)
                .max(consumed)
                .min(self.buf.len());
            match find_frame_terminator(&self.buf[search_from..]) {
                Some((rel, term_len)) => {
                    let end = search_from + rel + term_len;
                    let frame = &self.buf[consumed..end];
                    consumed = end;
                    self.scanned = end;
                    let Some((_event_type, data_str)) = parse_sse_frame(frame) else {
                        continue; // no data: line — keepalive/comment frame
                    };
                    if data_str.is_empty()
                        || data_str == busbar_substrate_values::proto::SSE_DONE_SENTINEL
                    {
                        continue; // egress terminator/keepalive — the array close is finish()'s job
                    }
                    // Validate the payload is JSON before forwarding so a malformed frame cannot
                    // corrupt the array; re-serialize from the parsed Value to normalize whitespace.
                    let Ok(data) =
                        busbar_substrate_values::json::parse_str::<serde_json::Value>(&data_str)
                    else {
                        continue;
                    };
                    if self.started {
                        out.push(b',');
                    } else {
                        out.push(b'[');
                        self.started = true;
                    }
                    out.extend_from_slice(data.to_string().as_bytes());
                }
                None => {
                    self.scanned = self.buf.len();
                    break;
                }
            }
        }
        if consumed > 0 {
            self.buf.drain(..consumed);
            self.scanned = self.buf.len();
        }
        if self.buf.len() > Self::MAX_BUF {
            self.aborted = true;
            self.buf.clear();
            self.buf.shrink_to_fit();
            self.scanned = 0;
        }
        out
    }

    /// Call once at end-of-stream. Emits the closing `]` (and the opening `[` too, as `[]`, when the
    /// stream carried no chunk) so the body is always a complete, parseable JSON array. When the
    /// framer ABORTED (the reassembly buffer overran `MAX_BUF` without a frame terminator), the
    /// stream was silently truncated — so instead of a bare `]` that would make the partial array
    /// look complete, append a Gemini-shaped `google.rpc.Status` error element so a parsing client
    /// can see the stream ended abnormally (then close the array).
    pub fn finish(&mut self) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        if self.aborted {
            return self.finish_with_error(
                500,
                GRPC_INTERNAL,
                // Client-facing wire body: must carry NO product/internal vocabulary (the
                // protocol-indistinguishability promise). "upstream" is busbar-internal routing
                // vocabulary no real Gemini API ever emits — a fingerprintable tell. Mirror Gemini's
                // own canonical 500 status message text instead (the `google.rpc.Status.message` a
                // real Generative Language API 500 carries), so substring-matching clients can't
                // distinguish the proxy.
                "Internal error encountered.",
            );
        }
        self.finished = true;
        if self.started {
            b"]".to_vec()
        } else {
            b"[]".to_vec()
        }
    }

    /// Close the array at end-of-stream when this framer sits DOWNSTREAM of a cross-protocol
    /// [`StreamTranslate`] (gemini ingress, non-gemini egress). Identical to [`finish`] except it ALSO
    /// surfaces an abort that happened on the TRANSLATE side: when the translate's reassembly buffer
    /// overflowed `MAX_BUF` it stopped feeding this framer and its SSE terminal-error frame is NOT fed
    /// through (an SSE error cannot ride inside a JSON-array body), so this framer's own `aborted` flag
    /// stays clear and a plain [`finish`] would emit a bare `]` — a SILENT truncation indistinguishable
    /// from a successful short completion. Pass `translate_aborted = StreamTranslate::aborted()`; when
    /// EITHER side aborted, emit the Gemini-shaped error element + `]` (mirroring the SSE-ingress
    /// terminal-error path in `StreamTranslate::finish`) instead of the bare close. Idempotent via the
    /// shared `finished` flag.
    ///
    /// [`finish`]: Self::finish
    ///
    /// Production wiring lives in `proxy engine`: on a NORMAL close the `FirstByteBody`
    /// `Poll::Ready(None)` JSON-array arm FEEDS `translate.finish()`'s tail through [`Self::feed`] (so the
    /// terminal usage frame becomes a trailing array element) and then calls this with
    /// `translate.aborted()`; on an ABORT it skips feeding the tail and relies on this error-close.
    pub fn finish_for_translate(&mut self, translate_aborted: bool) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        if translate_aborted || self.aborted {
            return self.finish_with_error(
                500,
                GRPC_INTERNAL,
                // Same client-facing wire body as the framer-side abort in `finish`: a native
                // Gemini 500 `google.rpc.Status.message`, carrying no busbar-internal vocabulary
                // (the protocol-indistinguishability promise).
                "Internal error encountered.",
            );
        }
        self.finish()
    }

    /// Terminate the array with a trailing Gemini-shaped error element, then the closing `]`. Used on
    /// a mid-stream upstream transport failure (and on internal abort): a native Gemini JSON-array
    /// body is `application/json`, so the in-band error MUST itself be a valid array element — a
    /// `{"error":{"code","message","status"}}` object matching Gemini's `google.rpc.Status` envelope
    /// (the same shape `GeminiWriter::write_error` emits). Emitting raw SSE `event:`/`data:` text here
    /// (the bug this replaces) spliced non-JSON into the array, yielding an unparseable body and a
    /// protocol tell (a native Gemini JSON-array stream never contains SSE framing). Idempotent.
    pub fn finish_with_error(&mut self, code: u16, status: &str, message: &str) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let err = serde_json::json!({
            "error": { "code": code, "message": message, "status": status }
        });
        let mut out: Vec<u8> = Vec::new();
        if self.started {
            out.push(b',');
        } else {
            out.push(b'[');
            self.started = true;
        }
        out.extend_from_slice(err.to_string().as_bytes());
        out.push(b']');
        out
    }
}

impl busbar_substrate_values::proto::ArrayStreamFramer for GeminiJsonArrayFramer {
    fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        GeminiJsonArrayFramer::feed(self, chunk)
    }

    fn finish_for_translate(&mut self, translate_aborted: bool) -> Vec<u8> {
        GeminiJsonArrayFramer::finish_for_translate(self, translate_aborted)
    }

    fn finish_with_server_error(&mut self, message: &str) -> Vec<u8> {
        // The implementor owns the wire shape: a native Gemini server error is HTTP 500 / gRPC
        // `INTERNAL`. The agnostic caller passes only the message, so proxy engine names no Gemini value.
        GeminiJsonArrayFramer::finish_with_error(self, 500, GRPC_INTERNAL, message)
    }
}
