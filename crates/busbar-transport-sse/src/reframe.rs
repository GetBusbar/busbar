// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND MIRROR of the inbound carve: on the MOUNT side, turning one complete success
//! message — and any records that must precede it — into an event stream.
//!
//! [`super::carve_complete_frames`] does the inbound half: it re-segments a byte stream an upstream
//! sent AS an event stream into frames. This is the other direction. A served door that produced ONE
//! complete `200` answer, plus a run of records it wants delivered ahead of that answer, can offer
//! that same answer as an event stream instead of a single body — when, and only when, the caller
//! asked for one.
//!
//! ## Two pieces, both surface-neutral
//!
//! * [`prefers_event_stream`] reads the caller's `Accept` header and answers one question: did the
//!   caller PREFER an event stream? It is a q-value negotiation, not a substring test — a caller that
//!   lists `text/event-stream;q=0.1, application/json` asked for the body, and a caller that lists
//!   `text/event-stream` with no lower q asked for the stream.
//! * [`reframe`] lays the records out first, each as its own event, then the result as the last
//!   event — the "logs ahead of the result" ordering, so a consumer sees everything the door wanted
//!   it to see BEFORE the answer that ends the exchange.
//!
//! Neither piece is wired to anything: a mount consumes this only once a plane declares it wants the
//! reframe, so the transport is byte-for-byte unchanged until then.

/// The media type an event stream is served as.
const EVENT_STREAM: &str = "text/event-stream";

/// Does the caller PREFER an event stream over a single body?
///
/// Reads the `Accept` header as a list of media ranges, each with an optional `;q=` weight (default
/// `1.0`, per RFC 9110). The answer is yes when `text/event-stream` is named EXPLICITLY with a
/// non-zero weight at least as high as the best weight any concrete body range carries. A bare `*/*`
/// does not count as naming the event stream — a client that accepts anything has expressed no
/// preference for a stream, and defaulting it to one would change how an ordinary caller is answered.
#[must_use]
pub fn prefers_event_stream(accept: &str) -> bool {
    let mut event_q: Option<f32> = None;
    let mut body_q: f32 = 0.0;
    for range in accept.split(',') {
        let mut parts = range.split(';').map(str::trim);
        let Some(media) = parts.next() else {
            continue;
        };
        let media = media.to_ascii_lowercase();
        if media.is_empty() {
            continue;
        }
        let mut q = 1.0_f32;
        for param in parts {
            if let Some(v) = param.strip_prefix("q=") {
                q = v.trim().parse::<f32>().unwrap_or(1.0).clamp(0.0, 1.0);
            }
        }
        if media == EVENT_STREAM {
            event_q = Some(event_q.map_or(q, |e| e.max(q)));
        } else if media != "*/*" {
            // Any other CONCRETE range is a body the caller would also take; `*/*` expresses no
            // preference and is left out of the comparison deliberately.
            body_q = body_q.max(q);
        }
    }
    match event_q {
        Some(q) if q > 0.0 => q >= body_q,
        _ => false,
    }
}

/// Reframe one complete success message into event-stream bytes, laying `records` out first — each as
/// its own event — then `result` as the final event.
///
/// The framing is the same one [`super::carve_complete_frames`] reads on the way in: each event is a
/// run of `field: value` lines terminated by a blank line. A payload that itself spans lines is split
/// across `data:` lines, which is how a multi-line SSE payload is carried; a consumer re-joins them
/// on newlines. The record events are named `log` and the answer `result`, so the "logs ahead of the
/// result" ordering is legible on the wire and not just in the byte order.
#[must_use]
pub fn reframe(records: &[&[u8]], result: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for record in records {
        push_event(&mut out, "log", record);
    }
    push_event(&mut out, "result", result);
    out
}

/// One SSE event: an `event:` line naming its type, one `data:` line per line of the payload, and the
/// blank line that terminates the frame.
fn push_event(out: &mut Vec<u8>, event: &str, payload: &[u8]) {
    out.extend_from_slice(b"event: ");
    out.extend_from_slice(event.as_bytes());
    out.push(b'\n');
    for line in payload.split(|&b| b == b'\n') {
        out.extend_from_slice(b"data: ");
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.push(b'\n');
}

// ── THE COMPOSITION-ROOT-OWNED SSE-REFRAME SEAM (HOST-CAPS S3, DECISIONS #26) ─────────────────────
//
// The server-side reframe above is TWO neutral free functions. This seam names that pair as ONE host
// capability a mount reaches through a trait object rather than by calling the free functions
// directly, so the composition root can install the reframer once at boot and a later pass swap the
// implementation WITHOUT the mount changing. ADDITIVE AND DORMANT: the production impl
// [`PassThroughReframe`] delegates to the exact free functions above, and NOTHING on the shipped path
// consults the seam yet — the transport is byte-for-byte unchanged until a mount opts in (W2). The
// composition-root install ([`install_sse_reframe`]) mirrors the egress seam's `install_hostless_egress`.

/// THE SERVER-SIDE SSE-REFRAME HOST CAPABILITY, as a neutral trait a mount reaches through instead of
/// calling [`prefers_event_stream`] / [`reframe`] directly. `Send + Sync` so the installed capability
/// is a process-wide `&'static dyn`.
pub trait SseReframe: Send + Sync {
    /// Does the caller PREFER an event stream over a single body? The q-value negotiation of
    /// [`prefers_event_stream`].
    fn prefers_event_stream(&self, accept: &str) -> bool;

    /// Reframe one complete success message into event-stream bytes, records first. The framing of
    /// [`reframe`].
    fn reframe(&self, records: &[&[u8]], result: &[u8]) -> Vec<u8>;
}

/// The production SSE-reframe capability: a BYTE-FOR-BYTE pass-through to the free functions
/// [`prefers_event_stream`] and [`reframe`]. The composition root installs this today, so a mount
/// that opts onto the seam (W2) gets exactly the bytes the free functions produce now.
pub struct PassThroughReframe;

impl SseReframe for PassThroughReframe {
    fn prefers_event_stream(&self, accept: &str) -> bool {
        prefers_event_stream(accept)
    }

    fn reframe(&self, records: &[&[u8]], result: &[u8]) -> Vec<u8> {
        reframe(records, result)
    }
}

/// THE PROCESS-WIDE SSE-reframe capability, installed once by the composition root
/// ([`install_sse_reframe`]). A mount reads it back through [`sse_reframe`] and gets `None` in a build
/// that installed none — the dormant default, under which every served door calls the free functions
/// directly and the wire is unchanged.
static REFRAMER: std::sync::OnceLock<&'static dyn SseReframe> = std::sync::OnceLock::new();

/// Install the process SSE-reframe capability — the composition root's one write, at boot, before any
/// mount reframes. Idempotent by `OnceLock`: a second install is a no-op (the first wins).
pub fn install_sse_reframe(reframer: &'static dyn SseReframe) {
    let _ = REFRAMER.set(reframer);
}

/// The installed SSE-reframe capability, or `None` when none was installed (the dormant default).
#[must_use]
pub fn sse_reframe() -> Option<&'static dyn SseReframe> {
    REFRAMER.get().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_body_accept_does_not_prefer_a_stream() {
        assert!(!prefers_event_stream("application/json"));
        assert!(!prefers_event_stream("*/*"));
        assert!(!prefers_event_stream(""));
    }

    #[test]
    fn an_explicit_event_stream_at_equal_or_higher_weight_prefers_it() {
        assert!(prefers_event_stream("text/event-stream"));
        assert!(prefers_event_stream(
            "application/json;q=0.5, text/event-stream"
        ));
        assert!(prefers_event_stream(
            "text/event-stream;q=1.0, application/json;q=1.0"
        ));
    }

    #[test]
    fn a_down_weighted_event_stream_does_not_win() {
        assert!(!prefers_event_stream(
            "text/event-stream;q=0.1, application/json"
        ));
        assert!(!prefers_event_stream("text/event-stream;q=0"));
    }

    #[test]
    fn records_lead_the_result_and_each_is_its_own_frame() {
        let bytes = reframe(&[b"one", b"two"], b"answer");
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(
            text,
            "event: log\ndata: one\n\nevent: log\ndata: two\n\nevent: result\ndata: answer\n\n"
        );
        // The result is last: a consumer sees both logs before the answer.
        assert!(text.find("data: one").unwrap() < text.find("data: answer").unwrap());
        assert!(text.find("data: two").unwrap() < text.find("data: answer").unwrap());
    }

    #[test]
    fn a_multi_line_payload_is_split_across_data_lines() {
        let bytes = reframe(&[], b"a\nb");
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "event: result\ndata: a\ndata: b\n\n"
        );
    }

    #[test]
    fn the_seam_is_a_byte_for_byte_pass_through_to_the_free_functions() {
        // The HOST-CAPS S3 seam must be a FAITHFUL pass-through: a mount that opts onto it (W2) must
        // get exactly the bytes the free functions produce today, or the reframe is not byte-safe.
        let reframer = PassThroughReframe;
        for accept in [
            "application/json",
            "*/*",
            "",
            "text/event-stream",
            "application/json;q=0.5, text/event-stream",
            "text/event-stream;q=0.1, application/json",
            "text/event-stream;q=0",
        ] {
            assert_eq!(
                reframer.prefers_event_stream(accept),
                prefers_event_stream(accept),
                "seam prefers_event_stream diverged from the free fn for {accept:?}"
            );
        }
        for (records, result) in [
            (vec![&b"one"[..], &b"two"[..]], &b"answer"[..]),
            (vec![], &b"a\nb"[..]),
            (vec![&b"log-line"[..]], &b"answer"[..]),
        ] {
            assert_eq!(
                reframer.reframe(&records, result),
                reframe(&records, result),
                "seam reframe diverged from the free fn"
            );
        }
    }

    #[test]
    fn the_composition_root_install_hands_the_installed_capability_back() {
        // Dormant by default: nothing installs the seam on the shipped path, so a fresh process reads
        // `None`. This test installs its own and reads it back, exercising the OnceLock accessor the
        // composition root uses — mirroring the egress seam's `install_hostless_egress`/`hostless`.
        static REFRAMER: PassThroughReframe = PassThroughReframe;
        install_sse_reframe(&REFRAMER);
        let installed = sse_reframe().expect("the just-installed reframer reads back");
        assert_eq!(
            installed.reframe(&[b"x"], b"y"),
            reframe(&[b"x"], b"y"),
            "the installed capability reframes byte-identically to the free fn"
        );
    }

    #[test]
    fn every_reframed_event_carries_a_field_the_inbound_carve_recognises() {
        // The outbound framing and the inbound recogniser are the two halves of one wire: what this
        // produces must read back as a real frame, not a comment the carve would drop.
        let bytes = reframe(&[b"log-line"], b"answer");
        let mut buf = bytes.clone();
        let (frames, _moved) = crate::carve_complete_frames(&mut buf, 0);
        assert_eq!(frames.len(), 2);
        for frame in &frames {
            assert!(crate::proto::frame_carries_a_field(frame));
        }
    }
}
