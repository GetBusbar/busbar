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
    // The HOST-CAPS seam must be a FAITHFUL pass-through: a mount that opts onto it must
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
