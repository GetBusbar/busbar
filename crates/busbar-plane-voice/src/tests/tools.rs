//! The tool-executor port's own test double, held to the rule the port exists to enforce: what
//! comes off the provider's wire is DATA, and only a serializer decides what a string may contain.

use crate::tools::{EchoToolExecutor, ToolExecutor};

/// Drive one future to completion on this thread.
///
/// This crate has no async runtime in its closure and must not gain one to test a port whose only
/// async-ness is the `#[async_trait]` desugaring. The port's futures are ready on their first poll —
/// they await nothing — so a bare poll with a no-op waker is the whole executor needed, and adding
/// `tokio` as a dev-dependency to avoid writing it would put an async runtime in the dependency seam
/// the crate root promises is empty.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    // The crate forbids `unsafe`, so the waker is the standard library's own no-op one rather than a
    // hand-rolled vtable over a null pointer.
    let waker = Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);
    // The port's futures await nothing, so one poll answers. A future that did not would hang here
    // rather than quietly reporting a wrong answer.
    let mut pinned = std::pin::pin!(future);
    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("the tool-executor port's futures await nothing"),
    }
}

/// A tool name is DATA. It cannot open a key.
///
/// The echo used to be a `format!` splicing `name` straight into a hand-written object, so a name
/// carrying a quote wrote keys of the caller's choosing into the result — from a `pub` module of a
/// production crate. `name` comes off the provider's JSON with no charset restriction at all.
#[test]
fn a_tool_name_carrying_json_punctuation_cannot_open_a_key_of_its_own() {
    let hostile = r#"a","injected":"yes"#;
    let out = block_on(EchoToolExecutor.execute(hostile, br#"{"q":1}"#));
    let parsed: serde_json::Value =
        serde_json::from_slice(&out).expect("the echo is valid JSON whatever the name contains");
    assert_eq!(
        parsed["tool"], hostile,
        "the whole name is one string value, punctuation and all"
    );
    assert!(
        parsed.get("injected").is_none(),
        "the name opened a key of its own: {parsed}"
    );
    assert_eq!(parsed["echo"]["q"], 1, "the arguments still round-trip");
    assert_eq!(
        parsed.as_object().map(serde_json::Map::len),
        Some(2),
        "the echo has exactly the two members it declares: {parsed}"
    );
}

/// Arguments that are not JSON travel as the string they are.
///
/// Pasted verbatim where a value belongs, a non-JSON argument blob produced a document nothing could
/// read — the same defect as the name, one member over.
#[test]
fn arguments_that_are_not_json_still_produce_a_readable_echo() {
    let out = block_on(EchoToolExecutor.execute("lookup", b"not json at all"));
    let parsed: serde_json::Value =
        serde_json::from_slice(&out).expect("the echo is valid JSON whatever the arguments are");
    assert_eq!(parsed["echo"], "not json at all");
}
