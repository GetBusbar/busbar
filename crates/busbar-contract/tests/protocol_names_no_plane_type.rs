//! The protocol seam names no transport's types (BUSBAR-1.6.0.md Part 2 #49, "core names zero plane
//! types"; Part 4: every ABI shape lives in busbar-contract and is neutral; TODO row 34c).
//!
//! `protocol.rs` is the vocabulary a dialect implements and the kernel reads back. A head crosses it
//! as [`HeadFields`](busbar_contract::protocol::HeadFields) pairs and a status as a `u16`; the
//! kernel converts to and from its transport's header and status types at its own edges. The check
//! is a source scan rather than a type assertion, because the property is "this path appears
//! nowhere", which no type can state about itself.

/// `protocol.rs`, as written.
fn protocol_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol.rs");
    std::fs::read_to_string(&path).expect("protocol.rs is readable")
}

/// No line of `protocol.rs` reaches into the `http` crate: no `use http`, no `http::` path.
#[test]
fn the_protocol_seam_names_no_http_type() {
    let offenders: Vec<String> = protocol_source()
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("http::") || line.trim_start().starts_with("use http"))
        .map(|(i, line)| format!("protocol.rs:{}: {}", i + 1, line.trim()))
        .collect();
    assert!(
        offenders.is_empty(),
        "the protocol seam names the http crate's types: {offenders:#?}"
    );
}
