use super::*;

// Gemini's URL embeds the model; non-Gemini protocols keep their fixed path.
#[test]
fn test_gemini_upstream_path_for_embeds_model() {
    let gemini_writer = GeminiWriter;
    assert_eq!(
        gemini_writer.upstream_path_for("gemini-1.5-pro"),
        "/v1beta/models/gemini-1.5-pro:generateContent"
    );
    // Default (non-Gemini) ignores the model.
    assert_eq!(
        anthropic_writer().upstream_path_for("anything"),
        "/v1/messages"
    );
    assert_eq!(
        openai_writer().upstream_path_for("anything"),
        "/v1/chat/completions"
    );
}

// gemini is now a registered, buildable protocol.
#[test]
fn test_gemini_registered_in_builtins() {
    let g = crate::proto_codec::protocol_for("gemini").expect("gemini should be registered");
    assert_eq!(g.name(), "gemini");
    assert_eq!(
        g.writer().upstream_path_for("m"),
        "/v1beta/models/m:generateContent"
    );
    // x-goog-api-key auth header, read off GEMINI'S OWN DECLARATION. Calling
    // `api_key_headers("x-goog-api-key", "k")` and asserting the name comes back — as this did —
    // asserts the helper echoes its argument: the header name was the test's input, and the Gemini
    // protocol was never consulted. If Gemini regressed to `Authorization: Bearer`, every upstream
    // call 401s and that form stayed green.
    crate::ensure_test_protocols_registered();
    let decl = decl_for("gemini").expect("gemini declares itself");
    let build = decl
        .egress_auth_headers
        .expect("gemini declares a native egress-auth builder");
    let ctx = busbar_substrate_values::proto::SigningContext {
        host: "generativelanguage.googleapis.com",
        canonical_uri: "/v1beta/models/m:generateContent",
        body: b"{}",
        timestamp_epoch: 1_752_000_000,
        upstream_creds: busbar_api::UpstreamCreds::Own,
    };
    let headers = build("k", &ctx);
    let named: Vec<(&str, &str)> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.to_str().expect("ascii header value")))
        .collect();
    assert_eq!(
        named,
        vec![("x-goog-api-key", "k")],
        "gemini's declared egress auth is the raw key in x-goog-api-key — no Bearer, no extra headers"
    );
}
