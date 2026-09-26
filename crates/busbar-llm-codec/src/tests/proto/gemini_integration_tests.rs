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
    // Since #83a S2-a the declaration states the scheme as DATA and the host presents it: the raw
    // key in `x-goog-api-key` for every mode, no Bearer (the host's presented bytes are pinned in its
    // suite over `testing/plane-copies/declared-credentials.json`).
    let decl = decl_for("gemini").expect("gemini declares itself");
    let raw = busbar_contract::protocol::CredentialHeader::Raw {
        header: "x-goog-api-key",
        trim_start: false,
    };
    assert!(
        matches!(
            decl.egress_scheme,
            Some(busbar_contract::protocol::EgressScheme::Static { families: [], own, passthrough })
                if own == raw && passthrough == raw
        ),
        "gemini's declared egress auth is the raw key in x-goog-api-key — no Bearer"
    );
}
