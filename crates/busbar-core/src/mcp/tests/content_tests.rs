// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONTENT SURFACES: binary resources, resource templates that resolve, and typed prompt
//! content — plus the characterisation that records why `-32021` is NOT emitted here.
//!
//! ## Why every registration in this file is written as YAML
//!
//! Each of those three adds CONFIG. A test that constructed `ResourceAllowCfg { blob: … }` as a
//! Rust literal would prove the field exists on a struct and nothing about whether an operator can
//! write it: `McpServerDefCfg` is `deny_unknown_fields`, so the only thing that decides whether
//! `blob:` is a key an operator may type is the `Deserialize` impl. These fixtures therefore go
//! through `serde_yaml`, exactly as `config.yaml` does, and then through `validate_server`, exactly
//! as both the file path and the admin write path do.
//!
//! It is also what makes these tests RED on a tree without the feature rather than
//! uncompilable — the fixture is a string, so the failure is "the config was refused", which is the
//! honest statement of what is missing.
//!
//! ## Why they are driven over a socket
//!
//! What B2 and B4 claim is that a CLIENT receives a `blob` / an `image` block. That is a statement
//! about the wire, and `method::resources_read` returning a `Response` is not the wire.

use crate::mcp::envelope::PROTOCOL_VERSION;
use crate::mcp::McpCfg;
use crate::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";

/// A 1x1 PNG. Tiny on purpose: what is asserted is that the bytes travel in a `blob`/`data` field
/// with the declared mime type, never that they decode to a particular picture.
const PNG_1X1: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

/// Boot an MCP deployment with ONE registered server, described in the operator's own YAML.
async fn serve(server_id: &str, yaml: &str) -> (String, tokio::task::JoinHandle<()>) {
    crate::metrics::init();
    let def: crate::mcp::config::McpServerDefCfg = serde_yaml::from_str(yaml)
        .unwrap_or_else(|e| panic!("the `tools:` registration was refused by the grammar: {e}"));
    let app = TestApp::new()
        .mcp(&McpCfg {
            canonical_uri: CANONICAL.to_string(),
            authorization_servers: vec!["https://login.example.com".to_string()],
            scopes_supported: Vec::new(),
            allowed_origins: Vec::new(),
        })
        .mcp_server(server_id, def)
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/mcp"), handle)
}

/// One JSON-RPC call, with the mirrored headers this revision requires. Returns `(status, body)`.
async fn call(url: &str, method: &str, params: serde_json::Value) -> (u16, serde_json::Value) {
    let mut params = params;
    let meta = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    params
        .as_object_mut()
        .expect("params is an object")
        .insert("_meta".into(), meta);
    // `Mcp-Name` mirrors `params.name` on tools/call and prompts/get, and `params.uri` on
    // resources/read. Built from the params rather than passed separately so a test cannot
    // accidentally send a mismatch and read the resulting `-32020` as the thing it meant to assert.
    let name = match method {
        "tools/call" | "prompts/get" => params.get("name").and_then(|v| v.as_str()),
        "resources/read" => params.get("uri").and_then(|v| v.as_str()),
        _ => None,
    }
    .map(str::to_string);

    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    });
    let mut req = reqwest::Client::new()
        .post(url)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .header("mcp-method", method);
    if let Some(n) = name {
        req = req.header("mcp-name", n);
    }
    let resp = req.json(&body).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or_default())
}

// ── B2: binary resources ───────────────────────────────────────────────────────────────────────

const BINARY_SERVER: &str = r#"
url: "https://tools.example.com/mcp"
pin: { mechanism: unpinned }
resources_allow:
  "test://static-binary":
    name: "A binary resource"
    mime_type: "image/png"
    blob: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
"#;

/// A resource declared with `blob:` is served as `blob`, not as `text`.
///
/// `resources_allow` carried only `text:` before this, so an operator with a PNG had two choices:
/// declare it as `text` (and hand a client base64 in a field a client will render as prose) or not
/// expose it. `ResourceContents` in the schema is a union of a text form and a blob form, and busbar
/// answered only one half of it.
#[tokio::test]
async fn a_resource_declared_with_blob_is_served_as_a_blob() {
    let (url, _h) = serve("bin", BINARY_SERVER).await;
    let (status, body) = call(
        &url,
        "resources/read",
        serde_json::json!({ "uri": "test://static-binary" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let content = &body["result"]["contents"][0];
    assert_eq!(content["mimeType"], "image/png", "{body}");
    assert_eq!(content["blob"], PNG_1X1, "{body}");
    // A blob resource has NO `text`. The schema's two forms are alternatives, and a content block
    // carrying both would be a client's choice of which to believe.
    assert!(
        content.get("text").is_none(),
        "a blob resource also carried a text field: {content}"
    );
}

/// `text:` and `blob:` on ONE resource is a config refusal, not a silent preference.
///
/// The two are the schema's alternatives. Accepting both and picking one would put the choice of
/// what a client reads in the hands of whichever branch happens to run first, which is exactly the
/// class of silent resolution the resource routing key was namespaced to avoid.
#[test]
fn a_resource_may_not_declare_both_text_and_blob() {
    let yaml = r#"
url: "https://tools.example.com/mcp"
pin: { mechanism: unpinned }
resources_allow:
  "test://both":
    text: "hello"
    blob: "aGVsbG8="
"#;
    let def: crate::mcp::config::McpServerDefCfg =
        serde_yaml::from_str(yaml).expect("the shape is legal; the VALUE rule is what refuses it");
    let err = crate::mcp::config::validate_server("bin", &def)
        .expect_err("declaring both forms of one resource must be refused");
    assert!(err.contains("blob") && err.contains("text"), "{err}");
}

/// A `blob:` that is not base64 is refused at BOOT, where the operator can fix it.
///
/// The alternative is a client receiving a `blob` it cannot decode, which surfaces as "busbar sent
/// me rubbish" hours later and in somebody else's log.
#[test]
fn a_blob_that_is_not_base64_is_refused_at_boot() {
    let yaml = r#"
url: "https://tools.example.com/mcp"
pin: { mechanism: unpinned }
resources_allow:
  "test://bad":
    blob: "this is not base64!!"
"#;
    let def: crate::mcp::config::McpServerDefCfg = serde_yaml::from_str(yaml).unwrap();
    let err = crate::mcp::config::validate_server("bin", &def)
        .expect_err("a blob that cannot decode must be refused at boot");
    assert!(err.contains("base64"), "{err}");
}

// ── B3: resource templates that resolve ────────────────────────────────────────────────────────

const TEMPLATE_SERVER: &str = r#"
url: "https://tools.example.com/mcp"
pin: { mechanism: unpinned }
resource_templates_allow:
  "test://template/{id}/data":
    name: "Templated data"
    mime_type: "application/json"
    text: '{"id":"{id}","templateTest":true,"data":"Data for ID: {id}"}'
"#;

/// `resources/templates/list` enumerates what the operator declared, instead of the empty list it
/// answered for every deployment.
///
/// The empty list was the correct answer while the registry had no concept of a template. It stopped
/// being correct the moment an operator could declare one, and the difference is not cosmetic: a
/// client discovers templates ONLY from this method, so an unconditional `[]` means a declared
/// template is unreachable by any client that did not already know it existed.
#[tokio::test]
async fn declared_templates_are_enumerated() {
    let (url, _h) = serve("tpl", TEMPLATE_SERVER).await;
    let (status, body) = call(&url, "resources/templates/list", serde_json::json!({})).await;
    assert_eq!(status, 200, "{body}");
    let templates = body["result"]["resourceTemplates"]
        .as_array()
        .unwrap_or_else(|| panic!("no resourceTemplates array: {body}"));
    assert_eq!(templates.len(), 1, "{body}");
    assert_eq!(templates[0]["uriTemplate"], "test://template/{id}/data");
    assert_eq!(templates[0]["name"], "Templated data");
    assert_eq!(templates[0]["mimeType"], "application/json");
}

/// A read against an EXPANDED template URI resolves, and the parameter reaches the content.
///
/// This is the whole of B3: a template that is listed but cannot be read is a catalogue entry
/// advertising a capability the server does not have.
#[tokio::test]
async fn an_expanded_template_uri_resolves_and_substitutes() {
    let (url, _h) = serve("tpl", TEMPLATE_SERVER).await;
    let (status, body) = call(
        &url,
        "resources/read",
        serde_json::json!({ "uri": "test://template/123/data" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let content = &body["result"]["contents"][0];
    // The URI ECHOED IS THE ONE THE CALLER ASKED FOR, not the template. A client correlates the
    // content it got with the URI it sent; answering with the unexpanded template would hand back an
    // identifier that names every expansion at once.
    assert_eq!(content["uri"], "test://template/123/data", "{body}");
    let text = content["text"].as_str().unwrap_or_default();
    assert!(
        text.contains("123"),
        "the parameter never reached the content: {content}"
    );
    assert!(
        !text.contains("{id}"),
        "an unsubstituted placeholder survived into the content: {content}"
    );
}

/// A URI that does NOT match any template is still not found.
///
/// The matcher must be a matcher and not a wildcard: a template that answered every URI would turn
/// `resources_allow`'s approval-by-URI into approval-by-existence, which is the one thing the
/// registry's whole design refuses.
#[tokio::test]
async fn a_uri_that_matches_no_template_is_still_not_found() {
    let (url, _h) = serve("tpl", TEMPLATE_SERVER).await;
    for uri in [
        // Right prefix, wrong tail.
        "test://template/123/other",
        // A variable must not swallow a path separator, or one template claims the whole subtree.
        "test://template/123/extra/data",
        // An EMPTY expansion is not an expansion.
        "test://template//data",
        // Another server's spelling.
        "other_test://template/123/data",
    ] {
        let (status, body) = call(&url, "resources/read", serde_json::json!({ "uri": uri })).await;
        assert_eq!(status, 404, "`{uri}` was matched by the template: {body}");
    }
}

// ── B4: typed prompt content ───────────────────────────────────────────────────────────────────

const PROMPT_SERVER: &str = r#"
url: "https://tools.example.com/mcp"
pin: { mechanism: unpinned }
prompts_allow:
  simple:
    description: "The text form, unchanged."
    template: "This is a simple prompt for testing."
  with_image:
    description: "An image and a question about it."
    messages:
      - content:
          type: image
          data: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
          mime_type: "image/png"
      - content:
          type: text
          text: "Please analyze the image above."
  with_resource:
    description: "An embedded resource and a question about it."
    messages:
      - content:
          type: resource
          resource:
            uri: "{resourceUri}"
            mime_type: "text/plain"
            text: "Embedded resource content for testing."
      - content:
          type: text
          text: "Please process the embedded resource above."
"#;

/// The TEXT form still works, byte for byte.
///
/// B4 adds a shape; it must not change the one every existing registration uses. A `prompts_allow`
/// entry carrying only `description` + `template` is the documented spelling and stays the
/// documented spelling.
#[tokio::test]
async fn the_text_only_prompt_form_is_unchanged() {
    let (url, _h) = serve("p", PROMPT_SERVER).await;
    let (status, body) = call(
        &url,
        "prompts/get",
        serde_json::json!({ "name": "p_simple" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let messages = body["result"]["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1, "{body}");
    assert_eq!(messages[0]["role"], "user");
    assert_eq!(messages[0]["content"]["type"], "text");
    assert_eq!(
        messages[0]["content"]["text"],
        "This is a simple prompt for testing."
    );
}

/// An IMAGE content block reaches the client with its data and its declared mime type.
#[tokio::test]
async fn a_prompt_can_carry_image_content() {
    let (url, _h) = serve("p", PROMPT_SERVER).await;
    let (status, body) = call(
        &url,
        "prompts/get",
        serde_json::json!({ "name": "p_with_image" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let messages = body["result"]["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2, "{body}");
    let image = &messages[0]["content"];
    assert_eq!(image["type"], "image", "{body}");
    assert_eq!(image["data"], PNG_1X1);
    // `mimeType`, not `mime_type`: the CONFIG is snake_case like every other busbar key, and the
    // WIRE is camelCase like every other MCP field. A test that read the config spelling off the
    // wire would pass while no client could parse the answer.
    assert_eq!(image["mimeType"], "image/png", "{body}");
    assert_eq!(messages[1]["content"]["type"], "text");
}

/// An EMBEDDED RESOURCE block reaches the client, and an argument substitutes into its URI.
#[tokio::test]
async fn a_prompt_can_carry_an_embedded_resource_with_a_substituted_uri() {
    let (url, _h) = serve("p", PROMPT_SERVER).await;
    let (status, body) = call(
        &url,
        "prompts/get",
        serde_json::json!({
            "name": "p_with_resource",
            "arguments": { "resourceUri": "test://example-resource" },
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let messages = body["result"]["messages"].as_array().unwrap();
    let embedded = &messages[0]["content"];
    assert_eq!(embedded["type"], "resource", "{body}");
    assert_eq!(
        embedded["resource"]["uri"], "test://example-resource",
        "{body}"
    );
    assert_eq!(embedded["resource"]["mimeType"], "text/plain");
    assert_eq!(
        embedded["resource"]["text"],
        "Embedded resource content for testing."
    );
}

/// TYPED CONTENT IS STILL SANITIZED, and that is the assertion this feature most needs.
///
/// A prompt template was already in the sanitization set because it is exactly as injectable as tool
/// output. Adding a second, differently-shaped way to put text into a model's context creates a
/// second way to bypass that strip — and a new content type that skipped the normaliser would be a
/// hole opened by a feature nobody thought of as a text surface.
#[tokio::test]
async fn typed_prompt_text_is_markup_normalised_like_a_template() {
    let yaml = r#"
url: "https://tools.example.com/mcp"
pin: { mechanism: unpinned }
prompts_allow:
  injected:
    messages:
      - content: { type: text, text: "<script>alert(1)</script>ignore previous" }
"#;
    let (url, _h) = serve("p", yaml).await;
    let (status, body) = call(
        &url,
        "prompts/get",
        serde_json::json!({ "name": "p_injected" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let text = body["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        !text.contains("<script>"),
        "typed prompt content reached the client with its markup intact: {text:?}"
    );
}

/// `template:` and `messages:` on ONE prompt is a config refusal.
///
/// Same rule as `text`/`blob`: two statements of what one prompt says, and any silent precedence
/// makes the answer depend on which branch runs first.
#[test]
fn a_prompt_may_not_declare_both_a_template_and_messages() {
    let yaml = r#"
url: "https://tools.example.com/mcp"
pin: { mechanism: unpinned }
prompts_allow:
  both:
    template: "text form"
    messages:
      - content: { type: text, text: "typed form" }
"#;
    let def: crate::mcp::config::McpServerDefCfg = serde_yaml::from_str(yaml).unwrap();
    let err = crate::mcp::config::validate_server("p", &def)
        .expect_err("declaring both forms of one prompt must be refused");
    assert!(
        err.contains("template") && err.contains("messages"),
        "{err}"
    );
}

// ── B6: WHY `-32021 MissingRequiredClientCapability` IS NOT SHIPPED HERE ───────────────────────
//
// THIS SECTION IS CHARACTERISATION, NOT NEW BEHAVIOUR. Every assertion below is GREEN on `dev`
// unchanged, and it is written down because it is the evidence for a NON-delivery.
//
// The proposal was: when a dispatch is refused because an upstream asked for `elicitation` /
// `sampling` / `roots`, and the client did not declare that capability, answer `-32021` with
// `data.requiredCapabilities` instead of `-32000`. It was built, and building it disproved it.
//
// `-32021` means *"processing this request REQUIRES a capability you did not declare"*. For busbar
// that claim is false, and the pair of tests below is what makes it false: a client that DOES
// declare the capability gets the SAME refusal, with the same status, the same code and the same
// audit reason. The capability is not what decides the outcome. What decides it is that the OPERATOR
// did not grant this server that authority (`ask_ungranted`) and that an upstream's ask terminates
// at busbar and is never proxied — so the remedy is `tools.<server>.grants.<kind>`, in the
// operator's config, and telling the client to go and acquire a capability would send it to fix the
// one thing that was already right.
//
// The implementation also failed loudly rather than subtly, which is worth recording: it turned
// `upstream_join_tests::an_upstreams_ask_is_recognised_off_the_wire_and_refused_deny_by_default`
// from `403` to `400` — busbar's own policy refusal re-attributed to the caller as a malformed
// request. That is the defect in one line.
//
// WHERE `-32021` IS GENUINELY OWED is the capability FILTER on an ask busbar mints ITSELF
// (SEP-2322 / `input-required-result-capability-check`): there, a capability the client has not
// declared really is the thing that stops the request, because busbar would otherwise be sending an
// `inputRequests` the client cannot answer — which `PAT.MRTR.NO-UNDECLARED-CAPABILITY` forbids. That
// path is the concurrent input-required work and is deliberately not touched here.

/// A registered upstream that answers every `tools/call` with an `InputRequiredResult` asking for
/// ELICITATION — that is, asking somebody to go and ask a human.
async fn asking_upstream() -> (String, tokio::task::JoinHandle<()>) {
    let router = axum::Router::new().route(
        "/mcp",
        axum::routing::post(|body: String| async move {
            let id = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("id").cloned())
                .unwrap_or(serde_json::Value::Null);
            axum::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "type": "input_required", "request": "elicitation/create" },
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/mcp"), handle)
}

/// Boot busbar in front of `upstream`, with one approved tool and NO ask grants.
async fn serve_with_upstream(upstream: &str) -> (String, tokio::task::JoinHandle<()>) {
    let yaml = format!(
        r#"
url: "{upstream}"
allow_private: true
pin:
  mechanism: cert_spki
  key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
tools_allow:
  ask:
    schema_hash: "sha256:ask"
    description: "An upstream tool that always asks for input."
"#
    );
    serve("up", &yaml).await
}

/// One `tools/call`, with the client's declared capabilities under the caller's control.
async fn call_with_capabilities(
    url: &str,
    capabilities: serde_json::Value,
) -> (u16, serde_json::Value) {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "up_ask",
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": capabilities,
            },
        },
    });
    let resp = reqwest::Client::new()
        .post(url)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .header("mcp-method", "tools/call")
        .header("mcp-name", "up_ask")
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or_default())
}

/// THE CLIENT'S DECLARED CAPABILITIES DO NOT CHANGE THE ANSWER, and that is the finding.
///
/// Two requests differing in exactly one `_meta` member — one declaring the empty capability set,
/// one declaring `elicitation` — get byte-identical refusals. A `-32021` on the first would be a
/// diagnosis the second disproves.
///
/// It is also the first assertion of the ask-termination property made over a REAL SOCKET rather
/// than through `method::dispatch`: the sibling in `upstream_join_tests` calls the dispatcher
/// directly, so it cannot see the HTTP status a client actually receives.
#[tokio::test]
async fn an_upstreams_ask_is_refused_identically_whatever_the_client_declared() {
    let (upstream, _u) = asking_upstream().await;
    let (url, _h) = serve_with_upstream(&upstream).await;

    let (declared_nothing_status, declared_nothing) =
        call_with_capabilities(&url, serde_json::json!({})).await;
    let (declared_it_status, declared_it) =
        call_with_capabilities(&url, serde_json::json!({ "elicitation": {} })).await;

    assert_eq!(
        (declared_nothing_status, declared_it_status),
        (403, 403),
        "a policy refusal is `403`, not a `400` blaming the caller's request: {declared_nothing} \
         {declared_it}"
    );
    assert_eq!(
        declared_nothing["error"], declared_it["error"],
        "the client's capability declaration changed the refusal, which would make \
         `MissingRequiredClientCapability` a true diagnosis; it did not"
    );
    assert_eq!(
        declared_nothing["error"]["code"], -32000,
        "{declared_nothing}"
    );
    assert_eq!(
        declared_nothing["error"]["data"]["reason"], "ask_ungranted",
        "{declared_nothing}"
    );
    // The termination rule, asserted where a client would read it.
    let message = declared_nothing["error"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        message.contains("terminates at busbar"),
        "the caller is told busbar declined, never handed the ask to answer: {message}"
    );
}
