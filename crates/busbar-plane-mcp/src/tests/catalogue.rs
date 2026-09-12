//! Tests for `catalogue.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.

use super::{
    discovery_document, prompt_document, resource_read, substitute_arguments, ResourceRead,
    ServerIdentity,
};
use busbar_contract::catalogue::{
    Address, CatalogueEntry, CatalogueView, Found, PromptContent, PromptMessage, PromptTemplate,
    Resolution, ResourceBody,
};

/// A registry that answers whatever it was handed. Stands in for `busbar-mcp`'s own grant-scoped
/// catalogue: what these cells measure is the DOCUMENT, and the grant walk that decides what reaches
/// the face is proven on the engine's side of the seam, against the real gate.
#[derive(Default)]
struct Fake {
    tools: Vec<CatalogueEntry>,
    prompts: Vec<CatalogueEntry>,
    resources: Vec<CatalogueEntry>,
    empty: bool,
    answer: Option<Resolution>,
}

impl CatalogueView for Fake {
    fn tools_for(&self) -> Vec<CatalogueEntry> {
        self.tools.clone()
    }
    fn prompts_for(&self) -> Vec<CatalogueEntry> {
        self.prompts.clone()
    }
    fn resources_for(&self) -> Vec<CatalogueEntry> {
        self.resources.clone()
    }
    fn is_empty(&self) -> bool {
        self.empty
    }
    fn resolve(&self, _address: Address<'_>) -> Resolution {
        self.answer.clone().unwrap_or(Resolution::NotFound)
    }
}

fn entry(server: &str, name: &str) -> CatalogueEntry {
    CatalogueEntry {
        name: name.into(),
        server: server.into(),
    }
}

fn identity() -> ServerIdentity<'static> {
    ServerIdentity {
        name: "busbar",
        version: "1.6.0",
        protocol_version: "2026-07-28",
        supported_versions: &["2026-07-28"],
        tasks_extension_id: "io.modelcontextprotocol/tasks",
    }
}

/// The counts are of what THIS caller reached, and the `servers` list is the DEDUPED, SORTED union
/// of the three inventories' servers — not the registry's server list, which would name servers this
/// caller holds nothing on.
#[test]
fn the_discovery_document_counts_and_names_only_what_the_caller_reached() {
    let view = Fake {
        tools: vec![entry("beta", "beta_a"), entry("alpha", "alpha_a")],
        prompts: vec![entry("alpha", "alpha_p")],
        resources: vec![entry("gamma", "gamma_r")],
        ..Fake::default()
    };
    let doc = discovery_document(&view, &identity(), &["tools/list", "prompts/get"]);
    assert_eq!(doc["counts"]["tools"], 2);
    assert_eq!(doc["counts"]["prompts"], 1);
    assert_eq!(doc["counts"]["resources"], 1);
    assert_eq!(
        doc["servers"],
        serde_json::json!(["alpha", "beta", "gamma"]),
        "the servers list is sorted and deduped across all three inventories"
    );
    assert_eq!(
        doc["methods"],
        serde_json::json!(["tools/list", "prompts/get"])
    );
    assert_eq!(doc["serverInfo"]["name"], "busbar");
    assert_eq!(doc["protocolVersion"], "2026-07-28");
}

/// "You may see nothing" and "there is nothing" are DIFFERENT statements, and the document makes
/// both: a caller reaching nothing on a populated registry gets empty counts with
/// `registryEmpty: false`, which is what stops a client retrying for ever.
#[test]
fn an_empty_slice_on_a_populated_registry_is_not_an_empty_registry() {
    let view = Fake {
        empty: false,
        ..Fake::default()
    };
    let doc = discovery_document(&view, &identity(), &[]);
    assert_eq!(doc["counts"]["tools"], 0);
    assert_eq!(doc["registryEmpty"], false);
    assert_eq!(
        doc["servers"],
        serde_json::json!([]),
        "no reach means no server is named"
    );
}

/// The tasks extension is advertised UNCONDITIONALLY, under `extensions` and never as a v1-style
/// `capabilities.tasks` slot — see the doc comment on the document.
#[test]
fn the_tasks_extension_is_advertised_under_extensions_and_not_as_a_capability_slot() {
    let doc = discovery_document(&Fake::default(), &identity(), &[]);
    assert!(doc["capabilities"]["extensions"]["io.modelcontextprotocol/tasks"].is_object());
    assert!(
        doc["capabilities"]["tasks"].is_null(),
        "the extension REPLACED the v1 capability slot; advertising both claims two protocols"
    );
    assert_eq!(doc["capabilities"]["resources"]["subscribe"], true);
    assert_eq!(doc["capabilities"]["prompts"]["listChanged"], true);
}

fn text_prompt(template: &str) -> Resolution {
    Resolution::One(Found::Prompt(PromptTemplate {
        name: "srv_p".into(),
        server: "srv".into(),
        description: Some("a <b>bold</b> description".into()),
        messages: vec![PromptMessage {
            role: "user".into(),
            content: PromptContent::Text {
                text: template.into(),
            },
        }],
    }))
}

/// SUBSTITUTE FIRST, NORMALISE SECOND. The caller's argument value carries markup, and it is
/// stripped — a filter that ran before substitution would let the argument through untouched.
#[test]
fn a_caller_argument_is_substituted_and_then_stripped() {
    let view = Fake {
        answer: Some(text_prompt("hello {who}")),
        ..Fake::default()
    };
    let params = serde_json::json!({ "arguments": { "who": "<script>x</script>world" } });
    let doc = prompt_document(&view, "srv_p", Some(&params)).expect("the prompt resolves");
    let text = doc["messages"][0]["content"]["text"].as_str().unwrap();
    assert!(
        !text.contains("<script>"),
        "the substituted argument went out unfiltered: {text}"
    );
    assert!(
        text.contains("world"),
        "the argument was not substituted at all: {text}"
    );
    assert!(
        !doc["description"].as_str().unwrap().contains("<b>"),
        "the description is stripped too"
    );
}

/// An address this caller may not see, and one that does not exist, are ONE answer.
#[test]
fn a_prompt_the_caller_may_not_see_is_absent_rather_than_refused_by_name() {
    let view = Fake::default();
    assert!(prompt_document(&view, "srv_p", None).is_none());
}

/// An unknown placeholder survives verbatim; the empty substitution would read as a complete prompt
/// that means something else.
#[test]
fn an_unknown_placeholder_is_left_alone() {
    let params = serde_json::json!({ "arguments": { "a": "A" } });
    assert_eq!(
        substitute_arguments("{a} and {b}", Some(&params)),
        "A and {b}"
    );
    assert_eq!(
        substitute_arguments("{a", Some(&params)),
        "{a",
        "an unclosed brace is the operator's literal text"
    );
    assert_eq!(
        substitute_arguments("{a}", None),
        "{a}",
        "no arguments at all leaves the template untouched"
    );
}

/// ONE PASS OVER THE TEMPLATE: a `{b}` spelled inside the value of `a` is NOT filled from `b`.
#[test]
fn one_argument_never_decides_what_another_means() {
    let params = serde_json::json!({ "arguments": { "a": "{b}", "b": "BOOM" } });
    assert_eq!(substitute_arguments("{a}", Some(&params)), "{b}");
}

/// `blob` and `text` are alternatives: a blob resource emits the payload UNFILTERED and no `text`
/// member at all.
#[test]
fn a_blob_resource_emits_the_payload_unfiltered_and_no_text() {
    let view = Fake {
        answer: Some(Resolution::One(Found::Resource(ResourceBody {
            uri: "file:///x".into(),
            mime_type: Some("image/png".into()),
            text: None,
            blob: Some("PHNjcmlwdD4=".into()),
        }))),
        ..Fake::default()
    };
    let ResourceRead::Contents(doc) = resource_read(&view, "file:///x") else {
        panic!("a resolved resource must answer contents");
    };
    let block = &doc["contents"][0];
    assert_eq!(block["uri"], "file:///x");
    assert_eq!(block["mimeType"], "image/png");
    assert_eq!(block["blob"], "PHNjcmlwdD4=");
    assert!(
        block["text"].is_null(),
        "a markup strip over base64 corrupts the payload and protects nothing"
    );
}

/// A text resource is stripped, and an approved-but-empty resource answers the empty text form
/// rather than an error.
#[test]
fn a_text_resource_is_stripped_and_an_empty_one_is_not_an_error() {
    let view = Fake {
        answer: Some(Resolution::One(Found::Resource(ResourceBody {
            uri: "file:///y".into(),
            mime_type: None,
            text: Some("<b>hi</b>".into()),
            blob: None,
        }))),
        ..Fake::default()
    };
    let ResourceRead::Contents(doc) = resource_read(&view, "file:///y") else {
        panic!("a resolved resource must answer contents");
    };
    assert!(!doc["contents"][0]["text"].as_str().unwrap().contains("<b>"));

    let empty = Fake {
        answer: Some(Resolution::One(Found::Resource(ResourceBody {
            uri: "file:///z".into(),
            ..ResourceBody::default()
        }))),
        ..Fake::default()
    };
    let ResourceRead::Contents(doc) = resource_read(&empty, "file:///z") else {
        panic!("an approved-but-empty resource is still a resource");
    };
    assert_eq!(doc["contents"][0]["text"], "");
}

/// A contended address is its OWN terminal, and it carries the candidates. Collapsing it into
/// not-found would report a contended approval as a missing one.
#[test]
fn a_contended_address_is_named_rather_than_guessed_at() {
    let view = Fake {
        answer: Some(Resolution::Ambiguous(vec!["a_x".into(), "b_x".into()])),
        ..Fake::default()
    };
    assert_eq!(
        resource_read(&view, "file:///x"),
        ResourceRead::Ambiguous(vec!["a_x".into(), "b_x".into()])
    );
    assert_eq!(
        resource_read(&Fake::default(), "file:///x"),
        ResourceRead::NotFound
    );
}
