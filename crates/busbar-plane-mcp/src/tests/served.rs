//! Tests for `served.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.
//!
//! ## The last two source reads, retired
//!
//! Five of these asked their question TWICE: once of the answer this module composes, and once of
//! the SOURCE the console-era answer was written in — `include_str!` over
//! `../../../busbar-mcp/src/…`. That second half was the move-pin, and it cost what every one of
//! this directory's other source reads cost before it was retired: a coupling to a sibling crate
//! this manifest does not name and must not. It left the plane unable to be BUILT or DELETED on its
//! own, which is not a style complaint — `scripts/plane-delete-test.sh mcp` builds this crate with
//! `busbar-mcp` physically removed, and two `include_str!` lines were the whole of why that build
//! failed. The two lines named two files of `busbar-mcp` that were not on disk, and the build
//! stopped on `error: couldn't read` for each of them, quoting the relative path each `include_str!`
//! had spelled.
//!
//! So they go, on the same terms `claims.rs`, `facts.rs`, `ops.rs` and `jsonrpc.rs` retired theirs
//! on. Every value assertion stays — each of the five already read the member and its value off
//! this module's own answer, and that half is the half that goes red on a byte of the wire. What is
//! given up is a text search for a fragment of another crate's private function, which went red on a
//! reformatting and could not have survived that crate's own deletion in any case. The two halves
//! stay pinned to one wire where a wire pin belongs: the MCP conformance battery
//! (`testing/mcp-conformance`) drives both and judges them against the same protocol.

use busbar_contract::ids::OpClassId;

use super::{
    cache_hints, completion_result, composed, initialize_result, instructions, ping_result,
    prompt_get_result, prompts_list_result, reads, resource_read_result,
    resource_templates_list_result, resources_list_result, task_ack_result, task_get_result,
    tool_call_result, tools_list_result, Composing, Reads, ANSWERED, CACHE_SCOPE, CACHE_TTL_MS,
    COMPOSED, PROTOCOL_VERSION, SERVER_NAME,
};
use crate::{ops, records};

/// The revision is the codec's own string and not a copy of it.
#[test]
fn the_revision_is_the_codecs_own() {
    assert_eq!(PROTOCOL_VERSION, busbar_mcp_codec::codec::PROTOCOL_VERSION);
}

/// Every member of the handshake document is the one the console loop writes, value included.
///
/// Read member by member off the answer this module composes, then looked for in the loop's own
/// source. A member this module invented would not be found there; a value it changed would be found
/// under a different spelling.
#[test]
fn the_handshake_is_the_console_loops_own() {
    let answer = initialize_result("9.9.9");
    let object = answer.as_object().expect("the handshake is a document");

    assert_eq!(object["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(object["serverInfo"]["name"], SERVER_NAME);
    // The version is the NODE's, handed in. That is the one thing the move changed, and it changed
    // because `env!("CARGO_PKG_VERSION")` read in a different crate is a different number.
    assert_eq!(object["serverInfo"]["version"], "9.9.9");

    // The five capability members, each with the value the loop declares.
    let capabilities = &object["capabilities"];
    assert_eq!(
        capabilities["tools"],
        serde_json::json!({"listChanged": true})
    );
    assert_eq!(
        capabilities["prompts"],
        serde_json::json!({"listChanged": true})
    );
    assert_eq!(
        capabilities["resources"],
        serde_json::json!({"listChanged": true, "subscribe": true})
    );
    assert_eq!(capabilities["completions"], serde_json::json!({}));
    assert_eq!(capabilities["logging"], serde_json::json!({}));
    assert_eq!(
        capabilities
            .as_object()
            .expect("capabilities is a document")
            .len(),
        5,
        "the handshake declares a capability the console loop does not"
    );

    // And the server's own name, as the wire carries it.
    assert_eq!(SERVER_NAME, "busbar");
}

/// The sentence the handshake carries is the console loop's own, word for word.
///
/// Its own test because it is the one member that is FORMATTED: the loop writes it across three
/// source lines with a continuation, so the comparison is over the words rather than over the
/// literal. Each phrase is long enough that a rewording moves it.
#[test]
fn the_instructions_are_the_console_loops_own() {
    let said = instructions();
    assert!(said.starts_with("This server speaks MCP revision "));
    assert!(said.contains(PROTOCOL_VERSION));
    // Each phrase is long enough that a rewording moves it, and it is asked of what this module
    // SAYS rather than of the source another crate says it in.
    for phrase in [
        "no handshake is required,",
        "and every request states its protocol version and client capabilities in",
        "`params._meta`.",
    ] {
        assert!(
            said.contains(phrase),
            "the handshake no longer says: {phrase}"
        );
    }
}

/// The liveness answer is the empty document, here and there.
#[test]
fn the_liveness_answer_is_empty() {
    assert_eq!(ping_result(), serde_json::json!({}));
}

/// The caching hints are the pair the server half writes, under the names it writes them.
#[test]
fn the_cache_hints_are_the_server_halfs_own() {
    let hinted = cache_hints(serde_json::json!({ "tools": [] }));
    assert_eq!(hinted["cacheScope"], CACHE_SCOPE);
    assert_eq!(hinted["ttlMs"], CACHE_TTL_MS);
    // The two values themselves, as the wire carries them: a scope that is not `private` or a TTL
    // that is not zero is a different caching instruction to every client that reads them.
    assert_eq!(CACHE_SCOPE, "private");
    assert_eq!(CACHE_TTL_MS, 0);
    // And nothing else is attached: a third hint would be a member no client was told to expect.
    assert_eq!(
        hinted
            .as_object()
            .expect("a hinted answer is a document")
            .len(),
        3
    );
}

/// A value that is not a document is handed back untouched.
#[test]
fn a_hint_is_only_added_to_a_document() {
    assert_eq!(
        cache_hints(serde_json::json!([1, 2])),
        serde_json::json!([1, 2])
    );
    assert_eq!(
        cache_hints(serde_json::json!(null)),
        serde_json::json!(null)
    );
}

/// The listing is the tools handed in, under the member the server half writes, with the hints.
#[test]
fn the_listing_is_the_server_halfs_shape() {
    let listed = tools_list_result(vec![serde_json::json!({"name": "a"})]);
    assert_eq!(listed["tools"], serde_json::json!([{"name": "a"}]));
    assert_eq!(listed["cacheScope"], CACHE_SCOPE);
    assert_eq!(listed["ttlMs"], CACHE_TTL_MS);
    assert_eq!(
        listed.as_object().expect("a listing is a document").len(),
        3,
        "the listing carries a member the server half does not write"
    );
    // A caller whose grant reaches nothing gets the empty list rather than an error.
    assert_eq!(
        tools_list_result(Vec::new())["tools"],
        serde_json::json!([])
    );
}

/// A call's answer carries NO caching hint, and is otherwise the upstream's own document.
///
/// The absence is the assertion: a hint here would invite a client to reuse the answer to an effect.
#[test]
fn a_call_is_not_cacheable() {
    let answered = tool_call_result(serde_json::json!({"content": []}));
    assert_eq!(answered, serde_json::json!({"content": []}));
    assert!(answered.get("cacheScope").is_none());
    assert!(answered.get("ttlMs").is_none());
}

/// Every class this module answers is a class the plane declares, and every one has a reading.
#[test]
fn every_answered_class_is_declared_and_read() {
    for op in ANSWERED {
        assert!(
            ops::OP_CLASSES.contains(op),
            "{op} is answered and is not a declared class"
        );
        assert!(reads(*op).is_some(), "{op} is answered and reads nothing");
    }
    assert_eq!(
        ANSWERED.len(),
        13,
        "every class this mount can carry: the six the mount cannot are named in the deletion list"
    );
}

/// A class this plane does not answer says so, rather than being read as reading nothing.
///
/// The six below are not "not yet". Each of them arrives somewhere the mounted request surface is
/// not — a bodyless address, a provider-opened round on an outbound hop, a run of events, or a
/// message that obliges no answer — so a reading written for any of them would be a declaration
/// nothing ever reaches. They are enumerated in the MCP deletion list beside the seam each waits on,
/// and this cell is what keeps that list honest: the day one of them gains a reading without gaining
/// a seam, this goes red.
#[test]
fn an_unanswered_class_has_no_reading() {
    for op in [
        ops::OP_DISCOVER,
        ops::OP_NOTIFICATION,
        ops::OP_SAMPLING,
        ops::OP_ROOTS_LIST,
        ops::OP_ELICITATION,
        ops::OP_SUBSCRIPTIONS_LISTEN,
    ] {
        assert_eq!(reads(op), None, "{op} has a reading this stage cannot run");
    }
    assert_eq!(reads(OpClassId::new("not_a_class")), None);
}

/// The two constant answers read nothing, and say so.
#[test]
fn the_constant_answers_read_nothing() {
    assert_eq!(reads(ops::OP_INITIALIZE), Some(Reads::Nothing));
    assert_eq!(reads(ops::OP_PING), Some(Reads::Nothing));
    assert!(Reads::Nothing.legs().is_empty());
}

/// Every leg a reading names is a leg the plane's own plan for that class runs.
///
/// The containment in the ONE direction it holds. The plan is the single source for what a unit
/// runs; a reading naming a leg the plan never runs would be an answer assembled from a record
/// nobody read, and this is what makes that red rather than empty.
#[test]
fn every_named_leg_is_a_planned_leg() {
    for op in ANSWERED {
        let Some(reading) = reads(*op) else {
            unreachable!("every answered class has a reading")
        };
        for (schema, operation) in reading.legs() {
            assert!(
                records::operations_for(*schema).contains(operation),
                "{op} names {operation} on {schema}, which the schema does not declare"
            );
        }
    }
}

/// The two readings that touch records name the schemas their own names claim.
#[test]
fn the_readings_name_the_schemas_they_say_they_do() {
    let snapshot: Vec<&str> = Reads::CatalogueSnapshot
        .legs()
        .iter()
        .map(|(schema, _)| schema.as_str())
        .collect();
    assert_eq!(
        snapshot,
        vec![
            records::SCHEMA_CATALOGUE.as_str(),
            records::SCHEMA_DEMOTION.as_str()
        ]
    );
    let registry: Vec<&str> = Reads::ServerRegistry
        .legs()
        .iter()
        .map(|(schema, _)| schema.as_str())
        .collect();
    assert_eq!(
        registry,
        vec![
            records::SCHEMA_CATALOGUE.as_str(),
            records::SCHEMA_DEMOTION.as_str()
        ]
    );
    // A listing SCANS and a call GETS: the two readings differ in the operation, not only in the
    // schema, and reading a listing with a get would answer one record where a caller asked for all
    // of them.
    assert!(Reads::CatalogueSnapshot
        .legs()
        .iter()
        .all(|(_, op)| *op == records::OP_SCAN));
    assert!(Reads::ServerRegistry
        .legs()
        .iter()
        .all(|(_, op)| *op == records::OP_GET));
}

/// The three listings are read the way `tools/list` is read, and for the same reason.
///
/// One reading for four classes because one SENTENCE covers all four: a listing is what was
/// approved, minus what is quarantined. A listing composed from the catalogue alone would advertise
/// the operator's approved shape for a server that has stopped serving it that way, which is the
/// sentence [`Reads::CatalogueSnapshot`] is written under.
#[test]
fn the_listings_read_the_catalogue_snapshot() {
    for op in [
        ops::OP_TOOLS_LIST,
        ops::OP_PROMPTS_LIST,
        ops::OP_RESOURCES_LIST,
        ops::OP_RESOURCE_TEMPLATES_LIST,
    ] {
        assert_eq!(
            reads(op),
            Some(Reads::CatalogueSnapshot),
            "{op} is a listing and is not read as one"
        );
    }
}

/// Each listing carries its OWN member name, and carries the cacheable pair beside it.
///
/// The member is the whole of what separates these answers on the wire: a listing rendered under
/// another listing's member is an answer to a question the caller did not ask, and every client of
/// this protocol reads the member rather than the request it replies to.
#[test]
fn each_listing_carries_its_own_member() {
    let one = vec![serde_json::json!({"name": "a"})];
    for (answer, member) in [
        (prompts_list_result(one.clone()), "prompts"),
        (resources_list_result(one.clone()), "resources"),
        (
            resource_templates_list_result(one.clone()),
            "resourceTemplates",
        ),
    ] {
        assert_eq!(answer[member], serde_json::json!([{"name": "a"}]));
        assert_eq!(answer["cacheScope"], CACHE_SCOPE);
        assert_eq!(answer["ttlMs"], CACHE_TTL_MS);
        assert_eq!(
            answer.as_object().expect("a listing is a document").len(),
            3,
            "the {member} listing carries a member the server half does not write"
        );
    }
}

/// A caller whose grant reaches nothing gets the EMPTY listing rather than an error.
///
/// Asserted per listing rather than once, because it is the rule each of them is written under: an
/// error would tell a caller that something exists behind the grant, and the empty list is what the
/// existing server answers on all four.
#[test]
fn an_empty_grant_lists_nothing_rather_than_refusing() {
    assert_eq!(
        prompts_list_result(Vec::new())["prompts"],
        serde_json::json!([])
    );
    assert_eq!(
        resources_list_result(Vec::new())["resources"],
        serde_json::json!([])
    );
    assert_eq!(
        resource_templates_list_result(Vec::new())["resourceTemplates"],
        serde_json::json!([])
    );
}

/// The three task verbs read the ONE task the request names, and read nothing else.
///
/// One reading for three classes, and the reading is the READ half of their plans. Two of the three
/// go on to write the task back, and that write is deliberately not named here: a write leg run from
/// the root with no key and no body would put an empty record where a caller's task was.
#[test]
fn the_task_verbs_read_the_one_task_they_name() {
    for op in [ops::OP_TASK_GET, ops::OP_TASK_UPDATE, ops::OP_TASK_CANCEL] {
        assert_eq!(
            reads(op),
            Some(Reads::TaskRecord),
            "{op} names a task and is not read as naming one"
        );
    }
    let named: Vec<(&str, &str)> = Reads::TaskRecord
        .legs()
        .iter()
        .map(|(schema, op)| (schema.as_str(), *op))
        .collect();
    assert_eq!(
        named,
        vec![(records::SCHEMA_TASK.as_str(), records::OP_GET)]
    );
}

/// A task is handed back exactly as the record says it is, with no caching hint on it.
///
/// The absence of the hint is the assertion. A task is the one answer of this protocol whose whole
/// purpose is to have CHANGED since the last time it was asked for, so a hint inviting a client to
/// keep it would invite the client to poll a value it never re-reads.
#[test]
fn a_task_is_handed_back_as_the_record_says_it_is() {
    let detailed = serde_json::json!({"taskId": "t-1", "status": "working"});
    let answered = task_get_result(detailed.clone());
    assert_eq!(answered, detailed);
    assert!(answered.get("cacheScope").is_none());
    assert!(answered.get("ttlMs").is_none());
}

/// Delivering to a task and cancelling one are ACKED with the empty document, and with nothing else.
///
/// One function for the two acks, because they are one ack. An ack carrying the task's own
/// identifier or status would be a second, racing view of the task beside the one `tasks/get`
/// answers, and a client would have to decide which of the two to believe.
#[test]
fn the_task_acks_are_the_empty_document() {
    assert_eq!(task_ack_result(), serde_json::json!({}));
    assert!(task_ack_result()
        .as_object()
        .expect("an ack is a document")
        .is_empty());
}

/// The two verbs that name ONE catalogue entry read exactly that, and read no demotion row.
///
/// The difference from [`Reads::ServerRegistry`] is the whole cell: a call resolves an entry AND
/// asks whether the server behind it has been taken out of service, because a call reaches that
/// server. Rendering a prompt or reading a resource is answered from what was approved, and the
/// plan for both says so — the demotion row is not on it, so a reading that named one would be an
/// answer assembled from a record the unit never read.
#[test]
fn the_named_reads_read_one_catalogue_entry() {
    for op in [ops::OP_PROMPT_GET, ops::OP_RESOURCE_READ] {
        assert_eq!(
            reads(op),
            Some(Reads::CatalogueEntry),
            "{op} names one entry and is not read as naming one"
        );
    }
    let named: Vec<(&str, &str)> = Reads::CatalogueEntry
        .legs()
        .iter()
        .map(|(schema, op)| (schema.as_str(), *op))
        .collect();
    assert_eq!(
        named,
        vec![(records::SCHEMA_CATALOGUE.as_str(), records::OP_GET)]
    );
    assert_ne!(Reads::CatalogueEntry, Reads::ServerRegistry);
}

/// A rendered prompt carries its description and its messages, and carries NO caching hint.
///
/// The absence is the assertion. A rendered prompt is composed from the caller's own arguments
/// substituted into the operator's template, so two callers sending different arguments get
/// different documents from one entry — and a hint inviting either of them to keep it would invite
/// them to reuse the other's.
#[test]
fn a_rendered_prompt_carries_its_description_and_messages() {
    let messages = vec![serde_json::json!({"role": "user", "content": "hi"})];
    let answered = prompt_get_result(Some("what it does"), messages.clone());
    assert_eq!(answered["description"], "what it does");
    assert_eq!(answered["messages"], serde_json::json!(messages));
    assert!(answered.get("cacheScope").is_none());
    assert!(answered.get("ttlMs").is_none());
    assert_eq!(
        answered
            .as_object()
            .expect("a rendered prompt is a document")
            .len(),
        2,
        "a rendered prompt carries a member the server half does not write"
    );
    // A prompt registered without a description says so with `null`, and does not drop the member:
    // a client reading an absent member cannot tell it from a member this build forgot to write.
    let undescribed = prompt_get_result(None, Vec::new());
    assert_eq!(undescribed["description"], serde_json::Value::Null);
    assert_eq!(undescribed["messages"], serde_json::json!([]));
}

/// A resource's contents come back under `contents`, as a LIST, with the cacheable pair.
///
/// The list is the shape even for the one resource a read names, because the protocol declares it
/// that way and a client that unwrapped a single object would break on the day a resource is
/// answered in two parts.
#[test]
fn a_resource_read_answers_a_list_of_contents() {
    let one = vec![serde_json::json!({"uri": "file:///a", "text": "x"})];
    let answered = resource_read_result(one.clone());
    assert_eq!(answered["contents"], serde_json::json!(one));
    assert_eq!(answered["cacheScope"], CACHE_SCOPE);
    assert_eq!(answered["ttlMs"], CACHE_TTL_MS);
    assert_eq!(answered.as_object().expect("a read is a document").len(), 3);
}

/// Completion is answered from NOTHING, and the answer is the empty set stated in full.
///
/// Two assertions in one cell because they are one fact. The reading is [`Reads::Nothing`] and the
/// answer is a constant, and both are true for the same reason: a completion is a set of candidate
/// VALUES for a named argument, and the only place this node could get one is an operator declaring
/// it — which no registration does. So the honest answer is "there are no suggestions", spelled
/// out with `hasMore` and `total` rather than left as an omission, because a caller reading a bare
/// empty array cannot tell a complete answer from a truncated one.
///
/// The request's refs are deliberately not read. A completion naming a prompt the caller may not
/// see would otherwise answer differently from one naming a prompt that does not exist, and the
/// difference is a probe for what is behind the grant.
#[test]
fn completion_reads_nothing_and_answers_the_empty_set() {
    assert_eq!(reads(ops::OP_COMPLETION), Some(Reads::Nothing));
    let answered = completion_result();
    assert_eq!(
        answered,
        serde_json::json!({
            "completion": { "values": [], "hasMore": false, "total": 0 },
        })
    );
    assert!(answered.get("cacheScope").is_none());
}

/// **WHOSE BYTES THE ANSWER IS, asserted as bytes.**
///
/// The document below is what a caller reads, and it is written out in full rather than rebuilt from
/// the same helpers the subject uses — a cell that composed its expectation the way the subject
/// composes its answer asserts that a function equals itself. Every member is pinned: the version,
/// the echoed identifier, the empty candidate set stated in full, and the discriminator this node
/// stamps rather than passes through.
///
/// The member ORDER is the serializer's and not this crate's: the document type sorts its members,
/// so the bytes below are sorted, and a build that turned insertion order on would go red here
/// rather than silently reshape every answer this node gives.
#[test]
fn completion_bytes_are_composed_by_this_plane() {
    let bytes = composed(
        ops::OP_COMPLETION,
        &Composing {
            rpc_id: Some(b"1"),
            rows: &[],
        },
    )
    .expect("completion is a composed class")
    .expect("a numeric identifier writes");
    assert_eq!(
        core::str::from_utf8(&bytes).expect("the answer is text"),
        r#"{"id":1,"jsonrpc":"2.0","result":{"completion":{"hasMore":false,"total":0,"values":[]},"resultType":"complete"}}"#
    );
}

/// A STRING identifier is echoed as the string it is, and the quotes travel with it.
///
/// Its own cell beside the numeric one because the two are different arms of the reader and the
/// difference is invisible in the answer's shape: an identifier read as a number and echoed as a
/// string is an answer no client correlates.
#[test]
fn a_string_identifier_is_echoed_as_the_string_it_arrived_as() {
    let bytes = composed(
        ops::OP_COMPLETION,
        &Composing {
            rpc_id: Some(br#""abc""#),
            rows: &[],
        },
    )
    .expect("completion is a composed class")
    .expect("a string identifier writes");
    assert_eq!(
        core::str::from_utf8(&bytes).expect("the answer is text"),
        r#"{"id":"abc","jsonrpc":"2.0","result":{"completion":{"hasMore":false,"total":0,"values":[]},"resultType":"complete"}}"#
    );
}

/// An arrival with NO identifier gets no identifier member, which is the success path's asymmetry.
///
/// The refusal path always writes the member and writes the empty value where there is none; this
/// one omits it. Pinned here because a peer's own test for "is this a response" is whether the
/// member is there at all.
#[test]
fn a_composed_answer_with_no_identifier_omits_the_member() {
    let bytes = composed(ops::OP_COMPLETION, &Composing::default())
        .expect("completion is a composed class")
        .expect("no identifier writes");
    assert_eq!(
        core::str::from_utf8(&bytes).expect("the answer is text"),
        r#"{"jsonrpc":"2.0","result":{"completion":{"hasMore":false,"total":0,"values":[]},"resultType":"complete"}}"#
    );
}

/// **[`COMPOSED`] and [`composed`] are one statement, and this cell holds them to it.**
///
/// The root derives its fall-through gate from the LIST and takes its bytes from the FUNCTION, so a
/// class the function answers without the list declaring it is a class whose legacy arm the deletion
/// list would still call reachable while it was not — and a class the list declares without the
/// function answering it is a fall-through the root has been told not to take. Either way one of the
/// two readers is wrong about which bytes reach the caller.
#[test]
fn every_composed_class_is_declared_and_every_declared_class_composes() {
    for op in ops::OP_CLASSES {
        assert_eq!(
            composed(
                *op,
                &Composing {
                    rpc_id: Some(b"1"),
                    rows: &[]
                }
            )
            .is_some(),
            COMPOSED.contains(op),
            "{op} answers and declares differently"
        );
    }
}

/// Composing the BYTES is a stricter claim than answering the UNIT, so [`COMPOSED`] is inside
/// [`ANSWERED`].
///
/// A class whose bytes this plane wrote but whose unit the loop does not answer would be a document
/// composed for a request nothing decided: no reading was declared for it, so no record leg ran, and
/// the answer would be assembled from state the unit never read.
#[test]
fn composed_is_a_subset_of_answered() {
    for op in COMPOSED {
        assert!(
            ANSWERED.contains(op),
            "{op} composes bytes without being answered"
        );
        assert!(
            reads(*op).is_some(),
            "{op} composes bytes without declaring a reading"
        );
    }
}

/// Two rows of every kind, on two servers, in catalogue order — what a listing is composed from.
fn eight_rows() -> Vec<crate::catalogue::Row> {
    use crate::catalogue::{Row, RowKind};
    let mut rows = Vec::new();
    for kind in RowKind::ALL {
        for server in ["db", "fs"] {
            let name = format!("{server}_{}", kind.as_str());
            rows.push(Row {
                kind: *kind,
                server: server.to_string(),
                name: name.clone(),
                wire: serde_json::json!({ "name": name, "description": format!("{server} d") }),
            });
        }
    }
    rows
}

/// **THE THREE LISTINGS' BYTES ARE THIS PLANE'S, written out in full.**
///
/// One cell per class would be three copies of one statement; one loop is the statement once. Each
/// document below is the legacy arm's shape for the same rows — `cache_hints` over the member, the
/// discriminator stamped, the identifier echoed, members sorted by the serializer — spelled out
/// rather than rebuilt from the same helpers, so this asserts a document and not a function's
/// equality with itself. Only the rows of the listing's own kind appear, in the order handed in.
#[test]
fn the_three_listings_bytes_are_composed_by_this_plane() {
    let rows = eight_rows();
    let from = Composing {
        rpc_id: Some(b"9"),
        rows: &rows,
    };
    for (op, expected) in [
        (
            ops::OP_PROMPTS_LIST,
            r#"{"id":9,"jsonrpc":"2.0","result":{"cacheScope":"private","prompts":[{"description":"db d","name":"db_prompt"},{"description":"fs d","name":"fs_prompt"}],"resultType":"complete","ttlMs":0}}"#,
        ),
        (
            ops::OP_RESOURCES_LIST,
            r#"{"id":9,"jsonrpc":"2.0","result":{"cacheScope":"private","resources":[{"description":"db d","name":"db_resource"},{"description":"fs d","name":"fs_resource"}],"resultType":"complete","ttlMs":0}}"#,
        ),
        (
            ops::OP_RESOURCE_TEMPLATES_LIST,
            r#"{"id":9,"jsonrpc":"2.0","result":{"cacheScope":"private","resourceTemplates":[{"description":"db d","name":"db_resource_template"},{"description":"fs d","name":"fs_resource_template"}],"resultType":"complete","ttlMs":0}}"#,
        ),
    ] {
        let bytes = composed(op, &from)
            .unwrap_or_else(|| panic!("{op} is a composed class"))
            .expect("a numeric identifier writes");
        assert_eq!(
            core::str::from_utf8(&bytes).expect("the answer is text"),
            expected,
            "{op}"
        );
    }
}

/// A listing over NO rows is the empty listing, stated in full, and not a refusal.
///
/// The rows arrive narrowed, so "no rows" is both "no `tools:` block" and "a caller whose grant
/// reaches nothing", and the legacy answers the same empty document for both. Pinned as bytes.
#[test]
fn a_listing_over_no_rows_is_the_empty_listing() {
    let bytes = composed(ops::OP_PROMPTS_LIST, &Composing::default())
        .expect("a composed class")
        .expect("no identifier writes");
    assert_eq!(
        core::str::from_utf8(&bytes).expect("the answer is text"),
        r#"{"jsonrpc":"2.0","result":{"cacheScope":"private","prompts":[],"resultType":"complete","ttlMs":0}}"#
    );
}

/// `tools/list` is NOT composed, and this cell is what makes taking it by accident red.
///
/// The reason is on [`COMPOSED`]'s own documentation: the quarantine filter reads the live
/// sightings, which are not a record this plane can be handed, so a tools listing composed from rows
/// would advertise what the legacy hides. The tool rows are still rows — they are on the same scan —
/// and this asserts that holding them is not the same as composing over them.
#[test]
fn the_tools_listing_is_not_composed_while_quarantine_is_a_sighting() {
    assert!(!COMPOSED.contains(&ops::OP_TOOLS_LIST));
    let rows = eight_rows();
    assert!(rows
        .iter()
        .any(|r| r.kind == crate::catalogue::RowKind::Tool));
    assert!(composed(
        ops::OP_TOOLS_LIST,
        &Composing {
            rpc_id: Some(b"1"),
            rows: &rows
        }
    )
    .is_none());
}
