// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT AN ANSWER IS, for the operations this plane answers out of its own declarations and its own
//! records — moved here from inside the protocol's server.
//!
//! ## What moved, and why it could
//!
//! Four methods are the first through the loop, and the four are not alike. Two of them —
//! `initialize` and `ping` — are answered by the existing server from COMPILE-TIME CONSTANTS: no
//! catalogue, no registry, no clock, no session. They were written inside a console serve loop
//! (`busbar-mcp`'s console serve entry), which is the one place in the tree that could not be reached
//! without opening a process's standard input. That is a wire fact living inside an I/O loop, and
//! this module is where it belongs: it is what the bytes MEAN, and it is a `fn` over nothing.
//!
//! The other two — `tools/list` and `tools/call` — are not pure, and this module does not pretend
//! they are. What moved for them is the part that IS: the classification of which state an answer is
//! composed from, the caching hints the cacheable answers carry, and the shape the answer is
//! assembled into. What did NOT move is every reach — the catalogue read, the sightings read, the
//! grant walk, the quarantine filter, the hop — because a plane performs no input and no output.
//! Those are declared here as [`Reads`], which names the record legs the KERNEL runs on this plane's
//! behalf, and they are run by the root over the store.
//!
//! ## The rule this module is written under
//!
//! If a byte differs between what this module produces and what the existing server produces, the
//! existing server is the answer and this module has the bug. Every constant below is PINNED by a
//! test that reads that server's own source, because this crate may not name it — a copy that is
//! checked is not a second opinion.

use busbar_contract::ids::{OpClassId, RecordSchemaId};

use crate::{ops, records};

/// The name this node publishes itself under, on every document that names a server.
///
/// One constant for the two documents that carry it, because they are two statements of one fact:
/// a node whose handshake said one name and whose discovery said another would be two servers to
/// any client that read both.
pub const SERVER_NAME: &str = "busbar";

/// The revision this build implements, as the wire spells it.
///
/// The codec's own, not a copy: three crates must agree on this string and the compiler holds the
/// equality rather than a comment.
pub const PROTOCOL_VERSION: &str = busbar_mcp_codec::codec::PROTOCOL_VERSION;

/// Who may keep a cacheable answer. One reader per caller, because every cacheable answer of this
/// protocol is computed from the CALLER's own grant — a shared cache would hand one caller's
/// entitlement to another.
pub const CACHE_SCOPE: &str = "private";

/// How long a cacheable answer may be kept without asking again.
///
/// Zero, and it is a declaration rather than an omission: the answers are grant-scoped and the grant
/// can move at any moment, so the honest lifetime is none. The hint is still written, because a
/// client that reads no hint at all cannot tell a deliberate zero from a server that forgot.
pub const CACHE_TTL_MS: i64 = 0;

/// The state one served operation is composed from.
///
/// A CLASSIFICATION and not a fetch. Every arm names what the kernel must have run before this
/// plane's answer can be assembled, in the plane's own record vocabulary — so the root reads which
/// legs to run off the declaration rather than off a table it keeps beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reads {
    /// Nothing at all. The answer is a function of this build and of no caller, no registration and
    /// no record. There is no leg to run and no state that could make two callers' answers differ.
    Nothing,
    /// The catalogue snapshot, as it stood when this unit arrived, minus what is quarantined.
    ///
    /// Two schemas and not one: what was approved, and what has since been demoted. A listing
    /// composed from the first alone advertises the operator's approved shape for a server that has
    /// stopped serving it that way.
    CatalogueSnapshot,
    /// The ONE registration the request names, and the demotion row beside it — the server
    /// registry, as this plane reaches it.
    ///
    /// A call is the one operation that needs a named entry rather than a listing: the catalogue
    /// entry says whether this caller may reach the named tool and what shape it was approved at,
    /// and the demotion row says whether the server behind it has been taken out of service.
    ///
    /// **A gap, named rather than hidden.** [`crate::records::SCHEMA_SETTINGS`] is where a
    /// registration's own applied configuration belongs, and this plane's plan for a call does not
    /// read it: how the server is reached still comes from the registration table the root holds.
    /// That is where the reach is today, and moving it is a later stage's work, not a leg this
    /// module can invent.
    ServerRegistry,
    /// The ONE long-running task the request names, as the kernel holds it.
    ///
    /// Every task verb of this protocol names its subject in `params.taskId` and answers about that
    /// subject alone, so the reading is a single `get` and never a scan: a verb that scanned would
    /// have read every caller's tasks in order to answer about one of them, and a task identifier is
    /// the only credential a poll presents.
    ///
    /// **The write half is deliberately absent.** Delivering to a task and cancelling one both go on
    /// to put the task back, and that leg carries a record key and a body the answer produces — so
    /// naming it here would have the root run it with the empty key, which writes an empty record
    /// over a caller's task. What an answer is COMPOSED FROM is a read; what it goes on to do is the
    /// plan's, and the plan already has both.
    TaskRecord,
    /// The ONE catalogue entry the request names, and nothing beside it.
    ///
    /// Distinct from [`Reads::ServerRegistry`] by the demotion row, and the difference is the whole
    /// of it. A call resolves an entry AND asks whether the server behind that entry has been taken
    /// out of service, because a call goes on to reach that server. Rendering a prompt or reading a
    /// resource is answered from what the operator approved, and the plan for both says so — the
    /// demotion row is not on it, so naming one here would be an answer assembled from a record the
    /// unit never read.
    CatalogueEntry,
}

impl Reads {
    /// The record legs this reading is composed of.
    ///
    /// A SUBSET of the plan [`crate::plane`] returns for the classes that read this way, never a
    /// second copy of it: the plan is the single source for what a unit runs, and this names the
    /// part of it an answer is composed FROM. The test below asserts the containment in the one
    /// direction it holds, so a reading that named a leg the plan never runs is red here rather than
    /// an answer assembled from a record nobody read.
    #[must_use]
    pub fn legs(self) -> &'static [(RecordSchemaId, &'static str)] {
        match self {
            Reads::Nothing => &[],
            Reads::CatalogueSnapshot => &[
                (records::SCHEMA_CATALOGUE, records::OP_SCAN),
                (records::SCHEMA_DEMOTION, records::OP_SCAN),
            ],
            Reads::ServerRegistry => &[
                (records::SCHEMA_CATALOGUE, records::OP_GET),
                (records::SCHEMA_DEMOTION, records::OP_GET),
            ],
            Reads::TaskRecord => &[(records::SCHEMA_TASK, records::OP_GET)],
            Reads::CatalogueEntry => &[(records::SCHEMA_CATALOGUE, records::OP_GET)],
        }
    }
}

/// What one operation class reads, where this plane declares an answer for it.
///
/// `None` for a class this stage does not answer through the loop. That is a declaration and not a
/// gap: the composition root's served set is derived from this function, so an operation with no
/// reading here is one the mount hands straight to the surface that already answers it.
#[must_use]
pub fn reads(op: OpClassId) -> Option<Reads> {
    match op {
        // The three answers composed from no record at all. The two console-era verbs are functions
        // of this build; completion is a function of the registry HAVING no candidate values to
        // offer, which no registration declares — so all three are the same reading for three
        // different reasons, and each reason is written on its own answer below.
        ops::OP_INITIALIZE | ops::OP_PING | ops::OP_COMPLETION => Some(Reads::Nothing),
        // THE FOUR LISTINGS, one reading. A listing of this protocol is the same sentence four
        // times over — what was approved, minus what is quarantined — and the member it is rendered
        // under is the whole of what makes them four answers rather than one.
        ops::OP_TOOLS_LIST
        | ops::OP_PROMPTS_LIST
        | ops::OP_RESOURCES_LIST
        | ops::OP_RESOURCE_TEMPLATES_LIST => Some(Reads::CatalogueSnapshot),
        ops::OP_TOOL_CALL => Some(Reads::ServerRegistry),
        // THE THREE TASK VERBS, one reading. All three name one task and answer about that task,
        // and the two that go on to write it back declare that write on the plan rather than here.
        ops::OP_TASK_GET | ops::OP_TASK_UPDATE | ops::OP_TASK_CANCEL => Some(Reads::TaskRecord),
        // The two that name ONE entry and answer about it. Both go on to reach the server behind
        // that entry, and both declare that hop on the plan rather than as a reading.
        ops::OP_PROMPT_GET | ops::OP_RESOURCE_READ => Some(Reads::CatalogueEntry),
        _ => None,
    }
}

/// Every operation class this module composes an answer for, in declaration order.
///
/// It is a list rather than a predicate because the composition root prints it at boot and the
/// mount's own shadow predicate is built from it — and a set two readers derive separately is a set
/// they can derive differently.
///
/// A class here is a class the LEG answers; a class absent from here is one the mount hands to the
/// surface that already answers it, which on this node is the protocol's legacy body. So this list
/// growing is the only thing that makes that body unreachable, and it grows one coherent group at a
/// time rather than all at once, because each group has its own reading and its own wire shape to
/// be right about.
pub const ANSWERED: &[OpClassId] = &[
    ops::OP_INITIALIZE,
    ops::OP_PING,
    ops::OP_TOOLS_LIST,
    ops::OP_TOOL_CALL,
    ops::OP_PROMPTS_LIST,
    ops::OP_RESOURCES_LIST,
    ops::OP_RESOURCE_TEMPLATES_LIST,
    ops::OP_TASK_GET,
    ops::OP_TASK_UPDATE,
    ops::OP_TASK_CANCEL,
    ops::OP_PROMPT_GET,
    ops::OP_RESOURCE_READ,
    ops::OP_COMPLETION,
];

/// Add the caching hints to a result that is CACHEABLE.
///
/// One function so the pair cannot drift apart across the cacheable answers, for the same reason the
/// error envelope is one function for its status-and-code pair: a hint that says one scope in one
/// place and another elsewhere is a hint no client can act on.
///
/// A result that is not a document is handed back untouched. There is nothing to hint ABOUT, and
/// wrapping one here would change a shape the caller is going to read.
#[must_use]
pub fn cache_hints(value: serde_json::Value) -> serde_json::Value {
    let mut value = value;
    if let Some(object) = value.as_object_mut() {
        object.insert("cacheScope".into(), CACHE_SCOPE.into());
        object.insert("ttlMs".into(), CACHE_TTL_MS.into());
    }
    value
}

/// The `initialize` answer: the console-era negotiation, as this build answers it.
///
/// busbar implements ONE revision and this result says so — `protocolVersion` names it, so a
/// legacy-era client either speaks it from here on or disconnects, which is the negotiation
/// completing in either direction. No session is created because the revision has none to create.
///
/// The version is a PARAMETER and not `env!("CARGO_PKG_VERSION")`, and that is the one thing that
/// changed in the move. The number belongs to the NODE, and reading it out of whichever crate the
/// function happens to live in is how a function that moves crates changes a byte on the wire.
///
/// Nothing here is read from a caller, a registration or a clock: two callers get the same document,
/// and so does the same caller twice.
#[must_use]
pub fn initialize_result(node_version: &str) -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": true },
            "prompts": { "listChanged": true },
            "resources": { "listChanged": true, "subscribe": true },
            "completions": {},
            "logging": {},
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": node_version,
        },
        "instructions": instructions(),
    })
}

/// The sentence the handshake hands a client about what it has connected to.
///
/// Its own function because it is the one member of the handshake that is FORMATTED rather than
/// written, and a format string reproduced at a second call site is a second wording.
#[must_use]
pub fn instructions() -> String {
    format!(
        "This server speaks MCP revision {PROTOCOL_VERSION}: no handshake is required, and every \
         request states its protocol version and client capabilities in `params._meta`."
    )
}

/// The `ping` answer: the empty document.
///
/// It is a function rather than a constant expression at each call site for the reason every other
/// answer here is one — there is exactly one place this protocol's answer to `ping` is written down,
/// and a second `json!({})` somewhere else is a second place for it to stop being empty.
#[must_use]
pub fn ping_result() -> serde_json::Value {
    serde_json::json!({})
}

/// The `tools/list` answer, over the tools the caller may see.
///
/// The LIST is the argument, and that is the whole of the split. Which tools a caller may see is an
/// entitlement walk over a grant, then a trust filter over the drift sightings, then a render — none
/// of which is a plane's to do, and all of which is composed from the record legs [`Reads`] names.
/// What this function owns is the shape the answers are handed back in, which is a wire fact.
///
/// A caller whose grant reaches nothing gets the empty list rather than an error. That is
/// deliberate: an error would tell a caller that something exists behind the grant, and the empty
/// list is what the existing server answers.
#[must_use]
pub fn tools_list_result(tools: Vec<serde_json::Value>) -> serde_json::Value {
    cache_hints(serde_json::json!({ "tools": tools }))
}

/// The `prompts/list` answer, over the prompts the caller may see.
///
/// Its own function rather than an argument to a shared one, for the reason each of the four
/// listings has its own: the MEMBER is the answer's identity on the wire, and a listing rendered
/// under a member computed from a parameter is a listing one wrong argument turns into a different
/// protocol's answer. The entitlement walk, the trust filter and the render are not here and are not
/// this plane's — [`Reads::CatalogueSnapshot`] names the record legs they are composed from.
#[must_use]
pub fn prompts_list_result(prompts: Vec<serde_json::Value>) -> serde_json::Value {
    cache_hints(serde_json::json!({ "prompts": prompts }))
}

/// The `resources/list` answer, over the resources the caller may read.
#[must_use]
pub fn resources_list_result(resources: Vec<serde_json::Value>) -> serde_json::Value {
    cache_hints(serde_json::json!({ "resources": resources }))
}

/// The `resources/templates/list` answer, over the URI templates the caller may expand.
///
/// A resource template is an approval of a SHAPE rather than of an address, so it is a listing of
/// its own and not a variety of the one above: the two are approved by different operator
/// declarations and a client expands one and reads the other.
#[must_use]
pub fn resource_templates_list_result(templates: Vec<serde_json::Value>) -> serde_json::Value {
    cache_hints(serde_json::json!({ "resourceTemplates": templates }))
}

/// The `tools/call` answer, over what the server that was reached said.
///
/// NOT cached and deliberately not: a call is an effect, and a hint inviting a client to reuse the
/// answer would invite it to skip the effect. The existing server writes no hint here either, which
/// is the pin.
///
/// The discriminator is NOT stamped here. It is stamped once, by [`crate::jsonrpc::success`], over
/// every answer this plane writes — and stamping it here as well would be the one member of the
/// envelope written in two places.
#[must_use]
pub fn tool_call_result(upstream: serde_json::Value) -> serde_json::Value {
    upstream
}

/// The `prompts/get` answer: one rendered prompt, with the description it was registered under.
///
/// NOT cached, and the absence is deliberate: a rendered prompt is the operator's template with the
/// CALLER's own arguments substituted into it, so two callers sending different arguments get
/// different documents out of one entry — and a hint inviting either to keep it would invite them to
/// reuse the other's.
///
/// The description is `Option` and is written as `null` rather than omitted where there is none. A
/// client reading an absent member cannot tell a prompt registered without a description from a
/// build that forgot to write one.
///
/// **The substitution and the markup strip are not here and must not be.** Both read the caller's
/// own bytes and both are performed before this is called; what this owns is the shape the two
/// halves are handed back in, which is a wire fact.
#[must_use]
pub fn prompt_get_result(
    description: Option<&str>,
    messages: Vec<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "description": description,
        "messages": messages,
    })
}

/// The `resources/read` answer: what the named resource holds, as a LIST.
///
/// A list even for the one resource a read names, because the protocol declares it that way: a
/// client that unwrapped a single object would break on the day a resource is answered in two
/// parts, and this build not having that day yet is not a licence to publish a shape that forbids
/// it.
#[must_use]
pub fn resource_read_result(contents: Vec<serde_json::Value>) -> serde_json::Value {
    cache_hints(serde_json::json!({ "contents": contents }))
}

/// The `completion/complete` answer: the empty candidate set, stated in full.
///
/// **The empty set is a fact about the registry and not a stub.** A completion is a set of candidate
/// VALUES for a named argument, and the only place this node could get one is an operator declaring
/// it — a prompt is registered with a description and a template, and neither states a value set.
/// There is nothing to ask an upstream for either: a completion is answered from the catalogue this
/// node itself serves, so asking an upstream would be asking it to complete an argument of a prompt
/// this node composed.
///
/// So the honest answer is "there are no suggestions", spelled with `hasMore` and `total` rather
/// than left as a bare empty array — a caller reading one of those cannot tell a complete answer
/// from a truncated one.
///
/// **It takes no argument, and that is the security property rather than an economy.** The
/// request's refs are deliberately not resolved against the catalogue: a completion naming a prompt
/// the caller may not see would otherwise answer differently from one naming a prompt that does not
/// exist, and the difference between those two answers is a probe for what is behind the grant.
#[must_use]
pub fn completion_result() -> serde_json::Value {
    serde_json::json!({
        "completion": { "values": [], "hasMore": false, "total": 0 },
    })
}

/// The `tasks/get` answer: the task, as the record this plane keeps it in says it is.
///
/// NOT cached, and the absence of the hint is the declaration rather than an oversight: a task is
/// the one answer of this protocol whose whole purpose is to have CHANGED since the last time it was
/// asked for, so a hint inviting a client to keep it would invite it to poll a value it never
/// re-reads.
///
/// There is no companion verb that fetches what a finished task finished WITH, and there must not
/// be: a client that could observe a task as complete and then fail to fetch its result is a client
/// that has paid for something it cannot collect. So whatever the task carries travels on this one
/// answer, which is why the argument is the record's own document and not a status.
#[must_use]
pub fn task_get_result(task: serde_json::Value) -> serde_json::Value {
    task
}

/// The answer to delivering into a task, and to asking one to stop: the empty document.
///
/// ONE function for the two verbs, because it is one ack. An ack carrying the task's own identifier
/// or its status would be a second, racing view of the task beside the one `tasks/get` answers, and
/// a client handed two views has to decide which of them to believe — so there is exactly one reader
/// of a task's state and this is not it.
///
/// Distinct from [`ping_result`] despite the same bytes, for the reason every answer in this module
/// is its own function: they are two facts that happen to agree today, and a shared function would
/// make one of them change when the other did.
#[must_use]
pub fn task_ack_result() -> serde_json::Value {
    serde_json::json!({})
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHOSE BYTES THE ANSWER IS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// Every class whose ANSWER BYTES this plane composes, in declaration order.
///
/// **This is a narrower statement than [`ANSWERED`] and the difference is the whole of it.** A class
/// in `ANSWERED` is one whose UNIT the loop owns: the kernel runs its record legs and the twelve
/// steps decide it. A class here is one whose BYTES are additionally this plane's own — the document
/// that reaches the caller was written by [`composed`] below and by nothing else, so the surface the
/// mount wrapped is never asked about it and its arm there is unreachable.
///
/// A class is added here only when every input its answer is composed from is already in this
/// plane's hands — on [`Composing`], and nowhere else. Three of the four listings are: the rows the
/// catalogue leg hands back, already narrowed to the caller by the scope walk, are the whole of what
/// `prompts/list`, `resources/list` and `resources/templates/list` are composed from, and the render
/// travels ON the row. **`tools/list` is not**, and the reason is the one input the other three do
/// not read: the quarantine filter is asked of the LIVE SIGHTINGS — what the last refresh observed
/// each server serving, held in the protocol crate's memory — and not of a record. The demotion
/// records this plane's `Reads::CatalogueSnapshot` scans are a strict subset of the states that
/// filter hides (a tool missing from the last observed list, a failed observation), so a tools
/// listing composed from rows and demotion records would advertise, for some servers, what the
/// legacy hides. It joins when the sightings are a kernel-held record, which is the next cut.
///
/// It is a list rather than a predicate because the root's fall-through gate is derived from it, and
/// a set two readers derive separately is a set they can derive differently.
pub const COMPOSED: &[OpClassId] = &[
    ops::OP_COMPLETION,
    ops::OP_PROMPTS_LIST,
    ops::OP_RESOURCES_LIST,
    ops::OP_RESOURCE_TEMPLATES_LIST,
];

/// EVERYTHING A COMPOSED ANSWER IS COMPOSED FROM, handed in by the root as data.
///
/// Two halves, and the split between them is the whole of the catalogue-as-data face. `rpc_id` is
/// the arrival's — the identifier's raw bytes as the plane read them. `rows` are the KERNEL'S: the
/// catalogue records the route plan's read legs handed back, decoded in this plane's own grammar
/// ([`crate::catalogue::Row`]), and already narrowed to what THIS caller may see. The narrowing is
/// the scope walk's decision and is made before this value exists; a plane that filtered rows here
/// would be a plane interpreting a grant, which is the one thing the contract says it may not do.
///
/// A class composed from nothing reads neither half, and a class composed from rows reads the rows
/// and never the store. There is no third source: a composed answer that reached for anything not
/// on this value would be an answer composed from state the unit never read.
#[derive(Clone, Copy, Debug, Default)]
pub struct Composing<'a> {
    /// The identifier's RAW bytes exactly as they arrived, quotes and all — see
    /// [`crate::jsonrpc::Envelope::id_bytes`]. `None` is an arrival that carried no identifier.
    pub rpc_id: Option<&'a [u8]>,
    /// The catalogue rows this caller may see, in the order the catalogue lists them.
    pub rows: &'a [crate::catalogue::Row],
}

/// The whole answer document for one composed class, as the bytes that go on the wire.
///
/// `None` is a class this plane does not compose the bytes of — the root hands it to the surface the
/// mount wrapped, exactly as it did before this function existed. That is the DECLARATION and not a
/// gap: [`COMPOSED`] is the same statement as a list, and the two are pinned to each other by a cell
/// so a class answered here without being declared there cannot happen.
///
/// The envelope is [`crate::jsonrpc::success`] and the discriminator is
/// [`crate::jsonrpc::RESULT_TYPE_COMPLETE`], both by call rather than by copy: this is the same
/// writer the plane's own `encode_response` uses for an answer this node composed itself, so a
/// change to how this protocol frames a result moves both paths at once or neither.
///
/// `rpc_id` on [`Composing`] is echoed as the bytes it arrived as, and an arrival that carried no
/// identifier gets no member, which is the success path's own asymmetry rather than a choice made
/// here.
///
/// # Errors
/// Returns an encode error when the identifier's bytes cannot be read back as a value. The reader
/// admits only identifiers this can write, so it is the impossible arm — written as an error rather
/// than an unwrap because the day the two stop agreeing is a day a caller is owed a refusal, not a
/// day this node panics on the request path.
#[must_use]
pub fn composed(
    op: OpClassId,
    from: &Composing<'_>,
) -> Option<Result<Vec<u8>, busbar_contract::wire::Encode>> {
    use crate::catalogue::{wire_of, RowKind};
    let result = match op {
        // The empty candidate set, stated in full. Composed from no record and no caller, which is
        // why it is the first class whose bytes this plane can own: there is nothing to reach for.
        ops::OP_COMPLETION => completion_result(),
        // THE THREE LISTINGS COMPOSED FROM ROWS ALONE. Each is the rows of its own kind, in the
        // order the catalogue leg handed them, under its own member, with the cacheable pair — the
        // shape the result functions above already own. Nothing is filtered here: the rows arrived
        // narrowed, and a listing that narrowed again would be a second reading of the grant.
        ops::OP_PROMPTS_LIST => prompts_list_result(wire_of(from.rows, RowKind::Prompt)),
        ops::OP_RESOURCES_LIST => resources_list_result(wire_of(from.rows, RowKind::Resource)),
        ops::OP_RESOURCE_TEMPLATES_LIST => {
            resource_templates_list_result(wire_of(from.rows, RowKind::ResourceTemplate))
        }
        _ => return None,
    };
    Some(envelope(&result, from.rpc_id))
}

/// One composed result, wrapped in this protocol's successful envelope.
///
/// Its own function so every arm of [`composed`] is a RESULT and the framing is written once. An arm
/// that built its own envelope would be a second place for the discriminator, the version member and
/// the identifier's omission rule to be decided.
fn envelope(
    result: &serde_json::Value,
    rpc_id: Option<&[u8]>,
) -> Result<Vec<u8>, busbar_contract::wire::Encode> {
    let id = match rpc_id {
        Some(raw) => Some(crate::jsonrpc::id_value(raw)?),
        None => None,
    };
    let body =
        serde_json::to_vec(result).map_err(|_| busbar_contract::wire::Encode::Unrepresentable)?;
    crate::jsonrpc::success(id.as_ref(), &body, crate::jsonrpc::RESULT_TYPE_COMPLETE)
}

#[cfg(test)]
#[path = "tests/served.rs"]
mod tests;
