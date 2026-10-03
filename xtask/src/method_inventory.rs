//! `cargo xtask method-inventory [--write | --check | --selftest]` — THE METHOD INVENTORY GENERATOR.
//!
//! DERIVES the MCP and A2A method inventory, and the method x direction x transport MATRIX, from
//! sources that enumerate mechanically, and writes it to `qa/method-inventory.json`, which
//! `crates/busbar/tests/method_coverage.rs` turns into a build failure for any cell that is neither
//! implemented nor explicitly waived. NOT A GATE: a human runs it, reads the diff, and commits it.
//!
//! WHY THE LIST IS NOT TYPED OUT BY HAND. The owner's ruling for 1.6.0 is "i want full alphabet
//! coverage not just A-J. I want A-Z". A hand-written method list is precisely how coverage ends at
//! J with nobody noticing: an absent row looks exactly like a row that was considered and found not
//! to apply. So the inventory is READ OUT OF THE SPECIFICATION AUTHORS' OWN ARTEFACTS:
//!
//! * MCP: rmcp 3.1.2, `src/model.rs`. Every `const_string!(XMethod = "wire/name")` is the complete
//!   set of wire method names the SDK knows; the four `ts_union!` blocks (ClientRequest /
//!   ServerRequest / ClientNotification / ServerNotification) say who ORIGINATES each one. A method
//!   whose const is in no union is an ORPHAN and must be classified explicitly in
//!   [`mcp_orphan_originator`] — never silently dropped.
//! * A2A: a2a-pb 0.2.0, `proto/a2a.proto`. The `service A2AService` block's rpc list IS the method
//!   list, and each rpc's `google.api.http` option IS the HTTP+JSON binding.
//!
//! WHAT IS NOT MECHANICAL, AND HOW IT IS KEPT HONEST. Three facts cannot be read out of either
//! artefact; each is written down here with a citation and a CROSS-CHECK that refuses to run when
//! the derived list moves underneath it: [`LEGACY_JSONRPC_0_3`] must cover EXACTLY the derived rpc
//! set; [`extra_surfaces`] lists the surfaces that are neither rpcs nor JSON-RPC methods, with the
//! requirement ids that exercise them; every N/A cell carries a reason.
//!
//! The SDK sources are located in the cargo registry (`$CARGO_HOME` or `~/.cargo`,
//! `registry/src/*/rmcp-3.1.2/src/model.rs` and `a2a-pb-0.2.0/proto/a2a.proto`) and the command
//! REFUSES rather than skips when they are absent: an inventory derived from an absent source would
//! be an inventory of nothing.
//!
//! The command is a faithful port of the retired Python script of the same name; its output is
//! byte-identical to that script's, and the file's `_comment` header names this command.

use crate::ctx::Ctx;
use crate::rx::Regex;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const RMCP_VERSION: &str = "3.1.2";
pub const A2A_PB_VERSION: &str = "0.2.0";

/// MCP revision the pinned rmcp implements, and the A2A spec tag the pinned proto is cut from.
pub const MCP_REVISION: &str = "2026-07-28";
pub const A2A_SPEC_TAG: &str = "v1.0.1";

pub const MCP_TRANSPORTS: [&str; 2] = ["streamable-http", "stdio"];
pub const A2A_TRANSPORTS: [&str; 3] = ["jsonrpc", "http+json", "grpc"];
/// busbar is asked / busbar asks. It is BOTH, on BOTH protocols.
pub const ROLES: [&str; 2] = ["server", "client"];

/// The inventory's path under the tree.
pub const OUT: &str = "qa/method-inventory.json";

/// The two directions every method is owed a cell in, written as a LITERAL rather than read from
/// [`ROLES`]: a check that compares the cells against ROLES only restates the loop that built them.
const BOTH_DIRECTIONS: [&str; 2] = ["client", "server"];

/// A2A SPEC 9.1 "Method Naming" makes the JSON-RPC method name the PascalCase rpc name. SPEC 9.3's
/// Base Request Structure still shows the 0.3-era "category/action" placeholder, and SPEC 3.6.2
/// requires an agent to read a missing A2A-Version header AS 0.3 -- so the 0.3 names remain a live
/// surface, not history. The mapping is not derivable from the proto (SubscribeToTask ->
/// tasks/resubscribe is not a transform of anything), so it is written out and then cross-checked
/// for exact coverage of the derived rpc set.
pub const LEGACY_JSONRPC_0_3: &[(&str, &str)] = &[
    ("SendMessage", "message/send"),
    ("SendStreamingMessage", "message/stream"),
    ("GetTask", "tasks/get"),
    ("ListTasks", "tasks/list"),
    ("CancelTask", "tasks/cancel"),
    ("SubscribeToTask", "tasks/resubscribe"),
    (
        "CreateTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/set",
    ),
    (
        "GetTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/get",
    ),
    (
        "ListTaskPushNotificationConfigs",
        "tasks/pushNotificationConfig/list",
    ),
    (
        "DeleteTaskPushNotificationConfig",
        "tasks/pushNotificationConfig/delete",
    ),
    ("GetExtendedAgentCard", "agent/getAuthenticatedExtendedCard"),
];

/// rmcp declares this constant but routes it through no union, so a derivation that reads only the
/// unions loses it. SEP-1036 out-of-band elicitation responses: the response travels client ->
/// server, so the originator is the client. `(wire, originator, kind, note)`.
pub fn mcp_orphan_originator(wire: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match wire {
        "notifications/elicitation/response" => Some((
            "client",
            "notification",
            "rmcp declares ElicitationResponseNotificationMethod but lists it in no ts_union!; \
             SEP-1036 sends the elicitation response from client to server",
        )),
        _ => None,
    }
}

/// A surface the suites in testing/ exercise that is in NEITHER the rmcp method constants nor the
/// proto service block.
pub struct Extra {
    pub protocol: &'static str,
    pub method: &'static str,
    pub originator: &'static str,
    pub kind: &'static str,
    pub why_not_derived: &'static str,
    pub exercised_by: &'static [&'static str],
    pub na: &'static [(&'static str, &'static str)],
}

pub fn extra_surfaces() -> Vec<Extra> {
    vec![
        Extra {
            protocol: "a2a",
            method: "GET /.well-known/agent-card.json",
            originator: "client",
            kind: "http-resource",
            why_not_derived: "A2A SPEC 8.2 and the IANA registration in SPEC 14.3 define the Agent Card as an HTTP \
resource. It is not an rpc in service A2AService, so a proto-only derivation misses \
it entirely -- and it is the FIRST thing every A2A client fetches.",
            exercised_by: &[
                "a2a-tck CARD-DISC-001",
                "a2a-tck CARD-STRUCT-001",
                "a2a-tck CARD-PROTO-001/002",
                "a2a-tck CARD-CACHE-001/002/003",
                "a2a-tck CARD-SIGN-001..004",
                "a2a-tck CARD-EXT-001/002",
            ],
            na: &[(
                "grpc",
                "The card is an HTTP resource at a well-known path, not an rpc; gRPC has no \
well-known-path concept and the proto service block does not declare it. A gRPC-only \
peer discovers busbar via the same HTTP fetch.",
            )],
        },
        Extra {
            protocol: "a2a",
            method: "PushNotificationDelivery",
            originator: "server",
            kind: "webhook",
            why_not_derived: "Delivering a push notification is the agent POSTing a Task to the client's webhook \
URL. It is an obligation of the server role with no rpc, no JSON-RPC method and no \
gRPC form -- so it is invisible to the service block even though three TCK MUSTs \
judge it.",
            exercised_by: &[
                "a2a-tck PUSH-DELIVER-001",
                "a2a-tck PUSH-DELIVER-002",
                "a2a-tck PUSH-DELIVER-003",
            ],
            na: &[
                (
                    "jsonrpc",
                    "Delivery is an outbound HTTP POST to the client's webhook. There is no \
JSON-RPC request for it; the JSON-RPC binding only carries the CONFIG methods.",
                ),
                (
                    "grpc",
                    "Same: the proto declares the config messages, never a delivery rpc.",
                ),
            ],
        },
        Extra {
            protocol: "mcp",
            method: "GET /mcp (open SSE stream)",
            originator: "client",
            kind: "http-verb",
            why_not_derived: "Opening the server-to-client SSE stream, and resuming it with Last-Event-ID, is a \
streamable-HTTP transport obligation with no JSON-RPC method name, so an \
rmcp-model-only derivation cannot see it. Without it NO server-originated request \
or notification can reach the client over HTTP.",
            exercised_by: &[
                "mcp-conformance (official) server-sse-multiple-streams",
                "mcp-conformance (official) server-stateless",
            ],
            na: &[(
                "stdio",
                "stdio has no session envelope and no second channel: the stream IS the \
process's stdout, opened once at spawn.",
            )],
        },
        Extra {
            protocol: "mcp",
            method: "DELETE /mcp (terminate session)",
            originator: "client",
            kind: "http-verb",
            why_not_derived: "Explicit session termination is a streamable-HTTP verb, not a JSON-RPC method. It is \
the only way a client can tell a gateway to drop server-side state it is being \
billed for.",
            exercised_by: &[
                "mcp-conformance (official) server-stateless",
                "mcp-conformance (in-house battery) SEAM session clauses",
            ],
            na: &[(
                "stdio",
                "A stdio session ends when the process does; there is no session id to \
delete.",
            )],
        },
    ]
}

// ---------------------------------------------------------------------------
// Ordered JSON, written exactly as Python's `json.dumps(doc, indent=2)` writes it.
// ---------------------------------------------------------------------------

/// A JSON value with INSERTION-ORDERED objects (the file's key order is part of its bytes).
#[derive(Clone, Debug, PartialEq)]
pub enum J {
    Str(String),
    Int(usize),
    Bool(bool),
    List(Vec<J>),
    Obj(Vec<(String, J)>),
}

fn s(v: &str) -> J {
    J::Str(v.to_string())
}

fn obj(pairs: Vec<(&str, J)>) -> J {
    J::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn str_list(v: &[&str]) -> J {
    J::List(v.iter().map(|x| s(x)).collect())
}

/// Python's `ensure_ascii` string escape: everything outside ` `..`~` is escaped, non-BMP as a
/// surrogate pair.
fn dump_str(out: &mut String, v: &str) {
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
        }
    }
    out.push('"');
}

fn dump(out: &mut String, v: &J, depth: usize) {
    let pad = |out: &mut String, d: usize| {
        for _ in 0..d {
            out.push_str("  ");
        }
    };
    match v {
        J::Str(x) => dump_str(out, x),
        J::Int(n) => out.push_str(&n.to_string()),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::List(items) if items.is_empty() => out.push_str("[]"),
        J::List(items) => {
            out.push_str("[\n");
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                pad(out, depth + 1);
                dump(out, it, depth + 1);
            }
            out.push('\n');
            pad(out, depth);
            out.push(']');
        }
        J::Obj(pairs) if pairs.is_empty() => out.push_str("{}"),
        J::Obj(pairs) => {
            out.push_str("{\n");
            for (i, (k, it)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                pad(out, depth + 1);
                dump_str(out, k);
                out.push_str(": ");
                dump(out, it, depth + 1);
            }
            out.push('\n');
            pad(out, depth);
            out.push('}');
        }
    }
}

/// `json.dumps(v, indent=2) + "\n"`.
pub fn to_json(v: &J) -> String {
    let mut out = String::new();
    dump(&mut out, v, 0);
    out.push('\n');
    out
}

// ---------------------------------------------------------------------------
// MCP, out of rmcp's own model.rs
// ---------------------------------------------------------------------------

fn rx(p: &str) -> Regex {
    Regex::new(p).unwrap_or_else(|e| panic!("method-inventory pattern {p:?}: {e}"))
}

const MCP_UNIONS: [(&str, &str, &str); 4] = [
    ("ClientRequest", "client", "request"),
    ("ServerRequest", "server", "request"),
    ("ClientNotification", "client", "notification"),
    ("ServerNotification", "server", "notification"),
];

/// `(method, originator)` -> `(kind, source)`.
pub type McpRows = BTreeMap<(String, String), (String, String)>;

fn captures(re: &Regex, src: &str, groups: usize) -> Vec<Vec<String>> {
    re.find_iter(src.as_bytes())
        .iter()
        .map(|m| {
            (1..=groups)
                .map(|g| m.str_of(src.as_bytes(), g).unwrap_or_default())
                .collect()
        })
        .collect()
}

/// Return the MCP rows from rmcp's `model.rs`. `Err` is a REFUSAL (the script's `die`).
pub fn derive_mcp(model_src: &str) -> Result<McpRows, String> {
    let const_re = rx(r#"const_string!\(\s*(\w+)\s*=\s*"([^"]*)"\s*,?\s*\)"#);
    let alias_re = rx(r"pub type (\w+)\s*=\s*\w+\s*<\s*(\w+Method)\b");
    let union_re = rx(r"ts_union!\(\s*export type (\w+)\s*=\s*([\s\S]*?)\);");

    let mut consts: BTreeMap<String, String> = BTreeMap::new();
    for c in captures(&const_re, model_src, 2) {
        if c[0].ends_with("Method") {
            consts.insert(c[0].clone(), c[1].clone());
        }
    }
    if consts.len() < 30 {
        return Err(format!(
            "only {} method constants found in rmcp model.rs -- refusing to generate a vacuous inventory",
            consts.len()
        ));
    }
    let aliases: BTreeMap<String, String> = captures(&alias_re, model_src, 2)
        .into_iter()
        .map(|c| (c[0].clone(), c[1].clone()))
        .collect();
    let unions: BTreeMap<String, Vec<String>> = captures(&union_re, model_src, 2)
        .into_iter()
        .map(|c| {
            let variants = c[1]
                .split('|')
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().trim_end_matches(';').to_string())
                .collect();
            (c[0].clone(), variants)
        })
        .collect();

    let mut rows: Vec<(String, String, String, String)> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = Default::default();
    for (union, originator, kind) in MCP_UNIONS {
        let Some(variants) = unions.get(union) else {
            return Err(format!(
                "rmcp no longer declares ts_union! {union}; the derivation is out of date"
            ));
        };
        for variant in variants {
            let variant = variant.replace("box ", "");
            let variant = variant.trim();
            if variant.starts_with("Custom") {
                // CustomRequest/CustomNotification are the escape hatch for methods the SDK does
                // not model. They are not methods and must not become rows.
                continue;
            }
            let Some(const_name) = aliases.get(variant) else {
                return Err(format!(
                    "{union} variant {variant} has no `pub type` binding a method constant; the parser is stale, not the SDK"
                ));
            };
            let Some(wire) = consts.get(const_name) else {
                return Err(format!(
                    "{variant} binds {const_name}, which is not a method constant"
                ));
            };
            seen.insert(const_name.clone());
            rows.push((
                wire.clone(),
                originator.to_string(),
                kind.to_string(),
                format!("rmcp {RMCP_VERSION} {union}::{variant}"),
            ));
        }
    }

    // Anything declared but not routed. Never dropped: classified here or the run fails.
    for (const_name, wire) in &consts {
        if seen.contains(const_name) {
            continue;
        }
        let Some((originator, kind, note)) = mcp_orphan_originator(wire) else {
            return Err(format!(
                "rmcp declares method constant {const_name} = {} but lists it in no ts_union!, and MCP_ORPHAN_ORIGINATOR does not classify it. Classify it with a citation -- do not delete this check.",
                py_repr(wire)
            ));
        };
        rows.push((
            wire.clone(),
            originator.to_string(),
            kind.to_string(),
            format!("rmcp {RMCP_VERSION} const {const_name} ({note})"),
        ));
    }

    // Two distinct obligations share the name `ping` (client->server and server->client). The row
    // key is (method, originator) precisely so neither disappears into the other.
    let mut keyed: McpRows = BTreeMap::new();
    for (wire, originator, kind, source) in rows {
        keyed.entry((wire, originator)).or_insert((kind, source));
    }
    Ok(keyed)
}

/// Python's `repr()` of a str, for the refusal text (single quotes unless the text holds one).
fn py_repr(v: &str) -> String {
    if v.contains('\'') && !v.contains('"') {
        format!("\"{v}\"")
    } else {
        format!("'{}'", v.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}

/// Python's `repr()` of a list of str.
fn py_repr_list(v: &[String]) -> String {
    format!(
        "[{}]",
        v.iter().map(|x| py_repr(x)).collect::<Vec<_>>().join(", ")
    )
}

// ---------------------------------------------------------------------------
// A2A, out of a2a-pb's vendored a2a.proto
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Rpc {
    pub server_streaming: bool,
    pub verb: String,
    pub path: String,
}

pub fn derive_a2a(proto_src: &str) -> Result<BTreeMap<String, Rpc>, String> {
    let service_re = rx(r"service\s+A2AService\s*\{([\s\S]*?)\n\}");
    let rpc_re = rx(
        r"rpc\s+(\w+)\s*\(\s*(?:stream\s+)?[\w.]+\s*\)\s*returns\s*\(\s*(stream\s+)?[\w.]+\s*\)\s*\{([\s\S]*?)\n  \}",
    );
    let http_re = rx(r#"(get|post|put|patch|delete)\s*:\s*"([^"]+)""#);

    let Some(m) = service_re.search(proto_src.as_bytes()) else {
        return Err("a2a.proto has no `service A2AService` block".to_string());
    };
    let body = m.str_of(proto_src.as_bytes(), 1).unwrap_or_default();
    let mut rpcs: BTreeMap<String, Rpc> = BTreeMap::new();
    for m in rpc_re.find_iter(body.as_bytes()) {
        let name = m.str_of(body.as_bytes(), 1).unwrap_or_default();
        let streaming = m.group(2).is_some_and(|(a, b)| b > a);
        let opts = m.str_of(body.as_bytes(), 3).unwrap_or_default();
        // Skip the {tenant}-prefixed additional_bindings: same method, same obligation, a
        // deployment-shape prefix. The primary binding is the one a cell is about.
        let first = captures(&http_re, &opts, 2)
            .into_iter()
            .find(|c| !c[1].contains("{tenant}"));
        let Some(first) = first else {
            return Err(format!(
                "rpc {name} carries no google.api.http binding; the HTTP+JSON column would be a guess"
            ));
        };
        rpcs.insert(
            name,
            Rpc {
                server_streaming: streaming,
                verb: first[0].to_uppercase(),
                path: first[1].clone(),
            },
        );
    }
    if rpcs.len() < 8 {
        return Err(format!(
            "only {} rpcs parsed out of service A2AService -- refusing to generate a vacuous inventory",
            rpcs.len()
        ));
    }

    // The alias table must cover EXACTLY the derived set. This is the check that makes the one
    // hand-written A2A table safe: a new rpc upstream stops the build here.
    let missing: Vec<String> = rpcs
        .keys()
        .filter(|k| !LEGACY_JSONRPC_0_3.iter().any(|(n, _)| n == k))
        .cloned()
        .collect();
    let mut extra: Vec<String> = LEGACY_JSONRPC_0_3
        .iter()
        .filter(|(n, _)| !rpcs.contains_key(*n))
        .map(|(n, _)| n.to_string())
        .collect();
    extra.sort();
    if !missing.is_empty() {
        return Err(format!(
            "LEGACY_JSONRPC_0_3 has no 0.3 name for {}; supply it with a spec citation",
            py_repr_list(&missing)
        ));
    }
    if !extra.is_empty() {
        return Err(format!(
            "LEGACY_JSONRPC_0_3 names {}, which the proto no longer declares; remove the stale alias",
            py_repr_list(&extra)
        ));
    }
    Ok(rpcs)
}

// ---------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Method {
    pub protocol: String,
    pub method: String,
    pub originator: String,
    pub transports: Vec<String>,
    pub na: Vec<(String, String)>,
    json: J,
}

#[derive(Clone, Debug)]
pub struct Cell {
    pub id: String,
    pub protocol: String,
    pub method: String,
    pub originator: String,
    pub role: String,
    pub transport: String,
    pub na_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Doc {
    pub methods: Vec<Method>,
    pub cells: Vec<Cell>,
    roles: Vec<String>,
}

pub fn cell_id(
    protocol: &str,
    transport: &str,
    role: &str,
    originator: &str,
    method: &str,
) -> String {
    format!("{protocol}|{transport}|{role}|{originator}|{method}")
}

/// What the cell actually demands of busbar. A method 'implemented' in one direction is still a
/// missing letter, and these two words are the difference.
pub fn obligation(role: &str, originator: &str) -> &'static str {
    if role != originator {
        "handle"
    } else {
        "issue"
    }
}

fn legacy(name: &str) -> &'static str {
    LEGACY_JSONRPC_0_3
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, w)| *w)
        .unwrap_or("")
}

/// Build the matrix over `roles` (production passes [`ROLES`]; the selftest narrows it to prove
/// the both-directions check cannot be passed vacuously).
pub fn build(mcp_rows: &McpRows, a2a_rpcs: &BTreeMap<String, Rpc>, roles: &[&str]) -> Doc {
    let mut methods: Vec<Method> = Vec::new();

    for ((wire, originator), (kind, source)) in mcp_rows {
        methods.push(Method {
            protocol: "mcp".into(),
            method: wire.clone(),
            originator: originator.clone(),
            transports: MCP_TRANSPORTS.iter().map(|t| t.to_string()).collect(),
            na: vec![],
            json: obj(vec![
                ("protocol", s("mcp")),
                ("method", s(wire)),
                ("originator", s(originator)),
                ("kind", s(kind)),
                ("derived_from", s(source)),
                ("transports", str_list(&MCP_TRANSPORTS)),
                ("na", J::Obj(vec![])),
            ]),
        });
    }

    for (name, info) in a2a_rpcs {
        methods.push(Method {
            protocol: "a2a".into(),
            method: name.clone(),
            originator: "client".into(),
            transports: A2A_TRANSPORTS.iter().map(|t| t.to_string()).collect(),
            na: vec![],
            json: obj(vec![
                ("protocol", s("a2a")),
                ("method", s(name)),
                ("originator", s("client")),
                ("kind", s("rpc")),
                (
                    "derived_from",
                    s(&format!(
                        "a2a-pb {A2A_PB_VERSION} proto/a2a.proto service A2AService"
                    )),
                ),
                ("transports", str_list(&A2A_TRANSPORTS)),
                ("server_streaming", J::Bool(info.server_streaming)),
                (
                    "wire_names",
                    // SPEC 9.1 vs SPEC 9.3; both are live because SPEC 3.6.2 makes a version-less
                    // request a 0.3 request. A gateway that serves only one of these serves half
                    // its callers.
                    obj(vec![
                        ("jsonrpc_1_0", s(name)),
                        ("jsonrpc_0_3", s(legacy(name))),
                        ("http+json", s(&format!("{} {}", info.verb, info.path))),
                        ("grpc", s(&format!("/a2a.v1.A2AService/{name}"))),
                    ]),
                ),
                ("na", J::Obj(vec![])),
            ]),
        });
    }

    for e in extra_surfaces() {
        let transports: &[&str] = if e.protocol == "mcp" {
            &MCP_TRANSPORTS
        } else {
            &A2A_TRANSPORTS
        };
        methods.push(Method {
            protocol: e.protocol.into(),
            method: e.method.into(),
            originator: e.originator.into(),
            transports: transports.iter().map(|t| t.to_string()).collect(),
            na: e
                .na
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            json: obj(vec![
                ("protocol", s(e.protocol)),
                ("method", s(e.method)),
                ("originator", s(e.originator)),
                ("kind", s(e.kind)),
                (
                    "derived_from",
                    s(&format!("not derivable: {}", e.why_not_derived)),
                ),
                ("exercised_by", str_list(e.exercised_by)),
                ("transports", str_list(transports)),
                (
                    "na",
                    J::Obj(e.na.iter().map(|(a, b)| (a.to_string(), s(b))).collect()),
                ),
            ]),
        });
    }

    let mut cells = Vec::new();
    for m in &methods {
        for transport in &m.transports {
            for role in roles {
                cells.push(Cell {
                    id: cell_id(&m.protocol, transport, role, &m.originator, &m.method),
                    protocol: m.protocol.clone(),
                    method: m.method.clone(),
                    originator: m.originator.clone(),
                    role: role.to_string(),
                    transport: transport.clone(),
                    na_reason: m
                        .na
                        .iter()
                        .find(|(t, _)| t == transport)
                        .map(|(_, r)| r.clone()),
                });
            }
        }
    }
    // Python's sort is stable; so is this.
    cells.sort_by(|a, b| a.id.cmp(&b.id));
    Doc {
        methods,
        cells,
        roles: roles.iter().map(|r| r.to_string()).collect(),
    }
}

/// The `_comment` header the generated file carries. It names THIS command.
pub const HEADER: [&str; 11] = [
    "GENERATED by `cargo xtask method-inventory`. Do not edit by hand.",
    "Regenerate:  cargo xtask method-inventory --write",
    "",
    "This is the ENUMERATED method inventory for MCP and A2A, expanded into the",
    "method x direction x transport matrix. crates/busbar/tests/method_coverage.rs",
    "reads it and FAILS the build for any cell that is neither implemented nor",
    "explicitly waived in qa/method-coverage.status.",
    "",
    "A cell with an na_reason is not owed an implementation. A cell WITHOUT one is,",
    "and its absence from the status file is a MISSING -- which is a build failure,",
    "not a silence.",
];

/// The file's whole document as ordered JSON.
pub fn doc_json(doc: &Doc) -> J {
    let header: Vec<J> = HEADER.iter().map(|l| s(l)).collect();
    let count = |p: &str| doc.methods.iter().filter(|m| m.protocol == p).count();
    let cells: Vec<J> = doc
        .cells
        .iter()
        .map(|c| {
            let mut pairs = vec![
                ("id", s(&c.id)),
                ("protocol", s(&c.protocol)),
                ("method", s(&c.method)),
                ("originator", s(&c.originator)),
                ("role", s(&c.role)),
                ("transport", s(&c.transport)),
                ("obligation", s(obligation(&c.role, &c.originator))),
            ];
            if let Some(r) = &c.na_reason {
                pairs.push(("na_reason", s(r)));
            }
            obj(pairs)
        })
        .collect();
    obj(vec![
        ("_comment", J::List(header)),
        ("mcp_revision", s(MCP_REVISION)),
        ("a2a_spec_tag", s(A2A_SPEC_TAG)),
        (
            "derived_from",
            obj(vec![
                ("mcp", s(&format!("rmcp {RMCP_VERSION} src/model.rs"))),
                (
                    "a2a",
                    s(&format!("a2a-pb {A2A_PB_VERSION} proto/a2a.proto")),
                ),
            ]),
        ),
        ("roles", J::List(doc.roles.iter().map(|r| s(r)).collect())),
        (
            "methods",
            J::List(doc.methods.iter().map(|m| m.json.clone()).collect()),
        ),
        ("cells", J::List(cells)),
        (
            "counts",
            obj(vec![
                ("mcp_methods", J::Int(count("mcp"))),
                ("a2a_methods", J::Int(count("a2a"))),
                ("cells", J::Int(doc.cells.len())),
                (
                    "na_cells",
                    J::Int(doc.cells.iter().filter(|c| c.na_reason.is_some()).count()),
                ),
            ]),
        ),
    ])
}

/// Every (protocol, method, transport) a METHOD declares, whose cells do not carry both
/// directions. Keyed off `methods` — not off the cells — so a method with NO cells at all (an
/// emptied ROLES, a filter in `build`) is a gap rather than an absence nobody iterates.
pub fn one_direction_gaps(doc: &Doc) -> Vec<(String, String, String)> {
    let mut seen: BTreeMap<(String, String, String), std::collections::BTreeSet<String>> =
        BTreeMap::new();
    for c in &doc.cells {
        seen.entry((c.protocol.clone(), c.method.clone(), c.transport.clone()))
            .or_default()
            .insert(c.role.clone());
    }
    let both: std::collections::BTreeSet<String> =
        BOTH_DIRECTIONS.iter().map(|r| r.to_string()).collect();
    let mut gaps = Vec::new();
    for m in &doc.methods {
        for t in &m.transports {
            let key = (m.protocol.clone(), m.method.clone(), t.clone());
            if seen.get(&key) != Some(&both) {
                gaps.push(key);
            }
        }
    }
    gaps
}

/// Derive the whole matrix from the two sources' text.
pub fn derive_doc(model_src: &str, proto_src: &str) -> Result<Doc, String> {
    let mcp = derive_mcp(model_src)?;
    let a2a = derive_a2a(proto_src)?;
    Ok(build(&mcp, &a2a, &ROLES))
}

/// Derive and render the whole file from the two sources' text.
pub fn render_from(model_src: &str, proto_src: &str) -> Result<String, String> {
    Ok(to_json(&doc_json(&derive_doc(model_src, proto_src)?)))
}

// ---------------------------------------------------------------------------
// Sources: the cargo registry
// ---------------------------------------------------------------------------

/// `<registry>/src/*/<pattern>`, the last in sorted order, or a refusal.
pub fn find_source(pattern: &str, what: &str) -> Result<PathBuf, String> {
    let home = std::env::var("CARGO_HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".cargo"))
        })
        .unwrap_or_else(|| PathBuf::from(".cargo"));
    let src = home.join("registry").join("src");
    let mut hits: Vec<PathBuf> = std::fs::read_dir(&src)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path().join(pattern))
                .filter(|p| p.exists())
                .collect()
        })
        .unwrap_or_default();
    hits.sort();
    hits.pop().ok_or_else(|| {
        format!(
            "cannot find {what} under {}/registry/src/*/{pattern}. Run `cargo fetch` for a crate depending on it. This REFUSES rather than skipping: an inventory derived from an absent source would be an inventory of nothing.",
            home.display()
        )
    })
}

fn read_sources() -> Result<(String, String), String> {
    let rmcp = find_source(
        &format!("rmcp-{RMCP_VERSION}/src/model.rs"),
        &format!("rmcp {RMCP_VERSION}"),
    )?;
    let proto = find_source(
        &format!("a2a-pb-{A2A_PB_VERSION}/proto/a2a.proto"),
        &format!("a2a-pb {A2A_PB_VERSION}"),
    )?;
    let rd = |p: &PathBuf| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
    Ok((rd(&rmcp)?, rd(&proto)?))
}

// ---------------------------------------------------------------------------
// Self-test: the derivation must be unable to lose a method quietly.
// ---------------------------------------------------------------------------

/// The script's `--selftest`, over the given sources: `(pass, transcript lines)`.
pub fn selftest_over(model: &str, protosrc: &str) -> (bool, Vec<String>) {
    let mut ok = true;
    let mut out = vec!["method-inventory SELF-TEST (the derivation cannot be lied to)".to_string()];
    let mut check = |out: &mut Vec<String>, name: &str, refused: bool, expect_refusal: bool| {
        if refused != expect_refusal {
            ok = false;
            out.push(format!(
                "  FAIL {name}: expected {}",
                if expect_refusal { "refusal" } else { "success" }
            ));
        } else {
            out.push(format!("  ok   {name}"));
        }
    };

    // 1. Baseline: the real sources parse.
    check(
        &mut out,
        "real sources parse",
        derive_mcp(model).is_err(),
        false,
    );
    check(
        &mut out,
        "real proto parses",
        derive_a2a(protosrc).is_err(),
        false,
    );

    // 2. Deleting a method from a union must NOT silently shrink the answer -- the constant is
    //    then an unclassified orphan and the run must refuse.
    let doctored = model.replacen("    | CallToolRequest\n", "", 1);
    let doctoring_failed = doctored == model;
    if doctoring_failed {
        out.push(
            "  FAIL doctoring: could not remove CallToolRequest from ClientRequest".to_string(),
        );
    }
    check(
        &mut out,
        "a method dropped from a union is refused, not lost",
        derive_mcp(&doctored).is_err(),
        true,
    );

    // 3. An rpc added to the proto with no 0.3 alias must stop the run.
    let added = protosrc.replacen(
        "  // Sends a message to an agent.",
        "  rpc FrobnicateTask(GetTaskRequest) returns (Task) {\n    option (google.api.http) = {\n      get: \"/tasks/{id=*}:frob\"\n    };\n  }\n  // Sends a message to an agent.",
        1,
    );
    check(
        &mut out,
        "a new rpc with no 0.3 alias is refused",
        derive_a2a(&added).is_err(),
        true,
    );

    // 4. A vacuous parse (empty source) must refuse rather than emit an empty inventory.
    check(
        &mut out,
        "empty rmcp source refuses",
        derive_mcp("").is_err(),
        true,
    );
    check(
        &mut out,
        "empty proto refuses",
        derive_a2a("").is_err(),
        true,
    );
    if doctoring_failed {
        ok = false;
    }

    let (Ok(mcp), Ok(a2a)) = (derive_mcp(model), derive_a2a(protosrc)) else {
        out.push("SELF-TEST FAIL".to_string());
        return (false, out);
    };
    let doc = build(&mcp, &a2a, &ROLES);

    // 5. Every N/A cell carries a reason.
    let bad: Vec<&str> = doc
        .cells
        .iter()
        .filter(|c| c.na_reason.as_ref().is_some_and(|r| r.trim().is_empty()))
        .map(|c| c.id.as_str())
        .collect();
    if bad.is_empty() {
        out.push("  ok   every N/A cell carries a reason".into());
    } else {
        ok = false;
        out.push(format!("  FAIL N/A cells without a reason: {bad:?}"));
    }

    // 6. Both roles exist for every method.
    let lopsided = one_direction_gaps(&doc);
    if lopsided.is_empty() {
        out.push("  ok   every method has both a server-role and a client-role cell".into());
    } else {
        ok = false;
        out.push(format!(
            "  FAIL methods present in only one direction: {:?}",
            &lopsided[..lopsided.len().min(5)]
        ));
    }
    match doc.cells.iter().find(|c| c.role == "client") {
        Some(victim) => {
            let dropped = Doc {
                cells: doc
                    .cells
                    .iter()
                    .filter(|c| c.id != victim.id)
                    .cloned()
                    .collect(),
                ..doc.clone()
            };
            let key = (
                victim.protocol.clone(),
                victim.method.clone(),
                victim.transport.clone(),
            );
            if one_direction_gaps(&dropped).contains(&key) {
                out.push("  ok   a method missing its client-role cell is reported".into());
            } else {
                ok = false;
                out.push(format!(
                    "  FAIL a doc missing the client cell {} was not reported",
                    victim.id
                ));
            }
        }
        None => {
            ok = false;
            out.push("  FAIL the matrix has no client-role cell at all".into());
        }
    }
    for (label, narrowed) in [("(\"server\",)", vec!["server"]), ("()", vec![])] {
        if one_direction_gaps(&build(&mcp, &a2a, &narrowed)).is_empty() {
            ok = false;
            out.push(format!(
                "  FAIL a build with ROLES={label} passed the both-directions check"
            ));
        } else {
            out.push(format!(
                "  ok   a build with ROLES={label} is reported, not passed vacuously"
            ));
        }
    }

    out.push(format!("SELF-TEST {}", if ok { "PASS" } else { "FAIL" }));
    (ok, out)
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

const USAGE: &str = "usage: cargo xtask method-inventory (--write | --check | --selftest)";

fn die(msg: &str) -> i32 {
    eprintln!("method-inventory: {msg}");
    2
}

/// `--check`'s decision over the fresh render and the committed text.
pub fn check_text(committed: Option<&str>, fresh: &str) -> Result<(), String> {
    let Some(committed) = committed else {
        return Err(format!(
            "{OUT} does not exist. Generate it with `cargo xtask method-inventory --write`"
        ));
    };
    if committed != fresh {
        return Err("qa/method-inventory.json is STALE against the pinned SDK sources. The specification moved and the matrix did not. Regenerate with `cargo xtask method-inventory --write` and read the diff -- a new row is a new obligation.".to_string());
    }
    Ok(())
}

pub fn main(cx: &Ctx, args: &[String]) -> i32 {
    let flags: Vec<&str> = args.iter().map(String::as_str).collect();
    let mode = match flags.as_slice() {
        ["--write"] => "write",
        ["--check"] => "check",
        ["--selftest"] => "selftest",
        _ => {
            eprintln!("{USAGE}");
            return 2;
        }
    };
    if mode == "selftest" {
        let (model, proto) = match read_sources() {
            Ok(x) => x,
            Err(e) => return die(&e),
        };
        let (ok, lines) = selftest_over(&model, &proto);
        for l in lines {
            println!("{l}");
        }
        return if ok { 0 } else { 1 };
    }
    let (model, proto) = match read_sources() {
        Ok(x) => x,
        Err(e) => return die(&e),
    };
    let doc = match derive_doc(&model, &proto) {
        Ok(d) => d,
        Err(e) => return die(&e),
    };
    let fresh = to_json(&doc_json(&doc));
    if mode == "write" {
        if let Err(e) = cx.write_file(OUT, &fresh) {
            eprintln!("method-inventory: cannot write {OUT}: {e}");
            return 3;
        }
        let count = |p: &str| doc.methods.iter().filter(|m| m.protocol == p).count();
        println!(
            "wrote {}: {} MCP methods, {} A2A methods, {} cells ({} N/A)",
            cx.abs(OUT).display(),
            count("mcp"),
            count("a2a"),
            doc.cells.len(),
            doc.cells.iter().filter(|c| c.na_reason.is_some()).count()
        );
        return 0;
    }
    let committed = cx.read(OUT).ok();
    match check_text(committed.as_deref(), &fresh) {
        Ok(()) => {
            println!("qa/method-inventory.json matches a fresh derivation");
            0
        }
        Err(e) => die(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A model.rs shaped like rmcp's: `n` request/notification methods spread over the four
    /// unions, a `Custom*` escape hatch in each, and one orphan const in no union.
    fn model(orphan_wire: &str) -> String {
        let mut src = String::new();
        let groups = [
            ("ClientRequest", "Request", 0..8),
            ("ServerRequest", "Request", 8..16),
            ("ClientNotification", "Notification", 16..24),
            ("ServerNotification", "Notification", 24..30),
        ];
        for i in 0..30 {
            src.push_str(&format!(
                "const_string!(M{i}Method = \"m/{i}\");\npub type V{i} = Request<M{i}Method, ()>;\n"
            ));
        }
        src.push_str(&format!(
            "const_string!(ElicitationResponseNotificationMethod = \"{orphan_wire}\");\n"
        ));
        // A const whose name does not end in Method is not a method constant.
        src.push_str("const_string!(Unrelated = \"not/a/method\");\n");
        for (name, _, range) in groups {
            src.push_str(&format!("ts_union!(\n    export type {name} =\n"));
            for i in range {
                src.push_str(&format!("    | V{i}\n"));
            }
            src.push_str("    | Custom;\n);\n");
        }
        src
    }

    fn good_model() -> String {
        model("notifications/elicitation/response")
    }

    fn proto_with(extra: &str, drop: Option<&str>) -> String {
        let mut src = String::from("syntax = \"proto3\";\nservice A2AService {\n");
        for (name, _) in LEGACY_JSONRPC_0_3 {
            if Some(*name) == drop {
                continue;
            }
            src.push_str(&format!(
                "  rpc {name}({name}Request) returns ({}{name}Response) {{\n    option (google.api.http) = {{\n      post: \"/v1/{name}\"\n      body: \"*\"\n      additional_bindings {{\n        post: \"/{{tenant}}/v1/{name}\"\n      }}\n    }};\n  }}\n",
                if *name == "SendStreamingMessage" { "stream " } else { "" },
            ));
        }
        src.push_str(extra);
        src.push_str("}\n");
        src
    }

    fn good_proto() -> String {
        proto_with("", None)
    }

    #[test]
    fn the_fixture_derives_and_the_orphan_is_classified() {
        let rows = derive_mcp(&good_model()).expect("the fixture parses");
        assert_eq!(
            rows.len(),
            31,
            "30 routed methods plus the classified orphan"
        );
        let orphan = &rows[&(
            "notifications/elicitation/response".to_string(),
            "client".to_string(),
        )];
        assert_eq!(orphan.0, "notification");
        assert!(orphan
            .1
            .contains("const ElicitationResponseNotificationMethod"));
        let first = &rows[&("m/0".to_string(), "client".to_string())];
        assert_eq!(first.1, "rmcp 3.1.2 ClientRequest::V0");
    }

    #[test]
    fn an_orphan_const_nobody_classified_is_refused() {
        let err = derive_mcp(&model("notifications/novel")).expect_err("must refuse");
        assert!(
            err.contains("rmcp declares method constant ElicitationResponseNotificationMethod = 'notifications/novel' but lists it in no ts_union!, and MCP_ORPHAN_ORIGINATOR does not classify it"),
            "{err}"
        );
    }

    #[test]
    fn a_method_dropped_from_a_union_is_an_orphan_not_lost() {
        let doctored = good_model().replacen("    | V3\n", "", 1);
        let err = derive_mcp(&doctored).expect_err("must refuse");
        assert!(
            err.contains("M3Method = 'm/3' but lists it in no ts_union!"),
            "{err}"
        );
    }

    #[test]
    fn a_union_variant_with_no_binding_is_refused() {
        let doctored = good_model().replacen("    | V3\n", "    | Unbound\n    | V3\n", 1);
        let err = derive_mcp(&doctored).expect_err("must refuse");
        assert!(
            err.contains("ClientRequest variant Unbound has no `pub type` binding a method constant; the parser is stale, not the SDK"),
            "{err}"
        );
    }

    #[test]
    fn a_binding_to_a_non_method_const_is_refused() {
        let doctored = good_model().replacen("Request<M3Method, ()>", "Request<M99Method, ()>", 1);
        let err = derive_mcp(&doctored).expect_err("must refuse");
        assert!(
            err.contains("V3 binds M99Method, which is not a method constant"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_union_is_refused() {
        let doctored =
            good_model().replacen("export type ServerNotification", "export type Other", 1);
        let err = derive_mcp(&doctored).expect_err("must refuse");
        assert_eq!(
            err,
            "rmcp no longer declares ts_union! ServerNotification; the derivation is out of date"
        );
    }

    #[test]
    fn a_vacuous_model_is_refused() {
        let err = derive_mcp("").expect_err("must refuse");
        assert_eq!(
            err,
            "only 0 method constants found in rmcp model.rs -- refusing to generate a vacuous inventory"
        );
        // 29 constants is one short of the floor.
        let short: String = good_model().replacen(
            "const_string!(ElicitationResponseNotificationMethod = \"notifications/elicitation/response\");\n",
            "",
            1,
        );
        let short = short.replacen("const_string!(M29Method = \"m/29\");\n", "", 1);
        assert!(derive_mcp(&short)
            .expect_err("must refuse")
            .starts_with("only 29 method constants"));
    }

    #[test]
    fn the_fixture_proto_derives_with_the_primary_binding() {
        let rpcs = derive_a2a(&good_proto()).expect("the fixture proto parses");
        assert_eq!(rpcs.len(), LEGACY_JSONRPC_0_3.len());
        let m = &rpcs["SendMessage"];
        assert_eq!(
            (m.verb.as_str(), m.path.as_str()),
            ("POST", "/v1/SendMessage")
        );
        assert!(!m.server_streaming);
        assert!(rpcs["SendStreamingMessage"].server_streaming);
    }

    #[test]
    fn a_new_rpc_with_no_legacy_alias_is_refused() {
        let extra = "  rpc FrobnicateTask(GetTaskRequest) returns (Task) {\n    option (google.api.http) = {\n      get: \"/tasks/{id=*}:frob\"\n    };\n  }\n";
        let err = derive_a2a(&proto_with(extra, None)).expect_err("must refuse");
        assert_eq!(
            err,
            "LEGACY_JSONRPC_0_3 has no 0.3 name for ['FrobnicateTask']; supply it with a spec citation"
        );
    }

    #[test]
    fn an_alias_for_an_rpc_the_proto_dropped_is_refused() {
        let err = derive_a2a(&proto_with("", Some("GetTask"))).expect_err("must refuse");
        assert_eq!(
            err,
            "LEGACY_JSONRPC_0_3 names ['GetTask'], which the proto no longer declares; remove the stale alias"
        );
    }

    #[test]
    fn an_rpc_with_no_http_binding_is_refused() {
        let extra = "  rpc Bare(BareRequest) returns (BareResponse) {\n  }\n";
        let err = derive_a2a(&proto_with(extra, None)).expect_err("must refuse");
        assert_eq!(
            err,
            "rpc Bare carries no google.api.http binding; the HTTP+JSON column would be a guess"
        );
    }

    #[test]
    fn a_vacuous_or_absent_proto_is_refused() {
        assert_eq!(
            derive_a2a("").expect_err("must refuse"),
            "a2a.proto has no `service A2AService` block"
        );
        let few = "service A2AService {\n  rpc GetTask(R) returns (T) {\n    option (google.api.http) = {\n      get: \"/t\"\n    };\n  }\n}\n";
        assert_eq!(
            derive_a2a(few).expect_err("must refuse"),
            "only 1 rpcs parsed out of service A2AService -- refusing to generate a vacuous inventory"
        );
    }

    fn derived() -> Doc {
        derive_doc(&good_model(), &good_proto()).expect("fixtures derive")
    }

    #[test]
    fn every_method_has_both_directions_and_na_cells_carry_reasons() {
        let doc = derived();
        assert!(one_direction_gaps(&doc).is_empty());
        assert!(doc
            .cells
            .iter()
            .all(|c| c.na_reason.as_ref().is_none_or(|r| !r.trim().is_empty())));
        // 31 mcp + 11 a2a + 4 extras
        assert_eq!(doc.methods.len(), 31 + 11 + 4);
        let ids: Vec<&String> = doc.cells.iter().map(|c| &c.id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "cells are sorted by id");
    }

    #[test]
    fn a_method_missing_its_client_cell_is_reported() {
        let doc = derived();
        let victim = doc
            .cells
            .iter()
            .find(|c| c.role == "client")
            .expect("a client cell")
            .clone();
        let dropped = Doc {
            cells: doc
                .cells
                .iter()
                .filter(|c| c.id != victim.id)
                .cloned()
                .collect(),
            ..doc.clone()
        };
        assert!(one_direction_gaps(&dropped).contains(&(
            victim.protocol,
            victim.method,
            victim.transport
        )));
    }

    #[test]
    fn narrowed_roles_are_reported_not_passed_vacuously() {
        let mcp = derive_mcp(&good_model()).expect("model");
        let a2a = derive_a2a(&good_proto()).expect("proto");
        for narrowed in [vec!["server"], vec![]] {
            assert!(
                !one_direction_gaps(&build(&mcp, &a2a, &narrowed)).is_empty(),
                "{narrowed:?}"
            );
        }
    }

    #[test]
    fn the_selftest_passes_over_the_fixtures_except_where_the_doctoring_has_no_target() {
        // The script's doctoring edit targets rmcp's real `| CallToolRequest` line; the fixture has
        // none, and the selftest must say so rather than pass.
        let (ok, lines) = selftest_over(&good_model(), &good_proto());
        assert!(!ok);
        assert!(
            lines.iter().any(|l| l.contains("FAIL doctoring")),
            "{lines:?}"
        );
    }

    #[test]
    fn obligation_is_handle_when_the_peer_originates() {
        assert_eq!(obligation("server", "client"), "handle");
        assert_eq!(obligation("client", "client"), "issue");
    }

    #[test]
    fn the_json_is_written_as_python_writes_it() {
        let v = obj(vec![
            ("a", J::List(vec![])),
            ("b", J::Obj(vec![])),
            ("c", str_list(&["x\"y\\z\n", "é\u{1F600}\u{7f}"])),
            ("d", J::Bool(true)),
            ("e", J::Int(7)),
        ]);
        assert_eq!(
            to_json(&v),
            "{\n  \"a\": [],\n  \"b\": {},\n  \"c\": [\n    \"x\\\"y\\\\z\\n\",\n    \"\\u00e9\\ud83d\\ude00\\u007f\"\n  ],\n  \"d\": true,\n  \"e\": 7\n}\n"
        );
    }

    #[test]
    fn check_refuses_a_missing_or_stale_file() {
        assert!(check_text(None, "x")
            .expect_err("absent")
            .contains("does not exist"));
        assert!(check_text(Some("y"), "x")
            .expect_err("stale")
            .contains("STALE"));
        assert!(check_text(Some("x"), "x").is_ok());
    }

    #[test]
    fn the_generated_header_names_this_command() {
        let text = render_from(&good_model(), &good_proto()).expect("render");
        assert!(
            text.contains("\"GENERATED by `cargo xtask method-inventory`. Do not edit by hand.\"")
        );
        assert!(!text.contains("scripts/method-inventory.py"));
    }

    /// The committed file must equal a fresh derivation from the real pinned sources. Skipped (said
    /// aloud) when the cargo registry does not hold them; `cargo xtask method-inventory --check`
    /// REFUSES in that case rather than skipping.
    #[test]
    fn the_committed_inventory_equals_a_fresh_derivation_of_the_real_sources() {
        let Ok((model, proto)) = read_sources() else {
            eprintln!("SKIPPED: rmcp/a2a-pb sources are not in the cargo registry on this machine");
            return;
        };
        let fresh = render_from(&model, &proto).expect("the real sources derive");
        let committed = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../")
                .join(OUT),
        )
        .expect("the committed inventory");
        assert_eq!(
            committed, fresh,
            "run `cargo xtask method-inventory --write` and read the diff"
        );
        let (ok, lines) = selftest_over(&model, &proto);
        assert!(ok, "{lines:#?}");
    }
}
