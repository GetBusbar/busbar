// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ARGUMENT HALF OF THE DISPATCH SSRF GUARD: a schema-aware walk of the nested per-request
//! `tools/call` arguments, finding every URL and every host they carry and asking the host's ONE
//! destination judge (`dest.judge`, BUSBAR-1.6.0.md Appendix C B.3 item 11) about each. The plane
//! reads the value; the deployment's egress rules decide it.
//!
//! ## The gap this closes, stated as the live consequence
//!
//! The transport guard closes the URL/host/address/redirect half: busbar resolves the UPSTREAM's own URL
//! once, judges every address the resolver returned, and connects to the address that was judged.
//! Routing is likewise immune to attacker text, because a route is decided on the bound identity
//! and `super::dispatch` provably reads no free text at all.
//!
//! Neither of those makes the PAYLOAD safe. A model that has just read a hostile tool description
//! can still put `http://169.254.169.254/latest/meta-data/…` into a tool ARGUMENT, and without this
//! module busbar hands that argument to the upstream untouched. An argument is attacker-influenced
//! DATA travelling to an operator-chosen destination, which is the classic SSRF shape and a
//! different shape from the one the routing rule answers.
//!
//! ## Why the PINNED schema is what makes this a check rather than a guess
//!
//! `super::catalogue` already fetches, canonicalises and hash-pins each tool's input schema, and a
//! schema that changed to hide or reveal a URL field is DRIFT, which quarantines the server before
//! any call goes out. So the schema this walk reads is not "whatever the upstream said this
//! morning" — it is the exact document whose digest an operator approved. [`super::dispatch`]
//! re-compares that digest immediately before handing the schema here, so the walk cannot be
//! steered by a schema swapped underneath it.
//!
//! ## Two detectors, and why there are two
//!
//! 1. **DECLARED.** A string whose schema declares a URL-ish `format` — `uri`, `uri-reference`,
//!    `iri`, `url`, `hostname`, `idn-hostname`, `ipv4`, `ipv6` — is judged in full: scheme
//!    allowlist for the URL kinds, host judgement for all of them. Nested objects, arrays, tuple
//!    positions, `additionalProperties` and `allOf`/`anyOf`/`oneOf` branches are all followed, so
//!    "several levels deep" is not a special case.
//!
//! 2. **UNDECLARED.** Most real MCP tools take a URL in a plain `{"type": "string"}` with no
//!    `format` at all. A walk that judged only declared fields would therefore refuse almost
//!    nothing while reporting green, so every string in the arguments is ALSO judged when the whole
//!    value (after trimming) begins `http://` or `https://`. That prefix has exactly one reading:
//!    it is a URL. Nothing narrower is sniffed — a bare `localhost` in an untyped `query` field
//!    stays untouched, because refusing a hostname-shaped word in free text breaks real tools and
//!    buys nothing an attacker cannot restate.
//!
//! The counts of both are RETURNED ([`ArgScan`]) rather than kept internal, because a walker that
//! visits nothing refuses nothing and passes every test it is given. A caller — and the tests —
//! can assert the walk actually reached fields.
//!
//! ## What this module deliberately does NOT do
//!
//! - **No host rules of its own.** The scheme allowlist and the host reader are the walk's; every
//!   verdict on a host is `dest.judge`'s, under the deployment's egress rules (its allow-list, the
//!   metadata hosts, the private-address setting), so an argument and the connector's dial are
//!   judged by the same guard.
//! - **No DNS.** The transport guard resolves and PINS because busbar is the party that connects.
//!   For an argument busbar is NOT the connecting party: the upstream resolves the name itself,
//!   later, from its own resolver. A lookup here would therefore be advisory at best — trivially
//!   defeated by rebinding, since nothing binds our answer to the upstream's connect — while
//!   costing a per-argument lookup on the dispatch path and turning busbar into a name-resolution
//!   oracle for whatever a model types. So the judgement is decided from the string alone, and the
//!   honest consequence is stated rather than softened: a hostname whose A record points at
//!   loopback is NOT caught here.
//! - **No `$ref` resolution.** A `$ref` is followed nowhere; a URL field reachable only through one
//!   is not visited.
//! - **No mid-string URLs.** A URL embedded inside a longer free-text value in an UNDECLARED field
//!   is not detected. Substring matching over prose is how a guard acquires false positives, and a
//!   false positive here refuses a legitimate call.
//! - **No plaintext-to-public rule.** `super::ssrf` refuses `http` to a public host because
//!   busbar's own upstream credential rides that request. No busbar credential rides a tool
//!   argument, so the rule does not transfer and is not applied.

use busbar_contract::abi::host::service::{
    DEST_ALLOWED, DEST_INTERNAL, DEST_METADATA, DEST_NO_HOST, DEST_OBFUSCATED,
};
use busbar_contract::net::{extract_normalized_host, scheme_is};
use serde_json::Value;

/// THE HOST'S JUDGE, as the walk asks it: one host an argument names (an IPv6 literal bracketed,
/// as `dest.judge` reads a `host[:port]`), answered with the host's `DEST_*` verdict, or `None`
/// when the host gave none (the value is then refused: fail closed).
pub type Judge<'a> = dyn FnMut(&str) -> Option<u64> + 'a;

/// How deep into the ARGUMENT value the walk goes before refusing. Arguments arrive as already
/// parsed JSON, so this is a floor under stack safety rather than the primary bound; exceeding it
/// is a refusal instead of a truncation, because a walk that silently stops is a walk that reports
/// "nothing found" on the one document built to make it stop.
const MAX_VALUE_DEPTH: usize = 64;

/// How far the SCHEMA-side expansion follows `allOf`/`anyOf`/`oneOf` nesting. Bounded separately
/// from the value depth because a pinned schema can nest combinators independently of how deep the
/// arguments go.
const MAX_COMBINATOR_DEPTH: usize = 8;

/// The `format` values that make a string field URL-ish. Matched case-insensitively: JSON Schema
/// spells these lowercase, and an upstream writing `URI` should not thereby remove a field from the
/// walk.
const URLISH_FORMATS: &[&str] = &[
    "uri",
    "uri-reference",
    "iri",
    "url",
    "hostname",
    "idn-hostname",
    "ipv4",
    "ipv6",
];

/// What a URL-ish format says the value IS, which decides how it is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Urlish {
    /// An absolute URL. A non-`http(s)` scheme is refused; `file:`, `gopher:` and friends are
    /// refused by absence rather than by a list somebody has to maintain.
    AbsoluteUrl,
    /// A URI reference, which may legitimately be relative. A relative reference names no host and
    /// is admissible; a scheme-relative `//host/path` names one and is judged.
    Reference,
    /// A bare host: `hostname`, `idn-hostname`, `ipv4`, `ipv6`.
    Host,
}

/// Why one argument value was refused. Each arm names the offending value, because a refusal an
/// operator cannot diagnose is a refusal an operator disables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgWhy {
    /// An absolute-URL field carrying something that is not `http(s)`.
    Scheme(String),
    /// The value has no host component to judge.
    NoHost(String),
    /// `dest.judge` answered `DEST_METADATA`: a cloud-metadata endpoint, by name, address or the
    /// deployment's own list. Refused unconditionally, `allow_private` or not.
    CloudMetadata(String),
    /// `dest.judge` answered `DEST_OBFUSCATED`: an alternate IPv4 encoding (`2130706433`,
    /// `0x7f000001`, `127.1`) that a resolver expands but a canonical IP-literal check misses.
    ObfuscatedHost(String),
    /// `dest.judge` answered `DEST_INTERNAL`: an internal host the egress rules do not admit here.
    InternalHost(String),
    /// `dest.judge` refused the host with another `DEST_*` verdict.
    Refused(String, u64),
    /// The host gave no verdict (it serves no `dest.judge`, or the judgement failed).
    Unjudged(String),
    /// The argument nested deeper than the walk will follow.
    DepthExceeded,
}

impl std::fmt::Display for ArgWhy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgWhy::Scheme(v) => write!(
                f,
                "`{v}` is not an http(s) URL, and no other scheme is passed through in a tool \
                 argument"
            ),
            ArgWhy::NoHost(v) => write!(f, "`{v}` has no host to check"),
            ArgWhy::CloudMetadata(h) => write!(
                f,
                "`{h}` is a cloud-metadata endpoint; that is refused unconditionally, because an \
                 operator opting a server into private addressing has said nothing about the \
                 service whose whole value to an attacker is that it hands out credentials"
            ),
            ArgWhy::ObfuscatedHost(h) => write!(
                f,
                "`{h}` is an alternate IPv4 encoding a resolver expands; write the address in \
                 dotted-quad form so it can be checked"
            ),
            ArgWhy::InternalHost(h) => write!(
                f,
                "`{h}` is an internal address; set this server's `allow_private` if reaching \
                 internal hosts through its tools is deliberate (the deployment's destination \
                 rules still apply)"
            ),
            ArgWhy::Refused(h, verdict) => write!(
                f,
                "`{h}` is refused by the deployment's destination rules (verdict {verdict})"
            ),
            ArgWhy::Unjudged(h) => write!(
                f,
                "`{h}` could not be checked against the deployment's destination rules, so it is \
                 refused"
            ),
            ArgWhy::DepthExceeded => write!(
                f,
                "the tool arguments nest deeper than {MAX_VALUE_DEPTH} levels, which is refused \
                 rather than walked partially"
            ),
        }
    }
}

/// ONE REFUSED ARGUMENT, located precisely. The pointer is an RFC 6901 JSON Pointer into the
/// arguments, so an operator reading the refusal is told WHICH field of a nested document was the
/// problem rather than being handed the document back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgRefusal {
    /// RFC 6901 pointer, e.g. `/delivery/callbacks/1`.
    pub pointer: String,
    /// The schema-declared format that put this field in scope, or `None` when the field was
    /// caught by the undeclared `http(s)://` detector.
    pub declared_format: Option<String>,
    /// Why the value was refused.
    pub why: ArgWhy,
}

impl std::fmt::Display for ArgRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let at = if self.pointer.is_empty() {
            "the argument"
        } else {
            self.pointer.as_str()
        };
        match &self.declared_format {
            Some(fmt) => write!(
                f,
                "tool argument {at} (schema format `{fmt}`) was refused: {}",
                self.why
            ),
            None => write!(
                f,
                "tool argument {at} carries a URL the schema does not declare, and it was refused: \
                 {}",
                self.why
            ),
        }
    }
}

/// WHAT THE WALK ACTUALLY VISITED. Returned on success so a caller can assert a non-zero floor: a
/// walker that finds nothing refuses nothing and passes every test, which is the false-green shape
/// this check exists to avoid being.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArgScan {
    /// String values judged because the pinned schema declared a URL-ish format for them.
    pub declared_judged: usize,
    /// String values judged because the value itself began `http://` or `https://` while the
    /// schema declared no URL-ish format there.
    pub undeclared_judged: usize,
    /// Every string leaf the walk reached, judged or not. The denominator that makes the two
    /// numerators above readable.
    pub strings_seen: usize,
}

impl ArgScan {
    /// Total values that were actually put through the guard.
    /// Not read on the dispatch path: `mcp::upstream` acts on the REFUSAL, and the counts exist
    /// for the floor assertions that stop a walker which visits nothing from passing.
    #[allow(dead_code)]
    pub fn judged(&self) -> usize {
        self.declared_judged + self.undeclared_judged
    }
}

/// THE ENTRY POINT: walk `arguments` against the PINNED `schema` and refuse on the first
/// inadmissible value.
///
/// Fails on the first refusal rather than collecting all of them, because the call is refused
/// either way and the operator's question is "why was this refused", which one named field answers.
/// Every host found is asked of `judge` ([`Judge`]).
pub fn guard(
    schema: &Value,
    arguments: &Value,
    mut judge: impl FnMut(&str) -> Option<u64>,
) -> Result<ArgScan, ArgRefusal> {
    let mut scan = ArgScan::default();
    let mut pointer = String::new();
    walk(&[schema], arguments, &mut pointer, 0, &mut judge, &mut scan)?;
    Ok(scan)
}

/// The value-driven walk. The VALUE drives and the schema rides alongside, which is what lets the
/// undeclared detector see fields the schema never mentioned — a schema-driven walk cannot, by
/// construction, visit a field the schema omits.
fn walk(
    schemas: &[&Value],
    value: &Value,
    pointer: &mut String,
    depth: usize,
    judge: &mut Judge<'_>,
    scan: &mut ArgScan,
) -> Result<(), ArgRefusal> {
    if depth > MAX_VALUE_DEPTH {
        return Err(ArgRefusal {
            pointer: pointer.clone(),
            declared_format: None,
            why: ArgWhy::DepthExceeded,
        });
    }
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let mark = pointer.len();
                pointer.push('/');
                pointer.push_str(&escape_token(k));
                let child = child_for_key(schemas, k);
                let child_refs: Vec<&Value> = child;
                walk(&child_refs, v, pointer, depth + 1, judge, scan)?;
                pointer.truncate(mark);
            }
            Ok(())
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                let mark = pointer.len();
                pointer.push('/');
                pointer.push_str(&i.to_string());
                let child = child_for_index(schemas, i);
                let child_refs: Vec<&Value> = child;
                walk(&child_refs, v, pointer, depth + 1, judge, scan)?;
                pointer.truncate(mark);
            }
            Ok(())
        }
        Value::String(s) => judge_string(schemas, s, pointer, judge, scan),
        _ => Ok(()),
    }
}

/// One string leaf: declared first, then the undeclared `http(s)://` detector.
fn judge_string(
    schemas: &[&Value],
    s: &str,
    pointer: &str,
    judge: &mut Judge<'_>,
    scan: &mut ArgScan,
) -> Result<(), ArgRefusal> {
    scan.strings_seen += 1;
    let trimmed = s.trim();
    if let Some((format, kind)) = first_urlish(schemas) {
        scan.declared_judged += 1;
        return judge_argument(kind, trimmed, judge).map_err(|why| ArgRefusal {
            pointer: pointer.to_string(),
            declared_format: Some(format),
            why,
        });
    }
    if starts_with_http(trimmed) {
        scan.undeclared_judged += 1;
        return judge_argument(Urlish::AbsoluteUrl, trimmed, judge).map_err(|why| ArgRefusal {
            pointer: pointer.to_string(),
            declared_format: None,
            why,
        });
    }
    Ok(())
}

/// Whether the WHOLE value is an `http(s)` URL. Deliberately a prefix test on the whole trimmed
/// string rather than a search: see the module header on why substring matching over free text is
/// not wanted here.
fn starts_with_http(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn judge_argument(kind: Urlish, value: &str, judge: &mut Judge<'_>) -> Result<(), ArgWhy> {
    match kind {
        Urlish::AbsoluteUrl => judge_absolute(value, judge),
        Urlish::Reference => {
            // A scheme-relative reference (`//169.254.169.254/x`) inherits the base scheme and
            // names a host, so it is judged as one. A path-relative reference names no host and
            // there is nothing to judge.
            if let Some(rest) = value.strip_prefix("//") {
                let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
                let host = authority.rsplit('@').next().unwrap_or(authority);
                return judge_host(strip_port(host), judge);
            }
            if value.contains("://") {
                return judge_absolute(value, judge);
            }
            Ok(())
        }
        Urlish::Host => {
            // A `hostname`/`ipv4`/`ipv6`-declared field is supposed to carry a bare host, but
            // nothing stops a caller writing a full absolute URL into it instead. Left to
            // `judge_host` as-is, a value like `https://169.254.169.254/x` is not a syntactically
            // valid host, so the judge (reading it as an opaque host string) would miss the
            // address entirely — the scheme and path are noise to it, not a signal to strip. Any embedded `://` means this is actually a URL wearing
            // a `hostname` declaration, so it is judged as one (scheme allowlist + host judgement
            // on the REAL host), the same authority the `Reference` arm above already gives a
            // scheme-relative value.
            if value.contains("://") {
                return judge_absolute(value, judge);
            }
            judge_host(value, judge)
        }
    }
}

/// An absolute URL: the scheme allowlist, then the host.
fn judge_absolute(url: &str, judge: &mut Judge<'_>) -> Result<(), ArgWhy> {
    if !scheme_is(url, "http") && !scheme_is(url, "https") {
        return Err(ArgWhy::Scheme(url.to_string()));
    }
    // `extract_normalized_host` is the tree's strictest host reader: it mirrors the WHATWG
    // tab/newline strip, the backslash fold, the userinfo drop, the trailing-root-dot strip and the
    // percent-decode that a connecting stack applies. Re-deriving any of that here would be a
    // second copy of a guard that already exists.
    let host = extract_normalized_host(url).ok_or_else(|| ArgWhy::NoHost(url.to_string()))?;
    judge_host(&host, judge)
}

/// THE HOST, ASKED OF THE HOST'S ONE JUDGE (`dest.judge`, BUSBAR-1.6.0.md Appendix C B.3 item 11):
/// the plane reads the host and holds no rule about it. `judge`'s verdict is rendered as the
/// refusal; a host that gave none refuses the value.
fn judge_host(raw: &str, judge: &mut Judge<'_>) -> Result<(), ArgWhy> {
    let host = normalize_host(raw).ok_or_else(|| ArgWhy::NoHost(raw.to_string()))?;
    let dest = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    match judge(&dest) {
        Some(DEST_ALLOWED) => Ok(()),
        Some(DEST_METADATA) => Err(ArgWhy::CloudMetadata(host)),
        Some(DEST_OBFUSCATED) => Err(ArgWhy::ObfuscatedHost(host)),
        Some(DEST_INTERNAL) => Err(ArgWhy::InternalHost(host)),
        Some(DEST_NO_HOST) => Err(ArgWhy::NoHost(host)),
        Some(verdict) => Err(ArgWhy::Refused(host, verdict)),
        None => Err(ArgWhy::Unjudged(host)),
    }
}

/// Normalize a bare host the same way a URL's host component is normalized, by routing it through
/// the same reader: an IPv6 literal is bracketed so the reader sees an authority rather than a
/// host:port, and everything else is passed as written.
fn normalize_host(raw: &str) -> Option<String> {
    extract_normalized_host(&probe_url(raw))
}

fn probe_url(host: &str) -> String {
    if busbar_contract::net::host_ip(host).is_some_and(|ip| ip.is_ipv6()) {
        format!("https://[{host}]/")
    } else {
        format!("https://{host}/")
    }
}

/// Drop a `:port` suffix from an authority, leaving a bracketed IPv6 literal intact for
/// [`normalize_host`] to unwrap.
fn strip_port(authority: &str) -> &str {
    if authority.starts_with('[') {
        return authority;
    }
    match authority.rsplit_once(':') {
        Some((left, _)) if !left.contains(':') => left,
        _ => authority,
    }
}

/// RFC 6901 token escaping: `~` becomes `~0` and `/` becomes `~1`, in that order, so a key
/// containing either cannot forge a different pointer than the one it is at.
fn escape_token(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// The first URL-ish `format` declared for this position, in declaration order across the expanded
/// schema nodes.
fn first_urlish(schemas: &[&Value]) -> Option<(String, Urlish)> {
    for node in expanded(schemas) {
        let Some(format) = node.get("format").and_then(Value::as_str) else {
            continue;
        };
        let lower = format.to_ascii_lowercase();
        if !URLISH_FORMATS.contains(&lower.as_str()) {
            continue;
        }
        let kind = match lower.as_str() {
            "uri-reference" => Urlish::Reference,
            "hostname" | "idn-hostname" | "ipv4" | "ipv6" => Urlish::Host,
            _ => Urlish::AbsoluteUrl,
        };
        return Some((format.to_string(), kind));
    }
    None
}

/// A schema node plus every `allOf`/`anyOf`/`oneOf` branch reachable from it, so a URL-ish format
/// hidden inside a combinator is still found.
fn expanded<'a>(schemas: &[&'a Value]) -> Vec<&'a Value> {
    let mut out = Vec::new();
    expand_into(schemas, &mut out, MAX_COMBINATOR_DEPTH);
    out
}

fn expand_into<'a>(schemas: &[&'a Value], out: &mut Vec<&'a Value>, budget: usize) {
    if budget == 0 {
        return;
    }
    for node in schemas {
        if !node.is_object() {
            continue;
        }
        out.push(node);
        for key in ["allOf", "anyOf", "oneOf"] {
            if let Some(branches) = node.get(key).and_then(Value::as_array) {
                let refs: Vec<&Value> = branches.iter().collect();
                expand_into(&refs, out, budget - 1);
            }
        }
    }
}

/// The schema(s) governing object member `key`: `properties` where it is named, otherwise the
/// object's `additionalProperties` schema where there is one.
fn child_for_key<'a>(schemas: &[&'a Value], key: &str) -> Vec<&'a Value> {
    let mut out = Vec::new();
    for node in expanded(schemas) {
        if let Some(named) = node
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|m| m.get(key))
        {
            out.push(named);
        } else if let Some(extra) = node.get("additionalProperties") {
            if extra.is_object() {
                out.push(extra);
            }
        }
    }
    out
}

/// The schema(s) governing array element `index`: the tuple position where the schema gives one
/// (`prefixItems`, or the legacy array form of `items`), otherwise the single `items` schema.
fn child_for_index<'a>(schemas: &[&'a Value], index: usize) -> Vec<&'a Value> {
    let mut out = Vec::new();
    for node in expanded(schemas) {
        if let Some(tuple) = node.get("prefixItems").and_then(Value::as_array) {
            if let Some(at) = tuple.get(index) {
                out.push(at);
                continue;
            }
        }
        match node.get("items") {
            Some(Value::Array(tuple)) => {
                if let Some(at) = tuple.get(index) {
                    out.push(at);
                }
            }
            Some(single) if single.is_object() => out.push(single),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/argguard_tests.rs"]
mod tests;
