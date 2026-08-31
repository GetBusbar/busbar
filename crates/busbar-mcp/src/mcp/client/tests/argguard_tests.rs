// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ARGUMENT-SIDE SSRF GUARD: a metadata endpoint planted in a NESTED tool argument is refused,
//! a legitimate external URL in the SAME field still passes, and the walk is proven to have visited
//! a non-zero number of fields.
//!
//! That last one is not decoration. A walker that finds nothing refuses nothing and passes every
//! refusal test it is given, so every test here that asserts a refusal also asserts the walk
//! reached the field, and one test pins the visited counts exactly.

use crate::mcp::client::argguard::{guard, ArgRefusal, ArgWhy};
use crate::mcp::client::catalogue::CatalogueCache;
use crate::mcp::client::dispatch::{check_arguments, resolve, DispatchRefusal};
use crate::mcp::client::ssrf::SsrfPolicy;
use crate::mcp::client::support::{approved_server, key_wildcard, tool};
use serde_json::{json, Value};

fn public() -> SsrfPolicy {
    SsrfPolicy::default()
}

fn private_ok() -> SsrfPolicy {
    SsrfPolicy {
        allow_private: true,
    }
}

/// A schema whose `uri` field sits two levels down inside nested objects — the shape a real
/// webhook-taking tool has, and the shape a flat walk misses.
fn nested_uri_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "message": {"type": "string"},
            "delivery": {
                "type": "object",
                "properties": {
                    "callback": {"type": "string", "format": "uri"}
                }
            }
        }
    })
}

fn nested_uri_args(url: &str) -> Value {
    json!({"message": "hello", "delivery": {"callback": url}})
}

/// THE HEADLINE CASE. A model that has just read a hostile tool description puts the instance
/// metadata endpoint into a NESTED argument of a tool whose pinned schema declares that field a
/// `uri`. It is refused, at the exact field, naming the reason.
#[test]
fn a_metadata_endpoint_in_a_nested_uri_argument_is_refused() {
    let args = nested_uri_args("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
    let err = guard(&nested_uri_schema(), &args, public())
        .expect_err("the instance metadata endpoint must not be passed through to the upstream");
    assert_eq!(
        err,
        ArgRefusal {
            pointer: "/delivery/callback".into(),
            declared_format: Some("uri".into()),
            why: ArgWhy::CloudMetadata("169.254.169.254".into()),
        }
    );
    // The rendered refusal names the field and the reason, so an operator reading it can act.
    let rendered = err.to_string();
    assert!(rendered.contains("/delivery/callback"), "{rendered}");
    assert!(rendered.contains("169.254.169.254"), "{rendered}");
}

/// THE CONTROL. A guard with no control is a closed door, and a closed door breaks every real tool.
/// The SAME field, the SAME schema, a legitimate external URL: it passes, and the walk reports that
/// it did in fact judge it.
#[test]
fn a_legitimate_external_url_in_the_same_field_still_passes() {
    let args = nested_uri_args("https://hooks.example.com/services/T000/B000/xyz");
    let scan = guard(&nested_uri_schema(), &args, public())
        .expect("an ordinary external webhook URL must still be dispatched");
    assert_eq!(
        scan.declared_judged, 1,
        "the walk must have actually reached and judged the callback field"
    );
    assert_eq!(scan.undeclared_judged, 0);
    assert_eq!(scan.strings_seen, 2, "`message` and `callback`");
}

/// THE FLOOR, pinned exactly rather than as an inequality. Nested object, array of strings, a field
/// four levels deep and a bare-host field are all in one document, and the counts say which of them
/// the walk reached. Five is the number of URL-ish fields the document declares; if the walk ever
/// reports fewer, it stopped following one of those four shapes.
#[test]
fn the_walk_visits_every_declared_url_field_and_says_how_many() {
    let schema = json!({
        "type": "object",
        "properties": {
            "callback": {"type": "string", "format": "uri"},
            "mirrors": {"type": "array", "items": {"type": "string", "format": "uri"}},
            "delivery": {"type": "object", "properties": {
                "endpoint": {"type": "object", "properties": {
                    "target": {"type": "object", "properties": {
                        "url": {"type": "string", "format": "uri"}
                    }}
                }}
            }},
            "origin": {"type": "string", "format": "hostname"},
            "note": {"type": "string"}
        }
    });
    let args = json!({
        "callback": "https://hooks.example.com/a",
        "mirrors": ["https://a.example.com/1", "https://b.example.com/2"],
        "delivery": {"endpoint": {"target": {"url": "https://deep.example.com/z"}}},
        "origin": "api.example.com",
        // Free text that MENTIONS a metadata URL mid-sentence. The undeclared detector reads whole
        // values, never substrings, so this is untouched — the documented limit, asserted rather
        // than described.
        "note": "the runbook says never to call http://169.254.169.254/ from a tool"
    });
    let scan = guard(&schema, &args, public()).expect("every URL here is a public one");
    assert_eq!(
        scan.declared_judged, 5,
        "callback + 2 mirrors + the four-deep url + origin"
    );
    assert_eq!(scan.undeclared_judged, 0, "the note is prose, not a URL");
    assert_eq!(scan.strings_seen, 6);
    assert!(scan.judged() >= 5);
}

/// Each element of an array of URLs is judged on its own, so a hostile entry cannot hide behind
/// admissible siblings.
#[test]
fn one_hostile_entry_in_an_array_of_urls_refuses_the_whole_call() {
    let schema = json!({
        "type": "object",
        "properties": {
            "mirrors": {"type": "array", "items": {"type": "string", "format": "uri"}}
        }
    });
    let args = json!({"mirrors": [
        "https://a.example.com/1",
        "https://b.example.com/2",
        "http://169.254.169.254/latest/meta-data/"
    ]});
    let err = guard(&schema, &args, public()).expect_err("the third entry must refuse the call");
    assert_eq!(err.pointer, "/mirrors/2");
    assert_eq!(err.why, ArgWhy::CloudMetadata("169.254.169.254".into()));
    // The control: the same array with every entry public passes, and all three were judged.
    let ok = json!({"mirrors": [
        "https://a.example.com/1", "https://b.example.com/2", "https://c.example.com/3"
    ]});
    let scan = guard(&schema, &ok, public()).expect("three public mirrors are fine");
    assert_eq!(scan.declared_judged, 3);
}

/// A URL-ish field FOUR levels below the argument root, inside an array inside an object inside an
/// object, is still reached.
#[test]
fn a_url_field_several_levels_deep_is_still_reached() {
    let schema = json!({
        "type": "object",
        "properties": {"a": {"type": "object", "properties": {
            "b": {"type": "object", "properties": {
                "c": {"type": "array", "items": {"type": "object", "properties": {
                    "d": {"type": "string", "format": "uri"}
                }}}
            }}
        }}}
    });
    let args = json!({"a": {"b": {"c": [{"d": "http://169.254.169.254/"}]}}});
    let err = guard(&schema, &args, public()).expect_err("depth must not launder the value");
    assert_eq!(err.pointer, "/a/b/c/0/d");
    let ok = json!({"a": {"b": {"c": [{"d": "https://ok.example.com/"}]}}});
    assert_eq!(
        guard(&schema, &ok, public())
            .expect("a public URL at the same depth passes")
            .declared_judged,
        1
    );
}

/// EVERY ENCODING THE TRANSPORT GUARD ALREADY HANDLES, handled here too: the alternate IPv4 forms,
/// IPv4-mapped IPv6, the `localhost` family, and the metadata DNS names.
#[test]
fn the_encodings_the_transport_guard_handles_are_refused_in_arguments_too() {
    let metadata = [
        "http://169.254.169.254/latest/meta-data/",
        // Alternate encodings of the SAME address: decimal, hex, per-octet octal.
        "http://2852039166/",
        "http://0xa9fea9fe/",
        "http://0251.0376.0251.0376/",
        // Percent-encoded dots, which a connecting stack decodes.
        "http://169%2E254%2E169%2E254/",
        // A trailing root dot, which a resolver treats as the same rooted name.
        "http://169.254.169.254./",
        // IPv4-mapped IPv6: the v4 ruleset must not be bypassable by a v6 spelling.
        "http://[::ffff:169.254.169.254]/",
        // Other clouds' endpoints, and the whole link-local range they live in.
        "http://169.254.170.2/",
        "http://100.100.100.200/",
        "http://[fd00:ec2::254]/",
        // BOTH metadata DNS names.
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://instance-data.ec2.internal/latest/",
    ];
    assert_eq!(metadata.len(), 12, "the metadata set must not shrink");
    for url in metadata {
        let err = guard(&nested_uri_schema(), &nested_uri_args(url), public())
            .err()
            .unwrap_or_else(|| panic!("`{url}` must be refused, but it passed"));
        assert!(
            matches!(err.why, ArgWhy::CloudMetadata(_)),
            "`{url}` must be refused AS metadata, got {err:?}"
        );
    }

    let obfuscated_loopback = [
        "http://2130706433/",
        "http://0x7f000001/",
        "http://017700000001/",
        "http://127.1/",
    ];
    assert_eq!(obfuscated_loopback.len(), 4);
    for url in obfuscated_loopback {
        let err = guard(&nested_uri_schema(), &nested_uri_args(url), public())
            .expect_err("an alternate IPv4 encoding must be refused");
        assert!(
            matches!(err.why, ArgWhy::ObfuscatedHost(_)),
            "`{url}` must be refused AS an obfuscated host, got {err:?}"
        );
    }

    let internal = [
        "http://localhost:8080/x",
        "http://LOCALHOST/x",
        "http://tool.localhost/x",
        "http://127.0.0.1/x",
        "http://[::1]/x",
        "http://[::ffff:127.0.0.1]/x",
        "http://0.0.0.0/x",
        "http://10.0.0.5/x",
        "http://172.16.0.1/x",
        "http://192.168.1.1/x",
        "http://100.64.0.1/x",
        "http://[fc00::1]/x",
        "http://[fe80::1]/x",
    ];
    assert_eq!(internal.len(), 13, "the internal set must not shrink");
    for url in internal {
        let err = guard(&nested_uri_schema(), &nested_uri_args(url), public())
            .expect_err("an internal destination must be refused");
        assert!(
            matches!(err.why, ArgWhy::InternalHost(_)),
            "`{url}` must be refused AS internal, got {err:?}"
        );
    }

    // THE CONTROL, again: ordinary public destinations in the same field are NOT refused, so the
    // three loops above are not passing because everything is refused.
    for url in ["https://api.example.com/v1/x", "https://93.184.216.34/x"] {
        assert_eq!(
            guard(&nested_uri_schema(), &nested_uri_args(url), public())
                .unwrap_or_else(|e| panic!("`{url}` must pass, got {e}"))
                .declared_judged,
            1
        );
    }
}

/// A metadata refusal is unconditional; an internal one is the operator's to opt into. That is the
/// same split `super::ssrf` draws, and it has to be the same one — an operator saying "this server
/// is on our internal network" has said nothing about the credential-vending endpoint.
#[test]
fn allow_private_admits_internal_hosts_and_never_admits_metadata() {
    assert!(matches!(
        guard(
            &nested_uri_schema(),
            &nested_uri_args("http://10.0.0.5/x"),
            public()
        ),
        Err(ArgRefusal {
            why: ArgWhy::InternalHost(_),
            ..
        })
    ));
    assert!(guard(
        &nested_uri_schema(),
        &nested_uri_args("http://mcp.internal:8080/x"),
        private_ok()
    )
    .is_ok());
    assert!(guard(
        &nested_uri_schema(),
        &nested_uri_args("http://10.0.0.5/x"),
        private_ok()
    )
    .is_ok());

    for url in [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://2852039166/",
    ] {
        let err = guard(&nested_uri_schema(), &nested_uri_args(url), private_ok())
            .expect_err("metadata is refused under every policy");
        assert!(
            matches!(err.why, ArgWhy::CloudMetadata(_)),
            "`{url}` under allow_private: {err:?}"
        );
    }
    // An obfuscated encoding stays refused under `allow_private` too: a value spelled so the check
    // cannot read it is refused rather than guessed at.
    assert!(matches!(
        guard(
            &nested_uri_schema(),
            &nested_uri_args("http://2130706433/"),
            private_ok()
        ),
        Err(ArgRefusal {
            why: ArgWhy::ObfuscatedHost(_),
            ..
        })
    ));
}

/// A declared absolute-URL field accepts `http(s)` and nothing else. Other schemes are refused by
/// absence rather than by a blocklist somebody has to keep up with.
#[test]
fn a_declared_uri_field_takes_no_scheme_but_http_and_https() {
    let banned = [
        "file:///etc/passwd",
        "gopher://169.254.169.254/",
        "smb://host/share",
        "ftp://host/",
        "data:text/plain;base64,aGk=",
        "ws://host/",
        "jar:file:///x!/y",
    ];
    assert_eq!(banned.len(), 7, "the banned-scheme set must not shrink");
    for url in banned {
        let err = guard(&nested_uri_schema(), &nested_uri_args(url), private_ok())
            .expect_err("only http(s) is passed through");
        assert!(
            matches!(err.why, ArgWhy::Scheme(_)),
            "`{url}` must be refused on its scheme, got {err:?}"
        );
    }
}

/// The bare-host formats are judged as hosts rather than as URLs, so a `hostname` / `ipv4` / `ipv6`
/// field cannot smuggle a loopback or metadata target past a URL-shaped check.
#[test]
fn bare_host_formats_are_judged_as_hosts() {
    let schema = json!({
        "type": "object",
        "properties": {
            "host": {"type": "string", "format": "hostname"},
            "idn": {"type": "string", "format": "idn-hostname"},
            "v4": {"type": "string", "format": "ipv4"},
            "v6": {"type": "string", "format": "ipv6"}
        }
    });
    for (field, value) in [
        ("host", "metadata.google.internal"),
        ("idn", "localhost"),
        ("v4", "169.254.169.254"),
        ("v6", "::1"),
    ] {
        let args = json!({ field: value });
        assert!(
            guard(&schema, &args, public()).is_err(),
            "`{value}` in `{field}` must be refused"
        );
    }
    // The control: an ordinary public host in every one of the four fields passes, all four judged.
    let ok = json!({"host": "api.example.com", "idn": "api.example.com",
                    "v4": "93.184.216.34", "v6": "2606:2800:220:1:248:1893:25c8:1946"});
    let scan = guard(&schema, &ok, public()).expect("public hosts pass");
    assert_eq!(scan.declared_judged, 4);
}

/// THE UNDECLARED CASE, and the decision it encodes. Most real MCP tools take a URL in a plain
/// `{"type": "string"}`, so a walk that judged only declared fields would refuse almost nothing.
/// A string whose WHOLE value is an `http(s)` URL is therefore judged wherever it appears — and
/// nothing narrower is, because refusing a hostname-shaped word in free text breaks real tools.
#[test]
fn an_http_url_in_an_undeclared_field_is_judged_and_a_hostname_shaped_word_is_not() {
    let schema = json!({
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "query": {"type": "string"}
        }
    });
    let err = guard(
        &schema,
        &json!({"target": "http://169.254.169.254/latest/meta-data/", "query": "x"}),
        public(),
    )
    .expect_err("an undeclared field carrying a whole URL is still judged");
    assert_eq!(err.pointer, "/target");
    assert_eq!(
        err.declared_format, None,
        "the schema declared no format here, and the refusal says so"
    );

    // A field the schema does not mention AT ALL — not in `properties`, no `additionalProperties`.
    let err = guard(
        &schema,
        &json!({"undeclared_extra": "https://localhost/admin"}),
        public(),
    )
    .expect_err("a field the schema never mentions is still walked");
    assert_eq!(err.pointer, "/undeclared_extra");
    assert!(matches!(err.why, ArgWhy::InternalHost(_)));

    // AND THE LIMIT, asserted: bare hostnames, mid-string URLs and non-http schemes in UNDECLARED
    // fields are NOT sniffed. Each of these is a legitimate value for some real tool.
    let tolerated = json!({
        "query": "localhost",
        "a": "169.254.169.254",
        "b": "see http://169.254.169.254/ for the format",
        "c": "file:///etc/passwd",
        "d": "//169.254.169.254/x"
    });
    let scan = guard(&schema, &tolerated, public())
        .expect("the undeclared detector reads whole http(s) values and nothing else");
    assert_eq!(scan.undeclared_judged, 0);
    assert_eq!(
        scan.strings_seen, 5,
        "all five were walked, none was judged"
    );
}

/// A URL-ish format reached only through a combinator branch, through `additionalProperties`, or at
/// a tuple position is still found. Each is a shape a naive `properties`-only walk misses.
#[test]
fn combinators_additional_properties_and_tuple_positions_are_all_followed() {
    let schema = json!({
        "type": "object",
        "properties": {
            "one": {"anyOf": [{"type": "null"}, {"type": "string", "format": "uri"}]},
            "bag": {"type": "object", "additionalProperties": {"type": "string", "format": "uri"}},
            "pair": {"type": "array", "prefixItems": [
                {"type": "string"},
                {"type": "string", "format": "uri"}
            ]}
        }
    });
    let hostile = "http://169.254.169.254/";
    for (args, pointer) in [
        (json!({"one": hostile}), "/one"),
        (json!({"bag": {"whatever": hostile}}), "/bag/whatever"),
        (json!({"pair": ["label", hostile]}), "/pair/1"),
    ] {
        let err = guard(&schema, &args, public())
            .err()
            .unwrap_or_else(|| panic!("the field at {pointer} must be reached and refused"));
        assert_eq!(err.pointer, pointer);
        assert_eq!(err.declared_format.as_deref(), Some("uri"));
    }
    // The control: the same three shapes with public URLs pass, and each judged one field.
    for args in [
        json!({"one": "https://ok.example.com/"}),
        json!({"bag": {"whatever": "https://ok.example.com/"}}),
        json!({"pair": ["label", "https://ok.example.com/"]}),
    ] {
        assert_eq!(
            guard(&schema, &args, public())
                .expect("public URLs pass in every shape")
                .declared_judged,
            1
        );
    }
}

/// `uri-reference` may legitimately be relative, so a relative reference is admissible — but a
/// SCHEME-RELATIVE one names a host and is judged like any other.
#[test]
fn a_uri_reference_is_relative_or_judged_but_never_waved_through() {
    let schema = json!({
        "type": "object",
        "properties": {"path": {"type": "string", "format": "uri-reference"}}
    });
    for relative in ["/v1/items", "items/3", "?q=1", "#frag"] {
        let scan = guard(&schema, &json!({ "path": relative }), public())
            .unwrap_or_else(|e| panic!("`{relative}` is a legitimate relative reference: {e}"));
        assert_eq!(
            scan.declared_judged, 1,
            "it was judged, and it was admissible"
        );
    }
    for hostile in [
        "//169.254.169.254/latest/",
        "http://169.254.169.254/latest/",
    ] {
        let err = guard(&schema, &json!({ "path": hostile }), public())
            .expect_err("a reference that names a host is judged on that host");
        assert_eq!(err.why, ArgWhy::CloudMetadata("169.254.169.254".into()));
    }
}

/// Arguments nested past the walk's depth bound are REFUSED rather than silently truncated. A walk
/// that quietly stops reports "nothing found" on the one document built to make it stop.
#[test]
fn arguments_nested_past_the_bound_are_refused_rather_than_truncated() {
    let mut deep = json!("http://169.254.169.254/");
    for _ in 0..100 {
        deep = json!({ "n": deep });
    }
    let err = guard(&json!({"type": "object"}), &deep, public())
        .expect_err("a document too deep to walk must refuse, not pass");
    assert_eq!(err.why, ArgWhy::DepthExceeded);
    // The control: a shallow document is not refused for depth.
    assert!(guard(&json!({"type": "object"}), &json!({"n": "hi"}), public()).is_ok());
}

/// A key containing a `/` or a `~` is escaped per RFC 6901, so the pointer in a refusal names the
/// field it actually came from rather than a different one.
#[test]
fn pointer_tokens_are_escaped_so_a_key_cannot_forge_a_location() {
    let schema = json!({
        "type": "object",
        "properties": {"a/b": {"type": "string", "format": "uri"}}
    });
    let err = guard(
        &schema,
        &json!({"a/b": "http://169.254.169.254/"}),
        public(),
    )
    .expect_err("refused");
    assert_eq!(err.pointer, "/a~1b");
}

// ── the dispatch seam ────────────────────────────────────────────────────────────────────────────

fn schema_with_callback() -> Value {
    json!({
        "type": "object",
        "properties": {
            "delivery": {"type": "object", "properties": {
                "callback": {"type": "string", "format": "uri"}
            }}
        }
    })
}

fn approved_notes_cache() -> CatalogueCache {
    let cache = CatalogueCache::new();
    cache.apply(|servers| {
        servers.insert(
            "notes".into(),
            approved_server(
                "notes",
                vec![tool("send", "posts a note", schema_with_callback())],
            ),
        );
    });
    cache
}

/// THE SEAM: the schema the walk reads comes from the PINNED catalogue entry, reached through a
/// resolution, not from anything the caller supplied alongside the arguments.
#[test]
fn dispatch_walks_the_pinned_schema_and_refuses_a_metadata_argument() {
    let cache = approved_notes_cache();
    let caller = key_wildcard("k");
    let snapshot = cache.load();
    let resolved = resolve(&snapshot, "notes_send", &caller).expect("resolves");

    let hostile = nested_uri_args("http://169.254.169.254/latest/meta-data/");
    let err = check_arguments(&snapshot, &resolved, &hostile, public())
        .expect_err("the metadata endpoint must not reach the upstream");
    assert!(
        matches!(err, DispatchRefusal::ToolArgument(_)),
        "expected an argument refusal, got {err:?}"
    );
    assert!(err.to_string().contains("/delivery/callback"), "{err}");

    // THE CONTROL: the same tool, the same field, a real webhook — and the walk reports that it
    // judged it, so this is a pass rather than a walk that never ran.
    let ok = nested_uri_args("https://hooks.example.com/T/B/x");
    let scan = check_arguments(&snapshot, &resolved, &ok, public())
        .expect("a legitimate webhook URL is dispatched");
    assert_eq!(scan.declared_judged, 1);
}

/// VERDICT PARITY: the host-owned `guard_url` slot returns bit-identical allow/deny AND the same
/// refusal class + offending-host bytes as this module's inline structural judge, for every input.
/// The slot is where the SSRF/URL guard moves to (the host owns the `net_guard` chokepoint a plane
/// cannot name); this pins the two implementations together so neither can drift from the other.
#[test]
fn guard_url_slot_matches_the_inline_arg_guard_for_every_input() {
    use busbar_core::plane_host::{guard_url_over, GuardOutcome};
    use busbar_plugin::hot::GuardClass;

    let app = busbar_core::test_support::TestApp::new().build();

    // The inline judge's verdict for one absolute URL, reduced to the slot's neutral (class, host)
    // shape by routing it through a declared-`uri` field (the AbsoluteUrl path the slot reproduces).
    fn inline(url: &str, policy: SsrfPolicy) -> Result<(), (GuardClass, String)> {
        match guard(&nested_uri_schema(), &nested_uri_args(url), policy) {
            Ok(_) => Ok(()),
            Err(ArgRefusal { why, .. }) => Err(match why {
                ArgWhy::Scheme(v) => (GuardClass::Scheme, v),
                ArgWhy::NoHost(v) => (GuardClass::NoHost, v),
                ArgWhy::CloudMetadata(h) => (GuardClass::CloudMetadata, h),
                ArgWhy::ObfuscatedHost(h) => (GuardClass::ObfuscatedHost, h),
                ArgWhy::InternalHost(h) => (GuardClass::InternalHost, h),
                ArgWhy::DepthExceeded => unreachable!("a single URL argument does not nest"),
            }),
        }
    }

    // The full corpus the inline guard's own tests exercise: metadata (by address, alternate
    // encoding and DNS name), obfuscated loopback, the internal range, banned schemes, and the
    // public/private-opt-in controls.
    let corpus: &[&str] = &[
        "http://169.254.169.254/latest/meta-data/",
        "http://2852039166/",
        "http://0xa9fea9fe/",
        "http://0251.0376.0251.0376/",
        "http://169%2E254%2E169%2E254/",
        "http://169.254.169.254./",
        "http://[::ffff:169.254.169.254]/",
        "http://169.254.170.2/",
        "http://100.100.100.200/",
        "http://[fd00:ec2::254]/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://instance-data.ec2.internal/latest/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://017700000001/",
        "http://127.1/",
        "http://localhost:8080/x",
        "http://LOCALHOST/x",
        "http://tool.localhost/x",
        "http://127.0.0.1/x",
        "http://[::1]/x",
        "http://[::ffff:127.0.0.1]/x",
        "http://0.0.0.0/x",
        "http://10.0.0.5/x",
        "http://172.16.0.1/x",
        "http://192.168.1.1/x",
        "http://100.64.0.1/x",
        "http://[fc00::1]/x",
        "http://[fe80::1]/x",
        "file:///etc/passwd",
        "gopher://169.254.169.254/",
        "smb://host/share",
        "ftp://host/",
        "data:text/plain;base64,aGk=",
        "ws://host/",
        "jar:file:///x!/y",
        "https://api.example.com/v1/x",
        "https://93.184.216.34/x",
        "https://hooks.example.com/services/T000/B000/xyz",
        "http://mcp.internal:8080/x",
    ];

    for &url in corpus {
        for allow_private in [false, true] {
            let policy = SsrfPolicy { allow_private };
            let expected = inline(url, policy);
            let actual = match guard_url_over(&app, url, allow_private) {
                GuardOutcome::Allow => Ok(()),
                GuardOutcome::Deny { class, reason } => Err((class, reason)),
            };
            assert_eq!(
                actual, expected,
                "verdict parity for `{url}` (allow_private={allow_private})"
            );
        }
    }
}

/// The schema is RE-PINNED at the walk: a resolution carrying a digest the catalogue no longer
/// serves is drift, and the walk does not run against a document the operator never approved.
#[test]
fn a_resolution_whose_digest_no_longer_matches_refuses_before_the_walk() {
    let cache = approved_notes_cache();
    let caller = key_wildcard("k");
    let snapshot = cache.load();
    let mut resolved = resolve(&snapshot, "notes_send", &caller).expect("resolves");
    resolved.identity.digest = format!("sha256:{}", "0".repeat(64));

    let err = check_arguments(
        &snapshot,
        &resolved,
        &nested_uri_args("https://hooks.example.com/x"),
        public(),
    )
    .expect_err("a stale digest must refuse rather than walk an unapproved schema");
    assert!(
        matches!(err, DispatchRefusal::SchemaDrift { .. }),
        "expected drift, got {err:?}"
    );
}
