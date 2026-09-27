// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **AN `otlp` INSTANCE IS REFUSED IN 1.5.5's WORDS** — driven through the real binary's
//! `--validate`, now that `module: otlp` is the linked `busbar-export-otlp` sink on the export axis
//! (K9e-2; owner answer Q75 fixed the export, not the refusals).
//!
//! The `fields:` refusals are byte for byte what the shipped 1.5.5 binary printed for an `otlp`
//! instance (measured by the K9e-2 slot, `busbar-run/k9e-v155-otlp-fields-refusals.txt`): the traces
//! stream cannot be projected, an unknown field, an empty list, a field of another stream, a stream
//! the module cannot carry. A second instance is refused while the configuration resolves, as a
//! configuration error, naming the first; a settings key the sink does not know, and a missing
//! `url`, are refused in the configuration grammar's words.
//!
//! Which sinks the build links is the binary's own answer: a build that does not link the sink has no
//! `otlp` to refuse this way, and says it is an unknown exporter.

use std::path::PathBuf;
use std::process::Command;

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-otlp-refusals-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// `--validate` over a config whose only section is `export:` with `instances`: the refusal's lines
/// — the header, then each `  - ` item — or, when it validates, nothing.
fn refusal(instances: &str) -> Vec<String> {
    let dir = fixture_dir();
    std::fs::write(dir.join("providers.yaml"), "").unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!("listen: \"127.0.0.1:0\"\nproviders: {{}}\nmodels: {{}}\nexport:\n{instances}"),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--validate")
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .output()
        .expect("run busbar");
    let _ = std::fs::remove_dir_all(&dir);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    text.lines()
        .skip_while(|l| !l.starts_with("[error]"))
        .map(str::to_string)
        .collect()
}

const URL: &str = "settings: { url: \"http://localhost:4318/v1/traces\" }";

/// 1.5.5's refusal of a PINNED traces field (`trace_id` has no producer a `fields:` list may name).
const PINNED: &str = "  - export.trace.fields: the `traces` stream cannot be projected with `fields:` \
                      in this release — its PINNED field `trace_id` (which `fields:` may never omit, \
                      because it is what makes the records joinable) HAS NO PRODUCER yet and \
                      arrives in a later release. Omit `fields:` to receive the stream's produced \
                      default set.";
/// 1.5.5's list of the traces stream's fields, in its order.
const FIELDS: &str = "pool | provider | trace_id | span_id | parent_span_id | name | start | \
                      duration_us | ingress | op | lane | model";

#[test]
fn an_otlp_instance_is_refused_in_the_words_1_5_5_used() {
    // A build that does not link the sink cannot speak for it.
    let linked = refusal(&format!("  trace: {{ module: otlp, {URL} }}\n"));
    if linked.iter().any(|l| l.contains("unknown exporter 'otlp'")) {
        return;
    }
    assert!(
        linked.is_empty(),
        "a plain otlp instance validates: {linked:?}"
    );

    let header = |l: &[String]| l.first().map(|h| h.ends_with(" config errors:")) == Some(true);
    let cases: Vec<(&str, Vec<String>)> = vec![
        (
            "fields: [bogus]",
            vec![
                PINNED.to_string(),
                format!(
                    "  - export.trace.fields: unknown field `bogus`. The fields of the subscribed \
                     streams are: {FIELDS}."
                ),
            ],
        ),
        ("fields: [trace_id, span_id]", vec![PINNED.to_string()]),
        ("fields: [pool]", vec![PINNED.to_string()]),
        (
            "fields: []",
            vec![
                "  - export.trace.fields: is EMPTY — `fields:` is an EXHAUSTIVE OVERRIDE, so an \
                 empty list means a record with no fields at all. Omit the key to take each \
                 subscribed stream's default fields."
                    .to_string(),
            ],
        ),
        (
            "fields: [model_requested]",
            vec![
                PINNED.to_string(),
                format!(
                    "  - export.trace.fields: `model_requested` is not a field of any subscribed \
                     stream (traces), so it would never arrive. The fields of the subscribed \
                     streams are: {FIELDS}."
                ),
            ],
        ),
        (
            "streams: [logs]",
            vec![
                "  - export.trace.streams: `module: otlp` cannot carry the `logs` stream (it \
                 carries: traces), so this subscription would deliver nothing. Point a different \
                 module at this stream, or drop it from `streams:`."
                    .to_string(),
            ],
        ),
    ];
    for (key, want) in cases {
        let got = refusal(&format!("  trace: {{ module: otlp, {URL}, {key} }}\n"));
        assert!(header(&got), "{key}: a configuration error: {got:?}");
        assert_eq!(got[1..], want[..], "{key}");
    }

    // A second instance: refused while the configuration resolves, naming the first.
    let got = refusal(&format!(
        "  traces: {{ module: otlp, {URL} }}\n  again: {{ module: otlp, {URL} }}\n"
    ));
    assert!(header(&got), "a configuration error: {got:?}");
    assert_eq!(
        got[1..],
        ["  - export.again: a second `module: otlp` instance (already defined as 'traces'). OTLP \
          installs the ONE process-global tracer subscriber, so a second instance could only be \
          silently ignored — keep a single instance."
            .to_string()]
    );

    // The settings' grammar.
    for (settings, want) in [
        (
            "{ url: \"http://x/\", otlp_endpoint: \"y\" }",
            "  - export.traces.settings: unknown field `otlp_endpoint`, expected `url`",
        ),
        ("{}", "  - export.traces.settings: missing field `url`"),
    ] {
        let got = refusal(&format!(
            "  traces: {{ module: otlp, settings: {settings} }}\n"
        ));
        assert!(header(&got), "{settings}: a configuration error: {got:?}");
        assert_eq!(got[1..], [want.to_string()], "{settings}");
    }
}
