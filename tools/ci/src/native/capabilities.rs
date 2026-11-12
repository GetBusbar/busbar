//! Protected provisioning decisions for known offline conformance adapters
//! (former `native_conformance_capabilities`). An available row authorizes an
//! attempt with verified inputs; it is never a suite verdict.
use super::sp::{self, R, value_error};
use super::{CORE, Q, pysteps};
use crate::json::{self, Value, object};
use crate::sha256;

type Owner = &'static [(&'static str, &'static [&'static str])];

const LLM: &[&str] = &["llm-specs"];

/// The former `OWNERS` table, in its declaration order.
pub fn owner(repository: &str) -> Option<Owner> {
    Some(match repository {
        CORE => &[
            ("tls", &["testssl"]),
            ("sbom", &["sbom"]),
            ("oidf-oauth2", &["oidf", "oidc-source"]),
            ("fapi2", &["oidf", "oidc-source"]),
            ("h2", &["h2"]),
            ("evidence-audit-trail", &[]),
            ("evidence-rbac", &["zap", "oidc-source"]),
            ("evidence-tls", &["tlsfuzzer"]),
        ],
        "GetBusbar/busbar-plane-decisions" => &[("jev", &[])],
        "GetBusbar/busbar-plane-streaming" => &[
            ("voice-openai-realtime", &[]),
            ("voice-gemini-live", &[]),
            ("voice-twilio", &[]),
        ],
        "GetBusbar/busbar-plane-llm" => &[
            ("llm-anthropic", LLM),
            ("llm-openai", LLM),
            ("llm-responses", LLM),
            ("llm-gemini", LLM),
            ("llm-bedrock", LLM),
            ("llm-cohere", LLM),
            ("voice-transcribe", LLM),
            ("voice-tts", LLM),
        ],
        "GetBusbar/busbar-plane-mcp" => &[("mcp", &["mcp-tools"])],
        "GetBusbar/busbar-plane-a2a" => &[("a2a", &["a2a-tools"])],
        "GetBusbar/busbar-export-otlp" => {
            &[("otlp", &["otlp"]), ("otel-semconv-weaver", &["weaver"])]
        }
        "GetBusbar/busbar-transport-ws" => &[("ws", &["ws"])],
        "GetBusbar/busbar-transport-webrtc" => &[("webrtc-browser", &["webrtc"])],
        _ => return None,
    })
}

/// `manifest(repository, source, bundles, ready)`.
pub fn manifest(repository: &str, source: &str, bundles: &Value, ready: bool) -> Value {
    let mut rows: Vec<(String, Value)> = Vec::new();
    for (name, required) in owner(repository).unwrap_or(&[]) {
        let mut missing: Vec<&str> = required
            .iter()
            .copied()
            .filter(|b| bundles.get(b).is_none())
            .collect();
        missing.sort();
        let row = if ready && missing.is_empty() {
            object([("available", true.into())])
        } else {
            let reason = if missing.is_empty() {
                "pinned offline runtime and dependency seed are not ready".to_owned()
            } else {
                format!("missing verified offline inputs: {}", missing.join(", "))
            };
            object([("available", false.into()), ("reason", reason.into())])
        };
        rows.push(((*name).to_owned(), row));
    }
    if repository == CORE {
        let row = if ready && bundles.get("release-engineering").is_some() {
            object([("available", true.into())])
        } else {
            object([
                ("available", false.into()),
                (
                    "reason",
                    "verified offline release-engineering controls are not staged".into(),
                ),
            ])
        };
        rows.push(("slsa-verifier".into(), row));
    }
    object([
        ("schema", "busbar.conformance.capabilities/1".into()),
        ("repo", repository.into()),
        ("source", source.into()),
        ("toolchain_ready", ready.into()),
        ("suites", Value::Object(rows)),
    ])
}

pub fn prepare(q: &mut Q) -> R<()> {
    if owner(&q.repository).is_none() {
        return Ok(());
    }
    let execution = q.execution();
    let Some(seed) = execution
        .dependency_seed_sha256
        .clone()
        .filter(|s| !s.is_empty())
    else {
        return Err(value_error(
            "conformance provisioning requires the verified per-job dependency seed",
        ));
    };
    // Real fixed-source runtime check inside this exact candidate boundary.
    let python = execution.python().to_owned();
    q.run_timeout(
        "conformance-runtime-preflight",
        vec![
            python,
            "-I".into(),
            "-B".into(),
            "-c".into(),
            pysteps::CONFORMANCE_PREFLIGHT.into(),
        ],
        120,
    )?;
    let empty = Value::Object(Vec::new());
    let bundles = q
        .receipt
        .at("conformance_inputs")
        .get("bundles")
        .unwrap_or(&empty)
        .clone();
    let source = q.source();
    let record = manifest(&q.repository, &source, &bundles, true);
    let path = q.control.join("conformance-provisioning.json");
    sp::write(&path, json::dumps(&record, true) + "\n")?;
    sp::chmod(&path, 0o444)?;
    let expected = sha256::hex(&sp::read(&path)?);
    let repository = q.repository.clone();
    let digest = q.execution().set_conformance_capabilities(
        Some(&path),
        &repository,
        &source,
        Some(&expected),
    )?;
    q.receipt
        .set("conformance_capabilities_sha256", digest.into());
    q.receipt.set(
        "conformance_provisioning",
        object([
            ("dependency_seed_sha256", seed.into()),
            (
                "inputs_sha256",
                q.receipt.at("conformance_inputs").at("plan_sha256").clone(),
            ),
            ("available_is_verdict", false.into()),
            ("suites", record.at("suites").clone()),
        ]),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_needs_every_verified_input() {
        let bundles = crate::json::parse(br#"{"testssl": {}, "release-engineering": {}}"#).unwrap();
        let record = manifest(CORE, "s", &bundles, true);
        let suites = record.at("suites");
        assert_eq!(suites.keys()[0], "tls");
        assert_eq!(suites.at("tls").at("available").as_bool(), Some(true));
        assert_eq!(
            suites.at("fapi2").at("reason").as_str(),
            Some("missing verified offline inputs: oidc-source, oidf")
        );
        assert_eq!(
            suites.at("slsa-verifier").at("available").as_bool(),
            Some(true)
        );
        assert_eq!(
            manifest(CORE, "s", &bundles, false)
                .at("suites")
                .at("evidence-audit-trail")
                .at("reason")
                .as_str(),
            Some("pinned offline runtime and dependency seed are not ready")
        );
        assert!(
            manifest("GetBusbar/other", "s", &bundles, true)
                .at("suites")
                .keys()
                .is_empty()
        );
    }
}
