// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Scenario data files (`scenarios/*.yaml`): one busbar config (with placeholders), the setup
//! steps that run against the booted gateway, and the cases (traffic shapes) measured against it.
//! Suites (`scenarios/suites.yaml`) are named lists of scenarios.
//!
//! Placeholders are `{NAME}` tokens: `{LISTEN}`, `{ADMIN}` (host:port), `{MOCK}` (the mock's
//! base URL), `{MOCK_ADDR}`, `{WORK}`, `{CARD_ISSUER_KEY}`, `{MCP_SCHEMA_HASH}`, every variable a
//! setup step saves (`{KEY}`, `{AT}`, ...), every docker service's `{<VAR>}` host port, and
//! `{PAD}` (a request body's `pad` bytes of filler).

use crate::driver::{Proto, Req, Shape};
use crate::mock::llm::{Dialect, MARKER};
use crate::mock::MockConfig;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    pub group: String,
    #[serde(default)]
    pub description: String,
    /// Oldest busbar the 1.6 `config` applies to; older binaries use `config_1_5` or skip.
    #[serde(default)]
    pub min_version: Option<String>,
    /// Dynamic plugins this scenario loads, by tarball file-name prefix in `--plugins-dir`.
    #[serde(default)]
    pub plugins: Vec<String>,
    /// External services (stores) started with docker for the scenario.
    #[serde(default)]
    pub docker: Vec<DockerService>,
    #[serde(default)]
    pub mock: MockConfig,
    pub config: String,
    #[serde(default)]
    pub config_1_5: Option<String>,
    #[serde(default)]
    pub providers: Option<String>,
    #[serde(default)]
    pub providers_1_5: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Setup steps (see [`Step`]); kept as JSON values because YAML externally tagged enums
    /// need `!tags`, and `- mint_key: {...}` reads better.
    #[serde(default)]
    pub setup: Vec<serde_json::Value>,
    #[serde(default)]
    pub cases: Vec<CaseSpec>,
    /// Generated LLM cases (ingress x egress x stream x pad x tools), one list per block.
    #[serde(default)]
    pub llm_matrix: Vec<LlmMatrix>,
    /// Files written under the work dir before boot (relative path -> content, placeholders filled).
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerService {
    /// Template variable bound to the published host port (`{PG_PORT}`).
    pub var: String,
    pub image: String,
    /// The container port to publish.
    pub port: u16,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// A substring of the container log that means ready (else: the port accepts).
    #[serde(default)]
    pub ready_log: Option<String>,
    /// How many times `ready_log` must appear (postgres logs it twice).
    #[serde(default = "one")]
    pub ready_count: usize,
}

fn one() -> usize {
    1
}

/// A setup step, run in order after boot.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    /// POST /api/v1/admin/keys `{name, group}`; saves the plaintext key as `{<as>}`.
    MintKey {
        #[serde(rename = "as")]
        save_as: String,
        group: String,
    },
    /// The audience-bound bearer a plane ingress (mcp, a2a, streams) takes: the minted key's
    /// claims plus `a: <aud>`, re-signed with the node signing key.
    AudienceToken {
        #[serde(rename = "as")]
        save_as: String,
        from: String,
        aud: String,
    },
    /// One HTTP exchange; `save` binds `{VAR}` to a top-level JSON field of the answer.
    Http {
        #[serde(default)]
        listener: Listener,
        #[serde(default = "post")]
        method: String,
        path: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        #[serde(default)]
        body: String,
        #[serde(default = "ok200")]
        expect: u16,
        #[serde(default)]
        save: BTreeMap<String, String>,
    },
    SleepMs(u64),
    /// A Google-style service-account JSON with a fresh RSA key (`openssl genpkey`), saved as
    /// `{<as>}` (JSON-escaped for an env value).
    RsaServiceAccount {
        #[serde(rename = "as")]
        save_as: String,
        token_uri: String,
    },
}

fn post() -> String {
    "POST".into()
}
fn ok200() -> u16 {
    200
}
fn w1() -> u32 {
    1
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Listener {
    #[default]
    Data,
    Admin,
    Mock,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ShapeSpec {
    /// Closed loop: requests in flight.
    #[serde(default)]
    pub closed: Option<usize>,
    /// Open loop: arrivals per second.
    #[serde(default)]
    pub open: Option<f64>,
    /// Open loop: the in-flight cap.
    #[serde(default)]
    pub connections: Option<usize>,
}

impl ShapeSpec {
    pub fn shape(&self) -> Shape {
        match (self.open, self.closed) {
            (Some(rate), _) => Shape::Open {
                rate,
                connections: self.connections.unwrap_or(256),
            },
            (None, Some(c)) => Shape::Closed { concurrency: c },
            (None, None) => Shape::Closed { concurrency: 32 },
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReqSpec {
    #[serde(default)]
    pub listener: Listener,
    #[serde(default = "post")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
    /// `{PAD}` in the body becomes this many filler bytes.
    #[serde(default)]
    pub pad: usize,
    #[serde(default = "ok200")]
    pub expect: u16,
    /// Every sampled answer must contain this.
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default = "w1")]
    pub weight: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Background {
    pub shape: ShapeSpec,
    pub requests: Vec<ReqSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    pub name: String,
    #[serde(default)]
    pub proto: Proto,
    #[serde(default)]
    pub shape: ShapeSpec,
    pub requests: Vec<ReqSpec>,
    /// The upstream request the gateway makes, sent straight to the mock for the added-latency
    /// baseline.
    #[serde(default)]
    pub direct: Option<ReqSpec>,
    /// A concurrent secondary load (admin ops under load), measured separately.
    #[serde(default)]
    pub background: Option<Background>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmMatrix {
    pub ingress: Vec<String>,
    pub egress: Vec<String>,
    #[serde(default = "no")]
    pub stream: Vec<bool>,
    #[serde(default = "zero")]
    pub pad: Vec<usize>,
    #[serde(default = "no")]
    pub tools: Vec<bool>,
    /// The client credential (`{KEY}` after a `mint_key`, or any literal when auth is open).
    #[serde(default = "bench_key")]
    pub key: String,
    /// Model name of egress `e` is `<model_prefix><e>`.
    #[serde(default = "m_prefix")]
    pub model_prefix: String,
    #[serde(default)]
    pub shape: ShapeSpec,
    #[serde(default)]
    pub proto: Proto,
}

fn no() -> Vec<bool> {
    vec![false]
}
fn zero() -> Vec<usize> {
    vec![0]
}
fn bench_key() -> String {
    "bench-token".into()
}
fn m_prefix() -> String {
    "m-".into()
}

/// Names of the suites and the scenarios each runs.
impl Scenario {
    pub fn steps(&self) -> Result<Vec<Step>, String> {
        self.setup
            .iter()
            .map(|v| serde_json::from_value(v.clone()).map_err(|e| format!("setup step {v}: {e}")))
            .collect()
    }
}

pub type Suites = BTreeMap<String, Vec<String>>;

pub fn scenarios_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scenarios")
}

pub fn load_suites(dir: &Path) -> Result<Suites, String> {
    let p = dir.join("suites.yaml");
    let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))
}

pub fn load(dir: &Path, name: &str) -> Result<Scenario, String> {
    let p = if name.ends_with(".yaml") {
        PathBuf::from(name)
    } else {
        dir.join(format!("{name}.yaml"))
    };
    let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    let s: Scenario = serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
    s.steps().map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(s)
}

pub fn all_names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            (n.ends_with(".yaml") && n != "suites.yaml").then(|| n.trim_end_matches(".yaml").into())
        })
        .collect();
    v.sort();
    v
}

/// Replace every `{K}` for the keys of `vars`.
pub fn fill(text: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = text.to_string();
    for (k, v) in vars {
        let token = format!("{{{k}}}");
        if out.contains(&token) {
            out = out.replace(&token, v);
        }
    }
    out
}

pub fn filler(n: usize) -> String {
    "lorem ipsum dolor sit amet "
        .chars()
        .cycle()
        .take(n)
        .collect()
}

/// A request spec with placeholders filled, ready for the driver.
pub fn to_req(r: &ReqSpec, vars: &BTreeMap<String, String>) -> Result<Req, String> {
    let mut v = vars.clone();
    v.insert("PAD".into(), filler(r.pad));
    let method = Method::from_bytes(r.method.as_bytes()).map_err(|e| e.to_string())?;
    let mut headers = Vec::new();
    for (k, val) in &r.headers {
        let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| format!("header {k}: {e}"))?;
        let value =
            HeaderValue::from_str(&fill(val, &v)).map_err(|e| format!("header {k}: {e}"))?;
        headers.push((name, value));
    }
    Ok(Req {
        method,
        path: fill(&r.path, &v),
        headers,
        body: Bytes::from(fill(&r.body, &v)),
        expect_status: r.expect,
        expect_contains: r.contains.as_ref().map(|c| fill(c, &v).into_bytes()),
        weight: r.weight,
    })
}

/// The ingress-dialect bytes a complete streamed answer always carries.
fn stream_terminator(d: Dialect) -> &'static str {
    match d {
        Dialect::Openai => "[DONE]",
        Dialect::Anthropic => "message_stop",
        Dialect::Responses => "response.completed",
        Dialect::Gemini => "STOP",
        Dialect::Cohere => "message-end",
        Dialect::Bedrock => "messageStop",
    }
}

/// The matrix's cases.
pub fn expand_matrix(m: &LlmMatrix) -> Result<Vec<CaseSpec>, String> {
    let mut out = Vec::new();
    for ing in &m.ingress {
        let di = Dialect::parse(ing).ok_or(format!("llm_matrix: unknown dialect {ing}"))?;
        for eg in &m.egress {
            let de = Dialect::parse(eg).ok_or(format!("llm_matrix: unknown dialect {eg}"))?;
            for &stream in &m.stream {
                for &tools in &m.tools {
                    for &pad in &m.pad {
                        let model = format!("{}{}", m.model_prefix, eg);
                        let mut name = format!("{ing}>{eg}");
                        if stream {
                            name.push_str(" stream");
                        }
                        if tools {
                            name.push_str(" tools");
                        }
                        if pad > 0 {
                            name.push_str(&format!(" {}KiB", pad / 1024));
                        }
                        if m.proto == Proto::H2c {
                            name.push_str(" h2c");
                        }
                        name.push_str(&format!(" {}", m.shape.shape().describe()));
                        let mut headers: BTreeMap<String, String> =
                            di.auth_headers(&m.key).into_iter().collect();
                        headers.insert("content-type".into(), "application/json".into());
                        let text = if pad > 0 {
                            "{PAD}".to_string()
                        } else {
                            "hello".into()
                        };
                        let contains = if stream {
                            stream_terminator(di)
                        } else {
                            di.answer_marker(tools)
                        };
                        let request = ReqSpec {
                            listener: Listener::Data,
                            method: "POST".into(),
                            path: di.path(&model, stream),
                            headers,
                            body: di.request_body(&model, &text, stream, tools),
                            pad,
                            expect: 200,
                            contains: Some(contains.into()),
                            weight: 1,
                        };
                        let mut direct_headers = BTreeMap::new();
                        direct_headers.insert("content-type".into(), "application/json".into());
                        let direct = ReqSpec {
                            listener: Listener::Mock,
                            method: "POST".into(),
                            path: de.path("mock", stream),
                            headers: direct_headers,
                            body: de.request_body("mock", &text, stream, tools),
                            pad,
                            expect: 200,
                            contains: None,
                            weight: 1,
                        };
                        out.push(CaseSpec {
                            name,
                            proto: m.proto,
                            shape: m.shape.clone(),
                            requests: vec![request],
                            direct: Some(direct),
                            background: None,
                        });
                    }
                }
            }
        }
    }
    let _ = MARKER;
    Ok(out)
}

/// `1.6` / `1.5.5` as a comparable triple.
pub fn parse_version(v: &str) -> (u32, u32, u32) {
    let mut it = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scenario_file_parses_and_every_suite_names_real_scenarios() {
        let dir = scenarios_dir();
        let names = all_names(&dir);
        assert!(!names.is_empty());
        for n in &names {
            let s = load(&dir, n).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(&s.name, n, "file name matches scenario name");
            assert!(
                !s.cases.is_empty() || !s.llm_matrix.is_empty(),
                "{n} has cases"
            );
            for m in &s.llm_matrix {
                expand_matrix(m).unwrap();
            }
            for c in &s.cases {
                for r in &c.requests {
                    to_req(r, &BTreeMap::new()).unwrap();
                }
            }
        }
        for (suite, list) in load_suites(&dir).unwrap() {
            for n in list {
                assert!(
                    names.contains(&n),
                    "suite {suite} names unknown scenario {n}"
                );
            }
        }
    }

    #[test]
    fn fill_replaces_only_known_tokens() {
        let mut v = BTreeMap::new();
        v.insert("KEY".to_string(), "k1".to_string());
        assert_eq!(fill("{ env: X } {KEY}", &v), "{ env: X } k1");
    }

    #[test]
    fn the_matrix_expands_every_pairing() {
        let m: LlmMatrix = serde_yaml::from_str(
            "ingress: [openai, gemini]\negress: [anthropic, bedrock]\nstream: [false, true]\n",
        )
        .unwrap();
        let cases = expand_matrix(&m).unwrap();
        assert_eq!(cases.len(), 8);
        assert!(cases.iter().any(|c| c.name == "gemini>bedrock stream c=32"));
    }
}
