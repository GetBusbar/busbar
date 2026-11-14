// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Running a scenario: docker services, mocks, boot, setup, then per case a c=1 latency probe
//! (through the gateway and straight to the mock), a warmed-up load window with RSS sampling and
//! CPU accounting, and a post-load RSS reading.

use crate::driver::{self, pct_us, Outcome, Plan, Proto, Shape};
use crate::gateway::{self, BootSpec, Gateway};
use crate::mock::{self, Mock};
use crate::procstat;
use crate::scenario::{self, CaseSpec, Listener, ReqSpec, Scenario, Step};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Phase lengths.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Windows {
    pub idle_s: f64,
    pub probe_s: f64,
    pub warmup_s: f64,
    pub measure_s: f64,
    pub post_s: f64,
}

impl Windows {
    pub fn short() -> Self {
        Self {
            idle_s: 1.0,
            probe_s: 0.7,
            warmup_s: 1.0,
            measure_s: 3.0,
            post_s: 1.0,
        }
    }
    pub fn long() -> Self {
        Self {
            idle_s: 10.0,
            probe_s: 5.0,
            warmup_s: 5.0,
            measure_s: 60.0,
            post_s: 30.0,
        }
    }
}

pub struct Env {
    pub bin: PathBuf,
    pub version: (u32, u32, u32),
    pub windows: Windows,
    pub plugins_dir: Option<PathBuf>,
    pub work_root: PathBuf,
    pub mock_threads: usize,
    pub rt: tokio::runtime::Runtime,
    pub keep_work: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Pcts {
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub p999: f64,
    pub max: f64,
}

impl Pcts {
    fn of(h: &hdrhistogram::Histogram<u64>) -> Self {
        Self {
            p50: pct_us(h, 0.50),
            p90: pct_us(h, 0.90),
            p99: pct_us(h, 0.99),
            p999: pct_us(h, 0.999),
            max: if h.is_empty() {
                0.0
            } else {
                h.max() as f64 / 1000.0
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Rss {
    pub idle_mib: f64,
    pub steady_mib: f64,
    pub peak_mib: f64,
    pub post_mib: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct BackgroundResult {
    pub rps: f64,
    pub ok: u64,
    pub latency_us: Pcts,
    pub errors: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CaseResult {
    pub scenario: String,
    pub group: String,
    pub case: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub shape: String,
    pub proto: String,
    pub rps: f64,
    pub ok: u64,
    /// Answered bodies checked against the case's `contains:` (every one), and those missing it.
    pub body_total: u64,
    pub body_miss: u64,
    pub errors: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_error: Option<String>,
    /// Under load, microseconds.
    pub latency_us: Pcts,
    /// Time to first body chunk under load (streams), microseconds.
    pub first_byte_us: Pcts,
    /// c=1 through the gateway.
    pub probe_gateway_us: Pcts,
    /// c=1 straight to the mock (the same upstream request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_direct_us: Option<Pcts>,
    /// Gateway minus upstream at c=1: p50, p99.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added_p50_us: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added_p99_us: Option<f64>,
    /// Gateway process CPU time over the load window / requests served in it.
    pub cpu_us_per_req: f64,
    /// The hammer's own CPU (driver + mocks) per request over the same window.
    pub hammer_cpu_us_per_req: f64,
    pub rss: Rss,
    /// (mean rps of the last third of the windows - first third) / first third, percent.
    pub drift_pct: f64,
    pub windows_rps: Vec<u64>,
    pub boot_ms: f64,
    pub threads: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<BackgroundResult>,
    pub mock_hits: Value,
}

fn mib(b: u64) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

fn skipped(s: &Scenario, why: String) -> CaseResult {
    CaseResult {
        scenario: s.name.clone(),
        group: s.group.clone(),
        case: "-".into(),
        status: "skipped".into(),
        note: Some(why),
        ..Default::default()
    }
}

fn failed(s: &Scenario, case: &str, why: String) -> CaseResult {
    CaseResult {
        scenario: s.name.clone(),
        group: s.group.clone(),
        case: case.into(),
        status: "failed".into(),
        note: Some(why),
        ..Default::default()
    }
}

/// Running docker containers, removed on drop.
struct Containers(Vec<String>);

impl Drop for Containers {
    fn drop(&mut self) {
        for id in &self.0 {
            let _ = Command::new("docker").args(["rm", "-f", id]).output();
        }
    }
}

fn start_docker(s: &Scenario, vars: &mut BTreeMap<String, String>) -> Result<Containers, String> {
    let mut started = Containers(Vec::new());
    for svc in &s.docker {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "-d", "--rm", "-p"]);
        cmd.arg(format!("127.0.0.1::{}", svc.port));
        for (k, v) in &svc.env {
            cmd.args(["-e", &format!("{k}={v}")]);
        }
        cmd.arg(&svc.image);
        cmd.args(&svc.args);
        let out = cmd.output().map_err(|e| format!("docker: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "docker run {}: {}",
                svc.image,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
        started.0.push(id.clone());
        let port_out = Command::new("docker")
            .args(["port", &id, &svc.port.to_string()])
            .output()
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&port_out.stdout);
        let port = text
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse::<u16>().ok())
            .ok_or(format!("docker port {}: {text}", svc.image))?;
        vars.insert(svc.var.clone(), port.to_string());
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let ready = match &svc.ready_log {
                Some(needle) => {
                    let logs = Command::new("docker").args(["logs", &id]).output();
                    logs.map(|o| {
                        let all = format!(
                            "{}{}",
                            String::from_utf8_lossy(&o.stdout),
                            String::from_utf8_lossy(&o.stderr)
                        );
                        all.matches(needle.as_str()).count() >= svc.ready_count
                    })
                    .unwrap_or(false)
                }
                None => std::net::TcpStream::connect(("127.0.0.1", port)).is_ok(),
            };
            if ready {
                break;
            }
            if Instant::now() > deadline {
                return Err(format!("{} not ready after 90 s", svc.image));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    Ok(started)
}

fn stage_plugins(s: &Scenario, env: &Env, work: &Path) -> Result<(), String> {
    if s.plugins.is_empty() {
        return Ok(());
    }
    let dir = env.plugins_dir.as_ref().ok_or_else(|| {
        format!(
            "needs dynamic plugins {:?}: pass --plugins-dir with their tarballs",
            s.plugins
        )
    })?;
    let dest = work.join("plugins");
    std::fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
    let entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .collect();
    for want in &s.plugins {
        let hit = entries.iter().find(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with(want.as_str()) && n.ends_with(".tar.gz")
        });
        let hit = hit.ok_or(format!("plugin {want}*.tar.gz not in {}", dir.display()))?;
        std::fs::copy(hit.path(), dest.join(hit.file_name())).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn admin_token() -> String {
    let mut b = [0u8; 16];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    format!("hammer-admin-{}", hex(&b))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The audience-bound bearer: the minted key's `sub`, `exp`, `kid` (and `g`) plus `a: <aud>`,
/// signed with the node's ed25519 key (the oracle's `audience_token`).
fn audience_token(signing_key_hex: &str, plain: &str, aud: &str) -> Result<String, String> {
    use base64::Engine as _;
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let seed: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&signing_key_hex[2 * i..2 * i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let rest = plain
        .strip_prefix("bbk_")
        .ok_or("the minted key is not a bbk_ key")?;
    let claims: Value = serde_json::from_slice(
        &e.decode(rest.split('.').next().unwrap_or("").trim_end_matches('='))
            .map_err(|x| x.to_string())?,
    )
    .map_err(|x| x.to_string())?;
    let mut out = serde_json::Map::new();
    for k in ["sub", "exp", "kid"] {
        out.insert(
            k.into(),
            claims
                .get(k)
                .cloned()
                .ok_or(format!("the minted key carries no `{k}`"))?,
        );
    }
    out.insert("a".into(), Value::String(aud.into()));
    if let Some(g) = claims.get("g") {
        out.insert("g".into(), g.clone());
    }
    let body = serde_json::to_vec(&Value::Object(out)).map_err(|x| x.to_string())?;
    let kp =
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|x| x.to_string())?;
    Ok(format!(
        "bbk_{}.{}",
        e.encode(&body),
        e.encode(kp.sign(&body).as_ref())
    ))
}

fn service_account(token_uri: &str) -> Result<String, String> {
    let out = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        .output()
        .map_err(|e| format!("openssl: {e}"))?;
    if !out.status.success() {
        return Err("openssl genpkey failed".into());
    }
    let pem = String::from_utf8_lossy(&out.stdout).into_owned();
    Ok(
        serde_json::json!({"type": "service_account", "project_id": "hammer",
        "private_key_id": "hammer", "private_key": pem,
        "client_email": "hammer@hammer.iam.gserviceaccount.com", "token_uri": token_uri})
        .to_string(),
    )
}

fn addr_of(l: Listener, gw: (SocketAddr, SocketAddr), mock: SocketAddr) -> SocketAddr {
    match l {
        Listener::Data => gw.0,
        Listener::Admin => gw.1,
        Listener::Mock => mock,
    }
}

fn run_steps(
    steps: &[Step],
    vars: &mut BTreeMap<String, String>,
    gw: (SocketAddr, SocketAddr),
    mock: SocketAddr,
    signing: &str,
) -> Result<(), String> {
    for step in steps {
        match step {
            Step::SleepMs(ms) => std::thread::sleep(Duration::from_millis(*ms)),
            Step::MintKey { save_as, group } => {
                let body = format!("{{\"name\":\"hammer-{save_as}\",\"group\":\"{group}\"}}");
                let r = gateway::call(
                    gw.1,
                    "POST",
                    "/api/v1/admin/keys",
                    &[
                        (
                            "authorization".into(),
                            format!("Bearer {}", vars["ADMIN_TOKEN"]),
                        ),
                        ("content-type".into(), "application/json".into()),
                    ],
                    body.as_bytes(),
                )?;
                if r.status != 200 && r.status != 201 {
                    return Err(format!("mint_key: {} {}", r.status, r.text()));
                }
                let v: Value = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
                let token = v
                    .get("token")
                    .and_then(Value::as_str)
                    .ok_or(format!("mint_key: no token in {}", r.text()))?;
                vars.insert(save_as.clone(), token.into());
            }
            Step::AudienceToken { save_as, from, aud } => {
                let t = audience_token(
                    signing,
                    &scenario::fill(from, vars),
                    &scenario::fill(aud, vars),
                )?;
                vars.insert(save_as.clone(), t);
            }
            Step::RsaServiceAccount { save_as, token_uri } => {
                let sa = service_account(&scenario::fill(token_uri, vars))?;
                vars.insert(save_as.clone(), sa);
            }
            Step::Http {
                listener,
                method,
                path,
                headers,
                body,
                expect,
                save,
            } => {
                let mut h: Vec<(String, String)> = headers
                    .iter()
                    .map(|(k, v)| (k.clone(), scenario::fill(v, vars)))
                    .collect();
                if *listener == Listener::Admin
                    && !h
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                {
                    h.push((
                        "authorization".into(),
                        format!("Bearer {}", vars["ADMIN_TOKEN"]),
                    ));
                }
                if !body.is_empty()
                    && !h
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                {
                    h.push(("content-type".into(), "application/json".into()));
                }
                let p = scenario::fill(path, vars);
                let r = gateway::call(
                    addr_of(*listener, gw, mock),
                    method,
                    &p,
                    &h,
                    scenario::fill(body, vars).as_bytes(),
                )?;
                if r.status != *expect {
                    return Err(format!(
                        "{method} {p}: {} (want {expect}) {}",
                        r.status,
                        r.text()
                    ));
                }
                if !save.is_empty() {
                    let v: Value = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
                    for (var, field) in save {
                        let got = v
                            .get(field)
                            .map(|x| x.as_str().map_or(x.to_string(), str::to_string))
                            .ok_or(format!("{p}: no `{field}` in {}", r.text()))?;
                        vars.insert(var.clone(), got);
                    }
                }
            }
        }
    }
    Ok(())
}

fn reqs(
    specs: &[ReqSpec],
    vars: &BTreeMap<String, String>,
) -> Result<(Listener, Vec<driver::Req>), String> {
    let l = specs.first().map_or(Listener::Data, |r| r.listener);
    let mut out = Vec::new();
    for r in specs {
        if r.listener != l {
            return Err("one case's requests must share a listener".into());
        }
        let mut req = scenario::to_req(r, vars)?;
        if l == Listener::Admin
            && !req
                .headers
                .iter()
                .any(|(k, _)| k == http::header::AUTHORIZATION)
        {
            req.headers.push((
                http::header::AUTHORIZATION,
                http::HeaderValue::from_str(&format!("Bearer {}", vars["ADMIN_TOKEN"]))
                    .map_err(|e| e.to_string())?,
            ));
        }
        out.push(req);
    }
    Ok((l, out))
}

fn plan(
    addr: SocketAddr,
    proto: Proto,
    reqs: Vec<driver::Req>,
    shape: Shape,
    warmup: f64,
    measure: f64,
) -> Plan {
    Plan {
        addr,
        proto,
        reqs,
        shape,
        start: Instant::now() + Duration::from_millis(50),
        warmup: Duration::from_secs_f64(warmup),
        measure: Duration::from_secs_f64(measure),
        timeout: Duration::from_secs(30),
        h2_streams: 64,
        sample_every: 97,
    }
}

fn drift(windows: &[u64]) -> f64 {
    if windows.len() < 3 {
        return 0.0;
    }
    let third = windows.len() / 3;
    let mean = |w: &[u64]| w.iter().sum::<u64>() as f64 / w.len().max(1) as f64;
    let first = mean(&windows[..third]);
    let last = mean(&windows[windows.len() - third..]);
    if first <= 0.0 {
        return 0.0;
    }
    (last - first) / first * 100.0
}

fn median(mut v: Vec<u64>) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[v.len() / 2]
}

/// Run one scenario; one result per case (or one skipped/failed row).
pub fn run_scenario(env: &Env, s: &Scenario, log: &mut dyn FnMut(&str)) -> Vec<CaseResult> {
    let v16 = env.version >= (1, 6, 0);
    let min = s
        .min_version
        .as_deref()
        .map_or((0, 0, 0), scenario::parse_version);
    if env.version < min {
        return vec![skipped(
            s,
            format!("needs busbar >= {}", s.min_version.as_deref().unwrap_or("")),
        )];
    }
    let (config_t, providers_t) = if v16 {
        (s.config.clone(), s.providers.clone().unwrap_or_default())
    } else {
        match &s.config_1_5 {
            Some(c) => (
                c.clone(),
                s.providers_1_5
                    .clone()
                    .or_else(|| s.providers.clone())
                    .unwrap_or_default(),
            ),
            None => {
                return vec![skipped(
                    s,
                    format!(
                        "no 1.5 config: busbar {}.{}.{} has no such plane/kind",
                        env.version.0, env.version.1, env.version.2
                    ),
                )]
            }
        }
    };
    let mut cases = s.cases.clone();
    for m in &s.llm_matrix {
        match scenario::expand_matrix(m) {
            Ok(c) => cases.extend(c),
            Err(e) => return vec![failed(s, "-", e)],
        }
    }

    let work = env.work_root.join(&s.name);
    let _ = std::fs::remove_dir_all(&work);
    if let Err(e) = std::fs::create_dir_all(&work) {
        return vec![failed(s, "-", e.to_string())];
    }
    if let Err(e) = stage_plugins(s, env, &work) {
        return vec![skipped(s, e)];
    }
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    let _containers = match start_docker(s, &mut vars) {
        Ok(c) => c,
        Err(e) => return vec![skipped(s, format!("docker: {e}"))],
    };
    let mock = match Mock::start(s.mock.clone(), env.mock_threads) {
        Ok(m) => m,
        Err(e) => return vec![failed(s, "-", format!("mock: {e}"))],
    };
    let listen: SocketAddr = ([127, 0, 0, 1], gateway::free_port()).into();
    let admin: SocketAddr = ([127, 0, 0, 1], gateway::free_port()).into();
    let signing = match gateway::signing_key(&env.bin) {
        Ok(k) => k,
        Err(e) => return vec![failed(s, "-", e)],
    };
    let _ = std::fs::write(work.join("signing.key"), &signing);
    let token = admin_token();
    vars.insert("LISTEN".into(), listen.to_string());
    vars.insert("ADMIN".into(), admin.to_string());
    vars.insert("MOCK".into(), mock.base());
    vars.insert("MOCK_ADDR".into(), mock.addr.to_string());
    vars.insert(
        "MOCK_TLS".into(),
        format!("https://127.0.0.1:{}", mock.tls_addr.port()),
    );
    vars.insert("MOCK_SPKI".into(), mock.spki_pin.clone());
    vars.insert(
        "MOCK_CA_PEM_JSON".into(),
        serde_json::to_string(&mock.cert_pem).unwrap_or_default(),
    );
    vars.insert("WORK".into(), work.display().to_string());
    vars.insert("CARD_ISSUER_KEY".into(), mock::card_issuer_key());
    vars.insert("MCP_SCHEMA_HASH".into(), mock::MCP_PING_SCHEMA_HASH.into());
    vars.insert("ADMIN_TOKEN".into(), token.clone());
    vars.insert("FREE_PORT_A".into(), gateway::free_port().to_string());
    vars.insert("FREE_PORT_B".into(), gateway::free_port().to_string());

    // Steps that must run before boot (a service account the config's env needs).
    let steps = match s.steps() {
        Ok(v) => v,
        Err(e) => return vec![failed(s, "-", e)],
    };
    let (pre, post): (Vec<Step>, Vec<Step>) = steps
        .into_iter()
        .partition(|st| matches!(st, Step::RsaServiceAccount { .. }));
    if let Err(e) = run_steps(&pre, &mut vars, (listen, admin), mock.addr, &signing) {
        return vec![failed(s, "-", format!("setup: {e}"))];
    }

    for (rel, content) in &s.files {
        let p = work.join(rel);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&p, scenario::fill(content, &vars)) {
            return vec![failed(s, "-", format!("files: {}: {e}", p.display()))];
        }
    }

    let mut genv: Vec<(String, String)> = vec![
        ("BUSBAR_ADMIN_TOKEN".into(), token.clone()),
        ("HAMMER_ADMIN_TOKEN".into(), token),
        ("HAMMER_SIGNING_KEY".into(), signing.clone()),
        ("HAMMER_UPSTREAM_KEY".into(), "hammer-upstream-key".into()),
        (
            "HAMMER_BEDROCK_KEY".into(),
            "AKIAHAMMERACCESSKEY:hammer-secret-access-key".into(),
        ),
        ("BUSBAR_STATE_FILE".into(), String::new()),
    ];
    for (k, v) in &s.env {
        genv.push((k.clone(), scenario::fill(v, &vars)));
    }
    let mut gw = match Gateway::boot(BootSpec {
        bin: &env.bin,
        work: work.clone(),
        config: scenario::fill(&config_t, &vars),
        providers: scenario::fill(&providers_t, &vars),
        env: genv,
        listen,
        admin,
    }) {
        Ok(g) => g,
        Err(e) => return vec![failed(s, "-", format!("boot: {e}"))],
    };
    log(&format!(
        "  booted pid {} in {:.0} ms",
        gw.pid,
        gw.boot.as_secs_f64() * 1000.0
    ));
    if let Err(e) = run_steps(&post, &mut vars, (listen, admin), mock.addr, &signing) {
        let tail = gw.log_tail(15);
        return vec![failed(s, "-", format!("setup: {e}\n{tail}"))];
    }

    std::thread::sleep(Duration::from_secs_f64(env.windows.idle_s));
    let idle = procstat::read(gw.pid).map_or(0, |r| r.rss);
    let origin = Instant::now();
    let sampler = procstat::Sampler::start(gw.pid, origin, Duration::from_millis(100));

    let mut results = Vec::new();
    for c in &cases {
        log(&format!("  case {}", c.name));
        let r = run_case(env, s, c, &vars, &mut gw, &mock, &sampler, origin, idle);
        let dead = r.status == "failed";
        results.push(r);
        if dead && !gw.alive() {
            break;
        }
    }
    drop(sampler);
    gw.stop();
    if !env.keep_work {
        let _ = std::fs::remove_dir_all(&work);
    }
    results
}

#[allow(clippy::too_many_arguments)]
fn run_case(
    env: &Env,
    s: &Scenario,
    c: &CaseSpec,
    vars: &BTreeMap<String, String>,
    gw: &mut Gateway,
    mock: &Mock,
    sampler: &procstat::Sampler,
    origin: Instant,
    idle_rss: u64,
) -> CaseResult {
    let w = env.windows;
    let gwa = (gw.listen, gw.admin);
    let (listener, main_reqs) = match reqs(&c.requests, vars) {
        Ok(x) => x,
        Err(e) => return failed(s, &c.name, e),
    };
    let target = addr_of(listener, gwa, mock.addr);
    let shape = c.shape.shape();
    let hits_before = mock.stats.snapshot();
    let case_from = origin.elapsed();

    // c=1 probes: through the gateway, then straight to the mock.
    let (probe, _) = env.rt.block_on(driver::run(plan(
        target,
        c.proto,
        main_reqs.clone(),
        Shape::Closed { concurrency: 1 },
        0.2,
        w.probe_s,
    )));
    let direct = match &c.direct {
        Some(d) => match reqs(std::slice::from_ref(d), vars) {
            Ok((_, dreq)) => Some(
                env.rt
                    .block_on(driver::run(plan(
                        mock.addr,
                        c.proto,
                        dreq,
                        Shape::Closed { concurrency: 1 },
                        0.2,
                        w.probe_s,
                    )))
                    .0,
            ),
            Err(e) => return failed(s, &c.name, e),
        },
        None => None,
    };

    // The load window, with an optional background load beside it.
    let main = plan(target, c.proto, main_reqs, shape, w.warmup_s, w.measure_s);
    let bg = match &c.background {
        Some(b) => match reqs(&b.requests, vars) {
            Ok((l, r)) => Some(plan(
                addr_of(l, gwa, mock.addr),
                Proto::H1,
                r,
                b.shape.shape(),
                w.warmup_s,
                w.measure_s,
            )),
            Err(e) => return failed(s, &c.name, e),
        },
        None => None,
    };
    let (m_start, m_end) = (main.measure_start(), main.end());
    let pid = gw.pid;
    let cpu = std::thread::spawn(move || {
        std::thread::sleep(m_start.saturating_duration_since(Instant::now()));
        let a = (procstat::read(pid), procstat::self_cpu_ns());
        std::thread::sleep(m_end.saturating_duration_since(Instant::now()));
        let b = (procstat::read(pid), procstat::self_cpu_ns());
        (a, b)
    });
    let ((out, first_error), bg_out) = env.rt.block_on(async move {
        let bgf = async move {
            match bg {
                Some(p) => Some(driver::run(p).await.0),
                None => None,
            }
        };
        tokio::join!(driver::run(main), bgf)
    });
    let ((ga, sa), (gb, sb)) = cpu.join().unwrap_or(((None, 0), (None, 0)));
    let load_from = m_start.saturating_duration_since(origin);
    let load_to = m_end.saturating_duration_since(origin);
    let mid = load_from + (load_to - load_from) / 2;
    let steady = median(sampler.between(mid, load_to));
    let peak = sampler
        .between(case_from, load_to + Duration::from_millis(200))
        .into_iter()
        .max()
        .unwrap_or(0);
    std::thread::sleep(Duration::from_secs_f64(w.post_s));
    let post_r = procstat::read(gw.pid);
    let alive = gw.alive();

    let served = out.ok.max(1) as f64;
    let cpu_us = match (ga, gb) {
        (Some(a), Some(b)) => (b.cpu_ns.saturating_sub(a.cpu_ns)) as f64 / 1000.0 / served,
        _ => 0.0,
    };
    // Only when both c=1 probes completed requests inside their windows.
    let added = direct
        .as_ref()
        .filter(|d| !d.latency.is_empty() && !probe.latency.is_empty())
        .map(|d| {
            (
                pct_us(&probe.latency, 0.5) - pct_us(&d.latency, 0.5),
                pct_us(&probe.latency, 0.99) - pct_us(&d.latency, 0.99),
            )
        });
    let mut hits = serde_json::Map::new();
    if let (Value::Object(after), Value::Object(before)) = (mock.stats.snapshot(), hits_before) {
        for (k, v) in after {
            if v.is_string() {
                hits.insert(k, v);
                continue;
            }
            let d = v.as_u64().unwrap_or(0) - before.get(&k).and_then(Value::as_u64).unwrap_or(0);
            if d > 0 {
                hits.insert(k, d.into());
            }
        }
    }
    let status = case_status(alive, out.ok, out.body_miss);
    let note = if !alive {
        Some(format!("gateway died:\n{}", gw.log_tail(15)))
    } else if out.ok == 0 {
        Some("no request succeeded".to_string())
    } else if out.body_miss > 0 {
        Some(format!(
            "body_miss {}: answers without the expected `contains:` marker",
            body_miss_text(out.body_miss, out.body_total)
        ))
    } else {
        None
    };
    CaseResult {
        scenario: s.name.clone(),
        group: s.group.clone(),
        case: c.name.clone(),
        status: status.into(),
        note,
        shape: shape.describe(),
        proto: format!("{:?}", c.proto).to_lowercase(),
        rps: out.rps(),
        ok: out.ok,
        body_total: out.body_total,
        body_miss: out.body_miss,
        errors: merged_errors(&out, &probe),
        first_error,
        latency_us: Pcts::of(&out.latency),
        first_byte_us: Pcts::of(&out.first_byte),
        probe_gateway_us: Pcts::of(&probe.latency),
        probe_direct_us: direct.as_ref().map(|d| Pcts::of(&d.latency)),
        added_p50_us: added.map(|a| a.0),
        added_p99_us: added.map(|a| a.1),
        cpu_us_per_req: cpu_us,
        hammer_cpu_us_per_req: sb.saturating_sub(sa) as f64 / 1000.0 / served,
        rss: Rss {
            idle_mib: mib(idle_rss),
            steady_mib: mib(steady),
            peak_mib: mib(peak),
            post_mib: mib(post_r.map_or(0, |r| r.rss)),
        },
        drift_pct: drift(&out.windows),
        windows_rps: out.windows.clone(),
        boot_ms: gw.boot.as_secs_f64() * 1000.0,
        threads: post_r.map_or(0, |r| r.threads),
        background: bg_out.map(|b| BackgroundResult {
            rps: b.rps(),
            ok: b.ok,
            latency_us: Pcts::of(&b.latency),
            errors: b.errors.clone(),
        }),
        mock_hits: Value::Object(hits),
    }
}

/// A case is FAILED when the gateway died, nothing succeeded, or any checked body missed its
/// `contains:` marker.
fn case_status(alive: bool, ok: u64, body_miss: u64) -> &'static str {
    if !alive || ok == 0 || body_miss > 0 {
        "failed"
    } else {
        "ok"
    }
}

/// `n/total`: checked bodies that missed their `contains:` marker, of all checked.
pub fn body_miss_text(miss: u64, total: u64) -> String {
    format!("{miss}/{total}")
}

fn merged_errors(load: &Outcome, probe: &Outcome) -> BTreeMap<String, u64> {
    let mut m = load.errors.clone();
    for (k, v) in &probe.errors {
        *m.entry(format!("probe {k}")).or_insert(0) += v;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SELFTEST (design mcp-issuer §3.4, §4): a case with `contains:` checks EVERY body, not one
    /// in 97, and fails on any miss. A local far end answers one body in a hundred without the
    /// marker; every answered body is checked, the misses are counted as `body_miss n/total`, and
    /// the case is FAILED.
    #[test]
    fn a_contains_case_where_one_body_in_a_hundred_misses_is_failed() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            let served = Arc::new(AtomicU64::new(0));
            tokio::spawn(async move {
                while let Ok((s, _)) = l.accept().await {
                    let served = Arc::clone(&served);
                    tokio::spawn(async move {
                        let svc = hyper::service::service_fn(move |_req| {
                            let n = served.fetch_add(1, Ordering::Relaxed);
                            let body: &'static [u8] = if n % 100 == 99 {
                                b"nothing to see"
                            } else {
                                b"ok marker"
                            };
                            async move {
                                Ok::<_, std::convert::Infallible>(http::Response::new(
                                    http_body_util::Full::new(bytes::Bytes::from_static(body)),
                                ))
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(s), svc)
                            .await;
                    });
                }
            });
            let req = driver::Req {
                method: http::Method::GET,
                path: "/".into(),
                headers: Vec::new(),
                body: bytes::Bytes::new(),
                expect_status: 200,
                expect_contains: Some(b"marker".to_vec()),
                weight: 1,
            };
            let p = plan(
                addr,
                Proto::H1,
                vec![req],
                Shape::Closed { concurrency: 4 },
                0.0,
                1.0,
            );
            let (out, _) = driver::run(p).await;
            assert!(out.ok >= 200, "enough answers to hold misses: {}", out.ok);
            assert!(out.body_miss >= 1, "the misses are seen: {out:?}");
            assert_eq!(
                out.body_total,
                out.ok + out.body_miss,
                "every answered body is checked"
            );
            assert_eq!(case_status(true, out.ok, out.body_miss), "failed");
            assert_eq!(case_status(true, out.ok, 0), "ok");
            assert_eq!(
                body_miss_text(out.body_miss, out.body_total),
                format!("{}/{}", out.body_miss, out.body_total)
            );
        });
    }

    #[test]
    fn drift_compares_the_last_third_to_the_first() {
        assert_eq!(drift(&[100, 100, 100, 50, 50, 50]), -50.0);
        assert_eq!(drift(&[10, 10]), 0.0);
    }

    #[test]
    fn an_audience_token_is_resigned_over_the_key_claims() {
        use base64::Engine as _;
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let claims = e.encode(br#"{"sub":"k1","exp":9,"kid":"x","g":"grp"}"#);
        let t = audience_token(
            &"11".repeat(32),
            &format!("bbk_{claims}.sig"),
            "http://a/mcp",
        )
        .unwrap();
        let body = e
            .decode(t.trim_start_matches("bbk_").split('.').next().unwrap())
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["a"], "http://a/mcp");
        assert_eq!(v["g"], "grp");
    }
}
