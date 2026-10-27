// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BLACK-BOX SINKS: the shipped `busbar` binary, driven only from outside.
//!
//! [`node`] plants every canary a config can carry (env and file SecretRefs, `${VAR}` interpolation
//! into a plugin setting, a provider's URL userinfo, the admin token, an export URL's path token)
//! and serves: it mints a key, sends one request per provider carrying caller-credential canaries,
//! reads every admin view, waits for the request-log export, then stops the node. The sinks are the
//! node's whole log (stdout+stderr, so every tracing line and any panic message), every admin and
//! data-plane response, the exported request log, `--validate` over the same config, and what each
//! far end received.
//!
//! [`refusals`] runs `--validate` over configs built to be REFUSED with a canary inside, so the
//! refusal and diagnostic text is a sink.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;

use crate::canary::{Canary, Sink};
use crate::common;

/// A fresh scratch directory for one scenario.
pub fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-canary-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).expect("the scratch dir");
    d
}

/// A far end answering every request with a whole Anthropic message, recording each request it
/// received (head and body) for the sweep.
struct FarEnd {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

fn far_end() -> FarEnd {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a far end");
    let port = listener.local_addr().expect("its address").port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                if let Some((head, body)) = common::upstream::read_request(&mut conn) {
                    log.lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(format!("{head}{}", String::from_utf8_lossy(&body)));
                    common::upstream::respond(
                        &mut conn,
                        200,
                        &serde_json::json!({
                            "id": "msg_canary",
                            "type": "message",
                            "role": "assistant",
                            "model": "m",
                            "content": [{"type": "text", "text": "ok"}],
                            "stop_reason": "end_turn",
                            "stop_sequence": null,
                            "usage": {"input_tokens": 1, "output_tokens": 1}
                        }),
                    );
                }
            });
        }
    });
    FarEnd { port, seen }
}

/// One HTTP/1.1 exchange over a fresh connection: the whole raw response (head and body).
fn http(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> String {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return String::new();
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nconnection: close\r\n\
         content-length: {}\r\n",
        body.len()
    );
    if !body.is_empty() {
        req.push_str("content-type: application/json\r\n");
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    let _ = s.write_all(req.as_bytes());
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn wait_for(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

/// The canaries the served node is planted with, by name.
pub struct NodeCanaries {
    pub env_ref: Canary,
    pub file_ref: Canary,
    pub interp: Canary,
    pub userinfo: Canary,
    pub userinfo_dead: Canary,
    pub admin_token: Canary,
    pub url_path_token: Canary,
    pub caller_cookie: Canary,
    pub caller_header: Canary,
}

impl NodeCanaries {
    pub fn all(&self) -> Vec<Canary> {
        vec![
            self.env_ref.clone(),
            self.file_ref.clone(),
            self.interp.clone(),
            self.userinfo.clone(),
            self.userinfo_dead.clone(),
            self.admin_token.clone(),
            self.url_path_token.clone(),
            self.caller_cookie.clone(),
            self.caller_header.clone(),
        ]
    }
}

/// The URL userinfo user both userinfo canaries ride with.
pub const USERINFO_USER: &str = "canaryuser";

/// `user:pass` as an `authorization: Basic` value carries it.
pub fn basic_form(pass: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{USERINFO_USER}:{pass}"))
}

/// The admin views the sweep reads (GET, with the admin token).
const ADMIN_VIEWS: &[&str] = &[
    "/api/v1/admin/config",
    "/api/v1/admin/config/settings",
    "/api/v1/admin/config/versions",
    "/api/v1/admin/providers",
    "/api/v1/admin/models",
    "/api/v1/admin/pools",
    "/api/v1/admin/export",
    "/api/v1/admin/export/hook",
    "/api/v1/admin/export/hook/settings",
    "/api/v1/admin/export/reqlog",
    "/api/v1/admin/identity-providers",
    "/api/v1/admin/identity-providers/admin-tokens",
    "/api/v1/admin/identity-providers/admin-tokens/settings",
    "/api/v1/admin/auth",
    "/api/v1/admin/admin-auth",
    "/api/v1/admin/plugins?type=auth",
    "/api/v1/admin/plugins?type=secret",
    "/api/v1/admin/plugins?type=store",
    "/api/v1/admin/plugins?type=hooks",
    "/api/v1/admin/info",
    "/api/v1/admin/keys",
    "/api/v1/admin/usage",
    "/api/v1/admin/audit",
    "/api/v1/admin/trust",
    "/api/v1/admin/hooks",
    "/metrics",
    "/healthz",
];

/// The served node's config.yaml and providers.yaml, every canary planted.
fn write_node_config(
    dir: &Path,
    c: &NodeCanaries,
    far: &[(&str, u16)],
    data: u16,
    admin: u16,
) -> PathBuf {
    let port = |name: &str| far.iter().find(|(n, _)| *n == name).map_or(9, |(_, p)| *p);
    std::fs::write(
        dir.join("providers.yaml"),
        format!(
            "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:{}\"\n  api_key_env: MOCK_KEY\n\
             mockfile:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:{}\"\n  api_key_env: MOCK_KEY\n\
             mockuser:\n  protocol: anthropic\n  base_url: \"http://{USERINFO_USER}:{}@127.0.0.1:{}\"\n  api_key_env: MOCK_KEY\n\
             mockdead:\n  protocol: anthropic\n  base_url: \"http://{USERINFO_USER}:{}@127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
            port("mock"),
            port("mockfile"),
            c.userinfo.value,
            port("mockuser"),
            c.userinfo_dead.value,
        ),
    )
    .expect("providers.yaml");
    std::fs::write(dir.join("api-key.txt"), &c.file_ref.value).expect("the key file");
    let signing = common::credentials::generate_signing_key().1;
    std::fs::write(dir.join("signing.key"), signing).expect("the signing key");
    let reqlog = dir.join("reqlog.jsonl");
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data}"
admin_listen: "127.0.0.1:{admin}"
providers_file: "{providers}"
advanced:
  allow_destinations: ["127.0.0.1"]
store: {{module: memory}}
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: CANARY_ADMIN_TOKEN }}
auth:
  chain:
    - keys
  signing_key: {{ file: "{signing}" }}
  admin_auth:
    - admin-tokens
providers:
  mock:
    api_key: {{ env: CANARY_ENV_REF }}
  mockfile:
    api_key: {{ file: "{keyfile}" }}
  mockuser:
    api_key: {{ env: MOCK_KEY }}
  mockdead:
    api_key: {{ env: MOCK_KEY }}
models:
  m-env: {{ provider: mock }}
  m-file: {{ provider: mockfile }}
  m-user: {{ provider: mockuser }}
  m-dead: {{ provider: mockdead }}
export:
  reqlog:
    module: request-log-file
    settings: {{ path: "{reqlog}" }}
  hook:
    module: request-log-webhook
    settings:
      url: "https://hooks.canary.invalid/services/{path_token}"
      auth_header: {{ name: Authorization, value: "Bearer ${{CANARY_INTERP}}" }}
"#,
            providers = dir.join("providers.yaml").display(),
            signing = dir.join("signing.key").display(),
            keyfile = dir.join("api-key.txt").display(),
            reqlog = reqlog.display(),
            path_token = c.url_path_token.value,
        ),
    )
    .expect("config.yaml");
    reqlog
}

/// The node's environment: every env-planted canary.
fn env_of(cmd: &mut Command, dir: &Path, c: &NodeCanaries) {
    cmd.env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env_remove("BUSBAR_PROVIDERS")
        .env("MOCK_KEY", "not-a-canary")
        .env("CANARY_ENV_REF", &c.env_ref.value)
        .env("CANARY_INTERP", &c.interp.value)
        .env("CANARY_ADMIN_TOKEN", &c.admin_token.value)
        .env("RUST_BACKTRACE", "1")
        // The most a log can say: an operator debugging a node turns this on.
        .env("RUST_LOG", "trace");
}

fn stop(child: &mut Child) {
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();
    if !wait_for(Duration::from_secs(15), || {
        child.try_wait().ok().flatten().is_some()
    }) {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// SERVE a planted node and collect every sink a black box can see.
pub fn node(c: &NodeCanaries) -> (Vec<Sink>, Vec<String>) {
    let mut sinks = Vec::new();
    let mut notes = Vec::new();
    let dir = scratch("node");
    let ends = [
        ("mock", far_end()),
        ("mockfile", far_end()),
        ("mockuser", far_end()),
    ];
    let ports: Vec<(&str, u16)> = ends.iter().map(|(n, f)| (*n, f.port)).collect();
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    let reqlog = write_node_config(&dir, c, &ports, data, admin);

    // `--validate` over the same config: its whole output is a sink.
    let mut v = Command::new(common::boot::exe());
    v.arg("--validate");
    env_of(&mut v, &dir, c);
    let out = v.output().expect("run busbar --validate");
    let validate = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "the planted config validates (the sweep needs it to serve): {validate}"
    );
    sinks.push(Sink::text("validate:ok", "busbar --validate", validate));

    let log_path = dir.join("node.log");
    let log = std::fs::File::create(&log_path).expect("the node log");
    let mut cmd = Command::new(common::boot::exe());
    env_of(&mut cmd, &dir, c);
    cmd.stdout(log.try_clone().expect("the log twice"))
        .stderr(log);
    let mut child = cmd.spawn().expect("spawn busbar");
    let _dump = common::boot::DumpOnPanic(&log_path);
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let up = wait_for(Duration::from_secs(30), || {
        if child.try_wait().ok().flatten().is_some() {
            return true;
        }
        common::boot::log_shows_data_and_admin_listening(&read_log())
    });
    assert!(
        up && child.try_wait().ok().flatten().is_none(),
        "the planted node serves; log:\n{}",
        read_log()
    );

    let bearer = format!("Bearer {}", c.admin_token.value);
    let minted = http(
        admin,
        "POST",
        "/api/v1/admin/keys",
        &[("authorization", &bearer)],
        r#"{"name":"canary"}"#,
    );
    sinks.push(Sink::text(
        "admin:POST /api/v1/admin/keys",
        "mint",
        minted.clone(),
    ));
    let token = minted
        .split("\"token\":\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .map(str::to_string);
    if token.is_none() {
        notes.push("no key minted: the data-plane requests ran unauthenticated".into());
    }
    let key = format!("Bearer {}", token.unwrap_or_default());
    let cookie = format!("sid={}", c.caller_cookie.value);
    for model in ["m-env", "m-file", "m-user", "m-dead"] {
        let path = format!("/{model}/v1/messages");
        let answer = http(
            data,
            "POST",
            &path,
            &[
                ("authorization", &key),
                ("cookie", &cookie),
                ("x-custom-auth", &c.caller_header.value),
                ("anthropic-version", "2023-06-01"),
            ],
            &format!(
                r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
            ),
        );
        sinks.push(Sink::text(format!("data:POST {path}"), model, answer));
    }
    for view in ADMIN_VIEWS {
        let answer = http(admin, "GET", view, &[("authorization", &bearer)], "");
        sinks.push(Sink::text(format!("admin:GET {view}"), *view, answer));
    }
    // The request log is written behind the response: wait for it, bounded.
    wait_for(Duration::from_secs(5), || {
        std::fs::read_to_string(&reqlog).is_ok_and(|t| t.lines().count() >= 4)
    });
    match std::fs::read_to_string(&reqlog) {
        Ok(t) => sinks.push(Sink::text("export:request-log-file", "reqlog.jsonl", t)),
        Err(e) => notes.push(format!("the request-log export wrote nothing: {e}")),
    }
    // Give a failing webhook delivery its moment to log.
    std::thread::sleep(Duration::from_millis(500));
    stop(&mut child);
    sinks.push(Sink::text("log:node", "stdout+stderr", read_log()));
    for (name, end) in &ends {
        for (k, req) in end
            .seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .enumerate()
        {
            sinks.push(Sink::text(
                format!("far-end:{name}"),
                format!("request {k}"),
                req.clone(),
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    (sinks, notes)
}

/// `--validate` over `config` (with `env`): exit code and the whole output.
fn validate(dir: &Path, config: &str, env: &[(&str, &str)]) -> (i32, String) {
    std::fs::write(dir.join("config.yaml"), config).expect("config.yaml");
    let mut cmd = Command::new(common::boot::exe());
    cmd.arg("--validate")
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env_remove("BUSBAR_PROVIDERS")
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .env("MOCK_KEY", "not-a-canary");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run busbar --validate");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The canaries the refusal configs carry, by name.
pub struct RefusalCanaries {
    pub inline_api_key: Canary,
    pub webhook_header_shape: Canary,
    pub webhook_url_scheme: Canary,
    pub base_url_userinfo_bad: Canary,
    pub signing_key_file: Canary,
}

impl RefusalCanaries {
    pub fn all(&self) -> Vec<Canary> {
        vec![
            self.inline_api_key.clone(),
            self.webhook_header_shape.clone(),
            self.webhook_url_scheme.clone(),
            self.base_url_userinfo_bad.clone(),
            self.signing_key_file.clone(),
        ]
    }
}

/// One refusal case: its name, its config, and the environment it runs with.
type RefusalCase = (&'static str, String, Vec<(&'static str, String)>);

/// REFUSE configs built around a canary: each `--validate` refusal is a sink.
pub fn refusals(c: &RefusalCanaries) -> (Vec<Sink>, Vec<String>) {
    let dir = scratch("refusals");
    let mut sinks = Vec::new();
    let mut notes = Vec::new();
    let head = format!(
        "listen: \"127.0.0.1:0\"\nproviders_file: \"{}\"\nstore: {{module: memory}}\n",
        dir.join("providers.yaml").display()
    );
    let catalog = "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n";
    std::fs::write(dir.join("providers.yaml"), catalog).expect("providers.yaml");
    std::fs::write(dir.join("bad-signing.key"), &c.signing_key_file.value).expect("the key file");
    let model = "models:\n  m: { provider: mock }\n";
    let cases: Vec<RefusalCase> = vec![
        (
            // An inline literal where a reference is required (the deserializer's refusal).
            "inline-api-key",
            format!(
                "{head}providers:\n  mock:\n    api_key: \"{}\"\n{model}",
                c.inline_api_key.value
            ),
            vec![],
        ),
        (
            // A string where the auth header map is expected.
            "webhook-auth-header-shape",
            format!(
                "{head}providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n{model}export:\n  hook:\n    \
                 module: request-log-webhook\n    settings:\n      url: \"https://hooks.canary.invalid/x\"\n      \
                 auth_header: \"Bearer ${{CANARY_H2}}\"\n"
            ),
            vec![("CANARY_H2", c.webhook_header_shape.value.clone())],
        ),
        (
            // A refused (non-https) webhook URL carrying a token in its query.
            "webhook-url-scheme",
            format!(
                "{head}providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n{model}export:\n  hook:\n    \
                 module: request-log-webhook\n    settings:\n      url: \"http://hooks.canary.invalid/x?api_key={}\"\n",
                c.webhook_url_scheme.value
            ),
            vec![],
        ),
        (
            // A provider base_url with userinfo and a malformed port.
            "base-url-userinfo-bad-port",
            format!(
                "{head}providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n    base_url: \"http://{USERINFO_USER}:{}@127.0.0.1:notaport\"\n{model}",
                c.base_url_userinfo_bad.value
            ),
            vec![],
        ),
        (
            // A file SecretRef whose CONTENT is malformed: the signing key file holds the canary,
            // not 64 hex characters.
            "signing-key-file-content",
            format!(
                "{head}providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n{model}auth:\n  chain: [keys]\n  \
                 signing_key: {{ file: \"{}\" }}\n",
                dir.join("bad-signing.key").display()
            ),
            vec![],
        ),
    ];
    for (name, config, env) in cases {
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let (code, text) = validate(&dir, &config, &env);
        if code == 0 {
            notes.push(format!(
                "refusal case `{name}` was ACCEPTED by --validate (exit 0)"
            ));
        }
        sinks.push(Sink::text(
            format!("refusal:{name}"),
            format!("busbar --validate (exit {code})"),
            text,
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    (sinks, notes)
}
