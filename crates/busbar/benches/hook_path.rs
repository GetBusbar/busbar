// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK-PATH BENCH — cells **C1** and **C2** of the added-latency instrument.
//!
//! # Why this file exists
//!
//! Moving the hook's view of a request off the raw ingress body and onto the IR costs something on
//! exactly one deployment shape: same-protocol in and out, a content-granted hook, no rewrite. That
//! cost has been accepted on the record. **Accepted is not unmeasured** — this project's standing
//! rule is that a number comes from an instrument, not from an assertion, and the sub-100µs
//! added-latency claim is load-bearing on the site.
//!
//! **There was no microbenchmark harness in this repository at all**: no `criterion` in any
//! `Cargo.toml`, no `benches/` directory, no `[[bench]]` target. Building the instrument was
//! therefore a unit of work rather than a footnote, and this file is it.
//!
//! # The two cells, as defined
//!
//! | cell | config | what it means |
//! |---|---|---|
//! | **C1** | same-protocol (openai→openai), **NO hook configured** | **the regression gate.** A deployment that runs no content hook must pay EXACTLY NOTHING. If C1 moves, the boot-time fast path is not gating and the design is not built as specified — stop and fix the seam. |
//! | **C2** | same-protocol, ONE `prompt: ro` tap that returns immediately | **the accepted cost.** This is the number that gets published. |
//!
//! C1 is the one with teeth, and it has teeth in a specific, planned way: the unit that lands the
//! `any_content_hook` boot gate proves the gate is load-bearing by **first landing it INVERTED**
//! (always build the IR), watching C1 REGRESS here, and only then correcting it. A gate that has
//! never been watched to cost something has not been shown to be doing anything. This harness is
//! what that unit reads.
//!
//! # What is measured, and what deliberately is not
//!
//! This is a **black-box** instrument: it boots the REAL shipped binary against a local stub
//! upstream and times a real HTTP round trip through the whole request path — ingress, auth,
//! governance, the hook seam, selection, dispatch, response. The stub upstream answers instantly
//! from memory, so what varies between C1 and C2 is busbar's own work.
//!
//! It is black-box for a structural reason and not a stylistic one: `busbar` is a **binary-only**
//! package (`[[bin]]`, no `[lib]`), so its internals are `pub(crate)` and unreachable from a bench
//! target, which is a separate crate. A microbenchmark that called `build_prompt_projection` and
//! `read_request` directly — the instrument that would make a C2 regression *attributable* rather
//! than merely visible — therefore cannot be written without first giving the crate a library
//! target. **That is a real production-structure change and it is out of scope for a unit whose
//! whole contract is "no production change at all".** It is recorded here as the known gap rather
//! than quietly skipped: when the attributable number is needed, the library target is the
//! prerequisite, and it should land as its own change with its own reasoning.
//!
//! # Running it
//!
//! ```text
//! cargo build --workspace --all-targets          # C2 needs the hook cdylib built
//! cargo bench -p busbar --bench hook_path
//! ```
//!
//! The regression workflow — which is the whole point of C1 — is criterion's own baselines:
//!
//! ```text
//! cargo bench -p busbar --bench hook_path -- --save-baseline before
//! # …land the change (for the gate proof: land it INVERTED)…
//! cargo bench -p busbar --bench hook_path -- --baseline before
//! ```
//!
//! # The baseline, measured
//!
//! First reading on this harness (macOS arm64, debug-free `bench` profile, loopback stub upstream,
//! four cells in one process, 60 samples over 20s each):
//!
//! ```text
//! C1_same_protocol_no_hook                  [ 87.3 µs   93.5 µs  100.2 µs]
//! C2_same_protocol_prompt_ro_tap            [ 81.6 µs   83.2 µs   85.2 µs]
//! C1_same_protocol_no_hook_200turns         [323.3 µs  339.4 µs  355.7 µs]
//! C2_same_protocol_prompt_ro_tap_200turns   [306.0 µs  336.4 µs  370.7 µs]
//! ```
//!
//! **Read that honestly: at a `prompt: ro` TAP, C2's cost is below this instrument's noise floor at
//! both body sizes** — C2 came out marginally *under* C1 on the short body, which is noise and not a
//! speed-up. That is a real result and not a broken cell: a tap does not block dispatch, so what
//! lands on the critical path is the projection alone, and today's projection borrows (`Cow`) for
//! bare-string content. It also sets the expectation for the cutover: an IR build that ALLOCATES a
//! `String` per block is exactly the change this pair would show, most visibly in the 200-turn
//! cells, where the per-turn term dominates the round trip's ~80µs fixed floor.
//!
//! **Numbers are comparable within one run and much less so across runs** (an isolated C2 measured
//! 153µs on the same tree minutes earlier, on a differently-loaded machine). Always read a delta
//! from a saved baseline in the same session; never quote one of these figures against a number
//! taken on another day.
//!
//! C2 needs a `kind: hook` plugin to attach, and uses the hermetic `busbar-hook-test-plugin`
//! cdylib — packed here into an UNSIGNED tarball and loaded under `plugins.trust.allow_unsigned`,
//! the same path the in-crate hook tests use (a bench cannot sign with the embedded first-party
//! release key). If that cdylib has not been built, C2 **refuses to run rather than reporting a
//! number for a deployment with no hook in it** — a bench that silently measures the wrong cell is
//! worse than one that stops.

use busbar_plugin_sign::{HookNeeds, Manifest, NeedLevel};
use criterion::{criterion_group, criterion_main, Criterion};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────────────────────
// FIXTURE PLUMBING
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A free loopback port, asked of the OS. A hard-coded port is a red that is not a defect the first
/// time this machine happens to have something on it.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-bench-hook-path-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn read_log(p: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(p) {
        let _ = f.read_to_string(&mut s);
    }
    s
}

/// The canned upstream answer. Small on purpose: the cell measures BUSBAR's added latency, so the
/// upstream's own body-size cost is held constant and kept negligible.
const UPSTREAM_REPLY: &str = r#"{"id":"chatcmpl-bench","object":"chat.completion","created":1,"model":"stub-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}"#;

/// A stub OpenAI-protocol upstream, answering from memory on its own runtime thread. Never returns
/// (the process exit tears it down), which is what a bench fixture wants: one upstream for the whole
/// run, so no cell pays another cell's startup.
fn spawn_stub_upstream() -> u16 {
    let port = free_port();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let app = axum::Router::new().fallback(axum::routing::any(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    UPSTREAM_REPLY,
                )
            }));
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    port
}

/// The hermetic hook cdylib, found the same way the in-crate hook tests find it: newest of the
/// uplifted copy and the raw `deps/` compiler output, because a scoped `cargo build` only produces
/// the latter.
fn hook_cdylib() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?;
    let name = busbar_plugin_loader::plugin_library_filename("busbar_hook_test_plugin");
    [
        profile_dir.join(&name),
        profile_dir.join("deps").join(&name),
    ]
    .into_iter()
    .filter_map(|p| {
        std::fs::metadata(&p)
            .and_then(|m| m.modified())
            .ok()
            .map(|t| (p, t))
    })
    .max_by_key(|(_, t)| *t)
    .map(|(p, _)| p)
}

/// Pack the hook cdylib into an UNSIGNED tarball in `dir`, declaring `prompt: ro` — the grant the
/// C2 cell is about. Unsigned + `allow_unsigned` is the only path available outside release CI, and
/// it still runs the full scan/trust/load pipeline.
fn install_prompt_ro_hook(dir: &Path) {
    let cdylib = hook_cdylib().expect(
        "the hook-test-plugin cdylib is not built, so the C2 cell would silently measure a \
         deployment with NO hook in it. Run `cargo build --workspace --all-targets` first.",
    );
    let lib = std::fs::read(&cdylib).expect("read hook cdylib");
    let mut m = Manifest {
        name: "busbar-bench-hook".into(),
        alias: "bench-hook".into(),
        kind: "hook".into(),
        version: "1.6.0".into(),
        publisher: "busbar-bench".into(),
        abi_version: *busbar_plugin_loader::supported_abi("hook")
            .iter()
            .max()
            .unwrap(),
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: HookNeeds {
            prompt: NeedLevel::Ro,
            user: NeedLevel::No,
        },
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    m.sha256 = busbar_plugin_sign::sha256_hex(&lib);
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", &lib).unwrap();
    std::fs::write(dir.join("bench-hook.tar.gz"), tarball).unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE DEPLOYMENT UNDER TEST
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A booted busbar process plus everything needed to drive and tear it down. `Drop` kills the child,
/// so a panicking bench never leaves a listener behind.
struct Deployment {
    child: Child,
    url: String,
    log: PathBuf,
    _dir: PathBuf,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Boot the REAL binary on a same-protocol openai→openai deployment pointed at the stub upstream.
///
/// `hooks` is spliced in verbatim: empty for C1, a `prompt: ro` tap for C2. Everything else — the
/// listen addresses, the provider, the model, the pool — is identical between the two cells, so the
/// difference between their numbers is the hook seam and nothing else.
fn boot(tag: &str, upstream_port: u16, with_hook: bool) -> Deployment {
    let dir = fixture_dir(tag);
    let data_port = free_port();
    let admin_port = free_port();

    std::fs::write(
        dir.join("providers.yaml"),
        format!(
            "stub:\n  protocol: openai\n  base_url: \"http://127.0.0.1:{upstream_port}\"\n  api_key_env: STUB_KEY\n"
        ),
    )
    .unwrap();

    let (plugins_block, hooks_block) = if with_hook {
        let plugins_dir = dir.join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();
        install_prompt_ro_hook(&plugins_dir);
        (
            format!(
                "plugins:\n  enabled: true\n  dir: \"{}\"\n  trust:\n    allow_unsigned: true\n",
                plugins_dir.display()
            ),
            // A TAP, `prompt: ro`, at the request stage: the content projection is built and handed
            // over, and the hook itself returns immediately. That isolates the projection's cost
            // from any policy work a gate would do.
            "hooks:\n  bench-tap:\n    module: bench-hook\n    kind: tap\n    phase: [request]\n    prompt: ro\n"
                .to_string(),
        )
    } else {
        (String::new(), String::new())
    };

    // The RESERVED all-pools attach key, not the pool's own `hooks:` list: a pool's list carries
    // gates (fire-and-wait, they influence routing) and REFUSES a tap at config validation. A tap
    // attaches once, for every pool, here.
    let pool_hooks = if with_hook {
        "  hooks: [bench-tap]\n"
    } else {
        ""
    };

    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
admin_require_mtls: false
auth:
  chain: []
{plugins_block}providers:
  stub:
    api_key: {{ env: STUB_KEY }}
models:
  bench-model:
    provider: stub
{hooks_block}pools:
{pool_hooks}  bench:
    members:
      - model: bench-model
"#
        ),
    )
    .unwrap();

    let log = dir.join("out.log");
    let out = std::fs::File::create(&log).unwrap();
    let err = out.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("STUB_KEY", "x")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn busbar");

    let mut d = Deployment {
        child,
        url: format!("http://127.0.0.1:{data_port}/v1/chat/completions"),
        log,
        _dir: dir,
    };

    // Wait for the listener itself rather than for a log line: `RUST_LOG=warn` keeps the boot
    // banner quiet, and a bench that mistakes "not yet listening" for "slow" reports a fiction.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = d.child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?}); log:\n{}",
                read_log(&d.log)
            );
        }
        if std::net::TcpStream::connect(
            d.url
                .trim_start_matches("http://")
                .trim_end_matches("/v1/chat/completions"),
        )
        .is_ok()
        {
            return d;
        }
        assert!(
            Instant::now() < deadline,
            "busbar did not listen within 60s; log:\n{}",
            read_log(&d.log)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The request body a cell sends: a same-protocol OpenAI chat completion with real prompt text, so a
/// `prompt: ro` grant has something to project, at `turns` conversation turns.
///
/// **Body size is a parameter and not a constant on purpose.** The projection's cost is per-turn,
/// while the fixed cost of a loopback HTTP round trip is not, so a four-turn body is the honest
/// shape of a typical request and a long history is where a per-turn regression becomes
/// unmistakable rather than marginal. A regression gate that can only see a change larger than its
/// own noise floor is a gate that passes the change it was built to catch.
fn request_body(turns: usize) -> serde_json::Value {
    let mut messages = vec![serde_json::json!(
        {"role": "system", "content": "You are a careful assistant."}
    )];
    for i in 0..turns {
        let role = if i % 2 == 0 { "user" } else { "assistant" };
        messages.push(serde_json::json!({
            "role": role,
            "content": format!(
                "Turn {i}: the pump tripped at 04:12 and the standby did not start; \
                 summarise the incident report and list the follow-up actions."
            )
        }));
    }
    serde_json::json!({
        "model": "bench",
        "messages": messages,
        "max_tokens": 64
    })
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE CELLS
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// One measured cell: boot the deployment, then time one full request/response per iteration.
///
/// The FIRST request after boot is discarded — it pays lane construction, the upstream connection
/// handshake and pool warm-up, none of which is what either cell is about.
fn run_cell(c: &mut Criterion, name: &str, upstream_port: u16, with_hook: bool, turns: usize) {
    let dep = boot(name, upstream_port, with_hook);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(4)
        .build()
        .unwrap();
    let body = request_body(turns);

    let warm = rt.block_on(async {
        client
            .post(&dep.url)
            .json(&body)
            .send()
            .await
            .expect("first request")
    });
    assert!(
        warm.status().is_success(),
        "cell '{name}' did not serve a 2xx (got {}), so its number would be the cost of an ERROR \
         path, not of the request path; log:\n{}",
        warm.status(),
        read_log(&dep.log)
    );

    c.bench_function(name, |b| {
        b.iter(|| {
            let resp = rt
                .block_on(async { client.post(&dep.url).json(&body).send().await })
                .expect("request");
            assert!(resp.status().is_success());
            std::hint::black_box(resp);
        })
    });
}

/// Turns in the SHORT body — a typical request.
const SHORT: usize = 4;
/// Turns in the LONG body — a replayed agent history, where a per-turn cost is visible above the
/// round trip's fixed floor.
const LONG: usize = 200;

/// **C1 — same-protocol, NO hook.** The regression gate: this number must not move when the hook
/// path changes. It is the cell the inverted-gate proof reads.
fn c1_same_protocol_no_hook(c: &mut Criterion) {
    let upstream = spawn_stub_upstream();
    run_cell(c, "C1_same_protocol_no_hook", upstream, false, SHORT);
}

/// **C1-long — the same cell on a 200-turn history.** Same claim, better resolution: if a change
/// makes an unhooked deployment do per-turn work, this is where it shows first.
fn c1_same_protocol_no_hook_long(c: &mut Criterion) {
    let upstream = spawn_stub_upstream();
    run_cell(
        c,
        "C1_same_protocol_no_hook_200turns",
        upstream,
        false,
        LONG,
    );
}

/// **C2 — same-protocol, one `prompt: ro` tap.** The accepted cost, and the published number. The
/// content projection is built and handed to a hook that returns immediately.
fn c2_same_protocol_prompt_ro_tap(c: &mut Criterion) {
    let upstream = spawn_stub_upstream();
    run_cell(c, "C2_same_protocol_prompt_ro_tap", upstream, true, SHORT);
}

/// **C2-long.** The accepted cost with a history long enough that the projection, rather than the
/// socket, dominates the difference from C1.
fn c2_same_protocol_prompt_ro_tap_long(c: &mut Criterion) {
    let upstream = spawn_stub_upstream();
    run_cell(
        c,
        "C2_same_protocol_prompt_ro_tap_200turns",
        upstream,
        true,
        LONG,
    );
}

criterion_group! {
    name = hook_path;
    // A booted process per cell and a real socket per iteration: the default 100 samples over 5s
    // would spend most of the run in warm-up rather than in measurement.
    config = Criterion::default().sample_size(60).measurement_time(Duration::from_secs(20));
    targets =
        c1_same_protocol_no_hook,
        c2_same_protocol_prompt_ro_tap,
        c1_same_protocol_no_hook_long,
        c2_same_protocol_prompt_ro_tap_long
}
criterion_main!(hook_path);
