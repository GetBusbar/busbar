//! THE a2a RIG — the two instruments `testing/README.md` describes, driven the way the removed
//! `qa-conformance-a2a.yml` drove them, with that workflow's verdict job as the decider.
//!
//! * `testing/a2a-harness/`: the independent battery (`python3 -m a2aht`), held to pinned
//!   baselines against two third-party controls (a2a-go v2.4.0 over REST and JSON-RPC, a2a-python
//!   1.1.2), plus its negative control, swap proof and timezone pin.
//! * `testing/a2a-tck/`: the publisher's own TCK (`run-tck.sh`), held to its pinned verdict
//!   against the a2a-go control on both bindings.
//! * The governance probe (`testing/a2a-governance/`) runs as the workflow ran it — it must have
//!   observed something and must label itself NOT a conformance result — and never contributes a
//!   finding about busbar.
//! * THE SUBJECT: a busbar built from this checkout, booted by `scripts/a2a-subject/boot.sh`
//!   (which proves the plane's audience boundary before either instrument starts), judged by the
//!   battery (`--battery`) and the TCK (`--tck`).
//!
//! Every control leg judges an INSTRUMENT: any one red ⇒ `not-run` (nothing about busbar was
//! judged). A red subject leg ⇒ `fail`. Every leg green ⇒ `pass`. That is [`super::decide_legs`],
//! the same rule the mcp rig is judged by. `TZ=America/New_York` on every leg is load-bearing, not
//! cosmetic (see the `tz-is-load-bearing` leg).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::rigs::{decide_legs, read_opt, Rig, Runner};
use super::subject;
use super::Outcome;

/// Each violation the harness's broken fake peer injects, by the test that exists to catch it
/// (the removed workflow's `negative-control` PAIRS, verbatim).
pub const NEGATIVE_PAIRS: &[(&str, &str)] = &[
    (
        "card.required_fields",
        "PROTO AgentCard: the REQUIRED `version` is absent",
    ),
    (
        "card.protocol_version_no_patch",
        "SPEC 3.6: the card advertises protocolVersion 1.0.3",
    ),
    (
        "core.task_state_is_defined_enum",
        "PROTO enum TaskState: emits TASK_STATE_MADE_UP",
    ),
    (
        "adv.concurrent_interleaved_tasks",
        "SPEC 3.4.2: one task id reused for every task",
    ),
    (
        "core.stream_opens_with_task_or_message",
        "SPEC 3.1.2: streams an event for a task never created",
    ),
];

fn outcomes(report: &str) -> Result<BTreeMap<String, String>, String> {
    let v: Value =
        serde_json::from_str(report).map_err(|e| format!("a battery report is not JSON ({e})"))?;
    Ok(v.get("results")
        .and_then(Value::as_array)
        .ok_or("a battery report has no `results`")?
        .iter()
        .filter_map(|r| {
            Some((
                r.get("id")?.as_str()?.to_string(),
                r.get("outcome")?.as_str()?.to_string(),
            ))
        })
        .collect())
}

/// THE NEGATIVE CONTROL'S DISCRIMINATION: the battery against the broken peer exited 1 (tests ran
/// and failed), it reached the honest peer too (not 3), and every injected violation's test FAILED
/// against the broken peer and PASSED against the honest one.
pub fn discriminates(
    broken_exit: Option<i32>,
    honest_exit: Option<i32>,
    broken: Option<&str>,
    honest: Option<&str>,
) -> Result<(), String> {
    match broken_exit {
        Some(1) => {}
        Some(0) => return Err(
            "the battery exited 0 against the deliberately broken peer: it cannot tell a broken \
                 peer from a working one"
                .into(),
        ),
        Some(3) => return Err("the battery never reached the broken peer (exit 3)".into()),
        other => {
            return Err(format!(
                "the broken peer produced {}, expected exit 1",
                super::rigs::rc(other)
            ))
        }
    }
    if honest_exit == Some(3) || honest_exit.is_none() {
        return Err("the battery never reached the honest peer".into());
    }
    let b = outcomes(broken.ok_or("no report against the broken peer")?)?;
    let h = outcomes(honest.ok_or("no report against the honest peer")?)?;
    let bad: Vec<String> = NEGATIVE_PAIRS
        .iter()
        .filter_map(|(id, violation)| {
            let bo = b.get(*id).map_or("ABSENT", String::as_str);
            let ho = h.get(*id).map_or("ABSENT", String::as_str);
            (bo != "FAIL" || ho != "PASS")
                .then(|| format!("{id} broken={bo} honest={ho} ({violation})"))
        })
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} of {} injected violations not discriminated: {}",
            bad.len(),
            NEGATIVE_PAIRS.len(),
            bad.join("; ")
        ))
    }
}

/// THE GOVERNANCE PROBE'S FLOOR: at least three observations, and the report marks itself as NOT a
/// conformance result.
pub fn governance_observed(report: Option<&str>) -> Result<(), String> {
    let v: Value = serde_json::from_str(report.ok_or("the governance probe wrote no report")?)
        .map_err(|e| format!("the governance report is not JSON ({e})"))?;
    let n = v
        .get("results")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if n < 3 {
        return Err(format!(
            "the governance probe recorded {n} result(s); it did not run"
        ));
    }
    if v.pointer("/meta/not_a_conformance_result")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("the governance report does not mark itself NOT a conformance result".into());
    }
    Ok(())
}

/// A background peer, stopped on drop.
struct Peer(Child);

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Wait until `http://127.0.0.1:<port>/.well-known/agent-card.json` answers 2xx.
fn await_card(port: u16, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        let ok = Command::new("curl")
            .args(["-fsS", "-m", "2", "-o", "/dev/null"])
            .arg(format!(
                "http://127.0.0.1:{port}/.well-known/agent-card.json"
            ))
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

impl Runner {
    fn spawn_peer(
        &self,
        cwd: &Path,
        log: &Path,
        argv: &[&str],
        env: &[(&str, String)],
    ) -> Option<Peer> {
        let file = std::fs::File::create(log).ok()?;
        let err = file.try_clone().ok()?;
        let mut c = Command::new(argv[0]);
        c.args(&argv[1..])
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(file)
            .stderr(err);
        for (k, v) in env {
            c.env(k, v);
        }
        c.spawn().ok().map(Peer)
    }

    pub(super) fn run_a2a(&self) -> Outcome {
        let rig = Rig::A2a;
        if let Some(o) = self.missing(
            rig,
            &["bash", "python3", "go", "node", "cargo", "curl", "git"],
        ) {
            return o;
        }
        let dir = self.work_dir(rig);
        let harness = self.root.join("testing/a2a-harness");
        let governance = self.root.join("testing/a2a-governance");
        let cache = self.cache.join("a2a");
        let bin_dir = cache.join("a2aht/bin");
        let src_dir = cache.join("a2aht/src");
        let _ = std::fs::create_dir_all(&cache);
        let _ = std::fs::remove_dir_all(harness.join("reports"));
        let _ = std::fs::create_dir_all(harness.join("reports"));
        let env: Vec<(&str, String)> = vec![
            ("TZ", "America/New_York".into()),
            ("A2AHT_CONTROL_BIN", bin_dir.to_string_lossy().into_owned()),
            ("A2AHT_CONTROL_SRC", src_dir.to_string_lossy().into_owned()),
            (
                "A2A_TCK_WORK",
                cache.join("a2a-tck").to_string_lossy().into_owned(),
            ),
            ("A2AHT_OUT", dir.join("tz").to_string_lossy().into_owned()),
        ];
        let a2a = bin_dir.join("a2a").to_string_lossy().into_owned();
        let leg =
            |name: &str, argv: &[&str], cwd: Option<&Path>| self.leg(rig, name, argv, cwd, &env);
        let mut controls: Vec<(&str, Option<i32>)> = Vec::new();

        // The battery's own machinery, each guard made to fail.
        controls.push((
            "harness-selftest",
            leg(
                "harness-selftest",
                &["python3", "testing/a2a-harness/scripts/harness-selftest.py"],
                None,
            ),
        ));
        controls.push((
            "tck-baseline-selftest",
            leg(
                "tck-baseline-selftest",
                &["python3", "testing/a2a-tck/check-baseline-selftest.py"],
                None,
            ),
        ));
        controls.push((
            "subject-selftest",
            leg(
                "subject-selftest",
                &["bash", "scripts/a2a-subject/boot.sh", "--selftest"],
                None,
            ),
        ));
        controls.push((
            "install-control-go",
            leg(
                "install-control-go",
                &[
                    "bash",
                    "testing/a2a-harness/scripts/install-control.sh",
                    "go",
                ],
                None,
            ),
        ));
        controls.push((
            "install-control-python",
            leg(
                "install-control-python",
                &[
                    "bash",
                    "testing/a2a-harness/scripts/install-control.sh",
                    "python",
                ],
                None,
            ),
        ));

        // Instrument 1 against a2a-go, both bindings, each held to its pinned baseline.
        for (binding, extra, baseline) in [
            ("rest", "", "control-a2a-go-rest.json"),
            (
                "jsonrpc",
                " --transport jsonrpc",
                "control-a2a-go-jsonrpc.json",
            ),
        ] {
            let report = format!("reports/control-{binding}.json");
            let launch = format!("{a2a} serve --echo --port 9099 --quiet{extra}");
            let drive = format!("{a2a} send {{url}} hello-from-harness");
            let label = format!("control:a2a-go/{binding}");
            let ran = leg(
                &format!("control-a2a-go-{binding}"),
                &[
                    "python3",
                    "-m",
                    "a2aht",
                    "run",
                    "--launch",
                    &launch,
                    "--port",
                    "9099",
                    "--label",
                    &label,
                    "--tier",
                    "pre-release",
                    "--client-drive",
                    &drive,
                    "--known-deviations",
                    "baselines/known-deviations-a2a-go.json",
                    "--json",
                    &report,
                    "--allow-red",
                ],
                Some(harness.as_path()),
            );
            let held = if ran == Some(0) {
                let baseline = format!("baselines/{baseline}");
                leg(
                    &format!("control-a2a-go-{binding}-baseline"),
                    &[
                        "python3",
                        "-m",
                        "a2aht",
                        "baseline",
                        "--report",
                        &report,
                        "--baseline",
                        &baseline,
                    ],
                    Some(harness.as_path()),
                )
            } else {
                ran
            };
            controls.push((
                if binding == "rest" {
                    "control-a2a-go-rest"
                } else {
                    "control-a2a-go-jsonrpc"
                },
                held,
            ));
        }

        // Instrument 1 against a2a-python, started out of band so its own words reach the log.
        let py = src_dir
            .join("venv/bin/python")
            .to_string_lossy()
            .into_owned();
        let sample = src_dir
            .join("a2a-python/samples/hello_world_agent.py")
            .to_string_lossy()
            .into_owned();
        let python_control = match self.spawn_peer(
            &self.root,
            &dir.join("a2a-python-peer.log"),
            &[&py, &sample],
            &env,
        ) {
            Some(peer) if await_card(41241, 60) => {
                let ran = leg(
                    "control-a2a-python",
                    &[
                        "python3",
                        "-m",
                        "a2aht",
                        "run",
                        "--endpoint",
                        "http://127.0.0.1:41241",
                        "--label",
                        "control:a2a-python",
                        "--tier",
                        "pre-release",
                        "--known-deviations",
                        "baselines/known-deviations-a2a-python.json",
                        "--role",
                        "server",
                        "--allow-undriven-bindings",
                        "GRPC",
                        "--json",
                        "reports/control-python.json",
                        "--allow-red",
                    ],
                    Some(harness.as_path()),
                );
                drop(peer);
                if ran == Some(0) {
                    leg(
                        "control-a2a-python-baseline",
                        &[
                            "python3",
                            "-m",
                            "a2aht",
                            "baseline",
                            "--report",
                            "reports/control-python.json",
                            "--baseline",
                            "baselines/control-a2a-python.json",
                        ],
                        Some(harness.as_path()),
                    )
                } else {
                    ran
                }
            }
            _ => None,
        };
        controls.push(("control-a2a-python", python_control));

        // The negative control: a broken peer MUST be red, an honest one not, per injected violation.
        let negative = match subject::free_ports(2) {
            Ok(p) => {
                let (bp, hp) = (p[0].to_string(), p[1].to_string());
                let broken = self.spawn_peer(
                    &harness,
                    &dir.join("broken-peer.log"),
                    &[
                        "python3",
                        "-m",
                        "a2aht",
                        "fake-peer",
                        "--port",
                        &bp,
                        "--broken",
                    ],
                    &env,
                );
                let honest = self.spawn_peer(
                    &harness,
                    &dir.join("honest-peer.log"),
                    &["python3", "-m", "a2aht", "fake-peer", "--port", &hp],
                    &env,
                );
                if broken.is_some()
                    && honest.is_some()
                    && await_card(p[0], 30)
                    && await_card(p[1], 30)
                {
                    let run_against = |port: &str, label: &str| {
                        let ep = format!("http://127.0.0.1:{port}");
                        let json = format!("reports/{label}.json");
                        leg(
                            label,
                            &[
                                "python3",
                                "-m",
                                "a2aht",
                                "run",
                                "--endpoint",
                                &ep,
                                "--label",
                                label,
                                "--tier",
                                "pull-request",
                                "--role",
                                "server",
                                "--json",
                                &json,
                            ],
                            Some(harness.as_path()),
                        )
                    };
                    let be = run_against(&bp, "negative-control");
                    let he = run_against(&hp, "honest-control");
                    let verdict = discriminates(
                        be,
                        he,
                        read_opt(&harness.join("reports/negative-control.json")).as_deref(),
                        read_opt(&harness.join("reports/honest-control.json")).as_deref(),
                    );
                    if let Err(e) = &verdict {
                        eprintln!("  a2a: negative-control: {e}");
                    }
                    Some(i32::from(verdict.is_err()))
                } else {
                    None
                }
            }
            Err(_) => None,
        };
        controls.push(("negative-control", negative));

        controls.push((
            "swap-proof",
            leg(
                "swap-proof",
                &["bash", "./scripts/swap-proof.sh"],
                Some(harness.as_path()),
            ),
        ));
        controls.push((
            "tz-is-load-bearing",
            leg(
                "tz-is-load-bearing",
                &["bash", "testing/a2a-harness/scripts/tz-is-load-bearing.sh"],
                None,
            ),
        ));

        // Instrument 2: the official TCK against the a2a-go control, both bindings.
        controls.push((
            "tck-control-http-json",
            leg(
                "tck-control-http-json",
                &["bash", "testing/a2a-tck/run-tck.sh", "control-http-json"],
                None,
            ),
        ));
        controls.push((
            "tck-control-jsonrpc",
            leg(
                "tck-control-jsonrpc",
                &["bash", "testing/a2a-tck/run-tck.sh", "control-jsonrpc"],
                None,
            ),
        ));

        // The governance probe: observed something, and says it is not conformance.
        let gov_report = dir.join("governance.json").to_string_lossy().into_owned();
        let launch = format!("{a2a} serve --echo --port 9098 --quiet");
        let drive = format!("{a2a} send {{url}} governance-probe");
        let gov = leg(
            "governance-probe",
            &[
                "python3",
                "-m",
                "a2agov",
                "--launch",
                &launch,
                "--port",
                "9098",
                "--label",
                "control:a2a-go",
                "--client-drive",
                &drive,
                "--json",
                gov_report.as_str(),
            ],
            Some(governance.as_path()),
        );
        let gov = match gov {
            Some(0) => {
                let floor = governance_observed(read_opt(Path::new(&gov_report)).as_deref());
                if let Err(e) = &floor {
                    eprintln!("  a2a: governance-probe: {e}");
                }
                Some(i32::from(floor.is_err()))
            }
            other => other,
        };
        controls.push(("governance-probe", gov));

        // The subject, armed by a binary built from this checkout, or not armed at all.
        let mut subjects: Vec<(&str, Option<i32>)> = Vec::new();
        let instruments_ok = controls.iter().all(|(_, c)| *c == Some(0));
        if instruments_ok {
            let bin = match self.busbar() {
                Ok(b) => b,
                Err(e) => {
                    return Outcome::not_run(format!(
                    "no subject ({e}): the controls proved the instruments, nothing proved busbar"
                ))
                }
            };
            let mut senv = env.clone();
            senv.push(("A2A_SUBJECT_BUSBAR_BIN", bin.to_string_lossy().into_owned()));
            senv.push((
                "A2A_TCK_OUT",
                dir.join("tck-out-subject").to_string_lossy().into_owned(),
            ));
            subjects.push((
                "subject-battery",
                self.leg(
                    rig,
                    "subject-battery",
                    &["bash", "scripts/a2a-subject/boot.sh", "--battery"],
                    None,
                    &senv,
                ),
            ));
            subjects.push((
                "subject-tck",
                self.leg(
                    rig,
                    "subject-tck",
                    &["bash", "scripts/a2a-subject/boot.sh", "--tck"],
                    None,
                    &senv,
                ),
            ));
        }
        decide_legs(&controls, &subjects, &self.rel(&dir))
    }
}
