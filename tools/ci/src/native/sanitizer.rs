//! Controller-selected C TSan execution after same-runtime control
//! qualification (former `native_sanitizer` and the host side of
//! `toolchain/tsan_linux29_probe` / `sanitizer_profile`). The candidate
//! profile is never activated beyond the fixed C unit command.
use super::confine::{Execution, Profile, Restriction, Roots, canonical, digest};
use super::sp::{self, Dict, R, at, value_error};
use super::{Q, pysteps};
use crate::json::{self, Value, object};
use crate::sha256;
use std::path::{Path, PathBuf};

fn rule() -> Value {
    json::parse(br#"{"names": ["personality"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 0, "value": 262144, "op": "SCMP_CMP_EQ"}]}"#)
        .unwrap()
}

pub fn pins(trusted: &Path) -> R<Value> {
    sp::read_json(&trusted.join("scripts/architecture/toolchain/tsan-linux29-pins.json"))
}

/// `sanitizer_profile.verify_delta(baseline, result)`.
fn verify_delta(baseline: &Value, result: &Value) -> R<()> {
    let mut a = baseline.keys();
    let mut b = result.keys();
    a.sort();
    b.sort();
    if a != b
        || a.iter()
            .any(|k| *k != "syscalls" && baseline.at(k) != result.at(k))
    {
        return Err(value_error("sanitizer profile changed non-syscall policy"));
    }
    let mut expected = baseline.at("syscalls").as_array().unwrap_or(&[]).to_vec();
    expected.push(rule());
    if result.at("syscalls") != &Value::Array(expected) {
        return Err(value_error(
            "sanitizer profile must append only the exact personality argument",
        ));
    }
    Ok(())
}

/// `derive(raw)`: the pinned Docker 29.1.3 baseline plus the one exception.
pub fn derive(raw: &[u8], pins: &Value) -> R<Value> {
    if Some(sha256::hex(raw).as_str()) != pins.at("baseline_sha256").as_str() {
        return Err(value_error(
            "baseline differs from the pinned Docker 29.1.3 source",
        ));
    }
    let baseline = sp::loads(raw)?;
    let syscalls = at(&baseline, "syscalls")?;
    if baseline.at("defaultAction").as_str() != Some("SCMP_ACT_ERRNO")
        || syscalls
            .as_array()
            .is_some_and(|rows| rows.contains(&rule()))
    {
        return Err(value_error("unexpected baseline policy"));
    }
    let mut result = baseline.clone();
    if let Some(Value::Array(rows)) = result.get_mut("syscalls") {
        rows.push(rule());
    }
    verify_delta(&baseline, &result)?;
    if Some(sha256::hex(&canonical(&result)).as_str()) != pins.at("profile_sha256").as_str() {
        return Err(value_error("derived profile digest differs"));
    }
    Ok(result)
}

fn prepare_profiles(baseline_path: &Path, destination: &Path, pins: &Value) -> R<Value> {
    let raw = sp::read(baseline_path)?;
    let profile = derive(&raw, pins)?;
    sp::mkdirs(destination, false)?;
    sp::write(&destination.join("baseline.json"), &raw)?;
    sp::write(&destination.join("sanitizer.json"), canonical(&profile))?;
    let record = object([
        ("schema", "busbar.native-tsan-probe-profile/1".into()),
        ("pins", pins.clone()),
        ("baseline_sha256", pins.at("baseline_sha256").clone()),
        ("profile_sha256", pins.at("profile_sha256").clone()),
        ("exact_delta", rule()),
        ("per_process_aslr_disabled", true.into()),
        ("production_activation", false.into()),
    ]);
    sp::write(&destination.join("profile-record.json"), canonical(&record))?;
    Ok(record)
}

/// `ProfileExecution(config, roots, control, profile, expected, baseline)`.
#[allow(clippy::too_many_arguments)]
fn profile_execution(
    config: &Value,
    roots: Roots,
    control: &Path,
    entry: &Path,
    profile: &Path,
    expected: &str,
    baseline: &Path,
    pins: &Value,
) -> R<Execution> {
    let mut execution = Execution::new(config.clone(), roots, control, entry.to_owned())?;
    execution.profile = Some(load_profile(profile, expected, baseline, pins)?);
    Ok(execution)
}

fn load_profile(profile: &Path, expected: &str, baseline: &Path, pins: &Value) -> R<Profile> {
    let path = sp::resolve(profile);
    if digest(&path)? != expected {
        return Err(value_error("local profile digest differs"));
    }
    let data = sp::read_json(&path)?;
    let baseline_data = sp::read_json(baseline)?;
    derive(&sp::read(baseline)?, pins)?;
    if data != baseline_data {
        verify_delta(&baseline_data, &data)?;
    }
    Ok(Profile {
        path,
        sha256: expected.to_owned(),
        data,
    })
}

const SOURCE: &str = "#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <sys/personality.h>
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;
static int counter;
static void *worker(void *ignored) {
    (void)ignored;
    pthread_barrier_wait(&barrier);
    for (int n = 0; n < 1000; ++n) {
#ifndef DELIBERATE_RACE
        pthread_mutex_lock(&mutex);
#endif
        ++counter;
#ifndef DELIBERATE_RACE
        pthread_mutex_unlock(&mutex);
#endif
    }
    return 0;
}
int main(void) {
    printf(\"personality=%d\\n\", personality(0xffffffff)); fflush(stdout);
    if (pthread_barrier_init(&barrier, 0, 2)) return 2;
    pthread_t one, two;
    if (pthread_create(&one, 0, worker, 0) || pthread_create(&two, 0, worker, 0)) return 3;
    pthread_join(one, 0); pthread_join(two, 0);
    pthread_barrier_destroy(&barrier);
    return 0;
}
";

struct Probe<'a> {
    control: PathBuf,
    checkout: PathBuf,
    rows: Vec<(String, Value)>,
    env: Dict,
    _pins: &'a Value,
}

impl Probe<'_> {
    fn run(
        &mut self,
        execution: &mut Execution,
        name: &str,
        argv: Vec<String>,
        success: bool,
    ) -> R<sp::Done> {
        let result = execution.run_captured(&argv, &self.checkout, &self.env, 60)?;
        let row = object([
            (
                "argv",
                Value::Array(argv.iter().map(|a| a.as_str().into()).collect()),
            ),
            ("exit_code", Value::int(result.code)),
            ("stdout", result.text().into()),
            (
                "stderr",
                String::from_utf8_lossy(&result.stderr).into_owned().into(),
            ),
            (
                "profile_sha256",
                execution
                    .profile
                    .as_ref()
                    .map(|p| p.sha256.clone())
                    .unwrap_or_default()
                    .into(),
            ),
        ]);
        sp::write(
            &self.control.join(format!("{name}.json")),
            json::dumps_indent(&row) + "\n",
        )?;
        self.rows.retain(|(n, _)| n != name);
        self.rows.push((name.to_owned(), row));
        if success && result.code != 0 {
            let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
            let count = stderr.chars().count();
            let tail: String = stderr.chars().skip(count.saturating_sub(2000)).collect();
            return Err(value_error(format!("{name} failed: {tail}")));
        }
        Ok(result)
    }
}

/// `probe(config_path, config_sha256, baseline_path, work)`: native x86
/// Docker 29.1.3 TSan controls; never activates candidate policy.
pub fn probe(
    entry: &Path,
    config_path: &Path,
    config_sha256: &str,
    baseline_path: &Path,
    work: &Path,
    pins: &Value,
) -> R<Value> {
    if digest(config_path)? != config_sha256 {
        return Err(value_error("runtime configuration digest differs"));
    }
    let config = sp::read_json(config_path)?;
    let work = sp::resolve(work);
    sp::mkdirs(&work, false)?;
    let record = prepare_profiles(baseline_path, &work.join("profiles"), pins)?;
    let roots = Roots {
        checkout: work.join("checkout"),
        candidate: work.join("candidate"),
        trusted: work.join("trusted"),
        harness: work.join("harness"),
    };
    let control = work.join("control");
    for path in [
        &roots.checkout,
        &roots.candidate,
        &roots.trusted,
        &roots.harness,
        &control,
    ] {
        sp::mkdir(path, 0o777, false)?;
    }
    sp::mkdir(&roots.checkout.join(".git"), 0o777, false)?;
    sp::write(&roots.harness.join("immutable"), "trusted harness\n")?;
    sp::write(&control.join("secret"), "controller fixture secret\n")?;
    let baseline = work.join("profiles/baseline.json");
    let baseline_sha = record
        .at("baseline_sha256")
        .as_str()
        .unwrap_or("")
        .to_owned();
    let profile_sha = record
        .at("profile_sha256")
        .as_str()
        .unwrap_or("")
        .to_owned();
    let mut original = profile_execution(
        &config,
        roots.clone(),
        &control,
        entry,
        &baseline,
        &baseline_sha,
        &baseline,
        pins,
    )?;
    let mut sanitizer = profile_execution(
        &config,
        roots.clone(),
        &control,
        entry,
        &work.join("profiles/sanitizer.json"),
        &profile_sha,
        &baseline,
        pins,
    )?;
    let mut report = object([
        ("schema", "busbar.native-tsan-probe/1".into()),
        (
            "scope",
            "fixed-source native x86 runtime controls only".into(),
        ),
        ("image", config.at("image").clone()),
        ("engine", Value::Null),
        ("profile", record),
        ("production_activation", false.into()),
        ("release_eligible", false.into()),
    ]);
    let mut env = Dict::default();
    env.set("TSAN_OPTIONS", "halt_on_error=1:exitcode=66");
    let mut probe = Probe {
        control: control.clone(),
        checkout: roots.checkout.clone(),
        rows: Vec::new(),
        env,
        _pins: pins,
    };
    let outcome = (|| -> R<()> {
        let version =
            original.client(&sp::strings(&["version", "--format", "{{json .Server}}"]))?;
        let engine_record = object([
            ("exit_code", Value::int(version.code)),
            ("stdout", version.text().into()),
            (
                "stderr",
                String::from_utf8_lossy(&version.stderr).into_owned().into(),
            ),
        ]);
        sp::write(
            &work.join("engine.json"),
            json::dumps_indent(&engine_record) + "\n",
        )?;
        if version.code != 0 {
            return Err(value_error("could not observe Docker engine identity"));
        }
        let engine = sp::loads(&version.stdout)?;
        report.set("engine", engine.clone());
        if engine.at("Version") != pins.at("engine_version")
            || engine.at("GitCommit") != pins.at("engine_build_git_commit")
        {
            let observed = object([
                ("Version", engine.at("Version").clone()),
                ("GitCommit", engine.at("GitCommit").clone()),
            ]);
            return Err(value_error(format!(
                "daemon differs from pinned Ubuntu engine build: {}",
                json::dumps(&observed, false)
            )));
        }
        let host = probe.run(
            &mut original,
            "platform",
            sp::strings(&["uname", "-smr"]),
            true,
        )?;
        let platform = host.text();
        if !(platform.starts_with("Linux ") && platform.trim_end().ends_with(" x86_64")) {
            return Err(value_error(
                "native x86 Linux worker required; other architectures cannot qualify this probe",
            ));
        }
        probe.run(
            &mut original,
            "compiler-version",
            sp::strings(&["cc", "--version"]),
            true,
        )?;
        let source = roots.checkout.join("sanitizer.c");
        sp::write(&source, SOURCE)?;
        report.set("source_sha256", digest(&source)?.into());
        let clean = roots.candidate.join("clean");
        let race = roots.candidate.join("race");
        for (name, target, flags) in [
            ("compile-clean", &clean, vec![]),
            ("compile-race", &race, vec!["-DDELIBERATE_RACE"]),
        ] {
            let mut argv = sp::strings(&["cc", "-std=c11", "-g", "-fsanitize=thread", "-pthread"]);
            argv.extend(sp::strings(&flags));
            argv.extend([sp::text(&source), "-o".into(), sp::text(target)]);
            probe.run(&mut original, name, argv, true)?;
        }
        report.set(
            "instrumented_binaries",
            object([
                ("race_free_sha256", digest(&clean)?.into()),
                ("race_sha256", digest(&race)?.into()),
            ]),
        );
        // Randomized TSan startup may fault before producing a diagnostic;
        // retain this attempt without treating it as an assertion or a pass.
        probe.run(
            &mut original,
            "baseline-tsan",
            vec![sp::text(&clean)],
            false,
        )?;
        report.set("baseline_tsan_role", "diagnostic-only".into());
        let python = config
            .at(pysteps::INTERPRETER_KEY)
            .as_str()
            .unwrap_or("")
            .to_owned();
        let denied = probe.run(
            &mut original,
            "baseline-personality-denial",
            vec![
                python,
                "-I".into(),
                "-c".into(),
                pysteps::BASELINE_PERSONALITY_CONTROL.into(),
            ],
            false,
        )?;
        if denied.code != 0 {
            return Err(value_error(
                "baseline personality control did not exit successfully",
            ));
        }
        let expected = json::parse(
            br#"{"argument": 262144, "before": 0, "result": -1, "errno": 1, "after": 0}"#,
        )
        .unwrap();
        if sp::loads(&denied.stdout)? != expected {
            return Err(value_error(
                "baseline did not deny the exact personality operation with EPERM",
            ));
        }
        report.set("baseline_personality_denied", true.into());
        let setarch = |binary: &Path| {
            vec![
                "setarch".to_owned(),
                "--addr-no-randomize".into(),
                sp::text(binary),
            ]
        };
        let good = probe.run(
            &mut sanitizer,
            "sanitizer-race-free",
            setarch(&clean),
            false,
        )?;
        let bad = probe.run(
            &mut sanitizer,
            "sanitizer-deliberate-race",
            setarch(&race),
            false,
        )?;
        if !(good.code == 0 && good.text().contains("personality=262144")) {
            return Err(value_error(
                "race-free instrumented control did not pass with observed process ASLR disabled",
            ));
        }
        if !(bad.code == 66
            && String::from_utf8_lossy(&bad.stderr).contains("ThreadSanitizer: data race"))
        {
            return Err(value_error("instrumented deliberate race was not detected"));
        }
        let denial = pysteps::denial_witness(&work);
        probe.env.set("CI_JOB_TOKEN", "fixture-secret");
        probe.env.set("AWS_SECRET_ACCESS_KEY", "fixture-secret");
        probe
            .env
            .set("GOOGLE_APPLICATION_CREDENTIALS", "/host/secret");
        let witness = probe.run(
            &mut sanitizer,
            "sanitizer-denial-witness",
            vec![
                pysteps::IMAGE_PYTHON.into(),
                "-c".into(),
                denial.clone(),
                denial,
            ],
            true,
        )?;
        report.set("status", "native-x86-sanitizer-controls-pass".into());
        report.set("per_process_aslr_disabled", true.into());
        report.set("race_free_passed", true.into());
        report.set("deliberate_race_detected", true.into());
        report.set("denial_witness", sp::loads(&witness.stdout)?);
        Ok(())
    })();
    if let Err(error) = &outcome {
        report.set("status", "failed".into());
        report.set("error", error.message.as_str().into());
    }
    report.set("commands", Value::Object(probe.rows));
    report.set(
        "baseline_observations",
        Value::Array(original.observations.clone()),
    );
    report.set(
        "sanitizer_observations",
        Value::Array(sanitizer.observations.clone()),
    );
    let written = sp::write(
        &work.join("result.json"),
        json::dumps_indent(&report) + "\n",
    );
    for path in [
        &roots.checkout,
        &roots.candidate,
        &roots.trusted,
        &roots.harness,
    ] {
        sp::rmtree(path)?;
    }
    written?;
    outcome?;
    Ok(report)
}

/// `run_c_unit_tsan(q)`: called only by the trusted C qualification branch.
pub fn run_c_unit_tsan(q: &mut Q) -> R<()> {
    let execution = q.execution.as_ref().unwrap();
    if execution.profile.is_some() {
        return Err(value_error("C TSan requires confined execution"));
    }
    let binary = q.work.join("unit-tsan");
    if !binary.is_file() || sp::is_symlink(&binary) {
        return Err(value_error(
            "C TSan requires a regular compiled unit binary",
        ));
    }
    let pins = pins(&q.trusted)?;
    let baseline = q
        .trusted
        .join("scripts/architecture/toolchain/tsan-linux29-baseline.json");
    derive(&sp::read(&baseline)?, &pins)?;
    let config_path = q.control.join("sanitizer-runtime-config.json");
    sp::write(&config_path, canonical(&execution.config))?;
    let config_digest = digest(&config_path)?;
    let proof_work = q.control.join("sanitizer-runtime-proof");
    let entry = execution.entry.clone();
    let proof = probe(
        &entry,
        &config_path,
        &config_digest,
        &baseline,
        &proof_work,
        &pins,
    );
    // Retain failed controls too, including failures before sample execution.
    for (source, target) in [
        ("result.json", "sanitizer-runtime.json"),
        ("engine.json", "sanitizer-engine.json"),
    ] {
        let path = proof_work.join(source);
        if path.is_file() {
            sp::write(&q.evidence.join(target), sp::read(&path)?)?;
        }
    }
    let proof = proof?;
    let execution = q.execution.as_ref().unwrap();
    let qualified = proof.at("status").as_str() == Some("native-x86-sanitizer-controls-pass")
        && proof.at("baseline_personality_denied").as_bool() == Some(true)
        && proof.at("race_free_passed").as_bool() == Some(true)
        && proof.at("deliberate_race_detected").as_bool() == Some(true)
        && proof.at("denial_witness").at("all_denied").as_bool() == Some(true)
        && proof.at("image") == execution.config.at("image");
    if !qualified {
        return Err(value_error(
            "same-runtime sanitizer controls did not qualify",
        ));
    }
    if canonical(&execution.config) != sp::read(&config_path)? {
        return Err(value_error(
            "runtime configuration changed after sanitizer controls",
        ));
    }
    let profile_path = proof_work.join("profiles/sanitizer.json");
    let expected = pins.at("profile_sha256").as_str().unwrap_or("").to_owned();
    // Same validation as constructing the former sanitizer execution.
    Execution::new(
        execution.config.clone(),
        execution.roots.clone(),
        &execution.control,
        execution.entry.clone(),
    )?;
    let profile = load_profile(&profile_path, &expected, &baseline, &pins)?;
    let command = vec![
        "setarch".to_owned(),
        "--addr-no-randomize".into(),
        sp::text(&binary),
    ];
    q.receipt.set(
        "sanitizer_runtime",
        object([
            ("configuration_sha256", config_digest.into()),
            (
                "controls_sha256",
                digest(&q.evidence.join("sanitizer-runtime.json"))?.into(),
            ),
            ("profile_sha256", expected.as_str().into()),
            ("binary_sha256", digest(&binary)?.into()),
            ("scope", "c-unit-tsan".into()),
            (
                "argv",
                Value::Array(command.iter().map(|a| a.as_str().into()).collect()),
            ),
        ]),
    );
    let execution = q.execution();
    execution.profile = Some(profile);
    execution.restriction = Some(Restriction {
        command: command.clone(),
    });
    let ran = q.run("c-unit-tsan", command);
    let execution = q.execution();
    execution.profile = None;
    execution.restriction = None;
    ran.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_appends_only_the_exact_personality_exception() {
        let baseline = json::parse(br#"{"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}]}"#).unwrap();
        let mut result = baseline.clone();
        if let Some(Value::Array(rows)) = result.get_mut("syscalls") {
            rows.push(rule());
        }
        verify_delta(&baseline, &result).unwrap();
        let mut widened = result.clone();
        widened.set("defaultAction", "SCMP_ACT_ALLOW".into());
        assert_eq!(
            verify_delta(&baseline, &widened).unwrap_err().message,
            "sanitizer profile changed non-syscall policy"
        );
        let raw = crate::json::encoded(&baseline);
        let pins = object([
            ("baseline_sha256", sha256::hex(&raw).into()),
            ("profile_sha256", sha256::hex(&canonical(&result)).into()),
        ]);
        assert_eq!(derive(&raw, &pins).unwrap(), result);
        assert_eq!(
            derive(b"{}", &pins).unwrap_err().message,
            "baseline differs from the pinned Docker 29.1.3 source"
        );
    }
}
