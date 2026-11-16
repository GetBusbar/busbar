// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `bin/oracle`'s selftests, ported from the shell shim (BLD-6): each guard refuses what it exists
//! to refuse, before its green is trusted. Same scenarios, same assertions, same output lines
//! (`  [ok]     <msg>` / `  [FAILED] <msg>`, then the summary line or `oracle <name>: FAILED`).
//!
//! Where the shim drove a scratch copy of itself, this spawns a busbar-ci-checks binary
//! (`oracle run <sub> ...`, `BUSBAR_ORACLE_HOME` naming the scratch checkout): this program, or
//! the one the optional trailing argument names (a parent revision's, for the red proof). Where it
//! called a shell function, this calls the Rust one; `clone_engine` and `fetch_judge` run in a child
//! of this program (`selftest-call`) so the git noise and the stderr the assertions read are
//! captured, as the shim's redirections captured them.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::oracle;
use crate::oracle_judge::{
    assert_no_token, base64_encode, clone_engine, fetch_judge, git_with_token, is_executable,
    judge_arch, judge_env, make_executable, release_token, sha256_of, temp_base, verify_judge_sig,
    Fail, Source, TempDir, ORACLE_RELEASE_KEY_PEMS,
};
use crate::oracle_run::code_of;

/// The CI markers a scratch run is stripped of (a selftest judges a local run unless it plants one).
const NOCI: &[&str] = &[
    "BUSBAR_ORACLE_JUDGE_PATH",
    "CI",
    "MODERNCI",
    "MODERNCI_JOB",
    "MODERNCI_TO_SHA",
    "MODERNCI_HEAD",
    "MODERNCI_COMMIT",
];
const TOKENS: [&str; 3] = ["BUSBAR_RELEASE_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"];
const PLANT: &str = "plant-token-0123456789";
const PLANTED_JUDGE: &str = "#!/bin/sh\necho planted-judge\n";

/// The selftests' subcommands; `None` for anything else.
pub(crate) fn run(sub: &str, rest: &[String], here: &Path) -> Option<i32> {
    // The binary under test (a parent revision's, for the red proof), else this program.
    let under = rest.first().map_or_else(this_exe, PathBuf::from);
    let under = under.as_path();
    Some(match sub {
        "shard-selftest" => selftest(
            sub,
            "the shards cover the corpus exactly once, and a shard that judged less is red",
            |r, st| shard(r, st, here),
        ),
        "private-tmp-selftest" => selftest(
            sub,
            "each recording runs in its own private TMPDIR",
            |r, st| private_tmp(r, st, under),
        ),
        "replay-refusal-selftest" => selftest(
            sub,
            "a replay that judged nothing is refused, never read as a verdict",
            |r, st| replay_refusal(r, st, under),
        ),
        "premise-selftest" => selftest(
            sub,
            "a filtered run evaluates its forgivenesses' premises or refuses by name",
            premise,
        ),
        "token-selftest" => selftest(
            sub,
            "the engine clone stores no credential; a CI run reads no token",
            |r, st| token(r, st, here),
        ),
        "fetch-selftest" => selftest(
            sub,
            "the judge is the pinned digest's, or there is none",
            |r, st| fetch(r, st, here),
        ),
        "release-key-selftest" => selftest(
            sub,
            "the judge verifies with busbar-release's trusted keys and no other",
            release_key,
        ),
        "ci-token-selftest" => selftest(
            sub,
            "a CI run reads no token; a local run still may",
            |r, st| ci_token(r, st, under),
        ),
        // Internal: one judge function in a child, so its stderr can be read.
        "selftest-call" => call(rest),
        _ => return None,
    })
}

// ---- the harness -----------------------------------------------------------------------------------

#[derive(Default)]
struct Report {
    fail: bool,
    /// A fixture that could not be built: the whole verdict is this line.
    abort: Option<String>,
}

impl Report {
    fn ok(&self, msg: &str) {
        println!("  [ok]     {msg}");
    }

    fn bad(&mut self, msg: &str) {
        println!("  [FAILED] {msg}");
        self.fail = true;
    }

    fn check(&mut self, good: bool, ok: &str, bad: &str) {
        if good {
            self.ok(ok);
        } else {
            self.bad(bad);
        }
    }

    fn finish(&self, name: &str, summary: &str) -> i32 {
        if let Some(why) = &self.abort {
            println!("oracle {name}: {why}");
            return 1;
        }
        if self.fail {
            println!("oracle {name}: FAILED");
            1
        } else {
            println!("oracle {name}: {summary}");
            0
        }
    }
}

/// Run one selftest in a fresh scratch directory (removed after); a fixture that cannot be written
/// is a `[FAILED]` row.
fn selftest(
    name: &str,
    summary: &str,
    body: impl FnOnce(&mut Report, &Path) -> io::Result<()>,
) -> i32 {
    let mut report = Report::default();
    match TempDir::new(&temp_base(), "busbar-oracle-selftest.") {
        Ok(scratch) => {
            if let Err(error) = body(&mut report, scratch.path()) {
                report.bad(&format!("the fixture could not be made: {error}"));
            }
        }
        Err(error) => report.bad(&format!("cannot make a scratch dir: {error}")),
    }
    report.finish(name, summary)
}

fn this_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("busbar-ci-checks"))
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn put(path: &Path, body: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, body)
}

/// A throwaway fixture script, runnable.
fn script(path: &Path, body: &str) -> io::Result<()> {
    put(path, body)?;
    make_executable(path)
}

fn read_trimmed(path: &Path) -> String {
    std::fs::read_to_string(path)
        .map(|body| String::from(body.trim_end()))
        .unwrap_or_default()
}

/// What a child did: its exit status, stdout and stderr.
struct Ran {
    rc: i32,
    out: String,
    err: String,
}

fn ran(mut command: Command) -> Ran {
    command.stdin(Stdio::null());
    match command.output() {
        Ok(output) => Ran {
            rc: code_of(output.status),
            out: lossy(&output.stdout),
            err: lossy(&output.stderr),
        },
        Err(error) => Ran {
            rc: 127,
            out: String::new(),
            err: format!(
                "cannot run {}: {error}",
                command.get_program().to_string_lossy()
            ),
        },
    }
}

/// Whether a command succeeded, all output discarded.
fn quiet(command: &mut Command) -> bool {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// A command's stdout, trimmed; nothing when it fails.
fn stdout_of(command: &mut Command) -> String {
    command
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from(lossy(&output.stdout).trim()))
        .unwrap_or_default()
}

/// `<exe> oracle run <args...>` against the checkout `home`.
fn oracle_cmd(exe: &Path, home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(exe);
    command
        .args(["oracle", "run"])
        .args(args)
        .env("BUSBAR_ORACLE_HOME", home);
    command
}

fn no_ci(command: &mut Command) {
    for name in NOCI {
        command.env_remove(name);
    }
}

/// Run `body` with each named variable set (`Some`) or unset (`None`), then restore them all.
/// The selftest process is single-threaded.
fn with_env<T>(set: &[(&str, Option<&str>)], body: impl FnOnce() -> T) -> T {
    let saved: Vec<(&str, Option<OsString>)> = set
        .iter()
        .map(|(name, _)| (*name, std::env::var_os(name)))
        .collect();
    for (name, value) in set {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
    let result = body();
    for (name, value) in saved.iter().rev() {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
    result
}

/// The first `name` on the PATH (`command -v`), else `/usr/bin/<name>`.
fn which(name: &str) -> String {
    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(name))
                .find(|candidate| is_executable(candidate))
        })
        .map_or_else(|| format!("/usr/bin/{name}"), |path| text(&path))
}

/// The first file called `name` under `dir` (`find <dir> -name <name> | head -1`).
fn find_named(dir: &Path, name: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_named(&path, name) {
                return Some(found);
            }
        } else if path.file_name() == Some(OsStr::new(name)) {
            return Some(path);
        }
    }
    None
}

fn answer(args: &[&str]) -> oracle::Answer {
    let args: Vec<String> = args.iter().map(|arg| String::from(*arg)).collect();
    oracle::answer(&args)
}

/// An Ed25519 key pair through openssl; whether there is one.
fn keypair(key: &Path, public: &Path) -> bool {
    quiet(
        Command::new("openssl")
            .args(["genpkey", "-algorithm", "ed25519", "-out"])
            .arg(key),
    ) && quiet(
        Command::new("openssl")
            .args(["pkey", "-in"])
            .arg(key)
            .args(["-pubout", "-out"])
            .arg(public),
    )
}

/// `msg` signed with `key`, base64 (empty when openssl did not sign).
fn sign(key: &Path, msg: &Path, raw: &Path) -> String {
    quiet(
        Command::new("openssl")
            .args(["pkeyutl", "-sign", "-inkey"])
            .arg(key)
            .args(["-rawin", "-in"])
            .arg(msg)
            .arg("-out")
            .arg(raw),
    );
    std::fs::read(raw)
        .map(|bytes| base64_encode(&bytes))
        .unwrap_or_default()
}

/// `selftest-call clone-engine <repo> <ref> <checkout>` | `selftest-call fetch-judge <pin> <cache>
/// <source dir> [<pem>...]`: the judge function, its path on stdout, its refusal on stderr.
fn call(rest: &[String]) -> i32 {
    let args: Vec<&str> = rest.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["clone-engine", repo, rref, checkout] => {
            clone_engine(repo, rref, Path::new(*checkout)).map(|()| None)
        }
        ["fetch-judge", pin, cache, source, pems @ ..] => {
            let keys: Vec<String> = if pems.is_empty() {
                ORACLE_RELEASE_KEY_PEMS.iter().map(|pem| String::from(*pem)).collect()
            } else {
                pems.iter().map(|pem| String::from(*pem)).collect()
            };
            fetch_judge(
                pin,
                Path::new(*cache),
                &Source::Dir(PathBuf::from(*source)),
                &keys,
            )
            .map(Some)
        }
        _ => Err(Fail::new(
            2,
            "oracle selftest-call: clone-engine <repo> <ref> <checkout> | fetch-judge <pin> <cache> <source dir> [<pem>...]",
        )),
    };
    match result {
        Ok(path) => {
            if let Some(path) = path {
                println!("{}", path.display());
            }
            0
        }
        Err(fail) => {
            if !fail.message.is_empty() {
                eprintln!("{}", fail.message);
            }
            i32::from(fail.code)
        }
    }
}

// ---- shard-selftest ----------------------------------------------------------------------------------

fn shard(r: &mut Report, st: &Path, here: &Path) -> io::Result<()> {
    let exe = this_exe();
    let data = |dir: &Path, args: &[&str]| -> Ran {
        let mut command = oracle_cmd(&exe, here, args);
        command.env("BUSBAR_ORACLE_DATA", dir);
        ran(command)
    };
    put(
        &st.join("cells.json"),
        r#"{"cells":[{"id":"a|1"},{"id":"a|2"},{"id":"b|1"},{"id":"b|2"},{"id":"c|1"}]}"#,
    )?;
    put(&st.join("accepted-differences.json"), r#"{"accepted":[]}"#)?;
    r.check(
        data(st, &["shard-cover", "2"]).rc == 0,
        "two shards cover five cells exactly once",
        "a sound split was refused",
    );
    for n in ["1", "3", "5", "7"] {
        if data(st, &["shard-cover", n]).rc != 0 {
            r.bad(&format!("{n} shards: a sound split was refused"));
        }
    }
    let dup = st.join("dup");
    put(
        &dup.join("cells.json"),
        r#"{"cells":[{"id":"a|1"},{"id":"a|2"},{"id":"a|1"}]}"#,
    )?;
    put(&dup.join("accepted-differences.json"), r#"{"accepted":[]}"#)?;
    r.check(
        data(dup.as_path(), &["shard-cover", "2"]).rc != 0,
        "a corpus that repeats an id is refused",
        "a corpus that repeats an id was covered",
    );
    r.check(
        data(st, &["shard-filter", "3", "2"]).rc != 0,
        "a shard outside 1..n is refused",
        "shard 3 of 2 answered a filter",
    );
    let rep = st.join("rep");
    std::fs::create_dir_all(&rep)?;
    let rep_text = text(&rep);
    let verified = || data(st, &["shard-verify", "1", "2", rep_text.as_str()]).rc == 0;
    r.check(
        !verified(),
        "a shard that wrote no report is refused",
        "a shard with no report was verified",
    );
    put(&rep.join("selected-ids.txt"), "a|1\nb|1\n")?;
    r.check(
        !verified(),
        "a shard that did not select a cell it owns is refused",
        "a shard missing one of its cells was verified",
    );
    put(&rep.join("selected-ids.txt"), "a|1\nb|1\nc|1\nb|2\n")?;
    r.check(
        verified(),
        "a shard that selected all it owns (and premise context) is verified",
        "a complete shard was refused",
    );
    // shard-spec: ORACLE_SHARD / MODERNCI_SHARD / MODERNCI_SHARD_INDEX+COUNT, i from 0, answered as k from 1.
    let spec = |vars: &str| -> Ran {
        let mut command = oracle_cmd(&exe, here, &["shard-spec"]);
        for name in [
            "ORACLE_SHARD",
            "MODERNCI_SHARD",
            "MODERNCI_SHARD_INDEX",
            "MODERNCI_SHARD_COUNT",
        ] {
            command.env_remove(name);
        }
        command.envs(
            vars.split_whitespace()
                .filter_map(|pair| pair.split_once('=')),
        );
        ran(command)
    };
    let says = |vars: &str| String::from(spec(vars).out.trim_end_matches('\n'));
    let read = says("ORACLE_SHARD=0/4") == "1 4"
        && says("MODERNCI_SHARD=3/4") == "4 4"
        && says("MODERNCI_SHARD_INDEX=1 MODERNCI_SHARD_COUNT=4") == "2 4"
        && says("").is_empty()
        && says("ORACLE_SHARD=0/1").is_empty();
    r.check(
        read,
        "a shard named i/N (from 0) by any of its names is shard i+1 of N; none, or N=1, is the whole run",
        "a shard spec was misread",
    );
    for vars in [
        "ORACLE_SHARD=4/4",
        "ORACLE_SHARD=x",
        "ORACLE_SHARD=0/4 MODERNCI_SHARD=1/4",
        "MODERNCI_SHARD_INDEX=1",
        "ORACLE_SHARD=0/0",
    ] {
        if spec(vars).rc == 0 {
            r.bad(&format!("shard spec '{vars}' was answered"));
        }
    }
    r.ok("a shard spec that is not a shard, or two that disagree, is refused");
    // shard-merge: green only for shards 1..N of one N, each once, each green, together every cell.
    for k in ["1", "2"] {
        let dir = st.join(format!("m{k}"));
        put(
            &dir.join("selected-ids.txt"),
            &data(st, &["shard-ids", k, "2"]).out,
        )?;
        put(&dir.join("shard.tsv"), &format!("{k}\t2\t0\n"))?;
    }
    let (m1, m2) = (text(&st.join("m1")), text(&st.join("m2")));
    let merged = |dirs: &[&str]| {
        let mut args = vec!["shard-merge"];
        args.extend_from_slice(dirs);
        data(st, &args).rc == 0
    };
    r.check(
        merged(&[m1.as_str(), m2.as_str()]),
        "two green shards that judged every cell merge green",
        "a sound merge was refused",
    );
    r.check(
        !merged(&[m1.as_str()]),
        "a merge missing a shard is red",
        "a merge missing a shard was green",
    );
    r.check(
        !merged(&[m1.as_str(), m1.as_str()]),
        "a merge with a shard twice is red",
        "a merge with a shard twice was green",
    );
    put(&st.join("m2/shard.tsv"), "2\t2\t1\n")?;
    r.check(
        !merged(&[m1.as_str(), m2.as_str()]),
        "a merge with a red shard is red",
        "a merge with a red shard was green",
    );
    Ok(())
}

// ---- private-tmp-selftest ----------------------------------------------------------------------------

const PRIVATE_TMP_ENGINE: &str = r#"#!/usr/bin/env bash
[ "$1" = record ] || exit 0
n="$(find "${TMPDIR:?}" -name 'busbar-plugins-*' 2>/dev/null | wc -l | tr -d ' ')"
echo "$TMPDIR $n" >>"$(dirname "$0")/seen"
"#;

/// Both record paths (`oracle run record` and the generated tool-dir record.sh) run against a
/// scratch checkout with a stub engine, from a host TMPDIR planted with dead-pid staging dirs in the
/// 1.5.5 and 1.6.0 layouts. The engine must see none of them, and its private dir must be gone.
fn private_tmp(r: &mut Report, st: &Path, under: &Path) -> io::Result<()> {
    let (repo, host, out) = (st.join("repo"), st.join("host"), st.join("out"));
    std::fs::create_dir_all(repo.join("testing/shadow-oracle"))?;
    std::fs::create_dir_all(&out)?;
    let dead = stdout_of(Command::new("sh").args(["-c", "echo $$"]));
    let uid = stdout_of(Command::new("id").arg("-u"));
    let mine = host.join(format!("busbar-plugins-{dead}-x"));
    std::fs::create_dir_all(&mine)?;
    std::fs::create_dir_all(host.join(format!(
        "busbar-plugin-staging-{uid}/busbar-plugins-{dead}-x"
    )))?;
    let engine = st.join("engine");
    script(&engine, PRIVATE_TMP_ENGINE)?;
    let out_a = text(&out.join("a"));
    let mut record = oracle_cmd(
        under,
        &repo,
        &["record", "--bin", "/x", "--out", out_a.as_str()],
    );
    no_ci(&mut record);
    for name in [
        "ORACLE_LISTEN_PORT",
        "ORACLE_ADMIN_PORT",
        "ORACLE_MOCK_PORT",
        "CARGO_TARGET_DIR",
    ] {
        record.env_remove(name);
    }
    record
        .env("TMPDIR", &host)
        .env("BUSBAR_ORACLE_RUST_BIN", &engine);
    ran(record);
    if let Some(record_sh) = find_named(&repo.join("target"), "record.sh") {
        let mut forward = Command::new(&record_sh);
        forward.args(["--bin", "/x", "--out"]).arg(out.join("b"));
        no_ci(&mut forward);
        forward
            .env("TMPDIR", &host)
            .env("BUSBAR_ORACLE_RUST_BIN", &engine);
        ran(forward);
    }
    let seen = std::fs::read_to_string(st.join("seen")).unwrap_or_default();
    let prefix = format!("{}/busbar-oracle-tmp.", host.display());
    let mut n = 0;
    for line in seen.lines() {
        let mut fields = line.split_whitespace();
        let dir = fields.next().unwrap_or_default();
        let count = fields.next().unwrap_or_default();
        n += 1;
        if !dir.starts_with(&prefix) {
            r.bad(&format!("path {n}: TMPDIR was not private: {dir}"));
        }
        if count != "0" {
            r.bad(&format!(
                "path {n}: the engine saw {count} staging dir(s) from the host"
            ));
        }
        if !dir.is_empty() && Path::new(dir).exists() {
            r.bad(&format!(
                "path {n}: the private TMPDIR outlived the run: {dir}"
            ));
        }
    }
    if n != 2 {
        r.bad(&format!(
            "expected 2 recordings (bin/oracle record, record.sh), saw {n}"
        ));
    }
    if !mine.is_dir() {
        r.bad("the host's own temp entries were touched");
    }
    Ok(())
}

// ---- replay-refusal-selftest -------------------------------------------------------------------------

const REPLAY_ENGINE: &str = r#"#!/usr/bin/env bash
[ "$1" = diff ] || exit 0
echo diff >>"$(dirname "$0")/calls"
out=""; prev=""; for a in "$@"; do [ "$prev" = --out ] && out="$a"; prev="$a"; done
case "${STUB:-}" in
  usage) echo "error: unexpected argument found" >&2; exit 2 ;;
  zero) mkdir -p "$out"; echo '{"totals": {"owed": 0}}' >"$out/report.json"; exit 0 ;;
  some) mkdir -p "$out"; echo '{"totals": {"owed": 3}}' >"$out/report.json"; exit 1 ;;
esac
"#;

/// A replay that judged nothing is refused, never read as a verdict: `--filter` (record's flag) is
/// refused by name before the engine runs; an engine argument refusal stops the replay there; a
/// report that compared zero owed cells is refused (3); a report that compared some passes the
/// engine's exit through.
fn replay_refusal(r: &mut Report, st: &Path, under: &Path) -> io::Result<()> {
    let repo = st.join("repo");
    let data = repo.join("testing/shadow-oracle");
    put(
        &data.join("cells.json"),
        "{\"cells\": [{\"id\": \"fam|a\"}]}\n",
    )?;
    put(
        &data.join("accepted-differences.json"),
        "{\"accepted\": []}\n",
    )?;
    std::fs::create_dir_all(st.join("out"))?;
    let engine = st.join("engine");
    script(&engine, REPLAY_ENGINE)?;
    let calls = st.join("calls");
    let replay = |mode: &str, out: &str, extra: &[&str]| -> (Ran, usize) {
        let _ = std::fs::write(&calls, "");
        let out_dir = text(&st.join("out").join(out));
        let mut args = vec!["replay", "--candidate", "c", "--out", out_dir.as_str()];
        args.extend_from_slice(extra);
        let mut command = oracle_cmd(under, &repo, &args);
        no_ci(&mut command);
        command
            .env_remove("BUSBAR_ORACLE_DATA")
            .env("STUB", mode)
            .env("BUSBAR_ORACLE_RUST_BIN", &engine);
        let result = ran(command);
        let count = std::fs::read_to_string(&calls).map_or(0, |log| log.lines().count());
        (result, count)
    };
    let head = |err: &str| err.chars().take(200).collect::<String>();
    let (got, n) = replay("some", "f", &["--filter", "fam"]);
    if got.rc == 2 && got.err.contains("--id-filter") && n == 0 {
        r.ok("replay --filter is refused by name before the engine runs");
    } else {
        r.bad(&format!(
            "replay --filter: rc={}, engine calls {n}, {}",
            got.rc,
            head(&got.err)
        ));
    }
    let (got, n) = replay("usage", "u", &[]);
    if got.rc == 2 && got.err.contains("nothing was judged") && n == 1 {
        r.ok("an engine argument refusal stops the replay; no other section runs");
    } else {
        r.bad(&format!(
            "engine refusal: rc={}, engine calls {n}, {}",
            got.rc,
            head(&got.err)
        ));
    }
    let (got, _) = replay("zero", "z", &[]);
    if got.rc == 3 && got.err.contains("ZERO owed cells") {
        r.ok("a replay that compared zero owed cells is refused");
    } else {
        r.bad(&format!("zero judged: rc={}, {}", got.rc, head(&got.err)));
    }
    let (got, _) = replay("some", "s", &[]);
    if got.rc == 1 {
        r.ok("a replay that judged cells answers the engine's verdict");
    } else {
        r.bad(&format!("judged: rc={}, {}", got.rc, head(&got.err)));
    }
    Ok(())
}

// ---- premise-selftest --------------------------------------------------------------------------------

const PREMISE_ACCEPTED: &str = r#"{"accepted": [{"id": "PLANT", "cells": "^fam\\|forgiven$", "premise": {"all": [{"cell": "probe|premise", "status": 200}]}}]}
"#;

fn premise(r: &mut Report, st: &Path) -> io::Result<()> {
    put(
        &st.join("cells.json"),
        "{\"cells\": [{\"id\": \"fam|forgiven\"}, {\"id\": \"fam|other\"}, {\"id\": \"probe|premise\"}]}\n",
    )?;
    let accepted = st.join("accepted-differences.json");
    put(&accepted, PREMISE_ACCEPTED)?;
    let data_text = text(st);
    let data = data_text.as_str();
    let widen = |filter: &str| answer(&["widen-filter", data, filter]);
    let wide = |filter: &str| String::from(widen(filter).stdout.trim_end_matches('\n'));
    let got = wide(r"^fam\|forgiven$");
    let search = |texts: &[&str]| {
        let mut args = vec!["regex-search", got.as_str()];
        args.extend_from_slice(texts);
        answer(&args).code == 0
    };
    if search(&["probe|premise", "fam|forgiven"]) && !search(&["fam|other"]) {
        r.ok("a filter selecting a forgiven cell but not its premise is widened to the premise");
    } else {
        r.bad(&format!(
            "the premise cell was not added to the filter: {got}"
        ));
    }
    let other = wide(r"^fam\|other$");
    if other == r"^fam\|other$" {
        r.ok("a filter that selects no forgiven cell is left as it is");
    } else {
        r.bad(&format!("an unrelated filter was widened: {other}"));
    }
    put(
        &accepted,
        &PREMISE_ACCEPTED.replace("probe|premise\", \"status\"", "probe|gone\", \"status\""),
    )?;
    let refused = widen(r"^fam\|forgiven$");
    if refused.code == 0 {
        r.bad("a premise naming a cell the corpus lacks was not refused");
    } else if refused.stderr.contains("probe|gone") {
        r.ok("a premise naming a cell the corpus lacks is refused, by name");
    } else {
        r.bad(&format!(
            "the refusal did not name the premise cell: {}",
            refused.stderr.trim_end()
        ));
    }
    put(&accepted, PREMISE_ACCEPTED)?;
    let log = st.join("out");
    put(
        &log,
        "accepted-differences: entry 'PLANT' is WITHHELD \u{2014} premise UNEVALUABLE: premise probes cell \"probe|premise\", which the build under test did not record\n",
    )?;
    let log_text = text(&log);
    let withheld = |filter: &str| answer(&["withheld", data, log_text.as_str(), filter]);
    let selected = withheld(r"^fam\|forgiven$");
    if selected.code == 0 {
        r.bad("a withheld forgiveness the filter selected was not refused");
    } else if selected.stderr.contains("probe|premise") {
        r.ok("a replay whose selected forgiveness was withheld refuses, naming the premise");
    } else {
        r.bad("the replay refusal did not name the premise");
    }
    r.check(
        withheld(r"^fam\|other$").code == 0,
        "a withheld forgiveness the filter did not select is not this run's refusal",
        "an unselected withheld forgiveness refused the run",
    );
    Ok(())
}

// ---- token-selftest ----------------------------------------------------------------------------------

/// The engine clone stores no credential: a fresh clone under a planted token, and an existing
/// checkout whose origin a previous version stored as `https://x-access-token:<token>@github.com/…`,
/// each end with no trace of either in .git/config; and the guard refuses a config that has one.
fn token(r: &mut Report, st: &Path, here: &Path) -> io::Result<()> {
    // A throwaway fixture repo: no host hook or signing applies to it.
    let src = st.join("src");
    let built = quiet(Command::new("git").args(["init", "-q"]).arg(&src))
        && quiet(Command::new("git").arg("-C").arg(&src).args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "pin",
        ]));
    let rref = if built {
        stdout_of(
            Command::new("git")
                .arg("-C")
                .arg(&src)
                .args(["rev-parse", "HEAD"]),
        )
    } else {
        String::new()
    };
    if rref.is_empty() {
        r.abort = Some(String::from("could not build the fixture repo"));
        return Ok(());
    }
    let exe = this_exe();
    let fresh = st.join("fresh");
    let fresh_text = text(&fresh);
    let clone = |repo: &str| -> Ran {
        let mut command = oracle_cmd(
            &exe,
            here,
            &[
                "selftest-call",
                "clone-engine",
                repo,
                rref.as_str(),
                fresh_text.as_str(),
            ],
        );
        command.env("BUSBAR_RELEASE_TOKEN", PLANT);
        ran(command)
    };
    let config = || std::fs::read_to_string(fresh.join(".git/config")).ok();
    let stored =
        |words: &[&str]| config().is_some_and(|cfg| words.iter().any(|word| cfg.contains(*word)));
    let src_url = format!("file://{}", src.display());
    if clone(src_url.as_str()).rc != 0 {
        r.bad("the fresh clone failed");
    }
    if config().is_none() || stored(&["plant-token", "x-access-token", "extraheader"]) {
        r.bad("a fresh clone stored the token");
    } else {
        r.ok("a fresh clone under a token stores none");
    }
    quiet(
        Command::new("git")
            .arg("-C")
            .arg(&fresh)
            .args(["remote", "set-url", "origin"])
            .arg(format!(
                "https://x-access-token:{PLANT}@github.com/GetBusbar/busbar-release.git"
            )),
    );
    let guarded = with_env(&[("BUSBAR_RELEASE_TOKEN", Some(PLANT))], || {
        assert_no_token(&fresh).is_err()
    });
    r.check(
        guarded,
        "the guard refuses a config holding a token",
        "the guard passed a config holding the token",
    );
    if clone(src_url.as_str()).rc != 0 {
        r.bad("re-using the stale checkout failed");
    }
    r.check(
        !stored(&["plant-token", "x-access-token"]),
        "a stale tokenized origin is scrubbed",
        "a stale tokenized origin survived a run",
    );
    // A checkout that already holds the pin is reused offline: with an unreachable origin, no
    // fetch is attempted. Judged on git's own stderr.
    let gone = format!("file://{}", st.join("no-such-repo").display());
    let offline = clone(gone.as_str());
    let lower = offline.err.to_lowercase();
    if ["fatal", "error", "does not appear", "could not read"]
        .iter()
        .any(|word| lower.contains(*word))
    {
        r.bad(&format!(
            "a checkout holding the pin still fetched: {}",
            offline.err.lines().next().unwrap_or_default()
        ));
    } else {
        r.ok("a checkout holding the pin is reused without a fetch");
    }
    if stored(&["plant-token", "x-access-token", "extraheader"]) {
        r.bad("the offline reuse stored the token");
    }
    // A CI RUN READS NO TOKEN: under each CI marker, with every token name set, git is handed no
    // credential header and release_token yields nothing; with none, a local run's token is used.
    let hdr = || {
        let mut git = git_with_token();
        git.arg("-C")
            .arg(&src)
            .args(["config", "--get", "http.https://github.com/.extraheader"]);
        stdout_of(&mut git)
    };
    let markers: [(&str, &str); 7] = [
        ("MODERNCI", "1"),
        ("MODERNCI_JOB", "oracle"),
        ("MODERNCI_TO_SHA", rref.as_str()),
        ("MODERNCI_HEAD", rref.as_str()),
        ("MODERNCI_COMMIT", rref.as_str()),
        ("BUSBAR_ORACLE_JUDGE_PATH", "/nonexistent"),
        ("CI", "true"),
    ];
    for (name, value) in markers {
        let mut env: Vec<(&str, Option<&str>)> =
            NOCI.iter().map(|marker| (*marker, None)).collect();
        env.push((name, Some(value)));
        env.extend(TOKENS.iter().map(|token| (*token, Some(PLANT))));
        let got = with_env(&env, || {
            format!("{}{}", hdr(), release_token().unwrap_or_default())
        });
        if got.is_empty() {
            r.ok(&format!(
                "under {name} no token is read, every token name set"
            ));
        } else {
            r.bad(&format!(
                "under {name} a token was read (git got a credential header)"
            ));
        }
    }
    let mut env: Vec<(&str, Option<&str>)> = NOCI.iter().map(|marker| (*marker, None)).collect();
    env.push(("GH_TOKEN", Some(PLANT)));
    r.check(
        !with_env(&env, hdr).is_empty(),
        "GREEN twin: a local run (no CI marker) still hands git its token",
        "a local run's token was not used: the CI rows above prove nothing",
    );
    Ok(())
}

// ---- fetch-selftest ----------------------------------------------------------------------------------

/// RED-before-green for the fetched judge, offline: a fixture "release" directory stands in for the
/// dev-bin API (the directory source), and a throwaway Ed25519 key for busbar-release's.
#[allow(clippy::too_many_lines)]
fn fetch(r: &mut Report, st: &Path, here: &Path) -> io::Result<()> {
    let arch = judge_arch();
    let rref = "0123456789abcdef0123456789abcdef01234567";
    let name = format!("busbar-oracle-linux-{arch}-{rref}");
    let rel = st.join("rel");
    std::fs::create_dir_all(&rel)?;
    std::fs::create_dir_all(st.join("cache"))?;
    let judge = rel.join(&name);
    put(&judge, PLANTED_JUDGE)?;
    let good = sha256_of(&judge).unwrap_or_default();
    let pin_ok = format!("release_ref={rref}\nsha256_linux_{arch}={good}");
    let exe = this_exe();
    let rel_text = text(&rel);
    let get = |pin: &str, cache: &str, libc: Option<&str>, pem: Option<&str>| -> Ran {
        let cache_text = text(&st.join(cache));
        let mut args = vec![
            "selftest-call",
            "fetch-judge",
            pin,
            cache_text.as_str(),
            rel_text.as_str(),
        ];
        args.extend(pem);
        let mut command = oracle_cmd(&exe, here, &args);
        if let Some(libc) = libc {
            command.env("ORACLE_JUDGE_LIBC", libc);
        }
        ran(command)
    };
    let runs = |got: &Ran| {
        got.rc == 0 && stdout_of(&mut Command::new(got.out.trim_end())) == "planted-judge"
    };
    r.check(
        runs(&get(&pin_ok, "cache", None, None)),
        "the pinned digest's judge is fetched, cached and runs",
        "the pinned digest's judge was not fetched",
    );
    let _ = std::fs::remove_file(&judge);
    r.check(
        runs(&get(&pin_ok, "cache", None, None)),
        "a cached judge is reused by its digest, with no source",
        "the cached judge was not reused",
    );
    // THE CACHE IS KEYED BY THE ENVIRONMENT (ModernCI #1827): a judge cached on one C library is
    // never handed to a host with another, and the same environment reuses it.
    put(&judge, PLANTED_JUDGE)?;
    if get(&pin_ok, "cachek", Some("glibc2.35"), None).rc == 0 {
        let _ = std::fs::remove_file(&judge);
        r.check(
            get(&pin_ok, "cachek", Some("glibc2.39"), None).rc != 0,
            "a judge cached on another C library is not reused",
            "a judge cached on glibc2.35 was handed to a glibc2.39 host",
        );
        r.check(
            runs(&get(&pin_ok, "cachek", Some("glibc2.35"), None)),
            "the same environment reuses its cached judge",
            "the same environment did not reuse its cached judge",
        );
    } else {
        r.bad("the keyed fixture judge was not fetched");
    }
    // A JUDGE THAT DOES NOT START is no judge: fetched, it refuses; cached, it is deleted and
    // fetched again (and refuses the same way when the source holds the same bytes).
    put(
        &judge,
        "#!/bin/sh\n[ \"$1\" = --help ] && exit 127\necho dead-judge\n",
    )?;
    let dead = sha256_of(&judge).unwrap_or_default();
    let pin_dead = format!("release_ref={rref}\nsha256_linux_{arch}={dead}");
    let got = get(&pin_dead, "cached", None, None);
    if got.rc == 0 {
        r.bad("a judge that does not start was handed out");
    } else if got.err.contains("does not start") {
        r.ok("a fetched judge that does not start refuses");
    } else {
        r.bad(&format!(
            "the dead-judge refusal did not say so: {}",
            got.err.trim_end()
        ));
    }
    let kept = st
        .join("cached")
        .join(&dead)
        .join(judge_env())
        .join("busbar-oracle");
    if let Some(parent) = kept.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(&judge, &kept)?;
    make_executable(&kept)?;
    let got = get(&pin_dead, "cached", None, None);
    if got.rc == 0 {
        r.bad("a cached judge that does not start was handed out");
    } else if got.err.contains("deleting it") && !kept.exists() {
        r.ok("a cached judge that does not start is deleted, never reused");
    } else {
        r.bad(&format!(
            "the dead cached judge was not deleted: {}",
            got.err.trim_end()
        ));
    }
    put(&judge, PLANTED_JUDGE)?;
    let pin_wrong = format!("release_ref={rref}\nsha256_linux_{arch}={}", "f".repeat(64));
    let got = get(&pin_wrong, "cache2", None, None);
    if got.rc == 0 {
        r.bad("a judge whose sha256 is not the pin's ran");
    } else if got.err.contains("refusing the judge") {
        r.ok("a wrong sha256 refuses the judge");
    } else {
        r.bad(&format!(
            "the wrong-sha refusal did not say so: {}",
            got.err.trim_end()
        ));
    }
    let got = get(&format!("release_ref={rref}"), "cache3", None, None);
    if got.rc == 0 {
        r.bad("a pin with no line for this architecture produced a judge");
    } else if got.err.contains("no judge") {
        r.ok(&format!(
            "a pin with no sha256_linux_{arch} line has no judge"
        ));
    } else {
        r.bad(&format!(
            "the missing-line refusal did not say \"no judge\": {}",
            got.err.trim_end()
        ));
    }
    let side = rel.join(format!("{name}.sha256"));
    put(&side, &"e".repeat(64))?;
    r.check(
        get(&pin_ok, "cache4", None, None).rc != 0,
        "a published .sha256 disagreeing with the pin refuses",
        "a published .sha256 disagreeing with the pin was accepted",
    );
    put(&side, &format!("{good}  {name}\n"))?;
    let (key, public) = (st.join("k.pem"), st.join("pub.pem"));
    if keypair(&key, &public) {
        let msg = st.join("msg");
        put(&msg, &format!("{name}\n{good}\n"))?;
        put(
            &rel.join(format!("{name}.sig")),
            &sign(&key, &msg, &st.join("sig.bin")),
        )?;
        let pem = read_trimmed(&public);
        r.check(
            get(&pin_ok, "cache5", None, Some(pem.as_str())).rc == 0,
            "a .sig made by the release key is accepted",
            "a good .sig was refused",
        );
        let got = get(&pin_ok, "cache6", None, None);
        if got.rc == 0 {
            r.bad("a .sig made by another key was accepted under busbar-release's key");
        } else if got.err.contains("release key") {
            r.ok("a .sig made by another key refuses");
        } else {
            r.bad(&format!(
                "the bad-.sig refusal did not say so: {}",
                got.err.trim_end()
            ));
        }
    } else {
        r.bad("no openssl with Ed25519 here: the .sig check cannot be proven");
    }
    Ok(())
}

// ---- release-key-selftest ----------------------------------------------------------------------------

/// The judge's .sig is checked against busbar-release's TRUSTED release keys: the owner's
/// 2026-10-28 key, which signs, and no other (the earlier key is refused, owner ruling 2026-10-28).
fn release_key(r: &mut Report, st: &Path) -> io::Result<()> {
    const NEW: &str = "MCowBQYDK2VwAyEAHC1U0BcT6iFe98mWXNriKeDNxO6xOaoMY5UXotNweEs=";
    const OLD: &str = "MCowBQYDK2VwAyEAT8gl0GhaEpxYXdRqfeNZ6KU8KgmI+8qbtP8UZPNPJiU=";
    r.check(
        ORACLE_RELEASE_KEY_PEMS
            .first()
            .is_some_and(|pem| pem.contains(NEW)),
        "the owner's 2026-10-28 key is trusted, and first (it signs)",
        "the owner's 2026-10-28 key is not the first trusted key",
    );
    r.check(
        ORACLE_RELEASE_KEY_PEMS.len() == 1,
        "the owner's 2026-10-28 key is the only trusted key",
        "a key other than the owner's 2026-10-28 key is trusted",
    );
    r.check(
        !ORACLE_RELEASE_KEY_PEMS.iter().any(|pem| pem.contains(OLD)),
        "the earlier key busbar-release-2026-10-09 is not trusted",
        "the earlier key busbar-release-2026-10-09 is still trusted",
    );
    let (a, a_pub) = (st.join("a.pem"), st.join("a.pub"));
    let (u, u_pub) = (st.join("u.pem"), st.join("u.pub"));
    if !(keypair(&a, &a_pub) && keypair(&u, &u_pub)) {
        r.bad("no openssl with Ed25519 here: the .sig check cannot be proven");
        return Ok(());
    }
    let name = format!("busbar-oracle-linux-aarch64-{}", "a".repeat(40));
    let hex = "b".repeat(64);
    let msg = st.join("msg");
    put(&msg, &format!("{name}\n{hex}\n"))?;
    let (a_sig, u_sig) = (st.join("a.sig"), st.join("u.sig"));
    put(&a_sig, &sign(&a, &msg, &st.join("a.bin")))?;
    put(&u_sig, &sign(&u, &msg, &st.join("u.bin")))?;
    // [u, a]: `&both[1..]` is a alone, `&both[..1]` is u alone.
    let both = [read_trimmed(&u_pub), read_trimmed(&a_pub)];
    let trusted: Vec<String> = ORACLE_RELEASE_KEY_PEMS
        .iter()
        .map(|pem| String::from(*pem))
        .collect();
    let verifies = |sig: &Path, keys: &[String]| verify_judge_sig(&name, &hex, sig, keys).is_ok();
    r.check(
        verifies(&a_sig, &both),
        "a .sig by the second listed key verifies",
        "a .sig by a listed key was refused",
    );
    r.check(
        !verifies(&u_sig, &both[1..]),
        "a .sig by a key not on the list is refused",
        "a .sig by a key not on the list verified",
    );
    r.check(
        !verifies(&u_sig, &trusted),
        "busbar-release's trusted keys refuse a .sig by an unknown key",
        "busbar-release's trusted keys accepted a .sig by an unknown key",
    );
    // a .sig by a key that LEFT the list (the earlier key's case, proven with a key held here)
    r.check(
        verifies(&a_sig, &both) && !verifies(&a_sig, &both[..1]),
        "a .sig by a key removed from the list is refused",
        "a .sig by a removed key still verified",
    );
    r.check(
        !verifies(&a_sig, &[]),
        "no trusted key verifies nothing",
        "a .sig verified against no key at all",
    );
    Ok(())
}

// ---- ci-token-selftest -------------------------------------------------------------------------------

/// What a scratch shim run is stripped of before its scenario plants anything.
const SHIM_CLEARED: &[&str] = &[
    "MODERNCI",
    "MODERNCI_JOB",
    "MODERNCI_TO_SHA",
    "MODERNCI_HEAD",
    "MODERNCI_COMMIT",
    "BUSBAR_ORACLE_JUDGE_PATH",
    "BUSBAR_ORACLE_RUST_BIN",
    "CI",
    "BUSBAR_RELEASE_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "BUSBAR_ORACLE_RELEASE_REPO",
    "BUSBAR_ORACLE_RELEASE_REF",
    "BUSBAR_ORACLE_SHA256_LINUX_X86_64",
    "BUSBAR_ORACLE_SHA256_LINUX_AARCH64",
    "BUSBAR_ORACLE_CRATE",
    "BUSBAR_ORACLE_BIN",
    "BUSBAR_GOLDEN_1_5_5_TREE",
    "BUSBAR_ORACLE_DATA",
    "BUSBAR_ORACLE_PRODUCT_ROOT",
    "BUSBAR_ORACLE_TOOL_DIR",
    "BUSBAR_RELEASE_CHECKOUT",
    "MODERNCI_CACHE_DIR",
    "CARGO_TARGET_DIR",
];

/// A CI RUN READS NO TOKEN (OWNER 2026-10-26, "cut it"), end to end. The binary under test runs in
/// a scratch checkout with the branch file's judge env set and EVERY token name planted; the
/// release API (curl) and git are logging fakes and `uname -s` answers $FAKE_OS. The GREEN twin, a
/// local run (no CI marker), still hands git its token, so the CI rows prove the rule and not a
/// broken fake.
fn ci_token(r: &mut Report, st: &Path, under: &Path) -> io::Result<()> {
    let nosha = "f".repeat(64);
    let cfg: [(&str, &str); 6] = [
        (
            "BUSBAR_ORACLE_RELEASE_REPO",
            "https://github.com/GetBusbar/busbar-release.git",
        ),
        (
            "BUSBAR_ORACLE_RELEASE_REF",
            "151ad095a21819dca97e8bdb3384c3c3eb2eb806",
        ),
        ("BUSBAR_ORACLE_SHA256_LINUX_X86_64", nosha.as_str()),
        ("BUSBAR_ORACLE_SHA256_LINUX_AARCH64", nosha.as_str()),
        ("BUSBAR_ORACLE_CRATE", "busbar-release-oracle"),
        ("BUSBAR_ORACLE_BIN", "busbar-oracle"),
    ];
    // fakes on PATH: uname -s answers $FAKE_OS (uname -m is the host's); curl logs, keeps any config
    // it is handed on stdin (-K -: where a token would ride) and fails (no fetch); git logs whether
    // it was handed a credential header (GIT_CONFIG_KEY_0) and never clones (no network).
    let fakebin = st.join("fakebin");
    let s = st.display();
    let (real_uname, real_git) = (which("uname"), which("git"));
    script(
        &fakebin.join("uname"),
        &format!(
            "#!/bin/sh\nif [ \"$1\" = -s ]; then echo \"$FAKE_OS\"; else exec {real_uname} \"$@\"; fi\n"
        ),
    )?;
    script(
        &fakebin.join("curl"),
        &format!(
            "#!/bin/sh\necho \"curl $*\" >>\"{s}/curl\"\ncase \"$*\" in *\"-K -\"*) cat >>\"{s}/curl.stdin\";; esac\nexit 22\n"
        ),
    )?;
    script(
        &fakebin.join("git"),
        &format!(
            "#!/bin/sh\n[ -n \"${{GIT_CONFIG_KEY_0:-}}\" ] && echo \"git-credential $GIT_CONFIG_KEY_0\" >>\"{s}/git\"\ncase \" $* \" in *\" clone \"*) echo \"git clone\" >>\"{s}/git\"; exit 128;; esac\nexec {real_git} \"$@\"\n"
        ),
    )?;
    let repo = st.join("repo");
    quiet(Command::new("git").args(["init", "-q"]).arg(&repo));
    let data = repo.join("testing/shadow-oracle");
    put(
        &data.join("cells.json"),
        "{\"cells\": [{\"id\": \"fam|a\"}]}\n",
    )?;
    put(
        &data.join("accepted-differences.json"),
        "{\"accepted\": []}\n",
    )?;
    let log = |file: &str| std::fs::read_to_string(st.join(file)).unwrap_or_default();
    let path_env = format!(
        "{}:{}",
        fakebin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // One run of the binary under test: the config's judge env and every token set, plus `marker`.
    let shim = |marker: Option<(&str, &str)>, os: &str| -> Ran {
        for file in ["curl", "curl.stdin", "git"] {
            let _ = std::fs::write(st.join(file), "");
        }
        let mut command = oracle_cmd(under, &repo, &["--help"]);
        command.current_dir(&repo);
        for name in SHIM_CLEARED {
            command.env_remove(name);
        }
        command.env("PATH", &path_env).envs(cfg).env("FAKE_OS", os);
        for name in TOKENS {
            command.env(name, PLANT);
        }
        if let Some((name, value)) = marker {
            command.env(name, value);
        }
        ran(command)
    };
    let detail = |got: &Ran| {
        let err: String = got
            .err
            .chars()
            .take(400)
            .map(|c| if c == '\n' { ' ' } else { c })
            .collect();
        format!(" (rc={}; {err})", got.rc)
    };
    let no_token_read = || log("curl").is_empty() && !log("curl.stdin").contains("plant-token");
    // (e) under ModernCI, the config's judge env, NO judge path handed over, on Linux: NO JUDGE
    // naming BUSBAR_ORACLE_JUDGE_PATH, nothing fetched, no token read.
    let got = shim(Some(("MODERNCI", "1")), "Linux");
    if got.rc != 0
        && no_token_read()
        && got
            .err
            .contains("NO JUDGE: ModernCI handed over no BUSBAR_ORACLE_JUDGE_PATH")
    {
        r.ok("(e) under ModernCI, the config's judge, no judge path, every token set: NO JUDGE, zero fetches, no token read");
    } else {
        r.bad(&format!(
            "(e) a ModernCI run without a judge path fetched the judge ({} fetches){}",
            log("curl").lines().count(),
            detail(&got)
        ));
    }
    // (f) a bare CI= run on Linux, every token set: the release API is never called.
    let got = shim(Some(("CI", "true")), "Linux");
    if got.rc != 0 && no_token_read() && got.err.contains("a CI run never reads busbar-release") {
        r.ok("(f) a bare CI= run on Linux, every token set: NO JUDGE, the release API never called, no token read");
    } else {
        r.bad(&format!(
            "(f) a CI= run reached the release API ({} fetches; token on curl's stdin: {}){}",
            log("curl").lines().count(),
            log("curl.stdin")
                .lines()
                .filter(|line| line.contains("plant-token"))
                .count(),
            detail(&got)
        ));
    }
    // (g) a bare CI= run off Linux, every token set: the engine clone gets no credential header.
    let got = shim(Some(("CI", "true")), "Darwin");
    let git_log = log("git");
    if git_log.contains("git clone") && !git_log.contains("git-credential") {
        r.ok(
            "(g) a bare CI= run off Linux, every token set: the engine clone carries no credential",
        );
    } else {
        r.bad(&format!(
            "(g) a CI= run handed git a credential ({}){}",
            git_log.replace('\n', ";"),
            detail(&got)
        ));
    }
    // GREEN twin of (g): a LOCAL run (no CI marker) still authenticates its engine clone.
    let got = shim(None, "Darwin");
    let git_log = log("git");
    if git_log.contains("git-credential") {
        r.ok("(g) GREEN twin: a local run's engine clone still uses the token");
    } else {
        r.bad(&format!(
            "(g) twin: a local run's clone carried no credential ({}){}",
            git_log.replace('\n', ";"),
            detail(&got)
        ));
    }
    Ok(())
}
