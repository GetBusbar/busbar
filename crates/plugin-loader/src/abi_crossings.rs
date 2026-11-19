// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `abi_crossings`: no secret crosses the interface in the clear toward a plugin that does not own it
//! (DESIGN-interface-revision F2, G.1 item 7).
//!
//! The harness half of the security test. A test arms the process's crossing recorder before the engine
//! starts, plants every provider credential and every resolved secret of the run with the instances
//! allowed to read it, drives traffic, then takes the verdict. The verdict is a pass only if:
//!
//! - at least one secret was planted and at least one call crossed toward every kind the test names
//!   (a run that planted nothing or crossed nothing proves nothing, and is a failure);
//! - no planted secret, in its own form or as hex or base64, was found in any head, text, blob or lent
//!   pair of any call, or in any resume, toward an instance that is not one of its owners.
//!
//! The recorder is the one hook on the one crossing place (`call::record`), so there is no call it does
//! not see: the seven adapters have no other way to reach a table entry.

use std::sync::OnceLock;

use busbar_plugin_abi::types::KindCode;

use crate::call::record::{self, Crossings, Leak};

static ARMED: OnceLock<Crossings> = OnceLock::new();

/// Arm the process's recorder. Idempotent; None when another recorder was installed first (then this
/// run cannot be judged and the caller must fail).
pub fn arm() -> Option<&'static Crossings> {
    let crossings = ARMED.get_or_init(Crossings::new);
    // `install` answers false on the second call of this function too; the recorder is ours if it was
    // ever installed by us, which `ARMED` being set before any other installer guarantees only when the
    // first install succeeded.
    static OURS: OnceLock<bool> = OnceLock::new();
    OURS.get_or_init(|| record::install(crossings))
        .then_some(crossings)
}

/// What a run came to.
#[derive(Debug)]
pub struct Verdict {
    pub planted: usize,
    pub crossings: u64,
    pub bytes: u64,
    /// Calls toward each kind, index `KindCode as usize - 1`.
    pub by_kind: [u64; 7],
    pub leaks: Vec<Leak>,
}

/// The verdict of the armed recorder so far. None when `arm` was never called.
pub fn verdict() -> Option<Verdict> {
    let crossings = ARMED.get()?;
    Some(Verdict::of(crossings))
}

impl Verdict {
    pub fn of(crossings: &Crossings) -> Verdict {
        Verdict {
            planted: crossings.planted(),
            crossings: crossings.crossings(),
            bytes: crossings.bytes(),
            by_kind: KindCode::ALL.map(|kind| crossings.toward_kind(kind)),
            leaks: crossings.leaks(),
        }
    }

    /// Every way this run fails, one line each; empty for a pass. `kinds` are the kinds the run must
    /// have crossed toward.
    pub fn failures(&self, kinds: &[KindCode]) -> Vec<String> {
        let mut out = Vec::new();
        if self.planted == 0 {
            out.push("no secret was planted: the run proves nothing".to_string());
        }
        if self.crossings == 0 {
            out.push("no call crossed the interface: the recorder saw nothing".to_string());
        }
        for kind in kinds {
            if self.by_kind[*kind as usize - 1] == 0 {
                out.push(format!(
                    "no call crossed toward a {} plugin: that kind was not exercised",
                    kind.word()
                ));
            }
        }
        for leak in &self.leaks {
            out.push(format!(
                "LEAK: secret '{}' crossed toward {} instance '{}' (image {}) in table entry {}, at {:?}",
                leak.label,
                leak.kind.word(),
                leak.name,
                leak.plugin,
                leak.method,
                leak.place
            ));
        }
        out
    }

    /// The summary line a passing run prints.
    pub fn summary(&self) -> String {
        format!(
            "abi_crossings: {} crossings, {} bytes scanned, {} secrets planted, {} leaks",
            self.crossings,
            self.bytes,
            self.planted,
            self.leaks.len()
        )
    }

    /// Panics with every failure; prints the summary on a pass.
    pub fn require_clean(&self, kinds: &[KindCode]) {
        let failures = self.failures(kinds);
        assert!(
            failures.is_empty(),
            "{}\n{}",
            self.summary(),
            failures.join("\n")
        );
        println!("{}", self.summary());
    }
}

// ---- the witness: judging the real binary from outside the process ----

/// The file of planted secrets a witness build reads at start: one secret a line,
/// `label<TAB>hex of the secret<TAB>owner,owner` (owners are instance names; the third field may be empty).
pub const PLANTS_ENV: &str = "BUSBAR_CROSSING_WITNESS_PLANTS";
/// The file a witness build writes its verdict to (replaced whole each time it changes).
pub const VERDICT_ENV: &str = "BUSBAR_CROSSING_WITNESS_VERDICT";

/// One line of a plant file.
pub fn plant_line(label: &str, secret: &[u8], owners: &[&str]) -> String {
    format!("{label}\t{}\t{}\n", hex::encode(secret), owners.join(","))
}

/// Arm the recorder from the two environment variables. Called once when the loader's process resources
/// are made, in a witness build only. Unset variables: nothing is armed (a witness build then runs as
/// any other). A plant file that cannot be read or parsed is an error the caller refuses to start on:
/// a witness that planted less than the test wrote would pass for the wrong reason.
pub fn arm_from_env() -> Result<bool, String> {
    let (Some(plants), Some(_verdict)) =
        (std::env::var_os(PLANTS_ENV), std::env::var_os(VERDICT_ENV))
    else {
        return Ok(false);
    };
    let text = std::fs::read_to_string(&plants)
        .map_err(|e| format!("crossing witness: the plant file cannot be read: {e}"))?;
    let crossings =
        arm().ok_or("crossing witness: another crossing recorder was installed first")?;
    for (at, line) in text.lines().enumerate() {
        let mut fields = line.split('\t');
        let (Some(label), Some(secret)) = (fields.next(), fields.next()) else {
            return Err(format!(
                "crossing witness: plant line {} has no secret",
                at + 1
            ));
        };
        let secret = hex::decode(secret)
            .map_err(|_| format!("crossing witness: plant line {} is not hex", at + 1))?;
        let owners: Vec<&str> = fields
            .next()
            .unwrap_or("")
            .split(',')
            .filter(|owner| !owner.is_empty())
            .collect();
        if !crossings.plant(label, &secret, &owners) {
            return Err(format!(
                "crossing witness: plant line {} is shorter than {} bytes",
                at + 1,
                record::SHORTEST
            ));
        }
    }
    Ok(true)
}

/// Write the verdict file if anything crossed since it was last written. Called from the loader's
/// watchdog thread on each of its scans, so the file is at most one scan behind the traffic and needs no
/// orderly shutdown to exist. Written to a sibling file and renamed, so a reader never sees half of one.
pub fn tick() {
    static WRITTEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
    let (Some(crossings), Some(path)) = (ARMED.get(), std::env::var_os(VERDICT_ENV)) else {
        return;
    };
    let now = crossings.crossings();
    if WRITTEN.swap(now, std::sync::atomic::Ordering::Relaxed) == now {
        return;
    }
    let path = std::path::PathBuf::from(path);
    let mut staged = path.clone().into_os_string();
    staged.push(".part");
    if std::fs::write(&staged, Verdict::of(crossings).to_text()).is_ok() {
        let _ = std::fs::rename(&staged, &path);
    }
}

impl Verdict {
    /// The verdict as the witness writes it: counts, then one line per leak. No secret is in it.
    pub fn to_text(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "planted\t{}", self.planted);
        let _ = writeln!(out, "crossings\t{}", self.crossings);
        let _ = writeln!(out, "bytes\t{}", self.bytes);
        for kind in KindCode::ALL {
            let _ = writeln!(
                out,
                "kind\t{}\t{}",
                kind.word(),
                self.by_kind[kind as usize - 1]
            );
        }
        for leak in &self.leaks {
            let _ = writeln!(
                out,
                "leak\t{}\t{}\t{}\t{}\t{}\t{:?}",
                leak.label,
                leak.kind.word(),
                leak.name,
                leak.plugin,
                leak.method,
                leak.place
            );
        }
        out
    }

    /// Every way a written verdict fails, one line each; empty for a pass. The test side of the
    /// witness: it reads the file the binary wrote and never needs the recorder's types. `planted` is
    /// how many secrets the test wrote to the plant file; `kinds` are the kind words the run must have
    /// crossed toward. A file that cannot be understood is a failure, never a pass.
    pub fn failures_of_text(text: &str, planted: usize, kinds: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        let (mut seen_planted, mut crossings) = (None, None);
        let mut by_kind: Vec<(&str, u64)> = Vec::new();
        for line in text.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            match fields.as_slice() {
                ["planted", n] => seen_planted = n.parse::<usize>().ok(),
                ["crossings", n] => crossings = n.parse::<u64>().ok(),
                ["bytes", _] => {}
                ["kind", word, n] => match n.parse::<u64>() {
                    Ok(n) => by_kind.push((*word, n)),
                    Err(_) => out.push(format!("unreadable verdict line: {line}")),
                },
                ["leak", label, kind, name, plugin, method, place] => out.push(format!(
                    "LEAK: secret '{label}' crossed toward {kind} instance '{name}' (image {plugin}) in table entry {method}, at {place}"
                )),
                _ => out.push(format!("unreadable verdict line: {line}")),
            }
        }
        if seen_planted != Some(planted) {
            out.push(format!(
                "the witness planted {seen_planted:?} secrets; the test wrote {planted}"
            ));
        }
        if planted == 0 {
            out.push("no secret was planted: the run proves nothing".to_string());
        }
        if crossings.is_none_or(|n| n == 0) {
            out.push("no call crossed the interface: the recorder saw nothing".to_string());
        }
        for kind in kinds {
            if !by_kind.iter().any(|(word, n)| word == kind && *n > 0) {
                out.push(format!(
                    "no call crossed toward a {kind} plugin: that kind was not exercised"
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::frame::{Frame, Mono};
    use crate::call::record::{Place, Recorder, Seen, Who};

    const PROVIDER_KEY: &[u8] = b"sk-live-planted-7c41d09be2f6a8-upstream-provider-key";
    const RESOLVED: &[u8] = b"resolved-secret-51f0aa93c7de4b12-from-the-vault";

    fn who(kind: KindCode, plugin: &'static str, name: &'static str, slot: u32) -> Who<'static> {
        Who {
            kind,
            plugin,
            name,
            instance: u64::from(slot),
            slot,
        }
    }

    /// One call toward `to` carrying `blob` as its only byte argument.
    fn cross(rec: &Crossings, to: &Who<'_>, method: u8, blob: &[u8]) {
        let frame = Frame::new((), [], [blob]);
        let call = frame.call(Mono::NONE);
        rec.toward(to, method, &Seen::of(0, &call, &[]));
    }

    /// The run every case starts from: the vault resolves a secret, the auth plugin mints with it, a
    /// plane and a transport carry a request whose head holds only a sealed mark.
    fn honest_run(rec: &Crossings) {
        rec.plant("provider-key", PROVIDER_KEY, &["vault", "operator-auth"]);
        rec.plant("vault-secret", RESOLVED, &["vault"]);
        cross(
            rec,
            &who(KindCode::Secret, "busbar-secret-vault", "vault", 1),
            0,
            b"vault://kv/provider",
        );
        cross(
            rec,
            &who(KindCode::Auth, "busbar-auth-apikey", "operator-auth", 2),
            3,
            PROVIDER_KEY,
        );
        cross(
            rec,
            &who(KindCode::Plane, "busbar-plane-llm", "llm", 3),
            0,
            b"{\"model\":\"m\"}",
        );
        cross(
            rec,
            &who(KindCode::Transport, "busbar-transport-http", "http", 4),
            2,
            b"POST /v1/messages HTTP/1.1\r\nhost: provider.example\r\n",
        );
    }

    const KINDS: [KindCode; 4] = [
        KindCode::Secret,
        KindCode::Auth,
        KindCode::Plane,
        KindCode::Transport,
    ];

    #[test]
    fn an_honest_run_is_clean_and_says_what_it_scanned() {
        let rec = Crossings::new();
        honest_run(&rec);
        let verdict = Verdict::of(&rec);
        assert_eq!(verdict.failures(&KINDS), Vec::<String>::new());
        assert_eq!(verdict.crossings, 4);
        assert!(verdict.summary().ends_with("2 secrets planted, 0 leaks"));
    }

    /// THE RED HALF. A provider credential written into the head a transport is handed is the leak the
    /// sealed-credential design exists to stop; the test must fail on it, naming the secret by label,
    /// the instance and the place, and never printing the secret.
    #[test]
    #[should_panic(
        expected = "LEAK: secret 'provider-key' crossed toward transport instance 'http'"
    )]
    fn a_provider_credential_handed_to_a_transport_fails_the_run() {
        let rec = Crossings::new();
        honest_run(&rec);
        let mut head = b"POST /v1/messages HTTP/1.1\r\nx-api-key: ".to_vec();
        head.extend_from_slice(PROVIDER_KEY);
        cross(
            &rec,
            &who(KindCode::Transport, "busbar-transport-http", "http", 4),
            2,
            &head,
        );
        Verdict::of(&rec).require_clean(&KINDS);
    }

    #[test]
    fn a_resolved_secret_handed_to_a_plane_or_a_hook_fails_the_run() {
        let rec = Crossings::new();
        honest_run(&rec);
        cross(
            &rec,
            &who(KindCode::Plane, "busbar-plane-llm", "llm", 3),
            2,
            RESOLVED,
        );
        cross(
            &rec,
            &who(KindCode::Hook, "busbar-hook-ranking", "ranking", 5),
            0,
            RESOLVED,
        );
        let verdict = Verdict::of(&rec);
        let failures = verdict.failures(&KINDS);
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(failures.iter().all(|line| line.contains("'vault-secret'")));
        assert!(
            failures
                .iter()
                .all(|line| !line.contains("51f0aa93c7de4b12")),
            "a failure line never prints the secret"
        );
        assert!(verdict
            .leaks
            .iter()
            .all(|leak| leak.place == Place::Blob(0)));
    }

    #[test]
    fn a_secret_given_back_to_a_non_owner_in_a_resume_fails_the_run() {
        let rec = Crossings::new();
        honest_run(&rec);
        // The plane (slot 3) asked for a step and is resumed with bytes that hold the provider key.
        rec.resumed(3, PROVIDER_KEY);
        let verdict = Verdict::of(&rec);
        assert_eq!(verdict.leaks.len(), 1);
        assert_eq!(verdict.leaks[0].place, Place::Resume);
        assert_eq!(&*verdict.leaks[0].name, "llm");
    }

    #[test]
    fn a_run_that_planted_nothing_or_missed_a_kind_is_a_failure() {
        let rec = Crossings::new();
        cross(
            &rec,
            &who(KindCode::Plane, "busbar-plane-llm", "llm", 3),
            0,
            b"{}",
        );
        let failures = Verdict::of(&rec).failures(&KINDS);
        assert!(failures
            .iter()
            .any(|line| line.starts_with("no secret was planted")));
        assert!(failures
            .iter()
            .any(|line| line.contains("toward a transport plugin")));
        assert!(Verdict::of(&Crossings::new())
            .failures(&[])
            .iter()
            .any(|line| line.starts_with("no call crossed")));
    }
}

#[cfg(test)]
mod witness_tests {
    use super::*;
    use crate::call::frame::{Frame, Mono};
    use crate::call::record::{Recorder, Seen, Who};

    const KEY: &[u8] = b"sk-live-planted-99aa01bb22cc33dd-upstream-provider-key";

    fn run(leak: bool) -> Verdict {
        let rec = Crossings::new();
        rec.plant("provider-key", KEY, &["vault"]);
        let http = Who {
            kind: KindCode::Transport,
            plugin: "busbar-transport-http",
            name: "http",
            instance: 4,
            slot: 4,
        };
        let blob: &[u8] = if leak { KEY } else { b"GET / HTTP/1.1\r\n" };
        let frame = Frame::new((), [], [blob]);
        let call = frame.call(Mono::NONE);
        rec.toward(&http, 2, &Seen::of(0, &call, &[]));
        Verdict::of(&rec)
    }

    #[test]
    fn a_clean_verdict_reads_back_clean() {
        let text = run(false).to_text();
        assert_eq!(
            Verdict::failures_of_text(&text, 1, &["transport"]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_leak_survives_the_file_and_the_file_holds_no_secret() {
        let text = run(true).to_text();
        let failures = Verdict::failures_of_text(&text, 1, &["transport"]);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0]
            .starts_with("LEAK: secret 'provider-key' crossed toward transport instance 'http'"));
        assert!(!text.contains("99aa01bb22cc33dd"));
        assert!(!text.contains(&hex::encode(KEY)));
    }

    #[test]
    fn a_verdict_that_planted_less_than_the_test_wrote_is_a_failure() {
        let text = run(false).to_text();
        assert!(Verdict::failures_of_text(&text, 2, &["transport"])
            .iter()
            .any(|line| line.starts_with("the witness planted Some(1) secrets")));
    }

    #[test]
    fn an_empty_or_garbled_file_is_a_failure_never_a_pass() {
        assert!(!Verdict::failures_of_text("", 1, &[]).is_empty());
        assert!(
            Verdict::failures_of_text("planted\t1\ncrossings\t5\nnonsense\n", 1, &[])
                .iter()
                .any(|line| line.starts_with("unreadable verdict line"))
        );
        assert!(
            Verdict::failures_of_text("planted\t1\ncrossings\t5\n", 1, &["auth"])
                .iter()
                .any(|line| line.contains("toward a auth plugin"))
        );
    }

    #[test]
    fn a_plant_line_is_label_hex_owners() {
        assert_eq!(
            plant_line("k", b"\x01\xff", &["vault", "operator-auth"]),
            "k\t01ff\tvault,operator-auth\n"
        );
    }
}
