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
