// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRANSPORT (ABI-MIN3-INTERFACE §14): TRANSPORT-SECURITY-POLICY §8 tests 1-15 (replaces C-TLS-REFUSED, rule
//! 14). Test 11 is W1-X1's source check. The generic ENDPOINT match is `FakeNeeds::undeclared`, run by every suite.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! Core halves that need no booted fixture run now: the one verdict every kind shares (arms 2, 3, 6 and 15 at
//! `transport_verdict`) and the `insecure_transport` setting grammar (arm 7). The arms that boot a fixture
//! plugin through `Registry` (a `plugin!`-built image per kind that declares an ENDPOINT, then `check`/`open`)
//! stay ignored until that fixture set exists; each reason names what is missing.

use busbar_plugin_abi::host_side::caller::{transport_verdict, Accept, Verdict};
use busbar_plugin_abi::need::need_flag::{TLS_INBAND, TLS_MUTUAL, TLS_NONE, TLS_REQUIRED};

const NOTHING: Accept = Accept(0);
const PLAINTEXT: Accept = Accept(Accept::PLAINTEXT);
const UNVERIFIED: Accept = Accept(Accept::UNVERIFIED_TLS);

#[test]
fn the_verdict_has_no_loopback_exemption() {
    for dest in [
        "127.0.0.1:5432",
        "[::1]:5432",
        "localhost:5432",
        "127.1.2.3:80",
    ] {
        assert_eq!(
            transport_verdict(NOTHING, TLS_NONE, dest),
            Verdict::Refuse,
            "{dest}"
        );
        assert_eq!(
            transport_verdict(UNVERIFIED, TLS_NONE, dest),
            Verdict::Refuse,
            "{dest}: unverified_tls does not admit plaintext"
        );
        assert_eq!(
            transport_verdict(PLAINTEXT, TLS_NONE, dest),
            Verdict::Plain,
            "{dest}: only an acceptance does"
        );
    }
    assert_eq!(
        transport_verdict(NOTHING, TLS_NONE, "http://localhost:8080/x"),
        Verdict::Refuse
    );
}

#[test]
fn the_verdict_has_no_unix_exemption() {
    for dest in ["unix:/var/run/db.sock", "UNIX:/tmp/x.sock"] {
        for tls in [TLS_NONE, TLS_REQUIRED] {
            assert_eq!(
                transport_verdict(NOTHING, tls, dest),
                Verdict::Refuse,
                "{dest} {tls}"
            );
            assert_eq!(
                transport_verdict(PLAINTEXT, tls, dest),
                Verdict::Plain,
                "{dest} {tls}: admitted with accept: plaintext, whatever the kind"
            );
        }
    }
}

#[test]
fn each_acceptance_bit_admits_exactly_what_it_names() {
    for tls in [TLS_REQUIRED, TLS_MUTUAL, TLS_INBAND] {
        assert_eq!(
            transport_verdict(NOTHING, tls, "db.internal:5432"),
            Verdict::Verify
        );
        assert_eq!(
            transport_verdict(UNVERIFIED, tls, "db.internal:5432"),
            Verdict::WaiveVerify
        );
        assert_eq!(
            transport_verdict(PLAINTEXT, tls, "db.internal:5432"),
            Verdict::Verify,
            "plaintext does not waive verification"
        );
    }
    assert_eq!(
        transport_verdict(UNVERIFIED, TLS_NONE, "db.internal:5432"),
        Verdict::Refuse,
        "unverified_tls does not admit TLS_NONE"
    );
    assert_eq!(
        transport_verdict(
            Accept(Accept::PLAINTEXT | Accept::UNVERIFIED_TLS),
            TLS_NONE,
            "db:1"
        ),
        Verdict::Plain
    );
}

#[test]
#[ignore = "owner: W1-K7 (blocked: needs a fixture plugin per kind (store, auth, secret, export, hook) that declares a TLS_NONE ENDPOINT, booted through Registry check/open; the BUSBAR-3160 text is `judge_endpoints` in plugin-loader instance.rs, private, and --check-config/admin DRY_RUN need the boot path)"]
fn transport_plaintext_refused_at_check() {
    todo!("owner: W1-K7 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K7 (blocked: the booted-fixture half of arm 2; its verdict half is `the_verdict_has_no_loopback_exemption`)"]
fn transport_no_loopback_exemption() {
    todo!("owner: W1-K7 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A (blocked: the booted-fixture half of arm 3 (store and non-store fixture, `unix:` ENDPOINT); its verdict half is `the_verdict_has_no_unix_exemption`)"]
fn transport_no_unix_exemption() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A (blocked: a plugin!-built fixture with zero endpoints that OPENs TLS_NONE through the connector, with the audit row read back; no such fixture or connector harness in busbar-plugin-test)"]
fn transport_in_process_needs_nothing() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A (blocked: needs a booted fixture and the log/health/admin readback (BUSBAR-3162 once per boot and reload, inst.runtime.transport, the `transport` health check) plus the self-signed TLS server; kernel boot is not reachable from this crate)"]
fn transport_accept_plaintext_visible() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K8C (blocked: `config.insecure_transport_accepted` and `egress.insecure_transport_refused` are not in the kernel's AUDIT_ACTIONS (crates/busbar-kernel/src/audit/auditlog.rs), so x-busbar-audit-actions lacks them; OUTSTANDING A5 AUDIT_ACTIONS tail)"]
fn admin_dry_run_runtime_transport_and_health() {
    todo!("owner: W1-K8C (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A (blocked: a self-signed TLS server fixture and a connector dial over a fixture plugin's OPEN, plus the PoolKey `verify` bit read across two instances; the verdict half is `each_acceptance_bit_admits_exactly_what_it_names`)"]
fn transport_accept_unverified_tls() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

/// Arm 7 (TRANSPORT-SECURITY-POLICY §4): the `insecure_transport` object's grammar, through the kernel's own
/// config type. Every refusal is BUSBAR-3163 and names `<path>.insecure_transport.<key>`. The unused-acceptance
/// refusal needs a plugin's declared endpoints, so it runs with the booted-fixture arms.
#[test]
fn transport_setting_validation() {
    use busbar_kernel::config::min3::{InsecureTransport, InsecureTransportDoc};

    fn parse(yaml: &str) -> Result<InsecureTransport, String> {
        let doc: InsecureTransportDoc =
            busbar_contract::yaml::from_str(yaml).map_err(|e| e.to_string())?;
        doc.resolve("store.main")
    }

    for (yaml, key) in [
        ("{ accept: plaintext }", "reason"),
        ("{ accept: plaintext, reason: \"\" }", "reason"),
        ("{ accept: plaintext, reason: \"   \" }", "reason"),
        (
            "{ accept: plaintext, reason: \"<why this instance needs it>\" }",
            "reason",
        ),
        ("{ accept: plaintext, reason: \"two\\nlines\" }", "reason"),
        ("{ accept: [], reason: r }", "accept"),
        ("{ accept: [plaintext, plaintext], reason: r }", "accept"),
    ] {
        let err = parse(yaml).expect_err(yaml);
        assert!(err.starts_with("BUSBAR-3163"), "{yaml}: {err}");
        assert!(
            err.contains(&format!("store.main.insecure_transport.{key}")),
            "{yaml}: {err}"
        );
    }
    let long = format!("{{ accept: plaintext, reason: \"{}\" }}", "x".repeat(257));
    let err = parse(&long).expect_err("257 characters");
    assert!(
        err.starts_with("BUSBAR-3163") && err.contains("256"),
        "{err}"
    );
    parse(&format!(
        "{{ accept: plaintext, reason: \"{}\" }}",
        "x".repeat(256)
    ))
    .expect("256 is the limit");
    assert!(parse("{ accept: yes, reason: r }").is_err(), "accept: yes");
    assert!(parse("{ accept: plaintext, reason: r, extra: 1 }")
        .expect_err("an unknown key")
        .contains("unknown field"));
    assert!(parse("{ reason: r }").is_err(), "accept is required");
}

#[test]
#[ignore = "owner: W1-C1A (blocked: a fixture that declares TLS_INBAND and OPENs TLS_NONE through the connector (DENIED before DNS, `egress.insecure_transport_refused`, no connect) and one that dials TLS_NONE in `open`; connector harness absent)"]
fn transport_need_time_authoritative() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A (blocked: needs the self-signed server fixture and a connector dial with `verify: pin` / `trust_anchors` options; BUSBAR-3161 text lives in the connector's TLS dial, no harness here)"]
fn transport_verify_options() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-L2 (blocked: `decode_endpoints` in plugin-loader instance.rs is private and reachable only through a fixture plugin's check answer; needs a plugin!-built fixture that answers hand-written ENDPOINT records (more than 16, over-long dest, unknown op, egress > 4, bit 0x200))"]
fn endpoint_record_decode() {
    todo!("owner: W1-L2 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-X1 (blocked: the source check has no scanner in this crate for `is_loopback`/`names_loopback`/`plaintext` field/`limits.plaintext` across core and every plugin repo; the plugin-repo half is the fleet lint)"]
fn transport_source_checks() {
    todo!("owner: W1-X1 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K8C (blocked: the three transport audit actions are absent from the kernel's AUDIT_ACTIONS (auditlog.rs) and from the admin x-busbar-audit-actions component; OUTSTANDING A5 AUDIT_ACTIONS tail)"]
fn audit_actions_catalogue() {
    todo!("owner: W1-K8C (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K9 (blocked: needs busbar-migrate and a 1.5.5-shaped config corpus with the acceptance line; busbar-migrate is not a dev-dependency of this crate and the oracle cells (S2-MOB-C3 / QM1) are not on dev)"]
fn upgrade_from_155_shape_carries_acceptance() {
    todo!("owner: W1-K9 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A (blocked: needs a transport-kind fixture with a `ws://`/h2c upstream and K7's core-known client endpoints judged at check; boot path and the self-signed `wss://` server are absent here)"]
fn transport_instance_client_dial() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A (blocked: a fixture declaring no endpoint plus the self-signed TLS_INBAND upgrade server; the verdict half is covered by `each_acceptance_bit_admits_exactly_what_it_names`)"]
fn transport_undeclared_acceptance_kept() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}
