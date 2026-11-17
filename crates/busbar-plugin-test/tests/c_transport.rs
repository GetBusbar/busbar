// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRANSPORT (ABI-MIN3-INTERFACE §14): TRANSPORT-SECURITY-POLICY §8 tests 1-15 (replaces C-TLS-REFUSED, rule
//! 14). Test 11 is W1-X1's source check. The generic ENDPOINT match is `FakeNeeds::undeclared`, run by every suite.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! Core halves that need no booted fixture: the one verdict every kind shares (arms 2, 3, 6 and 15 at
//! `transport_verdict`) and the `insecure_transport` setting grammar (arm 7). Booted arms admit a `plugin!`-built
//! fixture per kind (`fixtures/min3_endpoints.rs`: store, auth, secret, export, hook, transport, each declaring
//! the ENDPOINTs its config names) into the suite harness (`Registry<FakeNeeds>`) and judge them at `check`, where
//! core refuses BUSBAR-3160/3163 before any open and any dial. Arm 10 reaches the loader's ENDPOINT decode through
//! a hand-wired image whose CHECK answer carries records the SDK writer will not emit. Where only part of an arm
//! runs here, the arm stays ignored naming what is missing and a sibling test carries the part that runs.

use busbar_plugin_abi::fail::refused::R_CONFIG;
use busbar_plugin_abi::host_side::caller::{transport_verdict, Accept, InstanceLimits, Verdict};
use busbar_plugin_abi::need::need_flag::{
    TLS_INBAND, TLS_MASK, TLS_MUTUAL, TLS_NONE, TLS_REQUIRED,
};
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_loader::instance::{DeclaredEndpoint, InstanceSpec, OpenError};
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;

use crate::min3_endpoints as fixture;

const NOTHING: Accept = Accept(0);
const PLAINTEXT: Accept = Accept(Accept::PLAINTEXT);
const UNVERIFIED: Accept = Accept(Accept::UNVERIFIED_TLS);
const BOTH: Accept = Accept(Accept::PLAINTEXT | Accept::UNVERIFIED_TLS);

#[test]
fn case_spec_preserves_explicit_limits_and_endpoint_observations() {
    use busbar_plugin_test::suites::harness::{Accept, InstanceLimits, OpenPurpose};

    let h = admit(fixture::hook::PLUGIN.plugin());
    let config = declaring(&["none 0 localhost:8080"]);
    let mut spec = h.spec("explicit-limits", &config);
    spec.purpose = OpenPurpose::ConvertUnstamped;
    assert!(
        h.check_spec(&spec).is_err(),
        "plaintext requires explicit acceptance"
    );
    spec.limits = InstanceLimits {
        accept: Accept(Accept::PLAINTEXT),
        ..InstanceLimits::default()
    };
    h.check_spec(&spec).expect("explicit plaintext acceptance");
    assert_eq!(
        h.declared().len(),
        1,
        "public check keeps endpoint observations"
    );
    spec.purpose = OpenPurpose::Canonical;
    drop(h.open_spec(&spec).expect("canonical hook open"));
    spec.name = "missing-config";
    spec.purpose = OpenPurpose::ConvertUnstamped;
    let error = h
        .open_spec(&spec)
        .err()
        .expect("conversion requires CONFIG");
    assert!(format!("{error:?}").contains("open CONFIG or CORE_CFG violates its purpose"));
}

/// One endpoint-declaring fixture per kind, with an instance name of that kind ("no kind changes the verdict").
fn kinds() -> [(&'static str, &'static Plugin); 6] {
    [
        ("store", fixture::store::PLUGIN.plugin()),
        ("auth.corp", fixture::auth::PLUGIN.plugin()),
        ("secrets.vault", fixture::secret::PLUGIN.plugin()),
        ("export.siem", fixture::export::PLUGIN.plugin()),
        ("hooks.web", fixture::hook::PLUGIN.plugin()),
        ("transports.ws", fixture::transport::PLUGIN.plugin()),
    ]
}

fn admit(plugin: &'static Plugin) -> Harness {
    Harness::admit(plugin, FakeNeeds::new())
        .unwrap_or_else(|refusal| panic!("the fixture is admitted: {refusal}"))
}

/// The fixture config that declares `entries` as OPEN endpoints (`<tls> <egress> <dest>`).
fn declaring(entries: &[&str]) -> Vec<u8> {
    let quoted: Vec<String> = entries.iter().map(|e| format!("\"{e}\"")).collect();
    format!("{{\"open\":[{}]}}", quoted.join(",")).into_bytes()
}

/// `check` of instance `name` under `accept` (the instance's parsed `insecure_transport.accept`), returning the
/// declared endpoints it admitted.
fn check_with(
    h: &Harness,
    name: &str,
    config: &[u8],
    accept: Accept,
) -> Result<Vec<DeclaredEndpoint>, OpenError> {
    let spec = InstanceSpec {
        purpose: busbar_plugin_loader::instance::OpenPurpose::Canonical,
        identity: h.identity(),
        name,
        config_json: config,
        limits: InstanceLimits {
            accept,
            ..InstanceLimits::default()
        },
        public_url: None,
        caller_upstreams: &[],
    };
    h.block_on(h.registry().check_endpoints(&spec))
}

/// The text of a CONFIG refusal (R_CONFIG); anything else fails the arm.
fn config_text(refused: &OpenError) -> &str {
    match refused {
        OpenError::Config { code, text, .. } if *code == R_CONFIG => text,
        other => panic!("not a CONFIG refusal: {other:?}"),
    }
}

/// The opening of core's BUSBAR-3160 refusal for `dest` (TRANSPORT-SECURITY-POLICY §6).
fn refusal_3160(name: &str, h: &Harness, dest: &str) -> String {
    format!(
        "BUSBAR-3160: {name} (module {}) would connect to {dest} without TLS",
        h.identity()
    )
}

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
#[ignore = "owner: W1-K7; the booted registry half runs as `transport_plaintext_refused_at_check_every_kind`. Remaining: (a) the full BUSBAR-3160 frame of TRANSPORT-SECURITY-POLICY §6 (`(<class>, plaintext)`, the two fixes and the printed `insecure_transport` line with the instance path and config path): `judge_endpoints` (plugin-loader instance.rs) renders only the first clause and no kernel code renders the rest; (b) the boot, `--check-config` and admin DRY_RUN halves: no boot, CLI or admin path calls `Registry::check`/`check_endpoints` on dev (the admin half is W1-K8C, `admin_dry_run_runtime_transport_and_health`)"]
fn transport_plaintext_refused_at_check() {
    todo!("owner: W1-K7 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A; the zero-endpoint boot half runs as `transport_in_process_needs_nothing_at_check`. Remaining: the later OPEN TLS_NONE DENIED and audited is the connector's gate (busbar-core-connector `HostNeeds::open` -> need/policy.rs `refused`, audit row `egress.insecure_transport_refused` through `audit_ring::AUDIT`, which lands only in the store-backed admin log); the suite harness runs `Registry<FakeNeeds>` (no gate) and busbar-plugin-test has no `Registry<HostNeeds>` harness (NeedIo/Resolve doubles) nor an audit readback"]
fn transport_in_process_needs_nothing() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A (with W1-K8C for the admin half). Remaining: BUSBAR-3162 once per boot and reload is logged only for plane seats (busbar root/plane_seats.rs); no boot opens the other kinds through the MIN-3 Registry (min3_boot configured(), OUTSTANDING rows 7 to 10); `config.insecure_transport_accepted` waits for MR !2617 (audit actions); `inst.runtime.transport` and the `transport` health check are absent from busbar-core-admin; the self-signed TLS dial is the connector's (`HostNeeds::open` over `ConnectorIo`), with no harness here"]
fn transport_accept_plaintext_visible() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K8C. Remaining: `config.insecure_transport_accepted` and `egress.insecure_transport_refused` in AUDIT_ACTIONS / `x-busbar-audit-actions` wait for MR !2617 to land on dev; `inst.runtime.transport`, the `transport` health check and an admin DRY_RUN that calls `Registry::check_endpoints` are absent from busbar-core-admin"]
fn admin_dry_run_runtime_transport_and_health() {
    todo!("owner: W1-K8C (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A. Remaining: the self-signed server dial, TLS_NONE refused at the Need and the PoolKey `verify` bit across two instances are busbar-core-connector `HostNeeds::open` (need.rs, `NeedKey.waived`) over `ConnectorIo`; no `Registry<HostNeeds>` harness with a self-signed TLS server in busbar-plugin-test. The connector's own units cover the parts (need_key_tests `a_waived_conn_never_serves_a_verified_open`, need_net_tests `only_a_held_accept_waives_verification`); the verdict half is `each_acceptance_bit_admits_exactly_what_it_names`"]
fn transport_accept_unverified_tls() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

/// TRANSPORT-SECURITY-POLICY §8 test 7, the config arms (W1-K7): a missing, empty or placeholder `reason`, a
/// `reason` over 256 characters or with a newline, an `accept` that is not `plaintext`/`unverified_tls` (or an
/// empty or repeated list) and an unknown key each refuse the load with BUSBAR-3163 naming the key; a valid
/// acceptance becomes the instance's `InstanceLimits.accept`. The unused-acceptance arm needs the instance's
/// declared ENDPOINTs, so it is judged at `check` (W1-L2's refusal), not at parse.
#[test]
fn transport_setting_validation() {
    use busbar_kernel::config::min3::parse_min3;
    use busbar_kernel::config::{deploy_from_yaml_str, resolve, Grammar};
    use busbar_plugin_abi::host_side::caller::Accept;
    let deploy = |block: &str| {
        let yaml = format!(
            "providers: {{}}\nmodels: {{}}\nstore:\n  module: postgres\n  insecure_transport: {block}\n"
        );
        deploy_from_yaml_str(&yaml, &Grammar::empty())
            .unwrap_or_else(|e| panic!("{block}: `insecure_transport` is config grammar: {e}"))
    };
    let long = format!("{{ accept: plaintext, reason: \"{}\" }}", "x".repeat(257));
    for (block, key) in [
        ("{ accept: plaintext }", "reason"),
        ("{ accept: plaintext, reason: \"\" }", "reason"),
        (
            "{ accept: plaintext, reason: \"<why this is acceptable>\" }",
            "reason",
        ),
        (long.as_str(), "reason"),
        ("{ accept: plaintext, reason: \"two\\nlines\" }", "reason"),
        ("{ accept: yes, reason: \"legacy db\" }", "accept"),
        ("{ accept: [], reason: \"legacy db\" }", "accept"),
        (
            "{ accept: [plaintext, plaintext], reason: \"legacy db\" }",
            "accept",
        ),
        (
            "{ accept: plaintext, reason: \"legacy db\", until: 2027 }",
            "until",
        ),
    ] {
        let refused = parse_min3(&deploy(block)).err().expect(block);
        let want = format!("BUSBAR-3163: store.insecure_transport.{key}");
        assert!(
            refused.iter().any(|r| r.starts_with(&want)),
            "{block}: {refused:?}"
        );
    }

    let ok = deploy("{ accept: [plaintext, unverified_tls], reason: \"pg sidecar, INFRA-142\" }");
    let cfg = resolve(&ok, &Default::default()).expect("a valid acceptance loads");
    assert_eq!(
        busbar_kernel::appbuild::instance_limits(&cfg, "store", "store").accept,
        Accept(Accept::PLAINTEXT | Accept::UNVERIFIED_TLS)
    );
}

/// The registry half of arm 1 (TRANSPORT-SECURITY-POLICY §8 test 1), booted: a TLS_NONE endpoint `db:5432` that
/// `check` declares refuses CONFIG with BUSBAR-3160 naming the instance, its module and the dest, with zero connects,
/// for a store, an auth, a secret, an export, a hook and a transport fixture, in identical words once the instance
/// and module are set aside (no kind changes the verdict). The same endpoint over TLS passes `check`.
#[test]
fn transport_plaintext_refused_at_check_every_kind() {
    let mut texts = Vec::new();
    for (name, plugin) in kinds() {
        let h = admit(plugin);
        let refused = h
            .check(name, &declaring(&["none 2 db:5432"]))
            .expect_err(name);
        let text = config_text(&refused);
        assert!(
            text.starts_with(&refusal_3160(name, &h, "db:5432")),
            "{name}: {text}"
        );
        texts.push(
            text.replace(h.identity(), "<module>")
                .replace(name, "<instance>"),
        );
        h.check(name, &declaring(&["required 2 db:5432"]))
            .unwrap_or_else(|e| panic!("{name}: verified TLS needs no acceptance: {e:?}"));
        assert!(h.seen().is_empty(), "{name}: zero connects");
    }
    assert!(
        texts.windows(2).all(|pair| pair[0] == pair[1]),
        "every kind refuses in the same words: {texts:?}"
    );
}

/// TRANSPORT-SECURITY-POLICY §8 test 2: `127.0.0.1`, `[::1]` and `localhost` are refused at `check` exactly as
/// `db:5432` is (the same refusal with the dest in its place), for every kind, even under the loopback egress
/// class, with zero connects. The verdict half is `the_verdict_has_no_loopback_exemption`.
#[test]
fn transport_no_loopback_exemption() {
    for (name, plugin) in kinds() {
        let h = admit(plugin);
        let remote = h
            .check(name, &declaring(&["none 2 db:5432"]))
            .expect_err(name);
        let remote = config_text(&remote).to_owned();
        for dest in ["127.0.0.1:5432", "[::1]:5432", "localhost:5432"] {
            for class in [2, 4] {
                let entry = format!("none {class} {dest}");
                let refused = h
                    .check(name, &declaring(&[entry.as_str()]))
                    .expect_err(dest);
                assert_eq!(
                    config_text(&refused),
                    remote.replace("db:5432", dest),
                    "{name} {dest} (egress {class})"
                );
            }
        }
        assert!(h.seen().is_empty(), "{name}: zero connects");
    }
}

/// TRANSPORT-SECURITY-POLICY §8 test 3: a `unix:` endpoint is refused at `check` without an acceptance (whatever
/// TLS mode it states, and under `accept: unverified_tls`) and admitted with `accept: plaintext`, for the store and
/// every non-store fixture alike. The verdict half is `the_verdict_has_no_unix_exemption`.
#[test]
fn transport_no_unix_exemption() {
    const SOCKET: &str = "unix:/var/run/db.sock";
    for (name, plugin) in kinds() {
        let h = admit(plugin);
        let plain = declaring(&["none 2 unix:/var/run/db.sock"]);
        let stated_tls = declaring(&["required 2 unix:/var/run/db.sock"]);
        for (config, accept) in [
            (&plain, NOTHING),
            (&plain, UNVERIFIED),
            (&stated_tls, NOTHING),
        ] {
            let refused = check_with(&h, name, config, accept).expect_err(name);
            let text = config_text(&refused);
            assert!(
                text.starts_with(&refusal_3160(name, &h, SOCKET)),
                "{name} {accept:?}: {text}"
            );
        }
        let admitted = check_with(&h, name, &plain, PLAINTEXT)
            .unwrap_or_else(|e| panic!("{name}: accept: plaintext admits the socket: {e:?}"));
        assert_eq!(admitted.len(), 1, "{name}");
        assert_eq!(&*admitted[0].dest, SOCKET, "{name}");
        assert_eq!(admitted[0].flags & TLS_MASK, TLS_NONE, "{name}");
        assert!(h.seen().is_empty(), "{name}: zero connects");
    }
}

/// The boot half of arm 4 (TRANSPORT-SECURITY-POLICY §8 test 4): an instance that declares no endpoint passes
/// `check` with no `insecure_transport` for every kind (nothing to judge, and no kind or plugin list is consulted),
/// and opens.
#[test]
fn transport_in_process_needs_nothing_at_check() {
    for (name, plugin) in kinds() {
        let h = admit(plugin);
        let declared = check_with(&h, name, b"{}", NOTHING)
            .unwrap_or_else(|e| panic!("{name}: no endpoint, no setting: {e:?}"));
        assert!(declared.is_empty(), "{name}: {declared:?}");
    }
    let h = admit(fixture::secret::PLUGIN.plugin());
    h.open_secret("secrets.env", b"{}")
        .unwrap_or_else(|e| panic!("an in-process instance opens with no setting: {e:?}"));
    assert!(h.seen().is_empty(), "no connect");
}

/// The booted clause of arm 7 that parse cannot judge (TRANSPORT-SECURITY-POLICY §4 "unused acceptance"): an
/// acceptance none of the instance's declared endpoints needs refuses CONFIG at `check` with BUSBAR-3163 naming the
/// instance and its module; an acceptance a declared endpoint does need is admitted.
#[test]
fn transport_unused_acceptance_refused_at_check() {
    for (name, plugin) in kinds() {
        let h = admit(plugin);
        let tls = declaring(&["required 2 db.internal:5432"]);
        let plain = declaring(&["none 2 db.internal:5432"]);
        let both = declaring(&["required 2 db.internal:5432", "none 2 db.internal:5433"]);
        let unused = format!(
            "BUSBAR-3163: {name} (module {}) sets insecure_transport, but none of its declared endpoints needs it",
            h.identity()
        );
        for (config, accept) in [(&tls, PLAINTEXT), (&plain, BOTH)] {
            let refused = check_with(&h, name, config, accept).expect_err(name);
            assert!(
                config_text(&refused).starts_with(&unused),
                "{name} {accept:?}: {refused:?}"
            );
        }
        for (config, accept) in [(&tls, UNVERIFIED), (&plain, PLAINTEXT), (&both, BOTH)] {
            check_with(&h, name, config, accept)
                .unwrap_or_else(|e| panic!("{name} {accept:?}: a needed acceptance: {e:?}"));
        }
    }
}

/// The check half of arm 15 (TRANSPORT-SECURITY-POLICY §8 test 15): an instance that declares no endpoint keeps an
/// acceptance (no BUSBAR-3163: with nothing declared it cannot be unused), and the kernel's BUSBAR-3162 line over
/// what it declared says "no declared endpoint uses this yet".
#[test]
fn transport_undeclared_acceptance_kept_at_check() {
    use busbar_kernel::config::min3::InsecureTransport;
    for (name, plugin) in kinds() {
        let h = admit(plugin);
        for accept in [PLAINTEXT, UNVERIFIED, BOTH] {
            let declared = check_with(&h, name, b"{}", accept)
                .unwrap_or_else(|e| panic!("{name} {accept:?}: the acceptance is kept: {e:?}"));
            assert!(declared.is_empty(), "{name}: {declared:?}");
            let kept = InsecureTransport {
                accept,
                reason: "legacy sidecar, INFRA-142".into(),
            };
            let shown: Vec<String> = declared.iter().map(|e| e.dest.to_string()).collect();
            let line = kept.warning_line(name, h.identity(), &shown);
            assert!(
                line.starts_with(&format!("BUSBAR-3162: {name} (module {})", h.identity())),
                "{line}"
            );
            assert!(
                line.contains("no declared endpoint uses this yet"),
                "{line}"
            );
        }
    }
}

/// TRANSPORT-SECURITY-POLICY §8 test 10 (C-NEED-DECODE's ENDPOINT rows): more than 16 ENDPOINT records, a dest over
/// 2,048 bytes, an op other than OPEN/FETCH, an egress class above 4 or the retired bit 0x200 in a CHECK answer is
/// INVALID, and core refuses CONFIG naming the instance. The bounds themselves (16 records, a 2,048-byte dest)
/// decode. The SDK writer refuses all but one of these before they reach the wire; the egress class above 4 it
/// lets through (four bits) is refused by core's decode.
#[test]
fn endpoint_record_decode() {
    const NAME: &str = "secrets.raw";
    let h = admit(fixture::raw::PLUGIN.plugin());
    let config_of = |named: &str| format!("{{\"case\":\"{named}\"}}").into_bytes();
    for (named, why) in [
        ("seventeen", "more than 16"),
        ("long-dest", "dest over 2,048 bytes"),
        ("bad-op", "op"),
        ("egress-five", "flags"),
        ("bit-200", "flags"),
    ] {
        let refused = h.check(NAME, &config_of(named)).expect_err(named);
        let text = config_text(&refused);
        assert!(
            text.starts_with(&format!("{NAME}: the plugin declared an invalid ENDPOINT")),
            "{named}: {text}"
        );
        assert!(text.contains(&format!("({why})")), "{named}: {text}");
    }
    let sixteen = check_with(&h, NAME, &config_of("sixteen"), NOTHING)
        .unwrap_or_else(|e| panic!("16 records decode: {e:?}"));
    assert_eq!(sixteen.len(), 16);
    let longest = check_with(&h, NAME, &config_of("max-dest"), NOTHING)
        .unwrap_or_else(|e| panic!("a 2,048-byte dest decodes: {e:?}"));
    assert_eq!(longest.len(), 1);
    assert_eq!(longest[0].dest.len(), 2_048);
    assert!(h.seen().is_empty(), "zero connects");

    let sdk = admit(fixture::secret::PLUGIN.plugin());
    let refused = sdk
        .check(NAME, &declaring(&["required 5 db.internal:5432"]))
        .expect_err("egress class 5");
    let text = config_text(&refused);
    assert!(
        text.starts_with(&format!("{NAME}: the plugin declared an invalid ENDPOINT")),
        "{text}"
    );
    assert!(text.contains("(flags)"), "{text}");
    for tls in ["required", "mutual", "inband"] {
        let entry = format!("{tls} 4 db.internal:5432");
        let declared = check_with(&sdk, NAME, &declaring(&[entry.as_str()]), NOTHING)
            .unwrap_or_else(|e| panic!("{tls} at egress class 4 decodes: {e:?}"));
        let want = match tls {
            "required" => TLS_REQUIRED,
            "mutual" => TLS_MUTUAL,
            _ => TLS_INBAND,
        };
        assert_eq!(declared[0].flags & TLS_MASK, want, "{tls}");
    }
}

#[test]
#[ignore = "owner: W1-C1A. Remaining: (a) a declared-TLS_INBAND fixture's TLS_NONE OPEN DENIED before DNS, audited, no connect, is the connector gate (`HostNeeds::open`; the suite harness runs FakeNeeds, no `Registry<HostNeeds>` harness or audit readback here); (b) core turning a Need refusal during `open` into its own BUSBAR-3160 CONFIG refusal (policy §3 \"At the Need\") is not on dev: plugin-loader chains.rs `open_instance` returns the plugin's answer and BUSBAR-3160 is rendered only by `judge_endpoints` at check"]
fn transport_need_time_authoritative() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A. Remaining: the BUSBAR-3161 refusal is rendered nowhere on dev (only named in plugin-loader instance.rs `judge_endpoints`' doc); the self-signed server dial with `trust_anchors` / `destinations[].verify: pin` (kernel config/tls.rs `TlsDestinationCfg.verify`) is the connector's TLS dial (`HostNeeds::open` over `ConnectorIo`), with no harness here"]
fn transport_verify_options() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-X1 (blocked: the source check has no scanner in this crate for `is_loopback`/`names_loopback`/`plaintext` field/`limits.plaintext` across core and every plugin repo (busbar-core-connector guard.rs still defines `is_loopback` and `names_loopback`; which call sites are admission paths is the scanner's judgement); the plugin-repo half is the fleet lint)"]
fn transport_source_checks() {
    todo!("owner: W1-X1 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K8C (waits for MR !2617, the transport audit actions in the kernel's AUDIT_ACTIONS (audit/auditlog.rs) and the admin `x-busbar-audit-actions` component, to land on dev)"]
fn audit_actions_catalogue() {
    todo!("owner: W1-K8C (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K9. The plan, stamp and byte-for-byte carry half runs in busbar-migrate's own `src/tests/steps_tests.rs::upgrade_from_155_shape_carries_acceptance` over its public `plan` (base config 1d, overlay hook 1c, overlay named map). Remaining: the \"boots\" half, the gateway booting the planned config through the MIN-3 Registry (min3_boot configured(), OUTSTANDING rows 7 to 10)"]
fn upgrade_from_155_shape_carries_acceptance() {
    todo!("owner: W1-K9 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A. Remaining: K7's listing of a transport instance's core-known client endpoints (its `ws://`/h2c upstreams from core config) at check is not on dev: `check_endpoints` (plugin-loader instance.rs) judges only the ENDPOINT records the plugin's own `check` declared; BUSBAR-3161 and the self-signed `wss://` dial are the connector's, with no harness here. The transport fixture (`min3_endpoints::transport`) is ready"]
fn transport_instance_client_dial() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A; the kept-acceptance half runs as `transport_undeclared_acceptance_kept_at_check`. Remaining: the TLS_NONE dial in `open` admitted under the acceptance is the connector gate (`HostNeeds::open`; the suite harness runs FakeNeeds), and `accept: unverified_tls` over a TLS_INBAND upgrade against the self-signed server is `HostNeeds::starttls` over `ConnectorIo`; no `Registry<HostNeeds>` harness with a self-signed TLS server here"]
fn transport_undeclared_acceptance_kept() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}
