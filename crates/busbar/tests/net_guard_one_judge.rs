// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE NETWORK JUDGE — the gate that says there is exactly one, and that both names reach it.
//!
//! ## What this file used to be
//!
//! It was `net_guard_extraction_parity.rs`, an anti-drift gate between TWO copies of the SSRF host
//! extraction: the live one in `busbar-kernel`'s `net_guard` and the extracted one in the egress
//! unit's `trust::net`. It existed because the two had already drifted once in a way that produced
//! a real denylist bypass, and because — in its own words — "both copies had tests; neither suite
//! could see the difference, because neither suite could see the other copy."
//!
//! A parity test is not a fix. It is the admission that a fix is owed, and it can only ever say
//! that two judges currently agree; it cannot stop a third from being written, and it did not stop
//! the fork it was watching from growing a metadata bypass on the copy that dials.
//!
//! ## What it is now
//!
//! There is one definition. It lives in [`busbar_kernel_egress::trust::net`], and
//! `busbar_kernel::net_guard` is a re-export shim over it. So the two names below are two paths to
//! ONE function, and every equality in this file is trivially true — *while that stays true*.
//!
//! That is precisely what this file now gates. The failure mode it watches for is no longer "the
//! two copies disagree" but "somebody re-grew a second copy behind one of these names", and the
//! shape of that regression is identical: a local definition under `busbar_kernel::net_guard` that
//! answers some hostile spelling differently from the unit. The rows below are chosen to be the
//! spellings a re-fork would get wrong — in particular [`BARE_AUTHORITIES`], which the shim's
//! predecessor answered `None` for while the unit judged them, and the metadata NAMES, which is
//! where the live bypass actually was.
//!
//! The table is HOSTILE input on purpose. An equality gate over well-formed URLs would pass against
//! two copies that disagree about every spelling an attacker would actually send.

/// Every spelling the one judge must read identically through both names. Each row is a destination
/// as it could appear in a config file, a header, or a redirect `Location` — with the padding, the
/// deleted bytes, the percent-escapes, the alternate encodings and the authority-boundary tricks
/// that are the reason the extraction is more than a `split("://")`.
const HOSTILE: &[&str] = &[
    // ── The WHATWG first step, both halves ───────────────────────────────────────────────────────
    "http://169.254.169.254 ",
    " http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/ ",
    "\u{1}http://169.254.169.254/",
    "http://169.254.169.254/\u{1f}",
    "\u{0}https://10.99.99.99",
    "https://10.99.99.99\u{0}",
    "\t https://10.99.99.99/ \r\n",
    "   https://api.openai.com/v1   ",
    // Interior tab / CR / LF, deleted from anywhere in the input rather than trimmed.
    "http://169.254.169\t.254/",
    "http://169.254.169.254\r\n/",
    "https://api.openai\n.com/v1",
    // The CONTROL for the trim: an interior space is NOT one of the three deleted bytes and is not
    // at either end, so a malformed host must stay malformed rather than be silently repaired into
    // something that matches.
    "http://169.254.169 .254/",
    // ── Percent-encoding ─────────────────────────────────────────────────────────────────────────
    "https://169%2E254%2E169%2E254/",
    "http://169%2e254%2e169%2e254/latest/meta-data/",
    "https://169.254.169.254%2E/",
    "https://169.254.169.254%00.evil.example/",
    // A dangling / malformed escape must not be "decoded" into a different host.
    "https://169.254.169.254%/",
    "https://169.254.169.254%zz/",
    "https://10.0.0.1%2",
    // ── Obfuscated hosts ─────────────────────────────────────────────────────────────────────────
    "http://2852039166/",              // decimal-int IMDS
    "http://0xA9FEA9FE/",              // hex IMDS
    "http://0251.0376.0251.0376/",     // octal IMDS
    "http://169.254.169.254./",        // trailing FQDN root dot
    "http://[::ffff:169.254.169.254]", // IPv4-mapped v6 literal
    "http://[::1]:443/",               // bracketed v6 with a port
    "http://[fd00:ec2::254]/",         // IMDSv6
    // ── Authority-boundary tricks ────────────────────────────────────────────────────────────────
    "https://10.0.0.1\\x.allowed.com/",
    "https://api.openai.com@169.254.169.254/",
    "https://user:pass@10.99.99.99:8443/v1",
    "https://169.254.169.254:80/?q=#frag",
    "https://169.254.169.254#@allowed.com",
    // ── Degenerate shapes ────────────────────────────────────────────────────────────────────────
    "",
    " ",
    "https://",
    "https:// ",
    "://169.254.169.254",
    "ftp://169.254.169.254/",
    "HTTPS://169.254.169.254/",
    "https://169.254.169.254",
];

/// The bare-authority spellings: a destination written as `host[:port]` with no scheme at all.
///
/// These used to be the ONE place the two copies were allowed to answer differently, and that
/// difference was pinned here with its direction. It is gone, because the copies are gone: the one
/// judge falls back to `extract_normalized_authority_host` when there is no `://`, so a lane may
/// spell its destination either way and the operator's denylist fires for both.
///
/// They stay in this file as the sharpest re-fork detector it has. A second copy grown behind
/// `busbar_kernel::net_guard` would almost certainly be the OLD shape — scheme-only extraction,
/// `None` for every row here — so this is the table where "somebody re-forked the guard" shows up
/// as a refusal that silently stopped happening.
const BARE_AUTHORITIES: &[&str] = &[
    "10.99.99.99",
    "10.99.99.99 ",
    " 10.99.99.99:8443",
    "169.254.169.254:8080",
    "169.254.169.254 ",
    "api.openai.com",
];

/// Both names read the same host out of every hostile spelling.
///
/// `extract_normalized_host` is the seam both denylist judgements are built on, so an equality here
/// is an equality of every check downstream of it.
#[test]
fn both_names_reach_one_extraction() {
    let mut compared = 0usize;
    for spelling in HOSTILE.iter().chain(BARE_AUTHORITIES) {
        let through_kernel = busbar_kernel::net_guard::extract_normalized_host(spelling);
        let through_unit = busbar_kernel_egress::trust::net::extract_normalized_host(spelling);
        assert_eq!(
            through_kernel, through_unit,
            "`busbar_kernel::net_guard` and the egress unit read {spelling:?} as different hosts — \
             the shim has grown a second definition, and whichever one a call site routes through \
             now decides whether this destination is guarded"
        );
        compared += 1;
    }
    // A floor rather than an equality with `HOSTILE.len()`, which could only restate the loop: the
    // point is that the hostile table cannot be quietly shrunk to make a disagreement go away.
    assert!(
        compared >= 40,
        "the hostile table shrank; a deleted row is a spelling that stopped being judged in public"
    );
}

/// And the same answer all the way through the denylist judgement, which is what a caller sees.
///
/// The extraction being equal does not by itself make the JUDGEMENTS equal — the allow-override
/// match, the alternate-encoding expansion and the operator's extra-blocked set are all downstream
/// of it, and each is somewhere a second copy could differ. Driving the same lists through both
/// names is the end-to-end form of the same claim, and the one an operator's
/// `blocked_metadata_hosts` entry actually depends on.
#[test]
fn both_names_reach_one_denylist_judgement() {
    let operator_blocked = vec!["10.99.99.99".to_string(), "internal.example".to_string()];
    let operator_allowed = vec!["api.openai.com".to_string()];
    for spelling in HOSTILE.iter().chain(BARE_AUTHORITIES) {
        // The bare guard, no operator lists at all.
        assert_eq!(
            busbar_kernel::net_guard::ssrf_blocked_host(spelling, &[], false, &[]),
            busbar_kernel_egress::trust::net::ssrf_blocked_host(spelling, &[], false, &[]),
            "bare guard disagrees on {spelling:?}"
        );
        // With the operator's denylist — the arm the trailing-space bypass defeated.
        assert_eq!(
            busbar_kernel::net_guard::ssrf_blocked_host(spelling, &[], false, &operator_blocked),
            busbar_kernel_egress::trust::net::ssrf_blocked_host(
                spelling,
                &[],
                false,
                &operator_blocked
            ),
            "operator denylist disagrees on {spelling:?}"
        );
        // With a surgical allow-override, which must win through both names or through neither.
        assert_eq!(
            busbar_kernel::net_guard::ssrf_blocked_host(
                spelling,
                &operator_allowed,
                false,
                &operator_blocked
            ),
            busbar_kernel_egress::trust::net::ssrf_blocked_host(
                spelling,
                &operator_allowed,
                false,
                &operator_blocked
            ),
            "allow-override disagrees on {spelling:?}"
        );
    }
}

/// THE DIVERGENCE THAT WAS PINNED HERE IS GONE, AND THIS IS THE STATEMENT THAT IT STAYS GONE.
///
/// A bare `host[:port]` carries no scheme, so `extract_normalized_host` finds nothing — and the one
/// judge then falls back to `extract_normalized_authority_host` and judges it anyway. The shim's
/// predecessor had no such fallback and answered `None` for every row, which is the shape a re-fork
/// would have. So this asserts the refusal HAPPENS through the kernel name, not merely that the two
/// names agree: two copies that both went quiet would satisfy an equality and guard nothing.
#[test]
fn the_bare_authority_arm_is_reached_through_the_kernel_name() {
    let operator_blocked = ["10.99.99.99".to_string()];
    let mut refused = 0usize;
    for spelling in BARE_AUTHORITIES {
        for blocked in [&[][..], &operator_blocked[..]] {
            let through_kernel =
                busbar_kernel::net_guard::ssrf_blocked_host(spelling, &[], false, blocked);
            let through_unit =
                busbar_kernel_egress::trust::net::ssrf_blocked_host(spelling, &[], false, blocked);
            assert_eq!(
                through_kernel, through_unit,
                "the bare-authority arm answers differently through the two names for {spelling:?}"
            );
            if through_kernel.is_some() {
                refused += 1;
            }
        }
    }
    assert!(
        refused >= 6,
        "the bare-authority arm stopped refusing ({refused} refusals) — an operator's denylist \
         entry silently stops firing for every destination spelled without a scheme"
    );
}

/// THE METADATA LIST IS ONE LIST, AND THE ARM THAT DIALS READS IT.
///
/// This is the bug that was actually live, stated directly. `net_guard` kept a two-entry
/// `METADATA_HOSTS` that [`judge_host_name`] — the arm the resolve-then-pin DIALING path consults —
/// read, while a six-entry copy shadowed privately inside `ssrf_blocked_host` served config
/// validation. Four names were refused at boot and dialled at runtime.
///
/// `metadata.platformequinix.com` is why the NAME arm is the only arm that can help: it resolves
/// and pins to a globally routable address, so no address predicate says anything about it at all.
///
/// [`judge_host_name`]: busbar_kernel_egress::trust::net::judge_host_name
#[test]
fn the_dialing_arm_and_the_config_arm_read_the_same_metadata_list() {
    let names = busbar_kernel::net_guard::METADATA_HOSTS;
    assert_eq!(
        names,
        busbar_kernel_egress::trust::net::METADATA_HOSTS,
        "the shim and the unit publish different metadata lists"
    );
    assert!(
        names.len() >= 6 && names.contains(&"metadata.platformequinix.com"),
        "the metadata list shrank back toward the two-entry copy: {names:?}"
    );
    let permissive = busbar_kernel::net_guard::GuardPolicy {
        allow_private: true,
        ..busbar_kernel::net_guard::GuardPolicy::default()
    };
    for name in names {
        // The DIALING arm, under the permissive stance: the metadata arm is unconditional, so
        // `allow_private` must not reach it.
        assert!(
            busbar_kernel::net_guard::judge_host_name(name, permissive).is_err(),
            "`{name}` is on the metadata list and the dialing arm let it through"
        );
        // And the CONFIG arm, over the same name spelled as a URL.
        assert!(
            busbar_kernel::net_guard::ssrf_blocked_host(
                &format!("https://{name}/latest/meta-data/"),
                &[],
                false,
                &[]
            )
            .is_some(),
            "`{name}` is on the metadata list and the config arm let it through"
        );
    }
}

/// The CONTROL. Without it, a judge that returned `None` for everything would pass every gate above
/// while guarding nothing at all.
#[test]
fn the_hostile_table_actually_reaches_the_guard_through_both_names() {
    let mut blocked_through_kernel = 0usize;
    let mut blocked_through_unit = 0usize;
    for spelling in HOSTILE {
        if busbar_kernel::net_guard::ssrf_blocked_host(spelling, &[], false, &[]).is_some() {
            blocked_through_kernel += 1;
        }
        if busbar_kernel_egress::trust::net::ssrf_blocked_host(spelling, &[], false, &[]).is_some()
        {
            blocked_through_unit += 1;
        }
    }
    assert!(
        // A LOOSE floor on purpose: this is the control for the equalities above, not a second copy
        // of them. It must stay green however the table is extended, and go red only when the table
        // stops carrying destinations the guard refuses at all.
        blocked_through_kernel >= 15 && blocked_through_unit >= 15,
        "the hostile table stopped being hostile: {blocked_through_kernel} through the kernel \
         name, {blocked_through_unit} through the unit — an equality between two names that refuse \
         nothing is not a gate"
    );
}
