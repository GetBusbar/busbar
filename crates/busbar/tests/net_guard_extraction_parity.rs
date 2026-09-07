// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ANTI-DRIFT GATE FOR THE TWO COPIES OF THE SSRF HOST EXTRACTION.
//!
//! There are two of them: the live one in `busbar-substrate::net_guard`, and the extracted unit in
//! `busbar-unit-trust::net`. They exist to read the same host out of the same string, because the
//! whole safety property is "the guard sees the authority the socket will connect to". The moment
//! they read it differently, one of them is a bypass — and which one is a bypass depends only on
//! which copy a given call site happens to route through, which is not a property anybody can hold
//! in their head.
//!
//! The extraction already drifted once, silently: the unit was moved across WITHOUT the first half
//! of the WHATWG basic parser's first step (the leading/trailing C0-and-space trim), keeping only
//! the interior tab/LF/CR deletion. A destination of `"https://10.99.99.99 "` — one trailing space,
//! what an unquoted YAML scalar or a console copy-paste leaves — was then read by the unit as the
//! host `10.99.99.99 `, which parses as no `IpAddr` and matches no `HostSet` entry, so an
//! operator's denylist entry silently did not fire while the connecting stack trimmed the space and
//! dialled the blocked host. Both copies had tests; neither suite could see the difference, because
//! neither suite could see the other copy.
//!
//! This file is the only place in the tree that can. The composition root already names both crates
//! as ordinary dependencies (`busbar-substrate` for the plane-facing seams, `busbar-unit-trust` for
//! the verify step), so stating the equality here costs no new edge and no new dependency in either
//! leaf — and in particular does not put the substrate inside the unit, whose whole architectural
//! claim is that it depends on nothing but the capability crate.
//!
//! The table is HOSTILE input on purpose. An equality gate over well-formed URLs would pass against
//! two copies that disagree about every spelling an attacker would actually send.

/// Every spelling both copies must read identically. Each row is a destination as it could appear
/// in a config file, a header, or a redirect `Location` — with the padding, the deleted bytes, the
/// percent-escapes, the alternate encodings and the authority-boundary tricks that are the reason
/// the extraction is more than a `split("://")`.
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
    // at either end, so a malformed host must stay malformed in both copies rather than be
    // silently repaired into something that matches.
    "http://169.254.169 .254/",
    // ── Percent-encoding ─────────────────────────────────────────────────────────────────────────
    "https://169%2E254%2E169%2E254/",
    "http://169%2e254%2e169%2e254/latest/meta-data/",
    "https://169.254.169.254%2E/",
    "https://169.254.169.254%00.evil.example/",
    // A dangling / malformed escape must not be "decoded" into a different host by one copy only.
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
/// These are the ONE place the two copies are allowed to answer differently, and the difference is
/// deliberate and one-directional. `extract_normalized_host` returns `None` for all of them in both
/// copies (there is no `://` to strip), but the unit's `judge_against_lists` then falls back to
/// `extract_normalized_authority_host` and judges the authority anyway, because a lane may spell its
/// destination either way and which spelling an operator used is not a security question. The
/// substrate has no such fallback. So the unit is STRICTLY STRICTER here, never laxer — which is the
/// only direction a divergence between two copies of a guard may run, and is pinned as such below
/// rather than left as a silent difference for the equality gate to trip over.
const BARE_AUTHORITIES: &[&str] = &[
    "10.99.99.99",
    "10.99.99.99 ",
    " 10.99.99.99:8443",
    "169.254.169.254:8080",
    "169.254.169.254 ",
    "api.openai.com",
];

/// The two copies read the same host out of every hostile spelling.
///
/// This is the direct statement of the property. `extract_normalized_host` is the seam both
/// denylist judgements are built on, so an equality here is an equality of every check downstream
/// of it.
#[test]
fn both_copies_of_the_extraction_read_the_same_host() {
    let mut compared = 0usize;
    for spelling in HOSTILE.iter().chain(BARE_AUTHORITIES) {
        let live = busbar_substrate::net_guard::extract_normalized_host(spelling);
        let unit = busbar_unit_trust::net::extract_normalized_host(spelling);
        assert_eq!(
            live, unit,
            "the substrate and the trust unit read {spelling:?} as different hosts — whichever one \
             a call site routes through decides whether this destination is guarded, which is the \
             drift this gate exists to refuse"
        );
        compared += 1;
    }
    // A floor rather than an equality with `HOSTILE.len()`, which could only restate the loop: the
    // point is that the hostile table cannot be quietly shrunk to make a disagreement go away.
    assert!(
        compared >= 40,
        "the hostile table shrank; a deleted row is a spelling the two copies stopped agreeing on \
         in public"
    );
}

/// And the same answer all the way through the denylist judgement, which is what a caller sees.
///
/// The extraction being equal does not by itself make the JUDGEMENTS equal — the allow-override
/// match, the alternate-encoding expansion and the operator's extra-blocked set are all downstream
/// of it, and each is a second copy. Driving the same lists through both is the end-to-end form of
/// the same claim, and the one the operator's `blocked_metadata_hosts` entry actually depends on.
#[test]
fn both_copies_judge_the_same_hostile_table_the_same_way() {
    let operator_blocked = vec!["10.99.99.99".to_string(), "internal.example".to_string()];
    let operator_allowed = vec!["api.openai.com".to_string()];
    for spelling in HOSTILE {
        // The bare guard, no operator lists at all.
        assert_eq!(
            busbar_substrate::net_guard::ssrf_blocked_host(spelling, &[], false, &[]),
            busbar_unit_trust::net::ssrf_blocked_host(spelling, &[], false, &[]),
            "bare guard disagrees on {spelling:?}"
        );
        // With the operator's denylist — the arm the trailing-space bypass defeated.
        assert_eq!(
            busbar_substrate::net_guard::ssrf_blocked_host(spelling, &[], false, &operator_blocked),
            busbar_unit_trust::net::ssrf_blocked_host(spelling, &[], false, &operator_blocked),
            "operator denylist disagrees on {spelling:?}"
        );
        // With a surgical allow-override, which must win in both copies or in neither.
        assert_eq!(
            busbar_substrate::net_guard::ssrf_blocked_host(
                spelling,
                &operator_allowed,
                false,
                &operator_blocked
            ),
            busbar_unit_trust::net::ssrf_blocked_host(
                spelling,
                &operator_allowed,
                false,
                &operator_blocked
            ),
            "allow-override disagrees on {spelling:?}"
        );
    }
}

/// THE ONE PINNED DIVERGENCE, and its direction.
///
/// A bare `host[:port]` carries no scheme, so `extract_normalized_host` finds nothing in either
/// copy — but the unit falls back to `extract_normalized_authority_host` and judges it anyway,
/// while the substrate does not. Pinned here so the difference is a decision on the record rather
/// than a surprise in the equality gate, and pinned WITH ITS DIRECTION: the unit refuses what the
/// substrate waves through, never the reverse. A change that flipped this — the unit going quiet on
/// a spelling the substrate blocks — is the drift that matters, and it goes red here.
#[test]
fn the_bare_authority_fallback_makes_the_unit_stricter_and_never_laxer() {
    let operator_blocked = ["10.99.99.99".to_string()];
    let mut unit_stricter = 0usize;
    for spelling in BARE_AUTHORITIES {
        for blocked in [&[][..], &operator_blocked[..]] {
            let live =
                busbar_substrate::net_guard::ssrf_blocked_host(spelling, &[], false, blocked);
            let unit = busbar_unit_trust::net::ssrf_blocked_host(spelling, &[], false, blocked);
            assert!(
                live.is_none(),
                "the substrate grew a bare-authority judgement for {spelling:?} ({live:?}) — the \
                 two copies now overlap here and the equality gate above should be judging this \
                 row instead of this one"
            );
            if unit.is_some() {
                unit_stricter += 1;
            }
        }
    }
    assert!(
        unit_stricter >= 6,
        "the unit stopped judging bare authorities ({unit_stricter} refusals) — an operator's \
         denylist entry silently stops firing for every destination spelled without a scheme"
    );
}

/// The CONTROL. Without it, two copies that both returned `None` for everything would pass the two
/// gates above while guarding nothing at all.
#[test]
fn the_hostile_table_actually_reaches_the_guard_in_both_copies() {
    let mut blocked_by_live = 0usize;
    let mut blocked_by_unit = 0usize;
    for spelling in HOSTILE {
        if busbar_substrate::net_guard::ssrf_blocked_host(spelling, &[], false, &[]).is_some() {
            blocked_by_live += 1;
        }
        if busbar_unit_trust::net::ssrf_blocked_host(spelling, &[], false, &[]).is_some() {
            blocked_by_unit += 1;
        }
    }
    assert!(
        // A LOOSE floor on purpose: this is the control for the equality gates, not a second copy
        // of them. It must stay green whichever way the two copies happen to disagree, and go red
        // only when the table stops carrying destinations either guard refuses at all.
        blocked_by_live >= 15 && blocked_by_unit >= 15,
        "the hostile table stopped being hostile: live blocked {blocked_by_live}, unit blocked \
         {blocked_by_unit} — an equality between two guards that refuse nothing is not a gate"
    );
}
