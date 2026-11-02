// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

const HOSTILE: &[&str] = &[
    "http://169.254.169.254 ",
    " http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/ ",
    "\u{1}http://169.254.169.254/",
    "http://169.254.169.254/\u{1f}",
    "\u{0}https://10.99.99.99",
    "https://10.99.99.99\u{0}",
    "\t https://10.99.99.99/ \r\n",
    "   https://api.example.com/v1   ",
    "http://169.254.169\t.254/",
    "http://169.254.169.254\r\n/",
    "https://api.example\n.com/v1",
    "http://169.254.169 .254/",
    "https://169%2E254%2E169%2E254/",
    "http://169%2e254%2e169%2e254/latest/meta-data/",
    "https://169.254.169.254%2E/",
    "https://169.254.169.254%00.evil.example/",
    "https://169.254.169.254%/",
    "https://169.254.169.254%zz/",
    "https://10.0.0.1%2",
    "http://2852039166/",
    "http://0xA9FEA9FE/",
    "http://0251.0376.0251.0376/",
    "http://169.254.169.254./",
    "http://[::ffff:169.254.169.254]",
    "http://[::1]:443/",
    "http://[fd00:ec2::254]/",
    "https://10.0.0.1\\x.allowed.com/",
    "https://api.example.com@169.254.169.254/",
    "https://user:pass@10.99.99.99:8443/v1",
    "https://169.254.169.254:80/?q=#frag",
    "https://169.254.169.254#@allowed.com",
    "",
    " ",
    "https://",
    "https:// ",
    "://169.254.169.254",
    "ftp://169.254.169.254/",
    "HTTPS://169.254.169.254/",
    "https://169.254.169.254",
];

const BARE_AUTHORITIES: &[&str] = &[
    "10.99.99.99",
    "10.99.99.99 ",
    " 10.99.99.99:8443",
    "169.254.169.254:8080",
    "169.254.169.254 ",
    "api.example.com",
];

#[test]
fn both_names_reach_one_extraction() {
    let mut compared = 0usize;
    for spelling in HOSTILE.iter().chain(BARE_AUTHORITIES) {
        let through_kernel = busbar_kernel::config_validate::extract_normalized_host(spelling);
        let through_unit = busbar_kernel_egress::trust::net::extract_normalized_host(spelling);
        assert_eq!(
            through_kernel, through_unit,
            "`busbar_kernel::config_validate` and the egress unit read {spelling:?} as different hosts — \
             the shim has grown a second definition, and whichever one a call site routes through \
             now decides whether this destination is guarded"
        );
        compared += 1;
    }

    assert!(
        compared >= 40,
        "the hostile table shrank; a deleted row is a spelling that stopped being judged in public"
    );
}

#[test]
fn both_names_reach_one_denylist_judgement() {
    let operator_blocked = vec!["10.99.99.99".to_string(), "internal.example".to_string()];
    let operator_allowed = vec!["api.example.com".to_string()];
    for spelling in HOSTILE.iter().chain(BARE_AUTHORITIES) {
        assert_eq!(
            busbar_kernel::config_validate::ssrf_blocked_host(spelling, &[], false, &[]),
            busbar_kernel_egress::trust::net::ssrf_blocked_host(spelling, &[], false, &[]),
            "bare guard disagrees on {spelling:?}"
        );

        assert_eq!(
            busbar_kernel::config_validate::ssrf_blocked_host(
                spelling,
                &[],
                false,
                &operator_blocked
            ),
            busbar_kernel_egress::trust::net::ssrf_blocked_host(
                spelling,
                &[],
                false,
                &operator_blocked
            ),
            "operator denylist disagrees on {spelling:?}"
        );

        assert_eq!(
            busbar_kernel::config_validate::ssrf_blocked_host(
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

#[test]
fn the_bare_authority_arm_is_reached_through_the_kernel_name() {
    let operator_blocked = ["10.99.99.99".to_string()];
    let mut refused = 0usize;
    for spelling in BARE_AUTHORITIES {
        for blocked in [&[][..], &operator_blocked[..]] {
            let through_kernel =
                busbar_kernel::config_validate::ssrf_blocked_host(spelling, &[], false, blocked);
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

#[test]
fn the_dialing_arm_and_the_config_arm_read_the_same_metadata_list() {
    let names = busbar_contract::net::METADATA_HOSTS;
    assert_eq!(
        names,
        busbar_kernel_egress::trust::net::METADATA_HOSTS,
        "the contract and the unit publish different metadata lists"
    );
    assert!(
        names.len() >= 6 && names.contains(&"metadata.platformequinix.com"),
        "the metadata list shrank back toward the two-entry copy: {names:?}"
    );
    for name in names {
        assert!(
            busbar_kernel::config_validate::ssrf_blocked_host(
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

#[test]
fn the_hostile_table_actually_reaches_the_guard_through_both_names() {
    let mut blocked_through_kernel = 0usize;
    let mut blocked_through_unit = 0usize;
    for spelling in HOSTILE {
        if busbar_kernel::config_validate::ssrf_blocked_host(spelling, &[], false, &[]).is_some() {
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
