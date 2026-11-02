// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::release_none_contract;

#[test]
fn release_none_accepts_only_the_two_exact_plane_lifecycle_answers() {
    for answer in [
        "Ready lease=false ",
        "Refused lease=false release: no such lease",
    ] {
        release_none_contract(answer);
    }
}

#[test]
fn release_none_rejects_faults_unexplained_refusals_and_other_errors() {
    for answer in [
        "Fault lease=false ",
        "Fault lease=false release: no such lease",
        "Refused lease=false ",
        "Refused lease=false another error",
        "Refused lease=false release: no such lease trailing bytes",
        "Refused lease=true release: no such lease",
        "Ready lease=true ",
        "Ready lease=false another error",
        "Ready lease=false",
        "Failed lease=false release: no such lease",
        "Pending lease=false ",
    ] {
        assert!(
            std::panic::catch_unwind(|| release_none_contract(answer)).is_err(),
            "an invalid release-none answer was accepted: {answer}"
        );
    }
}
