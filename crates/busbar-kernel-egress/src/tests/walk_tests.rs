// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The walk: how many attempts, which cell they record against, when a failure fails over, and
//! when it does not.
//!
//! Carried over from the previous release's pool-cell and reroute tests. The claims are the same:
//! a member that cannot be reached at all is failed over from; a member that answered is not; the
//! outcome lands on the ROUTING pool's cell and not the default one; the hop cap is a hop cap and
//! not an attempt cap; and the request budget is spent once, after the success, and given back
//! when the answer does not arrive whole.

// ── the lane cross-check ─────────────────────────────────────────────────────────────────────────

mod lane_cross_check {
    use crate::attempt::lane_matches_seal;
    use busbar_contract::LaneId;

    fn field(name: &str, value: &str) -> (String, Vec<u8>) {
        (name.to_string(), value.as_bytes().to_vec())
    }

    fn sealed() -> Option<LaneId> {
        Some(LaneId::new("lane-a"))
    }

    /// The matching case, and the plain divergence — the check's reason for existing.
    #[test]
    fn the_envelope_lane_must_be_the_one_the_trust_unit_sealed() {
        assert!(lane_matches_seal(Some("host"), &[field("host", "lane-a")], sealed()).is_ok());
        assert!(lane_matches_seal(Some("host"), &[field("host", "lane-b")], sealed()).is_err());
        // No lane field declared, or the envelope carries none: nothing to cross-check.
        assert!(lane_matches_seal(None, &[field("host", "lane-b")], sealed()).is_ok());
        assert!(lane_matches_seal(Some("host"), &[field("other", "x")], sealed()).is_ok());
    }

    /// ENVELOPE FIELD NAMES ARE CASE-INSENSITIVE ON THE WIRE, so the check must be too.
    ///
    /// A case-sensitive `find` let a decoration that wrote `Host` where the lane field is spelled
    /// `host` carry any lane it liked: the check found nothing, returned `Ok`, and the request went
    /// out on a lane nobody had compared against the seal. The egress-auth unit's own cross-check
    /// has always matched with `eq_ignore_ascii_case`; this one now agrees.
    #[test]
    fn the_field_is_found_whatever_case_the_decoration_spelled_it_in() {
        assert!(
            lane_matches_seal(Some("host"), &[field("Host", "lane-b")], sealed()).is_err(),
            "a diverged lane under a different capitalisation is still a diverged lane"
        );
        assert!(lane_matches_seal(Some("host"), &[field("HOST", "lane-a")], sealed()).is_ok());
        assert!(lane_matches_seal(Some("Host"), &[field("host", "lane-b")], sealed()).is_err());
    }

    /// TWO ENTRIES CARRYING THE LANE FIELD IS A REFUSAL, not a first-match.
    ///
    /// Taking the first meant a decoration could append a second spelling of the field and leave
    /// the check answering about the entry it was happy with while the transport encoded both. A
    /// request whose lane is written down twice has no answer to "which lane is this priced on".
    #[test]
    fn a_duplicated_lane_field_is_refused_rather_than_read_first_match() {
        let duplicated = [field("host", "lane-a"), field("host", "lane-b")];
        assert!(
            lane_matches_seal(Some("host"), &duplicated, sealed()).is_err(),
            "the first entry agreeing with the seal does not make the second one disappear"
        );
        // Including across spellings, and including when both agree — the ambiguity is the defect.
        let mixed_case = [field("host", "lane-a"), field("Host", "lane-a")];
        assert!(lane_matches_seal(Some("host"), &mixed_case, sealed()).is_err());
        // And a destination with no sealed lane still refuses a duplicate: the field is unreadable
        // whatever it would have been compared against.
        assert!(lane_matches_seal(Some("host"), &duplicated, None).is_err());
    }
}
