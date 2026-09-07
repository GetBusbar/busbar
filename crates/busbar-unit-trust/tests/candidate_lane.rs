// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `Candidate::lane` reads the lane off the facts the plane wrote.
//!
//! The whole point of the accessor is that the lane is not a second copy kept beside the facts —
//! it is read off them, so the two cannot disagree. A version that answered `None` for everything
//! would leave every existing test in the crate green: nothing else calls it. Downstream, a
//! candidate that reports no lane is a candidate with no lane to price, no lane for the breaker to
//! hold an opinion about, and no lane for the allow-list to be checked against — the three
//! conjuncts the upstream rule is made of, all skipped, silently.

use busbar_contract::UpstreamAddress;
use busbar_unit_trust::{Candidate, DestinationFacts};

fn candidate(facts: DestinationFacts) -> Candidate {
    Candidate {
        facts,
        lane_index: None,
    }
}

/// Every kind that HAS a lane reports that lane, and every kind that has none reports none.
#[test]
fn a_candidate_reports_the_lane_its_facts_carry_and_only_that_lane() {
    let priced = busbar_caps::LaneId::new("bedrock-us-east-1");
    let other = busbar_caps::LaneId::new("openai-default");

    for (what, facts, want) in [
        (
            "a fresh upstream",
            DestinationFacts::Upstream {
                transport: "tls",
                address: UpstreamAddress::Socket {
                    authority: "bedrock.us-east-1.amazonaws.com:443",
                    sni: None,
                    extras: &[],
                },
                lane: priced,
            },
            Some(priced),
        ),
        (
            "an upstream on a different lane",
            DestinationFacts::Upstream {
                transport: "tls",
                address: UpstreamAddress::Socket {
                    authority: "api.openai.com:443",
                    sni: None,
                    extras: &[],
                },
                lane: other,
            },
            Some(other),
        ),
        (
            "a session accrual",
            DestinationFacts::SessionAccrual { lane: priced },
            Some(priced),
        ),
        (
            "a kernel verb, which is not priced on a lane",
            DestinationFacts::KernelVerb { verb: "status" },
            None,
        ),
        (
            "a peer, which is not priced on a lane",
            DestinationFacts::Peer {
                node: "node-b",
                selector: "session",
            },
            None,
        ),
    ] {
        assert_eq!(candidate(facts).lane(), want, "{what}");
    }
}

/// The lane the accessor answers is the facts' own, not a value the candidate was separately given:
/// two candidates over the same facts answer the same lane whatever else differs about them.
#[test]
fn the_lane_comes_from_the_facts_and_not_from_anything_beside_them() {
    let lane = busbar_caps::LaneId::new("bedrock-us-east-1");
    let facts = DestinationFacts::Upstream {
        transport: "tls",
        address: UpstreamAddress::Socket {
            authority: "bedrock.us-east-1.amazonaws.com:443",
            sni: None,
            extras: &[],
        },
        lane,
    };
    let unindexed = Candidate {
        facts,
        lane_index: None,
    };
    let indexed = Candidate {
        facts,
        lane_index: Some(3),
    };
    assert_eq!(unindexed.lane(), Some(lane));
    assert_eq!(indexed.lane(), Some(lane));
    assert_eq!(unindexed.lane(), facts.lane());
}
