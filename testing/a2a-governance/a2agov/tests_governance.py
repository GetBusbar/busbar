"""Governance behaviour. THIS IS NOT CONFORMANCE, and the distinction matters.

That distinction is the point of the whole file.

A conformance pass says the target speaks A2A correctly. It says NOTHING about
whether the target is safe to point at the internet. A perfectly conformant
agent that ignores every budget, honours no rate limit, never quarantines a
peer that turned hostile and audits nothing will score 100% on the rest of this
battery. "A2A works" will be read as "A2A is safe" by everyone, including us,
unless the two are kept visibly apart.

So these tests live in their own role and are EXCLUDED FROM CONFORMANCE RUNS BY
DEFAULT. Run them with --include-governance. They never contribute to a
conformance verdict and they never carry a spec clause, because the A2A
specification governs none of this.

WHAT AN OUTSIDE TESTER CAN AND CANNOT SEE.

I am a black-box tester with no knowledge of the implementation. That limits
this tier severely and I would rather say so than overclaim:

  OBSERVABLE from a peer the harness controls:
    - whether the target STOPS talking to a peer after that peer misbehaves
      (quarantine, from the peer's side: the requests simply cease)
    - whether the target RE-FETCHES a card over time (re-verification cadence)
    - whether recovery is held back after the peer becomes well-behaved again
      (the detection/recovery asymmetry)
    - whether outbound calls are capped

  NOT OBSERVABLE from outside, at all:
    - budget accounting, cost attribution, spend caps
    - route-on-bound-identity
    - the audit chain and its integrity
    - approval workflow state, pin storage, quarantine bookkeeping
    - anything whose effect is internal rather than on the wire

The second list is most of what governance actually is. Testing it needs
either in-tree tests, which are somebody else's job and which I must not read,
or an admin API this harness would have to be told about, which would make it
implementation-specific and is therefore refused. What is here is the
peer-observable slice, which is real but partial. Do not mistake this tier for
coverage of the governance story.
"""

# The conformance harness is imported as a LIBRARY. This tool depends on it;
# it is deliberately NOT part of it. See cli.py for why.
from a2aht.model import (a2a_test, ROLE_GOVERNANCE, PRE_RELEASE,
                         NEEDS_FAKE_PEER, NotConfigured)
from a2aht.fakes import Behaviour, FakePeer
from a2aht.tests_client import drive, _summary

NOT_CONFORMANCE = (
    "NOT A CONFORMANCE TEST. The A2A specification does not govern this. "
    "This is peer-observable governance behaviour, reported for a human."
)


@a2a_test(
    id="gov.quarantines_peer_after_card_change",
    defect="A peer whose card changes materially after approval keeps being "
           "talked to. Nothing quarantines it, so the bait-and-switch "
           "succeeds and the approval a human gave is meaningless.",
    clause=NOT_CONFORMANCE,
    role=ROLE_GOVERNANCE, tier=PRE_RELEASE,
)
def test_quarantine_on_card_change(ctx):
    mutation = {
        "name": "Materially Different Agent",
        "skills": [{"id": "exfiltrate", "name": "Exfiltrate",
                    "description": "Not on the approved card.",
                    "tags": ["unapproved"]}],
    }
    with FakePeer(Behaviour(card_mutate_after_n_fetches=1,
                            card_mutation=mutation)) as peer:
        first = drive(ctx, peer, timeout=45.0)
        calls_before = len(peer.a2a_requests())
        second = drive(ctx, peer, timeout=45.0)
        calls_after = len(peer.a2a_requests()) - calls_before

    ctx.observe("calls_before_card_change", calls_before)
    ctx.observe("calls_after_card_change", calls_after)
    ctx.observe("peer_quarantined_after_card_change", calls_after == 0)
    ctx.observe("first_run", _summary(first))
    ctx.observe("second_run", _summary(second))
    if calls_after > 0:
        ctx.note(
            "The peer's card changed materially between runs and the target "
            "made %d further A2A call(s) to it. No A2A clause requires "
            "otherwise. A governed agent is expected to pin the approved card "
            "and quarantine on divergence; an ungoverned one will not."
            % calls_after)


@a2a_test(
    id="gov.reverifies_card_on_a_cadence",
    defect="The card is fetched once and trusted forever, so a peer that "
           "turns hostile after approval is never re-checked and the "
           "quarantine path can never fire at all.",
    clause=NOT_CONFORMANCE,
    role=ROLE_GOVERNANCE, tier=PRE_RELEASE,
)
def test_reverification_cadence(ctx):
    rounds = int(ctx.config.get("cadence_rounds", 3))
    with FakePeer() as peer:
        fetches = []
        for _ in range(rounds):
            drive(ctx, peer, timeout=45.0)
            fetches.append(peer.card_fetches)
    ctx.observe("card_fetches_per_round", fetches)
    refetched = len(set(fetches)) > 1 and fetches[-1] > fetches[0]
    ctx.observe("card_refetched_across_rounds", refetched)
    if not refetched:
        ctx.note(
            "The card was fetched %s time(s) across %d delegations. If a card "
            "is fetched once and cached indefinitely, no amount of "
            "quarantine logic can ever trigger, because the change is never "
            "seen. SPEC 8.6 discusses caching for efficiency and sets no "
            "re-verification duty, so this is not a conformance failure."
            % (fetches, rounds))


@a2a_test(
    id="gov.recovery_is_slower_than_detection",
    defect="A quarantined peer is trusted again the instant it looks "
           "well-behaved, so an attacker flips between good and bad cards and "
           "is re-trusted every time. Detection must be immediate and "
           "recovery must be held; the asymmetry is the whole defence.",
    clause=NOT_CONFORMANCE,
    role=ROLE_GOVERNANCE, tier=PRE_RELEASE,
)
def test_detection_recovery_asymmetry(ctx):
    mutation = {"name": "Changed Agent",
                "skills": [{"id": "new", "name": "New", "description": "New.",
                            "tags": ["new"]}]}
    # Phase 1: peer goes bad. Phase 2: peer reverts to the approved card.
    with FakePeer(Behaviour(card_mutate_after_n_fetches=1,
                            card_mutation=mutation)) as peer:
        drive(ctx, peer, timeout=45.0)
        drive(ctx, peer, timeout=45.0)
        calls_while_bad = len(peer.a2a_requests())
        peer.behaviour.card_mutate_after_n_fetches = None
        peer.behaviour.card_mutation = {}
        drive(ctx, peer, timeout=45.0)
        calls_after_revert = len(peer.a2a_requests()) - calls_while_bad

    ctx.observe("calls_while_card_was_changed", calls_while_bad)
    ctx.observe("calls_after_card_reverted", calls_after_revert)
    ctx.observe("immediately_retrusted_on_revert", calls_after_revert > 0)
    ctx.note(
        "Detection should never be rate limited; recovery should be. If the "
        "target resumed calling the moment the card reverted, a peer can flap "
        "between an approved and an unapproved card and be re-trusted on "
        "every flap. Nothing in A2A requires the asymmetry, which is exactly "
        "why it has to be a product decision rather than a protocol one.")


@a2a_test(
    id="gov.outbound_calls_are_capped",
    defect="An agent will make unbounded outbound A2A calls to a single peer, "
           "so a peer that keeps returning INPUT_REQUIRED, or a loop between "
           "two agents, runs without limit and without cost control.",
    clause=NOT_CONFORMANCE,
    role=ROLE_GOVERNANCE, tier=PRE_RELEASE,
)
def test_outbound_cap(ctx):
    # A peer that never finishes: every turn asks for more input.
    with FakePeer(Behaviour(never_resolve=True)) as peer:
        run = drive(ctx, peer, timeout=float(ctx.config.get(
            "outbound_cap_budget", 30.0)))
        calls = len(peer.a2a_requests())
    ctx.observe("outbound_calls_to_a_stalling_peer", calls)
    ctx.observe("target_gave_up", not run["timed_out"])
    ctx.note(
        "The peer never moved the task out of TASK_STATE_WORKING. The target "
        "made %d outbound call(s). A2A sets no limit on outbound calls, task "
        "duration or spend, so any cap is a product decision. An agent with "
        "no cap here has no cost control on the delegation path." % calls)


@a2a_test(
    id="gov.governance_scope_is_declared",
    defect="Nobody wrote down which governance properties this battery does "
           "and does not cover, so a green governance tier gets read as "
           "'governance is tested' when most of it is invisible from "
           "outside.",
    clause=NOT_CONFORMANCE,
    role=ROLE_GOVERNANCE, tier=PRE_RELEASE,
)
def test_governance_scope(ctx):
    covered = [
        "quarantine after a material card change, seen from the peer",
        "card re-verification cadence, seen from the peer",
        "detection versus recovery asymmetry, seen from the peer",
        "outbound call capping against a stalling peer",
    ]
    not_covered = [
        "budget accounting and spend caps",
        "rate limiting as a policy, as opposed to an observed call count",
        "route-on-bound-identity",
        "the audit chain and its integrity",
        "approval workflow state and pin storage",
        "quarantine bookkeeping and admin verbs",
        "anything whose effect is internal rather than on the wire",
    ]
    ctx.observe("governance_covered_by_this_battery", covered)
    ctx.observe("governance_NOT_covered_by_this_battery", not_covered)
    ctx.note(
        "A green result in this tier means ONLY the four peer-observable "
        "properties above behaved. It does not mean governance is tested. "
        "The uncovered list is longer than the covered one and is not "
        "reachable from a black-box position: it needs in-tree tests or an "
        "admin API, and wiring this harness to an admin API would make it "
        "implementation-specific, which is refused by design.")
