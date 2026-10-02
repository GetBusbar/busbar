# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""`python3 -m a2asup` -- point the supplementary suite at one A2A subject.

EXIT CODES, and they are three because two would hide the difference that matters:
    0   every MUST this suite can decide was decided and passed
    1   the suite ran and the subject failed at least one requirement -- a NUMBER
    3   the suite could not START (no card, no usable interface) -- the ABSENCE of a number
A caller that treats 3 as "a low score" is reporting a verdict on a run that never happened.
"""

from __future__ import annotations

import argparse
import sys

from a2asup.runner import report, run
from a2asup.target import Target
from a2asup.verifier_probe import build_verifier_probe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="a2asup",
        description=(
            "Busbar-authored supplementary conformance coverage for A2A requirements the pinned "
            "official TCK declares and does not execute. NOT the official TCK; its counts are "
            "never added to the TCK's."
        ),
    )
    parser.add_argument("--label", required=True, help="names this target in every report line")
    parser.add_argument(
        "--card-url",
        required=True,
        help="the subject's Agent Card. Every endpoint driven is read out of it (SPEC 5.2).",
    )
    parser.add_argument("--token", help="credential for principal A")
    parser.add_argument(
        "--token-b",
        help=(
            "credential for a SECOND, distinct principal. AUTH-SCOPE-002/003 cannot be decided "
            "without it and say so rather than passing vacuously."
        ),
    )
    parser.add_argument(
        "--issuer-key",
        help=(
            "base64 DER SubjectPublicKeyInfo of the card-signing public key, obtained out of band "
            "as SPEC 8.4 assumes. Required to decide CARD-SIGN-001/002 for a signed card."
        ),
    )
    parser.add_argument(
        "--upstream-record",
        help=(
            "JSONL of the requests the subject ORIGINATED upstream. The only vantage point from "
            "which VER-CLIENT-001 (a client-role requirement) is decidable."
        ),
    )
    parser.add_argument(
        "--admin-base",
        help=(
            "operator API base URL of a subject that VERIFIES upstream agent cards. Enables the "
            "CARD-SIGN-004 probe; without it that requirement reports NOT_APPLICABLE."
        ),
    )
    parser.add_argument("--admin-token", help="bearer for --admin-base")
    parser.add_argument(
        "--verifier-agent-url",
        help="an agent endpoint whose card the subject would fetch and verify, for CARD-SIGN-004",
    )
    parser.add_argument("--json", dest="json_out", help="write the machine-readable report here")
    args = parser.parse_args(argv)

    target = Target(
        label=args.label,
        card_url=args.card_url,
        token=args.token,
        token_b=args.token_b,
        upstream_record=args.upstream_record,
    )
    try:
        target.load()
    except Exception as exc:  # noqa: BLE001
        print(f"a2asup: could not start: {exc}", file=sys.stderr)
        print(
            "a2asup: exit 3 means NOTHING WAS TESTED. That is the absence of a score, not a low "
            "one, and it must not be reported as a conformance result.",
            file=sys.stderr,
        )
        return 3

    print(f"a2a-supplement vs {args.label}")
    print(f"  card: {args.card_url}")
    print(f"  interfaces: {[(i.binding, i.version, i.url) for i in target.interfaces]}")
    print(
        f"  credentials: principal A {'yes' if args.token else 'NO'}, "
        f"principal B {'yes' if args.token_b else 'NO'}, "
        f"issuer key {'yes' if args.issuer_key else 'NO'}, "
        f"upstream recording {'yes' if args.upstream_record else 'NO'}"
    )
    print()

    verifier_probe = build_verifier_probe(
        admin_base=args.admin_base,
        admin_token=args.admin_token,
        agent_url=args.verifier_agent_url,
    )
    results = run(target, args.issuer_key, verifier_probe)
    return report(target, results, args.json_out)


if __name__ == "__main__":
    raise SystemExit(main())
