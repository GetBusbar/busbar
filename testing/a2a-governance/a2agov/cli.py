"""Governance probe. A SEPARATE TOOL from the conformance harness, on purpose.

The conformance harness (testing/a2a-harness) derives its entire value from
containing ZERO product knowledge. It is a clean-room reading of the published
A2A specification and nothing else, which is what lets it be pointed at any
implementation, including ours, without the test author's assumptions leaking
into the verdict.

Governance is product knowledge by definition: budgets, quarantine, trust
lifecycle and approval are OUR policy, not the protocol's. Putting them in the
same package would contaminate the harness and, worse, would let a green
conformance tick be read as a governance pass.

So this lives outside, imports the harness as a LIBRARY for its fake peers and
its driver, and never contributes to a conformance verdict.
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "a2a-harness"))

from a2aht import runner, model                     # noqa: E402
from a2aht.target import Target                     # noqa: E402
from a2agov import tests_governance                 # noqa: E402,F401


BANNER = """
================================================================================
A2A GOVERNANCE PROBE -- THIS IS NOT A CONFORMANCE RESULT
================================================================================
A conformance pass says the target speaks A2A correctly. It says NOTHING about
budgets, rate limits, quarantine, audit, or the trust lifecycle. A perfectly
conformant agent that ignores every budget and never quarantines anything
scores 100% on the conformance battery.

This probe observes ONLY what is visible from a peer the harness controls.
Most of governance is NOT visible from outside. See gov.governance_scope_is_declared.
================================================================================
"""


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="a2agov",
        description="Peer-observable A2A governance probe. NOT conformance.")
    ap.add_argument("--endpoint")
    ap.add_argument("--launch")
    ap.add_argument("--port", type=int)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--client-drive", required=True,
                    help="command that makes the subject delegate to {url}")
    ap.add_argument("--label", default="subject")
    ap.add_argument("--json")
    args = ap.parse_args(argv)

    print(BANNER)

    tests = [t for t in model.all_tests()
             if t.role == model.ROLE_GOVERNANCE]
    if not tests:
        sys.exit("no governance tests registered")

    target = Target(endpoint=args.endpoint, launch=args.launch,
                    port=args.port, host=args.host, label=args.label)
    target.start()
    try:
        results = runner.run_battery(
            target, {"client_drive": args.client_drive}, tests)
    finally:
        target.stop()

    rep = runner.report(results, target.label,
                        meta={"kind": "governance-probe",
                              "not_a_conformance_result": True})
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(rep, fh, indent=2, sort_keys=True)
    runner.print_human(rep, verbose=True)
    print("REMINDER: this is a governance probe, not a conformance verdict.\n")
    # A governance probe never gates on pass/fail; it reports observations.
    return 0


if __name__ == "__main__":
    sys.exit(main())
