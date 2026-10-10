"""Command line entry point.

  python -m a2aht run       run the battery against one target
  python -m a2aht diff      compare a subject report to a control report
  python -m a2aht baseline  check a control run against its pinned baseline
  python -m a2aht list      list the battery with defect lines

The target is always configuration. There is no flag anywhere that names a
particular implementation.
"""

import argparse
import json
import sys

from . import runner
from .model import EVERY_COMMIT, PULL_REQUEST, PRE_RELEASE
from .target import Target, TargetError


def _target_args(p):
    p.add_argument("--endpoint", help="base URL of an already-running agent")
    p.add_argument("--launch", help="command that starts the agent; the "
                                    "harness starts and stops it")
    p.add_argument("--port", type=int,
                   help="port the launched agent listens on; required with "
                        "--launch so readiness can be detected without "
                        "sleeping")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--cwd", help="working directory for --launch")
    p.add_argument("--card-url", help="explicit agent card URL, if the agent "
                                      "does not serve the well-known path")
    p.add_argument("--auth", help="an auth header, as 'Name: value'")
    p.add_argument("--insecure-tls", action="store_true",
                   help="do not verify TLS certificates")
    p.add_argument("--label", default=None,
                   help="name for this target in reports")
    p.add_argument("--allow-undriven-bindings", default="",
                   help="comma-separated bindings the target declares that "
                        "this battery cannot drive (e.g. GRPC). Records them "
                        "as an ACKNOWLEDGED GAP instead of failing. Never "
                        "silently ignored.")
    p.add_argument("--client-drive",
                   help="command that makes the target act as an A2A CLIENT. "
                        "{url} is replaced with the fake peer base URL and "
                        "{card_url} with its agent card URL. Without this, "
                        "client-role tests report NOT_CONFIGURED and the run "
                        "is RED.")


def build_target(args):
    return Target(
        endpoint=args.endpoint, launch=args.launch, port=args.port,
        host=args.host, card_url=args.card_url, auth_header=args.auth,
        insecure=args.insecure_tls, cwd=args.cwd,
        label=args.label or args.endpoint or args.launch or "target",
    )


def build_config(args):
    return {
        "client_drive": getattr(args, "client_drive", None),
        "cwd": getattr(args, "cwd", None),
        "concurrency": getattr(args, "concurrency", 8),
        "allow_undriven_bindings": getattr(args, "allow_undriven_bindings", ""),
    }


def cmd_run(args):
    tests = runner.load_tests()
    selected = runner.select(tests, tier=args.tier, role=args.role,
                             only=args.only,
                             needs=set(args.needs) if args.needs else None,
                             include_governance=getattr(
                                 args, "include_governance", False))
    if not selected:
        sys.stderr.write("no tests selected\n")
        return 2

    target = build_target(args)
    config = build_config(args)
    try:
        target.start()
    except TargetError as exc:
        sys.stderr.write("\n")
        sys.stderr.write("=" * 72 + "\n")
        sys.stderr.write("A2A CONFORMANCE GATE CANNOT RUN\n")
        sys.stderr.write("=" * 72 + "\n")
        sys.stderr.write("%s\n" % exc)
        sys.stderr.write(
            "\nThe subject under test is NOT REACHABLE, so independent A2A "
            "conformance CANNOT be established. This gate REFUSES TO PASS "
            "VACUOUSLY. It is red because nothing was tested, not because "
            "something failed.\n")
        sys.stderr.write("=" * 72 + "\n\n")
        return 3

    # Preflight. If the subject is not there at all, say so ONCE and loudly,
    # rather than emitting one stack trace per test. Fourteen tracebacks is
    # not a legible failure, and a gate nobody can read is a gate nobody acts
    # on.
    problem = _preflight(target)
    if problem:
        sys.stderr.write("\n")
        sys.stderr.write("=" * 72 + "\n")
        sys.stderr.write("A2A CONFORMANCE GATE: SUBJECT NOT REACHABLE\n")
        sys.stderr.write("=" * 72 + "\n")
        sys.stderr.write("%s\n\n" % problem)
        sys.stderr.write(
            "The implementation under test is NOT PRESENT, so independent "
            "A2A conformance CANNOT be established. This gate REFUSES TO "
            "PASS VACUOUSLY.\n\n"
            "This run is RED because NOTHING WAS TESTED, not because a test "
            "failed. Nothing about the harness is broken: run it against the "
            "pinned control to confirm.\n")
        sys.stderr.write("=" * 72 + "\n\n")
        target.stop()
        return 3

    try:
        results = runner.run_battery(target, config, selected)
    finally:
        target.stop()

    rep = runner.report(results, target.label,
                        meta={"tier": args.tier,
                              "client_drive_configured":
                                  bool(config["client_drive"]),
                              # WHICH DIRECTIONS THIS RUN MEASURED. `--role server`
                              # is a legitimate narrowing and it stays legitimate;
                              # what it must never be is INVISIBLE in the number it
                              # produces.
                              "role_audit": runner.role_audit(
                                  tests, selected, tier=args.tier)})

    if getattr(args, "known_deviations", None):
        from . import deviations
        try:
            doc = deviations.load(args.known_deviations)
        except deviations.DeviationFileError as exc:
            sys.stderr.write("\nKNOWN DEVIATION FILE REJECTED\n%s\n\n" % exc)
            return 4
        rep, _problems = deviations.apply(rep, doc)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(rep, fh, indent=2, sort_keys=True)
        sys.stderr.write("wrote %s\n" % args.json)
    bad = runner.print_human(rep, verbose=args.verbose)
    if rep.get("known_deviations"):
        from . import deviations
        deviations.print_summary(rep, sys.stdout)
    if args.allow_red:
        return 0
    return 1 if bad else 0


def _preflight(target):
    """Return a human-readable problem string, or None if the target answers.

    Deliberately narrow: this only distinguishes "nothing is listening / no
    card at all" from "an agent is there". Anything an agent actually answers,
    however badly, is a job for the battery, not for the preflight.
    """
    import urllib.parse
    from . import transport

    parts = urllib.parse.urlsplit(target.endpoint or "")
    if not parts.hostname:
        return "no usable endpoint was resolved for this target"
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if not transport.port_open(parts.hostname, port, timeout=5.0):
        return ("nothing is listening on %s:%s (from --endpoint %s)"
                % (parts.hostname, port, target.endpoint))
    resp = target.fetch_card_response(force=True)
    if resp is None or resp.status != 200 or resp.json_or_none() is None:
        return (
            "something is listening on %s:%s but it served no agent card at "
            "any of %s (last status %s).\n"
            "SPEC 8.1: 'A2A Servers MUST make an Agent Card available.' "
            "Without a card there is no A2A agent here to test."
            % (parts.hostname, port, target.card_candidates(),
               resp.status if resp else "no response"))
    return None


def cmd_diff(args):
    with open(args.control) as fh:
        control = json.load(fh)
    with open(args.subject) as fh:
        subject = json.load(fh)
    diff = runner.differential(control, subject)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(diff, fh, indent=2, sort_keys=True)
    defects = runner.print_differential(diff)
    return 1 if defects else 0


def cmd_baseline(args):
    with open(args.report) as fh:
        rep = json.load(fh)
    with open(args.baseline) as fh:
        base = json.load(fh)
    changes = runner.compare_to_baseline(rep, base)
    if not changes:
        print("\nCONTROL BASELINE MATCHED: %d tests, all outcomes identical "
              "to the pinned baseline.\n" % len(rep["results"]))
        return 0
    print("\nCONTROL BASELINE MISMATCH\n")
    print("The control is a KNOWN-GOOD reference pinned to an exact version. "
          "If its results changed, either the harness changed behaviour or "
          "the control did. Both need a human before any subject result can "
          "be trusted.\n")
    for c in changes:
        print("  %-52s baseline=%-14s now=%s"
              % (c["id"], c["baseline"], c["now"]))
    print("")
    return 1


def cmd_fake_peer(args):
    """Run a fake peer. `--broken` is the harness's negative control.

    A test suite that has never been seen to fail is not known to work. The
    broken peer violates a spread of specific MUSTs, so pointing the battery
    at it proves the battery actually fires, and proves the aiming mechanism
    works, using nothing but a variable change.
    """
    import time
    from .fakes import Behaviour, FakePeer

    behaviour = Behaviour()
    if args.broken:
        behaviour = Behaviour(
            # SPEC 5.7 / PROTO AgentCard: a REQUIRED field is absent.
            card_missing_fields=["version"],
            # SPEC 3.6: a patch-level protocol version in the card.
            card_protocol_version="1.0.3",
            # PROTO enum TaskState: a state that does not exist.
            emit_unknown_task_state="TASK_STATE_MADE_UP",
            # SPEC 3.4.2: task ids MUST be unique per task.
            emit_duplicate_task_ids=True,
            # SPEC 3.1.2: the stream MUST close at a terminal state.
            emit_response_to_nothing=True,
        )
    peer = FakePeer(behaviour, host=args.host, port=args.port,
                    binding=args.binding)
    peer.start()
    kind = "BROKEN (negative control)" if args.broken else "honest"
    print("fake A2A peer [%s] listening at %s" % (kind, peer.base_url))
    print("agent card: %s%s" % (peer.base_url, "/.well-known/agent-card.json"))
    if args.broken:
        print("\nthis peer deliberately violates, at minimum:")
        print("  PROTO AgentCard        the REQUIRED 'version' field is absent")
        print("  SPEC 3.6               card advertises protocolVersion 1.0.3")
        print("  PROTO enum TaskState   emits TASK_STATE_MADE_UP")
        print("  SPEC 3.4.2             reuses one task id for every task")
        print("  SPEC 3.1.2             streams an event for a task that was "
              "never created")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        peer.stop()
    return 0


def cmd_list(args):
    tests = runner.load_tests()
    by_role = {}
    for test in tests:
        by_role.setdefault(test.role, []).append(test)
    total = 0
    for role in sorted(by_role):
        print("\n%s ROLE" % role.upper())
        for test in sorted(by_role[role], key=lambda t: t.id):
            total += 1
            print("  %-52s %-14s %s" % (test.id, test.tier, test.needs))
            print("      catches: %s" % test.defect)
            if args.clauses:
                print("      clause : %s" % test.clause)
    print("\n%d tests total\n" % total)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="a2aht",
        description="Independent third-party A2A conformance battery, "
                    "written from the published specification (a2aproject/A2A "
                    "v1.0.1) with no knowledge of any implementation.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the battery against a target")
    _target_args(r)
    r.add_argument("--tier", choices=[EVERY_COMMIT, PULL_REQUEST, PRE_RELEASE],
                   default=PULL_REQUEST,
                   help="run tests up to and including this tier")
    r.add_argument("--role",
                   choices=["server", "client", "seam", "governance"])
    r.add_argument("--include-governance", action="store_true",
                   help="also run the GOVERNANCE tier. These are NOT "
                        "conformance tests and never contribute to a "
                        "conformance verdict.")
    r.add_argument("--only", nargs="*", help="substrings of test ids to run")
    r.add_argument("--needs", nargs="*",
                   choices=["fake-peer", "real-peer", "human"])
    r.add_argument("--concurrency", type=int, default=8)
    r.add_argument("--json", help="write the machine-readable report here")
    r.add_argument("--verbose", action="store_true",
                   help="print observations for passing tests too")
    r.add_argument("--allow-red", action="store_true",
                   help="always exit 0; for recording a baseline")
    r.add_argument("--known-deviations",
                   help="JSON file enumerating known deviations of this "
                        "target, each with clause, evidence and judgement. "
                        "Matching failures become BASELINED; an unrecorded "
                        "failure, a changed one, or a recorded one that has "
                        "been fixed all stay RED.")
    r.set_defaults(fn=cmd_run)

    f = sub.add_parser("fake-peer",
                       help="run a fake A2A peer; --broken gives the "
                            "negative control")
    f.add_argument("--port", type=int, default=0)
    f.add_argument("--host", default="127.0.0.1")
    f.add_argument("--binding", default="HTTP+JSON",
                   choices=["HTTP+JSON", "JSONRPC"])
    f.add_argument("--broken", action="store_true",
                   help="a deliberately non-conformant peer, used to prove "
                        "the battery actually fails when it should")
    f.set_defaults(fn=cmd_fake_peer)

    d = sub.add_parser("diff", help="differential a subject against a control")
    d.add_argument("--control", required=True)
    d.add_argument("--subject", required=True)
    d.add_argument("--json")
    d.set_defaults(fn=cmd_diff)

    b = sub.add_parser("baseline", help="check a control run against its "
                                        "pinned baseline")
    b.add_argument("--report", required=True)
    b.add_argument("--baseline", required=True)
    b.set_defaults(fn=cmd_baseline)

    l = sub.add_parser("list", help="list the battery")
    l.add_argument("--clauses", action="store_true")
    l.set_defaults(fn=cmd_list)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
