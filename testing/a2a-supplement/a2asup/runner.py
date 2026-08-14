# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Run every check, print a table nobody can misread, and exit on the MUST result.

THE REPORT IS SHAPED TO MAKE ONE MISTAKE IMPOSSIBLE. The official TCK's number and this suite's
number are different KINDS of evidence -- one is the specification publisher's oracle, one is the
implementer grading their own work -- and the failure mode that would make this whole directory
worthless is somebody adding them. So this runner never prints a total that could be mistaken for a
conformance score, prints the warning above its own counts, and records the same warning in the
JSON under `not_an_official_number`.
"""

from __future__ import annotations

import json
import time

from collections import Counter

from a2asup import checks_auth, checks_bind, checks_card, checks_ver
from a2asup.model import Result, Verdict
from a2asup.spec import REQUIREMENTS
from a2asup.target import Target

WARNING = (
    "BUSBAR-AUTHORED SUPPLEMENTARY COVERAGE. This is NOT the official A2A TCK and its counts are "
    "NOT TCK results. The requirement ids are the TCK's so the two can be cross-referenced; the "
    "EVIDENCE is ours. A pass here is weaker evidence than a pass there, and the two numbers must "
    "never be added or presented as one figure."
)


def run(target: Target, issuer_key: str | None, verifier_probe=None) -> list[Result]:
    """Every check, in order. An exception inside a check becomes an ERROR result and the run
    continues -- a check that dies must not take the other twenty with it, and it must not vanish."""
    plan: list[tuple[str, callable]] = [
        ("AUTH-TLS-001", lambda: checks_auth.check_auth_tls_001(target)),
        ("AUTH-SERVER-002", lambda: checks_auth.check_auth_server_002(target)),
        ("AUTH-INTASK-004", lambda: checks_auth.check_auth_intask_004(target)),
        ("AUTH-SCOPE-001", lambda: checks_auth.check_auth_scope_001(target)),
        ("AUTH-SCOPE-002", lambda: checks_auth.check_auth_scope_002(target)),
        ("AUTH-SCOPE-003", lambda: checks_auth.check_auth_scope_003(target)),
        ("BIND-EQUIV-001", lambda: checks_bind.check_bind_equiv_001(target)),
        ("BIND-EQUIV-002", lambda: checks_bind.check_bind_equiv_002(target)),
        ("BIND-EQUIV-003", lambda: checks_bind.check_bind_equiv_003(target)),
        ("BIND-EQUIV-004", lambda: checks_bind.check_bind_equiv_004(target)),
        ("CARD-SIGN-001", lambda: checks_card.check_card_sign_001(target, issuer_key)),
        ("CARD-SIGN-002", lambda: checks_card.check_card_sign_002(target, issuer_key)),
        ("CARD-SIGN-003", lambda: checks_card.check_card_sign_003(target)),
        ("CARD-SIGN-004", lambda: checks_card.check_card_sign_004(target, verifier_probe)),
        ("VER-CLIENT-001", lambda: checks_ver.check_ver_client_001(target)),
        ("VER-CLIENT-002", lambda: checks_ver.check_ver_client_002(target)),
        ("VER-SERVER-001", lambda: checks_ver.check_ver_server_001(target)),
        ("GRPC-SVC-003", lambda: checks_ver.check_grpc_svc_003(target)),
    ]
    results: list[Result] = []
    for req_id, fn in plan:
        started = time.time()
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 - a broken check is a finding, never a skip
            import traceback  # noqa: PLC0415

            result = Result(
                req_id,
                Verdict.ERROR,
                f"the check itself raised {type(exc).__name__}: {exc}. This is reported as ERROR "
                f"and counted as not-passed; a suite that swallowed it would be reporting green "
                f"over a check that never ran.",
                traceback.format_exc().splitlines()[-12:],
            )
        print(
            f"  {result.verdict.value:<15} {req_id:<17} "
            f"({REQUIREMENTS[req_id].level}, SPEC {REQUIREMENTS[req_id].section}, "
            f"{time.time() - started:.1f}s)"
        )
        print(f"      {result.summary}")
        results.append(result)
    return results


def report(target: Target, results: list[Result], out_path: str | None) -> int:
    counts = Counter(r.verdict for r in results)
    musts = [r for r in results if REQUIREMENTS[r.requirement].level == "MUST"]
    must_counts = Counter(r.verdict for r in musts)

    print()
    print("=" * 96)
    for line in _wrap(WARNING, 92):
        print("  " + line)
    print("=" * 96)
    print(f"  target: {target.label}  ({target.card_url})")
    print(f"  declared bindings: {sorted({i.binding for i in target.interfaces})}")
    print()
    print("  BUSBAR-SUPPLEMENT, MUST requirements only:")
    for verdict in Verdict:
        n = must_counts.get(verdict, 0)
        if n:
            print(f"    {verdict.value:<16} {n}")
    print(f"    {'TOTAL':<16} {len(musts)}")
    print()
    print(
        f"  => {must_counts.get(Verdict.PASS, 0)} of {len(musts)} MUST requirements DEMONSTRATED "
        f"by this suite."
    )
    print(
        "     PARTIAL, UNTESTABLE and NOT_APPLICABLE are NOT passes and are not added to that "
        "figure."
    )
    print()

    bad = [r for r in results if r.verdict in {Verdict.FAIL, Verdict.ERROR}]
    if bad:
        print("  NOT PASSING, with the evidence:")
        for r in bad:
            print(f"    - {r.requirement} [{r.verdict.value}] {r.summary}")
            for line in r.evidence[:14]:
                print(f"        | {line}")
        print()
    unresolved = [
        r
        for r in results
        if r.verdict in {Verdict.UNTESTABLE, Verdict.PARTIAL, Verdict.NOT_APPLICABLE}
    ]
    if unresolved:
        print("  NOT DECIDED FROM OUTSIDE, with the mechanism (this is a finding, not a gap):")
        for r in unresolved:
            print(f"    - {r.requirement} [{r.verdict.value}] {r.summary}")
        print()

    if out_path:
        import os  # noqa: PLC0415

        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "not_an_official_number": WARNING,
                    "label": target.label,
                    "card_url": target.card_url,
                    "declared_bindings": sorted({i.binding for i in target.interfaces}),
                    "must_total": len(musts),
                    "must_passed": must_counts.get(Verdict.PASS, 0),
                    "counts": {v.value: n for v, n in counts.items()},
                    "results": [r.to_json() for r in results],
                    "requirements": {
                        r.requirement: {
                            "level": REQUIREMENTS[r.requirement].level,
                            "section": REQUIREMENTS[r.requirement].section,
                            "sentence": REQUIREMENTS[r.requirement].sentence,
                            "reading": REQUIREMENTS[r.requirement].reading,
                            "limits": REQUIREMENTS[r.requirement].limits,
                        }
                        for r in results
                    },
                },
                handle,
                indent=2,
            )
        print(f"  JSON: {out_path}")

    return 1 if bad else 0


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines
