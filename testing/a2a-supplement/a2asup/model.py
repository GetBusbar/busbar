# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Verdicts, and the rule that there is no such thing as a skip.

THE FIVE VERDICTS AND WHY THERE IS NO SIXTH.

    PASS        the requirement's observable consequence was driven and held.
    FAIL        it was driven and did not hold.
    PARTIAL     the sentence is a conjunction, one conjunct was driven and held, and the other is
                not reachable from outside. Named conjunct by conjunct. NEVER counted as a pass.
    UNTESTABLE  no external observer can decide it, with the MECHANISM stated. This is a real
                finding, not an absence of one, and it is what an honest suite says instead of
                inventing an assertion.
    ERROR       the check itself broke. Loud, counted as not-passed, never silent.

There is deliberately NO `SKIP`. A suite that can skip will skip, and a skipped test reports the
same green as a passed one to every reader who is not looking closely. Where a requirement does not
apply to a particular target -- BIND-EQUIV against an agent that declares one binding -- the verdict
is NOT_APPLICABLE and it carries the reason; it is reported in its own column and never folded into
a pass count.
"""

from __future__ import annotations

import json

from dataclasses import asdict, dataclass, field
from enum import Enum


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    UNTESTABLE = "UNTESTABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"

    @property
    def is_pass(self) -> bool:
        return self is Verdict.PASS


@dataclass
class Result:
    requirement: str
    verdict: Verdict
    summary: str
    """One line. What was driven and what was observed."""
    evidence: list[str] = field(default_factory=list)
    """The raw observations the verdict rests on. Printed on every non-PASS."""

    def to_json(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


class CheckFailure(Exception):
    """Raised by a check to record a FAIL with evidence."""

    def __init__(self, summary: str, evidence: list[str] | None = None) -> None:
        super().__init__(summary)
        self.summary = summary
        self.evidence = evidence or []


def short(value: object, limit: int = 400) -> str:
    """Render an observation for the evidence log, truncated but never silently."""
    if isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True, default=str)
    else:
        text = str(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [{len(text) - limit} more chars]"
