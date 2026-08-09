"""Result model and test registry.

The single most important idea in this harness lives here: the difference
between an ASSERTION and an OBSERVATION.

  assert_must(...)  The spec mandates an exact answer. A wrong answer is a
                    defect in the target, full stop, whatever any other
                    implementation does.

  observe(...)      The spec permits variation. The value is recorded and
                    compared against the control. A difference is a DIVERGENCE
                    for a human to read, never a failure.

A harness that fails on legal variation gets muted within a week, and then it
protects nothing. An observe() becomes an assert_must() only when a clause
that mandates the value can be quoted next to it.
"""

import time
import traceback

# Outcome values, in order of increasing alarm.
PASS = "PASS"
OBSERVED = "OBSERVED"  # permitted variation recorded, no judgement
INAPPLICABLE = "INAPPLICABLE"  # optional capability not declared by target
NOT_CONFIGURED = "NOT_CONFIGURED"  # harness was not given what it needs, LOUD
FAIL = "FAIL"  # a MUST was violated
ERROR = "ERROR"  # the test itself blew up

# When a test may run.
EVERY_COMMIT = "every-commit"
PULL_REQUEST = "pull-request"
PRE_RELEASE = "pre-release"

# What the test needs to exist.
NEEDS_FAKE_PEER = "fake-peer"  # harness supplies both sides, cheap, hermetic
NEEDS_REAL_PEER = "real-peer"  # needs a real agent that actually does work
NEEDS_HUMAN = "human"  # cannot be automated at all

# Which role of the target is under test.
ROLE_SERVER = "server"  # target is the A2A server being talked to
ROLE_CLIENT = "client"  # target is the A2A client talking out
ROLE_SEAM = "seam"  # target is both, relaying between two peers
# NOT a conformance role. Governance tests are excluded from conformance runs
# by default so that a conformance pass can never be read as a governance pass.
ROLE_GOVERNANCE = "governance"


class Violation(Exception):
    """Raised by assert_must. Carries the governing clause."""

    def __init__(self, message, clause):
        super().__init__(message)
        self.message = message
        self.clause = clause


class NotConfigured(Exception):
    """Raised when the harness lacks a parameter it needs.

    This is deliberately NOT a skip. A gate that quietly passes having tested
    nothing is worse than no gate at all.
    """


class Inapplicable(Exception):
    """Raised when the target legally does not offer the capability tested."""


class Context:
    """Handed to every test. Accumulates assertions and observations."""

    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.observations = {}
        self.notes = []
        self.assertions = 0

    def assert_must(self, condition, message, clause):
        """Enforce a spec MUST. `clause` is mandatory and must be a citation."""
        if not clause:
            raise ValueError("assert_must without a clause citation")
        self.assertions += 1
        if not condition:
            raise Violation(message, clause)

    def observe(self, key, value, clause=None):
        """Record a value the spec permits to vary.

        `clause` is optional here and, when given, names the clause that makes
        the variation legal, not one that constrains it.
        """
        self.observations[key] = value
        if clause:
            self.observations.setdefault("_clauses", {})[key] = clause
        return value

    def note(self, text):
        self.notes.append(text)

    def require_config(self, key, why):
        value = self.config.get(key)
        if value in (None, ""):
            raise NotConfigured(
                "missing required parameter '%s': %s" % (key, why)
            )
        return value


class Result:
    def __init__(self, test, outcome, detail="", clause="", observations=None,
                 notes=None, elapsed=0.0):
        self.test = test
        self.outcome = outcome
        self.detail = detail
        self.clause = clause
        self.observations = observations or {}
        self.notes = notes or []
        self.elapsed = elapsed

    def to_dict(self):
        return {
            "id": self.test.id,
            "defect": self.test.defect,
            "clause": self.clause or self.test.clause,
            "role": self.test.role,
            "tier": self.test.tier,
            "needs": self.test.needs,
            "outcome": self.outcome,
            "detail": self.detail,
            "observations": self.observations,
            "notes": self.notes,
        }


class Test:
    def __init__(self, fn, id, defect, clause, role, tier, needs, tags):
        self.fn = fn
        self.id = id
        self.defect = defect
        self.clause = clause
        self.role = role
        self.tier = tier
        self.needs = needs
        self.tags = tags

    def run(self, target, config):
        ctx = Context(target, config)
        started = time.time()
        try:
            self.fn(ctx)
        except Violation as exc:
            return Result(self, FAIL, exc.message, exc.clause,
                          ctx.observations, ctx.notes, time.time() - started)
        except NotConfigured as exc:
            return Result(self, NOT_CONFIGURED, str(exc), "",
                          ctx.observations, ctx.notes, time.time() - started)
        except Inapplicable as exc:
            return Result(self, INAPPLICABLE, str(exc), "",
                          ctx.observations, ctx.notes, time.time() - started)
        except Exception:
            return Result(self, ERROR, traceback.format_exc(limit=6), "",
                          ctx.observations, ctx.notes, time.time() - started)
        outcome = OBSERVED if (ctx.observations and not ctx.assertions) else PASS
        return Result(self, outcome, "", "", ctx.observations, ctx.notes,
                      time.time() - started)


REGISTRY = []


def a2a_test(id, defect, clause, role, tier=PULL_REQUEST,
             needs=NEEDS_FAKE_PEER, tags=()):
    """Register a test.

    `defect` is a one-line statement of WHAT DEFECT THIS CATCHES. It is not
    optional and it is not a description of the mechanics. If you cannot say
    what breaks in the real world when this test goes red, delete the test.
    """
    if not defect or len(defect) < 15:
        raise ValueError("test %s needs a real defect statement" % id)

    def wrap(fn):
        REGISTRY.append(Test(fn, id, defect, clause, role, tier, needs,
                             tuple(tags)))
        return fn

    return wrap


def all_tests():
    return list(REGISTRY)
