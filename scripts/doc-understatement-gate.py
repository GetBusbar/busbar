#!/usr/bin/env python3
"""doc-understatement-gate.py -- the documentation and the engine must make the SAME claim.

    scripts/doc-understatement-gate.py                 # check the tree
    scripts/doc-understatement-gate.py --root .        # ditto, explicit root
    scripts/doc-understatement-gate.py --selftest      # prove this gate discriminates
    scripts/doc-understatement-gate.py --list          # what it watches, and what it probes

WHY THIS EXISTS, and it is not tidiness.

`docs/circuit-breaker.md` exists in SIX distinct versions across this fleet's 148 refs, and they
disagree with each other about whether busbar can reroute an MCP tool call. On `origin/dev` the
page says failover is "not yet wired"; on `feat/1.6.0-one-selection-loop` the same page says it
is live. Both sentences are true -- OF DIFFERENT TREES. The page and the wiring are one change,
which is exactly why the only two branches carrying the "it is live" text are the two branches
carrying the code. Split them and somebody publishes a false sentence in one direction or the
other, and which direction depends only on the accident of merge order.

THE HAZARD IS BIDIRECTIONAL, AND THE SECOND DIRECTION IS THE DANGEROUS ONE.

  * Lose the wiring hunk in a merge or a release squash and keep the prose => the docs claim a
    capability busbar does not have. That is a FALSE CAPABILITY CLAIM, the thing the staged-claims
    mechanism on the marketing site exists to prevent, and `/reliability/` and `/mcp/` have
    already contradicted each other once this release over precisely this claim.
  * Land the wiring and keep the old caveat => the docs deny a capability busbar HAS. Less
    dangerous, more embarrassing, and it is the same class of defect as the whole website audit:
    every defect runs one direction, the docs understating the engine.

A gate that only asked "does the page still say the good thing" would ACTIVELY CAUSE the first
and worse failure, by rewarding prose that runs ahead of the engine. So this gate is symmetric.

THE MITIGATION IT REPLACES. The proposal was "check `git rev-parse HEAD:docs/circuit-breaker.md`
after the merge, and again after the squash" -- a human remembering, twice, at the busiest moment
of a release. Two rules this release earned the hard way condemn that:

  * A RULING IS NOT A FIX. A note in a goals file is not a mechanism.
  * A "DO NOT DELETE THIS" COMMENT NEEDS AN EXPIRY CONDITION, or it preserves a false claim after
    the condition ends. That is literally how the published LiteLLM comparison came to argue
    against us: a true-at-the-time caveat outlived the thing it was caveating.

So the expiry condition is MECHANICAL. The prose takes a position; the engine is asked whether
that position is true; disagreement is red, in either direction. The caveat cannot outlive the
limitation it describes, because the engine is what closes it.

WHY THE CLAIM AND NOT THE BYTES. The obvious gate pins the blob hash. It is wrong for the same
reason four other conclusions were wrong this release: it is an IDENTIFIER-SHAPED CHECK. A pinned
hash goes red on the first legitimate typo fix -- and a gate that reddens for a correct edit is a
gate that gets deleted -- while still being unable to distinguish a corrected page from a
corrupted one. It only ever knows "different". Worse, a hash is a fact about ONE tree: the same
pin is simultaneously right on one branch and wrong on another, which is the exact situation
here. Reading the CLAIM works on every branch without being told which branch it is on.

WHY THE PROBES ARE A CENSUS AND NOT A CALL-SITE LIST. A named call site is itself
identifier-shaped: `mcp/reroute.rs` does not exist on `dev` at all, so a probe naming it learns
nothing except that a path is missing, and it breaks the day somebody renames the file. Instead
the probes ask the question the orchestrator's own manual verification asked -- WHO READS THIS
CONFIG AT RUNTIME? -- as a repo-wide census of non-comment, non-test readers. On `dev` every
single mention of `tool_pools`/`agent_pools` outside the config parser is a COMMENT, and the
field never reaches `state.rs` or `appbuild.rs`: parsed at boot, consumed by nothing. On the
wired branches there are real readers. That distinction is what the pages are actually claiming,
it survives a rename, and it cannot be satisfied by rewording a doc comment.

TWO CLAIMS, NOT ONE ATOM. "The breaker section" is not a single fact and must never be gated as
one. On `dev` today the trip/fast-fail half is GENUINELY LIVE on all three planes -- one FSM,
cells keyed `tool:<server-id>` and `agent:<agent-id>`, MCP answering 503 + Retry-After + a
JSON-RPC error, A2A rejecting a fresh submission with a pollable task id -- while ONLY the
failover/reroute half is unwired. A gate that lumped them together would demand the docs deny
fast-fail, which is a false red that would teach people to switch the gate off. So the two claims
carry SEPARATE vocabularies and separate probes, and the denial patterns are written narrowly
enough to tell "not yet wired IS FAILOVER" apart from "not yet wired INTO THE MCP DISPATCH PATH".

THE RULE, per capability:

    engine HAS it   =>  no watched page may DENY it, and every watched page must AFFIRM it.
    engine LACKS it =>  no watched page may AFFIRM it, and every watched page must DENY it.

SILENCE IS RED, and that is the half most easily left out. A gate that only forbids denials
passes a page whose entire section was dropped in a merge conflict: no denial, therefore green,
therefore a page that has quietly stopped telling operators anything. Understatement by deletion
is still understatement. A watched page must take a POSITION and the position must match.

FLOORS. A checker that finds nothing to check is not a passing checker. It refuses to run on an
empty registry, on a capability missing any field, on a watched page that does not exist, and on
a capability whose probes ALL name unreadable paths (that is registry drift, not an absent
capability -- an absent capability still has a readable tree to be absent from).
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parent.parent

# Paths whose mention of a config field proves nothing about runtime consumption: the parser that
# reads it, the validator that checks it, every test, and the test-support builders that construct
# fixtures. `dev` has mentions in all of these and consumes the field nowhere.
CENSUS_EXCLUDE = ("/config/", "/config_validate/", "/tests/", "_tests.rs", "/test_support/")


# ── THE CAPABILITY REGISTRY ───────────────────────────────────────────────────────────────────
# Each capability: what the engine may or may not do, the probes that decide which, the prose that
# DENIES it, the prose that AFFIRMS it, and the pages that must agree.
#
# Probe kinds:
#   ("census", needle)        -- non-comment, non-test readers anywhere under crates/. Hit if any.
#   ("code", needle, path)    -- a specific non-comment statement. A MISSING FILE IS A MISS, not an
#                                error: on `dev` the wiring files do not exist, and "the file that
#                                would do this is absent" is the strongest possible evidence that
#                                the capability is absent.
CAPABILITIES = [
    {
        "id": "mcp-a2a-failover-reroute",
        "what": "the MCP dispatch path and the A2A ingress walk `tool_pools:`/`agent_pools:` "
        "candidate sets through `failover::walk`, so a tripped primary is rerouted to its "
        "verified twin before the first byte",
        "probes": [
            # Not "does reroute.rs call walk()" -- that file does not exist on `dev`. This is the
            # runtime-consumption census: on `dev` every hit outside the config parser is a
            # comment and the field never reaches `state.rs`, so the count here is 0.
            ("census", "tool_pools"),
            ("census", "agent_pools"),
        ],
        "denials": [
            # NARROW ON PURPOSE. `dev`'s true sentence is "what is **not yet wired** is FAILOVER";
            # an older blob's FALSE sentence is "not yet wired INTO THE MCP DISPATCH PATH", which
            # denies the breaker instead and belongs to the other capability. A pattern that could
            # not tell those apart would fire falsely on `dev`, where fast-fail genuinely is live.
            (r"not\s+yet\s+wired\W{0,4}\s*is\s+failover", "says failover is not yet wired"),
            (r"seam\s+is\s+not\s+yet\s+wired", "says the selection seam is not yet wired"),
            (r"no\s+second\s+candidate\s+is\s+tried", "says no second candidate is tried"),
            (r"\bnever\s+rerouted\b", "says a tripped target is never rerouted"),
            (r"not\s+yet\s+consulted", "says a configured pool is not consulted at dispatch"),
            (r"\bnot\s+emitted\s+yet\b", "says the reroute wire tokens are not emitted yet"),
            (r"none\s+of\s+these\s+tokens\s+exist\s+in\s+the\s+engine", "says the tokens do not exist"),
            (r"relay\s+call\s+site\s+is\s+not\s+wired", "says the A2A relay call site is not wired"),
            (r"there\s+is\s+no\s+failover\s+on\s+MCP\s+or\s+A2A", "says there is no failover here"),
            (r"no\s+failover\s+on\s+these\s+planes(?!\W{0,40}(and gave|That reason))", "says there is no failover on these planes"),
        ],
        "affirmations": [
            (r"failover\s+half\s+is\s+live", "states the failover half is live"),
            (r"both\s+call\s+sites\s+are\s+wired", "states both call sites are wired"),
            (r"validated\s+at\s+boot\s+AND\s+consulted\s+at\s+dispatch", "states a pool is consulted at dispatch"),
            (r"rerouted\s+to\s+its\s+verified\s+twin", "states a tripped primary is rerouted"),
            (r"walked\s+the\s+same\s+way\s+at\s+admission", "states A2A submissions are walked at admission"),
        ],
        "pages": ["docs/circuit-breaker.md", "docs/operations.md"],
    },
    {
        "id": "mcp-a2a-breaker-trip-fastfail",
        "what": "the breaker's trip and fast-fail run on the MCP client leg and the A2A relay -- "
        "one FSM, cells keyed `tool:<server-id>` and `agent:<agent-id>`, a tripped target refusing "
        "in milliseconds rather than paying a timeout",
        # TRUE ON `dev` AND ON THE WIRED BRANCHES ALIKE. This entry exists so the failover patterns
        # above can be written narrowly without leaving the fast-fail claim ungated, and so that
        # the older blob which denies fast-fail as well is still caught.
        "probes": [
            ("code", 'format!("tool:{server}")', "crates/busbar-core/src/store/planes.rs"),
            ("code", 'format!("agent:{agent}")', "crates/busbar-core/src/store/planes.rs"),
        ],
        "denials": [
            (r"not\s+yet\s+wired\s+into\s+the\s+MCP\s+dispatch\s+path", "says the breaker is not wired into MCP dispatch"),
            (r"breaker\s+does\s+not\s+fire\s+today", "says the breaker does not fire today"),
            (r"does\s+not\s+fire\s+on\s+a\s+live\s+call", "says the breaker does not fire on a live call"),
            # TENSE IS LOAD-BEARING. "still PRODUCES nothing but slow calls" is the false present-
            # tense claim. "before it, a hard-down server PRODUCED nothing but slow calls" is true
            # history, appears on two other blobs, and must stay legal -- a gate that punished
            # accuracy would teach authors to delete correct sentences to get green.
            (r"produces\s+nothing\s+but\s+slow\s+calls", "says a hard-down server still only fails slowly"),
        ],
        "affirmations": [
            (r"trip\s+and\s+fast-fail\W{0,4}\s*are\s+live", "states trip and fast-fail are live"),
            (r"the\s+same\s+signal\s+is\s+live", "states the operator signal is live"),
            (r"refused\s+immediately", "states a tripped target refuses immediately"),
        ],
        "pages": ["docs/circuit-breaker.md", "docs/operations.md"],
    },
]


def die(msg: str) -> None:
    sys.stderr.write(f"doc-understatement-gate: {msg}\n")
    raise SystemExit(2)


def is_comment(line: str) -> bool:
    return line.strip().startswith(("//", "/*", "*"))


def real_code_lines(path: Path) -> list[str]:
    """Non-comment lines. Comments are excluded deliberately: on `dev` EVERY mention of
    `tool_pools` outside the config parser is a comment, so a probe that read comments would
    report the capability present on the one tree where it is provably absent."""
    try:
        text = path.read_text(encoding="utf8", errors="replace")
    except OSError:
        return []
    return [ln for ln in text.splitlines() if not is_comment(ln)]


def census(root: Path, needle: str) -> list[str]:
    """Every non-comment, non-test reader of `needle` under crates/. The runtime-consumption
    question, asked of the whole tree rather than of a file path that may not exist."""
    hits = []
    src = root / "crates"
    if not src.is_dir():
        die(f"no {src} -- this does not look like the engine repository.")
    for p in sorted(src.rglob("*.rs")):
        rel = "/" + str(p.relative_to(root))
        if any(x in rel for x in CENSUS_EXCLUDE):
            continue
        for lineno, line in enumerate(p.read_text(encoding="utf8", errors="replace").splitlines(), 1):
            if needle in line and not is_comment(line):
                hits.append(f"{p.relative_to(root)}:{lineno}")
    return hits


def probe_result(root: Path, probe: tuple) -> tuple[bool, str]:
    """(hit, human explanation). A probe never raises for an absent file -- absence is a miss."""
    if probe[0] == "census":
        hits = census(root, probe[1])
        if hits:
            return True, f"{len(hits)} runtime reader(s) of {probe[1]!r}, e.g. {hits[0]}"
        return False, f"no non-comment, non-test reader of {probe[1]!r} anywhere under crates/"
    _, needle, rel = probe
    p = root / rel
    if not p.is_file():
        return False, f"{rel} does not exist in this tree"
    if any(needle in ln for ln in real_code_lines(p)):
        return True, f"{rel} contains {needle!r} in real code"
    return False, f"{rel} exists but contains no real-code {needle!r}"


def wired(root: Path, cap: dict) -> tuple[bool, list[str]]:
    results = [probe_result(root, pr) for pr in cap["probes"]]
    # FLOOR: if every probe failed because its PATH is missing, that is registry drift rather than
    # an absent capability, and it must not quietly force the docs to deny something.
    if all(not ok and "does not exist in this tree" in why for ok, why in results) and results:
        die(
            f"every probe for `{cap['id']}` names a path that does not exist. That is registry "
            f"drift, not an absent capability, and reading it as 'absent' would demand the docs "
            f"deny something the engine may well do. Fix the registry."
        )
    return all(ok for ok, _ in results), [why for _, why in results]


def scan(text: str, vocab: list[tuple[str, str]]) -> list[tuple[int, str, str]]:
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for pattern, desc in vocab:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                hits.append((lineno, m.group(0), desc))
    return hits


def evaluate(pages: dict[str, str], is_wired: bool, cap: dict) -> list[str]:
    """THE RULE, as a pure function of (page text, engine state), so `--selftest` drives all four
    quadrants without touching any tree."""
    cap_id, what = cap["id"], cap["what"]
    problems = []
    for name, text in pages.items():
        denials = scan(text, cap["denials"])
        affirms = scan(text, cap["affirmations"])
        if is_wired:
            for lineno, matched, desc in denials:
                problems.append(
                    f"{name}:{lineno} DENIES a capability the engine HAS.\n"
                    f"      the page {desc}, matching {matched!r}.\n"
                    f"      the engine: {what}.\n"
                    f"      FIX: rewrite the sentence against the engine. Do not weaken the probe."
                )
            if not affirms:
                problems.append(
                    f"{name} says NOTHING about `{cap_id}`, and the engine HAS it.\n"
                    f"      silence is a failure here, not a neutral state: a merge that drops the "
                    f"paragraph leaves a page that has quietly stopped telling operators what "
                    f"busbar does, and leaves no denial behind to catch it.\n"
                    f"      FIX: state the capability on this page, or drop the page from this "
                    f"capability's watch list deliberately."
                )
        else:
            for lineno, matched, desc in affirms:
                problems.append(
                    f"{name}:{lineno} AFFIRMS a capability the engine LACKS.\n"
                    f"      the page {desc}, matching {matched!r}.\n"
                    f"      the engine does NOT do this in this tree.\n"
                    f"      THIS IS THE DANGEROUS DIRECTION: a published false capability claim. "
                    f"Either the wiring was lost in a merge or a squash (restore the WIRING -- the "
                    f"likelier case), or the prose landed ahead of the engine (restore the caveat)."
                )
            if not denials:
                problems.append(
                    f"{name} says NOTHING about `{cap_id}`, and the engine LACKS it.\n"
                    f"      a page that describes a path before it is wired is how a reader learns "
                    f"something false.\n"
                    f"      FIX: state the limitation on this page."
                )
    return problems


def load_pages(root: Path, cap: dict) -> dict[str, str]:
    pages = {}
    for rel in cap["pages"]:
        p = root / rel
        if not p.is_file():
            die(
                f"watched page {rel} does not exist. A gate whose subject has vanished must not "
                f"report a clean tree -- that is the shape of the failure it watches for."
            )
        pages[rel] = p.read_text(encoding="utf8", errors="replace")
    return pages


def floors() -> None:
    if not CAPABILITIES:
        die("the capability registry is EMPTY. A checker with nothing to check is not a passing checker.")
    for cap in CAPABILITIES:
        for field in ("id", "what", "probes", "pages", "denials", "affirmations"):
            if not cap.get(field):
                die(f"capability {cap.get('id', '<unnamed>')} has no {field} -- it would pass trivially.")


def do_list(root: Path) -> int:
    floors()
    for cap in CAPABILITIES:
        ok, whys = wired(root, cap)
        print(f"== {cap['id']} -- this tree says {'WIRED' if ok else 'NOT WIRED'} ==")
        print(f"   {cap['what']}")
        for why in whys:
            print(f"     - {why}")
        print(f"   pages: {', '.join(cap['pages'])}")
        print(f"   vocabulary: {len(cap['denials'])} denial(s), {len(cap['affirmations'])} affirmation(s)\n")
    return 0


def do_selftest(root: Path) -> int:
    bad = 0

    def check(label: str, ok: bool) -> None:
        nonlocal bad
        print(f"  [{'ok' if ok else 'FAILED'}]     {label}")
        if not ok:
            bad = 1

    floors()
    check("floors hold: every capability has probes, pages and both vocabularies", True)

    fo = CAPABILITIES[0]
    brk = CAPABILITIES[1]

    deny_fo = ("What is **not yet wired** is failover and reroute on these planes: no second "
               "candidate is tried today, a tripped target is refused, never rerouted.")
    affirm_fo = ("the **failover half is live too**: both call sites are wired, a pool is "
                 "validated at boot AND consulted at dispatch, rerouted to its verified twin.")
    silent = "The breaker is configured per pool with a `breaker:` block. Every field is optional."

    # THE FOUR QUADRANTS, through the real vocabularies.
    check("page DENIES + engine HAS  => RED (understatement: the original hazard)",
          any("DENIES" in m for m in evaluate({"p.md": deny_fo}, True, fo)))
    check("page AFFIRMS + engine HAS => green",
          evaluate({"p.md": affirm_fo}, True, fo) == [])
    check("page AFFIRMS + engine LACKS => RED (false capability claim: the dangerous direction)",
          any("AFFIRMS" in m for m in evaluate({"p.md": affirm_fo}, False, fo)))
    check("page DENIES + engine LACKS => green (this is `dev` today)",
          evaluate({"p.md": deny_fo}, False, fo) == [])

    # Silence, both ways.
    check("page SILENT + engine HAS => RED (understatement by deletion)",
          any("says NOTHING" in m for m in evaluate({"p.md": silent}, True, fo)))
    check("page SILENT + engine LACKS => RED",
          any("says NOTHING" in m for m in evaluate({"p.md": silent}, False, fo)))

    # THE FALSE-RED GUARD the orchestrator's finding demands: `dev`'s TRUE failover caveat must not
    # trip the BREAKER capability, because fast-fail genuinely is live there. Treating the breaker
    # section as one atom is what would produce this false red.
    check("`dev`'s true 'not yet wired IS FAILOVER' does NOT trip the breaker capability",
          scan(deny_fo, brk["denials"]) == [])
    check("the older 'not yet wired INTO THE MCP DISPATCH PATH' DOES trip the breaker capability",
          scan("It is not yet wired into the MCP dispatch path or the A2A relay.", brk["denials"]) != [])

    # Tense.
    check("PAST-tense 'produced nothing but slow calls' is legal (true history)",
          scan("Before it, a hard-down tool server produced nothing but slow calls.", brk["denials"]) == [])
    check("PRESENT-tense 'produces nothing but slow calls' is a denial",
          scan("a hard-down tool server still produces nothing but slow calls.", brk["denials"]) != [])

    # A probe must read CODE, not a comment ABOUT code -- on `dev` every mention of `tool_pools`
    # outside the config parser is a comment, so this is the difference between right and wrong.
    with tempfile.TemporaryDirectory() as td:
        fake = Path(td) / "crates" / "busbar-core" / "src"
        fake.mkdir(parents=True)
        (fake / "x.rs").write_text("//! tool_pools: described in a comment, consumed by nothing\n"
                                   "/// tool_pools\nfn nothing() {}\n")
        check("a needle appearing ONLY in comments is NOT a runtime reader",
              census(Path(td), "tool_pools") == [])
        (fake / "y.rs").write_text("let p = app.tool_pools.get(name);\n")
        check("a needle in real code IS a runtime reader",
              len(census(Path(td), "tool_pools")) == 1)

    # An absent wiring file is a MISS, never a crash: `dev` has no `mcp/reroute.rs` at all.
    with tempfile.TemporaryDirectory() as td:
        ok, why = probe_result(Path(td), ("code", "whatever", "crates/nope.rs"))
        check("an absent probe file reads as NOT WIRED rather than erroring", ok is False)

    if bad:
        print("\nSELFTEST FAILED")
        return 1
    print("\ndoc-understatement-gate selftest: four quadrants, silence, tense, the breaker/failover "
          "split and the comment/code distinction all discriminate")
    return 0


def main(argv: list[str]) -> int:
    root = DEFAULT_ROOT
    if "--root" in argv:
        root = Path(argv[argv.index("--root") + 1]).resolve()
    if "--selftest" in argv:
        return do_selftest(root)
    if "--list" in argv:
        return do_list(root)

    floors()
    failures = []
    for cap in CAPABILITIES:
        is_wired, _ = wired(root, cap)
        problems = evaluate(load_pages(root, cap), is_wired, cap)
        state = "WIRED" if is_wired else "NOT WIRED"
        if problems:
            failures.append((cap["id"], state, problems))
        else:
            print(f"  [ok]     {cap['id']}: engine {state}, {len(cap['pages'])} watched page(s) agree")

    if not failures:
        print(f"\ndoc-understatement-gate: {len(CAPABILITIES)} capability claim(s) checked against "
              f"this tree; the documentation neither understates nor overstates the engine.")
        return 0

    for cap_id, state, problems in failures:
        print(f"\n  [FAILED] {cap_id}: this tree is {state}, and the documentation disagrees.")
        for m in problems:
            print(f"    - {m}")
    sys.stderr.write(
        "\ndoc-understatement-gate: the documentation and the engine make different claims about "
        "the same capability, IN THIS TREE.\n"
        "This gate is the expiry condition on a caveat. A caveat that outlives the limitation it "
        "described does not become harmless; it becomes an argument against our own product, made "
        "in our own voice. And prose that lands AHEAD of the engine is worse still: it is a "
        "published false capability claim.\n"
        "The page and the wiring are ONE change. If you are merging, take both halves or neither.\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
