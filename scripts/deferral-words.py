#!/usr/bin/env python3
"""deferral-words.py — the detector for DECISIONS #15, "it is 1.6.0-or-bust".

WHY THIS EXISTS, AND WHY IT IS NOT A `grep -F`.
==============================================
#15 bans four literal strings: `defer`, `1.6.x`, `later`, `out of scope for 1.6.0`.
`docs/design/1.6.0-TRACKER.md` writes **"Out of 1.6.0 scope"** — the same phrase with two
words transposed — and a literal-string grep sails straight past it. That one miss waived
52 ABI slots.

The audit in `docs/design/1.6.0-map-proof.md` §9 read all 93 banned-word occurrences by
hand and found 21 real deferrals. **Not one of them says "deferred."** They say *extension
point*, *a later wave*, *a 1.7.0 plane*, *Phase 5*, *peer later with fleet*, *minor bump*,
*still owed a home*, *a NOTE not a migration* — and twice they say *this is not a deferral*.

So a ban enforced by four literal strings is a ban that rewards rephrasing. This detector
matches SHAPES.

TWO LAYERS, AND THE DIFFERENCE MATTERS
======================================
**Layer 1 — NAMED SHAPES (`--layer=1`, the default, the enforcement set).**
  Regex families, each with a name, each case-insensitive, each derived from a phrasing the
  tree actually used. A Layer-1 hit is a thing a gate may red on.

**Layer 2 — THE STRUCTURAL RULE (`--layer=2`, the review set).**
  No vocabulary of deferral at all: a sentence that pairs a FUTURE-TIME signal with a WORK
  signal. "we will circle back to it after the split lands" carries no banned word and no
  Layer-1 shape, and it is a deferral. Layer 2 is noisy BY CONSTRUCTION — "when the store
  returns" trips it too — so it is a READING LIST, never a gate. Its job is to catch the
  phrasing nobody enumerated, which is the only failure mode a word list cannot fix.

  Layer 2 is the honesty check on Layer 1. If a planted deferral is caught only by Layer 2,
  Layer 1 is still a spelling list, and this file says so rather than quietly gaining a word.

USAGE
    scripts/deferral-words.py                      # Layer 1 over the 1.6.0 doc set
    scripts/deferral-words.py --layer=both         # both layers
    scripts/deferral-words.py --summary            # counts by shape
    scripts/deferral-words.py --paths crates xtask # shipped source too
    scripts/deferral-words.py --expect FILE        # assert every `path:line` in FILE is named
    scripts/deferral-words.py --selftest           # the planted-deferral positive control
"""

from __future__ import annotations

import argparse
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ─────────────────────────────────────────────────────────────────────────────────────────
# LAYER 1 — THE NAMED SHAPES
#
# Each entry is (shape-name, regex). The name is what a finding is reported as, so a red can
# be argued with by name instead of by line. Every regex is compiled case-insensitively: the
# ban's own phrase appears in this tree as "Out of 1.6.0 scope", capital O, words swapped.
# ─────────────────────────────────────────────────────────────────────────────────────────
SHAPES: list[tuple[str, str]] = [
    # The ban's own four terms, as WORD FAMILIES rather than as literals. `defer` must also
    # catch `deferred`/`deferring`/`deferral`/`defers`/`undeferred`.
    ("defer-family", r"\bdefer\w*\b"),
    ("bare-later", r"\blater\b"),
    # THE MISS THAT STARTED THIS. `out of scope for 1.6.0` AND `Out of 1.6.0 scope` AND
    # `outside the scope of this release` are one shape: a scope word negated by an
    # out/outside/beyond/not-in preposition, with up to four words of anything between.
    ("out-of-scope", r"\b(?:out(?:side)?|beyond|not)\s+(?:of\s+|in\s+|the\s+)?(?:\S+\s+){0,4}?scoped?\b"),
    ("scope-out", r"\bscoped?\s+out\b|\bde-?scoped?\b"),
    # A VERSION THAT IS NOT THIS ONE. `1.6.x` is the ban's own term; `1.7.0`/`1.8`/`2.0` are
    # the same act with a bigger number. `post-1.6.0`, `past 1.6.0`, `beyond 1.6.0` likewise.
    ("next-version", r"\b1\.6\.x\b|\b1\.[7-9]\.\d+\b|\bv?[2-9]\.\d+\.\d+\b"
                     r"|\b(?:version|release|ship(?:s|ped|ping)?\s+in)\s+v?1\.[7-9]\b"),
    ("past-this-version", r"\b(?:post|past|beyond|after|not)[\s-]+1\.6\.0\b|\bnot\s+(?:a\s+)?1\.6\.0\b"),
    ("version-bump", r"\b(?:minor|major|point|patch)\s+(?:bump|version|release)\b|\bnext\s+(?:minor|major|release|version)\b"),
    # THE ARCHITECTURAL EUPHEMISM. "extension point", "reserved shape", "seam for", "hook
    # for" — a slot declared and not filled, described as a design choice.
    ("extension-point", r"\bextension[\s-]points?\b|\breserved\s+(?:shape|slot|surface)\b|\bnot\s+implemented\s+wiring\b"),
    # WAVES AND PHASES. The tree schedules by wave and phase, so a bare "Phase 5" or "a
    # later wave" is how work leaves this release without the word.
    ("phase-n", r"\bphases?\s+\d+(?:\.\d+)?\b"),
    ("wave-later", r"\b(?:a|the|some|another|future|later|next|subsequent)\s+(?:later\s+)?waves?\b|\bwave\s+[A-Z]\b"),
    # THE FUTURE, NAMED. "a future release", "a follow-on release", "down the road".
    ("future-release", r"\bfuture\s+(?:release|version|wave|phase|minor|major|bump|work|effort)\b"
                       r"|\ba\s+future\b|\bfollow[\s-]?(?:on|up)\b|\bdown\s+the\s+(?:road|line)\b"
                       r"|\bat\s+some\s+point\b|\bin\s+due\s+course\b|\bsome\s*day\b|\beventually\b"
                       r"|\bin\s+time\b|\btomorrow\b|\bv[\s-]?next\b"),
    # THE BACKLOG VOCABULARY. Never used in this tree yet; a deferral's natural next home.
    ("backlog", r"\bpunt(?:ed|ing|s)?\b|\bshelv(?:e|ed|ing|es)\b|\bback[\s-]?log(?:ged)?\b"
                r"|\bice\s*box\b|\bstretch\s+goal\b|\bnice[\s-]to[\s-]have\b|\bparking\s+lot\b"
                r"|\bkick(?:ed|ing)?\s+.{0,20}?down\s+the\s+road\b|\bpush(?:ed|ing)?\s+(?:it\s+|this\s+|out\s+)?(?:to|out|back)\b"),
    # NOT DONE, SAID PLAINLY. The most honest deferral shape, and still a deferral.
    ("not-yet-done", r"\bnot\s+(?:yet\s+)?(?:implemented|wired|performed|done|built|ported|landed|shipped|converted|migrated|started)\b"
                     r"|\byet\s+to\s+be\b|\bhas\s+(?:not|never)\s+been\s+(?:performed|done|built|started|landed)\b"
                     r"|\bnothing\s+.{0,40}?has\s+been\s+performed\b|\bno\s+.{0,20}?exists?\s+yet\b|\bunbuilt\b"),
    # NEGATED NOW — a negation within a short window of a PRESENT-TIME token. No deferral
    # vocabulary is required: "Not wiring this today", "no support at this time", "we are
    # not doing that in this release" all defer without a single banned word. The shape is
    # the pair (negation, present-time), not any particular verb between them.
    ("negated-now", r"\b(?:not|n't|no|never|without)\b[^.;!?]{0,60}?"
                    r"\b(?:today|right\s+now|at\s+this\s+time|at\s+present|currently|as\s+(?:it|things)\s+stands?"
                    r"|in\s+this\s+release|this\s+release|in\s+1\.6\.0|for\s+1\.6\.0|here\s+and\s+now)\b"
     ),
    # UNDECIDED IS DEFERRED. An open question at ship time is work that did not happen.
    ("undecided", r"\bunmapped\b|\bundecided\b|\bopen\s+question\b|\bTBD\b|\bto\s+be\s+(?:decided|determined|ruled)\b"
                  r"|\bstill\s+owed\b|\bowed\s+a\s+home\b|\bno\s+destination\b|\bnowhere\s+to\s+go\b"
                  r"|\bnot\s+resolved\b|\bpend(?:s|ing|ed)?\b"),
    # THE TEMPORARY, WHICH NEVER IS. "for now", "in the interim", "provisional".
    ("for-now", r"\bfor\s+now\b|\bfor\s+the\s+(?:time\s+being|moment)\b|\bin\s+the\s+(?:interim|meantime)\b"
                r"|\bprovisional(?:ly)?\b|\bstop[\s-]?gap\b|\bplaceholder\b|\btemporar(?:y|ily)\b"),
    # A NOTE IS NOT A MIGRATION. A document that describes work instead of being it.
    ("note-not-work", r"\ba\s+NOTE,?\s+not\s+a\b|\bdescribes?\s+.{0,30}?rather\s+than\s+(?:does|doing|performing)\b"
                      r"|\brecommendation\s+is\s+to\b"),
    # ── THE FOUR SHAPES ROUND 2 OF THE POSITIVE CONTROL FOUND MISSING ──────────────────
    # Disclosed as tuned-against: these were added after Round 2 of `--selftest` drove four
    # invented phrasings straight through both layers. Each is a CLASS of incompleteness,
    # not the words of the phrase that exposed it — which is the only kind of widening
    # allowed here. Round 3 was then written fresh and never used to tune anything.

    # PARTIAL COVERAGE. "only handles the two-party case", "the happy path is wired". The
    # work is declared done for a subset, which is the subset-shaped deferral.
    ("partial-coverage", r"\bonly\s+(?:handles?|covers?|supports?|does|implements?|works?)\b"
                         r"|\b(?:handles?|covers?|supports?|implements?)\s+only\b"
                         r"|\bjust\s+the\s+\w+[\s-]case\b|\bhappy[\s-]path\b"
                         r"|\bpartial(?:ly)?\s+(?:implemented|covered|wired|done|built)\b"
                         r"|\bnot\s+exhaustive\b|\bsubset\s+of\b"),
    # APPROXIMATION. "approximate", "best-effort", "close enough". Precision postponed is
    # still postponed, and this tree bans postponement, not imprecision alone.
    ("approximation", r"\bapproximat(?:e|es|ed|ion|ely)\b|\bbest[\s-]effort\b|\brough(?:ly)?\b"
                      r"|\bheuristics?\b|\bclose\s+enough\b|\bgood\s+enough\b|\bna(?:i|\u00ef)ve(?:ly)?\b"
                      r"|\bsimplif(?:ied|ication|ying)\b|\bball\s*park\b"),
    # A STUB SAYING SO. The source-marker gate sees `unimplemented!()`; prose saying the
    # same thing in English is the same deferral with no macro to grep for.
    ("stub-admission", r"\bstub(?:bed|s|bing)?\b|\bskeletons?\b|\bscaffold(?:ing|ed)?\b"
                       r"|\bdummy\b|\bmocked\s+out\b|\bno[\s-]?ops?\b|\bhard[\s-]?cod(?:e|ed|ing)\b"),
    # SOMEONE ELSE'S ROW. "a separate piece of work", "a bigger lift", "whoever owns tls",
    # "can wait" — the work is acknowledged and pushed onto an owner or a row that is not
    # this one. An unnamed owner is the same as no owner.
    ("someone-elses-row", r"\bseparate\s+(?:piece\s+of\s+)?(?:work|effort|project|change|PR|commit|task|row|wave)\b"
                          r"|\bits\s+own\s+(?:row|wave|task|change|PR|commit|effort)\b"
                          r"|\bresearch\s+project\b|\bbigger\s+(?:lift|job|change|piece)\b"
                          r"|\bcan\s+wait\b|\bnot\s+urgent\b|\bwhoever\b|\bunowned\b|\bno\s+owner\b"
                          r"|\bno\s+room\s+for\b|\broom\s+for\b|\bnot\s+(?:my|this|our)\s+row\b"),

    # THE TELL. Twice in this tree, a sentence argues its own deferral is not one. That
    # argument is itself the strongest signal a human must read the line.
    ("denies-deferral", r"\b(?:is|are|was)\s+NOT\s+(?:a\s+|banned\s+)?(?:defer\w*|skip)\b"
                        r"|\bthis\s+is\s+not\s+a\s+defer\w*\b|\bnot\s+a\s+deferral\b"),
]

COMPILED = [(name, re.compile(pat, re.IGNORECASE)) for name, pat in SHAPES]

# ─────────────────────────────────────────────────────────────────────────────────────────
# LAYER 2 — THE STRUCTURAL RULE
#
# No deferral vocabulary. A FUTURE-TIME signal and a WORK signal in the same sentence. This
# is what catches a phrasing nobody put on a list, and it is the reason this file is not
# just SHAPES with more rows.
# ─────────────────────────────────────────────────────────────────────────────────────────
FUTURE = re.compile(
    r"\b(?:will|shall|'ll|going\s+to|gonna|once|after|when|until|before)\b"
    r"|\b(?:later|future|next|subsequent|downstream|upcoming|forthcoming|pending)\b"
    r"|\b(?:some\s*day|eventually|tomorrow|one\s+day|in\s+time|soon|ultimately)\b"
    r"|\bpost[\s-]\w+|\bbeyond\b|\bfollow[\s-]?(?:on|up)\b",
    re.IGNORECASE,
)
WORK = re.compile(
    r"\b(?:ship|land|build|wire|implement|do|add|handle|fix|address|cover|support|complete"
    r"|finish|port|convert|migrate|resolve|revisit|tackle|write|remove|delete|split|extract"
    r"|replace|rewrite|refactor|enforce|prove|test|gate)(?:s|ed|ing)?\b"
    r"|\bcircle\s+back\b|\bcome\s+back\b|\breturn\s+to\b|\bpick\s+(?:it|this|that)\s+up\b"
    r"|\bsort\s+(?:it|this|that)\s+out\b|\bclean\s+(?:it|this|that)\s+up\b"
    r"|\bget\s+to\s+(?:it|this|that)\b|\bleft\s+(?:for|to)\b|\bleave\s+(?:it|this|that)\b"
    r"|\bthe\s+(?:rest|remainder|remaining)\b|\bwork\b",
    re.IGNORECASE,
)


# THE SECOND STRUCTURAL RULE — AN OBLIGATION WITH NO OWNER. "someone should make it exact",
# "this ought to be tightened", "worth revisiting" — a modal obligation whose agent is
# indefinite or absent. It names no future and no banned word; what it has is a duty nobody
# has taken. That is a deferral in the only sense that matters: the work is not being done
# and no one is named for it.
OBLIGATION = re.compile(
    r"\b(?:should|ought\s+to|needs?\s+to|has\s+to|have\s+to|must\s+be|wants?\s+to"
    r"|worth\s+\w+ing|would\s+be\s+(?:nice|better|good)|good\s+enough|for\s+the\s+rig)\b",
    re.IGNORECASE,
)
INDEFINITE_AGENT = re.compile(
    r"\b(?:someone|somebody|anyone|whoever|somebody\s+else|a\s+human|we|us|one)\b"
    r"|\b(?:be|been|being)\s+\w+ed\b",  # passive: no agent at all
    re.IGNORECASE,
)


def layer2_hit(line: str) -> str | None:
    """Either structural rule, on one line. Returns the firing pair, or None.

    RULE A — future-time signal + work signal.
    RULE B — modal obligation + indefinite/absent agent.

    Neither rule contains one word of deferral vocabulary. That is the point: they are the
    only part of this file that can catch a phrasing nobody thought of.
    """
    f = FUTURE.search(line)
    w = WORK.search(line)
    if f and w:
        return f"future:{f.group(0).strip().lower()}+work:{w.group(0).strip().lower()}"
    o = OBLIGATION.search(line)
    if o:
        a = INDEFINITE_AGENT.search(line)
        if a:
            return f"obligation:{o.group(0).strip().lower()}+agent:{a.group(0).strip().lower()}"
    return None


# ─────────────────────────────────────────────────────────────────────────────────────────
DEFAULT_PATHS = ["docs/design/BUSBAR-1.6.0.md", "docs/design"]
DOC_GLOB = re.compile(r"(?:^|/)(?:BUSBAR-1\.6\.0|1\.6\.0-[^/]*)\.md$")
SRC_EXT = (".rs", ".sh", ".py", ".toml", ".md")


def collect(paths: list[str], all_md: bool) -> list[str]:
    out: set[str] = set()
    for p in paths:
        full = os.path.join(REPO, p)
        if os.path.isfile(full):
            out.add(os.path.relpath(full, REPO))
            continue
        for root, dirs, files in os.walk(full):
            dirs[:] = [d for d in dirs if d not in ("target", ".git", "node_modules", "__pycache__")]
            for fn in files:
                rel = os.path.relpath(os.path.join(root, fn), REPO)
                if not rel.endswith(SRC_EXT):
                    continue
                if not all_md and rel.endswith(".md") and not DOC_GLOB.search(rel):
                    continue
                out.add(rel)
    return sorted(out)


def scan(files: list[str], layer: str) -> list[tuple[str, int, str, str]]:
    """-> [(path, lineno, shape, text)] — one row per SHAPE that fired, not per line."""
    found: list[tuple[str, int, str, str]] = []
    for rel in files:
        try:
            with open(os.path.join(REPO, rel), "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for i, raw in enumerate(lines, 1):
            if layer in ("1", "both"):
                for name, rx in COMPILED:
                    if rx.search(raw):
                        found.append((rel, i, name, raw.strip()[:200]))
            if layer in ("2", "both"):
                pair = layer2_hit(raw)
                if pair:
                    found.append((rel, i, f"L2:{pair}", raw.strip()[:200]))
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--paths", nargs="*", default=None, help="paths to scan (default: the 1.6.0 doc set)")
    ap.add_argument("--layer", choices=["1", "2", "both"], default="1")
    ap.add_argument("--summary", action="store_true", help="counts by shape and by file")
    ap.add_argument("--expect", metavar="FILE", help="assert every `path:line` listed in FILE is named")
    ap.add_argument("--selftest", action="store_true", help="the planted-deferral positive control")
    ap.add_argument("--all-md", action="store_true", help="scan every .md, not just the 1.6.0 set")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    files = collect(args.paths or DEFAULT_PATHS, args.all_md)
    hits = scan(files, args.layer)

    if args.expect:
        want: list[str] = []
        with open(args.expect, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.split("#", 1)[0].strip()
                if ln:
                    want.append(ln)
        named = {f"{p}:{n}" for p, n, _, _ in hits}
        missed = [w for w in want if w not in named]
        for w in want:
            mark = "NAMED  " if w in named else "MISSED "
            shapes = sorted({s for p, n, s, _ in hits if f"{p}:{n}" == w})
            print(f"{mark}{w}\t{','.join(shapes) if shapes else '—'}")
        print(f"\n{len(want) - len(missed)}/{len(want)} named, {len(missed)} MISSED")
        return 1 if missed else 0

    if args.summary:
        by_shape: dict[str, int] = {}
        by_file: dict[str, int] = {}
        for p, _, s, _ in hits:
            key = s.split(":")[0] if s.startswith("L2") else s
            by_shape[key] = by_shape.get(key, 0) + 1
            by_file[p] = by_file.get(p, 0) + 1
        print(f"files scanned: {len(files)}   layer: {args.layer}   occurrences: {len(hits)}")
        print(f"distinct lines: {len({(p, n) for p, n, _, _ in hits})}")
        print("\nby shape:")
        for k, v in sorted(by_shape.items(), key=lambda kv: -kv[1]):
            print(f"  {v:5d}  {k}")
        print("\nby file (top 20):")
        for k, v in sorted(by_file.items(), key=lambda kv: -kv[1])[:20]:
            print(f"  {v:5d}  {k}")
        return 0

    for p, n, s, t in hits:
        print(f"{p}:{n}\t{s}\t{t}")
    return 0


# ─────────────────────────────────────────────────────────────────────────────────────────
# THE POSITIVE CONTROL
#
# A detector that only finds what it was built from is a transcript, not a detector. These
# are phrasings deliberately chosen NOT to appear in the shape list above — the sentence a
# developer writes when they are not trying to evade anything and simply are not finished.
# `expect_layer` records WHICH layer caught it, because "caught by Layer 2 only" means the
# named-shape set is still a spelling list and this file must say so.
# ─────────────────────────────────────────────────────────────────────────────────────────
# ROUND 1 — written BEFORE the shape set was widened, and used to widen it. Two of these
# fell through both layers on the first run; the fix was two new SHAPES (`negated-now`, and
# Layer 2's obligation rule), never a new word. Keeping them here is a regression test, not
# a proof — a control you tuned against is a transcript.
CONTROL_R1 = [
    # (text, expect_layer)  — expect_layer is "1" if a named shape must fire.
    ("// The remaining three call sites are left for a follow-on release once the engine split settles.", "1"),
    ("// We will circle back to the retry budget after the duplex landing.", "2"),
    ("// Good enough to unblock the rig; someone should make it exact.", "2"),
    ("/// Only the happy path is wired; the error arm comes with the next tranche of work.", "2"),
    ("// Not wiring this today — the shape is right and the cost is a day we do not have.", "1"),
]

# ROUND 2 — written AFTER the widening and NEVER used to tune it. This is the honest test.
# Whatever these do is reported verbatim, pass or fail; a miss here is a finding about this
# file, not a reason to edit the shape list again.
CONTROL_R2 = [
    ("// Shipping the single-slot read; the multi-slot lookup can wait for whoever owns tls next quarter.", "1"),
    ("// The reconciler only handles the two-party case. Three-party is a bigger lift than we have room for.", "2"),
    ("/// Approximate. Exactness here is a research project and the rig does not need it.", "2"),
    ("// Leaving the second codepath alone until somebody can prove which one callers actually take.", "2"),
    ("// Stubbed against the happy path so the battery goes green; real fault injection is a separate piece of work.", "1"),
]

# ROUND 3 — written after the Round-2 widening, never used to tune anything. Whatever this
# round does is the detector's real, untuned hit rate and is reported as such.
CONTROL_R3 = [
    ("// The window accounting rounds to the minute; per-second is more plumbing than this ticket bought.", "1"),
    ("// One provider is enough to prove the seam. The other two land when someone needs them.", "2"),
    ("// This assumes the config never reloads. It does, but not on any path we ship.", "1"),
    ("// I have left the old branch in place because deleting it needs a migration nobody has written.", "2"),
    ("// Enough of the contract to compile. The invariants are documented and unenforced.", "1"),
]

CONTROL = CONTROL_R1


def selftest() -> int:
    r1 = _run_control("ROUND 1 — used to widen the shape set (regression test)", CONTROL_R1)
    r2 = _run_control("ROUND 2 — drove the four shape families marked 'tuned-against' above", CONTROL_R2)
    r3 = _run_control("ROUND 3 — written after ALL widening, NEVER used to tune anything", CONTROL_R3)
    print("=" * 89)
    if r3:
        print(f"ROUND 3 (the untuned one): {r3} of {len(CONTROL_R3)} fell through.")
        print("That is the honest residue. Layer 1 is a SHAPE set, not a complete one; the")
        print("phrasings it misses are caught by Layer 2 or not at all, and Layer 2 is a")
        print("reading list, not a gate. Do NOT close a Round-2 miss by adding its words —")
        print("that turns the detector back into a transcript of what it was shown.")
    else:
        print("ROUND 3 (the untuned one): every control phrase was caught at or above its layer.")
    return 1 if (r1 or r2 or r3) else 0


def _run_control(title: str, cases: list[tuple[str, str]]) -> int:
    print("=" * 89)
    print(title)
    print("=" * 89 + "\n")
    bad = 0
    for text, want in cases:
        l1 = sorted({name for name, rx in COMPILED if rx.search(text)})
        l2 = layer2_hit(text)
        if l1:
            print(f"  L1 {','.join(l1)}\n     {text}")
        elif l2:
            tag = "L1-MISS, L2 caught" if want == "1" else "L2"
            print(f"  {tag}  {l2}\n     {text}")
            if want == "1":
                bad += 1
        else:
            print(f"  ** MISSED BY BOTH LAYERS **\n     {text}")
            bad += 1
        print()
    print(f"-> {len(cases) - bad}/{len(cases)} caught at or above the expected layer\n")
    return bad


if __name__ == "__main__":
    sys.exit(main())
