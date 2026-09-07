#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# rules_extra.py -- the second measuring module of THE CONSTRUCTION GATE.
#
# WHY A SECOND MODULE. rules.py is one file that every rule author edits, and two authors adding a
# rule in the same week collide in it line by line. The rules here were all born from the same
# audit and share nothing with the rules there except the row shape, so they live in a file of
# their own: rules.py imports this module and calls `evaluate()` once, and `calibrate()` once. That
# is the whole seam. A rule belongs here when it is about how the REPAIR SHOP is built -- the gate
# scripts, the waivers, the tests -- or about a construction class this file already carries.
#
# EVERY RULE HERE MEASURES A CLASS, NOT AN INSTANCE. Each was written because the same shape of
# defect was found more than once by hand: a floor posted from a document size instead of the
# kernel's accumulator, a live-swappable section pinned in a OnceLock, a claimed route with no arm
# to decode it, a test that asserts nothing, a gate script that swallows the exit code of the very
# thing it exists to run, a waiver naming a file that is not there any more. Finding one of those by
# reading is luck; measuring the class is the instrument.
#
# The row shape and the scanning discipline are rules.py's: comments stripped with string literals
# respected, `#[cfg(test)]` blocks and `*/tests/*` paths classified as test code. Rules that must
# look at SHELL or at the ceilings file itself do their own reading, because the Rust scanner has
# nothing to say about either.

import fnmatch
import glob
import os
import re

import rules


# ── shared helpers ────────────────────────────────────────────────────────────────────────────────


def _shell_scripts(root, cfg):
    """Every shell script in scope, repo-relative and sorted.

    Globs are resolved with `recursive=True` so a `**` in the ceilings file reaches nested legs, and
    a glob matching nothing is silence rather than a finding: the self-test's scratch copy carries
    only part of `testing/`, and a rule that failed because a directory was not copied would be
    reporting on the copy rather than on the tree."""
    c = cfg["rules"]["gate-script-hygiene"]
    exempt = set(c.get("exempt", []))
    found = []
    for pattern in c["scope_globs"]:
        for path in glob.glob(os.path.join(root, pattern), recursive=True):
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if os.path.isfile(path) and rel not in exempt and rel not in found:
                found.append(rel)
    return sorted(found)


def _read_text(root, rel):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read().split("\n")
    except OSError:
        return []


# ── A. gate-script-hygiene ────────────────────────────────────────────────────────────────────────


_SET_LINE = re.compile(r"^\s*set\s+-[A-Za-z]*\b|^\s*set\s+-o\b")
_MUFFLE = re.compile(r"\|\|\s*(true|:)\s*(;|$|\|\||&&)")


def rule_gate_script_strict_mode(tree, cfg):
    """Every gate script asks the shell to stop lying to it.

    Two flags, not three. `-u` makes an unset variable an error rather than an empty string, which is
    the difference between a scope that shrank to nothing and a scope that was checked; `pipefail`
    makes the exit code of a pipeline the exit code of the command that failed, which is the
    difference between `scan | tee log` reporting the scan's verdict and reporting tee's. `-e` is
    deliberately NOT required: the ledger-style gates in this tree run every check and let
    verdict.sh decide, and `-e` would make the first red check the last one that ran."""
    c = cfg["rules"]["gate-script-hygiene"]
    root = tree.root
    scripts = _shell_scripts(root, cfg)
    head = c["head_lines"]
    offenders = []
    for rel in scripts:
        lines = _read_text(root, rel)[:head]
        opts = "".join(l for l in lines if _SET_LINE.match(l))
        has_u = bool(re.search(r"set\s+-[A-Za-z]*u", opts)) or "set -o nounset" in opts
        has_pipefail = "pipefail" in opts
        if not (has_u and has_pipefail):
            missing = ", ".join(
                w for w, ok in (("-u", has_u), ("pipefail", has_pipefail)) if not ok)
            offenders.append(f"{rel} (missing {missing})")
    current = len(offenders)
    if not scripts:
        detail = rules.VACUOUS + "no shell script in scope is present in this tree"
    else:
        detail = (f"{current} of {len(scripts)} gate script(s) do not set both `-u` and `pipefail` "
                  f"(ratchet {c['max_lax']}): "
                  + ("; ".join(offenders[:8]) + (" …" if current > 8 else "") if offenders
                     else "none"))
    return [rules.row("gate-script-hygiene:strict-mode", current <= c["max_lax"],
                      "every gate script sets `-u` and `pipefail`",
                      detail, current, c["max_lax"], c["why"], offenders)]


def rule_gate_script_muffled_subject(tree, cfg):
    """No gate script discards the exit code of the thing it exists to run.

    `cargo test … || true` is a gate that reports PASS whatever the tests did. The subject patterns
    below name the commands a gate in this tree runs to LEARN something — the compiler, the node,
    the helper scripts — as opposed to the housekeeping (`rm`, `mkdir`, `grep -c`) where a swallowed
    non-zero is the intended reading. A muffled subject is judged on the line, so a `|| true` two
    commands along the same line still counts: the pipeline it belongs to is the one that ran."""
    c = cfg["rules"]["gate-script-hygiene"]
    root = tree.root
    scripts = _shell_scripts(root, cfg)
    subject_rx = re.compile("|".join(c["subject_patterns"]))
    offenders = []
    for rel in scripts:
        for no, text in enumerate(_read_text(root, rel), start=1):
            stripped = text.lstrip()
            if stripped.startswith("#"):
                continue
            if _MUFFLE.search(text) and subject_rx.search(text):
                offenders.append(f"{rel}:{no}")
    current = len(offenders)
    if not scripts:
        detail = rules.VACUOUS + "no shell script in scope is present in this tree"
    else:
        detail = (f"{current} line(s) run a gate subject and discard its exit code "
                  f"(ratchet {c['max_muffled']}): "
                  + ("; ".join(offenders[:8]) + (" …" if current > 8 else "") if offenders
                     else "none"))
    return [rules.row("gate-script-hygiene:muffled-subject", current <= c["max_muffled"],
                      "no gate script swallows the exit code of the subject it runs",
                      detail, current, c["max_muffled"], c["why"], offenders)]


# ── B. unused-waiver ──────────────────────────────────────────────────────────────────────────────


def _waiver_paths(cfg):
    """Every repo path any waiver in the ceilings file names, as (where, path).

    Walks the whole configuration rather than a list of known rules, because the point of the rule
    is that a waiver added tomorrow is watched too. THREE shapes are read: a LIST under one of the
    waiver key names (`known_sites`, `known_bare`, `confined_to_paths`, `exempt_files`), a TABLE
    whose KEYS are paths (the per-file allow-lists), and a SCALAR under one of the waiver field
    names (`file`), which is how a waiver written as a table-per-site spells the path it excuses.
    A string that does not look like a repo path — a crate name, a symbol, a prose scope — is not a
    path and is left alone.

    THE THIRD SHAPE WAS THE HOLE. `[rules.no-test-doubles-in-production.known_sites.<name>]` is a
    table whose path is a VALUE under `file`, not a list entry and not a key, so the walk descended
    past it and every one of those reviewed sites was unwatched. So was `known_bare`, an
    eighteen-entry per-test waiver that was simply not on the key list. Both are exactly what this
    rule's own reason describes: an entry that goes on looking like it is watching a site that is
    not there any more, while the file comes back under a name it no longer matches."""
    c = cfg["rules"]["unused-waiver"]
    keys = set(c["waiver_list_keys"])
    tables = set(c["waiver_table_keys"])
    fields = set(c.get("waiver_field_keys", []))
    out = []

    def looks_like_a_path(s):
        return "/" in s and not s.startswith(("http", "-"))

    def walk(node, where):
        if isinstance(node, dict):
            for k, v in node.items():
                here = f"{where}.{k}" if where else k
                if k in keys and isinstance(v, list):
                    for entry in v:
                        if isinstance(entry, str) and looks_like_a_path(entry):
                            out.append((here, entry))
                elif k in tables and isinstance(v, dict):
                    for entry in v:
                        if looks_like_a_path(entry):
                            out.append((here, entry))
                elif k in fields and isinstance(v, str):
                    if looks_like_a_path(v):
                        out.append((here, v))
                else:
                    walk(v, here)

    walk(cfg, "")
    return out


def rule_unused_waiver(tree, cfg):
    """A waiver that excuses nothing is deleted, not kept.

    A `known_sites` entry naming a file that has since moved, or a `confined_to_paths` scope
    resolving to a directory that is not there, reads to the next person as debt that is still owed
    and to the gate as nothing at all. Worse, it is how a rule silently loosens: the entry stays,
    the file comes back under a name the entry no longer matches, and the site it was written to
    pin is now unwatched. The check is deliberately about EXISTENCE, not about whether the rule
    would have fired there — a waiver for a site that exists and is now clean is a judgement the
    owning rule makes, and this one does not second-guess it."""
    c = cfg["rules"]["unused-waiver"]
    offenders = []
    for where, entry in _waiver_paths(cfg):
        # `path::symbol` narrows a waiver to one function inside a file; the file is what has to be
        # there. A trailing separator means the entry is a directory prefix.
        path = entry.split("::", 1)[0].rstrip("/")
        if not path:
            continue
        if not os.path.exists(os.path.join(tree.root, path.replace("/", os.sep))):
            offenders.append(f"{where}: `{entry}` matches nothing in this tree")
    current = len(offenders)
    detail = (f"{current} waiver entr(ies) name a path that is not in the tree "
              f"(ceiling {c['max_unused']}): "
              + ("; ".join(offenders[:8]) + (" …" if current > 8 else "") if offenders else "none"))
    return [rules.row("unused-waiver", current <= c["max_unused"],
                      "every waiver in the ceilings file excuses something that is actually there",
                      detail, current, c["max_unused"], c["why"], offenders)]


# ── C. assertion-free tests ───────────────────────────────────────────────────────────────────────


_TEST_ATTR = re.compile(r"^\s*#\[(?:[A-Za-z_][A-Za-z0-9_]*::)*test(?:\(|\]|\s)")


def _raw_string_lines(path):
    """Line numbers that fall inside a multi-line RAW string literal.

    The shared scanner blanks `"…"` but not `r#"…"#`, so a test file that carries a fixture written
    as Rust source inside a raw string has that fixture read as if it were code: its `#[test]`
    attributes and `fn` names are found, and a rule counting tests reports fixtures that no harness
    will ever run. Approximate on purpose — an opening `r#"`/`r"` with no closing delimiter on the
    same line opens a span, the next `"#`/`"` closes it — because the alternative is a second Rust
    lexer, and the only decision resting on this is whether to look at a function at all."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read().split("\n")
    except OSError:
        return set()
    inside, spanned = False, set()
    for no, text in enumerate(raw, start=1):
        if inside:
            spanned.add(no)
            if '"#' in text or re.search(r'(?<!\\)"', text):
                inside = False
            continue
        m = re.search(r'r#*"', text)
        if m and '"#' not in text[m.end():]:
            inside = True
    return spanned


def _body_by_indent(lines, fn, raw_span=frozenset()):
    """The test's body, delimited by the closing brace at the `fn`'s own indentation.

    NOT `Fn.end`, deliberately. The shared brace matcher blanks `"…"` literals but not RAW strings,
    and a test that pins a JSON document with `r#"{…}"#` therefore looks brace-unbalanced to it: its
    extent stops early, its assertions fall outside, and it is reported as asserting nothing when it
    asserts eight things. Every file here is `cargo fmt`-clean, and rustfmt closes a function with a
    lone `}` at the signature's indentation, so that brace is the honest end. If it is not found —
    a macro-generated test, a file fmt has not seen — the matcher's own answer is used, which is
    the conservative direction: a longer body can only contain MORE evidence, never less."""
    indent = " " * (len(lines[fn.start - 1].code) - len(lines[fn.start - 1].code.lstrip()))
    closing = indent + "}"
    for i in range(fn.body_start, len(lines)):
        # A `}` inside a raw-string fixture is a character, not the end of anything. The fixtures in
        # this tree are Rust source written at column zero, so without this the body of every
        # top-level test that pins one ends at the fixture's first closing brace.
        if lines[i].no in raw_span:
            continue
        if lines[i].code.rstrip() == closing:
            return "\n".join(l.code for l in lines[fn.body_start - 1:i + 1])
    return "\n".join(l.code for l in lines[fn.body_start - 1:fn.end])


def _test_fns(root, cfg):
    """(rel, Fn, body_text) for every `#[test]`/`#[…::test]` function in scope.

    Scans its OWN file list rather than the shared Tree, because the shared scan covers `*/src` only
    and half the tests in this repository live in `crates/*/tests`. The attribute is looked for on
    the lines immediately above the `fn`, skipping the other attributes and the doc comment that
    normally sit between them."""
    c = cfg["rules"]["assertion-free-tests"]
    frags = cfg["gate"]["test_path_fragments"]
    evidence_rx = re.compile("|".join(c["evidence_patterns"]))
    found = []
    # ONE ENTRY PER FILE. The scope globs overlap on purpose (`src/*.rs` and `src/**/*.rs` between
    # them cover every depth on every glob implementation), and a file matched twice was measured
    # twice: the count doubled and the same test was listed under two names in the worklist.
    paths = sorted({p for pattern in c["scope_globs"]
                    for p in glob.glob(os.path.join(root, pattern), recursive=True)})
    for path in paths:
        if not path.endswith(".rs") or not os.path.isfile(path):
            continue
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        lines = rules.scan_file(path, frags)
        raw_span = _raw_string_lines(path)
        all_fns = [f for f in rules.find_fns(rel, lines) if f.start not in raw_span]
        # THE FILE'S OWN HELPERS COUNT. A battery of tests that each set up one case and hand it
        # to a shared `battery(…)` holding the assertions is a good test, not an empty one, and
        # a rule that could not see that would report the whole battery and be switched off. So
        # every function in the file is read once, and a test's body is judged together with the
        # bodies of the file's functions it calls, transitively. Same file only: a helper in
        # another module is a scan this rule does not do, and claiming otherwise would be worse
        # than not looking.
        bodies = {f.name: _body_by_indent(lines, f, raw_span) for f in all_fns}
        asserting = {n for n, b in bodies.items() if evidence_rx.search(b)}
        for _ in range(c["helper_depth"]):
            grew = False
            for n, b in bodies.items():
                if n in asserting:
                    continue
                if any(re.search(rules._word(h) + r"\s*[(<]", b) for h in asserting):
                    asserting.add(n)
                    grew = True
            if not grew:
                break
        for fn in all_fns:
            # The attribute block immediately above the signature: blank lines, doc comments
            # (already empty here, comments having been stripped) and attributes, and NOTHING
            # else. Being strict about "nothing else" is what stops a helper `fn` declared on
            # the first line of a test's body from inheriting that test's `#[test]` and being
            # reported under the helper's name.
            attrs, i = [], fn.start - 2
            while i >= 0:
                text = lines[i].code
                stripped = text.strip()
                if not stripped:
                    i -= 1
                    continue
                if stripped.startswith("#") or stripped.endswith(("]", "],")) \
                        or stripped.startswith(")"):
                    attrs.append(text)
                    i -= 1
                    continue
                break
            if any(_TEST_ATTR.match(a) for a in attrs):
                # The attributes are read together with the body. `#[should_panic]` IS the
                # assertion of a test that has no other: the claim is that the call panics, and
                # the harness checks it.
                body = "\n".join(attrs) + "\n" + bodies.get(fn.name, "")
                asserts = fn.name in asserting or bool(evidence_rx.search("\n".join(attrs)))
                found.append((rel, fn, body, asserts))
    return found


def rule_assertion_free_tests(tree, cfg):
    """A test that asserts nothing is a test that cannot fail.

    It runs, it is counted in the total, it turns a red suite green — and the only thing it proves
    is that the code under it did not panic. This counts test functions whose whole body contains no
    evidence of a claim: no `assert`, no `expect`, no `unwrap_err`, no `?`, no `panic!`. Ratcheted
    with the list, because the list IS the worklist: each name below is either given an assertion or
    deleted, and nothing new joins it."""
    c = cfg["rules"]["assertion-free-tests"]
    evidence_rx = re.compile("|".join(c["evidence_patterns"]))
    known = set(c.get("known_bare", []))
    tests = _test_fns(tree.root, cfg)
    offenders = []
    for rel, fn, body, asserts in tests:
        if asserts:
            continue
        name = f"{rel}::{fn.name}"
        if name in known:
            continue
        offenders.append(f"{name} ({rel}:{fn.start})")
    current = len(offenders)
    if not tests:
        detail = rules.VACUOUS + "no test function is present in the scanned tree"
    else:
        detail = (f"{current} of {len(tests)} test function(s) assert nothing "
                  f"(ratchet {c['max_bare']}): "
                  + ("; ".join(offenders[:8]) + (" …" if current > 8 else "") if offenders
                     else "none"))
    rows = [rules.row("assertion-free-tests", current <= c["max_bare"],
                      "every test makes a claim that can fail",
                      detail, current, c["max_bare"], c["why"], offenders)]

    # The second, quieter reading: a test whose NAME promises an exact figure and whose only
    # assertion is a bound. `assert!(n >= 1)` under `…_exactly_one` passes for two, for ten, and for
    # the regression the name was written to catch. Reported, never enforced: a bound can be the
    # honest claim (a timing floor, a capacity), and the reader is the one who can tell.
    exact_rx = re.compile("|".join(c["exactness_words"]))
    bound_only = []
    for rel, fn, body, asserts in tests:
        if not exact_rx.search(fn.name):
            continue
        if not asserts or not evidence_rx.search(body):
            continue  # counted above, or asserting somewhere this row cannot read
        if re.search(r"assert_eq!|assert_ne!|==|!=", body):
            continue
        if re.search(r"<=|>=|<|>", body):
            bound_only.append(f"{rel}::{fn.name} ({rel}:{fn.start})")
    detail = (f"{len(bound_only)} test(s) whose name promises an exact figure assert only a bound: "
              + ("; ".join(bound_only[:8]) + (" …" if len(bound_only) > 8 else "")
                 if bound_only else "none"))
    rows.append(rules.row("assertion-loose-for-name", True,
                          "a test whose name says `exactly` asserts equality, not a bound",
                          detail, len(bound_only), 0, c["why"], bound_only, informational=True))
    return rows


# ── D. accrued-floor-metered ──────────────────────────────────────────────────────────────────────


def rule_accrued_floor_metered(tree, cfg):
    """The floor the kernel settles against is the kernel's own accrual, not a document size.

    `Evidence::accrued_floor` is documented in busbar-kernel as "what the kernel counted while the
    unit ran" and the kernel reports its own accrual against `nano_units`. A root that fills it from
    a request document's byte count is handing the settlement table a figure in the wrong
    denomination: the table compares it against the located reading and posts the lower of the two,
    so a floor in bytes beside a located reading in a priced class decides the posting by an
    accident of scale. The sibling field `located` is NOT checked here and must not be: it is
    explicitly class-denominated (`class: Some(CLASS_BYTES)` beside it says which meter it is
    counted on), so requiring nanos of it would be requiring the wrong thing.

    The check is a REVIEWED-SOURCE list, in the same shape as this gate's other allow-lists: an
    initialiser whose right-hand side reads one of the named accumulators is the design working; any
    other source is a site a human has to look at. Adding a source means adding it below with a
    reason, which is the review this rule exists to force."""
    c = cfg["rules"]["accrued-floor-metered"]
    files = rules._scoped_files(tree, c["scope_globs"])
    source_rx = re.compile("|".join(c["metered_sources"]))
    field_rx = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(c["field"]) + r"\s*:")
    offenders = []
    for rel in files:
        lines = tree.files[rel]
        for idx, l in enumerate(lines):
            if l.intest:
                continue
            m = field_rx.search(l.code)
            if not m:
                continue
            # The value may be written on the same line or continue onto the next ones, as a
            # multi-line method chain does. Read forward until the initialiser's own comma.
            rhs = l.code[m.end():]
            j = idx + 1
            while "," not in rhs and j < len(lines) and j - idx <= c["lookahead_lines"]:
                rhs += " " + lines[j].code.strip()
                j += 1
            if not source_rx.search(rhs):
                offenders.append(f"{rel}:{l.no} `{rhs.strip()[:60]}`")
    current = len(offenders)
    if not files:
        detail = rules.VACUOUS + "no composition-root unit module is present in this tree"
    else:
        detail = (f"{current} `{c['field']}` initialiser(s) read a source that is not a reviewed "
                  f"accumulator (ratchet {c['max_unreviewed']}): "
                  + ("; ".join(offenders[:8]) if offenders else "none"))
    return [rules.row("accrued-floor-metered", current <= c["max_unreviewed"],
                      "the settled floor comes from the kernel's accumulator, not a document size",
                      detail, current, c["max_unreviewed"], c["why"], offenders)]


# ── E. live-config-pinned ─────────────────────────────────────────────────────────────────────────


def rule_live_config_pinned(tree, cfg):
    """A live-swappable configuration section is never pinned in a once-only cell.

    The admin contract divides the configuration in two: sections a `PUT` makes live immediately,
    and sections that need a reload. A `OnceLock`/`OnceCell` holding a value of a LIVE section is a
    promise the admin API cannot keep — the first request to touch it decides the value for the life
    of the process, and every later apply returns success while changing nothing that is read. The
    type list below is the live half of the contract, named as types; a section that becomes
    reload-scoped is removed from it, which is a decision, not a drift."""
    c = cfg["rules"]["live-config-pinned"]
    files = rules._scoped_files(tree, c["scope_globs"])
    cell = "|".join(re.escape(x) for x in c["once_types"])
    types = "|".join(re.escape(t) for t in c["live_types"])
    rx = re.compile(
        r"(?<![A-Za-z0-9_])(?:" + cell + r")\s*<\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*"
        r"(" + types + r")(?![A-Za-z0-9_])")
    offenders = []
    for rel in files:
        for l in tree.files[rel]:
            if l.intest:
                continue
            m = rx.search(l.code)
            if m:
                offenders.append(f"`{m.group(0)}` at {rel}:{l.no}")
    current = len(offenders)
    if not files:
        detail = rules.VACUOUS + "no composition-root or substrate source is present in this tree"
    else:
        detail = (f"{current} once-only cell(s) hold a live-swappable configuration type "
                  f"(ceiling {c['max_pinned']}): "
                  + ("; ".join(offenders[:8]) if offenders else "none"))
    return [rules.row("live-config-pinned", current <= c["max_pinned"],
                      "no live-swappable configuration section is pinned at first use",
                      detail, current, c["max_pinned"], c["why"], offenders)]


# ── F. claimed-path-has-arm ───────────────────────────────────────────────────────────────────────


_EXACT_PATH = re.compile(r"ExactPath\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
_STR_CONST = re.compile(
    r"(?<![A-Za-z0-9_])const\s+([A-Z_][A-Z0-9_]*)\s*:\s*&(?:'static\s+)?str\s*=\s*\"([^\"]*)\"")


def rule_claimed_path_has_arm(tree, cfg):
    """Every UNAUTHENTICATED route a plane claims is a route its decoder recognises.

    A claim is a promise to the router that requests on this path belong to this plane. If the
    plane's ingress decoder has no arm for that path, the request is handed to whatever the decoder
    does by default — and every plane's default arm reads a REQUEST ENVELOPE. That is fine for the
    protocol's own request surface, which is what the default arm is for. It is not fine for the
    surfaces this rule watches: an open claim is a discovery or callback document fetched with no
    body at all, so the default arm sees an empty frame and answers "nothing has arrived yet", on a
    surface where nothing more ever will. The caller is held open until it gives up. That is worse
    than not claiming the route: an unclaimed route is a 404 the caller can read.

    SCOPE IS THE OPEN CLAIMS, and that is what keeps the rule honest rather than noisy. Claims on
    the plane's authenticated request surface legitimately have no arm of their own — the default
    arm IS their arm — so counting those would report three sound routes for every unsound one and
    teach the reader to skip the row. An open claim is declared through a constructor whose name
    says so, which is the one thing every plane in this tree spells the same way.

    The check itself is by VALUE, not by name. Each `Selector::ExactPath(NAME)` is resolved to the
    string literal `NAME` is declared as, and the LITERAL is looked for in the rest of the plane's
    production sources. That is what makes the rule usable across planes that dispatch differently:
    one matches the path constants, another writes the same strings out in a `match`, and both are
    recognising the route. Only a path that appears nowhere but the claim itself has nothing that
    could possibly answer on it."""
    c = cfg["rules"]["claimed-path-has-arm"]
    open_rx = re.compile(c["open_claim_pattern"])
    rows = []
    # ONE ROW PER DECLARED PLANE, from the census — not one per claims file found on disk. The owed
    # id set is built from the same list (see expected_ids), and a rule whose rows are enumerated by
    # what it happened to find can never owe a row for what it did not: a claims module renamed out
    # from under `claims_glob` would simply stop producing its row, and a row nobody owes is a row
    # nobody notices is missing. A declared plane whose claims module is absent is UNPROVEN, which is
    # the same answer this gate gives everywhere else its subject goes away.
    found = {tree.crate_of(rel): rel for rel in sorted(tree.files)
             if fnmatch.fnmatch(rel.replace(os.sep, "/"), c["claims_glob"])}
    declared = cfg["gate"].get("expected_kind_crates", {}).get("plane", [])
    if not declared:
        return [rules.row("claimed-path-has-arm", not found,
                          "every claimed exact path has an arm in the plane's decoder",
                          rules.VACUOUS + "gate.expected_kind_crates declares no plane crate"
                          if not found else
                          rules.UNPROVEN + "gate.expected_kind_crates declares no plane crate, yet "
                          + ", ".join(sorted(found)) + " carries a claims module nothing measures",
                          len(found), 0, c["why"], sorted(found))]
    for crate in declared:
        ceiling = c["max_unanswered"].get(crate, 0)
        claims_rel = found.get(crate)
        if claims_rel is None:
            rows.append(rules._unproven(
                f"claimed-path-has-arm:{crate}", f"{crate} decodes every exact path it claims",
                f"no file matching {c['claims_glob']} exists under crates/{crate}, so this plane's "
                "claims were never read; point qa/construction.toml's [rules.claimed-path-has-arm] "
                "claims_glob at the module's new name, or strike the crate from "
                "gate.expected_kind_crates.plane", c["why"]))
            continue
        literals = {}
        for l in tree.files[claims_rel]:
            for m in _STR_CONST.finditer(l.code):
                literals[m.group(1)] = m.group(2)
        claimed = []
        for l in tree.files[claims_rel]:
            if l.intest:
                continue
            if not open_rx.search(l.code):
                continue
            for m in _EXACT_PATH.finditer(l.code):
                name = m.group(1)
                if name in literals and (name, literals[name]) not in claimed:
                    claimed.append((name, literals[name]))
        elsewhere = [rel for rel in tree.files
                     if rel != claims_rel and tree.crate_of(rel) == crate]
        answered = set()
        for rel in elsewhere:
            for l in tree.files[rel]:
                if l.intest:
                    continue
                for name, lit in claimed:
                    if lit and lit in l.code:
                        answered.add(lit)
        offenders = [f"`{name}` = \"{lit}\" claimed in {claims_rel}, named nowhere else in {crate}"
                     for name, lit in claimed if lit not in answered]
        current = len(offenders)
        detail = (f"{crate}: {current} of {len(claimed)} exact-path claim(s) have no arm "
                  f"(ratchet {ceiling}): " + ("; ".join(offenders) if offenders else "none"))
        rows.append(rules.row(f"claimed-path-has-arm:{crate}", current <= ceiling,
                              f"{crate} decodes every exact path it claims",
                              detail, current, ceiling, c["why"], offenders))
    return rows


# ── the seam rules.py calls ───────────────────────────────────────────────────────────────────────

# Every row id this module OWES, with no declared subject list behind it. Order matches evaluate().
SINGLETON_IDS = (
    "gate-script-hygiene:strict-mode", "gate-script-hygiene:muffled-subject", "unused-waiver",
    "assertion-free-tests", "assertion-loose-for-name", "accrued-floor-metered",
    "live-config-pinned",
)


def expected_ids(cfg):
    """The row ids this module owes, derived from the ceilings file alone.

    THE VERDICT ONLY SEES WHAT IS OWED. testing/fleet-fixtures/verdict.sh resolves EXPECTED_IDS
    against the ledger and ignores every row whose id is not on that list -- so a FAIL row this
    module wrote was read by nobody and `--check` exited 0 through it. Every rule here was
    unenforceable from the day the module was added: the self-test's plant loop reads ledger.tsv
    directly and saw each planted violation go red, which proved the ROW was written and never that
    the GATE went red on it. The two are only the same thing for an id the verdict owes.

    `claimed-path-has-arm` is per-plane, keyed by the census's declared plane crates rather than by
    the claims files found on disk, for the same reason rules.py derives its own owed set from the
    config: a claims module that moved out from under `claims_glob` must leave a row missing, not
    quietly stop being owed. The vacuous single row (no plane claims module anywhere in the tree) is
    owed under its bare id, because that is the id the rule writes in that case.
    """
    ids = list(SINGLETON_IDS)
    planes = cfg["gate"].get("expected_kind_crates", {}).get("plane", [])
    if planes:
        ids += [f"claimed-path-has-arm:{crate}" for crate in planes]
    else:
        ids.append("claimed-path-has-arm")
    return ids


def evaluate(tree, cfg):
    rows = []
    rows += rule_gate_script_strict_mode(tree, cfg)
    rows += rule_gate_script_muffled_subject(tree, cfg)
    rows += rule_unused_waiver(tree, cfg)
    rows += rule_assertion_free_tests(tree, cfg)
    rows += rule_accrued_floor_metered(tree, cfg)
    rows += rule_live_config_pinned(tree, cfg)
    rows += rule_claimed_path_has_arm(tree, cfg)
    return rows


def calibrate(rows, cfg):
    """Set this module's ceilings to today's measurements, for the self-test's green baseline."""
    by_id = {r["id"]: r for r in rows}
    r = cfg["rules"]
    r["gate-script-hygiene"]["max_lax"] = by_id["gate-script-hygiene:strict-mode"]["current"]
    r["gate-script-hygiene"]["max_muffled"] = by_id["gate-script-hygiene:muffled-subject"]["current"]
    r["unused-waiver"]["max_unused"] = by_id["unused-waiver"]["current"]
    r["assertion-free-tests"]["max_bare"] = by_id["assertion-free-tests"]["current"]
    r["accrued-floor-metered"]["max_unreviewed"] = by_id["accrued-floor-metered"]["current"]
    r["live-config-pinned"]["max_pinned"] = by_id["live-config-pinned"]["current"]
    for rid, spec in by_id.items():
        if rid.startswith("claimed-path-has-arm:"):
            r["claimed-path-has-arm"]["max_unanswered"][rid.split(":", 1)[1]] = spec["current"]
