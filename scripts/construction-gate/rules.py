#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# rules.py -- the measuring half of THE CONSTRUCTION GATE (scripts/construction-gate.sh).
#
# This file only MEASURES. It scans Rust source with the same discipline as
# scripts/plane-purity-lint.sh (comments and doc-comments stripped with string literals respected,
# `*/tests/*` and `*_tests.rs` files plus `#[cfg(test)] mod … { … }` blocks classified as test
# code), evaluates each construction invariant from qa/construction.toml, and emits:
#
#   --rows      one TSV row per invariant x scope  (id, PASS|FAIL, title, detail)  -> the ledger
#   --expected  the ids the run owes, so the verdict can see a rule that did not run
#   --report    a Markdown report with per-rule counts and worst offenders
#   --summary   one line per rule: current / threshold
#   --calibrate write a copy of the toml whose thresholds equal today's counts (used by the
#               self-test to obtain a green baseline before planting each violation)
#
# It never decides the verdict; testing/fleet-fixtures/verdict.sh does that from the ledger.
# Pure stdlib, no cargo, no network.

import argparse
import fnmatch
import glob
import json
import os
import re
import sys
import tomllib

# ── Source scanning (a faithful port of the purity lint's awk `strip()` + test tracking) ──────────


class Line:
    __slots__ = ("no", "code", "blank", "intest")

    def __init__(self, no, code, blank, intest):
        self.no = no          # 1-based line number
        self.code = code      # the line with comments stripped, strings kept
        self.blank = blank    # the same with string/char literal contents blanked (structure only)
        self.intest = intest  # True when the line is test code


def strip_comments(line, state):
    """Drop `//`-to-EOL and `/* … */` (which may span lines, via state['inblk']) while leaving
    string literals intact, so a `//` inside a string is not a comment and a token inside a string
    is still seen. Same rules as the purity lint."""
    out = []
    i, n = 0, len(line)
    instr = False
    while i < n:
        c = line[i]
        c2 = line[i:i + 2]
        if state["inblk"]:
            if c2 == "*/":
                state["inblk"] = False
                i += 2
            else:
                i += 1
            continue
        if instr:
            out.append(c)
            if c == "\\":
                out.append(line[i + 1:i + 2])
                i += 2
                continue
            if c == '"':
                instr = False
            i += 1
            continue
        if c2 == "/*":
            state["inblk"] = True
            i += 2
            continue
        if c2 == "//":
            break
        if c == '"':
            instr = True
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


_STR_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_CHAR_RE = re.compile(r"'(?:\\.|[^'\\])'")


def blank_literals(code):
    """Replace string and char literal contents with spaces so braces/parens inside them do not
    disturb structure matching. Lifetimes (`'a`) are not char literals and are left alone."""
    code = _STR_RE.sub(lambda m: '"' + " " * (len(m.group(0)) - 2) + '"', code)
    return _CHAR_RE.sub("' '", code)


_CFG_TEST_WORD = re.compile(r"[^a-z0-9_]test[^a-z0-9_]")
_MOD_WORD = re.compile(r"(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])")


def is_test_path(path, fragments):
    return any(f in path for f in fragments)


def scan_file(path, test_fragments):
    """Return the list of Line records for one file."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.read().split("\n")
    except OSError:
        return []
    state = {"inblk": False}
    testfile = is_test_path(path, test_fragments)
    testdepth = 0
    pend = False
    lines = []
    for idx, raw in enumerate(raw_lines, start=1):
        code = strip_comments(raw, state)
        blank = blank_literals(code)
        nopen = blank.count("{")
        nclose = blank.count("}")
        lc = " " + code.lower() + " "
        is_cfgtest = "#[cfg(" in code and bool(_CFG_TEST_WORD.search(lc))
        has_mod = bool(_MOD_WORD.search(code))
        entered = False
        if is_cfgtest and has_mod:
            testdepth = max(nopen - nclose, 0)
            entered = testdepth > 0
            pend = False
        elif pend and has_mod:
            testdepth = max(nopen - nclose, 0)
            entered = testdepth > 0
            pend = False
        elif pend and code.strip() and not is_cfgtest:
            pend = False
        elif testdepth > 0:
            testdepth = max(testdepth + nopen - nclose, 0)
        if is_cfgtest and not has_mod:
            pend = True
        intest = testfile or testdepth > 0 or entered
        lines.append(Line(idx, code, blank, intest))
    return lines


class Fn:
    __slots__ = ("name", "path", "start", "end", "intest", "body_start")

    def __init__(self, name, path, start, end, intest, body_start):
        self.name = name
        self.path = path
        self.start = start            # line of the `fn` keyword
        self.end = end                # line of the closing brace
        self.intest = intest
        self.body_start = body_start  # line of the opening brace

    @property
    def lines(self):
        return self.end - self.start + 1


_FN_RE = re.compile(r"(?<![A-Za-z0-9_])fn\s+([A-Za-z_][A-Za-z0-9_]*)")


def find_fns(path, lines):
    """Locate every function with a body and its extent, by brace matching on the blanked text.
    The body begins at the first `{` outside parentheses after the name; a `;` there first means a
    bodiless declaration (a trait method), which is skipped."""
    text = "\n".join(l.blank for l in lines)
    starts = []
    off = 0
    for l in lines:
        starts.append(off)
        off += len(l.blank) + 1

    def line_of(pos):
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo

    fns = []
    for m in _FN_RE.finditer(text):
        name = m.group(1)
        i = m.end()
        depth = 0
        body = -1
        n = len(text)
        while i < n:
            c = text[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif depth == 0 and c == ";":
                break
            elif depth == 0 and c == "{":
                body = i
                break
            i += 1
        if body < 0:
            continue
        depth = 0
        j = body
        end = -1
        while j < n:
            c = text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
            j += 1
        if end < 0:
            continue
        sl = line_of(m.start())
        fns.append(Fn(name, path, lines[sl].no, lines[line_of(end)].no,
                      lines[sl].intest, lines[line_of(body)].no))
    return fns


class Tree:
    """Every scanned file, its lines and its functions, loaded once."""

    def __init__(self, root, cfg):
        self.root = root
        self.cfg = cfg
        self.test_fragments = cfg["gate"]["test_path_fragments"]
        self.files = {}   # rel path -> [Line]
        self.fns = {}     # rel path -> [Fn]
        for pattern in cfg["gate"]["scan_roots"]:
            for d in sorted(glob.glob(os.path.join(root, pattern))):
                for dirpath, _dirs, names in os.walk(d):
                    for nm in sorted(names):
                        if not nm.endswith(".rs"):
                            continue
                        full = os.path.join(dirpath, nm)
                        rel = os.path.relpath(full, root)
                        self.files[rel] = scan_file(full, self.test_fragments)
        for rel, lines in self.files.items():
            self.fns[rel] = find_fns(rel, lines)

    def crate_of(self, rel):
        parts = rel.split(os.sep)
        return parts[1] if len(parts) > 1 and parts[0] == "crates" else parts[0]

    def enclosing_fn(self, rel, lineno):
        """The innermost function containing the line, or None."""
        best = None
        for f in self.fns.get(rel, []):
            if f.start <= lineno <= f.end and (best is None or f.lines < best.lines):
                best = f
        return best

    def find_fn_by_name(self, name):
        hits = []
        for rel, fns in self.fns.items():
            for f in fns:
                if f.name == name and not f.intest:
                    hits.append(f)
        return hits

    def grep(self, regex, production_only=True, files=None):
        """(rel, Line) for every line whose stripped code matches."""
        rx = re.compile(regex)
        out = []
        for rel in (files if files is not None else self.files):
            for l in self.files.get(rel, []):
                if production_only and l.intest:
                    continue
                if rx.search(l.code):
                    out.append((rel, l))
        return out


# ── Rules ─────────────────────────────────────────────────────────────────────────────────────────
# Each rule returns a list of Row dicts:
#   {id, status, title, detail, current, threshold, informational, offenders:[str], why}


def row(rid, ok, title, detail, current, threshold, why, offenders, informational=False):
    status = "PASS" if ok or informational else "FAIL"
    if informational:
        title = "WARN " + title
    return {
        "id": rid, "status": status, "title": title, "detail": detail, "current": current,
        "threshold": threshold, "why": why, "offenders": offenders,
        "informational": informational,
    }


def rule_one_attempt_seam(tree, cfg):
    c = cfg["rules"]["one-attempt-seam"]
    allowed = c["allowed_function"]
    sites = tree.grep(c["send_verb"])
    extra, inside = [], 0
    for rel, l in sites:
        f = tree.enclosing_fn(rel, l.no)
        fname = f.name if f else "<no enclosing fn>"
        if fname == allowed:
            inside += 1
        else:
            extra.append(f"{fname} at {rel}:{l.no}")
    offenders = list(extra)
    if inside == 0:
        offenders.append(f"allowed function `{allowed}` performs no attempt at all "
                         f"(the seam moved; update qa/construction.toml or restore it)")
    current = len(offenders)
    detail = (f"{current} attempt site(s) outside `{allowed}` (ceiling {c['max_extra_sites']}): "
              + ("; ".join(offenders) if offenders else "none"))
    return [row("one-attempt-seam", current <= c["max_extra_sites"],
                f"exactly one function sends the upstream attempt (`{allowed}`)",
                detail, current, c["max_extra_sites"], c["why"], offenders)]


def _is_glob(pattern):
    return any(ch in pattern for ch in "*?[")


def expand_files(tree, patterns):
    """Resolve a `files` list that may mix exact paths and globs (`crates/x/src/unit/*.rs`).
    Returns (matched rel paths in list order, exact paths not found, globs that matched nothing).
    A glob matching nothing is a NOTE, not a finding: it names files a later step adds."""
    matched, missing, empty_globs = [], [], []
    for pat in patterns:
        if _is_glob(pat):
            hits = sorted(fnmatch.filter(tree.fns.keys(), pat))
            if hits:
                matched.extend(h for h in hits if h not in matched)
            else:
                empty_globs.append(pat)
        elif pat in tree.fns:
            if pat not in matched:
                matched.append(pat)
        else:
            missing.append(pat)
    return matched, missing, empty_globs


def rule_request_path_fn_size(tree, cfg):
    c = cfg["rules"]["request-path-fn-size"]
    sized = []
    files, missing, empty_globs = expand_files(tree, c["files"])
    for rel in files:
        for f in tree.fns[rel]:
            if not f.intest:
                sized.append(f)
    sized.sort(key=lambda f: -f.lines)
    over = [f for f in sized if f.lines > c["max_lines"]]
    worst = sized[0].lines if sized else 0
    def code_lines(f):
        return sum(1 for l in tree.files[f.path][f.start - 1:f.end] if l.code.strip())

    offenders = [f"{f.name} {f.lines} lines, {code_lines(f)} of them code ({f.path}:{f.start})"
                 for f in sized[:c["top"]]]
    if missing:
        offenders.append("listed file(s) not found: " + ", ".join(missing))
    if empty_globs:
        offenders.append("glob(s) matching no file yet (not a finding): " + ", ".join(empty_globs))
    detail = (f"{len(over)} function(s) over {c['max_lines']} lines; worst {worst}: "
              + ("; ".join(offenders[:3]) if offenders else "none"))
    return [row("request-path-fn-size", not over and not missing,
                f"request-path functions stay under {c['max_lines']} lines",
                detail, worst, c["max_lines"], c["why"], offenders)]


def rule_ports_only(tree, cfg):
    prod = cfg["rules"]["ports-only"]
    test = cfg["rules"]["ports-only-tests"]
    needle = re.escape(prod["needle"])
    rows = []
    for crate in cfg["gate"]["plane_crates"]:
        files = [rel for rel in tree.files if rel.startswith(os.path.join("crates", crate) + os.sep)]
        per_file_prod, per_file_test = {}, {}
        for rel in files:
            for l in tree.files[rel]:
                if re.search(needle, l.code):
                    bucket = per_file_test if l.intest else per_file_prod
                    bucket[rel] = bucket.get(rel, 0) + 1
        for rid, spec, per_file in (("ports-only", prod, per_file_prod),
                                    ("ports-only-tests", test, per_file_test)):
            ceiling = spec["max_per_crate"].get(crate, 0)
            current = sum(per_file.values())
            top = sorted(per_file.items(), key=lambda kv: -kv[1])[:5]
            offenders = [f"{n} in {rel}" for rel, n in top]
            kind = "production" if rid == "ports-only" else "test"
            detail = (f"{crate}: {current} `{prod['needle']}` line(s) in {kind} code "
                      f"(ceiling {ceiling})" + (": " + "; ".join(offenders) if offenders else ""))
            rows.append(row(f"{rid}:{crate}", current <= ceiling,
                            f"{crate} names no `{prod['needle']}` in {kind} code",
                            detail, current, ceiling, spec["why"], offenders))
    return rows


_STATIC_RE = re.compile(r"(?<![A-Za-z0-9_])static\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:")
_USE_RE = re.compile(r"^\s*(pub(\([a-z]+\))?\s+)?use\s")


def rule_no_uninstalled_seam(tree, cfg):
    c = cfg["rules"]["no-uninstalled-seam"]
    name_rx = re.compile(c["seam_name_pattern"])
    seams = []
    # A seam DEFINED in the substrate's own test kit is a fixture's install hook, not a production
    # promise: it is never counted (a test-kit path fragment names it).
    exempt = c.get("exempt_seam_path_fragments", [])
    for rel, fns in tree.fns.items():
        if not rel.startswith(c["seam_root"].rstrip("/") + os.sep):
            continue
        if any(frag in rel for frag in exempt):
            continue
        lines = tree.files[rel]
        statics = set()
        for l in lines:
            for m in _STATIC_RE.finditer(l.blank):
                statics.add(m.group(1))
        if not statics:
            continue
        for f in fns:
            if f.intest or not name_rx.match(f.name):
                continue
            body = " ".join(l.code for l in lines[f.body_start - 1:f.end])
            if any(re.search(r"(?<![A-Za-z0-9_])" + re.escape(s) + r"(?![A-Za-z0-9_])", body)
                   for s in statics):
                seams.append(f)
    offenders, installed = [], []
    for f in seams:
        callers = []
        call_rx = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(f.name) + r"\s*\(")
        defn_rx = re.compile(r"fn\s+" + re.escape(f.name) + r"(?![A-Za-z0-9_])")
        for rel, l in tree.grep(call_rx.pattern):
            if any(frag in rel for frag in c["non_production_path_fragments"]):
                continue
            if defn_rx.search(l.code) or _USE_RE.match(l.code):
                continue
            callers.append(f"{rel}:{l.no}")
        if callers:
            installed.append(f"{f.name} <- {callers[0]}" + (f" (+{len(callers)-1})" if len(callers) > 1 else ""))
        else:
            offenders.append(f"{f.name} ({f.path}:{f.start}) has NO production installer")
    current = len(offenders)
    detail = (f"{len(seams)} installable seam(s) found, {current} without a production installer "
              f"(ceiling {c['max_uninstalled']}): " + ("; ".join(offenders) if offenders else "none"))
    r = row("no-uninstalled-seam", current <= c["max_uninstalled"] and seams,
            "every installable substrate seam has a production installer",
            detail, current, c["max_uninstalled"], c["why"], offenders)
    r["installed"] = installed
    if not seams:
        r["status"] = "FAIL"
        r["detail"] = "no installable seam matched the pattern at all; the scanner found nothing to check"
    return [r]


def rule_neutral_no_dialect(tree, cfg, hits_path):
    c = cfg["rules"]["neutral-no-dialect"]
    cats = set(c["categories"])
    if not hits_path or not os.path.exists(hits_path):
        return [row("neutral-no-dialect", False,
                    "neutral crates name no dialect or plane (delegated to plane-purity-lint.sh)",
                    "plane-purity-lint.sh produced no hits file; the delegated scan did not run",
                    -1, c["max_hits"], c["why"], [])]
    per_file = {}
    samples = []
    with open(hits_path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            parts = ln.rstrip("\n").split("\t")
            if len(parts) < 3 or parts[0] not in cats:
                continue
            f = parts[1].split(":")[0]
            per_file[f] = per_file.get(f, 0) + 1
            if len(samples) < 5:
                samples.append(f"{parts[0]} {parts[1]}: {parts[2][:80]}")
    current = sum(per_file.values())
    top = sorted(per_file.items(), key=lambda kv: -kv[1])[:5]
    offenders = [f"{n} in {f}" for f, n in top] + samples
    detail = (f"{current} {'/'.join(sorted(cats))} hit(s) in the neutral crates per plane-purity-lint.sh "
              f"(ceiling {c['max_hits']})" + (": " + "; ".join(offenders[:3]) if offenders else ""))
    return [row("neutral-no-dialect", current <= c["max_hits"],
                "neutral crates name no dialect or plane (delegated to plane-purity-lint.sh)",
                detail, current, c["max_hits"], c["why"], offenders)]


def rule_single_terminal(tree, cfg):
    c = cfg["rules"]["single-terminal"]
    term = c["terminal"]
    allowed = set(c["allowed_callers"])
    call_rx = r"(?<![A-Za-z0-9_])" + re.escape(term) + r"\s*\("
    defn_rx = re.compile(r"fn\s+" + re.escape(term) + r"(?![A-Za-z0-9_])")
    extra, seen_allowed = [], []
    for rel, l in tree.grep(call_rx):
        if defn_rx.search(l.code):
            continue
        f = tree.enclosing_fn(rel, l.no)
        fname = f.name if f else "<no enclosing fn>"
        if fname in allowed:
            seen_allowed.append(fname)
        else:
            extra.append(f"{fname} at {rel}:{l.no}")
    current = len(extra)
    detail = (f"{current} call(s) of `{term}` outside the allowed callers "
              f"{sorted(allowed)} (ceiling {c['max_extra_sites']}): "
              + ("; ".join(extra) if extra else "none")
              + f"; allowed callers seen: {sorted(set(seen_allowed))}")
    return [row("single-terminal", current <= c["max_extra_sites"],
                f"`{term}` is called only from its allowed doors",
                detail, current, c["max_extra_sites"], c["why"], extra)]


_TOK_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]")


def _tokens(tree, f):
    toks = []
    for l in tree.files[f.path][f.start - 1:f.end]:
        for t in _TOK_RE.findall(l.code):
            toks.append((t, l.no))
    return toks


def rule_duplicate_dispatch(tree, cfg):
    c = cfg["rules"]["duplicate-dispatch"]
    k = c["shingle_tokens"]
    names = c["twins"]
    fns = []
    missing = []
    for nm in names:
        hits = tree.find_fn_by_name(nm)
        if hits:
            fns.append(hits[0])
        else:
            missing.append(nm)
    blocks = []
    total = 0
    if len(fns) >= 2:
        for ai in range(len(fns)):
            for bi in range(ai + 1, len(fns)):
                a, b = fns[ai], fns[bi]
                ta, tb = _tokens(tree, a), _tokens(tree, b)
                index = {}
                for i in range(len(ta) - k + 1):
                    index.setdefault(tuple(t for t, _ in ta[i:i + k]), []).append(i)
                matches = []
                for j in range(len(tb) - k + 1):
                    for i in index.get(tuple(t for t, _ in tb[j:j + k]), ()):
                        matches.append((i, j))
                matches.sort()
                # Chain matches on a nearly constant diagonal into blocks; small gaps and small
                # diagonal drift are what a renamed variable or an extra argument produce.
                chains = []
                for i, j in matches:
                    d = j - i
                    placed = False
                    for ch in chains:
                        if abs(ch["d"] - d) <= 6 and 0 <= i - ch["ia1"] <= 60:
                            ch["ia1"], ch["ib1"], ch["d"] = i, j, d
                            placed = True
                            break
                    if not placed:
                        chains.append({"ia0": i, "ib0": j, "ia1": i, "ib1": j, "d": d})
                for ch in chains:
                    la0, la1 = ta[ch["ia0"]][1], ta[min(ch["ia1"] + k - 1, len(ta) - 1)][1]
                    lb0, lb1 = tb[ch["ib0"]][1], tb[min(ch["ib1"] + k - 1, len(tb) - 1)][1]
                    span = la1 - la0 + 1
                    if span >= c["min_block_lines"]:
                        blocks.append((span, a, la0, la1, b, lb0, lb1))
        blocks.sort(key=lambda x: -x[0])
        # Total duplicated lines: union of the first twin's spans.
        ivs = sorted((x[2], x[3]) for x in blocks)
        cur = None
        for s, e in ivs:
            if cur and s <= cur[1] + 1:
                cur[1] = max(cur[1], e)
            else:
                if cur:
                    total += cur[1] - cur[0] + 1
                cur = [s, e]
        if cur:
            total += cur[1] - cur[0] + 1
    offenders = [f"{span} lines: {a.name} {a.path}:{la0}-{la1} ~ {b.name} {b.path}:{lb0}-{lb1}"
                 for span, a, la0, la1, b, lb0, lb1 in blocks[:c["top_pairs"]]]
    if missing:
        offenders.append("twin(s) not found: " + ", ".join(missing))
    detail = (f"informational: {total} duplicated line(s) across {len(blocks)} shared block(s) "
              f">= {c['min_block_lines']} lines between {names}"
              + (": " + offenders[0] if offenders else ""))
    r = row("duplicate-dispatch", True,
            "near-duplicate blocks between the attempt twins",
            detail, total, c["max_duplicated_lines"], c["why"], offenders,
            informational=bool(c.get("informational", True)))
    r["blocks"] = [[x[2], x[3]] for x in blocks]  # first-twin spans, for the self-test planter
    return [r]


# ── The Teller-loop rules ─────────────────────────────────────────────────────────────────────────
# Each measures one construction promise of the rebuilt request loop. A rule whose subject does not
# exist yet (a directory or file a later step adds) reports PASS with a "vacuous" note rather than
# failing or crashing: the promise is trivially kept until there is something to keep it against.

VACUOUS = "vacuous: "


def _word(rx_literal):
    """A regex for `rx_literal` as a whole token (no identifier char immediately before it)."""
    return r"(?<![A-Za-z0-9_])" + re.escape(rx_literal)


def _call_sites(tree, verb, files=None):
    """Production lines calling `verb(`, excluding its own definition and `use` lines."""
    call_rx = _word(verb) + r"\s*\("
    defn_rx = re.compile(r"fn\s+" + re.escape(verb) + r"(?![A-Za-z0-9_])")
    out = []
    for rel, l in tree.grep(call_rx, files=files):
        if defn_rx.search(l.code) or _USE_RE.match(l.code):
            continue
        out.append((rel, l))
    return out


def rule_token_sealed(tree, cfg):
    """The Teller's tokens are built only inside the Teller: outside `allowed_root`, no production
    line spells one of the constructor patterns (`Decision::proceed(`, `Hold::`, …)."""
    c = cfg["rules"]["token-sealed"]
    root = c["allowed_root"].rstrip("/") + os.sep
    offenders = []
    for pat in c["patterns"]:
        for rel, l in tree.grep(_word(pat)):
            if rel.startswith(root):
                continue
            offenders.append(f"`{pat}` at {rel}:{l.no}")
    current = len(offenders)
    detail = (f"{current} token constructor(s) spelled outside {c['allowed_root']} "
              f"(ceiling {c['max_sites']}): " + ("; ".join(offenders) if offenders else "none"))
    if not any(rel.startswith(root) for rel in tree.files):
        detail = VACUOUS + f"{c['allowed_root']} does not exist yet; nothing to seal"
    return [row("token-sealed", current <= c["max_sites"],
                "the Teller's tokens are minted only inside the Teller",
                detail, current, c["max_sites"], c["why"], offenders)]


def _expanded_calls(tree, rel, entry, steps, depth=4):
    """Walk `entry`'s body in source order, splicing in the bodies of the file's own helper
    functions where they are called, and return the ordered list of step names met as
    `.step(` calls. The loop is split across helpers (a sync opener, an async runner), so the
    order is a property of the expansion, not of any one function."""
    local = {f.name: f for f in tree.fns.get(rel, []) if not f.intest}
    step_rx = re.compile(r"\.(" + "|".join(re.escape(s) for s in steps) + r")\s*\(")
    call_rx = re.compile(r"(?<![A-Za-z0-9_.:])([a-z_][a-z0-9_]*)\s*\(")
    seen = []

    def walk(name, d, stack):
        f = local.get(name)
        if f is None or d > depth or name in stack:
            return
        body = tree.files[rel][f.body_start - 1:f.end]
        for l in body:
            events = [(m.start(), "step", m.group(1)) for m in step_rx.finditer(l.code)]
            events += [(m.start(), "call", m.group(1)) for m in call_rx.finditer(l.code)
                       if m.group(1) in local and m.group(1) != name]
            for _pos, kind, nm in sorted(events):
                if kind == "step":
                    seen.append(nm)
                else:
                    walk(nm, d + 1, stack + [name])

    walk(entry, 0, [])
    return seen


def _in_order(seen, steps):
    """True when every step in `steps` occurs in `seen` and their FIRST occurrences are in order."""
    firsts = []
    for s in steps:
        if s not in seen:
            return False
        firsts.append(seen.index(s))
    return firsts == sorted(firsts)


def rule_teller_step_order(tree, cfg):
    c = cfg["rules"]["teller-step-order"]
    rel = c["file"]
    steps = c["steps"]
    findings = []
    if rel not in tree.fns:
        detail = VACUOUS + f"{rel} does not exist yet; no loop to order"
        return [row("teller-step-order", True,
                    "the Teller loop calls the nine steps once each, in the canonical order",
                    detail, 0, c["max_findings"], c["why"], [])]
    loops = [f for f in tree.fns[rel] if f.name == c["loop_function"] and not f.intest]
    if len(loops) != 1:
        findings.append(f"expected exactly one `fn {c['loop_function']}` in {rel}, found {len(loops)}")
    run_seen = _expanded_calls(tree, rel, c["loop_function"], steps)
    if not _in_order(run_seen, steps):
        findings.append(f"`{c['loop_function']}` (expanded through its helpers) calls the steps as "
                        f"{run_seen}; the canonical order is {steps}")
    door = steps[:steps.index(c["door_step"]) + 1]
    open_seen = _expanded_calls(tree, rel, c["opener_function"], steps)
    if not open_seen:
        findings.append(f"`{c['opener_function']}` calls no step at all in {rel}")
    elif not _in_order(open_seen, door) or any(s not in door for s in open_seen):
        findings.append(f"`{c['opener_function']}` (expanded) calls {open_seen}; a session opener "
                        f"runs exactly the steps up to the door, in order: {door}")
    current = len(findings)
    detail = (f"{current} order finding(s) in {rel} (ceiling {c['max_findings']}): "
              + ("; ".join(findings) if findings else
                 f"`{c['loop_function']}` runs {' → '.join(run_seen)}"))
    return [row("teller-step-order", current <= c["max_findings"],
                "the Teller loop calls the nine steps once each, in the canonical order",
                detail, current, c["max_findings"], c["why"], findings)]


def rule_one_teller_loop(tree, cfg):
    """Two rows: at most one production caller of the loop per plane crate (outside the Teller
    itself), and the count of legacy adapter call sites, a ratchet the planes drive to zero."""
    c = cfg["rules"]["one-teller-loop"]
    root = c["loop_root"].rstrip("/") + os.sep
    per_crate = {}
    for rel, l in _call_sites(tree, c["loop_verb"]):
        if rel.startswith(root):
            continue
        crate = tree.crate_of(rel)
        per_crate.setdefault(crate, []).append(f"{rel}:{l.no}")
    planes = cfg["gate"]["plane_crates"]
    worst = max((len(per_crate.get(p, [])) for p in planes), default=0)
    offenders = [f"{p}: {len(per_crate[p])} caller(s) of `{c['loop_verb']}(`: " + ", ".join(per_crate[p])
                 for p in planes if len(per_crate.get(p, [])) > c["max_callers_per_plane_crate"]]
    seen = {p: len(per_crate.get(p, [])) for p in planes}
    detail = (f"callers of `{c['loop_verb']}(` per plane crate {seen} "
              f"(ceiling {c['max_callers_per_plane_crate']} each): "
              + ("; ".join(offenders) if offenders else "none over"))
    if not any(rel.startswith(root) for rel in tree.files):
        detail = VACUOUS + f"{c['loop_root']} does not exist yet; no loop to call"
    rows = [row("one-teller-loop", worst <= c["max_callers_per_plane_crate"],
                "each plane runs its units through the one Teller loop, from one place",
                detail, worst, c["max_callers_per_plane_crate"], c["why"], offenders)]
    legacy = [f"{rel}:{l.no}" for rel, l in _call_sites(tree, c["legacy_verb"])]
    detail = (f"{len(legacy)} production call site(s) of the legacy `{c['legacy_verb']}(` adapter "
              f"(ceiling {c['max_legacy_sites']}): " + ("; ".join(legacy) if legacy else "none"))
    rows.append(row("one-teller-loop:run_gauntlet", len(legacy) <= c["max_legacy_sites"],
                    "the legacy adapter's call sites only ever shrink",
                    detail, len(legacy), c["max_legacy_sites"], c["why"], legacy))
    return rows


_RETURNS_RESPONSE = re.compile(r"->[^{;]*(?<![A-Za-z0-9_])Response(?![A-Za-z0-9_])")


def rule_no_response_escapes_audit(tree, cfg):
    c = cfg["rules"]["no-response-escapes-audit"]
    root = c["root"].rstrip("/") + os.sep
    files = [rel for rel in tree.fns if rel.startswith(root)]
    allowed = set(c["allowed_files"])
    offenders = []
    for rel in files:
        if os.path.basename(rel) in allowed:
            continue
        for f in tree.fns[rel]:
            if f.intest:
                continue
            sig = " ".join(l.code for l in tree.files[rel][f.start - 1:f.body_start])
            if _RETURNS_RESPONSE.search(sig):
                offenders.append(f"{f.name} returns a Response at {rel}:{f.start}")
    current = len(offenders)
    if not files:
        detail = VACUOUS + f"{c['root']} does not exist yet; no step file to check"
    else:
        detail = (f"{current} function(s) under {c['root']} returning a Response outside "
                  f"{sorted(allowed)} (ceiling {c['max_escapes']}): "
                  + ("; ".join(offenders) if offenders else "none"))
    return [row("no-response-escapes-audit", current <= c["max_escapes"],
                "only the Audit step hands a Response back to the loop",
                detail, current, c["max_escapes"], c["why"], offenders)]


def rule_terminal_doors_in_audit_step(tree, cfg):
    c = cfg["rules"]["terminal-doors-in-audit-step"]
    prefix = os.path.join("crates", c["crate"]) + os.sep
    files = [rel for rel in tree.files if rel.startswith(prefix)]
    offenders = []
    for door in c["doors"]:
        for rel, l in _call_sites(tree, door, files=files):
            if rel == c["allowed_file"]:
                continue
            offenders.append(f"`{door}(` at {rel}:{l.no}")
    current = len(offenders)
    if current == 0 and c["allowed_file"] not in tree.files:
        detail = VACUOUS + f"no door is called in {c['crate']} and {c['allowed_file']} does not exist yet"
    else:
        detail = (f"{current} terminal-door call(s) in {c['crate']} outside {c['allowed_file']} "
                  f"(ceiling {c['max_extra_sites']}): " + ("; ".join(offenders) if offenders else "none"))
    return [row("terminal-doors-in-audit-step", current <= c["max_extra_sites"],
                "the plane's terminal doors are called only from its Audit step",
                detail, current, c["max_extra_sites"], c["why"], offenders)]


def rule_one_pick_site(tree, cfg):
    c = cfg["rules"]["one-pick-site"]
    sites = [f"{rel}:{l.no}" for rel, l in _call_sites(tree, c["verb"])]
    current = len(sites)
    detail = (f"{current} production call site(s) of `{c['verb']}(` (ceiling {c['max_sites']}): "
              + ("; ".join(sites) if sites else "none"))
    return [row("one-pick-site", current <= c["max_sites"],
                "the lane pick is called from at most the loop and the fallback re-entry",
                detail, current, c["max_sites"], c["why"], sites)]


def evaluate(tree, cfg, hits_path):
    rows = []
    rows += rule_one_attempt_seam(tree, cfg)
    rows += rule_request_path_fn_size(tree, cfg)
    rows += rule_ports_only(tree, cfg)
    rows += rule_no_uninstalled_seam(tree, cfg)
    rows += rule_neutral_no_dialect(tree, cfg, hits_path)
    rows += rule_single_terminal(tree, cfg)
    rows += rule_duplicate_dispatch(tree, cfg)
    rows += rule_token_sealed(tree, cfg)
    rows += rule_teller_step_order(tree, cfg)
    rows += rule_one_teller_loop(tree, cfg)
    rows += rule_no_response_escapes_audit(tree, cfg)
    rows += rule_terminal_doors_in_audit_step(tree, cfg)
    rows += rule_one_pick_site(tree, cfg)
    return rows


# ── Output ────────────────────────────────────────────────────────────────────────────────────────


def write_rows(rows, path):
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write("\t".join(x.replace("\t", " ").replace("\n", " ")
                               for x in (r["id"], r["status"], r["title"], r["detail"])) + "\n")


def write_summary(rows, path):
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            mark = "WARN" if r["informational"] else r["status"]
            title = r["title"].removeprefix("WARN ")
            fh.write(f"{mark:4}  {r['id']:32} {r['current']:>6} / {r['threshold']:<6}  {title}\n")


def write_report(rows, cfg, path, root):
    out = ["# Construction gate report", "",
           f"Tree: `{root}`  ", "Ceilings: `qa/construction.toml`. Every value is current / ceiling; "
           "a rule fails when current is above its ceiling.", "", "| rule | status | current | ceiling |",
           "|---|---|---:|---:|"]
    for r in rows:
        mark = "WARN" if r["informational"] else r["status"]
        out.append(f"| {r['id']} | {mark} | {r['current']} | {r['threshold']} |")
    out.append("")
    for r in rows:
        mark = "WARN" if r["informational"] else r["status"]
        out += [f"## {r['id']} — {mark}", "", r["why"].strip(), "", f"**Finding:** {r['detail']}", ""]
        if r["offenders"]:
            out.append("Worst offenders:")
            out += [f"- {o}" for o in r["offenders"]]
            out.append("")
        if r.get("installed"):
            out.append("Seams with a production installer:")
            out += [f"- {o}" for o in r["installed"]]
            out.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))


def _toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    raise TypeError(type(v))


def _emit_table(name, tbl, out):
    scalars = {k: v for k, v in tbl.items() if not isinstance(v, dict)}
    subs = {k: v for k, v in tbl.items() if isinstance(v, dict)}
    if name:
        out.append(f"[{name}]")
    for k, v in scalars.items():
        key = k if re.match(r"^[A-Za-z0-9_-]+$", k) else json.dumps(k)
        out.append(f"{key} = {_toml_value(v)}")
    out.append("")
    for k, v in subs.items():
        _emit_table(f"{name}.{k}" if name else k, v, out)


def calibrate(rows, cfg, path):
    """Write a toml whose ceilings equal today's measured values (a green baseline)."""
    rules = cfg["rules"]
    by_id = {r["id"]: r for r in rows}
    rules["one-attempt-seam"]["max_extra_sites"] = by_id["one-attempt-seam"]["current"]
    rules["request-path-fn-size"]["max_lines"] = by_id["request-path-fn-size"]["current"]
    for crate in cfg["gate"]["plane_crates"]:
        rules["ports-only"]["max_per_crate"][crate] = by_id[f"ports-only:{crate}"]["current"]
        rules["ports-only-tests"]["max_per_crate"][crate] = by_id[f"ports-only-tests:{crate}"]["current"]
    rules["no-uninstalled-seam"]["max_uninstalled"] = by_id["no-uninstalled-seam"]["current"]
    rules["neutral-no-dialect"]["max_hits"] = max(by_id["neutral-no-dialect"]["current"], 0)
    rules["single-terminal"]["max_extra_sites"] = by_id["single-terminal"]["current"]
    rules["duplicate-dispatch"]["max_duplicated_lines"] = by_id["duplicate-dispatch"]["current"]
    rules["token-sealed"]["max_sites"] = by_id["token-sealed"]["current"]
    rules["teller-step-order"]["max_findings"] = by_id["teller-step-order"]["current"]
    rules["one-teller-loop"]["max_callers_per_plane_crate"] = by_id["one-teller-loop"]["current"]
    rules["one-teller-loop"]["max_legacy_sites"] = by_id["one-teller-loop:run_gauntlet"]["current"]
    rules["no-response-escapes-audit"]["max_escapes"] = by_id["no-response-escapes-audit"]["current"]
    rules["terminal-doors-in-audit-step"]["max_extra_sites"] = by_id["terminal-doors-in-audit-step"]["current"]
    rules["one-pick-site"]["max_sites"] = by_id["one-pick-site"]["current"]
    out = ["# calibrated copy of qa/construction.toml: every ceiling equals the measured value", ""]
    _emit_table("", cfg, out)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--toml", required=True)
    ap.add_argument("--purity-hits")
    ap.add_argument("--rows")
    ap.add_argument("--expected")
    ap.add_argument("--report")
    ap.add_argument("--summary")
    ap.add_argument("--calibrate")
    ap.add_argument("--json")
    a = ap.parse_args()
    with open(a.toml, "rb") as fh:
        cfg = tomllib.load(fh)
    tree = Tree(a.root, cfg)
    rows = evaluate(tree, cfg, a.purity_hits)
    if a.rows:
        write_rows(rows, a.rows)
    if a.expected:
        with open(a.expected, "w", encoding="utf-8") as fh:
            fh.write(" ".join(r["id"] for r in rows) + "\n")
    if a.report:
        write_report(rows, cfg, a.report, a.root)
    if a.summary:
        write_summary(rows, a.summary)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=1)
    if a.calibrate:
        calibrate(rows, cfg, a.calibrate)
    return 0


if __name__ == "__main__":
    sys.exit(main())
