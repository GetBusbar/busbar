#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""WORKFLOW INVARIANTS -- one named, falsifiable check per defect the 1.6.0 audit filed against
.github/workflows/ (items 332-361, the W0.12 slot) plus the CI wiring this directory owes.

Why a script and not prose: every one of these defects was a sentence in a workflow that stopped
being true, or a shell shape that quietly turned a red into a green, and nothing compared the two.
A check here states the invariant in code, reads the workflow TEXT (stdlib only: no YAML library,
for the same reason the release-order lint parses by hand -- a gate that silently stops running when
a runner image drops a package is worse than no gate), and names the file and line it refuses.

  python3 .github/workflows/lint/workflow-invariants.py              # judge the tree, exit 1 on a FAIL
  python3 .github/workflows/lint/workflow-invariants.py --only 333    # one check (RED proofs use this)
  python3 .github/workflows/lint/workflow-invariants.py --selftest   # every check fires on its defect
  python3 .github/workflows/lint/workflow-invariants.py --root DIR   # judge another checkout

--selftest plants each check's defect back into an in-memory copy of THIS tree and requires the
check to fire -- a check that cannot go red is not a check. A plant whose needle is no longer in
the tree is itself a failure (UNPLANTABLE): the check and its proof drifted apart.

Exit codes: 0 all hold / 1 a check failed / 2 usage or an unreadable input.
"""
import json
import os
import re
import sys

WF = ".github/workflows"
CI = WF + "/ci.yml"
VD = WF + "/verify-deploy.yml"
RS = WF + "/release-stage.yml"
KP = WF + "/manual-keep-proof.yml"
DRIFT = WF + "/sched-llm-spec-drift.yml"
MIRROR = WF + "/sched-ci-images-mirror.yml"
TARGETS = ".github/release-targets.json"
REQUIRED_DOC = ".github/required-status-checks.md"
# OWNER RULING Q39: the one site_curl definition, and the release-gate scripts that read the site.
RG = "scripts/release-gate"
SITE_CURL = RG + "/site-curl.sh"
LIB = RG + "/lib.sh"
CHANNELS = RG + "/channel-checks.sh"
FLEET = WF + "/fleet-autoscaler.yml"
# The workflow files this slot owns and holds to the shell-shape invariants (352, 343, 356, 358).
OWNED = [CI, VD, RS, KP, DRIFT]

FULL_TIER_GUARD = ("github.event_name != 'push' || contains(fromJSON('[\"refs/heads/main\", "
                   "\"refs/heads/dev\", \"refs/heads/qa\"]'), github.ref)")

# The bare-script selftests ci.yml owes (KICKOFF 15.5: "wire the script's own --selftest and make CI
# call it"), each named by the slot or stream that is owed it.
OWED_CI_CALLS = [
    "scripts/prove-remote.sh --selftest",
    "scripts/release-gate/gate.sh --selftest",
    ".github/scripts/required-status-checks-selftest.sh",
    ".github/scripts/actionlint-claim-selftest.sh",
    "actionlint -color .github/workflows/*.yml",
    "scripts/mcp-subject/h2-lib.sh --selftest",
    "scripts/mcp-subject/boot.sh --selftest",
    "scripts/a2a-subject/h2-lib.sh --selftest",
    "scripts/a2a-subject/h2-route-failover.sh --selftest",
    "scripts/rooms.sh --selftest",
    "scripts/proof-manifest.py --selftest",
    "scripts/verify-1.6.0-done.sh --selftest",
    "scripts/plane-noun-gate.sh --selftest",
    "scripts/pr-land.sh --selftest",
    "scripts/pr-queue.sh --selftest",
    "scripts/preflight.sh --selftest",
    "scripts/ci-runners-down.sh --selftest",
    "scripts/ci-service-endpoints.sh --selftest",
    "scripts/land-remote.sh --selftest",
    "scripts/snapshot-refs.sh --selftest",
    "scripts/documented-claims-check.py --selftest",
    "scripts/extract-inline-tests.py --selftest",
    "scripts/secret-accessor-seal-witness.sh --selftest",
    "scripts/secret-accessor-seal-witness.sh --check",
    "scripts/qa-gate-run.sh selftest",
    "scripts/release-check-1.5.2.sh --selftest",
    "scripts/ci-runners-selftest.sh",
    "scripts/plane-delete-test.sh --selftest",
    "scripts/proto-deletion-gate.sh --selftest",
    "scripts/branch-symbol-sweep.py --repo \"$GITHUB_WORKSPACE\" selftest --trunk HEAD",
    ".github/workflows/lint/workflow-invariants.py --selftest",
]


# ------------------------------------------------------------------------------------------------
# reading
# ------------------------------------------------------------------------------------------------

def load_tree(root):
    tree = {}
    for rel in sorted(os.listdir(os.path.join(root, WF))):
        if rel.endswith((".yml", ".yaml")):
            with open(os.path.join(root, WF, rel), encoding="utf-8") as f:
                tree[WF + "/" + rel] = f.read()
    for rel in (TARGETS, REQUIRED_DOC):
        p = os.path.join(root, rel)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                tree[rel] = f.read()
    rg = os.path.join(root, RG)
    if os.path.isdir(rg):
        for rel in sorted(os.listdir(rg)):
            if rel.endswith(".sh"):
                with open(os.path.join(rg, rel), encoding="utf-8") as f:
                    tree[RG + "/" + rel] = f.read()
    tree["@audit-ledger-exists"] = os.path.exists(os.path.join(root, "qa/audit-ledger.json"))
    return tree


def lines(tree, rel):
    return tree.get(rel, "").split("\n")


def indent(s):
    return len(s) - len(s.lstrip(" "))


def job_spans(ls):
    """[(key, start, end)] for every job under the top-level `jobs:` key (end exclusive)."""
    try:
        j0 = ls.index("jobs:")
    except ValueError:
        return []
    heads = [i for i in range(j0 + 1, len(ls)) if re.match(r"^  [A-Za-z0-9_-]+:\s*(#.*)?$", ls[i])]
    out = []
    for n, i in enumerate(heads):
        end = heads[n + 1] if n + 1 < len(heads) else len(ls)
        out.append((re.match(r"^  ([A-Za-z0-9_-]+):", ls[i]).group(1), i, end))
    return out


def job_span(ls, key):
    for k, s, e in job_spans(ls):
        if k == key:
            return s, e
    return None


def steps_in(ls, s, e):
    """[(start, end)] of each `- ` step item under `steps:` within [s, e)."""
    out = []
    for i in range(s, e):
        if re.match(r"^    steps:\s*$", ls[i]):
            items = [k for k in range(i + 1, e) if re.match(r"^      - ", ls[k])]
            for n, k in enumerate(items):
                end = items[n + 1] if n + 1 < len(items) else e
                out.append((k, end))
    return out


def run_blocks(ls):
    """[(first_body_line_index, [body lines], shell)] for every `run:` in the file."""
    out = []
    for i, l in enumerate(ls):
        m = re.match(r"^(\s*)(- )?run:\s*(.*)$", l)
        if not m:
            continue
        key_ind = len(m.group(1)) + (2 if m.group(2) else 0)
        rest = m.group(3)
        # the step's `shell:` key, if any, at the same indentation as `run:`
        shell = ""
        k = i
        while k > 0 and not re.match(r"^\s*- ", ls[k]):
            k -= 1
        for q in range(k, min(len(ls), i + 400)):
            if q > k and (re.match(r"^\s*- ", ls[q]) and indent(ls[q]) <= key_ind - 2):
                break
            mm = re.match(r"^\s*(- )?shell:\s*(.*)$", ls[q])
            if mm and (indent(ls[q]) + (2 if mm.group(1) else 0)) == key_ind:
                shell = mm.group(2).strip()
        if rest.startswith("|") or rest.startswith(">"):
            body, start = [], i + 1
            for q in range(i + 1, len(ls)):
                if ls[q].strip() == "" or indent(ls[q]) > key_ind:
                    body.append(ls[q])
                else:
                    break
            out.append((start, body, shell))
        elif rest:
            out.append((i, [rest], shell))
    return out


def executed_lines(tree, rel):
    """(line_no, text) for every non-comment line inside a run body."""
    out = []
    for start, body, _ in run_blocks(lines(tree, rel)):
        for n, b in enumerate(body):
            t = b.strip()
            if t and not t.startswith("#"):
                out.append((start + n + 1, t))
    return out


# ------------------------------------------------------------------------------------------------
# the checks: each returns a list of findings (empty = holds)
# ------------------------------------------------------------------------------------------------

def c_dupkeys(tree):
    """GitHub rejects a workflow whose `jobs:` map repeats a key; the whole file stops running."""
    bad = []
    for rel in sorted(k for k in tree if k.startswith(WF + "/") and k.endswith((".yml", ".yaml"))):
        seen = {}
        for key, s, _ in job_spans(lines(tree, rel)):
            if key.lower() in seen:
                bad.append("%s:%d job key '%s' is declared twice (first at line %d) -- GitHub refuses "
                           "the whole workflow" % (rel, s + 1, key, seen[key.lower()] + 1))
            seen.setdefault(key.lower(), s)
    return bad


def c332(tree):
    """Each verify-deploy check (a)-(n) runs independently: `!cancelled()` on every check step."""
    ls = lines(tree, VD)
    # `verify-site` (OWNER RULING Q5 / item 333: getbusbar.com checks moved to the self-hosted
    # runner Cloudflare trusts) carries checks (g)(h)(i)(k)(l.1)(n) under `needs.verify.outputs.*`
    # instead of `steps.ver.outputs.*` -- both are a resolved-version guard, just from a different
    # job's outputs, so this reader accepts either spelling and scans both job spans as one pool.
    spans = [sp for sp in (job_span(ls, "verify"), job_span(ls, "verify-site")) if sp]
    if not spans:
        return ["%s: no `verify` job" % VD]
    bad, n = [], 0
    for sp in spans:
        for s, e in steps_in(ls, *sp):
            if not re.match(r'^      - name: "?\(', ls[s]):
                continue
            n += 1
            cond = next((ls[q] for q in range(s, e) if re.match(r"^        if:", ls[q])), "")
            has_version_guard = ("steps.ver.outputs.version" in cond
                                  or "needs.verify.outputs.version" in cond)
            if "!cancelled()" not in cond or not has_version_guard:
                bad.append("%s:%d %s -- no `!cancelled()` + resolved-version guard, so the first failing "
                           "check skips it" % (VD, s + 1, ls[s].strip()))
    if n < 14:
        bad.append("%s: found only %d check steps named '(x) ...' (floor 14) -- the reader is broken"
                   % (VD, n))
    return bad


def _branch_end(ls, i):
    for q in range(i + 1, min(len(ls), i + 40)):
        t = ls[q].strip()
        if t in (";;", "fi", "else", "done") or t.startswith("elif ") or t in ("exit 0", "return 0"):
            return q
    return min(len(ls), i + 40)


def c333(tree):
    """A verify-deploy assertion that could not be evaluated is RED, never a green no-op."""
    ls = lines(tree, VD)
    bad = []
    for i, l in enumerate(ls):
        t = l.strip()
        if t.startswith("#"):
            continue
        if "::warning::" in t:
            bad.append("%s:%d a `::warning::` in the release verifier -- an assertion that did not run "
                       "is an ::error:: and a red, not a warning" % (VD, i + 1))
        if "VISIBLE SKIP" in t or "NOT EXERCISED" in t:
            # the controlling `if`: a skip that is by MODE (staging) is not a non-evaluation
            k = i - 1
            while k > 0 and not re.match(r"^\s*(if|elif) ", ls[k]) and not re.match(r"^\s*\S+\)\s*$", ls[k]):
                k -= 1
            if '"$STAGE" = "staging"' in ls[k]:
                continue
            end = _branch_end(ls, i)
            span = [x.strip() for x in ls[i:end + 1]]
            if not any(x in ("fail=1", "exit 1", "return 1") or x.startswith("exit 1") for x in span):
                bad.append("%s:%d `%s...` is followed by no fail=1/exit 1/return 1 before its branch ends "
                           "-- a non-evaluation that exits green" % (VD, i + 1, t[:60]))
    return bad


def c338(tree):
    """release-stage's tag pre-flight prints "free" only on a 404, and refuses every unknown."""
    ls = lines(tree, RS)
    bad = []
    hits = 0
    for i, l in enumerate(ls):
        if "is free" in l and "echo" in l:
            hits += 1
            k = i - 1
            while k > 0 and not re.match(r"^\s*(\S+\)|if |elif |else)", ls[k]):
                k -= 1
            if not re.match(r"^\s*404\)", ls[k]):
                bad.append("%s:%d prints a tag as free outside a `404)` arm (controlling line %d: %s)"
                           % (RS, i + 1, k + 1, ls[k].strip()[:60]))
        if "::warning::" in l and "tag-immutability" in l:
            bad.append("%s:%d skips the tag-immutability pre-flight with a warning" % (RS, i + 1))
    if hits < 2:
        bad.append("%s: found %d 'is free' lines (the version tag and the rc tag make 2)" % (RS, hits))
    return bad


def c339(tree):
    """Gate 0's red sweep judges every concluded run on the sha, not the waited-on set alone."""
    ls = lines(tree, RS)
    red = [(i, l) for i, l in enumerate(ls) if re.match(r'^\s*red="\$\(jq ', l)]
    if len(red) != 1:
        return ["%s: expected exactly one `red=\"$(jq ...` sweep, found %d" % (RS, len(red))]
    i, l = red[0]
    m = re.search(r"(/tmp/[A-Za-z0-9._-]+\.json)\)\"\s*$", l)
    if not m:
        return ["%s:%d the red sweep's input file cannot be read off the line" % (RS, i + 1)]
    f = m.group(1)
    w = [k for k, x in enumerate(ls) if re.search(r">\s*" + re.escape(f) + r"\s*$", x)]
    if not w:
        return ["%s:%d the red sweep reads %s, which nothing writes" % (RS, i + 1, f)]
    k = w[0]
    q = k
    while q > 0 and "jq -s" not in ls[q]:
        q -= 1
    filt = "\n".join(ls[q:k + 1])
    bad = []
    if "IN($want[])" in filt:
        bad.append("%s:%d the red sweep reads %s, written by the INCLUSION filter (line %d) -- it can "
                   "only ever name the required workflows" % (RS, i + 1, f, k + 1))
    if "IN($not[]) | not" not in filt:
        bad.append("%s:%d the red sweep's input (line %d) is not filtered by exclusion" % (RS, i + 1, k + 1))
    return bad


def c340(tree):
    """verify-deploy (c)'s expected-asset floor covers the platform archives AND the metadata assets."""
    try:
        meta = len(json.loads(tree[TARGETS])["metadata_assets"])
    except (KeyError, ValueError) as e:
        return ["%s unreadable: %s" % (TARGETS, e)]
    need = 5 + meta
    ls = lines(tree, VD)
    fl = [(i, int(m.group(1))) for i, l in enumerate(ls)
          for m in [re.search(r'"\$\{#expected\[@\]\}" -lt ([0-9]+)', l)] if m]
    if not fl:
        return ["%s: no expected-asset floor found" % VD]
    bad = ["%s:%d the expected-asset floor is %d; 5 platform archives + %d metadata assets make %d"
           % (VD, i + 1, n, meta, need) for i, n in fl if n < need]
    for i, l in enumerate(ls):
        if re.search(r"mapfile -t expected < <\(", l):
            bad.append("%s:%d the expected list is read through a process substitution, whose exit "
                       "status is discarded" % (VD, i + 1))
    return bad


def c341(tree):
    """ci.yml's gate-tier summary names every job the fast tier does not run."""
    ls = lines(tree, CI)
    guarded = []
    for key, s, e in job_spans(ls):
        cond = next((ls[q] for q in range(s, e) if re.match(r"^    if:", ls[q])), "")
        if FULL_TIER_GUARD in cond:
            guarded.append(key)
    sp = job_span(ls, "gate-tier")
    if not sp or len(guarded) < 10:
        return ["%s: gate-tier job %s, %d full-tier-guarded jobs found (floor 10)"
                % (CI, "present" if sp else "ABSENT", len(guarded))]
    text = "\n".join(ls[sp[0]:sp[1]])
    i = text.find("It did NOT run:")
    if i < 0:
        return ["%s: gate-tier prints no 'It did NOT run:' list" % CI]
    j = text.find('echo ""', i)
    said = set(re.findall(r"[a-z][a-z0-9-]+", text[i:j if j > 0 else None]))
    return ["%s: gate-tier's 'It did NOT run' list omits full-tier job `%s`" % (CI, g)
            for g in guarded if g not in said]


def c342(tree):
    """No workflow fetches audit pins or cites an audit-ledger gate the tree no longer has."""
    if tree.get("@audit-ledger-exists"):
        return []
    bad = []
    for rel in OWNED:
        for n, t in executed_lines(tree, rel):
            if "audit-pins" in t or "audit-ledger" in t:
                bad.append("%s:%d runs `%s` for an audit ledger deleted in 647f2fae9" % (rel, n, t[:70]))
        for i, l in enumerate(lines(tree, rel)):
            if re.search(r"for the `audit-ledger` step|audit_ledger::tests", l):
                bad.append("%s:%d justifies a checkout by the deleted `audit-ledger` gate" % (rel, i + 1))
    return bad


def _unescaped_backtick_in_dq(t):
    """Index of an unescaped backtick inside a double-quoted string on this shell line, or -1."""
    in_dq = in_sq = esc = False
    for n, ch in enumerate(t):
        if esc:
            esc = False
            continue
        if ch == "\\" and not in_sq:
            esc = True
            continue
        if ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
        elif ch == "`" and in_dq:
            return n
        elif ch == "#" and not in_dq and not in_sq and (n == 0 or t[n - 1] in " \t"):
            return -1
    return -1


def c343(tree):
    """An `echo "..."` diagnostic never EXECUTES the command it quotes (unescaped backticks)."""
    bad = []
    for rel in OWNED:
        for n, t in executed_lines(tree, rel):
            if re.match(r"^(echo|printf)\b", t) and _unescaped_backtick_in_dq(t) >= 0:
                bad.append("%s:%d unescaped backtick inside a double-quoted echo -- command substitution: %s"
                           % (rel, n, t[:80]))
    return bad


def c352(tree):
    """A `rc=${PIPESTATUS[0]}` capture is reachable: errexit cannot kill the step first."""
    bad = []
    for rel in OWNED:
        for start, body, shell in run_blocks(lines(tree, rel)):
            errexit = not ("{0}" in shell and "-e" not in shell)
            for n, b in enumerate(body):
                t = b.strip()
                if t.startswith("#"):
                    continue
                for m in re.finditer(r"\bset ([-+][a-z]+)", t):
                    if "e" in m.group(1):
                        errexit = m.group(1).startswith("-")
                if "PIPESTATUS" in t and re.search(r"rc=\"?\$\{PIPESTATUS", t):
                    guarded = re.search(r"\|\|\s*rc=\"?\$\{PIPESTATUS", t)
                    if errexit and not guarded:
                        bad.append("%s:%d `%s` runs after a pipeline under errexit -- a failing pipeline "
                                   "aborts the step first, so the capture and its diagnostic are dead"
                                   % (rel, start + n + 1, t[:60]))
    return bad


def c353(tree):
    """ci.yml runs `verify-artifact.py --coverage`, the detector release-stage.yml cites."""
    hit = [n for n, t in executed_lines(tree, CI) if re.search(r"verify-artifact\.py\b.*--coverage", t)]
    return [] if hit else ["%s: no step runs `scripts/verify-artifact.py --coverage`" % CI]


def c356(tree):
    """Event data and dispatch inputs reach a script as env, never spliced into the script text."""
    bad = []
    for rel in OWNED:
        for n, t in executed_lines(tree, rel):
            if re.search(r"\$\{\{\s*(inputs\.|github\.event\.|github\.head_ref)", t):
                bad.append("%s:%d `${{ }}` event data spliced into a run body: %s" % (rel, n, t[:80]))
    return bad


FUNCTION_WORDS = {"a", "an", "the", "it", "to", "of", "and", "or", "not", "so", "is", "that",
                  "which", "with", "for", "from", "by", "as", "at", "on", "in", "its", "their"}


def c357(tree):
    """No comment block stops mid-sentence and runs into the next block's heading."""
    bad = []
    for rel in OWNED:
        ls = lines(tree, rel)
        for i in range(len(ls) - 1):
            a, b = ls[i].strip(), ls[i + 1].strip()
            if not (a.startswith("#") and b.startswith("#")):
                continue
            words = a.lstrip("#").strip().split()
            # A lowercase function word cannot end a sentence ("... that is not an"). An UPPERCASE
            # one is emphasis running onto the next line ("it was NOT / BEING CHECKED"), not a cut.
            if not words or words[-1] not in FUNCTION_WORDS:
                continue
            nb = b.lstrip("#").strip()
            ind_a = len(a.lstrip("#")) - len(a.lstrip("#").lstrip())
            ind_b = len(b.lstrip("#")) - len(b.lstrip("#").lstrip())
            heading = re.match(r"^[A-Z][A-Z0-9-]+( [A-Z][A-Z0-9-]+)+[.:—]", nb)
            # a numbered item continuing a list at A's own level is the list going on, not a cut
            listed = re.match(r"^[0-9]+\. ", nb) and ind_a < ind_b
            if heading or listed or nb.startswith("──"):
                bad.append("%s:%d comment ends mid-sentence ('...%s') and line %d starts a new block"
                           % (rel, i + 1, " ".join(words[-3:]), i + 2))
    return bad


def c358(tree):
    """No list item is itself a nested sequence (`- -`) -- a paths-filter entry is one string."""
    bad = []
    for rel in OWNED:
        for i, l in enumerate(lines(tree, rel)):
            if re.match(r"^\s*-\s+-\s", l):
                bad.append("%s:%d nested sequence item: %s" % (rel, i + 1, l.strip()[:60]))
    return bad


def c361(tree):
    """Every key the verify job declares in `env:` is read; no GHCR check hardcodes the repo."""
    ls = lines(tree, VD)
    sp = job_span(ls, "verify")
    if not sp:
        return ["%s: no `verify` job" % VD]
    s, e = sp
    keys, i = [], s
    while i < e and not re.match(r"^    env:\s*$", ls[i]):
        i += 1
    for q in range(i + 1, e):
        m = re.match(r"^      ([A-Z_][A-Z0-9_]*):", ls[q])
        if m:
            keys.append((q, m.group(1)))
        elif ls[q].strip() and not ls[q].strip().startswith("#") and indent(ls[q]) <= 4:
            break
    # GH_TOKEN is read by the `gh` CLI itself, never by name.
    implicit = {"GH_TOKEN"}
    body = "\n".join(ls[s:e])
    bad = []
    for q, k in keys:
        if k in implicit:
            continue
        reads = len(re.findall(r"\$\{?%s\b|env\.%s\b" % (k, k), body))
        if reads == 0:
            bad.append("%s:%d env `%s` is declared and read by nothing" % (VD, q + 1, k))
    for q in range(s, e):
        if re.search(r'reg-digest\.sh\s+("?\$?\{?auth_host\}?"?|ghcr\.io)\s+\S+\s+"getbusbar/busbar"', ls[q]):
            bad.append("%s:%d a registry check hardcodes the repository instead of reading the env"
                       % (VD, q + 1))
    if len(keys) < 3:
        bad.append("%s: read only %d env keys off the verify job (floor 3)" % (VD, len(keys)))
    return bad


def c_owed_keep_scope(tree):
    """(b) keep-proof honours .keep-proof.toml only on a keep-* ref, as prove-remote.sh does."""
    ls = lines(tree, KP)
    bad = []
    for start, body, _ in run_blocks(ls):
        text = "\n".join(body)
        if re.search(r"if \[ -f \.keep-proof\.toml \]", text):
            if "keep-*)" not in text or not re.search(r"exit [1-9]", text):
                bad.append("%s:%d reads .keep-proof.toml with no keep-* ref guard that refuses"
                           % (KP, start + 1))
            if text.find("keep-*)") > text.find("sed -n") >= 0:
                bad.append("%s:%d parses the scope file before the keep-* guard" % (KP, start + 1))
            return bad
    return ["%s: no step reads .keep-proof.toml -- the reader is broken" % KP]


def c_owed_drift(tree):
    """(c) a NON-required `llm-spec-drift` job runs vendor.sh --drift on push and on a schedule."""
    t = tree.get(DRIFT)
    if t is None:
        return ["%s is absent" % DRIFT]
    bad = []
    if not any("vendor.sh --drift" in x for _, x in executed_lines(tree, DRIFT)):
        bad.append("%s runs no `vendor.sh --drift`" % DRIFT)
    for trig in ("push:", "schedule:"):
        if not re.search(r"^  %s" % trig, t, re.M):
            bad.append("%s has no `%s` trigger" % (DRIFT, trig[:-1]))
    if not job_span(lines(tree, DRIFT), "llm-spec-drift"):
        bad.append("%s has no `llm-spec-drift` job" % DRIFT)
    if re.search(r"continue-on-error|\|\|\s*true", "\n".join(x for _, x in executed_lines(tree, DRIFT))
                 + t[t.find("jobs:"):]):
        bad.append("%s softens the job (continue-on-error / || true)" % DRIFT)
    if "llm-spec-drift" in tree.get(REQUIRED_DOC, ""):
        bad.append("%s lists llm-spec-drift -- it must never be a required check" % REQUIRED_DOC)
    if "llm-spec-drift" in tree.get(CI, ""):
        bad.append("%s names llm-spec-drift -- it must stay out of the required umbrella" % CI)
    return bad


def c_owed_consumer_state(tree):
    """(W0.4 b) the mirror's `--consumer-state` read refuses on a non-zero exit, never reads it as a state."""
    ex = executed_lines(tree, MIRROR)
    hits = [(n, t) for n, t in ex if "ci-images.py --consumer-state" in t and not t.startswith("echo ")]
    if not hits:
        return ["%s: nothing reads `ci-images.py --consumer-state` -- the reader is broken" % MIRROR]
    return ["%s:%d `%s` -- the exit status is not tested, so a refusal is not named" % (MIRROR, n, t[:70])
            for n, t in hits if not re.match(r"^if ! state=\"\$\(", t)]


def c_owed_gate_all(tree):
    """(d) `cargo xtask gate --all` runs on push in ci.yml, plainly, and its red is visible."""
    ls = lines(tree, CI)
    hits = [n for n, t in executed_lines(tree, CI) if re.match(r"^cargo xtask gate --all\b", t)]
    if not hits:
        return ["%s: no step runs `cargo xtask gate --all` -- it runs in no automatic workflow" % CI]
    bad = []
    for n in hits:
        t = ls[n - 1]
        job = next((k for k, s, e in job_spans(ls) if s < n <= e), None)
        s, e = job_span(ls, job)
        body = "\n".join(ls[s:e])
        if "|| true" in t or "--report" in t or re.search(r"^\s*continue-on-error:\s*true", body, re.M):
            bad.append("%s:%d `gate --all` is softened (|| true / --report / continue-on-error)" % (CI, n))
        cond = next((ls[q] for q in range(s, e) if re.match(r"^    if:", ls[q])), "")
        if FULL_TIER_GUARD in cond:
            bad.append("%s:%d `gate --all` runs only on the full tier, not on every push" % (CI, n))
        if not re.search(r"^\s*- %s\s*$" % re.escape(job), "\n".join(ls[job_span(ls, "ci-umbrella")[0]:]), re.M):
            bad.append("%s: job `%s` is not in the umbrella's needs, so its result is printed nowhere" % (CI, job))
    return bad


# A getbusbar.com host (the apex or any subdomain: docs., api., ...), and a curl/wget that is NOT
# site_curl. `_` counts as a word character, so `site_curl` never matches the bare form.
_SITE_URL = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9-]+\.)*getbusbar\.com(?![\w-])")
_BARE_FETCH = re.compile(r"(?<![\w./-])(curl|wget)(?=\s|$)")
_SITE_SRC = '. "$RUNNER_TEMP/site-curl.sh"'
_SITE_WRITER = re.compile(r'^(\s*)cat > "\$RUNNER_TEMP/site-curl\.sh" <<\'SH\'\s*$')


def _logical(pairs):
    """Join backslash-continued shell lines: [(first_line_no, text)], comments dropped."""
    out, cur, at = [], "", None
    for n, raw in pairs:
        t = raw.strip()
        if not cur and (not t or t.startswith("#")):
            continue
        if at is None:
            at = n
        if t.endswith("\\"):
            cur += t[:-1] + " "
            continue
        out.append((at, cur + t))
        cur, at = "", None
    if cur:
        out.append((at, cur))
    return out


def _code(t):
    """Drop a trailing `  # comment` (whitespace, #, whitespace): prose, not a command."""
    return re.sub(r"\s#\s.*$", "", t)


def _bare_site_fetches(rel, pairs):
    bad = []
    for n, t in _logical((n, _code(x)) for n, x in pairs):
        # a MESSAGE naming the documented one-liner is not a fetch: skip echo/record/string lines and
        # drop \`...\` spans (the `curl -fsSL https://getbusbar.com/install.sh | sh` quoted to users)
        if re.match(r"""^(\{\s*)?(echo|printf|record|declared)\b|^["']""", t):
            continue
        t = re.sub(r"\\`.*?\\`", "", t)
        if _SITE_URL.search(t) and _BARE_FETCH.search(t):
            bad.append("%s:%d a getbusbar.com fetch WITHOUT the X-Busbar-Verify header (bare curl/wget, "
                       "not site_curl) -- Cloudflare answers it 403/429: `%s`" % (rel, n, t[:90]))
    return bad


def _fn_body(text, name):
    m = re.search(r"^%s\(\) \{.*?^\}" % re.escape(name), text, re.M | re.S)
    return m.group(0) if m else ""


def c_q39(tree):
    """(Q39) every getbusbar.com fetch in CI sends X-Busbar-Verify via site_curl, scoped, never empty."""
    bad = []
    helper = tree.get(SITE_CURL)
    if helper is None:
        return ["%s: missing -- the one site_curl definition (OWNER RULING Q39)" % SITE_CURL]
    if "X-Busbar-Verify: %s" not in helper or "getbusbar.com|*.getbusbar.com)" not in helper:
        bad.append("%s: no longer sends `X-Busbar-Verify` scoped to getbusbar.com hosts" % SITE_CURL)
    # 1. no workflow run body and no release-gate script fetches getbusbar.com bare
    wfs = sorted(k for k in tree if k.startswith(WF + "/") and k.endswith((".yml", ".yaml")))
    for rel in wfs:
        for start, body, _ in run_blocks(lines(tree, rel)):
            bad += _bare_site_fetches(rel, [(start + i + 1, b) for i, b in enumerate(body)])
            if re.search(r"\$\{\{\s*secrets\.SITE_VERIFY_TOKEN\s*\}\}", "\n".join(body)):
                bad.append("%s:%d SITE_VERIFY_TOKEN spliced into script text -- pass it as env" % (rel, start))
    for rel in sorted(k for k in tree if k.startswith(RG + "/") and k.endswith(".sh")):
        bad += _bare_site_fetches(rel, list(enumerate(tree[rel].split("\n"), 1)))
    # 2. lib.sh's two site readers go through site_curl, which lib.sh sources
    lib = tree.get(LIB, "")
    for fn, want in (("http_code", "site_curl "), ("fetch", 'site_curl "${CURL_OPTS[@]}"')):
        body = "\n".join(_code(x) for x in _fn_body(lib, fn).split("\n"))
        if want not in body or _BARE_FETCH.search(body):
            bad.append("%s: %s() does not fetch through `%s` -- the site rows go out bare" % (LIB, fn, want.strip()))
    if not re.search(r'^\. "\$\(dirname "\$\{BASH_SOURCE\[0\]\}"\)/site-curl\.sh"', lib, re.M):
        bad.append("%s: does not source site-curl.sh" % LIB)
    # 3. every job that reads the site: the token as job env, an empty-token refusal, a mask; and in
    #    a job with no checkout, a VERBATIM heredoc copy of site-curl.sh that every user sources
    site_jobs = 0
    for rel in wfs:
        ls = lines(tree, rel)
        for job, js, je in job_spans(ls):
            blocks = [(st, b) for st, b, _ in run_blocks(ls) if js < st <= je]
            text = "\n".join("\n".join(b) for _, b in blocks)
            if "site_curl" not in text and "release-gate/channel-checks.sh" not in text:
                continue
            site_jobs += 1
            where = "%s job `%s`" % (rel, job)
            steps_at = next((q for q in range(js, je) if re.match(r"^    steps:\s*$", ls[q])), je)
            if not any(re.match(r"^      SITE_VERIFY_TOKEN: \$\{\{ secrets\.SITE_VERIFY_TOKEN \}\}", ls[q])
                       for q in range(js, steps_at)):
                bad.append("%s reads getbusbar.com but has no job env "
                           "`SITE_VERIFY_TOKEN: ${{ secrets.SITE_VERIFY_TOKEN }}`" % where)
            refuses = False
            for _, b in blocks:
                bt = [x.strip() for x in b]
                for i, x in enumerate(bt):
                    if x == 'if [ -z "${SITE_VERIFY_TOKEN:-}" ]; then':
                        arm = bt[i + 1:i + 4]
                        if (any(y.startswith('echo "::error::') and "SITE_VERIFY_TOKEN" in y and "Q39" in y
                                for y in arm) and "exit 1" in arm):
                            refuses = True
            if not refuses:
                bad.append("%s: no step fails with an ::error:: naming SITE_VERIFY_TOKEN and Q39 when the "
                           "token is empty -- the site checks would go out bare, silently" % where)
            if 'echo "::add-mask::${SITE_VERIFY_TOKEN}"' not in text:
                bad.append("%s: SITE_VERIFY_TOKEN is never ::add-mask::ed" % where)
            if "site_curl" not in text:
                continue  # sources lib.sh from a checkout; the lib.sh leg above covers it
            copies = 0
            for st, b in blocks:
                for i, x in enumerate(b):
                    m = _SITE_WRITER.match(x)
                    if not m:
                        continue
                    copies += 1
                    ind, got = len(m.group(1)), []
                    for y in b[i + 1:]:
                        if y.strip() == "SH":
                            break
                        got.append(y[ind:] if y.strip() else "")
                    if "\n".join(got) != helper.rstrip("\n"):
                        bad.append("%s:%d the site_curl heredoc is not a verbatim copy of %s"
                                   % (rel, st + i + 1, SITE_CURL))
                uses = any("site_curl " in y and not y.strip().startswith("#")
                           and "site_curl()" not in y for y in b)
                if uses and not any(_SITE_WRITER.match(y) for y in b) and not any(
                        y.strip().startswith(_SITE_SRC) for y in b):
                    bad.append("%s:%d a step calls site_curl without sourcing %s" % (rel, st, _SITE_SRC))
            if copies != 1:
                bad.append("%s writes the site_curl helper %d times (want exactly 1)" % (where, copies))
    if site_jobs < 3:
        bad.append("found only %d jobs reading getbusbar.com (floor 3: pointers, verify-site, the release "
                   "gate's channels) -- the reader is broken" % site_jobs)
    return bad


def c_owed_ci_calls(tree):
    """(a) + 15.5: ci.yml runs every bare-script selftest this directory owes."""
    ex = [t for _, t in executed_lines(tree, CI)]
    return ["%s: no step runs `%s`" % (CI, c) for c in OWED_CI_CALLS if not any(c in t for t in ex)]


CHECKS = [
    ("dupkeys", c_dupkeys), ("332", c332), ("333", c333), ("338", c338), ("339", c339),
    ("340", c340), ("341", c341), ("342", c342), ("343", c343), ("352", c352), ("353", c353),
    ("356", c356), ("357", c357), ("358", c358), ("361", c361), ("owed-b", c_owed_keep_scope),
    ("owed-c", c_owed_drift), ("owed-a", c_owed_ci_calls), ("owed-w04", c_owed_consumer_state),
    ("owed-d", c_owed_gate_all), ("q39", c_q39),
]


# ------------------------------------------------------------------------------------------------
# the self-test: each check's defect, planted back into this tree
# ------------------------------------------------------------------------------------------------

def _sub(rel, old, new, count=1):
    def f(tree):
        t = tree.get(rel, "")
        if old not in t:
            raise LookupError("needle not in %s: %r" % (rel, old[:70]))
        tree[rel] = t.replace(old, new, count)
        return tree
    return f


def _drop(rel):
    def f(tree):
        tree.pop(rel, None)
        return tree
    return f


PLANTS = [
    ("dupkeys", "a job key declared twice (the merge that re-added `coverage`)",
     _sub(CI, "\n  ci-umbrella:\n", "\n  fmt:\n    runs-on: latchkey-small\n    steps:\n      - run: 'true'\n\n  ci-umbrella:\n")),
    ("332", "a check step back on the default success() guard",
     _sub(VD, "        if: ${{ !cancelled() && steps.ver.outputs.version != '' && steps.helpers.outcome == 'success' && inputs.stage != 'staging' }}\n",
          "        if: ${{ inputs.stage != 'staging' }}\n")),
    ("333", "the (h) edge-block arm exiting 0",
     _sub(VD, '''returns HTTP ${code} to GitHub runners"; } >> "$GITHUB_STEP_SUMMARY"
              exit 1''', '''returns HTTP ${code} to GitHub runners"; } >> "$GITHUB_STEP_SUMMARY"
              exit 0''')),
    ("333", "the (k) edge-block arm returning 0",
     _sub(VD, '''Same marketing-side fix as (h): allow Actions egress through the bot rules."
                return 1''', '''Same marketing-side fix as (h): allow Actions egress through the bot rules."
                return 0''')),
    ("338", "a non-200 answer printed as a free tag",
     _sub(RS, '''          code="$(head_code "$V")"\n''',
          '''          code="$(head_code "$V")"\n          [ "$code" = 200 ] || echo "Docker Hub tag ${V} is free (HTTP ${code} on HEAD manifest)."\n''')),
    ("339", "the red sweep reading the inclusion-filtered set",
     _sub(RS, "\\(.url)\"' /tmp/all-runs.json)\"", "\\(.url)\"' /tmp/runs.json)\"")),
    ("340", "the asset floor back at 5",
     _sub(VD, '"${#expected[@]}" -lt 7 ]', '"${#expected[@]}" -lt 5 ]')),
    ("341", "a full-tier job dropped from the did-NOT-run list",
     _sub(CI, "coverage, perf-build-gate, teller-steps", "coverage, teller-steps")),
    ("342", "the audit-pins fetch restored",
     _sub(CI, "        run: bash scripts/verify-1.6.0-done.sh --selftest\n",
          "        run: bash scripts/verify-1.6.0-done.sh --selftest\n      - name: pins\n        run: git fetch origin '+refs/backup/audit-pins/*:refs/audit-pins/*' || true\n")),
    ("343", "the census diagnostic's backticks unescaped",
     _sub(CI, "\\`cargo test --no-run --message-format=json\\` produced",
          "`cargo test --no-run --message-format=json` produced")),
    ("352", "the release gate's PIPESTATUS capture after an errexit pipeline",
     _sub(RS, '''          rc=0
          cargo test --workspace --locked --verbose 2>&1 | tee "$RUNNER_TEMP/release-test.log" || rc=${PIPESTATUS[0]}''',
          '''          cargo test --workspace --locked --verbose 2>&1 | tee "$RUNNER_TEMP/release-test.log"
          rc=${PIPESTATUS[0]}''')),
    ("353", "--coverage wired nowhere",
     _sub(CI, "        run: python3 scripts/verify-artifact.py --coverage\n",
          "        run: python3 scripts/verify-artifact.py --selftest\n")),
    ("356", "the workflow_run branch spliced into the script",
     _sub(VD, 'V="$WORKFLOW_RUN_BRANCH"', 'V="${{ github.event.workflow_run.head_branch }}"')),
    ("357", "the teller-steps block cut mid-sentence",
     _sub(CI, "  # reddens on the push that stops a cell executing, not at release time.\n", "")),
    ("358", "the kernel paths-filter entry nested",
     _sub(CI, "              - 'crates/busbar-kernel/**'", "              -               - 'crates/busbar-kernel/**'")),
    ("361", "GHCR checks hardcoding the repository again",
     lambda tree: _sub(VD, '"$ghcr_repo" "$V"', '"getbusbar/busbar" "$V"')(
         _sub(VD, 'ghcr_repo="${GHCR_IMAGE#ghcr.io/}"', 'ghcr_repo="getbusbar/busbar"', 2)(
             _sub(VD, "${GHCR_IMAGE}:${V}", "ghcr.io/getbusbar/busbar:${V}", 2)(tree)))),
    ("owed-b", "the keep-* guard removed",
     _sub(KP, "              keep-*) ;;\n", "")),
    ("owed-c", "the daily schedule removed",
     _sub(DRIFT, "  schedule:\n    - cron: '17 6 * * *'\n", "")),
    ("owed-c", "the drift workflow deleted", _drop(DRIFT)),
    ("owed-w04", "the consumer-state read back to a bare assignment",
     _sub(MIRROR, 'if ! state="$(python3 scripts/ci-images.py --consumer-state)"; then',
          'state="$(python3 scripts/ci-images.py --consumer-state)"; if false; then')),
    ("owed-d", "gate --all softened with || true",
     _sub(CI, "        run: cargo xtask gate --all\n", "        run: cargo xtask gate --all || true\n")),
    ("owed-d", "gate --all wired nowhere",
     _sub(CI, "        run: cargo xtask gate --all\n", "        run: cargo xtask gate structure-lint\n")),
    ("q39", "a bare `curl https://getbusbar.com` in verify-site's (k)",
     _sub(VD, 'body="$(site_curl -sS -m 30', 'body="$(curl -sS -m 30')),
    ("q39", "a bare curl to a getbusbar.com subdomain in a release-gate script",
     _sub(CHANNELS, 'INSTALL_URL="https://getbusbar.com/install.sh"\n',
          'INSTALL_URL="https://getbusbar.com/install.sh"\ncurl -fsS https://docs.getbusbar.com/ >/dev/null\n')),
    ("q39", "lib.sh's fetch() back on bare curl",
     _sub(LIB, 'site_curl "${CURL_OPTS[@]}" "$1"', 'curl "${CURL_OPTS[@]}" "$1"')),
    ("q39", "the SITE_VERIFY_TOKEN job env dropped from verify-site",
     _sub(VD, "      STAGE: ${{ inputs.stage || 'public' }}\n      SITE_VERIFY_TOKEN:",
          "      STAGE: ${{ inputs.stage || 'public' }}\n      NOT_THE_TOKEN:")),
    ("q39", "the empty-token refusal exiting 0 in the release gate's channels job",
     _sub(FLEET, 'a fork pull_request gets no secrets)."\n            exit 1', 'a fork pull_request gets no secrets)."\n            exit 0')),
    ("q39", "the secret spliced into script text",
     _sub(VD, 'echo "::add-mask::${SITE_VERIFY_TOKEN}"', 'echo "::add-mask::${{ secrets.SITE_VERIFY_TOKEN }}"')),
    ("q39", "a heredoc copy of site_curl drifted from site-curl.sh",
     _sub(VD, "          SITE_CURL_NO_TOKEN=125\n", "          SITE_CURL_NO_TOKEN=0\n")),
    ("q39", "(k) calling site_curl without sourcing the helper",
     _sub(VD, '          . "$RUNNER_TEMP/site-curl.sh"  # OWNER RULING Q39: site_curl, written by the Q39 step above\n          fail=0\n          # These back',
          '          fail=0\n          # These back')),
    ("owed-a", "the prove-remote selftest unwired",
     _sub(CI, "        run: ./scripts/prove-remote.sh --selftest\n", "        run: 'true'\n")),
]


def run_checks(tree, only=None, quiet=False):
    failed = 0
    for cid, fn in CHECKS:
        if only and cid != only:
            continue
        found = fn(tree)
        doc = (fn.__doc__ or "").strip().split("\n")[0]
        if found:
            failed += 1
            print("FAIL  %-8s %s" % (cid, doc))
            for f in found:
                print("        %s" % f)
        elif not quiet:
            print("PASS  %-8s %s" % (cid, doc))
    return failed


def selftest(root):
    base = load_tree(root)
    bad = 0
    ids = {c for c, _ in CHECKS}
    planted = {c for c, _, _ in PLANTS}
    for cid in sorted(ids - planted):
        print("  [FAILED] %s has no planted defect -- a check nobody has seen go red" % cid)
        bad += 1
    fns = dict(CHECKS)
    for cid in sorted(ids):
        if fns[cid](dict(base)):
            print("  [FAILED] %s is red on this tree before anything is planted" % cid)
            bad += 1
    for cid, what, plant in PLANTS:
        try:
            tree = plant(dict(base))
        except LookupError as e:
            print("  [FAILED] %s UNPLANTABLE (%s): %s" % (cid, what, e))
            bad += 1
            continue
        if fns[cid](tree):
            print("  [ok]     %-8s fires on: %s" % (cid, what))
        else:
            print("  [FAILED] %-8s stayed green on: %s" % (cid, what))
            bad += 1
    print("workflow-invariants selftest: %s" % ("every check fires on its defect" if not bad
                                                 else "%d FAILED" % bad))
    return 1 if bad else 0


def main(argv):
    root, only, st = ".", None, False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--root" and i + 1 < len(argv):
            root, i = argv[i + 1], i + 2
        elif a == "--only" and i + 1 < len(argv):
            only, i = argv[i + 1], i + 2
        elif a == "--selftest":
            st, i = True, i + 1
        else:
            print("usage: workflow-invariants.py [--root DIR] [--only ID] [--selftest]", file=sys.stderr)
            return 2
    if not os.path.isdir(os.path.join(root, WF)):
        print("workflow-invariants: no %s under %s" % (WF, root), file=sys.stderr)
        return 2
    if only and only not in dict(CHECKS):
        print("workflow-invariants: unknown check %r" % only, file=sys.stderr)
        return 2
    if st:
        return selftest(root)
    failed = run_checks(load_tree(root), only)
    print("workflow-invariants: %s" % ("all hold" if not failed else "%d check(s) FAILED" % failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
