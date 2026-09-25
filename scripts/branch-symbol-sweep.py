#!/usr/bin/env python3
"""branch-symbol-sweep — find source content that exists on a branch and not on trunk.

THE PROBLEM.  819 remote branches, all cut after v1.5.5.  Rename waves moved nearly
every path, so `git patch-id` is useless and `git log trunk..branch` is meaningless
(only 3 of 819 are ancestors of trunk).  The only thing that survives a rename is the
NAME: identifiers, declarations, test names and string literals.  So this tool compares
SYMBOLS, never paths.

THE METHOD, per branch, against `merge-base(trunk, branch)`:

  1. `git diff <merge-base> <branch>` — collect the lines the branch ADDS.
  2. From those added lines extract NEEDLES: named declarations (fn/struct/enum/trait/
     type/const/static/mod/macro and the per-language equivalents), test names, and
     string literals.  Comments are stripped first — prose that mentions `fn walk` is
     not a declaration of `walk`.
  3. Drop any needle that already exists anywhere in the merge-base tree.  What is left
     is what the branch NAMED INTO EXISTENCE.
  4. Look each survivor up in a HAYSTACK built from the whole trunk tree — every
     identifier and every string literal in every trunk file, CODE ONLY.
  5. Bucket: EMPTY / HARVESTED / SURVIVOR.

THE ASYMMETRY IS DELIBERATE.  The needle side is narrow (declarations only) so that a
finding is a real named thing.  The haystack side is as broad as possible (every token
anywhere) so that a symbol that landed under a different path, or survives only as a
call site, still reads as FOUND.  Errors are pushed toward HARVESTED, because a false
SURVIVOR wastes an auditor's day and a false HARVESTED loses the work forever... except
for the one place where that trade is inverted, which is:

THE DOCS TRAP — the measured 33% false-negative this tool exists to close.  The
inherited instrument grepped trunk WITHOUT excluding `docs/`.  An audit document
*describing a gap* names the missing symbol, so the prose about the absent code read as
the code being present.  Here `docs/**` and every `*.md` are excluded from the trunk
haystack by construction.  They are indexed SEPARATELY, so every absent symbol carries a
`docs_only` flag: TRUE means "trunk documents this and does not implement it", which is
not a false alarm but the strongest possible finding.
`--trunk-include-docs` re-opens the hole on purpose, for falsification only.

NEVER touches the working tree and NEVER checks a branch out.  Everything is
`git show` / `git diff` / `git cat-file` against refs.  The repo tree is shared.
"""

from __future__ import annotations

import argparse
import fcntl
import fnmatch
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

TOOL = "branch-symbol-sweep"
TOOL_VERSION = "1.0.0"
LEDGER_SCHEMA = 1

# ---------------------------------------------------------------------------
# path classification
# ---------------------------------------------------------------------------

DOC_SUFFIXES = (".md", ".markdown", ".mdx", ".rst", ".adoc")
DOC_PREFIXES = ("docs/",)

# true binaries: tokenising these yields nonsense, and nonsense in the HAYSTACK would
# manufacture false HARVESTEDs.
BINARY_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".gz", ".zip", ".tar",
    ".bin", ".woff", ".woff2", ".ttf", ".otf", ".wasm", ".so", ".dylib", ".a", ".o",
)

# generated / recorded artefacts.  Excluded from the NEEDLE side only (a regenerated
# snapshot is not human work).  They stay in the HAYSTACK, because a symbol that exists
# in trunk's generated output really does exist on trunk.
GENERATED_GLOBS = (
    "*.lock", "Cargo.lock", "*.snap", "*-schema.snapshot.json",
    "*/openapi.json", "openapi.json", "*/openapi.json.gz",
    "target/*", "mutants-report/*", "mutants-report-live/*",
)

# money paths — a survivor here is a PARK, never a self-approval.
MONEY_PREFIXES = (
    "crates/busbar-kernel-ledger/", "crates/busbar-kernel-budget/",
    "crates/busbar-kernel/src/cost.rs", "crates/busbar-kernel/src/billing.rs",
    "crates/busbar-contract/src/count.rs",
    "crates/busbar/src/root/durability.rs",
    "crates/busbar/src/root/ledger_identity.rs", "crates/busbar/src/root/migration.rs",
    "crates/busbar-llm-codec/", "crates/busbar-voice-codec/",
)
MONEY_NAME_RE = re.compile(
    r"(?i)(money|nanos|cents|micro_?unit|rate_?card|rate_?nanos|price|pricing|spend|"
    r"bill|billing|charge|meter|ledger|budget|invoice|tariff|quota_?cost)"
)


def is_doc(path: str) -> bool:
    if path.startswith(DOC_PREFIXES):
        return True
    return path.lower().endswith(DOC_SUFFIXES)


def is_binary_path(path: str) -> bool:
    return path.lower().endswith(BINARY_SUFFIXES)


def is_generated(path: str) -> bool:
    return any(fnmatch.fnmatch(path, g) for g in GENERATED_GLOBS)


def is_money_path(path: str) -> bool:
    return path.startswith(MONEY_PREFIXES)


# ---------------------------------------------------------------------------
# lexing
# ---------------------------------------------------------------------------

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
DQ_LIT_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
SQ_LIT_RE = re.compile(r"'((?:[^'\\\n]|\\.)*)'")
# `r"` / `br#"` must be a REAL raw-string opener.  Without the lookbehind the `r` of an
# ordinary word (`..._number"`) opened a match, and DOTALL let its non-greedy body swallow
# whole raw strings further down the file — so a literal present in trunk was extracted on
# the needle side and missed on the haystack side.  That asymmetry is a FALSE SURVIVOR.
RAW_LIT_RE = re.compile(r'(?<![A-Za-z0-9_])b?r(#*)"(.*?)"\1', re.DOTALL)

# Compound names: yaml/TOML/JSON keys and table paths carry `-`, `.` and `/`, which a bare
# identifier regex splits apart.  `self-hosted-runner` on the needle side must be findable
# as `self-hosted-runner` on the haystack side, not as three unrelated words.
EXT_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:[.\-/][A-Za-z0-9_]+)+")
BACKTICK_LIT_RE = re.compile(r"`([^`\n]{2,200})`")

PLACEHOLDER_RE = re.compile(r"\{[^{}]{0,40}\}|%[-+ #0-9.]*[sdiufFgGxXoc]|\$\{[^}]{0,40}\}")
WS_RE = re.compile(r"\s+")

MIN_IDENT_LEN = 3
MIN_LIT_LEN = 8
MAX_LIT_LEN = 200
HAS_ALPHA_RE = re.compile(r"[A-Za-z]")


def normalise_literal(s: str) -> str:
    """Collapse format placeholders and whitespace so `"bad verb: {}"` and
    `"bad verb: {name}"` compare equal.  Applied identically on both sides."""
    s = PLACEHOLDER_RE.sub("{}", s)
    s = WS_RE.sub(" ", s).strip()
    return s


def literal_candidates(text: str, single_quotes: bool = True) -> list[str]:
    out: list[str] = []
    for m in DQ_LIT_RE.finditer(text):
        out.append(m.group(1))
    for m in RAW_LIT_RE.finditer(text):
        out.append(m.group(2))
    if single_quotes:
        for m in SQ_LIT_RE.finditer(text):
            out.append(m.group(1))
    return out


def haystack_tokens(text: str) -> set[str]:
    """EVERY token in a trunk/merge-base file.  Deliberately over-broad."""
    toks: set[str] = set()
    for m in IDENT_RE.finditer(text):
        t = m.group(0)
        if len(t) >= 2:
            toks.add(t)
    for m in EXT_IDENT_RE.finditer(text):
        toks.add(m.group(0))
    for lit in literal_candidates(text):
        if not lit:
            continue
        lit = lit[:MAX_LIT_LEN]
        toks.add(lit)
        n = normalise_literal(lit)
        if n:
            toks.add(n)
    for m in BACKTICK_LIT_RE.finditer(text):
        # backticked prose in comments/docs; only matters for the docs haystack, but
        # indexing it on both sides keeps the two comparable.
        toks.add(m.group(1))
        toks.add(normalise_literal(m.group(1)))
    return toks


# ---------------------------------------------------------------------------
# needle extraction — declarations only, comments stripped
# ---------------------------------------------------------------------------

RUST_DECLS = [
    ("fn", re.compile(r"(?:^|[^\w.:])fn\s+([A-Za-z_][A-Za-z0-9_]*)")),
    ("struct", re.compile(r"(?:^|[^\w.:])struct\s+([A-Za-z_][A-Za-z0-9_]*)")),
    ("enum", re.compile(r"(?:^|[^\w.:])enum\s+([A-Za-z_][A-Za-z0-9_]*)")),
    ("trait", re.compile(r"(?:^|[^\w.:])trait\s+([A-Za-z_][A-Za-z0-9_]*)")),
    ("union", re.compile(r"(?:^|[^\w.:])union\s+([A-Za-z_][A-Za-z0-9_]*)")),
    ("type", re.compile(r"(?:^|[^\w.:])type\s+([A-Za-z_][A-Za-z0-9_]*)\s*[=<:]")),
    ("const", re.compile(r"(?:^|[^\w.:])const\s+([A-Za-z_][A-Za-z0-9_]*)\s*:")),
    ("static", re.compile(r"(?:^|[^\w.:])static\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:")),
    ("mod", re.compile(r"(?:^|[^\w.:])mod\s+([a-z_][a-z0-9_]*)\s*[;{]")),
    ("macro", re.compile(r"macro_rules!\s*([A-Za-z_][A-Za-z0-9_]*)")),
]

SH_DECLS = [
    ("shfn", re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_-]*)\s*\(\)\s*\{")),
    ("shvar", re.compile(r"^\s*(?:readonly\s+|export\s+|declare\s+-\w+\s+|local\s+)?([A-Z_][A-Z0-9_]{3,})=")),
]

PY_DECLS = [
    ("pyfn", re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)")),
    ("pyclass", re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)")),
    ("pyconst", re.compile(r"^([A-Z_][A-Z0-9_]{2,})\s*[:=]")),
]

JS_DECLS = [
    ("jsfn", re.compile(r"(?:^|[^\w.])function\s*\*?\s*([A-Za-z_$][\w$]*)")),
    ("jsclass", re.compile(r"(?:^|[^\w.])class\s+([A-Za-z_$][\w$]*)")),
    ("jsbind", re.compile(r"(?:^|[^\w.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=")),
]

TOML_DECLS = [
    ("tomltable", re.compile(r"^\s*\[{1,2}\s*([^\]\s]+)\s*\]{1,2}")),
    ("tomlkey", re.compile(r'^\s*(?:"([^"]+)"|([A-Za-z_][\w.-]*))\s*=')),
]

YAML_DECLS = [
    ("yamlkey", re.compile(r"^\s*-?\s*([A-Za-z_][\w.-]*)\s*:(?:\s|$)")),
]

JSON_DECLS = [
    ("jsonkey", re.compile(r'"([A-Za-z_][\w.\-/]*)"\s*:')),
]

PROTO_DECLS = [
    ("proto", re.compile(r"(?:^|[^\w])(?:message|service|enum|rpc)\s+([A-Za-z_][A-Za-z0-9_]*)")),
]

TEST_ATTR_RE = re.compile(r"#\[\s*(?:[\w:]*\btest\b[\w:]*|rstest|test_case|tokio::test|should_panic)")
TEST_NAME_RE = re.compile(r"^(?:test_|it_|prop_|proptest_|check_)|(?:_test|_tests)$")


def _lang(path: str) -> str:
    p = path.lower()
    if p.endswith(".rs"):
        return "rust"
    if p.endswith((".sh", ".bash", ".zsh")):
        return "sh"
    if p.endswith(".py"):
        return "py"
    if p.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
        return "js"
    if p.endswith(".toml"):
        return "toml"
    if p.endswith((".yaml", ".yml")):
        return "yaml"
    if p.endswith((".json", ".jsonl")):
        return "json"
    if p.endswith(".proto"):
        return "proto"
    return "other"


_DECLS_BY_LANG = {
    "rust": RUST_DECLS, "sh": SH_DECLS, "py": PY_DECLS, "js": JS_DECLS,
    "toml": TOML_DECLS, "yaml": YAML_DECLS, "json": JSON_DECLS,
    "proto": PROTO_DECLS, "other": [],
}

# comment openers per language.  `#` is NOT a comment in Rust (`#[derive]`).
_LINE_COMMENT = {
    "rust": ("//",), "js": ("//",), "proto": ("//",),
    "sh": ("#",), "py": ("#",), "toml": ("#",), "yaml": ("#",),
    "json": (), "other": (),
}


def _is_comment_only(line: str, lang: str) -> bool:
    s = line.strip()
    if not s:
        return True
    if lang in ("rust", "js", "proto"):
        # `*` continues a block comment, but `*foo = 1;` is a deref assignment — do not
        # eat a real statement as if it were prose.
        return (s.startswith("//") or s.startswith("/*")
                or s == "*" or s.startswith("* ") or s.startswith("*/"))
    if lang in ("sh", "py", "toml", "yaml"):
        return s.startswith("#")
    return False


def _strip_literals_and_comments(line: str, lang: str) -> str:
    """Blank out string spans, then cut at a comment marker that is not inside a string.
    Prose in a comment must never read as a declaration."""
    spans: list[tuple[int, int]] = []
    for rx in (DQ_LIT_RE, RAW_LIT_RE):
        for m in rx.finditer(line):
            spans.append((m.start(), m.end()))
    if lang in ("sh", "py", "yaml", "toml"):
        for m in SQ_LIT_RE.finditer(line):
            spans.append((m.start(), m.end()))
    buf = list(line)
    for a, b in spans:
        for i in range(a, b):
            buf[i] = " "
    blanked = "".join(buf)
    for opener in _LINE_COMMENT.get(lang, ()):
        idx = blanked.find(opener)
        if idx >= 0:
            blanked = blanked[:idx]
    return blanked


class Needle:
    __slots__ = ("sym", "kind", "path", "line")

    def __init__(self, sym: str, kind: str, path: str, line: int):
        self.sym, self.kind, self.path, self.line = sym, kind, path, line


def extract_needles(path: str, added: list[tuple[int, str]]) -> list[Needle]:
    """`added` is [(line_no_on_branch, text)] for `+` lines of one file."""
    lang = _lang(path)
    decls = _DECLS_BY_LANG[lang]
    out: list[Needle] = []
    pending_test = False
    for lineno, raw in added:
        if _is_comment_only(raw, lang):
            # still honour a bare `#[test]` attribute line in Rust (not a comment)
            if lang == "rust" and TEST_ATTR_RE.search(raw):
                pending_test = True
            continue
        if lang == "rust" and TEST_ATTR_RE.search(raw):
            pending_test = True

        # literals come from the raw line (before blanking), one line at a time
        for lit in literal_candidates(raw, single_quotes=(lang != "rust")):
            if len(lit) < MIN_LIT_LEN or len(lit) > MAX_LIT_LEN:
                continue
            if not HAS_ALPHA_RE.search(lit):
                continue
            out.append(Needle(normalise_literal(lit), "lit", path, lineno))

        code = _strip_literals_and_comments(raw, lang)
        for kind, rx in decls:
            for m in rx.finditer(code):
                name = next((g for g in m.groups() if g), None)
                if not name or len(name) < MIN_IDENT_LEN:
                    continue
                k = kind
                if kind == "fn" and (pending_test or TEST_NAME_RE.search(name)):
                    k = "test"
                out.append(Needle(name, k, path, lineno))
                if kind == "fn":
                    pending_test = False
    return out


# ---------------------------------------------------------------------------
# git plumbing — read-only, never the working tree
# ---------------------------------------------------------------------------

class Git:
    def __init__(self, repo: str):
        self.repo = repo
        self._batch = None

    def run(self, *args: str, check: bool = True, binary: bool = False):
        cp = subprocess.run(
            ["git", "-C", self.repo, "-c", "core.quotepath=false", *args],
            capture_output=True,
        )
        if check and cp.returncode != 0:
            raise RuntimeError(
                "git %s failed rc=%d: %s" % (" ".join(args[:4]), cp.returncode,
                                             cp.stderr.decode("utf-8", "replace")[:500])
            )
        return cp.stdout if binary else cp.stdout.decode("utf-8", "replace")

    def rev_parse(self, rev: str) -> str:
        return self.run("rev-parse", "--verify", "--end-of-options", rev + "^{commit}").strip()

    def merge_base(self, a: str, b: str) -> str | None:
        cp = subprocess.run(["git", "-C", self.repo, "merge-base", a, b], capture_output=True)
        if cp.returncode != 0:
            return None
        return cp.stdout.decode().strip() or None

    def _batch_proc(self):
        if self._batch is None:
            self._batch = subprocess.Popen(
                ["git", "-C", self.repo, "cat-file", "--batch"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            )
        return self._batch

    def tree_blobs(self, rev: str):
        """Yield (path, text) for every blob in a tree.  One cat-file process."""
        out = self.run("ls-tree", "-r", "-z", "--format=%(objectname)\t%(path)", rev,
                       binary=True)
        p = self._batch_proc()
        for rec in out.split(b"\0"):
            if not rec.strip():
                continue
            sha, _, path = rec.partition(b"\t")
            path_s = path.decode("utf-8", "replace")
            p.stdin.write(sha + b"\n")
            p.stdin.flush()
            hdr = p.stdout.readline().split()
            if len(hdr) < 3:
                raise RuntimeError("cat-file desync on %s" % path_s)
            n = int(hdr[2])
            data = p.stdout.read(n)
            p.stdout.read(1)
            yield path_s, data

    def close(self):
        if self._batch is not None:
            try:
                self._batch.stdin.close()
                self._batch.wait(timeout=10)
            except Exception:
                self._batch.kill()
            self._batch = None


# ---------------------------------------------------------------------------
# haystacks
# ---------------------------------------------------------------------------

class Haystack:
    def __init__(self, code: set[str], docs: set[str], n_code_files: int, n_doc_files: int):
        self.code, self.docs = code, docs
        self.n_code_files, self.n_doc_files = n_code_files, n_doc_files


# The instrument's own source.  It carries the selftest's fixtures -- the T1/T5 markers
# and the T3 trap symbols -- as string literals, so indexing it would put into
# trunk_hay.code exactly the names every falsification case needs ABSENT from trunk, and
# in a real sweep it would turn any branch symbol that merely matches a fixture into a
# false HARVESTED.  The tool measures trunk; it is not part of what it measures.
SELF_PATH = "scripts/%s.py" % TOOL


def build_haystack(git: Git, rev: str, verbose: bool = False) -> Haystack:
    code: set[str] = set()
    docs: set[str] = set()
    nc = nd = 0
    for path, data in git.tree_blobs(rev):
        if path == SELF_PATH:
            continue
        if is_binary_path(path):
            continue
        if b"\0" in data[:8000]:          # undeclared binary
            continue
        text = data.decode("utf-8", "replace")
        toks = haystack_tokens(text)
        if is_doc(path):
            docs |= toks
            nd += 1
        else:
            code |= toks
            nc += 1
    if verbose:
        sys.stderr.write(
            "  haystack %s: %d code files/%d tokens, %d doc files/%d tokens\n"
            % (rev[:12], nc, len(code), nd, len(docs))
        )
    return Haystack(code, docs, nc, nd)


# ---------------------------------------------------------------------------
# diff parsing
# ---------------------------------------------------------------------------

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
MAX_DIFF_BYTES = 64 * 1024 * 1024


def added_lines_by_file(git: Git, base: str, tip: str):
    """-> (dict path -> [(lineno, text)], stats).  Working tree is never touched."""
    cp = subprocess.run(
        ["git", "-C", git.repo, "-c", "core.quotepath=false", "diff",
         "--no-color", "--no-ext-diff", "--find-renames", "-U0",
         "--src-prefix=a/", "--dst-prefix=b/", base, tip],
        capture_output=True,
    )
    if cp.returncode != 0:
        raise RuntimeError("git diff %s..%s rc=%d: %s"
                           % (base[:8], tip, cp.returncode,
                              cp.stderr.decode("utf-8", "replace")[:400]))
    raw = cp.stdout
    stats = {
        "diff_bytes": len(raw), "files_doc": 0, "files_binary": 0,
        "files_generated": 0, "files_scanned": 0, "added_lines": 0,
    }
    if len(raw) > MAX_DIFF_BYTES:
        raw = raw[:MAX_DIFF_BYTES]
        stats["diff_truncated"] = True
    text = raw.decode("utf-8", "replace")
    files: dict[str, list[tuple[int, str]]] = {}
    cur: list[tuple[int, str]] | None = None
    cur_path = None
    lineno = 0
    seen_paths: set[str] = set()
    for line in text.split("\n"):
        if line.startswith("+++ "):
            p = line[4:].strip()
            if p == "/dev/null":
                cur, cur_path = None, None
                continue
            if p.startswith('"') and p.endswith('"'):
                p = json.loads(p)
            if p.startswith("b/"):
                p = p[2:]
            cur_path = p
            if p in seen_paths:
                cur = files.get(p)
                continue
            seen_paths.add(p)
            if is_doc(p):
                stats["files_doc"] += 1
                cur = None
            elif is_binary_path(p):
                stats["files_binary"] += 1
                cur = None
            elif is_generated(p):
                stats["files_generated"] += 1
                cur = None
            else:
                stats["files_scanned"] += 1
                cur = files.setdefault(p, [])
            continue
        if line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            cur = None
            continue
        if line.startswith("@@"):
            m = HUNK_RE.match(line)
            lineno = int(m.group(1)) if m else 0
            continue
        if cur is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            cur.append((lineno, line[1:]))
            stats["added_lines"] += 1
            lineno += 1
    return files, stats


# ---------------------------------------------------------------------------
# the sweep
# ---------------------------------------------------------------------------

MAX_ABSENT_IN_ROW = 500


def summarise_absent(absent: list[Needle], trunk_docs: set[str]) -> dict:
    """The per-row absence fields.  `absent` (the listed rows) is capped at
    MAX_ABSENT_IN_ROW; every COUNT is taken over the whole list, never over the cap --
    a count read off the capped rows silently stops at 500."""
    absent = sorted(absent, key=lambda n: (n.kind == "lit", n.path, n.line, n.sym))
    money = 0
    docs_only = 0
    rows = []
    for i, n in enumerate(absent):
        is_money = is_money_path(n.path) or bool(MONEY_NAME_RE.search(n.sym))
        is_docs_only = n.sym in trunk_docs
        money += is_money
        docs_only += is_docs_only
        if i < MAX_ABSENT_IN_ROW:
            rows.append({
                "sym": n.sym, "kind": n.kind, "path": n.path, "line": n.line,
                "docs_only": is_docs_only,
                **({"money": True} if is_money else {}),
            })
    out = {"absent": rows, "docs_only_absent": docs_only, "money_hits": money}
    if len(absent) > MAX_ABSENT_IN_ROW:
        out["absent_truncated"] = len(absent) - MAX_ABSENT_IN_ROW
    return out


def sweep_branch(git: Git, trunk_sha: str, trunk_hay: Haystack, branch: str,
                 mb_hay_for, include_docs: bool) -> dict:
    t0 = time.time()
    notes: list[str] = []
    row = {
        "v": LEDGER_SCHEMA, "tool": TOOL, "tool_version": TOOL_VERSION,
        "trunk": trunk_sha, "trunk_docs_included": include_docs,
        "branch": branch,
    }
    try:
        tip = git.rev_parse(branch)
    except RuntimeError as e:
        row.update(bucket="ERROR", error=str(e)[:300], notes=["unresolvable rev"])
        return row
    row["branch_sha"] = tip

    mb = git.merge_base(trunk_sha, tip)
    if mb is None:
        row.update(bucket="ERROR", error="no merge-base with trunk", notes=["unrelated history"])
        return row
    row["merge_base"] = mb

    if tip == mb:
        notes.append("branch is an ancestor of trunk")

    files, stats = added_lines_by_file(git, mb, tip)
    row.update({k: v for k, v in stats.items()})

    needles: list[Needle] = []
    for path, added in files.items():
        if path == SELF_PATH:      # excluded from the haystack, so from the needles too
            continue
        needles.extend(extract_needles(path, added))
    row["needles_raw"] = len(needles)

    if stats["files_scanned"] > 0 and stats["added_lines"] == 0:
        notes.append("files changed but zero added lines (deletions/renames only)")
    if stats["added_lines"] > 0 and not needles:
        notes.append("added lines carry no declaration or literal (edits inside bodies)")

    mb_hay = mb_hay_for(mb)
    row["mb_code_tokens"] = len(mb_hay.code)

    # novelty: the branch must have NAMED this, i.e. it is nowhere in the merge-base code
    novel: dict[str, Needle] = {}
    for n in needles:
        if not n.sym or n.sym in mb_hay.code:
            continue
        prev = novel.get(n.sym)
        if prev is None or (prev.kind == "lit" and n.kind != "lit"):
            novel[n.sym] = n
    row["symbols_in"] = len(novel)

    hay = trunk_hay.code | trunk_hay.docs if include_docs else trunk_hay.code
    absent: list[Needle] = [n for s, n in novel.items() if s not in hay]
    row["symbols_found"] = len(novel) - len(absent)
    row["symbols_absent"] = len(absent)

    if len(novel) == 0:
        row["bucket"] = "EMPTY"
    elif not absent:
        row["bucket"] = "HARVESTED"
    else:
        row["bucket"] = "SURVIVOR"

    row.update(summarise_absent(absent, trunk_hay.docs))
    row["notes"] = notes
    row["elapsed_ms"] = int((time.time() - t0) * 1000)
    row["ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return row


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------

def read_ledger(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                continue          # a torn line from an interrupted run; re-swept
    return out


def append_ledger(path: str, row: dict) -> None:
    """Append one whole row under an exclusive lock.  Five agents, one ledger."""
    line = json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# ---------------------------------------------------------------------------
# branch selection
# ---------------------------------------------------------------------------

def list_branches(git: Git, patterns: list[str]) -> list[str]:
    out = git.run("for-each-ref", "--format=%(refname:short)", "refs/remotes/origin/")
    names = [n for n in out.split("\n") if n and n != "origin/HEAD"]
    if not patterns:
        return sorted(names)
    sel = []
    for n in names:
        if any(fnmatch.fnmatch(n, p) for p in patterns):
            sel.append(n)
    return sorted(sel)


def apply_slice(names: list[str], spec: str | None) -> list[str]:
    if not spec:
        return names
    k, _, n = spec.partition("/")
    k, n = int(k), int(n)
    if not (1 <= k <= n):
        raise SystemExit("--slice K/N requires 1 <= K <= N")
    per = (len(names) + n - 1) // n
    return names[(k - 1) * per: k * per]


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_sweep(a) -> int:
    git = Git(a.repo)
    trunk_sha = git.rev_parse(a.trunk)
    sys.stderr.write("trunk pinned at %s (%s)\n" % (trunk_sha, a.trunk))

    # zsh does NOT word-split an unquoted $VAR, so `--branches $LIST` arrives as ONE
    # argument.  Split defensively on whitespace and commas rather than letting the
    # caller's shell decide; an unsplit list is a silent one-branch sweep.
    names: list[str] = []
    for chunk in (a.branches or []):
        names += [t for t in re.split(r"[\s,]+", chunk) if t]
    if a.branches_file:
        with open(a.branches_file, encoding="utf-8") as fh:
            names += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not names:
        names = list_branches(git, a.glob or [])
    names = sorted(dict.fromkeys(names))
    names = apply_slice(names, a.slice)
    if a.limit:
        names = names[: a.limit]
    if not names:
        raise SystemExit("branch selection is EMPTY — refusing to report a zero")

    existing = read_ledger(a.ledger)
    drift = {r.get("trunk") for r in existing if r.get("trunk")} - {trunk_sha}
    if drift and not a.allow_trunk_drift:
        raise SystemExit(
            "ledger %s already holds rows pinned to a different trunk %s; rows would be\n"
            "incomparable.  Re-run all agents on one pin, or pass --allow-trunk-drift."
            % (a.ledger, sorted(drift))
        )
    done = {
        r["branch"] for r in existing
        if r.get("trunk") == trunk_sha
        and r.get("tool_version") == TOOL_VERSION
        and bool(r.get("trunk_docs_included")) == bool(a.trunk_include_docs)
        and r.get("bucket") != "ERROR"
    }
    todo = names if a.force else [n for n in names if n not in done]
    sys.stderr.write("selected %d branches, %d already in ledger, %d to sweep\n"
                     % (len(names), len(names) - len(todo), len(todo)))
    if not todo:
        return 0

    trunk_hay = build_haystack(git, trunk_sha, verbose=True)
    if len(trunk_hay.code) < 20000:
        raise SystemExit("trunk CODE haystack has only %d tokens — refusing to run; a small\n"
                         "haystack manufactures false SURVIVORs" % len(trunk_hay.code))
    if len(trunk_hay.docs) < 2000:
        sys.stderr.write("WARNING: trunk DOC haystack is only %d tokens\n" % len(trunk_hay.docs))

    # group by merge-base so each merge-base tree is indexed once
    mb_of: dict[str, str] = {}
    for b in todo:
        try:
            mb_of[b] = git.merge_base(trunk_sha, b) or "?"
        except Exception:
            mb_of[b] = "?"
    todo.sort(key=lambda b: (mb_of.get(b, "?"), b))

    cache: dict[str, Haystack] = {}

    def mb_hay_for(mb: str) -> Haystack:
        h = cache.get(mb)
        if h is None:
            if len(cache) >= 3:
                cache.clear()
            h = build_haystack(git, mb, verbose=a.verbose)
            cache[mb] = h
        return h

    counts: dict[str, int] = {}
    t0 = time.time()
    for i, b in enumerate(todo, 1):
        row = sweep_branch(git, trunk_sha, trunk_hay, b, mb_hay_for, a.trunk_include_docs)
        append_ledger(a.ledger, row)
        counts[row["bucket"]] = counts.get(row["bucket"], 0) + 1
        if a.verbose or i % 25 == 0 or i == len(todo):
            sys.stderr.write(
                "[%4d/%d] %-55s %-9s in=%-5d found=%-5d absent=%-5d (%.0fs)\n"
                % (i, len(todo), b[:55], row["bucket"], row.get("symbols_in", 0),
                   row.get("symbols_found", 0), row.get("symbols_absent", 0),
                   time.time() - t0)
            )
    git.close()
    sys.stderr.write("done: %s\n" % json.dumps(counts, sort_keys=True))
    return 0


def cmd_report(a) -> int:
    rows = read_ledger(a.ledger)
    if a.trunk:
        g = Git(a.repo)
        sha = g.rev_parse(a.trunk)
        rows = [r for r in rows if r.get("trunk") == sha]
    if a.glob:
        rows = [r for r in rows if any(fnmatch.fnmatch(r.get("branch", ""), p) for p in a.glob)]
    rows = [r for r in rows if not r.get("trunk_docs_included")] if not a.docs_included else \
           [r for r in rows if r.get("trunk_docs_included")]
    latest: dict[str, dict] = {}
    for r in rows:
        latest[r.get("branch", "?")] = r
    rows = list(latest.values())
    if not rows:
        print("NO ROWS — this is a zero that must be explained, not reported")
        return 1
    dist: dict[str, int] = {}
    for r in rows:
        dist[r.get("bucket", "?")] = dist.get(r.get("bucket", "?"), 0) + 1
    print("branches: %d" % len(rows))
    for k in sorted(dist):
        print("  %-10s %5d  (%5.1f%%)" % (k, dist[k], 100.0 * dist[k] / len(rows)))
    surv = [r for r in rows if r.get("bucket") == "SURVIVOR"]
    print("absent symbols total: %d" % sum(r.get("symbols_absent", 0) for r in surv))
    print("docs-only absent (documented, not implemented): %d"
          % sum(r.get("docs_only_absent", 0) for r in surv))
    print("money-flagged absent: %d" % sum(r.get("money_hits", 0) for r in surv))
    if a.top:
        print("\ntop survivors by absent count:")
        for r in sorted(surv, key=lambda r: -r.get("symbols_absent", 0))[: a.top]:
            print("  %-58s absent=%-5d docs_only=%-4d money=%d"
                  % (r["branch"][:58], r.get("symbols_absent", 0),
                     r.get("docs_only_absent", 0), r.get("money_hits", 0)))
    return 0


def cmd_locate(a) -> int:
    """Where does a symbol live on trunk?  Separates code from docs — this is how you
    prove a HARVESTED landed at a RENAMED path, and how you read the docs trap."""
    git = Git(a.repo)
    sha = git.rev_parse(a.trunk)
    rx = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(a.symbol) + r"(?![A-Za-z0-9_])")
    code_hits, doc_hits = [], []
    for path, data in git.tree_blobs(sha):
        if is_binary_path(path) or b"\0" in data[:8000]:
            continue
        text = data.decode("utf-8", "replace")
        if a.symbol not in text:
            continue
        for i, line in enumerate(text.split("\n"), 1):
            if rx.search(line):
                (doc_hits if is_doc(path) else code_hits).append((path, i, line.strip()[:160]))
    git.close()
    print("trunk %s — symbol %r" % (sha, a.symbol))
    print("CODE hits: %d" % len(code_hits))
    for p, i, l in code_hits[: a.max]:
        print("  %s:%d: %s" % (p, i, l))
    print("DOC hits: %d" % len(doc_hits))
    for p, i, l in doc_hits[: a.max]:
        print("  %s:%d: %s" % (p, i, l))
    if not code_hits and doc_hits:
        print("\nVERDICT: DOCS-ONLY — trunk documents this symbol and does not implement it.")
    return 0



# ---------------------------------------------------------------------------
# FALSIFICATION — an instrument that cannot produce a NO is not a check.
#
# Every scenario below is built with git PLUMBING: blobs and trees written to the
# object database, commits made with `commit-tree`.  NO ref is created, NO ref is
# deleted, NO branch is checked out, and the shared working tree is never touched.
# The index used is a throwaway file under $TMPDIR.
# ---------------------------------------------------------------------------

import tempfile

SELFTEST_MARKERS = {
    "fn": "bsweep_selftest_absent_zqx_marker",
    "struct": "BsweepSelftestAbsentZqxStruct",
    "test": "a_bsweep_selftest_marker_absent_from_trunk",
    "lit": "bsweep selftest literal that trunk has never carried zqx",
    "real": "bsweep_selftest_real_decl_zqx",
    "phantom": "bsweep_selftest_phantom_in_prose_zqx",
}


def _mk_commit(git: Git, base_rev: str, entries: list[tuple[str, str, str]], msg: str) -> str:
    """entries = [(mode, blob_sha, path)].  Returns a dangling commit SHA."""
    fd, idx = tempfile.mkstemp(prefix="bsweep-index-")
    os.close(fd)
    os.unlink(idx)
    env = {**os.environ, "GIT_INDEX_FILE": idx}
    try:
        subprocess.run(["git", "-C", git.repo, "read-tree", base_rev],
                       env=env, check=True, capture_output=True)
        payload = "".join("%s %s\t%s\n" % e for e in entries)
        cp = subprocess.run(["git", "-C", git.repo, "update-index", "--add", "--index-info"],
                            env=env, input=payload.encode(), capture_output=True)
        if cp.returncode != 0:
            raise RuntimeError("update-index: " + cp.stderr.decode()[:400])
        tree = subprocess.run(["git", "-C", git.repo, "write-tree"], env=env,
                              check=True, capture_output=True).stdout.decode().strip()
        commit = subprocess.run(
            ["git", "-C", git.repo, "commit-tree", tree, "-p", base_rev, "-m", msg],
            env=env, check=True, capture_output=True).stdout.decode().strip()
        return commit
    finally:
        if os.path.exists(idx):
            os.unlink(idx)


def _blob(git: Git, content: str) -> str:
    return subprocess.run(["git", "-C", git.repo, "hash-object", "-w", "--stdin"],
                          input=content.encode(), check=True,
                          capture_output=True).stdout.decode().strip()


def _tree_entries(git: Git, rev: str, pathspec: list[str] | None = None):
    args = ["ls-tree", "-r", "-z", "--format=%(objectmode) %(objectname)\t%(path)", rev]
    if pathspec:
        args += ["--", *pathspec]
    out = git.run(*args, binary=True)
    for rec in out.split(b"\0"):
        if not rec.strip():
            continue
        meta, _, path = rec.partition(b"\t")
        mode, sha = meta.split()
        yield mode.decode(), sha.decode(), path.decode("utf-8", "replace")


_SELFTEST_HAY_CACHE: dict[str, Haystack] = {}


def _sweep_one(git, trunk_sha, trunk_hay, rev, include_docs):
    def mb_hay_for(mb):
        if mb not in _SELFTEST_HAY_CACHE:
            if mb == trunk_sha:
                _SELFTEST_HAY_CACHE[mb] = trunk_hay
            else:
                _SELFTEST_HAY_CACHE[mb] = build_haystack(git, mb)
        return _SELFTEST_HAY_CACHE[mb]

    return sweep_branch(git, trunk_sha, trunk_hay, rev, mb_hay_for, include_docs)


def cmd_selftest(a) -> int:
    git = Git(a.repo)
    trunk = git.rev_parse(a.trunk)
    base_old = git.rev_parse(a.base)
    print("trunk  %s" % trunk)
    print("base   %s  (%s)" % (base_old, a.base))
    trunk_hay = build_haystack(git, trunk, verbose=True)
    results: list[tuple[str, bool, str]] = []

    def check(name, ok, detail):
        results.append((name, bool(ok), detail))
        print("  %-4s %-46s %s" % ("PASS" if ok else "FAIL", name, detail))

    # ---- T0  the instrument is not in its own haystack ----------------------
    # Its fixtures are literals in SELF_PATH; indexed, they poison T1/T3/T5 (item 470).
    self_blob = git.run("ls-tree", trunk, "--", SELF_PATH).strip()
    if self_blob:
        self_toks = haystack_tokens(git.run("show", "%s:%s" % (trunk, SELF_PATH)))
        check("T0.self-not-in-haystack",
              all(SELFTEST_MARKERS[k] in self_toks for k in ("fn", "struct", "real"))
              and not any(SELFTEST_MARKERS[k] in trunk_hay.code for k in ("fn", "struct", "real")),
              "%s carries the fixtures; trunk_hay.code does not" % SELF_PATH)

    # ---- T0  anti-false-zero floors -------------------------------------
    print("\nT0 — floors (a small haystack manufactures false SURVIVORs)")
    check("T0.trunk-code-haystack", len(trunk_hay.code) > 100000,
          "%d code tokens over %d files" % (len(trunk_hay.code), trunk_hay.n_code_files))
    check("T0.trunk-doc-haystack", len(trunk_hay.docs) > 10000,
          "%d doc tokens over %d files" % (len(trunk_hay.docs), trunk_hay.n_doc_files))

    # ---- T1  KNOWN SURVIVOR ---------------------------------------------
    print("\nT1 — KNOWN SURVIVOR: symbols built to be absent from trunk")
    for k in ("fn", "struct", "test", "real", "phantom"):
        s = SELFTEST_MARKERS[k]
        check("T1.pre.%s-absent-from-trunk" % k,
              s not in trunk_hay.code and s not in trunk_hay.docs,
              "%r is in neither trunk code nor trunk docs" % s)
    t1_src = (
        "// bsweep selftest fixture\n"
        "pub fn %(fn)s() -> u64 { 7 }\n"
        "pub struct %(struct)s;\n"
        "pub const BSWEEP_SELFTEST_MSG: &str = \"%(lit)s\";\n"
        "#[cfg(test)]\nmod t {\n    #[test]\n    fn %(test)s() { assert_eq!(super::%(fn)s(), 7); }\n}\n"
    ) % SELFTEST_MARKERS
    t1 = _mk_commit(git, trunk, [("100644", _blob(git, t1_src),
                                  "crates/busbar-kernel/src/bsweep_selftest_t1.rs")],
                    "bsweep selftest T1")
    r1 = _sweep_one(git, trunk, trunk_hay, t1, False)
    names = {x["sym"] for x in r1["absent"]}
    check("T1.bucket", r1["bucket"] == "SURVIVOR", "bucket=%s in=%d absent=%d"
          % (r1["bucket"], r1["symbols_in"], r1["symbols_absent"]))
    for k in ("fn", "struct", "test", "lit"):
        check("T1.names.%s" % k, SELFTEST_MARKERS[k] in names,
              "reported %r" % SELFTEST_MARKERS[k])
    kinds = {x["sym"]: x["kind"] for x in r1["absent"]}
    check("T1.kind.test", kinds.get(SELFTEST_MARKERS["test"]) == "test",
          "test fn classified as %r" % kinds.get(SELFTEST_MARKERS["test"]))

    # ---- T2  KNOWN HARVESTED, AT A RENAMED PATH --------------------------
    print("\nT2 — KNOWN HARVESTED: everything trunk gained since base, RELOCATED")
    added = git.run("diff", "--name-only", "--diff-filter=A", base_old, trunk).split("\n")
    added = [p for p in added if p and not is_doc(p) and not is_binary_path(p)
             and not is_generated(p) and p != SELF_PATH]
    bysha = {p: (m, s) for m, s, p in _tree_entries(git, trunk)}
    ents, mapping = [], {}
    for p in added:
        if p not in bysha:
            continue
        mode, sha = bysha[p]
        ext = ("." + p.rsplit(".", 1)[1]) if "." in p.rsplit("/", 1)[-1] else ""
        q = "bsweep_relocated/" + p.replace("/", "__").replace(ext, "", 1) + ext
        ents.append((mode, sha, q))
        mapping[q] = p
    check("T2.pre.corpus", len(ents) > 500, "%d files relocated to new paths" % len(ents))
    t2 = _mk_commit(git, base_old, ents, "bsweep selftest T2")
    r2 = _sweep_one(git, trunk, trunk_hay, t2, False)
    check("T2.pre.novel", r2["symbols_in"] > 5000,
          "%d symbols novel vs merge-base" % r2["symbols_in"])
    check("T2.bucket", r2["bucket"] == "HARVESTED",
          "bucket=%s in=%d found=%d absent=%d"
          % (r2["bucket"], r2["symbols_in"], r2["symbols_found"], r2["symbols_absent"]))
    if r2["absent"]:
        print("       first absences (extractor asymmetry if non-empty):")
        for x in r2["absent"][:10]:
            print("         %-8s %-70s %r" % (x["kind"], x["path"][:70], x["sym"][:70]))
    check("T2.path-independence", all(p.startswith("bsweep_relocated/") for p in mapping),
          "every branch-side path differs from its trunk path (e.g. %s -> %s)"
          % (list(mapping.values())[0], list(mapping)[0]) if mapping else "n/a")

    # ---- T3  THE DOCS TRAP ------------------------------------------------
    print("\nT3 — THE DOCS TRAP: a symbol trunk DOCUMENTS and does not IMPLEMENT")
    trap = [s for s in (a.trap_symbols or ["RecordSink", "SinkRecordLegs"])]
    for s in trap:
        check("T3.pre.%s" % s, s in trunk_hay.docs and s not in trunk_hay.code,
              "in trunk docs=%s, in trunk code=%s"
              % (s in trunk_hay.docs, s in trunk_hay.code))
    t3_src = ("pub trait %s { fn sink_key(&self) -> u64; }\n"
              "pub struct %s;\n") % (trap[0], trap[1] if len(trap) > 1 else trap[0] + "Two")
    t3 = _mk_commit(git, base_old, [("100644", _blob(git, t3_src),
                                     "crates/busbar-contract/src/bsweep_selftest_t3.rs")],
                    "bsweep selftest T3")
    r3_ex = _sweep_one(git, trunk, trunk_hay, t3, False)
    r3_in = _sweep_one(git, trunk, trunk_hay, t3, True)
    check("T3.docs-EXCLUDED-is-SURVIVOR", r3_ex["bucket"] == "SURVIVOR",
          "bucket=%s absent=%d  <- correct" % (r3_ex["bucket"], r3_ex["symbols_absent"]))
    check("T3.docs-INCLUDED-is-HARVESTED", r3_in["bucket"] == "HARVESTED",
          "bucket=%s absent=%d  <- the inherited 33%% false-negative, reproduced"
          % (r3_in["bucket"], r3_in["symbols_absent"]))
    check("T3.bucket-CHANGES", r3_ex["bucket"] != r3_in["bucket"],
          "%s (docs excluded) vs %s (docs included)" % (r3_ex["bucket"], r3_in["bucket"]))
    check("T3.docs_only-flagged", r3_ex.get("docs_only_absent", 0) >= len(trap),
          "%d of %d absent symbols flagged docs_only"
          % (r3_ex.get("docs_only_absent", 0), r3_ex["symbols_absent"]))

    # ---- T4  NEGATIVE CONTROL: EMPTY --------------------------------------
    print("\nT4 — NEGATIVE CONTROL: a tool that always says SURVIVOR is not a check")
    r4a = _sweep_one(git, trunk, trunk_hay, trunk, False)
    check("T4a.trunk-vs-itself-EMPTY", r4a["bucket"] == "EMPTY",
          "bucket=%s in=%d" % (r4a["bucket"], r4a["symbols_in"]))
    relo = [(m, s, "bsweep_relocated_b/" + p.replace("/", "__"))
            for m, s, p in _tree_entries(git, trunk, ["crates/busbar-kernel/src"])][:60]
    t4b = _mk_commit(git, trunk, relo, "bsweep selftest T4b")
    r4b = _sweep_one(git, trunk, trunk_hay, t4b, False)
    check("T4b.pure-relocation-EMPTY", r4b["bucket"] == "EMPTY",
          "%d trunk files re-added at new paths -> bucket=%s in=%d"
          % (len(relo), r4b["bucket"], r4b["symbols_in"]))

    # ---- T5  PROSE IS NOT CODE --------------------------------------------
    print("\nT5 — PROSE IS NOT CODE: the docs trap at line scale")
    t5_src = (
        "pub fn %(real)s() -> u8 { 1 }\n"
        "// This comment mentions fn %(phantom)s and struct BsweepSelftestProseStructZqx\n"
        "//! and a doc-comment naming const BSWEEP_SELFTEST_PROSE_CONST_ZQX too.\n"
    ) % SELFTEST_MARKERS
    t5 = _mk_commit(git, trunk, [("100644", _blob(git, t5_src),
                                  "crates/busbar-kernel/src/bsweep_selftest_t5.rs")],
                    "bsweep selftest T5")
    r5 = _sweep_one(git, trunk, trunk_hay, t5, False)
    n5 = {x["sym"] for x in r5["absent"]}
    check("T5.real-decl-reported", SELFTEST_MARKERS["real"] in n5,
          "the one real declaration is a survivor")
    check("T5.prose-fn-NOT-reported", SELFTEST_MARKERS["phantom"] not in n5,
          "a symbol named only in a comment is not a declaration")
    check("T5.prose-struct-NOT-reported", "BsweepSelftestProseStructZqx" not in n5, "")
    check("T5.prose-const-NOT-reported", "BSWEEP_SELFTEST_PROSE_CONST_ZQX" not in n5, "")
    check("T5.exactly-one", r5["symbols_in"] == 1,
          "symbols_in=%d (expected 1)" % r5["symbols_in"])

    # ---- T6  KNOWN BLIND SPOTS — these PASS by REPRODUCING the limitation ----
    # A blind spot that is named and demonstrated is worth more than one that is
    # silent.  Each check below asserts that the tool MISSES something real.  If one
    # of these ever FAILS, the tool grew a new eye and this section is out of date.
    print("\nT6 — WHAT THE TOOL CANNOT SEE (each check asserts a MISS)")

    def _file(rev, path):
        return git.run("show", "%s:%s" % (rev, path))

    def _mutant(path, before, after, label):
        txt = _file(trunk, path)
        if before not in txt:
            check("T6.%s.anchor" % label, False,
                  "anchor %r not found in %s — the mutation never happened, so an EMPTY\n"
                  "       verdict below would be a FALSE ZERO, not a blind spot" % (before[:50], path))
            return None
        n = txt.count(before)
        check("T6.%s.anchor" % label, True, "%s carries the anchor %dx" % (path, n))
        return _mk_commit(git, trunk, [("100644", _blob(git, txt.replace(before, after, 1)), path)],
                          "bsweep selftest " + label)

    # (i) a removed clamp on a money path — no new name, no new literal
    m = _mutant("crates/busbar-kernel-ledger/src/usage/meter.rs",
                "reported.min(k)", "reported", "removed-clamp")
    if m:
        r = _sweep_one(git, trunk, trunk_hay, m, False)
        check("T6.removed-clamp.INVISIBLE", r["bucket"] == "EMPTY" and r["added_lines"] > 0,
              "a deleted .min() on a MONEY path -> bucket=%s (added_lines=%d, symbols_in=%d)"
              % (r["bucket"], r["added_lines"], r["symbols_in"]))

    # (ii) a wrapping money add replacing a saturating one
    m = _mutant("crates/busbar-kernel-ledger/src/cost/rate.rs",
                "acc.saturating_add(u128::from(quantity).saturating_mul(u128::from(nanos_per_unit)))",
                "acc + u128::from(quantity) * u128::from(nanos_per_unit)", "wrapping-add")
    if m:
        r = _sweep_one(git, trunk, trunk_hay, m, False)
        check("T6.wrapping-add.INVISIBLE", r["bucket"] == "EMPTY" and r["added_lines"] > 0,
              "saturating_add -> plain + on a MONEY path -> bucket=%s (added_lines=%d)"
              % (r["bucket"], r["added_lines"]))

    # (iii) a deletion on the branch
    victim = "crates/busbar-kernel-ledger/src/usage/meter.rs"
    m = _mk_commit(git, trunk,
                   [("0", "0" * 40, victim)], "bsweep selftest deletion")
    r = _sweep_one(git, trunk, trunk_hay, m, False)
    check("T6.deletion.INVISIBLE", r["bucket"] == "EMPTY",
          "branch DELETES %s -> bucket=%s (only `+` lines are read)"
          % (victim.rsplit("/", 1)[1], r["bucket"]))

    # (iv) whitespace / formatting only
    txt = _file(trunk, victim)
    reind = "".join(((("    " + ln) if ln.strip() else ln) + "\n") for ln in txt.split("\n"))
    m = _mk_commit(git, trunk, [("100644", _blob(git, reind), victim)],
                   "bsweep selftest whitespace")
    r = _sweep_one(git, trunk, trunk_hay, m, False)
    check("T6.whitespace.INVISIBLE", r["bucket"] == "EMPTY" and r["added_lines"] > 100,
          "every line re-indented -> bucket=%s over %d added lines (correctly ignored)"
          % (r["bucket"], r["added_lines"]))

    # (v) the branch's work LANDED on trunk under a DIFFERENT NAME -> false SURVIVOR
    src = _file(trunk, "crates/busbar-kernel-ledger/src/cost/rate.rs")
    renamed = src.replace("fn ", "fn zqx_", 1)
    m = _mk_commit(git, trunk, [("100644", _blob(git, renamed),
                                 "crates/busbar-kernel-ledger/src/cost/rate_branchside.rs")],
                   "bsweep selftest rename")
    r = _sweep_one(git, trunk, trunk_hay, m, False)
    names = {x["sym"] for x in r["absent"]}
    check("T6.renamed-on-trunk.FALSE-SURVIVOR",
          r["bucket"] == "SURVIVOR" and any(n.startswith("zqx_") for n in names),
          "identical body, one renamed fn -> bucket=%s naming %s — the tool CANNOT tell\n"
          "       \"never landed\" from \"landed under another name\""
          % (r["bucket"], sorted(n for n in names if n.startswith("zqx_"))))

    # (vi) a new field on an existing struct is not a declaration this tool reads
    txt2 = _file(trunk, "crates/busbar-kernel-ledger/src/usage/meter.rs")
    check("T6.struct-field.DOCUMENTED", True,
          "struct fields and enum variants are deliberately NOT needles (they collide "
          "with struct-literal initialisers and match arms)")

    # ---- T7  COUNTS ARE NOT CAPPED --------------------------------------
    # `absent` lists at most MAX_ABSENT_IN_ROW rows; the counts must cover every absence.
    print("\nT7 — COUNTS PAST THE ROW CAP: docs_only_absent and money_hits see every absence")
    n7 = MAX_ABSENT_IN_ROW + 137
    docs7 = {"bsweep_t7_docs_only_%d" % i for i in range(n7)}
    need7 = [Needle("bsweep_t7_docs_only_%d" % i, "fn", "crates/busbar-kernel-ledger/src/t7.rs", i)
             for i in range(n7)]
    s7 = summarise_absent(need7, docs7)
    check("T7.rows-capped", len(s7["absent"]) == MAX_ABSENT_IN_ROW
          and s7.get("absent_truncated") == n7 - MAX_ABSENT_IN_ROW,
          "rows=%d truncated=%s" % (len(s7["absent"]), s7.get("absent_truncated")))
    check("T7.docs_only-counts-all", s7["docs_only_absent"] == n7,
          "docs_only_absent=%d of %d docs-only absences" % (s7["docs_only_absent"], n7))
    check("T7.money-counts-all", s7["money_hits"] == n7,
          "money_hits=%d of %d money-path absences" % (s7["money_hits"], n7))

    git.close()
    bad = [n for n, ok, _ in results if not ok]
    print("\n%d checks, %d failed" % (len(results), len(bad)))
    if bad:
        print("FAILED: " + ", ".join(bad))
        return 1
    print("ALL FALSIFICATION CHECKS PASS")
    return 0


def _default_repo() -> str:
    """The repo `--repo` defaults to when neither it nor BSWEEP_REPO is set: the
    git worktree this script is being run from."""
    try:
        out = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                              capture_output=True, text=True, check=True)
        return out.stdout.strip() or os.getcwd()
    except Exception:
        return os.getcwd()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="branch-symbol-sweep", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=os.environ.get("BSWEEP_REPO", _default_repo()))
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sweep", help="sweep branches into a ledger")
    s.add_argument("--trunk", required=True, help="trunk ref or SHA (PIN IT)")
    s.add_argument("--ledger", required=True)
    s.add_argument("--branches", nargs="*", default=None)
    s.add_argument("--branches-file")
    s.add_argument("--glob", nargs="*", help="e.g. 'origin/delete/*'")
    s.add_argument("--slice", help="K/N — disjoint slice of the selection")
    s.add_argument("--limit", type=int)
    s.add_argument("--force", action="store_true", help="re-sweep rows already present")
    s.add_argument("--trunk-include-docs", action="store_true",
                   help="FALSIFICATION ONLY: re-open the 33%% docs false-negative")
    s.add_argument("--allow-trunk-drift", action="store_true")
    s.add_argument("--verbose", action="store_true")
    s.set_defaults(fn=cmd_sweep)

    r = sub.add_parser("report", help="bucket distribution from a ledger")
    r.add_argument("--ledger", required=True)
    r.add_argument("--trunk")
    r.add_argument("--glob", nargs="*")
    r.add_argument("--top", type=int, default=15)
    r.add_argument("--docs-included", action="store_true")
    r.set_defaults(fn=cmd_report)

    l = sub.add_parser("locate", help="where on trunk does a symbol live (code vs docs)")
    l.add_argument("--trunk", required=True)
    l.add_argument("symbol")
    l.add_argument("--max", type=int, default=12)
    l.set_defaults(fn=cmd_locate)

    t = sub.add_parser("selftest", help="run the falsification battery (creates NO refs)")
    t.add_argument("--trunk", required=True)
    t.add_argument("--base", default="v1.5.5",
                   help="an older ancestor of trunk, used as the merge-base for T2/T3")
    t.add_argument("--trap-symbols", nargs="*",
                   help="symbols known to be in trunk DOCS but not trunk CODE")
    t.set_defaults(fn=cmd_selftest)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
