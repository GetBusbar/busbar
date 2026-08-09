#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""PUBLIC-HYGIENE gate — nothing in a file a customer can read may describe how the software was
BUILT rather than what it DOES.

WHY THIS IS A GATE AND NOT A CLEANUP. busbar is sold to enterprises, and the repo, the docs site and
the generated `openapi.json` are all public. A reader who finds internal audit ids, a developer's
home directory or a TDD narration in a shipped file does not conclude "untidy"; they conclude the
product was assembled by a process they were not shown. That is a commercial fact about the product,
not a tidiness one, so it needs a control that holds forever rather than a sweep that holds until
the next commit.

Three manual sweeps across the public repos found, all at once: an internal design mockup live and
crawlable, a public README that was an internal design report, a developer home directory in two
public workflows, internal issue ids (`E-007`, `C6`, `self-service D2`) served inside operator-facing
API docs, and a shipped comment in which the author described their own working constraints. Every
one of those is a TEXT class. A sweep removes the instances; this removes the class.

WHAT IT JUDGES. Eleven rules, each derived from text that was actually found in this repo's history
rather than from imagination — see RULES below, where every rule carries the reason it exists. Each
rule is matched per LINE over the files a reader can actually get at, and each hit names the rule, so
a failure is always actionable rather than a vibe.

THE FALSE-POSITIVE CONTROLS ARE LOAD-BEARING. A gate that cries wolf gets switched off, and then it
protects nothing at all. Three controls are therefore treated as first-class requirements, each with
its own GREEN fixture in the self-test:

  * VENDOR AND PRODUCT NAMES. This is an LLM gateway: Anthropic, OpenAI, Claude, Claude Code and
    Gemini are things it ROUTES TO, and `Claude-on-Vertex` is a shipped feature name. No rule may fire
    on a provider name.
  * TECHNICAL INVARIANTS. `MUST be a no-op`, `fail closed`, `do not touch the breaker` describe CODE.
    The editor-directed rule only fires on prose whose object is THE FILE ITSELF ("do not revert this",
    "whoever touches this next"), which is why "do not touch the breaker" is silent and safe.
  * IDENTIFIERS AND TEST NAMES. A hit whose surrounding token is a snake_case identifier is dropped,
    so `fn red_before_green_guard()` and `const CARGO_MUTANTS_NOTE` are silent while the same words in
    prose are not.

IT CANNOT PASS WHILE DOING NOTHING. The failure mode this project has been bitten by repeatedly is a
gate that reports green having executed nothing, so:

  * discovering ZERO files is a HARD FAILURE (exit 2), never a pass — a bad `--root` cannot read as
    "clean";
  * the number of files scanned and rules applied is printed on EVERY run, so coverage is visible
    rather than assumed;
  * every pattern is compiled at import, so a malformed rule raises immediately instead of silently
    matching nothing;
  * `--selftest` requires every rule in the table to own BOTH a RED fixture that it flags and a GREEN
    twin that stays silent, and a rule with no fixture FAILS the self-test rather than being skipped.
    A rule never observed failing is not known to work.

SCOPE. What ships or is publicly visible: source and its comments, `scripts/`, `.github/`, `docs/`,
top-level markdown, `Cargo.toml` descriptions, and generated artifacts such as the admin
`openapi.json`. File discovery prefers `git ls-files`, which is the exact definition of "what the
public gets", and falls back to a filtered walk outside a git checkout. Lockfiles, `target/`, `.git/`,
minified vendor bundles and binary assets are excluded.

`--root` scopes the scan to one tree, which is what lets a plugin repo run this against its own
checkout from core's reusable workflow with no per-repo adoption work.

ESCAPE HATCH. `# public-hygiene-lint: allow — <reason>` on the offending line or the line above it.
Per-line, with a written reason, and still counted and reported, so an allow is a visible claim
somebody made rather than a silent hole.

USAGE
    public-hygiene-lint.py [--root <dir>] [--selftest] [--rules] [--quiet]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

# ── the escape hatch ───────────────────────────────────────────────────────────────────────────────
ALLOW = re.compile(r"public-hygiene-lint:\s*allow\s*[:—-]?\s*(.*)")

# This file IS the rule table: it necessarily contains a literal copy of every pattern it forbids, so
# it is the one file that cannot be scanned by itself. Named explicitly rather than by a wildcard, so
# the exemption cannot quietly grow.
SELF = "scripts/public-hygiene-lint.py"


class Pat:
    """One pattern, plus the optional line context that makes it precise.

    `require` and `forbid` are the difference between a rule and a nuisance: they let a pattern that
    would be far too broad on its own ("phase 2") fire only where the surrounding line proves it is
    the leak we mean, and stay silent where the same words are ordinary technical prose."""

    def __init__(self, rx, require=None, forbid=None, path_forbid=None, flags=re.I):
        self.rx = re.compile(rx, flags)
        self.require = re.compile(require, re.I) if require else None
        self.forbid = re.compile(forbid, re.I) if forbid else None
        # A pattern that is only sound in some FILE KINDS. The bare-section-reference pattern is the
        # motivating case: `§2` inside a published markdown doc is that doc pointing at its own
        # section (exactly what we want people to write), while the same token in a source comment
        # points at a document the reader has never seen.
        self.path_forbid = re.compile(path_forbid, re.I) if path_forbid else None

    def find(self, line, rel=""):
        if self.path_forbid and self.path_forbid.search(rel):
            return []
        if self.require and not self.require.search(line):
            return []
        if self.forbid and self.forbid.search(line):
            return []
        return list(self.rx.finditer(line))


class Rule:
    def __init__(self, rid, title, why, pats, skip_paths=None):
        self.id = rid
        self.title = title
        self.why = why
        self.pats = pats
        # A per-rule path exemption, for the case where a file's SUBJECT is the thing the rule names
        # (a script that runs cargo-mutants must be allowed to say "cargo-mutants").
        self.skip = re.compile(skip_paths, re.I) if skip_paths else None


# Algorithm names that are ALSO valid hex strings (`ed25519`, `deadbeef`-shaped constants, digest
# vocabulary). Any line carrying one is not a line citing a commit.
CRYPTO_WORDS = (r"sha-?\d|digest|checksum|blake|hmac|argon|scrypt|bcrypt|base64|"
                r"25519|secp\d|aes-?\d|chacha|poly\d")

# ── THE RULES ──────────────────────────────────────────────────────────────────────────────────────
# Every one of these is derived from text that was really present in this repo's public files. The
# `why` is what gets printed next to a hit, so the person who trips it learns the class rather than
# just the regex.
RULES = [
    Rule(
        "tdd-narration",
        "test-driven-development narration",
        "describes how the code was WRITTEN, not what it does; a reader of a shipped file is being "
        "shown our process instead of the software",
        # Deliberately NOT "goes RED" or "RED/GREEN discipline": in this repo those are ordinary CI
        # vocabulary for a gate's own pass/fail state (`plugins.yaml`, `config-stability-gate.sh`,
        # `release-check.sh` all use them correctly), and flagging them would make the gate a nuisance
        # on exactly the files that are most careful. Both are GREEN fixtures below.
        [
            Pat(r"RED[-_ ]before[-_ ]GREEN"),
            Pat(r"\bTDD\b", flags=0),
        ],
    ),
    Rule(
        "mutation-testing",
        "mutation-testing workflow leaked into shipped prose",
        "names an internal QA tool and the campaign it was run in; the shipped comment should state "
        "the invariant the test protects, not the harness that found the gap",
        [
            Pat(r"cargo[-_ ]mutants"),
            Pat(r"\bmutation[- ]testing\b"),
            Pat(r"\bkills?\s+(?:the\s+)?[^.\n]{0,40}\bmutants?\b"),
            Pat(r"\bsurviv(?:ing|ed|es)\s+mutants?\b"),
        ],
        # A file whose SUBJECT is the mutation-testing run may name the tool it runs. Basename-scoped,
        # so it exempts `scripts/run-mutants-ec2.sh` and nothing that merely mentions it in passing.
        skip_paths=r"(^|/)[^/]*mutants[^/]*$",
    ),
    Rule(
        "internal-issue-id",
        "internal issue / task / audit-round identifier",
        "cites a tracker or audit artifact the reader cannot open; `task #141` and `R27 #8` shipped "
        "inside operator-facing API documentation",
        [
            Pat(r"\b(?:task|item|finding|issue|defect|gap|guard|ticket)s?\s*#\s*\d+"),
            Pat(r"\b(?:round|wave|audit)\s*#?\s*\d+\b"),
            Pat(r"\bR\d{1,3}\s+(?:#\d+|LOW|MED|MEDIUM|HIGH|CRIT|CRITICAL)\b", flags=0),
            Pat(r"\bE-0\d{2}\b", flags=0),
            Pat(r"\bCFG-\d{1,3}\b", flags=0),
            Pat(r"\bcodeaudit\b"),
        ],
    ),
    Rule(
        "audit-finding-id",
        "bare audit finding identifier",
        "a one-or-two-letter-plus-number decision id (`C6`, `S1`, `self-service D2`) is meaningless "
        "outside the audit that assigned it, and was shipped in the public API spec",
        [
            # Context-carrying forms only. A bare `[A-Z]\d` token on its own is far too common in real
            # technical prose (`H2`, `S3`, `P95`) to be a rule; each of these carries the phrasing that
            # makes it a CITATION rather than a name. The id SHAPE is `C6` / `R27` / `E-007` — a
            # hyphen is admitted only before a zero-padded triple, so the arithmetic `(N-1)` in
            # `hash & (N-1)` is not an audit id. (It was, in the first draft of this rule.)
            Pat(r"(?:would have caught|filed against|self-service|covers|per)\s+[A-Z]{1,2}(?:\d{1,3}|-\d{3})\b",
                flags=0),
            Pat(r"\b(?:the|a)\s+[A-Z]{1,2}(?:\d{1,3}|-\d{3})\s+(?:class|concern|finding|decision|item)\b",
                flags=0),
            # The bare parenthetical id. Audit ids are short (`C6`, `S1`, `R27`, `E-007`); the two
            # exclusions are the vendor error code (`GH013`) and the latency percentile (`P95`),
            # both of which are real technical tokens that wear the same shape.
            Pat(r"[(,;]\s*(?!P(?:50|95|99)\b|GH\d)[A-Z]{1,2}(?:\d{1,2}|-\d{3})\s*\)", flags=0),
            # THE WORD `auditor` MAKES IT A CITATION, whatever the id looks like. The three patterns
            # above all lean on the id SHAPE (`C6`, `R27`, `E-007`), and shape-matching has a tail:
            # `auditor MCP-2 M` and `(auditor MCP-1 H9)` are audit findings cited exactly the same
            # way, and both slip past every one of them. `auditor` followed by anything id-shaped
            # needs no heuristic — the phrasing already says it is a reference to an audit the reader
            # has never seen.
            Pat(r"\bauditor\s+[A-Za-z]{1,4}[-\s]?\d", flags=re.I),
        ],
    ),
    Rule(
        "private-doc-reference",
        "pointer to an unpublished internal document",
        "sends a public reader to a document they cannot open; section references to REAL in-repo "
        "docs and to RFCs are deliberately kept",
        [
            Pat(r"\b(?:the\s+)?companion\s+design\b"),
            Pat(r"\bdesign\s*(?:doc(?:ument)?\b|§)"),
            Pat(r"\bENGINE-BUGS\.md\b"),
            Pat(r"[A-Za-z0-9_-]+-SPEC\.md\b"),
            Pat(r"\bbusbarAI-private\b|\b_handoffs\b"),
            # PRIVATE DESIGN DOCUMENTS, BY NAME. These have to be listed explicitly, and the reason
            # is a false negative this rule carried until 2026-08-09: the `§` pattern below EXEMPTS
            # any line containing `.md`, because naming a real in-repo doc beside a section number is
            # exactly the citation we want people to keep writing. The exemption could not tell a
            # PUBLIC doc from a PRIVATE one, so `mcp-design.md §5.1` sailed through while a bare
            # `§5.1` was caught — handing the reader the precise filename of a document they cannot
            # open, which is a WORSE leak than the dangling reference the rule does catch.
            Pat(r"\b(?:mcp|a2a|smart-router|config-redesign)-design\.md\b"),
            Pat(r"\baudit-decisions[A-Za-z0-9_.-]*\.md\b"),
            Pat(r"\b\d+\.\d+\.\d+-(?:design|dev|brief|DECISIONS)[A-Za-z0-9_.-]*\.md\b"),
            # A DANGLING THREAT-CATALOGUE ROW. `threat 17` is a row of the private threat→defence
            # table, cited the same way a `§` is and leaking the same way, in a shape the section
            # pattern does not match. `threat model` / `threat surface` as prose is fine and is not
            # matched: this is specifically a NUMBERED row.
            Pat(r"\bthreat\s+\d+\b", forbid=r"THREAT_MODEL\.md\b|\bdocs/"),
            # A DANGLING section reference: `§9.1` with nothing on the line saying which document. A
            # line that names a real in-repo doc, a docs/ path or an RFC is exactly the citation we
            # want people to keep writing, so it is excluded — and so is every prose file, where a
            # bare `§2` is the document pointing at its OWN section (`docs/migration-1.3.md` does
            # exactly that, correctly). What remains is a source comment citing a section of
            # something the reader has never seen.
            Pat(r"§\s*\d+(?:\.\d+)*",
                # Citing a PUBLISHED standard by section is exactly right and must never be
                # discouraged: auth-oidc cites `OIDC Core 1.0 §3.1.3.7` correctly.
                forbid=r"\.md\b|\bRFC\b|\bdocs/|\bhttps?://|\bOIDC\b|\bOpenID\b|\bOAuth\b|\bSAML\b|"
                       r"\bJWT\b|\bJWS\b|\bJOSE\b|\bIETF\b|\bW3C\b|\bECMA\b|\bPOSIX\b|\bUnicode\b|"
                       r"\bISO[ -]?\d",
                path_forbid=r"\.(md|rst|txt|html?)$"),
        ],
    ),
    Rule(
        "phase-plan",
        "internal delivery-plan vocabulary",
        "phases, units and numbered features are how the WORK was organised; none of it is a "
        "property of the running software",
        [
            Pat(r"\bFeature-\d+\b"),
            Pat(r"\bphase[-_ ]plan\b"),
            Pat(r"\b(?:unit|milestone)\s+[A-Z]\b", flags=0),
            # `phase 2` is legitimate technical prose (a two-phase commit, a handshake phase), so this
            # one fires only where the line also carries plan vocabulary.
            Pat(r"\bphase\s+\d+(?:\.\d+)?\b",
                require=r"\bdesign|\bplan\b|\bbrief\b|\bscope\b|\baudit|\bround\b|deliverable"),
        ],
    ),
    Rule(
        "editor-directed",
        "prose addressed to whoever edits the file next",
        "speaks to a future maintainer instead of describing the software; the object is the FILE, "
        "which is what keeps invariant prose like `do not touch the breaker` silent",
        [
            Pat(r"\bif you(?:'re| are)\s+tempted\b"),
            Pat(r"\b(?:do not|don't|never)\s+revert\s+this\b"),
            Pat(r"\b(?:do not|don't)\s+[\"“']?fix[\"”']?\s+this\b"),
            Pat(r"\bread\s+this\s+(?:first|before)\b"),
            Pat(r"\bleave\s+this\s+(?:alone|as[- ]is)\b"),
            Pat(r"\bwhoever\s+(?:touches|edits|reads|changes)\s+this\b"),
            Pat(r"\bbefore\s+you\s+(?:change|touch|edit|delete)\s+this\b"),
            Pat(r"\bthe\s+next\s+person\s+(?:who|to)\b"),
            Pat(r"\b(?:do not|don't)\s+(?:change|touch|delete|remove)\s+this\s+"
                r"(?:line|comment|test|block|file|function|assertion)\b"),
        ],
    ),
    Rule(
        "authoring-meta",
        "meta-commentary on how the change was authored",
        "narrates the authoring transaction (who asked, what was in scope, who decides); a shipped "
        "file should carry no evidence that it was commissioned at all",
        [
            Pat(r"\bas instructed\b"),
            Pat(r"\b(?:per|in|from) the brief\b"),
            # `as requested` is real English in a gateway ("the encoding as requested by the client"),
            # so the standalone, clause-final form is the only one that fires.
            Pat(r"\bas requested\b(?!\s+(?:by|in|via|from|through|the|with))"),
            Pat(r"\b(?:the|an?)\s+agents?\s+(?:that|who)\s+(?:authored|wrote|generated|produced)\b"),
            Pat(r"\bnot\s+made\s+unilaterally\b"),
            Pat(r"\b(?:product\s+)?call\s+for\s+a\s+human\b"),
            Pat(r"\bout of scope for this (?:pass|brief|task|change)\b"),
            # "as an AI" is the classic tell, but busbar IS marketed as "an AI control plane", so
            # only the SELF-REFERENTIAL form (followed by a clause break or a first-person subject)
            # fires. Both marketing files that say "as an AI control plane" are GREEN.
            Pat(r"\bas an AI\b(?=[,.;]|\s+(?:I\b|model\b|language\b|assistant\b))"),
            Pat(r"\bthis assistant\b"),
        ],
    ),
    Rule(
        "personal-identifier",
        "a named individual addressed in source",
        "a shipped file naming a person and what they asked for reads as a private conversation the "
        "customer was accidentally shown",
        [
            Pat(r"\b(?:Matthew|Matt)\b(?:'s\b|\s+(?:asked|wants|said|requested|prefers|decided|"
                r"wanted|noted|flagged|approved|confirmed))", flags=0),
            Pat(r"\bper\s+(?:Matthew|Matt)\b", flags=0),
        ],
    ),
    Rule(
        "machine-path",
        "a developer home directory",
        "an absolute path under a personal home directory names a person AND a machine, and two "
        "public workflows shipped one",
        [
            # Known SERVICE accounts are machine constants, not people: GitHub's hosted runners are
            # `/home/runner` and `/Users/runner`, and container images use a handful of standard ones.
            Pat(r"/Users/(?!(?:runner|Shared|shared)\b)[A-Za-z0-9._-]+/", flags=0),
            Pat(r"/home/(?!(?:runner|ubuntu|root|node|app|user|nonroot|vscode|linuxbrew|circleci|"
                r"jenkins|gitpod|wiremock|container)\b)[A-Za-z0-9._-]+/", flags=0),
        ],
    ),
    Rule(
        "commit-hash-citation",
        "bare commit-hash citation in prose",
        "a hash resolves only against history the reader does not have; name the behaviour or the "
        "release instead",
        [
            # `ed25519` is seven hex characters. So are a lot of algorithm names, which is why the
            # crypto vocabulary is an explicit exclusion rather than a hope.
            Pat(r"\b(?:commit|sha|rev|revision|fixed in|landed in|introduced in|reverted in)\s+"
                r"[`\"']?(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}\b",
                forbid=CRYPTO_WORDS),
            Pat(r"\(\s*(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{7,12}\s*\)",
                forbid=CRYPTO_WORDS + r"|0x"),
        ],
    ),
]

RULES_BY_ID = {r.id: r for r in RULES}
if len(RULES_BY_ID) != len(RULES):  # a duplicated id would silently shadow a rule's fixtures
    raise SystemExit("public-hygiene-lint: duplicate rule id in RULES")


# ── file discovery ─────────────────────────────────────────────────────────────────────────────────
# What a reader can get at: shipped source, the comments inside it, the workflows, the docs, and the
# generated artifacts. Extension-scoped so a binary asset is never read as text.
TEXT_EXTS = (
    ".rs", ".py", ".sh", ".bash", ".toml", ".yaml", ".yml", ".json", ".md", ".mjs", ".js", ".ts",
    ".tsx", ".jsx", ".html", ".htm", ".css", ".scss", ".sql", ".txt", ".service", ".conf", ".cfg",
    ".ini", ".env-example", ".proto", ".graphql", ".xml", ".rst", ".astro", ".vue", ".svelte",
)
TEXT_NAMES = ("Dockerfile", "Makefile", "LICENSE", "NOTICE", "CODEOWNERS", "Justfile")
SKIP_DIRS = {".git", "target", "node_modules", ".venv", "venv", "vendor", "dist", "build", ".cargo",
             "__pycache__", ".next", ".svelte-kit", ".wrangler", ".idea", ".vscode", ".claude"}
# Lockfiles and machine-emitted bundles: enormous, unreadable, and not prose anyone judges us on.
SKIP_FILES = re.compile(
    r"(^|/)(Cargo\.lock|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|"
    r"[^/]*\.min\.(js|css)|[^/]*\.bundle\.js|[^/]*\.map)$")


# Verbatim historical artifacts. `tests/migration-corpus/` holds the config files EXACTLY as each
# release shipped them, so the migrator can be proven still to handle them. They are evidence, not
# prose: scrubbing a phrase out of a 2026 config to satisfy a rule written in 2026 would corrupt the
# very thing the corpus exists to preserve, and the corpus README says in terms that the fix for a
# failure there is the migrator, never the file.
SKIP_PATHS = re.compile(r"(^|/)tests/migration-corpus/")


def is_text_candidate(rel):
    base = os.path.basename(rel)
    if SKIP_FILES.search(rel) or SKIP_PATHS.search(rel):
        return False
    if any(part in SKIP_DIRS for part in rel.split("/")):
        return False
    return base in TEXT_NAMES or base.startswith("Dockerfile") or rel.endswith(TEXT_EXTS)


def git_files(root):
    """`git ls-files` is the exact definition of "what the public gets" — it is the set the remote
    serves. Returns None (not an empty list) when this is not a git checkout, so the caller can tell
    "not a repo" apart from "a repo with no files", which is the difference between falling back and
    failing."""
    try:
        r = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, text=True,
                           timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return [p for p in r.stdout.split("\0") if p]


def walk_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            out.append(os.path.relpath(os.path.join(dirpath, f), root))
    return out


def discover(root):
    """-> (sorted relative paths, how they were found). ZERO files is never returned as success; the
    caller turns it into a hard failure, because a mistyped `--root` must not read as "clean"."""
    listing, how = git_files(root), "git ls-files"
    if listing is None:
        listing, how = walk_files(root), "filesystem walk (not a git checkout)"
    keep = []
    for rel in listing:
        rel = rel.replace(os.sep, "/")
        if rel == SELF or not is_text_candidate(rel):
            continue
        p = os.path.join(root, rel)
        if os.path.isfile(p) and not os.path.islink(p):
            keep.append(rel)
    return sorted(set(keep)), how


# ── matching ───────────────────────────────────────────────────────────────────────────────────────
IDENT_CHARS = re.compile(r"[A-Za-z0-9_]")


def in_identifier(line, start, end):
    """True when the match is part of a snake_case identifier rather than prose.

    This is the control that keeps test names and constants silent: `fn red_before_green_guard()` and
    `const CARGO_MUTANTS_NOTE` contain the flagged words, but a maintainer reading them learns nothing
    about our process — they are names. Expanding to the surrounding word-token and requiring an
    underscore is what distinguishes the two, and the flagged words are deliberately written to match
    across `-`, `_` and space so that this control is REACHED (and therefore tested) rather than
    bypassed by the pattern simply not matching."""
    l, r = start, end
    while l > 0 and IDENT_CHARS.match(line[l - 1]):
        l -= 1
    while r < len(line) and IDENT_CHARS.match(line[r]):
        r += 1
    tok = line[l:r]
    return tok != line[start:end] and "_" in tok


class Hit:
    def __init__(self, path, lineno, rule, text, excerpt):
        self.path, self.lineno, self.rule = path, lineno, rule
        self.text, self.excerpt = text, excerpt


def scan_text(rel, body):
    """Every rule against every line of one file -> (hits, allowed)."""
    hits, allowed = [], []
    lines = body.split("\n")
    for i, line in enumerate(lines):
        if len(line) > 4000:  # a minified or generated one-liner: not prose anyone reads
            continue
        for rule in RULES:
            if rule.skip and rule.skip.search(rel):
                continue
            for pat in rule.pats:
                for m in pat.find(line, rel):
                    if in_identifier(line, m.start(), m.end()):
                        continue
                    excerpt = line.strip()
                    if len(excerpt) > 160:
                        excerpt = excerpt[:157] + "..."
                    h = Hit(rel, i + 1, rule, m.group(0), excerpt)
                    a = ALLOW.search(line) or (i and ALLOW.search(lines[i - 1]))
                    if a:
                        h.excerpt = (a.group(1).strip() or "no reason given")
                        allowed.append(h)
                    else:
                        hits.append(h)
                    break  # one hit per rule per line: a report, not a wall
                else:
                    continue
                break
    return hits, allowed


def scan(root, out=sys.stdout, quiet=False):
    """-> (hits, allowed, files, how). Raises SystemExit(2) on an empty scan — see the module
    docstring: a gate that can pass having read nothing is worse than no gate."""
    files, how = discover(root)
    if not files:
        out.write(f"  public-hygiene-lint: NO FILES FOUND under {root} ({how}).\n"
                  "  That is a HARD FAILURE, not a pass — check --root.\n")
        raise SystemExit(2)
    hits, allowed = [], []
    for rel in files:
        try:
            with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
                body = fh.read()
        except OSError:
            continue
        h, a = scan_text(rel, body)
        hits += h
        allowed += a
    if not quiet:
        out.write(f"  scanned {len(files)} file(s) via {how}; {len(RULES)} rules applied\n")
    return hits, allowed, files, how


def report(hits, allowed, out=sys.stdout):
    by_rule = {}
    for h in hits:
        by_rule.setdefault(h.rule.id, []).append(h)
    for rid in sorted(by_rule):
        rule = RULES_BY_ID[rid]
        out.write(f"\n  [{rid}] {rule.title} — {len(by_rule[rid])} hit(s)\n")
        out.write(f"      why: {rule.why}\n")
        for h in by_rule[rid]:
            out.write(f"      {h.path}:{h.lineno}: {h.excerpt}\n")
    for h in allowed:
        out.write(f"  allowed  {h.path}:{h.lineno} [{h.rule.id}] — {h.excerpt}\n")


# ── SELF-TEST — every rule with a RED fixture and a GREEN twin ──────────────────────────────────────
# One entry per rule, keyed by rule id, checked for COMPLETENESS against the table above: a rule with
# no fixture fails the self-test rather than being quietly skipped. RED must be flagged BY THAT RULE;
# GREEN must be silent under EVERY rule, which is what makes the green side a real control and not a
# weaker copy of the red one.
FIXTURES = {
    "tdd-narration": (
        "// RED-BEFORE-GREEN: the pre-fix branch returned None here, so this assertion failed.\n"
        "// Proven by TDD before the fix landed.\n",
        "// The pre-1.5.3 branch returned None here; this asserts the 1.5.3 behaviour instead.\n"
        "fn red_before_green_guard() {}\n"
        "const TDD_NOTE: &str = \"x\";\n"
        "// The registry gate goes RED until every consumer is wired, and its own self-test proves\n"
        "// the classifier's RED/GREEN discipline before its verdict is trusted.\n",
    ),
    "mutation-testing": (
        "// cargo-mutants flags this comparison; the test below kills the `<=` mutant.\n",
        "// `<` and `<=` are behaviourally distinct here: an exactly-at-limit request must be\n"
        "// admitted, and the test below pins that boundary.\n"
        "fn cargo_mutants_note() {}\n",
    ),
    "internal-issue-id": (
        "/// The declared-signal bag (task #141): request-phase entries a hook may emit.\n"
        "// R27 #8 and the CFG-12 gate catalog entry both land here. E-007 filed against it.\n",
        "/// The declared-signal bag: the request-phase entries a hook may emit.\n"
        "// RFC 7231 section 5.2 governs the header this parses.\n"
        "fn task_141_signal_bag() {}\n",
    ),
    "audit-finding-id": (
        "/// `allowed_scopes` OMITTED = ALL scopes of every kind (C6).\n"
        "// MINT-TIME group resolution (self-service D2): a bound group must exist now.\n"
        "// The assertion that would have caught D4 (a leaked temp on a pre-rename error).\n"
        # Shape-matching has a tail: these two are audit findings cited identically and slipped
        # past every shape pattern, because `MCP-2 M` and `MCP-1 H9` are not `C6`.
        "// Auditor MCP-2 M is the finding, and this module is where it lands.\n"
        "// The stdio child is net-new engine surface (auditor MCP-1 H9).\n",
        "/// `allowed_scopes` OMITTED = ALL scopes of every kind; an explicit `[]` = none.\n"
        "// The assertion that pins the leaked-temp case: a failed write leaves no `.tmp`.\n"
        "// Serves HTTP/2 (h2) and falls back to HTTP/1.1.\n"
        "// A power of two, so `hash & (N-1)` selects the shard with a mask and no modulo.\n"
        "let idx = hash & (N-1);\n"
        "// The PAT is refused (GH013) when the tag already exists.\n"
        "// Tail latency for this lane (P95), sampled per minute.\n",
    ),
    "private-doc-reference": (
        "// See the companion design's section on projections, and design doc section 5.\n"
        "// Filed in busbar-ui/docs/ENGINE-BUGS.md and plugin-settings-schema-SPEC.md.\n"
        "// The ceiling rule is stated at §9.1.\n"
        # The false negative this rule carried until 2026-08-09. Naming the private document is a
        # WORSE leak than a dangling `§`, and the `.md` exemption used to wave it through.
        "// `mcp-design.md` §5.1 locks the config block as `tools:`.\n"
        "// The trust lifecycle is a2a-design.md §6.1's contract, parameterised.\n"
        "// Recorded in audit-decisions-1.5.3.md as the resolved reading.\n"
        "// The rationale is 1.5.4-design.md §3, which this mirrors.\n"
        # A numbered row of the private threat catalogue, leaking the same way a `§` does.
        "// This fallback IS threat 17: the caller's own credential, silently substituted.\n",
        "// See docs/admin-api.md §5 for the projection rules this implements.\n"
        "// RFC 7231 §5.2 defines the negotiation this follows.\n"
        "// For the MULTI-VALUED array form, OIDC Core 1.0 §3.1.3.7 is the governing rule.\n"
        # `threat` as prose, and the PUBLISHED threat model, must both keep working.
        "// The threat model for this path is the confused deputy, not replay.\n"
        "// THREAT_MODEL.md numbers this threat 3; the defence is the audience check.\n",
    ),
    "phase-plan": (
        "/// The Feature-2 decision-observability catalog; 1.5.3 unit G covers the gate.\n"
        "// Deferred to phase 3.5 of the delivery plan.\n",
        "// The two-phase commit below writes the temp first, then renames.\n"
        "// Handshake phase 2 sends the client hello.\n",
    ),
    "editor-directed": (
        "// If you are tempted to simplify this, do not revert this ordering. Read this first.\n"
        "// Whoever touches this next: leave this alone.\n",
        "// Reordering these two writes reintroduces the torn-state window: the rename MUST be a\n"
        "// no-op when the temp is absent, and the breaker must fail closed, so do not touch the\n"
        "// breaker from this path.\n",
    ),
    "authoring-meta": (
        "// Left as instructed; per the brief this is out of scope for this pass, and the wider\n"
        "// change is a product call for a human, not made unilaterally here.\n",
        "// Narrowed deliberately: widening it would change the wire contract, which is a\n"
        "// compatibility decision this change does not make.\n"
        "// Returns the encoding as requested by the client.\n"
        "// Busbar sits in the middle as an AI control plane and translates losslessly.\n",
    ),
    "personal-identifier": (
        "// Matthew asked for the ceiling to be inclusive, so the bound is <=.\n"
        "// Matthew's bar for this is a clean boot.\n",
        "// The ceiling is inclusive: an exactly-at-limit request is admitted.\n"
        "// git config user.name \"Matthew Jackson\"  # the release bot identity\n",
    ),
    "machine-path": (
        "- run: cp -r /Users/dev/Developer/busbarAI/target/x .\n"
        "- run: install -m 0755 /home/dev/bin/busbar /usr/local/bin/busbar\n",
        "- run: cp -r /home/runner/work/busbar/target/x .\n"
        "- run: install -m 0755 /Users/runner/work/busbar/bin/busbar /usr/local/bin/busbar\n"
        "- run: docker run -v ./fixtures:/home/wiremock/mappings:ro wiremock\n",
    ),
    "commit-hash-citation": (
        "// Fixed in 4bb03d7 after the parser regressed; see commit 53d5774bd70db8.\n"
        "// The prior behaviour (2789501) allowed it.\n",
        "// Fixed in 1.5.3 after the parser regressed; the prior behaviour allowed it.\n"
        "// The digest is sha256(prev_hash | seq | ts) and is compared in constant time.\n"
        "//! A signed token: (ed25519), two base64url segments, busbar on both ends.\n",
    ),
}

# Extra GREEN controls that are about the FILE KIND rather than one rule, so they cannot live in a
# rule's twin. Both are real text from this repo that an earlier draft of the gate flagged.
EXTRA_GREEN = {
    # A published doc pointing at its OWN section is the citation style we want people to keep.
    "self-reference.md": (
        "Move your logic into a small socket hook binary and register it as in §2.\n"
        "See §4.1 for the rollback path.\n"
    ),
    # Release automation that legitimately configures a human's git identity: a NAME is not the leak,
    # a name plus what that person asked for is.
    "release-bot.yml": (
        "      - run: |\n"
        "          git config user.name \"Matthew Jackson\"\n"
        "          git config user.email \"matthew@example.com\"\n"
    ),
}

# An allow-marker fixture: the escape hatch must be PROVEN to work, or the first legitimate exception
# turns into an argument for switching the whole gate off.
ALLOWED_FIXTURE = (
    "// public-hygiene-lint: allow — this file documents the lint's own vocabulary\n"
    "// RED-BEFORE-GREEN narration, deliberately quoted.\n"
)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def selftest(out=sys.stdout):
    out.write("\n== public-hygiene-lint SELF-TEST (every rule proven RED, every twin proven GREEN) ==\n")
    tree = tempfile.mkdtemp(prefix="busbar-public-hygiene-selftest-")
    try:
        fail = 0

        # (0) COMPLETENESS — a rule with no fixture is a rule nobody has ever seen work.
        missing = [r.id for r in RULES if r.id not in FIXTURES]
        orphan = [k for k in FIXTURES if k not in RULES_BY_ID]
        if missing or orphan:
            out.write(f"  FIXTURE COVERAGE FAILED: rules with no fixture {missing}; "
                      f"fixtures with no rule {orphan}\n")
            return 1
        out.write(f"  COVERAGE: all {len(RULES)} rules carry a RED fixture and a GREEN twin\n")

        written = 0
        for rid, (red, green) in FIXTURES.items():
            write(os.path.join(tree, "red", rid + ".rs"), red)
            write(os.path.join(tree, "green", rid + ".rs"), green)
            written += 2
        for name, body in EXTRA_GREEN.items():
            write(os.path.join(tree, "green", name), body)
            written += 1
        write(os.path.join(tree, "green", "allowed.rs"), ALLOWED_FIXTURE)
        written += 1

        hits, allowed, files, how = scan(tree, out=out, quiet=True)

        # (1) FLOOR — the scanner must actually have READ the fixtures. Without this the two
        #     assertions below both pass vacuously on an empty file list.
        want_files = written
        if len(files) != want_files:
            fail = 1
            out.write(f"  FLOOR FAILED: expected {want_files} fixture files, discovered "
                      f"{len(files)} ({how})\n")
        else:
            out.write(f"  FLOOR: all {len(files)} fixture files discovered and read ({how})\n")

        # (2) RED — every rule flags ITS OWN fixture. Flagged by some other rule does not count.
        red_ok, red_bad = 0, []
        for rid in FIXTURES:
            mine = [h for h in hits if h.path == f"red/{rid}.rs" and h.rule.id == rid]
            if mine:
                red_ok += 1
            else:
                other = sorted({h.rule.id for h in hits if h.path == f"red/{rid}.rs"})
                red_bad.append((rid, other))
        if red_bad:
            fail = 1
            out.write("  RED FAILED: these rules did not flag their own fixture "
                      f"(rules that did fire, if any, in brackets): {red_bad}\n")
        else:
            out.write(f"  RED: {red_ok}/{len(RULES)} rules flagged their own planted fixture\n")

        # (3) GREEN — the twins are silent under EVERY rule, including the false-positive controls:
        #     vendor/product names, technical invariants, and identifiers that merely contain a
        #     flagged word.
        loud = [(h.path, h.rule.id, h.excerpt) for h in hits if h.path.startswith("green/")]
        if loud:
            fail = 1
            out.write(f"  GREEN FAILED: {len(loud)} false positive(s) on the control twins:\n")
            for p, rid, ex in loud:
                out.write(f"      {p} [{rid}]: {ex}\n")
        else:
            out.write(f"  GREEN: {len(RULES)} twins + {len(EXTRA_GREEN)} file-kind controls silent — "
                      "vendor names (Anthropic, OpenAI, Claude, Claude Code, Gemini, "
                      "Claude-on-Vertex), technical invariants (`MUST be a no-op`, `fail closed`, "
                      "`do not touch the breaker`), identifiers/test names carrying a flagged word, "
                      "CI RED/GREEN vocabulary, "
                      "`hash & (N-1)`, `(ed25519)`, a doc citing its own §2 and a release bot's "
                      "git identity all stayed silent\n")

        # (4) The escape hatch works, and is REPORTED rather than invisible.
        if len(allowed) == 1 and allowed[0].path == "green/allowed.rs":
            out.write("  ALLOW: the `# public-hygiene-lint: allow — <reason>` marker suppressed its "
                      "hit and the suppression is still reported\n")
        else:
            fail = 1
            out.write(f"  ALLOW FAILED: expected exactly one reported allow, got "
                      f"{[(h.path, h.rule.id) for h in allowed]}\n")

        # (5) The empty-scan HARD FAILURE. A mistyped --root must not read as clean, and the only
        #     honest way to know that is to point the scanner at an empty tree and require it to die.
        empty = tempfile.mkdtemp(prefix="busbar-public-hygiene-empty-")
        try:
            devnull = open(os.devnull, "w")
            try:
                scan(empty, out=devnull, quiet=True)
                fail = 1
                out.write("  EMPTY FAILED: a scan that found zero files returned success\n")
            except SystemExit as e:
                if e.code == 2:
                    out.write("  EMPTY: a scan that discovers zero files exits 2 (hard failure), so "
                              "a mistyped --root can never read as clean\n")
                else:
                    fail = 1
                    out.write(f"  EMPTY FAILED: expected exit 2, got {e.code}\n")
            finally:
                devnull.close()
        finally:
            shutil.rmtree(empty, ignore_errors=True)

        out.write(f"  self-test: {len(RULES)} rules, {red_ok} red fixtures flagged, "
                  f"{len(RULES) - len({p for p, _, _ in loud})} green twins silent\n")
        if fail:
            out.write("  public-hygiene-lint SELF-TEST FAILED — this gate would not catch what it "
                      "claims to, or would cry wolf on legitimate text\n")
            return 1
        out.write("  ok\n")
        return 0
    finally:
        shutil.rmtree(tree, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=".", help="tree to scan (default: cwd)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--rules", action="store_true", help="print the rule table and exit")
    ap.add_argument("--quiet", action="store_true", help="only print failures")
    a = ap.parse_args()

    if a.rules:
        for r in RULES:
            print(f"{r.id:24s} {r.title}\n{'':24s} why: {r.why}\n")
        return 0
    if a.selftest:
        return selftest()

    root = os.path.abspath(a.root)
    if not a.quiet:
        print(f"\n== public-hygiene: what a customer reads, in {root} ==")
    hits, allowed, files, _how = scan(root, quiet=a.quiet)
    report(hits, allowed)
    print("\n== result ==")
    print(f"  {len(files)} public file(s) scanned against {len(RULES)} rules — "
          f"{len(hits)} hit(s), {len(allowed)} allowed")
    if hits:
        print("  public-hygiene-lint FAILED")
        print("  These lines describe how the software was BUILT, not what it does, in files a")
        print("  customer can read. Rewrite the text to state the behaviour or the invariant; if a")
        print("  line is genuinely legitimate, mark it:")
        print("    # public-hygiene-lint: allow — <why this text belongs in a public file>")
        return 1
    print("  public-hygiene-lint passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
