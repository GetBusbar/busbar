#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""EXECUTABLE-config drift gate — every busbar config that a machine actually RUNS, through the
real `busbar --validate`.

THE GAP THIS CLOSES. Every pre-existing gate on config grammar is scoped to DOCS:

  * `crates/busbar/tests/docs_examples.rs` validates `<!-- doc-check: config -->` blocks in `docs/**`;
  * marketing's `check-config-blocks.mjs` validates the blocks it PUBLISHES.

Nothing has ever looked at the configs that are EXECUTED — the `cat > config.yaml <<EOF` heredocs in
CI workflows and shell scripts, the config strings baked into Rust integration tests, the yaml under
`examples/**` and `docker/**`. Those are precisely the ones that rot: a docs example is read by a
human every release, an e2e heredoc is read by nobody until an engine upgrade refuses to boot it.

The 1.5.3 retired-auth-grammar defect was found in a long list of plugin repos AND in core's own
`plugin-ci.yml` — and in EVERY case the offending config was an executable one, invisible to both
docs gates. This scans that surface.

HOW IT JUDGES — the real binary, never a reimplementation. Extracted documents are handed to the
compiled `busbar --validate`, exactly the way `docs_examples.rs` does it. A reimplementation of
`detect_legacy_markers` would drift from the engine within one release and give false confidence;
this cannot, because it IS the engine.

`--validate` RESOLVES built-in secret refs: `{ env: VAR }` is read from the environment and
`{ file: /path }` is read from disk, and an unresolvable one is a hard failure (see
`validate_builtin_secrets_resolve` in `main.rs`). That is right for an operator validating a real
deployment, and wrong for this scanner, whose question is only ever whether a document has a valid
SHAPE. So `validate()` below gives every referenced secret something real to resolve to: each named
env var is set to a placeholder, and every `file:` ref is pointed at a scratch file. What survives is
a verdict about the document, never about the machine the scan happens to run on.

FIDELITY. A heredoc is not a file; it is a shell template. Rather than EXECUTING extracted shell
(which would be arbitrary code execution out of whatever repo is being scanned — this gate runs over
plugin repos), unresolved expansions are substituted TEXTUALLY:

    ${{ github.… }} / $(cmd) / `cmd`   ->  a literal placeholder
    $VAR / ${VAR} / ${VAR:-default}    ->  a NAME-SHAPED placeholder: a *PORT* var becomes a port, a
                                           *DIR*/*PATH*/*FILE* var becomes a path inside the scratch
                                           dir, everything else a plain scalar.

That heuristic exists so substitution never manufactures a failure of its own (`listen:
"127.0.0.1:$PORT"` must not become an unparseable socket address). Substitution is recorded per
document and reported, so a verdict is never mistaken for one on the literal text.

VERDICTS. Non-zero `--validate` is a FAILURE. Three carve-outs, each narrow and each REPORTED rather
than hidden, because a gate whose false positives are unmanageable gets switched off:

  * "env"      — the config names a PLUGIN module that is not installed in the scratch dir. Inherent
                 to a lint that does not build and sign plugin tarballs, and the only error class
                 that depends on anything outside the config text.
  * "artifact" — the error message names one of this lint's own placeholders, so the SUBSTITUTION
                 caused it, not the config. A shell variable holding a YAML fragment that the
                 structural rules below could not classify.
  * "allow"    — an explicit `# executable-config-lint: allow — <reason>` above the document. For the
                 one case the gate cannot infer: a DELIBERATELY INVALID config, like
                 release-check.sh's no-signing_key fixture, which exists to prove busbar fail-closes
                 on it. Per-document, with a written reason, and still listed in the output.

GATING is per SOURCE, because "invalid" does not mean the same thing everywhere:

  * heredocs and shipped yaml are documents meant to BOOT — ANY --validate failure is a defect;
  * a Rust test literal may legitimately be a fragment or a negative fixture, so only the RETIRED-
    GRAMMAR verdict fails it. That verdict is the one that survives both: `detect_legacy_markers`
    runs before the typed parse, so a fragment with a retired auth block still trips it.

config.yaml vs providers.yaml. `providers.<name>.api_key_env:` is a FATAL retired marker inside a
config.yaml `providers:` block, and completely INERT in a providers.yaml catalog, whose top level is
provider names — core's own `crates/busbar/tests/cli_validate.rs` writes exactly that, legitimately.
Conflating the two produces a churn of false positives, so every extracted document is classified
first (by the filename it is written to, else by shape) and then validated in the right ROLE: a
catalog is fed as `BUSBAR_PROVIDERS` alongside a generated stub config that references every provider
in it, so the catalog goes through the real pipeline rather than being pattern-matched.

SELF-TEST. `--selftest` builds a fixture tree carrying a RED and a GREEN twin of every extractor
(workflow heredoc, shell heredoc, Rust literal, standalone yaml) plus the false-positive traps
(a providers catalog using `api_key_env:`, a non-busbar heredoc, an unrelated Rust string), and
requires the scanner to flag exactly the RED set and stay silent on the GREEN set. It also asserts an
extraction FLOOR, so a scanner that has quietly stopped finding anything fails instead of passing
vacuously. In the discipline of `scripts/settings-leak-lint.sh`: a gate that passes vacuously is
worse than no gate.

The floor is not theoretical. Two vacuity bugs were caught by it, or by pointing the scanner at a
pre-fix checkout, while this was being written: hard-coded `crates/*/tests` extracted ZERO documents
from every plugin repo (crate at the repo root, not under `crates/`), and a format! arg alone on its
line under a `|` block indicator made the whole document unparseable, so it was dropped as "not a
busbar config" rather than flagged. Both are now RED fixtures.

USAGE
    executable-config-lint.py --busbar <path/to/busbar> [--root <dir>] [--selftest] [--quiet]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:  # pragma: no cover - CI images all ship PyYAML
    sys.stderr.write("executable-config-lint: PyYAML is required (pip install pyyaml)\n")
    sys.exit(2)

# ── what a busbar config LOOKS like ────────────────────────────────────────────────────────────────
# Root keys of `DeployCfg`. Deliberately a SUBSET biased to keys nothing else uses, so a
# docker-compose / systemd / kustomize heredoc in the same workflow is not mistaken for a config.
CONFIG_ROOT_KEYS = {
    "listen", "public_url", "tls", "admin_listen", "config", "providers_file", "admin_tls",
    "admin_require_mtls", "auth", "identity-providers", "providers", "models", "pools", "hooks",
    "groups", "rate_card", "per_request_fee", "store", "secrets", "advanced", "export", "plugins",
    "security", "limits", "health", "routing",
}
# A config is only recognized when it carries one of these — the keys that make a document a
# DEPLOYMENT rather than a fragment. `providers:`/`models:` alone would match a providers catalog
# that happens to have a provider named "models".
CONFIG_ANCHOR_KEYS = {"auth", "models", "plugins", "store", "listen", "admin_listen",
                      "identity-providers", "pools", "groups", "export", "routing"}
# A providers CATALOG: top level is provider NAME -> {protocol/base_url/...}.
CATALOG_ENTRY_KEYS = {"protocol", "base_url", "api_key", "api_key_env", "models", "headers",
                      "timeout", "extra_headers", "organization"}

LEGACY_BANNER = "looks like a busbar 1.x config"
# Every placeholder this lint injects carries this marker, so a --validate error CAUSED BY the
# substitution can be told apart from a defect in the config text (see verdict "artifact").
MARKER = "busbar-lint"
# The ONLY environment-dependent error class (see the module docstring): this lint does not build,
# sign or install plugin tarballs, so a config naming a plugin module cannot resolve it here.
ENV_ERROR_PATTERNS = (
    "no plugin matching",
    "is installed in",
)


class Doc:
    """One extracted document: where it came from, what it is, and how faithful the text is."""

    def __init__(self, source, target, kind, text, substituted, gate="full"):
        self.source = source          # the FILE (+ step) — the pairing key, see catalog_for()
        self.origin = f"{source} -> {target}" if target else source
        self.kind = kind              # "config" | "providers"
        self.text = text
        self.substituted = substituted  # list of expansions replaced with placeholders
        # HOW HARD this document is gated — see GATING in the module docstring.
        #   "full"    a document meant to BOOT: any --validate failure is a defect.
        #   "legacy"  a Rust test literal: only a RETIRED-grammar verdict is a defect.
        self.gate = gate


# ── expansion substitution (TEXTUAL — extracted shell is never executed) ────────────────────────────
GH_EXPR = re.compile(r"\$\{\{.*?\}\}", re.S)
CMD_SUBST = re.compile(r"\$\((?:[^()]|\([^()]*\))*\)")
BACKTICKS = re.compile(r"`[^`]*`")
BRACED_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[-=?+]([^}]*))?\}")
BARE_VAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


def placeholder_for(name, scratch):
    """A placeholder SHAPED like what the variable name implies, so substitution never manufactures
    a validation failure of its own (a port var must not become an unparseable socket address)."""
    u = name.upper()
    # PORT as a NAME TOKEN (PORT, LISTEN_PORT, SINK_PORT), never as a substring — `EXPORT_MODULE`
    # contains "PORT" and a substring match turned an exporter NAME into the scalar 8080, which
    # validates as `unknown exporter '8080'`: a manufactured failure carrying no marker, so the
    # artifact carve-out could not even recognise its own handiwork.
    if re.search(r"(?:^|_)PORTS?(?:_|$)", u):
        return "8080"
    if any(t in u for t in ("DIR", "PATH", "WORKDIR", "TMP", "HOME", "ROOT")):
        return os.path.join(scratch, "w")
    if "FILE" in u or u.endswith("_KEY") or "PEM" in u or "CERT" in u:
        return os.path.join(scratch, "w", name.lower())
    if "URL" in u or "ISS" in u or "AUD" in u:
        return "https://" + MARKER + ".invalid/" + name.lower()
    return MARKER + "-" + name.lower()


WHOLE_LINE_VAR = re.compile(r"^([ \t]*)\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?[ \t]*$")
# The Rust equivalent: a `format!` argument alone on its line — `ca_cert_pem: |\n{}\n` is how every
# PEM-carrying config literal in the fleet is written.
WHOLE_LINE_ARG = re.compile(r"^([ \t]*)\{([A-Za-z_][A-Za-z0-9_]*)?(?::[^{}]*)?\}[ \t]*$")
BLOCK_SCALAR_KEY = re.compile(r":[ \t]*[|>][+-]?[0-9]*[ \t]*$")


def substitute_fragment_lines(text, record, pattern=None, sigil="$"):
    """A shell variable that occupies a WHOLE LINE is not a scalar — it is a YAML FRAGMENT, and
    replacing it with a scalar placeholder produces a document that cannot even be parsed (which
    would then hide the real verdict, since `detect_legacy_markers` runs on a PARSED document).

    Two structural cases, both decidable from the surrounding text alone:
      * the previous key line ends in a BLOCK indicator (`ca_cert_pem: |`) — the variable holds the
        block BODY, so it becomes one placeholder line indented past that key;
      * otherwise the variable holds a block of KEYS (`$REF` in signing-gate.sh, a whole
        `store:`/`auth:` stanza) — the line is DROPPED, leaving a document that is still a valid
        config, just without that optional stanza.
    """
    lines = text.split("\n")
    out = []
    for i, line in enumerate(lines):
        m = (pattern or WHOLE_LINE_VAR).match(line)
        if not m:
            out.append(line)
            continue
        prev = next((l for l in reversed(out) if l.strip()), "")
        if BLOCK_SCALAR_KEY.search(prev):
            indent = len(prev) - len(prev.lstrip(" "))
            record.append("%s%s (block body)" % (sigil, m.group(2) or "arg"))
            out.append(" " * (indent + 2) + MARKER + "-block")
        else:
            record.append("%s%s (yaml fragment, line dropped)"
                          % (sigil, m.group(2) or "arg"))
    return "\n".join(out)


def substitute(text, scratch, record):
    text = substitute_fragment_lines(text, record)
    def gh(_m):
        record.append("${{ … }}")
        return MARKER + "-expr"

    def cmd(_m):
        record.append("$( … )")
        return MARKER + "-cmd"

    def braced(m):
        if m.group(2):
            return m.group(2)
        record.append("${%s}" % m.group(1))
        return placeholder_for(m.group(1), scratch)

    def bare(m):
        record.append("$%s" % m.group(1))
        return placeholder_for(m.group(1), scratch)

    text = GH_EXPR.sub(gh, text)
    text = CMD_SUBST.sub(cmd, text)
    text = BACKTICKS.sub(cmd, text)
    text = BRACED_VAR.sub(braced, text)
    text = BARE_VAR.sub(bare, text)
    return text


# ── classification ─────────────────────────────────────────────────────────────────────────────────
def classify(text, target_name=None):
    """-> "config" | "providers" | None (not a busbar document).

    The FILENAME the document is written to wins when it is decisive; otherwise shape. Getting this
    wrong is the documented false-positive generator (`api_key_env:`), so shape detection is
    deliberately strict: an ambiguous document is dropped, never guessed into the wrong role."""
    try:
        doc = yaml.safe_load(text)
    except Exception:
        # Unparseable is only interesting if the filename says it is meant to be a busbar config;
        # a broken YAML config.yaml is a real defect and must reach the binary.
        if target_name and "config" in target_name and "providers" not in target_name:
            return "config"
        return None
    if not isinstance(doc, dict) or not doc:
        return None

    keys = set(doc.keys())
    looks_config = bool(keys & CONFIG_ANCHOR_KEYS) and keys <= CONFIG_ROOT_KEYS
    entries = [v for v in doc.values() if isinstance(v, dict)]
    looks_catalog = (
        len(entries) == len(doc)
        and bool(entries)
        and all(bool(set(v.keys()) & CATALOG_ENTRY_KEYS) for v in entries)
        and all(("protocol" in v or "base_url" in v) for v in entries)
    )

    if target_name:
        base = os.path.basename(target_name).lower()
        if "providers" in base and looks_catalog:
            return "providers"
        if "config" in base and looks_config:
            return "config"
    if looks_config and not looks_catalog:
        return "config"
    if looks_catalog and not looks_config:
        return "providers"
    return None


# ── extractor 1/2: heredocs, in workflow `run:` blocks and in shell scripts ─────────────────────────
HEREDOC = re.compile(
    r"""(?P<indent>[ \t]*)          # leading indent (already dedented by the YAML parser for run:)
        (?:[^\n]*?)                 # the command: `cat > "$X"`, `tee -a x`, `install …`, …
        (?P<op>>>?)\s*             # `>` creates a whole document; `>>` APPENDS a fragment
        (?P<target>[^\s<>|;&]+)     # the redirect target — the FILENAME, our best kind signal
        [^\n<]*
        <<(?P<dash>-?)\s*(?P<q>['"]?)(?P<delim>[A-Za-z_][A-Za-z0-9_]*)(?P=q)[ \t]*$""",
    re.X | re.M,
)


def extract_heredocs(text, origin, scratch):
    """Every `… > <file> <<[-]DELIM … DELIM` body in `text`.

    Handles the three shapes that actually occur: an UNQUOTED delimiter (the shell expands `$VAR`, so
    we substitute), a QUOTED delimiter (`<<'EOF'` — verbatim, no substitution, and none applied), and
    `<<-` (leading TABS stripped). Bodies are also dedented by their own minimum common indent, which
    is what makes a heredoc written inside an indented `run: |` block parse as YAML at all."""
    out = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        m = HEREDOC.match(lines[i])
        if not m:
            i += 1
            continue
        delim, dash, quoted = m.group("delim"), m.group("dash") == "-", m.group("q") != ""
        # `cat >> file` appends a FRAGMENT to a document written elsewhere; on its own it is not a
        # config and validating it as one produces a guaranteed "missing field `providers`".
        append = m.group("op") == ">>"
        opener = i  # `i` is advanced past the body below; the allow marker sits above the OPENER
        body, j = [], i + 1
        while j < len(lines):
            probe = lines[j].lstrip("\t") if dash else lines[j]
            if probe.strip() == delim and probe.lstrip() == probe.strip():
                break
            body.append(lines[j].lstrip("\t") if dash else lines[j])
            j += 1
        raw = "\n".join(body) + "\n"
        i = j + 1

        indents = [len(l) - len(l.lstrip(" ")) for l in body if l.strip()]
        if indents:
            cut = min(indents)
            raw = "\n".join(l[cut:] if l.strip() else l for l in body) + "\n"

        record = []
        rendered = raw if quoted else substitute(raw, scratch, record)
        kind = classify(rendered, m.group("target"))
        if kind and not append:
            out.append(Doc(origin, os.path.basename(m.group("target").strip('"\'')),
                           kind, rendered, record,
                           gate=allow_marker(lines, opener)))
    return out


ALLOW = re.compile(r"executable-config-lint:\s*allow\s*[—:-]?\s*(.*)")
ALLOW_LOOKBACK = 8


def allow_marker(lines, at):
    """An explicit, per-document opt-out: `# executable-config-lint: allow — <reason>` on one of the
    lines just above the document.

    This exists for the one legitimate case the gate cannot infer — a DELIBERATELY INVALID executable
    config. `release-check.sh` writes a config with no `auth.signing_key` precisely to assert that
    busbar fail-closes on it; that document is correct as written and must never be "fixed". The
    marker is per-document, carries a written reason, and the document is still REPORTED (as skipped),
    so an allow is a visible claim someone made, not a silent hole. Using it for anything else is the
    defect this gate exists to catch, wearing a hat."""
    for k in range(max(0, at - ALLOW_LOOKBACK), at + 1):
        m = ALLOW.search(lines[k])
        if m:
            return "allow:" + (m.group(1).strip() or "no reason given")
    return "full"


def scan_workflows(root, scratch):
    docs = []
    wfdir = os.path.join(root, ".github", "workflows")
    for name in sorted(os.listdir(wfdir)) if os.path.isdir(wfdir) else []:
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(wfdir, name)
        try:
            wf = yaml.safe_load(open(path, encoding="utf-8"))
        except Exception:
            continue
        rel = os.path.relpath(path, root)
        for job in (wf or {}).get("jobs", {}).values():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps", []) or []:
                if isinstance(step, dict) and isinstance(step.get("run"), str):
                    label = step.get("name", "?")
                    label = str(label).split("—")[0].strip()[:48]
                    docs += extract_heredocs(step["run"], f"{rel} [{label}]", scratch)
    return docs


def scan_shell(root, scratch):
    docs = []
    for path in walk(root, exts=(".sh", ".bash")):
        try:
            text = open(path, encoding="utf-8").read()
        except Exception:
            continue
        docs += extract_heredocs(text, os.path.relpath(path, root), scratch)
    return docs


# ── extractor 3: Rust string literals in test trees ─────────────────────────────────────────────────
RAW_STR = re.compile(r'r(#*)"(.*?)"\1', re.S)
# A normal literal, INCLUDING the `"…\` + newline continuation form that a multi-line `format!`
# config is invariably written in (see auth-oidc's e2e.rs, and core's own tests).
NORM_STR = re.compile(r'"((?:[^"\\]|\\.|\\\n)*)"', re.S)
FMT_ARG = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)?(?::[^{}]*)?\}")


def unescape_rust(s):
    s = re.sub(r"\\\n\s*", "", s)          # line continuation: backslash-newline eats the indent
    out, i = [], 0
    simple = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "0": "\0", "'": "'"}
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            c = s[i + 1]
            if c in simple:
                out.append(simple[c]); i += 2; continue
            if c == "x" and i + 3 < len(s):
                try:
                    out.append(chr(int(s[i + 2:i + 4], 16))); i += 4; continue
                except ValueError:
                    pass
            out.append(c); i += 2; continue
        out.append(s[i]); i += 1
    return "".join(out)


def render_rust_literal(body, scratch, record, is_raw):
    text = body if is_raw else unescape_rust(body)
    # A FORMAT string is identified by its doubled braces — that is the only unambiguous tell, and
    # every busbar config literal has them (`api_key: {{ env: X }}`). A plain literal keeps its
    # braces untouched, so a flow-style `settings: {}` is never mangled into a placeholder.
    if "{{" in text or "}}" in text:
        def arg(m):
            name = m.group(1) or "arg"
            record.append("{%s}" % name)
            return placeholder_for(name, scratch)
        text = re.sub(r"\{\{", "\x00", text)
        text = re.sub(r"\}\}", "\x01", text)
        # A format arg ALONE on its line is a YAML fragment or a block-scalar BODY, not a scalar —
        # same reasoning as the shell case, and the same fix. Without this, `ca_cert_pem: |\n{}\n`
        # renders as an empty block followed by a stray scalar, the document fails to PARSE, and the
        # whole config is silently dropped as "not a busbar config" — a miss, not a failure. That is
        # exactly how auth-oidc's second e2e config escaped an earlier version of this scanner.
        text = substitute_fragment_lines(text, record, WHOLE_LINE_ARG, sigil="")
        text = FMT_ARG.sub(arg, text)
        text = text.replace("\x00", "{").replace("\x01", "}")
    return text


def scan_rust(root, scratch):
    docs = []
    for path in rust_test_files(root):
        try:
            src = open(path, encoding="utf-8").read()
        except Exception:
            continue
        rel = os.path.relpath(path, root)
        spans = []
        for m in RAW_STR.finditer(src):
            spans.append((m.start(), m.group(2), True))
        raw_ranges = [(m.start(), m.end()) for m in RAW_STR.finditer(src)]
        for m in NORM_STR.finditer(src):
            if any(a <= m.start() < b for a, b in raw_ranges):
                continue
            spans.append((m.start(), m.group(1), False))
        for pos, body, is_raw in spans:
            if "\n" not in body and "\\n" not in body:
                continue  # a one-line literal is never a config
            record = []
            text = render_rust_literal(body, scratch, record, is_raw)
            kind = classify(text)
            if kind:
                line = src.count("\n", 0, pos) + 1
                srclines = src.split("\n")
                g = allow_marker(srclines, min(line - 1, len(srclines) - 1))
                docs.append(Doc(rel, f"line {line}", kind, text, record,
                                gate=g if g.startswith("allow:") else "legacy"))
    return docs


def rust_test_files(root):
    """Cargo INTEGRATION-test trees, at any depth: a directory named `tests` whose PARENT holds a
    `Cargo.toml`. That is cargo's own definition of an integration test, so it needs no per-layout
    knowledge — it finds `crates/<c>/tests/` in core's monorepo layout AND `<plugin>-plugin/tests/`
    in a plugin repo's flat layout, which are different shapes entirely.

    (An earlier version hard-coded `crates/*/tests` + a root `tests/`. That extracted ZERO documents
    from every plugin repo — where the crate directory sits at the repo root — i.e. the gate passed
    vacuously on exactly the repos it exists to protect. The self-test's fixture crate now lives at a
    plugin-shaped path with a Cargo.toml beside it, so that regression fails the self-test.)

    Deliberately NOT `src/**/tests/**`: a unit-test module beside the code it tests is where the
    engine's own NEGATIVE fixtures live — `config_validate/tests/tests.rs` is a wall of configs that
    are invalid ON PURPOSE, each asserting a specific error message. Those parents hold no
    Cargo.toml, so this rule excludes them for free."""
    out = []
    for dirpath, dirnames, _files in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if os.path.basename(dirpath) != "tests":
            continue
        if os.path.isfile(os.path.join(os.path.dirname(dirpath), "Cargo.toml")):
            out += walk(dirpath, exts=(".rs",))
    return sorted(set(out))


# ── extractor 4: standalone yaml that ships (examples/, docker/, root config) ──────────────────────
def scan_standalone(root, _scratch):
    docs = []
    candidates = []
    for base in ("config.yaml", "providers.yaml", "plugins.yaml"):
        p = os.path.join(root, base)
        if os.path.isfile(p):
            candidates.append(p)
    for sub in ("examples", "docker", "deploy", "qa/fixtures", "scripts/fixtures"):
        d = os.path.join(root, sub)
        if os.path.isdir(d):
            candidates += walk(d, exts=(".yaml", ".yml"))
    for path in sorted(set(candidates)):
        try:
            text = open(path, encoding="utf-8").read()
        except Exception:
            continue
        kind = classify(text, os.path.basename(path))
        if kind:
            head = text.split("\n")[:ALLOW_LOOKBACK + 1]
            docs.append(Doc(os.path.relpath(path, root), None, kind, text, [],
                            gate=allow_marker(head, len(head) - 1)))
    return docs


SKIP_DIRS = {".git", "target", "node_modules", ".venv", "vendor", "dist", "build", ".cargo"}


def walk(root, exts, only_dirs=None):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
                       or d == ".github"]
        if only_dirs and not any(("/" + d + "/") in (dirpath + "/") for d in only_dirs):
            continue
        for f in sorted(filenames):
            if f.endswith(exts):
                out.append(os.path.join(dirpath, f))
    return sorted(out)


# ── the verdict, from the REAL binary ──────────────────────────────────────────────────────────────
STUB_PROVIDERS = ('busbar-lint-mock:\n  protocol: anthropic\n'
                  '  base_url: "http://127.0.0.1:9"\n  api_key: { env: BUSBAR_LINT_KEY }\n')


def stub_config_for(catalog_text):
    """A minimal config.yaml that REFERENCES every provider in `catalog_text`, so a providers catalog
    is validated in its real ROLE by the real pipeline instead of being pattern-matched."""
    try:
        names = [k for k in (yaml.safe_load(catalog_text) or {})]
    except Exception:
        names = []
    names = [n for n in names if isinstance(n, str)] or ["busbar-lint-mock"]
    body = 'listen: "127.0.0.1:0"\nproviders:\n'
    for n in names:
        body += f"  {n}:\n    api_key: {{ env: BUSBAR_LINT_KEY }}\n"
    body += f"models:\n  busbar-lint-model:\n    provider: {names[0]}\n"
    return body


def catalog_for(config_text, siblings):
    """The providers.yaml a config document is validated AGAINST.

    A config and its catalog are TWO documents — a config.yaml heredoc names providers that a
    providers.yaml heredoc a few lines above defines. Validating the config against an empty catalog
    would fail every one of them on "provider 'x' referenced in config.yaml not found in
    providers.yaml", which is a CROSS-FILE wiring fact, not a grammar defect, and not what this gate
    is for. (The self-test caught exactly this: the GREEN twins failed on it.)

    So: start from any providers catalog extracted from the SAME source (same workflow step / same
    script / same test file), then SYNTHESIZE a stub entry for every provider the config names that
    the catalog does not carry. The synthesized entry is deliberately inert."""
    base = {}
    for s in siblings:
        try:
            parsed = yaml.safe_load(s) or {}
        except Exception:
            continue
        if isinstance(parsed, dict):
            base.update({k: v for k, v in parsed.items() if isinstance(v, dict)})
    try:
        named = (yaml.safe_load(config_text) or {}).get("providers") or {}
    except Exception:
        named = {}
    for n in named if isinstance(named, dict) else []:
        base.setdefault(n, {"protocol": "anthropic", "base_url": "http://127.0.0.1:9",
                            "api_key": {"env": "BUSBAR_LINT_KEY"}})
    if not base:
        return STUB_PROVIDERS
    return yaml.safe_dump(base, default_flow_style=False, sort_keys=False)


# A secret value that satisfies every built-in shape check: 64 hex chars is valid for
# `auth.signing_key`, and harmless as any other secret's value.
PLACEHOLDER_SECRET = "0" * 63 + "1"

_ENV_REF = re.compile(r"env:\s*([A-Za-z_][A-Za-z0-9_]*)")
_FILE_REF = re.compile(r"file:\s*[^}\s]+")


def _referenced_env_names(*texts):
    """Every `{ env: NAME }` the documents under test reference, in first-seen order.

    Enumerating the names here instead would rot: the scanned corpus spans docs, heredocs, and every
    shipped release, and a doc adding one new variable would turn the gate red for a reason that has
    nothing to do with the config's shape.
    """
    seen = []
    for text in texts:
        for name in _ENV_REF.findall(text or ""):
            if name not in seen:
                seen.append(name)
    return seen


def _point_file_refs_at(text, stand_in):
    """Rewrite `{ file: /some/path }` to a real file, so validation tests the config's SHAPE.

    A shipped artifact names a PRODUCTION path (`/var/lib/busbar/signing.key`) that exists on no CI
    runner and on no developer's laptop. The document is not wrong for saying so.
    """
    return _FILE_REF.sub("file: " + stand_in, text or "")


def validate(doc, busbar, scratch, siblings=()):
    """-> (verdict, detail): "ok" | "legacy" | "env" | "artifact" | "invalid" (see VERDICTS above)."""
    d = tempfile.mkdtemp(dir=scratch)
    cfg, prov = os.path.join(d, "config.yaml"), os.path.join(d, "providers.yaml")
    if doc.kind == "providers":
        cfg_text, prov_text = stub_config_for(doc.text), doc.text
    else:
        cfg_text, prov_text = doc.text, catalog_for(doc.text, siblings)

    # `--validate` RESOLVES built-in (`env`/`file`) secret references and exits non-zero when one
    # cannot resolve. That is deliberate: a gateway whose credentials are missing fails every
    # upstream request, and it should say so before it boots rather than after. But it means this
    # scanner would otherwise report a document as INVALID because of THIS MACHINE's environment
    # rather than because of anything written in the document. Give every referenced secret
    # something real to resolve to, so the verdict is about the config and nothing else.
    stand_in = os.path.join(d, "secret-stand-in")
    open(stand_in, "w", encoding="utf-8").write(PLACEHOLDER_SECRET)
    cfg_text, prov_text = (_point_file_refs_at(cfg_text, stand_in),
                           _point_file_refs_at(prov_text, stand_in))

    open(cfg, "w", encoding="utf-8").write(cfg_text)
    open(prov, "w", encoding="utf-8").write(prov_text)
    env = dict(os.environ, BUSBAR_CONFIG=cfg, BUSBAR_PROVIDERS=prov)
    env.pop("BUSBAR_CONFIG_OVERLAY", None)
    for name in _referenced_env_names(cfg_text, prov_text):
        env[name] = PLACEHOLDER_SECRET
    try:
        r = subprocess.run([busbar, "--validate"], env=env, capture_output=True, text=True,
                           timeout=60)
    except subprocess.TimeoutExpired:
        return "invalid", "busbar --validate timed out"
    if r.returncode == 0:
        return "ok", ""
    blob = r.stdout + r.stderr
    errs = [l for l in blob.splitlines() if l.startswith("[error]") or l.startswith("  - ")]
    if errs:
        detail = "\n      ".join(errs)
    elif blob.strip():
        detail = blob.strip().splitlines()[-1]
    else:
        detail = "exit %d" % r.returncode
    if LEGACY_BANNER in blob:
        return "legacy", detail
    if any(p in blob for p in ENV_ERROR_PATTERNS):
        return "env", detail
    # The error names one of OUR placeholders, so the substitution caused it, not the config text.
    # (A shell variable holding a YAML fragment that substitute_fragment_lines could not classify.)
    if MARKER in blob:
        return "artifact", detail
    return "invalid", detail


# ── the scan ───────────────────────────────────────────────────────────────────────────────────────
def collect(root, scratch):
    os.makedirs(os.path.join(scratch, "w", "plugins"), exist_ok=True)
    docs = []
    docs += scan_workflows(root, scratch)
    docs += scan_shell(root, scratch)
    docs += scan_rust(root, scratch)
    docs += scan_standalone(root, scratch)
    # De-duplicate identical text from the same file (a heredoc repeated verbatim in two steps).
    seen, uniq = set(), []
    for d in docs:
        key = (d.origin, d.text)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(d)
    return uniq


def run_scan(root, busbar, quiet=False, out=sys.stdout):
    scratch = tempfile.mkdtemp(prefix=MARKER + "-scan-")
    try:
        docs = collect(root, scratch)
        # Catalogs found alongside a config (same workflow step / script / test file) are what that
        # config is validated against — see catalog_for().
        by_source = {}
        for d in docs:
            if d.kind == "providers":
                by_source.setdefault(d.source, []).append(d.text)
        bad, env_skipped, ok = [], [], 0
        for d in docs:
            if d.gate.startswith("allow:"):
                env_skipped.append((d, d.gate))
                if not quiet:
                    out.write(f"  allowed  {d.origin} ({d.kind}) — {d.gate[6:]}\n")
                continue
            verdict, detail = validate(d, busbar, scratch, by_source.get(d.source, ()))
            if verdict == "ok":
                ok += 1
                if not quiet:
                    out.write(f"  ok       {d.origin} ({d.kind})\n")
            elif verdict in ("env", "artifact") or (verdict == "invalid" and d.gate == "legacy"):
                # Either a plugin this lint cannot install, or a Rust test literal that is invalid
                # for some reason OTHER than retired grammar — a fragment, or a negative fixture
                # asserting exactly that error. Reported, never fatal.
                env_skipped.append((d, detail))
                if not quiet:
                    why = {"env": "plugin not installed in the scan scratch dir",
                           "artifact": "a shell variable holding a YAML fragment could not be "
                                       "rendered — verdict not attributable to the config text"}.get(
                        verdict, "test literal, not gated beyond retired grammar")
                    out.write(f"  skipped  {d.origin} ({d.kind}) — {why}\n")
            else:
                bad.append((d, verdict, detail))
                tag = "RETIRED " if verdict == "legacy" else "INVALID "
                out.write(f"  {tag} {d.origin} ({d.kind})\n      {detail}\n")
                if d.substituted:
                    uniq = sorted(set(d.substituted))
                    out.write(f"      (expansions substituted: {', '.join(uniq[:8])})\n")
        return docs, ok, env_skipped, bad
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# ── SELF-TEST — the scanner must not be lie-able ────────────────────────────────────────────────────
RED_WF = """\
name: red
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: RED workflow heredoc — retired inline admin_auth
        run: |
          cat > "$WORKDIR/config.yaml" <<EOF
          auth:
            chain: [keys]
            admin_auth:
              - admin-tokens: { token: { env: BUSBAR_ADMIN_TOKEN } }
          providers:
            mock:
              api_key: { env: MOCK_KEY }
          models:
            m:
              provider: mock
          EOF
      - name: GREEN twin — 1.5.3 define-once grammar
        run: |
          cat > "$WORKDIR/ok-config.yaml" <<EOF
          identity-providers:
            admin-tokens:
              module: admin-tokens
              token: { env: BUSBAR_ADMIN_TOKEN }
          auth:
            chain: [keys]
            signing_key: { env: BUSBAR_LINT_SIGNING_KEY }
            admin_auth: [admin-tokens]
          providers:
            mock:
              api_key: { env: MOCK_KEY }
          models:
            m:
              provider: mock
          EOF
      - name: TRAP — a non-busbar heredoc must be ignored entirely
        run: |
          cat > docker-compose.yml <<'EOF'
          services:
            web:
              image: nginx
              ports: ["80:80"]
          EOF
"""

RED_SH = """\
#!/usr/bin/env bash
# RED: a QUOTED delimiter (no expansion) carrying the retired inline chain entry.
cat > "$D/config.yaml" <<'EOF'
auth:
  chain:
    - keys
    - oidc:
        settings:
          issuer: "https://issuer.example"
  admin_auth: [admin-tokens]
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  m:
    provider: mock
EOF

# GREEN twin, written with a `<<-` tab-stripped heredoc to exercise that path too.
\tcat > "$D/good-config.yaml" <<-EOF
\tidentity-providers:
\t  admin-tokens:
\t    module: admin-tokens
\t    token: { env: T }
\tauth:
\t  chain: [keys]
\t  signing_key: { env: BUSBAR_LINT_SIGNING_KEY }
\t  admin_auth: [admin-tokens]
\tproviders:
\t  mock:
\t    api_key: { env: MOCK_KEY }
\tmodels:
\t  m:
\t    provider: mock
\tEOF
"""

RED_RS = r'''
fn red() {
    let cfg = format!(
        "listen: \"127.0.0.1:{port}\"\n\
         auth:\n  chain: [keys]\n  admin_auth:\n    - admin-tokens: {{ token: {{ env: T }} }}\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  m:\n    provider: mock\n",
    );
    // RED (block-scalar arg): the shape auth-oidc's second e2e config is written in — a PEM injected
    // by a positional `{}` alone on its line, under a `|` block indicator.
    let cfg2 = format!(
        "listen: \"127.0.0.1:{port3}\"\n\
         auth:\n  chain:\n    - keys\n    - oidc:\n        settings:\n          issuer: \"i\"\n\
         \x20         ca_cert_pem: |\n{}\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  m:\n    provider: mock\n",
    );
    let good = format!(
        "listen: \"127.0.0.1:{port2}\"\n\
         identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: T }} }}\n\
         auth:\n  chain: [keys]\n  signing_key: {{ env: K }}\n  admin_auth: [admin-tokens]\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  m:\n    provider: mock\n",
    );
    // TRAP: an unrelated multi-line string must not be picked up as a config.
    let note = "line one\nline two\nline three\n";
}
'''

# TRAP: the shape `cli_validate.rs` legitimately writes. `api_key_env:` here is INERT (a catalog's
# top level is provider NAMES, so there is no `providers:` block for the marker to live in).
GREEN_CATALOG = """\
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:9"
  api_key_env: MOCK_KEY
"""

# RED: the SAME key inside a config.yaml `providers:` block, where it IS a retired marker.
RED_YAML = """\
listen: "127.0.0.1:0"
providers:
  mock:
    api_key_env: MOCK_KEY
models:
  m:
    provider: mock
"""


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w", encoding="utf-8").write(text)


def selftest(busbar, out=sys.stdout):
    out.write("\n== executable-config-lint SELF-TEST (the scanner cannot be lied to) ==\n")
    tree = tempfile.mkdtemp(prefix="busbar-exec-cfg-selftest-")
    try:
        write(os.path.join(tree, ".github/workflows/red.yml"), RED_WF)
        write(os.path.join(tree, "scripts/red.sh"), RED_SH)
        write(os.path.join(tree, "demo-plugin/Cargo.toml"), "[package]\nname = \"demo-plugin\"\n")
        write(os.path.join(tree, "demo-plugin/tests/red.rs"), RED_RS)
        write(os.path.join(tree, "examples/providers.yaml"), GREEN_CATALOG)
        write(os.path.join(tree, "examples/red-config.yaml"), RED_YAML)

        docs, ok, env_skipped, bad = run_scan(tree, busbar, quiet=True, out=out)
        fail, passed = 0, 0

        # (1) EXTRACTION FLOOR — a scanner that has stopped finding anything must not pass vacuously.
        by_src = {
            "workflow heredoc": [d for d in docs if "workflows/red.yml" in d.origin],
            "shell heredoc": [d for d in docs if "scripts/red.sh" in d.origin],
            "rust literal": [d for d in docs if "demo-plugin/tests/red.rs" in d.origin],
            "standalone yaml": [d for d in docs if d.origin.startswith("examples/")],
        }
        missing = [k for k, v in by_src.items() if len(v) < 2]
        if missing:
            fail = 1
            out.write(f"  FLOOR FAILED: each extractor must find both its RED and GREEN twin; "
                      f"short: {missing} — {[(k, [d.origin for d in v]) for k, v in by_src.items()]}\n")
        else:
            passed += 1
            out.write(f"  FLOOR: all 4 extractors found both twins "
                      f"({len(docs)} documents: {sum(1 for d in docs if d.kind=='config')} config, "
                      f"{sum(1 for d in docs if d.kind=='providers')} providers)\n")

        # (2) RED — every planted defect flagged, and flagged as RETIRED, not merely "invalid".
        flagged = {d.origin for d, _, _ in bad}
        legacy = {d.origin for d, v, _ in bad if v == "legacy"}
        want = ["workflows/red.yml", "scripts/red.sh", "tests/red.rs", "examples/red-config.yaml"]
        miss = [w for w in want if not any(w in f for f in legacy)]
        rust_hits = [f for f in legacy if "demo-plugin/tests/red.rs" in f]
        if miss or len(bad) != 5 or len(rust_hits) != 2:
            fail = 1
            out.write(f"  RED FAILED: expected exactly 5 RETIRED hits (one per extractor, TWO from "
                      f"the Rust file); missing {miss}; rust={sorted(rust_hits)}; "
                      f"got {sorted(flagged)}\n")
        else:
            passed += 1
            out.write("  RED: the retired inline admin_auth (workflow heredoc), the retired inline "
                      "chain entry (quoted shell heredoc), the retired form in a Rust format! "
                      "literal, the retired form in a format! literal whose PEM arrives as a "
                      "block-scalar arg alone on its line, and `providers.*.api_key_env:` in a "
                      "standalone config.yaml — all 5 flagged as RETIRED by the real binary\n")

        # (3) GREEN — the 1.5.3 twins, the non-busbar heredoc and the unrelated Rust string are
        #     silent, and the providers CATALOG using `api_key_env:` is NOT a false positive.
        # The GREEN twins identify themselves by CONTENT — each is the 1.5.3 define-once rewrite of
        # the RED fixture beside it — plus the providers catalog. Matching on content rather than on
        # a filename substring keeps this assertion honest when both twins live in one file.
        twins = [d for d in docs
                 if "identity-providers:" in d.text or d.origin == "examples/providers.yaml"]
        loud = [d.origin for d in twins if d.origin in flagged]
        if len(twins) != 4:
            fail = 1
            out.write(f"  GREEN FAILED: expected 4 GREEN twins (one per extractor), found "
                      f"{[d.origin for d in twins]}\n")
        catalog = [d for d in docs if d.origin == "examples/providers.yaml"]
        # The unrelated Rust string and the docker-compose heredoc must never even be EXTRACTED —
        # a scanner that extracts them would drown a real repo in noise.
        traps = [d for d in docs if "docker-compose" in d.origin or "line one" in d.text]
        if not loud and not traps and catalog and catalog[0].kind == "providers" and ok >= 3:
            passed += 1
            out.write("  GREEN: every 1.5.3 twin is silent; the docker-compose heredoc and the "
                      "unrelated Rust string are never extracted; the providers CATALOG's "
                      "`api_key_env:` is correctly INERT (classified providers, not config — the "
                      "same key in a config.yaml `providers:` block is the RED hit above)\n")
        else:
            fail = 1
            out.write(f"  GREEN FAILED: twins wrongly flagged {loud}; traps wrongly extracted "
                      f"{[d.origin for d in traps]}; ok={ok}; catalog="
                      f"{[(d.origin, d.kind) for d in catalog]}\n")

        out.write(f"  self-test: {passed}/3 fixture groups passed\n")
        if fail:
            out.write("  executable-config-lint SELF-TEST FAILED — the scanner would let a "
                      "retired executable config through\n")
            return 1
        out.write("  ok\n")
        return 0
    finally:
        shutil.rmtree(tree, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--busbar", required=True, help="path to the compiled busbar binary")
    ap.add_argument("--root", default=".", help="tree to scan (default: cwd)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="only print failures")
    ap.add_argument(
        "--min-docs",
        type=int,
        default=1,
        help="floor on the number of extracted documents; below it the run FAILS. "
             "This gate is 'for each executable config, assert it validates', which is "
             "VACUOUSLY TRUE over zero configs — an extractor that stops matching (a "
             "renamed workflows dir, a heredoc style change, a moved examples/) makes it "
             "pass forever having validated nothing. Core passes --min-docs 40 (50 today).",
    )
    a = ap.parse_args()

    busbar = os.path.abspath(a.busbar)
    if not os.access(busbar, os.X_OK):
        sys.stderr.write(f"executable-config-lint: not executable: {busbar}\n")
        return 2
    if a.selftest:
        return selftest(busbar)

    root = os.path.abspath(a.root)
    print(f"\n== executable configs in {root} through the real `busbar --validate` ==")
    docs, ok, env_skipped, bad = run_scan(root, busbar, quiet=a.quiet)
    print(f"\n== result ==")
    print(f"  {len(docs)} executable busbar document(s) extracted — "
          f"{ok} valid, {len(env_skipped)} skipped (plugin not installed), {len(bad)} FAILED")
    if bad:
        print("  executable-config-lint FAILED")
        print("  A config a machine RUNS is invalid under this engine. Docs gates cannot see these:")
        print("    CI/shell heredocs, Rust test literals, examples/ and docker/ yaml.")
        print("  Fix the config text at the origin above; `busbar --migrate-config <file>` rewrites")
        print("  a retired 1.x block, and `busbar --validate` reproduces the verdict on a real file.")
        return 1
    # ── EXTRACTION FLOOR — checked AFTER `bad`, so a real invalid config is still reported first.
    # Everything above is "for each extracted document, assert it validates", which is VACUOUSLY
    # TRUE over zero documents. All four extractors are DISCOVERY-based (a workflows dir, heredoc
    # syntax, Rust string literals, a yaml glob); any of them can quietly stop matching, and the
    # gate then prints "0 documents — 0 FAILED / passed" and exits 0 forever while invalid configs
    # a machine actually runs sail through unvalidated.
    if len(docs) < a.min_docs:
        print("  executable-config-lint FAILED — EXTRACTION FLOOR NOT MET")
        print(f"  extracted {len(docs)} document(s), expected >= {a.min_docs}.")
        print("  This gate validated (almost) nothing, so its verdict is meaningless — NOT a pass.")
        print("  An extractor has stopped matching: check the workflows dir, the heredoc styles,")
        print("  the Rust test trees and the examples/ + docker/ globs. If the corpus legitimately")
        print("  shrank, lower --min-docs in the SAME commit that removes the documents.")
        return 1
    print("  executable-config-lint passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
