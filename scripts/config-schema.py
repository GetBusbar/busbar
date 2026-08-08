#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# config-schema.py — the config-stability gate's engine.
#
# Two jobs, one file (no external deps; stdlib only, so it runs on the same bare runner every other
# scripts/*-lint.sh does):
#
#   gen <config-src-dir>            Emit a DETERMINISTIC structural fingerprint of the config surface
#                                   (every serde-`Deserialize` struct/enum under crates/busbar/src/config)
#                                   as canonical pretty JSON on stdout. This is the "schema snapshot"
#                                   the drift guard freezes — the config-grammar analogue of the
#                                   committed openapi.json the admin API drift-guards against.
#
#   classify <baseline.json> <fresh.json>
#                                   Walk baseline-vs-fresh fingerprint trees and classify every delta
#                                   ADDITIVE (green) or BREAKING (red). Exit 0 iff every delta is
#                                   additive; exit 3 if any delta is breaking (each printed with its
#                                   JSON-path + reason). This is the additive-only enforcement the
#                                   openapi guard does NOT have — the whole point of 1.5.3.
#
# WHY a structural fingerprint and not schemars: a schemars-derived `JsonSchema` on `DeployCfg`
# would need invasive changes to config/mod.rs and a compile step. A fingerprint extracted from the
# typed config source is derived from
# the same source of truth, is featureless-safe (no cargo feature, no compile), and captures exactly
# the deltas the additive rule cares about: field add/remove/retype, optional<->required, and enum
# variant append/drop. Refining the emitter to schemars later is itself an additive change to `gen`.

import json
import re
import sys
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────────────────────────
# Source extraction: strip comments, then brace-match out every `#[derive(..Deserialize..)] struct|enum`.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


def strip_comments(src: str) -> str:
    """Remove // line comments and /* */ block comments WITHOUT disturbing byte offsets that matter
    for brace matching — we replace comment spans with equivalent-length spaces so column/brace
    counting downstream stays valid. String literals are left intact (config types have string
    defaults with `//` inside URLs, e.g. `http://`)."""
    out = []
    i, n = 0, len(src)
    in_str = False
    in_char = False
    while i < n:
        c = src[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if in_char:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == "'":
                in_char = False
            i += 1
            continue
        # not in a string
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            # line comment → blank to EOL (keep the newline)
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            if j == -1:
                j = n
            else:
                j += 2
            for k in range(i, j):
                out.append("\n" if src[k] == "\n" else " ")
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def match_block(src: str, open_idx: int) -> int:
    """Given the index of a `{`, return the index just past its matching `}`."""
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


# An attribute cluster (`#[...]` lines, possibly several) immediately preceding a `struct`/`enum`.
ITEM_RE = re.compile(
    r"(?P<attrs>(?:^[ \t]*#\[[^\n]*\]\s*)*)"
    r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?P<kw>struct|enum)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<generics><[^{;]*>)?\s*(?P<open>[{;])",
    re.MULTILINE,
)

# A hand-written `impl<'de> Deserialize<'de> for X` (any of the three import spellings the tree uses).
MANUAL_DE_RE = re.compile(
    r"^\s*impl\s*<\s*'de\s*>\s*(?:serde::|de::)?Deserialize\s*<\s*'de\s*>\s+for\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)

# A TOP-LEVEL type alias: `pub(crate) type HookDefs = indexmap::IndexMap<String, HookDefCfg>;`
# Anchored at column 0 on purpose — an indented `type Value = …;` is a local alias inside a fn or
# impl (a private implementation detail), not config grammar, and must not be able to trip the gate.
ALIAS_RE = re.compile(
    r"^(?:pub(?:\([^)]*\))?\s+)?type\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<target>[^;]+);",
    re.MULTILINE,
)

# rename_all mappings we honor (the ones config types actually use).
_RENAME_ALL = {
    "snake_case": lambda s: re.sub(r"(?<!^)(?=[A-Z])", "_", s).lower(),
    "kebab-case": lambda s: re.sub(r"(?<!^)(?=[A-Z])", "-", s).lower(),
    "lowercase": lambda s: s.lower(),
    "UPPERCASE": lambda s: s.upper(),
    "camelCase": lambda s: s[:1].lower() + s[1:],
    "PascalCase": lambda s: s,
    "SCREAMING_SNAKE_CASE": lambda s: re.sub(r"(?<!^)(?=[A-Z])", "_", s).upper(),
}


# ── COVERAGE HOLE (1.5.4): config-grammar types that live OUTSIDE crates/busbar/src/config ────────
#
# `gen` globs `crates/busbar/src/config/*.rs`. Anything defined elsewhere was INVISIBLE: it appeared
# in the snapshot only as the STRING in a field slot (`"type": "SecretRef"`), so its own shape was
# never fingerprinted, and a BREAKING change to it passed the additive-only gate GREEN. Proven, not
# assumed: deleting the whole `{ file: <path> }` sugar form from `SecretRef` -- which makes every
# `api_key: { file: /run/secrets/key }` config fail to parse -- produced "no schema delta".
#
# This is an EXPLICIT ALLOWLIST, not a wider glob, and deliberately so: `auth/mod.rs` is a large
# engine module whose other types are NOT config grammar, and dragging them in would fill the
# snapshot with internal churn that trains reviewers to ignore it. Each entry names the file and the
# exact type names in it that ARE config grammar.
#
# Adding a row here is how a future out-of-config config type gets covered.
EXTERNAL_SOURCES = (
    # The grammar of EVERY secret reference in the config (`api_key:`, `tls.cert:`,
    # `auth.signing_key:`, `identity-providers.<n>.token:`, `browser_login.client_secret:`).
    ("crates/secret-ref/src/lib.rs", ("SecretRef",)),
    # The grammar of `pools.upstream_credentials:` and each pool's own `upstream_credentials:`.
    ("crates/busbar/src/auth/mod.rs", ("UpstreamCreds",)),
)


def repo_root_from(src_dir: str) -> Path:
    """Locate the repository root by walking UP from the config source dir.

    HARD ERROR if not found, never a silent skip. The external-source rows above are real gate
    coverage; quietly dropping them because a path lookup failed would hand anyone the exact bypass
    this function exists to close (the same posture as the gate's unresolvable-baseline-ref rule).
    """
    p = Path(src_dir).resolve()
    for cand in (p, *p.parents):
        if (cand / "crates").is_dir() and (cand / "scripts").is_dir():
            return cand
    raise SystemExit(
        f"config-schema: cannot locate the repo root above {src_dir!r} (looked for a directory "
        "containing both `crates/` and `scripts/`). The EXTERNAL_SOURCES coverage cannot be "
        "resolved, and skipping it silently would be a free gate bypass."
    )


# The `match key.as_str() { "module" => ..., ... }` arms inside a hand-written `visit_map`: the
# AUTHORITATIVE list of wire keys such a type accepts.
MANUAL_KEY_RE = re.compile(r'^\s*"(?P<key>[A-Za-z0-9_.-]+)"\s*=>', re.MULTILINE)
# `fn visit_str` / `fn visit_map` / ... on the visitor: WHICH YAML node kinds the type accepts at
# all. `SecretRef` deliberately implements `visit_str` only to REJECT a bare string (an inline
# literal secret); losing that rejection is a security regression, and losing `visit_map` would
# retire the map form outright. Both are grammar, so both are fingerprinted.
MANUAL_VISIT_RE = re.compile(r"^\s*fn\s+(?P<v>visit_[a-z0-9_]+)\s*<", re.MULTILINE)


def parse_manual_de(src: str, name: str, impl_start: int) -> dict:
    """Fingerprint a HAND-WRITTEN `impl<'de> Deserialize<'de> for X` by its ACCEPTED WIRE KEYS.

    Before 1.5.4 these were recorded as an opaque sentinel (`{"fields": {}}`), which caught the type
    DISAPPEARING and nothing else. That is not enough for `SecretRef`: its accepted keys ARE the
    grammar of every secret reference in the config, and dropping one (retiring the `{ file: ... }`
    sugar) is a breaking change that the sentinel passed green.

    Every key is recorded OPTIONAL, because in a hand-written visitor the required/optional decision
    lives in imperative code that no regex can read. That is the right bias: a DROPPED key is still a
    field-removal (BREAKING, which is the case that matters), while a NEW accepted key is an additive
    widening -- exactly the classification each deserves.

    WHAT THIS STILL CANNOT SEE (stated, not papered over): the VALUE type behind a key. `{ env: VAR }`
    taking a String vs a map is invisible here, because the value type is only implied by a
    `next_value()?` inference site. Key-set changes and node-kind changes are covered; value-type
    changes on a hand-written impl are not.
    """
    end = match_block(src, src.index("{", impl_start))
    body = src[impl_start:end]
    fields = {}
    for m in MANUAL_KEY_RE.finditer(body):
        fields[m.group("key")] = {"type": "<manual>", "optional": True}
    for m in MANUAL_VISIT_RE.finditer(body):
        fields[f"<<visit:{m.group('v')}>>"] = {"type": "<visitor>", "optional": True}
    return {"kind": "struct", "fields": fields, "deserialize": "manual"}


def container_serde(attrs: str) -> dict:
    """Extract container-level serde knobs we care about: rename_all, deny_unknown_fields, plus
    whether the type derives Deserialize at all (gate for inclusion)."""
    derives = " ".join(re.findall(r"#\[derive\(([^)]*)\)\]", attrs))
    is_de = "Deserialize" in derives
    rename_all = None
    m = re.search(r'#\[serde\([^)]*rename_all\s*=\s*"([^"]+)"', attrs)
    if m:
        rename_all = m.group(1)
    deny = "deny_unknown_fields" in attrs
    transparent = "transparent" in attrs
    return {
        "is_de": is_de,
        "rename_all": rename_all,
        "deny_unknown_fields": deny,
        "transparent": transparent,
    }


def field_serde(attrs: str):
    """Per-field serde knobs. Returns (serde_rename|None, has_default, skip, flatten)."""
    rename = None
    m = re.search(r'#\[serde\([^)]*\brename\s*=\s*"([^"]+)"', attrs)
    if m:
        rename = m.group(1)
    has_default = bool(re.search(r"#\[serde\([^)]*\bdefault\b", attrs))
    skip = bool(
        re.search(r"#\[serde\([^)]*\bskip(_deserializing)?\b", attrs)
    )
    flatten = bool(re.search(r"#\[serde\([^)]*\bflatten\b", attrs))
    return rename, has_default, skip, flatten


def norm_type(t: str):
    """Normalize a Rust field type to (inner_type_string, optional). `Option<T>` unwraps to (T, True).
    Whitespace is collapsed so formatting never registers as a retype."""
    t = re.sub(r"\s+", " ", t).strip().rstrip(",").strip()
    optional = False
    m = re.match(r"^Option\s*<\s*(.+)\s*>$", t)
    if m:
        optional = True
        t = m.group(1).strip()
    return t, optional


def split_top(body: str):
    """Split a struct/enum body on top-level commas, respecting <> () [] {} nesting."""
    parts = []
    depth = 0
    cur = []
    for c in body:
        if c in "<([{":
            depth += 1
        elif c in ">)]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def parse_struct(body: str, csd: dict) -> dict:
    fields = {}
    # ── HOLE (1.5.4): container `rename_all` was applied to enum VARIANTS but never to struct
    # FIELDS. `#[serde(rename_all = "kebab-case")]` on a config struct renames EVERY wire key it
    # carries -- `max_admin_scope:` becomes `max-admin-scope:`, breaking every config that sets the
    # old spelling -- and the snapshot showed ZERO delta, because field names were emitted as the
    # Rust identifiers. The wire key is what the gate must freeze, so the rename is applied here,
    # exactly as `parse_enum` already does for variants.
    rename_fn = _RENAME_ALL.get(csd.get("rename_all") or "PascalCase", lambda s: s)
    if (csd.get("rename_all") or "PascalCase") == "PascalCase":
        # PascalCase on a struct field is serde's identity-ish case for our purposes: Rust fields are
        # already snake_case and serde does not touch them without an explicit rename_all. Keep the
        # identity so adding this dimension does not rewrite every existing field name.
        rename_fn = lambda s: s  # noqa: E731
    # Pull leading attribute clusters attached to each field. We walk the body linearly, buffering
    # `#[...]` attrs until a field decl consumes them.
    # First, split off attribute lines vs field decls by scanning tokens.
    # Simpler: regex each field as (attrs)(name): (type) up to top-level comma.
    entries = split_top(body)
    pending_attrs = ""
    for raw in entries:
        seg = raw.strip()
        if not seg:
            continue
        # an entry may itself begin with attribute lines
        # capture leading #[...] clusters
        attrs = pending_attrs
        pending_attrs = ""
        while True:
            m = re.match(r"\s*(#\[[^\n]*\])\s*", seg)
            if not m:
                break
            attrs += m.group(1) + "\n"
            seg = seg[m.end():]
        fm = re.match(
            r"(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)$",
            seg,
            re.DOTALL,
        )
        if not fm:
            # could be a trailing attribute-only entry; carry attrs forward
            if attrs.strip():
                pending_attrs = attrs
            continue
        name, ty = fm.group(1), fm.group(2)
        rename, has_default, skip, flatten = field_serde(attrs)
        if skip:
            continue
        inner, opt = norm_type(ty)
        if flatten:
            # a flattened field contributes its target type's surface; record it as a marker so a
            # change to WHICH type is flattened is caught, without needing cross-type resolution.
            fields[f"<<flatten:{inner}>>"] = {"type": inner, "optional": True}
            continue
        # An explicit per-field `#[serde(rename = "...")]` WINS over container rename_all (serde's
        # own precedence); otherwise the container rule renames the Rust identifier.
        serde_name = rename or rename_fn(name)
        fields[serde_name] = {"type": inner, "optional": bool(opt or has_default)}
    # ── HOLE (1.5.4): `deny_unknown_fields` was PARSED by container_serde and then DISCARDED, so
    # adding it to an existing section -- which turns every config carrying an extra key from
    # "accepted, ignored" into a HARD PARSE FAILURE -- was invisible to the gate. It is a property of
    # the wire grammar, so it belongs in the fingerprint.
    return {
        "kind": "struct",
        "fields": fields,
        "deny_unknown_fields": bool(csd.get("deny_unknown_fields")),
    }


def parse_enum(body: str, csd: dict) -> dict:
    variants = []
    rename_fn = _RENAME_ALL.get(csd.get("rename_all") or "PascalCase", lambda s: s)
    entries = split_top(body)
    pending_attrs = ""
    for raw in entries:
        seg = raw.strip()
        if not seg:
            continue
        attrs = pending_attrs
        pending_attrs = ""
        while True:
            m = re.match(r"\s*(#\[[^\n]*\])\s*", seg)
            if not m:
                break
            attrs += m.group(1) + "\n"
            seg = seg[m.end():]
        vm = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", seg)
        if not vm:
            if attrs.strip():
                pending_attrs = attrs
            continue
        vname = vm.group(1)
        rename, _, skip, _ = field_serde(attrs)
        if skip:
            continue
        variants.append(rename or rename_fn(vname))
    return {"kind": "enum", "variants": sorted(set(variants))}


def extract(src_dir: str) -> dict:
    types = {}
    files = sorted(
        p
        for p in Path(src_dir).glob("*.rs")
        if p.name != "mod.rs" or True  # include mod.rs
    )
    for path in files:
        raw = path.read_text(encoding="utf-8", errors="replace")
        src = strip_comments(raw)
        for m in ITEM_RE.finditer(src):
            csd = container_serde(m.group("attrs") or "")
            if not csd["is_de"]:
                continue
            name = m.group("name")
            if m.group("open") == ";":
                # unit struct or tuple-struct-with-semicolon; record as opaque struct (no fields)
                types[name] = {"kind": "struct", "fields": {}}
                continue
            open_idx = m.start("open")
            end = match_block(src, open_idx)
            body = src[open_idx + 1 : end - 1]
            if m.group("kw") == "enum":
                parsed = parse_enum(body, csd)
            else:
                parsed = parse_struct(body, csd)
            # last definition wins (config has no duplicate type names across the module)
            types[name] = parsed

        # ── HOLE 1: types with a HAND-WRITTEN `impl<'de> Deserialize<'de> for X` carry no derive, so
        # the derive-gated walk above skips them entirely — yet they ARE config surface (PoolCfg,
        # PoolsCfg, LimitCfg, OnErrorCfg, OnExhaustedCfg all deserialize by hand to accept a
        # shorthand-scalar-or-table). Their INNER `Raw*` helper structs are already captured above
        # (they do derive), so the field-level surface is tracked; what would otherwise be invisible
        # is the type itself DISAPPEARING. Record each as a sentinel so a section removal is still
        # caught RED. `custom` is a marker, not a field, so it never produces field-level noise.
        for m in MANUAL_DE_RE.finditer(src):
            name = m.group("name")
            if name in types:
                continue
            types[name] = parse_manual_de(src, name, m.end())

        # ── HOLE 2: `pub type HookDefs = IndexMap<String, HookDefCfg>;` — the named-DEFINITION-map
        # aliases are the shape of `hooks:`/`export:`/`identity-providers:` themselves.
        # A field typed `ExportDefs` compares equal even if the alias were retargeted, so pin the
        # alias TARGET too: retargeting `IndexMap<String, ExportDefCfg>` -> `Vec<ExportDefCfg>` is a
        # grammar break (named map -> list) and must land as a RETYPE, not silence.
        for m in ALIAS_RE.finditer(src):
            target = re.sub(r"\s+", " ", m.group("target")).strip()
            # A callback/trait-object alias is plumbing, never config grammar — excluded so an
            # internal signature change can't masquerade as a config break.
            if "dyn " in target or "Fn(" in target:
                continue
            types[f"type {m.group('name')}"] = {
                "kind": "alias",
                "target": target,
            }

    # ── EXTERNAL SOURCES: config-grammar types defined outside crates/busbar/src/config. See
    # EXTERNAL_SOURCES for why this is an allowlist rather than a wider glob.
    root = repo_root_from(src_dir)
    for rel, wanted in EXTERNAL_SOURCES:
        path = root / rel
        if not path.is_file():
            # HARD ERROR, never a skip: a moved/renamed file must fail loudly, or the coverage this
            # row buys evaporates silently on the commit that moves it.
            raise SystemExit(
                f"config-schema: EXTERNAL_SOURCES names {rel!r}, which does not exist. Update the "
                "row (or delete it, if the type is genuinely gone) -- skipping it would silently "
                f"drop {', '.join(wanted)} out of the frozen-grammar gate."
            )
        src = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        found = set()
        for m in ITEM_RE.finditer(src):
            name = m.group("name")
            if name not in wanted:
                continue
            csd = container_serde(m.group("attrs") or "")
            if m.group("open") == ";":
                types[name] = {"kind": "struct", "fields": {}, "deny_unknown_fields": False}
                found.add(name)
                continue
            open_idx = m.start("open")
            end = match_block(src, open_idx)
            body = src[open_idx + 1 : end - 1]
            if m.group("kw") == "enum":
                types[name] = parse_enum(body, csd)
            else:
                types[name] = parse_struct(body, csd)
            found.add(name)
        # A hand-written Deserialize (SecretRef) has no derive, so ITEM_RE's derive gate skips it.
        for m in MANUAL_DE_RE.finditer(src):
            name = m.group("name")
            if name in wanted:
                types[name] = parse_manual_de(src, name, m.end())
                found.add(name)
        missing = sorted(set(wanted) - found)
        if missing:
            raise SystemExit(
                f"config-schema: EXTERNAL_SOURCES row {rel!r} names {missing} but no such "
                "Deserialize type was found in it. A renamed/removed config-grammar type must fail "
                "the generator, not silently shrink the gate's coverage."
            )

    return {
        "_meta": {
            "description": "busbar config-surface structural fingerprint — FROZEN at 1.5.3, "
            "additive-only forever (enforced by the config-stability gate).",
            "frozen_at": "1.5.3",
            "generator": "scripts/config-schema.py gen",
            "surface": "serde-Deserialize structs/enums (derived AND hand-impl'd) + the "
            "named-definition-map type aliases under crates/busbar/src/config",
        },
        "types": types,
    }


def canonical(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# Classifier: additive (green) vs breaking (red).
# ─────────────────────────────────────────────────────────────────────────────────────────────────

FROZEN_MSG = (
    "the config grammar is FROZEN after 1.5.3 — additive-only (new OPTIONAL key / section / enum "
    "variant). 1.5.3 was the LAST config-breaking release. Regenerating the snapshot does NOT "
    "launder a break: the additive check reads the committed baseline, not your working tree."
)


def classify(baseline: dict, fresh: dict):
    """Return list of (severity, jsonpath, reason). severity is 'BREAKING' or 'ADDITIVE'."""
    findings = []
    bt = baseline.get("types", {})
    ft = fresh.get("types", {})

    for tname in sorted(set(bt) | set(ft)):
        b = bt.get(tname)
        f = ft.get(tname)
        if b is None:
            findings.append(("ADDITIVE", tname, "new type/section added"))
            continue
        if f is None:
            findings.append(
                ("BREAKING", tname, "type/section REMOVED (a config referencing it now fails)")
            )
            continue
        if b.get("kind") != f.get("kind"):
            findings.append(
                (
                    "BREAKING",
                    tname,
                    f"kind changed {b.get('kind')} -> {f.get('kind')} (shape change)",
                )
            )
            continue
        if b["kind"] == "alias":
            # A named-definition-map alias (`hooks:`/`export:`/`identity-providers:` shape). Any
            # retarget is a grammar change — `IndexMap<String, T>` -> `Vec<T>` turns a named map into
            # a list, which breaks every config that used the map form.
            if b.get("target") != f.get("target"):
                findings.append(
                    (
                        "BREAKING",
                        tname,
                        f"type alias RETARGETED {b.get('target')!r} -> {f.get('target')!r} "
                        "(the definition-map shape changed)",
                    )
                )
            continue
        if b["kind"] == "struct":
            # ── deny_unknown_fields (1.5.4). ADDING it to an existing section turns every config
            # that carries an extra key under it from "accepted and ignored" into a HARD PARSE
            # FAILURE, so it is BREAKING. REMOVING it only widens what parses, so it is additive.
            #
            # RATCHET, deliberately: the comparison runs only when the BASELINE already carries the
            # key. Snapshots committed before 1.5.4 have no `deny_unknown_fields` at all, and
            # comparing `None` against a freshly-emitted `True` would fire a BREAKING finding on
            # every already-strict section the moment this dimension is introduced -- a wall of
            # false red on the very commit that adds the coverage. `None` means "this baseline
            # predates the dimension", not "it was false". From the next commit on, every baseline
            # carries the key and the rule is fully live. Self-extinguishing, like the gate's
            # one-time snapshot bootstrap.
            if "deny_unknown_fields" in b:
                bd, fd = b.get("deny_unknown_fields"), f.get("deny_unknown_fields")
                if fd and not bd:
                    findings.append(
                        (
                            "BREAKING",
                            f"{tname}.<deny_unknown_fields>",
                            "deny_unknown_fields ADDED (a config carrying any extra key under this "
                            "section now fails to parse instead of being accepted)",
                        )
                    )
                elif bd and not fd:
                    findings.append(
                        (
                            "ADDITIVE",
                            f"{tname}.<deny_unknown_fields>",
                            "deny_unknown_fields removed (widens the accepted set)",
                        )
                    )
            bf, ff = b.get("fields", {}), f.get("fields", {})
            for fld in sorted(set(bf) | set(ff)):
                path = f"{tname}.{fld}"
                bv = bf.get(fld)
                fv = ff.get(fld)
                if bv is None:
                    if fv.get("optional"):
                        findings.append(("ADDITIVE", path, "new OPTIONAL field added"))
                    else:
                        findings.append(
                            (
                                "BREAKING",
                                path,
                                "new REQUIRED field added (breaks a config that omits it)",
                            )
                        )
                    continue
                if fv is None:
                    findings.append(
                        ("BREAKING", path, "field REMOVED (breaks a config that sets it)")
                    )
                    continue
                if bv.get("type") != fv.get("type"):
                    findings.append(
                        (
                            "BREAKING",
                            path,
                            f"field RETYPED {bv.get('type')!r} -> {fv.get('type')!r} (shape change)",
                        )
                    )
                if bv.get("optional") and not fv.get("optional"):
                    findings.append(
                        (
                            "BREAKING",
                            path,
                            "field made REQUIRED (was optional; breaks a config that omits it)",
                        )
                    )
                elif not bv.get("optional") and fv.get("optional"):
                    findings.append(
                        ("ADDITIVE", path, "field relaxed required -> optional (widens accepted set)")
                    )
        else:  # enum
            bvar, fvar = set(b.get("variants", [])), set(f.get("variants", []))
            for v in sorted(fvar - bvar):
                findings.append(("ADDITIVE", f"{tname}::{v}", "enum variant APPENDED"))
            for v in sorted(bvar - fvar):
                findings.append(
                    (
                        "BREAKING",
                        f"{tname}::{v}",
                        "enum variant REMOVED/RENAMED (breaks a config using the old value)",
                    )
                )
    return findings


def cmd_gen(argv):
    if len(argv) != 1:
        print("usage: config-schema.py gen <config-src-dir>", file=sys.stderr)
        return 2
    sys.stdout.write(canonical(extract(argv[0])))
    return 0


def load_waivers(path: str):
    """Parse the committed break-waiver file.

    WHY this exists, and why it is safe: 1.5.3 is the release that BREAKS config one last time, and
    this gate lands DURING it, while the grammar units are still landing. Without an escape hatch the
    gate would block its own release. Without a NARROW one, it would be a rubber stamp.

    The hatch is therefore a COMMITTED FILE, never an env var: an env var can be flipped in a workflow
    edit and reviewed by nobody, whereas every waiver here shows up as an added line in the PR diff,
    next to the break it excuses. Each waiver must name an EXACT path (`Type.field` / `Type::Variant`
    / `Type`) plus a reason — no globs, no wildcards, no "waive everything". A waiver suppresses that
    one path and nothing else, and every applied waiver is printed LOUDLY in the gate output with its
    reason, so a reviewer sees exactly what was excused.

    Format (`#` comments and blank lines ignored):
        Type.field = reason text
    """
    waivers = {}
    p = Path(path)
    if not p.exists():
        return waivers
    for lineno, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            raise SystemExit(
                f"{path}:{lineno}: malformed waiver {raw.strip()!r} — expected `path = reason`"
            )
        key, _, reason = line.partition("=")
        key, reason = key.strip(), reason.strip()
        if not key or not reason:
            raise SystemExit(
                f"{path}:{lineno}: a waiver must name BOTH an exact path AND a reason"
            )
        if "*" in key or "?" in key:
            raise SystemExit(
                f"{path}:{lineno}: waiver path {key!r} contains a wildcard — waivers must be EXACT "
                "paths so each excused break is individually reviewable"
            )
        waivers[key] = reason
    return waivers


def cmd_classify(argv):
    if len(argv) not in (2, 3):
        print(
            "usage: config-schema.py classify <baseline.json> <fresh.json> [waivers-file]",
            file=sys.stderr,
        )
        return 2
    baseline = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    fresh = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    waivers = load_waivers(argv[2]) if len(argv) == 3 else {}

    findings = classify(baseline, fresh)
    additive = [x for x in findings if x[0] == "ADDITIVE"]
    raw_breaking = [x for x in findings if x[0] == "BREAKING"]
    # A waiver matches ONE exact path. Everything else stays RED.
    waived = [x for x in raw_breaking if x[1] in waivers]
    breaking = [x for x in raw_breaking if x[1] not in waivers]

    for _, path, reason in additive:
        print(f"  additive OK   {path}: {reason}")
    for _, path, reason in waived:
        print(f"  WAIVED        {path}: {reason}  <- waived: {waivers[path]}")
    for _, path, reason in breaking:
        print(f"  BREAKING  RED {path}: {reason}", file=sys.stderr)

    if waived:
        print(
            f"  ({len(waived)} break(s) explicitly WAIVED by a committed, per-path waiver — "
            "each is a reviewed line in the diff, not a blanket override)"
        )
    # An unused waiver is dead weight that would silently pre-authorize a FUTURE break. Fail on it so
    # the waiver file can never accumulate standing permission to break things.
    stale = sorted(set(waivers) - {x[1] for x in waived})
    if stale:
        for key in stale:
            print(
                f"  STALE WAIVER  {key}: waives a break that no longer exists — delete it "
                "(a lingering waiver silently pre-authorizes a future break at that path)",
                file=sys.stderr,
            )
        return 4
    if breaking:
        print("", file=sys.stderr)
        print(f"non-additive config change ({len(breaking)}); {FROZEN_MSG}", file=sys.stderr)
        return 3
    if not findings:
        print("  (no schema delta)")
    return 0


def main():
    if len(sys.argv) < 2:
        print("usage: config-schema.py {gen|classify} ...", file=sys.stderr)
        return 2
    cmd, rest = sys.argv[1], sys.argv[2:]
    if cmd == "gen":
        return cmd_gen(rest)
    if cmd == "classify":
        return cmd_classify(rest)
    print(f"unknown subcommand {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
