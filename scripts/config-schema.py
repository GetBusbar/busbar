#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# config-schema.py — the config-stability gate's engine.
#
# Two jobs, one file (no external deps; stdlib only, so it runs on the same bare runner every other
# scripts/*-lint.sh does):
#
#   gen [src ...]                   Emit a DETERMINISTIC structural fingerprint of the config surface
#                                   (every serde-`Deserialize` struct/enum in the TRACKED SOURCE SET,
#                                   `SOURCES` below) as canonical pretty JSON on stdout. This is the
#                                   "schema snapshot" the drift guard freezes — the config-grammar
#                                   analogue of the committed openapi.json the admin API
#                                   drift-guards against. With no arguments the tracked set is used;
#                                   explicit paths (dirs or files) are for the gate's self-test.
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
# THE TRACKED SOURCE SET — every file whose serde surface IS config grammar.
#
# This list is the gate's reach, and it used to be a single `crates/busbar/src/config/*.rs` glob.
# That glob is where a config type HAPPENS to live, not what a config type IS, and two of the most
# load-bearing grammars in the product sat outside it with ZERO fingerprint:
#
#   * `SecretRef` (crates/secret-ref/src/lib.rs) is the grammar of EVERY secret reference in the
#     config: the canonical `{ module, settings }` form and the `{ env: … }` / `{ file: … }` sugar.
#     It lives in its own crate precisely so plugins and schema tooling can reach it, which is what
#     put it outside a glob anchored on the busbar crate's config module.
#   * `UpstreamCreds` (crates/busbar/src/auth/mod.rs) is the `upstream_credentials:` key's value
#     grammar. It is deserialized straight out of the config document; it lives beside the
#     middleware that consumes it.
#   * `crates/busbar/src/a2a/` holds the ENTIRE `agents:` section grammar — the per-entry shape, the
#     four pin mechanisms, and the leased outbound credential. It was outside the set for the same
#     reason the two above were: it lives with the plane that consumes it rather than under the
#     config module. The snapshot recorded `agents: crate::a2a::config::AgentsCfg` and stopped
#     there, so every key an operator writes under an agent had NO fingerprint at all and a
#     BREAKING change to that grammar passed the additive-only check silently. Only the two files
#     that declare config types are tracked; the rest of the plane is runtime.
#
# A path is a directory (every `*.rs` directly inside it) or a single file. A path that does not
# exist is a HARD ERROR, never a skip: a source silently dropping out of the set would silently
# un-freeze its grammar, which is the exact failure this gate exists to prevent.
SOURCES = [
    "crates/busbar/src/config",
    "crates/secret-ref/src/lib.rs",
    "crates/busbar/src/auth/mod.rs",
    "crates/busbar/src/a2a/config.rs",
    "crates/busbar/src/a2a/creds.rs",
]


def resolve_sources(paths):
    """Expand the tracked source set to a deduplicated, sorted list of .rs files.

    A missing path, a directory holding no `*.rs`, or a non-`.rs` file is a hard error. There is no
    "the file moved, so the gate quietly stopped covering it" path."""
    files = []
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            raise SystemExit(
                f"config-schema: tracked source {raw!r} does not exist. The config-grammar gate "
                "covers a FIXED set of sources; a vanished one is a coverage hole, not a skip. If "
                "the file moved, update SOURCES in scripts/config-schema.py."
            )
        if p.is_dir():
            found = sorted(p.glob("*.rs"))
            if not found:
                raise SystemExit(
                    f"config-schema: tracked source directory {raw!r} contains no *.rs files"
                )
            files.extend(found)
        else:
            if p.suffix != ".rs":
                raise SystemExit(f"config-schema: tracked source {raw!r} is not a .rs file")
            files.append(p)
    # Stable order, no double-counting when a file is also reached through its directory.
    return sorted(set(files), key=lambda p: str(p))


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


CFG_TEST_MOD_RE = re.compile(r"#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{")


def strip_cfg_test_mods(src: str) -> str:
    """Blank out `#[cfg(test)] mod … { … }` bodies (length-preserving, like strip_comments).

    A test-only `#[derive(Deserialize)]` fixture is NOT config grammar, and the tracked source set
    now includes files that carry inline test modules. Left in, a fixture type would be frozen into
    the grammar, and — because the extractor is last-definition-wins — a fixture sharing a real
    type's name would REPLACE the real grammar in the fingerprint. Neither is acceptable."""
    while True:
        m = CFG_TEST_MOD_RE.search(src)
        if not m:
            return src
        end = match_block(src, m.end() - 1)
        blanked = "".join("\n" if c == "\n" else " " for c in src[m.start():end])
        src = src[: m.start()] + blanked + src[end:]


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

# rename_all mappings, in serde's own two flavours.
#
# serde applies a rename rule to the IDENT, and a field ident is `snake_case` while a variant ident
# is `PascalCase` — so the SAME rule name is a different transform on each. `kebab-case` on the
# variant `LeastBad` is `least-bad`, but on the field `max_tokens` it is `max-tokens`, and the
# PascalCase-shaped transform would leave `max_tokens` untouched. Getting that wrong does not
# produce a loud error, it produces a fingerprint that quietly disagrees with the parser.
_VARIANT_RENAME_ALL = {
    "snake_case": lambda s: re.sub(r"(?<!^)(?=[A-Z])", "_", s).lower(),
    "kebab-case": lambda s: re.sub(r"(?<!^)(?=[A-Z])", "-", s).lower(),
    "lowercase": lambda s: s.lower(),
    "UPPERCASE": lambda s: s.upper(),
    "camelCase": lambda s: s[:1].lower() + s[1:],
    "PascalCase": lambda s: s,
    "SCREAMING_SNAKE_CASE": lambda s: re.sub(r"(?<!^)(?=[A-Z])", "_", s).upper(),
    "SCREAMING-KEBAB-CASE": lambda s: re.sub(r"(?<!^)(?=[A-Z])", "-", s).upper(),
}

_FIELD_RENAME_ALL = {
    "snake_case": lambda s: s,
    "kebab-case": lambda s: s.replace("_", "-"),
    "lowercase": lambda s: s.lower(),
    "UPPERCASE": lambda s: s.upper(),
    "camelCase": lambda s: "".join(
        w if i == 0 else w.capitalize() for i, w in enumerate(s.split("_"))
    ),
    "PascalCase": lambda s: "".join(w.capitalize() for w in s.split("_")),
    "SCREAMING_SNAKE_CASE": lambda s: s.upper(),
    "SCREAMING-KEBAB-CASE": lambda s: s.replace("_", "-").upper(),
}


def container_serde(attrs: str) -> dict:
    """Extract container-level serde knobs we care about: rename_all, deny_unknown_fields, plus
    whether the type derives Deserialize at all (gate for inclusion)."""
    derives = " ".join(re.findall(r"#\[derive\(([^)]*)\)\]", attrs))
    is_de = "Deserialize" in derives
    rename_all = None
    m = re.search(r'#\[serde\([^)]*rename_all\s*=\s*"([^"]+)"', attrs)
    if m:
        rename_all = m.group(1)
    deny = bool(re.search(r"#\[serde\([^)]*\bdeny_unknown_fields\b", attrs))
    transparent = bool(re.search(r"#\[serde\([^)]*\btransparent\b", attrs))
    return {
        "is_de": is_de,
        "rename_all": rename_all,
        "deny_unknown_fields": deny,
        "transparent": transparent,
    }


def rename_fn_for(csd: dict, ident: str):
    """The container-level `rename_all` transform for `ident` in ("field", "variant").

    An unknown value is a hard error rather than a silent identity fallback: `rename_all` rewrites
    every wire key on the container, so quietly not applying one would report a grammar the parser
    does not accept — a fingerprint that lies is worse than no fingerprint."""
    ra = csd.get("rename_all")
    if ra is None:
        return lambda s: s
    table = _FIELD_RENAME_ALL if ident == "field" else _VARIANT_RENAME_ALL
    fn = table.get(ra)
    if fn is None:
        raise SystemExit(
            f"config-schema: unsupported #[serde(rename_all = {ra!r})] on a {ident}. Add it to the "
            "rename tables in this file — an "
            "unhandled rename_all would fingerprint wire keys the parser does not actually accept."
        )
    return fn


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


def container_flags(csd: dict) -> dict:
    """The container-level knobs that are part of the ACCEPTED-DOCUMENT grammar, recorded on every
    node so a flip is a snapshot delta.

    `deny_unknown_fields` decides whether a document carrying an extra key parses or is rejected;
    turning it ON breaks every config that carries a key busbar used to ignore. `transparent`
    decides whether the wire form is a map or the single inner value. Both were parsed and then
    thrown away, so either could be flipped with ZERO snapshot delta."""
    return {
        "deny_unknown_fields": bool(csd.get("deny_unknown_fields")),
        "transparent": bool(csd.get("transparent")),
    }


def parse_struct(body: str, csd: dict) -> dict:
    fields = {}
    rename_fn = rename_fn_for(csd, "field")
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
        # Container `rename_all` renames the WIRE KEY of every field it covers (a per-field
        # `rename` still wins). This used to be applied to enum variants only, so adding
        # `rename_all` to a config struct renamed every one of its keys with zero snapshot delta.
        serde_name = rename or rename_fn(name)
        fields[serde_name] = {"type": inner, "optional": bool(opt or has_default)}
    return {"kind": "struct", "fields": fields, **container_flags(csd)}


def parse_enum(body: str, csd: dict) -> dict:
    variants = []
    rename_fn = rename_fn_for(csd, "variant")
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
    return {"kind": "enum", "variants": sorted(set(variants)), **container_flags(csd)}


# The string-literal match arms of a hand-written `Deserialize` impl. A hand-written impl exists in
# this tree for exactly one reason — to accept a SUGAR spelling the derive cannot express — and the
# spellings it accepts are these literals (`"env"`/`"file"`/`"module"`/`"settings"` for `SecretRef`,
# `"requests"`/`"tokens"`/`"per"`/… for `LimitCfg`). They are wire keys, so they are grammar.
MATCH_ARM_RE = re.compile(r'((?:"[^"\n]*"\s*\|\s*)*"[^"\n]*")\s*=>')
STR_LIT_RE = re.compile(r'"([^"\n]*)"')


def manual_de_detail(src: str, impl_open_idx: int, decls: dict, name: str):
    """Fingerprint a hand-written `impl<'de> Deserialize<'de> for X`.

    Two halves, because a hand-written impl has two halves of grammar:
      * the ACCEPTED WIRE KEYS — the impl's string match arms, i.e. the spellings a document may
        use. For `SecretRef` that is `module` / `settings` / `env` / `file`.
      * the TYPE of each wire-visible member, taken from `X`'s own struct declaration. `X` carries
        no `Deserialize` derive (that is the point of a hand-written impl), so the derive-gated walk
        skipped it entirely and `SecretRef { module: String, settings: Map<String, Value> }` could
        be retyped freely.

    ONLY wire-visible members are recorded. A hand-impl'd type's declaration is also its PARSED
    RESULT, and those two things are not the same set: `LimitCfg` accepts `requests:`/`tokens:` and
    stores `amount`/`metric`, `PoolCfg` accepts nothing by literal at all (it delegates to derived
    `Raw*` helpers that this generator already fingerprints). Freezing the whole declaration would
    fire RED on a purely internal field rename that no config can observe, and a gate that cries
    wolf is a gate that gets muted. Intersecting with the wire keys keeps every entry here
    something a user's document can actually contain."""
    end = match_block(src, impl_open_idx)
    body = src[impl_open_idx:end]
    keys = set()
    for m in MATCH_ARM_RE.finditer(body):
        keys.update(STR_LIT_RE.findall(m.group(1)))
    decl_fields = (decls.get(name) or {}).get("fields", {})
    return {
        "kind": "manual",
        "wire_keys": sorted(keys),
        "fields": {k: v for k, v in decl_fields.items() if k in keys},
    }


def declared_shape(src: str, m) -> dict:
    """Parse a struct/enum declaration REGARDLESS of whether it derives Deserialize."""
    csd = container_serde(m.group("attrs") or "")
    if m.group("open") == ";":
        return {"fields": {}, **container_flags(csd)}
    open_idx = m.start("open")
    end = match_block(src, open_idx)
    body = src[open_idx + 1 : end - 1]
    if m.group("kw") == "enum":
        return parse_enum(body, csd)
    return parse_struct(body, csd)


def extract(paths) -> dict:
    types = {}
    files = resolve_sources(paths)
    sources = {}
    decls = {}
    for path in files:
        src = strip_cfg_test_mods(strip_comments(path.read_text(encoding="utf-8", errors="replace")))
        sources[path] = src
        # Every declaration in the tracked set, derive or not, so a hand-written `Deserialize` impl
        # in one file can be matched to its type's declaration in another.
        for m in ITEM_RE.finditer(src):
            shape = declared_shape(src, m)
            decls[m.group("name")] = {k: v for k, v in shape.items() if k != "kind"}

    for path, src in sources.items():
        for m in ITEM_RE.finditer(src):
            csd = container_serde(m.group("attrs") or "")
            if not csd["is_de"]:
                continue
            name = m.group("name")
            if m.group("open") == ";":
                # unit struct or tuple-struct-with-semicolon; record as opaque struct (no fields)
                types[name] = {"kind": "struct", "fields": {}, **container_flags(csd)}
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
        # shorthand-scalar-or-table, and `SecretRef` is the grammar of every secret reference).
        # The `X` sentinel below records that the type EXISTS, so a section removal is caught RED.
        # It records nothing else, which was the hole: `SecretRef`'s own `{ module, settings }`
        # shape and its `{ env: … }` / `{ file: … }` sugar were both unfingerprinted, so retyping
        # either sailed through the additive gate green.
        #
        # The detail lands under a SEPARATE `manual-de X` key rather than being folded into the `X`
        # sentinel. That is deliberate: folding it in would turn every already-tracked hand-impl'd
        # type's `fields: {}` into a populated map, and the classifier would read that fidelity
        # increase as a pile of new REQUIRED fields, i.e. a false RED on the very commit that adds
        # the coverage. A new key is honestly additive, and from here on it is frozen like anything
        # else. Same shape as the `type X` alias keys.
        for m in MANUAL_DE_RE.finditer(src):
            name = m.group("name")
            types.setdefault(name, {"kind": "struct", "fields": {}, "deserialize": "manual"})
            open_idx = src.find("{", m.end())
            if open_idx != -1:
                types[f"manual-de {name}"] = manual_de_detail(src, open_idx, decls, name)

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
    return {
        "_meta": {
            "description": "busbar config-surface structural fingerprint — FROZEN at 1.5.3, "
            "additive-only forever (enforced by the config-stability gate).",
            "frozen_at": "1.5.3",
            "generator": "scripts/config-schema.py gen",
            "surface": "serde-Deserialize structs/enums (derived AND hand-impl'd, including each "
            "hand-impl'd type's declared shape and accepted wire keys) + the named-definition-map "
            "type aliases, over the tracked source set (SOURCES in scripts/config-schema.py): the "
            "busbar config module, SecretRef, and UpstreamCreds",
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


def field_findings(tname: str, bf: dict, ff: dict, findings: list):
    """Classify a field map (a derived struct's, or a hand-impl'd type's declared shape)."""
    for fld in sorted(set(bf) | set(ff)):
        path = f"{tname}.{fld}"
        bv = bf.get(fld)
        fv = ff.get(fld)
        if bv is None:
            if fv.get("optional"):
                findings.append(("ADDITIVE", path, "new OPTIONAL field added"))
            else:
                findings.append(
                    ("BREAKING", path, "new REQUIRED field added (breaks a config that omits it)")
                )
            continue
        if fv is None:
            findings.append(("BREAKING", path, "field REMOVED (breaks a config that sets it)"))
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


def variant_findings(tname: str, bvar, fvar, findings: list, what="enum variant"):
    bvar, fvar = set(bvar or []), set(fvar or [])
    for v in sorted(fvar - bvar):
        findings.append(("ADDITIVE", f"{tname}::{v}", f"{what} APPENDED"))
    for v in sorted(bvar - fvar):
        findings.append(
            (
                "BREAKING",
                f"{tname}::{v}",
                f"{what} REMOVED/RENAMED (breaks a config using the old value)",
            )
        )


def container_flag_findings(tname: str, b: dict, f: dict, findings: list):
    """Classify the container knobs that decide WHICH DOCUMENTS PARSE.

    Both were previously extracted and thrown away, so both could be flipped with zero delta.

    `deny_unknown_fields` off -> on is BREAKING in the plainest possible sense: a config carrying an
    extra key parsed yesterday and is a hard boot error today. On -> off only widens what is
    accepted, so it is additive. `transparent` changes the wire form between a map and a bare inner
    value, so a flip in EITHER direction breaks configs written against the other.

    A key ABSENT from the baseline means that snapshot predates flag recording; it is not evidence
    of the flag being off, so it yields no finding. That branch is self-extinguishing (the generator
    now writes both flags on every struct/enum node, and the gate's self-test asserts it does), and
    it is the only tolerant reading in here."""
    for flag, both_ways in (("deny_unknown_fields", False), ("transparent", True)):
        bv, fv = b.get(flag), f.get(flag)
        if bv is None or fv is None or bool(bv) == bool(fv):
            continue
        if flag == "deny_unknown_fields" and not bv:
            findings.append(
                (
                    "BREAKING",
                    f"{tname}[deny_unknown_fields]",
                    "deny_unknown_fields turned ON (a config carrying any extra key under this "
                    "section parsed before and is a hard error now)",
                )
            )
        elif flag == "deny_unknown_fields":
            findings.append(
                (
                    "ADDITIVE",
                    f"{tname}[deny_unknown_fields]",
                    "deny_unknown_fields turned OFF (widens the accepted set)",
                )
            )
        elif both_ways:
            findings.append(
                (
                    "BREAKING",
                    f"{tname}[transparent]",
                    f"serde(transparent) {bv} -> {fv} (the wire form changes between a map and the "
                    "bare inner value; configs written for either spelling break)",
                )
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
        # The knobs that decide WHICH DOCUMENTS PARSE, on every kind that can carry them.
        container_flag_findings(tname, b, f, findings)
        if b["kind"] == "manual":
            # A hand-written `Deserialize`: its accepted spellings and their declared types.
            field_findings(tname, b.get("fields", {}), f.get("fields", {}), findings)
            variant_findings(
                tname, b.get("wire_keys"), f.get("wire_keys"), findings, what="accepted wire key"
            )
        elif b["kind"] == "struct":
            field_findings(tname, b.get("fields", {}), f.get("fields", {}), findings)
        else:  # enum
            variant_findings(tname, b.get("variants"), f.get("variants"), findings)
    return findings


def cmd_gen(argv):
    """`gen` with no arguments fingerprints the TRACKED SOURCE SET (`SOURCES`). Explicit paths are
    for the gate's self-test, which fingerprints throwaway fixture sources."""
    sys.stdout.write(canonical(extract(argv or SOURCES)))
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
